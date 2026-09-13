use std::collections::BTreeMap;

use anchor_identity::{
    IdentityId, IdentityState, SignedIdentityEvent, apply_inception, apply_ordinary_event,
    derive_identity_id,
};

use crate::LedgerError;

/// Holds the state of the ledger, including all identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerState {
    identities: BTreeMap<IdentityId, IdentityState>,
}

impl LedgerState {
    /// Creates a ledger state with no identities.
    pub fn empty() -> Self {
        Self {
            identities: BTreeMap::new(),
        }
    }

    /// Wraps a map of identity states as a ledger state.
    pub fn from_identities(identities: BTreeMap<IdentityId, IdentityState>) -> Self {
        Self { identities }
    }

    /// Returns all identities in the ledger, keyed by ID.
    pub fn identities(&self) -> &BTreeMap<IdentityId, IdentityState> {
        &self.identities
    }

    /// Returns a single identity's state, if it exists.
    pub fn identity(&self, id: &IdentityId) -> Option<&IdentityState> {
        self.identities.get(id)
    }
}

/// Applies a single event to the ledger and returns the resulting identity state, without mutating `state`.
pub fn apply_one(
    state: &LedgerState,
    event: &SignedIdentityEvent,
) -> Result<IdentityState, LedgerError> {
    match event {
        SignedIdentityEvent::Inception(signed_inception) => {
            let id = derive_identity_id(signed_inception.inception())?;

            if state.identities.contains_key(&id) {
                return Err(LedgerError::IdentityAlreadyExists(id));
            }

            let identity_state = apply_inception(event)?;

            Ok(identity_state)
        }
        SignedIdentityEvent::Ordinary(signed_event) => {
            let id = signed_event.event().identity();
            let identity_state = state
                .identities
                .get(id)
                .ok_or(LedgerError::UnknownIdentity(*id))?;

            let next_state = apply_ordinary_event(identity_state, event)?;

            Ok(next_state)
        }
    }
}

/// Applies a batch of transactions to the ledger, rejecting the whole batch if any event is invalid.
pub fn apply_all(
    state: &LedgerState,
    transactions: &[SignedIdentityEvent],
) -> Result<LedgerState, LedgerError> {
    let mut scratch = state.clone();

    for event in transactions {
        let next = apply_one(&scratch, event)?;

        scratch.identities.insert(*next.id(), next);
    }

    Ok(scratch)
}

/// Applies each candidate that succeeds against the running state, silently dropping the rest.
pub fn select_valid(
    state: &LedgerState,
    candidates: &[SignedIdentityEvent],
) -> (Vec<SignedIdentityEvent>, LedgerState) {
    let mut scratch = state.clone();
    let mut accepted = Vec::new();

    for candidate in candidates {
        if let Ok(next) = apply_one(&scratch, candidate) {
            scratch.identities.insert(*next.id(), next);

            accepted.push(candidate.clone());
        }
    }

    (accepted, scratch)
}

#[cfg(test)]
mod tests {
    use anchor_identity::{ApplyError, EventVerificationError, Sequence};
    use anchor_testing::{deactivate_event, inception_event, rotate_event, signing_key};
    use anyhow::{Context, Result};

    use super::*;

    #[test]
    fn empty_ledger_has_no_identities() {
        let ledger = LedgerState::empty();

        assert!(ledger.identity(&IdentityId::from_bytes([0; 32])).is_none());
    }

    #[test]
    fn apply_one_accepts_inception() -> Result<()> {
        let signer = signing_key(0x11);
        let ledger = LedgerState::empty();
        let (event, _id) = inception_event(&signer, 0x22)?;

        let state = apply_one(&ledger, &event)?;

        assert_eq!(state.sequence(), Sequence::ZERO);

        Ok(())
    }

    #[test]
    fn apply_one_rejects_duplicate_inception() -> Result<()> {
        let signer = signing_key(0x11);
        let (event, id) = inception_event(&signer, 0x22)?;
        let ledger = apply_all(&LedgerState::empty(), std::slice::from_ref(&event))?;

        let result = apply_one(&ledger, &event);

        assert!(matches!(
            result,
            Err(LedgerError::IdentityAlreadyExists(actual)) if actual == id
        ));

        Ok(())
    }

    #[test]
    fn apply_one_rejects_ordinary_event_for_unknown_identity() -> Result<()> {
        let signer = signing_key(0x11);
        let ledger = LedgerState::empty();
        let (inception, _id) = inception_event(&signer, 0x22)?;
        let state = apply_one(&ledger, &inception)?;
        let event = deactivate_event(&state, &signer)?;

        let result = apply_one(&ledger, &event);

        assert!(matches!(
            result,
            Err(LedgerError::UnknownIdentity(actual)) if actual == *state.id()
        ));

        Ok(())
    }

    #[test]
    fn apply_one_accepts_ordinary_event_against_known_identity() -> Result<()> {
        let signer = signing_key(0x11);
        let (inception, id) = inception_event(&signer, 0x22)?;
        let ledger = apply_all(&LedgerState::empty(), std::slice::from_ref(&inception))?;
        let event = deactivate_event(ledger.identity(&id).context("unknown identity")?, &signer)?;

        let state = apply_one(&ledger, &event)?;

        assert!(state.is_deactivated());
        assert_eq!(state.sequence(), Sequence::from_u64(1));

        Ok(())
    }

    #[test]
    fn apply_one_propagates_apply_errors() -> Result<()> {
        let signer = signing_key(0x11);
        let wrong_signer = signing_key(0x44);
        let (inception, id) = inception_event(&signer, 0x22)?;
        let ledger = apply_all(&LedgerState::empty(), std::slice::from_ref(&inception))?;
        let event = deactivate_event(
            ledger.identity(&id).context("unknown identity")?,
            &wrong_signer,
        )?;

        let result = apply_one(&ledger, &event);

        assert!(matches!(
            result,
            Err(LedgerError::Apply(ApplyError::EventVerification(
                EventVerificationError::InvalidSignature { key_index: 0 }
            )))
        ));

        Ok(())
    }

    #[test]
    fn apply_all_applies_multiple_identities() -> Result<()> {
        let signer = signing_key(0x11);
        let (first, first_id) = inception_event(&signer, 0x22)?;
        let (second, second_id) = inception_event(&signer, 0x33)?;

        let ledger = apply_all(&LedgerState::empty(), &[first, second])?;

        assert!(ledger.identity(&first_id).is_some());
        assert!(ledger.identity(&second_id).is_some());

        Ok(())
    }

    #[test]
    fn apply_all_applies_sequential_events_for_same_identity_in_one_batch() -> Result<()> {
        let signer = signing_key(0x11);
        let (inception, id) = inception_event(&signer, 0x22)?;
        let inception_state = apply_one(&LedgerState::empty(), &inception)?;
        let deactivate = deactivate_event(&inception_state, &signer)?;

        let ledger = apply_all(&LedgerState::empty(), &[inception, deactivate])?;

        assert!(
            ledger
                .identity(&id)
                .context("unknown identity")?
                .is_deactivated()
        );

        Ok(())
    }

    #[test]
    fn apply_all_rejects_whole_batch_on_any_failure() -> Result<()> {
        let signer = signing_key(0x11);
        let (valid, valid_id) = inception_event(&signer, 0x22)?;
        let (other_inception, other_id) = inception_event(&signer, 0x99)?;
        let other_state = apply_one(&LedgerState::empty(), &other_inception)?;
        let unknown = deactivate_event(&other_state, &signer)?;

        let result = apply_all(&LedgerState::empty(), &[valid, unknown]);

        assert!(matches!(
            result,
            Err(LedgerError::UnknownIdentity(actual)) if actual == other_id
        ));
        assert_ne!(valid_id, other_id);

        Ok(())
    }

    #[test]
    fn apply_all_rejects_conflicting_same_identity_events() -> Result<()> {
        let signer = signing_key(0x11);
        let (inception, id) = inception_event(&signer, 0x22)?;
        let inception_state = apply_one(&LedgerState::empty(), &inception)?;
        let first = rotate_event(&inception_state, 0x22, 0x99)?;
        let second = rotate_event(&inception_state, 0x33, 0x44)?;

        let result = apply_all(&LedgerState::empty(), &[inception, first, second]);

        assert!(matches!(
            result,
            Err(LedgerError::Apply(ApplyError::EventVerification(
                EventVerificationError::UnexpectedSequence
            )))
        ));
        assert_ne!(id, IdentityId::from_bytes([0; 32]));

        Ok(())
    }

    #[test]
    fn select_valid_filters_invalid_candidates() -> Result<()> {
        let signer = signing_key(0x11);
        let (valid, valid_id) = inception_event(&signer, 0x22)?;
        let (other_inception, _) = inception_event(&signer, 0x99)?;
        let other_state = apply_one(&LedgerState::empty(), &other_inception)?;
        let invalid = deactivate_event(&other_state, &signer)?;

        let (accepted, ledger) =
            select_valid(&LedgerState::empty(), &[valid.clone(), invalid.clone()]);

        assert_eq!(accepted, vec![valid]);
        assert!(ledger.identity(&valid_id).is_some());

        Ok(())
    }

    #[test]
    fn select_valid_keeps_first_of_conflicting_pair() -> Result<()> {
        let signer = signing_key(0x11);
        let (inception, id) = inception_event(&signer, 0x22)?;
        let inception_state = apply_one(&LedgerState::empty(), &inception)?;
        let first = deactivate_event(&inception_state, &signer)?;
        let second = rotate_event(&inception_state, 0x33, 0x44)?;

        let (accepted, ledger) = select_valid(
            &LedgerState::empty(),
            &[inception.clone(), first.clone(), second],
        );

        assert_eq!(accepted, vec![inception, first]);
        assert!(
            ledger
                .identity(&id)
                .context("unknown identity")?
                .is_deactivated()
        );

        Ok(())
    }
}
