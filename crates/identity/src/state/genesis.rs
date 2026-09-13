use crate::{
    ApplyError, IdentityState, Sequence, SignedIdentityEvent, derive_signed_event_id,
    verify_signed_inception,
};

/// Verifies a signed inception event and returns the identity's genesis state.
pub fn apply_inception(event: &SignedIdentityEvent) -> Result<IdentityState, ApplyError> {
    let inception = event.as_inception().ok_or(ApplyError::ExpectedInception)?;
    let id = verify_signed_inception(inception)?;
    let latest_event = derive_signed_event_id(event)?;
    let genesis = inception.inception();

    Ok(IdentityState::from_parts(
        id,
        Sequence::ZERO,
        latest_event,
        genesis.control().clone(),
        *genesis.commitment(),
        Vec::new(),
        false,
    )?)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::{
        EventId, IdentityAction, IdentityEvent, IdentityId, Inception, InceptionSignatureTarget,
        InceptionVerificationError, KeySet, SignedIdentityEvent, SignedInception,
        SignedOrdinaryEvent, derive_identity_id, derive_inception_signature_target,
        derive_next_key_commitment,
        testing::{control_key, dummy_keyset, sign, signing_key},
    };

    use super::*;

    fn signed_inception(byte: u8) -> Result<(SignedInception, KeySet)> {
        let signer = signing_key(byte);
        let control = KeySet::new(1, vec![control_key(&signer)])?;
        let commitment = derive_next_key_commitment(&dummy_keyset(1, &[byte.wrapping_add(1)])?)?;
        let inception = Inception::new(control.clone(), commitment);
        let target = derive_inception_signature_target(&inception)?;
        let signed = SignedInception::new(inception, vec![sign(0, &signer, target.as_bytes())])?;

        Ok((signed, control))
    }

    #[test]
    fn apply_inception_constructs_genesis_state() -> Result<()> {
        let (signed, control) = signed_inception(0x11)?;
        let event = SignedIdentityEvent::inception(signed.clone());

        let state = apply_inception(&event)?;

        assert_eq!(*state.id(), derive_identity_id(signed.inception())?);
        assert_eq!(state.sequence(), Sequence::ZERO);
        assert_eq!(*state.latest_event(), derive_signed_event_id(&event)?);
        assert_eq!(state.control(), &control);
        assert_eq!(*state.commitment(), *signed.inception().commitment());
        assert!(state.devices().is_empty());
        assert!(!state.is_deactivated());

        Ok(())
    }

    #[test]
    fn apply_inception_rejects_ordinary_event() -> Result<()> {
        let identity_event = IdentityEvent::new(
            IdentityId::from_bytes([1; 32]),
            Sequence::ZERO,
            EventId::from_bytes([2; 32]),
            IdentityAction::deactivate(),
        );
        let ordinary = SignedOrdinaryEvent::new(identity_event, Vec::new())?;
        let event = SignedIdentityEvent::ordinary(ordinary);

        let result = apply_inception(&event);

        assert!(matches!(result, Err(ApplyError::ExpectedInception)));

        Ok(())
    }

    #[test]
    fn apply_inception_propagates_verification_failures() -> Result<()> {
        let signer = signing_key(0x11);
        let control = KeySet::new(1, vec![control_key(&signer)])?;
        let commitment = derive_next_key_commitment(&dummy_keyset(1, &[0x22])?)?;
        let inception = Inception::new(control, commitment);
        let wrong_target = InceptionSignatureTarget::from_bytes([0; 32]);
        let signed =
            SignedInception::new(inception, vec![sign(0, &signer, wrong_target.as_bytes())])?;
        let event = SignedIdentityEvent::inception(signed);

        let result = apply_inception(&event);

        assert!(matches!(
            result,
            Err(ApplyError::InceptionVerification(
                InceptionVerificationError::InvalidSignature { key_index: 0 }
            ))
        ));

        Ok(())
    }
}
