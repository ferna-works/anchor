use crate::{
    ApplyError, DeviceState, IdentityAction, IdentityState, SignedIdentityEvent, derive_device_id,
    derive_next_key_commitment, derive_signed_event_id, verify_signed_ordinary_event,
};

/// Verifies a signed ordinary event against an identity's current state and returns
/// the resulting state.
pub fn apply_ordinary_event(
    state: &IdentityState,
    event: &SignedIdentityEvent,
) -> Result<IdentityState, ApplyError> {
    let signed = event.as_ordinary().ok_or(ApplyError::ExpectedOrdinary)?;

    verify_signed_ordinary_event(state, signed)?;

    let id = *state.id();
    let sequence = signed.event().sequence();
    let latest_event = derive_signed_event_id(event)?;

    match signed.event().action() {
        IdentityAction::RotateControl(rotation) => {
            let revealed =
                derive_next_key_commitment(rotation.control()).map_err(ApplyError::Commitment)?;

            if &revealed != state.commitment() {
                return Err(ApplyError::CommitmentMismatch);
            }

            Ok(IdentityState::from_parts(
                id,
                sequence,
                latest_event,
                rotation.control().clone(),
                *rotation.commitment(),
                Vec::new(),
                state.is_deactivated(),
            )?)
        }
        IdentityAction::AuthorizeDevice(authorization) => {
            let key = *authorization.key();
            let device_id = derive_device_id(&key).map_err(ApplyError::DeviceId)?;

            if state.devices().contains_key(&device_id) {
                return Err(ApplyError::DeviceAlreadyAuthorized);
            }

            let mut devices = state.devices().clone();
            devices.insert(device_id, DeviceState::new(key));

            Ok(IdentityState::from_parts(
                id,
                sequence,
                latest_event,
                state.control().clone(),
                *state.commitment(),
                devices.into_iter().collect(),
                state.is_deactivated(),
            )?)
        }
        IdentityAction::RevokeDevice(revocation) => {
            let mut devices = state.devices().clone();

            if devices.remove(revocation.device()).is_none() {
                return Err(ApplyError::DeviceNotAuthorized);
            }

            Ok(IdentityState::from_parts(
                id,
                sequence,
                latest_event,
                state.control().clone(),
                *state.commitment(),
                devices.into_iter().collect(),
                state.is_deactivated(),
            )?)
        }
        IdentityAction::Deactivate => Ok(IdentityState::from_parts(
            id,
            sequence,
            latest_event,
            state.control().clone(),
            *state.commitment(),
            state.devices().clone().into_iter().collect(),
            true,
        )?),
        IdentityAction::RevokeCredential(_) | IdentityAction::CommitCredential(_) => {
            Ok(IdentityState::from_parts(
                id,
                sequence,
                latest_event,
                state.control().clone(),
                *state.commitment(),
                state.devices().clone().into_iter().collect(),
                state.is_deactivated(),
            )?)
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::{
        AuthorizeDevice, EventVerificationError, Inception, KeySet, RevokeDevice, RotateControl,
        Sequence, SignedInception, apply_inception, derive_device_id,
        derive_inception_signature_target,
        testing::{control_key, genesis_state, keyset, ordinary_event, sign, signing_key},
    };

    use super::*;

    #[test]
    fn apply_ordinary_event_rejects_inception_event() -> Result<()> {
        let (signer, state) = genesis_state(0x11)?;
        let control = KeySet::new(1, vec![control_key(&signer)])?;
        let commitment = derive_next_key_commitment(&keyset(1, &[0x22])?)?;
        let inception = Inception::new(control, commitment);
        let target = derive_inception_signature_target(&inception)?;
        let signed = SignedInception::new(inception, vec![sign(0, &signer, target.as_bytes())])?;
        let event = SignedIdentityEvent::inception(signed);

        let result = apply_ordinary_event(&state, &event);

        assert!(matches!(result, Err(ApplyError::ExpectedOrdinary)));

        Ok(())
    }

    #[test]
    fn apply_ordinary_event_authorize_device_adds_device() -> Result<()> {
        let (signer, state) = genesis_state(0x11)?;
        let device_key = control_key(&signing_key(0x22));
        let event = ordinary_event(
            &state,
            IdentityAction::authorize_device(AuthorizeDevice::new(device_key)),
            &signer,
        )?;

        let next = apply_ordinary_event(&state, &event)?;
        let device_id = derive_device_id(&device_key)?;

        assert!(next.devices().contains_key(&device_id));
        assert_eq!(next.sequence(), Sequence::from_u64(1));
        assert_eq!(next.control(), state.control());
        assert_eq!(next.commitment(), state.commitment());
        assert!(!next.is_deactivated());

        Ok(())
    }

    #[test]
    fn apply_ordinary_event_authorize_device_rejects_duplicate() -> Result<()> {
        let (signer, state) = genesis_state(0x11)?;
        let device_key = control_key(&signing_key(0x22));
        let event = ordinary_event(
            &state,
            IdentityAction::authorize_device(AuthorizeDevice::new(device_key)),
            &signer,
        )?;
        let state = apply_ordinary_event(&state, &event)?;
        let event = ordinary_event(
            &state,
            IdentityAction::authorize_device(AuthorizeDevice::new(device_key)),
            &signer,
        )?;

        let result = apply_ordinary_event(&state, &event);

        assert!(matches!(result, Err(ApplyError::DeviceAlreadyAuthorized)));

        Ok(())
    }

    #[test]
    fn apply_ordinary_event_revoke_device_removes_device() -> Result<()> {
        let (signer, state) = genesis_state(0x11)?;
        let device_key = control_key(&signing_key(0x22));
        let device_id = derive_device_id(&device_key)?;
        let authorize = ordinary_event(
            &state,
            IdentityAction::authorize_device(AuthorizeDevice::new(device_key)),
            &signer,
        )?;
        let state = apply_ordinary_event(&state, &authorize)?;
        let revoke = ordinary_event(
            &state,
            IdentityAction::revoke_device(RevokeDevice::new(device_id)),
            &signer,
        )?;

        let next = apply_ordinary_event(&state, &revoke)?;

        assert!(!next.devices().contains_key(&device_id));

        Ok(())
    }

    #[test]
    fn apply_ordinary_event_revoke_device_rejects_unauthorized() -> Result<()> {
        let (signer, state) = genesis_state(0x11)?;
        let device_id = derive_device_id(&control_key(&signing_key(0x22)))?;
        let event = ordinary_event(
            &state,
            IdentityAction::revoke_device(RevokeDevice::new(device_id)),
            &signer,
        )?;

        let result = apply_ordinary_event(&state, &event);

        assert!(matches!(result, Err(ApplyError::DeviceNotAuthorized)));

        Ok(())
    }

    #[test]
    fn apply_ordinary_event_deactivate_sets_flag_and_preserves_devices() -> Result<()> {
        let (signer, state) = genesis_state(0x11)?;
        let device_key = control_key(&signing_key(0x22));
        let device_id = derive_device_id(&device_key)?;
        let authorize = ordinary_event(
            &state,
            IdentityAction::authorize_device(AuthorizeDevice::new(device_key)),
            &signer,
        )?;
        let state = apply_ordinary_event(&state, &authorize)?;
        let deactivate = ordinary_event(&state, IdentityAction::deactivate(), &signer)?;

        let next = apply_ordinary_event(&state, &deactivate)?;

        assert!(next.is_deactivated());
        assert!(next.devices().contains_key(&device_id));

        Ok(())
    }

    #[test]
    fn apply_ordinary_event_rotate_control_updates_state_and_clears_devices() -> Result<()> {
        let current_signer = signing_key(0x11);
        let next_signer = signing_key(0x55);
        let control = KeySet::new(1, vec![control_key(&current_signer)])?;
        let next_control = KeySet::new(1, vec![control_key(&next_signer)])?;
        let commitment = derive_next_key_commitment(&next_control)?;
        let inception = Inception::new(control, commitment);
        let target = derive_inception_signature_target(&inception)?;
        let signed =
            SignedInception::new(inception, vec![sign(0, &current_signer, target.as_bytes())])?;
        let state = apply_inception(&SignedIdentityEvent::inception(signed))?;

        let device_key = control_key(&signing_key(0x66));
        let authorize = ordinary_event(
            &state,
            IdentityAction::authorize_device(AuthorizeDevice::new(device_key)),
            &current_signer,
        )?;
        let state = apply_ordinary_event(&state, &authorize)?;
        assert!(!state.devices().is_empty());

        let new_commitment = derive_next_key_commitment(&keyset(1, &[0x77])?)?;
        let rotation = RotateControl::new(next_control.clone(), new_commitment);
        let event = ordinary_event(
            &state,
            IdentityAction::rotate_control(rotation),
            &next_signer,
        )?;

        let next = apply_ordinary_event(&state, &event)?;

        assert_eq!(next.control(), &next_control);
        assert_eq!(*next.commitment(), new_commitment);
        assert!(next.devices().is_empty());
        assert_eq!(next.sequence(), Sequence::from_u64(2));

        Ok(())
    }

    #[test]
    fn apply_ordinary_event_rotate_control_rejects_commitment_mismatch() -> Result<()> {
        let (_signer, state) = genesis_state(0x11)?;
        let unrelated_signer = signing_key(0x77);
        let unrelated_control = KeySet::new(1, vec![control_key(&unrelated_signer)])?;
        let new_commitment = derive_next_key_commitment(&keyset(1, &[0x88])?)?;
        let rotation = RotateControl::new(unrelated_control, new_commitment);
        let event = ordinary_event(
            &state,
            IdentityAction::rotate_control(rotation),
            &unrelated_signer,
        )?;

        let result = apply_ordinary_event(&state, &event);

        assert!(matches!(result, Err(ApplyError::CommitmentMismatch)));

        Ok(())
    }

    #[test]
    fn apply_ordinary_event_propagates_verification_failures() -> Result<()> {
        let (_signer, state) = genesis_state(0x11)?;
        let wrong_signer = signing_key(0x99);
        let event = ordinary_event(&state, IdentityAction::deactivate(), &wrong_signer)?;

        let result = apply_ordinary_event(&state, &event);

        assert!(matches!(
            result,
            Err(ApplyError::EventVerification(
                EventVerificationError::InvalidSignature { key_index: 0 }
            ))
        ));

        Ok(())
    }

    #[test]
    fn apply_ordinary_event_revoke_credential_advances_sequence_only() -> Result<()> {
        let (signer, state) = genesis_state(0x11)?;
        let credential = crate::CredentialHash::from_bytes([0xaa; 32]);
        let event = ordinary_event(
            &state,
            IdentityAction::revoke_credential(crate::RevokeCredential::new(credential)),
            &signer,
        )?;

        let next = apply_ordinary_event(&state, &event)?;

        assert_eq!(next.sequence(), Sequence::from_u64(1));
        assert_eq!(next.control(), state.control());
        assert_eq!(next.commitment(), state.commitment());
        assert_eq!(next.devices(), state.devices());
        assert!(!next.is_deactivated());

        Ok(())
    }

    #[test]
    fn apply_ordinary_event_commit_credential_advances_sequence_only() -> Result<()> {
        let (signer, state) = genesis_state(0x11)?;
        let credential = crate::CredentialHash::from_bytes([0xbb; 32]);
        let event = ordinary_event(
            &state,
            IdentityAction::commit_credential(crate::CommitCredential::new(credential)),
            &signer,
        )?;

        let next = apply_ordinary_event(&state, &event)?;

        assert_eq!(next.sequence(), Sequence::from_u64(1));
        assert_eq!(next.control(), state.control());
        assert_eq!(next.commitment(), state.commitment());
        assert_eq!(next.devices(), state.devices());
        assert!(!next.is_deactivated());

        Ok(())
    }
}
