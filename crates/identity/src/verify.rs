use p256::ecdsa::signature::Verifier as _;

use crate::{
    EventVerificationError, IdentityAction, IdentityId, IdentityState, InceptionVerificationError,
    KeySet, KeySignature, PublicKey, Signature, SignedInception, SignedOrdinaryEvent,
    derive_event_signature_target, derive_identity_id, derive_inception_signature_target,
};

/// Verifies a signed inception's control-key signatures and returns the resulting identity ID.
pub fn verify_signed_inception(
    inception: &SignedInception,
) -> Result<IdentityId, InceptionVerificationError> {
    let target = derive_inception_signature_target(inception.inception())?;
    let control = inception.inception().control();

    verify_key_signatures(control, target.as_bytes(), inception.signatures())?;

    Ok(derive_identity_id(inception.inception())?)
}

/// Verifies a signed ordinary event against an identity's current state, checking sequencing,
/// linkage, and control-key signatures.
pub fn verify_signed_ordinary_event(
    state: &IdentityState,
    signed: &SignedOrdinaryEvent,
) -> Result<(), EventVerificationError> {
    let event = signed.event();

    if state.is_deactivated() {
        return Err(EventVerificationError::Deactivated);
    }

    if event.identity() != state.id() {
        return Err(EventVerificationError::IdentityMismatch);
    }

    let expected = state
        .sequence()
        .checked_next()
        .ok_or(EventVerificationError::SequenceExhausted)?;

    if event.sequence() != expected {
        return Err(EventVerificationError::UnexpectedSequence);
    }

    if event.previous() != state.latest_event() {
        return Err(EventVerificationError::PreviousMismatch);
    }

    let control = match event.action() {
        IdentityAction::RotateControl(rotation) => rotation.control(),
        _ => state.control(),
    };

    if signed.signatures().len() < usize::from(control.threshold()) {
        return Err(EventVerificationError::InsufficientSignatures {
            threshold: control.threshold(),
            actual: signed.signatures().len(),
        });
    }

    let target = derive_event_signature_target(event)?;

    verify_key_signatures(control, target.as_bytes(), signed.signatures())?;

    Ok(())
}

fn verify_key_signatures(
    control: &KeySet,
    target: &[u8],
    signatures: &[KeySignature],
) -> Result<(), KeySignatureError> {
    for entry in signatures {
        let key = control.keys().get(usize::from(entry.key_index())).ok_or(
            KeySignatureError::KeyIndexOutOfRange {
                index: entry.key_index(),
                key_count: control.keys().len(),
            },
        )?;

        match (key, entry.signature()) {
            (PublicKey::Ed25519(key_bytes), Signature::Ed25519(sig_bytes)) => {
                let verifying_key =
                    ed25519_dalek::VerifyingKey::from_bytes(key_bytes).map_err(|_| {
                        KeySignatureError::InvalidPublicKey {
                            key_index: entry.key_index(),
                        }
                    })?;
                let signature = ed25519_dalek::Signature::from_bytes(sig_bytes);

                verifying_key
                    .verify_strict(target, &signature)
                    .map_err(|_| KeySignatureError::InvalidSignature {
                        key_index: entry.key_index(),
                    })?;
            }
            (PublicKey::P256(key_bytes), Signature::P256(sig_bytes)) => {
                let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes.as_ref())
                    .map_err(|_| KeySignatureError::InvalidPublicKey {
                        key_index: entry.key_index(),
                    })?;
                let signature = p256::ecdsa::Signature::from_slice(sig_bytes).map_err(|_| {
                    KeySignatureError::InvalidSignature {
                        key_index: entry.key_index(),
                    }
                })?;

                if signature.normalize_s() != signature {
                    return Err(KeySignatureError::InvalidSignature {
                        key_index: entry.key_index(),
                    });
                }

                verifying_key.verify(target, &signature).map_err(|_| {
                    KeySignatureError::InvalidSignature {
                        key_index: entry.key_index(),
                    }
                })?;
            }
            _ => {
                return Err(KeySignatureError::InvalidSignature {
                    key_index: entry.key_index(),
                });
            }
        }
    }

    Ok(())
}

enum KeySignatureError {
    KeyIndexOutOfRange { index: u16, key_count: usize },
    InvalidPublicKey { key_index: u16 },
    InvalidSignature { key_index: u16 },
}

impl From<KeySignatureError> for InceptionVerificationError {
    fn from(error: KeySignatureError) -> Self {
        match error {
            KeySignatureError::KeyIndexOutOfRange { index, key_count } => {
                Self::KeyIndexOutOfRange { index, key_count }
            }
            KeySignatureError::InvalidPublicKey { key_index } => {
                Self::InvalidPublicKey { key_index }
            }
            KeySignatureError::InvalidSignature { key_index } => {
                Self::InvalidSignature { key_index }
            }
        }
    }
}

impl From<KeySignatureError> for EventVerificationError {
    fn from(error: KeySignatureError) -> Self {
        match error {
            KeySignatureError::KeyIndexOutOfRange { index, key_count } => {
                Self::KeyIndexOutOfRange { index, key_count }
            }
            KeySignatureError::InvalidPublicKey { key_index } => {
                Self::InvalidPublicKey { key_index }
            }
            KeySignatureError::InvalidSignature { key_index } => {
                Self::InvalidSignature { key_index }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result};
    use ed25519_dalek::Signer as _;

    use crate::{
        AuthorizeDevice, EventId, IdentityAction, IdentityEvent, Inception, KeySignature,
        PublicKey, RotateControl, Signature as IdentitySignature, SignedInception,
        SignedOrdinaryEvent, apply_ordinary_event, derive_event_signature_target,
        derive_identity_id, derive_inception_signature_target, derive_next_key_commitment,
        testing::{
            control_key, dummy_keyset, genesis_state, invalid_ed25519_public_key_bytes,
            ordinary_event, sign, signing_key,
        },
    };

    use super::*;

    fn p256_signing_key(byte: u8) -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[byte; 32]).expect("valid P-256 scalar")
    }

    fn p256_control_key(key: &p256::ecdsa::SigningKey) -> PublicKey {
        let compressed: p256::CompressedPoint = key.verifying_key().into();

        PublicKey::from_p256_bytes(
            compressed
                .as_slice()
                .try_into()
                .expect("compressed point is 33 bytes"),
        )
    }

    fn p256_sign(index: u16, key: &p256::ecdsa::SigningKey, message: &[u8]) -> KeySignature {
        let signature: p256::ecdsa::Signature = key.sign(message);
        let signature = signature.normalize_s();

        KeySignature::new(
            index,
            IdentitySignature::from_p256_bytes(
                signature
                    .to_bytes()
                    .as_slice()
                    .try_into()
                    .expect("ECDSA signature is 64 bytes"),
            ),
        )
    }

    fn high_s_sibling(signature: p256::ecdsa::Signature) -> p256::ecdsa::Signature {
        let low = signature.normalize_s();

        if low == signature {
            let (r, s) = signature.split_scalars();
            let negated_s: p256::Scalar = -*s;

            p256::ecdsa::Signature::from_scalars(r.to_bytes(), negated_s.to_bytes())
                .expect("negated scalar is still a valid signature component")
        } else {
            signature
        }
    }

    #[test]
    fn verifies_one_of_one_signed_inception() -> Result<()> {
        let signer = signing_key(0x11);
        let control = KeySet::new(1, vec![control_key(&signer)])?;
        let commitment = derive_next_key_commitment(&dummy_keyset(1, &[0x22])?)?;
        let inception = Inception::new(control, commitment);
        let target = derive_inception_signature_target(&inception)?;
        let signed = SignedInception::new(inception, vec![sign(0, &signer, target.as_bytes())])?;

        let identity = verify_signed_inception(&signed)?;

        assert_eq!(identity, derive_identity_id(signed.inception())?);

        Ok(())
    }

    #[test]
    fn verifies_two_of_three_signed_inception() -> Result<()> {
        let first = signing_key(0x11);
        let second = signing_key(0x22);
        let third = signing_key(0x33);
        let control = KeySet::new(
            2,
            vec![
                control_key(&first),
                control_key(&second),
                control_key(&third),
            ],
        )?;
        let commitment = derive_next_key_commitment(&dummy_keyset(1, &[0x44])?)?;
        let inception = Inception::new(control, commitment);
        let target = derive_inception_signature_target(&inception)?;
        let signed = SignedInception::new(
            inception,
            vec![
                sign(0, &first, target.as_bytes()),
                sign(2, &third, target.as_bytes()),
            ],
        )?;

        verify_signed_inception(&signed)?;

        Ok(())
    }

    #[test]
    fn verification_rejects_signature_for_wrong_index() -> Result<()> {
        let first = signing_key(0x11);
        let second = signing_key(0x22);
        let control = KeySet::new(1, vec![control_key(&first), control_key(&second)])?;
        let commitment = derive_next_key_commitment(&dummy_keyset(1, &[0x33])?)?;
        let inception = Inception::new(control, commitment);
        let target = derive_inception_signature_target(&inception)?;
        let signed = SignedInception::new(inception, vec![sign(1, &first, target.as_bytes())])?;

        let result = verify_signed_inception(&signed);

        assert!(matches!(
            result,
            Err(InceptionVerificationError::InvalidSignature { key_index: 1 })
        ));

        Ok(())
    }

    #[test]
    fn verification_rejects_tampered_inception() -> Result<()> {
        let signer = signing_key(0x11);
        let control = KeySet::new(1, vec![control_key(&signer)])?;
        let original = Inception::new(
            control.clone(),
            derive_next_key_commitment(&dummy_keyset(1, &[0x22])?)?,
        );
        let original_target = derive_inception_signature_target(&original)?;
        let tampered = Inception::new(
            control,
            derive_next_key_commitment(&dummy_keyset(1, &[0x23])?)?,
        );
        let signed =
            SignedInception::new(tampered, vec![sign(0, &signer, original_target.as_bytes())])?;

        let result = verify_signed_inception(&signed);

        assert!(matches!(
            result,
            Err(InceptionVerificationError::InvalidSignature { key_index: 0 })
        ));

        Ok(())
    }

    #[test]
    fn verification_checks_every_signature_not_just_threshold_many() -> Result<()> {
        let first = signing_key(0x11);
        let second = signing_key(0x22);
        let control = KeySet::new(1, vec![control_key(&first), control_key(&second)])?;
        let commitment = derive_next_key_commitment(&dummy_keyset(1, &[0x33])?)?;
        let inception = Inception::new(control, commitment);
        let target = derive_inception_signature_target(&inception)?;
        let signed = SignedInception::new(
            inception,
            vec![
                sign(0, &first, target.as_bytes()),
                sign(1, &first, target.as_bytes()),
            ],
        )?;

        let result = verify_signed_inception(&signed);

        assert!(matches!(
            result,
            Err(InceptionVerificationError::InvalidSignature { key_index: 1 })
        ));

        Ok(())
    }

    #[test]
    fn verification_rejects_invalid_public_key_bytes() -> Result<()> {
        let invalid_key = invalid_ed25519_public_key_bytes()?;
        let control = KeySet::new(1, vec![PublicKey::from_ed25519_bytes(invalid_key)])?;
        let commitment = derive_next_key_commitment(&dummy_keyset(1, &[0x22])?)?;
        let inception = Inception::new(control, commitment);
        let signed = SignedInception::new(
            inception,
            vec![KeySignature::new(
                0,
                IdentitySignature::from_ed25519_bytes([0_u8; 64]),
            )],
        )?;

        let result = verify_signed_inception(&signed);

        assert!(matches!(
            result,
            Err(InceptionVerificationError::InvalidPublicKey { key_index: 0 })
        ));

        Ok(())
    }

    #[test]
    fn verifies_signed_inception_with_a_p256_control_key() -> Result<()> {
        let signer = p256_signing_key(0x11);
        let control = KeySet::new(1, vec![p256_control_key(&signer)])?;
        let commitment = derive_next_key_commitment(&dummy_keyset(1, &[0x22])?)?;
        let inception = Inception::new(control, commitment);
        let target = derive_inception_signature_target(&inception)?;
        let signed =
            SignedInception::new(inception, vec![p256_sign(0, &signer, target.as_bytes())])?;

        let identity = verify_signed_inception(&signed)?;

        assert_eq!(identity, derive_identity_id(signed.inception())?);

        Ok(())
    }

    #[test]
    fn verifies_signed_inception_with_mixed_ed25519_and_p256_control_keys() -> Result<()> {
        let ed25519_signer = signing_key(0x11);
        let p256_signer = p256_signing_key(0x22);
        let control = KeySet::new(
            2,
            vec![control_key(&ed25519_signer), p256_control_key(&p256_signer)],
        )?;
        let commitment = derive_next_key_commitment(&dummy_keyset(1, &[0x33])?)?;
        let inception = Inception::new(control, commitment);
        let target = derive_inception_signature_target(&inception)?;
        let signed = SignedInception::new(
            inception,
            vec![
                sign(0, &ed25519_signer, target.as_bytes()),
                p256_sign(1, &p256_signer, target.as_bytes()),
            ],
        )?;

        verify_signed_inception(&signed)?;

        Ok(())
    }

    #[test]
    fn verification_rejects_high_s_p256_signature() -> Result<()> {
        let signer = p256_signing_key(0x11);
        let control = KeySet::new(1, vec![p256_control_key(&signer)])?;
        let commitment = derive_next_key_commitment(&dummy_keyset(1, &[0x22])?)?;
        let inception = Inception::new(control, commitment);
        let target = derive_inception_signature_target(&inception)?;
        let signature: p256::ecdsa::Signature = signer.sign(target.as_bytes());
        let malleable = high_s_sibling(signature);

        assert_ne!(malleable, malleable.normalize_s(), "sibling must be high-S");

        let signed = SignedInception::new(
            inception,
            vec![KeySignature::new(
                0,
                IdentitySignature::from_p256_bytes(
                    malleable
                        .to_bytes()
                        .as_slice()
                        .try_into()
                        .expect("ECDSA signature is 64 bytes"),
                ),
            )],
        )?;

        let result = verify_signed_inception(&signed);

        assert!(matches!(
            result,
            Err(InceptionVerificationError::InvalidSignature { key_index: 0 })
        ));

        Ok(())
    }

    #[test]
    fn verification_rejects_p256_key_paired_with_ed25519_signature() -> Result<()> {
        let signer = p256_signing_key(0x11);
        let control = KeySet::new(1, vec![p256_control_key(&signer)])?;
        let commitment = derive_next_key_commitment(&dummy_keyset(1, &[0x22])?)?;
        let inception = Inception::new(control, commitment);
        let signed = SignedInception::new(
            inception,
            vec![KeySignature::new(
                0,
                IdentitySignature::from_ed25519_bytes([0_u8; 64]),
            )],
        )?;

        let result = verify_signed_inception(&signed);

        assert!(matches!(
            result,
            Err(InceptionVerificationError::InvalidSignature { key_index: 0 })
        ));

        Ok(())
    }

    #[test]
    fn verify_signed_ordinary_event_accepts_valid_event() -> Result<()> {
        let (signer, state) = genesis_state(0x11)?;
        let signed = ordinary_event(&state, IdentityAction::deactivate(), &signer)?;

        verify_signed_ordinary_event(
            &state,
            signed.as_ordinary().context("expected an ordinary event")?,
        )?;

        Ok(())
    }

    #[test]
    fn verify_signed_ordinary_event_rejects_deactivated_state() -> Result<()> {
        let (signer, state) = genesis_state(0x11)?;
        let deactivate = ordinary_event(&state, IdentityAction::deactivate(), &signer)?;
        let deactivated = apply_ordinary_event(&state, &deactivate)?;
        let next = ordinary_event(
            &deactivated,
            IdentityAction::authorize_device(AuthorizeDevice::new(control_key(&signing_key(0x22)))),
            &signer,
        )?;

        let result = verify_signed_ordinary_event(
            &deactivated,
            next.as_ordinary().context("expected an ordinary event")?,
        );

        assert!(matches!(result, Err(EventVerificationError::Deactivated)));

        Ok(())
    }

    #[test]
    fn verify_signed_ordinary_event_rejects_identity_mismatch() -> Result<()> {
        let (signer, state) = genesis_state(0x11)?;
        let (_, other_state) = genesis_state(0x33)?;
        let signed = ordinary_event(&state, IdentityAction::deactivate(), &signer)?;

        let result = verify_signed_ordinary_event(
            &other_state,
            signed.as_ordinary().context("expected an ordinary event")?,
        );

        assert!(matches!(
            result,
            Err(EventVerificationError::IdentityMismatch)
        ));

        Ok(())
    }

    #[test]
    fn verify_signed_ordinary_event_rejects_unexpected_sequence() -> Result<()> {
        let (signer, state) = genesis_state(0x11)?;
        let event = IdentityEvent::new(
            *state.id(),
            state
                .sequence()
                .checked_next()
                .context("sequence exhausted")?
                .checked_next()
                .context("sequence exhausted")?,
            *state.latest_event(),
            IdentityAction::deactivate(),
        );
        let target = derive_event_signature_target(&event)?;
        let signed = SignedOrdinaryEvent::new(event, vec![sign(0, &signer, target.as_bytes())])?;

        let result = verify_signed_ordinary_event(&state, &signed);

        assert!(matches!(
            result,
            Err(EventVerificationError::UnexpectedSequence)
        ));

        Ok(())
    }

    #[test]
    fn verify_signed_ordinary_event_rejects_previous_mismatch() -> Result<()> {
        let (signer, state) = genesis_state(0x11)?;
        let event = IdentityEvent::new(
            *state.id(),
            state
                .sequence()
                .checked_next()
                .context("sequence exhausted")?,
            EventId::from_bytes([0xff; 32]),
            IdentityAction::deactivate(),
        );
        let target = derive_event_signature_target(&event)?;
        let signed = SignedOrdinaryEvent::new(event, vec![sign(0, &signer, target.as_bytes())])?;

        let result = verify_signed_ordinary_event(&state, &signed);

        assert!(matches!(
            result,
            Err(EventVerificationError::PreviousMismatch)
        ));

        Ok(())
    }

    #[test]
    fn verify_signed_ordinary_event_rejects_insufficient_signatures() -> Result<()> {
        let (_signer, state) = genesis_state(0x11)?;
        let event = IdentityEvent::new(
            *state.id(),
            state
                .sequence()
                .checked_next()
                .context("sequence exhausted")?,
            *state.latest_event(),
            IdentityAction::deactivate(),
        );
        let signed = SignedOrdinaryEvent::new(event, Vec::new())?;

        let result = verify_signed_ordinary_event(&state, &signed);

        assert!(matches!(
            result,
            Err(EventVerificationError::InsufficientSignatures {
                threshold: 1,
                actual: 0
            })
        ));

        Ok(())
    }

    #[test]
    fn verify_signed_ordinary_event_rejects_invalid_signature() -> Result<()> {
        let (_signer, state) = genesis_state(0x11)?;
        let wrong_signer = signing_key(0x99);
        let signed = ordinary_event(&state, IdentityAction::deactivate(), &wrong_signer)?;

        let result = verify_signed_ordinary_event(
            &state,
            signed.as_ordinary().context("expected an ordinary event")?,
        );

        assert!(matches!(
            result,
            Err(EventVerificationError::InvalidSignature { key_index: 0 })
        ));

        Ok(())
    }

    #[test]
    fn verify_signed_ordinary_event_authorizes_rotate_control_with_new_keys() -> Result<()> {
        let (_signer, state) = genesis_state(0x11)?;
        let new_signer = signing_key(0x55);
        let new_control = KeySet::new(1, vec![control_key(&new_signer)])?;
        let new_commitment = derive_next_key_commitment(&dummy_keyset(1, &[0x66])?)?;
        let rotation = RotateControl::new(new_control, new_commitment);
        let signed = ordinary_event(
            &state,
            IdentityAction::rotate_control(rotation),
            &new_signer,
        )?;

        verify_signed_ordinary_event(
            &state,
            signed.as_ordinary().context("expected an ordinary event")?,
        )?;

        Ok(())
    }
}
