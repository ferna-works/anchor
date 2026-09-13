use p256::ecdsa::signature::Verifier as _;

use crate::{
    IdentityId, InceptionVerificationError, KeySet, KeySignature, PublicKey, Signature,
    SignedInception, derive_identity_id, derive_inception_signature_target,
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

fn verify_key_signatures(
    control: &KeySet,
    target: &[u8],
    signatures: &[KeySignature],
) -> Result<(), InceptionVerificationError> {
    for entry in signatures {
        let key = control.keys().get(usize::from(entry.key_index())).ok_or(
            InceptionVerificationError::KeyIndexOutOfRange {
                index: entry.key_index(),
                key_count: control.keys().len(),
            },
        )?;

        match (key, entry.signature()) {
            (PublicKey::Ed25519(key_bytes), Signature::Ed25519(sig_bytes)) => {
                let verifying_key =
                    ed25519_dalek::VerifyingKey::from_bytes(key_bytes).map_err(|_| {
                        InceptionVerificationError::InvalidPublicKey {
                            key_index: entry.key_index(),
                        }
                    })?;
                let signature = ed25519_dalek::Signature::from_bytes(sig_bytes);

                verifying_key
                    .verify_strict(target, &signature)
                    .map_err(|_| InceptionVerificationError::InvalidSignature {
                        key_index: entry.key_index(),
                    })?;
            }
            (PublicKey::P256(key_bytes), Signature::P256(sig_bytes)) => {
                let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes.as_ref())
                    .map_err(|_| InceptionVerificationError::InvalidPublicKey {
                        key_index: entry.key_index(),
                    })?;
                let signature = p256::ecdsa::Signature::from_slice(sig_bytes).map_err(|_| {
                    InceptionVerificationError::InvalidSignature {
                        key_index: entry.key_index(),
                    }
                })?;

                if signature.normalize_s() != signature {
                    return Err(InceptionVerificationError::InvalidSignature {
                        key_index: entry.key_index(),
                    });
                }

                verifying_key.verify(target, &signature).map_err(|_| {
                    InceptionVerificationError::InvalidSignature {
                        key_index: entry.key_index(),
                    }
                })?;
            }
            _ => {
                return Err(InceptionVerificationError::InvalidSignature {
                    key_index: entry.key_index(),
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use ed25519_dalek::Signer as _;

    use crate::testing::keyset;
    use crate::{
        Inception, KeySignature, PublicKey, Signature as IdentitySignature, SignedInception,
        derive_identity_id, derive_inception_signature_target, derive_next_key_commitment,
    };

    use super::*;

    fn ed25519_signing_key(byte: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[byte; 32])
    }

    fn ed25519_control_key(key: &ed25519_dalek::SigningKey) -> PublicKey {
        PublicKey::from_ed25519_bytes(key.verifying_key().to_bytes())
    }

    fn ed25519_sign(
        index: u16,
        key: &ed25519_dalek::SigningKey,
        target: &crate::InceptionSignatureTarget,
    ) -> KeySignature {
        let signature = key.sign(target.as_bytes());

        KeySignature::new(
            index,
            IdentitySignature::from_ed25519_bytes(signature.to_bytes()),
        )
    }

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
        let signer = ed25519_signing_key(0x11);
        let control = KeySet::new(1, vec![ed25519_control_key(&signer)])?;
        let commitment = derive_next_key_commitment(&keyset(1, &[0x22])?)?;
        let inception = Inception::new(control, commitment);
        let target = derive_inception_signature_target(&inception)?;
        let signed = SignedInception::new(inception, vec![ed25519_sign(0, &signer, &target)])?;

        let identity = verify_signed_inception(&signed)?;

        assert_eq!(identity, derive_identity_id(signed.inception())?);

        Ok(())
    }

    #[test]
    fn verifies_two_of_three_signed_inception() -> Result<()> {
        let first = ed25519_signing_key(0x11);
        let second = ed25519_signing_key(0x22);
        let third = ed25519_signing_key(0x33);
        let control = KeySet::new(
            2,
            vec![
                ed25519_control_key(&first),
                ed25519_control_key(&second),
                ed25519_control_key(&third),
            ],
        )?;
        let commitment = derive_next_key_commitment(&keyset(1, &[0x44])?)?;
        let inception = Inception::new(control, commitment);
        let target = derive_inception_signature_target(&inception)?;
        let signed = SignedInception::new(
            inception,
            vec![
                ed25519_sign(0, &first, &target),
                ed25519_sign(2, &third, &target),
            ],
        )?;

        verify_signed_inception(&signed)?;

        Ok(())
    }

    #[test]
    fn verification_rejects_signature_for_wrong_index() -> Result<()> {
        let first = ed25519_signing_key(0x11);
        let second = ed25519_signing_key(0x22);
        let control = KeySet::new(
            1,
            vec![ed25519_control_key(&first), ed25519_control_key(&second)],
        )?;
        let commitment = derive_next_key_commitment(&keyset(1, &[0x33])?)?;
        let inception = Inception::new(control, commitment);
        let target = derive_inception_signature_target(&inception)?;
        let signed = SignedInception::new(inception, vec![ed25519_sign(1, &first, &target)])?;

        let result = verify_signed_inception(&signed);

        assert!(matches!(
            result,
            Err(InceptionVerificationError::InvalidSignature { key_index: 1 })
        ));

        Ok(())
    }

    #[test]
    fn verification_rejects_tampered_inception() -> Result<()> {
        let signer = ed25519_signing_key(0x11);
        let control = KeySet::new(1, vec![ed25519_control_key(&signer)])?;
        let original = Inception::new(
            control.clone(),
            derive_next_key_commitment(&keyset(1, &[0x22])?)?,
        );
        let original_target = derive_inception_signature_target(&original)?;
        let tampered = Inception::new(control, derive_next_key_commitment(&keyset(1, &[0x23])?)?);
        let signed =
            SignedInception::new(tampered, vec![ed25519_sign(0, &signer, &original_target)])?;

        let result = verify_signed_inception(&signed);

        assert!(matches!(
            result,
            Err(InceptionVerificationError::InvalidSignature { key_index: 0 })
        ));

        Ok(())
    }

    #[test]
    fn verification_checks_every_signature_not_just_threshold_many() -> Result<()> {
        let first = ed25519_signing_key(0x11);
        let second = ed25519_signing_key(0x22);
        let control = KeySet::new(
            1,
            vec![ed25519_control_key(&first), ed25519_control_key(&second)],
        )?;
        let commitment = derive_next_key_commitment(&keyset(1, &[0x33])?)?;
        let inception = Inception::new(control, commitment);
        let target = derive_inception_signature_target(&inception)?;
        let signed = SignedInception::new(
            inception,
            vec![
                ed25519_sign(0, &first, &target),
                ed25519_sign(1, &first, &target),
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
        let invalid_key = (0_u32..)
            .find_map(|candidate| {
                let mut bytes = [0_u8; 32];
                bytes[..4].copy_from_slice(&candidate.to_be_bytes());
                ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                    .is_err()
                    .then_some(bytes)
            })
            .ok_or_else(|| anyhow::anyhow!("could not find invalid Ed25519 key bytes"))?;
        let control = KeySet::new(1, vec![PublicKey::from_ed25519_bytes(invalid_key)])?;
        let commitment = derive_next_key_commitment(&keyset(1, &[0x22])?)?;
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
        let commitment = derive_next_key_commitment(&keyset(1, &[0x22])?)?;
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
        let ed25519_signer = ed25519_signing_key(0x11);
        let p256_signer = p256_signing_key(0x22);
        let control = KeySet::new(
            2,
            vec![
                ed25519_control_key(&ed25519_signer),
                p256_control_key(&p256_signer),
            ],
        )?;
        let commitment = derive_next_key_commitment(&keyset(1, &[0x33])?)?;
        let inception = Inception::new(control, commitment);
        let target = derive_inception_signature_target(&inception)?;
        let signed = SignedInception::new(
            inception,
            vec![
                ed25519_sign(0, &ed25519_signer, &target),
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
        let commitment = derive_next_key_commitment(&keyset(1, &[0x22])?)?;
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
        let commitment = derive_next_key_commitment(&keyset(1, &[0x22])?)?;
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
}
