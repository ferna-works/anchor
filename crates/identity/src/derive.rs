use anchor_codec::{EncodeError, encode};
use blake3::derive_key;

use crate::{
    DeviceId, EventId, EventSignatureTarget, IdentityEvent, IdentityId, Inception,
    InceptionSignatureTarget, KeySet, NextKeyCommitment, PublicKey, SignedIdentityEvent,
};

pub const IDENTITY_ID_DOMAIN: &str = "works.ferna.anchor.commitment.identity-id.v0";
pub const DEVICE_ID_DOMAIN: &str = "works.ferna.anchor.commitment.device-id.v0";
pub const NEXT_KEY_COMMITMENT_DOMAIN: &str = "works.ferna.anchor.commitment.next-key-commitment.v0";
pub const INCEPTION_SIGNATURE_DOMAIN: &str = "works.ferna.anchor.commitment.inception-signature.v0";
pub const EVENT_SIGNATURE_DOMAIN: &str = "works.ferna.anchor.commitment.event-signature.v0";
pub const SIGNED_EVENT_ID_DOMAIN: &str = "works.ferna.anchor.commitment.signed-event-id.v0";

/// Derives an identity's ID from its inception configuration.
pub fn derive_identity_id(inception: &Inception) -> Result<IdentityId, EncodeError> {
    let bytes = encode(inception)?;
    let hash = derive_key(IDENTITY_ID_DOMAIN, &bytes);

    Ok(IdentityId::from_bytes(hash))
}

/// Derives a device's ID from its public key.
pub fn derive_device_id(key: &PublicKey) -> Result<DeviceId, EncodeError> {
    let bytes = encode(key)?;
    let hash = derive_key(DEVICE_ID_DOMAIN, &bytes);

    Ok(DeviceId::from_bytes(hash))
}

/// Derives the commitment an inception or rotation binds to its next control set.
pub fn derive_next_key_commitment(next_control: &KeySet) -> Result<NextKeyCommitment, EncodeError> {
    let bytes = encode(next_control)?;
    let hash = derive_key(NEXT_KEY_COMMITMENT_DOMAIN, &bytes);

    Ok(NextKeyCommitment::from_bytes(hash))
}

/// Derives the target bytes an inception's control keys must sign.
pub fn derive_inception_signature_target(
    inception: &Inception,
) -> Result<InceptionSignatureTarget, EncodeError> {
    let bytes = encode(inception)?;
    let hash = derive_key(INCEPTION_SIGNATURE_DOMAIN, &bytes);

    Ok(InceptionSignatureTarget::from_bytes(hash))
}

/// Derives the target bytes an ordinary event's control keys must sign.
pub fn derive_event_signature_target(
    event: &IdentityEvent,
) -> Result<EventSignatureTarget, EncodeError> {
    let bytes = encode(event)?;
    let hash = derive_key(EVENT_SIGNATURE_DOMAIN, &bytes);

    Ok(EventSignatureTarget::from_bytes(hash))
}

/// Derives a signed event's ID, used to reference it from later events and query responses.
pub fn derive_signed_event_id(event: &SignedIdentityEvent) -> Result<EventId, EncodeError> {
    let bytes = encode(event)?;
    let hash = derive_key(SIGNED_EVENT_ID_DOMAIN, &bytes);

    Ok(EventId::from_bytes(hash))
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::PublicKey;

    use super::*;

    fn key(byte: u8) -> PublicKey {
        PublicKey::from_ed25519_bytes([byte; 32])
    }

    fn keyset(threshold: u16, bytes: &[u8]) -> Result<KeySet> {
        let keys = bytes.iter().copied().map(key).collect();

        Ok(KeySet::new(threshold, keys)?)
    }

    #[test]
    fn next_key_commitment_binds_key_bytes() -> Result<()> {
        let first = derive_next_key_commitment(&keyset(1, &[0x11])?)?;
        let second = derive_next_key_commitment(&keyset(1, &[0x12])?)?;

        assert_ne!(first, second);

        Ok(())
    }

    #[test]
    fn next_key_commitment_binds_threshold() -> Result<()> {
        let one_of_two = derive_next_key_commitment(&keyset(1, &[0x11, 0x22])?)?;
        let two_of_two = derive_next_key_commitment(&keyset(2, &[0x11, 0x22])?)?;

        assert_ne!(one_of_two, two_of_two);

        Ok(())
    }

    #[test]
    fn next_key_commitment_binds_key_order() -> Result<()> {
        let first = derive_next_key_commitment(&keyset(1, &[0x11, 0x22])?)?;
        let reordered = derive_next_key_commitment(&keyset(1, &[0x22, 0x11])?)?;

        assert_ne!(first, reordered);

        Ok(())
    }

    #[test]
    fn identity_id_binds_next_key_commitment() -> Result<()> {
        let control = keyset(1, &[0x11])?;
        let first_commitment = derive_next_key_commitment(&keyset(1, &[0x22])?)?;
        let second_commitment = derive_next_key_commitment(&keyset(1, &[0x23])?)?;
        let first = Inception::new(control.clone(), first_commitment);
        let second = Inception::new(control, second_commitment);

        assert_ne!(derive_identity_id(&first)?, derive_identity_id(&second)?);

        Ok(())
    }

    #[test]
    fn identity_id_binds_initial_control() -> Result<()> {
        let commitment = derive_next_key_commitment(&keyset(1, &[0x22])?)?;
        let first = Inception::new(keyset(1, &[0x11])?, commitment);
        let second = Inception::new(keyset(1, &[0x12])?, commitment);

        assert_ne!(derive_identity_id(&first)?, derive_identity_id(&second)?);

        Ok(())
    }

    #[test]
    fn hash_domains_separate_identical_material() {
        let material = b"same bytes";

        let hashes = [
            derive_key(IDENTITY_ID_DOMAIN, material),
            derive_key(NEXT_KEY_COMMITMENT_DOMAIN, material),
            derive_key(INCEPTION_SIGNATURE_DOMAIN, material),
            derive_key(EVENT_SIGNATURE_DOMAIN, material),
            derive_key(SIGNED_EVENT_ID_DOMAIN, material),
            derive_key(DEVICE_ID_DOMAIN, material),
        ];

        for (index, hash) in hashes.iter().enumerate() {
            assert!(!hashes[..index].contains(hash));
        }
    }
}
