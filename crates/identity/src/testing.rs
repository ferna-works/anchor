#![cfg(test)]

use anyhow::Result;
use ed25519_dalek::Signer as _;

use crate::{KeySet, KeySignature, PublicKey, Signature};

pub(crate) fn key(byte: u8) -> PublicKey {
    PublicKey::from_ed25519_bytes([byte; 32])
}

pub(crate) fn keyset(threshold: u16, bytes: &[u8]) -> Result<KeySet> {
    let keys = bytes.iter().copied().map(key).collect();

    Ok(KeySet::new(threshold, keys)?)
}

pub(crate) fn signature(index: u16) -> KeySignature {
    KeySignature::new(index, Signature::from_ed25519_bytes([index as u8; 64]))
}

pub(crate) fn signing_key(byte: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[byte; 32])
}

pub(crate) fn control_key(key: &ed25519_dalek::SigningKey) -> PublicKey {
    PublicKey::from_ed25519_bytes(key.verifying_key().to_bytes())
}

pub(crate) fn sign(index: u16, key: &ed25519_dalek::SigningKey, message: &[u8]) -> KeySignature {
    let signature = key.sign(message);

    KeySignature::new(index, Signature::from_ed25519_bytes(signature.to_bytes()))
}

pub(crate) fn invalid_ed25519_public_key_bytes() -> Result<[u8; 32]> {
    (0_u32..)
        .find_map(|candidate| {
            let mut bytes = [0_u8; 32];
            bytes[..4].copy_from_slice(&candidate.to_be_bytes());

            ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                .is_err()
                .then_some(bytes)
        })
        .ok_or_else(|| anyhow::anyhow!("could not find invalid Ed25519 key bytes"))
}
