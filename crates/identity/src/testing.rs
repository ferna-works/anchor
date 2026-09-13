#![cfg(test)]

use anyhow::Result;

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
