#![cfg(test)]

use anyhow::Result;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};

use crate::{
    IdentityAction, IdentityEvent, IdentityState, Inception, KeySet, KeySignature, PublicKey,
    Signature, SignedIdentityEvent, SignedInception, SignedOrdinaryEvent, apply_inception,
    derive_event_signature_target, derive_inception_signature_target, derive_next_key_commitment,
};

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
    SigningKey::from_bytes(&[byte; 32])
}

pub(crate) fn control_key(key: &ed25519_dalek::SigningKey) -> PublicKey {
    PublicKey::from_ed25519_bytes(key.verifying_key().to_bytes())
}

pub(crate) fn sign(index: u16, key: &ed25519_dalek::SigningKey, message: &[u8]) -> KeySignature {
    let signature = key.sign(message);

    KeySignature::new(index, Signature::from_ed25519_bytes(signature.to_bytes()))
}

pub(crate) fn genesis_state(byte: u8) -> Result<(ed25519_dalek::SigningKey, IdentityState)> {
    let signer = signing_key(byte);
    let control = KeySet::new(1, vec![control_key(&signer)])?;
    let commitment = derive_next_key_commitment(&keyset(1, &[byte.wrapping_add(1)])?)?;
    let inception = Inception::new(control, commitment);
    let target = derive_inception_signature_target(&inception)?;
    let signed = SignedInception::new(inception, vec![sign(0, &signer, target.as_bytes())])?;
    let event = SignedIdentityEvent::inception(signed);
    let state = apply_inception(&event)?;

    Ok((signer, state))
}

pub(crate) fn ordinary_event(
    state: &IdentityState,
    action: IdentityAction,
    signer: &ed25519_dalek::SigningKey,
) -> Result<SignedIdentityEvent> {
    let event = IdentityEvent::new(
        *state.id(),
        state.sequence().checked_next().expect("sequence exhausted"),
        *state.latest_event(),
        action,
    );
    let target = derive_event_signature_target(&event)?;
    let signed = SignedOrdinaryEvent::new(event, vec![sign(0, signer, target.as_bytes())])?;

    Ok(SignedIdentityEvent::ordinary(signed))
}

pub(crate) fn invalid_ed25519_public_key_bytes() -> Result<[u8; 32]> {
    (0_u32..)
        .find_map(|candidate| {
            let mut bytes = [0_u8; 32];
            bytes[..4].copy_from_slice(&candidate.to_be_bytes());

            VerifyingKey::from_bytes(&bytes).is_err().then_some(bytes)
        })
        .ok_or_else(|| anyhow::anyhow!("could not find invalid Ed25519 key bytes"))
}
