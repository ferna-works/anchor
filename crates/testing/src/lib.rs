use anchor_identity::{
    IdentityAction, IdentityEvent, IdentityId, IdentityState, Inception, KeySet, KeySignature,
    PublicKey, RotateControl, Signature, SignedIdentityEvent, SignedInception, SignedOrdinaryEvent,
    apply_inception, derive_event_signature_target, derive_identity_id,
    derive_inception_signature_target, derive_next_key_commitment,
};
use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey};

pub fn key(byte: u8) -> PublicKey {
    PublicKey::from_ed25519_bytes([byte; 32])
}

pub fn dummy_keyset(threshold: u16, bytes: &[u8]) -> Result<KeySet> {
    Ok(KeySet::new(
        threshold,
        bytes.iter().copied().map(key).collect(),
    )?)
}

pub fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn control_key(signer: &SigningKey) -> PublicKey {
    PublicKey::from_ed25519_bytes(signer.verifying_key().to_bytes())
}

pub fn real_keyset(threshold: u16, seeds: &[u8]) -> Result<KeySet> {
    let keys = seeds
        .iter()
        .copied()
        .map(|seed| control_key(&signing_key(seed)))
        .collect();

    Ok(KeySet::new(threshold, keys)?)
}

pub fn sign(index: u16, key: &SigningKey, message: &[u8]) -> KeySignature {
    let signature = key.sign(message);

    KeySignature::new(index, Signature::from_ed25519_bytes(signature.to_bytes()))
}

pub fn signed_inception(signer: &SigningKey, commitment_seed: u8) -> Result<SignedInception> {
    let control = KeySet::new(1, vec![control_key(signer)])?;
    let commitment = derive_next_key_commitment(&real_keyset(1, &[commitment_seed])?)?;
    let configuration = Inception::new(control, commitment);
    let target = derive_inception_signature_target(&configuration)?;

    Ok(SignedInception::new(
        configuration,
        vec![sign(0, signer, target.as_bytes())],
    )?)
}

pub fn inception_event(
    signer: &SigningKey,
    commitment_seed: u8,
) -> Result<(SignedIdentityEvent, IdentityId)> {
    let inception = signed_inception(signer, commitment_seed)?;
    let id = derive_identity_id(inception.inception())?;

    Ok((SignedIdentityEvent::inception(inception), id))
}

pub fn genesis_state(signer: &SigningKey, commitment_seed: u8) -> Result<IdentityState> {
    let inception = signed_inception(signer, commitment_seed)?;

    Ok(apply_inception(&SignedIdentityEvent::inception(inception))?)
}

pub fn deactivate_event(state: &IdentityState, signer: &SigningKey) -> Result<SignedIdentityEvent> {
    let event = IdentityEvent::new(
        *state.id(),
        state
            .sequence()
            .checked_next()
            .context("sequence exhausted")?,
        *state.latest_event(),
        IdentityAction::deactivate(),
    );
    let target = derive_event_signature_target(&event)?;
    let signed = SignedOrdinaryEvent::new(event, vec![sign(0, signer, target.as_bytes())])?;

    Ok(SignedIdentityEvent::ordinary(signed))
}

pub fn rotate_event(
    state: &IdentityState,
    control_seed: u8,
    commitment_seed: u8,
) -> Result<SignedIdentityEvent> {
    let control = real_keyset(1, &[control_seed])?;
    let commitment = derive_next_key_commitment(&dummy_keyset(1, &[commitment_seed])?)?;
    let rotation = RotateControl::new(control, commitment);
    let event = IdentityEvent::new(
        *state.id(),
        state
            .sequence()
            .checked_next()
            .context("sequence exhausted")?,
        *state.latest_event(),
        IdentityAction::rotate_control(rotation),
    );
    let target = derive_event_signature_target(&event)?;
    let signed = SignedOrdinaryEvent::new(
        event,
        vec![sign(0, &signing_key(control_seed), target.as_bytes())],
    )?;

    Ok(SignedIdentityEvent::ordinary(signed))
}
