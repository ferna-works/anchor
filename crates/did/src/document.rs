use std::collections::BTreeMap;

use anchor_identity::{DeviceId, IdentityState, PublicKey};
use multibase::Base;
use ssi::{
    dids::{
        DIDBuf, DIDURLBuf,
        document::{DIDVerificationMethod, Document},
    },
    multicodec::{ED25519_PUB, MultiEncodedBuf, P256_PUB},
};

/// Returns the verification method ID for the control key at `index`.
pub fn control_key_id(did: impl std::fmt::Display, index: usize) -> String {
    format!("{did}#control-{index}")
}

/// Returns the verification method ID for a device's key.
pub fn device_key_id(did: impl std::fmt::Display, device_id: &DeviceId) -> String {
    format!(
        "{did}#device-{}",
        multibase::encode(Base::Base58Btc, device_id.as_bytes())
    )
}

/// Builds a DID Document from an identity's current state.
pub fn build_document(did: &DIDBuf, state: &IdentityState) -> Document {
    let mut document = Document::new(did.clone());

    for (index, key) in state.control().keys().iter().enumerate() {
        let id = fragment_url(&control_key_id(did, index));

        document
            .verification_method
            .push(verification_method(&id, did, key));

        // Control keys keep all three relationships. Pre-rotation means a leaked control key
        // can't take over rotation without the pre-committed next key,
        // so the wider scope doesn't hurt us.
        let relationships = &mut document.verification_relationships;
        relationships.authentication.push(id.clone().into());
        relationships.assertion_method.push(id.clone().into());
        relationships.capability_invocation.push(id.into());
    }

    for (device_id, device) in state.devices() {
        let id = fragment_url(&device_key_id(did, device_id));

        document
            .verification_method
            .push(verification_method(&id, did, device.key()));

        document
            .verification_relationships
            .authentication
            .push(id.into());
    }

    document
}

fn fragment_url(id: &str) -> DIDURLBuf {
    id.parse()
        .expect("a DID plus a plain-ASCII fragment is always a valid DID URL")
}

fn verification_method(
    id: &DIDURLBuf,
    controller: &DIDBuf,
    public_key: &PublicKey,
) -> DIDVerificationMethod {
    let (codec, method_type) = match public_key {
        PublicKey::Ed25519(_) => (ED25519_PUB, "Ed25519VerificationKey2020"),
        PublicKey::P256(_) => (P256_PUB, "Multikey"),
    };
    let multi_encoded = MultiEncodedBuf::encode_bytes(codec, public_key.as_bytes());
    let public_key_multibase = multibase::encode(Base::Base58Btc, multi_encoded.as_bytes());

    let mut properties = BTreeMap::new();

    properties.insert(
        "publicKeyMultibase".to_string(),
        serde_json::Value::String(public_key_multibase),
    );

    DIDVerificationMethod::new(
        id.clone(),
        method_type.to_string(),
        controller.clone(),
        properties,
    )
}

#[cfg(test)]
mod tests {
    use anchor_identity::{
        AuthorizeDevice, IdentityAction, IdentityEvent, SignedIdentityEvent, SignedOrdinaryEvent,
        apply_ordinary_event, derive_device_id, derive_event_signature_target,
    };
    use anchor_testing::{control_key, genesis_state, key, sign, signing_key};
    use anyhow::Result;
    use ssi::dids::DIDURLReference;

    use crate::to_did;

    use super::*;

    #[test]
    fn control_keys_get_full_authority_relationships() -> Result<()> {
        let signer = signing_key(0x11);
        let state = genesis_state(&signer, 0x22)?;
        let did = to_did(state.id());

        let document = build_document(&did, &state);

        assert_eq!(document.id, did);
        assert_eq!(document.verification_method.len(), 1);

        let method = &document.verification_method[0];

        assert_eq!(method.id.to_string(), format!("{did}#control-0"));
        assert_eq!(method.controller, did);

        let relationships = &document.verification_relationships;

        assert_eq!(relationships.authentication.len(), 1);
        assert_eq!(relationships.assertion_method.len(), 1);
        assert_eq!(relationships.capability_invocation.len(), 1);

        Ok(())
    }

    #[test]
    fn device_keys_are_authentication_only() -> Result<()> {
        let signer = signing_key(0x11);
        let state = genesis_state(&signer, 0x22)?;
        let device_key = key(0x55);
        let event = IdentityEvent::new(
            *state.id(),
            state
                .sequence()
                .checked_next()
                .expect("sequence not exhausted"),
            *state.latest_event(),
            IdentityAction::authorize_device(AuthorizeDevice::new(device_key)),
        );
        let target = derive_event_signature_target(&event)?;
        let signed = SignedOrdinaryEvent::new(event, vec![sign(0, &signer, target.as_bytes())])?;
        let state = apply_ordinary_event(&state, &SignedIdentityEvent::ordinary(signed))?;
        let did = to_did(state.id());

        let document = build_document(&did, &state);

        assert_eq!(document.verification_method.len(), 2);

        let device_id = derive_device_id(&device_key)?;
        let device_method_id = fragment_url(&device_key_id(&did, &device_id));

        let relationships = &document.verification_relationships;

        assert_eq!(relationships.authentication.len(), 2);
        assert!(relationships.authentication.iter().any(|entry| {
            match entry.id() {
                DIDURLReference::Absolute(url) => url.as_str() == device_method_id.as_str(),
                DIDURLReference::Relative(_) => false,
            }
        }));
        assert_eq!(relationships.assertion_method.len(), 1);
        assert_eq!(relationships.capability_invocation.len(), 1);

        Ok(())
    }

    #[test]
    fn public_key_multibase_carries_the_ed25519_multicodec_prefix() -> Result<()> {
        let signer = signing_key(0x11);
        let state = genesis_state(&signer, 0x22)?;
        let did = to_did(state.id());

        let document = build_document(&did, &state);
        let method = &document.verification_method[0];
        let encoded = method
            .properties
            .get("publicKeyMultibase")
            .and_then(|value| value.as_str())
            .expect("publicKeyMultibase present");
        let (base, bytes) = multibase::decode(encoded)?;

        assert_eq!(base, Base::Base58Btc);
        assert_eq!(bytes[..2], [0xed, 0x01]);
        assert_eq!(&bytes[2..], control_key(&signer).as_bytes());

        Ok(())
    }
}
