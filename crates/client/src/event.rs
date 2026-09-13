use anchor_codec::encode;
use anchor_identity::{
    AuthorizeDevice, DeviceId, EventId, EventSignatureTarget, IdentityAction, IdentityEvent,
    IdentityId, IdentityState, Inception, InceptionSignatureTarget, KeySet, KeySignature,
    PublicKey, RevokeDevice, RotateControl, Signature, SignedIdentityEvent, SignedInception,
    SignedOrdinaryEvent, derive_event_signature_target, derive_identity_id,
    derive_inception_signature_target, derive_next_key_commitment, derive_signed_event_id,
};
use ed25519_dalek::{Signer, SigningKey};

use crate::{
    ClientError, RpcClient, TrustedChain, VerificationPolicy,
    query::{QueryResult, fetch_state_unverified, query},
};

#[derive(Debug, Clone)]
pub struct InceptionRequest {
    configuration: Inception,
    target: InceptionSignatureTarget,
}

impl InceptionRequest {
    /// Returns the inception configuration to be signed and submitted.
    pub fn configuration(&self) -> &Inception {
        &self.configuration
    }

    /// Returns the bytes control keys must sign to authorize this inception.
    pub fn signing_target(&self) -> &[u8] {
        self.target.as_bytes()
    }
}

/// Builds an inception configuration ready for signing, without contacting a node.
pub fn prepare_inception(
    control_keys: &[PublicKey],
    threshold: Option<u16>,
    next_keys: &[PublicKey],
    next_threshold: Option<u16>,
) -> Result<InceptionRequest, ClientError> {
    let control = build_keyset(threshold, control_keys.to_vec())?;

    let next = build_keyset(next_threshold, next_keys.to_vec())?;
    let commitment = derive_next_key_commitment(&next)?;

    let configuration = Inception::new(control, commitment);
    let target = derive_inception_signature_target(&configuration)?;

    Ok(InceptionRequest {
        configuration,
        target,
    })
}

/// Signs, broadcasts, and confirms an inception, returning the new identity's ID and commit height.
pub async fn finish_inception(
    client: &RpcClient,
    trusted: &TrustedChain,
    policy: &VerificationPolicy,
    request: InceptionRequest,
    mut signatures: Vec<KeySignature>,
) -> Result<(IdentityId, u64), ClientError> {
    signatures.sort_by_key(KeySignature::key_index);

    let id = derive_identity_id(&request.configuration)?;
    let inception = SignedInception::new(request.configuration, signatures)?;
    let tx = encode(&SignedIdentityEvent::inception(inception))?;

    let height = broadcast(client, trusted, policy, &tx, Submission::Inception(id)).await?;

    Ok((id, height))
}

#[derive(Debug, Clone)]
pub struct EventRequest {
    event: IdentityEvent,
    target: EventSignatureTarget,
    control: KeySet,
}

impl EventRequest {
    /// Returns the event to be signed and submitted.
    pub fn event(&self) -> &IdentityEvent {
        &self.event
    }

    /// Returns the bytes control keys must sign to authorize this event.
    pub fn signing_target(&self) -> &[u8] {
        self.target.as_bytes()
    }

    /// Returns the control-set index of `key`, if it's authorized to sign this event.
    pub fn key_index(&self, key: &PublicKey) -> Option<u16> {
        self.control
            .keys()
            .iter()
            .position(|candidate| candidate == key)
            .map(|index| index as u16)
    }
}

/// Fetches an identity's current state and builds a control-rotation event ready for signing.
pub async fn prepare_rotate_control(
    client: &RpcClient,
    id: IdentityId,
    reveal_keys: &[PublicKey],
    reveal_threshold: Option<u16>,
    next_keys: &[PublicKey],
    next_threshold: Option<u16>,
) -> Result<EventRequest, ClientError> {
    let state = fetch_state_unverified(client, id)
        .await?
        .ok_or(ClientError::UnknownIdentity(id))?;

    let reveal = build_keyset(reveal_threshold, reveal_keys.to_vec())?;
    let next = build_keyset(next_threshold, next_keys.to_vec())?;
    let commitment = derive_next_key_commitment(&next)?;
    let action = IdentityAction::rotate_control(RotateControl::new(reveal, commitment));

    prepare_event(state, id, action)
}

/// Fetches an identity's current state and builds a device-authorization event ready for signing.
pub async fn prepare_authorize_device(
    client: &RpcClient,
    id: IdentityId,
    device_key: PublicKey,
) -> Result<EventRequest, ClientError> {
    let state = fetch_state_unverified(client, id)
        .await?
        .ok_or(ClientError::UnknownIdentity(id))?;
    let action = IdentityAction::authorize_device(AuthorizeDevice::new(device_key));

    prepare_event(state, id, action)
}

/// Fetches an identity's current state and builds a device-revocation event ready for signing.
pub async fn prepare_revoke_device(
    client: &RpcClient,
    id: IdentityId,
    device_id: DeviceId,
) -> Result<EventRequest, ClientError> {
    let state = fetch_state_unverified(client, id)
        .await?
        .ok_or(ClientError::UnknownIdentity(id))?;
    let action = IdentityAction::revoke_device(RevokeDevice::new(device_id));

    prepare_event(state, id, action)
}

/// Fetches an identity's current state and builds a deactivation event ready for signing.
pub async fn prepare_deactivate(
    client: &RpcClient,
    id: IdentityId,
) -> Result<EventRequest, ClientError> {
    let state = fetch_state_unverified(client, id)
        .await?
        .ok_or(ClientError::UnknownIdentity(id))?;

    prepare_event(state, id, IdentityAction::deactivate())
}

fn prepare_event(
    state: IdentityState,
    id: IdentityId,
    action: IdentityAction,
) -> Result<EventRequest, ClientError> {
    let sequence = state
        .sequence()
        .checked_next()
        .ok_or(ClientError::SequenceExhausted)?;

    let control = match &action {
        IdentityAction::RotateControl(rotation) => rotation.control().clone(),
        _ => state.control().clone(),
    };
    let event = IdentityEvent::new(id, sequence, *state.latest_event(), action);
    let target = derive_event_signature_target(&event)?;

    Ok(EventRequest {
        event,
        target,
        control,
    })
}

/// Signs, broadcasts, and confirms an ordinary event, returning its commit height.
pub async fn finish_event(
    client: &RpcClient,
    trusted: &TrustedChain,
    policy: &VerificationPolicy,
    request: EventRequest,
    mut signatures: Vec<KeySignature>,
) -> Result<u64, ClientError> {
    signatures.sort_by_key(KeySignature::key_index);

    let id = *request.event().identity();
    let signed = SignedOrdinaryEvent::new(request.event, signatures)?;
    let identity_event = SignedIdentityEvent::ordinary(signed);
    let expected_event = derive_signed_event_id(&identity_event)?;
    let tx = encode(&identity_event)?;

    broadcast(
        client,
        trusted,
        policy,
        &tx,
        Submission::Event { id, expected_event },
    )
    .await
}

/// Creates a new identity, signing with `signers` and submitting it in one call.
pub async fn inception(
    client: &RpcClient,
    trusted: &TrustedChain,
    policy: &VerificationPolicy,
    signers: &[SigningKey],
    threshold: Option<u16>,
    next_keys: &[PublicKey],
    next_threshold: Option<u16>,
) -> Result<(IdentityId, u64), ClientError> {
    let control_keys: Vec<PublicKey> = signers.iter().map(public_key_of).collect();
    let request = prepare_inception(&control_keys, threshold, next_keys, next_threshold)?;

    let signatures = signers
        .iter()
        .enumerate()
        .map(|(index, signer)| sign(index as u16, signer, request.signing_target()))
        .collect();

    finish_inception(client, trusted, policy, request, signatures).await
}

/// Rotates an identity's control keys, signing with `signers` and submitting it in one call.
#[allow(clippy::too_many_arguments)]
pub async fn rotate_control(
    client: &RpcClient,
    trusted: &TrustedChain,
    policy: &VerificationPolicy,
    id: IdentityId,
    signers: &[SigningKey],
    reveal_keys: &[PublicKey],
    reveal_threshold: Option<u16>,
    next_keys: &[PublicKey],
    next_threshold: Option<u16>,
) -> Result<u64, ClientError> {
    let request = prepare_rotate_control(
        client,
        id,
        reveal_keys,
        reveal_threshold,
        next_keys,
        next_threshold,
    )
    .await?;

    let signatures = sign_request(&request, signers)?;

    finish_event(client, trusted, policy, request, signatures).await
}

/// Authorizes a device, signing with `signers` and submitting it in one call.
pub async fn authorize_device(
    client: &RpcClient,
    trusted: &TrustedChain,
    policy: &VerificationPolicy,
    id: IdentityId,
    signers: &[SigningKey],
    device_key: PublicKey,
) -> Result<u64, ClientError> {
    let request = prepare_authorize_device(client, id, device_key).await?;
    let signatures = sign_request(&request, signers)?;

    finish_event(client, trusted, policy, request, signatures).await
}

/// Revokes a device, signing with `signers` and submitting it in one call.
pub async fn revoke_device(
    client: &RpcClient,
    trusted: &TrustedChain,
    policy: &VerificationPolicy,
    id: IdentityId,
    signers: &[SigningKey],
    device_id: DeviceId,
) -> Result<u64, ClientError> {
    let request = prepare_revoke_device(client, id, device_id).await?;
    let signatures = sign_request(&request, signers)?;

    finish_event(client, trusted, policy, request, signatures).await
}

/// Deactivates an identity, signing with `signers` and submitting it in one call.
pub async fn deactivate(
    client: &RpcClient,
    trusted: &TrustedChain,
    policy: &VerificationPolicy,
    id: IdentityId,
    signers: &[SigningKey],
) -> Result<u64, ClientError> {
    let request = prepare_deactivate(client, id).await?;
    let signatures = sign_request(&request, signers)?;

    finish_event(client, trusted, policy, request, signatures).await
}

fn sign_request(
    request: &EventRequest,
    signers: &[SigningKey],
) -> Result<Vec<KeySignature>, ClientError> {
    signers
        .iter()
        .map(|signer| {
            let public = public_key_of(signer);
            let index = request
                .key_index(&public)
                .ok_or(ClientError::KeyNotInControlSet(public))?;

            Ok(sign(index, signer, request.signing_target()))
        })
        .collect()
}

enum Submission {
    Inception(IdentityId),
    Event {
        id: IdentityId,
        expected_event: EventId,
    },
}

impl Submission {
    fn identity_id(&self) -> IdentityId {
        match self {
            Submission::Inception(id) => *id,
            Submission::Event { id, .. } => *id,
        }
    }
}

async fn broadcast(
    client: &RpcClient,
    trusted: &TrustedChain,
    policy: &VerificationPolicy,
    tx: &[u8],
    submission: Submission,
) -> Result<u64, ClientError> {
    let response = client.broadcast_tx_commit(tx).await?;

    if response.check_tx.code != 0 {
        return recover_or_reject(
            client,
            trusted,
            policy,
            submission,
            "check_tx",
            response.check_tx.log,
        )
        .await;
    }

    if response.tx_result.code != 0 {
        return recover_or_reject(
            client,
            trusted,
            policy,
            submission,
            "finalize_block",
            response.tx_result.log,
        )
        .await;
    }

    Ok(response.height)
}

async fn recover_or_reject(
    client: &RpcClient,
    trusted: &TrustedChain,
    policy: &VerificationPolicy,
    submission: Submission,
    stage: &'static str,
    log: String,
) -> Result<u64, ClientError> {
    let QueryResult { height, state } =
        query(client, trusted, policy, submission.identity_id()).await?;

    if already_applied(&submission, state.as_ref()) {
        return Ok(height);
    }

    Err(ClientError::TxRejected { stage, log })
}

fn already_applied(submission: &Submission, state: Option<&IdentityState>) -> bool {
    match submission {
        Submission::Inception(_) => state.is_some(),
        Submission::Event { expected_event, .. } => {
            state.is_some_and(|state| state.latest_event() == expected_event)
        }
    }
}

fn build_keyset(threshold: Option<u16>, keys: Vec<PublicKey>) -> Result<KeySet, ClientError> {
    let threshold = threshold.unwrap_or(keys.len() as u16);

    Ok(KeySet::new(threshold, keys)?)
}

fn sign(index: u16, signer: &SigningKey, message: &[u8]) -> KeySignature {
    let signature = signer.sign(message);

    KeySignature::new(index, Signature::from_ed25519_bytes(signature.to_bytes()))
}

fn public_key_of(signer: &SigningKey) -> PublicKey {
    PublicKey::from_ed25519_bytes(signer.verifying_key().to_bytes())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use anchor_commitment::Jmt;
    use anchor_identity::{apply_inception, apply_ordinary_event};
    use anchor_proof::IdentityStateProof;
    use anchor_testing::signing_key;
    use anyhow::{Context, Result};
    use base64::prelude::*;
    use jmt::{KeyHash, mock::MockTreeStore};
    use mockito::{Matcher, Server};
    use serde_json::json;

    use super::*;

    fn rejected_broadcast_response(log: &str) -> String {
        json!({
            "jsonrpc": "2.0",
            "id": -1,
            "result": {
                "check_tx": { "code": 32, "log": log },
                "tx_result": { "code": 0, "log": "" },
                "height": "0"
            }
        })
        .to_string()
    }

    fn trusted_chain() -> Result<TrustedChain> {
        Ok(TrustedChain::from_genesis_json(include_str!(
            "../../../vectors/devnet-genesis.json"
        ))?)
    }

    fn permissive_policy() -> VerificationPolicy {
        VerificationPolicy {
            max_header_age: Duration::from_secs(60 * 60 * 24 * 365 * 100),
            max_clock_drift: Duration::from_secs(60 * 60 * 24 * 365 * 100),
        }
    }

    fn signed_header_json() -> Result<serde_json::Value> {
        Ok(serde_json::from_str(include_str!(
            "../../../vectors/signed-header.json"
        ))?)
    }

    fn header_height() -> Result<u64> {
        signed_header_json()?["header"]["height"]
            .as_str()
            .context("fixture header height must be a string")?
            .parse()
            .context("fixture header height must be a valid u64")
    }

    fn commit_response() -> Result<String> {
        Ok(json!({
            "jsonrpc": "2.0",
            "id": -1,
            "result": {
                "signed_header": signed_header_json()?,
                "canonical": false
            }
        })
        .to_string())
    }

    fn nonexistent_query_response(identity_id: IdentityId, state_height: u64) -> Result<String> {
        let store = MockTreeStore::new(true);
        let tree = Jmt::<_>::new(&store);
        let (_root, batch) = tree.put_value_set(Vec::new(), 0)?;
        store.write_tree_update_batch(batch)?;

        let key_hash = KeyHash(identity_id.to_bytes());
        let (_, merkle_proof) = tree.get_with_proof(key_hash, 0)?;
        let proof_bytes = IdentityStateProof::new(merkle_proof).to_bytes()?;

        Ok(json!({
            "jsonrpc": "2.0",
            "id": -1,
            "result": {
                "response": {
                    "code": 0,
                    "log": "",
                    "value": "",
                    "proofOps": { "ops": [{ "data": BASE64_STANDARD.encode(proof_bytes) }] },
                    "height": state_height.to_string()
                }
            }
        })
        .to_string())
    }

    fn inception_request_and_id(
        signer: &SigningKey,
    ) -> Result<(InceptionRequest, KeySignature, IdentityId)> {
        let control_key = public_key_of(signer);
        let next_key = public_key_of(&signing_key(0x22));
        let request = prepare_inception(&[control_key], None, &[next_key], None)?;
        let signature = sign(0, signer, request.signing_target());
        let id = derive_identity_id(request.configuration())?;

        Ok((request, signature, id))
    }

    #[test]
    fn already_applied_recognizes_a_landed_inception() -> Result<()> {
        let signer = signing_key(0x11);
        let (request, signature, id) = inception_request_and_id(&signer)?;
        let inception = SignedInception::new(request.configuration().clone(), vec![signature])?;
        let state = apply_inception(&SignedIdentityEvent::inception(inception))?;

        assert!(already_applied(&Submission::Inception(id), Some(&state)));
        assert!(!already_applied(&Submission::Inception(id), None));

        Ok(())
    }

    #[test]
    fn already_applied_recognizes_a_landed_event() -> Result<()> {
        let signer = signing_key(0x11);
        let (request, signature, id) = inception_request_and_id(&signer)?;
        let inception = SignedInception::new(request.configuration().clone(), vec![signature])?;
        let state = apply_inception(&SignedIdentityEvent::inception(inception))?;

        let device_key = public_key_of(&signing_key(0x33));
        let action = IdentityAction::authorize_device(AuthorizeDevice::new(device_key));
        let event_request = prepare_event(state.clone(), id, action)?;
        let event_signature = sign(0, &signer, event_request.signing_target());

        let signed = SignedOrdinaryEvent::new(event_request.event.clone(), vec![event_signature])?;
        let identity_event = SignedIdentityEvent::ordinary(signed);
        let expected_event = derive_signed_event_id(&identity_event)?;
        let next_state = apply_ordinary_event(&state, &identity_event)?;

        let submission = Submission::Event { id, expected_event };

        assert!(already_applied(&submission, Some(&next_state)));
        assert!(
            !already_applied(&submission, Some(&state)),
            "the identity existing isn't enough; the expected event must be its latest"
        );
        assert!(!already_applied(&submission, None));

        Ok(())
    }

    #[tokio::test]
    async fn finish_inception_propagates_a_genuine_rejection() -> Result<()> {
        let signer = signing_key(0x11);
        let (request, signature, id) = inception_request_and_id(&signer)?;

        let mut server = Server::new_async().await;
        let broadcast = server
            .mock("GET", "/broadcast_tx_commit")
            .match_query(Matcher::Any)
            .with_body(rejected_broadcast_response("invalid signature"))
            .create_async()
            .await;
        let commit = server
            .mock("GET", "/commit")
            .match_query(Matcher::Any)
            .with_body(commit_response()?)
            .create_async()
            .await;
        let query = server
            .mock("GET", "/abci_query")
            .match_query(Matcher::Any)
            .with_body(nonexistent_query_response(id, header_height()? - 1)?)
            .create_async()
            .await;
        let client = RpcClient::new(server.url());

        let result = finish_inception(
            &client,
            &trusted_chain()?,
            &permissive_policy(),
            request,
            vec![signature],
        )
        .await;

        assert!(matches!(
            result,
            Err(ClientError::TxRejected {
                stage: "check_tx",
                ..
            })
        ));
        broadcast.assert_async().await;
        commit.assert_async().await;
        query.assert_async().await;

        Ok(())
    }

    #[tokio::test]
    async fn finish_event_propagates_a_genuine_rejection() -> Result<()> {
        let signer = signing_key(0x11);
        let (request, signature, id) = inception_request_and_id(&signer)?;
        let inception = SignedInception::new(request.configuration().clone(), vec![signature])?;
        let state = apply_inception(&SignedIdentityEvent::inception(inception))?;

        let device_key = public_key_of(&signing_key(0x33));
        let action = IdentityAction::authorize_device(AuthorizeDevice::new(device_key));
        let event_request = prepare_event(state, id, action)?;
        let event_signature = sign(0, &signer, event_request.signing_target());

        let mut server = Server::new_async().await;
        let broadcast = server
            .mock("GET", "/broadcast_tx_commit")
            .match_query(Matcher::Any)
            .with_body(rejected_broadcast_response("invalid signature"))
            .create_async()
            .await;
        let commit = server
            .mock("GET", "/commit")
            .match_query(Matcher::Any)
            .with_body(commit_response()?)
            .create_async()
            .await;
        let query = server
            .mock("GET", "/abci_query")
            .match_query(Matcher::Any)
            .with_body(nonexistent_query_response(id, header_height()? - 1)?)
            .create_async()
            .await;
        let client = RpcClient::new(server.url());

        let result = finish_event(
            &client,
            &trusted_chain()?,
            &permissive_policy(),
            event_request,
            vec![event_signature],
        )
        .await;

        assert!(matches!(
            result,
            Err(ClientError::TxRejected {
                stage: "check_tx",
                ..
            })
        ));
        broadcast.assert_async().await;
        commit.assert_async().await;
        query.assert_async().await;

        Ok(())
    }
}
