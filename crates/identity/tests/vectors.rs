use anchor_codec::{CanonicalEncode, DecodeValue, decode, encode, hex};
use anchor_identity::{
    AuthorizeDevice, CommitCredential, CredentialHash, DeviceId, EventId, EventSignatureTarget,
    IdentityAction, IdentityEvent, IdentityId, Inception, InceptionSignatureTarget, KeySet,
    KeySignature, NextKeyCommitment, PublicKey, RevokeCredential, RevokeDevice, RotateControl,
    Sequence, Signature, SignedIdentityEvent, SignedInception, SignedOrdinaryEvent,
};
use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Deserialize)]
struct CanonicalVectors {
    identity_ids: Vec<IdVector>,
    event_ids: Vec<IdVector>,
    device_ids: Vec<IdVector>,
    next_key_commitments: Vec<IdVector>,
    inception_signature_targets: Vec<IdVector>,
    event_signature_targets: Vec<IdVector>,
    public_keys: Vec<PublicKeyVector>,
    signatures: Vec<SignatureVector>,
    key_signatures: Vec<KeySignatureVector>,
    key_sets: Vec<KeySetVector>,
    inception_configurations: Vec<InceptionConfigVector>,
    identity_events: Vec<IdentityEventVector>,
    signed_inceptions: Vec<SignedInceptionVector>,
    derived_ids: DerivedIdVectors,
}

#[derive(Deserialize)]
struct IdVector {
    bytes: String,
    canonical: String,
}

#[derive(Deserialize)]
struct KeyVector {
    algorithm: String,
    key: String,
}

#[derive(Deserialize)]
struct PublicKeyVector {
    #[serde(flatten)]
    key: KeyVector,
    canonical: String,
}

#[derive(Deserialize)]
struct SignatureVector {
    algorithm: String,
    signature: String,
    canonical: String,
}

#[derive(Deserialize)]
struct KeySignatureFields {
    key_index: u16,
    algorithm: String,
    signature: String,
}

#[derive(Deserialize)]
struct KeySignatureVector {
    #[serde(flatten)]
    fields: KeySignatureFields,
    canonical: String,
}

#[derive(Deserialize)]
struct KeySetFields {
    threshold: u16,
    keys: Vec<KeyVector>,
}

#[derive(Deserialize)]
struct KeySetVector {
    #[serde(flatten)]
    fields: KeySetFields,
    canonical: String,
}

#[derive(Deserialize)]
struct InceptionConfigFields {
    control_threshold: u16,
    control_keys: Vec<KeyVector>,
    next_key_commitment: String,
}

#[derive(Deserialize)]
struct InceptionConfigVector {
    #[serde(flatten)]
    fields: InceptionConfigFields,
    canonical: String,
}

#[derive(Deserialize)]
struct ActionFields {
    kind: String,
    device_key: Option<KeyVector>,
    device_id: Option<String>,
    control_threshold: Option<u16>,
    control_keys: Option<Vec<KeyVector>>,
    next_key_commitment: Option<String>,
    credential_hash: Option<String>,
}

#[derive(Deserialize)]
struct IdentityEventFields {
    identity: String,
    sequence: u64,
    previous: String,
    action: ActionFields,
}

#[derive(Deserialize)]
struct IdentityEventVector {
    #[serde(flatten)]
    fields: IdentityEventFields,
    canonical: String,
}

#[derive(Deserialize)]
struct SignedInceptionFields {
    configuration: InceptionConfigFields,
    signatures: Vec<KeySignatureFields>,
}

#[derive(Deserialize)]
struct SignedInceptionVector {
    #[serde(flatten)]
    fields: SignedInceptionFields,
    canonical: String,
}

#[derive(Deserialize)]
struct SignedIdentityEventFields {
    kind: String,
    event: Option<IdentityEventFields>,
    configuration: Option<InceptionConfigFields>,
    signatures: Vec<KeySignatureFields>,
}

#[derive(Deserialize)]
struct DerivedIdVectors {
    identity_ids: Vec<IdentityIdVector>,
    next_key_commitments: Vec<NextKeyCommitmentVector>,
    inception_signature_targets: Vec<InceptionSignatureTargetVector>,
    event_signature_targets: Vec<EventSignatureTargetVector>,
    event_ids: Vec<EventIdVector>,
    device_ids: Vec<DeviceIdVector>,
}

#[derive(Deserialize)]
struct IdentityIdVector {
    inception_configuration: InceptionConfigFields,
    expected: String,
}

#[derive(Deserialize)]
struct NextKeyCommitmentVector {
    key_set: KeySetFields,
    expected: String,
}

#[derive(Deserialize)]
struct InceptionSignatureTargetVector {
    inception_configuration: InceptionConfigFields,
    expected: String,
}

#[derive(Deserialize)]
struct EventSignatureTargetVector {
    identity_event: IdentityEventFields,
    expected: String,
}

#[derive(Deserialize)]
struct EventIdVector {
    signed_identity_event: SignedIdentityEventFields,
    expected: String,
}

#[derive(Deserialize)]
struct DeviceIdVector {
    public_key: KeyVector,
    expected: String,
}

fn fixed_bytes<const N: usize>(value: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value)?;

    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("expected {N} bytes, got {}", bytes.len()))
}

fn key_from(vector: &KeyVector) -> Result<PublicKey> {
    match vector.algorithm.as_str() {
        "ed25519" => Ok(PublicKey::from_ed25519_bytes(fixed_bytes(&vector.key)?)),
        "p256" => Ok(PublicKey::from_p256_bytes(fixed_bytes(&vector.key)?)),
        other => bail!("unsupported key algorithm {other}"),
    }
}

fn signature_from(algorithm: &str, signature: &str) -> Result<Signature> {
    match algorithm {
        "ed25519" => Ok(Signature::from_ed25519_bytes(fixed_bytes(signature)?)),
        "p256" => Ok(Signature::from_p256_bytes(fixed_bytes(signature)?)),
        other => bail!("unsupported signature algorithm {other}"),
    }
}

fn key_set_from(fields: &KeySetFields) -> Result<KeySet> {
    let keys = fields
        .keys
        .iter()
        .map(key_from)
        .collect::<Result<Vec<_>>>()?;

    Ok(KeySet::new(fields.threshold, keys)?)
}

fn key_signature_from(fields: &KeySignatureFields) -> Result<KeySignature> {
    Ok(KeySignature::new(
        fields.key_index,
        signature_from(&fields.algorithm, &fields.signature)?,
    ))
}

fn action_from(fields: &ActionFields) -> Result<IdentityAction> {
    match fields.kind.as_str() {
        "deactivate" => Ok(IdentityAction::deactivate()),
        "authorize_device" => {
            let key = fields.device_key.as_ref().context("missing device_key")?;

            Ok(IdentityAction::authorize_device(AuthorizeDevice::new(
                key_from(key)?,
            )))
        }
        "revoke_device" => {
            let device_id = fields.device_id.as_ref().context("missing device_id")?;

            Ok(IdentityAction::revoke_device(RevokeDevice::new(
                DeviceId::from_bytes(fixed_bytes(device_id)?),
            )))
        }
        "rotate_control" => {
            let threshold = fields
                .control_threshold
                .context("missing control_threshold")?;
            let keys = fields
                .control_keys
                .as_ref()
                .context("missing control_keys")?
                .iter()
                .map(key_from)
                .collect::<Result<Vec<_>>>()?;
            let control = KeySet::new(threshold, keys)?;
            let commitment = NextKeyCommitment::from_bytes(fixed_bytes(
                fields
                    .next_key_commitment
                    .as_ref()
                    .context("missing next_key_commitment")?,
            )?);

            Ok(IdentityAction::rotate_control(RotateControl::new(
                control, commitment,
            )))
        }
        "revoke_credential" => {
            let credential_hash = fields
                .credential_hash
                .as_ref()
                .context("missing credential_hash")?;

            Ok(IdentityAction::revoke_credential(RevokeCredential::new(
                CredentialHash::from_bytes(fixed_bytes(credential_hash)?),
            )))
        }
        "commit_credential" => {
            let credential_hash = fields
                .credential_hash
                .as_ref()
                .context("missing credential_hash")?;

            Ok(IdentityAction::commit_credential(CommitCredential::new(
                CredentialHash::from_bytes(fixed_bytes(credential_hash)?),
            )))
        }
        other => bail!("unsupported action kind {other}"),
    }
}

fn inception_config_from(fields: &InceptionConfigFields) -> Result<Inception> {
    let keys = fields
        .control_keys
        .iter()
        .map(key_from)
        .collect::<Result<Vec<_>>>()?;
    let control = KeySet::new(fields.control_threshold, keys)?;
    let commitment = NextKeyCommitment::from_bytes(fixed_bytes(&fields.next_key_commitment)?);

    Ok(Inception::new(control, commitment))
}

fn identity_event_from(fields: &IdentityEventFields) -> Result<IdentityEvent> {
    Ok(IdentityEvent::new(
        IdentityId::from_bytes(fixed_bytes(&fields.identity)?),
        Sequence::from_u64(fields.sequence),
        EventId::from_bytes(fixed_bytes(&fields.previous)?),
        action_from(&fields.action)?,
    ))
}

fn signed_inception_from(fields: &SignedInceptionFields) -> Result<SignedInception> {
    let inception = inception_config_from(&fields.configuration)?;
    let signatures = fields
        .signatures
        .iter()
        .map(key_signature_from)
        .collect::<Result<Vec<_>>>()?;

    Ok(SignedInception::new(inception, signatures)?)
}

fn signed_identity_event_from(fields: &SignedIdentityEventFields) -> Result<SignedIdentityEvent> {
    let signatures = fields
        .signatures
        .iter()
        .map(key_signature_from)
        .collect::<Result<Vec<_>>>()?;

    match fields.kind.as_str() {
        "ordinary" => {
            let event = fields.event.as_ref().context("missing event")?;
            let event = identity_event_from(event)?;

            Ok(SignedIdentityEvent::ordinary(SignedOrdinaryEvent::new(
                event, signatures,
            )?))
        }
        "inception" => {
            let configuration = fields
                .configuration
                .as_ref()
                .context("missing configuration")?;
            let inception = inception_config_from(configuration)?;

            Ok(SignedIdentityEvent::inception(SignedInception::new(
                inception, signatures,
            )?))
        }
        other => bail!("unsupported signed identity event kind {other}"),
    }
}

fn assert_round_trips<T>(value: &T, expected_hex: &str) -> Result<()>
where
    T: DecodeValue + CanonicalEncode + PartialEq + std::fmt::Debug,
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let expected = hex::decode(expected_hex)?;
    let actual = encode(value)?;

    if actual != expected {
        bail!(
            "canonical bytes changed: expected {expected_hex}, got {}",
            hex::encode(&actual)
        );
    }

    if decode::<T>(&expected)? != *value {
        bail!("decoded value does not round trip");
    }

    Ok(())
}

#[test]
fn canonical_vectors_match_codec_and_derivation() -> Result<()> {
    let vectors: CanonicalVectors =
        serde_json::from_str(include_str!("../../../vectors/canonical.json"))?;

    for vector in &vectors.identity_ids {
        let value = IdentityId::from_bytes(fixed_bytes(&vector.bytes)?);

        assert_round_trips(&value, &vector.canonical)?;
    }

    for vector in &vectors.event_ids {
        let value = EventId::from_bytes(fixed_bytes(&vector.bytes)?);

        assert_round_trips(&value, &vector.canonical)?;
    }

    for vector in &vectors.device_ids {
        let value = DeviceId::from_bytes(fixed_bytes(&vector.bytes)?);

        assert_round_trips(&value, &vector.canonical)?;
    }

    for vector in &vectors.next_key_commitments {
        let value = NextKeyCommitment::from_bytes(fixed_bytes(&vector.bytes)?);

        assert_round_trips(&value, &vector.canonical)?;
    }

    for vector in &vectors.inception_signature_targets {
        let value = InceptionSignatureTarget::from_bytes(fixed_bytes(&vector.bytes)?);

        assert_round_trips(&value, &vector.canonical)?;
    }

    for vector in &vectors.event_signature_targets {
        let value = EventSignatureTarget::from_bytes(fixed_bytes(&vector.bytes)?);

        assert_round_trips(&value, &vector.canonical)?;
    }

    for vector in &vectors.public_keys {
        assert_round_trips(&key_from(&vector.key)?, &vector.canonical)?;
    }

    for vector in &vectors.signatures {
        let value = signature_from(&vector.algorithm, &vector.signature)?;

        assert_round_trips(&value, &vector.canonical)?;
    }

    for vector in &vectors.key_signatures {
        assert_round_trips(&key_signature_from(&vector.fields)?, &vector.canonical)?;
    }

    for vector in &vectors.key_sets {
        assert_round_trips(&key_set_from(&vector.fields)?, &vector.canonical)?;
    }

    for vector in &vectors.inception_configurations {
        assert_round_trips(&inception_config_from(&vector.fields)?, &vector.canonical)?;
    }

    for vector in &vectors.identity_events {
        assert_round_trips(&identity_event_from(&vector.fields)?, &vector.canonical)?;
    }

    for vector in &vectors.signed_inceptions {
        assert_round_trips(&signed_inception_from(&vector.fields)?, &vector.canonical)?;
    }

    for vector in &vectors.derived_ids.identity_ids {
        let inception = inception_config_from(&vector.inception_configuration)?;
        let identity_id = anchor_identity::derive_identity_id(&inception)?;

        assert_eq!(hex::encode(identity_id.as_bytes()), vector.expected);
    }

    for vector in &vectors.derived_ids.next_key_commitments {
        let key_set = key_set_from(&vector.key_set)?;
        let commitment = anchor_identity::derive_next_key_commitment(&key_set)?;

        assert_eq!(hex::encode(commitment.as_bytes()), vector.expected);
    }

    for vector in &vectors.derived_ids.inception_signature_targets {
        let inception = inception_config_from(&vector.inception_configuration)?;
        let target = anchor_identity::derive_inception_signature_target(&inception)?;

        assert_eq!(hex::encode(target.as_bytes()), vector.expected);
    }

    for vector in &vectors.derived_ids.event_signature_targets {
        let event = identity_event_from(&vector.identity_event)?;
        let target = anchor_identity::derive_event_signature_target(&event)?;

        assert_eq!(hex::encode(target.as_bytes()), vector.expected);
    }

    for vector in &vectors.derived_ids.event_ids {
        let event = signed_identity_event_from(&vector.signed_identity_event)?;
        let event_id = anchor_identity::derive_signed_event_id(&event)?;

        assert_eq!(hex::encode(event_id.as_bytes()), vector.expected);
    }

    for vector in &vectors.derived_ids.device_ids {
        let key = key_from(&vector.public_key)?;
        let device_id = anchor_identity::derive_device_id(&key)?;

        assert_eq!(hex::encode(device_id.as_bytes()), vector.expected);
    }

    Ok(())
}
