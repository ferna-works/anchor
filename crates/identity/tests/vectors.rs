use anchor_codec::{CanonicalEncode, DecodeValue, decode, encode, hex};
use anchor_identity::{
    DeviceId, EventId, EventSignatureTarget, IdentityId, InceptionSignatureTarget, KeySet,
    KeySignature, NextKeyCommitment, PublicKey, Signature,
};
use anyhow::{Result, bail};
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
struct KeySignatureVector {
    key_index: u16,
    algorithm: String,
    signature: String,
    canonical: String,
}

#[derive(Deserialize)]
struct KeySetVector {
    threshold: u16,
    keys: Vec<KeyVector>,
    canonical: String,
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
fn canonical_vectors_match_codec() -> Result<()> {
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
        let signature = signature_from(&vector.algorithm, &vector.signature)?;
        let value = KeySignature::new(vector.key_index, signature);

        assert_round_trips(&value, &vector.canonical)?;
    }

    for vector in &vectors.key_sets {
        let keys = vector
            .keys
            .iter()
            .map(key_from)
            .collect::<Result<Vec<_>>>()?;
        let value = KeySet::new(vector.threshold, keys)?;

        assert_round_trips(&value, &vector.canonical)?;
    }

    Ok(())
}
