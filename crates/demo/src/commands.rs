use std::path::{Path, PathBuf};

use anchor_client::{HistoryResult, QueryResult, RpcClient, TrustedChain, VerificationPolicy};
use anchor_codec::hex;
use anchor_identity::{
    CredentialHash, DeviceId, IdentityAction, IdentityId, PublicKey, Sequence, SignedIdentityEvent,
    derive_signed_event_id,
};
use ed25519_dalek::SigningKey;

use crate::{error::CliError, keys, output};

/// Generates a signing key and writes its hex seed to `path`.
pub fn keygen(path: &Path, force: bool) -> Result<(), CliError> {
    let key = keys::generate(path, force)?;
    let public = key.verifying_key().to_bytes();

    output::success(&format!("wrote key to {}", path.display()));
    output::field("public key", &hex::encode(&public));

    Ok(())
}

/// Prints the hex public key for a signing key file.
pub fn pubkey(path: &Path) -> Result<(), CliError> {
    let key = keys::load(path)?;

    println!("{}", hex::encode(&key.verifying_key().to_bytes()));

    Ok(())
}

/// Creates a new identity and prints its ID and DID.
pub async fn inception(
    node: &str,
    genesis_path: &Path,
    policy: &VerificationPolicy,
    key_paths: &[PathBuf],
    threshold: Option<u16>,
    next_keys: &[String],
    next_threshold: Option<u16>,
) -> Result<(), CliError> {
    let signers = load_keys(key_paths)?;
    let next_keys = next_keys
        .iter()
        .map(|hex| parse_public_key(hex))
        .collect::<Result<Vec<_>, _>>()?;

    let client = RpcClient::new(node);
    let trusted = load_trusted_chain(genesis_path)?;
    let (id, height) = anchor_client::inception(
        &client,
        &trusted,
        policy,
        &signers,
        threshold,
        &next_keys,
        next_threshold,
    )
    .await?;

    output::success(&format!("committed at height {height}"));
    output::field("identity id", &hex::encode(&id.to_bytes()));
    output::field("did", &anchor_did::to_did(&id).to_string());

    Ok(())
}

/// Queries and prints an identity's verified current state.
pub async fn query(
    node: &str,
    genesis_path: &Path,
    policy: &VerificationPolicy,
    id_hex: &str,
) -> Result<(), CliError> {
    let id = parse_identity_id(id_hex)?;
    let client = RpcClient::new(node);
    let trusted = load_trusted_chain(genesis_path)?;

    let QueryResult { height, state } = anchor_client::query(&client, &trusted, policy, id).await?;

    output::header(&format!("identity {}", hex::encode(&id.to_bytes())));
    output::field("did", &anchor_did::to_did(&id).to_string());
    output::field("verified at height", &height.to_string());

    let Some(state) = state else {
        output::field("status", "not found (absence proof verified)");

        return Ok(());
    };

    output::field("status", "found (existence proof verified)");
    output::field("sequence", &state.sequence().as_u64().to_string());
    output::field("deactivated", &state.is_deactivated().to_string());
    output::field(
        "control threshold",
        &format!(
            "{} of {}",
            state.control().threshold(),
            state.control().keys().len()
        ),
    );

    for (index, key) in state.control().keys().iter().enumerate() {
        output::field(
            &format!("control key[{index}]"),
            &hex::encode(key.as_bytes()),
        );
    }

    for (device_id, device) in state.devices() {
        output::field(
            "device",
            &format!(
                "{} ({})",
                hex::encode(&device_id.to_bytes()),
                hex::encode(device.key().as_bytes())
            ),
        );
    }

    Ok(())
}

/// Fetches and prints an identity's verified event history.
pub async fn history(
    node: &str,
    genesis_path: &Path,
    policy: &VerificationPolicy,
    id_hex: &str,
) -> Result<(), CliError> {
    let id = parse_identity_id(id_hex)?;
    let client = RpcClient::new(node);
    let trusted = load_trusted_chain(genesis_path)?;
    let HistoryResult {
        height,
        state: _,
        events,
    } = anchor_client::history(&client, &trusted, policy, id).await?;

    output::header(&format!("identity {} history", hex::encode(&id.to_bytes())));
    output::field("verified at height", &height.to_string());
    output::field("events", &events.len().to_string());

    for event in events {
        let event_id = derive_signed_event_id(&event)?;
        let (sequence, action) = event_summary(&event);

        output::field(
            &format!("event[{}]", sequence.as_u64()),
            &format!("{} ({action})", hex::encode(event_id.as_bytes())),
        );
    }

    Ok(())
}

/// Resolves a `did:ferna` identifier and prints its DID Document.
pub async fn resolve(
    node: &str,
    genesis_path: &Path,
    policy: &VerificationPolicy,
    did: &str,
) -> Result<(), CliError> {
    let client = RpcClient::new(node);
    let trusted = load_trusted_chain(genesis_path)?;
    let resolution = anchor_did::resolve(&client, &trusted, policy, did).await?;

    output::header(&format!("resolved {did}"));

    match resolution {
        anchor_did::Resolution::Found { document, height } => {
            output::field("verified at height", &height.to_string());
            output::field("status", "found");
            println!("{}", anchor_did::to_json_pretty(&document)?);
        }
        anchor_did::Resolution::Deactivated { height } => {
            output::field("verified at height", &height.to_string());
            output::field("status", "deactivated");
        }
        anchor_did::Resolution::NotFound { height } => {
            output::field("verified at height", &height.to_string());
            output::field("status", "not found (absence proof verified)");
        }
    }

    Ok(())
}

fn event_summary(event: &SignedIdentityEvent) -> (Sequence, &'static str) {
    match event {
        SignedIdentityEvent::Inception(_) => (Sequence::ZERO, "inception"),
        SignedIdentityEvent::Ordinary(signed) => {
            let action = match signed.event().action() {
                IdentityAction::RotateControl(_) => "rotate control",
                IdentityAction::AuthorizeDevice(_) => "authorize device",
                IdentityAction::RevokeDevice(_) => "revoke device",
                IdentityAction::Deactivate => "deactivate",
                IdentityAction::CommitCredential(_) => "commit credential",
                IdentityAction::RevokeCredential(_) => "revoke credential",
            };

            (signed.event().sequence(), action)
        }
    }
}

/// Rotates an identity's control keys.
#[allow(clippy::too_many_arguments)]
pub async fn rotate_control(
    node: &str,
    genesis_path: &Path,
    policy: &VerificationPolicy,
    id_hex: &str,
    key_paths: &[PathBuf],
    reveal_keys: &[String],
    reveal_threshold: Option<u16>,
    next_keys: &[String],
    next_threshold: Option<u16>,
) -> Result<(), CliError> {
    let id = parse_identity_id(id_hex)?;
    let signers = load_keys(key_paths)?;
    let reveal_keys = reveal_keys
        .iter()
        .map(|hex| parse_public_key(hex))
        .collect::<Result<Vec<_>, _>>()?;
    let next_keys = next_keys
        .iter()
        .map(|hex| parse_public_key(hex))
        .collect::<Result<Vec<_>, _>>()?;

    let client = RpcClient::new(node);
    let trusted = load_trusted_chain(genesis_path)?;
    let height = anchor_client::rotate_control(
        &client,
        &trusted,
        policy,
        id,
        &signers,
        &reveal_keys,
        reveal_threshold,
        &next_keys,
        next_threshold,
    )
    .await?;

    output::success(&format!("committed at height {height}"));

    Ok(())
}

/// Authorizes a new device key for an identity.
pub async fn authorize_device(
    node: &str,
    genesis_path: &Path,
    policy: &VerificationPolicy,
    id_hex: &str,
    key_paths: &[PathBuf],
    device_key_hex: &str,
) -> Result<(), CliError> {
    let id = parse_identity_id(id_hex)?;
    let signers = load_keys(key_paths)?;
    let device_key = parse_public_key(device_key_hex)?;

    let client = RpcClient::new(node);
    let trusted = load_trusted_chain(genesis_path)?;
    let height =
        anchor_client::authorize_device(&client, &trusted, policy, id, &signers, device_key)
            .await?;

    output::success(&format!("committed at height {height}"));

    Ok(())
}

/// Revokes an authorized device from an identity.
pub async fn revoke_device(
    node: &str,
    genesis_path: &Path,
    policy: &VerificationPolicy,
    id_hex: &str,
    key_paths: &[PathBuf],
    device_id_hex: &str,
) -> Result<(), CliError> {
    let id = parse_identity_id(id_hex)?;
    let signers = load_keys(key_paths)?;
    let device_id = parse_device_id(device_id_hex)?;

    let client = RpcClient::new(node);
    let trusted = load_trusted_chain(genesis_path)?;
    let height =
        anchor_client::revoke_device(&client, &trusted, policy, id, &signers, device_id).await?;

    output::success(&format!("committed at height {height}"));

    Ok(())
}

/// Commits a credential hash to an identity.
pub async fn commit_credential(
    node: &str,
    genesis_path: &Path,
    policy: &VerificationPolicy,
    id_hex: &str,
    key_paths: &[PathBuf],
    credential_hex: &str,
) -> Result<(), CliError> {
    let id = parse_identity_id(id_hex)?;
    let signers = load_keys(key_paths)?;
    let credential = parse_credential_hash(credential_hex)?;

    let client = RpcClient::new(node);
    let trusted = load_trusted_chain(genesis_path)?;
    let height =
        anchor_client::commit_credential(&client, &trusted, policy, id, &signers, credential)
            .await?;

    output::success(&format!("committed at height {height}"));

    Ok(())
}

/// Revokes a previously committed credential from an identity.
pub async fn revoke_credential(
    node: &str,
    genesis_path: &Path,
    policy: &VerificationPolicy,
    id_hex: &str,
    key_paths: &[PathBuf],
    credential_hex: &str,
) -> Result<(), CliError> {
    let id = parse_identity_id(id_hex)?;
    let signers = load_keys(key_paths)?;
    let credential = parse_credential_hash(credential_hex)?;

    let client = RpcClient::new(node);
    let trusted = load_trusted_chain(genesis_path)?;
    let height =
        anchor_client::revoke_credential(&client, &trusted, policy, id, &signers, credential)
            .await?;

    output::success(&format!("committed at height {height}"));

    Ok(())
}

/// Permanently deactivates an identity.
pub async fn deactivate(
    node: &str,
    genesis_path: &Path,
    policy: &VerificationPolicy,
    id_hex: &str,
    key_paths: &[PathBuf],
) -> Result<(), CliError> {
    let id = parse_identity_id(id_hex)?;
    let signers = load_keys(key_paths)?;

    let client = RpcClient::new(node);
    let trusted = load_trusted_chain(genesis_path)?;
    let height = anchor_client::deactivate(&client, &trusted, policy, id, &signers).await?;

    output::success(&format!("committed at height {height}"));

    Ok(())
}

fn load_keys(paths: &[PathBuf]) -> Result<Vec<SigningKey>, CliError> {
    paths
        .iter()
        .map(|path| keys::load(path))
        .collect::<Result<Vec<_>, _>>()
        .map_err(CliError::from)
}

fn load_trusted_chain(path: &Path) -> Result<TrustedChain, CliError> {
    let json = std::fs::read_to_string(path).map_err(|source| CliError::ReadGenesis {
        path: path.display().to_string(),
        source,
    })?;

    Ok(TrustedChain::from_genesis_json(&json)?)
}

fn parse_public_key(input: &str) -> Result<PublicKey, CliError> {
    let bytes = hex::decode(input)?;
    let len = bytes.len();

    match len {
        32 => Ok(PublicKey::from_ed25519_bytes(
            bytes.try_into().expect("length was checked"),
        )),
        33 => Ok(PublicKey::from_p256_bytes(
            bytes.try_into().expect("length was checked"),
        )),
        _ => Err(CliError::InvalidPublicKeyLength(len)),
    }
}

fn parse_identity_id(input: &str) -> Result<IdentityId, CliError> {
    let bytes = hex::decode(input)?;
    let len = bytes.len();

    IdentityId::from_slice(&bytes).ok_or(CliError::InvalidIdLength(len))
}

fn parse_device_id(input: &str) -> Result<DeviceId, CliError> {
    let bytes = hex::decode(input)?;
    let len = bytes.len();

    DeviceId::from_slice(&bytes).ok_or(CliError::InvalidDeviceIdLength(len))
}

fn parse_credential_hash(input: &str) -> Result<CredentialHash, CliError> {
    let bytes = hex::decode(input)?;
    let len = bytes.len();

    CredentialHash::from_slice(&bytes).ok_or(CliError::InvalidCredentialHashLength(len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_public_key_accepts_32_bytes_as_ed25519() {
        let bytes = [7u8; 32];

        let key = parse_public_key(&hex::encode(&bytes)).unwrap();

        assert_eq!(key, PublicKey::from_ed25519_bytes(bytes));
    }

    #[test]
    fn parse_public_key_accepts_33_bytes_as_p256() {
        let bytes = [7u8; 33];

        let key = parse_public_key(&hex::encode(&bytes)).unwrap();

        assert_eq!(key, PublicKey::from_p256_bytes(bytes));
    }

    #[test]
    fn parse_public_key_rejects_wrong_length() {
        let error = parse_public_key(&hex::encode(&[7u8; 10])).unwrap_err();

        assert!(matches!(error, CliError::InvalidPublicKeyLength(10)));
    }

    #[test]
    fn parse_public_key_rejects_invalid_hex() {
        let error = parse_public_key("not-hex").unwrap_err();

        assert!(matches!(error, CliError::Hex(_)));
    }

    #[test]
    fn parse_identity_id_round_trips_through_hex() {
        let bytes = [9u8; 32];

        let id = parse_identity_id(&hex::encode(&bytes)).unwrap();

        assert_eq!(id, IdentityId::from_bytes(bytes));
    }

    #[test]
    fn parse_identity_id_rejects_wrong_length() {
        let error = parse_identity_id(&hex::encode(&[9u8; 31])).unwrap_err();

        assert!(matches!(error, CliError::InvalidIdLength(31)));
    }

    #[test]
    fn parse_device_id_round_trips_through_hex() {
        let bytes = [3u8; 32];

        let id = parse_device_id(&hex::encode(&bytes)).unwrap();

        assert_eq!(id, DeviceId::from_bytes(bytes));
    }

    #[test]
    fn parse_device_id_rejects_wrong_length() {
        let error = parse_device_id(&hex::encode(&[3u8; 33])).unwrap_err();

        assert!(matches!(error, CliError::InvalidDeviceIdLength(33)));
    }

    #[test]
    fn parse_credential_hash_round_trips_through_hex() {
        let bytes = [5u8; 32];

        let credential = parse_credential_hash(&hex::encode(&bytes)).unwrap();

        assert_eq!(credential, CredentialHash::from_bytes(bytes));
    }

    #[test]
    fn parse_credential_hash_rejects_wrong_length() {
        let error = parse_credential_hash(&hex::encode(&[5u8; 31])).unwrap_err();

        assert!(matches!(error, CliError::InvalidCredentialHashLength(31)));
    }
}
