use anchor_client::{ClientError, TrustedError};
use anchor_codec::{EncodeError, HexError};
use anchor_did::DidError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error("invalid hex: {0}")]
    Hex(#[from] HexError),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Trusted(#[from] TrustedError),
    #[error("could not read trusted genesis file {path}: {source}")]
    ReadGenesis {
        path: String,
        source: std::io::Error,
    },
    #[error(transparent)]
    Did(#[from] DidError),
    #[error("could not encode value: {0}")]
    Encode(#[from] EncodeError),
    #[error("public key must be exactly 32 (Ed25519) or 33 (P256) bytes, got {0}")]
    InvalidPublicKeyLength(usize),
    #[error("identity ID must be exactly 32 bytes, got {0}")]
    InvalidIdLength(usize),
    #[error("device ID must be exactly 32 bytes, got {0}")]
    InvalidDeviceIdLength(usize),
    #[error("credential hash must be exactly 32 bytes, got {0}")]
    InvalidCredentialHashLength(usize),
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("could not read key file {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("could not write key file {path}: {source}")]
    Write {
        path: String,
        source: std::io::Error,
    },
    #[error("key file {0} already exists (pass --force to overwrite)")]
    AlreadyExists(String),
    #[error("key file {path} does not contain a 32-byte hex seed: {source}")]
    InvalidHex { path: String, source: HexError },
    #[error("key file {path} must contain exactly 32 bytes, found {actual}")]
    WrongLength { path: String, actual: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_public_key_length_message_includes_actual_length() {
        let error = CliError::InvalidPublicKeyLength(10);

        assert_eq!(
            error.to_string(),
            "public key must be exactly 32 (Ed25519) or 33 (P256) bytes, got 10"
        );
    }

    #[test]
    fn read_genesis_message_includes_path_and_source() {
        let source = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let error = CliError::ReadGenesis {
            path: "genesis.json".to_string(),
            source,
        };

        assert_eq!(
            error.to_string(),
            "could not read trusted genesis file genesis.json: no such file"
        );
    }

    #[test]
    fn key_already_exists_message_mentions_force_flag() {
        let error = KeyError::AlreadyExists("seed.hex".to_string());

        assert_eq!(
            error.to_string(),
            "key file seed.hex already exists (pass --force to overwrite)"
        );
    }
}
