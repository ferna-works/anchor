use std::{fs, path::Path};

use anchor_codec::hex;
use ed25519_dalek::SigningKey;

use crate::error::KeyError;

/// Generates a fresh signing key and writes its hex seed to `path`.
pub fn generate(path: &Path, force: bool) -> Result<SigningKey, KeyError> {
    if !force && path.exists() {
        return Err(KeyError::AlreadyExists(path.display().to_string()));
    }

    let key = SigningKey::generate(&mut rand::rng());

    fs::write(path, hex::encode(&key.to_bytes())).map_err(|source| KeyError::Write {
        path: path.display().to_string(),
        source,
    })?;

    Ok(key)
}

/// Loads a signing key from its hex seed file.
pub fn load(path: &Path) -> Result<SigningKey, KeyError> {
    let contents = fs::read_to_string(path).map_err(|source| KeyError::Read {
        path: path.display().to_string(),
        source,
    })?;

    let bytes = hex::decode(contents.trim()).map_err(|source| KeyError::InvalidHex {
        path: path.display().to_string(),
        source,
    })?;

    let actual = bytes.len();
    let seed: [u8; 32] = bytes.try_into().map_err(|_| KeyError::WrongLength {
        path: path.display().to_string(),
        actual,
    })?;

    Ok(SigningKey::from_bytes(&seed))
}
