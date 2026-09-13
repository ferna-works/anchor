use anchor_codec::DecodeError;
use thiserror::Error;

#[non_exhaustive]
#[derive(Debug, Error)]
pub enum DecodeIdentityError {
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    KeySet(#[from] KeySetError),
    #[error(transparent)]
    PublicKey(#[from] PublicKeyError),
}

#[non_exhaustive]
#[derive(Debug, Error)]
pub enum PublicKeyError {
    #[error("key was {actual} bytes, expected {expected}")]
    UnexpectedByteLength { expected: usize, actual: usize },
}

#[non_exhaustive]
#[derive(Debug, Error)]
pub enum KeySetError {
    #[error("key set must contain at least one key")]
    Empty,
    #[error("key count {actual} exceeds maximum {maximum}")]
    TooManyKeys { actual: usize, maximum: usize },
    #[error("key set contains a duplicate public key")]
    DuplicateKey,
    #[error("key threshold must be greater than zero")]
    ZeroThreshold,
    #[error("key threshold {threshold} exceeds key count {key_count}")]
    ThresholdExceedsKeyCount { threshold: u16, key_count: usize },
}
