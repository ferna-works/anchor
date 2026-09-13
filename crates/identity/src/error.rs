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
    #[error(transparent)]
    SignedInception(#[from] SignedInceptionError),
    #[error(transparent)]
    KeySignatureList(#[from] KeySignatureListError),
    #[error("unsupported protocol version {actual}")]
    UnsupportedVersion { actual: u16 },
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

#[non_exhaustive]
#[derive(Debug, Error)]
pub enum SignedInceptionError {
    #[error(transparent)]
    KeySignatureList(#[from] KeySignatureListError),
    #[error("signature count {actual} does not meet threshold {threshold}")]
    InsufficientSignatures { threshold: u16, actual: usize },
    #[error("signature key index {index} is out of range for {key_count} keys")]
    KeyIndexOutOfRange { index: u16, key_count: usize },
}

#[non_exhaustive]
#[derive(Debug, Error)]
pub enum KeySignatureListError {
    #[error("signature count {actual} exceeds maximum {maximum}")]
    TooManySignatures { maximum: usize, actual: usize },
    #[error("duplicate signature key index {index}")]
    DuplicateKeyIndex { index: u16 },
    #[error("signature key index {actual} follows {previous}")]
    UnorderedKeyIndex { previous: u16, actual: u16 },
}
