use std::convert::Infallible;

use thiserror::Error;

#[non_exhaustive]
#[derive(Debug, Error)]
pub enum EncodeError {
    #[error(transparent)]
    Cbor(#[from] minicbor::encode::Error<Infallible>),
}

#[non_exhaustive]
#[derive(Debug, Error)]
pub enum DecodeError {
    #[error(transparent)]
    Cbor(#[from] minicbor::decode::Error),
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error("unexpected byte string length: expected {expected}, got {actual}")]
    UnexpectedByteLength { expected: usize, actual: usize },
    #[error("indefinite-length arrays are not allowed")]
    IndefiniteArray,
    #[error("indefinite-length maps are not allowed")]
    IndefiniteMap,
    #[error("unexpected array length: expected {expected}, got {actual}")]
    UnexpectedArrayLength { expected: u64, actual: u64 },
    #[error("collection length {actual} exceeds maximum {maximum}")]
    CollectionTooLarge { maximum: usize, actual: u64 },
    #[error("unsupported tag {actual}")]
    UnsupportedTag { actual: u16 },
    #[error("trailing bytes")]
    TrailingBytes,
    #[error("noncanonical encoding")]
    Noncanonical,
}

#[non_exhaustive]
#[derive(Debug, Error)]
pub enum HexError {
    #[error("hex string has odd length")]
    OddLength,
    #[error("invalid hex digit")]
    InvalidDigit,
}
