use anchor_codec::{
    DecodeError, DecodeValue, EncodeError, EncodeValue, read_bounded_array_length,
    require_array_length,
};
use minicbor::{Decoder, Encoder};

use crate::{DecodeIdentityError, KeySetError, PublicKeyError};

const ED25519_TAG: u16 = 0;
const P256_TAG: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signature {
    Ed25519([u8; 64]),
    P256([u8; 64]),
}

impl Signature {
    /// Wraps a raw Ed25519 signature.
    pub const fn from_ed25519_bytes(bytes: [u8; 64]) -> Self {
        Self::Ed25519(bytes)
    }

    /// Wraps a raw P-256 signature.
    pub const fn from_p256_bytes(bytes: [u8; 64]) -> Self {
        Self::P256(bytes)
    }

    /// Returns the raw signature bytes by reference.
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Ed25519(bytes) => bytes,
            Self::P256(bytes) => bytes,
        }
    }

    /// Returns the raw signature bytes, consuming `self`.
    pub fn to_bytes(self) -> Vec<u8> {
        match self {
            Self::Ed25519(bytes) => bytes.to_vec(),
            Self::P256(bytes) => bytes.to_vec(),
        }
    }
}

impl EncodeValue for Signature {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError> {
        match self {
            Self::Ed25519(bytes) => encode_tagged_bytes(encoder, ED25519_TAG, bytes),
            Self::P256(bytes) => encode_tagged_bytes(encoder, P256_TAG, bytes),
        }
    }
}

impl DecodeValue for Signature {
    type Error = DecodeIdentityError;

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self, DecodeIdentityError> {
        let (tag, bytes) = decode_tagged_bytes(decoder)?;

        match tag {
            ED25519_TAG => Ok(Self::Ed25519(fixed_bytes(bytes)?)),
            P256_TAG => Ok(Self::P256(fixed_bytes(bytes)?)),
            actual => Err(DecodeIdentityError::Decode(DecodeError::UnsupportedTag {
                actual,
            })),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeySignature {
    key_index: u16,
    signature: Signature,
}

impl KeySignature {
    /// Pairs a signature with the index of the control key that produced it.
    pub const fn new(key_index: u16, signature: Signature) -> Self {
        Self {
            key_index,
            signature,
        }
    }

    /// Returns the index of the control key that produced this signature.
    pub const fn key_index(&self) -> u16 {
        self.key_index
    }

    /// Returns the signature.
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }
}

impl EncodeValue for KeySignature {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError> {
        encoder.array(2)?;
        encoder.u16(self.key_index())?;
        self.signature().encode_value(encoder)?;

        Ok(())
    }
}

impl DecodeValue for KeySignature {
    type Error = DecodeIdentityError;

    fn decode_value(decoder: &mut minicbor::Decoder<'_>) -> Result<Self, Self::Error> {
        require_array_length(decoder, 2)?;

        let key_index = decoder.u16().map_err(DecodeError::from)?;
        let signature = Signature::decode_value(decoder)?;

        Ok(Self::new(key_index, signature))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PublicKey {
    Ed25519([u8; 32]),
    P256([u8; 33]),
}

impl PublicKey {
    /// Wraps a raw Ed25519 public key.
    pub const fn from_ed25519_bytes(bytes: [u8; 32]) -> Self {
        Self::Ed25519(bytes)
    }

    /// Wraps a raw P-256 public key.
    pub const fn from_p256_bytes(bytes: [u8; 33]) -> Self {
        Self::P256(bytes)
    }

    /// Returns the raw public key bytes by reference.
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Ed25519(bytes) => bytes,
            Self::P256(bytes) => bytes,
        }
    }

    /// Returns the raw public key bytes, consuming `self`.
    pub fn to_bytes(self) -> Vec<u8> {
        match self {
            Self::Ed25519(bytes) => bytes.to_vec(),
            Self::P256(bytes) => bytes.to_vec(),
        }
    }
}

impl EncodeValue for PublicKey {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError> {
        match self {
            Self::Ed25519(bytes) => encode_tagged_bytes(encoder, ED25519_TAG, bytes),
            Self::P256(bytes) => encode_tagged_bytes(encoder, P256_TAG, bytes),
        }
    }
}

impl DecodeValue for PublicKey {
    type Error = DecodeIdentityError;

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self, DecodeIdentityError> {
        let (tag, bytes) = decode_tagged_bytes(decoder)?;

        match tag {
            ED25519_TAG => Ok(Self::Ed25519(fixed_bytes(bytes)?)),
            P256_TAG => Ok(Self::P256(fixed_bytes(bytes)?)),
            actual => Err(DecodeIdentityError::Decode(DecodeError::UnsupportedTag {
                actual,
            })),
        }
    }
}

fn fixed_bytes<const N: usize>(bytes: &[u8]) -> Result<[u8; N], PublicKeyError> {
    <[u8; N]>::try_from(bytes).map_err(|_| PublicKeyError::UnexpectedByteLength {
        expected: N,
        actual: bytes.len(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySet {
    threshold: u16,
    keys: Vec<PublicKey>,
}

impl KeySet {
    pub const MAX_KEYS: usize = 32;

    /// Builds a key set, rejecting an empty, oversized, duplicate-containing, or invalid-threshold set.
    pub fn new(threshold: u16, keys: Vec<PublicKey>) -> Result<Self, KeySetError> {
        if keys.is_empty() {
            return Err(KeySetError::Empty);
        }

        if keys.len() > Self::MAX_KEYS {
            return Err(KeySetError::TooManyKeys {
                actual: keys.len(),
                maximum: Self::MAX_KEYS,
            });
        }

        if threshold == 0 {
            return Err(KeySetError::ZeroThreshold);
        }

        if usize::from(threshold) > keys.len() {
            return Err(KeySetError::ThresholdExceedsKeyCount {
                threshold,
                key_count: keys.len(),
            });
        }

        for (index, key) in keys.iter().enumerate() {
            if keys[..index].contains(key) {
                return Err(KeySetError::DuplicateKey);
            }
        }

        Ok(Self { threshold, keys })
    }

    /// Returns the number of signatures required to authorize an action under this set.
    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    /// Returns the set's public keys, in order.
    pub fn keys(&self) -> &[PublicKey] {
        &self.keys
    }
}

impl EncodeValue for KeySet {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError> {
        encoder.array(2)?;
        encoder.u16(self.threshold())?;
        encoder.array(self.keys().len() as u64)?;

        for key in self.keys() {
            key.encode_value(encoder)?;
        }

        Ok(())
    }
}

impl DecodeValue for KeySet {
    type Error = DecodeIdentityError;

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self, DecodeIdentityError> {
        require_array_length(decoder, 2)?;

        let threshold = decoder.u16().map_err(DecodeError::from)?;
        let key_count = read_bounded_array_length(decoder, Self::MAX_KEYS)?;
        let mut keys = Vec::with_capacity(key_count as usize);

        for _ in 0..key_count {
            keys.push(PublicKey::decode_value(decoder)?);
        }

        Ok(Self::new(threshold, keys)?)
    }
}

fn encode_tagged_bytes(
    encoder: &mut Encoder<Vec<u8>>,
    tag: u16,
    bytes: &[u8],
) -> Result<(), EncodeError> {
    encoder.array(2)?;
    encoder.u16(tag)?;
    encoder.bytes(bytes)?;

    Ok(())
}

fn decode_tagged_bytes<'b>(
    decoder: &mut Decoder<'b>,
) -> Result<(u16, &'b [u8]), DecodeIdentityError> {
    require_array_length(decoder, 2)?;

    let tag = decoder.u16().map_err(DecodeError::from)?;
    let bytes = decoder.bytes().map_err(DecodeError::from)?;

    Ok((tag, bytes))
}

#[cfg(test)]
mod tests {
    use anchor_codec::{decode, encode};
    use anyhow::Result;

    use crate::testing::key;

    use super::*;

    #[test]
    fn signature_round_trips() -> Result<()> {
        let value = Signature::from_ed25519_bytes([1; 64]);
        let bytes = encode(&value)?;

        assert_eq!(decode::<Signature>(&bytes)?, value);

        Ok(())
    }

    #[test]
    fn key_signature_round_trips() -> Result<()> {
        let signature = Signature::from_ed25519_bytes([1; 64]);
        let value = KeySignature::new(1, signature);
        let bytes = encode(&value)?;

        assert_eq!(decode::<KeySignature>(&bytes)?, value);

        Ok(())
    }

    #[test]
    fn public_key_round_trips() -> Result<()> {
        let value = PublicKey::from_ed25519_bytes([0x0; 32]);
        let bytes = encode(&value)?;

        assert_eq!(decode::<PublicKey>(&bytes)?, value);

        Ok(())
    }

    #[test]
    fn keyset_round_trips() -> Result<()> {
        let value = KeySet::new(1, vec![key(0x0)])?;
        let bytes = encode(&value)?;

        assert_eq!(decode::<KeySet>(&bytes)?, value);

        Ok(())
    }

    #[test]
    fn key_set_rejects_empty_keys() {
        let result = KeySet::new(1, vec![]);

        assert!(matches!(result, Err(KeySetError::Empty)));
    }

    #[test]
    fn key_set_rejects_too_many_keys() {
        let actual = KeySet::MAX_KEYS + 1;
        let keys = (0..actual).map(|index| key(index as u8)).collect();

        let result = KeySet::new(1, keys);

        assert!(matches!(
            result,
            Err(KeySetError::TooManyKeys {
                actual: observed,
                maximum: KeySet::MAX_KEYS,
            }) if observed == actual
        ));
    }

    #[test]
    fn key_set_accepts_one_key_with_threshold_one() {
        let result = KeySet::new(1, vec![key(1)]);

        assert!(result.is_ok());
    }

    #[test]
    fn key_set_accepts_multiple_keys_with_valid_threshold() {
        let result = KeySet::new(2, vec![key(1), key(2), key(3)]);

        assert!(result.is_ok());
    }

    #[test]
    fn key_set_rejects_zero_threshold() {
        let result = KeySet::new(0, vec![key(1)]);

        assert!(matches!(result, Err(KeySetError::ZeroThreshold)));
    }

    #[test]
    fn key_set_rejects_threshold_above_key_count() {
        let result = KeySet::new(2, vec![key(1)]);

        assert!(matches!(
            result,
            Err(KeySetError::ThresholdExceedsKeyCount {
                threshold: 2,
                key_count: 1,
            })
        ));
    }

    #[test]
    fn key_set_rejects_duplicate_keys() {
        let result = KeySet::new(1, vec![key(1), key(1)]);

        assert!(matches!(result, Err(KeySetError::DuplicateKey)));
    }

    #[test]
    fn key_set_preserves_key_order() -> Result<()> {
        let key_set = KeySet::new(1, vec![key(3), key(1), key(2)])?;

        assert_eq!(key_set.keys(), [key(3), key(1), key(2)]);

        Ok(())
    }
}
