use minicbor::{Decoder, Encoder};

use crate::{DecodeError, DecodeValue, EncodeError, EncodeValue};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FixedBytesArray<const N: usize>([u8; N]);

impl<const N: usize> FixedBytesArray<N> {
    /// Wraps a fixed-size byte array.
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying bytes by reference.
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    /// Returns the underlying bytes, consuming `self`.
    pub const fn to_bytes(self) -> [u8; N] {
        self.0
    }

    /// Wraps a byte slice, returning `None` if its length isn't exactly `N`.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        Some(Self(slice.try_into().ok()?))
    }
}

impl<const N: usize> EncodeValue for FixedBytesArray<N> {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError> {
        encoder.bytes(&self.0)?;

        Ok(())
    }
}

impl<const N: usize> DecodeValue for FixedBytesArray<N> {
    type Error = DecodeError;

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let decoded = decoder.bytes()?;
        let bytes: [u8; N] = decoded
            .try_into()
            .map_err(|_| DecodeError::UnexpectedByteLength {
                expected: N,
                actual: decoded.len(),
            })?;

        Ok(Self(bytes))
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use minicbor::Encoder;

    use crate::{DecodeError, decode, encode};

    use super::*;

    type Id = FixedBytesArray<4>;

    fn encode_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
        let mut encoder = Encoder::new(Vec::new());

        encoder.bytes(bytes)?;

        Ok(encoder.into_writer())
    }

    #[test]
    fn fixed_byte_array_round_trips() -> Result<()> {
        let value = Id::from_bytes([1, 2, 3, 4]);
        let bytes = encode(&value)?;

        assert_eq!(decode::<Id>(&bytes)?, value);

        Ok(())
    }

    #[test]
    fn fixed_byte_array_rejects_wrong_length() -> Result<()> {
        let bytes = encode_bytes(&[1, 2, 3])?;

        let result = decode::<Id>(&bytes);

        assert!(matches!(
            result,
            Err(DecodeError::UnexpectedByteLength {
                expected: 4,
                actual: 3
            })
        ));

        Ok(())
    }

    #[test]
    fn fixed_byte_array_rejects_trailing_bytes() -> Result<()> {
        let mut bytes = encode_bytes(&[1, 2, 3, 4])?;
        bytes.push(0xff);

        let result = decode::<Id>(&bytes);

        assert!(matches!(result, Err(DecodeError::TrailingBytes)));

        Ok(())
    }

    #[test]
    fn fixed_byte_array_rejects_noncanonical_length_prefix() {
        let mut bytes = vec![0x58, 0x04];
        bytes.extend_from_slice(&[1, 2, 3, 4]);

        let result = decode::<Id>(&bytes);

        assert!(matches!(result, Err(DecodeError::Noncanonical)));
    }
}
