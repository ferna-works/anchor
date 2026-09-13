use minicbor::{Decoder, Encoder};

use crate::{DecodeError, DecodeValue, EncodeError, EncodeValue};

pub trait FixedByteString: Sized {
    const LENGTH: usize;

    fn from_slice(bytes: &[u8]) -> Option<Self>;
    fn as_slice(&self) -> &[u8];
}

impl<T: FixedByteString> EncodeValue for T {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError> {
        encoder.bytes(self.as_slice())?;

        Ok(())
    }
}

impl<T: FixedByteString> DecodeValue for T {
    type Error = DecodeError;

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let decoded = decoder.bytes()?;

        T::from_slice(decoded).ok_or(DecodeError::UnexpectedByteLength {
            expected: T::LENGTH,
            actual: decoded.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use minicbor::Encoder;

    use crate::{DecodeError, decode, encode};

    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Id([u8; 4]);

    impl FixedByteString for Id {
        const LENGTH: usize = 4;

        fn from_slice(bytes: &[u8]) -> Option<Self> {
            Some(Self(bytes.try_into().ok()?))
        }

        fn as_slice(&self) -> &[u8] {
            &self.0
        }
    }

    fn encode_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
        let mut encoder = Encoder::new(Vec::new());

        encoder.bytes(bytes)?;

        Ok(encoder.into_writer())
    }

    #[test]
    fn fixed_byte_string_round_trips() -> Result<()> {
        let value = Id([1, 2, 3, 4]);
        let bytes = encode(&value)?;

        assert_eq!(decode::<Id>(&bytes)?, value);

        Ok(())
    }

    #[test]
    fn fixed_byte_string_rejects_wrong_length() -> Result<()> {
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
    fn fixed_byte_string_rejects_trailing_bytes() -> Result<()> {
        let mut bytes = encode_bytes(&[1, 2, 3, 4])?;
        bytes.push(0xff);

        let result = decode::<Id>(&bytes);

        assert!(matches!(result, Err(DecodeError::TrailingBytes)));

        Ok(())
    }

    #[test]
    fn fixed_byte_string_rejects_noncanonical_length_prefix() {
        let mut bytes = vec![0x58, 0x04];
        bytes.extend_from_slice(&[1, 2, 3, 4]);

        let result = decode::<Id>(&bytes);

        assert!(matches!(result, Err(DecodeError::Noncanonical)));
    }
}
