use minicbor::Encoder;

use crate::EncodeError;

pub trait CanonicalEncode {
    /// Encodes `self` to its canonical CBOR byte representation.
    fn to_canonical_bytes(&self) -> Result<Vec<u8>, EncodeError>;
}

/// Encodes a value to its canonical CBOR byte representation.
pub fn encode<T: CanonicalEncode>(value: &T) -> Result<Vec<u8>, EncodeError> {
    value.to_canonical_bytes()
}

pub trait EncodeValue {
    /// Writes this value's CBOR encoding into `encoder`.
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError>;
}

impl<T: EncodeValue> CanonicalEncode for T {
    fn to_canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut encoder = Encoder::new(Vec::new());

        self.encode_value(&mut encoder)?;

        Ok(encoder.into_writer())
    }
}

/// Encodes a CBOR array of `items` into `encoder`.
pub fn encode_array<T: EncodeValue>(
    encoder: &mut Encoder<Vec<u8>>,
    items: &[T],
) -> Result<(), EncodeError> {
    encoder.array(items.len() as u64)?;

    for item in items {
        item.encode_value(encoder)?;
    }

    Ok(())
}

/// Encodes `items` as a standalone CBOR array.
pub fn encode_list<T: EncodeValue>(items: &[T]) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = Encoder::new(Vec::new());

    encode_array(&mut encoder, items)?;

    Ok(encoder.into_writer())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use minicbor::Decoder;

    use crate::{DecodeError, DecodeValue, FixedBytesArray, decode, decode_array, decode_list};

    use super::*;

    type Id = FixedBytesArray<2>;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Ids(Vec<Id>);

    impl EncodeValue for Ids {
        fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError> {
            encode_array(encoder, &self.0)
        }
    }

    impl DecodeValue for Ids {
        type Error = DecodeError;

        fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            Ok(Self(decode_array(decoder, 8)?))
        }
    }

    #[test]
    fn array_round_trips() -> Result<()> {
        let value = Ids(vec![
            Id::from_bytes([1, 2]),
            Id::from_bytes([3, 4]),
            Id::from_bytes([5, 6]),
        ]);
        let bytes = encode(&value)?;

        assert_eq!(decode::<Ids>(&bytes)?, value);

        Ok(())
    }

    #[test]
    fn list_round_trips() -> Result<()> {
        let value = vec![
            Id::from_bytes([1, 2]),
            Id::from_bytes([3, 4]),
            Id::from_bytes([5, 6]),
        ];
        let bytes = encode_list(&value)?;

        assert_eq!(decode_list::<Id>(&bytes, 8)?, value);

        Ok(())
    }
}
