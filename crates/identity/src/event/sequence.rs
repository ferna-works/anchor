use anchor_codec::{DecodeError, DecodeValue, EncodeError, EncodeValue};
use minicbor::{Decoder, Encoder};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sequence(u64);

impl Sequence {
    pub const ZERO: Self = Self(0);

    /// Wraps a raw sequence number.
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw sequence number.
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns the next sequence number, or `None` if it would overflow.
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

impl EncodeValue for Sequence {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError> {
        encoder.u64(self.as_u64())?;

        Ok(())
    }
}

impl DecodeValue for Sequence {
    type Error = DecodeError;

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self, Self::Error> {
        Ok(Self::from_u64(decoder.u64()?))
    }
}

#[cfg(test)]
mod tests {
    use anchor_codec::{decode, encode};
    use anyhow::Result;

    use super::*;

    #[test]
    fn sequence_rejects_trailing_bytes() -> Result<()> {
        let mut bytes = encode(&Sequence::ZERO)?;
        bytes.push(0xff);

        let result = decode::<Sequence>(&bytes);

        assert!(matches!(result, Err(DecodeError::TrailingBytes)));

        Ok(())
    }

    #[test]
    fn sequence_rejects_noncanonical_length_prefix() {
        let bytes = vec![0x1b, 0, 0, 0, 0, 0, 0, 0, 0];

        let result = decode::<Sequence>(&bytes);

        assert!(matches!(result, Err(DecodeError::Noncanonical)));
    }

    #[test]
    fn checked_next_advances_by_one() {
        assert_eq!(Sequence::ZERO.checked_next(), Some(Sequence::from_u64(1)));
    }

    #[test]
    fn checked_next_returns_none_at_max() {
        assert_eq!(Sequence::from_u64(u64::MAX).checked_next(), None);
    }
}
