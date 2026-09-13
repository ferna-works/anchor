use core::cmp::Ordering;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;

use minicbor::{Decoder, Encoder};

use crate::{DecodeError, DecodeValue, EncodeError, EncodeValue, FixedBytesArray};

pub struct TaggedBytes<Tag, const N: usize> {
    bytes: FixedBytesArray<N>,
    tag: PhantomData<Tag>,
}

impl<Tag, const N: usize> TaggedBytes<Tag, N> {
    /// Wraps a fixed-size byte array under this type's tag.
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self {
            bytes: FixedBytesArray::from_bytes(bytes),
            tag: PhantomData,
        }
    }

    /// Returns the underlying bytes by reference.
    pub const fn as_bytes(&self) -> &[u8; N] {
        self.bytes.as_bytes()
    }

    /// Returns the underlying bytes, consuming `self`.
    pub const fn to_bytes(self) -> [u8; N] {
        self.bytes.to_bytes()
    }

    /// Wraps a byte slice under this type's tag, returning `None` if its length isn't exactly `N`.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        Some(Self {
            bytes: FixedBytesArray::from_slice(slice)?,
            tag: PhantomData,
        })
    }
}

impl<Tag, const N: usize> Clone for TaggedBytes<Tag, N> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Tag, const N: usize> Copy for TaggedBytes<Tag, N> {}

impl<Tag, const N: usize> fmt::Debug for TaggedBytes<Tag, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TaggedBytes").field(&self.bytes).finish()
    }
}

impl<Tag, const N: usize> PartialEq for TaggedBytes<Tag, N> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<Tag, const N: usize> Eq for TaggedBytes<Tag, N> {}

impl<Tag, const N: usize> PartialOrd for TaggedBytes<Tag, N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<Tag, const N: usize> Ord for TaggedBytes<Tag, N> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl<Tag, const N: usize> Hash for TaggedBytes<Tag, N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl<Tag, const N: usize> EncodeValue for TaggedBytes<Tag, N> {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError> {
        self.bytes.encode_value(encoder)
    }
}

impl<Tag, const N: usize> DecodeValue for TaggedBytes<Tag, N> {
    type Error = DecodeError;

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            bytes: FixedBytesArray::decode_value(decoder)?,
            tag: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::{decode, encode};

    use super::*;

    enum IdTag {}
    type Id = TaggedBytes<IdTag, 4>;

    #[test]
    fn tagged_bytes_round_trips() -> Result<()> {
        let value = Id::from_bytes([1, 2, 3, 4]);
        let bytes = encode(&value)?;

        assert_eq!(decode::<Id>(&bytes)?, value);

        Ok(())
    }
}
