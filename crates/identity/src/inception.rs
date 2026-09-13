use anchor_codec::{
    DecodeError, DecodeValue, EncodeError, EncodeValue, read_bounded_array_length,
    require_array_length,
};
use minicbor::Encoder;

use crate::{
    DecodeIdentityError, EVENT_VERSION, KeySet, KeySignature, KeySignatureListError,
    NextKeyCommitment, SignedInceptionError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inception {
    version: u16,
    control: KeySet,
    commitment: NextKeyCommitment,
}

impl Inception {
    /// Creates an identity's inception configuration.
    pub fn new(control: KeySet, commitment: NextKeyCommitment) -> Self {
        Self {
            version: EVENT_VERSION,
            control,
            commitment,
        }
    }

    /// Returns the encoding version this inception was created with.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Returns the identity's initial control key set.
    pub fn control(&self) -> &KeySet {
        &self.control
    }

    /// Returns the commitment the identity's first control rotation must reveal.
    pub fn commitment(&self) -> &NextKeyCommitment {
        &self.commitment
    }
}

impl EncodeValue for Inception {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError> {
        encoder.array(3)?;
        encoder.u16(self.version())?;
        self.control().encode_value(encoder)?;
        self.commitment().encode_value(encoder)?;

        Ok(())
    }
}

impl DecodeValue for Inception {
    type Error = DecodeIdentityError;

    fn decode_value(decoder: &mut minicbor::Decoder<'_>) -> Result<Self, Self::Error> {
        require_array_length(decoder, 3)?;

        let version = decoder.u16().map_err(DecodeError::from)?;

        if version != EVENT_VERSION {
            return Err(DecodeIdentityError::UnsupportedVersion { actual: version });
        }

        let control = KeySet::decode_value(decoder)?;
        let commitment = NextKeyCommitment::decode_value(decoder)?;

        Ok(Self::new(control, commitment))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedInception {
    inception: Inception,
    signatures: Vec<KeySignature>,
}

impl SignedInception {
    /// Pairs an inception with its control-key signatures, validating them against the control set.
    pub fn new(
        inception: Inception,
        signatures: Vec<KeySignature>,
    ) -> Result<Self, SignedInceptionError> {
        if signatures.len() > KeySet::MAX_KEYS {
            return Err(KeySignatureListError::TooManySignatures {
                maximum: KeySet::MAX_KEYS,
                actual: signatures.len(),
            }
            .into());
        }

        let key_count = inception.control().keys().len();
        let mut previous = None;

        for entry in &signatures {
            if usize::from(entry.key_index()) >= key_count {
                return Err(SignedInceptionError::KeyIndexOutOfRange {
                    index: entry.key_index(),
                    key_count,
                });
            }

            if let Some(previous) = previous {
                if entry.key_index() == previous {
                    return Err(KeySignatureListError::DuplicateKeyIndex {
                        index: entry.key_index(),
                    }
                    .into());
                }

                if entry.key_index() < previous {
                    return Err(KeySignatureListError::UnorderedKeyIndex {
                        previous,
                        actual: entry.key_index(),
                    }
                    .into());
                }
            }

            previous = Some(entry.key_index());
        }

        if signatures.len() < usize::from(inception.control().threshold()) {
            return Err(SignedInceptionError::InsufficientSignatures {
                threshold: inception.control().threshold(),
                actual: signatures.len(),
            });
        }

        Ok(Self {
            inception,
            signatures,
        })
    }

    /// Returns the inception configuration.
    pub const fn inception(&self) -> &Inception {
        &self.inception
    }

    /// Returns the control-key signatures over the inception.
    pub fn signatures(&self) -> &[KeySignature] {
        &self.signatures
    }
}

impl EncodeValue for SignedInception {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError> {
        encoder.array(2)?;
        self.inception().encode_value(encoder)?;
        encoder.array(self.signatures().len() as u64)?;

        for signature in self.signatures() {
            signature.encode_value(encoder)?;
        }

        Ok(())
    }
}

impl DecodeValue for SignedInception {
    type Error = DecodeIdentityError;

    fn decode_value(decoder: &mut minicbor::Decoder<'_>) -> Result<Self, Self::Error> {
        require_array_length(decoder, 2)?;

        let inception = Inception::decode_value(decoder)?;
        let signature_count = read_bounded_array_length(decoder, KeySet::MAX_KEYS)?;
        let mut signatures = Vec::with_capacity(signature_count as usize);

        for _ in 0..signature_count {
            signatures.push(KeySignature::decode_value(decoder)?);
        }

        Ok(Self::new(inception, signatures)?)
    }
}

#[cfg(test)]
mod tests {
    use anchor_codec::{decode, encode};
    use anyhow::Result;
    use minicbor::Encoder;

    use crate::{
        derive_next_key_commitment,
        testing::{dummy_keyset, signature},
    };

    use super::*;

    fn inception() -> Result<Inception> {
        let control = dummy_keyset(1, &[0x11])?;
        let commitment = derive_next_key_commitment(&dummy_keyset(1, &[0x22])?)?;

        Ok(Inception::new(control, commitment))
    }

    #[test]
    fn inception_decode_rejects_wrong_version() -> Result<()> {
        let control = dummy_keyset(1, &[0x11])?;
        let commitment = derive_next_key_commitment(&dummy_keyset(1, &[0x22])?)?;

        let mut encoder = Encoder::new(Vec::new());
        encoder.array(3)?;
        encoder.u16(EVENT_VERSION + 1)?;
        control.encode_value(&mut encoder)?;
        commitment.encode_value(&mut encoder)?;

        let bytes = encoder.into_writer();
        let result = decode::<Inception>(&bytes);

        assert!(matches!(
            result,
            Err(DecodeIdentityError::UnsupportedVersion { actual }) if actual == EVENT_VERSION + 1
        ));

        Ok(())
    }

    #[test]
    fn signed_inception_rejects_insufficient_signatures() -> Result<()> {
        let control = dummy_keyset(2, &[0x11, 0x22])?;
        let commitment = derive_next_key_commitment(&dummy_keyset(1, &[0x33])?)?;
        let inception = Inception::new(control, commitment);

        let result = SignedInception::new(inception, vec![signature(0)]);

        assert!(matches!(
            result,
            Err(SignedInceptionError::InsufficientSignatures {
                threshold: 2,
                actual: 1
            })
        ));

        Ok(())
    }

    #[test]
    fn signed_inception_rejects_out_of_range_key_index() -> Result<()> {
        let inception = inception()?;

        let result = SignedInception::new(inception, vec![signature(1)]);

        assert!(matches!(
            result,
            Err(SignedInceptionError::KeyIndexOutOfRange {
                index: 1,
                key_count: 1
            })
        ));

        Ok(())
    }

    #[test]
    fn signed_inception_rejects_duplicate_key_index() -> Result<()> {
        let control = dummy_keyset(1, &[0x11, 0x22])?;
        let commitment = derive_next_key_commitment(&dummy_keyset(1, &[0x33])?)?;
        let inception = Inception::new(control, commitment);

        let result = SignedInception::new(inception, vec![signature(0), signature(0)]);

        assert!(matches!(
            result,
            Err(SignedInceptionError::KeySignatureList(
                KeySignatureListError::DuplicateKeyIndex { index: 0 }
            ))
        ));

        Ok(())
    }

    #[test]
    fn signed_inception_rejects_unordered_key_index() -> Result<()> {
        let control = dummy_keyset(1, &[0x11, 0x22])?;
        let commitment = derive_next_key_commitment(&dummy_keyset(1, &[0x33])?)?;
        let inception = Inception::new(control, commitment);

        let result = SignedInception::new(inception, vec![signature(1), signature(0)]);

        assert!(matches!(
            result,
            Err(SignedInceptionError::KeySignatureList(
                KeySignatureListError::UnorderedKeyIndex {
                    previous: 1,
                    actual: 0
                }
            ))
        ));

        Ok(())
    }

    #[test]
    fn signed_inception_rejects_too_many_signatures() -> Result<()> {
        let inception = inception()?;
        let signatures = vec![signature(0); KeySet::MAX_KEYS + 1];

        let result = SignedInception::new(inception, signatures);

        assert!(matches!(
            result,
            Err(SignedInceptionError::KeySignatureList(
                KeySignatureListError::TooManySignatures {
                    maximum: KeySet::MAX_KEYS,
                    actual,
                }
            )) if actual == KeySet::MAX_KEYS + 1
        ));

        Ok(())
    }

    #[test]
    fn signed_inception_round_trips() -> Result<()> {
        let control = dummy_keyset(1, &[0x11, 0x22])?;
        let commitment = derive_next_key_commitment(&dummy_keyset(1, &[0x33])?)?;
        let inception = Inception::new(control, commitment);
        let value = SignedInception::new(inception, vec![signature(0), signature(1)])?;
        let bytes = encode(&value)?;

        assert_eq!(decode::<SignedInception>(&bytes)?, value);

        Ok(())
    }

    #[test]
    fn signed_inception_decode_rejects_semantically_invalid_bytes() -> Result<()> {
        let inception = inception()?;

        let mut encoder = Encoder::new(Vec::new());
        encoder.array(2)?;
        inception.encode_value(&mut encoder)?;
        encoder.array(1)?;
        signature(5).encode_value(&mut encoder)?;

        let bytes = encoder.into_writer();

        let result = decode::<SignedInception>(&bytes);

        assert!(matches!(
            result,
            Err(DecodeIdentityError::SignedInception(
                SignedInceptionError::KeyIndexOutOfRange {
                    index: 5,
                    key_count: 1
                }
            ))
        ));

        Ok(())
    }
}
