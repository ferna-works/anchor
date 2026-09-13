use anchor_codec::{
    DecodeError, DecodeValue, EncodeError, EncodeValue, read_bounded_array_length,
    require_array_length,
};
use minicbor::Encoder;

use crate::{
    DecodeIdentityError, EVENT_VERSION, EventId, IdentityAction, IdentityId, KeySet, KeySignature,
    KeySignatureListError, Sequence, SignedInception,
};

pub(crate) const INCEPTION_EVENT_TAG: u16 = 0;
pub(crate) const ORDINARY_EVENT_TAG: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityEvent {
    version: u16,
    identity: IdentityId,
    sequence: Sequence,
    previous: EventId,
    action: IdentityAction,
}

impl IdentityEvent {
    /// Creates an ordinary event for an identity's next sequence number.
    pub const fn new(
        identity: IdentityId,
        sequence: Sequence,
        previous: EventId,
        action: IdentityAction,
    ) -> Self {
        Self {
            version: EVENT_VERSION,
            identity,
            sequence,
            previous,
            action,
        }
    }

    /// Returns the encoding version this event was created with.
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Returns the ID of the identity this event applies to.
    pub const fn identity(&self) -> &IdentityId {
        &self.identity
    }

    /// Returns this event's sequence number.
    pub const fn sequence(&self) -> Sequence {
        self.sequence
    }

    /// Returns the ID of the event this one follows.
    pub const fn previous(&self) -> &EventId {
        &self.previous
    }

    /// Returns the action this event applies.
    pub const fn action(&self) -> &IdentityAction {
        &self.action
    }
}

impl EncodeValue for IdentityEvent {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError> {
        encoder.array(5)?;
        encoder.u16(self.version())?;
        self.identity().encode_value(encoder)?;
        self.sequence().encode_value(encoder)?;
        self.previous().encode_value(encoder)?;
        self.action().encode_value(encoder)?;

        Ok(())
    }
}

impl DecodeValue for IdentityEvent {
    type Error = DecodeIdentityError;

    fn decode_value(decoder: &mut minicbor::Decoder<'_>) -> Result<Self, Self::Error> {
        require_array_length(decoder, 5)?;

        let version = decoder.u16().map_err(DecodeError::from)?;

        if version != EVENT_VERSION {
            return Err(DecodeIdentityError::UnsupportedVersion { actual: version });
        }

        let identity = IdentityId::decode_value(decoder)?;
        let sequence = Sequence::decode_value(decoder)?;
        let previous = EventId::decode_value(decoder)?;
        let action = IdentityAction::decode_value(decoder)?;

        Ok(IdentityEvent::new(identity, sequence, previous, action))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedOrdinaryEvent {
    event: IdentityEvent,
    signatures: Vec<KeySignature>,
}

impl SignedOrdinaryEvent {
    /// Pairs an ordinary event with its control-key signatures, validating their key-index ordering.
    pub fn new(
        event: IdentityEvent,
        signatures: Vec<KeySignature>,
    ) -> Result<Self, KeySignatureListError> {
        if signatures.len() > KeySet::MAX_KEYS {
            return Err(KeySignatureListError::TooManySignatures {
                maximum: KeySet::MAX_KEYS,
                actual: signatures.len(),
            });
        }

        let mut previous = None;

        for signature in &signatures {
            if let Some(previous) = previous {
                if signature.key_index() == previous {
                    return Err(KeySignatureListError::DuplicateKeyIndex {
                        index: signature.key_index(),
                    });
                }

                if signature.key_index() < previous {
                    return Err(KeySignatureListError::UnorderedKeyIndex {
                        previous,
                        actual: signature.key_index(),
                    });
                }
            }

            previous = Some(signature.key_index());
        }

        Ok(Self { event, signatures })
    }

    /// Returns the event.
    pub const fn event(&self) -> &IdentityEvent {
        &self.event
    }

    /// Returns the control-key signatures over the event.
    pub fn signatures(&self) -> &[KeySignature] {
        &self.signatures
    }
}

impl EncodeValue for SignedOrdinaryEvent {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError> {
        encoder.array(2)?;
        self.event().encode_value(encoder)?;
        encoder.array(self.signatures().len() as u64)?;

        for signature in self.signatures() {
            signature.encode_value(encoder)?;
        }

        Ok(())
    }
}

impl DecodeValue for SignedOrdinaryEvent {
    type Error = DecodeIdentityError;

    fn decode_value(decoder: &mut minicbor::Decoder<'_>) -> Result<Self, Self::Error> {
        require_array_length(decoder, 2)?;

        let event = IdentityEvent::decode_value(decoder)?;
        let signature_count = read_bounded_array_length(decoder, KeySet::MAX_KEYS)?;
        let mut signatures = Vec::with_capacity(signature_count as usize);

        for _ in 0..signature_count {
            let signature = KeySignature::decode_value(decoder)?;

            signatures.push(signature);
        }

        Ok(Self::new(event, signatures)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedIdentityEvent {
    Inception(SignedInception),
    Ordinary(SignedOrdinaryEvent),
}

impl SignedIdentityEvent {
    /// Wraps a signed inception as an identity event.
    pub const fn inception(inception: SignedInception) -> Self {
        Self::Inception(inception)
    }

    /// Returns the signed inception, if this event is one.
    pub const fn as_inception(&self) -> Option<&SignedInception> {
        match self {
            Self::Inception(inception) => Some(inception),
            Self::Ordinary(_) => None,
        }
    }

    /// Wraps a signed ordinary event as an identity event.
    pub const fn ordinary(event: SignedOrdinaryEvent) -> Self {
        Self::Ordinary(event)
    }

    /// Returns the signed ordinary event, if this event is one.
    pub const fn as_ordinary(&self) -> Option<&SignedOrdinaryEvent> {
        match self {
            Self::Inception(_) => None,
            Self::Ordinary(event) => Some(event),
        }
    }
}

impl EncodeValue for SignedIdentityEvent {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError> {
        encoder.array(2)?;

        match self {
            Self::Inception(inception) => {
                encoder.u16(INCEPTION_EVENT_TAG)?;
                inception.encode_value(encoder)?;
            }
            Self::Ordinary(event) => {
                encoder.u16(ORDINARY_EVENT_TAG)?;
                event.encode_value(encoder)?;
            }
        }

        Ok(())
    }
}

impl DecodeValue for SignedIdentityEvent {
    type Error = DecodeIdentityError;

    fn decode_value(decoder: &mut minicbor::Decoder<'_>) -> Result<Self, Self::Error> {
        require_array_length(decoder, 2)?;

        let tag = decoder.u16().map_err(DecodeError::from)?;

        match tag {
            INCEPTION_EVENT_TAG => {
                let inception = SignedInception::decode_value(decoder)?;

                Ok(Self::Inception(inception))
            }
            ORDINARY_EVENT_TAG => {
                let event = SignedOrdinaryEvent::decode_value(decoder)?;

                Ok(Self::Ordinary(event))
            }
            actual => Err(DecodeIdentityError::Decode(DecodeError::UnsupportedTag {
                actual,
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use anchor_codec::{decode, encode};
    use anyhow::Result;
    use minicbor::Encoder;

    use crate::{
        IdentityId, Inception, KeySet, RotateControl, SignedInception, derive_next_key_commitment,
        testing::{dummy_keyset, signature},
    };

    use super::*;

    fn action() -> Result<IdentityAction> {
        let control = dummy_keyset(1, &[0x11])?;
        let commitment = derive_next_key_commitment(&dummy_keyset(1, &[0x22])?)?;

        Ok(IdentityAction::rotate_control(RotateControl::new(
            control, commitment,
        )))
    }

    fn identity_event() -> Result<IdentityEvent> {
        Ok(IdentityEvent::new(
            IdentityId::from_bytes([1; 32]),
            Sequence::from_u64(1),
            EventId::from_bytes([2; 32]),
            action()?,
        ))
    }

    fn signed_inception() -> Result<SignedInception> {
        let control = dummy_keyset(1, &[0x33])?;
        let commitment = derive_next_key_commitment(&dummy_keyset(1, &[0x44])?)?;
        let inception = Inception::new(control, commitment);

        Ok(SignedInception::new(inception, vec![signature(0)])?)
    }

    #[test]
    fn identity_event_round_trips() -> Result<()> {
        let value = identity_event()?;
        let bytes = encode(&value)?;

        assert_eq!(decode::<IdentityEvent>(&bytes)?, value);

        Ok(())
    }

    #[test]
    fn identity_event_decode_rejects_wrong_version() -> Result<()> {
        let mut encoder = Encoder::new(Vec::new());
        encoder.array(5)?;
        encoder.u16(EVENT_VERSION + 1)?;
        IdentityId::from_bytes([1; 32]).encode_value(&mut encoder)?;
        Sequence::from_u64(1).encode_value(&mut encoder)?;
        EventId::from_bytes([2; 32]).encode_value(&mut encoder)?;
        action()?.encode_value(&mut encoder)?;

        let bytes = encoder.into_writer();

        let result = decode::<IdentityEvent>(&bytes);

        assert!(matches!(
            result,
            Err(DecodeIdentityError::UnsupportedVersion { actual }) if actual == EVENT_VERSION + 1
        ));

        Ok(())
    }

    #[test]
    fn signed_ordinary_event_rejects_too_many_signatures() -> Result<()> {
        let signatures = vec![signature(0); KeySet::MAX_KEYS + 1];

        let result = SignedOrdinaryEvent::new(identity_event()?, signatures);

        assert!(matches!(
            result,
            Err(KeySignatureListError::TooManySignatures {
                maximum: KeySet::MAX_KEYS,
                actual,
            }) if actual == KeySet::MAX_KEYS + 1
        ));

        Ok(())
    }

    #[test]
    fn signed_ordinary_event_rejects_duplicate_key_index() -> Result<()> {
        let result = SignedOrdinaryEvent::new(identity_event()?, vec![signature(0), signature(0)]);

        assert!(matches!(
            result,
            Err(KeySignatureListError::DuplicateKeyIndex { index: 0 })
        ));

        Ok(())
    }

    #[test]
    fn signed_ordinary_event_rejects_unordered_key_index() -> Result<()> {
        let result = SignedOrdinaryEvent::new(identity_event()?, vec![signature(1), signature(0)]);

        assert!(matches!(
            result,
            Err(KeySignatureListError::UnorderedKeyIndex {
                previous: 1,
                actual: 0
            })
        ));

        Ok(())
    }

    #[test]
    fn signed_ordinary_event_round_trips() -> Result<()> {
        let value = SignedOrdinaryEvent::new(identity_event()?, vec![signature(0), signature(1)])?;
        let bytes = encode(&value)?;

        assert_eq!(decode::<SignedOrdinaryEvent>(&bytes)?, value);

        Ok(())
    }

    #[test]
    fn signed_ordinary_event_decode_rejects_semantically_invalid_bytes() -> Result<()> {
        let mut encoder = Encoder::new(Vec::new());
        encoder.array(2)?;
        identity_event()?.encode_value(&mut encoder)?;
        encoder.array(2)?;
        signature(0).encode_value(&mut encoder)?;
        signature(0).encode_value(&mut encoder)?;

        let bytes = encoder.into_writer();

        let result = decode::<SignedOrdinaryEvent>(&bytes);

        assert!(matches!(
            result,
            Err(DecodeIdentityError::KeySignatureList(
                KeySignatureListError::DuplicateKeyIndex { index: 0 }
            ))
        ));

        Ok(())
    }

    #[test]
    fn signed_identity_event_round_trips_inception() -> Result<()> {
        let value = SignedIdentityEvent::inception(signed_inception()?);
        let bytes = encode(&value)?;

        assert_eq!(decode::<SignedIdentityEvent>(&bytes)?, value);

        Ok(())
    }

    #[test]
    fn signed_identity_event_round_trips_ordinary() -> Result<()> {
        let signed = SignedOrdinaryEvent::new(identity_event()?, vec![signature(0)])?;
        let value = SignedIdentityEvent::ordinary(signed);
        let bytes = encode(&value)?;

        assert_eq!(decode::<SignedIdentityEvent>(&bytes)?, value);

        Ok(())
    }

    #[test]
    fn signed_identity_event_decode_rejects_unsupported_tag() -> Result<()> {
        let mut encoder = Encoder::new(Vec::new());
        encoder.array(2)?;
        encoder.u16(99)?;
        encoder.array(0)?;

        let bytes = encoder.into_writer();

        let result = decode::<SignedIdentityEvent>(&bytes);

        assert!(matches!(
            result,
            Err(DecodeIdentityError::Decode(DecodeError::UnsupportedTag {
                actual: 99
            }))
        ));

        Ok(())
    }
}
