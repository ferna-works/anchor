use std::collections::BTreeMap;

use anchor_codec::{
    DecodeError, DecodeValue, EncodeError, EncodeValue, read_bounded_map_length,
    require_array_length,
};
use minicbor::{Decoder, Encoder};

use crate::{
    DecodeIdentityError, DeviceId, EventId, IdentityId, IdentityStateError, KeySet,
    NextKeyCommitment, PublicKey, Sequence, derive_device_id,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityState {
    id: IdentityId,
    sequence: Sequence,
    latest_event: EventId,
    control: KeySet,
    commitment: NextKeyCommitment,
    devices: BTreeMap<DeviceId, DeviceState>,
    deactivated: bool,
}

impl IdentityState {
    pub const MAX_DEVICES: usize = 32;

    /// Builds a validated identity state from its parts, rejecting invalid or inconsistent input:
    /// invalid control or device public keys, too many devices, a device ID that doesn't match
    /// its derived key, or duplicate device IDs.
    pub fn from_parts(
        id: IdentityId,
        sequence: Sequence,
        latest_event: EventId,
        control: KeySet,
        commitment: NextKeyCommitment,
        devices: Vec<(DeviceId, DeviceState)>,
        deactivated: bool,
    ) -> Result<Self, IdentityStateError> {
        for (index, key) in control.keys().iter().enumerate() {
            if !is_valid_public_key(key) {
                return Err(IdentityStateError::InvalidControlPublicKey { index });
            }
        }

        if devices.len() > Self::MAX_DEVICES {
            return Err(IdentityStateError::TooManyDevices {
                maximum: Self::MAX_DEVICES,
            });
        }

        let mut device_map = BTreeMap::new();

        for (stored_id, device) in devices {
            if !is_valid_public_key(device.key()) {
                return Err(IdentityStateError::InvalidDevicePublicKey { id: stored_id });
            }

            let derived_id =
                derive_device_id(device.key()).map_err(IdentityStateError::DeviceId)?;

            if stored_id != derived_id {
                return Err(IdentityStateError::DeviceIdMismatch);
            }

            if device_map.insert(stored_id, device).is_some() {
                return Err(IdentityStateError::DuplicateDeviceId);
            }
        }

        Ok(Self {
            id,
            sequence,
            latest_event,
            control,
            commitment,
            devices: device_map,
            deactivated,
        })
    }

    /// Returns the identity's ID.
    pub const fn id(&self) -> &IdentityId {
        &self.id
    }

    /// Returns the sequence number of the identity's latest applied event.
    pub const fn sequence(&self) -> Sequence {
        self.sequence
    }

    /// Returns the ID of the identity's latest applied event.
    pub const fn latest_event(&self) -> &EventId {
        &self.latest_event
    }

    /// Returns the identity's current control key set.
    pub const fn control(&self) -> &KeySet {
        &self.control
    }

    /// Returns the commitment the identity's next control rotation must reveal.
    pub const fn commitment(&self) -> &NextKeyCommitment {
        &self.commitment
    }

    /// Returns the identity's currently authorized devices.
    pub const fn devices(&self) -> &BTreeMap<DeviceId, DeviceState> {
        &self.devices
    }

    /// Returns whether the identity has been permanently deactivated.
    pub const fn is_deactivated(&self) -> bool {
        self.deactivated
    }
}

fn is_valid_public_key(key: &PublicKey) -> bool {
    match *key {
        PublicKey::Ed25519(bytes) => ed25519_dalek::VerifyingKey::from_bytes(&bytes).is_ok(),
        PublicKey::P256(bytes) => p256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes).is_ok(),
    }
}

impl EncodeValue for IdentityState {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError> {
        encoder.array(7)?;
        self.id().encode_value(encoder)?;
        self.sequence().encode_value(encoder)?;
        self.latest_event().encode_value(encoder)?;
        self.control().encode_value(encoder)?;
        self.commitment().encode_value(encoder)?;

        encoder.map(self.devices().len() as u64)?;

        for (device_id, device_state) in self.devices() {
            device_id.encode_value(encoder)?;
            device_state.encode_value(encoder)?;
        }

        encoder.bool(self.is_deactivated())?;

        Ok(())
    }
}

impl DecodeValue for IdentityState {
    type Error = DecodeIdentityError;

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self, Self::Error> {
        require_array_length(decoder, 7)?;

        let id = IdentityId::decode_value(decoder)?;
        let sequence = Sequence::decode_value(decoder)?;
        let latest_event = EventId::decode_value(decoder)?;
        let control = KeySet::decode_value(decoder)?;
        let commitment = NextKeyCommitment::decode_value(decoder)?;

        let device_count = read_bounded_map_length(decoder, Self::MAX_DEVICES)? as usize;
        let mut devices = Vec::with_capacity(device_count);

        for _ in 0..device_count {
            let device_id = DeviceId::decode_value(decoder)?;
            let device_state = DeviceState::decode_value(decoder)?;

            devices.push((device_id, device_state));
        }

        let deactivated = decoder.bool().map_err(DecodeError::from)?;

        Ok(Self::from_parts(
            id,
            sequence,
            latest_event,
            control,
            commitment,
            devices,
            deactivated,
        )?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceState {
    key: PublicKey,
}

impl DeviceState {
    /// Wraps an authorized device's public key.
    pub const fn new(key: PublicKey) -> Self {
        Self { key }
    }

    /// Returns the device's public key.
    pub const fn key(&self) -> &PublicKey {
        &self.key
    }

    /// Derives this device's ID from its public key.
    pub fn id(&self) -> Result<DeviceId, EncodeError> {
        derive_device_id(&self.key)
    }
}

impl EncodeValue for DeviceState {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError> {
        self.key().encode_value(encoder)
    }
}

impl DecodeValue for DeviceState {
    type Error = DecodeIdentityError;

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self, Self::Error> {
        let key = PublicKey::decode_value(decoder)?;

        Ok(Self::new(key))
    }
}

#[cfg(test)]
mod tests {
    use anchor_codec::{decode, encode};
    use anyhow::Result;

    use crate::{
        derive_next_key_commitment,
        testing::{control_key, invalid_ed25519_public_key_bytes, keyset, signing_key},
    };

    use super::*;

    fn device(byte: u8) -> Result<(DeviceId, DeviceState)> {
        let state = DeviceState::new(control_key(&signing_key(byte)));
        let id = state.id()?;

        Ok((id, state))
    }

    #[test]
    fn identity_state_round_trips() -> Result<()> {
        let control = KeySet::new(1, vec![control_key(&signing_key(0x11))])?;
        let commitment = derive_next_key_commitment(&keyset(1, &[0x22])?)?;
        let (device_id, device_state) = device(0x33)?;
        let value = IdentityState::from_parts(
            IdentityId::from_bytes([1; 32]),
            Sequence::from_u64(2),
            EventId::from_bytes([2; 32]),
            control,
            commitment,
            vec![(device_id, device_state)],
            false,
        )?;
        let bytes = encode(&value)?;

        assert_eq!(decode::<IdentityState>(&bytes)?, value);

        Ok(())
    }

    #[test]
    fn from_parts_rejects_invalid_control_public_key() -> Result<()> {
        let invalid = invalid_ed25519_public_key_bytes()?;
        let control = KeySet::new(1, vec![PublicKey::from_ed25519_bytes(invalid)])?;
        let commitment = derive_next_key_commitment(&keyset(1, &[0x22])?)?;

        let result = IdentityState::from_parts(
            IdentityId::from_bytes([1; 32]),
            Sequence::ZERO,
            EventId::from_bytes([2; 32]),
            control,
            commitment,
            Vec::new(),
            false,
        );

        assert!(matches!(
            result,
            Err(IdentityStateError::InvalidControlPublicKey { index: 0 })
        ));

        Ok(())
    }

    #[test]
    fn from_parts_rejects_invalid_device_public_key() -> Result<()> {
        let control = KeySet::new(1, vec![control_key(&signing_key(0x11))])?;
        let commitment = derive_next_key_commitment(&keyset(1, &[0x22])?)?;
        let invalid = invalid_ed25519_public_key_bytes()?;
        let device_state = DeviceState::new(PublicKey::from_ed25519_bytes(invalid));
        let device_id = DeviceId::from_bytes([9; 32]);

        let result = IdentityState::from_parts(
            IdentityId::from_bytes([1; 32]),
            Sequence::ZERO,
            EventId::from_bytes([2; 32]),
            control,
            commitment,
            vec![(device_id, device_state)],
            false,
        );

        assert!(matches!(
            result,
            Err(IdentityStateError::InvalidDevicePublicKey { id }) if id == device_id
        ));

        Ok(())
    }

    #[test]
    fn from_parts_rejects_device_id_mismatch() -> Result<()> {
        let control = KeySet::new(1, vec![control_key(&signing_key(0x11))])?;
        let commitment = derive_next_key_commitment(&keyset(1, &[0x22])?)?;
        let (_, device_state) = device(0x33)?;
        let wrong_id = DeviceId::from_bytes([9; 32]);

        let result = IdentityState::from_parts(
            IdentityId::from_bytes([1; 32]),
            Sequence::ZERO,
            EventId::from_bytes([2; 32]),
            control,
            commitment,
            vec![(wrong_id, device_state)],
            false,
        );

        assert!(matches!(result, Err(IdentityStateError::DeviceIdMismatch)));

        Ok(())
    }

    #[test]
    fn from_parts_rejects_duplicate_device_id() -> Result<()> {
        let control = KeySet::new(1, vec![control_key(&signing_key(0x11))])?;
        let commitment = derive_next_key_commitment(&keyset(1, &[0x22])?)?;
        let (device_id, device_state) = device(0x33)?;

        let result = IdentityState::from_parts(
            IdentityId::from_bytes([1; 32]),
            Sequence::ZERO,
            EventId::from_bytes([2; 32]),
            control,
            commitment,
            vec![(device_id, device_state), (device_id, device_state)],
            false,
        );

        assert!(matches!(result, Err(IdentityStateError::DuplicateDeviceId)));

        Ok(())
    }

    #[test]
    fn from_parts_rejects_too_many_devices() -> Result<()> {
        let control = KeySet::new(1, vec![control_key(&signing_key(0x11))])?;
        let commitment = derive_next_key_commitment(&keyset(1, &[0x22])?)?;
        let junk = DeviceState::new(PublicKey::from_ed25519_bytes([0; 32]));
        let devices = vec![(DeviceId::from_bytes([0; 32]), junk); IdentityState::MAX_DEVICES + 1];

        let result = IdentityState::from_parts(
            IdentityId::from_bytes([1; 32]),
            Sequence::ZERO,
            EventId::from_bytes([2; 32]),
            control,
            commitment,
            devices,
            false,
        );

        assert!(matches!(
            result,
            Err(IdentityStateError::TooManyDevices { maximum })
                if maximum == IdentityState::MAX_DEVICES
        ));

        Ok(())
    }

    #[test]
    fn device_state_round_trips() -> Result<()> {
        let key = control_key(&signing_key(0x11));
        let value = DeviceState::new(key);
        let bytes = encode(&value)?;

        assert_eq!(decode::<DeviceState>(&bytes)?, value);
        assert_eq!(value.id()?, derive_device_id(&key)?);

        Ok(())
    }
}
