use anchor_codec::{DecodeError, DecodeValue, EncodeError, EncodeValue, require_array_length};
use minicbor::Encoder;

use crate::{CredentialHash, DecodeIdentityError, DeviceId, KeySet, NextKeyCommitment, PublicKey};

pub(crate) const ROTATE_CONTROL_ACTION_TAG: u16 = 0;
pub(crate) const AUTHORIZE_DEVICE_ACTION_TAG: u16 = 1;
pub(crate) const REVOKE_DEVICE_ACTION_TAG: u16 = 2;
pub(crate) const DEACTIVATE_ACTION_TAG: u16 = 3;
pub(crate) const COMMIT_CREDENTIAL_ACTION_TAG: u16 = 4;
pub(crate) const REVOKE_CREDENTIAL_ACTION_TAG: u16 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityAction {
    RotateControl(RotateControl),
    AuthorizeDevice(AuthorizeDevice),
    RevokeDevice(RevokeDevice),
    Deactivate,
    CommitCredential(CommitCredential),
    RevokeCredential(RevokeCredential),
}

impl IdentityAction {
    /// Wraps a control-rotation action.
    pub const fn rotate_control(rotation: RotateControl) -> Self {
        Self::RotateControl(rotation)
    }

    /// Wraps a device-authorization action.
    pub const fn authorize_device(authorization: AuthorizeDevice) -> Self {
        Self::AuthorizeDevice(authorization)
    }

    /// Wraps a device-revocation action.
    pub const fn revoke_device(revocation: RevokeDevice) -> Self {
        Self::RevokeDevice(revocation)
    }

    /// Creates a deactivation action.
    pub const fn deactivate() -> Self {
        Self::Deactivate
    }

    /// Wraps a credential-commitment action.
    pub const fn commit_credential(commitment: CommitCredential) -> Self {
        Self::CommitCredential(commitment)
    }

    /// Wraps a credential-revocation action.
    pub const fn revoke_credential(revocation: RevokeCredential) -> Self {
        Self::RevokeCredential(revocation)
    }
}

impl EncodeValue for IdentityAction {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError> {
        encoder.array(2)?;

        match self {
            Self::RotateControl(rotation) => {
                encoder.u16(ROTATE_CONTROL_ACTION_TAG)?;
                rotation.encode_value(encoder)?;
            }
            Self::AuthorizeDevice(key) => {
                encoder.u16(AUTHORIZE_DEVICE_ACTION_TAG)?;
                key.encode_value(encoder)?;
            }
            Self::RevokeDevice(device) => {
                encoder.u16(REVOKE_DEVICE_ACTION_TAG)?;
                device.encode_value(encoder)?;
            }
            Self::Deactivate => {
                encoder.u16(DEACTIVATE_ACTION_TAG)?;
                encoder.array(0)?;
            }
            Self::CommitCredential(commitment) => {
                encoder.u16(COMMIT_CREDENTIAL_ACTION_TAG)?;
                commitment.encode_value(encoder)?;
            }
            Self::RevokeCredential(revocation) => {
                encoder.u16(REVOKE_CREDENTIAL_ACTION_TAG)?;
                revocation.encode_value(encoder)?;
            }
        }

        Ok(())
    }
}

impl DecodeValue for IdentityAction {
    type Error = DecodeIdentityError;

    fn decode_value(decoder: &mut minicbor::Decoder<'_>) -> Result<Self, Self::Error> {
        require_array_length(decoder, 2)?;

        let tag = decoder.u16().map_err(DecodeError::from)?;

        match tag {
            ROTATE_CONTROL_ACTION_TAG => {
                let rotation = RotateControl::decode_value(decoder)?;

                Ok(Self::RotateControl(rotation))
            }
            AUTHORIZE_DEVICE_ACTION_TAG => {
                let authorization = AuthorizeDevice::decode_value(decoder)?;

                Ok(Self::AuthorizeDevice(authorization))
            }
            REVOKE_DEVICE_ACTION_TAG => {
                let revocation = RevokeDevice::decode_value(decoder)?;

                Ok(Self::RevokeDevice(revocation))
            }
            DEACTIVATE_ACTION_TAG => {
                require_array_length(decoder, 0)?;

                Ok(Self::Deactivate)
            }
            REVOKE_CREDENTIAL_ACTION_TAG => {
                let revocation = RevokeCredential::decode_value(decoder)?;

                Ok(Self::RevokeCredential(revocation))
            }
            COMMIT_CREDENTIAL_ACTION_TAG => {
                let commitment = CommitCredential::decode_value(decoder)?;

                Ok(Self::CommitCredential(commitment))
            }

            actual => Err(DecodeIdentityError::Decode(DecodeError::UnsupportedTag {
                actual,
            })),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateControl {
    control: KeySet,
    commitment: NextKeyCommitment,
}

impl RotateControl {
    /// Creates a rotation revealing a new control set and committing to the one after it.
    pub const fn new(control: KeySet, commitment: NextKeyCommitment) -> Self {
        Self {
            control,
            commitment,
        }
    }

    /// Returns the control set this rotation reveals.
    pub const fn control(&self) -> &KeySet {
        &self.control
    }

    /// Returns the commitment this rotation binds to the following control set.
    pub const fn commitment(&self) -> &NextKeyCommitment {
        &self.commitment
    }
}

impl EncodeValue for RotateControl {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError> {
        encoder.array(2)?;
        self.control().encode_value(encoder)?;
        self.commitment().encode_value(encoder)?;

        Ok(())
    }
}

impl DecodeValue for RotateControl {
    type Error = DecodeIdentityError;

    fn decode_value(decoder: &mut minicbor::Decoder<'_>) -> Result<Self, Self::Error> {
        require_array_length(decoder, 2)?;

        let control = KeySet::decode_value(decoder)?;
        let commitment = NextKeyCommitment::decode_value(decoder)?;

        Ok(Self::new(control, commitment))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizeDevice {
    key: PublicKey,
}

impl AuthorizeDevice {
    /// Creates an authorization for the given device public key.
    pub const fn new(key: PublicKey) -> Self {
        Self { key }
    }

    /// Returns the device's public key.
    pub const fn key(&self) -> &PublicKey {
        &self.key
    }
}

impl EncodeValue for AuthorizeDevice {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError> {
        encoder.array(1)?;
        self.key().encode_value(encoder)?;

        Ok(())
    }
}

impl DecodeValue for AuthorizeDevice {
    type Error = DecodeIdentityError;

    fn decode_value(decoder: &mut minicbor::Decoder<'_>) -> Result<Self, Self::Error> {
        require_array_length(decoder, 1)?;

        let key = PublicKey::decode_value(decoder)?;

        Ok(Self::new(key))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokeDevice {
    device: DeviceId,
}

impl RevokeDevice {
    /// Creates a revocation for the given device ID.
    pub const fn new(device: DeviceId) -> Self {
        Self { device }
    }

    /// Returns the ID of the device being revoked.
    pub const fn device(&self) -> &DeviceId {
        &self.device
    }
}

impl EncodeValue for RevokeDevice {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError> {
        encoder.array(1)?;
        self.device().encode_value(encoder)?;

        Ok(())
    }
}

impl DecodeValue for RevokeDevice {
    type Error = DecodeIdentityError;

    fn decode_value(decoder: &mut minicbor::Decoder<'_>) -> Result<Self, Self::Error> {
        require_array_length(decoder, 1)?;

        let device = DeviceId::decode_value(decoder)?;

        Ok(Self::new(device))
    }
}

/// An optional commitment to an opaque credential hash, made by the identity issuing the
/// credential at grant time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitCredential {
    credential: CredentialHash,
}

impl CommitCredential {
    /// Creates a commitment to the given credential hash.
    pub const fn new(credential: CredentialHash) -> Self {
        Self { credential }
    }

    /// Returns the hash of the credential being committed.
    pub const fn credential(&self) -> &CredentialHash {
        &self.credential
    }
}

impl EncodeValue for CommitCredential {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError> {
        encoder.array(1)?;
        self.credential().encode_value(encoder)?;

        Ok(())
    }
}

impl DecodeValue for CommitCredential {
    type Error = DecodeIdentityError;

    fn decode_value(decoder: &mut minicbor::Decoder<'_>) -> Result<Self, Self::Error> {
        require_array_length(decoder, 1)?;

        let credential = CredentialHash::decode_value(decoder)?;

        Ok(Self::new(credential))
    }
}

/// A revocation of an opaque credential hash, committed by the identity that issued the
/// credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokeCredential {
    credential: CredentialHash,
}

impl RevokeCredential {
    /// Creates a revocation for the given credential hash.
    pub const fn new(credential: CredentialHash) -> Self {
        Self { credential }
    }

    /// Returns the hash of the credential being revoked.
    pub const fn credential(&self) -> &CredentialHash {
        &self.credential
    }
}

impl EncodeValue for RevokeCredential {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), EncodeError> {
        encoder.array(1)?;
        self.credential().encode_value(encoder)?;

        Ok(())
    }
}

impl DecodeValue for RevokeCredential {
    type Error = DecodeIdentityError;

    fn decode_value(decoder: &mut minicbor::Decoder<'_>) -> Result<Self, Self::Error> {
        require_array_length(decoder, 1)?;

        let credential = CredentialHash::decode_value(decoder)?;

        Ok(Self::new(credential))
    }
}

#[cfg(test)]
mod tests {
    use anchor_codec::decode;
    use anyhow::Result;

    use super::*;

    #[test]
    fn identity_action_decode_rejects_unsupported_tag() -> Result<()> {
        let mut encoder = Encoder::new(Vec::new());
        encoder.array(2)?;
        encoder.u16(99)?;
        encoder.array(0)?;

        let bytes = encoder.into_writer();

        let result = decode::<IdentityAction>(&bytes);

        assert!(matches!(
            result,
            Err(DecodeIdentityError::Decode(DecodeError::UnsupportedTag {
                actual: 99
            }))
        ));

        Ok(())
    }

    #[test]
    fn revoke_credential_round_trips() -> Result<()> {
        use anchor_codec::encode;

        let value = IdentityAction::revoke_credential(RevokeCredential::new(
            CredentialHash::from_bytes([7; 32]),
        ));
        let bytes = encode(&value)?;

        assert_eq!(decode::<IdentityAction>(&bytes)?, value);

        Ok(())
    }

    #[test]
    fn commit_credential_round_trips() -> Result<()> {
        use anchor_codec::encode;

        let value = IdentityAction::commit_credential(CommitCredential::new(
            CredentialHash::from_bytes([9; 32]),
        ));
        let bytes = encode(&value)?;

        assert_eq!(decode::<IdentityAction>(&bytes)?, value);

        Ok(())
    }
}
