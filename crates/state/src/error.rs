use anchor_codec::EncodeError;
use anchor_identity::{ApplyError, IdentityId};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error(transparent)]
    Apply(#[from] ApplyError),
    #[error("unknown identity: {0:?}")]
    UnknownIdentity(IdentityId),
    #[error("identity already exists: {0:?}")]
    IdentityAlreadyExists(IdentityId),
}
