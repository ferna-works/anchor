mod derive;
mod digest;
mod error;
mod event;
mod inception;
mod signing;
#[cfg(test)]
mod testing;
mod verify;

pub use derive::{
    derive_device_id, derive_event_signature_target, derive_identity_id,
    derive_inception_signature_target, derive_next_key_commitment, derive_signed_event_id,
};
pub use digest::{
    CredentialHash, DeviceId, EventId, EventSignatureTarget, IdentityId, InceptionSignatureTarget,
    NextKeyCommitment,
};

pub use error::{
    DecodeIdentityError, InceptionVerificationError, KeySetError, KeySignatureListError,
    PublicKeyError, SignedInceptionError,
};
pub use event::{
    AuthorizeDevice, CommitCredential, EVENT_VERSION, IdentityAction, IdentityEvent,
    RevokeCredential, RevokeDevice, RotateControl, Sequence, SignedIdentityEvent,
    SignedOrdinaryEvent,
};
pub use inception::{Inception, SignedInception};
pub use signing::{KeySet, KeySignature, PublicKey, Signature};
pub use verify::verify_signed_inception;
