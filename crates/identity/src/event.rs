mod action;
mod envelope;
mod sequence;

pub use action::{
    AuthorizeDevice, CommitCredential, IdentityAction, RevokeCredential, RevokeDevice,
    RotateControl,
};
pub use envelope::{IdentityEvent, SignedIdentityEvent, SignedOrdinaryEvent};
pub use sequence::Sequence;

pub const EVENT_VERSION: u16 = 0;
