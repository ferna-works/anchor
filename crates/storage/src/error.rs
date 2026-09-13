use anchor_codec::EncodeError;
use anchor_identity::{DecodeIdentityError, IdentityId, Sequence};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage backend failed: {0}")]
    Backend(#[from] redb::Error),
    #[error("failed to encode stored value: {0}")]
    Encode(#[from] EncodeError),
    #[error("failed to decode stored value: {0}")]
    Decode(#[from] DecodeIdentityError),
    #[error("state commitment tree operation failed: {0}")]
    Tree(#[from] anyhow::Error),
    #[error("failed to encode or decode a state commitment tree entry: {0}")]
    Borsh(#[from] std::io::Error),
    #[error("state commitment root is missing at height {height}")]
    MissingRoot { height: u64 },
    #[error("expected the next commit to be at height {expected}, got {actual}")]
    NonSequentialCommit { expected: u64, actual: u64 },
    #[error("identity {id:?} already has an event at sequence {sequence:?}")]
    EventAlreadyStored { id: IdentityId, sequence: Sequence },
}

macro_rules! convert_redb_errors {
    ($($error:ty),+ $(,)?) => {
        $(
            impl From<$error> for StorageError {
                fn from(error: $error) -> Self {
                    Self::Backend(error.into())
                }
            }
        )+
    };
}

convert_redb_errors!(
    redb::CommitError,
    redb::DatabaseError,
    redb::StorageError,
    redb::TableError,
    redb::TransactionError,
);
