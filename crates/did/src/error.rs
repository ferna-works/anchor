use anchor_client::ClientError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DidError {
    #[error("{0:?} is not a did:ferna identifier")]
    UnsupportedDid(String),
    #[error("did:ferna identifier decodes to {actual} bytes, expected 32")]
    InvalidIdentityIdLength { actual: usize },
    #[error("could not decode did:ferna identifier: {0}")]
    Multibase(#[from] multibase::Error),
    #[error("could not serialize DID Document: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Client(#[from] ClientError),
}
