use anchor_codec::EncodeError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("proof verification failed: {0}")]
    Verification(#[from] anyhow::Error),
    #[error("failed to decode proof: {0}")]
    Decode(#[from] std::io::Error),
    #[error(transparent)]
    Encode(#[from] EncodeError),
}
