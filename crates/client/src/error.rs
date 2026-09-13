use anchor_codec::EncodeError;
use anchor_identity::{
    ApplyError, DecodeIdentityError, IdentityId, KeySetError, KeySignatureListError, PublicKey,
    Sequence, SignedInceptionError,
};
use anchor_proof::ProofError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error(transparent)]
    Rpc(#[from] RpcError),
    #[error("could not encode value: {0}")]
    Encode(#[from] EncodeError),
    #[error("invalid identity data: {0}")]
    Identity(#[from] DecodeIdentityError),
    #[error("proof verification failed: {0}")]
    Proof(#[from] ProofError),
    #[error("invalid key set: {0}")]
    KeySet(#[from] KeySetError),
    #[error("invalid signature list: {0}")]
    KeySignatureList(#[from] KeySignatureListError),
    #[error("invalid signed inception: {0}")]
    SignedInception(#[from] SignedInceptionError),
    #[error("query failed: {0}")]
    QueryFailed(String),
    #[error("{stage} rejected the transaction: {log}")]
    TxRejected { stage: &'static str, log: String },
    #[error("identity {0:?} was not found")]
    UnknownIdentity(IdentityId),
    #[error("signing key {0:?} does not match any key in the current control set")]
    KeyNotInControlSet(PublicKey),
    #[error("identity sequence is exhausted")]
    SequenceExhausted,
    #[error("chain has not committed any blocks yet")]
    ChainEmpty,
    #[error("query response for an existing identity is missing its proof")]
    MissingProof,
    #[error("signed-header verification failed: {0}")]
    Verification(#[from] VerificationError),
    #[error("verified header contains a {actual}-byte app hash; requires 32 bytes")]
    InvalidAppHashLength { actual: usize },
    #[error("identity history ended early: expected {expected} events, received {actual}")]
    IncompleteHistory { expected: u64, actual: u64 },
    #[error("identity history contains an invalid event at sequence {sequence:?}: {source}")]
    InvalidHistory {
        sequence: Sequence,
        source: ApplyError,
    },
    #[error("identity history inception derives a different identity ID")]
    HistoryIdentityMismatch,
    #[error("replayed identity history does not match the proven current state")]
    HistoryStateMismatch,
}

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("http request to {url} failed: {source}")]
    Http {
        url: String,
        source: Box<reqwest::Error>,
    },
    #[error("could not parse response from {url}: {source}")]
    Json {
        url: String,
        source: serde_json::Error,
    },
    #[error("could not decode base64 field in response from {url}: {source}")]
    Base64 {
        url: String,
        source: base64::DecodeError,
    },
    #[error("{url} returned a JSON-RPC error: {message}")]
    Node { url: String, message: String },
    #[error("node returned a malformed height: {0}")]
    InvalidHeight(String),
    #[error("no RPC endpoints configured")]
    NoEndpoints,
    #[error("chain has no application height that can yet be anchored by a later header")]
    NoVerifiableApplicationHeight,
    #[error("node returned query height {actual}, expected {expected}")]
    UnexpectedQueryHeight { expected: u64, actual: u64 },
}

#[derive(Debug, Error)]
pub enum TrustedError {
    #[error("could not parse genesis JSON: {0}")]
    GenesisJson(#[from] serde_json::Error),
    #[error("genesis validator set is empty")]
    EmptyValidatorSet,
    #[error("genesis validator set has invalid total voting power")]
    InvalidTotalVotingPower,
    #[error("genesis validator address does not match public key")]
    ValidatorAddressMismatch,
}

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("signed header belongs to chain {actual}, expected {expected}")]
    ChainIdMismatch { expected: String, actual: String },
    #[error("signed header validator set does not match trusted genesis")]
    ValidatorSetMismatch,
    #[error("signed header commit is invalid: {0}")]
    InvalidCommit(String),
    #[error("signed header is too old")]
    StaleHeader,
    #[error("signed header is too far in the future")]
    HeaderFromFuture,
}
