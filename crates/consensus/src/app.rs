use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use anchor_codec::{decode, encode, encode_list};
use anchor_commitment::Height;
use anchor_identity::{IdentityId, IdentityState, Sequence, SignedIdentityEvent};
use anchor_state::{LedgerState, apply_one};
use anchor_storage::LedgerStore;
use tendermint_abci::Application;
use tendermint_proto::v0_38::{
    abci::{
        ExecTxResult, RequestCheckTx, RequestFinalizeBlock, RequestInfo, RequestQuery,
        ResponseCheckTx, ResponseCommit, ResponseFinalizeBlock, ResponseInfo, ResponseQuery,
    },
    crypto::{ProofOp, ProofOps},
};

const APP_VERSION: u64 = 0;

const IDENTITY_QUERY_PATH: &str = "/identity";
const IDENTITY_HISTORY_QUERY_PATH: &str = "/identity/history";
const HISTORY_REQUEST_LENGTH: usize = 44;
const MAX_HISTORY_PAGE_SIZE: u32 = 64;
const IDENTITY_STATE_PROOF_OP: &str = "works.ferna.anchor.identity-state-proof.v0";

#[derive(Debug)]
struct PendingCommit {
    height: Height,
    changed: BTreeMap<IdentityId, IdentityState>,
    events: Vec<SignedIdentityEvent>,
    root: Vec<u8>,
}

/// A Tendermint ABCI application that wraps a ledger store.
#[derive(Debug, Clone)]
pub struct LedgerApplication {
    store: Arc<LedgerStore>,
    pending: Arc<Mutex<Option<PendingCommit>>>,
}

impl LedgerApplication {
    /// Wraps a ledger store as a Tendermint ABCI application.
    pub fn new(store: Arc<LedgerStore>) -> Self {
        Self {
            store,
            pending: Arc::new(Mutex::new(None)),
        }
    }

    fn read_height(&self) -> Result<u64, Box<ResponseQuery>> {
        self.store.height().map_err(|error| {
            tracing::error!(%error, "failed to read committed ledger height");

            Box::new(query_error("failed to read committed ledger height"))
        })
    }

    fn query_history(&self, request: RequestQuery) -> ResponseQuery {
        let bytes: &[u8] = &request.data;

        if bytes.len() != HISTORY_REQUEST_LENGTH {
            return query_error(format!(
                "history query data must be {HISTORY_REQUEST_LENGTH} bytes, got {}",
                bytes.len()
            ));
        }

        let id = IdentityId::from_slice(&bytes[..32]).expect("length checked above");
        let from = Sequence::from_u64(u64::from_be_bytes(
            bytes[32..40].try_into().expect("length checked above"),
        ));
        let limit = u32::from_be_bytes(bytes[40..44].try_into().expect("length checked above"));

        if limit == 0 || limit > MAX_HISTORY_PAGE_SIZE {
            return query_error(format!(
                "history query limit must be between 1 and {MAX_HISTORY_PAGE_SIZE}"
            ));
        }

        let events = match self.store.event_log(id, from, limit as usize) {
            Ok(events) => events,
            Err(error) => return query_error(format!("failed to read identity history: {error}")),
        };

        let value = match encode_list(&events) {
            Ok(value) => value,
            Err(error) => {
                return query_error(format!("failed to encode identity history: {error}"));
            }
        };

        let height = match self.read_height() {
            Ok(height) => height,
            Err(response) => return *response,
        };

        let height = match response_height(height) {
            Ok(height) => height,
            Err(response) => return *response,
        };

        ResponseQuery {
            code: 0,
            value: value.into(),
            height,
            ..Default::default()
        }
    }

    fn query_identity(&self, request: RequestQuery) -> ResponseQuery {
        let Some(id) = IdentityId::from_slice(&request.data) else {
            return query_error("query data must be a 32-byte identity ID");
        };

        let height = if request.height == 0 {
            match self.read_height() {
                Ok(height) => height,
                Err(response) => return *response,
            }
        } else {
            match u64::try_from(request.height) {
                Ok(height) => height,
                Err(_) => return query_error("query height must not be negative"),
            }
        };

        let (state, proof) = match self.store.prove(id, Height::from_u64(height)) {
            Ok(result) => result,
            Err(error) => return query_error(format!("failed to prove identity state: {error}")),
        };

        let value = match state.as_ref().map(encode).transpose() {
            Ok(value) => value.unwrap_or_default(),
            Err(error) => {
                return query_error(format!("failed to encode identity state: {error}"));
            }
        };

        let proof_ops = if request.prove {
            match proof.to_bytes() {
                Ok(data) => Some(ProofOps {
                    ops: vec![ProofOp {
                        r#type: IDENTITY_STATE_PROOF_OP.to_string(),
                        key: request.data.to_vec(),
                        data,
                    }],
                }),
                Err(error) => {
                    return query_error(format!("failed to encode identity state proof: {error}"));
                }
            }
        } else {
            None
        };

        let height = match response_height(height) {
            Ok(height) => height,
            Err(response) => return *response,
        };

        ResponseQuery {
            code: 0,
            key: request.data,
            value: value.into(),
            proof_ops,
            height,
            ..Default::default()
        }
    }
}

impl Application for LedgerApplication {
    fn info(&self, _: RequestInfo) -> ResponseInfo {
        let height = self.store.height().unwrap_or_else(|error| {
            tracing::error!(%error, "failed to read committed ledger height");

            panic!("failed to read committed ledger height");
        });

        let last_block_app_hash = if height > 0 {
            self.store
                .state_root(Height::from_u64(height))
                .map(|root| root.as_ref().to_vec().into())
                .unwrap_or_else(|error| {
                    tracing::error!(%error, height, "failed to read committed ledger root");

                    panic!("failed to read committed ledger root");
                })
        } else {
            vec![].into()
        };

        let last_block_height = i64::try_from(height).unwrap_or_else(|error| {
            tracing::error!(%error, height, "committed ledger height exceeds u64");

            panic!("committed ledger height exceeds u64");
        });

        ResponseInfo {
            data: "Ledger".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            app_version: APP_VERSION,
            last_block_height,
            last_block_app_hash,
        }
    }

    fn query(&self, request: RequestQuery) -> ResponseQuery {
        if request.path == IDENTITY_HISTORY_QUERY_PATH {
            return self.query_history(request);
        }

        if request.path == IDENTITY_QUERY_PATH {
            return self.query_identity(request);
        }

        query_error(format!("unsupported query path: {}", request.path))
    }

    fn check_tx(&self, request: RequestCheckTx) -> ResponseCheckTx {
        let event = match decode::<SignedIdentityEvent>(&request.tx) {
            Ok(event) => event,
            Err(error) => {
                return ResponseCheckTx {
                    code: 1,
                    log: format!("failed to decode tx: {error}"),
                    ..Default::default()
                };
            }
        };

        let ledger = match self.store.load() {
            Ok(ledger) => ledger,
            Err(error) => {
                tracing::error!(%error, "failed to load committed ledger state");

                return ResponseCheckTx {
                    code: 1,
                    log: format!("failed to load committed ledger state: {error}"),
                    ..Default::default()
                };
            }
        };

        let identity = apply_one(&ledger, &event);

        let code = if identity.is_ok() { 0 } else { 1 };
        let log = if let Err(error) = identity {
            format!("failed to apply tx: {error}")
        } else {
            "".to_string()
        };

        ResponseCheckTx {
            code,
            log,
            ..Default::default()
        }
    }

    fn finalize_block(&self, request: RequestFinalizeBlock) -> ResponseFinalizeBlock {
        let height = u64::try_from(request.height)
            .map(Height::from_u64)
            .unwrap_or_else(|error| {
                tracing::error!(%error, height = request.height, "invalid block height");

                panic!("invalid block height");
            });

        let mut state = self.store.load().unwrap_or_else(|error| {
            tracing::error!(%error, "failed to load committed ledger state");

            panic!("failed to load committed ledger state");
        });

        let mut changed = BTreeMap::new();
        let mut events = Vec::new();
        let mut results = Vec::with_capacity(request.txs.len());

        for tx in request.txs {
            let event = match decode::<SignedIdentityEvent>(&tx) {
                Ok(event) => event,
                Err(error) => {
                    results.push(ExecTxResult {
                        code: 1,
                        log: error.to_string(),
                        ..Default::default()
                    });

                    continue;
                }
            };

            match apply_one(&state, &event) {
                Ok(next) => {
                    events.push(event);
                    changed.insert(*next.id(), next.clone());

                    let mut identities = state.identities().clone();
                    identities.insert(*next.id(), next);

                    state = LedgerState::from_identities(identities);

                    results.push(ExecTxResult::default());
                }
                Err(error) => results.push(ExecTxResult {
                    code: 1,
                    log: error.to_string(),
                    ..Default::default()
                }),
            }
        }

        let root = self
            .store
            .preview_root(height, &changed)
            .unwrap_or_else(|error| {
                tracing::error!(%error, height = height.as_u64(), "failed to preview ledger root");

                panic!("failed to preview ledger root");
            })
            .as_ref()
            .to_vec();

        let mut pending = self.pending.lock().unwrap_or_else(|error| {
            tracing::error!(%error, "pending commit mutex poisoned");

            panic!("pending commit mutex poisoned");
        });

        *pending = Some(PendingCommit {
            height,
            changed,
            events,
            root: root.clone(),
        });

        ResponseFinalizeBlock {
            tx_results: results,
            app_hash: root.into(),
            ..Default::default()
        }
    }

    fn commit(&self) -> ResponseCommit {
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(|error| {
                tracing::error!(%error, "pending commit mutex poisoned");

                panic!("pending commit mutex poisoned");
            })
            .take()
            .unwrap_or_else(|| {
                tracing::error!("commit called without a finalized block");

                panic!("commit called without a finalized block");
            });

        let root = self
            .store
            .commit(pending.height, &pending.changed, &pending.events)
            .unwrap_or_else(|error| {
                tracing::error!(
                    %error,
                    height = pending.height.as_u64(),
                    "failed to commit ledger state"
                );

                panic!("failed to commit ledger state");
            });

        assert_eq!(
            root.as_ref(),
            pending.root,
            "committed ledger root differs from finalized root"
        );

        ResponseCommit::default()
    }
}

fn query_error(log: impl Into<String>) -> ResponseQuery {
    ResponseQuery {
        code: 1,
        log: log.into(),
        ..Default::default()
    }
}

fn response_height(height: u64) -> Result<i64, Box<ResponseQuery>> {
    i64::try_from(height).map_err(|error| {
        tracing::error!(%error, height, "committed ledger height exceeds i64");

        Box::new(query_error("committed ledger height exceeds i64"))
    })
}

#[cfg(test)]
mod tests {
    use anchor_codec::{decode, decode_list};
    use anchor_commitment::Jmt;
    use anchor_proof::IdentityStateProof;
    use anchor_storage::LedgerStore;
    use anchor_testing::{deactivate_event, inception_event, signing_key};
    use anyhow::Result;
    use jmt::RootHash;
    use tempfile::NamedTempFile;
    use tendermint_proto::v0_38::abci::{
        RequestCheckTx, RequestFinalizeBlock, RequestInfo, RequestQuery,
    };

    use super::*;

    fn app() -> Result<(LedgerApplication, NamedTempFile)> {
        let file = NamedTempFile::new()?;
        let store = Arc::new(LedgerStore::open(file.path())?);

        Ok((LedgerApplication::new(store), file))
    }

    #[test]
    fn info_reports_zero_height_and_empty_hash_before_any_commit() -> Result<()> {
        let (app, _file) = app()?;

        let response = app.info(RequestInfo::default());

        assert_eq!(response.last_block_height, 0);
        assert!(response.last_block_app_hash.is_empty());

        Ok(())
    }

    #[test]
    fn check_tx_accepts_a_valid_transaction() -> Result<()> {
        let (app, _file) = app()?;
        let signer = signing_key(0x11);
        let (tx, _) = inception_event(&signer, 0x22)?;

        let response = app.check_tx(RequestCheckTx {
            tx: encode(&tx)?.into(),
            r#type: 0,
        });

        assert_eq!(response.code, 0);

        Ok(())
    }

    #[test]
    fn check_tx_rejects_malformed_bytes_without_panicking() -> Result<()> {
        let (app, _file) = app()?;

        let response = app.check_tx(RequestCheckTx {
            tx: vec![0xff, 0x00, 0x01].into(),
            r#type: 0,
        });

        assert_ne!(response.code, 0);
        assert!(!response.log.is_empty());

        Ok(())
    }

    #[test]
    fn check_tx_rejects_a_transaction_that_fails_to_apply() -> Result<()> {
        let file = NamedTempFile::new()?;
        let signer = signing_key(0x11);
        let (tx, _) = inception_event(&signer, 0x22)?;

        {
            let state = apply_one(&LedgerState::empty(), &tx)?;
            let mut identities = BTreeMap::new();
            identities.insert(*state.id(), state);
            let store = LedgerStore::open(file.path())?;
            store.commit(Height::from_u64(1), &identities, &[])?;
        }

        let store = Arc::new(LedgerStore::open(file.path())?);
        let app = LedgerApplication::new(store);

        let response = app.check_tx(RequestCheckTx {
            tx: encode(&tx)?.into(),
            r#type: 0,
        });

        assert_ne!(response.code, 0);

        Ok(())
    }

    #[test]
    fn finalize_block_buffers_without_writing_to_storage() -> Result<()> {
        let (app, file) = app()?;
        let signer = signing_key(0x11);
        let (tx, _) = inception_event(&signer, 0x22)?;

        let response = app.finalize_block(RequestFinalizeBlock {
            txs: vec![encode(&tx)?.into()],
            height: 1,
            ..Default::default()
        });

        assert_eq!(response.tx_results.len(), 1);
        assert_eq!(response.tx_results[0].code, 0);
        assert!(!response.app_hash.is_empty());

        drop(app);

        let store = LedgerStore::open(file.path())?;
        assert_eq!(store.height()?, 0);
        assert!(store.load()?.identities().is_empty());

        Ok(())
    }

    #[test]
    fn finalize_block_marks_a_bad_tx_and_still_applies_the_rest() -> Result<()> {
        let (app, _file) = app()?;
        let signer = signing_key(0x11);
        let (valid, _) = inception_event(&signer, 0x22)?;
        let malformed = vec![0xff, 0x00];

        let response = app.finalize_block(RequestFinalizeBlock {
            txs: vec![malformed.into(), encode(&valid)?.into()],
            height: 1,
            ..Default::default()
        });

        assert_eq!(response.tx_results.len(), 2);
        assert_ne!(response.tx_results[0].code, 0);
        assert_eq!(response.tx_results[1].code, 0);

        Ok(())
    }

    #[test]
    fn commit_writes_the_finalized_block_and_matches_its_root() -> Result<()> {
        let (app, file) = app()?;
        let signer = signing_key(0x11);
        let (tx, _) = inception_event(&signer, 0x22)?;

        let finalize_response = app.finalize_block(RequestFinalizeBlock {
            txs: vec![encode(&tx)?.into()],
            height: 1,
            ..Default::default()
        });

        app.commit();
        drop(app);

        let store = LedgerStore::open(file.path())?;
        assert_eq!(store.height()?, 1);
        assert_eq!(store.load()?.identities().len(), 1);
        assert_eq!(
            store.state_root(Height::from_u64(1))?.as_ref(),
            finalize_response.app_hash
        );

        Ok(())
    }

    #[test]
    fn committed_events_are_returned_by_the_paginated_history_query() -> Result<()> {
        let (app, _file) = app()?;
        let signer = signing_key(0x11);
        let (tx, id) = inception_event(&signer, 0x22)?;
        let expected = tx.clone();

        app.finalize_block(RequestFinalizeBlock {
            txs: vec![encode(&tx)?.into()],
            height: 1,
            ..Default::default()
        });
        app.commit();

        let mut data = Vec::from(id.to_bytes());
        data.extend_from_slice(&0_u64.to_be_bytes());
        data.extend_from_slice(&1_u32.to_be_bytes());
        let response = app.query(RequestQuery {
            path: IDENTITY_HISTORY_QUERY_PATH.to_string(),
            data: data.into(),
            ..Default::default()
        });

        assert_eq!(response.code, 0);
        assert_eq!(
            decode_list::<SignedIdentityEvent>(&response.value, 1)?,
            vec![expected]
        );

        Ok(())
    }

    #[test]
    fn history_retains_multiple_events_for_one_identity_in_the_same_block() -> Result<()> {
        let (app, _file) = app()?;
        let signer = signing_key(0x11);
        let (inception, id) = inception_event(&signer, 0x22)?;
        let state = apply_one(&LedgerState::empty(), &inception)?;
        let deactivation = deactivate_event(&state, &signer)?;

        app.finalize_block(RequestFinalizeBlock {
            txs: vec![encode(&inception)?.into(), encode(&deactivation)?.into()],
            height: 1,
            ..Default::default()
        });
        app.commit();

        let mut data = Vec::from(id.to_bytes());
        data.extend_from_slice(&0_u64.to_be_bytes());
        data.extend_from_slice(&2_u32.to_be_bytes());
        let response = app.query(RequestQuery {
            path: IDENTITY_HISTORY_QUERY_PATH.to_string(),
            data: data.into(),
            ..Default::default()
        });

        assert_eq!(response.code, 0);
        assert_eq!(
            decode_list::<SignedIdentityEvent>(&response.value, 2)?,
            vec![inception, deactivation]
        );

        Ok(())
    }

    #[test]
    fn info_reflects_a_committed_block() -> Result<()> {
        let (app, _file) = app()?;
        let signer = signing_key(0x11);
        let (tx, _) = inception_event(&signer, 0x22)?;

        app.finalize_block(RequestFinalizeBlock {
            txs: vec![encode(&tx)?.into()],
            height: 1,
            ..Default::default()
        });
        app.commit();

        let response = app.info(RequestInfo::default());

        assert_eq!(response.last_block_height, 1);
        assert!(!response.last_block_app_hash.is_empty());

        Ok(())
    }

    #[test]
    #[should_panic(expected = "commit called without a finalized block")]
    fn commit_panics_without_a_prior_finalize_block() {
        let (app, _file) = app().unwrap();

        app.commit();
    }

    #[test]
    fn query_rejects_unsupported_path() -> Result<()> {
        let (app, _file) = app()?;

        let response = app.query(RequestQuery {
            path: "/nope".to_string(),
            ..Default::default()
        });

        assert_ne!(response.code, 0);

        Ok(())
    }

    #[test]
    fn query_rejects_malformed_identity_bytes() -> Result<()> {
        let (app, _file) = app()?;

        let response = app.query(RequestQuery {
            path: IDENTITY_QUERY_PATH.to_string(),
            data: vec![0xaa; 4].into(),
            ..Default::default()
        });

        assert_ne!(response.code, 0);

        Ok(())
    }

    #[test]
    fn query_returns_empty_value_and_a_valid_absence_proof_for_an_unknown_identity() -> Result<()> {
        let (app, _file) = app()?;
        let unknown = IdentityId::from_bytes([0x99; 32]);

        let response = app.query(RequestQuery {
            path: IDENTITY_QUERY_PATH.to_string(),
            data: unknown.to_bytes().to_vec().into(),
            prove: true,
            ..Default::default()
        });

        assert_eq!(response.code, 0);
        assert!(response.value.is_empty());

        let proof_ops = response.proof_ops.expect("absence proof should be present");
        let proof = IdentityStateProof::from_bytes(&proof_ops.ops[0].data)?;
        proof.verify_nonexistence(Jmt::<LedgerStore>::EMPTY_ROOT, unknown)?;

        Ok(())
    }

    #[test]
    fn query_at_height_zero_reads_the_latest_committed_state_with_a_verifiable_proof() -> Result<()>
    {
        let (app, _file) = app()?;
        let signer = signing_key(0x11);
        let (tx, id) = inception_event(&signer, 0x22)?;

        app.finalize_block(RequestFinalizeBlock {
            txs: vec![encode(&tx)?.into()],
            height: 1,
            ..Default::default()
        });
        app.commit();
        let info = app.info(RequestInfo::default());
        let root: [u8; 32] = info.last_block_app_hash.to_vec().try_into().unwrap();
        let root = RootHash::from(root);

        let response = app.query(RequestQuery {
            path: IDENTITY_QUERY_PATH.to_string(),
            data: id.to_bytes().to_vec().into(),
            prove: true,
            ..Default::default()
        });

        assert_eq!(response.code, 0);
        assert_eq!(response.height, 1);

        let state = decode::<IdentityState>(&response.value)?;
        assert_eq!(state.id(), &id);

        let proof_ops = response
            .proof_ops
            .expect("existence proof should be present");
        assert_eq!(proof_ops.ops[0].r#type, IDENTITY_STATE_PROOF_OP);
        let proof = IdentityStateProof::from_bytes(&proof_ops.ops[0].data)?;
        proof.verify_existence(root, id, &state)?;

        Ok(())
    }

    #[test]
    fn query_without_prove_omits_proof_ops() -> Result<()> {
        let (app, _file) = app()?;
        let signer = signing_key(0x11);
        let (tx, id) = inception_event(&signer, 0x22)?;

        app.finalize_block(RequestFinalizeBlock {
            txs: vec![encode(&tx)?.into()],
            height: 1,
            ..Default::default()
        });
        app.commit();

        let response = app.query(RequestQuery {
            path: IDENTITY_QUERY_PATH.to_string(),
            data: id.to_bytes().to_vec().into(),
            prove: false,
            ..Default::default()
        });

        assert_eq!(response.code, 0);
        assert!(response.proof_ops.is_none());

        Ok(())
    }
}
