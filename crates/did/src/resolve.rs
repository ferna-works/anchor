use anchor_client::{QueryResult, RpcClient, TrustedChain, VerificationPolicy, query};
use ssi::dids::document::{
    Document,
    representation::{JsonLd, json_ld::Options},
};

use crate::{
    DidError,
    document::build_document,
    id::{parse_did, to_did},
};

pub enum Resolution {
    Found {
        document: Box<Document>,
        height: u64,
    },
    Deactivated {
        height: u64,
    },
    NotFound {
        height: u64,
    },
}

/// Resolves a `did:ferna` identifier to its DID Document, verifying the underlying ledger state.
pub async fn resolve(
    client: &RpcClient,
    trusted: &TrustedChain,
    policy: &VerificationPolicy,
    did: &str,
) -> Result<Resolution, DidError> {
    let id = parse_did(did)?;
    let QueryResult { height, state } = query(client, trusted, policy, id).await?;

    let Some(state) = state else {
        return Ok(Resolution::NotFound { height });
    };

    if state.is_deactivated() {
        return Ok(Resolution::Deactivated { height });
    }

    Ok(Resolution::Found {
        document: Box::new(build_document(&to_did(&id), &state)),
        height,
    })
}

/// Renders a DID Document as pretty-printed JSON-LD.
pub fn to_json_pretty(document: &Document) -> Result<String, DidError> {
    let represented = JsonLd::new(document.clone(), Options::default());

    Ok(serde_json::to_string_pretty(&represented)?)
}
