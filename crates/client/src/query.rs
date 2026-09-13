use anchor_codec::decode;
use anchor_identity::{IdentityId, IdentityState};
use anchor_proof::IdentityStateProof;
use jmt::RootHash;

use crate::{
    ClientError, RpcClient, TrustedChain, VerificationPolicy, verification::verify_signed_header,
};

pub struct QueryResult {
    pub height: u64,
    pub state: Option<IdentityState>,
}

/// Queries an identity's state at the latest verifiable height, verifying the signed header and
/// Merkle proof. The queried height trails the signed header by one block, since a header's
/// app_hash commits to the state after the *previous* block.
pub async fn query(
    client: &RpcClient,
    trusted: &TrustedChain,
    policy: &VerificationPolicy,
    id: IdentityId,
) -> Result<QueryResult, ClientError> {
    let (signed_header, response) = client
        .identity_state_at_latest_verifiable_height(id.to_bytes())
        .await?;

    let app_hash = verify_signed_header(trusted, policy, &signed_header, tendermint::Time::now())?;
    let app_hash_length = app_hash.as_bytes().len();
    let root_bytes: [u8; 32] =
        app_hash
            .as_bytes()
            .try_into()
            .map_err(|_| ClientError::InvalidAppHashLength {
                actual: app_hash_length,
            })?;
    let root = RootHash::from(root_bytes);

    if response.code != 0 {
        return Err(ClientError::QueryFailed(response.log));
    }

    let proof_bytes = response.proof.ok_or(ClientError::MissingProof)?;
    let proof = IdentityStateProof::from_bytes(&proof_bytes)?;

    if response.value.is_empty() {
        proof.verify_nonexistence(root, id)?;

        return Ok(QueryResult {
            height: response.height,
            state: None,
        });
    }

    let state = decode::<IdentityState>(&response.value)?;
    proof.verify_existence(root, id, &state)?;

    Ok(QueryResult {
        height: response.height,
        state: Some(state),
    })
}

pub(crate) async fn fetch_state_unverified(
    client: &RpcClient,
    id: IdentityId,
) -> Result<Option<IdentityState>, ClientError> {
    let response = client.abci_query(id.to_bytes(), 0, false).await?;

    if response.code != 0 {
        return Err(ClientError::QueryFailed(response.log));
    }

    if response.value.is_empty() {
        return Ok(None);
    }

    Ok(Some(decode::<IdentityState>(&response.value)?))
}
