use anchor_codec::decode_list;
use anchor_identity::{
    IdentityId, IdentityState, Sequence, SignedIdentityEvent, apply_inception, apply_ordinary_event,
};

use crate::{ClientError, RpcClient, TrustedChain, VerificationPolicy, query};

const HISTORY_PAGE_SIZE: u32 = 64;

pub struct HistoryResult {
    pub height: u64,
    pub state: IdentityState,
    pub events: Vec<SignedIdentityEvent>,
}

/// Fetches and replays an identity's complete signed event history, verifying it matches the
/// proven current state. Individual events aren't Merkle-proven on their own; trust comes from
/// the replay landing exactly on the state `query` already verified.
pub async fn history(
    client: &RpcClient,
    trusted: &TrustedChain,
    policy: &VerificationPolicy,
    id: IdentityId,
) -> Result<HistoryResult, ClientError> {
    let current = query(client, trusted, policy, id).await?;
    let expected = current.state.ok_or(ClientError::UnknownIdentity(id))?;
    let event_count = expected
        .sequence()
        .as_u64()
        .checked_add(1)
        .ok_or(ClientError::SequenceExhausted)?;
    let mut events = Vec::new();

    while (events.len() as u64) < event_count {
        let from = events.len() as u64;
        let remaining = event_count - from;
        let limit = remaining.min(u64::from(HISTORY_PAGE_SIZE)) as u32;
        let response = client.abci_history(id.to_bytes(), from, limit).await?;

        if response.code != 0 {
            return Err(ClientError::QueryFailed(response.log));
        }

        let page = decode_list::<SignedIdentityEvent>(&response.value, HISTORY_PAGE_SIZE as usize)?;

        if page.is_empty() {
            return Err(ClientError::IncompleteHistory {
                expected: event_count,
                actual: events.len() as u64,
            });
        }

        events.extend(page);
    }

    if events.len() as u64 != event_count {
        return Err(ClientError::IncompleteHistory {
            expected: event_count,
            actual: events.len() as u64,
        });
    }

    verify_complete_history(id, &expected, &events)?;

    Ok(HistoryResult {
        height: current.height,
        state: expected,
        events,
    })
}

fn verify_complete_history(
    id: IdentityId,
    expected: &IdentityState,
    events: &[SignedIdentityEvent],
) -> Result<(), ClientError> {
    let Some(inception) = events.first() else {
        return Err(ClientError::IncompleteHistory {
            expected: expected.sequence().as_u64().saturating_add(1),
            actual: 0,
        });
    };

    let mut replayed =
        apply_inception(inception).map_err(|source| ClientError::InvalidHistory {
            sequence: Sequence::ZERO,
            source,
        })?;

    if replayed.id() != &id {
        return Err(ClientError::HistoryIdentityMismatch);
    }

    for event in &events[1..] {
        let sequence = event
            .as_ordinary()
            .map(|signed| signed.event().sequence())
            .unwrap_or(Sequence::ZERO);

        replayed = apply_ordinary_event(&replayed, event)
            .map_err(|source| ClientError::InvalidHistory { sequence, source })?;
    }

    if replayed != *expected {
        return Err(ClientError::HistoryStateMismatch);
    }

    Ok(())
}
