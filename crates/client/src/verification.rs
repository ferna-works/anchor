use std::time::Duration;
use tendermint::{AppHash, block::signed_header::SignedHeader};
use tendermint_light_client_verifier::{ProdVerifier, Verdict, types::UntrustedBlockState};

use crate::{TrustedChain, VerificationError};

pub struct VerificationPolicy {
    pub max_header_age: Duration,
    pub max_clock_drift: Duration,
}

pub(crate) fn verify_signed_header(
    trusted: &TrustedChain,
    policy: &VerificationPolicy,
    signed_header: &SignedHeader,
    now: tendermint::Time,
) -> Result<AppHash, VerificationError> {
    if signed_header.header.chain_id != trusted.chain_id {
        return Err(VerificationError::ChainIdMismatch {
            expected: trusted.chain_id.to_string(),
            actual: signed_header.header.chain_id.to_string(),
        });
    }

    verify_header_freshness(signed_header.header.time, now, policy)?;

    if signed_header.header.validators_hash != trusted.validators.hash() {
        return Err(VerificationError::ValidatorSetMismatch);
    }

    let untrusted = UntrustedBlockState {
        signed_header,
        validators: &trusted.validators,
        next_validators: None,
    };

    let verifier = ProdVerifier::default();

    require_success(verifier.verify_validator_sets(&untrusted))?;
    require_success(verifier.verify_commit(&untrusted))?;

    Ok(signed_header.header.app_hash.clone())
}

fn verify_header_freshness(
    header_time: tendermint::Time,
    now: tendermint::Time,
    policy: &VerificationPolicy,
) -> Result<(), VerificationError> {
    if header_time > now {
        let drift = header_time
            .duration_since(now)
            .map_err(|_| VerificationError::HeaderFromFuture)?;

        if drift > policy.max_clock_drift {
            return Err(VerificationError::HeaderFromFuture);
        }
    } else {
        let age = now
            .duration_since(header_time)
            .map_err(|_| VerificationError::StaleHeader)?;

        if age > policy.max_header_age {
            return Err(VerificationError::StaleHeader);
        }
    }

    Ok(())
}

fn require_success(verdict: Verdict) -> Result<(), VerificationError> {
    match verdict {
        Verdict::Success => Ok(()),
        Verdict::NotEnoughTrust(tally) => Err(VerificationError::InvalidCommit(format!(
            "insufficient voting power: {tally}"
        ))),
        Verdict::Invalid(error) => Err(VerificationError::InvalidCommit(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use anyhow::Result;
    use tendermint::{Hash, Time, block::CommitSig};

    use super::*;

    fn trusted_chain() -> Result<TrustedChain> {
        Ok(TrustedChain::from_genesis_json(include_str!(
            "../../../vectors/devnet-genesis.json"
        ))?)
    }

    fn signed_header() -> Result<SignedHeader> {
        Ok(serde_json::from_str(include_str!(
            "../../../vectors/signed-header.json"
        ))?)
    }

    fn time(seconds: i64) -> Result<Time> {
        Ok(Time::from_unix_timestamp(seconds, 0)?)
    }

    fn freshness_policy() -> VerificationPolicy {
        VerificationPolicy {
            max_header_age: Duration::from_secs(60),
            max_clock_drift: Duration::from_secs(5),
        }
    }

    fn verify_fixture(
        trusted: &TrustedChain,
        signed_header: &SignedHeader,
    ) -> std::result::Result<AppHash, VerificationError> {
        verify_signed_header(
            trusted,
            &freshness_policy(),
            signed_header,
            signed_header.header.time,
        )
    }

    #[test]
    fn accepts_a_recent_header() -> Result<()> {
        verify_header_freshness(time(970)?, time(1_000)?, &freshness_policy())?;

        Ok(())
    }

    #[test]
    fn accepts_a_header_exactly_at_the_maximum_age() -> Result<()> {
        verify_header_freshness(time(940)?, time(1_000)?, &freshness_policy())?;

        Ok(())
    }

    #[test]
    fn rejects_a_header_older_than_the_maximum_age() -> Result<()> {
        let result = verify_header_freshness(time(939)?, time(1_000)?, &freshness_policy());

        assert!(matches!(result, Err(VerificationError::StaleHeader)));

        Ok(())
    }

    #[test]
    fn accepts_a_future_header_within_the_clock_drift_allowance() -> Result<()> {
        verify_header_freshness(time(1_005)?, time(1_000)?, &freshness_policy())?;

        Ok(())
    }

    #[test]
    fn rejects_a_header_beyond_the_clock_drift_allowance() -> Result<()> {
        let result = verify_header_freshness(time(1_006)?, time(1_000)?, &freshness_policy());

        assert!(matches!(result, Err(VerificationError::HeaderFromFuture)));

        Ok(())
    }

    #[test]
    fn rejects_a_signed_header_from_a_different_chain() -> Result<()> {
        let mut trusted = trusted_chain()?;
        trusted.chain_id = "different-chain".parse()?;
        let signed_header = signed_header()?;

        let result = verify_fixture(&trusted, &signed_header);

        assert!(matches!(
            result,
            Err(VerificationError::ChainIdMismatch { .. })
        ));

        Ok(())
    }

    #[test]
    fn rejects_a_header_whose_validator_hash_does_not_match_genesis() -> Result<()> {
        let trusted = trusted_chain()?;
        let mut signed_header = signed_header()?;
        signed_header.header.validators_hash = Hash::Sha256([0; 32]);

        let result = verify_fixture(&trusted, &signed_header);

        assert!(matches!(
            result,
            Err(VerificationError::ValidatorSetMismatch)
        ));

        Ok(())
    }

    #[test]
    fn accepts_a_genuine_commit_from_more_than_two_thirds_of_the_trusted_set() -> Result<()> {
        let trusted = trusted_chain()?;
        let signed_header = signed_header()?;
        let expected_app_hash = signed_header.header.app_hash.clone();

        let app_hash = verify_fixture(&trusted, &signed_header)?;

        assert_eq!(app_hash, expected_app_hash);

        Ok(())
    }

    #[test]
    fn rejects_a_commit_that_names_a_different_header_hash() -> Result<()> {
        let trusted = trusted_chain()?;
        let mut signed_header = signed_header()?;
        signed_header.commit.block_id.hash = Hash::Sha256([0; 32]);

        let result = verify_fixture(&trusted, &signed_header);

        assert!(matches!(result, Err(VerificationError::InvalidCommit(_))));

        Ok(())
    }

    #[test]
    fn rejects_a_commit_with_a_signature_from_a_different_validator() -> Result<()> {
        let trusted = trusted_chain()?;
        let mut json: serde_json::Value =
            serde_json::from_str(include_str!("../../../vectors/signed-header.json"))?;
        let replacement = json["commit"]["signatures"][1]["signature"].clone();
        json["commit"]["signatures"][0]["signature"] = replacement;
        let signed_header: SignedHeader = serde_json::from_value(json)?;

        let result = verify_fixture(&trusted, &signed_header);

        assert!(matches!(result, Err(VerificationError::InvalidCommit(_))));

        Ok(())
    }

    #[test]
    fn rejects_a_commit_without_more_than_two_thirds_of_the_trusted_voting_power() -> Result<()> {
        let trusted = trusted_chain()?;
        let mut signed_header = signed_header()?;
        signed_header.commit.signatures[0] = CommitSig::BlockIdFlagAbsent;
        signed_header.commit.signatures[1] = CommitSig::BlockIdFlagAbsent;

        let result = verify_fixture(&trusted, &signed_header);

        assert!(matches!(result, Err(VerificationError::InvalidCommit(_))));

        Ok(())
    }
}
