use serde::Deserialize;
use tendermint::{
    account::Id as AccountId,
    chain::Id as ChainId,
    validator::{Info, Set},
};

use crate::TrustedError;

pub struct TrustedChain {
    pub(crate) chain_id: ChainId,
    pub(crate) validators: Set,
}

impl TrustedChain {
    /// Builds a trust root from a CometBFT genesis file's chain ID and validator set. Validates
    /// that each validator's address matches its public key and that total voting power can't
    /// overflow.
    pub fn from_genesis_json(json: &str) -> Result<Self, TrustedError> {
        let genesis: TrustedGenesis = serde_json::from_str(json)?;

        if genesis.validators.is_empty() {
            return Err(TrustedError::EmptyValidatorSet);
        }

        let total_voting_power =
            genesis
                .validators
                .iter()
                .try_fold(0_u64, |total, validator| {
                    total
                        .checked_add(validator.power())
                        .ok_or(TrustedError::InvalidTotalVotingPower)
                })?;

        // Check if the total voting power exceeds the maximum allowed value;
        // `Set::without_proposer` can panic if we don't.
        if total_voting_power > Set::MAX_TOTAL_VOTING_POWER {
            return Err(TrustedError::InvalidTotalVotingPower);
        }

        for validator in &genesis.validators {
            let expected_address = AccountId::from(validator.pub_key);

            if validator.address != expected_address {
                return Err(TrustedError::ValidatorAddressMismatch);
            }
        }

        Ok(Self {
            chain_id: genesis.chain_id,
            validators: Set::without_proposer(genesis.validators),
        })
    }
}

#[derive(Deserialize)]
struct TrustedGenesis {
    chain_id: ChainId,
    validators: Vec<Info>,
}

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result};

    use super::*;

    #[test]
    fn parses_testnet_genesis() -> Result<()> {
        let json = include_str!("../../../vectors/devnet-genesis.json");

        let trusted = TrustedChain::from_genesis_json(json)?;

        assert_eq!(trusted.chain_id.as_str(), "anchor-devnet");
        assert_eq!(trusted.validators.validators().len(), 4);
        assert_eq!(trusted.validators.total_voting_power().value(), 4);
        assert!(trusted.validators.proposer().is_none());

        Ok(())
    }

    #[test]
    fn rejects_an_empty_validator_set() {
        let json = r#"{
              "chain_id": "chain-test",
              "validators": []
          }"#;

        let result = TrustedChain::from_genesis_json(json);

        assert!(matches!(result, Err(TrustedError::EmptyValidatorSet)));
    }

    #[test]
    fn rejects_malformed_genesis_json() {
        let result = TrustedChain::from_genesis_json(r#"{"chain_id":"chain-test""#);

        assert!(matches!(result, Err(TrustedError::GenesisJson(_))));
    }

    #[test]
    fn rejects_a_validator_address_that_does_not_match_its_public_key() {
        let json = r#"{
            "chain_id": "chain-test",
            "validators": [
                {
                    "address": "9D24C5C697BB50A404F189C2F5DE4548D8C9DEDB",
                    "pub_key": {
                        "type": "tendermint/PubKeyEd25519",
                        "value": "zOoPe9epbVhY8TpLi9/b1+pg3Ey9jYlImTdcH/p8vjs="
                    },
                    "power": "1",
                    "name": "mismatched-validator"
                }
            ]
        }"#;

        let result = TrustedChain::from_genesis_json(json);

        assert!(matches!(
            result,
            Err(TrustedError::ValidatorAddressMismatch)
        ));
    }

    #[test]
    fn rejects_total_voting_power_that_would_make_validator_set_construction_panic() -> Result<()> {
        let mut genesis: serde_json::Value =
            serde_json::from_str(include_str!("../../../vectors/devnet-genesis.json"))?;
        let validators = genesis["validators"]
            .as_array_mut()
            .context("test genesis validators must be an array")?;

        validators.truncate(2);

        for validator in validators {
            validator["power"] = Set::MAX_TOTAL_VOTING_POWER.to_string().into();
        }

        let result = TrustedChain::from_genesis_json(&genesis.to_string());

        assert!(matches!(result, Err(TrustedError::InvalidTotalVotingPower)));

        Ok(())
    }

    #[test]
    fn validator_set_hash_does_not_depend_on_genesis_validator_order() -> Result<()> {
        let json = include_str!("../../../vectors/devnet-genesis.json");
        let original = TrustedChain::from_genesis_json(json)?;

        let mut reordered_genesis: serde_json::Value = serde_json::from_str(json)?;
        reordered_genesis["validators"]
            .as_array_mut()
            .context("test genesis validators must be an array")?
            .reverse();
        let reordered = TrustedChain::from_genesis_json(&reordered_genesis.to_string())?;

        assert_eq!(original.validators.hash(), reordered.validators.hash());

        Ok(())
    }
}
