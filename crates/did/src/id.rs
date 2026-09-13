use anchor_identity::IdentityId;
use multibase::Base;
use ssi::dids::{DID, DIDBuf};

use crate::DidError;

const METHOD_NAME: &str = "ferna";

/// Formats an identity ID as a `did:ferna` identifier.
pub fn to_did(id: &IdentityId) -> DIDBuf {
    let encoded = multibase::encode(Base::Base58Btc, id.as_bytes());

    DIDBuf::from_string(format!("did:{METHOD_NAME}:{encoded}"))
        .expect("a multibase string is always a valid DID method-specific-id")
}

/// Parses a `did:ferna` identifier back into its identity ID.
pub fn parse_did(input: &str) -> Result<IdentityId, DidError> {
    let did = DID::new(input).map_err(|_| DidError::UnsupportedDid(input.to_string()))?;

    if did.method_name() != METHOD_NAME {
        return Err(DidError::UnsupportedDid(input.to_string()));
    }

    let (base, bytes) = multibase::decode(did.method_specific_id())?;
    let actual = bytes.len();

    if base != Base::Base58Btc {
        return Err(DidError::UnsupportedDid(input.to_string()));
    }

    IdentityId::from_slice(&bytes).ok_or(DidError::InvalidIdentityIdLength { actual })
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;

    #[test]
    fn did_round_trips_through_an_identity_id() -> Result<()> {
        let id = IdentityId::from_bytes([0x42; 32]);
        let did = to_did(&id);

        assert!(did.as_str().starts_with("did:ferna:"));
        assert_eq!(parse_did(did.as_str())?, id);

        Ok(())
    }

    #[test]
    fn different_identity_ids_produce_different_dids() {
        let first = to_did(&IdentityId::from_bytes([0x11; 32]));
        let second = to_did(&IdentityId::from_bytes([0x22; 32]));

        assert_ne!(first, second);
    }

    #[test]
    fn parse_did_rejects_a_different_method() {
        let result = parse_did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");

        assert!(matches!(result, Err(DidError::UnsupportedDid(_))));
    }

    #[test]
    fn parse_did_rejects_malformed_did_syntax() {
        let result = parse_did("not a did at all");

        assert!(matches!(result, Err(DidError::UnsupportedDid(_))));
    }

    #[test]
    fn parse_did_rejects_a_non_base58btc_encoding() {
        let result = parse_did("did:ferna:mAAAA");

        assert!(matches!(result, Err(DidError::UnsupportedDid(_))));
    }

    #[test]
    fn parse_did_rejects_the_wrong_byte_length() {
        let short = format!(
            "did:ferna:{}",
            multibase::encode(Base::Base58Btc, [0x01, 0x02, 0x03])
        );

        let result = parse_did(&short);

        assert!(matches!(
            result,
            Err(DidError::InvalidIdentityIdLength { actual: 3 })
        ));
    }
}
