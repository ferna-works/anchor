use anchor_codec::encode;
use anchor_commitment::LedgerHasher;
use anchor_identity::{IdentityId, IdentityState};
use jmt::{KeyHash, RootHash, proof::SparseMerkleProof};

use crate::ProofError;

/// Represents a proof of the existence of an identity in the ledger.
#[derive(Debug, Clone, PartialEq)]
pub struct IdentityStateProof {
    proof: SparseMerkleProof<LedgerHasher>,
}

// Borsh is used for serializing and deserializing the proof because
// `SparseMerkleProof` has no public constructor from raw parts,
// so there's no way to decode our own wire format back into one.
impl IdentityStateProof {
    /// Wraps a JMT sparse Merkle proof.
    pub fn new(proof: SparseMerkleProof<LedgerHasher>) -> Self {
        Self { proof }
    }

    /// Decodes a proof from its Borsh wire format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProofError> {
        let proof = borsh::from_slice(bytes)?;

        Ok(Self::new(proof))
    }

    /// Encodes the proof to its Borsh wire format.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProofError> {
        Ok(borsh::to_vec(&self.proof)?)
    }

    /// Verifies that `identity_state` is the value committed to `identity_id` under `root_hash`.
    pub fn verify_existence(
        &self,
        root_hash: RootHash,
        identity_id: IdentityId,
        identity_state: &IdentityState,
    ) -> Result<(), ProofError> {
        let encoded_state = encode(identity_state)?;

        Ok(self.proof.verify_existence(
            root_hash,
            KeyHash(identity_id.to_bytes()),
            encoded_state,
        )?)
    }

    /// Verifies that `identity_id` has no committed value under `root_hash`.
    pub fn verify_nonexistence(
        &self,
        root_hash: RootHash,
        identity_id: IdentityId,
    ) -> Result<(), ProofError> {
        Ok(self
            .proof
            .verify_nonexistence(root_hash, KeyHash(identity_id.to_bytes()))?)
    }
}

#[cfg(test)]
mod tests {
    use anchor_testing::{genesis_state as build_state, signing_key};
    use anyhow::Result;
    use jmt::{JellyfishMerkleTree, mock::MockTreeStore};

    use super::*;

    #[test]
    fn verify_existence_succeeds_for_a_real_proof_from_bytes_alone() -> Result<()> {
        let signer = signing_key(0x11);
        let state = build_state(&signer, 0x22)?;
        let store = MockTreeStore::new(true);
        let tree = JellyfishMerkleTree::<_, LedgerHasher>::new(&store);
        let key_hash = KeyHash(state.id().to_bytes());

        let (root, batch) = tree.put_value_set(vec![(key_hash, Some(encode(&state)?))], 0)?;
        store.write_tree_update_batch(batch)?;

        let (_, merkle_proof) = tree.get_with_proof(key_hash, 0)?;
        let bytes = IdentityStateProof::new(merkle_proof).to_bytes()?;

        let proof = IdentityStateProof::from_bytes(&bytes)?;
        proof.verify_existence(root, *state.id(), &state)?;

        Ok(())
    }

    #[test]
    fn verify_existence_fails_for_the_wrong_state() -> Result<()> {
        let signer = signing_key(0x11);
        let state = build_state(&signer, 0x22)?;
        let wrong_state = build_state(&signer, 0x33)?;
        let store = MockTreeStore::new(true);
        let tree = JellyfishMerkleTree::<_, LedgerHasher>::new(&store);
        let key_hash = KeyHash(state.id().to_bytes());

        let (root, batch) = tree.put_value_set(vec![(key_hash, Some(encode(&state)?))], 0)?;
        store.write_tree_update_batch(batch)?;

        let (_, merkle_proof) = tree.get_with_proof(key_hash, 0)?;
        let proof = IdentityStateProof::new(merkle_proof);

        assert!(
            proof
                .verify_existence(root, *state.id(), &wrong_state)
                .is_err()
        );

        Ok(())
    }

    #[test]
    fn proof_from_one_height_does_not_verify_against_a_later_roots_hash() -> Result<()> {
        let signer = signing_key(0x11);
        let unchanged = build_state(&signer, 0x22)?;
        let other = build_state(&signer, 0x33)?;
        let store = MockTreeStore::new(true);
        let tree = JellyfishMerkleTree::<_, LedgerHasher>::new(&store);
        let unchanged_key = KeyHash(unchanged.id().to_bytes());
        let other_key = KeyHash(other.id().to_bytes());

        let (root_0, batch_0) =
            tree.put_value_set(vec![(unchanged_key, Some(encode(&unchanged)?))], 0)?;
        store.write_tree_update_batch(batch_0)?;
        let (_, proof_at_0) = tree.get_with_proof(unchanged_key, 0)?;

        let (root_1, batch_1) = tree.put_value_set(vec![(other_key, Some(encode(&other)?))], 1)?;
        store.write_tree_update_batch(batch_1)?;

        assert_ne!(root_0, root_1);

        let proof = IdentityStateProof::new(proof_at_0);

        assert!(
            proof
                .verify_existence(root_0, *unchanged.id(), &unchanged)
                .is_ok()
        );
        assert!(
            proof
                .verify_existence(root_1, *unchanged.id(), &unchanged)
                .is_err(),
            "a proof captured at height 0 must not verify against height 1's root, \
             even though `unchanged`'s own value never changed"
        );

        Ok(())
    }

    #[test]
    fn verify_nonexistence_succeeds_for_an_absent_identity_and_fails_for_a_present_one()
    -> Result<()> {
        let signer = signing_key(0x11);
        let present = build_state(&signer, 0x22)?;
        let absent = build_state(&signer, 0x33)?;
        let store = MockTreeStore::new(true);
        let tree = JellyfishMerkleTree::<_, LedgerHasher>::new(&store);
        let present_key = KeyHash(present.id().to_bytes());
        let absent_key = KeyHash(absent.id().to_bytes());

        let (root, batch) = tree.put_value_set(vec![(present_key, Some(encode(&present)?))], 0)?;
        store.write_tree_update_batch(batch)?;

        let (_, absence_proof) = tree.get_with_proof(absent_key, 0)?;
        let proof = IdentityStateProof::new(absence_proof);
        proof.verify_nonexistence(root, *absent.id())?;

        let (_, presence_proof) = tree.get_with_proof(present_key, 0)?;
        let proof = IdentityStateProof::new(presence_proof);

        assert!(proof.verify_nonexistence(root, *present.id()).is_err());

        Ok(())
    }

    #[test]
    fn tampering_the_encoded_proof_bytes_fails_closed() -> Result<()> {
        let signer = signing_key(0x11);
        let state = build_state(&signer, 0x22)?;
        let store = MockTreeStore::new(true);
        let tree = JellyfishMerkleTree::<_, LedgerHasher>::new(&store);
        let key_hash = KeyHash(state.id().to_bytes());

        let (root, batch) = tree.put_value_set(vec![(key_hash, Some(encode(&state)?))], 0)?;
        store.write_tree_update_batch(batch)?;

        let (_, merkle_proof) = tree.get_with_proof(key_hash, 0)?;
        let bytes = IdentityStateProof::new(merkle_proof).to_bytes()?;

        IdentityStateProof::from_bytes(&bytes)?.verify_existence(root, *state.id(), &state)?;

        for index in 0..bytes.len() {
            let mut tampered = bytes.clone();
            tampered[index] ^= 0xff;

            let outcome = IdentityStateProof::from_bytes(&tampered)
                .and_then(|proof| proof.verify_existence(root, *state.id(), &state));

            assert!(
                outcome.is_err(),
                "tampering byte {index} must not silently verify"
            );
        }

        Ok(())
    }
}
