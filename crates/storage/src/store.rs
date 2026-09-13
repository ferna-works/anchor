use std::{collections::BTreeMap, path::Path, sync::Mutex};

use anchor_codec::{decode, encode};
use anchor_commitment::{Height, Jmt};
use anchor_identity::{
    IdentityId, IdentityState, Sequence, SignedIdentityEvent, derive_identity_id,
};
use anchor_proof::IdentityStateProof;
use anchor_state::LedgerState;
use jmt::{KeyHash, RootHash, storage::TreeUpdateBatch};
use redb::{Database, ReadableDatabase, ReadableTable};

use crate::{
    StorageError,
    schema::{
        HEIGHT_KEY, IDENTITIES_TABLE, IDENTITY_EVENTS_TABLE, JMT_HISTORY_TABLE, JMT_NODES_TABLE,
        META_TABLE,
    },
    tree::{history_key, versioned_key},
};

/// A ledger store backed by a redb database.
pub struct LedgerStore {
    database: Database,
    write_lock: Mutex<()>,
}

impl LedgerStore {
    pub(crate) fn database(&self) -> &Database {
        &self.database
    }

    /// Opens (or creates) a redb-backed ledger store at `path`.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let database = Database::create(path)?;
        let write = database.begin_write()?;

        write.open_table(META_TABLE)?;
        write.open_table(IDENTITIES_TABLE)?;
        write.open_table(IDENTITY_EVENTS_TABLE)?;
        write.open_table(JMT_NODES_TABLE)?;
        write.open_table(JMT_HISTORY_TABLE)?;

        write.commit()?;

        Ok(Self {
            database,
            write_lock: Mutex::new(()),
        })
    }

    /// Returns the height of the last committed block, or 0 if none has been committed.
    pub fn height(&self) -> Result<u64, StorageError> {
        let read = self.database.begin_read()?;

        let meta = read.open_table(META_TABLE)?;
        let height = meta
            .get(HEIGHT_KEY)?
            .map(|value| value.value())
            .unwrap_or(0);

        Ok(height)
    }

    /// Loads the full ledger state as of the last commit.
    pub fn load(&self) -> Result<LedgerState, StorageError> {
        let read = self.database.begin_read()?;

        let identities = read.open_table(IDENTITIES_TABLE)?;
        let mut collected = BTreeMap::new();

        for entry in identities.iter()? {
            let (_, bytes) = entry?;
            let state = decode::<IdentityState>(bytes.value())?;

            collected.insert(*state.id(), state);
        }

        Ok(LedgerState::from_identities(collected))
    }

    fn checked_update(
        &self,
        height: Height,
        changed: &BTreeMap<IdentityId, IdentityState>,
    ) -> Result<(RootHash, TreeUpdateBatch), StorageError> {
        let expected = self
            .height()?
            .checked_add(1)
            .expect("ledger height overflowed u64");

        if height.as_u64() != expected {
            return Err(StorageError::NonSequentialCommit {
                expected,
                actual: height.as_u64(),
            });
        }

        Ok(Jmt::new(self).put_value_set(value_set(changed)?, height.as_u64())?)
    }

    /// Durably writes changed identities and their events at `height`, advancing the ledger by one block.
    pub fn commit(
        &self,
        height: Height,
        changed: &BTreeMap<IdentityId, IdentityState>,
        events: &[SignedIdentityEvent],
    ) -> Result<RootHash, StorageError> {
        let _guard = self.write_lock.lock().expect("write lock poisoned");

        let (root, batch) = self.checked_update(height, changed)?;

        let write = self.database.begin_write()?;

        {
            let mut identities = write.open_table(IDENTITIES_TABLE)?;

            for (id, identity) in changed {
                let encoded = encode(identity)?;
                identities.insert(id.as_bytes().as_slice(), encoded.as_slice())?;
            }

            let mut event_log = write.open_table(IDENTITY_EVENTS_TABLE)?;

            for event in events {
                let (id, sequence) = event_position(event)?;
                let key = event_key(id, sequence);
                if event_log.get(key.as_slice())?.is_some() {
                    return Err(StorageError::EventAlreadyStored { id, sequence });
                }
                let encoded = encode(event)?;
                event_log.insert(key.as_slice(), encoded.as_slice())?;
            }

            let mut meta = write.open_table(META_TABLE)?;
            meta.insert(HEIGHT_KEY, height.as_u64())?;

            let mut nodes = write.open_table(JMT_NODES_TABLE)?;
            let mut history = write.open_table(JMT_HISTORY_TABLE)?;

            for (key, node) in batch.node_batch.nodes() {
                let node = borsh::to_vec(node)?;
                let key = borsh::to_vec(key)?;

                nodes.insert(key.as_slice(), node.as_slice())?;
            }

            for ((version, key_hash), value) in batch.node_batch.values() {
                let value = borsh::to_vec(value)?;
                let key = history_key(*key_hash, *version);

                history.insert(key.as_slice(), value.as_slice())?;
            }
        }

        write.commit()?;

        Ok(root)
    }

    /// Returns the committed state root at `height`.
    pub fn state_root(&self, height: Height) -> Result<RootHash, StorageError> {
        let height = height.as_u64();
        let root = Jmt::new(self).get_root_hash_option(height)?;

        match root {
            Some(root) => Ok(root),
            None if height == 0 => Ok(Jmt::<LedgerStore>::EMPTY_ROOT),
            None => Err(StorageError::MissingRoot { height }),
        }
    }

    /// Computes the state root `commit` would produce for `changed`, without writing anything.
    pub fn preview_root(
        &self,
        height: Height,
        changed: &BTreeMap<IdentityId, IdentityState>,
    ) -> Result<RootHash, StorageError> {
        let (root, _batch) = self.checked_update(height, changed)?;

        Ok(root)
    }

    /// Returns an identity's state at `height` along with a Merkle proof of its inclusion or absence.
    pub fn prove(
        &self,
        id: IdentityId,
        height: Height,
    ) -> Result<(Option<IdentityState>, IdentityStateProof), StorageError> {
        let (value, proof) =
            Jmt::new(self).get_with_proof(KeyHash(id.to_bytes()), height.as_u64())?;
        let state = value
            .map(|bytes| decode::<IdentityState>(&bytes))
            .transpose()?;

        Ok((state, IdentityStateProof::new(proof)))
    }

    /// Returns up to `limit` of an identity's stored events, starting at sequence `from`.
    pub fn event_log(
        &self,
        id: IdentityId,
        from: Sequence,
        limit: usize,
    ) -> Result<Vec<SignedIdentityEvent>, StorageError> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let read = self.database.begin_read()?;
        let events = read.open_table(IDENTITY_EVENTS_TABLE)?;
        let start = event_key(id, from);
        let end = event_key(id, Sequence::from_u64(u64::MAX));
        let mut collected = Vec::new();

        for entry in events.range(start.as_slice()..=end.as_slice())?.take(limit) {
            let (_, bytes) = entry?;
            collected.push(decode(bytes.value())?);
        }

        Ok(collected)
    }
}

type ValueSet = Vec<(KeyHash, Option<Vec<u8>>)>;

fn value_set(changed: &BTreeMap<IdentityId, IdentityState>) -> Result<ValueSet, StorageError> {
    let mut values = Vec::new();

    for (id, identity) in changed {
        values.push((KeyHash(id.to_bytes()), Some(encode(identity)?)));
    }

    Ok(values)
}

fn event_key(id: IdentityId, sequence: Sequence) -> [u8; 40] {
    versioned_key(id.as_bytes(), sequence.as_u64())
}

fn event_position(event: &SignedIdentityEvent) -> Result<(IdentityId, Sequence), StorageError> {
    match event {
        SignedIdentityEvent::Inception(inception) => {
            Ok((derive_identity_id(inception.inception())?, Sequence::ZERO))
        }
        SignedIdentityEvent::Ordinary(signed) => {
            Ok((*signed.event().identity(), signed.event().sequence()))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread};

    use anchor_state::apply_all;
    use anchor_testing::{inception_event, rotate_event, signing_key};
    use anyhow::{Context, Result};
    use tempfile::NamedTempFile;

    use super::*;

    fn open_store() -> Result<LedgerStore> {
        let file = NamedTempFile::new()?;

        Ok(LedgerStore::open(file.path())?)
    }

    #[test]
    fn open_creates_an_empty_store() -> Result<()> {
        let store = open_store()?;

        assert_eq!(store.height()?, 0);
        assert!(store.load()?.identities().is_empty());
        assert_eq!(
            store.state_root(Height::from_u64(0))?,
            Jmt::<LedgerStore>::EMPTY_ROOT
        );

        Ok(())
    }

    #[test]
    fn empty_committed_root_survives_reopen() -> Result<()> {
        let file = NamedTempFile::new()?;
        let height = Height::from_u64(1);

        let committed_root = {
            let store = LedgerStore::open(file.path())?;
            let root = store.commit(height, &BTreeMap::new(), &[])?;

            assert_eq!(root, Jmt::<LedgerStore>::EMPTY_ROOT);
            assert_eq!(store.state_root(height)?, root);

            root
        };

        let reopened = LedgerStore::open(file.path())?;

        assert_eq!(reopened.height()?, 1);
        assert_eq!(reopened.state_root(height)?, committed_root);

        Ok(())
    }

    #[test]
    fn commit_rejects_a_height_that_skips_ahead() -> Result<()> {
        let store = open_store()?;

        let result = store.commit(Height::from_u64(2), &BTreeMap::new(), &[]);

        assert!(matches!(
            result,
            Err(StorageError::NonSequentialCommit {
                expected: 1,
                actual: 2
            })
        ));

        Ok(())
    }

    #[test]
    fn commit_rejects_a_height_that_repeats_the_last_one() -> Result<()> {
        let store = open_store()?;
        store.commit(Height::from_u64(1), &BTreeMap::new(), &[])?;

        let result = store.commit(Height::from_u64(1), &BTreeMap::new(), &[]);

        assert!(matches!(
            result,
            Err(StorageError::NonSequentialCommit {
                expected: 2,
                actual: 1
            })
        ));

        Ok(())
    }

    #[test]
    fn commit_serializes_concurrent_writers_at_the_same_height() -> Result<()> {
        let store = Arc::new(open_store()?);

        let handles: Vec<_> = (0..8u8)
            .map(|seed| {
                let store = Arc::clone(&store);

                thread::spawn(move || -> Result<RootHash> {
                    let signer = signing_key(seed);
                    let (event, _) = inception_event(&signer, seed)?;
                    let state = apply_all(&LedgerState::empty(), &[event])?;

                    Ok(store.commit(Height::from_u64(1), state.identities(), &[])?)
                })
            })
            .collect();

        let results: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().expect("commit thread panicked"))
            .collect();
        let successes = results.iter().filter(|r| r.is_ok()).count();

        assert_eq!(
            successes, 1,
            "exactly one of several concurrent commits at the same height should succeed"
        );
        assert_eq!(store.height()?, 1);
        assert_eq!(store.load()?.identities().len(), 1);

        Ok(())
    }

    #[test]
    fn commit_persists_height_and_state() -> Result<()> {
        let store = open_store()?;
        let signer = signing_key(0x11);
        let (event, _) = inception_event(&signer, 0x22)?;
        let state = apply_all(&LedgerState::empty(), &[event])?;

        store.commit(Height::from_u64(1), state.identities(), &[])?;

        assert_eq!(store.height()?, 1);
        assert_eq!(store.load()?, state);

        Ok(())
    }

    #[test]
    fn commit_persists_an_append_only_paginated_event_log() -> Result<()> {
        let store = open_store()?;
        let signer = signing_key(0x11);
        let (inception, _) = inception_event(&signer, 0x22)?;
        let inception_state = apply_all(&LedgerState::empty(), std::slice::from_ref(&inception))?;
        let id = *inception_state
            .identities()
            .keys()
            .next()
            .context("expected an identity")?;

        store.commit(
            Height::from_u64(1),
            inception_state.identities(),
            std::slice::from_ref(&inception),
        )?;

        let rotation = rotate_event(
            inception_state
                .identity(&id)
                .context("expected the identity to be present")?,
            0x22,
            0x33,
        )?;
        let rotated_state = apply_all(&inception_state, std::slice::from_ref(&rotation))?;
        store.commit(
            Height::from_u64(2),
            rotated_state.identities(),
            std::slice::from_ref(&rotation),
        )?;

        assert_eq!(
            store.event_log(id, Sequence::ZERO, 10)?,
            vec![inception.clone(), rotation.clone()]
        );
        assert_eq!(
            store.event_log(id, Sequence::from_u64(1), 1)?,
            vec![rotation]
        );
        assert!(store.event_log(id, Sequence::from_u64(2), 10)?.is_empty());

        let duplicate = store.commit(Height::from_u64(3), &BTreeMap::new(), &[inception]);

        assert!(matches!(
            duplicate,
            Err(StorageError::EventAlreadyStored {
                id: duplicate_id,
                sequence: Sequence::ZERO,
            }) if duplicate_id == id
        ));
        assert_eq!(store.height()?, 2);

        Ok(())
    }

    #[test]
    fn preview_root_matches_what_commit_actually_produces_without_writing() -> Result<()> {
        let store = open_store()?;
        let signer = signing_key(0x11);
        let (event, _) = inception_event(&signer, 0x22)?;
        let state = apply_all(&LedgerState::empty(), &[event])?;

        let previewed = store.preview_root(Height::from_u64(1), state.identities())?;

        assert_eq!(store.height()?, 0);
        assert!(store.load()?.identities().is_empty());

        store.commit(Height::from_u64(1), state.identities(), &[])?;
        let committed = store.state_root(Height::from_u64(1))?;

        assert_eq!(previewed, committed);

        Ok(())
    }

    #[test]
    fn preview_root_rejects_a_height_that_skips_ahead() -> Result<()> {
        let store = open_store()?;

        let result = store.preview_root(Height::from_u64(2), &BTreeMap::new());

        assert!(matches!(
            result,
            Err(StorageError::NonSequentialCommit {
                expected: 1,
                actual: 2
            })
        ));

        Ok(())
    }

    #[test]
    fn prove_returns_a_verifiable_inclusion_and_absence_proof() -> Result<()> {
        let store = open_store()?;
        let signer = signing_key(0x11);
        let (event, _) = inception_event(&signer, 0x22)?;
        let state = apply_all(&LedgerState::empty(), &[event])?;
        store.commit(Height::from_u64(1), state.identities(), &[])?;

        let present_id = *state
            .identities()
            .keys()
            .next()
            .context("expected an identity")?;
        let (present_state, present_proof) = store.prove(present_id, Height::from_u64(1))?;
        let root = store.state_root(Height::from_u64(1))?;

        let present_state = present_state.context("identity should be present")?;
        present_proof.verify_existence(root, present_id, &present_state)?;

        let absent_id = IdentityId::from_bytes([0xff; 32]);
        let (absent_state, absent_proof) = store.prove(absent_id, Height::from_u64(1))?;

        assert!(absent_state.is_none());

        absent_proof.verify_nonexistence(root, absent_id)?;

        Ok(())
    }

    #[test]
    fn commit_leaves_previously_committed_identities_readable_and_provable_when_only_others_change()
    -> Result<()> {
        let store = open_store()?;
        let signer = signing_key(0x11);

        let (first_event, _) = inception_event(&signer, 0x22)?;
        let first_state = apply_all(&LedgerState::empty(), &[first_event])?;
        store.commit(Height::from_u64(1), first_state.identities(), &[])?;

        let (second_event, _) = inception_event(&signer, 0x33)?;
        let second_state = apply_all(&LedgerState::empty(), &[second_event])?;
        store.commit(Height::from_u64(2), second_state.identities(), &[])?;

        assert_eq!(store.load()?.identities().len(), 2);

        let first_id = *first_state
            .identities()
            .keys()
            .next()
            .context("expected an identity")?;
        let root = store.state_root(Height::from_u64(2))?;
        let (first_proven, first_proof) = store.prove(first_id, Height::from_u64(2))?;
        let first_proven =
            first_proven.context("identity from height 1 should still be present")?;
        first_proof.verify_existence(root, first_id, &first_proven)?;

        Ok(())
    }

    #[test]
    fn prove_returns_a_verifiable_absence_proof_before_the_first_commit() -> Result<()> {
        let store = open_store()?;
        let id = IdentityId::from_bytes([0x42; 32]);
        let height = Height::from_u64(0);

        let (state, proof) = store.prove(id, height)?;

        assert!(state.is_none());

        proof.verify_nonexistence(store.state_root(height)?, id)?;

        Ok(())
    }

    #[test]
    fn commit_applies_multiple_identities() -> Result<()> {
        let store = open_store()?;
        let signer = signing_key(0x11);
        let (first, _) = inception_event(&signer, 0x22)?;
        let (second, _) = inception_event(&signer, 0x33)?;
        let state = apply_all(&LedgerState::empty(), &[first, second])?;

        store.commit(Height::from_u64(1), state.identities(), &[])?;

        assert_eq!(store.load()?.identities().len(), 2);

        Ok(())
    }

    #[test]
    fn later_commit_overwrites_earlier_identity_state() -> Result<()> {
        let store = open_store()?;
        let signer = signing_key(0x11);
        let (event, _) = inception_event(&signer, 0x22)?;
        let inception_state = apply_all(&LedgerState::empty(), &[event])?;
        store.commit(Height::from_u64(1), inception_state.identities(), &[])?;

        let identity = inception_state
            .identities()
            .values()
            .next()
            .context("expected an identity")?;
        let rotation = rotate_event(identity, 0x22, 0x44)?;
        let rotated_state = apply_all(&inception_state, &[rotation])?;
        store.commit(Height::from_u64(2), rotated_state.identities(), &[])?;

        assert_eq!(store.height()?, 2);
        assert_eq!(store.load()?, rotated_state);

        Ok(())
    }

    #[test]
    fn state_root_reflects_state_and_survives_reopen() -> Result<()> {
        let file = NamedTempFile::new()?;
        let signer = signing_key(0x11);
        let (first_event, _) = inception_event(&signer, 0x22)?;
        let first_state = apply_all(&LedgerState::empty(), &[first_event])?;
        let (second_event, _) = inception_event(&signer, 0x33)?;
        let second_state = apply_all(&first_state, &[second_event])?;

        let (root_1, root_2) = {
            let store = LedgerStore::open(file.path())?;
            store.commit(Height::from_u64(1), first_state.identities(), &[])?;
            store.commit(Height::from_u64(2), second_state.identities(), &[])?;

            let root_1 = store.state_root(Height::from_u64(1))?;
            let root_1_again = store.state_root(Height::from_u64(1))?;
            let root_2 = store.state_root(Height::from_u64(2))?;

            assert_eq!(
                root_1, root_1_again,
                "root at a fixed height must be stable"
            );
            assert_ne!(
                root_1, root_2,
                "root must change when state changes between heights"
            );

            (root_1, root_2)
        };

        let reopened = LedgerStore::open(file.path())?;

        assert_eq!(
            root_1,
            reopened.state_root(Height::from_u64(1))?,
            "root at height 1 must survive reopen"
        );
        assert_eq!(
            root_2,
            reopened.state_root(Height::from_u64(2))?,
            "root at height 2 must survive reopen"
        );

        Ok(())
    }

    #[test]
    fn state_persists_across_reopen() -> Result<()> {
        let file = NamedTempFile::new()?;
        let signer = signing_key(0x11);
        let (event, _) = inception_event(&signer, 0x22)?;
        let state = apply_all(&LedgerState::empty(), &[event])?;

        {
            let store = LedgerStore::open(file.path())?;
            store.commit(Height::from_u64(1), state.identities(), &[])?;
        }

        let reopened = LedgerStore::open(file.path())?;

        assert_eq!(reopened.height()?, 1);
        assert_eq!(reopened.load()?, state);

        Ok(())
    }
}
