use anyhow::{Error, Result};
use jmt::{
    KeyHash, Version,
    storage::{LeafNode, Node, NodeKey, TreeReader},
};
use redb::ReadableDatabase;

use crate::{
    schema::{HEIGHT_KEY, JMT_HISTORY_TABLE, JMT_NODES_TABLE, META_TABLE},
    store::LedgerStore,
};

impl TreeReader for LedgerStore {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let encoded = borsh::to_vec(node_key)?;

        let read = self.database().begin_read()?;

        let nodes = read.open_table(JMT_NODES_TABLE)?;
        let value = nodes.get(&*encoded)?.map(|v| v.value().to_vec());
        let mut node = value.map(|v| borsh::from_slice(&v)).transpose()?;

        if node.is_none() && node_key.nibble_path().is_empty() {
            let meta = read.open_table(META_TABLE)?;
            let height = meta
                .get(HEIGHT_KEY)?
                .map(|value| value.value())
                .unwrap_or(0);

            if node_key.version() <= height {
                node = Some(Node::Null);
            }
        }

        Ok(node)
    }

    fn get_value_option(&self, max_version: Version, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        let read = self.database().begin_read()?;

        let history = read.open_table(JMT_HISTORY_TABLE)?;
        let start = history_key(key_hash, 0);
        let end = history_key(key_hash, max_version);

        let value = history
            .range(start.as_slice()..=end.as_slice())?
            .next_back()
            .map(|entry| {
                let (_, value) = entry?;
                Ok::<Option<Vec<u8>>, Error>(borsh::from_slice(value.value())?)
            })
            .transpose()?
            .flatten();

        Ok(value)
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        Ok(None)
    }
}

pub(crate) fn versioned_key(prefix: &[u8; 32], suffix: u64) -> [u8; 40] {
    let mut encoded = [0; 40];

    encoded[..32].copy_from_slice(prefix);
    encoded[32..].copy_from_slice(&suffix.to_be_bytes());

    encoded
}

pub(crate) fn history_key(key_hash: KeyHash, version: Version) -> [u8; 40] {
    versioned_key(&key_hash.0, version)
}
