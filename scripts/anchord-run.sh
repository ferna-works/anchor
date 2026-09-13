#!/usr/bin/env bash

# Runs one anchord instance of the local devnet, keyed by node index.

set -euo pipefail

repo_root="$PWD"
node_state="$repo_root/.devenv/state"
node_index="$1"
abci_port=$((26658 + node_index * 10))

mkdir -p "$node_state/node$node_index"

exec cargo run --manifest-path "$repo_root/Cargo.toml" -p anchor-node --bin anchord -- \
  --state "$node_state/node$node_index/state" \
  --abci "127.0.0.1:$abci_port"
