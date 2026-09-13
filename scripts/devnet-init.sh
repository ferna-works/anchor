#!/usr/bin/env bash

# Generates config for a local CometBFT devnet, one node directory per
# validator or non-validator, each on its own localhost ports.

set -euo pipefail

repo_root="$PWD"
out="$repo_root/.devenv/state/devnet"
validator_count=4
full_node_count=1
node_count=$((validator_count + full_node_count))

lock="${out}.lock"

while ! mkdir "$lock" 2>/dev/null; do
  while [ -d "$lock" ] && [ ! -f "$out/node0/config/genesis.json" ]; do
    sleep 0.2
  done

  if [ -f "$out/node0/config/genesis.json" ]; then
    exit 0
  fi
done

scratch="${out}.tmp.$$"
trap 'rm -rf "$scratch"; rmdir "$lock" 2>/dev/null || true' EXIT

if [ -f "$out/node0/config/genesis.json" ]; then
  exit 0
fi

rm -rf "$out"

cometbft testnet \
  --v "$validator_count" \
  --n "$full_node_count" \
  --o "$scratch" \
  --starting-ip-address 127.0.0.1 \
  --populate-persistent-peers=false

declare -a node_ids
declare -a p2p_ports

for ((i = 0; i < node_count; i++)); do
  node_dir="$scratch/node$i"
  p2p_port=$((26656 + i * 10))
  rpc_port=$((26657 + i * 10))
  abci_port=$((26658 + i * 10))

  config="$node_dir/config/config.toml"

  yq -p toml -o toml -i \
    ".proxy_app = \"tcp://127.0.0.1:${abci_port}\"" \
    "$config"

  yq -p toml -o toml -i \
    ".rpc.laddr = \"tcp://0.0.0.0:${rpc_port}\"" \
    "$config"

  yq -p toml -o toml -i \
    ".p2p.laddr = \"tcp://0.0.0.0:${p2p_port}\"" \
    "$config"

  yq -p json -o json -i \
    '.chain_id = "anchor-devnet"' \
    "$node_dir/config/genesis.json"

  node_ids[i]=$(cometbft show-node-id --home "$node_dir")
  p2p_ports[i]=$p2p_port
done

for ((i = 0; i < node_count; i++)); do
  peers=""

  for ((j = 0; j < node_count; j++)); do
    if [ "$j" -eq "$i" ]; then
      continue
    fi

    peer="${node_ids[j]}@127.0.0.1:${p2p_ports[j]}"
    peers="${peers:+${peers},}${peer}"
  done

  yq -p toml -o toml -i \
    ".p2p.persistent_peers = \"${peers}\"" \
    "$scratch/node$i/config/config.toml"
done

mv "$scratch" "$out"

echo "Initialized ${validator_count}-validator, ${full_node_count}-full-node devnet at ${out}" >&2
