#!/usr/bin/env bash

# Initializes (if needed) and starts one CometBFT node of the local devnet.

set -euo pipefail

repo_root="$PWD"
devnet_init="$repo_root/scripts/devnet-init.sh"
node_state="$repo_root/.devenv/state"
node_index="$1"
devnet_dir="$node_state/devnet"

"$devnet_init"

exec cometbft start --home "$devnet_dir/node$node_index"
