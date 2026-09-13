# Demo

ⓘ **You'll need a local devnet running** (see [README.md](../../README.md)).

Generate two keys and create an identity. The `--key` is what signs, the
`--next-key` is what the identity's first control rotation will later reveal:

```sh
just demo keygen alice.key
just demo keygen next.key
just demo inception --key alice.key --next-key "$(just demo pubkey next.key)" \
    --genesis .devenv/state/devnet/node0/config/genesis.json
# ✓ committed at height 18
#   identity id: 02a33bb5a217ed5514465b2e1b2cf2c9f28beaa00daa26f8f3a442ce8cc076a5
```

`query` verifies a signed header against the trusted genesis validator set, then
verifies the returned state proof against that header's application root.

```sh
just demo query 02a33bb5a217ed5514465b2e1b2cf2c9f28beaa00daa26f8f3a442ce8cc076a5 \
    --genesis .devenv/state/devnet/node0/config/genesis.json
# identity 02a33bb5a217ed5514465b2e1b2cf2c9f28beaa00daa26f8f3a442ce8cc076a5
#   verified at height: 21
#   status: found (existence proof verified)
#   sequence: 0
#   deactivated: false
#   control threshold: 1 of 1
#   control key[0]: 62506faf306080a75e4ab6dee578f8c2062eb2bb43fb9e25e65a00578daf253a
```

Authorize a device and confirm it shows up:

```sh
just demo keygen device.key
just demo authorize-device 02a33bb5a217ed5514465b2e1b2cf2c9f28beaa00daa26f8f3a442ce8cc076a5 \
    --key alice.key --device-key "$(just demo pubkey device.key)" \
    --genesis .devenv/state/devnet/node0/config/genesis.json
just demo query 02a33bb5a217ed5514465b2e1b2cf2c9f28beaa00daa26f8f3a442ce8cc076a5 \
    --genesis .devenv/state/devnet/node0/config/genesis.json
# ...
#   device: 20fe299b7b80ef4776541c36a06213650f4784242b586ff6c4c13f229400e466 (0504426e4ddd6c409b9839c060003e3b8b7950be10b53e1628eb26e9bb0963f4)
```

See `just demo --help` for revoking devices, rotating keys, and deactivating identities.
