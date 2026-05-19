# Root Genesis Operator Guide

The operator coordinates the ceremony but does not receive root secrets, plaintext FROST shares, or authority credentials. The portal is an untrusted relay for signed, bounded ceremony envelopes.

## Ceremony Policy

- Roster size: 13 independent certifiers.
- Signing threshold after genesis: any 7 of 13 certifiers.
- Genesis DKG completion rule: all 13 rostered certifiers complete both DKG rounds.
- Abort rule: if any certifier fails, abort and restart with a new signed roster and ceremony ID.
- Portal rule: round-two DKG payloads must be encrypted per recipient; raw round-two payloads are rejected.
- AVC rule: the root delegates to a normal operational AVC Issuing Authority DID. Routine AVC issuance remains on the existing AVC path.
- Output rule: secret-producing certifier commands require explicit unique
  `--output` paths. Do not request terminal capture or shared automation logs
  for DKG secret packages, sealed shares, or opened shares.

## Build Ceremony Configuration

Collect the 13 public certifier contact files and assemble a roster JSON array. Then create the ceremony config:

```bash
exochain genesis ceremony init \
  --ceremony-id exo-root-genesis-2026-001 \
  --network-id exochain-main \
  --repo-commit d8927686a34bdc28ba36d53938f665685d2c4c04 \
  --constitution-hash <32-byte-hex> \
  --created-physical-ms <hlc-physical-ms> \
  --roster root-roster.json \
  --out root-ceremony-config.json
```

The command enforces 7-of-13 policy, exactly 13 certifiers, unique DIDs, unique FROST identifiers, unique signing keys, and unique transport keys.

## Start Portal

```bash
exochain genesis portal \
  --config root-ceremony-config.json \
  --bind 127.0.0.1:3017
```

Portal endpoints:

- `GET /api/v1/root-genesis/portal`
- `POST /api/v1/root-genesis/portal/envelopes`

The portal verifies envelope signatures, ceremony ID, roster membership, phase/kind policy, payload hashes, payload size, and replay sequences.

## Bundle Assembly

After DKG finalization and root artifact signing:

```bash
exochain genesis assemble-bundle \
  --input root-bundle.assemble.input.json \
  --output root-trust-bundle.json
```

Verify before publication:

```bash
exochain genesis verify-bundle \
  --input root-bundle.verify.input.json
```

Publish the verified root trust bundle with the transcript hash, root public key package, and root-signed AVC issuer delegation. Do not publish certifier private material, sealed share passphrases, or raw round-two packages.

## Validation Gates

Before proposing the branch:

```bash
cargo test -p exo-root --test root_genesis
cargo test -p exo-node genesis
cargo tarpaulin --packages exo-root --include-files "crates/exo-root/src/**" --fail-under 100
cargo tarpaulin --packages exo-node --include-files "crates/exo-node/src/root_genesis.rs" --fail-under 100
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo doc --workspace --no-deps
```
