# CrossChecked Anchor Authority Owner Runbook

This runbook provisions, rotates, or retires one CrossChecked child authority in
the node-local durable `crosschecked_anchor_authorities` registry. It does not
issue a receipt, establish consensus finality, or make an underlying
CrossChecked conclusion true.

The owner command signs the existing `AuthorityProvisioningV1` or
`AuthorityRetirementV1` protocol object with the configured CrossChecked
intermediate key. It will make that object route-effective only when a
separate RFC 9591 FROST(Ed25519, SHA-512) 7-of-13 authorization verifies under
the group public key and epoch already pinned in the registry. The protocol
object, FROST artifact, lifecycle state, and first-application time commit in
one SQLite transaction. The normal commitment route remains commitment-only.

## Safety boundary

- Run this only on the owner-controlled EXOCHAIN node host.
- Use an existing node data directory. Do not point the command at a copied,
  temporary, or standby directory and describe that as production activation.
- Obtain the node DID, node response key ID, node public key, audience, and
  CrossChecked intermediate identity from the reviewed production
  configuration. The owner command file must match the values used by node
  startup exactly.
- The intermediate signer, owner command, and governance authorization files
  must each be a regular,
  non-symlinked, single-link file with mode `0400` or `0600`. The command
  refuses group/world access, unknown JSON fields, oversized files, uppercase
  or non-exact hex, and file substitution detected while reading.
- Never place a signing secret, DID, key ID, grant, scope alias, or public key
  on the command line. Do not paste the signer file into a shell heredoc.
- Treat the signed CBOR package as private operational evidence. It contains
  stable authority and scope correlation material and is not a public receipt.
- Keep the intermediate signer and all FROST participant shares offline except
  for the bounded owner ceremony. The node and owner command receive only the
  aggregate signature and signer-ID manifest, never participant shares.
  Remove the online working copy after independently preserving the approved
  secret custody copy and signed evidence.
- Supply all target times as reviewed Unix epoch milliseconds. The owner
  command reads the host clock only to prove that the first application falls
  within the FROST authorization's signed validity window. An exact durable
  replay remains valid after that window; an unused expired authorization does
  not.

The three JSON inputs below are schemas, not production values. Create the files
through the approved secrets/configuration workflow under an owner-only
directory, then apply `chmod 0400` or `chmod 0600` before execution.

## Intermediate signer input

```json
{
  "protocol_version": 1,
  "intermediate_did": "<configured CrossChecked intermediate DID>",
  "intermediate_key_id": "<configured intermediate key ID>",
  "signing_secret_hex": "<exact 32-byte lowercase Ed25519 secret hex>"
}
```

The command derives the public key from `signing_secret_hex` and requires it to
equal the separately pinned `intermediate_public_key_hex` in the owner command.
Possession of this key alone cannot provision, retire, or revoke an authority.

## Persistently pin the FROST governance group

Complete the independently controlled RFC 9591 distributed key generation
ceremony with 13 participants and threshold 7. Do not use a trusted dealer.
Before the first authority operation, start the node once with the exact
reviewed group public key and positive epoch in:

```text
EXOCHAIN_CROSSCHECKED_ANCHOR_GOVERNANCE_FROST_PUBLIC_KEY_HEX
EXOCHAIN_CROSSCHECKED_ANCHOR_GOVERNANCE_FROST_KEY_EPOCH
```

Startup persists these values in the empty authority registry. Stop the node
before the owner command. The owner command refuses to create a fresh registry,
and a command-supplied group key or epoch that differs from the persisted pin
fails closed. A group-key or group-epoch change therefore requires a separately
reviewed registry transition; it cannot be smuggled into an authority command.

## Provision one authority epoch

Prepare the following owner command. `grant_id_hex` and `scope_alias_hex` are
independent cryptographically random 32-byte values. The authority key ID must
be rooted at `authority_did`. `key_epoch` must be positive and greater than any
previous epoch stored for the same authority DID.

```json
{
  "protocol_version": 1,
  "expected_audience": "<configured closed audience>",
  "intermediate_did": "<configured CrossChecked intermediate DID>",
  "intermediate_key_id": "<configured intermediate key ID>",
  "intermediate_public_key_hex": "<exact 32-byte lowercase public key hex>",
  "node_did": "<production node DID>",
  "node_key_id": "<configured node response key ID>",
  "node_public_key_hex": "<exact 32-byte lowercase node public key hex>",
  "governance_group_public_key_hex": "<persistently pinned 32-byte FROST group public key hex>",
  "governance_key_epoch": 1,
  "authority_did": "<CrossChecked child authority DID>",
  "authority_key_id": "<child authority key ID>",
  "authority_public_key_hex": "<exact 32-byte lowercase child public key hex>",
  "grant_id_hex": "<32 random bytes as lowercase hex>",
  "scope_alias_hex": "<32 random bytes as lowercase hex>",
  "key_epoch": 1,
  "valid_from_ms": 0,
  "valid_until_ms": 1
}
```

The offline 7-of-13 ceremony signs the exact deterministic governance
preimage produced for this package and supplies a separate owner-only file:

```json
{
  "protocol_version": 1,
  "authorization_id_hex": "<single-use 32 random bytes as lowercase hex>",
  "ceremony_id_hex": "<32 random ceremony bytes as lowercase hex>",
  "governance_key_epoch": 1,
  "threshold": 7,
  "participant_count": 13,
  "signer_ids": [1, 2, 3, 4, 5, 6, 7],
  "lifecycle_event": "provision",
  "authority_did": "<exact child authority DID>",
  "authority_key_id": "<exact child authority key ID>",
  "authority_key_epoch": 1,
  "scope_alias_hex": "<exact scope alias from the command>",
  "package_hash_hex": "<BLAKE3-256 of exact signed provisioning CBOR>",
  "node_policy_hash_hex": "<BLAKE3-256 of the exact pinned node-policy preimage>",
  "authorization_sequence": 1,
  "prior_authorization_hash_hex": "0000000000000000000000000000000000000000000000000000000000000000",
  "valid_from_ms": 0,
  "valid_until_ms": 1,
  "signature_algorithm": "frost-ed25519-sha512-rfc9591",
  "signature_hex": "<exact 64-byte aggregate signature as lowercase hex>"
}
```

The first event for a scope is sequence 1 with a zero predecessor. Every later
event increments the sequence by exactly one and commits to the BLAKE3-256 hash
of the complete prior canonical authorization artifact. Authorization IDs and
ceremony IDs are each single-use globally. The seven signer IDs must be
strictly increasing, unique, and within 1 through 13.

Replace the illustrative time and epoch values with the reviewed production
values. Then execute:

```text
exochain crosschecked-anchor-authority provision \
  --data-dir <production-node-data-directory> \
  --command <owner-only-provision-command.json> \
  --intermediate-secret-file <owner-only-intermediate-secret.json> \
  --governance-authorization <owner-only-frost-authorization.json> \
  --signed-package-out <new-private-provisioning-evidence.cbor>
```

The command creates the registry directory with mode `0700`, persists the
signed package transactionally, restricts the SQLite file to `0600`, writes the
optional evidence with create-new `0600` semantics, and emits only:

```json
{
  "protocol_version": 1,
  "operation": "provision",
  "persistence_status": "committed_or_exact_replay",
  "package_sha256": "sha256:<digest>"
}
```

Re-running the exact command without reusing an existing evidence output path
is safe. The signed bytes are deterministic, and `AnchorStore` returns success
only for the byte-identical stored package. A different package under the same
authority DID/key ID is rejected.

Before enabling CrossChecked traffic:

1. Independently hash the private signed-CBOR evidence and compare it with
   `package_sha256`.
2. Confirm node startup uses the same audience, intermediate DID, intermediate
   key ID/public key, node key ID, and node identity represented in the owner
   command. A mismatch makes the node fail closed when opening the registry.
3. Start or restart the node with all eight commitment-route settings:
   `EXOCHAIN_CROSSCHECKED_ANCHOR_BEARER_TOKEN`,
   `EXOCHAIN_CROSSCHECKED_ANCHOR_EXPECTED_AUDIENCE`,
   `EXOCHAIN_CROSSCHECKED_ANCHOR_INTERMEDIATE_DID`,
   `EXOCHAIN_CROSSCHECKED_ANCHOR_INTERMEDIATE_KEY_ID`,
   `EXOCHAIN_CROSSCHECKED_ANCHOR_INTERMEDIATE_PUBLIC_KEY_HEX`,
   `EXOCHAIN_CROSSCHECKED_ANCHOR_NODE_KEY_ID`,
   `EXOCHAIN_CROSSCHECKED_ANCHOR_GOVERNANCE_FROST_PUBLIC_KEY_HEX`, and
   `EXOCHAIN_CROSSCHECKED_ANCHOR_GOVERNANCE_FROST_KEY_EPOCH`. The route bearer must be an
   independent 256-bit lowercase-hex secret. Never reuse the node admin
   bearer.
4. Submit one synthetic, non-user-data CrossChecked v3 receipt commitment.
5. Verify exact request acceptance, authenticated readback, receipt and wrapper
   signatures, and the truthful state `node_recorded`; do not claim consensus
   finality.

## Retire or revoke one exact authority epoch

Pause new CrossChecked anchor submissions at the caller before retirement so
the operational cutoff has an unambiguous boundary. Already committed exact
replays remain readable by design; retirement blocks new records.

```json
{
  "protocol_version": 1,
  "expected_audience": "<configured closed audience>",
  "intermediate_did": "<configured CrossChecked intermediate DID>",
  "intermediate_key_id": "<configured intermediate key ID>",
  "intermediate_public_key_hex": "<exact 32-byte lowercase public key hex>",
  "node_did": "<production node DID>",
  "node_key_id": "<configured node response key ID>",
  "node_public_key_hex": "<exact 32-byte lowercase node public key hex>",
  "governance_group_public_key_hex": "<persistently pinned 32-byte FROST group public key hex>",
  "governance_key_epoch": 1,
  "authority_did": "<exact child authority DID>",
  "authority_key_id": "<exact child authority key ID>",
  "key_epoch": 1,
  "retired_at_ms": 1
}
```

Replace the illustrative epoch and time. Create a new FROST authorization file
with lifecycle `retire` or `revoke`, sequence equal to the prior sequence plus
one, and `prior_authorization_hash_hex` equal to the exact prior artifact hash.
The two lifecycle events are distinct and cannot be substituted or replayed as
one another.

```text
exochain crosschecked-anchor-authority retire \
  --data-dir <production-node-data-directory> \
  --command <owner-only-retirement-command.json> \
  --intermediate-secret-file <owner-only-intermediate-secret.json> \
  --governance-authorization <owner-only-frost-authorization.json> \
  --signed-package-out <new-private-retirement-evidence.cbor>
```

Use the `revoke` subcommand with a separately signed `revoke` authorization for
revocation. The redacted result names the exact lifecycle event. Repeat execution is idempotent only
when the retirement bytes are exact. A different retirement time, target,
epoch, signer, or signature conflicts and is rejected.

After retirement:

1. Reopen or restart the node against the same registry.
2. Confirm a new, correctly signed commitment for the retired key epoch is
   rejected.
3. Confirm authenticated readback of records committed before retirement still
   returns the original canonical response bytes.
4. Resume traffic only through a separately provisioned and canary-verified new
   key epoch.

Retirement is forward-only. Do not edit `retired_at_ms` or
`retirement_cbor`, restore a pre-retirement database, or treat removal of the
evidence file as unretirement. Rotation provisions a new key ID and strictly
higher epoch, proves a canary, and then retires the old epoch.

## Failure and recovery

- A rejected command does not persist an authority package or lifecycle
  mutation. Correct the
  reviewed input and rerun; do not edit the database directly.
- If persistence succeeds but writing the optional evidence output fails, rerun
  the exact command with a fresh output path. Byte-exact idempotency prevents a
  second authority or retirement record.
- If the node cannot reopen the registry after the operation, leave the
  commitment route disabled. Reconcile the owner command with the pinned node
  runtime configuration; do not loosen validation or substitute a new
  intermediate key.
- Preserve the redacted command result, signed CBOR evidence hash, canonical
  FROST authorization artifact/hash, exact source commit, node identity/key
  fingerprint, and canary/readback result as separate
  release evidence. None of these alone proves deployment, production key
  provisioning, node recording, or consensus finality.
