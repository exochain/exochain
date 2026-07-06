# LiveSafe Public-Output AVC Ceremony

This runbook creates the narrow AVC credential material that lets an operator
register a LiveSafe public adapter-output authorization credential with an
EXOCHAIN node. It does not configure Railway, mutate LiveSafe environments, or
give LiveSafe the node admin bearer.

## Classification

- Touched runtime boundary: core runtime adapter.
- Adjacent surface: LiveSafe public trust-status output.
- Trust claim allowed: only after LiveSafe calls the EXOCHAIN node public-output
  authorization route and receives a matching envelope for the configured
  credential id and evidence hash.
- Core state written by this ceremony: the operator registration command can
  submit the signed AVC credential to `POST /api/v1/avc/issue`.
- LiveSafe secret boundary: LiveSafe must receive only the scoped public-output
  authorization bearer for its route after that bearer is available; it must not
  receive the node admin bearer used by the operator registration command.
- Test gate: `cargo test -p exochain-avc --test livesafe_public_output_ceremony_tests`
  and `cargo test -p exochain-node livesafe_public_output_ceremony_cli_uses_secret_and_bearer_sources_not_inline_values`.

## Inputs

Issuer signing material is a local operator file, never an argv value:

```json
{
  "issuer_did": "did:exo:livesafe-public-output-issuer",
  "signing_secret_hex": "<64 lowercase hex from the operator key manager>"
}
```

The evidence summary hash is produced by the separate LiveSafe canonical
evidence-summary contract. This Rust ceremony consumes that already-canonical
value as `sha256:<64 lowercase hex>` and does not hash evidence bytes itself.
Keep issuer signing material and any evidence files outside the repository.

## Prepare

```bash
cargo run -p exochain-node -- avc livesafe-public-output-ceremony prepare \
  --issuer-did did:exo:livesafe-public-output-issuer \
  --issuer-secret-input /secure/operator/livesafe-public-output-issuer.private.json \
  --evidence-input /secure/operator/livesafe-public-output-evidence.json \
  --evidence-hash sha256:<64-lowercase-hex> \
  --not-before-physical-ms 1783296000000 \
  --expires-at-physical-ms 1814832000000 \
  --idempotency-key livesafe-public-output-ceremony-20260705 \
  --output /secure/operator/livesafe-public-output-ceremony.json
```

The `--evidence-input` file is optional presence proof and is checked only for
file existence and non-empty contents; it is not hashed by this command. The
command refuses malformed evidence hashes, broad claim caps, non-LiveSafe
subjects/audiences, and non-public-output issuer scope. The output includes the
signed AVC credential, its credential id, the
`/api/v1/avc/issue` request body, and the later public-output authorization
request material. It does not include raw private keys, bearer tokens, or admin
tokens, and it does not include raw evidence bytes.

## Register

Use an operator-only admin bearer source at execution time:

```bash
export EXOCHAIN_OPERATOR_AVC_ADMIN_BEARER="<operator-admin-bearer-from-secret-manager>"

cargo run -p exochain-node -- avc livesafe-public-output-ceremony register \
  --input /secure/operator/livesafe-public-output-ceremony.json \
  --node-url "$EXOCHAIN_NODE_AVC_URL" \
  --admin-bearer-env EXOCHAIN_OPERATOR_AVC_ADMIN_BEARER \
  --output /secure/operator/livesafe-public-output-registration.json
```

File-based bearer source is also supported:

```bash
cargo run -p exochain-node -- avc livesafe-public-output-ceremony register \
  --input /secure/operator/livesafe-public-output-ceremony.json \
  --node-url "$EXOCHAIN_NODE_AVC_URL" \
  --admin-bearer-file /secure/operator/exochain-node-admin-bearer.txt \
  --output /secure/operator/livesafe-public-output-registration.json
```

The register command posts only to `/api/v1/avc/issue`. It redacts the bearer
from response text before writing output and refuses inline bearer argv flags.

## Operator Handoff Values

After registration succeeds, use the prepared package values for the later
LiveSafe runtime configuration step:

- `authorization_request.credential_id`
- `authorization_request.evidence_hash`
- `authorization_request.subject`
- `authorization_request.audience`
- `authorization_request.expires_at`

`authorization_request.credential_id` and
`authorization_request.evidence_hash` are operator handoff strings already
serialized as `sha256:<64 lowercase hex>`. Give LiveSafe those exact prefixed
values, not raw `Hash256` JSON arrays or plain bytes:

```bash
export LIVESAFE_PUBLIC_OUTPUT_CEREMONY=/secure/operator/livesafe-public-output-ceremony.json

export EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_CREDENTIAL_ID="$(jq -r '.authorization_request.credential_id' "$LIVESAFE_PUBLIC_OUTPUT_CEREMONY")"
export EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_EVIDENCE_HASH="$(jq -r '.authorization_request.evidence_hash' "$LIVESAFE_PUBLIC_OUTPUT_CEREMONY")"
```

The LiveSafe app still remains fail-closed until its own runtime has
`EXOCHAIN_NODE_AVC_URL`,
`EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_BEARER`,
`EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_CREDENTIAL_ID`, and
`EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_EVIDENCE_HASH` configured and the node returns a
matching authorization envelope.

## Disablement

To disable this public-output trust path, remove the LiveSafe public-output
runtime environment values or revoke the registered credential through the
existing AVC revocation flow. Do not rotate or expose the node admin bearer to
LiveSafe; it is operator-only registration authority.
