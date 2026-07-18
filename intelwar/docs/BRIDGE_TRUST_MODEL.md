# IntelWar Kernel Bridge — Trust Model & Limitations

**Status:** Binding for PM-001 / PM-002 prototype  
**Code:** `intelwar/crates/intelwar-core/src/bridge.rs`, bin `intelwar-log-append`  
**Adjacent caller:** `intelwar/services/log-api` via `INTELWAR_CORE_BIN`

## What is real

When `intelwar-log-append` runs successfully:

1. Gatekeeper **CGR Kernel** adjudicates `intelwar.log.append` against all eight EXOCHAIN invariants.
2. IntelWar overlays (IW-1…IW-8) run in `intelwar_core::invariants::enforce_all`.
3. A signed gatekeeper `Provenance` is verified with trusted DID keys.
4. A `LivingLogReceipt` is minted; `previous_receipt_hash` chains across invokes.
5. An `exo_dag` node is created for the entry payload (CBOR).

Responses from this path set `simulated: false` and `kernel_adjudicated: true`.

## What is adjacent / fixture

| Concern | Reality |
|---------|---------|
| Node `/api/consent` | Demo gate only — **not** exo-consent bailment |
| Kernel bailment | Fixture `BailmentState` + `ConsentRecord` inside the bridge |
| Actor / root keys | Generated once into `bridge_state.json` (local prototype secrets) |
| Synthetic attestation | Placeholder bytes until real AVC wiring (PM-004+) |
| log-api in-memory list | Convenience mirror; not the cryptographic Log |

## Simulated vs Kernel (log-api)

| `INTELWAR_CORE_BIN` | Behavior |
|---------------------|----------|
| Unset | Adjacent append; `simulated: true` |
| Set + success | Kernel path; `simulated: false` |
| Set + failure | **HTTP 503 fail-closed** — no simulated fallback |

## DAG scope

| Scope label | Meaning |
|-------------|---------|
| `local-multi-node-genesis` | First append in a state dir; empty parent set |
| `local-multi-node` | Subsequent appends; prior sealed CBOR payloads replayed into an in-memory `Dag`, tip used as parent |
| Gateway persist (optional) | When `INTELWAR_DAGDB_GATEWAY_URL` is set, log-api POSTs intake to exo-gateway after Kernel success |

### Gateway env (log-api, PM-002)

All required when the URL is set (else append **503 fail-closed**):

- `INTELWAR_DAGDB_GATEWAY_URL`
- `INTELWAR_DAGDB_AUTH_TOKEN`
- `INTELWAR_DAGDB_TENANT_ID`
- `INTELWAR_DAGDB_NAMESPACE`
- `INTELWAR_DAGDB_OWNER_DID`
- `INTELWAR_DAGDB_CONTROLLER_DID`
- `INTELWAR_DAGDB_SUBMITTED_BY_DID`
- `INTELWAR_DAGDB_WRITE_SIGNATURE`

Unset URL → local multi-node only (no gateway call). Incomplete config with URL set → fail closed at append.

**Note:** Kernel bridge state advances before gateway write. A 503 after Kernel success means the client must not treat the append as durable in DAG DB; local `bridge_state.json` may already contain the receipt/history (retry/idempotency via intake key).

## Do not claim

- Production DID/consent lifecycle  
- Multi-tenant DAG DB authority without gateway config  
- That adjacent UI “is” the Living Log without Kernel adjudication  
- Cross-process LogIntegrity without a shared `INTELWAR_CORE_STATE_DIR` (and gateway when required)

## Related invariants

IW-1 (consent fixtures vs demo), IW-2 (receipts), IW-6 (fail closed), IW-8 (LogIntegrity — local multi-node + optional gateway persist).
