# IntelWar Kernel Bridge — Trust Model (Kernel-Required)

**Status:** Binding — simulated path **deleted**  
**Code:** `intelwar/crates/intelwar-core/src/bridge.rs`, bins `intelwar-log-append`, `intelwar-crosscheck-verify`  
**Caller:** `intelwar/services/log-api` (requires bins)

## What is real

Every successful append:

1. Caller-supplied **Active** bailment + `ConsentRecord` covering `log:append` (not invented by the bridge).
2. Gatekeeper **CGR Kernel** adjudicates `intelwar.log.append` against all eight EXOCHAIN invariants.
3. IntelWar overlays (IW-1…IW-8) run in `intelwar_core::invariants::enforce_all`.
4. Signed gatekeeper `Provenance` verified with trusted DID keys.
5. `LivingLogReceipt` chained on `previous_receipt_hash`.
6. `exo_dag` node for the sealed CBOR entry payload.
7. Synthetic voice: attestation signature is **Ed25519 over a canonical message** (actor key) — no placeholder bytes.

Responses set `simulated: false` and `kernel_adjudicated: true`. Success paths **never** return `simulated: true`.

## Required env (log-api)

| Variable | Role |
|----------|------|
| `INTELWAR_CORE_BIN` | Path to `intelwar-log-append` — **required** or append → 503 |
| `INTELWAR_CROSSCHECK_BIN` | Path to `intelwar-crosscheck-verify` — **required** or verify → 503 |
| `INTELWAR_CORE_STATE_DIR` | Durable bridge state + log mirror (volume in production) |

Optional DAG DB (all-or-nothing when URL set):

- `INTELWAR_DAGDB_GATEWAY_URL` + auth/tenant/namespace/DIDs/write signature

| Durability label | Meaning |
|------------------|---------|
| `local_kernel` | Kernel + local multi-node DAG; gateway unset |
| `dagdb` | Kernel success **and** gateway intake OK |

Kernel success + configured gateway failure → **HTTP 503** (fail closed). Client must not treat the append as DAG-DB durable.

## Consent

| Surface | Reality |
|---------|---------|
| `POST /api/consent/grant` | Stores gatekeeper-compatible consent for the bridge stdin wire |
| Bridge stdin `consent` | Required; inactive/missing → bridge error → API 503 |
| Node ≠ inventing Kernel bailment | Bridge uses caller wire only |

## CrossCheck

| Condition | Behavior |
|-----------|----------|
| Bin missing | **503** — no structural-only success |
| Bin + valid Ed25519 | `core_verified: true`, `simulated: false` |
| Bin + failure | **503** fail-closed |

## Do not claim

- Full AVC receipt minting (typed follow-on; synthetic uses signed attestation today)
- Multi-tenant DID/KMS beyond state-dir / Railway secrets
- That UI proximity alone is constitutional enforcement

## Related invariants

IW-1 (caller consent), IW-2 (receipts), IW-4 (crosscheck), IW-6 (fail closed), IW-8 (LogIntegrity — local multi-node + optional gateway).
