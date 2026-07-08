# EXOCHAIN LLM Usage Receipt Extensions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a governed LLM usage receipt adapter that binds OpenAI-style model calls and MCP tool calls to AVC receipts while preserving an explicit custody boundary between minimized receipts, external customer object/KMS storage, and governed DAG DB tenant data.

**Architecture:** Build one core runtime adapter with two ingress lanes: `POST /api/v1/avc/llm-usage/receipts/emit` in the Rust node and `packages/exochain-llm-proxy` for OpenAI and MCP traffic. The Rust path verifies AVC authority, canonical LLM usage evidence, signatures, idempotency, custody policy, and then reuses the existing AVC receipt/finality machinery. The TypeScript proxy withholds model/tool output in production until the Rust path returns a committed receipt or a replayed committed receipt.

**Tech Stack:** Rust `exo-avc`, `exo-node`, `exo-dag-db-*`, canonical CBOR hashing via existing `hash_structured` helpers, TypeScript ESM package with Node >= 20 matching `packages/exochain-sdk`, fake OpenAI/MCP/object-store tests, and official OpenAI API reference checks immediately before coding endpoint-specific usage mappings.

## Global Constraints

- Absolute determinism applies: no floating point, no `HashMap`/`HashSet`, no production `SystemTime::now()` or `Instant::now()`, no JSON text hashing for receipt/evidence commitments.
- Use integer counters for token usage and cost: `u64` for token counts and minor currency units; `u32`/basis points for risk where existing AVC APIs use basis points.
- V1 targets OpenAI Responses, OpenAI Chat Completions, and MCP `tools/call`.
- Confirm exact OpenAI usage-field mapping against the official OpenAI API reference immediately before coding. As of this plan, Chat Completions exposes an optional `usage` object with `completion_tokens`, `prompt_tokens`, and `total_tokens`; streaming usage requires `stream_options: {"include_usage": true}` and can be absent if the stream is interrupted.
- The generic external `POST /api/v1/receipts` path remains disabled/fail-closed. This plan adds a trusted AVC adapter path, not open receipt ingestion.
- Default custody mode is `receipt_minimized`: AVC receipts store hashes, counts, policy identifiers, safe metadata, and opaque references only.
- DAG DB is governed data custody, not proof that EXOCHAIN never stores data. `dagdb_custody` is explicit, tenant/namespace scoped, consented, signed, idempotent, RLS-bound, and audited separately from receipt-minimized operation.
- External customer object/KMS mode stores plaintext/ciphertext outside EXOCHAIN. EXOCHAIN stores hashes, safe metadata, receipt links, and opaque hashed references; receipts do not store raw object URIs, KMS key material, provider keys, bearer tokens, raw prompts, raw completions, raw tool arguments, or raw tool results.
- Production fail-closed rule: if the provider or MCP call succeeds but EXOCHAIN receipt emission fails, the proxy returns `receipt_pending` with the idempotency key and withholds raw output.
- Non-production unreceipted output is allowed only behind an explicit configuration flag named `allowUnreceiptedOutputForDevelopment`; production config rejects that flag at startup.
- LLM/model calls require `Permission::Execute`.
- Human/user/app context can appear inside signed evidence as contextual fields, but it does not replace AVC authority, consent, signature, or tenant/session checks.
- Route errors, logs, test fixtures, and source guards must not disclose raw prompts, raw outputs, provider API keys, bearer tokens, KMS keys, private keys, raw signatures, authority internals, or customer secrets.
- The OpenAI/MCP proxy is classified as a core runtime adapter only while it mediates provider/MCP calls into EXOCHAIN receipt issuance and fail-closed behavior. Any Slack/GitHub/Teams/Codex workflow package built on top of this adapter requires its own adjacent-surface intake record before it can claim EXOCHAIN enforcement.

---

## Path Classification

- **Core runtime adapter:** `crates/exo-avc/src/llm_usage_receipt.rs`, `crates/exo-avc/src/receipt.rs`, `crates/exo-avc/src/validation.rs`, `crates/exo-node/src/avc.rs`, `crates/exo-node/src/mcp/tools/*` references used as fail-closed precedent.
- **Core runtime adapter / governed persistence:** DAG DB custody docs, `crates/exo-dag-db-api`, `crates/exo-dag-db-postgres`, and RLS/idempotency tests when explicit `dagdb_custody` storage is enabled.
- **Core runtime adapter package:** `packages/exochain-llm-proxy` when used as the enforcing OpenAI/MCP proxy.
- **Adjacent surface:** workflow/plugin producers for Codex, GitHub, Slack, Teams, browser sidecars, or product-specific integrations. They may produce signed evidence for this adapter; they may not mint EXOCHAIN receipts directly.
- **Imported evidence:** OpenAI API reference snapshots, provider docs, provider logs, MCP server logs, screenshots, scanner reports, and issue comments. Verify current docs/state before implementation claims.

## Corrected Custody Model

The old sentence that combined `EXOCHAIN` with `never stores decryptable payload material` is not accurate. DAG DB stores governed data. The corrected rule is:

> AVC LLM usage receipts are minimized by default: they bind a model/tool call to hashes, scoped authority, tenant/namespace, action identity, usage counters, custody policy, timestamps/finality evidence, and safe metadata. They must not contain raw prompts, completions, tool arguments, tool results, files, secrets, bearer tokens, private keys, raw signatures, KMS material, or decryptable payload references. DAG DB is separate governed custody: when explicitly authorized, it may store memory objects, summaries, graph/context records, and CBOR payloads under tenant/namespace isolation, consent, signatures/finality, idempotency, receipts, and RLS. For customers that require external custody, EXOCHAIN/DAG DB stores only hashes, safe metadata, and opaque hashed references while plaintext/ciphertext remains in customer object storage under customer KMS.

The three storage modes are:

| Mode | Name | EXOCHAIN receipt contents | DAG DB contents | Customer storage contents |
| --- | --- | --- | --- | --- |
| 1 | `receipt_minimized` | hashes, counters, safe metadata, custody policy id, receipt/finality refs | none required | raw provider payload can remain only in caller memory |
| 2 | `external_payload_ref` | hashes plus opaque hashed encrypted-ref id | optional safe metadata only | encrypted prompt/output blobs and keys under customer control |
| 3 | `dagdb_custody` | hashes, counters, safe metadata, DAG DB receipt refs | governed tenant data under explicit consent/policy/RLS | optional external backup outside EXOCHAIN |

## Files And Responsibilities

- Create `crates/exo-avc/src/llm_usage_receipt.rs`: owns `LlmUsageEvidence`, `LlmUsageEvidenceEnvelope`, `EncryptedPayloadRef`, `ProviderUsageMetrics`, `LlmUsageCustodyMode`, canonical hash helpers, validation helpers, and signature payload helpers.
- Modify `crates/exo-avc/src/lib.rs`: export the LLM usage module and add the new domain tag to `AVC_SIGNING_DOMAINS`.
- Modify `crates/exo-avc/src/receipt.rs`: add backward-compatible optional evidence fields or bind the LLM evidence hash through the existing action commitment path. Do not change legacy receipt serialization when absent.
- Modify `crates/exo-avc/src/validation.rs`: ensure the generated LLM usage action uses `Permission::Execute`, canonical descriptor hashing, and existing AVC deny reasons where possible.
- Modify `crates/exo-node/src/avc.rs`: add request/response DTOs and `POST /api/v1/avc/llm-usage/receipts/emit`, reusing existing `handle_emit_receipt` mechanics for registered credentials, subject signatures, timestamp evidence, idempotent storage, receipt chaining, and finality.
- Create `packages/exochain-llm-proxy/`: ESM TypeScript package with OpenAI and MCP proxy helpers, CLI/server entrypoints, fake provider tests, and privacy tests.
- Modify `docs/avc/README.md`: document the LLM usage receipt path, custody model, and fail-closed behavior.
- Modify `INTEGRATION.md` or add `docs/dagdb/llm-usage-custody.md`: document that DAG DB can store governed tenant data and that LLM usage receipts are minimized by default.

## Task 1: AVC LLM Usage Evidence Types

**Files:**
- Create: `crates/exo-avc/src/llm_usage_receipt.rs`
- Modify: `crates/exo-avc/src/lib.rs`
- Test: inline unit tests in `crates/exo-avc/src/llm_usage_receipt.rs`

**Interfaces:**
- Produces:
  - `pub const AVC_LLM_USAGE_EVIDENCE_DOMAIN: &str = "exo.avc.llm_usage.evidence.v1";`
  - `pub const AVC_LLM_USAGE_EVIDENCE_SIGNATURE_DOMAIN: &str = "exo.avc.llm_usage.evidence_signature.v1";`
  - `pub enum LlmUsageCustodyMode { ReceiptMinimized, ExternalPayloadRef, DagDbCustody }`
  - `pub struct ProviderUsageMetrics`
  - `pub struct EncryptedPayloadRef`
  - `pub struct LlmUsageEvidence`
  - `pub struct LlmUsageEvidenceEnvelope`
  - `pub fn llm_usage_evidence_hash(evidence: &LlmUsageEvidence) -> Result<Hash256, AvcError>`
  - `pub fn llm_usage_evidence_signature_payload(envelope: &LlmUsageEvidenceEnvelope) -> Result<Vec<u8>, AvcError>`
  - `pub fn validate_llm_usage_evidence(evidence: &LlmUsageEvidence) -> Result<(), AvcError>`

- [x] **Step 1: Write failing evidence determinism tests**

Add tests that build two identical `LlmUsageEvidence` values using only ordered collections and assert identical hash output. Add a second test that changes `model_id`, `prompt_hash`, `completion_hash`, `input_tokens`, `output_tokens`, and `custody_mode`, asserting each change changes the evidence hash.

Run:

```bash
cargo test -p exochain-avc llm_usage_evidence_hash -- --nocapture
```

Expected: tests fail because the module and helpers do not exist.

- [x] **Step 2: Add the LLM usage module with deterministic types**

Implement the module with `BTreeMap` or `BTreeSet` for any map/set field. Do not add raw prompt, raw completion, raw message, raw tool argument, raw tool result, raw URI, API key, bearer token, KMS key, private key, or raw signature fields.

The fields in `LlmUsageEvidence` must include:

```rust
pub struct LlmUsageEvidence {
    pub schema_version: u16,
    pub tenant_id: String,
    pub namespace: String,
    pub actor_did: Did,
    pub provider: String,
    pub provider_endpoint: String,
    pub model_id: String,
    pub provider_request_id_hash: Option<Hash256>,
    pub session_id_hash: Option<Hash256>,
    pub idempotency_key_hash: Hash256,
    pub action_id: Hash256,
    pub prompt_hash: Hash256,
    pub completion_hash: Option<Hash256>,
    pub tool_call_hash: Option<Hash256>,
    pub tool_result_hash: Option<Hash256>,
    pub usage: ProviderUsageMetrics,
    pub custody_mode: LlmUsageCustodyMode,
    pub encrypted_payload_refs: Vec<EncryptedPayloadRef>,
    pub custody_policy_hash: Hash256,
    pub created_at: Timestamp,
}
```

Use `hash_structured` over a domain-tagged serializable payload for the evidence hash.

- [x] **Step 3: Add validation helpers**

`validate_llm_usage_evidence` must fail when:

- `tenant_id`, `namespace`, `provider`, `provider_endpoint`, or `model_id` is empty.
- `usage.total_tokens` is less than `usage.input_tokens + usage.output_tokens`.
- `custody_mode == ReceiptMinimized` and `encrypted_payload_refs` is not empty.
- `custody_mode == ExternalPayloadRef` and `encrypted_payload_refs` is empty.
- `custody_mode == DagDbCustody` and `custody_policy_hash == Hash256::ZERO`.

- [x] **Step 4: Export the module and signing domains**

Modify `crates/exo-avc/src/lib.rs` to export the module and add both LLM usage domain constants to `AVC_SIGNING_DOMAINS`.

- [x] **Step 5: Verify focused tests**

Run:

```bash
cargo test -p exochain-avc llm_usage -- --nocapture
cargo test -p exochain-avc signing_domains -- --nocapture
```

Expected: all focused tests pass.

## Task 2: Receipt Evidence Binding

**Files:**
- Modify: `crates/exo-avc/src/receipt.rs`
- Modify: `crates/exo-avc/src/validation.rs`
- Test: inline tests in `receipt.rs` and `validation.rs`

**Interfaces:**
- Consumes: `llm_usage_evidence_hash`
- Produces:
  - `AvcTrustReceiptEvidence::llm_usage_evidence_hash: Option<Hash256>` or an equivalent action-commitment binding documented in code.
  - A helper that derives an `AvcActionRequest` with `Permission::Execute` and action name `llm.usage.receipt.emit`.

- [x] **Step 1: Write legacy compatibility tests**

Add a test proving a legacy `AvcTrustReceipt` with no LLM usage evidence deserializes and produces the same receipt hash/signing payload as before.

- [x] **Step 2: Write LLM evidence binding tests**

Add a test proving changing only `llm_usage_evidence_hash` changes the extended receipt signing payload and receipt id.

- [x] **Step 3: Implement the binding**

Prefer the narrowest change:

- If adding an optional field is cleaner, add `#[serde(default)] pub llm_usage_evidence_hash: Option<Hash256>` to `AvcTrustReceipt` and `AvcTrustReceiptEvidence`.
- If binding through action commitment is cleaner, create an LLM-specific action commitment helper and leave the receipt struct unchanged.

Document the selected path in a code comment next to the helper.

- [x] **Step 4: Derive the AVC action**

Add a helper that maps valid LLM usage evidence to an `AvcActionRequest`:

- `requested_permission: Permission::Execute`
- `action_name: Some("llm.usage.receipt.emit".into())`
- `estimated_budget_minor_units` from integer provider cost when present
- `estimated_risk_bp` from evidence or `None`
- `data_class` derived from custody policy, not from raw payload content

- [x] **Step 5: Verify focused tests**

Run:

```bash
cargo test -p exochain-avc receipt -- --nocapture
cargo test -p exochain-avc validation -- --nocapture
```

Expected: receipt compatibility and LLM binding tests pass.

## Task 3: Rust Node Route

**Files:**
- Modify: `crates/exo-node/src/avc.rs`
- Test: focused route tests in `crates/exo-node/src/avc.rs`

**Interfaces:**
- Consumes: `LlmUsageEvidenceEnvelope`, `validate_llm_usage_evidence`, LLM action derivation helper, existing AVC validation and receipt emission machinery.
- Produces: `POST /api/v1/avc/llm-usage/receipts/emit`

- [x] **Step 1: Write route happy-path test**

Add `avc_llm_usage_receipts_emit_accepts_valid_openai_style_evidence`:

- Registers a test AVC credential with `Permission::Execute`.
- Builds LLM usage evidence for provider `openai`, endpoint `responses`, custody mode `receipt_minimized`.
- Signs the evidence and the subject action.
- Calls `POST /api/v1/avc/llm-usage/receipts/emit`.
- Asserts response contains normal AVC receipt/finality fields.
- Asserts no raw prompt/output/provider token material exists in the response body.

- [x] **Step 2: Write negative route tests**

Add tests for:

- Missing AVC credential.
- Revoked AVC.
- Bad evidence signature.
- Bad subject signature.
- Missing idempotency key hash.
- Raw/decryptable content key in incoming evidence JSON.
- `ExternalPayloadRef` with no encrypted refs.
- `DagDbCustody` with zero custody policy hash.
- Duplicate idempotency key with different evidence hash.
- Receipt chain conflict.

- [x] **Step 3: Implement route DTOs**

Add request/response structs near the existing AVC DTOs. The request must accept:

- `validation`
- `subject_signature`
- `subject_public_key`
- `llm_usage_evidence`

The route must not accept raw prompt/output fields. Use `#[serde(deny_unknown_fields)]` on new DTOs where compatible with existing patterns.

- [x] **Step 4: Implement handler by reusing existing receipt emission**

Do not create a parallel trust path. The handler must:

- Validate LLM usage evidence.
- Verify adapter/evidence signature.
- Derive `AvcActionRequest` with `Permission::Execute`.
- Reuse registered credential validation.
- Reuse subject action signature verification.
- Reuse timestamp evidence/finality handling.
- Reuse idempotent storage and receipt chain conflict handling.

- [x] **Step 5: Verify focused tests**

Run:

```bash
cargo test -p exochain-node avc_llm_usage -- --nocapture
cargo test -p exochain-node avc_receipts_emit -- --nocapture
```

Expected: new LLM route tests pass and existing receipt emit tests still pass.

## Task 4: DAG DB Custody Documentation And Guards

**Files:**
- Modify: `INTEGRATION.md`
- Create: `docs/dagdb/llm-usage-custody.md`
- Modify or create focused DAG DB privacy/source guard tests

**Interfaces:**
- Consumes: storage mode names from Task 1.
- Produces: documented custody boundaries and tests preventing the old overclaim.

- [x] **Step 1: Add the custody doc**

Create `docs/dagdb/llm-usage-custody.md` with:

- The corrected custody statement from this plan.
- The three storage modes and what each stores.
- A rule that DAG DB stores governed data only through served routes and persistence APIs, never direct `dagdb_*` writes by consumers.
- A rule that raw/decryptable prompts and outputs require explicit `dagdb_custody` and separate consent/policy evidence.

- [x] **Step 2: Amend `INTEGRATION.md`**

Add a short section after the DAG DB runtime adapter contract explaining that DAG DB can store governed tenant data and that LLM usage receipt minimization is an adapter policy, not a global claim that EXOCHAIN never stores data.

- [x] **Step 3: Add source guard for banned overclaim**

Add a test or shell guard that fails if docs introduce the exact joined overclaim outside this plan file:

```text
EXOCHAIN + never stores decryptable payload material
```

The allowed phrasing must distinguish receipt minimization from DAG DB custody.

- [x] **Step 4: Add receipt-body exclusion tests**

Extend existing forbidden-material tests to reject `prompt`, `messages`, `completion`, `response_text`, `raw_output`, `raw_prompt`, `provider_api_key`, `bearer_token`, `kms_key`, and raw object URI fields in receipt bodies unless a test is explicitly exercising governed DAG DB custody records.

- [x] **Step 5: Verify focused tests**

Run:

```bash
bash tools/test_agent_prompt_boundaries.sh
cargo test -p exochain-dag-db-postgres --features postgres kg_export -- --nocapture
cargo test -p exochain-dag-db-exchange kg_writeback -- --nocapture
```

Expected: source guard and relevant privacy tests pass.

## Task 5: TypeScript OpenAI/MCP Proxy Package

**Files:**
- Create: `packages/exochain-llm-proxy/package.json`
- Create: `packages/exochain-llm-proxy/tsconfig.json`
- Create: `packages/exochain-llm-proxy/tsconfig.test.json`
- Create: `packages/exochain-llm-proxy/src/index.ts`
- Create: `packages/exochain-llm-proxy/src/openai.ts`
- Create: `packages/exochain-llm-proxy/src/mcp.ts`
- Create: `packages/exochain-llm-proxy/src/evidence.ts`
- Create: `packages/exochain-llm-proxy/src/receipt.ts`
- Create: `packages/exochain-llm-proxy/src/cli.ts`
- Create: `packages/exochain-llm-proxy/test/*.test.ts`

**Interfaces:**
- Produces:
  - `createReceiptedOpenAIClient`
  - `createReceiptedOpenAIProxy`
  - `createReceiptedMcpProxy`
  - `buildLlmUsageReceiptIntent`
  - `hashProviderPayload`
  - `emitUsageReceipt`
  - `resolveReceiptPending`

- [x] **Step 1: Scaffold package matching `packages/exochain-sdk`**

Use ESM, Node >= 20, TypeScript strict mode, `npm run build`, `npm test`, and injected `fetch` for tests.

- [x] **Step 2: Write fake OpenAI tests**

Tests must cover:

- Responses success.
- Chat Completions success.
- Provider failure emits failure receipt intent without leaking provider response body.
- Provider success plus receipt failure returns `receipt_pending`.
- Streaming final usage missing returns receipt evidence with `usage_complete: false`.
- No raw request/response text appears in the receipt body.

- [x] **Step 3: Write fake MCP tests**

Tests must cover:

- `tools/call` success receipt.
- `tools/call` failure receipt.
- Malformed MCP response rejected as untrusted.
- Missing MCP server config fails before call.
- Tool arguments and tool result are hashed/redacted by default.

- [x] **Step 4: Write fake object store/KMS tests**

Tests must cover:

- `external_payload_ref` writes encrypted blobs to fake object store.
- KMS failure blocks decryptable storage.
- Object store success plus receipt failure returns `receipt_pending`.
- Receipt evidence contains only hashed opaque refs, not raw URI or key id.

- [x] **Step 5: Implement package**

Implement the proxy so production never releases raw model/tool output without a committed receipt. The CLI commands are:

```bash
exochain-llm-proxy openai
exochain-llm-proxy mcp
exochain-llm-proxy receipt-status
```

All commands require explicit gateway URL, tenant id, namespace, actor DID, authority scope, storage mode, and idempotency key input.

- [x] **Step 6: Verify package tests**

Run:

```bash
cd packages/exochain-llm-proxy
npm test
npm run build
```

Expected: TypeScript build and Node tests pass without live OpenAI or live MCP calls.

## Task 6: End-To-End Integration Smoke

**Files:**
- Create: `tools/llm_usage_receipt_smoke.mjs`
- Test: shell or Node smoke fixture under `tools/` or `packages/exochain-llm-proxy/test/`

**Interfaces:**
- Consumes: Rust route from Task 3 and TypeScript proxy from Task 5.
- Produces: one command proving provider proxy -> optional encrypted payload ref -> EXOCHAIN AVC receipt -> receipt lookup.

- [x] **Step 1: Write smoke fixture**

Use fake provider and fake object store by default. The smoke must:

- Build deterministic OpenAI-style request/response fixtures.
- Hash prompt/output payloads.
- Store encrypted payload refs only when configured for `external_payload_ref`.
- Emit an LLM usage receipt through local EXOCHAIN node or test harness.
- Lookup the emitted receipt by hash/action commitment.
- Assert no raw prompt/output appears in the receipt.

- [x] **Step 2: Add production-readiness failure cases**

Smoke must fail when:

- Receipt emission is unavailable.
- Idempotency replay conflicts.
- Custody mode is omitted.
- Tenant/namespace mismatch occurs.
- Provider usage fields are absent and endpoint policy requires complete usage.

- [x] **Step 3: Verify smoke**

Run:

```bash
node tools/llm_usage_receipt_smoke.mjs --fixture fake-openai --storage-mode receipt_minimized
node tools/llm_usage_receipt_smoke.mjs --fixture fake-mcp --storage-mode receipt_minimized
node tools/llm_usage_receipt_smoke.mjs --fixture fake-openai --storage-mode external_payload_ref
```

Expected: all smoke commands pass with fake services; no live provider credentials are required.

## Task 7: Final Verification Gates

**Files:**
- No new files unless a focused guard needs a small helper script.

**Interfaces:**
- Consumes all prior tasks.
- Produces a verified implementation branch ready for review.

- [x] **Step 1: Run Rust focused gates**

```bash
cargo test -p exochain-avc llm_usage -- --nocapture
cargo test -p exochain-avc receipt -- --nocapture
cargo test -p exochain-node avc_llm_usage -- --nocapture
cargo test -p exochain-node avc_receipts_emit -- --nocapture
```

- [x] **Step 2: Run TypeScript gates**

```bash
cd packages/exochain-llm-proxy
npm test
npm run build
```

- [x] **Step 3: Run privacy/source guards**

```bash
bash tools/test_agent_prompt_boundaries.sh
bash tools/test_lynk_receipt_privacy.sh
```

The LYNK privacy guard must return no disallowed production/doc hits. Test fixture
hits are allowed only when the test asserts rejection or redaction.

- [x] **Step 4: Run integration smoke**

```bash
node tools/llm_usage_receipt_smoke.mjs --fixture fake-openai --storage-mode receipt_minimized
node tools/llm_usage_receipt_smoke.mjs --fixture fake-mcp --storage-mode receipt_minimized
node tools/llm_usage_receipt_smoke.mjs --fixture fake-openai --storage-mode external_payload_ref
```

- [x] **Step 5: Run formatting and lint gates**

```bash
cargo fmt --all -- --check
cargo clippy -p exochain-avc --all-targets -- -D warnings
cargo clippy -p exochain-node --all-targets -- -D warnings
```

Expected: all focused gates pass before broader workspace gates are attempted.

## Task 8: Coverage-First Release Packaging

**Files:**
- Modify: `docs/superpowers/plans/2026-07-08-llm-usage-receipt-extensions.md`
- Modify: `.superpowers/sdd/progress.md`
- Create: `packages/exochain-llm-proxy/README.md`
- Create: `packages/exochain-llm-proxy/AGENTS.md`
- Create: `packages/exochain-llm-proxy/examples/*.ts`
- Create: `packages/exochain-llm-proxy/snippets/*.md`
- Modify: `packages/exochain-llm-proxy/package.json`
- Modify: `packages/exochain-llm-proxy/tsconfig.test.json`
- Modify: `packages/exochain-llm-proxy/test/*.test.ts`
- Modify: `docs/avc/README.md`, `docs/guides/ai-agent-guide.md`, `docs/guides/mcp-integration.md`, `packages/README.md`, and `README.md`
- Modify: `site/**`
- Create: `docs/superpowers/lynk-coverage-evidence-2026-07-08.md`

**Interfaces:**
- Produces release packaging, agent-discoverable usage material, public exochain.com discovery copy, focused coverage gates, future-wave regression baselines, and package artifact checks.

- [x] **Step 1: Add wave readiness and coverage matrix**

Add a "Wave Readiness" section that fixes scope for:

- V1: OpenAI Responses, OpenAI Chat Completions, and MCP `tools/call`.
- Wave 2: Anthropic Messages as a separately tested provider adapter.
- Wave 3: generic OpenAI-compatible endpoints plus API/SDK wrapper modes.
- Wave 4: expanded MCP and workflow receipt producers for tools that create evidence only.

Add a "Coverage Matrix" section that names fast gates before the hour-scale Gate 3 tarpaulin run. Treat "110%" as a coverage reserve: every current branch plus future fail-closed baselines, not a literal percentage above 100.

- [x] **Step 2: Add package release artifacts**

Create package README, package AGENTS guidance, runnable examples, environment template, agent integration brief, and receipt-pending runbook. Every example must use placeholder values only and must not include raw provider secrets or customer object URIs.

- [x] **Step 3: Add TypeScript coverage and package gates**

Add:

```bash
npm run test:coverage
npm run check:package
npm run pack:dry-run
```

`test:coverage` must use Node test coverage thresholds of at least 95% lines, 95% functions, and 90% branches for package source. `check:package` must fail if README, AGENTS guidance, examples, snippets, or compiled declarations are missing.

- [x] **Step 4: Add future-wave fail-closed baselines**

Add executable tests proving unsupported Anthropic, generic OpenAI-compatible, SDK wrapper, and expanded MCP workflow lanes cannot claim receipt support in V1. Future waves must convert the relevant unsupported-lane test into a positive adapter test while retaining rejection cases.

- [x] **Step 5: Expand docs, site discovery, and privacy guards**

Update AVC, MCP, AI-agent, package index, top-level docs, and the public `/site` surface for exochain.com so humans and AI coding agents can discover LYNK. Classify `/site` as an adjacent public surface: it may describe the tested LYNK adapter and point to package/docs artifacts, but it must not imply constitutional enforcement beyond the actual EXOCHAIN core/API receipt path. Extend the privacy guard so README, AGENTS guidance, examples, snippets, and public-site copy cannot introduce raw prompts, outputs, provider keys, bearer tokens, raw object URIs, KMS keys, unsupported release-readiness claims, or the old EXOCHAIN/DAG DB custody overclaim.

- [x] **Step 6: Verify focused coverage before Gate 3**

Run:

```bash
cargo test -p exochain-avc llm_usage -- --nocapture
cargo test -p exochain-avc receipt -- --nocapture
cargo test -p exochain-avc validation -- --nocapture
cargo test -p exochain-node avc_llm_usage -- --nocapture
cargo test -p exochain-node avc_receipts_emit -- --nocapture
cd packages/exochain-llm-proxy && npm test && npm run build && npm run test:coverage && npm run check:package && npm run pack:dry-run
bash tools/test_agent_prompt_boundaries.sh
bash tools/test_lynk_receipt_privacy.sh
site-specific build/test command discovered from /site
```

Only after these pass, run the full scoped Gate 3 command:

```bash
cargo tarpaulin --workspace --exclude exochain-wasm --exclude exochain-proofs --out xml --output-dir coverage --engine llvm --timeout 900 --fail-under 90
```

If Gate 3 fails, parse `coverage/cobertura.xml`, add tests for uncovered LYNK branches, rerun focused coverage first, then rerun full Gate 3 once.

## Wave Readiness

- V1 is OpenAI Responses, OpenAI Chat Completions, and MCP `tools/call` only. These are positive support lanes and must remain production fail-closed when receipt emission fails.
- Wave 2 adds Anthropic Messages behind the same evidence and receipt contract. Until then, package CLI and public exports must reject Anthropic as unsupported rather than routing it through OpenAI assumptions.
- Wave 3 adds generic OpenAI-compatible endpoints, direct API wrappers, and SDK wrapper modes. Until then, generic base URLs may be used only for the OpenAI-compatible v1 paths already implemented.
- Wave 4 adds expanded MCP/workflow producers for Codex, GitHub, Slack, Teams, and adjacent tools. These producers may create signed LYNK evidence; they must not mint EXOCHAIN receipts directly.
- Every new wave must preserve the v1 regression suite, add positive adapter tests for its own lane, and keep unsupported-lane rejection tests for all lanes that still have no implementation.

## Coverage Matrix

| Surface | Fast coverage command | Required coverage before Gate 3 |
| --- | --- | --- |
| Rust AVC evidence | `cargo test -p exochain-avc llm_usage -- --nocapture` | Hash determinism, schema/domain checks, all validation failures, overflow, integer-only usage, encrypted-ref validation, custody modes, and forbidden-material guards. |
| Rust receipt/action | `cargo test -p exochain-avc receipt -- --nocapture`; `cargo test -p exochain-avc validation -- --nocapture` | Legacy compatibility, evidence hash binding, canonical `Permission::Execute`, custody data class, budget mapping, and fail-closed validation. |
| Rust node route/auth | `cargo test -p exochain-node avc_llm_usage -- --nocapture`; `cargo test -p exochain-node avc_receipts_emit -- --nocapture` | Happy paths, signature/key-resolution branches, bearer carve-out, malformed body, idempotent replay, evidence conflict, timestamp/finality failure, and response privacy. |
| TypeScript proxy | `cd packages/exochain-llm-proxy && npm run test:coverage` | OpenAI, MCP, storage, delivery, CLI, future unsupported lanes, examples, package artifacts, and privacy checks. |
| Smoke | `node tools/llm_usage_receipt_smoke.mjs ...` | Fake OpenAI/MCP success plus expected failures for receipt, idempotency, custody, tenant, and incomplete usage policies. |
| Privacy/docs | `bash tools/test_lynk_receipt_privacy.sh` | Docs, examples, snippets, source, and smoke fixtures do not leak raw/decryptable material or revive the old custody overclaim. |
| Public site | site-specific build/test command discovered from `/site` | LYNK is discoverable on exochain.com as an adjacent public surface, uses only placeholder-safe references, and does not make unsupported production/package-readiness claims. |
| Full Gate 3 | `cargo tarpaulin --workspace --exclude exochain-wasm --exclude exochain-proofs --out xml --output-dir coverage --engine llvm --timeout 900 --fail-under 90` | Run only after fast gates pass. Use `coverage/cobertura.xml` to target any uncovered LYNK branches. |

## Implementation Decisions Captured

- Custody default: `receipt_minimized`.
- Explicit custody modes: `receipt_minimized`, `external_payload_ref`, `dagdb_custody`.
- Encrypted payload refs may appear in receipt evidence only as hashed opaque references, not raw URIs or key identifiers.
- Production LLM receipt claims require committed AVC receipt/finality. Legal/compliance-grade claims require external timestamp/finality evidence, not local HLC alone.
- OpenAI exact field mapping is an implementation-time verification step against official docs; tests use fake providers and endpoint-specific fixture adapters.

## Self-Review

- Spec coverage: The plan covers the Rust evidence contract, receipt binding, node route, DAG DB custody correction, TypeScript OpenAI/MCP proxy, integration smoke, and verification gates.
- Placeholder scan: The plan avoids open-ended placeholder language and includes exact file paths, interface names, commands, and pass/fail expectations.
- Type consistency: Storage modes, exported helper names, route path, and package names are consistent across tasks.
