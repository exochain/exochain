# Cursor Agent Handoff — IntelWar

**Read this first.** Then Constitution → Invariants → Living Log model → Integration map.

| Field | Value |
|-------|-------|
| Branch | `intelwar` (from tag `v0.2.3` / `a50a15fd`) |
| Substrate | EXOCHAIN **v0.2.3** |
| Constitution | `intelwar/INTELWAR_CONSTITUTION.md` |
| Invariants | `intelwar/docs/INTELWAR_INVARIANTS_v1.md` |
| Log model | `intelwar/docs/LIVING_LOG_DATA_MODEL.md` |
| Integration | `intelwar/docs/INTELWAR_EXOCHAIN_v0.2.3_INTEGRATION.md` |
| Intake | `intelwar/ADJACENT-SURFACE-INTAKE.md` |

---

## Current constitutional state

- **8 IntelWar invariants** formalized (IW-1…IW-8), CGR-encodable.
- **Living Log append path implemented** in Rust: consent → authority → CGR →
  IntelWar overlays → receipt → `exo_dag::append`.
- **Tests green:** `cargo test -p intelwar-core` (4 tests).
- **Adjacent MVP:** `apps/intelwar-net` + `services/log-api` (simulated Log;
  trust_claim: none).
- **Log status:** Genesis simulated entry in log-api; constitutional genesis
  proven in Rust tests (not yet persisted to production DAG DB).

---

## Key file locations

| Concern | Path |
|---------|------|
| Append flow | `intelwar/crates/intelwar-core/src/append_flow.rs` |
| LogEntry / receipt | `intelwar/crates/intelwar-core/src/log_entry.rs` |
| IntelWar invariants | `intelwar/crates/intelwar-core/src/invariants.rs` |
| CGR Kernel | `crates/exo-gatekeeper/src/kernel.rs` |
| EXOCHAIN invariants | `crates/exo-gatekeeper/src/invariants.rs` |
| DAG append | `crates/exo-dag/src/dag.rs` |
| WASM hooks | `intelwar/wasm/hooks.js` |
| .ai stub | `intelwar/apps/intelwar-net/src/ai/crosscheck.js` |
| .tv stub | `intelwar/apps/intelwar-net/src/tv/provenance.js` |
| Triage | `intelwar/tools/triage.js` |
| Emit LogEntry | `intelwar/tools/emit-log-entry.js` |

### Primitive mappings (quick)

- Consent → `BailmentState` + `ConsentRecord` + `consent_allows_log_append`
- Authority → `AuthorityChain` / `signed_authority_link`
- Adjudication → `Kernel::adjudicate` action `intelwar.log.append`
- Voice → `VoiceKind` + `AgentAttestation` (IW-4)
- Ledger → `exo_dag::dag::append`
- Receipts → `LivingLogReceipt` chain (`previous_receipt_hash`)

---

## Token efficiency ($200 Cursor plan)

1. **Start here** — do not re-read all of EXOCHAIN; use Integration map + crate paths.
2. **One deep pass** on a crate, then reference by path/symbol in follow-ups.
3. Prefer **Composer multi-file edits** inside `intelwar/` with grounded paths.
4. Scope cargo to `-p intelwar-core` during iteration; full workspace gates only when
   touching shared crates / CI.
5. Put untrusted user/workflow text between `BEGIN_UNTRUSTED_*` markers (AGENTS.md).
6. After major work: emit Log artifact + update backlog below (Perpetual Motion Loop).

---

## How to propose changes that feed the Living Log

1. Triage: `node intelwar/tools/triage.js "your change summary"`.
2. Emit: `node intelwar/tools/emit-log-entry.js --summary "..." --voice synthetic`.
3. Implement against Constitution + invariant IDs in the PR/commit message.
4. For constitutional commits: extend `append_flow_tests` / call `append_log_entry`.
5. Adjacent UI changes must keep `simulated: true` / `trust_claim: none` until
   the adapter path is proven.

AI contributions MUST include `agent_attestation` (IW-4). Never present synthetic
output as human quorum voice.

---

## Perpetual Motion Backlog (ordered by compounding value)

```yaml
- id: PM-001
  title: Wire log-api append to intelwar-core via CLI or FFI/WASM
  why: Ends dual simulated/constitutional paths for demo appends
  invariants: [consent-before-memory, provenance-compounding, living-log-integrity]
  paths: [intelwar/services/log-api, intelwar/crates/intelwar-core, intelwar/wasm]
  command: cargo test -p intelwar-core && npm --prefix intelwar/services/log-api test
  done_when: Demo append can optionally set simulated:false only after Kernel Permitted

- id: PM-002
  title: Persist Living Log through exo-gateway DAG DB route
  why: Production memory; fail closed without pool/authority
  invariants: [living-log-integrity, authority-bound-append]
  paths: [crates/exo-gateway, intelwar/crates/intelwar-core, docs/dagdb]
  command: cargo test -p exochain-gateway --test dagdb_route_integration_contract
  done_when: Append writes tenant-scoped DAG DB with write signature

- id: PM-003
  title: DebateSession adapter over decision-forum DecisionObject
  why: Unlocks Doctrine/Amendment (IW-7) for real governance
  invariants: [debate-before-doctrine, human-override-sacred]
  paths: [intelwar/crates/intelwar-core/src/debate_session.rs, crates/decision-forum]
  command: cargo test -p intelwar-core
  done_when: Doctrine append fails without Approved/Recorded/Closed debate

- id: PM-004
  title: .ai crosscheck service calling CrossCheckResult verification
  why: Compounds multi-intelligence review before commit
  invariants: [crosscheck-before-commit, multi-intelligence-transparent]
  paths: [intelwar/apps/intelwar-net/src/ai, intelwar/crates/intelwar-core/src/crosscheck.rs]
  command: cargo test -p intelwar-core
  done_when: requires_crosscheck entries reject self-check and accept distinct checker

- id: PM-005
  title: .tv provenance viewer over LivingLogReceipt chains
  why: Makes compounding wisdom visible and auditable
  invariants: [provenance-compounding, multi-intelligence-transparent]
  paths: [intelwar/apps/intelwar-net/src/tv, intelwar/wasm]
  command: npm --prefix intelwar/apps/intelwar-net run build
  done_when: Viewer shows receipt chain + voice taxonomy for a real receipt

- id: PM-006
  title: ExoForge panel automation for IntelWar GitHub issues
  why: Self-governing intake with invariant labels
  invariants: [debate-before-doctrine]
  paths: [intelwar/tools/triage.js, exoforge/bin/exoforge-triage.js]
  command: node intelwar/tools/triage.js "consent gate regression"
  done_when: Issues auto-tagged with IW invariant ids

- id: PM-007
  title: Railway deploy intelwar.net with fail-closed env
  why: Public adjacent shell with honest trust labeling
  invariants: [human-override-sacred]
  paths: [intelwar/apps/intelwar-net/railway.json, intelwar/ADJACENT-SURFACE-INTAKE.md]
  command: npm --prefix intelwar/apps/intelwar-net run build
  done_when: Production site live; missing API URL yields empty/error Log not fake Permitted
```

---

## Validation commands

```bash
cargo test -p intelwar-core
node intelwar/tools/triage.js "consent living log append"
node intelwar/tools/emit-log-entry.js --summary "handoff checkpoint"
cd intelwar/services/log-api && npm install && npm test
cd intelwar/apps/intelwar-net && npm install && npm run build
```

## Agent attestation for this bootstrap session

```json
{
  "voice_kind": "synthetic",
  "tool": "cursor-agent",
  "model_id": "cursor-grok-4.5",
  "work": "IntelWar Phase 1-3 constitutional bootstrap on EXOCHAIN v0.2.3"
}
```
