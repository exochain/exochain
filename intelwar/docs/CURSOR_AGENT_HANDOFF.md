# CURSOR_AGENT_HANDOFF.md

**Project**: IntelWar  
**Branch**: `intelwar` (from v0.2.3 `a50a15fd`)  
**Latest Commit**: `9146588d` (PM-001 Kernel bridge + handoff sessions)
**Current Status**: PM-001 Kernel bridge landed (CLI + env-gated log-api). Next: PM-002.  
**Entry Point Rule**: Every new Cursor agent session **must** start by reading this entire file.

---

## CURRENT GLOBAL STATE (as of 2026-07-18)

### Constitutional Foundation (Adopted)
- **Invariants**: `intelwar/docs/INTELWAR_INVARIANTS_v1.md` (IW-1 to IW-8 + v0.2.3 Implementation Notes)
- **Constitution**: `intelwar/INTELWAR_CONSTITUTION.md`
- **Living Log Data Model**: `intelwar/docs/LIVING_LOG_DATA_MODEL.md`
- **Integration Map**: `intelwar/docs/INTELWAR_EXOCHAIN_v0.2.3_INTEGRATION.md`

**Key v0.2.3 Constraints** (must be respected):
- Gatekeeper governed role names are closed — custom roles risk violating `SeparationOfPowers`.
- Prefer `AuthorityLink` / `BailmentState` on the Kernel path for hot consent/authority checks.
- `QuorumLegitimate` is a no-op when `quorum_evidence` is `None`.
- All adjacent/MVP surfaces must remain explicitly marked `simulated: true` until the real WASM + gateway path proves `Permitted`.

### What Currently Exists
- **Core**: `intelwar/crates/intelwar-core` — append path + `bridge` module + `intelwar-log-append` CLI.
- **Apps**: `intelwar/apps/intelwar-net` — Railway-ready shell with Living Log viewer + consent demo.
- **Services**: `intelwar/services/log-api` — simulated by default; Kernel path when `INTELWAR_CORE_BIN` is set (fail closed on bridge errors).
- **Tools**: `intelwar/tools/triage.js` + `emit-log-entry.js`
- **Hooks**: Basic `.ai` crosscheck, `.tv` provenance, and WASM hook stubs.

### Perpetual Motion Backlog (Current Priority Order)
1. ~~**PM-001** — Wire `log-api` into `intelwar-core`~~ **DONE** (CLI bridge; ephemeral single-node DAG; receipt chain persists)
2. **PM-002** — Persist via `exo-gateway` DAG DB (fail-closed) — *includes multi-node DAG continuity*
3. **PM-003** — `DebateSession` ↔ decision-forum integration (respect IW-4 evidence links + closed role names)
4. **PM-004** — `.ai` crosscheck engine → `CrossCheckResult` verification path
5. **PM-005** — `.tv` provenance viewer over receipt chains
6. **PM-006** — ExoForge-style issue triage with IW labels
7. **PM-007** — Railway deploy of `intelwar.net` with fail-closed environment

### Session Protocol (Mandatory)
Every Cursor agent session **must** end by appending a block in this exact format to the bottom of this file:

```markdown
## Session [YYYY-MM-DD HH:MM] — [Short Descriptive Title]

**Changes Made:**
- ...

**Files Modified:**
- ...

**State Deltas:**
- ...

**Backlog Updates:**
- ...

**Validation Commands Run:**
- `cargo test -p intelwar-core`
- `cargo clippy -p intelwar-core -- -D warnings`
- ...

**Open Questions / Decisions for Next Session:**
- ...

**Recommended Next Action:**
- ...
```

### Validation Commands (Always Re-run After Changes)

```bash
cargo test -p intelwar-core
cargo clippy -p intelwar-core -- -D warnings
```

### Efficiency Rules for $200 Cursor Plan

1. Always start by reading this file + the latest session block.
2. Prefer Composer for multi-file refactors.
3. Reference files and invariants by ID (e.g. IW-2, PM-001) instead of re-explaining context.
4. Keep new context additions minimal and structured.

---

## CURRENT TASK FOR THIS SESSION

**Next:** PM-002 — Persist Living Log via `exo-gateway` DAG DB (fail-closed), replacing ephemeral single-node `dag_scope`.

**Kernel bridge usage (PM-001):**
```bash
cargo build -p intelwar-core --bin intelwar-log-append
export INTELWAR_CORE_BIN="$PWD/target/debug/intelwar-log-append"
export INTELWAR_CORE_STATE_DIR="$PWD/.intelwar-bridge-state"
npm --prefix intelwar/services/log-api start
```

Do not open a PR to `main`. All work stays on the `intelwar` branch until further notice.

This document is now the single source of truth for state.  
Future sessions should be able to begin working with minimal additional prompting after reading the latest session block.

---

## Session Log

## Session 2026-07-18 14:26 — Adopt invariants + install handoff

**Changes Made:**
- Replaced `INTELWAR_INVARIANTS_v1.md` with ratified IW-1…IW-8 + v0.2.3 notes
- Aligned `intelwar-core` overlay enum/checks and tooling IDs
- Installed this handoff as the mandatory session entrypoint
- Committed alignment as `f0846b01`

**Files Modified:**
- `intelwar/docs/INTELWAR_INVARIANTS_v1.md`
- `intelwar/crates/intelwar-core/src/invariants.rs` (+ related modules)
- `intelwar/docs/CURSOR_AGENT_HANDOFF.md`
- Constitution, integration map, Living Log model, triage/emit tools, adjacent stubs

**State Deltas:**
- Latest commit: `dec9ddc8` → `f0846b01`
- Invariant wire IDs now: `consent-required` … `log-integrity`
- Working tree clean after commit; PM-001 next

**Backlog Updates:**
- PM-003 note corrected to IW-4 (evidence) + closed role names (not IW-7)
- No backlog items completed this session yet

**Validation Commands Run:**
- `cargo test -p intelwar-core`
- `cargo clippy -p intelwar-core --all-targets -- -D warnings`

**Open Questions / Decisions for Next Session:**
- PM-001 bridge shape: subprocess CLI vs WASM vs FFI for Node `log-api`?
- Recommendation in flight: CLI binary + env-gated invoke; keep `simulated: true` when unset (fail closed / honest labeling)

**Recommended Next Action:**
- Implement PM-001: `intelwar-log-append` CLI + `log-api` env-gated Kernel bridge

## Session 2026-07-18 14:30 — Handoff install + PM-001 Kernel bridge

**Changes Made:**
- Replaced handoff with integrated perpetual-motion entrypoint + session protocol
- Committed invariants adoption as `f0846b01`
- Implemented PM-001: `bridge` module, `intelwar-log-append` CLI, env-gated `log-api` invoke
- Fail closed when `INTELWAR_CORE_BIN` set and bridge fails (no simulated Permitted)
- Receipt hashes chain across CLI invokes; DAG remains `ephemeral-single-node` until PM-002

**Files Modified:**
- `intelwar/docs/CURSOR_AGENT_HANDOFF.md`
- `intelwar/crates/intelwar-core/src/bridge.rs`
- `intelwar/crates/intelwar-core/src/bin/intelwar_log_append.rs`
- `intelwar/crates/intelwar-core/Cargo.toml`
- `intelwar/services/log-api/server.js`
- `.gitignore`

**State Deltas:**
- PM-001 complete (bridge shape = CLI + env gate)
- Unset `INTELWAR_CORE_BIN` → adjacent `simulated: true`
- Set `INTELWAR_CORE_BIN` → `simulated: false` + `kernel_adjudicated: true` on success

**Backlog Updates:**
- PM-001 marked DONE
- PM-002 now highest priority (DAG DB + multi-node continuity)

**Validation Commands Run:**
- `cargo test -p intelwar-core`
- `cargo clippy -p intelwar-core --all-targets -- -D warnings`
- CLI smoke: `intelwar-log-append` stdin JSON → `kernel_verdict: permitted`
- `npm --prefix intelwar/services/log-api test`

**Open Questions / Decisions for Next Session:**
- PM-002: store multi-node DAG in DAG DB vs local file rebuild with sealed timestamps?
- Should Railway deploy ship a prebuilt `intelwar-log-append` binary or keep simulated-only?

**Recommended Next Action:**
- Start PM-002 (gateway DAG DB persistence) or PM-007 if deploy urgency wins
