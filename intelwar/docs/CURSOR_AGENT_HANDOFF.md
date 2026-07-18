# CURSOR_AGENT_HANDOFF.md

**Project**: IntelWar  
**Branch**: `intelwar` (from v0.2.3 `a50a15fd`)  
**Latest Commit**: `dec9ddc8` (bootstrap)  
**Current Status**: Uncommitted changes exist from the last Cursor session (Invariants alignment + Rust overlay updates).  
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
- **Core**: `intelwar/crates/intelwar-core` — working consent → authority → CGR → overlay → receipt → `exo_dag::append` path. Tests passing, clippy clean.
- **Apps**: `intelwar/apps/intelwar-net` — Railway-ready shell with Living Log viewer + consent demo.
- **Services**: `intelwar/services/log-api` (adjacent, `simulated: true`).
- **Tools**: `intelwar/tools/triage.js` + `emit-log-entry.js`
- **Hooks**: Basic `.ai` crosscheck, `.tv` provenance, and WASM hook stubs.

### Perpetual Motion Backlog (Current Priority Order)
1. **PM-001** — Wire `log-api` cleanly into `intelwar-core` (remove dual simulated paths)
2. **PM-002** — Persist via `exo-gateway` DAG DB (fail-closed)
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

**First Action Required:**

1. Review the uncommitted changes from the previous session.
2. Create a clean commit on the `intelwar` branch with a clear message.
3. Update this handoff file with the new session block once the commit is done.
4. Then begin work on **PM-001** (or the next highest priority item agreed with the user).

Do not open a PR to `main`. All work stays on the `intelwar` branch until further notice.

This document is now the single source of truth for state.  
Future sessions should be able to begin working with minimal additional prompting after reading the latest session block.

---

## Session Log
