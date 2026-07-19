# CURSOR_AGENT_HANDOFF — IntelWar Operating Document

**Project:** IntelWar  
**Branch:** `intelwar` (never merge or open PRs to `main` without explicit human instruction)  
**Substrate:** EXOCHAIN v0.2.3 (`a50a15fd`)  
**Constitutional roots:** `INTELWAR_CONSTITUTION.md`, `docs/INTELWAR_INVARIANTS_v1.md` (IW-1…IW-8)  
**Entry rule:** Every Cursor agent session **must** read this entire file before changing code, docs, or backlog state.

This document is the **single source of truth** for project state, autonomy boundaries, and session continuity. Prefer updating this file over asking the human to re-explain context.

---

## 1. Autonomy & Decision Framework

### 1.1 Authorized to proceed without asking

The agent **may autonomously**:

1. **Read and analyze** any file under `intelwar/`, plus EXOCHAIN crates needed to ground work (especially `exo-gatekeeper`, `exo-dag`, `exo-consent`, `exo-authority`, `decision-forum`, `exochain-wasm`).
2. **Implement the currently authorized backlog item** (see §8) end-to-end within its documented scope, including tests, adjacent-shell wiring, and docs that describe the change.
3. **Fix bugs, clippy/fmt issues, and failing tests** introduced by its own work on the authorized item.
4. **Commit to `intelwar`** when quality gates pass (§6), using clear conventional messages focused on *why*.
5. **Update this handoff** (global state, backlog status, session log) after meaningful work — without waiting for permission.
6. **Run scoped validation** (`cargo test/clippy -p intelwar-core`, npm tests under `intelwar/services` / `intelwar/apps` as relevant).
7. **Emit Living Log artifacts** via `intelwar/tools/emit-log-entry.js` and triage via `intelwar/tools/triage.js` for decisions it makes.
8. **Small refactors** strictly inside the authorized item’s blast radius when they improve clarity or determinism without changing trust semantics.
9. **Continue the same authorized item** across a session boundary when the prior session block’s “Recommended Next Action” names that continuation and no hold is active.

### 1.2 Must stop and wait for explicit human confirmation

The agent **must stop** (update handoff with an open question; do not proceed) when:

| Trigger | Examples |
|---------|----------|
| **Hold points in §8** | Starting PM-002; marketing / public positioning work; any item marked HOLD |
| **Invariant or constitution change** | Editing IW-1…IW-8 semantics; amending `INTELWAR_CONSTITUTION.md` Articles; renumbering/renaming invariant wire IDs |
| **Trust-boundary change** | Claiming `simulated: false` / `kernel_adjudicated: true` without Kernel path; removing fail-closed behavior; blending adjacent and core secrets |
| **Consent model change** | Making Node `/api/consent` drive Kernel bailment; replacing fixture bailment with production DID lifecycle; weakening IW-1 checks |
| **Provenance / LogIntegrity semantics** | Changing receipt chaining rules; claiming multi-node DAG integrity without persistence; hashing JSON instead of CBOR |
| **Secrets & credentials** | Committing keys, tokens, `.env`, `bridge_state.json` with live keys; introducing shared core/adjacent production secrets |
| **Deployment / public surface** | Railway/production deploy of intelwar.net; DNS; public trust claims; enabling Kernel bridge in production by default |
| **Backlog priority rewrite** | Reordering PM items, cancelling DONE items, inventing parallel “urgent” tracks that displace §8 authorization |
| **Git remote / main** | Push to remote (unless human asked); PR to `main`; force-push; rebase onto main that rewrites shared history |
| **Ambiguous scope that expands TCB** | New crates that become workspace members; new ingress paths for credentials/signatures; WASM trust claims |
| **Repeated validation failure** | Same gate fails twice after a fix attempt → escalate in handoff; do not loop |

When stopping: append or update the session block with **Open Questions**, set **Current Task** to HOLD naming the decision, and end the turn. Do not half-implement past the boundary.

### 1.3 Commit rules (autonomous)

**May commit on `intelwar` when all are true:**

- Change set is limited to the authorized task (or handoff-only / docs-only continuity).
- Relevant quality gates in §6 passed.
- No secrets, credentials, or local bridge state files staged.
- Commit message explains why; references PM-ID and/or IW-IDs when relevant.
- Human has not forbidden commits for the current task.

**Must not commit when:**

- Gates fail; working tree includes unknown generated noise; or change touches a §1.2 stop trigger without prior human approval recorded in the handoff.

**Never:** `--no-verify`, force-push, amend others’ commits, or commit to `main`.

### 1.4 Starting vs continuing backlog items

- **Continue** the item named in §8 “Authorized now” without asking.
- **Start a new PM item** only if: (a) §8 authorizes it, or (b) the human explicitly names it in the latest user message, or (c) the prior session’s Recommended Next Action names it **and** no HOLD blocks it.
- **Do not** start marketing work, or enable Kernel/DAG secrets on public Railway, while §8 marks them HOLD.
- Completing an item: mark DONE in §4, update §3/§8, recommend the next item — but do not begin the next HOLD item until authorized.

### 1.5 Constitutional / trust / secrets / deploy (summary)

Treat as **human-gated** unless §8 later lifts the gate in writing:

- Invariants, constitution amendments, consent architecture, provenance semantics  
- Promoting adjacent paths off `simulated: true`  
- Secret handling beyond local prototype fixtures  
- Production/Railway/public launch and marketing claims  

---

## 2. Operating Principles

### 2.1 Prioritization

1. **Constitutional integrity** over feature velocity (IW-1, IW-2, IW-6, IW-8 especially).  
2. **Authorized backlog item** over opportunistic cleanup.  
3. **Fail-closed, honest labeling** over demo convenience.  
4. **Reuse EXOCHAIN v0.2.3 primitives** over reinvention (`AuthorityLink` / `BailmentState` on Kernel hot path; closed role names).  
5. **Compounding documentation** (this handoff + Living Log artifacts) over tribal knowledge.  
6. **Scoped validation** during iteration; widen gates only when workspace-wide crates outside `intelwar/` change.

### 2.2 Handling uncertainty

- Prefer the interpretation that **fails closed** and keeps `simulated: true` on adjacent surfaces.  
- If two designs are plausible and only one expands the trust boundary, choose the narrower one or STOP (§1.2).  
- Record the decision and alternative in the session block.  
- Do not invent constitutional authority for AI prose (IW-3): attest synthetic work.

### 2.3 Documenting decisions

- Material decisions → session block + optional `emit-log-entry.js` artifact.  
- Cite **IW-IDs** and **PM-IDs** instead of restating full doctrine.  
- Update §3 and §8 when reality changes (new bridge, new hold, new DONE).

### 2.4 Progress and blockers inside this file

- Progress: session blocks + backlog status columns.  
- Blockers: HOLD in §8 + Open Questions with a concrete ask for the human.  
- Do not rely on chat history as source of truth; the next session may only see this file.

### 2.5 Token efficiency ($200 plan)

- Start from this file + latest session block; then open only cited paths.  
- Prefer multi-file edits with grounded crate paths.  
- Avoid re-deriving EXOCHAIN internals already mapped in `INTELWAR_EXOCHAIN_v0.2.3_INTEGRATION.md`.

---

## 3. Current Global State

*As of PM-007 public deploy session 2026-07-18. Confirm with `git log -1 --oneline` on `intelwar`.*

### 3.1 Branch & commits

| Fact | Value |
|------|--------|
| Branch | `intelwar` |
| Base | Tag `v0.2.3` / `a50a15fd` |
| Notable commits | … · `63b6295e` PM-004–006 · tip includes PM-007 deploy |
| Remote / main | No PR to `main` authorized; do not push unless human asks |
| Public URLs | Web https://intelwar-net-production.up.railway.app · API https://log-api-production-0798.up.railway.app |

### 3.2 Constitutional foundation (adopted)

| Doc | Role |
|-----|------|
| `intelwar/INTELWAR_CONSTITUTION.md` | Living governance compact |
| `intelwar/docs/INTELWAR_INVARIANTS_v1.md` | IW-1…IW-8 + v0.2.3 implementation notes |
| `intelwar/docs/LIVING_LOG_DATA_MODEL.md` | CBOR + receipt schema |
| `intelwar/docs/INTELWAR_EXOCHAIN_v0.2.3_INTEGRATION.md` | Primitive mapping |
| `intelwar/ADJACENT-SURFACE-INTAKE.md` | Trust boundary for adjacent shells |

**Invariant wire IDs:** `consent-required`, `provenance-verifiable`, `multi-intelligence-transparent`, `evidence-disciplined`, `human-override-priority`, `fail-closed-enforcement`, `strategic-utility`, `log-integrity`.

### 3.3 What exists and what works

| Component | Path | Status |
|-----------|------|--------|
| Living Log core | `intelwar/crates/intelwar-core` | **Real Kernel path** + PM-003 doctrine↔decision-forum. Tests + clippy clean when last validated. |
| DebateSession | `debate_session.rs` | Binds to `DecisionObject`; human gate for Strategic/Constitutional |
| CrossCheck | `crosscheck.rs` + bin `intelwar-crosscheck-verify` | Ed25519 sign/verify; log-api `/api/crosscheck/verify` |
| Kernel bridge | `bridge.rs` + bin `intelwar-log-append` | **Real** adjudication; **local multi-node DAG** via payload-history replay; receipt chain in state file |
| Trust model doc | `docs/BRIDGE_TRUST_MODEL.md` | Binding limitations for bridge / log-api / DAG DB |
| log-api | `intelwar/services/log-api` | Kernel / DAG DB / crosscheck env gates; fail-closed when configured |
| intelwar-net | `intelwar/apps/intelwar-net` | **Public** on Railway; Living Log + .tv + .ai + consent demo |
| Tools | `intelwar/tools/*` | Triage with `iw:*` / `panel:*` labels + emit-log-entry |
| Deploy runbook | `docs/RAILWAY_DEPLOY.md` | PM-007 fail-closed Railway ops |
| wasm | `intelwar/wasm` | Extension stubs only |

### 3.4 Simulated vs real (critical)

| Path | Label | Meaning |
|------|-------|---------|
| log-api without `INTELWAR_CORE_BIN` | `simulated: true` | Adjacent demo only; not Kernel-adjudicated |
| log-api with `INTELWAR_CORE_BIN` + success | `simulated: false`, `kernel_adjudicated: true` | CGR + overlays; `dag_scope` `local-multi-node(-genesis)` |
| Node `/api/consent` | Demo consent | **Not** exo-consent bailment; Kernel uses fixture bailment in bridge |
| Multi-node LogIntegrity | Local replay + optional gateway | Shared `INTELWAR_CORE_STATE_DIR`; gateway when `INTELWAR_DAGDB_*` set |

### 3.5 v0.2.3 constraints in force

- Closed gatekeeper role names (`judge`, etc.).  
- Prefer `AuthorityLink` / `BailmentState` on Kernel hot path.  
- `QuorumLegitimate` no-op when `quorum_evidence` is `None` (OK for single-actor).  
- Adjacent surfaces stay honestly labeled until WASM + gateway prove Permitted for production claims.

### 3.6 PM-001 / PM-002 standing gaps

Still not production-complete: dual consent model; plaintext fixture keys in `bridge_state.json`; placeholder synthetic attestation; Kernel state may advance before a failing gateway write (client must treat 503 as non-durable for DAG DB); no live exo-gateway CI against a real pool.

---

## 4. Backlog Management

### 4.1 Current backlog

| ID | Title | Owner | Status | Notes |
|----|-------|-------|--------|-------|
| PM-001 | Wire log-api ↔ intelwar-core (CLI bridge) | Agent | **DONE** | Bridge-complete; hardening (Kernel IT + trust doc) done |
| PM-002 | Persist via exo-gateway DAG DB + multi-node continuity | Agent | **DONE** | Local multi-node replay + env-gated gateway fail-closed |
| PM-003 | DebateSession ↔ decision-forum | Agent | **DONE** | Doctrine/Amendment require DecisionObject + human gate |
| PM-004 | .ai crosscheck → CrossCheckResult verify | Agent | **DONE** | Ed25519 verify + log-api + .ai panel |
| PM-005 | .tv provenance viewer over receipts | Agent | **DONE** | Receipt-chain viewer in intelwar-net |
| PM-006 | ExoForge-style issue triage + IW labels | Agent | **DONE** | `iw:*` / `panel:*` labels + tests |
| PM-007 | Railway deploy intelwar.net fail-closed | Agent | **DONE** | Live on Railway.app; custom domain DNS pending |
| MKT-* | Marketing / positioning / public narrative | Human+Agent | **HOLD** | Not authorized until human opens |

Optional follow-ups (not authorized as new major PM): live gateway IT against real pool; tighten synthetic attestation; secret-storage policy for bridge state.

### 4.2 Process for advancing or reordering

1. Default order is the table order after skipping DONE and HOLD.  
2. Agent may mark an item **DONE** only when acceptance criteria in the item’s prior session notes (or handoff) are met and gates pass.  
3. Agent may **not** reorder, cancel, or un-HOLD items without human instruction recorded in a session block.  
4. Human may authorize by chat (“start PM-002”) or by editing §8; agent then updates §4/§8 and proceeds.  
5. Spikes that change trust semantics are §1.2 stops even if “helpful” for a PM.

### 4.3 Ownership

- **Agent:** implementation on authorized items; handoff maintenance; commits on `intelwar`.  
- **Human:** HOLD releases; invariant/constitution changes; deploy/marketing; push/PR to main; secret production policy.

---

## 5. Session Protocol (Mandatory)

Every session that changes repo state or makes a material decision **must** end by **appending** a block at the bottom of §9 Session Log using **exactly** this structure:

```markdown
## Session [YYYY-MM-DD HH:MM TZ] — [Short Descriptive Title]

**Authorization context:**
- Authorized item: [PM-ID or "handoff-only" or "review-only"]
- Hold status: [none | holding on …]

**Changes Made:**
- …

**Files Modified:**
- …

**Commits:**
- `hash` — subject line
- (or “none — working tree only”)

**State Deltas:**
- …

**Backlog Updates:**
- …

**Validation Commands Run:**
- `cargo test -p intelwar-core` → pass/fail
- `cargo clippy -p intelwar-core --all-targets -- -D warnings` → pass/fail
- …

**Open Questions / Decisions for Human:**
- … (or “none”)

**Recommended Next Action:**
- … (must be executable by the next agent under §1/§8)

**Agent attestation (IW-3):**
- voice_kind: synthetic
- tool: cursor-agent
- model_id: [as applicable]
- summary: [one line]
```

Rules:

- Append; do not delete prior session blocks (summarize ancient history only if the log becomes unwieldy, keeping the last ≥3 sessions verbatim).  
- If the session only rewrites this handoff, still append a block.  
- If STOPPED on §1.2, the Open Questions section is mandatory and Recommended Next Action must be “await human”.

---

## 6. Validation & Quality Gates

### 6.1 Minimum after Rust changes under `intelwar-core`

```bash
cargo test -p intelwar-core
cargo clippy -p intelwar-core --all-targets -- -D warnings
```

### 6.2 When touching adjacent Node surfaces

```bash
npm --prefix intelwar/services/log-api test
# if apps changed:
npm --prefix intelwar/apps/intelwar-net run build
```

### 6.3 When changing workspace membership / root Cargo.toml

Also run the broader workspace gates the change warrants (at minimum `cargo check -p intelwar-core` plus any affected `-p` crates). Prefer full workspace gates before any human-requested PR.

### 6.4 Commit eligibility

Commit only if:

1. Gates relevant to the change set passed.  
2. `git status` reviewed — no secrets, no `node_modules`, no `.intelwar-bridge-state`.  
3. Message is accurate; PM/IW cited when useful.  
4. Authorization exists under §1/§8.

Handoff-only commits: still preferred after substantive handoff rewrites so the next session sees committed truth.

---

## 7. Communication & Coordination Rules

### 7.1 How to surface questions

1. Write the question in the session block under **Open Questions / Decisions for Human**.  
2. Mirror a one-line HOLD in §8.  
3. In the chat reply to the human: short, decision-oriented ask (options A/B + recommendation).  
4. Do **not** spam clarification questions that this document already answers.

### 7.2 What the human should need to do

Ideally only:

- Release or confirm HOLDs (§8).  
- Answer Open Questions.  
- Optionally skim the latest session block.  
- Explicitly request push/PR/deploy/marketing when desired.

### 7.3 Keeping this file authoritative

- After every material session: update §3, §4, §8, and append §9.  
- Chat is ephemeral; handoff is durable.  
- When user instructions conflict with this file, obey the **newer explicit user message**, then update this file to match.

### 7.4 Classification reminder (EXOCHAIN AGENTS.md)

- `intelwar-core` = core runtime adapter (Kernel/DAG).  
- `apps/`, `services/` = adjacent; no trust claims by proximity.  
- Do not blend core remediations and adjacent polish in one commit unless inseparable; if combined, say why in the commit body.

---

## 8. Current Task & Hold Points

### 8.1 Authorized now

| Authorization | Scope |
|---------------|--------|
| **Active** | Handoff maintenance; session logging; ops fixes to live Railway services |
| **Not active** | **Marketing** narrative; Kernel/DAG DB secrets in public; push/PR to main |
| **Standing permission** | Bugfixes for regressions introduced while authorized; docs clarifications that do not change IW semantics |

### 8.2 Explicit HOLD (do not start)

1. **Marketing / public narrative / intelwar.net positioning** — **await human go-ahead**.  
2. **Invariant or constitution amendments** — **await human go-ahead**.  
3. **Push to remote / PR to `main`** — **await human go-ahead**.  
4. **Enabling `INTELWAR_CORE_BIN` / DAG DB secrets on public Railway** — **await human** (secret policy).

### 8.3 Decisions pending human

1. Point DNS for `intelwar.net` / `www` at Railway and re-run `railway domain intelwar.net` (CLI hit Unauthorized mid-session).  
2. Are disk fixture keys / Kernel bridge acceptable on public Railway, or keep simulated-only?  
3. Remain Node consent forever adjacent-only, or eventually bind to Kernel bailment?  
4. Require live exo-gateway CI evidence before any production trust claim?  
5. Open marketing / public positioning work?

### 8.4 Kernel bridge + optional DAG DB quick reference

```bash
cargo build -p intelwar-core --bin intelwar-log-append
export INTELWAR_CORE_BIN="$PWD/target/debug/intelwar-log-append"
export INTELWAR_CORE_STATE_DIR="$PWD/.intelwar-bridge-state"
# Optional fail-closed gateway persist (all INTELWAR_DAGDB_* required when URL set):
# export INTELWAR_DAGDB_GATEWAY_URL=...
npm --prefix intelwar/services/log-api start
npm --prefix intelwar/services/log-api test
```

Trust model: `intelwar/docs/BRIDGE_TRUST_MODEL.md`.

### 8.5 First actions for a new session

1. Read this file end-to-end (including latest §9 block).  
2. `git status` + `git log -3 --oneline` on `intelwar`.  
3. If §8 authorizes work → execute; else → only handoff/maintenance or answer the human’s new instruction.  
4. End with §5 session block (+ commit if gates allow).

---

## 9. Session Log

### Historical summary (pre-autonomy-rewrite)

- `dec9ddc8` — Bootstrap constitution, core, MVP shells.  
- `f0846b01` — Adopt ratified IW-1…IW-8; align overlays.  
- `9146588d` — PM-001 Kernel CLI bridge + fail-closed log-api.  
- Sessions 2026-07-18 14:26 / 14:30 / 15:04 — handoff install, PM-001 implementation, PM-001 review (accept with gaps; HOLD PM-002).

### Session 2026-07-18 14:26 — Adopt invariants + install handoff

**Changes Made:** Ratified IW docs alignment; handoff entrypoint.  
**Commits:** `f0846b01`.  
**Recommended Next Action:** (superseded) Implement PM-001.

### Session 2026-07-18 14:30 — PM-001 Kernel bridge

**Changes Made:** `bridge.rs`, `intelwar-log-append`, env-gated log-api, fail-closed 503.  
**Commits:** `9146588d` (+ follow-ups for lock/handoff pins).  
**Recommended Next Action:** (superseded) PM-002 or deploy — later HOLDed.

### Session 2026-07-18 15:04 — PM-001 high-signal review

**Changes Made:** Review only; HOLD on PM-002 pending human.  
**Commits:** none (handoff edits may have been uncommitted until autonomy rewrite).  
**Open Questions:** See §8.3.  
**Recommended Next Action:** Await human; strengthen handoff autonomy.

<!-- New sessions append below this line -->

## Session 2026-07-18 18:26 EDT — Autonomy handoff rewrite

**Authorization context:**
- Authorized item: handoff-only (human instructed rewrite + commit; no PM implementation)
- Hold status: holding on PM-002, PM-007, marketing, push/PR to main, invariant amendments

**Changes Made:**
- Completely rewrote `CURSOR_AGENT_HANDOFF.md` as a self-contained operating document
- Added Autonomy & Decision Framework (§1), Operating Principles (§2), expanded Global State (§3), Backlog Management (§4), mandatory Session Protocol (§5), Validation & Quality Gates (§6), Communication rules (§7), Current Task & Hold Points (§8)
- Preserved condensed historical session memory in §9
- Committed rewrite as `8b48b159`

**Files Modified:**
- `intelwar/docs/CURSOR_AGENT_HANDOFF.md`

**Commits:**
- `8b48b159` — intelwar: rewrite CURSOR_AGENT_HANDOFF for autonomous operation
- (this session block committed in follow-up)

**State Deltas:**
- Agent autonomy boundaries are now explicit (what to do vs when to STOP)
- PM-002 / PM-007 / marketing remain HOLD pending human
- PM-001 remains DONE (bridge-complete with documented gaps)
- No technical backlog implementation performed this session

**Backlog Updates:**
- None to PM status; process for advancing items documented in §4.2

**Validation Commands Run:**
- N/A for code (docs-only) — `git status` / commit on `intelwar` only
- Branch confirmed: `intelwar`

**Open Questions / Decisions for Human:**
- Same as §8.3 (PM-002 start criteria; bridge secret policy; Node consent binding)
- Optional: confirm this autonomy framework is acceptable as standing policy

**Recommended Next Action:**
- Await human: either release HOLD on PM-002 (or name hardening-first), or assign another authorized item; do not start PM-002 until instructed

**Agent attestation (IW-3):**
- voice_kind: synthetic
- tool: cursor-agent
- model_id: cursor-grok-4.5
- summary: Rewrote handoff for higher autonomy with constitutional hold points

## Session 2026-07-18 18:45 EDT — PM-001 harden + PM-002 complete

**Authorization context:**
- Authorized item: PM-001 light hardening, then PM-002 (human released HOLD)
- Hold status: holding on PM-003+, PM-007, marketing, push/PR to main, invariant amendments

**Changes Made:**
- Documented bridge trust model (`BRIDGE_TRUST_MODEL.md` + `bridge.rs` module docs)
- Added log-api Kernel-path integration test (two-append continuity) and fail-closed DAG DB tests
- PM-002: local multi-node DAG via `dag_payload_history_hex` replay; `dag_scope` labels
- PM-002: env-gated exo-gateway intake (`dagdb-persist.js`) with fail-closed incomplete/reject paths
- Updated this handoff §3/§4/§8

**Files Modified:**
- `intelwar/crates/intelwar-core/src/bridge.rs`
- `intelwar/docs/BRIDGE_TRUST_MODEL.md`
- `intelwar/docs/CURSOR_AGENT_HANDOFF.md`
- `intelwar/services/log-api/server.js`
- `intelwar/services/log-api/dagdb-persist.js`
- `intelwar/services/log-api/test.js`

**Commits:**
- `0d0f343a` — intelwar: harden PM-001 and complete PM-002 multi-node + DAG DB

**State Deltas:**
- PM-001 hardening complete; PM-002 marked DONE for stated prototype scope
- Multi-node continuity is local state-dir replay; gateway persist optional and fail-closed
- Next major PM (PM-003) requires human authorization

**Backlog Updates:**
- PM-001 → DONE (hardened)
- PM-002 → DONE
- HOLD now starts at PM-003+

**Validation Commands Run:**
- `cargo test -p intelwar-core` → pass
- `cargo clippy -p intelwar-core --all-targets -- -D warnings` → pass
- `cargo build -p intelwar-core --bin intelwar-log-append` → pass
- `npm --prefix intelwar/services/log-api test` → pass (6)

**Open Questions / Decisions for Human:**
- Authorize PM-003?
- Secret policy for `bridge_state.json` before any deploy?
- Live gateway CI required before production claims?

**Recommended Next Action:**
- Await human authorization for PM-003 (or other named item); do not start PM-003 until instructed

**Agent attestation (IW-3):**
- voice_kind: synthetic
- tool: cursor-agent
- model_id: cursor-grok-4.5
- summary: Hardened PM-001 and completed PM-002 multi-node + DAG DB fail-closed

## Session 2026-07-18 19:20 EDT — PM-003 DebateSession ↔ decision-forum

**Authorization context:**
- Authorized item: PM-003 (human: “continue with the next slice”)
- Hold status: holding on PM-004+, PM-007, marketing, push/PR to main, invariant amendments

**Changes Made:**
- Added `decision-forum` dependency; mapped BCTS → DebateTerminalState
- Doctrine / ConstitutionalAmendment appends require `debate_decision` DecisionObject (fail closed)
- Strategic/Constitutional classes enforce decision-forum human gate with verified human voter DIDs
- Integration tests: missing DecisionObject, human-gate denial, approved Strategic happy path
- Updated DEPENDENCY_PLAN, Living Log data model, integration map, this handoff

**Files Modified:**
- `intelwar/crates/intelwar-core/Cargo.toml`
- `intelwar/crates/intelwar-core/src/debate_session.rs`
- `intelwar/crates/intelwar-core/src/append_flow.rs`
- `intelwar/crates/intelwar-core/src/bridge.rs`
- `intelwar/crates/intelwar-core/src/lib.rs`
- `intelwar/crates/intelwar-core/tests/append_flow_tests.rs`
- `intelwar/crates/intelwar-core/tests/debate_doctrine_tests.rs`
- `intelwar/DEPENDENCY_PLAN.md`
- `intelwar/docs/LIVING_LOG_DATA_MODEL.md`
- `intelwar/docs/INTELWAR_EXOCHAIN_v0.2.3_INTEGRATION.md`
- `intelwar/docs/CURSOR_AGENT_HANDOFF.md`

**Commits:**
- `0dcfb6a1` — intelwar: PM-003 bind DebateSession to decision-forum

**State Deltas:**
- PM-003 DONE; bare DebateSession claims no longer suffice for doctrine/amendment
- Next major item PM-004 requires human authorization

**Backlog Updates:**
- PM-003 → DONE
- HOLD now starts at PM-004+

**Validation Commands Run:**
- `cargo test -p intelwar-core` → pass (including 3 doctrine integration tests)
- `cargo clippy -p intelwar-core --all-targets -- -D warnings` → pass

**Open Questions / Decisions for Human:**
- Authorize PM-004?
- Secret policy / Node consent binding / live gateway CI (unchanged)

**Recommended Next Action:**
- Await human authorization for PM-004 (or other named item); do not start PM-004 until instructed

**Agent attestation (IW-3):**
- voice_kind: synthetic
- tool: cursor-agent
- model_id: cursor-grok-4.5
- summary: Wired DebateSession to decision-forum DecisionObject with fail-closed doctrine path

## Session 2026-07-18 19:45 EDT — PM-004 / PM-005 / PM-006 complete

**Authorization context:**
- Authorized item: PM-004…PM-006 (human: “continue progressing through all slices”)
- Hold status: holding on PM-007 deploy, marketing, push/PR to main, invariant amendments

**Changes Made:**
- PM-004: Ed25519 CrossCheckResult sign/verify; `intelwar-crosscheck-verify` bin; log-api `/api/crosscheck/verify`; .ai panel
- PM-005: `.tv` receipt-chain provenance viewer + tests
- PM-006: triage `iw:*` / `panel:*` labels, `--labels` mode, unit tests
- Updated this handoff §3/§4/§8

**Files Modified:**
- `intelwar/crates/intelwar-core/src/crosscheck.rs` (+ bin, append_flow, Cargo.toml, lib.rs)
- `intelwar/services/log-api/{server.js,crosscheck-verify.js,test.js}`
- `intelwar/apps/intelwar-net/src/{App.jsx,ai/crosscheck.js,tv/provenance.js,components/*,styles.css,package.json}`
- `intelwar/tools/{triage.js,triage.test.js}`
- `intelwar/docs/CURSOR_AGENT_HANDOFF.md`

**Commits:**
- `63b6295e` — intelwar: complete PM-004 crosscheck, PM-005 provenance, PM-006 triage

**State Deltas:**
- Implementation backlog PM-001…PM-006 **DONE**
- Remaining human-gated: PM-007 deploy, marketing, push/PR

**Backlog Updates:**
- PM-004 → DONE; PM-005 → DONE; PM-006 → DONE

**Validation Commands Run:**
- `cargo test -p intelwar-core` → pass
- `cargo clippy -p intelwar-core --all-targets -- -D warnings` → pass
- `npm --prefix intelwar/services/log-api test` → pass (8)
- `npm --prefix intelwar/apps/intelwar-net test` → pass (3)
- `node --test intelwar/tools/triage.test.js` → pass (2)
- `npm --prefix intelwar/apps/intelwar-net run build` → pass

**Open Questions / Decisions for Human:**
- Authorize PM-007 deploy?
- Secret policy / consent binding / live gateway CI / marketing?

**Recommended Next Action:**
- Await human for PM-007 or marketing; do not deploy or open public narrative without instruction

**Agent attestation (IW-3):**
- voice_kind: synthetic
- tool: cursor-agent
- model_id: cursor-grok-4.5
- summary: Completed PM-004 crosscheck verify, PM-005 provenance viewer, PM-006 triage labels

## Session 2026-07-18 20:05 EDT — PM-007 public Railway deploy

**Authorization context:**
- Authorized item: PM-007 full public deploy (human: “continue with full public deploy”)
- Hold status: holding on marketing, push/PR to main, invariant amendments, enabling Kernel/DAG secrets on public

**Changes Made:**
- Created Railway project `intelwar` (ARMORCLOUD); services `log-api` + `intelwar-net`
- Deployed both; fail-closed `VITE_LOG_API_URL` gate; static `serve.mjs` for healthchecks
- Documented runbook `docs/RAILWAY_DEPLOY.md`; updated intake + README
- Custom domain `intelwar.net` not attached (CLI Unauthorized); Railway.app URLs live

**Files Modified:**
- `intelwar/apps/intelwar-net/{railway.json,package.json,scripts/*}`
- `intelwar/services/log-api/{railway.json,server.js}`
- `intelwar/docs/{RAILWAY_DEPLOY.md,CURSOR_AGENT_HANDOFF.md}`
- `intelwar/{README.md,ADJACENT-SURFACE-INTAKE.md}`

**Commits:**
- (tip after this session commit)

**State Deltas:**
- PM-007 DONE for public Railway.app shell (adjacent, `trust_claim: none`, Kernel unset)
- Custom domain + marketing remain human

**Backlog Updates:**
- PM-007 → DONE

**Validation Commands Run:**
- `npm --prefix intelwar/apps/intelwar-net test` → pass
- `curl https://log-api-production-0798.up.railway.app/health` → ok, trust_claim none
- `curl https://intelwar-net-production.up.railway.app/` → HTTP 200
- Railway deploy log-api + intelwar-net → SUCCESS

**Open Questions / Decisions for Human:**
- Attach `intelwar.net` DNS (re-auth Railway if needed)?
- Enable Kernel bridge secrets on public, or keep simulated?
- Authorize marketing?

**Recommended Next Action:**
- Human: DNS for intelwar.net + `railway login` then `railway domain intelwar.net --service intelwar-net`; optionally authorize marketing

**Agent attestation (IW-3):**
- voice_kind: synthetic
- tool: cursor-agent
- model_id: cursor-grok-4.5
- summary: Deployed IntelWar public adjacent shell to Railway with fail-closed API wiring
