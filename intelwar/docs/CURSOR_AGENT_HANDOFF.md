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
- **Do not** start PM-002, PM-007 (deploy), or marketing work while §8 marks them HOLD.
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

*As of handoff rewrite session 2026-07-18. Confirm with `git log -1 --oneline` on `intelwar`.*

### 3.1 Branch & commits

| Fact | Value |
|------|--------|
| Branch | `intelwar` |
| Base | Tag `v0.2.3` / `a50a15fd` |
| Notable commits | `dec9ddc8` bootstrap · `f0846b01` adopt IW-1…IW-8 · `9146588d` PM-001 Kernel bridge · tip may include later handoff-only commits |
| Remote / main | No PR to `main` authorized; do not push unless human asks |

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
| Living Log core | `intelwar/crates/intelwar-core` | **Real Kernel path:** consent → authority → CGR → overlays → receipt → `exo_dag::append`. Tests + clippy clean when last validated. |
| Kernel bridge | `bridge.rs` + bin `intelwar-log-append` | **Real** adjudication per invoke; **ephemeral single-node DAG**; receipt hashes chain via state file |
| log-api | `intelwar/services/log-api` | **Simulated by default**; Kernel when `INTELWAR_CORE_BIN` set; **503 fail-closed** on bridge error |
| intelwar-net | `intelwar/apps/intelwar-net` | Railway-ready React shell; Living Log viewer + consent demo; adjacent |
| Tools | `intelwar/tools/*` | Triage + emit-log-entry (simulated artifacts) |
| .ai / .tv / wasm | stubs under `apps/.../ai`, `tv`, `intelwar/wasm` | Extension points only |

### 3.4 Simulated vs real (critical)

| Path | Label | Meaning |
|------|-------|---------|
| log-api without `INTELWAR_CORE_BIN` | `simulated: true` | Adjacent demo only; not Kernel-adjudicated |
| log-api with `INTELWAR_CORE_BIN` + success | `simulated: false`, `kernel_adjudicated: true` | CGR + overlays ran; DAG scope still `ephemeral-single-node` |
| Node `/api/consent` | Demo consent | **Not** exo-consent bailment; Kernel uses fixture bailment in bridge |
| Multi-node LogIntegrity | Not yet | PM-002 |

### 3.5 v0.2.3 constraints in force

- Closed gatekeeper role names (`judge`, etc.).  
- Prefer `AuthorityLink` / `BailmentState` on Kernel hot path.  
- `QuorumLegitimate` no-op when `quorum_evidence` is `None` (OK for single-actor).  
- Adjacent surfaces stay honestly labeled until WASM + gateway prove Permitted for production claims.

### 3.6 PM-001 review verdict (standing)

Accepted as **bridge-complete** with known gaps: dual consent model, plaintext fixture keys in `bridge_state.json`, placeholder synthetic attestation, no Kernel-path npm integration test, ephemeral DAG. Not production LogIntegrity-complete.

---

## 4. Backlog Management

### 4.1 Current backlog

| ID | Title | Owner | Status | Notes |
|----|-------|-------|--------|-------|
| PM-001 | Wire log-api ↔ intelwar-core (CLI bridge) | Agent | **DONE** | `9146588d`; gaps documented in §3.6 |
| PM-002 | Persist via exo-gateway DAG DB + multi-node continuity | Agent | **HOLD** | Requires human go-ahead; primary IW-8 closer |
| PM-003 | DebateSession ↔ decision-forum | Agent | Queued | IW-4 evidence links; closed roles |
| PM-004 | .ai crosscheck → CrossCheckResult verify | Agent | Queued | IW-3 / IW-4 |
| PM-005 | .tv provenance viewer over receipts | Agent | Queued | IW-2 / IW-8 |
| PM-006 | ExoForge-style issue triage + IW labels | Agent | Queued | Process automation |
| PM-007 | Railway deploy intelwar.net fail-closed | Agent | **HOLD** | Deploy/public; human-gated |
| MKT-* | Marketing / positioning / public narrative | Human+Agent | **HOLD** | Not authorized until human opens |

Optional hardening (not separate PMs unless §8 authorizes): Kernel-path npm test; tighten synthetic attestation; secret-storage policy for bridge state.

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
| **Active** | Maintain and improve this handoff; session logging; triage/emit tooling docs alignment |
| **Not active** | New feature implementation on PM-002+ until human releases HOLD |
| **Standing permission** | Bugfixes strictly limited to regressions the agent introduced while authorized; docs clarifications that do not change IW semantics |

### 8.2 Explicit HOLD (do not start)

1. **PM-002** — exo-gateway DAG DB persistence / multi-node LogIntegrity — **await human go-ahead**.  
2. **PM-007** — Railway/production deploy — **await human go-ahead**.  
3. **Marketing / public narrative / intelwar.net positioning** — **await human go-ahead**.  
4. **Invariant or constitution amendments** — **await human go-ahead**.  
5. **Push to remote / PR to `main`** — **await human go-ahead**.

### 8.3 Decisions pending human (from PM-001 review)

Recorded for continuity; agent must not assume answers:

1. Proceed to PM-002 as-is, or require Kernel-path npm integration test first?  
2. Are disk fixture keys in `bridge_state.json` acceptable until deploy, or must secret policy land first?  
3. Remain Node consent forever adjacent-only, or eventually bind to Kernel bailment?

### 8.4 Kernel bridge quick reference (PM-001)

```bash
cargo build -p intelwar-core --bin intelwar-log-append
export INTELWAR_CORE_BIN="$PWD/target/debug/intelwar-log-append"
export INTELWAR_CORE_STATE_DIR="$PWD/.intelwar-bridge-state"
npm --prefix intelwar/services/log-api start
```

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
