<!--
Copyright 2026 Exochain Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
-->

# Catapult Integration Report: As-Is vs Planned

**Date:** 2026-04-08
**Crate:** exo-catapult v0.1.0-alpha
**Branch:** feat/exo-catapult

---

## 1. Executive Summary

The `exo-catapult` Rust crate is complete as a standalone library — 2,820 lines across 11 modules with 80 passing tests and zero clippy warnings. It models the FM 3-05 franchise incubator with full lifecycle state machine, ODA team management, and Paperclip-derived heartbeat/budget/goal systems.

Two integration layers remain:
1. **WASM Bridge** — Exposing catapult functions to JavaScript via `exochain-wasm`
2. **CommandBase Integration** — Wiring catapult agents into the 105-agent governance hypervisor

This report details what exists today, what the target integration looks like, and the precise gap between them.

---

## 2. As-Is: exo-catapult Crate

### 2.1 Module Inventory

| Module | Lines | Types | Tests | Purpose |
|--------|-------|-------|-------|---------|
| `oda.rs` | 211 | MosCode (8), OdaSlot (12) | 7 | FM 3-05 team structure, MOS codes, authority hierarchy |
| `phase.rs` | 176 | OperationalPhase (6) | 7 | 6-phase lifecycle state machine with transition validation |
| `agent.rs` | 285 | CatapultAgent, AgentRoster, AgentStatus (5) | 10 | Agent entities, slot management, DID generation |
| `franchise.rs` | 183 | FranchiseBlueprint, FranchiseRegistry, BusinessModel (6) | 6 | Immutable franchise templates |
| `newco.rs` | 388 | Newco, NewcoStatus (5), NewcoRegistry | 9 | Company entities with governed lifecycle |
| `heartbeat.rs` | 272 | HeartbeatMonitor, HeartbeatRecord, HeartbeatStatus (5), HeartbeatAlert, AlertSeverity (2) | 6 | Agent liveness with warning/critical thresholds |
| `budget.rs` | 328 | BudgetLedger, BudgetPolicy, CostEvent, BudgetVerdict (3), BudgetScope (3), BudgetMetric (3), BudgetWindow (3), BudgetTemplate | 7 | Integer-only budget enforcement |
| `goal.rs` | 354 | GoalTree, Goal, GoalLevel (4), GoalStatus (5), GoalTemplate, GoalSeed | 11 | Hierarchical alignment scoring in basis points |
| `receipt.rs` | 273 | FranchiseReceipt, FranchiseOperation (12), ReceiptChain | 4 | Hash-chained trust receipts with integrity verification |
| `integration.rs` | 225 | PaceConfig, DecisionClass (4), HealthSummary | 5 | PACE builder, decision classification, health summaries |
| `error.rs` | 83 | CatapultError (12) | 1 | Typed error variants |
| `lib.rs` | 42 | — | — | Module declarations, re-exports |
| **Total** | **2,820** | **~45 types** | **80** | |

### 2.2 What Works Today

- Full ODA 12-slot team with FM 3-05 MOS mapping
- Phase state machine with forward/backward transitions and roster gating
- Agent hiring pipeline: founders (HR + Deep Researcher) → leadership → full ODA
- Hash-chained receipt generation with integrity verification
- Heartbeat monitoring with configurable warning/critical thresholds
- Budget enforcement using integer cents and basis point thresholds
- Goal tree with hierarchical alignment scoring (0–10000 bps)
- PACE configuration derived from ODA command hierarchy
- Decision classification (Routine/Operational/Strategic/Constitutional)
- Health summary aggregation
- Full serde roundtrip for all types

### 2.3 What Does NOT Work Today

- **No WASM exports** — The crate compiles as `rlib` only; JavaScript cannot call any function
- **No CommandBase integration** — Agent profiles exist as Rust structs but are not written to Team/.md files or the SQLite `team_members` table
- **No GSD endpoints** — No HTTP surface for catapult operations
- **No governance receipt chain** — Receipts are generated in Rust but not written to CommandBase's `governance_receipts` SQLite table
- **No worker integration** — Catapult agents cannot be dispatched for autonomous task execution
- **No WebSocket events** — Newco lifecycle changes are not broadcast to the dashboard

---

## 3. As-Is: WASM Bridge (exochain-wasm)

### 3.1 Current Architecture

| Metric | Value |
|--------|-------|
| Exported functions | 110 |
| Binding files | 9 domain-specific + 1 serde bridge |
| Pattern | `#[wasm_bindgen] pub fn wasm_*(&str) -> Result<JsValue, JsValue>` |
| Serialization | JSON strings via `serde_bridge::from_json_str` / `to_js_value` |
| Error handling | Domain errors mapped to `JsValue::from_str(format!("Context: {e}"))` |
| Crate type | `cdylib` + `rlib` |
| Dependencies | 13 of 16 domain crates (excludes exo-gateway, exo-node, exo-catapult) |

### 3.2 Binding File Pattern

```
exochain-wasm/src/
├── lib.rs                      # mod declarations + pub use *_bindings::*
├── serde_bridge.rs             # from_json_str<T>(), to_js_value<T>()
├── core_bindings.rs            # 14 functions — crypto, hashing, events, BCTS
├── identity_bindings.rs        # 7 functions — Shamir, PACE, risk
├── authority_bindings.rs       # 4 functions — delegation chains
├── consent_bindings.rs         # 4 functions — bailment lifecycle
├── gatekeeper_bindings.rs      # 5 functions — combinators, invariants, holons
├── governance_bindings.rs      # 13 functions — quorum, clearance, audit
├── escalation_bindings.rs      # 8 functions — triage, feedback, kanban
├── legal_bindings.rs           # 12 functions — evidence, privilege, fiduciary
└── decision_forum_bindings.rs  # 43 functions — decisions, TNCs, challenges
```

### 3.3 Export Convention

Every function follows this exact pattern:

```rust
#[wasm_bindgen]
pub fn wasm_<domain>_<action>(json_param: &str, ...) -> Result<JsValue, JsValue> {
    let input: DomainType = from_json_str(json_param)?;
    let result = domain_crate::do_thing(&input)
        .map_err(|e| JsValue::from_str(&format!("Context: {e}")))?;
    to_js_value(&result)
}
```

Flat namespace — all 110 functions re-exported at crate root as `exochain_wasm::wasm_*`.

---

## 4. As-Is: CommandBase

### 4.1 Current Architecture

| Metric | Value |
|--------|-------|
| Agent profiles | 105 markdown files in Team/ |
| GSD endpoints | 21 (5 agent, 5 decision, 4 constitutional, 5 identity, 2 holon) |
| System API routes | 50+ across 18 route modules |
| WASM functions consumed | 110 via `app/services/exochain.js` (1,294 lines) |
| Database | SQLite with WAL mode |
| Agent execution | Worker polling every 10s, spawns `claude -p` CLI |
| Real-time | WebSocket broadcast for state changes |

### 4.2 Agent Profile Template (Team/*.md)

```markdown
# [Name] — [Title]

## Identity
- **Name:** [Name]
- **Title:** [Job Title]
- **Tier:** [board|c-suite|specialist|orchestrator|leader|co-leader]
- **Reports To:** [Manager Name]
- **Department:** [Department]

## Persona
[Character description]

## Core Competencies
[Skills list]

## Methodology
[Work process]

## Purview & Restrictions
### Owns
[Domains]
### Cannot Touch
[Off-limits areas]

## Quality Bar
[Acceptance criteria]
```

### 4.3 Database Schema for Team (SQLite)

```sql
team_members:
  id, name (UNIQUE), role, status, execution_mode, tier,
  reports_to, did_identity, llm_provider_id, llm_model,
  adapter_type, adapter_config, runtime_config,
  capabilities [], permissions [], metadata {},
  profile_path  -- path to Team/*.md file
```

### 4.4 Governance Receipt Chain

Every GSD action creates a hash-chained receipt in `governance_receipts`:

```sql
governance_receipts:
  id, action_type, entity_type, entity_id, actor, description,
  payload_hash, previous_hash, receipt_hash,
  branch (legislative|judicial|executive),
  adjudication (pass|warn|fail|defer),
  chain_depth, invariants_checked, verified
```

### 4.5 Worker Agent Dispatch

```
Poll SQLite → find eligible task → load member profile →
build prompt with persona + tools → spawn `claude -p` →
capture output → route to orchestrator for review → update status
```

---

## 5. Planned: WASM Bridge Integration

### 5.1 New File

`crates/exochain-wasm/src/catapult_bindings.rs` — ~18 exported functions

### 5.2 Planned Exports

| Function | Input | Output | Maps To |
|----------|-------|--------|---------|
| `wasm_create_franchise_blueprint` | name, model_json, constitution_hash_hex | FranchiseBlueprint as JsValue | `FranchiseRegistry::publish()` |
| `wasm_list_franchise_blueprints` | registry_json | Vec<Blueprint> as JsValue | `FranchiseRegistry::list()` |
| `wasm_instantiate_newco` | blueprint_json, name, founder_dids_json | Newco as JsValue | `Newco::new()` + hire founders |
| `wasm_transition_newco_phase` | newco_json, target_phase_json, actor_did | Updated Newco as JsValue | `Newco::advance_phase()` |
| `wasm_valid_phase_transitions` | phase_json | Vec<Phase> as JsValue | `OperationalPhase::valid_transitions()` |
| `wasm_hire_agent` | newco_json, slot_json, agent_json | Updated Newco as JsValue | `Newco::hire_agent()` |
| `wasm_release_agent` | newco_json, slot_json, actor_did | (Newco, Agent) as JsValue | `Newco::release_agent()` |
| `wasm_roster_status` | newco_json | RosterSummary as JsValue | Filled/vacant/active counts |
| `wasm_oda_authority_chain` | newco_json | AuthorityChain as JsValue | `build_pace_config()` + hierarchy |
| `wasm_record_heartbeat` | newco_json, agent_did, usage_json | Updated Monitor as JsValue | `HeartbeatMonitor::record()` |
| `wasm_check_heartbeat_health` | monitor_json, now_ms | Vec<Alert> as JsValue | `HeartbeatMonitor::check_health()` |
| `wasm_record_cost_event` | ledger_json, event_json | Updated Ledger as JsValue | `BudgetLedger::record_cost()` |
| `wasm_check_budget_status` | ledger_json, scope_json | BudgetVerdict as JsValue | `BudgetLedger::check_enforcement()` |
| `wasm_enforce_budget` | newco_json | EnforcementResult as JsValue | Check all scopes, return actions |
| `wasm_create_goal` | tree_json, goal_json | Updated Tree as JsValue | `GoalTree::add()` |
| `wasm_update_goal_status` | tree_json, goal_id, status_json | Updated Tree as JsValue | `GoalTree::update_status()` |
| `wasm_goal_alignment_score` | tree_json | u32 (bps) | `GoalTree::alignment_score()` |
| `wasm_generate_franchise_receipt` | newco_json, operation_json, actor_did | FranchiseReceipt as JsValue | `FranchiseReceipt::new()` |

### 5.3 Changes Required

| File | Change |
|------|--------|
| `exochain-wasm/Cargo.toml` | Add `exo-catapult = { path = "../exo-catapult" }` |
| `exochain-wasm/src/lib.rs` | Add `pub mod catapult_bindings;` + `pub use catapult_bindings::*;` |
| `exochain-wasm/src/catapult_bindings.rs` | New file — ~18 functions, ~400 lines |
| `exochain-wasm/Cargo.toml` [cargo-machete] | Add `"exo-catapult"` to ignored list |

### 5.4 Architectural Pattern

Follows the exact same pattern as the existing 110 functions:

```rust
use wasm_bindgen::prelude::*;
use crate::serde_bridge::{from_json_str, to_js_value};

#[wasm_bindgen]
pub fn wasm_instantiate_newco(
    blueprint_json: &str,
    name: &str,
    founder_dids_json: &str,
) -> Result<JsValue, JsValue> {
    let blueprint: FranchiseBlueprint = from_json_str(blueprint_json)?;
    let founder_dids: Vec<String> = from_json_str(founder_dids_json)?;
    // ... create newco, hire founders
    to_js_value(&newco)
}
```

### 5.5 Gap Analysis: WASM Bridge

| Aspect | As-Is | Planned | Gap |
|--------|-------|---------|-----|
| exo-catapult in WASM deps | Not listed | Listed as dependency | 1 line in Cargo.toml |
| catapult_bindings.rs | Does not exist | ~400 lines, 18 functions | New file |
| lib.rs mod declaration | 9 binding modules | 10 binding modules | 2 lines |
| Total WASM exports | 110 | ~128 | +18 functions |
| serde_bridge.rs | Complete — reusable | No changes needed | None |
| WASM binary size | ~2.8 MB (est.) | ~3.0 MB (est.) | +~200 KB |
| Build pipeline | wasm-pack, CI Gate | Same pipeline | No change |

**Effort estimate scope:** Small — follows established patterns exactly. The serde bridge, error handling, and export conventions are all proven. This is mechanical work.

---

## 6. Planned: CommandBase Integration

### 6.1 New Files

| File | Purpose | Est. Lines |
|------|---------|------------|
| `command-base/app/services/catapult.js` | JavaScript wrapper for catapult WASM functions | ~300 |
| `command-base/app/routes/catapult.js` | Express routes for franchise operations | ~400 |
| `command-base/Team/catapult-*.md` (×12 per newco) | ODA agent profiles generated from templates | ~100 each |

### 6.2 New Service Layer: catapult.js

Mirrors the existing `exochain.js` pattern — thin JavaScript wrappers around WASM calls:

```javascript
const wasm = require('@exochain/exochain-wasm');

function s(v) { return JSON.stringify(v); }

// Franchise
function createFranchiseBlueprint(name, model, constitutionHash) {
  return wasm.wasm_create_franchise_blueprint(name, s(model), constitutionHash);
}

// Newco
function instantiateNewco(blueprint, name, founderDids) {
  return wasm.wasm_instantiate_newco(s(blueprint), name, s(founderDids));
}

// ... 16 more wrappers
module.exports = { createFranchiseBlueprint, instantiateNewco, ... };
```

### 6.3 New Route Module: catapult.js

**Planned endpoints (mapped to GSD pattern):**

| Method | Path | Action | Receipt Type |
|--------|------|--------|--------------|
| `POST` | `/api/catapult/franchise` | Create franchise blueprint | `franchise_create` |
| `GET` | `/api/catapult/franchise` | List blueprints | — |
| `POST` | `/api/catapult/newco` | Instantiate newco from blueprint | `newco_create` |
| `GET` | `/api/catapult/newco/:id` | Get newco status + health summary | — |
| `POST` | `/api/catapult/newco/:id/phase` | Advance operational phase | `phase_transition` |
| `POST` | `/api/catapult/newco/:id/hire` | Hire agent into ODA slot | `agent_hire` |
| `POST` | `/api/catapult/newco/:id/release` | Release agent from slot | `agent_release` |
| `GET` | `/api/catapult/newco/:id/roster` | Get ODA roster status | — |
| `POST` | `/api/catapult/newco/:id/heartbeat` | Record agent heartbeat | `heartbeat_record` |
| `GET` | `/api/catapult/newco/:id/health` | Check heartbeat health | — |
| `POST` | `/api/catapult/newco/:id/cost` | Record cost event | `cost_record` |
| `GET` | `/api/catapult/newco/:id/budget` | Get budget status | — |
| `POST` | `/api/catapult/newco/:id/goal` | Create goal | `goal_create` |
| `PATCH` | `/api/catapult/newco/:id/goal/:gid` | Update goal status | `goal_update` |
| `GET` | `/api/catapult/newco/:id/alignment` | Get alignment score | — |

Each mutating endpoint creates a governance receipt and broadcasts a WebSocket event.

### 6.4 Agent Profile Generation

When a newco is instantiated, Catapult generates 12 Team/*.md profiles:

```
Team/catapult-<short_id>-venturecommander.md
Team/catapult-<short_id>-operationsdeputy.md
Team/catapult-<short_id>-processarchitect.md
Team/catapult-<short_id>-deepresearcher.md
Team/catapult-<short_id>-growthengineer1.md
Team/catapult-<short_id>-growthengineer2.md
Team/catapult-<short_id>-communications1.md
Team/catapult-<short_id>-communications2.md
Team/catapult-<short_id>-hrpeopleops1.md
Team/catapult-<short_id>-hrpeopleops2.md
Team/catapult-<short_id>-platformengineer1.md
Team/catapult-<short_id>-platformengineer2.md
```

Each profile follows the established Team/ template but with:
- **Tier** mapped from ODA authority depth (0→board, 1→c-suite, 2→leader, 3→specialist)
- **Reports To** following the ODA chain (specialists → ProcessArchitect → OperationsDeputy → VentureCommander)
- **Department** set to `Catapult — <newco name>`
- **Persona** generated from franchise blueprint business model + slot role
- **Purview** scoped to the MOS specialty domain

### 6.5 Database Schema Additions

```sql
-- New table: franchise blueprints
catapult_blueprints:
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  business_model TEXT NOT NULL,
  constitution_hash TEXT,
  blueprint_json TEXT NOT NULL,  -- full serialized FranchiseBlueprint
  created_at TEXT DEFAULT (datetime('now'))

-- New table: active newcos
catapult_newcos:
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  franchise_id TEXT REFERENCES catapult_blueprints(id),
  phase TEXT NOT NULL DEFAULT 'Assessment',
  status TEXT NOT NULL DEFAULT 'Provisioning',
  newco_json TEXT NOT NULL,  -- full serialized Newco state
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))

-- New table: ODA slot → team_member mapping
catapult_roster:
  newco_id TEXT REFERENCES catapult_newcos(id),
  slot TEXT NOT NULL,
  member_id INTEGER REFERENCES team_members(id),
  did_identity TEXT,
  hired_at TEXT,
  PRIMARY KEY (newco_id, slot)
```

### 6.6 Worker Integration

Catapult agents become eligible for autonomous execution through the existing worker pipeline:

1. **Profile loaded** from `catapult_roster` → `team_members` join
2. **Prompt built** with ODA role persona + franchise business context
3. **Dispatched** via `claude -p` with model selection per existing rules
4. **Receipt generated** for every autonomous action

The two founding agents (HR + Deep Researcher) are the first to execute autonomously during the Selection phase — HR evaluates candidates, Deep Researcher produces market intelligence.

### 6.7 Gap Analysis: CommandBase

| Aspect | As-Is | Planned | Gap |
|--------|-------|---------|-----|
| WASM service wrappers | `exochain.js` (110 functions, 1,294 lines) | + `catapult.js` (~18 functions, ~300 lines) | New file |
| Route modules | 18 modules, 21 GSD endpoints | + `catapult.js` (15 endpoints) | New file |
| Team profiles | 105 static .md files | + 12 per newco (generated) | Profile generator function |
| SQLite tables | team_members, tasks, governance_receipts, ... | + catapult_blueprints, catapult_newcos, catapult_roster | 3 new tables |
| server.js route mounting | 18 route mounts | + 1 catapult route mount | ~5 lines |
| bootstrap-schema.js | Existing tables | + 3 new CREATE TABLE statements | ~30 lines |
| Worker eligibility | Checks team_members.execution_mode | Same — catapult agents are team_members | No change to worker logic |
| WebSocket events | Broadcasts on GSD actions | + broadcasts on catapult actions | Follow existing pattern |
| Governance receipts | Hash-chained for all GSD actions | + hash-chained for all catapult actions | Follow existing pattern |

---

## 7. Integration Sequence

### Phase A: WASM Bridge (can proceed immediately)

```
1. Add exo-catapult dep to exochain-wasm/Cargo.toml
2. Create catapult_bindings.rs with 18 functions
3. Add mod + pub use to lib.rs
4. Build: wasm-pack build crates/exochain-wasm --target nodejs
5. Verify: wasm-pack test --node crates/exochain-wasm
```

**Depends on:** Nothing — exo-catapult crate is complete.

### Phase B: CommandBase Service + Routes (depends on Phase A)

```
1. Create app/services/catapult.js (WASM wrappers)
2. Create 3 SQLite tables in bootstrap-schema.js
3. Create app/routes/catapult.js (15 endpoints)
4. Mount routes in server.js
5. Add WebSocket event broadcasts
```

**Depends on:** WASM binary rebuilt with catapult exports.

### Phase C: Agent Profile Generation (depends on Phase B)

```
1. Build profile template generator (ODA slot → Team/*.md)
2. On newco creation: generate 12 profiles + insert team_members rows
3. Link catapult_roster to team_members via DID
4. On agent hire: update member status to 'active'
```

**Depends on:** Routes operational for newco creation.

### Phase D: Worker Dispatch (depends on Phase C)

```
1. No worker code changes needed — catapult agents are standard team_members
2. Set execution_mode='autonomous' for founding agents
3. Founding agents (HR + Deep Researcher) execute first
4. They hire remaining ODA through governed task pipeline
```

**Depends on:** Agent profiles exist in team_members table.

---

## 8. Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| WASM binary size increase | Low — catapult types are data-heavy, logic-light | Monitor with `wasm-pack build --release`, wasm-opt if needed |
| State management complexity | Medium — Newco state serialized as JSON blobs in SQLite | Follow existing pattern (governance_receipts stores full payload) |
| Profile generation at scale | Low — 12 files per newco, deterministic naming | Template-based generation, idempotent writes |
| Concurrent newco operations | Medium — SQLite WAL handles concurrent reads but single writer | Batch writes within transactions, same as existing GSD pattern |
| Founding agent bootstrap | Medium — HR and Deep Researcher must self-organize | Seed initial tasks with franchise blueprint goals |

---

## 9. Metrics Summary

| Metric | As-Is | After WASM Bridge | After Full CommandBase |
|--------|-------|-------|-------|
| ExoChain WASM exports | 110 | ~128 | ~128 |
| exo-catapult Rust LOC | 2,820 | 2,820 | 2,820 |
| exo-catapult tests | 80 | 80 | 80 |
| catapult_bindings.rs LOC | 0 | ~400 | ~400 |
| CommandBase JS service LOC | 0 | 0 | ~300 |
| CommandBase route LOC | 0 | 0 | ~400 |
| New SQLite tables | 0 | 0 | 3 |
| New API endpoints | 0 | 0 | 15 |
| Agent profiles per newco | 0 | 0 | 12 |
| Total new JS LOC | 0 | 0 | ~730 |
