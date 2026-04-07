# Plan: ExoChain Governance Layer Integration

**Planned by:** Atlas (Systems Architect)
**Reviewed by:** Gray (Orchestrator)
**Status:** Ready for Max's approval

---

## Context

Max wants ExoChain-style governance integrated into The Team at two levels:

1. **The Team itself** (Gray, all leaders, co-leaders) operates under mandatory governance — every action verified, constitutional invariants enforced, audit trail cryptographically signed.
2. **Projects** get an optional toggle at creation time — "Build on ExoChain infrastructure" (yes/no). Some projects want governance, others don't.

ExoChain is a Rust/WASM project. Our dashboard is Node.js/Express/SQLite. This plan designs a practical Phase 1 that works today with our stack while mirroring ExoChain's architectural patterns, then outlines Phase 2 for deeper integration (actual WASM modules, DID identities, etc.).

---

## What ExoChain Provides (Reference Architecture)

| Concept | What It Does | Our Phase 1 Equivalent |
|---------|-------------|----------------------|
| CGR Kernel | Enforces 9 constitutional invariants | Pre-transition checks in Express middleware |
| Holons | AI agents as first-class citizens with DID | Team members with unique IDs + future DID column |
| BLAKE3 hashing | Content-addressable integrity | `blake3` npm package for hashing actions/files |
| Receipt chains | Cryptographic state transition proofs | `governance_receipts` table with hash chains |
| 3-branch separation | Legislative/Executive/Judicial | Role-based action authorization |
| Constitutional invariants | Rules that can never be violated | Codified checks before state mutations |

---

## Phase 1: What We Build NOW

### 1. Database Changes

#### 1a. New column on `projects` table

```sql
ALTER TABLE projects ADD COLUMN exochain_governed INTEGER NOT NULL DEFAULT 0;
```

- `0` = standard project (no governance)
- `1` = ExoChain-governed project (full governance layer)

This is the per-project toggle. The Team itself is ALWAYS governed (hardcoded, not stored as a flag).

#### 1b. New table: `governance_receipts`

The core of the audit chain. Every governed action produces a receipt.

```sql
CREATE TABLE governance_receipts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- What happened
    action_type TEXT NOT NULL,          -- e.g. 'task_created', 'task_delivered', 'priority_changed', 'member_assigned', 'project_updated'
    entity_type TEXT NOT NULL,          -- 'task', 'project', 'team_member', 'decision', 'mission'
    entity_id INTEGER NOT NULL,
    -- Who did it
    actor TEXT NOT NULL,                -- team member name or 'Max' or 'system'
    actor_id INTEGER,                   -- team_members.id (NULL for Max/system)
    -- Content hash
    content_hash TEXT NOT NULL,         -- BLAKE3 hash of the action payload (JSON of what changed)
    -- Chain integrity
    previous_hash TEXT,                 -- BLAKE3 hash of the previous receipt (NULL for genesis)
    receipt_hash TEXT NOT NULL,         -- BLAKE3(content_hash + previous_hash + timestamp) — this receipt's identity
    -- Constitutional check
    invariants_checked TEXT NOT NULL DEFAULT '[]',   -- JSON array of invariant IDs that were checked
    invariants_passed INTEGER NOT NULL DEFAULT 1,    -- 1 = all passed, 0 = violation detected
    violation_details TEXT,             -- if invariants_passed = 0, what failed and why
    -- Context
    scope TEXT NOT NULL DEFAULT 'team', -- 'team' (mandatory) or 'project' (per-project toggle)
    project_id INTEGER REFERENCES projects(id),  -- NULL for team-level actions
    metadata TEXT DEFAULT '{}',         -- JSON blob for extra context
    -- Timestamps
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

CREATE INDEX idx_governance_receipts_entity ON governance_receipts(entity_type, entity_id);
CREATE INDEX idx_governance_receipts_chain ON governance_receipts(receipt_hash);
CREATE INDEX idx_governance_receipts_project ON governance_receipts(project_id);
CREATE INDEX idx_governance_receipts_scope ON governance_receipts(scope);
```

#### 1c. New table: `constitutional_invariants`

Codifies ExoChain's 9 invariants (and any custom ones for The Team).

```sql
CREATE TABLE constitutional_invariants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,          -- e.g. 'INV-001', 'INV-002'
    name TEXT NOT NULL,                 -- human-readable name
    description TEXT NOT NULL,          -- what it enforces
    check_function TEXT NOT NULL,       -- name of the JS function that performs the check
    severity TEXT NOT NULL DEFAULT 'block' CHECK(severity IN ('block', 'warn', 'log')),
        -- block = prevent the action, warn = allow but flag, log = record only
    enabled INTEGER NOT NULL DEFAULT 1,
    scope TEXT NOT NULL DEFAULT 'all' CHECK(scope IN ('all', 'team', 'project')),
        -- 'all' = applies everywhere, 'team' = team-level only, 'project' = project-level only
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);
```

Seed data (The Team's constitutional invariants, mapped from ExoChain's 9):

| Code | Name | What It Checks | Severity |
|------|------|---------------|----------|
| INV-001 | Authorization Required | Every action must have an identified actor | block |
| INV-002 | Chain Continuity | Receipt hash chain must be unbroken | block |
| INV-003 | No Silent Mutations | State changes without activity_log entries are forbidden | block |
| INV-004 | Priority Integrity | Priority can only be downgraded by Gray, upgraded by Max | block |
| INV-005 | Delivery Review Gate | Tasks cannot move to 'delivered' without passing through 'review' | block |
| INV-006 | Assignment Accountability | Every in_progress task must have an assigned member | warn |
| INV-007 | Provenance Required | Governed project outputs must have provenance chain | block |
| INV-008 | Single Orchestrator | Only one orchestrator (Gray) can exist at tier 'orchestrator' | block |
| INV-009 | Immutable History | Governance receipts cannot be modified or deleted after creation | block |

#### 1d. New table: `provenance_chain`

Tracks the lineage of outputs — who created what, from what inputs, through what process.

```sql
CREATE TABLE provenance_chain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- What was produced
    output_type TEXT NOT NULL,           -- 'file', 'task_result', 'decision', 'note'
    output_id INTEGER,                   -- references the relevant table
    output_hash TEXT NOT NULL,           -- BLAKE3 hash of the output content
    -- What it came from
    input_type TEXT,                      -- 'file', 'task', 'note', 'conversation'
    input_id INTEGER,
    input_hash TEXT,                      -- BLAKE3 of the input
    -- Who processed it
    actor TEXT NOT NULL,
    actor_id INTEGER REFERENCES team_members(id),
    -- How
    process_description TEXT,            -- e.g. 'Research by Pax', 'Code review by Rivet'
    -- Chain
    receipt_id INTEGER REFERENCES governance_receipts(id),  -- links to the governance receipt
    project_id INTEGER REFERENCES projects(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

CREATE INDEX idx_provenance_output ON provenance_chain(output_type, output_id);
CREATE INDEX idx_provenance_input ON provenance_chain(input_type, input_id);
```

#### 1e. Future-proofing column on `team_members`

```sql
ALTER TABLE team_members ADD COLUMN did_identity TEXT;  -- future: decentralized identity
```

Not used in Phase 1, but reserves the column for Phase 2 DID integration.

---

### 2. Server Changes

#### 2a. New dependency

```
npm install blake3
```

`blake3` is a Node.js binding for BLAKE3 hashing. Fast, no external dependencies, matches ExoChain's hash algorithm.

#### 2b. Governance module: `governance.js` (new file in `/app`)

A standalone module (not inline in server.js) containing:

**Core functions:**

- `computeBlake3(data)` — BLAKE3 hash of any string/buffer, returns hex
- `createReceipt(db, { actionType, entityType, entityId, actor, actorId, payload, scope, projectId })` — builds a receipt:
  1. Hash the payload JSON with BLAKE3 → `content_hash`
  2. Fetch the most recent receipt → get its `receipt_hash` as `previous_hash`
  3. Compute `receipt_hash = BLAKE3(content_hash + previous_hash + timestamp)`
  4. Insert into `governance_receipts`
  5. Return the receipt object
- `checkInvariants(db, actionType, entityType, entityId, payload)` — runs all enabled invariants relevant to this action type, returns `{ passed: bool, checked: [...], violations: [...] }`
- `verifyChain(db, limit?)` — walks the receipt chain backward, verifies each hash links correctly, returns integrity report
- `recordProvenance(db, { outputType, outputId, outputContent, inputType, inputId, inputContent, actor, actorId, processDescription, projectId })` — hashes input/output, creates provenance record linked to a receipt
- `isProjectGoverned(db, projectId)` — checks `projects.exochain_governed`

**Invariant check functions** (one per INV-XXX):

Each is a pure function: `(db, actionType, entityType, entityId, payload) => { passed: bool, detail: string }`.

Registered in a map so `checkInvariants` can iterate them.

#### 2c. Governance middleware

A new Express middleware applied to mutating routes:

```
function governanceMiddleware(actionType, entityType, getEntityId, getScope)
```

Wraps POST/PUT/DELETE handlers. Before the actual mutation:

1. Determine scope: is this a team-level action or a project-level action?
2. If project-level, check `isProjectGoverned()`. If not governed, skip governance and proceed normally.
3. If governed (team-level always, project-level when toggled on):
   a. Run `checkInvariants()` for this action type
   b. If any `block`-severity invariant fails → return 403 with violation details
   c. If `warn`-severity fails → proceed but flag in receipt
4. After the mutation succeeds, call `createReceipt()` to log the cryptographic receipt.
5. If the action produces output, call `recordProvenance()`.

**Routes that get governance middleware:**

| Route | Action Type | Scope |
|-------|------------|-------|
| POST /api/tasks | task_created | team (always) |
| PUT /api/tasks/:id | task_updated | team + project (if task is in a governed project) |
| PUT /api/tasks/:id/status | task_status_changed | team + project |
| POST /api/tasks/:id/assign | member_assigned | team |
| PUT /api/tasks/:id/priority | priority_changed | team |
| POST /api/projects | project_created | team |
| PUT /api/projects/:id | project_updated | project (if governed) |
| POST /api/team-members | member_added | team |
| PUT /api/team-members/:id | member_updated | team |
| POST /api/decisions | decision_logged | team |

Non-governed project routes execute normally with no overhead.

#### 2d. New API endpoints

| Endpoint | Purpose |
|----------|---------|
| GET /api/governance/receipts | List receipts, filterable by scope/project/entity/actor |
| GET /api/governance/receipts/:id | Single receipt detail |
| GET /api/governance/verify | Run chain verification, return integrity report |
| GET /api/governance/invariants | List all constitutional invariants with status |
| PUT /api/governance/invariants/:id | Enable/disable an invariant (Max only) |
| GET /api/governance/provenance/:entityType/:entityId | Full provenance chain for an entity |
| GET /api/governance/stats | Counts: total receipts, verified actions, violations, chain integrity status |
| GET /api/projects/:id/governance | Governance summary for a specific project |
| PUT /api/projects/:id/governance | Toggle ExoChain governance on/off for a project |

---

### 3. UI Changes

#### 3a. Project creation form — ExoChain toggle

In the existing "New Project" form (currently has Name, Status, Summary fields), add:

```
[  ] Build on ExoChain infrastructure
     Enables cryptographic verification, constitutional invariants,
     and provenance tracking for all project actions.
```

A toggle switch between the Status dropdown and Summary textarea. Default: off.

When toggled on, a subtle visual indicator appears (shield icon + "ExoChain Governed" label).

The toggle sends `exochain_governed: 1` in the POST /api/projects body.

#### 3b. Project cards — governance badge

On the project list (Executive Summary page), governed projects show a small badge:

- Shield icon + "Governed" in a distinctive color (suggested: teal or gold)
- Standard projects show nothing extra (no visual noise)

This makes it immediately obvious which projects are under governance.

#### 3c. Project detail page — governance section

When viewing a governed project, add a section below the summary:

**Governance Status Panel:**
- Chain integrity: Verified / Broken (with last-verified timestamp)
- Total receipts for this project
- Last verified action (timestamp + description)
- Violations detected (count, expandable list)
- Button: "Verify Chain" → calls GET /api/governance/verify?project_id=X
- Button: "View Receipts" → expands receipt log
- Toggle: "Disable Governance" (with confirmation dialog warning this is significant)

#### 3d. Project detail page — governance toggle for existing projects

On the project edit view, add the same toggle as creation. Changing from off to on:
- Confirmation dialog: "Enable ExoChain governance? All future actions on this project will be cryptographically verified."
- Creates a genesis receipt for the project

Changing from on to off:
- Confirmation dialog: "Disable ExoChain governance? Future actions will no longer be verified. Existing receipts are preserved."
- Creates a final receipt noting governance was disabled

#### 3e. Dashboard — governance overview

On the main dashboard (GET /api/dashboard), add a small "Governance" card:

- "X of Y projects governed"
- "Z actions verified today"
- Chain status: intact / broken
- Link to full governance view

#### 3f. Activity log — verification indicators

In the activity timeline (already exists), governed actions get a small icon:
- Green shield checkmark = verified (receipt exists, chain intact)
- Yellow warning = verified with warnings
- Red shield X = invariant violation was detected
- No icon = non-governed action

#### 3g. New sidebar section (or sub-page)

Add "Governance" to the sidebar navigation, or as a sub-section under an existing page. Contains:

- **Constitutional Invariants** — table of all 9 invariants, toggle-able (for Max)
- **Receipt Chain** — scrollable log of all receipts, filterable
- **Chain Verification** — run integrity check, see results
- **Provenance Explorer** — select any output, see its full input→process→output lineage

---

### 4. Implementation Sequence

Build in this order to keep things working at every step:

| Step | What | Files Touched | Depends On |
|------|------|--------------|-----------|
| 1 | Database migrations — add all new tables + columns | `the_team.db` via migration script | Nothing |
| 2 | Seed constitutional invariants | `the_team.db` | Step 1 |
| 3 | `governance.js` module — BLAKE3 hashing, receipt creation, invariant checks, chain verification | New: `app/governance.js` | Step 1, npm install blake3 |
| 4 | Governance middleware — wire into existing routes | `app/server.js` | Step 3 |
| 5 | New API endpoints — receipts, verification, provenance, stats | `app/server.js` | Step 3 |
| 6 | Project creation toggle (UI) | `app/public/app.js` | Step 1 (column exists) |
| 7 | Project card badges + detail governance panel (UI) | `app/public/app.js`, `app/public/styles.css` | Steps 5, 6 |
| 8 | Dashboard governance card (UI) | `app/public/app.js` | Step 5 |
| 9 | Activity log verification indicators (UI) | `app/public/app.js`, `app/public/styles.css` | Step 4 |
| 10 | Governance sidebar page — invariants, receipts, provenance explorer (UI) | `app/public/app.js`, `app/public/styles.css` | Steps 5, 7 |

**Estimated scope:** ~400-600 lines in `governance.js`, ~100 lines of SQL, ~200 lines added to `server.js`, ~500-800 lines of UI code in `app.js` + styles.

---

## Phase 2: What We Plan for LATER

These items deepen the integration toward actual ExoChain infrastructure once Phase 1 is proven:

### 2a. WASM Module Integration

Compile ExoChain's CGR Kernel to WASM and load it in Node.js. Replace our JavaScript invariant checks with the actual Rust-compiled kernel. This gives us:
- Identical invariant logic to ExoChain mainline
- Performance benefits of compiled Rust
- Formal verification compatibility

**Prerequisite:** ExoChain publishes WASM binaries or we compile from source.

### 2b. DID Identities for Team Members

Assign each team member (and Gray) a Decentralized Identifier following ExoChain's Holon identity spec:
- `did:exo:gray-orchestrator`
- `did:exo:pax-researcher`
- etc.

Use the `did_identity` column added in Phase 1. Sign receipts with DID-linked keys.

### 2c. Holon Registration

Register Gray and each team member as Holons in an ExoChain-compatible registry. This makes them first-class citizens in the ExoChain network, not just our local system.

### 2d. 3-Branch Separation of Powers

Map our team hierarchy to ExoChain's governance branches:
- **Legislative:** Max (sets rules, constitutional invariants, priorities)
- **Executive:** Gray + Leaders (execute work, make operational decisions)
- **Judicial:** Rivet + governance system (review, verify, enforce invariants)

Formalize this so certain actions require cross-branch approval.

### 2e. Cross-System Receipt Anchoring

Anchor our receipt chain hashes to an external immutable store (could be a blockchain, a git commit, or an ExoChain ledger). This provides tamper-evidence beyond our local SQLite database.

### 2f. Governance Templates per Project Type

Pre-built governance profiles:
- "Full Governance" — all invariants, strict mode
- "Light Governance" — logging + provenance, no blocking invariants
- "Audit Only" — receipts generated but no invariant checking
- "Custom" — pick and choose which invariants apply

### 2g. Inter-Project Provenance

When output from Project A becomes input to Project B, the provenance chain should cross project boundaries. Phase 1 tracks within a project; Phase 2 links across projects.

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| BLAKE3 over SHA-256 | Matches ExoChain's choice. Also faster in software than SHA-256. The `blake3` npm package provides native bindings. |
| Receipts in SQLite, not a separate store | Keeps the "one database" principle. Phase 2 can add external anchoring. |
| Team governance is mandatory, project governance is optional | Per Max's requirements. The Team is the governed entity; projects opt in. |
| Invariants are configurable, not hardcoded | Max can enable/disable invariants. New ones can be added. The `constitutional_invariants` table is the source of truth. |
| Middleware pattern, not inline checks | Keeps governance logic separate from business logic. Easy to add/remove governance from routes. Can be disabled per-route if needed. |
| `governance.js` as separate module | Avoids bloating `server.js` further (already 2000+ lines). Clean import, testable in isolation. |
| Genesis receipt per governed project | When governance is enabled on a project, a genesis receipt (previous_hash = NULL) anchors the chain. Team-level has its own genesis receipt. |

---

## What This Does NOT Do (Explicitly Out of Scope for Phase 1)

- No actual WASM execution — we implement the patterns in JavaScript
- No real DID resolution — the column exists but identities are local strings
- No external chain anchoring — receipts live only in SQLite
- No consensus mechanism — Gray is the single orchestrator, no multi-party consensus
- No formal verification — invariant checks are runtime JS, not formally proven
- No encryption of receipt data — hashed for integrity, not encrypted for confidentiality
- No network communication with ExoChain nodes — this is a local implementation of ExoChain patterns

---

## Validation Gates

Before marking each step complete:

| Gate | Criteria |
|------|---------|
| DB migrations | All new tables exist, schema matches plan, seed data inserted |
| Governance module | `computeBlake3` produces correct hashes, `createReceipt` builds valid chain, `checkInvariants` catches known violations, `verifyChain` detects tampering |
| Middleware | Governed routes produce receipts, non-governed routes work unchanged, block-severity violations return 403 |
| API endpoints | All 9 endpoints return correct data, filters work, verification catches broken chains |
| Project toggle | Creating a project with toggle ON stores `exochain_governed = 1`, toggle OFF stores 0, existing projects can be toggled |
| Dashboard UI | Governance card shows stats, project cards show badges, activity log shows verification icons |
| Governance page | Invariants table renders, receipt log scrolls and filters, provenance explorer traces lineage |
| End-to-end | Create a governed project → create a task in it → assign it → complete it → deliver it → verify the full receipt chain is intact and all invariants were checked at each step |
