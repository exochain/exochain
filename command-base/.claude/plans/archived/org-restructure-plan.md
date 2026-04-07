# Plan: Org Restructure — Member Memory, C-Suite Hierarchy & ExoChain Governance

**Author:** Atlas (Systems Architect & Technical Planner)
**Date:** 2026-03-29
**Status:** Ready for Gray's review and Max's approval
**Supersedes:** Extends `team-hierarchy.md` and `exochain-integration.md`

---

## Overview

Three interconnected systems designed together so they share schema, flow through the same hierarchy, and enforce governance uniformly:

1. **Member Context/Memory System** -- persistent per-member memory that survives across sessions
2. **C-Suite Org Restructure** -- adds an executive tier between Gray and the department leaders
3. **ExoChain Governance Integration** -- constitutional invariant enforcement at every tier

These are not independent features. The C-Suite tier determines who reviews what memory. Governance receipts are required when memory is written. Memory context determines what governance rules a member is aware of. They ship together.

---

# Design 1: Member Context/Memory System

## The Problem

Team members lose all context between sessions. Every time a member is activated, they start from scratch -- re-reading their profile, re-learning project state, re-discovering patterns they already figured out. This is wasteful and produces inconsistent work. Members should remember what they learned, what worked, what failed, and what Max prefers.

## Schema

### Table: `member_context`

```sql
CREATE TABLE IF NOT EXISTS member_context (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- WHO owns this context
    member_id INTEGER NOT NULL REFERENCES team_members(id),

    -- WHAT kind of context
    context_type TEXT NOT NULL CHECK(context_type IN (
        'project_knowledge',    -- things learned about a specific project
        'task_history',         -- patterns from past tasks (what worked, what failed)
        'preferences',          -- Max's preferences this member has observed
        'learned_patterns',     -- reusable patterns, shortcuts, conventions discovered
        'domain_expertise',     -- accumulated domain knowledge (e.g., "Clipper Engine uses FFmpeg 6.1")
        'active_context',       -- current working state (what they're in the middle of)
        'relationship',         -- knowledge about other members, tools, or external contacts
        'error_pattern'         -- known failure modes and how to avoid them
    )),

    -- WHAT this context is about (indexable key)
    context_key TEXT NOT NULL,
    -- e.g., "clipper_engine_architecture", "max_prefers_conventional_commits",
    --       "anvil_api_patterns", "ffmpeg_segment_flags"

    -- THE ACTUAL KNOWLEDGE (can be long)
    context_value TEXT NOT NULL,
    -- Free-form text. Can be a paragraph, a JSON blob, a code snippet,
    -- a list of bullet points -- whatever captures the knowledge best.

    -- HOW IMPORTANT is this context
    importance TEXT NOT NULL DEFAULT 'normal' CHECK(importance IN (
        'critical',   -- always loaded, no matter what (e.g., "Max hates when we ask permission for things we can handle")
        'high',       -- loaded in top-20 context budget
        'normal',     -- loaded if context budget allows
        'low'         -- only loaded if explicitly queried
    )),

    -- WHERE did this context come from
    source_task_id INTEGER REFERENCES tasks(id),
    source_description TEXT,  -- human-readable origin, e.g., "learned during task #42: API refactor"

    -- WHEN does this context expire
    expires_at TEXT,  -- NULL = never expires. ISO datetime for time-sensitive context.

    -- WHICH project does this relate to (optional)
    project_id INTEGER REFERENCES projects(id),

    -- TAGS for searchability
    tags TEXT DEFAULT '[]',  -- JSON array of string tags, e.g., '["clipper-engine","ffmpeg","video"]'

    -- TIMESTAMPS
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),

    -- UNIQUENESS: one member cannot have duplicate keys of the same type
    UNIQUE(member_id, context_type, context_key)
);

-- Indexes for fast context loading
CREATE INDEX IF NOT EXISTS idx_member_context_member
    ON member_context(member_id, importance);

CREATE INDEX IF NOT EXISTS idx_member_context_type
    ON member_context(member_id, context_type);

CREATE INDEX IF NOT EXISTS idx_member_context_project
    ON member_context(project_id);

CREATE INDEX IF NOT EXISTS idx_member_context_expiry
    ON member_context(expires_at)
    WHERE expires_at IS NOT NULL;
```

### Table: `context_load_log`

Tracks when context was loaded and how useful it was, enabling the system to learn which context matters.

```sql
CREATE TABLE IF NOT EXISTS context_load_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER NOT NULL REFERENCES team_members(id),
    task_id INTEGER REFERENCES tasks(id),
    context_ids_loaded TEXT NOT NULL DEFAULT '[]',  -- JSON array of member_context.id values
    total_items_loaded INTEGER NOT NULL DEFAULT 0,
    load_strategy TEXT NOT NULL DEFAULT 'budget',   -- 'budget', 'full', 'query', 'project_scoped'
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);
```

## Context Loading Mechanism

### On Task Start: Load Phase

When a member is activated for a task, their context is loaded in priority order:

```sql
-- Step 1: Always load CRITICAL context (no budget limit)
SELECT * FROM member_context
WHERE member_id = :member_id
  AND importance = 'critical'
  AND (expires_at IS NULL OR expires_at > datetime('now', 'localtime'))
ORDER BY updated_at DESC;

-- Step 2: Load HIGH context up to budget (default: 20 items total including critical)
SELECT * FROM member_context
WHERE member_id = :member_id
  AND importance = 'high'
  AND (expires_at IS NULL OR expires_at > datetime('now', 'localtime'))
ORDER BY updated_at DESC
LIMIT :remaining_budget;

-- Step 3: If task is associated with a project, load project-specific context
SELECT * FROM member_context
WHERE member_id = :member_id
  AND project_id = :project_id
  AND importance IN ('normal', 'high')
  AND (expires_at IS NULL OR expires_at > datetime('now', 'localtime'))
ORDER BY importance DESC, updated_at DESC
LIMIT 10;

-- Step 4: Fill remaining budget with NORMAL context (most recently updated first)
SELECT * FROM member_context
WHERE member_id = :member_id
  AND importance = 'normal'
  AND id NOT IN (:already_loaded_ids)
  AND (expires_at IS NULL OR expires_at > datetime('now', 'localtime'))
ORDER BY updated_at DESC
LIMIT :remaining_budget;
```

**Context Budget per tier:**

| Tier | Default Budget | Rationale |
|------|---------------|-----------|
| Orchestrator (Gray) | 50 | Needs broad awareness across all domains |
| C-Suite | 40 | Needs department-wide context |
| Leader | 25 | Deep domain context |
| Co-Leader | 20 | Inherits leader context + own observations |
| Subagent | 10 | Narrow task focus, minimal context needed |

Budget is stored in `system_settings`:

```sql
INSERT OR REPLACE INTO system_settings (key, value, updated_at)
VALUES ('context_budget_orchestrator', '50', datetime('now', 'localtime'));

INSERT OR REPLACE INTO system_settings (key, value, updated_at)
VALUES ('context_budget_csuite', '40', datetime('now', 'localtime'));

INSERT OR REPLACE INTO system_settings (key, value, updated_at)
VALUES ('context_budget_leader', '25', datetime('now', 'localtime'));

INSERT OR REPLACE INTO system_settings (key, value, updated_at)
VALUES ('context_budget_coleader', '20', datetime('now', 'localtime'));

INSERT OR REPLACE INTO system_settings (key, value, updated_at)
VALUES ('context_budget_subagent', '10', datetime('now', 'localtime'));
```

### On Task Completion: Write-Back Phase

When a member finishes a task, they write back what they learned:

```sql
-- UPSERT pattern: update if same key exists, insert if new
INSERT INTO member_context (member_id, context_type, context_key, context_value, importance, source_task_id, source_description, project_id, tags, updated_at)
VALUES (:member_id, :type, :key, :value, :importance, :task_id, :description, :project_id, :tags, datetime('now', 'localtime'))
ON CONFLICT(member_id, context_type, context_key)
DO UPDATE SET
    context_value = excluded.context_value,
    importance = excluded.importance,
    source_task_id = excluded.source_task_id,
    source_description = excluded.source_description,
    project_id = excluded.project_id,
    tags = excluded.tags,
    updated_at = datetime('now', 'localtime');
```

### Context Query: Self-Search

Members can query their own memory during a task:

```sql
-- Search by keyword in key or value
SELECT * FROM member_context
WHERE member_id = :member_id
  AND (context_key LIKE '%' || :query || '%'
       OR context_value LIKE '%' || :query || '%')
  AND (expires_at IS NULL OR expires_at > datetime('now', 'localtime'))
ORDER BY importance DESC, updated_at DESC
LIMIT 10;

-- Search by tag
SELECT * FROM member_context
WHERE member_id = :member_id
  AND tags LIKE '%"' || :tag || '"%'
ORDER BY importance DESC, updated_at DESC;
```

## Context Management Rules

### 1. Expiration and Archival

```sql
-- Archive expired context (run periodically by Cadence/Tempo)
UPDATE member_context
SET importance = 'low', context_type = 'task_history'
WHERE expires_at IS NOT NULL
  AND expires_at < datetime('now', 'localtime')
  AND importance != 'low';

-- Hard delete context older than 90 days with importance = 'low'
-- (only after archival, never delete critical/high)
DELETE FROM member_context
WHERE importance = 'low'
  AND updated_at < datetime('now', '-90 days')
  AND importance NOT IN ('critical', 'high');
```

### 2. Context Inheritance

Co-leaders inherit their leader's `critical` context:

```sql
-- When activating a co-leader, copy leader's critical context
INSERT OR IGNORE INTO member_context (member_id, context_type, context_key, context_value, importance, source_description, project_id, tags, created_at, updated_at)
SELECT
    :coleader_id,
    context_type,
    context_key,
    context_value,
    importance,
    'Inherited from leader ' || (SELECT name FROM team_members WHERE id = :leader_id),
    project_id,
    tags,
    datetime('now', 'localtime'),
    datetime('now', 'localtime')
FROM member_context
WHERE member_id = :leader_id
  AND importance = 'critical';
```

### 3. Context Promotion/Demotion

If context is loaded 5+ times across tasks, auto-promote to `high`. If not loaded in 30 days, auto-demote:

```sql
-- Promote frequently-used context
-- (run by analyzing context_load_log)
UPDATE member_context
SET importance = 'high', updated_at = datetime('now', 'localtime')
WHERE id IN (
    SELECT mc.id FROM member_context mc
    JOIN context_load_log cll ON cll.context_ids_loaded LIKE '%' || mc.id || '%'
    WHERE mc.importance = 'normal'
    GROUP BY mc.id
    HAVING COUNT(cll.id) >= 5
);

-- Demote stale context
UPDATE member_context
SET importance = 'low', updated_at = datetime('now', 'localtime')
WHERE importance = 'normal'
  AND updated_at < datetime('now', '-30 days')
  AND context_type NOT IN ('preferences', 'domain_expertise');
```

### 4. What Each Context Type Is For

| Type | Written When | Example Key | Example Value |
|------|-------------|-------------|---------------|
| `project_knowledge` | After working on a project task | `clipper_engine_db_schema` | "Uses PostgreSQL with 12 core tables. Video segments stored in S3, metadata in segments table..." |
| `task_history` | After completing any task | `api_refactor_task_42` | "Refactored /api/clips endpoint. Key learning: batch processing needs cursor pagination, not offset." |
| `preferences` | When observing Max's feedback | `max_commit_style` | "Max prefers conventional commits. No emojis. Short subject line. Body explains why, not what." |
| `learned_patterns` | When discovering reusable technique | `sqlite_wal_mode_fix` | "Always enable WAL mode before concurrent writes: PRAGMA journal_mode=WAL;" |
| `domain_expertise` | When accumulating knowledge | `ffmpeg_hls_flags` | "For HLS output use: -hls_time 6 -hls_list_size 0 -hls_segment_filename. Use -movflags +faststart for MP4." |
| `active_context` | During a task (work in progress) | `current_refactor_state` | "Halfway through migrating routes. /api/tasks done, /api/projects done, /api/governance NOT started." |
| `relationship` | When learning about team dynamics | `anvil_sql_conventions` | "Anvil uses snake_case for all columns. Always adds created_at/updated_at. Prefers explicit JOINs over subqueries." |
| `error_pattern` | When encountering/fixing bugs | `sqlite_busy_timeout` | "SQLite throws SQLITE_BUSY under concurrent writes. Fix: db.pragma('busy_timeout', 5000) on connection." |

---

# Design 2: C-Suite Org Structure

## The Problem

The current hierarchy is: Gray -> Leaders -> Co-Leaders -> Subagents. This is flat for a 30+ member org. Gray directly manages 11 leaders, which means:

1. Gray is a bottleneck for routing decisions
2. No one aggregates cross-domain context (e.g., "the backend API change affects frontend AND QA")
3. Leaders only see their own domain, not the bigger picture
4. There is no strategic layer between "orchestrate everything" and "do the work"

## The New Hierarchy

```
Gray (Orchestrator)
  |
  +-- CTO (Chief Technology Officer)
  |     +-- Anvil (Backend Developer)
  |     |     +-- Weld (Backend Co-Lead)
  |     +-- Spark (Frontend Developer)
  |     |     +-- Flint (Frontend Co-Lead)
  |     +-- Bastion (DevOps & Infrastructure Engineer)
  |     |     +-- Rampart (DevOps Co-Lead)
  |     +-- Lumen (UI Developer & Design Engineer)
  |     |     +-- Prism (UI Developer Co-Lead)
  |     +-- Rivet (QA & Functional Test Engineer)
  |     |     +-- Bolt (QA Co-Lead)
  |     |     +-- Probe (Test Coverage Specialist)
  |     +-- Hone (Platform Engineer & Continuous Improvement)
  |
  +-- CSO (Chief Strategy Officer)
  |     +-- Atlas (Systems Architect & Technical Planner)
  |     |     +-- Compass (Planning Co-Lead)
  |     +-- Pax (Senior Researcher)
  |     |     +-- Sage (Research Co-Lead)
  |     +-- Marshal (Executive Director -- Clipper Engine)
  |           +-- Forge (Foundation Director)
  |           +-- Cipher (Transcript Pipeline Director)
  |           +-- Splice (Generation Director)
  |           +-- Herald (Publishing Director)
  |           +-- Oracle (Intelligence Director)
  |           +-- Sentinel (Verification Director)
  |           +-- Scribe (Archivist Agent)
  |
  +-- COO (Chief Operating Officer)
  |     +-- Zenith (HR Director)
  |     |     +-- Nova (HR Co-Lead)
  |     +-- Cadence (Calendar Manager, Content Scheduler & Analytics)
  |           +-- Tempo (Analytics Auto-Worker & Scheduler)
  |
  +-- CLO (Chief Legal Officer)
        +-- (Future: Legal/Compliance specialists)
        +-- Governs ExoChain constitutional enforcement
```

## Schema Changes

### Tier Update

The existing `tier` column needs a new value:

```sql
-- Step 1: Drop the existing CHECK constraint and recreate with new tier
-- SQLite doesn't support ALTER CONSTRAINT, so we use a pragma approach
-- The safe way: create new column, copy, drop old, rename

-- Actually, SQLite CHECK constraints are only enforced on INSERT/UPDATE,
-- and the existing column already has data. We need to recreate the table
-- or use a simpler approach: just update the CHECK.
--
-- Simplest safe approach: SQLite ignores CHECK constraints on existing data
-- when you ALTER. But new INSERTs will fail. So we rebuild:

CREATE TABLE team_members_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL,
    profile_path TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'inactive')),
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    execution_mode TEXT NOT NULL DEFAULT 'system'
        CHECK(execution_mode IN ('system', 'terminal', 'autonomous')),
    tier TEXT NOT NULL DEFAULT 'leader'
        CHECK(tier IN ('orchestrator', 'csuite', 'leader', 'co-leader', 'subagent')),
    reports_to INTEGER REFERENCES team_members_new(id),
    did_identity TEXT,
    dedicated_role INTEGER NOT NULL DEFAULT 0,
    llm_provider_id INTEGER REFERENCES llm_providers(id),
    llm_model TEXT
);

-- Copy all existing data
INSERT INTO team_members_new
SELECT * FROM team_members;

-- Drop old table
DROP TABLE team_members;

-- Rename new table
ALTER TABLE team_members_new RENAME TO team_members;
```

### New C-Suite Members

```sql
-- CTO: Chief Technology Officer
INSERT INTO team_members (name, role, profile_path, status, tier, reports_to, execution_mode)
VALUES ('Axiom', 'Chief Technology Officer', 'Team/axiom.md', 'active', 'csuite', 1, 'system');

-- CSO: Chief Strategy Officer
INSERT INTO team_members (name, role, profile_path, status, tier, reports_to, execution_mode)
VALUES ('Vertex', 'Chief Strategy Officer', 'Team/vertex.md', 'active', 'csuite', 1, 'system');

-- COO: Chief Operating Officer
INSERT INTO team_members (name, role, profile_path, status, tier, reports_to, execution_mode)
VALUES ('Meridian', 'Chief Operating Officer', 'Team/meridian.md', 'active', 'csuite', 1, 'system');

-- CLO: Chief Legal Officer
INSERT INTO team_members (name, role, profile_path, status, tier, reports_to, execution_mode)
VALUES ('Canon', 'Chief Legal Officer', 'Team/canon.md', 'active', 'csuite', 1, 'system');
```

**Name rationale:**
- **Axiom** -- a self-evident truth; the foundation all technology is built on
- **Vertex** -- the highest point; strategic vision and planning
- **Meridian** -- the line connecting poles; operations that connect everything
- **Canon** -- established rules and principles; law and governance

### Re-wire Leader Reporting Lines

```sql
-- Technology leaders report to CTO (Axiom)
-- Assuming Axiom gets id = 30 (next autoincrement after current 29)
-- In practice, use: SELECT id FROM team_members WHERE name = 'Axiom'

UPDATE team_members SET reports_to = (SELECT id FROM team_members WHERE name = 'Axiom')
WHERE name IN ('Anvil', 'Spark', 'Bastion', 'Lumen', 'Rivet', 'Hone');

-- Strategy leaders report to CSO (Vertex)
UPDATE team_members SET reports_to = (SELECT id FROM team_members WHERE name = 'Vertex')
WHERE name IN ('Atlas', 'Pax', 'Marshal');

-- Operations leaders report to COO (Meridian)
UPDATE team_members SET reports_to = (SELECT id FROM team_members WHERE name = 'Meridian')
WHERE name IN ('Zenith', 'Cadence');

-- CLO (Canon) reports to Gray, no direct reports yet
-- Future legal/compliance specialists will report to Canon
```

## Context Flow: Downward (Directive -> Execution)

### How a directive flows from Gray to the worker

```
1. Gray receives directive from Max (or generates one from inbox)
     |
     v
2. Gray identifies which domain(s) are involved
     |
     v
3. Gray issues STRATEGIC DIRECTIVE to relevant C-Suite exec(s)
     - Directive contains: objective, constraints, priority, deadline
     - Directive is logged in `tasks` with assigned_to = C-Suite exec
     - C-Suite exec's context is loaded from member_context
     |
     v
4. C-Suite exec BREAKS DOWN the directive into TACTICAL TASKS
     - CTO might split: "Build the clips API" into:
       - Backend task for Anvil (API routes, DB queries)
       - Frontend task for Spark (UI for clip viewer)
       - QA task for Rivet (test the integration)
     - Each tactical task is a child task (via task_dependencies)
     - C-Suite exec assigns based on leader availability + context
     |
     v
5. Leaders EXECUTE or further delegate to co-leaders/subagents
     - Leader loads their own context from member_context
     - Leader does the work or splits to co-leader if busy
     |
     v
6. Work product flows back up (see upward flow below)
```

### Database support for directive chain

```sql
-- Add parent_task_id to track directive -> tactical task hierarchy
ALTER TABLE tasks ADD COLUMN parent_task_id INTEGER REFERENCES tasks(id);

-- Add directive_level to distinguish strategic vs tactical vs execution
ALTER TABLE tasks ADD COLUMN directive_level TEXT DEFAULT 'execution'
    CHECK(directive_level IN ('strategic', 'tactical', 'execution'));
```

**How this looks in practice:**

```sql
-- Gray creates strategic directive
INSERT INTO tasks (title, description, assigned_to, priority, directive_level)
VALUES ('Build Clipper Engine Phase 2', 'Full clips pipeline with HLS output',
        (SELECT id FROM team_members WHERE name = 'Axiom'), 'high', 'strategic');
-- Returns task_id = 100

-- Axiom breaks it down into tactical tasks
INSERT INTO tasks (title, assigned_to, priority, directive_level, parent_task_id)
VALUES ('Clips API endpoints', (SELECT id FROM team_members WHERE name = 'Anvil'),
        'high', 'tactical', 100);

INSERT INTO tasks (title, assigned_to, priority, directive_level, parent_task_id)
VALUES ('Clip viewer UI', (SELECT id FROM team_members WHERE name = 'Lumen'),
        'normal', 'tactical', 100);

INSERT INTO tasks (title, assigned_to, priority, directive_level, parent_task_id)
VALUES ('Integration tests for clips', (SELECT id FROM team_members WHERE name = 'Rivet'),
        'normal', 'tactical', 100);
```

## Context Flow: Upward (Results -> Summary)

### How results flow from workers back to Gray

```
1. Leader/Co-Leader completes execution task
     - Updates task status to 'review'
     - Writes back context to member_context (what they learned)
     - Logs output in task_files and activity_log
     |
     v
2. C-Suite exec reviews tactical task results
     - All tactical tasks under a strategic directive complete
     - C-Suite exec aggregates results into a SUMMARY
     - Summary includes: what was done, what worked, what didn't, blockers
     - C-Suite exec updates their own context (member_context)
     |
     v
3. C-Suite exec reports to Gray
     - Updates the strategic task status
     - Provides executive summary (not raw details)
     - Flags any escalations or decisions needed
     |
     v
4. Gray reviews and delivers to Max
     - Gray sees the executive summary, not every line of code
     - Gray can drill down if needed (query child tasks)
     - Gray delivers to Stew's inbox with appropriate summary
```

### Executive Summary mechanism

```sql
-- New table: executive_summaries
-- C-Suite execs write these when rolling up tactical results
CREATE TABLE IF NOT EXISTS executive_summaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL REFERENCES tasks(id),  -- the strategic-level task
    author_id INTEGER NOT NULL REFERENCES team_members(id),  -- the C-Suite exec
    summary TEXT NOT NULL,  -- the aggregated executive summary
    tactical_tasks_completed INTEGER NOT NULL DEFAULT 0,
    tactical_tasks_total INTEGER NOT NULL DEFAULT 0,
    blockers TEXT DEFAULT '[]',  -- JSON array of blocker descriptions
    escalations TEXT DEFAULT '[]',  -- JSON array of items needing Gray/Max attention
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);
```

## How `active_processes` Tracks Work at Each Level

The existing `active_processes` table already tracks which member is working on what. With the C-Suite layer, it naturally extends:

```sql
-- C-Suite exec breaking down a directive (planning work)
INSERT INTO active_processes (task_id, member_id, status)
VALUES (100, (SELECT id FROM team_members WHERE name = 'Axiom'), 'running');

-- Leader executing a tactical task
INSERT INTO active_processes (task_id, member_id, status)
VALUES (101, (SELECT id FROM team_members WHERE name = 'Anvil'), 'running');

-- Query: what's happening at each tier right now?
SELECT
    m.tier,
    m.name,
    t.title,
    t.directive_level,
    ap.status
FROM active_processes ap
JOIN team_members m ON ap.member_id = m.id
JOIN tasks t ON ap.task_id = t.id
WHERE ap.status = 'running'
ORDER BY
    CASE m.tier
        WHEN 'orchestrator' THEN 0
        WHEN 'csuite' THEN 1
        WHEN 'leader' THEN 2
        WHEN 'co-leader' THEN 3
        WHEN 'subagent' THEN 4
    END;
```

## Updated Routing Rules for CLAUDE.md

Gray's routing changes from leader-direct to C-Suite-first for multi-domain work:

| Scenario | Old Routing | New Routing |
|----------|-------------|-------------|
| Single-domain task (e.g., "fix this CSS") | Gray -> Lumen | Gray -> Lumen (unchanged for simple tasks) |
| Multi-domain task (e.g., "build the clips feature") | Gray -> split manually to Anvil + Lumen + Rivet | Gray -> Axiom (CTO) -> Axiom splits to Anvil + Lumen + Rivet |
| Strategic planning (e.g., "plan the next quarter") | Gray -> Atlas | Gray -> Vertex (CSO) -> Vertex delegates to Atlas + Pax |
| Hiring/ops (e.g., "we need a new specialist") | Gray -> Zenith | Gray -> Meridian (COO) -> Meridian delegates to Zenith |
| Legal/compliance question | Gray handles directly | Gray -> Canon (CLO) |
| Clipper Engine work | Gray -> Marshal | Gray -> Vertex (CSO) -> Marshal (Vertex owns strategy including CE) |

**Key rule: Gray can STILL go direct to leaders for simple, single-domain tasks.** The C-Suite layer is for coordination, not bureaucracy. If a task is clearly "fix this one CSS bug," Gray should not route through the CTO. The C-Suite is for when work crosses domains or requires strategic breakdown.

---

# Design 3: ExoChain Governance Integration

## What Requires Governance Receipts

Building on the existing `governance_receipts` and `constitutional_invariants` tables already in the database, here is the complete mapping of governed actions by tier:

### Tier-Specific Governed Actions

| Tier | Action | Receipt Required | Invariants Checked |
|------|--------|-----------------|-------------------|
| **Orchestrator** | Create strategic directive | Yes | INV-001, INV-003, INV-006 |
| **Orchestrator** | Hire/fire team member | Yes | INV-001, INV-003, INV-008 |
| **Orchestrator** | Deliver task to Max | Yes | INV-001, INV-003, INV-005 |
| **Orchestrator** | Change team structure | Yes | INV-001, INV-003, INV-008 |
| **C-Suite** | Break directive into tactical tasks | Yes | INV-001, INV-003, INV-006 |
| **C-Suite** | Assign leader to tactical task | Yes | INV-001, INV-003, INV-006 |
| **C-Suite** | Escalate to Gray | Yes | INV-001, INV-003 |
| **C-Suite** | Submit executive summary | Yes | INV-001, INV-003, INV-005 |
| **Leader** | Start execution task | Yes | INV-001, INV-003, INV-006 |
| **Leader** | Deliver task result | Yes | INV-001, INV-003, INV-005, INV-007 |
| **Leader** | Spawn subagent | Yes | INV-001, INV-003 |
| **Leader** | Write to member_context | Yes | INV-001, INV-003, INV-009 |
| **Leader** | Priority change | Yes | INV-001, INV-003, INV-004 |
| **Co-Leader** | All leader actions when activated | Yes | Same as leader |
| **Subagent** | Complete subtask | Yes | INV-001, INV-003 |
| **Any** | Modify governance receipt | BLOCKED | INV-009 (immutable) |
| **Any** | Delete governance receipt | BLOCKED | INV-009 (immutable) |
| **Any** | Modify constitutional invariant | Founder-only | INV-008 (Max only) |

### Actions That Do NOT Require Receipts

- Reading data (queries, context loading)
- Internal member-to-member communication
- Loading context from `member_context`
- Querying the activity log
- Viewing task status

## Constitutional Invariants: Enforcement at Each Tier

### New Invariants for the Expanded Hierarchy

The existing 9 invariants cover the basics. With the C-Suite layer and member context, we need additional ones:

```sql
-- New invariants for C-Suite governance
INSERT INTO constitutional_invariants (code, name, description, severity)
VALUES
    ('INV-010', 'Tier Boundary Respect',
     'Members cannot assign tasks to members more than one tier below them. C-Suite assigns to Leaders, Leaders assign to Co-Leaders/Subagents. No tier-skipping.',
     'warn'),

    ('INV-011', 'Context Write Authenticity',
     'A member can only write to their own member_context. No member can modify another member''s context.',
     'block'),

    ('INV-012', 'Executive Summary Required',
     'Strategic-level tasks cannot be marked complete without an executive_summary from the assigned C-Suite exec.',
     'block'),

    ('INV-013', 'Directive Chain Integrity',
     'Every tactical task must have a parent_task_id linking to a strategic directive. Orphan tactical tasks are forbidden.',
     'warn'),

    ('INV-014', 'Context Budget Enforcement',
     'Context loading must respect the tier-based budget. Exceeding budget triggers a warning receipt.',
     'warn'),

    ('INV-015', 'CLO Governance Review',
     'Changes to constitutional_invariants or governance_receipts schema require CLO (Canon) review receipt.',
     'block');
```

### How Invariants Are Enforced at Each Tier

**Orchestrator Tier (Gray):**
- INV-001 (Authorization): Gray is always authorized as the single orchestrator
- INV-008 (Single Orchestrator): Enforced on any `INSERT INTO team_members WHERE tier = 'orchestrator'` -- must fail if one already exists
- INV-005 (Delivery Review Gate): Gray must have a review receipt before marking any task as `delivered`

**C-Suite Tier:**
- INV-010 (Tier Boundary): C-Suite can only assign to leaders, never directly to co-leaders or subagents
- INV-012 (Executive Summary): Cannot mark a strategic directive complete without filing an executive summary
- INV-006 (Assignment Accountability): Every tactical task they create must have an `assigned_to` before moving to `in_progress`

**Leader Tier:**
- INV-005 (Delivery Review Gate): Leaders submit to their C-Suite exec for review, not directly to delivery
- INV-007 (Provenance Required): For governed projects, every output must have a provenance record
- INV-011 (Context Write Authenticity): Can only write to their own `member_context` rows

**Co-Leader Tier:**
- Same as Leaders when active
- INV-011 applies -- inherited context is read-only, they write their own observations

**Subagent Tier:**
- INV-001 (Authorization): Must be spawned by a leader/co-leader with a receipt
- INV-003 (No Silent Mutations): Every subtask completion generates a receipt

### Invariant Check Flow (Code Pattern)

```javascript
// In governance.js -- the enforcement engine
async function enforceInvariants(db, action) {
    const { actionType, actorId, entityType, entityId, payload } = action;

    // Get actor's tier
    const actor = db.prepare('SELECT tier, id, name FROM team_members WHERE id = ?').get(actorId);

    // Get all enabled invariants
    const invariants = db.prepare('SELECT * FROM constitutional_invariants WHERE enforced = 1').all();

    const results = [];

    for (const inv of invariants) {
        const check = invariantCheckers[inv.code];
        if (!check) continue;

        const result = check(db, actor, actionType, entityType, entityId, payload);
        results.push({
            code: inv.code,
            name: inv.name,
            passed: result.passed,
            severity: inv.severity,
            detail: result.detail
        });

        // BLOCK severity = stop immediately
        if (!result.passed && inv.severity === 'block') {
            return {
                allowed: false,
                blocked_by: inv.code,
                detail: result.detail,
                all_results: results
            };
        }
    }

    return {
        allowed: true,
        warnings: results.filter(r => !r.passed && r.severity === 'warn'),
        all_results: results
    };
}
```

## CLO (Canon) Integration with Governance

Canon's role is unique in the hierarchy. While other C-Suite execs manage work, Canon manages the rules themselves:

### Canon's Responsibilities

1. **Invariant Lifecycle**: Canon reviews and approves changes to `constitutional_invariants`. Max can request changes, but Canon validates them against the constitutional framework before they take effect.

2. **Governance Audits**: Canon periodically audits the `governance_receipts` chain integrity and reports findings.

3. **Compliance Reporting**: Canon generates compliance reports showing which invariants were checked, which were violated, and trends over time.

4. **Dispute Resolution**: When a member believes a governance block is incorrect (false positive), Canon reviews the case and can issue a one-time override receipt.

5. **ExoChain Alignment**: Canon ensures our governance implementation stays aligned with ExoChain's constitutional framework as it evolves.

### Canon's Database Footprint

```sql
-- Governance overrides: when Canon allows a blocked action
CREATE TABLE IF NOT EXISTS governance_overrides (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_id INTEGER NOT NULL REFERENCES governance_receipts(id),
    invariant_code TEXT NOT NULL,
    override_reason TEXT NOT NULL,
    approved_by INTEGER NOT NULL REFERENCES team_members(id),  -- must be Canon or Max
    approved_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    expires_at TEXT,  -- one-time overrides expire immediately; policy overrides can have duration
    scope TEXT NOT NULL DEFAULT 'one_time' CHECK(scope IN ('one_time', 'policy', 'permanent'))
);

-- Compliance reports: periodic audit summaries
CREATE TABLE IF NOT EXISTS compliance_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_period_start TEXT NOT NULL,
    report_period_end TEXT NOT NULL,
    total_receipts INTEGER NOT NULL DEFAULT 0,
    total_violations INTEGER NOT NULL DEFAULT 0,
    chain_integrity TEXT NOT NULL DEFAULT 'intact' CHECK(chain_integrity IN ('intact', 'broken', 'repaired')),
    invariant_coverage_pct REAL NOT NULL DEFAULT 100.0,
    findings TEXT DEFAULT '[]',  -- JSON array of audit findings
    recommendations TEXT DEFAULT '[]',  -- JSON array of recommended changes
    generated_by INTEGER NOT NULL REFERENCES team_members(id),  -- Canon
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);
```

---

# Full SQL Migration Script

Run this in order. Each section is idempotent (uses IF NOT EXISTS / OR IGNORE where possible).

```sql
-- ============================================================
-- MIGRATION: Org Restructure v1
-- Date: 2026-03-29
-- Author: Atlas (Systems Architect)
-- ============================================================

-- ============================================================
-- SECTION 1: Member Context/Memory System
-- ============================================================

CREATE TABLE IF NOT EXISTS member_context (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER NOT NULL REFERENCES team_members(id),
    context_type TEXT NOT NULL CHECK(context_type IN (
        'project_knowledge',
        'task_history',
        'preferences',
        'learned_patterns',
        'domain_expertise',
        'active_context',
        'relationship',
        'error_pattern'
    )),
    context_key TEXT NOT NULL,
    context_value TEXT NOT NULL,
    importance TEXT NOT NULL DEFAULT 'normal' CHECK(importance IN (
        'critical', 'high', 'normal', 'low'
    )),
    source_task_id INTEGER REFERENCES tasks(id),
    source_description TEXT,
    expires_at TEXT,
    project_id INTEGER REFERENCES projects(id),
    tags TEXT DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    UNIQUE(member_id, context_type, context_key)
);

CREATE INDEX IF NOT EXISTS idx_member_context_member
    ON member_context(member_id, importance);
CREATE INDEX IF NOT EXISTS idx_member_context_type
    ON member_context(member_id, context_type);
CREATE INDEX IF NOT EXISTS idx_member_context_project
    ON member_context(project_id);
CREATE INDEX IF NOT EXISTS idx_member_context_expiry
    ON member_context(expires_at)
    WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS context_load_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER NOT NULL REFERENCES team_members(id),
    task_id INTEGER REFERENCES tasks(id),
    context_ids_loaded TEXT NOT NULL DEFAULT '[]',
    total_items_loaded INTEGER NOT NULL DEFAULT 0,
    load_strategy TEXT NOT NULL DEFAULT 'budget',
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- Context budget settings
INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('context_budget_orchestrator', '50', datetime('now', 'localtime'));
INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('context_budget_csuite', '40', datetime('now', 'localtime'));
INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('context_budget_leader', '25', datetime('now', 'localtime'));
INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('context_budget_coleader', '20', datetime('now', 'localtime'));
INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('context_budget_subagent', '10', datetime('now', 'localtime'));

-- ============================================================
-- SECTION 2: C-Suite Tier & Hierarchy Changes
-- ============================================================

-- 2a. Rebuild team_members with updated tier CHECK constraint
-- WARNING: This is destructive. Back up the database first.
-- Run: cp the_team.db the_team.db.bak.$(date +%s)

CREATE TABLE IF NOT EXISTS team_members_v2 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL,
    profile_path TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'inactive')),
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    execution_mode TEXT NOT NULL DEFAULT 'system'
        CHECK(execution_mode IN ('system', 'terminal', 'autonomous')),
    tier TEXT NOT NULL DEFAULT 'leader'
        CHECK(tier IN ('orchestrator', 'csuite', 'leader', 'co-leader', 'subagent')),
    reports_to INTEGER REFERENCES team_members_v2(id),
    did_identity TEXT,
    dedicated_role INTEGER NOT NULL DEFAULT 0,
    llm_provider_id INTEGER REFERENCES llm_providers(id),
    llm_model TEXT
);

-- Copy existing data (only if team_members_v2 is empty -- idempotency guard)
INSERT OR IGNORE INTO team_members_v2 (id, name, role, profile_path, status, created_at, execution_mode, tier, reports_to, did_identity, dedicated_role, llm_provider_id, llm_model)
SELECT id, name, role, profile_path, status, created_at, execution_mode, tier, reports_to, did_identity, dedicated_role, llm_provider_id, llm_model
FROM team_members;

-- NOTE: The actual table swap (DROP team_members + RENAME team_members_v2)
-- must be done manually with foreign key checks disabled:
--
--   PRAGMA foreign_keys = OFF;
--   DROP TABLE IF EXISTS team_members;
--   ALTER TABLE team_members_v2 RENAME TO team_members;
--   PRAGMA foreign_keys = ON;
--
-- This is deliberately NOT automated to prevent accidental data loss.
-- Anvil should execute this with a database backup in place.

-- 2b. Add directive tracking columns to tasks
-- (These are safe ALTERs -- nullable columns with defaults)
ALTER TABLE tasks ADD COLUMN parent_task_id INTEGER REFERENCES tasks(id);
ALTER TABLE tasks ADD COLUMN directive_level TEXT DEFAULT 'execution'
    CHECK(directive_level IN ('strategic', 'tactical', 'execution'));

-- 2c. Executive summaries table
CREATE TABLE IF NOT EXISTS executive_summaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL REFERENCES tasks(id),
    author_id INTEGER NOT NULL REFERENCES team_members(id),
    summary TEXT NOT NULL,
    tactical_tasks_completed INTEGER NOT NULL DEFAULT 0,
    tactical_tasks_total INTEGER NOT NULL DEFAULT 0,
    blockers TEXT DEFAULT '[]',
    escalations TEXT DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- 2d. Insert C-Suite members
-- (Uses OR IGNORE to be idempotent -- won't duplicate if run again)
INSERT OR IGNORE INTO team_members (name, role, profile_path, status, tier, reports_to, execution_mode)
VALUES ('Axiom', 'Chief Technology Officer', 'Team/axiom.md', 'active', 'csuite',
        (SELECT id FROM team_members WHERE name = 'Gray'), 'system');

INSERT OR IGNORE INTO team_members (name, role, profile_path, status, tier, reports_to, execution_mode)
VALUES ('Vertex', 'Chief Strategy Officer', 'Team/vertex.md', 'active', 'csuite',
        (SELECT id FROM team_members WHERE name = 'Gray'), 'system');

INSERT OR IGNORE INTO team_members (name, role, profile_path, status, tier, reports_to, execution_mode)
VALUES ('Meridian', 'Chief Operating Officer', 'Team/meridian.md', 'active', 'csuite',
        (SELECT id FROM team_members WHERE name = 'Gray'), 'system');

INSERT OR IGNORE INTO team_members (name, role, profile_path, status, tier, reports_to, execution_mode)
VALUES ('Canon', 'Chief Legal Officer', 'Team/canon.md', 'active', 'csuite',
        (SELECT id FROM team_members WHERE name = 'Gray'), 'system');

-- 2e. Re-wire leader reporting lines to C-Suite
-- Technology leaders -> CTO (Axiom)
UPDATE team_members SET reports_to = (SELECT id FROM team_members WHERE name = 'Axiom')
WHERE name IN ('Anvil', 'Spark', 'Bastion', 'Lumen', 'Rivet', 'Hone')
  AND EXISTS (SELECT 1 FROM team_members WHERE name = 'Axiom');

-- Strategy leaders -> CSO (Vertex)
UPDATE team_members SET reports_to = (SELECT id FROM team_members WHERE name = 'Vertex')
WHERE name IN ('Atlas', 'Pax', 'Marshal')
  AND EXISTS (SELECT 1 FROM team_members WHERE name = 'Vertex');

-- Operations leaders -> COO (Meridian)
UPDATE team_members SET reports_to = (SELECT id FROM team_members WHERE name = 'Meridian')
WHERE name IN ('Zenith', 'Cadence')
  AND EXISTS (SELECT 1 FROM team_members WHERE name = 'Meridian');

-- ============================================================
-- SECTION 3: ExoChain Governance Expansion
-- ============================================================

-- 3a. New constitutional invariants for the expanded hierarchy
INSERT OR IGNORE INTO constitutional_invariants (code, name, description, severity)
VALUES ('INV-010', 'Tier Boundary Respect',
        'Members cannot assign tasks to members more than one tier below them. C-Suite assigns to Leaders, Leaders assign to Co-Leaders/Subagents. No tier-skipping.',
        'warn');

INSERT OR IGNORE INTO constitutional_invariants (code, name, description, severity)
VALUES ('INV-011', 'Context Write Authenticity',
        'A member can only write to their own member_context. No member can modify another member''s context.',
        'block');

INSERT OR IGNORE INTO constitutional_invariants (code, name, description, severity)
VALUES ('INV-012', 'Executive Summary Required',
        'Strategic-level tasks cannot be marked complete without an executive_summary from the assigned C-Suite exec.',
        'block');

INSERT OR IGNORE INTO constitutional_invariants (code, name, description, severity)
VALUES ('INV-013', 'Directive Chain Integrity',
        'Every tactical task must have a parent_task_id linking to a strategic directive. Orphan tactical tasks are forbidden.',
        'warn');

INSERT OR IGNORE INTO constitutional_invariants (code, name, description, severity)
VALUES ('INV-014', 'Context Budget Enforcement',
        'Context loading must respect the tier-based budget. Exceeding budget triggers a warning receipt.',
        'warn');

INSERT OR IGNORE INTO constitutional_invariants (code, name, description, severity)
VALUES ('INV-015', 'CLO Governance Review',
        'Changes to constitutional_invariants or governance_receipts schema require CLO (Canon) review receipt.',
        'block');

-- 3b. Governance overrides table (for Canon/CLO)
CREATE TABLE IF NOT EXISTS governance_overrides (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_id INTEGER NOT NULL REFERENCES governance_receipts(id),
    invariant_code TEXT NOT NULL,
    override_reason TEXT NOT NULL,
    approved_by INTEGER NOT NULL REFERENCES team_members(id),
    approved_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    expires_at TEXT,
    scope TEXT NOT NULL DEFAULT 'one_time' CHECK(scope IN ('one_time', 'policy', 'permanent'))
);

-- 3c. Compliance reports table (for Canon/CLO)
CREATE TABLE IF NOT EXISTS compliance_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_period_start TEXT NOT NULL,
    report_period_end TEXT NOT NULL,
    total_receipts INTEGER NOT NULL DEFAULT 0,
    total_violations INTEGER NOT NULL DEFAULT 0,
    chain_integrity TEXT NOT NULL DEFAULT 'intact' CHECK(chain_integrity IN ('intact', 'broken', 'repaired')),
    invariant_coverage_pct REAL NOT NULL DEFAULT 100.0,
    findings TEXT DEFAULT '[]',
    recommendations TEXT DEFAULT '[]',
    generated_by INTEGER NOT NULL REFERENCES team_members(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- ============================================================
-- SECTION 4: Indexes for Performance
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_tasks_parent ON tasks(parent_task_id)
    WHERE parent_task_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tasks_directive_level ON tasks(directive_level);
CREATE INDEX IF NOT EXISTS idx_executive_summaries_task ON executive_summaries(task_id);
CREATE INDEX IF NOT EXISTS idx_governance_overrides_receipt ON governance_overrides(receipt_id);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_period ON compliance_reports(report_period_start, report_period_end);
```

---

# Implementation Phases

## Phase 1: Database Schema (Zero Risk)

| Step | What | Risk |
|------|------|------|
| 1.1 | Back up `the_team.db` | None |
| 1.2 | Create `member_context` table | None -- new table |
| 1.3 | Create `context_load_log` table | None -- new table |
| 1.4 | Add `parent_task_id` and `directive_level` to `tasks` | None -- nullable columns |
| 1.5 | Create `executive_summaries` table | None -- new table |
| 1.6 | Create `governance_overrides` table | None -- new table |
| 1.7 | Create `compliance_reports` table | None -- new table |
| 1.8 | Insert context budget settings | None -- `OR IGNORE` |
| 1.9 | Insert new invariants (INV-010 through INV-015) | None -- `OR IGNORE` |

**Validation:** All tables exist, all indexes created, existing data untouched.

## Phase 2: C-Suite Team Members (Low Risk)

| Step | What | Risk |
|------|------|------|
| 2.1 | Rebuild `team_members` with `csuite` tier CHECK | Medium -- table rebuild, needs backup |
| 2.2 | Insert Axiom, Vertex, Meridian, Canon | None -- `OR IGNORE` |
| 2.3 | Re-wire leader `reports_to` to C-Suite | Low -- updates existing rows |
| 2.4 | Create C-Suite profiles (`Team/axiom.md`, etc.) | None -- new files |
| 2.5 | Update CLAUDE.md routing rules | Low -- documentation change |

**Validation:** `SELECT name, tier, reports_to FROM team_members` shows correct hierarchy. All leaders report to their C-Suite exec, C-Suite reports to Gray.

## Phase 3: Context System Integration (Medium Risk)

| Step | What | Risk |
|------|------|------|
| 3.1 | Build context loading functions in `governance.js` | None -- new code |
| 3.2 | Build context write-back functions | None -- new code |
| 3.3 | Integrate context loading into task dispatch flow | Low -- additive to existing flow |
| 3.4 | Integrate context write-back into task completion flow | Low -- additive |
| 3.5 | Seed initial context for existing members | None -- INSERT only |
| 3.6 | Add API endpoints for context CRUD | None -- new endpoints |

**Validation:** Start a task, verify context loaded from `member_context`. Complete a task, verify new context written back.

## Phase 4: Governance Enforcement (Medium Risk)

| Step | What | Risk |
|------|------|------|
| 4.1 | Add invariant check functions for INV-010 through INV-015 | None -- new code |
| 4.2 | Wire governance middleware to context write operations | Low |
| 4.3 | Wire governance middleware to C-Suite directive operations | Low |
| 4.4 | Build Canon's audit and override flows | None -- new code |
| 4.5 | Test invariant enforcement at each tier | None -- testing |

**Validation:** Attempt a tier-boundary violation (C-Suite assigning directly to subagent) -- should get `warn` receipt. Attempt to modify another member's context -- should get `block`. Complete a strategic task without executive summary -- should get `block`.

## Phase 5: UI Changes (Low Risk)

| Step | What | Risk |
|------|------|------|
| 5.1 | Update org chart to show C-Suite tier | Low -- UI only |
| 5.2 | Add member context viewer to team member detail page | None -- new UI |
| 5.3 | Add directive tree view (strategic -> tactical -> execution) | None -- new UI |
| 5.4 | Add governance dashboard with invariant status | None -- new UI |
| 5.5 | Add compliance report viewer | None -- new UI |

---

# Files to Create/Modify

| File | Action | What Changes |
|------|--------|-------------|
| `the_team.db` | MIGRATE | 5 new tables, 2 new columns on tasks, 6 new invariants, 4 new members |
| `CLAUDE.md` | MODIFY | Add C-Suite routing rules, context loading docs, governance tier rules |
| `Team/axiom.md` | CREATE | CTO profile (Zenith creates) |
| `Team/vertex.md` | CREATE | CSO profile (Zenith creates) |
| `Team/meridian.md` | CREATE | COO profile (Zenith creates) |
| `Team/canon.md` | CREATE | CLO profile (Zenith creates) |
| `app/governance.js` | MODIFY | Add invariant checkers for INV-010 through INV-015, context governance |
| `app/server.js` | MODIFY | New API endpoints for context CRUD, executive summaries, compliance |
| `app/public/app.js` | MODIFY | Org chart C-Suite tier, context viewer, directive tree |
| `app/public/styles.css` | MODIFY | C-Suite node styles, context panel styles |

---

# What This Does NOT Change

- Task statuses remain: new -> routing -> in_progress -> review -> completed -> delivered
- Inbox/Outbox folders unchanged
- Docker setup unchanged
- Worker service unchanged (enhanced, not replaced)
- Existing co-leader and subagent mechanics unchanged
- Existing 9 invariants unchanged (6 new ones added)
- Existing governance_receipts table unchanged (used as-is)
- How Max creates tasks unchanged

---

# Open Questions for Max

1. **C-Suite Names:** I picked Axiom (CTO), Vertex (CSO), Meridian (COO), Canon (CLO). All follow the single-word convention. Want to rename any?

2. **C-Suite Skip Rule:** Should Gray always go through C-Suite for multi-domain tasks, or should Gray be able to go direct to leaders when time is critical? (Recommendation: Gray can skip C-Suite for urgent single-domain tasks, must use C-Suite for multi-domain or strategic work.)

3. **Context Write Governance:** Should every `member_context` write generate a governance receipt, or only writes with `importance = 'critical'` or `'high'`? (Recommendation: Only critical/high, to avoid receipt bloat from routine context updates.)

4. **Additional C-Suite Roles:** Do you want a CFO (Chief Financial Officer) for budget/cost tracking? The existing `cost_events` and `budget_policies` tables could fall under a CFO. Or should that stay under COO (Meridian)?

5. **Canon's Authority:** Can Canon issue governance overrides independently, or does every override need Max's approval? (Recommendation: Canon can override `warn`-severity independently, `block`-severity overrides need Max's approval.)

6. **Context Expiration Default:** Should `active_context` type auto-expire after 7 days? 14 days? Never? (Recommendation: 7 days, since active context is about in-progress work that should be refreshed.)

---

# Decision: Ready for Approval

- Phase 1 is pure schema additions -- zero risk to existing data
- Phase 2 requires a table rebuild (team_members) -- needs database backup before execution
- Phases 3-5 are additive code and UI changes
- Each phase is independently deployable
- Rollback at any phase is straightforward (drop new tables, revert columns)
