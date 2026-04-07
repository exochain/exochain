# Paperclip-1 Full Integration Plan

**Author:** Atlas (Systems Architect)
**Date:** 2026-03-29
**Source:** `/Users/maxstewart/Desktop/The Team/repos/paperclip-1/`
**Target:** The Team Dashboard (Express + SQLite + vanilla JS)
**Prerequisite Reading:** `.claude/research/paperclip-1-deep-audit.md`

---

## Executive Summary

This plan integrates ALL 16 Paperclip systems into The Team dashboard across 7 build phases. Each phase is independently deployable. The core adaptation: Paperclip uses PostgreSQL + Drizzle + React + TypeScript; we translate everything to SQLite + better-sqlite3 + vanilla JS + custom CSS.

**Key constraint:** We ADD to existing dashboard pages. We do not replace anything.

---

## Translation Rules (Apply Everywhere)

| Paperclip | The Team |
|-----------|----------|
| `uuid("id").primaryKey().defaultRandom()` | `TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16))))` |
| `timestamp("x", { withTimezone: true })` | `TEXT DEFAULT (datetime('now','localtime'))` |
| `jsonb("x")` | `TEXT DEFAULT '{}'` (JSON string, parsed in JS) |
| `bigint("x", { mode: "number" })` | `INTEGER DEFAULT 0` |
| `bigserial("id")` | `INTEGER PRIMARY KEY AUTOINCREMENT` |
| `integer("x")` | `INTEGER DEFAULT 0` |
| `text("x")` | `TEXT` |
| `boolean("x")` | `INTEGER DEFAULT 0` (0/1) |
| `index(...)` | `CREATE INDEX IF NOT EXISTS ...` |
| `uniqueIndex(...)` | `CREATE UNIQUE INDEX IF NOT EXISTS ...` |
| Drizzle `eq()`, `and()`, `or()` | Raw SQL with `?` params |
| React component | Vanilla JS function returning HTML string |
| TanStack Query | `fetch()` + manual cache/refresh |
| WebSocket (ws) | Native `WebSocket` in browser + `ws` on server (already possible) |
| `companies.id` scope | Hardcoded single company (The Team) -- drop company_id FK, keep for future |

---

## Phase 1: Heartbeat Engine + Atomic Checkout + Activity Stream

**Impact:** HIGH -- This is the core autonomous agent execution loop.
**Dependencies:** None (foundation layer)
**Estimated effort:** Large

### 1A. Heartbeat System

**What it does in Paperclip:**
The heartbeat is the fundamental agent execution cycle. Agents wake on schedule or event triggers, execute a 9-step procedure (identity, approvals, get assignments, pick work, checkout, context, work, update, delegate), then sleep. The server orchestrates this via `heartbeat.ts` (135K lines) which manages:
- Scheduled intervals (cron-like)
- Event-triggered wakes (task assignment, @-mention, approval resolution)
- Session persistence across heartbeats (adapter session codecs)
- Concurrent run limits per agent
- Process lifecycle (spawn, monitor, capture output, record result)
- Budget gate checks before each run

**How to adapt for The Team:**
Our agents are Claude Code CLI sessions spawned by the auto-spawn terminal system. We adapt the heartbeat to be the scheduler that decides WHEN to spawn those terminals and WHAT context to inject.

The heartbeat service becomes a Node.js module in `server.js` that:
1. Runs a tick every 60 seconds checking which agents need to wake
2. Checks `agent_wakeup_requests` for event-triggered wakes
3. Checks `heartbeat_schedules` for cron-based schedules
4. Enforces budget gates before spawning
5. Records each run in `heartbeat_runs`
6. Captures the result when the process exits

**Database schema:**

```sql
-- Heartbeat runs: every time an agent wakes up and executes
CREATE TABLE IF NOT EXISTS heartbeat_runs (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    agent_id INTEGER NOT NULL REFERENCES team_members(id),
    invocation_source TEXT NOT NULL DEFAULT 'on_demand',
        -- 'scheduled', 'event_wake', 'on_demand', 'routine'
    trigger_detail TEXT,
    status TEXT NOT NULL DEFAULT 'queued',
        -- 'queued', 'running', 'succeeded', 'failed', 'cancelled', 'timed_out'
    started_at TEXT,
    finished_at TEXT,
    error TEXT,
    exit_code INTEGER,
    signal TEXT,
    usage_json TEXT DEFAULT '{}',
    result_json TEXT DEFAULT '{}',
    session_id_before TEXT,
    session_id_after TEXT,
    stdout_excerpt TEXT,
    stderr_excerpt TEXT,
    error_code TEXT,
    process_pid INTEGER,
    process_started_at TEXT,
    retry_of_run_id TEXT REFERENCES heartbeat_runs(id),
    process_loss_retry_count INTEGER NOT NULL DEFAULT 0,
    context_snapshot TEXT DEFAULT '{}',
    wakeup_request_id TEXT,
    task_id INTEGER REFERENCES tasks(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_heartbeat_runs_agent_started
    ON heartbeat_runs(agent_id, started_at);
CREATE INDEX IF NOT EXISTS idx_heartbeat_runs_status
    ON heartbeat_runs(status);

-- Heartbeat run events: granular log of what happened during a run
CREATE TABLE IF NOT EXISTS heartbeat_run_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES heartbeat_runs(id),
    agent_id INTEGER NOT NULL REFERENCES team_members(id),
    seq INTEGER NOT NULL,
    event_type TEXT NOT NULL,
        -- 'stdout', 'stderr', 'tool_call', 'status_change', 'error', 'metric'
    stream TEXT,
    level TEXT,
    message TEXT,
    payload TEXT DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_heartbeat_run_events_run_seq
    ON heartbeat_run_events(run_id, seq);

-- Agent wakeup requests: event-driven triggers
CREATE TABLE IF NOT EXISTS agent_wakeup_requests (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    agent_id INTEGER NOT NULL REFERENCES team_members(id),
    source TEXT NOT NULL,
        -- 'task_assignment', 'mention', 'approval_resolved', 'manual', 'routine'
    trigger_detail TEXT,
    reason TEXT,
    payload TEXT DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'queued',
        -- 'queued', 'claimed', 'completed', 'cancelled', 'coalesced'
    coalesced_count INTEGER NOT NULL DEFAULT 0,
    requested_by_type TEXT,   -- 'user', 'agent', 'system'
    requested_by_id TEXT,
    idempotency_key TEXT,
    run_id TEXT REFERENCES heartbeat_runs(id),
    requested_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    claimed_at TEXT,
    finished_at TEXT,
    error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_wakeup_agent_status
    ON agent_wakeup_requests(agent_id, status);

-- Agent runtime state: persistent state between heartbeats
CREATE TABLE IF NOT EXISTS agent_runtime_state (
    agent_id INTEGER PRIMARY KEY REFERENCES team_members(id),
    adapter_type TEXT NOT NULL DEFAULT 'claude_local',
    session_id TEXT,
    state_json TEXT NOT NULL DEFAULT '{}',
    last_run_id TEXT REFERENCES heartbeat_runs(id),
    last_run_status TEXT,
    total_input_tokens INTEGER NOT NULL DEFAULT 0,
    total_output_tokens INTEGER NOT NULL DEFAULT 0,
    total_cached_input_tokens INTEGER NOT NULL DEFAULT 0,
    total_cost_cents INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

-- Agent task sessions: session persistence per task
CREATE TABLE IF NOT EXISTS agent_task_sessions (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    agent_id INTEGER NOT NULL REFERENCES team_members(id),
    adapter_type TEXT NOT NULL DEFAULT 'claude_local',
    task_key TEXT NOT NULL,
    session_params_json TEXT DEFAULT '{}',
    session_display_id TEXT,
    last_run_id TEXT REFERENCES heartbeat_runs(id),
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(agent_id, adapter_type, task_key)
);
```

**API endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/heartbeat/run` | Trigger a heartbeat for a specific agent |
| `GET` | `/api/heartbeat/runs` | List runs with filters (agent_id, status, date range) |
| `GET` | `/api/heartbeat/runs/:id` | Get run detail with events |
| `GET` | `/api/heartbeat/runs/:id/events` | Stream run events |
| `POST` | `/api/heartbeat/runs/:id/cancel` | Cancel a running heartbeat |
| `GET` | `/api/agents/:id/runtime-state` | Get agent runtime state |
| `POST` | `/api/agents/:id/wake` | Queue a wakeup request |
| `GET` | `/api/agents/:id/wakeup-requests` | List wakeup requests |

**Frontend components:**

- **HeartbeatRunViewer** -- Live run viewer showing stdout/stderr stream, status badge, duration timer
- **AgentRunHistory** -- Paginated list of past runs per agent with status icons, duration, cost
- **HeartbeatScheduleConfig** -- Per-agent heartbeat interval configuration (dropdown: off, 5m, 15m, 30m, 1h, 4h, daily)
- **LiveRunWidget** -- Small widget on agent card showing current run status with spinner
- **RunTriggerButton** -- Manual "Run Now" button on agent detail page

### 1B. Atomic Checkout

**What it does in Paperclip:**
Before an agent works on a task, it must `POST /api/issues/{id}/checkout`. If another agent already has it checked out, it returns `409 Conflict`. This prevents double-work. The checkout is tied to the heartbeat run ID so it auto-releases when the run ends.

**How to adapt:**
Add checkout columns to existing `tasks` table and a checkout API. Our tasks table already exists; we augment it.

**Database schema:**

```sql
-- Add checkout columns to existing tasks table
ALTER TABLE tasks ADD COLUMN checkout_run_id TEXT REFERENCES heartbeat_runs(id);
ALTER TABLE tasks ADD COLUMN checkout_agent_id INTEGER REFERENCES team_members(id);
ALTER TABLE tasks ADD COLUMN checkout_locked_at TEXT;
ALTER TABLE tasks ADD COLUMN parent_task_id INTEGER REFERENCES tasks(id);
ALTER TABLE tasks ADD COLUMN goal_id TEXT REFERENCES goals(id);
```

**API endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/tasks/:id/checkout` | Checkout task for agent (409 if taken) |
| `POST` | `/api/tasks/:id/release` | Release task checkout |
| `GET` | `/api/tasks/:id/checkout-status` | Check who has it checked out |

**Frontend components:**

- **CheckoutBadge** -- Shows lock icon + agent name on task cards when checked out
- **CheckoutConflictModal** -- Alert when attempting to assign a checked-out task

### 1C. Enhanced Activity Stream

**What it does in Paperclip:**
Every mutation in the system is logged to `activity_log` with actor type, actor ID, action, entity type, entity ID, optional run ID, and details JSON. This creates a complete audit trail.

**How to adapt:**
We already have `activity_log` and `agent_activity_stream`. Enhance activity_log to match Paperclip's model.

**Database schema:**

```sql
-- Enhanced activity log (augment existing)
ALTER TABLE activity_log ADD COLUMN actor_type TEXT DEFAULT 'user';
    -- 'user', 'agent', 'system'
ALTER TABLE activity_log ADD COLUMN entity_type TEXT;
    -- 'task', 'agent', 'goal', 'approval', 'budget', 'heartbeat_run'
ALTER TABLE activity_log ADD COLUMN entity_id TEXT;
ALTER TABLE activity_log ADD COLUMN run_id TEXT REFERENCES heartbeat_runs(id);
ALTER TABLE activity_log ADD COLUMN details_json TEXT DEFAULT '{}';
```

**API endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/activity` | Filterable activity stream (entity_type, actor, date range) |
| `GET` | `/api/activity/agent/:id` | Activity for a specific agent |
| `GET` | `/api/activity/task/:id` | Activity for a specific task |

**Frontend components:**

- **ActivityFeed** -- Real-time scrolling feed with filter chips (by entity type, actor, date)
- **ActivityTimeline** -- Vertical timeline view on task/agent detail pages

---

## Phase 2: Goal Hierarchy + Task Comments + Issue Lifecycle

**Impact:** HIGH -- Gives every task a "why" and enables agent-to-agent communication.
**Dependencies:** Phase 1 (heartbeat_runs FK)
**Estimated effort:** Medium

### 2A. Goal Hierarchy

**What it does in Paperclip:**
Four-level hierarchy: Company goals -> Team goals -> Agent goals -> Tasks. Every task traces to a goal via `goalId`. Goals have levels: `company`, `team`, `agent`, `task`. Goals can be nested via `parentId`.

**How to adapt:**
We already have `end_goals`, `visions`, `projects`, and `project_goals`. We need to consolidate into a single `goals` table that matches Paperclip's model while preserving existing data.

**Database schema:**

```sql
CREATE TABLE IF NOT EXISTS goals (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    title TEXT NOT NULL,
    description TEXT,
    level TEXT NOT NULL DEFAULT 'task',
        -- 'company', 'team', 'agent', 'task'
    status TEXT NOT NULL DEFAULT 'planned',
        -- 'planned', 'active', 'completed', 'cancelled'
    parent_id TEXT REFERENCES goals(id),
    owner_agent_id INTEGER REFERENCES team_members(id),
    project_id INTEGER REFERENCES projects(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_goals_level ON goals(level);
CREATE INDEX IF NOT EXISTS idx_goals_parent ON goals(parent_id);
CREATE INDEX IF NOT EXISTS idx_goals_status ON goals(status);

-- Link existing projects to goals
ALTER TABLE projects ADD COLUMN goal_id TEXT REFERENCES goals(id);
```

**API endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/goals` | List goals with filters (level, status, owner) |
| `POST` | `/api/goals` | Create goal |
| `GET` | `/api/goals/:id` | Get goal with children and linked tasks |
| `PATCH` | `/api/goals/:id` | Update goal |
| `DELETE` | `/api/goals/:id` | Archive goal |
| `GET` | `/api/goals/:id/tree` | Get full goal tree (ancestors + descendants) |
| `GET` | `/api/goals/:id/tasks` | Get all tasks linked to this goal |

**Frontend components:**

- **GoalTree** -- Collapsible tree view showing company -> team -> agent -> task hierarchy
- **GoalCard** -- Card with title, progress bar (% of child tasks done), owner badge
- **GoalPicker** -- Dropdown/modal for selecting a goal when creating tasks
- **GoalBreadcrumb** -- Shows task's goal lineage on task detail page

### 2B. Task Comments (Agent Communication)

**What it does in Paperclip:**
All agent communication happens through issue comments. Comments are threaded on issues, support @-mentions that trigger agent wakeups, and include author (agent or user) attribution. No separate chat system.

**How to adapt:**
Add a task comments system. This replaces ad-hoc communication with structured, traceable conversations.

**Database schema:**

```sql
CREATE TABLE IF NOT EXISTS task_comments (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    author_agent_id INTEGER REFERENCES team_members(id),
    author_user_id TEXT,      -- 'max' or null
    body TEXT NOT NULL,
    run_id TEXT REFERENCES heartbeat_runs(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_task_comments_task
    ON task_comments(task_id, created_at);
CREATE INDEX IF NOT EXISTS idx_task_comments_author_agent
    ON task_comments(author_agent_id);
```

**API endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/tasks/:id/comments` | List comments (supports `?after=commentId` for deltas) |
| `POST` | `/api/tasks/:id/comments` | Add comment (triggers @-mention wakeups) |
| `GET` | `/api/tasks/:id/comments/:commentId` | Get specific comment |
| `PATCH` | `/api/tasks/:id/comments/:commentId` | Edit comment |
| `DELETE` | `/api/tasks/:id/comments/:commentId` | Delete comment |

**Frontend components:**

- **CommentThread** -- Scrollable comment list with agent avatars, timestamps, markdown rendering
- **CommentComposer** -- Text area with @-mention autocomplete for agent names
- **CommentBadge** -- Unread comment count badge on task cards

### 2C. Enhanced Issue Lifecycle

**What it does in Paperclip:**
Issues have a rich lifecycle: `backlog -> todo -> in_progress -> in_review -> blocked -> done -> cancelled`. Status transitions have side effects (set `startedAt` on `in_progress`, `completedAt` on `done`). Issues have `originKind` tracking where they came from, `requestDepth` for delegation depth, and `billingCode` for cross-team cost attribution.

**How to adapt:**
Augment existing `tasks` table with Paperclip's richer fields.

**Database schema:**

```sql
-- Enhance existing tasks table
ALTER TABLE tasks ADD COLUMN origin_kind TEXT NOT NULL DEFAULT 'manual';
    -- 'manual', 'delegated', 'routine', 'auto_action'
ALTER TABLE tasks ADD COLUMN origin_id TEXT;
ALTER TABLE tasks ADD COLUMN request_depth INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tasks ADD COLUMN billing_code TEXT;
ALTER TABLE tasks ADD COLUMN started_at TEXT;
ALTER TABLE tasks ADD COLUMN completed_at TEXT;
ALTER TABLE tasks ADD COLUMN cancelled_at TEXT;
ALTER TABLE tasks ADD COLUMN created_by_agent_id INTEGER REFERENCES team_members(id);
ALTER TABLE tasks ADD COLUMN created_by_user_id TEXT;
ALTER TABLE tasks ADD COLUMN identifier TEXT UNIQUE;
ALTER TABLE tasks ADD COLUMN issue_number INTEGER;
```

**Frontend components:**

- **StatusPipeline** -- Visual kanban-style status pipeline showing task flow
- **TaskOriginBadge** -- Shows where a task came from (manual, delegated, routine)

---

## Phase 3: Adapter Architecture + Skill System

**Impact:** HIGH -- Enables multiple agent runtimes and modular capability injection.
**Dependencies:** Phase 1 (heartbeat_runs)
**Estimated effort:** Large

### 3A. Adapter Architecture

**What it does in Paperclip:**
Adapters are the bridge between the control plane and agent runtimes. Each adapter implements:
- `execute(ctx: AdapterExecutionContext) -> AdapterExecutionResult` -- spawn the agent
- `testEnvironment(ctx) -> AdapterEnvironmentTestResult` -- verify the runtime is available
- `sessionCodec` -- encode/decode session state between heartbeats
- `listSkills` / `syncSkills` -- manage skill injection

10 adapters: `claude_local`, `codex_local`, `cursor`, `gemini_local`, `opencode_local`, `pi_local`, `hermes_local`, `openclaw_gateway`, `process`, `http`.

**How to adapt:**
Create an adapter registry in vanilla JS. Each adapter is a JS module exporting `execute()`, `testEnvironment()`, and optional `sessionCodec`. Start with `claude_local` (we already spawn Claude Code CLI), `process` (arbitrary commands), and `http` (webhooks).

**Database schema:**

```sql
-- Adapter registry (static, seeded on startup)
CREATE TABLE IF NOT EXISTS adapter_types (
    type TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    description TEXT,
    supports_sessions INTEGER NOT NULL DEFAULT 0,
    supports_skills INTEGER NOT NULL DEFAULT 0,
    supports_local_jwt INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'available',
        -- 'available', 'experimental', 'disabled'
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

-- Enhance team_members with adapter fields
ALTER TABLE team_members ADD COLUMN adapter_type TEXT NOT NULL DEFAULT 'claude_local';
ALTER TABLE team_members ADD COLUMN adapter_config TEXT NOT NULL DEFAULT '{}';
ALTER TABLE team_members ADD COLUMN runtime_config TEXT NOT NULL DEFAULT '{}';
    -- runtime_config: { heartbeatIntervalSec, maxConcurrentRuns, wakeOnDemand, ... }
ALTER TABLE team_members ADD COLUMN capabilities TEXT;
ALTER TABLE team_members ADD COLUMN last_heartbeat_at TEXT;
ALTER TABLE team_members ADD COLUMN budget_monthly_cents INTEGER NOT NULL DEFAULT 0;
ALTER TABLE team_members ADD COLUMN spent_monthly_cents INTEGER NOT NULL DEFAULT 0;
ALTER TABLE team_members ADD COLUMN pause_reason TEXT;
ALTER TABLE team_members ADD COLUMN paused_at TEXT;
ALTER TABLE team_members ADD COLUMN permissions TEXT NOT NULL DEFAULT '{}';
ALTER TABLE team_members ADD COLUMN metadata TEXT DEFAULT '{}';
ALTER TABLE team_members ADD COLUMN reports_to INTEGER REFERENCES team_members(id);
ALTER TABLE team_members ADD COLUMN icon TEXT;
```

**API endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/adapters` | List available adapter types |
| `GET` | `/api/adapters/:type` | Get adapter details + models |
| `POST` | `/api/adapters/:type/test` | Test adapter environment |
| `GET` | `/api/adapters/:type/models` | List available models for adapter |

**Adapter module structure** (in `app/adapters/`):

```
app/adapters/
  index.js           -- Registry: getAdapter(type), listAdapters()
  claude-local.js    -- Claude Code CLI adapter
  process.js         -- Shell command adapter
  http.js            -- HTTP webhook adapter
  types.js           -- JSDoc type definitions
```

**Frontend components:**

- **AdapterSelector** -- Dropdown showing available adapters with icons and status
- **AdapterConfigForm** -- Dynamic form based on adapter type (cwd, model, env vars, timeout)
- **AdapterTestButton** -- "Test Environment" button with green/red result display
- **AdapterModelPicker** -- Model dropdown populated from adapter's model list

### 3B. Skill System

**What it does in Paperclip:**
Skills are markdown files with YAML frontmatter (`name`, `description`) plus optional `references/` directories. Skills are:
- Stored in `company_skills` table (company-scoped)
- Injected per-adapter (claude_local uses `--add-dir` with temp symlinks)
- On-demand: agents see metadata, load full content when invoked
- Managed via API: install, assign to agents, sync

**How to adapt:**
Create a skills system where skills are markdown files on disk, registered in the database, and injected into agent sessions via the adapter.

**Database schema:**

```sql
CREATE TABLE IF NOT EXISTS skills (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    key TEXT NOT NULL UNIQUE,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    markdown TEXT NOT NULL,
    source_type TEXT NOT NULL DEFAULT 'local_path',
        -- 'local_path', 'git', 'inline'
    source_locator TEXT,     -- file path or git URL
    source_ref TEXT,         -- git ref
    trust_level TEXT NOT NULL DEFAULT 'markdown_only',
    file_inventory TEXT NOT NULL DEFAULT '[]',  -- JSON array
    metadata TEXT DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

-- Agent-skill assignments (many-to-many)
CREATE TABLE IF NOT EXISTS agent_skills (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    agent_id INTEGER NOT NULL REFERENCES team_members(id) ON DELETE CASCADE,
    skill_id TEXT NOT NULL REFERENCES skills(id) ON DELETE CASCADE,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(agent_id, skill_id)
);
CREATE INDEX IF NOT EXISTS idx_agent_skills_agent ON agent_skills(agent_id);
```

**API endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/skills` | List all skills |
| `POST` | `/api/skills` | Register a new skill |
| `POST` | `/api/skills/import` | Import skill from path or git URL |
| `GET` | `/api/skills/:id` | Get skill detail + markdown |
| `PATCH` | `/api/skills/:id` | Update skill |
| `DELETE` | `/api/skills/:id` | Remove skill |
| `POST` | `/api/agents/:id/skills/sync` | Sync agent's desired skills |
| `GET` | `/api/agents/:id/skills` | List agent's assigned skills |

**Frontend components:**

- **SkillLibrary** -- Grid of skill cards with name, description, assigned count
- **SkillEditor** -- Markdown editor for creating/editing skills inline
- **SkillAssigner** -- Checkbox list for assigning skills to an agent
- **SkillBadge** -- Small pill showing skill name on agent cards

---

## Phase 4: Budget/Cost Tracking + Governance/Approvals

**Impact:** MEDIUM-HIGH -- Financial controls and governance gates.
**Dependencies:** Phase 1 (heartbeat_runs), Phase 3 (adapter_type on agents)
**Estimated effort:** Medium

### 4A. Budget/Cost Tracking

**What it does in Paperclip:**
Per-agent monthly budgets with:
- `cost_events` table tracking every LLM call (provider, model, tokens, cost)
- `budget_policies` with scope (company/agent/project), monthly/lifetime windows, warn %, hard stop
- `budget_incidents` when thresholds are crossed
- Auto-pause agents at 100% budget usage
- Budget overview dashboard with charts

**How to adapt:**
We already have `cost_events` and `budget_policies` tables. Enhance them to match Paperclip's model, add incidents tracking and per-agent budgets.

**Database schema:**

```sql
-- Enhance existing cost_events (already has provider, model, tokens, cost_cents)
ALTER TABLE cost_events ADD COLUMN agent_id INTEGER REFERENCES team_members(id);
    -- Note: existing column is member_id; keep both during migration
ALTER TABLE cost_events ADD COLUMN goal_id TEXT REFERENCES goals(id);
ALTER TABLE cost_events ADD COLUMN heartbeat_run_id TEXT REFERENCES heartbeat_runs(id);
ALTER TABLE cost_events ADD COLUMN billing_code TEXT;
ALTER TABLE cost_events ADD COLUMN biller TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE cost_events ADD COLUMN billing_type TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE cost_events ADD COLUMN cached_input_tokens INTEGER DEFAULT 0;
ALTER TABLE cost_events ADD COLUMN occurred_at TEXT NOT NULL DEFAULT (datetime('now','localtime'));

-- Enhance existing budget_policies
-- (existing has: scope, scope_id, monthly_limit_cents, warn_at_percent, hard_stop)
ALTER TABLE budget_policies ADD COLUMN metric TEXT NOT NULL DEFAULT 'billed_cents';
ALTER TABLE budget_policies ADD COLUMN window_kind TEXT NOT NULL DEFAULT 'monthly';
    -- 'monthly', 'lifetime'
ALTER TABLE budget_policies ADD COLUMN notify_enabled INTEGER NOT NULL DEFAULT 1;
ALTER TABLE budget_policies ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1;
ALTER TABLE budget_policies ADD COLUMN updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'));

-- NEW: Budget incidents (when thresholds are crossed)
CREATE TABLE IF NOT EXISTS budget_incidents (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    policy_id INTEGER NOT NULL REFERENCES budget_policies(id),
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    metric TEXT NOT NULL,
    window_kind TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    threshold_type TEXT NOT NULL,
        -- 'warning', 'hard_stop'
    amount_limit INTEGER NOT NULL,
    amount_observed INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
        -- 'open', 'acknowledged', 'dismissed', 'resolved'
    approval_id TEXT REFERENCES approvals(id),
    resolved_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_budget_incidents_status ON budget_incidents(status);
CREATE INDEX IF NOT EXISTS idx_budget_incidents_scope
    ON budget_incidents(scope_type, scope_id, status);
```

**API endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/budgets/overview` | Budget overview: all scopes, spend vs limit, incidents |
| `GET` | `/api/budgets/policies` | List all budget policies |
| `POST` | `/api/budgets/policies` | Create/update budget policy |
| `GET` | `/api/budgets/incidents` | List budget incidents |
| `PATCH` | `/api/budgets/incidents/:id` | Acknowledge/dismiss/resolve incident |
| `GET` | `/api/agents/:id/budget` | Agent's budget status (spend, limit, % used) |
| `GET` | `/api/costs` | Cost events with filters (agent, date range, model) |
| `GET` | `/api/costs/summary` | Aggregated cost summary (by agent, by model, by day) |

**Frontend components:**

- **BudgetOverview** -- Dashboard widget showing total spend, per-agent bars, incidents
- **BudgetPolicyEditor** -- Form for setting budget limits per agent/project/global
- **CostBreakdownChart** -- Bar/line chart of costs over time by agent and model
- **BudgetIncidentBanner** -- Alert banner when thresholds are crossed
- **AgentBudgetMeter** -- Progress bar on agent card showing spend vs limit

### 4B. Governance/Approvals

**What it does in Paperclip:**
Structured approval workflows where agents request board (human) sign-off for high-stakes actions:
- Agent hiring requires board approval
- Budget overrides require approval
- Any agent can create an approval request
- Approvals have `pending -> approved/rejected` lifecycle
- Approval resolution triggers agent wakeups

**How to adapt:**
We already have `governance_receipts` and `constitutional_invariants`. Add a proper approvals table for structured approval workflows.

**Database schema:**

```sql
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    type TEXT NOT NULL,
        -- 'new_agent', 'budget_override', 'task_escalation', 'general'
    requested_by_agent_id INTEGER REFERENCES team_members(id),
    requested_by_user_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
        -- 'pending', 'approved', 'rejected', 'expired'
    payload TEXT NOT NULL DEFAULT '{}',   -- JSON: what's being approved
    decision_note TEXT,
    decided_by_user_id TEXT,
    decided_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status, type);

-- Link approvals to tasks
CREATE TABLE IF NOT EXISTS task_approvals (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    approval_id TEXT NOT NULL REFERENCES approvals(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(task_id, approval_id)
);

-- Approval comments (discussion thread on approvals)
CREATE TABLE IF NOT EXISTS approval_comments (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    approval_id TEXT NOT NULL REFERENCES approvals(id) ON DELETE CASCADE,
    author_agent_id INTEGER REFERENCES team_members(id),
    author_user_id TEXT,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
```

**API endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/approvals` | List approvals (filter by status, type) |
| `POST` | `/api/approvals` | Create approval request |
| `GET` | `/api/approvals/:id` | Get approval detail |
| `POST` | `/api/approvals/:id/approve` | Approve (triggers agent wake) |
| `POST` | `/api/approvals/:id/reject` | Reject (triggers agent wake) |
| `GET` | `/api/approvals/:id/tasks` | Linked tasks |
| `POST` | `/api/approvals/:id/comments` | Add comment to approval |

**Frontend components:**

- **ApprovalQueue** -- List of pending approvals with approve/reject buttons
- **ApprovalDetail** -- Full approval view with payload, comments, decision history
- **ApprovalRequestForm** -- Form for creating approval requests
- **PendingApprovalBadge** -- Badge in nav showing count of pending approvals
- **ApprovalGate** -- Inline blocker on task detail when approval is required

---

## Phase 5: PARA Memory System + CEO 3-File Model

**Impact:** MEDIUM-HIGH -- Persistent agent knowledge and identity.
**Dependencies:** Phase 3 (skills system for file injection)
**Estimated effort:** Medium

### 5A. PARA Memory System

**What it does in Paperclip:**
Three-layer file-based memory per agent:
1. **Knowledge Graph** (`$AGENT_HOME/life/`) -- PARA folders (Projects/Areas/Resources/Archives) with entity folders containing `summary.md` + `items.yaml`
2. **Daily Notes** (`$AGENT_HOME/memory/YYYY-MM-DD.md`) -- Raw timeline
3. **Tacit Knowledge** (`$AGENT_HOME/MEMORY.md`) -- User/operator patterns and preferences

Memory survives session restarts because it's on disk. Uses `qmd` for semantic search across memory files.

**How to adapt:**
Create a per-agent memory directory structure under `Team/memory/` and database tables to index the memory files. The existing `Team/*.md` profile files become the SOUL.md equivalent.

**Database schema:**

```sql
-- Memory entities index (mirrors file system, enables search without qmd)
CREATE TABLE IF NOT EXISTS agent_memory_entities (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    agent_id INTEGER NOT NULL REFERENCES team_members(id) ON DELETE CASCADE,
    category TEXT NOT NULL,
        -- 'project', 'area', 'resource', 'archive'
    entity_name TEXT NOT NULL,
    entity_type TEXT,
        -- 'person', 'company', 'topic', 'project', 'tool', etc.
    summary TEXT,
    file_path TEXT NOT NULL,   -- relative path under agent's memory dir
    fact_count INTEGER NOT NULL DEFAULT 0,
    last_accessed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(agent_id, category, entity_name)
);
CREATE INDEX IF NOT EXISTS idx_memory_entities_agent
    ON agent_memory_entities(agent_id, category);

-- Daily notes index
CREATE TABLE IF NOT EXISTS agent_daily_notes (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    agent_id INTEGER NOT NULL REFERENCES team_members(id) ON DELETE CASCADE,
    date TEXT NOT NULL,         -- YYYY-MM-DD
    file_path TEXT NOT NULL,
    word_count INTEGER DEFAULT 0,
    fact_extractions INTEGER DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(agent_id, date)
);

-- Tacit knowledge entries (indexed version of MEMORY.md)
CREATE TABLE IF NOT EXISTS agent_tacit_knowledge (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    agent_id INTEGER NOT NULL REFERENCES team_members(id) ON DELETE CASCADE,
    category TEXT NOT NULL,
        -- 'preference', 'pattern', 'lesson', 'mistake', 'tool_usage'
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    learned_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    last_confirmed_at TEXT,
    superseded_by TEXT REFERENCES agent_tacit_knowledge(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(agent_id, category, key)
);
```

**Directory structure:**

```
Team/memory/
  <agent-name>/
    life/
      projects/
        <name>/
          summary.md
          items.yaml
      areas/
        people/
          <name>/...
        companies/
          <name>/...
      resources/
        <topic>/...
      archives/
      index.md
    memory/
      YYYY-MM-DD.md
    MEMORY.md          -- tacit knowledge
```

**API endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/agents/:id/memory` | List agent's memory entities |
| `GET` | `/api/agents/:id/memory/search` | Search agent's memory (keyword) |
| `GET` | `/api/agents/:id/memory/entities/:entityId` | Get entity detail |
| `POST` | `/api/agents/:id/memory/entities` | Create entity |
| `PATCH` | `/api/agents/:id/memory/entities/:entityId` | Update entity |
| `GET` | `/api/agents/:id/memory/daily-notes` | List daily notes |
| `GET` | `/api/agents/:id/memory/daily-notes/:date` | Get daily note content |
| `GET` | `/api/agents/:id/memory/tacit` | List tacit knowledge |
| `POST` | `/api/agents/:id/memory/tacit` | Add tacit knowledge entry |
| `POST` | `/api/agents/:id/memory/synthesis` | Trigger weekly synthesis |

**Frontend components:**

- **MemoryBrowser** -- File-tree view of agent's PARA memory with content preview
- **MemoryEntityCard** -- Shows entity name, type, fact count, last accessed
- **DailyNotesCalendar** -- Calendar view with dots on days that have notes
- **TacitKnowledgeList** -- Grouped list of learned patterns/preferences
- **MemorySearchBar** -- Full-text search across all agent memory

### 5B. CEO 3-File Model

**What it does in Paperclip:**
Each agent (especially the CEO) gets three defining files:
1. **SOUL.md** -- Personality, voice, identity, values
2. **HEARTBEAT.md** -- Step-by-step execution checklist per heartbeat cycle
3. **AGENTS.md** -- Delegation rules, who to delegate what to, restrictions

These are injected into the agent's context at heartbeat time via the adapter.

**How to adapt:**
We already have `Team/<name>.md` profiles. Extend to a 3-file model per agent. Store file paths in database, inject via adapter.

**Database schema:**

```sql
-- Agent identity files
CREATE TABLE IF NOT EXISTS agent_identity_files (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    agent_id INTEGER NOT NULL REFERENCES team_members(id) ON DELETE CASCADE,
    file_type TEXT NOT NULL,
        -- 'soul', 'heartbeat', 'agents', 'custom'
    file_path TEXT NOT NULL,   -- relative to Team/
    content_hash TEXT,
    last_synced_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(agent_id, file_type)
);
```

**File structure:**

```
Team/
  gray/
    SOUL.md        -- Gray's personality and orchestration philosophy
    HEARTBEAT.md   -- Gray's per-heartbeat checklist
    AGENTS.md      -- Gray's delegation rules (existing CLAUDE.md content)
  atlas/
    SOUL.md        -- Atlas's architect identity
    HEARTBEAT.md   -- Atlas's planning procedure
    AGENTS.md      -- Atlas's delegation rules
  ...per agent...
```

**API endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/agents/:id/identity-files` | List agent's identity files |
| `GET` | `/api/agents/:id/identity-files/:type` | Get file content |
| `PUT` | `/api/agents/:id/identity-files/:type` | Create/update file |
| `DELETE` | `/api/agents/:id/identity-files/:type` | Remove file |

**Frontend components:**

- **IdentityFileTabs** -- Tab view on agent detail showing SOUL / HEARTBEAT / AGENTS
- **MarkdownEditor** -- Inline markdown editor for editing identity files
- **IdentityFileStatus** -- Badge showing if files are configured

---

## Phase 6: Routines + Worktree Management + Plugin System

**Impact:** MEDIUM -- Recurring automation, workspace isolation, extensibility.
**Dependencies:** Phase 1-3 (heartbeat + goals + adapters)
**Estimated effort:** Large

### 6A. Routines (Scheduled Recurring Tasks)

**What it does in Paperclip:**
Routines are scheduled recurring tasks with:
- Cron expressions for timing (timezone-aware)
- Multiple trigger types: `cron`, `webhook`, `manual`
- Concurrency policies: `coalesce_if_active`, `allow_concurrent`, `reject_if_active`
- Catch-up policies: `skip_missed`, `run_latest`, `run_all`
- Each routine run creates an issue assigned to the configured agent
- Links to projects and goals

**How to adapt:**
Add routines as scheduled task generators. The existing cron-like system in `server.js` handles the tick; routines define what to create on each tick.

**Database schema:**

```sql
CREATE TABLE IF NOT EXISTS routines (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    project_id INTEGER REFERENCES projects(id),
    goal_id TEXT REFERENCES goals(id),
    parent_task_id INTEGER REFERENCES tasks(id),
    title TEXT NOT NULL,
    description TEXT,
    assignee_agent_id INTEGER NOT NULL REFERENCES team_members(id),
    priority TEXT NOT NULL DEFAULT 'normal',
    status TEXT NOT NULL DEFAULT 'active',
        -- 'active', 'paused', 'archived'
    concurrency_policy TEXT NOT NULL DEFAULT 'coalesce_if_active',
    catch_up_policy TEXT NOT NULL DEFAULT 'skip_missed',
    created_by_agent_id INTEGER REFERENCES team_members(id),
    created_by_user_id TEXT,
    last_triggered_at TEXT,
    last_enqueued_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_routines_status ON routines(status);
CREATE INDEX IF NOT EXISTS idx_routines_assignee ON routines(assignee_agent_id);

CREATE TABLE IF NOT EXISTS routine_triggers (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    routine_id TEXT NOT NULL REFERENCES routines(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
        -- 'cron', 'webhook', 'manual'
    label TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    cron_expression TEXT,
    timezone TEXT DEFAULT 'UTC',
    next_run_at TEXT,
    last_fired_at TEXT,
    public_id TEXT UNIQUE,
    last_result TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_routine_triggers_routine
    ON routine_triggers(routine_id);
CREATE INDEX IF NOT EXISTS idx_routine_triggers_next_run
    ON routine_triggers(next_run_at);

CREATE TABLE IF NOT EXISTS routine_runs (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    routine_id TEXT NOT NULL REFERENCES routines(id) ON DELETE CASCADE,
    trigger_id TEXT REFERENCES routine_triggers(id),
    source TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'received',
        -- 'received', 'enqueued', 'running', 'completed', 'failed', 'coalesced'
    triggered_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    idempotency_key TEXT,
    trigger_payload TEXT DEFAULT '{}',
    linked_task_id INTEGER REFERENCES tasks(id),
    coalesced_into_run_id TEXT,
    failure_reason TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_routine_runs_routine
    ON routine_runs(routine_id, created_at);
```

**API endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/routines` | List routines |
| `POST` | `/api/routines` | Create routine |
| `GET` | `/api/routines/:id` | Get routine detail |
| `PATCH` | `/api/routines/:id` | Update routine |
| `DELETE` | `/api/routines/:id` | Archive routine |
| `POST` | `/api/routines/:id/run` | Manually trigger routine |
| `GET` | `/api/routines/:id/triggers` | List triggers |
| `POST` | `/api/routines/:id/triggers` | Add trigger |
| `PATCH` | `/api/routines/:id/triggers/:triggerId` | Update trigger |
| `DELETE` | `/api/routines/:id/triggers/:triggerId` | Remove trigger |
| `GET` | `/api/routines/:id/runs` | List routine run history |

**Frontend components:**

- **RoutinesList** -- Table of routines with status, schedule, last run, next run
- **RoutineEditor** -- Form for creating/editing routines with cron builder
- **RoutineRunHistory** -- Timeline of routine executions with status badges
- **CronBuilder** -- Visual cron expression builder (every X minutes/hours/days)
- **RoutineCard** -- Card on agent detail showing their assigned routines

### 6B. Worktree Management

**What it does in Paperclip:**
Isolated git worktrees per agent per task:
- `execution_workspaces` table tracks workspace state
- `workspace_operations` table logs git operations (clone, checkout, branch, merge)
- Worktrees are created on task checkout, cleaned up on task completion
- Supports strategies: `shared_workspace`, `per_issue_worktree`, `per_issue_branch`

**How to adapt:**
Add workspace tracking for agents working on git-backed projects. The Team already has `linked_repos` and `linked_paths`.

**Database schema:**

```sql
CREATE TABLE IF NOT EXISTS execution_workspaces (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
    source_task_id INTEGER REFERENCES tasks(id),
    mode TEXT NOT NULL,
        -- 'shared', 'per_task_worktree', 'per_task_branch'
    strategy_type TEXT NOT NULL DEFAULT 'local_fs',
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
        -- 'active', 'closed', 'cleanup_pending'
    cwd TEXT,
    repo_url TEXT,
    base_ref TEXT,
    branch_name TEXT,
    provider_type TEXT NOT NULL DEFAULT 'local_fs',
    last_used_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    opened_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    closed_at TEXT,
    metadata TEXT DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_exec_workspaces_project_status
    ON execution_workspaces(project_id, status);

CREATE TABLE IF NOT EXISTS workspace_operations (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    execution_workspace_id TEXT REFERENCES execution_workspaces(id),
    heartbeat_run_id TEXT REFERENCES heartbeat_runs(id),
    phase TEXT NOT NULL,
        -- 'clone', 'checkout', 'branch_create', 'merge', 'cleanup'
    command TEXT,
    cwd TEXT,
    status TEXT NOT NULL DEFAULT 'running',
    exit_code INTEGER,
    stdout_excerpt TEXT,
    stderr_excerpt TEXT,
    started_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    finished_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_workspace_ops_workspace
    ON workspace_operations(execution_workspace_id, started_at);
```

**API endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/workspaces` | List execution workspaces |
| `POST` | `/api/workspaces` | Create workspace (clone/worktree) |
| `GET` | `/api/workspaces/:id` | Get workspace detail |
| `POST` | `/api/workspaces/:id/close` | Close workspace |
| `GET` | `/api/workspaces/:id/operations` | List operations |
| `POST` | `/api/tasks/:id/workspace` | Create workspace for a specific task |

**Frontend components:**

- **WorkspaceList** -- Table of active workspaces with project, branch, last used
- **WorkspaceDetail** -- Shows git status, branch info, operation history
- **WorkspaceSelector** -- Dropdown for assigning workspace to a task

### 6C. Plugin System

**What it does in Paperclip:**
Full plugin architecture with:
- Plugin manifest (`PLUGIN_SPEC.md v1`), SDK, loader, worker manager
- Plugin tables: `plugins`, `plugin_config`, `plugin_state`, `plugin_jobs`, `plugin_logs`, `plugin_entities`, `plugin_webhooks`
- Plugins run as separate worker processes
- Scoped key-value state storage
- Hook system for lifecycle events

**How to adapt:**
Create a simplified plugin system. No worker processes initially -- plugins are JS modules loaded at startup that register hooks and API extensions.

**Database schema:**

```sql
CREATE TABLE IF NOT EXISTS plugins (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    plugin_key TEXT NOT NULL UNIQUE,
    package_name TEXT NOT NULL,
    version TEXT NOT NULL,
    api_version INTEGER NOT NULL DEFAULT 1,
    categories TEXT NOT NULL DEFAULT '[]',  -- JSON array
    manifest_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'installed',
        -- 'installed', 'active', 'disabled', 'error'
    package_path TEXT,
    last_error TEXT,
    installed_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS plugin_config (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    plugin_id TEXT NOT NULL REFERENCES plugins(id) ON DELETE CASCADE,
    config_json TEXT NOT NULL DEFAULT '{}',
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(plugin_id)
);

CREATE TABLE IF NOT EXISTS plugin_state (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    plugin_id TEXT NOT NULL REFERENCES plugins(id) ON DELETE CASCADE,
    scope_kind TEXT NOT NULL,
        -- 'instance', 'project', 'agent', 'task', 'goal', 'run'
    scope_id TEXT,
    namespace TEXT NOT NULL DEFAULT 'default',
    state_key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(plugin_id, scope_kind, scope_id, namespace, state_key)
);
CREATE INDEX IF NOT EXISTS idx_plugin_state_plugin_scope
    ON plugin_state(plugin_id, scope_kind);
```

**API endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/plugins` | List installed plugins |
| `POST` | `/api/plugins/install` | Install plugin from path |
| `GET` | `/api/plugins/:id` | Get plugin detail |
| `PATCH` | `/api/plugins/:id` | Enable/disable plugin |
| `DELETE` | `/api/plugins/:id` | Uninstall plugin |
| `GET` | `/api/plugins/:id/config` | Get plugin config |
| `PUT` | `/api/plugins/:id/config` | Update plugin config |
| `GET` | `/api/plugins/:id/state` | List plugin state entries |

**Frontend components:**

- **PluginMarketplace** -- Grid of available/installed plugins
- **PluginConfigPanel** -- Dynamic config form per plugin
- **PluginStatusBadge** -- Active/disabled/error state indicator

---

## Phase 7: Company Portability + OpenClaw + Eval System

**Impact:** MEDIUM -- Export/import, external agent connectivity, quality verification.
**Dependencies:** Phase 1-5 (nearly everything)
**Estimated effort:** Medium

### 7A. Company Portability

**What it does in Paperclip:**
Export/import entire company configurations as JSON packages:
- Exports: agents (with adapter config, skills, runtime state), goals, projects, issues, routines, budget policies
- Import modes: `new_company`, `merge_into_existing`
- Collision resolution: `rename`, `skip`
- Preview before apply

**How to adapt:**
Export/import The Team's configuration as a JSON package. Useful for backups, templates, and replicating team setups.

**Database schema:**

```sql
CREATE TABLE IF NOT EXISTS team_exports (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    name TEXT NOT NULL,
    description TEXT,
    format_version INTEGER NOT NULL DEFAULT 1,
    export_json TEXT NOT NULL,  -- full JSON package
    file_count INTEGER NOT NULL DEFAULT 0,
    agent_count INTEGER NOT NULL DEFAULT 0,
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS team_imports (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    source TEXT NOT NULL,         -- file path or 'manual'
    mode TEXT NOT NULL DEFAULT 'merge',
        -- 'merge', 'replace', 'new'
    status TEXT NOT NULL DEFAULT 'preview',
        -- 'preview', 'applying', 'completed', 'failed'
    preview_json TEXT,
    result_json TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    completed_at TEXT
);
```

**API endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/team/export/preview` | Preview what would be exported |
| `POST` | `/api/team/export` | Create export package |
| `GET` | `/api/team/exports` | List past exports |
| `GET` | `/api/team/exports/:id` | Download export package |
| `POST` | `/api/team/import/preview` | Preview import (show what changes) |
| `POST` | `/api/team/import/apply` | Apply import |
| `GET` | `/api/team/imports` | List past imports |

**Frontend components:**

- **ExportWizard** -- Multi-step wizard: select what to export, preview, download
- **ImportWizard** -- Upload JSON, preview changes, confirm, apply
- **ExportHistory** -- List of past exports with download links

### 7B. OpenClaw Integration

**What it does in Paperclip:**
OpenClaw gateway adapter connects to an external OpenClaw agent endpoint:
- Agent sends work via WebSocket/HTTP to an OpenClaw instance
- OpenClaw agents are autonomous -- they connect to Paperclip via the API
- Join request / invite flow for onboarding new OpenClaw agents
- The adapter handles the gateway protocol

**How to adapt:**
Add an `openclaw_gateway` adapter type that communicates with an OpenClaw endpoint. This allows The Team to connect to externally-hosted agents.

**Database schema:**

```sql
-- OpenClaw connection tracking
CREATE TABLE IF NOT EXISTS external_agent_connections (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    agent_id INTEGER NOT NULL REFERENCES team_members(id),
    connection_type TEXT NOT NULL DEFAULT 'openclaw',
    endpoint_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
        -- 'pending', 'connected', 'disconnected', 'error'
    api_key_hash TEXT,
    last_ping_at TEXT,
    last_error TEXT,
    config TEXT DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

-- Join requests (external agents requesting to join)
CREATE TABLE IF NOT EXISTS agent_join_requests (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    agent_name TEXT NOT NULL,
    agent_role TEXT,
    connection_type TEXT NOT NULL DEFAULT 'openclaw',
    endpoint_url TEXT,
    config TEXT DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending',
        -- 'pending', 'approved', 'rejected'
    approval_id TEXT REFERENCES approvals(id),
    decided_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
```

**API endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/openclaw/invite-prompt` | Generate invite prompt for OpenClaw |
| `POST` | `/api/openclaw/join-request` | Submit join request (from external agent) |
| `GET` | `/api/openclaw/join-requests` | List pending join requests |
| `POST` | `/api/openclaw/join-requests/:id/approve` | Approve join request |
| `POST` | `/api/openclaw/join-requests/:id/reject` | Reject join request |
| `GET` | `/api/agents/:id/connection` | Get external connection status |

**Frontend components:**

- **OpenClawConnector** -- Form for connecting to an OpenClaw endpoint
- **JoinRequestQueue** -- List of pending agent join requests with approve/reject
- **ConnectionStatusBadge** -- Real-time connection status on agent cards

### 7C. Eval System

**What it does in Paperclip:**
Promptfoo-based behavior evaluation:
- Test scenarios: assignment pickup, progress updates, blocked reporting, approval governance, checkout enforcement, 409 handling
- Tests run against multiple models
- Results stored and compared

**How to adapt:**
Create a simple eval runner that tests agent behavior against expected patterns.

**Database schema:**

```sql
CREATE TABLE IF NOT EXISTS eval_suites (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    name TEXT NOT NULL,
    description TEXT,
    scenarios TEXT NOT NULL DEFAULT '[]',  -- JSON array of test scenarios
    status TEXT NOT NULL DEFAULT 'draft',
        -- 'draft', 'ready', 'running', 'completed'
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS eval_runs (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    suite_id TEXT NOT NULL REFERENCES eval_suites(id),
    agent_id INTEGER REFERENCES team_members(id),
    status TEXT NOT NULL DEFAULT 'running',
        -- 'running', 'passed', 'failed', 'error'
    results_json TEXT DEFAULT '{}',
    score REAL,
    started_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    completed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS eval_results (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    run_id TEXT NOT NULL REFERENCES eval_runs(id) ON DELETE CASCADE,
    scenario_name TEXT NOT NULL,
    expected TEXT,
    actual TEXT,
    passed INTEGER NOT NULL DEFAULT 0,
    score REAL,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
```

**API endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/evals/suites` | List eval suites |
| `POST` | `/api/evals/suites` | Create eval suite |
| `POST` | `/api/evals/run` | Run eval suite against agent |
| `GET` | `/api/evals/runs` | List eval runs |
| `GET` | `/api/evals/runs/:id` | Get eval run results |

**Frontend components:**

- **EvalSuiteEditor** -- Form for creating test scenarios
- **EvalRunResults** -- Table of scenario results with pass/fail badges
- **EvalScoreCard** -- Score summary with trend chart

---

## Implementation Dependencies Graph

```
Phase 1 (Heartbeat + Checkout + Activity)
    |
    +---> Phase 2 (Goals + Comments + Issue Lifecycle)
    |         |
    |         +---> Phase 5 (PARA Memory + 3-File Model)
    |
    +---> Phase 3 (Adapters + Skills)
    |         |
    |         +---> Phase 5 (PARA Memory + 3-File Model)
    |         |
    |         +---> Phase 6 (Routines + Worktrees + Plugins)
    |
    +---> Phase 4 (Budgets + Approvals)
              |
              +---> Phase 7 (Portability + OpenClaw + Evals)
```

---

## New Dashboard Pages

| Page | Phase | Description |
|------|-------|-------------|
| **Heartbeat Monitor** | 1 | Live run viewer, run history, agent runtime state |
| **Goals** | 2 | Goal hierarchy tree, goal detail with linked tasks |
| **Approvals** | 4 | Approval queue, approval detail, decision log |
| **Budget Dashboard** | 4 | Cost charts, budget policies, incidents |
| **Agent Memory** | 5 | PARA browser, daily notes, tacit knowledge |
| **Routines** | 6 | Routine list, cron builder, run history |
| **Workspaces** | 6 | Active workspaces, operation log |
| **Plugins** | 6 | Plugin marketplace, config, state |
| **Evals** | 7 | Test suites, run results, scores |
| **Team Export/Import** | 7 | Export wizard, import wizard, history |

---

## Existing Pages to Enhance

| Existing Page | Enhancements | Phase |
|---------------|-------------|-------|
| **Dashboard** | Add heartbeat status widgets, pending approvals badge, budget meter, recent runs | 1, 4 |
| **Mission Control** | Add checkout status on tasks, goal breadcrumb, comment count badge | 1, 2 |
| **Team Roster** | Add adapter type, budget usage, last heartbeat, assigned skills | 3, 4 |
| **Agent Detail** | Add run history tab, identity files tab, memory tab, skills tab, budget tab | 1, 3, 4, 5 |
| **Task Detail** | Add comment thread, checkout badge, goal link, workspace link | 1, 2, 6 |
| **Projects** | Add goal link, workspace list, routine list | 2, 6 |
| **Analytics** | Add cost breakdown charts, budget trend, agent utilization | 4 |

---

## New team_members Columns Summary (Phase 3)

All columns added to the existing `team_members` table across phases:

```sql
-- Phase 1: Heartbeat
ALTER TABLE team_members ADD COLUMN last_heartbeat_at TEXT;

-- Phase 3: Adapter
ALTER TABLE team_members ADD COLUMN adapter_type TEXT NOT NULL DEFAULT 'claude_local';
ALTER TABLE team_members ADD COLUMN adapter_config TEXT NOT NULL DEFAULT '{}';
ALTER TABLE team_members ADD COLUMN runtime_config TEXT NOT NULL DEFAULT '{}';
ALTER TABLE team_members ADD COLUMN capabilities TEXT;
ALTER TABLE team_members ADD COLUMN permissions TEXT NOT NULL DEFAULT '{}';
ALTER TABLE team_members ADD COLUMN metadata TEXT DEFAULT '{}';
ALTER TABLE team_members ADD COLUMN reports_to INTEGER REFERENCES team_members(id);
ALTER TABLE team_members ADD COLUMN icon TEXT;

-- Phase 4: Budget
ALTER TABLE team_members ADD COLUMN budget_monthly_cents INTEGER NOT NULL DEFAULT 0;
ALTER TABLE team_members ADD COLUMN spent_monthly_cents INTEGER NOT NULL DEFAULT 0;
ALTER TABLE team_members ADD COLUMN pause_reason TEXT;
ALTER TABLE team_members ADD COLUMN paused_at TEXT;
```

---

## New tasks Columns Summary

All columns added to the existing `tasks` table across phases:

```sql
-- Phase 1: Checkout
ALTER TABLE tasks ADD COLUMN checkout_run_id TEXT;
ALTER TABLE tasks ADD COLUMN checkout_agent_id INTEGER;
ALTER TABLE tasks ADD COLUMN checkout_locked_at TEXT;
ALTER TABLE tasks ADD COLUMN parent_task_id INTEGER REFERENCES tasks(id);
ALTER TABLE tasks ADD COLUMN goal_id TEXT REFERENCES goals(id);

-- Phase 2: Issue lifecycle
ALTER TABLE tasks ADD COLUMN origin_kind TEXT NOT NULL DEFAULT 'manual';
ALTER TABLE tasks ADD COLUMN origin_id TEXT;
ALTER TABLE tasks ADD COLUMN request_depth INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tasks ADD COLUMN billing_code TEXT;
ALTER TABLE tasks ADD COLUMN started_at TEXT;
ALTER TABLE tasks ADD COLUMN completed_at TEXT;
ALTER TABLE tasks ADD COLUMN cancelled_at TEXT;
ALTER TABLE tasks ADD COLUMN created_by_agent_id INTEGER;
ALTER TABLE tasks ADD COLUMN created_by_user_id TEXT;
ALTER TABLE tasks ADD COLUMN identifier TEXT UNIQUE;
ALTER TABLE tasks ADD COLUMN issue_number INTEGER;
```

---

## Total New Tables: 30

| # | Table | Phase |
|---|-------|-------|
| 1 | `heartbeat_runs` | 1 |
| 2 | `heartbeat_run_events` | 1 |
| 3 | `agent_wakeup_requests` | 1 |
| 4 | `agent_runtime_state` | 1 |
| 5 | `agent_task_sessions` | 1 |
| 6 | `goals` | 2 |
| 7 | `task_comments` | 2 |
| 8 | `adapter_types` | 3 |
| 9 | `skills` | 3 |
| 10 | `agent_skills` | 3 |
| 11 | `budget_incidents` | 4 |
| 12 | `approvals` | 4 |
| 13 | `task_approvals` | 4 |
| 14 | `approval_comments` | 4 |
| 15 | `agent_memory_entities` | 5 |
| 16 | `agent_daily_notes` | 5 |
| 17 | `agent_tacit_knowledge` | 5 |
| 18 | `agent_identity_files` | 5 |
| 19 | `routines` | 6 |
| 20 | `routine_triggers` | 6 |
| 21 | `routine_runs` | 6 |
| 22 | `execution_workspaces` | 6 |
| 23 | `workspace_operations` | 6 |
| 24 | `plugins` | 6 |
| 25 | `plugin_config` | 6 |
| 26 | `plugin_state` | 6 |
| 27 | `team_exports` | 7 |
| 28 | `team_imports` | 7 |
| 29 | `external_agent_connections` | 7 |
| 30 | `agent_join_requests` | 7 |
| 31 | `eval_suites` | 7 |
| 32 | `eval_runs` | 7 |
| 33 | `eval_results` | 7 |

---

## Total New API Endpoints: ~85

| Phase | Count | Categories |
|-------|-------|-----------|
| 1 | 12 | Heartbeat runs, wakeups, runtime state, checkout |
| 2 | 14 | Goals, task comments, enhanced tasks |
| 3 | 15 | Adapters, skills, agent skills |
| 4 | 16 | Budget overview/policies/incidents, approvals |
| 5 | 15 | Memory entities/notes/tacit, identity files |
| 6 | 17 | Routines/triggers/runs, workspaces, plugins |
| 7 | 16 | Export/import, OpenClaw, evals |

---

## Files to Create/Modify

### New files:

```
app/
  adapters/
    index.js              -- Adapter registry
    claude-local.js       -- Claude Code adapter
    process.js            -- Shell command adapter
    http.js               -- HTTP webhook adapter
  services/
    heartbeat.js          -- Heartbeat scheduler + orchestrator
    budgets.js            -- Budget enforcement service
    routines.js           -- Routine scheduler
    skills.js             -- Skill loader + injector
    memory.js             -- PARA memory manager
    portability.js        -- Team export/import
  routes/
    heartbeat.js          -- Heartbeat API routes
    goals.js              -- Goals API routes
    comments.js           -- Task comments API routes
    adapters.js           -- Adapter API routes
    skills.js             -- Skills API routes
    budgets.js            -- Budget API routes
    approvals.js          -- Approvals API routes
    memory.js             -- Memory API routes
    routines.js           -- Routines API routes
    workspaces.js         -- Workspace API routes
    plugins.js            -- Plugin API routes
    portability.js        -- Export/import API routes
    openclaw.js           -- OpenClaw API routes
    evals.js              -- Eval API routes
  public/
    js/
      heartbeat-monitor.js     -- Heartbeat monitor page
      goal-tree.js             -- Goal hierarchy page
      approval-queue.js        -- Approvals page
      budget-dashboard.js      -- Budget page
      agent-memory.js          -- Memory browser page
      routines-page.js         -- Routines page
      workspaces-page.js       -- Workspaces page
      plugins-page.js          -- Plugins page
      evals-page.js            -- Evals page
      export-import-page.js    -- Export/import page
    css/
      heartbeat.css
      goals.css
      approvals.css
      memory.css
```

### Existing files to modify:

```
app/server.js            -- Add new table creation, route mounting, heartbeat scheduler
app/public/js/app.js     -- Add new page routes
app/public/js/dashboard.js  -- Add heartbeat widgets, budget meter, approval badge
app/public/js/mission-control.js -- Add checkout status, goal breadcrumb, comments
app/public/js/team.js    -- Add adapter type, budget, skills badges
app/public/js/agent-detail.js  -- Add tabs for runs, memory, skills, identity
app/public/index.html    -- Add nav items for new pages
```

---

## Migration Strategy

Each phase includes:
1. **Schema migration** -- `ALTER TABLE` for existing tables, `CREATE TABLE IF NOT EXISTS` for new tables
2. **Seed data** -- Default adapter types, default budget policies, system goals
3. **API routes** -- Mounted in `server.js` via `app.use()`
4. **Frontend pages** -- New JS files loaded by the hash router in `app.js`
5. **Existing page enhancements** -- Additive changes to existing page JS files

All migrations use `CREATE TABLE IF NOT EXISTS` and `ALTER TABLE ... ADD COLUMN` wrapped in try/catch for idempotency. This matches The Team's existing migration pattern in `server.js`.

---

## Priority Summary

| Phase | Priority | Reason |
|-------|----------|--------|
| **Phase 1** | CRITICAL | Foundation -- nothing else works without heartbeat + checkout |
| **Phase 2** | HIGH | Goals give work meaning; comments enable agent communication |
| **Phase 3** | HIGH | Adapter architecture enables runtime flexibility; skills enable modularity |
| **Phase 4** | HIGH | Financial controls prevent runaway costs; approvals add governance |
| **Phase 5** | MEDIUM-HIGH | Memory persistence makes agents smarter over time |
| **Phase 6** | MEDIUM | Routines automate recurring work; worktrees isolate work; plugins add extensibility |
| **Phase 7** | MEDIUM | Portability, external agents, and quality verification are polish |

---

*Plan filed by Atlas, Systems Architect*
*Source: Paperclip-1 full repository analysis*
*Target: The Team Dashboard (Express + SQLite + vanilla JS)*
