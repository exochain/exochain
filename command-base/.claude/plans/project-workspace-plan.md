# Project Workspace — Full Architecture Plan

**Architect:** Atlas
**Date:** 2026-03-29
**Status:** Ready for Approval
**Scope:** New "Workspace" page in the dashboard — live agent grid, project submission, plan approval, session summaries

---

## Table of Contents

1. [Overview](#1-overview)
2. [Live Agent Dashboard](#2-live-agent-dashboard)
3. [Project Submission Flow](#3-project-submission-flow)
4. [Database Schema](#4-database-schema)
5. [API Endpoints](#5-api-endpoints)
6. [Frontend Components](#6-frontend-components)
7. [Integration with Existing Auto-Spawn](#7-integration-with-existing-auto-spawn)
8. [Implementation Plan](#8-implementation-plan)

---

## 1. Overview

### What This Is

A new top-level page in the dashboard (`#workspace`) that gives Max a Mission Control view of all running agents. Think of it as Cursor's Background Agents web interface — but for Max's team of 22 AI members, running across multiple projects, viewable from any browser.

### Core Principles

1. **Refresh = latest state.** All data persists in SQLite. The page reconstructs from DB on every load. WebSocket is a bonus, not a requirement.
2. **Autonomous by default.** Agents work without Max present. He checks in when he wants.
3. **No forced interruptions.** Pause/cancel are available but never mandatory. No approval gates block execution unless Max explicitly set them up.
4. **Built on what exists.** The `spawnMemberTerminal()` function, `active_processes` table, `tasks` table, and WebSocket `broadcast()` are all already working. This is a better UI on top of that foundation plus a new activity stream table.

### What Already Exists (and We Keep)

| Component | Location | What It Does |
|-----------|----------|-------------|
| `spawnMemberTerminal()` | `server.js:5285` | Spawns Claude CLI processes, parses stdout for tool calls, updates `tasks.progress` and `tasks.current_step` |
| `active_processes` table | SQLite | Tracks running/completed/failed processes with PID, member_id, task_id |
| `broadcast()` | `server.js:7701` | WebSocket push to all connected clients |
| `monitorRenderProcessCard()` | `app.js:2501` | Renders a process card with avatar, status dot, progress bar, step info |
| `monitorRenderTaskCard()` | `app.js:2418` | Renders a task card with progress, assignee, execution log, pause/cancel |
| Live Monitor tab | `app.js:2821` (inside Tasks page) | 10-second polling + WebSocket updates, elapsed time counter |

### What's New

| Component | Purpose |
|-----------|---------|
| `agent_activity_stream` table | Granular per-event log (file read, edit, command, thinking) — the raw feed |
| `workspace_sessions` table | Groups a big prompt into a plannable, phased execution |
| `session_phases` table | Individual phases within a session |
| `#workspace` page | New top-level nav item with the agent grid, submission flow, and plan viewer |
| stdout-to-activity-stream bridge | Saves parsed tool calls from `spawnMemberTerminal()` to `agent_activity_stream` |

---

## 2. Live Agent Dashboard (Main View)

### 2.1 Layout

```
+------------------------------------------------------------------+
|  WORKSPACE                                        [+ New Project] |
+------------------------------------------------------------------+
|  Session Summary Bar (if returning user)                         |
|  "Since you left: 3 tasks completed, 2 files deployed, ..."     |
+------------------------------------------------------------------+
|                                                                  |
|  +------------------+  +------------------+  +------------------+|
|  | [A] Anvil        |  | [S] Spark        |  | [L] Lumen       ||
|  | Backend Dev      |  | Frontend Dev     |  | UI Engineer     ||
|  |                  |  |                  |  |                  ||
|  | Task: Add WebSo- |  | Task: Render ag- |  | Task: Style the ||
|  | cket endpoint    |  | ent grid cards   |  | workspace page  ||
|  |                  |  |                  |  |                  ||
|  | > Editing        |  | > Reading        |  | > Writing        ||
|  |   server.js...   |  |   app.js:2501... |  |   styles.css...  ||
|  |                  |  |                  |  |                  ||
|  | [====65%=====  ] |  | [===40%====    ] |  | [==30%===      ] ||
|  | 4m 32s           |  | 2m 15s           |  | 1m 08s           ||
|  |                  |  |                  |  |                  ||
|  | Files: server.js |  | Files: app.js    |  | Files: styles.css||
|  |        types.ts  |  |                  |  |                  ||
|  |                  |  |                  |  |                  ||
|  | [Pause] [Cancel] |  | [Pause] [Cancel] |  | [Pause] [Cancel] ||
|  | [v Expand Log]   |  | [v Expand Log]   |  | [v Expand Log]   ||
|  +------------------+  +------------------+  +------------------+|
|                                                                  |
+------------------------------------------------------------------+
```

### 2.2 Agent Card — Data Model

Each card maps to one row in `active_processes` (status = 'running'), joined with its `tasks` row and member info.

```
AgentCard {
  // From active_processes
  process_id        -- unique ID
  pid               -- OS process ID
  started_at        -- when spawned

  // From team_members
  member_name       -- "Anvil"
  member_role       -- "Backend Developer"
  member_id         -- for avatar color

  // From tasks
  task_id           -- linked task
  task_title        -- "Add WebSocket endpoint for activity stream"
  progress          -- 0-100
  current_step      -- "Anvil: Editing server.js..."

  // From agent_activity_stream (aggregated)
  files_touched     -- ["server.js", "types.ts"]   (distinct file_path from recent activity)
  recent_events     -- last 10 activity events (for expanded log view)
  event_counts      -- { reads: 12, edits: 5, commands: 3 }
}
```

### 2.3 Card States

| State | Visual | Actions Available |
|-------|--------|-------------------|
| **Running** | Green pulsing dot, progress bar animating | Pause, Cancel, Expand Log |
| **Paused** | Yellow dot, "PAUSED" badge | Resume, Cancel |
| **Completed** | Blue dot, progress at 100% | View Output, Dismiss |
| **Failed** | Red dot, error message shown | Retry, View Error Log, Dismiss |
| **Waiting** | Gray dot, "Waiting for approval" | Approve, Skip |

### 2.4 Expanded Log View

When the user clicks "Expand Log" on a card, it slides open to show the full activity stream for that agent:

```
+------------------------------------------+
| [A] Anvil — Backend Developer            |
| Task: Add WebSocket endpoint             |
+------------------------------------------+
| 10:42:15  READ   server.js (lines 1-100) |
| 10:42:18  READ   server.js (lines 5280-5600) |
| 10:42:22  THINK  "Need to add a new broadcast event for activity..." |
| 10:42:25  EDIT   server.js (line 5567: added saveActivityEvent call) |
| 10:42:28  READ   server.js (line 7700: checking broadcast function) |
| 10:42:31  EDIT   server.js (line 7710: added /api/agent-stream route) |
| 10:42:34  BASH   npm test (exit 0, 2.1s) |
| 10:42:37  WRITE  new file: agent-stream-types.ts |
| 10:42:40  THINK  "Testing the endpoint..." |
| 10:42:42  BASH   curl localhost:3000/api/agent-stream/1 (200 OK) |
+------------------------------------------+
```

Each event row is color-coded:
- **READ** — blue text
- **EDIT** — green text
- **WRITE** — green text, bold
- **BASH** — yellow text
- **THINK** — gray italic
- **ERROR** — red text

### 2.5 Real-Time Updates

**Primary mechanism: WebSocket** (already exists)

The server already calls `broadcast('task.updated', { id })` when progress changes. We add:
- `broadcast('agent.activity', { process_id, event })` — fired each time a new activity event is saved
- `broadcast('process.progress', { process_id, progress, current_step, files_touched })` — fired on throttled progress updates

**Fallback: Polling** (already exists)

The current monitor polls every 10 seconds. The workspace page will do the same, but only as a fallback if the WebSocket connection drops.

**On page refresh:**

All data comes from SQLite. The page calls `GET /api/workspace/active` and renders the grid from DB state. No dependency on WebSocket history.

---

## 3. Project Submission Flow

### 3.1 The Five Stages

```
INTAKE → DIGESTION → APPROVAL → EXECUTION → SUMMARY
```

#### Stage 1: Intake

Max pastes or uploads a big prompt (e.g., "Build the Clipper Engine media processing pipeline").

The UI shows:
- Text area / file upload
- Character count, estimated token count
- Project selector (which project is this for?)
- Priority selector
- "Submit to Gray" button

**What happens on submit:**
1. Create a `workspace_sessions` row (status: `intake`)
2. Save the raw prompt text
3. Broadcast `workspace.submitted`
4. Transition to `digesting` status

#### Stage 2: Digestion

Gray (or Atlas via delegation) reads the prompt and breaks it into phases. This happens automatically — no user action needed.

The UI shows:
- "Gray is analyzing your project..." with a spinner
- The raw prompt text (collapsed, expandable)
- Timer showing how long digestion is taking

**What happens:**
1. A task is created for Gray: "Digest workspace session #X"
2. Gray's spawned terminal reads the prompt, creates a phased plan
3. The plan is saved to `workspace_sessions.plan_json` (structured JSON) and `workspace_sessions.plan_markdown` (readable markdown)
4. Session status transitions to `pending_approval`
5. Broadcast `workspace.plan_ready`

#### Stage 3: Approval

Max reviews the plan Gray generated. The plan is a structured list of phases, each with:
- Phase title
- Description of what will be done
- Which team member(s) will handle it
- Estimated complexity (simple/moderate/complex)
- Dependencies (which phases must complete first)

The UI shows:
- The plan rendered as an interactive checklist
- Each phase has: title, description, assigned member(s), reorder handle
- Max can: edit titles/descriptions, reorder phases, remove phases, add phases
- "Execute Plan" button (starts all phases that have no dependencies)
- "Edit & Re-digest" button (sends modified instructions back to Gray)

**What happens on "Execute Plan":**
1. Save the final plan to `session_phases` table (one row per phase)
2. Set session status to `executing`
3. For each phase with no unmet dependencies: create a task, assign the member, call `spawnMemberTerminal()`
4. Broadcast `workspace.executing`

#### Stage 4: Execution

This is the Live Agent Dashboard described in Section 2. Each phase that's currently running shows up as an agent card.

Phases execute in dependency order:
- Independent phases run in parallel
- Dependent phases start automatically when their prerequisites complete
- If a phase fails, dependent phases are blocked (status: `blocked`)

The UI shows:
- The agent grid (one card per running phase/agent)
- A phase timeline on the side showing all phases, their status, and dependencies
- Phases transition: `pending` → `running` → `completed` / `failed`

#### Stage 5: Summary

When Max returns after being away, the workspace shows a summary of what happened.

The UI shows:
- "Since your last visit (6 hours ago):"
  - Phases completed: 3 of 7
  - Files modified: 14
  - Lines added: 482, removed: 67
  - Agents that ran: Anvil (2 tasks), Spark (1 task), Lumen (1 task)
  - Current status: Phase 4 in progress (Spark working on frontend grid)
  - Issues: Phase 3 failed (Bastion: Docker build error) — [View Error] [Retry]

**How "last visit" is tracked:**
- `workspace_sessions.last_viewed_at` — updated every time Max loads the workspace page
- Summary queries `agent_activity_stream` for events between `last_viewed_at` and now

---

## 4. Database Schema

### 4.1 New Table: `workspace_sessions`

Tracks a big project submission from intake through completion.

```sql
CREATE TABLE IF NOT EXISTS workspace_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    raw_prompt TEXT NOT NULL,
    prompt_chars INTEGER DEFAULT 0,
    prompt_tokens_est INTEGER DEFAULT 0,
    project_id INTEGER REFERENCES projects(id),
    priority TEXT DEFAULT 'normal' CHECK(priority IN ('low', 'normal', 'high', 'urgent')),
    status TEXT NOT NULL DEFAULT 'intake'
        CHECK(status IN ('intake', 'digesting', 'pending_approval', 'executing', 'paused', 'completed', 'failed', 'cancelled')),
    plan_markdown TEXT,
    plan_json TEXT,
    digested_by INTEGER REFERENCES team_members(id),
    approved_at TEXT,
    started_at TEXT,
    completed_at TEXT,
    last_viewed_at TEXT,
    summary_cache TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);
```

### 4.2 New Table: `session_phases`

Individual phases within a workspace session.

```sql
CREATE TABLE IF NOT EXISTS session_phases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES workspace_sessions(id) ON DELETE CASCADE,
    phase_number INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    assigned_member_id INTEGER REFERENCES team_members(id),
    assigned_member_name TEXT,
    complexity TEXT DEFAULT 'moderate' CHECK(complexity IN ('simple', 'moderate', 'complex')),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending', 'running', 'completed', 'failed', 'blocked', 'skipped', 'cancelled')),
    depends_on TEXT,
    task_id INTEGER REFERENCES tasks(id),
    process_id INTEGER REFERENCES active_processes(id),
    output_summary TEXT,
    started_at TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);
```

**Notes:**
- `depends_on` is a JSON array of phase IDs: `[1, 3]` means "wait for phases 1 and 3"
- `task_id` links to the actual task created when the phase starts executing
- `process_id` links to the active_processes row for the spawned terminal

### 4.3 New Table: `agent_activity_stream`

Granular per-event log of what each agent is doing. This is the "raw feed" that powers the expanded log view and the session summaries.

```sql
CREATE TABLE IF NOT EXISTS agent_activity_stream (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    process_id INTEGER NOT NULL REFERENCES active_processes(id),
    task_id INTEGER REFERENCES tasks(id),
    member_id INTEGER NOT NULL REFERENCES team_members(id),
    session_id INTEGER REFERENCES workspace_sessions(id),
    event_type TEXT NOT NULL
        CHECK(event_type IN ('read', 'edit', 'write', 'bash', 'grep', 'glob', 'think', 'error', 'tool_other', 'status_change')),
    file_path TEXT,
    file_name TEXT,
    detail TEXT,
    line_info TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

CREATE INDEX IF NOT EXISTS idx_activity_stream_process ON agent_activity_stream(process_id);
CREATE INDEX IF NOT EXISTS idx_activity_stream_task ON agent_activity_stream(task_id);
CREATE INDEX IF NOT EXISTS idx_activity_stream_session ON agent_activity_stream(session_id);
CREATE INDEX IF NOT EXISTS idx_activity_stream_created ON agent_activity_stream(created_at);
```

**Event types:**

| event_type | When | detail contains | file_path contains |
|-----------|------|-----------------|-------------------|
| `read` | Agent reads a file | File path and line range | Full path |
| `edit` | Agent edits a file | Old/new string summary (truncated) | Full path |
| `write` | Agent creates/overwrites a file | File path | Full path |
| `bash` | Agent runs a command | Command text (truncated to 200 chars) | null |
| `grep` | Agent searches codebase | Search pattern | Search path |
| `glob` | Agent finds files | Glob pattern | Search path |
| `think` | Agent's text output (reasoning) | Truncated text (first 200 chars) | null |
| `error` | Error occurred | Error message | null |
| `tool_other` | Unknown/other tool call | Tool name + summary | null |
| `status_change` | Process started/paused/completed/failed | New status | null |

### 4.4 Schema Relationship Diagram

```
workspace_sessions
    |
    +-- session_phases (1:many)
    |       |
    |       +-- tasks (1:1 per phase, via task_id)
    |       +-- active_processes (1:1 per phase, via process_id)
    |
    +-- agent_activity_stream (1:many, via session_id)

active_processes
    |
    +-- agent_activity_stream (1:many, via process_id)

tasks
    |
    +-- agent_activity_stream (1:many, via task_id)
    +-- active_processes (1:many, existing relationship)
```

---

## 5. API Endpoints

### 5.1 Workspace Session Endpoints

#### `POST /api/workspace/submit`

Submit a new big prompt for digestion.

**Request:**
```json
{
  "title": "Build Clipper Engine Media Pipeline",
  "prompt": "Full prompt text here...",
  "project_id": 5,
  "priority": "high"
}
```

**Response:**
```json
{
  "id": 1,
  "status": "digesting",
  "prompt_chars": 4200,
  "prompt_tokens_est": 1050,
  "message": "Gray is analyzing your project..."
}
```

**What it does:**
1. Insert into `workspace_sessions`
2. Calculate char count, estimate tokens (chars / 4)
3. Create a task for Gray: "Digest workspace session #1: Build Clipper Engine Media Pipeline"
4. Spawn Gray's terminal with instructions to read the prompt and produce a phased plan
5. Broadcast `workspace.submitted`

#### `GET /api/workspace/:id/plan`

Get the generated plan for a session.

**Response:**
```json
{
  "session_id": 1,
  "status": "pending_approval",
  "title": "Build Clipper Engine Media Pipeline",
  "plan_markdown": "## Phase 1: Database Schema\n...",
  "phases": [
    {
      "phase_number": 1,
      "title": "Database Schema & Migrations",
      "description": "Create tables for media assets, processing jobs, and output formats",
      "assigned_member_name": "Anvil",
      "assigned_member_id": 8,
      "complexity": "moderate",
      "depends_on": [],
      "status": "pending"
    },
    {
      "phase_number": 2,
      "title": "Media Upload API",
      "description": "POST /api/media/upload with multer, file validation, S3 storage",
      "assigned_member_name": "Anvil",
      "assigned_member_id": 8,
      "complexity": "complex",
      "depends_on": [1],
      "status": "pending"
    }
  ]
}
```

#### `PUT /api/workspace/:id/plan`

Approve or modify the plan.

**Request:**
```json
{
  "action": "approve",
  "phases": [
    {
      "phase_number": 1,
      "title": "Database Schema & Migrations",
      "description": "Create tables for media assets, processing jobs, and output formats",
      "assigned_member_id": 8,
      "complexity": "moderate",
      "depends_on": []
    }
  ]
}
```

**Actions:**
- `"approve"` — Accept the plan as-is (or with modifications in the `phases` array). Saves phases to `session_phases` table.
- `"redigest"` — Send the plan back to Gray with modification notes for a new version.
- `"cancel"` — Cancel the session entirely.

#### `POST /api/workspace/:id/execute`

Start execution of an approved plan.

**Response:**
```json
{
  "session_id": 1,
  "status": "executing",
  "phases_started": 2,
  "phases_pending": 5,
  "processes": [
    { "phase_id": 1, "process_id": 42, "member_name": "Anvil" },
    { "phase_id": 3, "process_id": 43, "member_name": "Lumen" }
  ]
}
```

**What it does:**
1. Set session status to `executing`
2. Find all phases with no unmet dependencies
3. For each: create a task, call `spawnMemberTerminal()`, update phase with `task_id` and `process_id`
4. Broadcast `workspace.executing`

#### `GET /api/workspace/:id/status`

Get current status of the session, all phases, and all running agents.

**Response:**
```json
{
  "session": {
    "id": 1,
    "title": "Build Clipper Engine Media Pipeline",
    "status": "executing",
    "created_at": "2026-03-29T10:00:00",
    "started_at": "2026-03-29T10:05:00",
    "last_viewed_at": "2026-03-29T14:00:00"
  },
  "phases": [
    {
      "id": 1,
      "phase_number": 1,
      "title": "Database Schema",
      "status": "completed",
      "assigned_member_name": "Anvil",
      "completed_at": "2026-03-29T10:18:00"
    },
    {
      "id": 2,
      "phase_number": 2,
      "title": "Media Upload API",
      "status": "running",
      "assigned_member_name": "Anvil",
      "task_progress": 45,
      "task_step": "Anvil: Editing server.js...",
      "started_at": "2026-03-29T10:18:00"
    }
  ],
  "active_agents": [
    {
      "process_id": 42,
      "member_name": "Anvil",
      "member_role": "Backend Developer",
      "member_id": 8,
      "task_title": "Media Upload API",
      "progress": 45,
      "current_step": "Editing server.js...",
      "started_at": "2026-03-29T10:18:00",
      "files_touched": ["server.js", "media-routes.js"],
      "event_counts": { "reads": 8, "edits": 3, "commands": 1 }
    }
  ],
  "summary_since_last_visit": {
    "hours_away": 4,
    "phases_completed": 1,
    "phases_started": 1,
    "files_modified": 6,
    "events_total": 34,
    "highlights": [
      "Phase 1 (Database Schema) completed by Anvil in 13 minutes",
      "Phase 2 (Media Upload API) started — currently 45% complete"
    ]
  }
}
```

#### `GET /api/workspace/active`

Get all active workspace sessions.

**Response:**
```json
{
  "sessions": [
    {
      "id": 1,
      "title": "Build Clipper Engine Media Pipeline",
      "status": "executing",
      "project_name": "Clipper Engine",
      "phases_total": 7,
      "phases_completed": 3,
      "phases_running": 2,
      "agents_active": 2,
      "created_at": "2026-03-29T10:00:00"
    }
  ],
  "standalone_agents": [
    {
      "process_id": 99,
      "member_name": "Hone",
      "task_title": "Fix button spacing on dashboard",
      "progress": 70,
      "current_step": "Editing styles.css...",
      "started_at": "2026-03-29T15:30:00"
    }
  ]
}
```

**Note:** `standalone_agents` are active processes NOT linked to any workspace session — regular tasks spawned from Mission Control or auto-queue. They still show up in the agent grid.

#### `POST /api/workspace/:id/pause`

Pause a workspace session. Kills all running processes for that session.

#### `POST /api/workspace/:id/resume`

Resume a paused session. Re-spawns terminals for phases that were in progress.

#### `POST /api/workspace/:id/cancel`

Cancel a session. Kills all processes, marks all pending phases as cancelled.

### 5.2 Agent Activity Stream Endpoint

#### `GET /api/agent-stream/:processId`

Get the activity stream for a specific agent process.

**Query params:**
- `since` — ISO timestamp, return events after this time (for incremental updates)
- `limit` — max events to return (default 50, max 500)

**Response:**
```json
{
  "process_id": 42,
  "member_name": "Anvil",
  "task_title": "Media Upload API",
  "events": [
    {
      "id": 1001,
      "event_type": "read",
      "file_name": "server.js",
      "file_path": "/Users/maxstewart/Desktop/The Team/app/server.js",
      "detail": "Reading lines 1-100",
      "line_info": "1-100",
      "created_at": "2026-03-29T10:18:05"
    },
    {
      "id": 1002,
      "event_type": "edit",
      "file_name": "server.js",
      "file_path": "/Users/maxstewart/Desktop/The Team/app/server.js",
      "detail": "Added saveActivityEvent function",
      "line_info": "5567",
      "created_at": "2026-03-29T10:18:12"
    }
  ],
  "files_touched": ["server.js", "media-routes.js"],
  "event_counts": { "read": 8, "edit": 3, "write": 1, "bash": 2, "think": 5 }
}
```

#### `GET /api/agent-stream/summary/:processId`

Get a condensed summary of an agent's activity (for the card view).

**Response:**
```json
{
  "process_id": 42,
  "total_events": 34,
  "files_touched": ["server.js", "media-routes.js", "types.ts"],
  "event_counts": { "read": 12, "edit": 5, "write": 2, "bash": 3, "think": 10, "error": 0 },
  "latest_event": {
    "event_type": "edit",
    "file_name": "server.js",
    "detail": "Adding multer upload handler",
    "created_at": "2026-03-29T10:42:31"
  },
  "duration_seconds": 1466
}
```

---

## 6. Frontend Components

### 6.1 Component Tree

```
renderWorkspace(container)
├── renderWorkspaceHeader()
├── renderSessionSummaryBar(session)          // "Since you left..." summary
├── renderSubmitPromptModal()                 // Modal for new project submission
├── renderPlanView(session)                   // Plan approval UI
├── renderAgentGrid(processes, phases)        // Grid of all running agents
│   └── renderAgentCard(process)              // Single agent card
│       └── renderAgentActivityLog(events)    // Expanded activity log
├── renderPhaseTimeline(phases)               // Sidebar showing phase progression
└── renderSessionList(sessions)               // List of all workspace sessions
```

### 6.2 `renderWorkspace(container)` — Main Page

The top-level renderer. Determines what to show based on current state:

```
if (no active sessions && no standalone agents):
    Show empty state + "Start a Project" button

if (active session in 'digesting' status):
    Show digestion spinner

if (active session in 'pending_approval' status):
    Show plan approval view

if (active session in 'executing' status):
    Show agent grid + phase timeline + summary bar (if returning)

if (standalone agents running but no session):
    Show agent grid only (these are regular tasks from Mission Control)

Always show "Session History" section at the bottom (collapsed)
```

**Navigation:** Added as a new top-level nav item in the sidebar, between "Mission" and "Tasks":

```html
<a href="#workspace" class="nav-item" data-page="workspace">
  <svg><!-- grid/terminal icon --></svg>
  <span class="nav-label">Workspace</span>
</a>
```

**Tabs within the workspace page:**

```
[Live Agents]  [Sessions]  [Submit New]
```

- **Live Agents** (default): The agent grid showing all currently running processes
- **Sessions**: List of all workspace sessions (active, completed, cancelled)
- **Submit New**: The prompt submission form

### 6.3 `renderAgentCard(process)` — Single Agent Card

Builds on the existing `monitorRenderProcessCard()` pattern but with richer data.

**Data sources:**
- `active_processes` table (process_id, pid, status, started_at)
- `tasks` table (title, progress, current_step)
- `team_members` table (name, role, member_id for avatar color)
- `agent_activity_stream` (aggregated: files_touched, event_counts, recent_events)

**Card HTML structure:**
```
.agent-card[data-process-id]
  .agent-card-header
    .agent-avatar (colored circle with initial)
    .agent-name-role
      .agent-name ("Anvil")
      .agent-role ("Backend Developer")
    .agent-status-dot (green pulsing = running, etc.)
  .agent-card-task
    .agent-task-title ("Add WebSocket endpoint for activity stream")
    .agent-project-tag (colored pill, e.g., "Clipper Engine")
  .agent-card-step
    .agent-step-icon (file/terminal/search icon based on event_type)
    .agent-step-text ("Editing server.js: adding saveActivityEvent call...")
  .agent-progress-bar
    .progress-fill (width based on progress %)
    .progress-text ("65%")
  .agent-card-meta
    .agent-elapsed ("4m 32s")
    .agent-files-touched ("3 files")
  .agent-card-files (collapsed by default)
    .agent-file-item ("server.js", "types.ts", "media-routes.js")
  .agent-card-actions
    button.agent-pause ("Pause")
    button.agent-cancel ("Cancel")
  .agent-card-log (collapsed by default, toggled by "Expand Log" button)
    button.agent-log-toggle ("Expand Log")
    .agent-log-events
      .agent-log-event (one per activity event)
```

### 6.4 `renderAgentGrid(processes)` — Agent Grid

A CSS Grid layout that arranges agent cards responsively:

```css
.agent-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
  gap: 16px;
  padding: 16px 0;
}
```

- 1 column on mobile
- 2 columns on tablet
- 3 columns on desktop
- 4+ columns on wide screens

### 6.5 `renderPlanView(session)` — Plan Approval UI

Shows the plan generated by Gray, rendered as interactive cards.

```
.plan-view
  .plan-header
    .plan-title ("Build Clipper Engine Media Pipeline")
    .plan-stats ("7 phases, ~45 minutes estimated")
  .plan-phases
    .plan-phase-card[data-phase=1]
      .plan-phase-number ("1")
      .plan-phase-content
        input.plan-phase-title ("Database Schema & Migrations")
        textarea.plan-phase-description ("Create tables for media assets...")
      .plan-phase-meta
        .plan-phase-assignee (avatar + name)
        .plan-phase-complexity (pill: "moderate")
        .plan-phase-deps ("Depends on: none")
      .plan-phase-actions
        button.plan-phase-remove ("Remove")
        handle.plan-phase-reorder (drag handle)
  .plan-actions
    button.plan-add-phase ("+ Add Phase")
    button.plan-redigest ("Send Back to Gray")
    button.plan-execute ("Execute Plan")
```

**Interaction:**
- Phase cards are drag-reorderable (HTML5 drag-and-drop, no library needed)
- Title and description are inline-editable (contentEditable or input fields)
- Assigned member is a dropdown of available team members
- Dependencies are shown as selectable checkboxes of other phases
- "Execute Plan" triggers `POST /api/workspace/:id/execute`

### 6.6 `renderSessionSummary(session)` — Return Summary

Shown at the top of the workspace when Max returns after being away.

```
.session-summary-bar
  .summary-icon (info icon)
  .summary-text
    "Since you left (6 hours ago): 3 phases completed, 2 running, 14 files modified"
  .summary-details (collapsed, toggleable)
    .summary-phase-list
      "Phase 1: Database Schema — completed by Anvil (13 min)"
      "Phase 2: Media Upload API — completed by Anvil (22 min)"
      "Phase 3: Docker Config — FAILED (Bastion: build error) [Retry]"
      "Phase 4: Frontend Grid — running (Spark, 45%)"
  .summary-dismiss (X button to close)
```

### 6.7 `renderSubmitPromptModal()` — Project Submission

A modal (or full-page form in the "Submit New" tab) for submitting a big prompt.

```
.submit-workspace
  .submit-header
    h2 "Submit a New Project"
    p "Describe what you want built. Gray will break it into phases."
  .submit-form
    input.submit-title (placeholder: "Project title")
    textarea.submit-prompt (placeholder: "Describe the full project...")
      .submit-char-count ("4,200 chars / ~1,050 tokens")
    select.submit-project (dropdown of existing projects + "New Project")
    select.submit-priority (low / normal / high / urgent)
    .submit-upload
      button "Attach Files" (optional file upload)
    button.submit-btn "Submit to Gray"
```

### 6.8 Real-Time Update Handler

In the WebSocket message handler (already exists in app.js), add handlers for workspace events:

```javascript
// Inside the existing WebSocket onmessage handler
case 'agent.activity':
  // Update the specific agent card's step text and activity count
  updateAgentCardActivity(data.process_id, data.event);
  break;

case 'process.progress':
  // Update progress bar and step text for a specific card
  updateAgentCardProgress(data.process_id, data.progress, data.current_step);
  break;

case 'workspace.submitted':
  // If on workspace page, show digestion state
  if (currentPage === 'workspace') refreshWorkspace();
  break;

case 'workspace.plan_ready':
  // If on workspace page, show plan approval view
  if (currentPage === 'workspace') refreshWorkspace();
  break;

case 'workspace.executing':
  // If on workspace page, switch to agent grid view
  if (currentPage === 'workspace') refreshWorkspace();
  break;

case 'workspace.phase_completed':
  // Update phase timeline, check if dependent phases should start
  if (currentPage === 'workspace') refreshWorkspace();
  break;
```

---

## 7. Integration with Existing Auto-Spawn

### 7.1 The Bridge: stdout Parser to Activity Stream

The key integration point is in `spawnMemberTerminal()` at server.js:5567-5674. The stdout parser already extracts tool calls (Read, Edit, Write, Bash, Grep, Glob) and updates `tasks.current_step`. We add a parallel write to `agent_activity_stream`.

**Current code (server.js ~5585):**
```javascript
if (block.type === 'tool_use') {
    toolCallCount++;
    const toolName = block.name || '';
    const input = block.input || {};
    if (toolName === 'Read' || toolName === 'read') {
        fileReadsCount++;
        const fname = (input.file_path || '').split('/').pop() || 'file';
        stepDescription = `Reading ${fname}...`;
    }
    // ... etc
}
```

**What we add — `saveActivityEvent()` call after each tool detection:**
```javascript
if (block.type === 'tool_use') {
    toolCallCount++;
    const toolName = block.name || '';
    const input = block.input || {};

    // ... existing step description logic ...

    // NEW: Save to activity stream
    saveActivityEvent(processId, taskId, memberId, sessionId, {
        event_type: mapToolToEventType(toolName),
        file_path: input.file_path || null,
        file_name: (input.file_path || '').split('/').pop() || null,
        detail: buildEventDetail(toolName, input),
        line_info: input.offset ? `${input.offset}-${(input.offset || 0) + (input.limit || 100)}` : null
    });
}
```

**New helper functions (added to server.js):**

```javascript
function saveActivityEvent(processId, taskId, memberId, sessionId, event) {
    try {
        db.prepare(`
            INSERT INTO agent_activity_stream
            (process_id, task_id, member_id, session_id, event_type, file_path, file_name, detail, line_info, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
            processId, taskId, memberId, sessionId || null,
            event.event_type, event.file_path, event.file_name,
            event.detail, event.line_info, localNow()
        );

        broadcast('agent.activity', {
            process_id: processId,
            task_id: taskId,
            member_id: memberId,
            event: event
        });
    } catch (e) {
        // Don't let activity logging break the main process
        console.error(`[ActivityStream] Failed to save event: ${e.message}`);
    }
}

function mapToolToEventType(toolName) {
    const map = {
        'Read': 'read', 'read': 'read',
        'Edit': 'edit', 'edit': 'edit',
        'Write': 'write', 'write': 'write',
        'Bash': 'bash', 'bash': 'bash',
        'Grep': 'grep', 'grep': 'grep',
        'Glob': 'glob', 'glob': 'glob'
    };
    return map[toolName] || 'tool_other';
}

function buildEventDetail(toolName, input) {
    switch (toolName) {
        case 'Read': case 'read':
            return `Reading ${input.file_path || 'file'}${input.offset ? ` from line ${input.offset}` : ''}`;
        case 'Edit': case 'edit':
            const oldSnippet = (input.old_string || '').slice(0, 60);
            return `Editing ${input.file_path || 'file'}: replacing "${oldSnippet}..."`;
        case 'Write': case 'write':
            return `Writing ${input.file_path || 'file'} (${(input.content || '').length} chars)`;
        case 'Bash': case 'bash':
            return `Running: ${(input.command || '').slice(0, 200)}`;
        case 'Grep': case 'grep':
            return `Searching for: ${input.pattern || '?'} in ${input.path || '.'}`;
        case 'Glob': case 'glob':
            return `Finding files: ${input.pattern || '*'}`;
        default:
            return `Using tool: ${toolName}`;
    }
}
```

### 7.2 Linking Workspace Sessions to Spawned Processes

When `POST /api/workspace/:id/execute` starts phases, it calls `spawnMemberTerminal()` for each phase. The `session_id` is passed through so activity events are tagged with both `process_id` and `session_id`.

**Modified spawn flow:**
1. `POST /api/workspace/:id/execute` creates tasks for each ready phase
2. For each task, call `spawnMemberTerminal(taskId, memberId, { sessionId, phaseId })`
3. `spawnMemberTerminal()` passes `sessionId` to `saveActivityEvent()` calls
4. When a process completes, check if dependent phases are now unblocked
5. Auto-start newly unblocked phases

### 7.3 Standalone Agents (Non-Session)

Agents spawned from Mission Control, auto-queue, or other trigger points still work exactly as before. They show up in the workspace agent grid as "standalone agents" — no session, no phase timeline, just the live card.

The `saveActivityEvent()` call is added to ALL spawn paths, not just workspace sessions. This means:
- Every agent gets an activity stream, whether it's part of a workspace session or not
- The workspace "Live Agents" tab shows ALL running agents, grouped as:
  - **Session agents** — grouped under their session, with phase timeline
  - **Standalone agents** — listed separately at the bottom

### 7.4 Phase Dependency Resolution

When a process completes (in the `child.on('close')` handler):

```javascript
// After handleSpawnSuccess()...

// Check if this process was part of a workspace session
const phase = db.prepare(`
    SELECT sp.*, ws.id as session_id
    FROM session_phases sp
    JOIN workspace_sessions ws ON sp.session_id = ws.id
    WHERE sp.process_id = ?
`).get(processId);

if (phase) {
    // Mark phase as completed
    db.prepare(`UPDATE session_phases SET status = 'completed', completed_at = ? WHERE id = ?`)
        .run(finishedAt, phase.id);

    // Check for newly unblocked phases
    const pendingPhases = db.prepare(`
        SELECT * FROM session_phases
        WHERE session_id = ? AND status = 'pending'
    `).all(phase.session_id);

    for (const pending of pendingPhases) {
        const deps = JSON.parse(pending.depends_on || '[]');
        if (deps.length === 0) continue;

        const completedDeps = db.prepare(`
            SELECT COUNT(*) as c FROM session_phases
            WHERE session_id = ? AND phase_number IN (${deps.join(',')}) AND status = 'completed'
        `).get(phase.session_id);

        if (completedDeps.c === deps.length) {
            // All dependencies met — start this phase
            startPhase(phase.session_id, pending.id);
        }
    }

    // Check if all phases are complete
    const remaining = db.prepare(`
        SELECT COUNT(*) as c FROM session_phases
        WHERE session_id = ? AND status NOT IN ('completed', 'skipped', 'cancelled')
    `).get(phase.session_id);

    if (remaining.c === 0) {
        db.prepare(`UPDATE workspace_sessions SET status = 'completed', completed_at = ? WHERE id = ?`)
            .run(finishedAt, phase.session_id);
        broadcast('workspace.completed', { session_id: phase.session_id });
    }
}
```

---

## 8. Implementation Plan

### Phase 1: Agent Activity Stream + Enhanced Agent Grid

**Goal:** Every spawned agent gets a detailed activity stream. The workspace page shows all running agents in a grid with rich cards.

**Deliverables:**
1. Create `agent_activity_stream` table (SQLite migration in server.js startup)
2. Add `saveActivityEvent()`, `mapToolToEventType()`, `buildEventDetail()` helper functions to server.js
3. Wire `saveActivityEvent()` into the stdout parser in `spawnMemberTerminal()` (both `tool_use` block handler and `content_block_start` handler)
4. Add `GET /api/agent-stream/:processId` endpoint
5. Add `GET /api/agent-stream/summary/:processId` endpoint
6. Add `#workspace` page to sidebar nav in index.html
7. Add `case 'workspace'` to `renderPage()` switch in app.js
8. Build `renderWorkspace(container)` with tabs: Live Agents, Sessions, Submit New
9. Build `renderAgentGrid(processes)` — CSS grid layout
10. Build `renderAgentCard(process)` — enhanced card with activity stream
11. Build `renderAgentActivityLog(events)` — expanded log view
12. Add `agent.activity` and `process.progress` WebSocket event handling
13. Add workspace styles to styles.css
14. Wire Pause/Cancel/Retry buttons (reuse existing `_pauseTask`, `_cancelTask`, `_retryTask`)

**Assigned to:**
- Anvil: Items 1-6 (backend: schema, helpers, endpoints)
- Spark: Items 7-12 (frontend: page, grid, cards, WebSocket)
- Lumen: Items 13-14 (CSS styles, button wiring)

**Validation gate:** Spawn an agent from Mission Control. Navigate to `#workspace`. See the agent card with live step updates. Click "Expand Log" and see the activity stream. Refresh page — card still shows current state.

---

### Phase 2: Project Submission + Plan Generation

**Goal:** Max can submit a big prompt from the workspace. Gray digests it and produces a phased plan.

**Deliverables:**
1. Create `workspace_sessions` table (SQLite migration)
2. Create `session_phases` table (SQLite migration)
3. Add `POST /api/workspace/submit` endpoint
4. Add `GET /api/workspace/:id/plan` endpoint
5. Add `GET /api/workspace/active` endpoint (list all sessions + standalone agents)
6. Build the Gray digestion prompt — instructions for reading a big prompt and outputting a JSON plan
7. Wire `spawnMemberTerminal()` to handle the digestion task (Gray reads prompt, outputs plan, saves to session)
8. Build `renderSubmitPromptModal()` — the submission form UI
9. Build digestion state UI (spinner, "Gray is analyzing...")
10. Add `workspace.submitted` and `workspace.plan_ready` WebSocket event handling

**Assigned to:**
- Anvil: Items 1-7 (backend: schema, endpoints, Gray digestion prompt)
- Spark: Items 8-10 (frontend: submission form, digestion state)

**Validation gate:** Submit a prompt from the workspace. See "Gray is analyzing..." spinner. After Gray completes, see the plan appear.

---

### Phase 3: Plan Approval UI + Phase Execution

**Goal:** Max can review, edit, and approve the plan. Execution spawns agents in dependency order.

**Deliverables:**
1. Add `PUT /api/workspace/:id/plan` endpoint (approve/modify/redigest)
2. Add `POST /api/workspace/:id/execute` endpoint
3. Add phase dependency resolution logic (start blocked phases when deps complete)
4. Wire `spawnMemberTerminal()` completion handler to check for dependent phases
5. Build `renderPlanView(session)` — interactive plan editor with drag-reorder
6. Build `renderPhaseTimeline(phases)` — sidebar showing phase progression
7. Wire "Execute Plan" button to start execution
8. Handle phase transitions in the agent grid (new cards appear as phases start)
9. Add `workspace.executing` and `workspace.phase_completed` WebSocket event handling
10. Add `POST /api/workspace/:id/pause` and `POST /api/workspace/:id/resume` endpoints

**Assigned to:**
- Anvil: Items 1-4, 10 (backend: endpoints, dependency resolution)
- Spark: Items 5-9 (frontend: plan editor, phase timeline, execution wiring)

**Validation gate:** Submit a prompt, get a plan, modify it (reorder a phase, remove a phase), click Execute. See agents spawn in correct dependency order. When Phase 1 completes, see Phase 2 (which depends on it) start automatically.

---

### Phase 4: Session Summaries + Overnight Mode

**Goal:** Max checks in and sees what happened while he was away. The system runs unattended.

**Deliverables:**
1. Add `last_viewed_at` tracking — update on each workspace page load
2. Add `GET /api/workspace/:id/summary` endpoint — generates summary between last visit and now
3. Build `renderSessionSummary(session)` — the "since you left" bar
4. Add summary generation logic (query `agent_activity_stream` for event counts, completed phases, files changed)
5. Add session history view — list of all past sessions with outcomes
6. Add overnight reliability hardening:
   - Process watchdog (detect stuck/zombie processes)
   - Auto-retry failed phases (configurable, default: 1 retry)
   - Session timeout (configurable, default: 8 hours for a full session)
7. Add notification integration — create notifications for: session completed, phase failed, plan ready for review
8. Build `renderSessionList(sessions)` — browsable history of all workspace sessions

**Assigned to:**
- Anvil: Items 1-2, 6-7 (backend: tracking, summary, reliability, notifications)
- Spark: Items 3, 5, 8 (frontend: summary bar, session list)
- Atlas: Item 4 (summary generation logic design)

**Validation gate:** Start a workspace session with 3+ phases. Close the browser. Wait for at least one phase to complete. Reopen the browser, navigate to workspace. See the summary bar: "Since you left (X minutes ago): 1 phase completed, 1 running, 5 files modified." Click "Details" and see per-phase breakdown.

---

### Dependencies Between Phases

```
Phase 1 (Activity Stream + Grid)
    |
    +-- Phase 2 (Submission + Plan Gen)
    |       |
    |       +-- Phase 3 (Plan Approval + Execution)
    |
    +-- Phase 4 (Summaries + Overnight)
```

Phase 1 is the foundation. Phases 2 and 4 can technically run in parallel after Phase 1. Phase 3 depends on Phase 2.

**Recommended order:** 1 -> 2 -> 3 -> 4

**Estimated timeline:**
- Phase 1: 1 session (Anvil + Spark + Lumen in parallel)
- Phase 2: 1 session (Anvil + Spark in parallel)
- Phase 3: 1 session (Anvil + Spark in parallel)
- Phase 4: 1 session (Anvil + Spark in parallel)

---

## Appendix A: File Touch Map

Files that will be modified or created in this feature:

| File | Phase | What Changes |
|------|-------|-------------|
| `app/server.js` | 1, 2, 3, 4 | New tables, `saveActivityEvent()`, workspace API endpoints, phase dependency resolution |
| `app/public/app.js` | 1, 2, 3, 4 | `renderWorkspace()` and all sub-components, WebSocket handlers |
| `app/public/index.html` | 1 | New nav item for `#workspace` |
| `app/public/styles.css` | 1, 3 | Agent card styles, grid layout, plan view styles, summary bar |

**No new files needed.** Everything goes into the existing server.js, app.js, index.html, and styles.css — consistent with the project's single-file architecture.

## Appendix B: Data Flow Diagram

```
Max submits prompt
    |
    v
POST /api/workspace/submit
    |
    v
workspace_sessions row created (status: digesting)
    |
    v
spawnMemberTerminal() for Gray (digestion task)
    |
    v
Gray reads prompt, generates plan JSON
    |
    v
Plan saved to workspace_sessions.plan_json
Session status -> pending_approval
broadcast('workspace.plan_ready')
    |
    v
Max reviews plan on #workspace page
    |
    v
PUT /api/workspace/:id/plan (action: approve)
    |
    v
session_phases rows created
    |
    v
POST /api/workspace/:id/execute
    |
    v
For each phase with no deps:
    Create task -> spawnMemberTerminal()
    |
    v
Agent runs, stdout parsed:
    -> tasks.progress updated
    -> tasks.current_step updated
    -> agent_activity_stream rows inserted
    -> broadcast('agent.activity')
    -> broadcast('task.updated')
    |
    v
Agent completes:
    -> active_processes.status = 'completed'
    -> session_phases.status = 'completed'
    -> Check dependent phases -> start if unblocked
    -> broadcast('workspace.phase_completed')
    |
    v
All phases complete:
    -> workspace_sessions.status = 'completed'
    -> broadcast('workspace.completed')
    -> Notification created
```

## Appendix C: Existing Code Reference Points

These are the exact locations implementers need to read before writing code:

| What | File | Line(s) | Why |
|------|------|---------|-----|
| `spawnMemberTerminal()` function | `server.js` | 5285-5763 | The core spawn function — activity stream hooks go here |
| stdout JSON parser (tool_use) | `server.js` | 5575-5643 | Where `saveActivityEvent()` calls will be inserted |
| `handleSpawnSuccess()` | `server.js` | 5788-5820 | Where phase completion check goes |
| `broadcast()` | `server.js` | 7701-7708 | WebSocket push — add new event types |
| `renderPage()` switch | `app.js` | 869-894 | Add `case 'workspace'` |
| `monitorRenderProcessCard()` | `app.js` | 2501-2550 | Pattern to follow for `renderAgentCard()` |
| `monitorRenderTaskCard()` | `app.js` | 2418-2499 | Pattern for card with progress, pause/cancel, log |
| `monitorRefreshData()` | `app.js` | 2620-2820 | Pattern for WebSocket + polling hybrid refresh |
| WebSocket message handler | `app.js` | ~600-790 | Where to add workspace event handlers |
| Nav sidebar | `index.html` | 60-145 | Where to add the workspace nav item |
| `active_processes` schema | SQLite | N/A | Existing table — `agent_activity_stream` references it |
