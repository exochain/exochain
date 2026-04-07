# Plan: Dual Execution Mode — Terminal vs 24/7 Autonomous

**Planned by:** Atlas (Systems Architect) + Gray (Orchestrator)
**Reviewed by:** Gray
**Status:** Ready for Max's approval

---

## Context

Max needs two execution modes:
1. **Terminal Mode** (primary, default) — Claude Code in the terminal. Current system. Must never break.
2. **24/7 Autonomous Mode** — Background worker executes tasks without a terminal open.

Max's constraint: No raw API key usage (credits run out fast). Use OAuth/subscription auth instead.

---

## Authentication Strategy: OAuth via Claude Code CLI

**Key finding:** The Claude Code CLI (`claude -p "prompt"`) can run non-interactively and authenticates via OAuth tokens from Max's Claude subscription. This means:
- No API key needed
- Uses Max's existing subscription (rate-limited by tier, not billed per token)
- Same auth as the terminal version

**How it works:**
1. Max runs `claude setup-token` once on his machine to extract the OAuth token
2. The token gets stored in the database (encrypted/masked in UI)
3. The Docker worker passes it as `CLAUDE_CODE_OAUTH_TOKEN` env var
4. The worker spawns `claude -p "task prompt" --output-format json` processes
5. Max's subscription handles the throughput

---

## Architecture

### Core Principle: Same Queue, Different Workers

Both modes read/write the same database. They don't interact directly. Swapping modes = toggling which worker is active.

```
Browser (Mission Control)
    ↓ writes tasks
Database (the_team.db)
    ↓ reads tasks
┌─────────────────┐    ┌─────────────────────┐
│  Terminal Mode   │ OR │  Autonomous Mode     │
│  (Claude Code    │    │  (Docker worker runs │
│   in terminal)   │    │   claude -p CLI)     │
└─────────────────┘    └─────────────────────┘
    ↓ writes results        ↓ writes results
Database + Outbox (same destination)
```

### Database Changes

```sql
-- System settings (execution mode, auth, model preferences)
CREATE TABLE system_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now', 'localtime'))
);

-- Seeds
INSERT INTO system_settings VALUES
    ('execution_mode', 'terminal'),        -- global default
    ('oauth_token', ''),                    -- Claude OAuth token for autonomous mode
    ('autonomous_model', 'sonnet'),         -- default model
    ('autonomous_model_complex', 'opus'),   -- model for complex/in-depth work
    ('worker_status', 'stopped');           -- stopped/running

-- Per-member mode override
ALTER TABLE team_members ADD COLUMN execution_mode TEXT DEFAULT 'system'
    CHECK(execution_mode IN ('system', 'terminal', 'autonomous'));
-- 'system' = follow the global setting
-- 'terminal' = always terminal regardless of global
-- 'autonomous' = always autonomous regardless of global
```

### Docker Services

```yaml
services:
  dashboard:
    # EXISTING — unchanged
    build: ./app
    container_name: the-team
    ports: ["3000:3000"]
    volumes: [".:/data/project"]
    environment: [DB_PATH, INBOX_PATH, OUTBOX_PATH]
    restart: unless-stopped

  worker:
    # NEW — autonomous execution worker
    build: ./worker
    container_name: the-team-worker
    volumes: [".:/data/project"]  # same mount = same DB
    environment:
      - DB_PATH=/data/project/the_team.db
      - INBOX_PATH=/data/project/Teams inbox:Result
      - OUTBOX_PATH=/data/project/Stew's inbox:Owner
    profiles: ["autonomous"]  # does NOT start by default
    restart: unless-stopped
```

Using Docker Compose `profiles` means `docker compose up -d` only starts the dashboard. The worker requires `docker compose --profile autonomous up -d worker` to start. The dashboard server controls this via Docker API or shell commands.

### Worker Process (`/worker/`)

```
worker/
├── Dockerfile          — node:20 + Claude Code CLI installed
├── package.json        — better-sqlite3 (same as dashboard)
├── index.js            — main polling loop
├── executor.js         — spawns claude -p with task context
└── profiles.js         — reads team member profiles + tools
```

**Polling loop (index.js):**
```
Every 10 seconds:
1. Read system_settings → is autonomous mode active?
2. If not → sleep
3. Find tasks: status = 'new' AND eligible for autonomous processing
   (system mode = autonomous, OR assigned member mode = autonomous)
4. For each task:
   a. Lock it (status → 'routing')
   b. Determine which team member handles it
   c. Read member profile + tools
   d. Build prompt with full context
   e. Choose model (sonnet default, opus for complex tasks based on priority)
   f. Spawn: claude -p "prompt" --output-format json --model {model}
   g. Parse output
   h. Quality review: spawn another claude -p as Gray to review
   i. If passes → deliver (status → 'delivered', write to outbox, notify)
   j. If fails → log issues, revise, loop back to (f)
```

**Model selection logic:**
- Priority urgent/high + description > 500 chars → Opus
- Everything else → Sonnet
- Configurable in system_settings

---

## Browser UI Changes

### 1. First-Load Mode Popup
Full-screen overlay on first visit (or when `execution_mode` is unset):

```
┌─────────────────────────────────────────────────────┐
│              How should Gray work?                    │
│                                                       │
│  ┌──────────────┐     ┌──────────────────┐           │
│  │  🖥 Terminal  │     │  ☁️  24/7 Auto    │           │
│  │              │     │                  │           │
│  │ Claude Code  │     │ Background worker│           │
│  │ in terminal  │     │ runs 24/7 in     │           │
│  │              │     │ Docker           │           │
│  │ [Status: ?]  │     │ [Status: ?]      │           │
│  └──────────────┘     └──────────────────┘           │
│                                                       │
│  □ Remember my choice                                 │
└─────────────────────────────────────────────────────┘
```

### 2. Sidebar Mode Indicator
Below the logo:
```
┌─────────────┐
│ T  The Team  │
│ ● Terminal   │  ← green dot = active, red = inactive
│   Mode  ▾    │  ← click to switch
└─────────────┘
```

### 3. Settings Page — Execution Mode Section
Top of Settings page, above Integrations:
- Global mode toggle: Terminal / Autonomous
- OAuth token input (masked, with show/hide)
- "Run `claude setup-token` in terminal to get your token" instruction
- Model preference: Sonnet (default) / Opus (complex tasks)
- Worker status: Running/Stopped + Start/Stop buttons
- Per-member overrides in each team member card

### 4. Validation & Safety
- Terminal mode + no terminal → "Terminal required — open Claude Code"
- Autonomous mode + no OAuth token → blocks activation
- Autonomous mode + worker stopped → "Start the worker from Settings"
- NEVER auto-switch modes
- Default is ALWAYS terminal

---

## Implementation Phases

### Phase 1: Database + Settings API (zero risk)
- Create system_settings table
- Add execution_mode column to team_members
- Server endpoints for settings CRUD
- Terminal heartbeat endpoint
- **Risk: None. Just adds new tables and endpoints.**

### Phase 2: Browser UI — Mode Selection (zero risk)
- First-load popup
- Sidebar mode indicator
- Execution Mode section in Settings
- Per-member mode toggles
- **Risk: None. Just adds UI elements.**

### Phase 3: Worker Service (isolated, opt-in)
- Build /worker/ directory
- Dockerfile with Claude Code CLI
- Polling loop + executor
- Docker Compose profile
- Dashboard worker controls
- **Risk: Contained. Worker is a separate service that doesn't start by default.**

### Phase 4: Testing + Verification
- Rivet tests both modes
- Verify terminal mode unaffected
- Test mode switching
- Test worker start/stop
- **Risk: None. Just testing.**

---

## Safety Guardrails (Non-Negotiable)

1. Terminal mode is the default. Always.
2. No auto-switching between modes. Ever.
3. Worker does NOT start by default. Must be explicitly started.
4. Worker only processes tasks eligible for autonomous mode.
5. All autonomous work logged with actor "Worker-{MemberName}" for clear distinction.
6. If autonomous mode fails, show error — don't fall back to terminal.
7. Per-member modes respected — terminal members' tasks are never touched by the worker.
8. OAuth token stored in database, masked in UI, never logged.

---

## What Max Needs To Do (One-Time Setup for Autonomous Mode)

1. Run `claude setup-token` in terminal
2. Copy the token
3. Paste it in Settings → Execution Mode → OAuth Token field
4. Start the worker
5. Done

---

## Decision: Approved to proceed?

Phase 1 and 2 can be built immediately with zero risk to the current system. Phase 3 requires the OAuth token setup. All phases are independently deployable — any phase can be rolled back without affecting others.
