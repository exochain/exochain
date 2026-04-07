The file doesn't exist yet and I need Write permission to create it. The Write and Bash tools were both denied. Let me explain this to you, Max.

I completed the full deep audit of Paperclip-1 but I cannot save the report file because both Write and Bash permissions were denied when I tried to create `/Users/maxstewart/Desktop/The Team/.claude/research/paperclip-1-deep-audit.md`. 

The directory exists (there are other research files there), but creating a new file requires either the Write tool or Bash's `echo`/`cat` redirect. Could you grant permission so I can save the report? Alternatively, I can deliver the full audit right here in the conversation.

In the meantime, here is the complete audit report:

---

# Paperclip-1 Deep Audit Report

**Author:** Pax (Senior Researcher)  
**Date:** 2026-03-29  
**Repo:** `/Users/maxstewart/Desktop/The Team/repos/paperclip-1/`  
**Source:** https://github.com/paperclipai/paperclip (forked)

---

## 1. Architecture Overview -- What Paperclip IS

Paperclip is an **open-source orchestration platform for AI-agent companies**. It is NOT an agent framework -- it does not tell you how to build agents. It is the **control plane** that organizes agents into companies with org charts, goals, budgets, governance, and accountability.

**Core metaphor:** "If OpenClaw is an employee, Paperclip is the company."

### The Two-Layer Architecture

```
Layer 1: Control Plane (Paperclip itself)
  - Express REST API + WebSocket realtime events
  - React + Vite dashboard UI
  - PostgreSQL via Drizzle ORM (embedded PGlite for zero-config dev)
  - Heartbeat scheduler, cron, budget enforcement
  - Plugin system with SDK

Layer 2: Execution Services (Adapters)
  - Agents run EXTERNALLY and report into the control plane
  - 10 adapter types: claude_local, codex_local, cursor, gemini_local,
    opencode_local, pi_local, hermes_local, openclaw_gateway, process, http
  - Each adapter: server module + UI module + CLI module
  - Session persistence across heartbeats
```

### Key Technical Stack

| Component | Technology |
|-----------|-----------|
| Backend | Node.js + Express + TypeScript |
| Database | PostgreSQL (Drizzle ORM), embedded PGlite for dev |
| Frontend | React 19 + Vite + Tailwind CSS v4 + shadcn/ui + Radix UI |
| Realtime | WebSocket (ws library) |
| Auth | Better Auth (session-based), JWT for agents |
| Package manager | pnpm workspaces (monorepo) |
| Testing | Vitest (unit), Playwright (e2e), Promptfoo (evals) |
| Container | Docker, docker-compose |
| Deployment | Self-hosted (local or Docker) |

---

## 2. Leadership / Agent Structure

### How Agents Are Defined

Agents in Paperclip are database records, NOT code files. Each agent has:

- **Identity:** name, role, title, icon, capabilities description
- **Org position:** reports_to (creates a strict tree), company_id
- **Adapter:** adapter_type + adapter_config (how this agent runs)
- **Budget:** monthly budget in cents, spent tracking, auto-pause at 100%
- **Status:** active, paused, idle, running, error, terminated
- **Runtime config:** heartbeat interval, wake-on-demand settings

**Key files:**
- `/server/src/services/agents.ts` -- agent CRUD and lifecycle (23K)
- `/server/src/services/heartbeat.ts` -- heartbeat orchestration (135K -- largest service)
- `/packages/db/src/schema/agents.ts` -- agent schema

### The Hierarchy

Paperclip uses a **strict org tree** (single reports_to chain, no multi-manager). Default setup:

1. **Board** (human operator) -- top authority, can override anything
2. **CEO** agent -- strategic direction, delegation, hiring
3. **CTO, CMO, etc.** -- department heads
4. **Engineers, marketers, etc.** -- individual contributors

The CEO is special -- gets three defining files:
- `SOUL.md` -- personality and voice (direct, CEO mindset, no filler)
- `HEARTBEAT.md` -- 8-step execution checklist per heartbeat
- `AGENTS.md` -- delegation rules (CEO must NEVER do IC work)

### How Agents Communicate

Communication is **task/comment-based only**. No separate chat system. All communication through:

1. **Issues** (tasks) -- core work unit with status workflow
2. **Comments** on issues -- threaded conversation
3. **@-mentions** in comments -- trigger heartbeat wakes for mentioned agents
4. **Approvals** -- governance gates requiring board sign-off

### How Work Is Delegated

1. CEO/manager creates issues with parentId linking to parent goals
2. Issues have single assigneeAgentId with **atomic checkout**
3. Agent must `POST /api/issues/{id}/checkout` before working (409 if taken by another)
4. Heartbeats are scheduled OR event-triggered (task assignment, @-mention, approval)
5. Escalation via chainOfCommand -- agents escalate to their manager

### Multi-Agent Coordination

- **Atomic checkout** prevents double-work
- **Goal hierarchy** -- all tasks trace to company goal (company -> team -> agent -> task)
- **Budget enforcement** -- per-agent monthly limits with hard stops
- **Session persistence** -- agents resume context across heartbeats via adapter session codecs
- **Wake-on-demand** -- event-based triggers beyond scheduled intervals

---

## 3. Infrastructure

### Server Architecture

**Main entry:** `/server/src/index.ts` (28K) -- boots Express, embedded Postgres, WebSocket, cron scheduler

**66 service files** in `/server/src/services/`. The largest:

| Service | Purpose | Lines |
|---------|---------|-------|
| `heartbeat.ts` | Core heartbeat orchestration | 135K |
| `company-portability.ts` | Import/export entire companies | 165K |
| `company-skills.ts` | Skill management and injection | 82K |
| `plugin-loader.ts` | Plugin system runtime | 70K |
| `issues.ts` | Task lifecycle, checkout, status | 65K |
| `workspace-runtime.ts` | Workspace/worktree management | 52K |
| `routines.ts` | Scheduled routines | 48K |
| `plugin-worker-manager.ts` | Plugin worker processes | 41K |
| `budgets.ts` | Budget tracking and enforcement | 32K |

**25 route files** in `/server/src/routes/`. Largest: access (93K), agents (79K), plugins (74K), issues (58K).

### Database Setup

- **57 schema tables** in `/packages/db/src/schema/`
- Core: companies, agents, issues, goals, projects, approvals, heartbeat_runs, cost_events, activity_log
- Auth: managed by Better Auth library
- Plugin: plugin_config, plugin_state, plugin_jobs, plugin_logs, plugin_entities, plugin_webhooks
- Budget: budget_policies, budget_incidents
- Workspace: execution_workspaces, workspace_operations, workspace_runtime_services

**Key data model decisions:**
- Everything is company-scoped (multi-company isolation)
- Single assignee per issue (atomic checkout)
- Issues have parent/child hierarchy for goal alignment
- Agent API keys hashed at rest
- Cost events tracked per agent per run
- Activity log for all mutations

### Deployment Model

Three modes:
1. **Local dev:** Embedded PGlite, `pnpm dev`, fully automatic
2. **Docker:** docker-compose with Postgres 17 + server container
3. **Production:** Hosted Postgres (Supabase, etc.)

Two deployment modes:
- `local_trusted` -- no login, implicit board access
- `authenticated` -- Better Auth sessions, private/public exposure

---

## 4. Skills System

### How Skills Are Defined

Skills are **markdown files with YAML frontmatter**:

```
skills/<skill-name>/
  SKILL.md           -- Frontmatter (name, description) + instructions
  references/        -- Supporting reference docs
```

### Skills Inventory

| Skill | Purpose |
|-------|---------|
| `paperclip` | Core heartbeat procedure, API reference, coordination rules |
| `paperclip-create-agent` | Governance-aware agent hiring workflow |
| `paperclip-create-plugin` | Plugin authoring guide |
| `para-memory-files` | PARA-method file-based memory system |
| `design-guide` | UI design system and component guide |
| `company-creator` | Create agent company packages from scratch or repos |
| `doc-maintenance` | Automated documentation drift detection |
| `pr-report` | Deep PR review and report generation |
| `release` | Release coordination workflow |
| `create-agent-adapter` | Guide for creating new adapters |

### How Skills Are Injected

Per-adapter injection (never pollutes the agent's working directory):
1. **claude_local:** Temp dir with `.claude/skills/` symlinks, passed via `--add-dir`
2. **codex_local:** Symlinks into `$CODEX_HOME/skills`
3. **Others:** Env var or prompt injection as fallback

Skills are on-demand procedures -- agent sees metadata, loads full content only when invoked.

---

## 5. CLI / Automation

The CLI (`/cli/`) is comprehensive:

**Setup:** `onboard`, `configure`, `doctor`, `run`
**Client:** `issue list/create/update`, `agent list/get`, `approval approve/reject`, `dashboard get`
**Company:** `company import/export/delete`
**Workspace:** `worktree init`, `worktree:make`, `worktree env`
**Infrastructure:** `db:backup`, `heartbeat run`, `env`, `allowed-hostname`

**25 automation scripts** in `/scripts/` covering dev, release, smoke testing, and asset generation.

---

## 6. UI Architecture

- **React 19 + Vite + Tailwind CSS v4 + shadcn/ui + Radix UI**
- **39 pages** covering dashboard, agents, issues, projects, goals, approvals, costs, org chart, plugins, routines, design guide
- **84 components** -- StatusBadge, EntityRow, MetricCard, KanbanBoard, CommandPalette, LiveRunWidget, etc.
- **WebSocket real-time** events for live updates
- **Three-zone layout:** sidebar (w-60) + main content (flex-1) + properties panel (w-80)
- **Living design guide** at `/design-guide` with all components and patterns

---

## 7. Evaluation System

**Promptfoo-based** behavior evals testing 8 core scenarios across 4 models (Claude Sonnet 4, GPT-4.1, Codex 5.4, Gemini 2.5 Pro). Tests: assignment pickup, progress updates, blocked reporting, approval governance, company boundaries, clean exit, checkout enforcement, 409 handling.

Planned phases: TypeScript harness -> pairwise scoring -> efficiency metrics -> production-case ingestion.

---

## 8. Key Systems to Adopt -- Ranked by Value

### Rank 1: Heartbeat System (HIGH)

Scheduled agent wake/sleep cycles with event triggers, session persistence, budget enforcement. Would give The Team's agents autonomous operation. Port the 9-step heartbeat procedure from `skills/paperclip/SKILL.md`.

### Rank 2: Skill System (HIGH)

SKILL.md format with frontmatter + references directories. Cleaner and more scalable than putting everything in CLAUDE.md. Skills as loaded procedures, not prompt bloat.

### Rank 3: Adapter Architecture (HIGH)

Three-consumer pattern (server + UI + CLI) with `AdapterExecutionContext -> AdapterExecutionResult` contract. Would let The Team support multiple agent runtimes.

### Rank 4: Goal Hierarchy (MEDIUM-HIGH)

Every task traces to company goal. Agents always know WHY. Add goals table, link tasks to goals, inject context.

### Rank 5: Company Portability (MEDIUM)

Export/import entire companies as packages. Could enable template-based team creation.

### Rank 6: Governance/Approvals (MEDIUM)

Structured approval workflow beyond The Team's current constitutional invariants.

### Rank 7: Eval System (MEDIUM)

Promptfoo behavior testing. Worth adopting when The Team needs to verify agent consistency.

### Rank 8-9: Plugin System, Worktree Management (LOW for now)

Complex systems not needed at current scale.

---

## 9. What to Skip

- **Plugin system** -- 250K+ lines of complexity, not needed yet
- **OpenClaw integration** -- specific to OpenClaw agents
- **NPM publishing** -- The Team is not distributable
- **Multi-company isolation** -- single organization
- **Mintlify docs site** -- different doc approach
- **Board claim/invite flow** -- different auth model

---

## 10. Specific Patterns to Port

### 1. Heartbeat Procedure (9-step from SKILL.md)
Identity -> Approval follow-up -> Get assignments -> Pick work -> Checkout -> Context -> Work -> Update -> Delegate

### 2. CEO Delegation Model (SOUL.md + HEARTBEAT.md + AGENTS.md)
Three-file decomposition for agent personas -- cleaner than one massive CLAUDE.md.

### 3. Atomic Checkout Semantics
`POST /checkout` with 409 on conflict prevents double-work. Implement as `task_locks` table.

### 4. PARA Memory System
Three-layer memory: knowledge graph (PARA folders), daily notes, tacit knowledge. File-based, survives session restarts.

### 5. Adapter Registry Pattern
```typescript
interface ServerAdapterModule {
  type: string;
  execute(ctx: AdapterExecutionContext): Promise<AdapterExecutionResult>;
  testEnvironment(ctx): Promise<AdapterEnvironmentTestResult>;
  sessionCodec?: AdapterSessionCodec;
}
```

---

## 11. Implementation Plan

| Phase | Scope | Timeline |
|-------|-------|----------|
| 1 | Heartbeat scheduler, atomic checkout, session persistence | Week 1-2 |
| 2 | SKILL.md format, port existing skills, skill injection | Week 2-3 |
| 3 | Goal hierarchy, task-to-goal linking, context injection | Week 3-4 |
| 4 | PARA memory system per agent, daily notes, tacit knowledge | Week 4-5 |
| 5 | Budget/cost tracking, auto-pause enforcement | Week 5-6 |

---

*Report filed by Pax, Senior Researcher*
*Source repo: /Users/maxstewart/Desktop/The Team/repos/paperclip-1/*