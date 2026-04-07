# Paperclip-1 Second Pass: Deep Pattern Analysis

**Analyst:** Pax (Senior Researcher)
**Date:** 2026-03-26
**Scope:** 8 untapped areas from the paperclip-1 codebase
**Target:** The Team Dashboard (vanilla JS + Express + SQLite)

---

## Area 1: Agent Execution Model (Heartbeat, Sessions, Lifecycle)

### What Paperclip Does

The heartbeat system (`server/src/services/heartbeat.ts` -- 1200+ lines) is the core execution engine. Here is how it works:

**Wakeup queue:** Agents receive wakeup requests (`agent_wakeup_requests` table) from multiple sources: timers, task assignments, on-demand manual triggers, or automation routines. Wakeups carry a source type, trigger detail, reason, payload, and idempotency key. Duplicate wakeups with the same idempotency key get coalesced (merged into one).

**Start lock:** A per-agent in-memory lock (`withAgentStartLock`) serializes concurrent start attempts. This prevents two simultaneous heartbeat triggers from double-launching the same agent.

**Concurrency control:** Configurable `maxConcurrentRuns` per agent (default 1, max 10). Before starting a run, the system counts active runs for that agent and blocks if at capacity.

**Task sessions:** The `agent_task_sessions` table maps (agent + adapter + taskKey) to a persistent session. When an agent gets woken up for issue #42, it resumes its previous session for that issue, not a blank context. Sessions track `sessionParamsJson`, `sessionDisplayId`, `lastRunId`.

**Session compaction:** When sessions get too old or too large (tracked by run count, raw input tokens, and session age hours), the system automatically rotates: it writes a "handoff markdown" summarizing the last run, clears the session, and starts fresh. This prevents infinite context growth.

**Process tracking:** Each run records `processPid` and `processStartedAt`. The service can check `isProcessAlive(pid)` using `process.kill(pid, 0)` to detect orphaned processes. Orphan recovery creates retry runs (`retryOfRunId`, `processLossRetryCount`).

**Runtime state:** `agent_runtime_state` stores the cumulative token counts, session ID, last run status, and last error per agent. Updated after every run completion.

**Live events:** Run progress streams to WebSocket clients via `publishLiveEvent`, so the UI shows real-time stdout/stderr.

### Would This Be Useful?

Partially. The Team already has a task system. What is genuinely useful:
- The wakeup queue pattern (deduplication via idempotency keys)
- Process liveness checking for long-running background agents
- Session persistence across invocations
- The concurrency lock pattern

### Practical for Vanilla JS + Express + SQLite?

The core patterns (wakeup queue, session table, process PID tracking) translate cleanly. The in-memory start lock works fine in a single-process Express app. SQLite can handle the session and runtime state tables.

### Verdict: MAYBE LATER

**Reasoning:** The full heartbeat system is overkill right now -- The Team dashboard is not launching AI agent child processes. However, the wakeup queue and session persistence patterns would be valuable IF Max starts running background AI workers (e.g., having Claude Code execute tasks automatically). Save this for when autonomous execution becomes a priority.

---

## Area 2: Budget / Cost Control System

### What Paperclip Does

This is a three-layer system:

**Layer 1 -- Cost Events** (`services/costs.ts`): Every AI invocation generates a `cost_event` with provider, model, biller, billingType (metered_api, subscription_included, subscription_overage, credits, fixed), input/output/cached tokens, and cost in cents. After each event, monthly spend totals are recalculated on both the agent and company records.

**Layer 2 -- Budget Policies** (`services/budgets.ts`, 960 lines): Budget policies define spending limits at three scopes: company, agent, or project. Each policy has:
- `amount` (limit in cents)
- `warnPercent` (default 80%) -- triggers a "soft" incident when crossed
- `hardStopEnabled` -- when true, crossing the full amount auto-pauses the agent/project/company
- `notifyEnabled` -- creates notification incidents
- `windowKind` -- "calendar_month_utc" or "lifetime"
- `metric` -- currently only "billed_cents"

When a cost event arrives, `evaluateCostEvent` checks all relevant policies. If the soft threshold is crossed, it creates a budget incident. If the hard threshold is crossed, it pauses the scope AND cancels active work.

**Layer 3 -- Budget Incidents & Approvals**: Hard stops create an approval request (`budget_override_required` type). The board member can either "raise budget and resume" (which raises the limit and resumes the agent) or "dismiss" (keeps it paused). Incidents track window boundaries so the same threshold is not re-triggered in the same billing window.

**Layer 4 -- Window Spend** (`costs.ts:windowSpend`): Pre-aggregates spending across rolling windows (5h, 24h, 7d) per provider. This feeds dashboard cards showing "you spent $X with Anthropic in the last 24 hours."

**Layer 5 -- Quota Windows** (`quota-windows.ts`): Queries each adapter's external rate-limit status with a 20-second timeout per provider. Uses `Promise.allSettled` so one provider's outage does not block the others.

**Layer 6 -- Finance Events** (`services/finance.ts`): A separate, more general ledger with debit/credit/estimated classifications, broken down by biller, agent, project, issue, and goal.

### Would This Be Useful?

YES, highly relevant. Max is running AI agents (Claude Code at minimum) and cost visibility is crucial. Knowing "I spent $47 on Claude this week" or "Agent X is burning through budget" is exactly the kind of thing a dashboard should show.

### Practical for Vanilla JS + Express + SQLite?

The core pattern (cost_events table + monthly aggregation + budget policy with warn/hard-stop) is straightforward in SQLite. The rolling window queries are just `SUM(cost_cents) WHERE occurred_at > datetime('now', '-24 hours')`. Budget enforcement (pause agent if over limit) maps directly to updating a status column.

The quota-windows external polling does not apply (that is specific to AI provider rate limits).

### Verdict: YES IMPLEMENT

**Effort:** Medium (2-3 hours)
**Impact:** High -- gives Max visibility into AI spending, prevents surprises
**What to implement:**
1. `cost_events` table (agent_id, provider, model, cost_cents, input_tokens, output_tokens, occurred_at)
2. Monthly/weekly spend summaries per agent and total
3. Budget limits per agent with warn threshold + hard stop
4. Dashboard card showing current month spend vs budget
5. Simple alert when 80% of budget is consumed

---

## Area 3: Onboarding Wizard

### What Paperclip Does

`OnboardingWizard.tsx` (500+ lines) is a 4-step modal wizard:

**Step 1 -- Create Company:** Name your company + optional goal. Creates the company entity and a top-level goal.

**Step 2 -- Configure Agent:** Pick an adapter (Claude, Codex, Gemini, Cursor, OpenCode, Pi, HTTP), set agent name (defaults to "CEO"), choose model, run environment test. The environment test (`testEnvironment` API) verifies the CLI tool is installed and API keys are valid before proceeding. If the Anthropic API key conflicts with subscription mode, it offers a one-click "unset API key" fix.

**Step 3 -- Define First Task:** Pre-populated with a default task ("Hire your first engineer and create a hiring plan"). User can edit title and description. Behind the scenes this creates a project and an issue.

**Step 4 -- Launch:** Creates the issue, assigns the agent, wakes it up. Shows an animated ASCII art "launching..." animation while the first run starts.

**Key patterns:**
- Route-aware opening: if the URL indicates a company needs setup, the wizard opens automatically
- Each step creates real entities (not queued for batch), so going back preserves what was created
- Error handling per step with inline error display
- Adapter model discovery with search/filter in a popover dropdown
- Query cache invalidation after each entity creation

### Would This Be Useful?

A simplified version, yes. When Max first opens The Team Dashboard, a guided setup flow could walk through: connecting to the database, configuring team members, and setting up the first task. First-run experience matters.

### Practical for Vanilla JS + Express + SQLite?

A multi-step wizard is dead simple in vanilla JS. No React needed -- just show/hide steps in a modal. The pattern of "create entity at each step, proceed, show error inline" works the same way.

### Verdict: MAYBE LATER

**Reasoning:** The Team Dashboard already has task creation and team member management. An onboarding wizard would help new users, but Max is the only user right now and already knows the system. This becomes important only if other people start using it. Not worth the effort now.

---

## Area 4: Workspace / Project Isolation

### What Paperclip Does

Three levels of workspace isolation:

**1. Company isolation:** Complete data separation at every query level. Every table has a `companyId` column. Every service function takes `companyId` as a parameter. Routes resolve companyId from URL prefix. This is full multi-tenancy.

**2. Project workspaces:** Each project can have multiple workspaces (`project_workspaces` table) with different `cwd` paths, repo URLs, refs. When an agent is assigned to an issue in a project, the system resolves which workspace to use.

**3. Execution workspaces** (`execution_workspaces` table, `execution-workspace-policy.ts`): Per-issue isolated execution environments. The policy system supports:
- `shared_workspace` -- agents share the project workspace
- `isolated_workspace` -- each issue gets its own workspace (via git worktree or cloud sandbox)
- `operator_branch` -- adapter-managed branching
- `adapter_default` -- let the adapter decide

Workspace strategies include `project_primary`, `git_worktree`, `adapter_managed`, and `cloud_sandbox`. The system auto-clones repos, creates worktrees, and cleans up after issues close.

**4. Managed workspaces:** When a project workspace has a `repoUrl` but no local `cwd`, the system automatically clones the repo into a managed directory (`~/.paperclip/data/workspaces/{companyId}/{projectId}/{repoName}/`) with a 10-minute timeout.

### Would This Be Useful?

The company isolation pattern is already partially in The Team (we have company scoping in the database). The execution workspace concept does not apply -- The Team dashboard is not spawning processes in isolated directories.

What IS useful: the project workspace model of "each project knows where its code lives" (repo URL + local path). If The Team manages multiple projects, linking each to a local path or repo URL is valuable for context.

### Verdict: SKIP

**Reasoning:** The Team already has project + task scoping. Git worktree isolation and cloud sandboxes are agent-execution concerns that do not apply to a management dashboard. The project-to-path linking is already partially handled by the `linked_repos` and `linked_paths` tables in The Team's database.

---

## Area 5: Error Handling Patterns

### What Paperclip Does

**HttpError class** (`errors.ts`): Clean hierarchy with factory functions: `badRequest(msg)`, `unauthorized()`, `forbidden()`, `notFound()`, `conflict(msg, details)`, `unprocessable(msg, details)`. Each carries a status code and optional details object.

**Error handler middleware** (`middleware/error-handler.ts`): Express error middleware that:
1. Catches `HttpError` -- returns the status + message + details. Only logs stack traces for 5xx errors.
2. Catches `ZodError` -- returns 400 with the Zod error array.
3. Catches everything else -- returns generic 500 "Internal server error", logs full error context (request body, params, query, route path).
4. Attaches `ErrorContext` to the response object so the Pino HTTP logger can include it in structured log entries.

**Process liveness checks** (`isProcessAlive`): Uses `process.kill(pid, 0)` to check if a child process still exists. Handles `EPERM` (exists but no permission) and `ESRCH` (does not exist) correctly.

**Retry logic** (heartbeat process recovery): When a run's process PID is no longer alive:
- If `processLossRetryCount < 3`, create a retry run with `retryOfRunId` pointing to the failed run
- Increment `processLossRetryCount`
- Re-queue the wakeup with the same context

**Budget graceful degradation**: `Promise.allSettled` for quota window checks -- one provider timeout does not block the whole response. Each failed provider returns `{ ok: false, error: "..." }` instead of throwing.

**Adapter environment testing**: Before starting an agent, the system tests the adapter environment and reports specific failures (CLI not found, API key invalid, version mismatch). The onboarding wizard shows these check results inline.

### Would This Be Useful?

Yes, parts of this are directly applicable:

1. The HttpError class + factory functions pattern is clean and worth copying.
2. The error handler middleware that enriches Pino log entries with request context.
3. The `Promise.allSettled` graceful degradation for parallel operations.

### Practical for Vanilla JS + Express + SQLite?

Trivially so. The HttpError class is 10 lines. The error handler middleware is 35 lines.

### Verdict: YES IMPLEMENT

**Effort:** Low (30-60 minutes)
**Impact:** Medium -- makes the API more predictable and debuggable
**What to implement:**
1. `HttpError` class with `badRequest`, `notFound`, `conflict`, `unprocessable` factory functions
2. Express error handler middleware that catches HttpError, returns structured JSON, and logs context on 5xx
3. Zod validation error formatting (if using Zod; otherwise skip)

---

## Area 6: Org Chart / Team Management UI

### What Paperclip Does

Paperclip models organizations as:
- **Companies** -- top-level entity with name, description, status (active/paused), budget, issue prefix, logo
- **Agents** -- belong to a company, have a `role` (ceo, engineer, etc.), `title`, `reportsTo` (references another agent), `status` (active/idle/running/paused/error/terminated)
- **Goals** -- hierarchical (company > project > task level), agents are aligned to goals
- **Projects** -- scoped under companies, with codebases and workspace configs

The UI components:
- `CompanyRail.tsx` -- vertical icon rail for switching between companies (like Discord's server bar)
- `CompanySwitcher.tsx` -- dropdown for company selection
- `SidebarAgents.tsx` -- lists agents with status indicators in the sidebar
- `AgentProperties.tsx` -- detail panel for agent configuration (adapter, model, runtime, permissions)
- `AgentConfigForm.tsx` -- full configuration form for agents
- `AgentActionButtons.tsx` -- pause/resume/terminate/restart actions
- `AgentIconPicker.tsx` -- pick an icon for each agent
- `Identity.tsx` -- avatar/identity display component

The `reportsTo` field enables org chart rendering, though I did not find a dedicated org chart visualization component in the UI (it appears to be in development or handled by the GoalTree component).

### Would This Be Useful?

The Team already HAS a team hierarchy (leaders, co-leaders, subagents). What would be useful:
- Status indicators on the team roster (who is busy, who is idle, who errored)
- Agent/team member action buttons (pause, activate, etc.)
- The CompanyRail pattern for workspace switching (if Max works across multiple projects)

### Practical for Vanilla JS + Express + SQLite?

The status indicator and action button patterns are trivial. The CompanyRail is just a vertical strip of icons. These are CSS/HTML patterns, not complex logic.

### Verdict: MAYBE LATER

**Reasoning:** The Team already has team member profiles and hierarchy. Adding status indicators and action buttons would be a nice polish, but the current system works. This is a "nice to have" that can wait until the dashboard UI gets its next major refresh.

---

## Area 7: Notification / Alert System

### What Paperclip Does

**Sidebar badges** (`services/sidebar-badges.ts`): A lightweight badge service that counts:
- Actionable approvals (pending + revision_requested)
- Failed runs (latest run per agent that is in failed/timed_out status)
- Join requests
- Unread touched issues

Returns a `SidebarBadges` object: `{ inbox: total, approvals: N, failedRuns: N, joinRequests: N }`. The sidebar renders these as numbered badges next to navigation items.

**Toast system** (`context/ToastContext.tsx`): Client-side toast notification provider with:
- 4 tones: info (4s), success (3.5s), warn (8s), error (10s)
- Max 5 toasts visible at once
- Deduplication: same toast title+body+tone suppressed for 3.5 seconds
- Optional action button with link
- Auto-dismiss with configurable TTL (min 1.5s, max 15s)
- Manual dismiss

**Live event toasts** (`context/LiveUpdatesProvider.tsx`): WebSocket events get mapped to toasts. When an agent starts/finishes a run, when an issue status changes, when an approval is needed -- the LiveUpdatesProvider converts these into `pushToast()` calls with appropriate tone and action links.

Features:
- Toast cooldown: max 3 toasts per 10-second window to prevent flooding
- Reconnection suppression: after WebSocket reconnect, suppress toasts for 2 seconds (to avoid spam from replayed events)
- Context-aware: if the user is already viewing the relevant issue/agent page, suppresses redundant toasts

**Approval cards** (`ApprovalCard.tsx`): Budget override requests and other governed actions show as cards in an inbox/approval queue with approve/reject actions.

### Would This Be Useful?

YES. The Team already has a `notifications` table but the client-side notification system (toast + badge count) is what makes notifications feel alive. The pattern of "WebSocket event -> convert to toast" is exactly what The Team needs for showing task deliveries, status changes, and decisions needed.

### Practical for Vanilla JS + Express + SQLite?

Completely. The toast system is pure DOM manipulation with timers. The sidebar badge is a single SQL query counting rows. The WebSocket-to-toast bridge is straightforward.

### Verdict: YES IMPLEMENT

**Effort:** Medium (2-3 hours)
**Impact:** High -- makes the dashboard feel alive and responsive
**What to implement:**
1. Toast notification system: show/dismiss/auto-expire toasts with 4 severity levels
2. Sidebar badge counts: unread notifications, pending tasks, failed operations
3. SSE or WebSocket events trigger client-side toasts for: task delivered, status changed, decision needed, agent error
4. Deduplication and flood prevention (max N toasts per window)

---

## Area 8: Pino Structured Logging

### What Paperclip Does

**Logger setup** (`middleware/logger.ts`):
- Uses Pino with `pino-transport` to multiplex to two targets:
  - **Console** (stdout): pino-pretty, info level, colorized, ignores req/res/responseTime fields for cleaner output
  - **File** (server.log): pino-pretty, debug level, no color, logs everything
- Log directory is configurable via env var (`PAPERCLIP_LOG_DIR`), config file, or defaults to `~/.paperclip/logs/`
- Auto-creates the log directory

**HTTP logger** (`pinoHttp`):
- Custom log levels based on status: 5xx = error, 4xx = warn, 2xx/3xx = info
- Custom success message: `"GET /api/issues 200"`
- Custom error message: `"POST /api/agents 422 -- Agent name already exists"` (includes the error message)
- Custom props on 4xx+: attaches `errorContext` (error details), `reqBody`, `reqParams`, `reqQuery`, `routePath`
- The error handler middleware stores `__errorContext` on the response object, and the HTTP logger picks it up

**Log redaction** (`log-redaction.ts`):
- Redacts the current OS username from all log output
- Redacts home directory paths (replaces `/Users/maxstewart` with `/Users/m*********`)
- Works on strings, arrays, and nested objects recursively
- Detects usernames from `$USER`, `$LOGNAME`, `$USERNAME`, `os.userInfo()`
- Detects home dirs from `$HOME`, `$USERPROFILE`, `os.homedir()`, plus platform-specific guesses
- Configurable via instance settings (`censorUsernameInLogs`)
- `maskUserNameForLogs("maxstewart")` -> `"m*********"`

### Would This Be Useful?

The structured logging is solid but possibly overkill for a single-user dashboard. What IS genuinely useful:
- Dual-output pattern (pretty console + full file log)
- HTTP logging with error context attachment
- The username redaction for logs that might be shared

### Practical for Vanilla JS + Express + SQLite?

Pino works with Express. The entire logger setup is under 90 lines. However, for a simple Express app, `morgan` or even `console.log` with a simple wrapper might be sufficient.

### Verdict: MAYBE LATER

**Effort:** Low (1 hour) -- but Pino adds a dependency chain (pino, pino-pretty, pino-http, pino-transport)
**Impact:** Low-Medium -- useful for debugging but the dashboard is not high-traffic
**Reasoning:** The Team dashboard is a single-user local tool. Structured logging matters more for multi-user production services. The error context pattern is the most valuable piece and can be implemented without Pino (just attach error context to `res.locals` and log it in a simple middleware). Wait until the app grows complex enough to need it.

---

## Ranked Recommendations

| Rank | Pattern | Verdict | Effort | Impact | Rationale |
|------|---------|---------|--------|--------|-----------|
| **1** | **Toast + Badge Notification System** | YES IMPLEMENT | Medium (2-3h) | High | Makes the dashboard feel alive. Toast for task deliveries/status changes + badge counts on sidebar nav. The Team already has a notifications table but no client-side notification UX. |
| **2** | **Cost/Budget Tracking** | YES IMPLEMENT | Medium (2-3h) | High | AI spending visibility. cost_events table, monthly aggregation, budget limits with warn/hard-stop. Dashboard card showing "$X spent this month." Critical as AI usage grows. |
| **3** | **HttpError + Error Handler Pattern** | YES IMPLEMENT | Low (30-60min) | Medium | Clean, predictable API errors. HttpError class with factory functions + Express middleware that catches errors, returns structured JSON, logs context. 45 total lines of code for massive DX improvement. |
| **4** | **Heartbeat Execution Model** | MAYBE LATER | High (8-12h) | High (future) | Full agent lifecycle management. Valuable when The Team starts running autonomous AI workers. Not needed until then. |
| **5** | **Pino Structured Logging** | MAYBE LATER | Low (1h) | Low-Med | Dual-output logging + error context. Nice for debugging but overkill for a single-user local tool right now. |
| **6** | **Onboarding Wizard** | MAYBE LATER | Medium (3-4h) | Low | Multi-step guided setup. Only matters if other people start using The Team dashboard. Max already knows the system. |
| **7** | **Team Status Indicators + Actions** | MAYBE LATER | Low (1-2h) | Low-Med | Visual status on team roster (busy/idle/error) + action buttons (pause/activate). Polish, not critical. |
| **8** | **Workspace/Project Isolation** | SKIP | High (6-10h) | Low | Git worktree isolation, execution sandboxing. These are agent-execution concerns. The Team is a management dashboard, not an execution environment. linked_repos/linked_paths already cover the use case. |

---

## Implementation Notes for Top 3

### Pattern 1: Toast + Badge System

**Database:** Already have `notifications` table. Add a `read` boolean column if missing.

**Server-side:**
```
GET /api/notifications/badges -> { inbox: N, pendingTasks: N, deliveredToday: N, errored: N }
```
Single query: `SELECT COUNT(*) FILTER (WHERE read = 0) as inbox, COUNT(*) FILTER (WHERE type = 'task_delivered' AND read = 0) as delivered ...`

**Client-side toast manager:**
- Queue of toast objects: `{ id, title, body, tone, ttlMs, action }`
- Max 5 visible, auto-dismiss by tone (info=4s, success=3.5s, warn=8s, error=10s)
- Dedup: same title+tone within 3.5s is suppressed
- Render as fixed-position stack in bottom-right

**SSE bridge:** When a notification is inserted, SSE pushes it to the browser, which calls `pushToast()`.

### Pattern 2: Cost/Budget Tracking

**New table:** `cost_events` (id, agent_name, provider, model, cost_cents, input_tokens, output_tokens, occurred_at, task_id)

**New columns on team_members:** `budget_monthly_cents`, `spent_monthly_cents`

**API endpoints:**
```
POST /api/costs                    -> log a cost event
GET  /api/costs/summary            -> { totalCents, budgetCents, utilizationPercent }
GET  /api/costs/by-agent           -> [{ agentName, costCents, tokenCount }]
GET  /api/costs/by-provider        -> [{ provider, costCents }]
```

**Dashboard widget:** Card showing "AI Spend: $XX.XX / $100.00 (78%)" with a progress bar that turns yellow at 80% and red at 100%.

### Pattern 3: HttpError + Error Handler

**errors.js:**
```javascript
class HttpError extends Error {
  constructor(status, message, details) {
    super(message);
    this.status = status;
    this.details = details;
  }
}
const badRequest = (msg, details) => new HttpError(400, msg, details);
const notFound = (msg = 'Not found') => new HttpError(404, msg);
const conflict = (msg, details) => new HttpError(409, msg, details);
const unprocessable = (msg, details) => new HttpError(422, msg, details);
```

**error-handler.js middleware:**
```javascript
function errorHandler(err, req, res, next) {
  if (err instanceof HttpError) {
    if (err.status >= 500) console.error(err);
    return res.status(err.status).json({ error: err.message, ...(err.details ? { details: err.details } : {}) });
  }
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
}
```

---

*End of second-pass analysis. The top 3 patterns (toast/badges, cost tracking, error handling) are genuinely useful, practical to implement, and would make Max's experience noticeably better. The "MAYBE LATER" items are real value but have poor timing-to-need ratios.*
