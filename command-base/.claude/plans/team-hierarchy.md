# Plan: Team Hierarchy — Leaders, Co-Leaders, Subagents & Parallel Execution

**Author:** Atlas (Systems Architect)
**Date:** 2026-03-26
**Status:** Ready for Max's approval

---

## The Problem in One Sentence

Gray talks to 6 people directly, each is a single point of failure for their domain, tasks run sequentially in one terminal, and when Lumen is busy doing UI work there is zero UI capacity left.

---

## What This Plan Solves

1. **Bottleneck on specialists** — Co-leaders double capacity per domain
2. **Sequential execution** — Parallel terminal processes let multiple team members work simultaneously
3. **Flat structure** — Three-tier hierarchy (Leader > Co-Leader > Subagent) with clear reporting lines
4. **Priority confusion** — Track original priority vs current priority so Max always knows what was urgent
5. **Low-priority neglect** — Analytics auto-worker chews through normal/low tasks in the background
6. **No org visibility** — Analytics page shows the live hierarchy, who's working, and what they're doing

---

## 1. Database Changes

### 1A. New Column on `team_members`: `tier` and `reports_to`

```sql
ALTER TABLE team_members ADD COLUMN tier TEXT NOT NULL DEFAULT 'leader'
    CHECK(tier IN ('orchestrator', 'leader', 'co-leader', 'subagent'));

ALTER TABLE team_members ADD COLUMN reports_to INTEGER REFERENCES team_members(id);
```

This is the hierarchy in two columns:

| Member | Tier | reports_to |
|--------|------|------------|
| Gray | orchestrator | NULL (top) |
| Pax | leader | 1 (Gray) |
| Lumen | leader | 1 (Gray) |
| Lumen's co-leader (e.g., "Prism") | co-leader | 4 (Lumen) |
| A spawned subagent | subagent | 4 (Lumen) or Prism's ID |

**Why `reports_to` on the same table instead of a separate join table:** The hierarchy is strict — every member has exactly one boss. A self-join is simpler and queryable:

```sql
-- Get Lumen's entire team (co-leaders + subagents)
SELECT * FROM team_members WHERE reports_to = 4;

-- Get the full org chart
SELECT m.name, m.tier, boss.name AS reports_to
FROM team_members m
LEFT JOIN team_members boss ON m.reports_to = boss.id
WHERE m.status = 'active';
```

### 1B. New Columns on `tasks`: Priority Tracking

```sql
ALTER TABLE tasks ADD COLUMN original_priority TEXT
    CHECK(original_priority IN ('low', 'normal', 'high', 'urgent'));

ALTER TABLE tasks ADD COLUMN downgraded_by TEXT;

ALTER TABLE tasks ADD COLUMN downgraded_at TEXT;
```

When a task is created, `original_priority` is set equal to `priority`. When Gray handles the urgent part and downgrades it:

```sql
UPDATE tasks SET
    priority = 'high',
    downgraded_by = 'Gray',
    downgraded_at = datetime('now', 'localtime')
WHERE id = 42;
-- original_priority stays 'urgent'
```

**How Max reads this:** If `original_priority != priority`, the task was downgraded. The UI shows both:
- "HIGH (was URGENT)" — with a small badge or strikethrough on the original
- Tasks that were always "high" just show "HIGH" with no badge

This is dead simple. One glance tells Max: "Gray handled the urgent part, now it's high-priority follow-through" vs "this was always just high."

### 1C. New Table: `active_processes`

```sql
CREATE TABLE active_processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER REFERENCES tasks(id),
    member_id INTEGER NOT NULL REFERENCES team_members(id),
    pid INTEGER,                    -- OS process ID (for the terminal/CLI process)
    terminal_session TEXT,          -- identifier for the terminal tab/tmux pane
    status TEXT NOT NULL DEFAULT 'running'
        CHECK(status IN ('running', 'completed', 'failed', 'killed')),
    started_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    completed_at TEXT,
    output_summary TEXT             -- brief result or error message
);
```

This table tracks every parallel process. The analytics page queries it to show "who's working right now." When a process finishes, it updates to `completed` or `failed`.

### 1D. Summary of All Database Changes

| Change | Table | Type | Risk |
|--------|-------|------|------|
| Add `tier` column | `team_members` | ALTER | Zero — new column with default |
| Add `reports_to` column | `team_members` | ALTER | Zero — nullable FK |
| Add `original_priority` column | `tasks` | ALTER | Zero — nullable, backfill existing |
| Add `downgraded_by` column | `tasks` | ALTER | Zero — nullable |
| Add `downgraded_at` column | `tasks` | ALTER | Zero — nullable |
| Create `active_processes` table | NEW | CREATE | Zero — new table |

**Backfill for existing data:**
```sql
-- Set tier for existing members
UPDATE team_members SET tier = 'orchestrator' WHERE name = 'Gray';
UPDATE team_members SET tier = 'leader' WHERE name != 'Gray';

-- Set reports_to for existing members
UPDATE team_members SET reports_to = 1 WHERE name != 'Gray'; -- All leaders report to Gray (id=1)

-- Backfill original_priority = current priority for all existing tasks
UPDATE tasks SET original_priority = priority WHERE original_priority IS NULL;
```

---

## 2. How Co-Leaders Work

### The Core Question: Pre-Created or Dynamic?

**Answer: Pre-created profiles, dynamically activated.**

Co-leaders are real entries in `team_members` with full `.md` profiles in `Team/`, but they start with `status = 'inactive'`. Gray (or Zenith) activates them when a leader's domain needs more capacity.

### Why Not Fully Dynamic?

Dynamically spawned co-leaders sound cool but create problems:
- No consistent personality or knowledge base
- Every spawn requires Pax researching + Zenith drafting a profile (overhead)
- Max can't build trust with someone who didn't exist 5 minutes ago
- The analytics page can't show useful history for ephemeral agents

Pre-created co-leaders are known entities. Max knows their names, can see their track record, and they have stable profiles that improve over time.

### How Many Co-Leaders?

One per leader to start. That doubles capacity per domain without complexity explosion. If a domain needs more, Zenith can hire a second co-leader later.

| Leader | Co-Leader | Domain |
|--------|-----------|--------|
| Pax (Research) | **Sage** | Secondary researcher — literature reviews, data gathering, fact-checking |
| Zenith (HR) | **Nova** | Onboarding assistant, profile drafting, team analytics |
| Lumen (UI Dev) | **Prism** | Secondary UI dev — component work, styling, responsive fixes |
| Rivet (QA) | **Bolt** | Secondary QA — test execution, regression checking, smoke tests |
| Atlas (Planning) | **Compass** | Secondary planner — task breakdowns, dependency mapping, timeline estimation |
| Cadence (Calendar) | **Tempo** | Calendar operations, scheduling conflicts, analytics data prep |

### Co-Leader Rules

1. **Gray normally routes through the leader.** "Lumen, handle this UI task" — Lumen can delegate to Prism if busy.
2. **Gray CAN go direct to a co-leader** if the leader is actively working on something else and time matters.
3. **Co-leaders cannot spawn subagents on their own.** Only leaders can spawn subagents (this prevents hierarchy sprawl).
4. **Co-leaders start inactive.** Gray activates them when needed: `UPDATE team_members SET status = 'active' WHERE name = 'Prism'`.
5. **Co-leaders share their leader's tools.** They inherit `member_tools` from their leader (query by `reports_to` if no personal tools configured).

### Co-Leader Activation Flow

```
Task arrives for Lumen's domain
    → Gray checks: Is Lumen currently working? (active_processes WHERE member_id = Lumen's ID AND status = 'running')
    → Lumen is busy?
        YES → Gray activates Prism (if inactive), assigns task to Prism
        NO  → Gray assigns to Lumen as normal
```

### Database Representation

```sql
-- Creating Prism (Lumen's co-leader)
INSERT INTO team_members (name, role, profile_path, status, tier, reports_to)
VALUES ('Prism', 'UI Developer (Co-Lead)', 'Team/prism.md', 'inactive', 'co-leader', 4);
-- 4 = Lumen's ID
```

---

## 3. Subagents

Subagents are different from co-leaders. They are temporary, task-scoped, and disposable.

### How Subagents Work Today

The `tasks.subagent_count` and `task_assignments.subagent_count` columns already exist. But right now they're just numbers — they don't map to actual parallel processes.

### How Subagents Work After This Plan

When a leader (or co-leader) needs to break a task into parallel subtasks, they register subagents:

```sql
-- Leader spawns 3 subagents for a task
INSERT INTO team_members (name, role, profile_path, status, tier, reports_to)
VALUES
    ('Lumen-sub-1', 'UI Subagent', 'Team/lumen.md', 'active', 'subagent', 4),
    ('Lumen-sub-2', 'UI Subagent', 'Team/lumen.md', 'active', 'subagent', 4),
    ('Lumen-sub-3', 'UI Subagent', 'Team/lumen.md', 'active', 'subagent', 4);
```

**Key difference from co-leaders:** Subagents share their parent's profile (same `profile_path`). They're clones, not individuals. When the task is done, they get set to `status = 'inactive'` or deleted.

**Naming convention:** `{LeaderName}-sub-{N}` — makes them instantly recognizable in logs and analytics.

### Subagent Lifecycle

```
Leader receives complex task
    → Leader decides it needs N parallel workers
    → Leader creates N subagent entries in team_members
    → Each subagent gets its own entry in active_processes (own terminal)
    → Subagents execute in parallel
    → Leader collects results, merges, does quality review
    → Subagents are deactivated
```

---

## 4. The Analytics Auto-Worker

### Who Is It?

**Tempo** — Cadence's co-leader. Cadence already owns analytics and scheduling. Tempo is the "background grinder" that works through the low-priority queue while the rest of the team handles what matters.

But Tempo is not just a co-leader. Tempo has a special `execution_mode` behavior:

### What Tempo Does

1. **Watches the task queue** for `normal` and `low` priority tasks that haven't been picked up
2. **Works through them in order** — oldest first, normal before low
3. **Handles them autonomously** — using the same Claude CLI execution as the worker service, OR in a dedicated terminal session
4. **Escalates to Gray** when:
   - The task requires a specialist domain (e.g., it's clearly UI work, not generic analytics)
   - The task has external consequences (sending emails, modifying repos)
   - The task description references things Tempo doesn't have access to
   - Tempo's quality review of its own work fails twice

### How Tempo Runs

Two modes, matching the existing execution architecture:

**Terminal mode:** Tempo gets a dedicated background terminal (tmux session or background process) that polls the DB for low-priority work. This runs alongside the main terminal where Max talks to Gray.

**Autonomous mode:** The existing Docker worker already processes tasks by priority. Tempo's behavior is built into the worker's `pollLoop` — it already processes `normal` and `low` tasks. The difference is that Tempo's profile adds context about what to escalate.

### Implementation

```sql
-- Tempo in the database
INSERT INTO team_members (name, role, profile_path, status, execution_mode, tier, reports_to)
VALUES ('Tempo', 'Analytics Auto-Worker & Scheduler', 'Team/tempo.md', 'active', 'autonomous', 'co-leader', 7);
-- 7 = Cadence's ID
```

The worker service (or a Tempo-specific background script) adds this filter:

```
Find tasks WHERE:
    status = 'new'
    AND priority IN ('normal', 'low')
    AND assigned_to IS NULL              -- not claimed by anyone
    AND NOT EXISTS (specialist domain)   -- not clearly someone else's job
ORDER BY
    CASE priority WHEN 'normal' THEN 0 WHEN 'low' THEN 1 END,
    created_at ASC
```

### Escalation Rules (Tempo's Profile)

Tempo's `.md` profile will include:

```
You are Tempo. You handle background tasks autonomously.

ESCALATE to Gray if:
- Task mentions UI, frontend, design, components → that's Lumen's domain
- Task mentions testing, QA, regression → that's Rivet's domain
- Task mentions hiring, profiles, onboarding → that's Zenith's domain
- Task involves git push, deploy, external APIs → needs leader approval
- Task is ambiguous and you're not sure what's being asked
- Your work fails quality review twice

DO NOT ESCALATE for:
- Data gathering, summarization, analysis
- Calendar and scheduling operations
- File organization and cleanup
- Writing drafts, outlines, summaries
- Database queries and reports
```

---

## 5. Priority Downgrade Tracking — Full Flow

### Step by Step

1. **Max creates a task** (or it arrives in inbox). `priority = 'urgent'`, `original_priority = 'urgent'`.

2. **Gray auto-works it** (per current CLAUDE.md rules — urgent/high get immediate attention).

3. **Gray handles the urgent part** — maybe it was "server is down, fix it." Gray delegates to the right leader, the fix goes out.

4. **Gray downgrades the task:**
   ```sql
   UPDATE tasks SET
       priority = 'high',
       downgraded_by = 'Gray',
       downgraded_at = '2026-03-26 14:30:00'
   WHERE id = 42;
   ```

5. **The remaining work** (documentation, follow-up, root cause analysis) continues at `high` priority.

### How the UI Shows This

**Task card / task list row:**

```
Priority pill when original == current:
    [URGENT]  — solid red, normal appearance

Priority pill when downgraded:
    [HIGH ← URGENT]  — amber pill with a small "← URGENT" suffix in muted text

    OR (simpler version):
    [HIGH] with a small downward arrow icon and tooltip: "Downgraded from URGENT by Gray at 2:30 PM"
```

**Recommended approach:** The simpler version. A small down-arrow icon on the priority pill, with a tooltip on hover. This way:
- At a glance, Max sees the current priority (what matters NOW)
- The arrow tells him "this was higher" without cluttering the UI
- The tooltip gives the full story

**In the analytics dashboard:**
- A new mini-chart: "Downgraded Tasks" — shows how many tasks Gray handled at each level
- This tells Max: "Gray resolved 4 urgent situations this week before they reached you"

---

## 6. Parallel Terminal Execution

This is the most technically important section. Right now, everything runs in one terminal — Gray gets a task, delegates it, waits for the result, moves on. That's sequential. We need parallel.

### The Approach: tmux Sessions

**Why tmux:** It's already available on macOS (installable via Homebrew), it runs in the background, each pane is an isolated shell, and you can attach/detach without killing processes. It's the simplest tool that actually solves the problem.

**Alternative considered: separate Terminal.app windows.** Rejected because you can't programmatically manage them reliably, and it clutters Max's screen.

**Alternative considered: background `claude -p` processes.** This is what the Docker worker does. But in terminal mode (Max's primary mode), we want processes that Max can actually observe if he wants to. tmux gives us both — background execution with optional visibility.

### Architecture

```
Max's terminal (main)
    └── Gray orchestrates from here

tmux session: "the-team"
    ├── pane 0: Lumen working on Task #12 (UI component)
    ├── pane 1: Pax researching for Task #13
    ├── pane 2: Tempo grinding through Task #14 (low priority)
    └── pane 3: Prism working on Task #15 (UI fix, Lumen is busy)
```

### How It Works

1. **Gray receives a task** and decides who handles it.

2. **Gray spawns a process** for that team member:
   ```bash
   # Create the tmux session if it doesn't exist
   tmux new-session -d -s the-team 2>/dev/null || true

   # Create a new pane for this task
   tmux new-window -t the-team -n "task-12-lumen"

   # Run the Claude CLI in that pane with the member's context
   tmux send-keys -t the-team:task-12-lumen \
       "claude -p '$(cat /tmp/task-12-prompt.txt)' --output-format text > /tmp/task-12-output.txt 2>&1; echo DONE > /tmp/task-12-status.txt" Enter
   ```

3. **Gray registers the process** in `active_processes`:
   ```sql
   INSERT INTO active_processes (task_id, member_id, terminal_session, status)
   VALUES (12, 4, 'the-team:task-12-lumen', 'running');
   ```

4. **Gray continues** to the next task without waiting. Multiple panes run simultaneously.

5. **Gray polls for completion** (or gets notified via the status file):
   ```bash
   # Check if a task's process is done
   test -f /tmp/task-12-status.txt && cat /tmp/task-12-output.txt
   ```

6. **On completion**, Gray reads the output, does quality review, and updates the database.

### Process Limits

Don't run 20 parallel Claude instances — that'll trash the machine. Set a configurable limit:

```sql
INSERT INTO system_settings (key, value)
VALUES ('max_parallel_processes', '4');
```

Gray checks `active_processes WHERE status = 'running'` count before spawning. If at the limit, the task queues until a slot opens.

### Conflict Prevention

Parallel processes can conflict if two agents try to edit the same file. Rules:

1. **Database writes use WAL mode** — SQLite handles concurrent reads fine and serializes writes. Already safe.
2. **File-based outputs go to unique paths** — each task writes to `/tmp/task-{id}-output.txt` or a task-specific subfolder.
3. **Repo work uses git branches** — if two agents work on the same repo, each gets a branch: `team/{member-name}/task-{id}`. Gray merges when both are done.
4. **Linked paths have a lock convention** — before a process writes to a linked path, it checks `active_processes` for other processes using the same path. If conflict, the task queues behind the first one.

### The active_processes Table Powers Everything

This table is the bridge between execution and visibility:

- **Gray** queries it to know who's busy before assigning work
- **The analytics page** queries it to show the live org chart with active indicators
- **The parallel executor** queries it to enforce process limits
- **The cleanup routine** marks stale processes (running > 30 min with no output) as `failed`

---

## 7. The Org Chart Visualization (Analytics Page)

### Where It Lives

New section in the **Team** tab of the analytics dashboard. It replaces (or sits above) the current member cards.

### What It Shows

```
                         ┌────────────┐
                         │   GRAY     │
                         │ Orchestr.  │
                         │  ● active  │
                         └─────┬──────┘
              ┌────────┬───────┼───────┬────────┬────────┐
         ┌────┴───┐ ┌──┴──┐ ┌─┴──┐ ┌──┴──┐ ┌──┴──┐ ┌──┴───┐
         │  PAX   │ │ZENI │ │LUME│ │RIVE│ │ATLAS│ │CADEN│
         │Research│ │ HR  │ │ UI │ │ QA │ │Plan │ │Cal  │
         │ 1 task │ │idle │ │2 tk│ │idle│ │idle │ │idle │
         └───┬────┘ └──┬──┘ └─┬──┘ └──┬──┘ └──┬──┘ └──┬──┘
          ┌──┴──┐  ┌──┴──┐ ┌─┴──┐ ┌──┴──┐ ┌──┴───┐ ┌─┴──┐
          │SAGE │  │NOVA │ │PRIS│ │BOLT│ │COMPA│ │TEMP│
          │ co  │  │ co  │ │ co │ │ co │ │ co  │ │auto│
          │idle │  │idle │ │1 tk│ │idle│ │idle │ │3 tk│
          └─────┘  └─────┘ └────┘ └────┘ └─────┘ └────┘
```

### Visual Design

Each node is a card:
- **Name** in bold
- **Role** abbreviated beneath
- **Status indicator:** Green dot = actively processing a task. Gray dot = idle. Yellow dot = in review. Red dot = error.
- **Task count:** "2 tasks" for active work
- **Click** a node to expand it — shows the task(s) they're working on, their output history, performance stats

### Data Source

```sql
-- Full org chart with live status
SELECT
    m.id,
    m.name,
    m.role,
    m.tier,
    m.status,
    m.reports_to,
    boss.name AS reports_to_name,
    COUNT(CASE WHEN ap.status = 'running' THEN 1 END) AS active_tasks,
    COUNT(CASE WHEN t.status IN ('new','routing','in_progress','review') THEN 1 END) AS open_tasks
FROM team_members m
LEFT JOIN team_members boss ON m.reports_to = boss.id
LEFT JOIN active_processes ap ON ap.member_id = m.id AND ap.status = 'running'
LEFT JOIN tasks t ON t.assigned_to = m.id AND t.status NOT IN ('completed','delivered')
WHERE m.status = 'active'
GROUP BY m.id
ORDER BY
    CASE m.tier
        WHEN 'orchestrator' THEN 0
        WHEN 'leader' THEN 1
        WHEN 'co-leader' THEN 2
        WHEN 'subagent' THEN 3
    END,
    m.name;
```

### New API Endpoint

```
GET /api/analytics/org-chart
```

Returns:
```json
{
    "members": [
        {
            "id": 1,
            "name": "Gray",
            "role": "Orchestrator",
            "tier": "orchestrator",
            "reports_to": null,
            "active_tasks": 0,
            "open_tasks": 2,
            "children": [
                {
                    "id": 2,
                    "name": "Pax",
                    "tier": "leader",
                    "active_tasks": 1,
                    "children": [
                        { "id": 8, "name": "Sage", "tier": "co-leader", "active_tasks": 0 }
                    ]
                }
            ]
        }
    ]
}
```

The server builds the nested tree from the flat `reports_to` relationships. Lumen renders it as an SVG tree using the existing chart library approach from the analytics plan.

---

## 8. How It All Fits Together — A Real Scenario

Max drops 4 tasks into the inbox at once:

| Task | Priority | Domain |
|------|----------|--------|
| "Fix the broken login page" | URGENT | UI |
| "Research competitors for pitch deck" | HIGH | Research |
| "Add unit tests for the API" | NORMAL | QA |
| "Organize the Google Drive folders" | LOW | General |

**What happens:**

1. **Gray** picks up all 4 tasks, logs them, assigns priorities.

2. **Task 1 (URGENT, UI):** Gray checks — is Lumen busy? No. Gray assigns to Lumen, spawns a tmux pane for Lumen. `active_processes` row created. Lumen starts working.

3. **Task 2 (HIGH, Research):** Gray assigns to Pax, spawns a second tmux pane. Pax starts working in parallel with Lumen.

4. **Task 3 (NORMAL, QA):** Gray could assign to Rivet, but it's normal priority. Instead, Gray lets it sit — Tempo (the auto-worker) will pick it up. But wait — this is QA-specific. Tempo's escalation rules say QA tasks go to Rivet. So Tempo flags it for Gray, and Gray assigns to Rivet when a process slot opens. OR, if we want Tempo to be smarter: Gray assigns it to Rivet directly since it's QA, and Rivet gets a tmux pane when a slot opens.

5. **Task 4 (LOW, General):** Tempo picks this up in the background. No specialist needed — it's file organization. Tempo handles it autonomously.

6. **Meanwhile, a 5th task arrives** — also UI work. Gray checks: Lumen is busy (active process running). Gray activates Prism (Lumen's co-leader), assigns the task to Prism, spawns a third tmux pane. Now Lumen and Prism work on UI tasks in parallel.

7. **Lumen finishes Task 1.** Gray reviews it, approves it. Gray downgrades it:
   ```
   original_priority: urgent → stays urgent
   priority: urgent → high (downgraded)
   downgraded_by: Gray
   ```
   The urgent fix is deployed. The follow-up (documentation, root cause) continues at high priority.

8. **Analytics page** shows: 4 tasks in progress across 4 team members, org chart has green dots on Lumen, Pax, Prism, and Tempo.

---

## 9. Implementation Phases

### Phase 1: Database Schema (zero risk)

1. Add `tier` and `reports_to` columns to `team_members`
2. Add `original_priority`, `downgraded_by`, `downgraded_at` columns to `tasks`
3. Create `active_processes` table
4. Add `max_parallel_processes` to `system_settings`
5. Backfill existing data (set tiers, reports_to, original_priority)
6. Add API endpoints for the new columns

**Validation:** All existing queries still work. New columns are nullable or have defaults. Zero breakage.

### Phase 2: Co-Leader Profiles

7. Write `.md` profiles for all 6 co-leaders (Sage, Nova, Prism, Bolt, Compass, Tempo)
8. Insert co-leader rows into `team_members` with `status = 'inactive'` and correct `reports_to`
9. Update CLAUDE.md with hierarchy rules (how Gray routes through leaders, when to activate co-leaders)

**Validation:** Co-leaders exist in the DB but don't affect anything until activated.

### Phase 3: Priority Downgrade System

10. Update the task creation flow to always set `original_priority = priority`
11. Add downgrade logic to Gray's auto-work flow (update priority, log the downgrade)
12. Update the task card UI to show downgrade indicators (arrow icon + tooltip)
13. Add "Downgraded Tasks" mini-stat to analytics

**Validation:** Create a test task at urgent, have Gray downgrade it, verify both priorities display correctly.

### Phase 4: Parallel Execution Engine

14. Install tmux on Max's machine if not present (`brew install tmux`)
15. Build the tmux session manager — functions to create panes, run commands, poll for completion
16. Integrate into Gray's dispatch flow — instead of executing inline, spawn a tmux pane
17. Register all spawned processes in `active_processes`
18. Build the completion polling/callback mechanism
19. Implement process limit enforcement (check count before spawning)
20. Add conflict detection for shared file paths

**Validation:** Spawn 3 parallel tasks, verify all complete independently, verify active_processes reflects reality, verify process limit works.

### Phase 5: Analytics Auto-Worker (Tempo)

21. Activate Tempo in the database
22. Build Tempo's background polling script (or integrate into worker service)
23. Implement escalation rules (domain detection, external-action detection)
24. Test with a batch of normal/low tasks — verify Tempo handles generics and escalates specialists

**Validation:** Drop 5 mixed tasks (some generic, some domain-specific). Verify Tempo handles the right ones and escalates the rest.

### Phase 6: Org Chart Visualization

25. Build `/api/analytics/org-chart` endpoint
26. Build the SVG tree renderer (nodes, edges, status indicators, click-to-expand)
27. Add the org chart to the Team tab of the analytics page
28. Wire up live status indicators using `active_processes` data
29. Add auto-refresh (poll every 10s, or use Server-Sent Events if already in place)

**Validation:** Org chart renders the full hierarchy. Green dots appear when processes are running. Click a node to see their active tasks.

---

## 10. Files to Create/Modify

| File | Action | What Changes |
|------|--------|-------------|
| `the_team.db` | ALTER + CREATE | 5 new columns, 1 new table, backfill data |
| `CLAUDE.md` | MODIFY | Add hierarchy rules, co-leader routing, parallel execution docs |
| `Team/sage.md` | CREATE | Pax's co-leader profile |
| `Team/nova.md` | CREATE | Zenith's co-leader profile |
| `Team/prism.md` | CREATE | Lumen's co-leader profile |
| `Team/bolt.md` | CREATE | Rivet's co-leader profile |
| `Team/compass.md` | CREATE | Atlas's co-leader profile |
| `Team/tempo.md` | CREATE | Cadence's co-leader profile (analytics auto-worker) |
| `app/server.js` | MODIFY | New API endpoints: org-chart, priority downgrade, active processes |
| `app/public/app.js` | MODIFY | Org chart renderer, priority badge UI, downgrade indicators |
| `app/public/styles.css` | MODIFY | Org chart layout, hierarchy node styles, status dot animations |
| `worker/index.js` | MODIFY | Tempo's auto-worker logic, parallel dispatch awareness |

---

## 11. What This Does NOT Change

- **Task statuses** — same flow: new > routing > in_progress > review > completed > delivered
- **Inbox/Outbox** — same folders, same file handling
- **Database tables** — no tables deleted or restructured, only additions
- **Docker setup** — same services, same compose file
- **The existing worker** — enhanced, not replaced
- **How Max creates tasks** — same as before, through Mission Control or conversation

---

## 12. Open Questions for Max

1. **Co-leader names:** I picked Sage, Nova, Prism, Bolt, Compass, Tempo. Want to rename any of them? They're your team.

2. **Process limit:** 4 parallel processes is the default. Max's machine is a Mac — how much RAM? If 16GB+, we could push to 6. If 8GB, stay at 3-4.

3. **Tempo's scope:** Should Tempo ONLY handle tasks that are explicitly low/normal, or should it also pick up tasks that have been sitting unassigned for more than X hours regardless of priority?

4. **Co-leader activation:** Should Gray activate co-leaders automatically when a leader is busy, or should Max approve each activation? (Recommendation: automatic, with a notification to Max.)

5. **Subagent cleanup:** Should subagents be deleted from `team_members` when their task is done, or kept as inactive for historical tracking? (Recommendation: kept inactive, with a periodic cleanup job.)

---

## Decision: Approved to proceed?

Phase 1-2 are zero-risk database additions and profile creation. Phase 3 is a UI-only change. Phase 4 is the big one (parallel execution) but it's additive — if it breaks, everything falls back to sequential. Phase 5 and 6 are independent features that can be built in any order.

Each phase is deployable on its own. No phase depends on all previous phases being complete (though the full experience needs all 6).
