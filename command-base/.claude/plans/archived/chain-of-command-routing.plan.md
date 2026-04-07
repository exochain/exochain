# Feature: Chain-of-Command Task Routing

## Summary
Implement server-side chain-of-command routing so that auto-assigned missions flow through Gray (CEO) as a routing agent who analyzes the task, identifies the correct Executive and Specialist(s), and outputs a structured routing decision that the server parses and acts on. Manual assignments from Max continue to bypass the chain.

## User Story
As Max (Chairman)
I want missions to automatically flow through the Board → Executive → Specialist chain
So that tasks are properly analyzed, routed to the right domain expert, and the hierarchy functions as designed in CLAUDE.md

## Problem Statement
Currently, when a mission is submitted without manual assignments (`auto_assign = true` or no members selected):
- The task is created with `status = 'new'` and sits idle (`server.js:5899`)
- The worker (`worker/index.js:204-232`) polls for `status = 'new'` tasks but uses a simple keyword-based `routeActionItem()` function (`server.js:5624-5662`) that maps keywords to categories, then `assignMember()` picks the least-loaded specialist (`server.js:8579-8647`)
- Gray is explicitly filtered OUT of terminal spawning (`server.js:14967`: `assignments.filter(a => a.name !== 'Gray')`)
- No Board review, no Executive involvement, no domain-based delegation
- The chain of command described in CLAUDE.md is purely aspirational text, not implemented logic

## Solution Statement
1. **New function `routeViaChainOfCommand(taskId)`** — spawns Gray with a lightweight, routing-only prompt (no code editing tools). Gray analyzes the task, outputs a JSON routing decision: which executive oversees, which specialist(s) to assign, with subagent counts and rationale.
2. **Server-side JSON parser** — extracts Gray's routing decision from CLI output, validates member names against the DB, creates `task_assignments`, and spawns the designated specialists via existing `spawnMemberTerminal()`.
3. **Modified `POST /api/mission`** — when `auto_assign = true` and no manual members, calls `routeViaChainOfCommand()` instead of leaving the task at `status = 'new'`.
4. **Status tracking** — new `current_step` updates show routing progress: "Gray analyzing..." → "Routing to {Executive}..." → "{Specialist} assigned" so the frontend queue reflects the chain in real time.
5. **Fallback** — if Gray's routing fails or produces unparseable output, fall back to the existing `assignMember()` keyword-based routing with a logged warning.

## Metadata

| Field | Value |
|-------|-------|
| Type | NEW_CAPABILITY |
| Complexity | MEDIUM |
| Systems Affected | `app/server.js` (routing logic, mission endpoint, autoSpawnForTask) |
| Dependencies | Existing `spawnMemberTerminal()`, `deptToCsuite` mapping, `team_members` table |
| Estimated Tasks | 5 |
| Confidence | 8/10 — well-understood codebase patterns, clear integration points, main risk is prompt reliability |

---

## UX Design

### Before State
```
Max submits mission (auto-assign ON)
        │
        ▼
   Task created (status='new')
        │
        ▼
   Sits idle until worker polls (10s)
        │
        ▼
   Worker uses keyword matching → picks random specialist
        │
        ▼
   No Board/Executive involvement
```

### After State
```
Max submits mission (auto-assign ON)
        │
        ▼
   Task created (status='routing')
        │
   current_step: "Gray analyzing task..."
        │
        ▼
   Gray spawned with routing-only prompt (haiku, max-turns=1, no tools)
        │
   current_step: "Routing via {Executive}..."
        │
        ▼
   Server parses Gray's JSON routing decision
        │
        ▼
   task_assignments created for specialist(s)
        │
   current_step: "{Specialist} assigned — spawning..."
        │
        ▼
   spawnMemberTerminal() for each specialist (existing flow)
```

### Interaction Changes

| Location | Before | After | User Impact |
|----------|--------|-------|-------------|
| Mission Control queue | Auto-assign tasks show "New" status | Shows "Routing" with live step: "Gray analyzing..." → "Routing to Onyx..." → "Alloy assigned" | Max sees the chain working in real time |
| Activity Log | Only logs `mission_submitted` | Also logs `chain_routing_started`, `chain_routing_decision`, `chain_routing_assigned` | Full audit trail of routing decisions |
| Success banner | "Mission sent to Gray (auto-assign)" | "Mission sent — Gray routing..." | Clearer feedback |

---

## NOT Building (Scope Limits)
- Board voting / quorum logic — Gray routes directly without convening all 8 board members (too slow, too expensive). The Board governance is for policy decisions, not per-task routing.
- Executive spawning — the Executive is logged as the routing authority but doesn't get their own terminal for regular routing. They only get spawned on escalation (existing behavior).
- Multi-step routing (Gray → Board → Executive → Specialist as separate spawns) — this would be 3 Claude CLI calls per task. Instead, Gray makes the full routing decision in one pass.
- Frontend changes to the routing display — the existing `current_step` field and `routing` status already render in the queue and monitor. No new UI components needed.

---

## Mandatory Reading

**Implementation agent MUST read these files before starting any task.**

| Priority | File | Lines | Why Read This |
|----------|------|-------|---------------|
| P0 | `app/server.js` | 5844-6003 | `POST /api/mission` — the entry point being modified |
| P0 | `app/server.js` | 14943-14981 | `autoSpawnForTask()` — the function being extended |
| P0 | `app/server.js` | 13006-13430 | `spawnMemberTerminal()` — how CLI spawning works (prompt, model, args, stdin) |
| P1 | `app/server.js` | 14650-14678 | `deptToCsuite` mapping — reuse this for routing context |
| P1 | `app/server.js` | 8579-8647 | `assignMember()` — the fallback function |
| P1 | `app/server.js` | 5624-5662 | `routeActionItem()` — existing keyword routing (fallback) |
| P2 | `app/server.js` | 13746-13860 | `handleSpawnSuccess()` — how output is processed (pattern for parsing) |

## Patterns to Mirror

**CLI Spawn with stdin piping (from `spawnMemberTerminal`):**
```javascript
// SOURCE: app/server.js:13384-13420
const args = ['--print', '--model', modelFlag, '--max-turns', String(maxTurns), '--dangerously-skip-permissions', '--verbose', '--output-format', 'stream-json'];

let child;
try {
  child = spawn(cliPath, args, {
    env,
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: workingDir,
    detached: false
  });
} catch (spawnErr) { ... }

// Write the prompt to stdin and close it
try {
  child.stdin.write(prompt);
  child.stdin.end();
} catch (stdinErr) { ... }
```

**Activity logging pattern:**
```javascript
// SOURCE: app/server.js:5957-5960
db.prepare(`
  INSERT INTO activity_log (task_id, actor, action, notes, created_at)
  VALUES (?, 'Gray', ?, ?, ?)
`).run(taskId, 'chain_routing_started', `Analyzing task for chain-of-command routing`, now);
```

**Task status update pattern:**
```javascript
// SOURCE: app/server.js:13317-13318
db.prepare(`UPDATE tasks SET status = ?, progress = ?, current_step = ?, updated_at = ? WHERE id = ?`)
  .run('routing', 5, 'Gray analyzing task...', now, taskId);
```

**deptToCsuite mapping (reuse directly):**
```javascript
// SOURCE: app/server.js:14658-14678
const deptToCsuite = {
  'Engineering': 'Onyx', 'Frontend': 'Onyx', 'Backend': 'Onyx',
  'DevOps': 'Onyx', 'QA': 'Onyx', 'Security': 'Onyx',
  'Platform': 'Quarry', 'Design': 'Quarry', 'Product': 'Quarry',
  'Research': 'Loom', 'Data': 'Loom',
  'Content': 'Blaze', 'Marketing': 'Blaze',
  'HR': 'Crest', 'Legal': 'Writ', 'Finance': 'Thorn',
  'Revenue': 'Summit', 'Customer': 'Summit', 'Operations': 'Sable'
};
```

## Files to Change

| File | Action | Justification |
|------|--------|---------------|
| `app/server.js` | UPDATE | Add `routeViaChainOfCommand()` function, modify `POST /api/mission` auto-assign path, update `autoSpawnForTask()` |

---

## Step-by-Step Tasks

Execute in order. Each task is atomic and independently verifiable.

### Task 1: Add `routeViaChainOfCommand(taskId)` function to `server.js`

**Action**: UPDATE `app/server.js`
**Where**: Insert before `autoSpawnForTask()` (before line 14940)
**Details**:

Create a new async function that:
1. Loads the task from DB
2. Loads the full specialist roster (active specialists with name, role, department, tier)
3. Loads the C-suite roster
4. Builds a routing-only prompt for Gray:
   - Gray's identity: "You are Gray, CEO. You are an ORCHESTRATOR. You NEVER do work yourself."
   - The task details (title, description, priority, attached files)
   - The full team roster organized by department (Executive → Specialists under them)
   - The `deptToCsuite` mapping so Gray knows who owns what domain
   - Clear instructions: "Analyze this task. Determine which domain(s) it belongs to. Route to the correct Executive and the best Specialist(s). Consider workload balance."
   - **Required output format**: A JSON block wrapped in `<routing>...</routing>` tags:
     ```json
     {
       "executive": "Onyx",
       "domain": "Engineering",
       "specialists": [
         {"name": "Alloy", "reason": "API endpoint work", "subagent_count": 1}
       ],
       "rationale": "This task involves building a new API endpoint..."
     }
     ```
5. Spawns Claude CLI with:
   - Model: `haiku` (fast, cheap — routing doesn't need heavy reasoning)
   - `--max-turns 1` (no tools needed, just output the routing decision)
   - `--print --output-format text` (no streaming needed, just text output)
   - Working directory: project root (doesn't matter, no file access)
6. Writes prompt to stdin, collects stdout
7. Parses the `<routing>...</routing>` JSON from stdout
8. Validates: each specialist name must exist in `team_members` as active specialist
9. Returns the parsed routing object or `null` on failure

**Prompt template** (key parts):
```
You are Gray, CEO of The Team. You are an ORCHESTRATOR — you NEVER do work yourself.

## Your Task
Analyze the following mission and route it to the correct team member(s).

### Mission Details
**Title:** ${task.title}
**Priority:** ${task.priority}
**Description:**
${task.description}

## The Team Hierarchy

### C-Suite Executives (route TO these by domain)
${csuite roster with departments}

### Specialists (assign THESE to do the work)
${specialist roster grouped by department, with current workload}

## Domain Routing Rules
${deptToCsuite mapping as readable rules}

## Instructions
1. Identify the domain(s) this task belongs to
2. Determine the responsible Executive
3. Pick the best Specialist(s) — consider skills match AND current workload
4. If the task spans multiple domains, assign specialists from each
5. Set subagent_count: 1 for focused tasks, 2-3 for large/complex ones

Output your routing decision as JSON inside <routing></routing> tags. Nothing else.
```

**Mirror**: `spawnMemberTerminal()` CLI spawn pattern at `server.js:13384-13420`
**Gotcha**: Use `--output-format text` (not `stream-json`) since we want simple text output, not streaming events. Use `--max-turns 1` to prevent tool use. Collect all stdout before parsing.
**Validate**: Function exists, can be called with a task ID, returns structured routing object or null

---

### Task 2: Add `parseRoutingDecision(stdout)` helper function

**Action**: UPDATE `app/server.js`
**Where**: Insert right before `routeViaChainOfCommand()`
**Details**:

Create a function that:
1. Extracts content between `<routing>` and `</routing>` tags from Gray's output
2. Parses it as JSON
3. Validates the structure:
   - `executive` must be a string matching an active c-suite member name
   - `specialists` must be a non-empty array
   - Each specialist must have `name` (string), `subagent_count` (number, 1-10)
   - Each specialist `name` must exist in `team_members` as active specialist
4. Resolves member IDs by querying `team_members` for each specialist name
5. Returns `{ executive, executiveId, domain, specialists: [{id, name, role, subagent_count, reason}], rationale }` or `null` on parse failure

**Fallback parsing**: If no `<routing>` tags found, try to find any JSON object in the output that has `specialists` and `executive` keys. This handles cases where the model outputs raw JSON without tags.

**Validate**: Can parse valid routing JSON, returns null for garbage input, validates member names against DB

---

### Task 3: Add `executeRoutingDecision(taskId, routing)` helper function

**Action**: UPDATE `app/server.js`
**Where**: Insert right after `parseRoutingDecision()`
**Details**:

Create a function that takes a parsed routing decision and:
1. Creates `task_assignments` rows for each specialist (same pattern as `server.js:5912-5918`)
2. Updates `tasks.assigned_to` to the first specialist (primary assignee)
3. Updates `tasks.status` to `'routing'`, `current_step` to `"Routing via {Executive} → {Specialist names}"`
4. Logs activity: `chain_routing_decision` with the full routing rationale
5. Logs the executive as the routing authority in activity_log
6. Creates a notification: "Gray routed '{title}' → {specialist names} via {executive}"
7. Broadcasts `task.updated` 
8. Calls `autoSpawnForTask(taskId)` to spawn the assigned specialists (existing function handles the rest)

**Mirror**: Transaction pattern from `server.js:5902-5970`
**Validate**: Creates correct task_assignments, spawns specialists

---

### Task 4: Modify `POST /api/mission` to use chain routing for auto-assign

**Action**: UPDATE `app/server.js`
**Where**: Lines 5974-5987 (the auto-spawn section) and line 5899 (status assignment)
**Details**:

Currently at line 5899:
```javascript
const status = resolvedAssignments.length > 0 ? 'routing' : 'new';
```

Change to:
```javascript
const status = 'routing'; // Always start as routing — chain handles the rest
```

Currently at lines 5974-5987, after the transaction, only manual assignments trigger spawning. Add a new branch for auto-assign:

```javascript
if (resolvedAssignments.length > 0) {
  // Manual assignments — bypass chain, spawn directly (existing code)
  const tId = Number(taskId);
  setImmediate(() => {
    autoSpawnForTask(tId).then(spawnResults => { ... });
  });
} else {
  // Auto-assign — route through chain of command
  const tId = Number(taskId);
  setImmediate(() => {
    // Update step to show Gray is analyzing
    db.prepare(`UPDATE tasks SET current_step = ?, updated_at = ? WHERE id = ?`)
      .run('Gray analyzing task...', localNow(), tId);
    broadcast('task.updated', { id: tId });
    
    routeViaChainOfCommand(tId).then(routing => {
      if (routing) {
        executeRoutingDecision(tId, routing);
      } else {
        // Fallback: use keyword-based assignment
        const category = routeActionItem(description);
        const fallbackMember = assignMember(category, null);
        if (fallbackMember) {
          // Create assignment and spawn
          db.prepare(`INSERT INTO task_assignments (task_id, member_id, subagent_count, created_at) VALUES (?, ?, 1, ?)`)
            .run(tId, fallbackMember.member_id, localNow());
          db.prepare(`UPDATE tasks SET assigned_to = ?, current_step = ?, updated_at = ? WHERE id = ?`)
            .run(fallbackMember.member_id, `Fallback: assigned to ${fallbackMember.member_name}`, localNow(), tId);
          broadcast('task.updated', { id: tId });
          autoSpawnForTask(tId).catch(console.error);
        } else {
          // No one available — leave at 'new' for manual assignment
          db.prepare(`UPDATE tasks SET status = 'new', current_step = ?, updated_at = ? WHERE id = ?`)
            .run('Routing failed — awaiting manual assignment', localNow(), tId);
          createNotification('decision_needed', 'Task needs assignment', `"${title}" could not be auto-routed. Please assign manually.`, tId);
          broadcast('task.updated', { id: tId });
        }
        db.prepare(`INSERT INTO activity_log (task_id, actor, action, notes, created_at) VALUES (?, 'Gray', 'chain_routing_fallback', ?, ?)`)
          .run(tId, 'Chain routing failed — used keyword fallback', localNow());
      }
    }).catch(err => {
      console.error(`[ChainRouting] Error: ${err.message}`);
      // Same fallback as above
      db.prepare(`UPDATE tasks SET status = 'new', current_step = ?, updated_at = ? WHERE id = ?`)
        .run('Routing error — awaiting manual assignment', localNow(), tId);
      createNotification('decision_needed', 'Routing error', `"${title}" routing failed: ${err.message}`, tId);
      broadcast('task.updated', { id: tId });
    });
  });
}
```

**Mirror**: The existing `setImmediate` fire-and-forget pattern at `server.js:5977`
**Gotcha**: Must handle the case where `routeViaChainOfCommand` throws or returns null — always fall back gracefully, never leave a task stuck
**Validate**: Auto-assign missions trigger chain routing; manual assignments bypass it

---

### Task 5: Update `autoSpawnForTask()` to allow Gray routing spawns

**Action**: UPDATE `app/server.js`
**Where**: Line 14967 (the Gray filter)
**Details**:

The current Gray filter is unconditional:
```javascript
const spawnableMembers = assignments.filter(a => a.name !== 'Gray');
```

This is still correct — Gray should never be spawned for actual work via `autoSpawnForTask()`. The routing spawn in `routeViaChainOfCommand()` uses its own lightweight CLI spawn (not `spawnMemberTerminal`), so this filter doesn't interfere.

**No change needed to line 14967.** But add an activity log entry when chain routing successfully assigns members, so the queue shows the routing path:

After `executeRoutingDecision()` calls `autoSpawnForTask()`, the existing spawn logic handles everything. The key addition is in `executeRoutingDecision()` where we log the chain: `"Board → {Executive} → {Specialist(s)}"`.

**Validate**: Gray is still filtered from `autoSpawnForTask()`. Chain routing spawns Gray separately via its own lightweight CLI call.

---

## Testing Strategy

### Manual Tests

| Test | Steps | Expected Result |
|------|-------|-----------------|
| Auto-assign routing | Submit mission with auto-assign ON, no members selected | Task shows "routing" status, current_step shows "Gray analyzing...", then routes to specialist(s) |
| Manual assignment bypass | Submit mission with specific members dragged in | Task goes directly to those members, no Gray routing |
| Routing fallback | Kill the claude CLI mid-routing (or set cli path to invalid) | Falls back to keyword-based assignment, logs warning |
| Multi-domain task | Submit "Build a new API endpoint with a frontend form and tests" | Gray assigns specialists from multiple departments |
| Priority routing | Submit urgent task with auto-assign | Routing still works, specialists get spawned |

### Edge Cases
- [ ] Task with only file attachments, no message text — Gray should still route based on file names/types
- [ ] All specialists in target department are busy (high running_tasks) — Gray should note load and still pick best available
- [ ] Claude CLI not available — should fall back to keyword routing immediately
- [ ] Gray outputs malformed JSON — parser returns null, fallback triggers
- [ ] Gray names a member that doesn't exist — parser filters them out, falls back if no valid members remain
- [ ] Gray outputs routing decision without `<routing>` tags — fallback JSON parsing catches it

---

## Validation Commands

**Package manager**: npm (detected from `app/package.json`)

1. **Server restart**: Kill and restart `node server.js` with env vars
2. **Smoke test**: `curl -X POST http://localhost:3000/api/mission -F 'message=Test chain routing' -F 'auto_assign=true' -F 'priority=normal'`
3. **Check task status**: `curl http://localhost:3000/api/queue | jq '.[0]'`
4. **Check activity log**: `sqlite3 the_team.db "SELECT * FROM activity_log WHERE action LIKE 'chain_%' ORDER BY id DESC LIMIT 5;"`
5. **Check task assignments**: `sqlite3 the_team.db "SELECT ta.*, tm.name FROM task_assignments ta JOIN team_members tm ON ta.member_id = tm.id ORDER BY ta.id DESC LIMIT 5;"`

## Acceptance Criteria
- [ ] Auto-assign missions trigger Gray as routing agent (visible in activity log)
- [ ] Gray's routing decision is parsed and applied (correct specialists assigned)
- [ ] Manual assignments bypass the chain entirely (no Gray involvement)
- [ ] Routing status is visible in the queue (current_step shows progress)
- [ ] Fallback works when Gray's routing fails (keyword-based assignment)
- [ ] Activity log shows full routing chain: Board → Executive → Specialist
- [ ] No regressions — manual assignments, escalation chain, auto-review all still work
- [ ] Routing is fast (haiku model, max-turns 1, no tools = ~2-5 seconds)

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Gray outputs unparseable routing JSON | Medium | Low | Robust parser with multiple extraction strategies + keyword fallback |
| Haiku model lacks context to route well | Low | Medium | Prompt includes full roster with departments and current workload |
| Routing adds latency to mission submission | Low | Low | Fire-and-forget via setImmediate, UI shows "routing" immediately |
| Gray routes all tasks to same specialist | Low | Medium | Include workload data in prompt, Gray instructed to balance load |
