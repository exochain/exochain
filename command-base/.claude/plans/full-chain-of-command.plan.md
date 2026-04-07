# Plan: Full Chain of Command for Board Room Directives

## Current Flow (broken)
```
Max → Board Room → keyword router → single specialist → auto-review → deliver
```
Problems: No Council deliberation, no standards, no C-Suite orchestration, no review chain.

## Target Flow
```
Max sends directive in Board Room
  ↓
Council deliberates (consensus, standards, plan)
  → Posts deliberation to Board Room chat
  → Defines: standards of work, acceptance criteria, sub-tasks
  ↓
C-Suite executive receives plan + standards
  → Breaks into sub-tasks for specialists
  → Assigns each sub-task
  ↓
Specialists execute sub-tasks
  → Each completes their piece
  ↓
C-Suite executive reviews all specialist work
  → Checks against standards
  → If fails: sends back to specialist with feedback
  → If passes: compiles and sends up
  ↓
Council reviews compiled work
  → Checks against original standards
  → If fails: sends back to C-Suite
  → If passes: delivers to Max
  ↓
Max receives finished product in Board Room
```

## Implementation Steps

### Step 1: Board Room directives use Council deliberation
- POST /api/board-room/:companyId/message should NOT skip Council
- Council spawns a Haiku call that produces:
  - Consensus summary
  - Standards of work (acceptance criteria)
  - Sub-tasks with specialist assignments
  - Executive owner

### Step 2: Council plan creates sub-tasks
- Parse Council's response into structured sub-tasks
- Create each as a child task linked to the parent
- Assign each to the right specialist

### Step 3: Executive review gate
- When all sub-tasks complete, notify the executive
- Executive reviews compiled output
- If standards met → sends to Council
- If not → sends back with feedback

### Step 4: Council final review
- Council reviews compiled work against original standards
- If passes → deliver to Max via Board Room
- If not → sends back to executive

### Step 5: Clean delivery to Max
- Final product posted as execution message in Board Room
- Notification created
- File saved to outbox
