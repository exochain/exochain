# Research Brief: AI Coding Workspace UX Patterns (Windsurf & Cursor)

**Researcher:** Pax
**Requested by:** the Board (for Max)
**Date:** 2026-03-29
**Purpose:** Research how Windsurf (Cascade) and Cursor (Composer/Agent) handle AI-powered coding workflows -- plan creation, real-time progress, diff views, approval controls, and multi-agent orchestration -- to inform the design of a web-based "Project Workspace" interface for Max's dashboard.

---

## Executive Summary

Windsurf and Cursor have converged on a similar core workflow: **Plan --> Approve --> Execute --> Review --> Accept/Reject**. Both have recently added parallel multi-agent capabilities (Windsurf Wave 13, Cursor 2.0 Mission Control). Cursor is further ahead on the web/mobile interface story with Background Agents accessible from any browser. Windsurf is stronger on "flow state" UX -- keeping the developer uninterrupted with real-time awareness of their actions.

For Max's use case (web dashboard, multiple projects, submit-and-watch, periodic summaries), the most relevant model is **Cursor's Background Agents + Web Interface**, combined with **Windsurf's Plan Mode file-based tracking** and **both platforms' diff approval patterns**.

---

## Part 1: Windsurf Cascade

### 1.1 What Cascade Is

Cascade is Windsurf's proprietary AI engine -- an agentic system that understands the entire codebase, makes multi-file changes, runs terminal commands, auto-fixes errors, and remembers preferences across sessions. It functions as an autonomous coding partner, not a simple autocomplete.

### 1.2 How Cascade Shows Real-Time Progress

| Signal | How It Works |
|--------|-------------|
| **Conversation panel** | All AI actions stream into a chat-like sidebar. Each step (file read, edit, terminal command, search) appears as a distinct message with expandable details. |
| **File activity tracking** | Cascade tracks which files you edit and view. It monitors recent edits, terminal history, open files, and clipboard activity to infer intent. The sidebar reflects what files are being touched in real time. |
| **Writes to disk before approval** | AI-generated code is written to the actual filesystem immediately (before you approve). Your dev server hot-reloads, so you see the result live in your browser. You then decide to accept or reject. |
| **Context window indicator** | Wave 13 added a visual indicator showing how much of the context window is in use, helping users anticipate limits and decide when to start a new session. |
| **Loading indicators** | Added loading spinners/indicators during "thinking" or long-running operations so the user knows the AI is working. |

### 1.3 Plan Creation and Approval

**Plan Mode** (introduced Wave 10) solves the problem of AI drifting from goals on complex tasks:

- When Plan Mode is activated, Cascade generates a `plan.md` file containing:
  - Notes and context
  - A structured task list (checkboxes)
  - The current goal being worked on
- As Cascade progresses, it **updates the plan file in real time** -- checking off completed items and updating the current goal.
- A **specialized planning agent** continuously refines the long-term plan while the primary model focuses on short-term actions.
- The developer can read and edit the plan file at any time to redirect priorities.

**Key insight for Max:** The plan-as-a-file pattern is powerful. It creates an artifact that persists, can be reviewed asynchronously, and provides a clear record of what was done vs. what remains.

### 1.4 Accept/Reject Controls

| Control | Behavior |
|---------|----------|
| **Per-hunk accept/reject** | Each changed section of code has its own Accept/Reject buttons. Keyboard shortcuts: `Option+Enter` (accept hunk), `Option+Shift+Backspace` (reject hunk). |
| **Per-file accept/reject** | Accept or reject all changes in a single file at once. |
| **Global accept/reject** | Buttons at the bottom of the screen to accept or reject all changes across all files. |
| **Navigation arrows** | Buttons to navigate between individual change hunks across files. |
| **Diff decorations** | In-editor red/green diff highlighting showing exactly what changed. |

### 1.5 Turbo Mode and Autonomy Levels

Cascade offers three levels of command auto-execution:

| Level | Behavior |
|-------|----------|
| **Off** | Every terminal command requires manual approval. |
| **Auto** | Most commands auto-execute; dangerous ones require approval. |
| **Turbo** | All terminal commands auto-execute unless explicitly on the "Deny" list. Maximum autonomy. |

**Key insight for Max:** This maps directly to his desired "submit and watch" flow. Turbo Mode is the closest existing pattern to what Max wants -- but in a web interface rather than an IDE.

### 1.6 Multi-File Editing

Cascade makes coordinated changes across multiple files simultaneously. It can handle tasks like adding a new API endpoint with the route, controller, model, and tests in one pass. Each modified file gets its own diff view with independent accept/reject controls.

### 1.7 Pause/Resume/Cancel

- **Interrupt**: Type a new message while Cascade is working to redirect it.
- **Resume**: Type "continue" and Cascade picks up where it left off, using its memory of recent actions and context.
- **Context continuity**: Cascade tracks recent actions so "continue my work" resumes seamlessly even after stepping away.
- No explicit "pause button" in the UI -- interruption is done conversationally.

### 1.8 Parallel Sessions (Wave 13)

- **Git worktrees**: Each Cascade session can operate in its own Git worktree -- a separate branch in a separate directory sharing the same Git history.
- **Side-by-side panes**: Multiple Cascade sessions can be docked in panes or tabs for monitoring agents simultaneously.
- **Dedicated terminal profiles**: Each agent session gets its own terminal, preventing conflicts.
- **No background agents**: Unlike Cursor, Windsurf's parallel sessions require the IDE to be open and visible. There is no "fire and forget" remote execution model yet.

### 1.9 Token/Cost Tracking

| Feature | Details |
|---------|---------|
| **Credit system** | Each message to Cascade costs credits. 1 prompt = 1 credit (regardless of how many actions Cascade takes to fulfill it). |
| **Model multipliers** | Different models cost different credit amounts (0 credits for free models like SWE-1.5, up to 30 credits for premium models). |
| **Pricing formula** | API price + 20% margin, converted at $0.04/credit. |
| **Monthly allocation** | Credits issued monthly per plan tier. Do not roll over. |
| **Add-on credits** | Purchased separately. These DO carry over. |
| **Auto-refill** | System tops up credits when balance drops below 15, with configurable budget caps ($160/month default). |
| **Context window indicator** | Visual bar showing how full the context is (not cost, but capacity). |

---

## Part 2: Cursor Composer & Agent

### 2.1 What Composer/Agent Is

Cursor started with "Composer" as its multi-file editing mode. It has since evolved into "Agent" mode -- a fully autonomous coding agent that can plan, edit files, run terminal commands, and iterate on errors. Agent mode subsumes Composer's capabilities.

### 2.2 How Cursor Shows the Plan Before Executing

**Plan Mode** (activated with `Shift+Tab` or auto-suggested for complex tasks):

1. **Codebase research phase**: The agent scans files, checks dependencies, analyzes documentation, and gathers context. It may ask clarifying questions.
2. **Plan creation**: Generates a Markdown file with:
   - File paths and code references
   - Structured to-do list
   - Rationale for each change
3. **Interactive plan editor**: Users can edit the plan inline -- adding, removing, or reordering tasks before execution begins.
4. **Execution**: Once the user approves the plan, the agent executes it step by step, showing diffs for each change.

**Key insight for Max:** Cursor's plan mode with its interactive editor is the gold standard for the "review before execute" pattern. The plan is a living document that the user co-authors with the AI.

### 2.3 Real-Time File Changes

| Signal | How It Works |
|--------|-------------|
| **Inline diff decorations** | Red/green highlighting in the editor showing exactly what changed. Alternating chunks of deleted (red) and added (green) code. |
| **Per-hunk accept/reject** | Each chunk can be independently accepted or rejected. |
| **Aggregated multi-file diffs** | All changes across files collected in one reviewable view. |
| **Agent drawer** | A sidebar/drawer showing the agent's current activity, files being modified, and progress through the plan. |
| **Streaming output** | Changes appear in real time as the agent generates them -- users see code being written character by character. |

### 2.4 How Users Approve/Reject/Guide Changes

- **Accept all / Reject all** buttons for the entire changeset.
- **Per-file and per-hunk** granular approval.
- **Inline editing**: Users can manually edit AI-generated code before accepting.
- **Conversational guidance**: Type follow-up instructions to redirect the agent mid-task.
- **Yolo mode**: Similar to Windsurf's Turbo Mode -- auto-applies changes without asking. Configurable per-user.

### 2.5 Background Agents (The Big Differentiator)

This is Cursor's most relevant feature for Max's use case:

| Feature | Details |
|---------|---------|
| **Remote execution** | Agents run in isolated Ubuntu VMs with internet access. They clone your repo from GitHub and work on a separate branch. |
| **Fire and forget** | Start a task, close your laptop, come back later. The agent keeps working. |
| **Web interface** | Access agents from any browser at `cursor.com/agents`. Create, monitor, review, and merge from desktop, tablet, or phone. Can be installed as a PWA. |
| **Live session joining** | Join an agent's live session from the web app to watch it work in real time. |
| **Diff review** | Review all agent-generated diffs from the web interface. Create pull requests directly. |
| **GitHub integration** | Agents push to branches and can open PRs. Team members with repo access can review and merge. |
| **Slack integration** | Launch agents via `@Cursor` in Slack. Receive completion notifications with links to Cursor and GitHub. |
| **Notification options** | Opt into Slack notifications when starting agents from web/mobile. |
| **Cost model** | Requires usage-based spending enabled (minimum $10-$20 funding). Each agent run consumes credits based on model and tokens used. |

**Key insight for Max:** Background Agents are exactly what Max is describing -- submit a task, watch it execute from a web UI, get notified when done. The web interface handles PR creation, diff review, and multi-agent management from any device.

### 2.6 Mission Control (Multi-Agent Management)

Cursor 2.0 introduced Mission Control -- the command center for parallel agent work:

| Feature | Details |
|---------|---------|
| **Grid view** | macOS Expose-style view of all running agent sessions. |
| **Up to 8 parallel agents** | Run multiple agents simultaneously on a single prompt or separate tasks. |
| **Agent sidebar** | Right-side panel where you create, name, and manage agents. Each agent shows status (running/completed/waiting), progress indicators, and output logs. |
| **Shadow Virtual File System (SVFS)** | Agents write to discrete virtual trees. Changes are logically merged and presented for single-click approval. |
| **Branch isolation** | Each agent works on its own branch via git worktrees or remote machines. No file conflicts. |
| **PRD-based task subdivision** | Submit a single Product Requirements Document and the system subdivides work across agents (e.g., Frontend Architect agent + Backend Database agent simultaneously). |

**Key insight for Max:** Mission Control is the closest existing product to what Max wants to build. The grid view of agents, status tracking, and parallel execution is the UX model to study.

### 2.7 Handling Large Context (Big Codebases)

- **Codebase indexing**: Cursor indexes the entire project for fast retrieval. Embeddings stored locally.
- **Smart context selection**: Agent automatically identifies relevant files and pulls them into context.
- **`.cursorrules` file**: Project-level instruction file that sets persistent context, coding conventions, and constraints.
- **Context pruning**: When approaching token limits, the agent summarizes older context and keeps recent changes.

---

## Part 3: Shared UX Patterns

### 3.1 The Universal Workflow

Both platforms converge on this cycle:

```
1. USER PROMPTS  -->  2. AI PLANS  -->  3. USER REVIEWS PLAN  -->  4. AI EXECUTES
                                                                         |
      6. USER ACCEPTS/REJECTS  <--  5. AI SHOWS DIFFS  <-----------------+
```

Each stage has clear visual affordances:
- **Stage 1**: Chat input with context indicators (which files are included).
- **Stage 2**: Plan appears as a structured markdown document with checkboxes.
- **Stage 3**: User can edit the plan, add constraints, remove tasks.
- **Stage 4**: Real-time streaming of changes, file-by-file.
- **Stage 5**: Diff view with red/green highlighting, per-hunk navigation.
- **Stage 6**: Accept/Reject at hunk, file, or global level.

### 3.2 Progress Indicators That Actually Mean Something

| Indicator | What It Communicates |
|-----------|---------------------|
| **Plan checkbox progress** | "3 of 7 tasks complete" -- concrete progress through the plan. |
| **File list with status** | Which files have been modified, which are pending, which are complete. |
| **Context window usage** | Visual bar showing how full the context is (when to start a new session). |
| **Streaming text** | Character-by-character output so the user knows the AI is actively generating. |
| **Terminal output** | Real-time terminal logs when commands are running (build, test, install). |
| **Agent status badges** | Running / Completed / Waiting / Error states for each agent session. |

### 3.3 User Intervention at Any Point

Both platforms support:
- **Mid-generation interruption**: Send a new message to redirect the AI.
- **Plan editing**: Modify the plan before or during execution.
- **Selective acceptance**: Accept some changes, reject others.
- **Manual editing**: Edit AI-generated code before accepting.
- **Branching**: AI works on a branch, user merges when satisfied.

### 3.4 Multiple Concurrent Sessions

| Feature | Windsurf | Cursor |
|---------|----------|--------|
| **Parallel agents** | Yes (Wave 13, git worktrees) | Yes (Mission Control, up to 8) |
| **Background execution** | No (must have IDE open) | Yes (remote VMs, fire-and-forget) |
| **Web access** | No | Yes (cursor.com/agents, PWA) |
| **Mobile access** | No | Yes (phone/tablet browser) |
| **Slack integration** | No | Yes (@Cursor bot) |
| **Branch isolation** | Git worktrees | Git worktrees + remote VMs |
| **Cross-agent coordination** | Manual | SVFS merge + single-click approval |

---

## Part 4: What Works for Max's Use Case

### 4.1 Max's Requirements Mapped to Existing Patterns

| Max Wants | Best Existing Pattern | Source |
|-----------|----------------------|--------|
| Submit a big prompt from web UI | Cursor Background Agents web interface | cursor.com/agents |
| See a plan before execution | Cursor Plan Mode + Windsurf Plan Mode | Both generate markdown plans with checkboxes |
| Approve the plan, then watch it execute | Cursor's plan-then-execute flow | Plan Mode approval triggers Agent execution |
| Active summaries every 20-30 minutes | **No existing pattern** -- both platforms show real-time streaming but neither generates periodic summaries | Custom feature needed |
| Pause/cancel/redirect at any time | Conversational interruption (both platforms) | Type a new message to redirect |
| Real-time progress on what files are being edited | Cursor's agent drawer + Windsurf's file activity tracking | Sidebar showing active files and agent status |
| Multi-project support | Cursor Mission Control (multiple agents across repos) | Each agent clones a different repo |
| All from a web interface | Cursor Background Agents web UI | Only Cursor has this today |
| AI agents do coding in spawned terminals | Both platforms run terminal commands as part of their agent flow | Terminal integration is standard |

### 4.2 Recommended Architecture for Max's Dashboard

Based on the research, here is what the "Project Workspace" view should include:

#### Panel 1: Agent Mission Control (left sidebar or grid)
Modeled after Cursor's Mission Control:
- Grid or list of all active agent sessions across all projects (Clipper Engine, Animation Studio, The Team dashboard).
- Each agent card shows: name, project, current task, status badge (running/paused/completed/error), elapsed time, credit/token cost so far.
- Click an agent to open its detail view.
- "New Agent" button to start a new task.

#### Panel 2: Plan View (center-top)
Modeled after both platforms' Plan Mode:
- When a new task is submitted, the AI generates a plan displayed as a structured markdown document with checkboxes.
- Max can edit the plan inline -- add tasks, remove tasks, reorder, add constraints.
- "Approve Plan" button to trigger execution.
- During execution, checkboxes update in real time as tasks complete.
- Plan shows which step is currently being worked on (highlighted or animated).

#### Panel 3: Live Activity Feed (center-bottom)
Modeled after Windsurf's conversation panel:
- Real-time streaming log of what the agent is doing: reading files, making edits, running commands, encountering errors.
- Each action is a collapsible card (expand to see details like terminal output or file contents).
- Color-coded by action type: blue (reading), green (writing), yellow (terminal), red (error).

#### Panel 4: Diff Review (right panel or modal)
Modeled after both platforms' diff views:
- Shows all changed files with red/green diff highlighting.
- Per-hunk accept/reject buttons.
- Per-file accept/reject.
- "Accept All" / "Reject All" global buttons.
- Navigation arrows to jump between changes.
- Side-by-side or unified diff toggle.

#### Panel 5: Summary & Controls (top bar)
Custom feature (neither platform does this well):
- **Active summary**: Auto-generated plain-English summary of what the agent has accomplished so far, updated every N minutes (configurable, default 20-30 min).
- **Pause** button: Suspends the agent's current work (saves state).
- **Resume** button: Picks up where it left off.
- **Cancel** button: Terminates the agent and rolls back uncommitted changes.
- **Redirect** input: Send a new instruction to change the agent's direction without canceling.
- **Token/cost counter**: Running total of tokens consumed and estimated cost.

### 4.3 Features Neither Platform Has (Opportunities)

These are gaps in both Windsurf and Cursor that Max's dashboard could fill:

| Gap | Opportunity |
|-----|-------------|
| **Periodic summaries** | Neither platform generates "here's what I've done in the last 30 minutes" summaries. Max's dashboard could poll the agent's activity log and generate a condensed summary on a timer. |
| **Cross-project dashboard** | Neither platform shows agents from multiple repos in one view. Mission Control is per-workspace. Max's dashboard manages all projects in one place. |
| **Delegation chain visibility** | Neither platform shows WHO (which team member) is doing the work. Max's dashboard shows the Board delegating to Anvil, Spark, etc. |
| **Historical session replay** | Neither platform lets you replay a past agent session to see what it did. Max's dashboard could store the full activity log and make it browsable. |
| **Cost budgeting per project** | Neither platform breaks down costs by project. Max's dashboard tracks token spend per project, per agent, per session. |
| **Approval queues** | Neither platform batches approvals. Max's dashboard could collect all pending approvals across agents into one queue: "3 plans need your review, 7 diffs ready to accept." |

### 4.4 Technical Implementation Notes

Based on how these platforms work under the hood:

1. **Agent execution model**: Both platforms run agents as long-running processes (Cursor in remote VMs, Windsurf locally). For Max's dashboard, each team member spawns a Claude Code CLI session -- this is already how The Team works with the auto-spawn terminal system.

2. **Real-time updates**: Both platforms use streaming (SSE or WebSocket) to push agent activity to the UI. Max's dashboard should use WebSocket (already in the stack) to stream agent output from spawned terminals to the browser.

3. **Plan files**: Both platforms use markdown files for plans. This is simple and effective. The dashboard should render markdown plans with interactive checkboxes.

4. **Diff generation**: Both platforms use standard unified diff format. Libraries like `diff2html` or `monaco-editor`'s diff viewer can render these in the browser.

5. **State persistence**: Cursor stores agent state in remote VMs. For Max's dashboard, store agent session state in SQLite (activity log, plan progress, file changes) so sessions survive browser refreshes and can be reviewed later.

6. **Branch isolation**: Both platforms use git worktrees or separate branches. Each agent session should work on a named branch, making rollback and review straightforward.

---

## Part 5: Competitive Landscape Note

Two other tools are worth noting:

**OpenAI Codex** (2025-2026): Launched as a cloud-based coding agent accessible from ChatGPT, a macOS app, and a CLI. Each task runs in a sandbox. The Codex App is described as "an orchestration layer -- a central dashboard where you manage multiple AI coding agents running simultaneously." Tasks take 1-30 minutes. It pushes PRs when done. This is conceptually very close to what Max wants, but locked into OpenAI's ecosystem.

**Antigravity/Superset**: Purpose-built for parallel agent orchestration. Worth investigating if Max wants to see how "AI team manager" interfaces handle task subdivision and conflict resolution across many agents.

---

## Sources

- [Cascade | Windsurf](https://windsurf.com/cascade)
- [Windsurf Cascade Docs](https://docs.windsurf.com/windsurf/cascade/cascade)
- [Windsurf Wave 10: Planning Mode](https://windsurf.com/blog/windsurf-wave-10-planning-mode)
- [Windsurf Wave 13: Parallel Agents](https://windsurf.com/blog/windsurf-wave-13)
- [Windsurf Workflows Docs](https://docs.windsurf.com/windsurf/cascade/workflows)
- [Windsurf Plans and Usage](https://docs.windsurf.com/windsurf/accounts/usage)
- [Windsurf Pricing & Credits Guide 2026](https://devgent.org/en/windsurf-pricing-credits-en/)
- [Cursor Plan Mode Blog Post](https://cursor.com/blog/plan-mode)
- [Cursor Background Agents Docs](https://docs.cursor.com/en/background-agent)
- [Cursor Web & Mobile Agent Docs](https://docs.cursor.com/get-started/web-and-mobile-agent)
- [Cursor Agent Best Practices](https://cursor.com/blog/agent-best-practices)
- [Cursor 2.0 Changelog](https://cursor.com/changelog/2-0)
- [Cursor Agent on Web Blog Post](https://cursor.com/blog/agent-web)
- [Cursor Background Agents in Slack](https://cursor.com/changelog/1-1)
- [Cursor 2.0 Review: Multi-Agent Editor](https://aitoolsreview.co.uk/insights/cursor-2-0-review-2026)
- [Windsurf vs Cursor Comparison (Builder.io)](https://www.builder.io/blog/windsurf-vs-cursor)
- [Cursor AI Review 2026 (Prismic)](https://prismic.io/blog/cursor-ai)
- [Windsurf Review 2026 (Second Talent)](https://www.secondtalent.com/resources/windsurf-review/)
- [Windsurf AI Review 2026 (NxCode)](https://www.nxcode.io/resources/news/windsurf-ai-review-2026-best-ide-for-beginners)
- [OpenAI Codex](https://openai.com/index/introducing-codex/)
- [Cursor vs Windsurf vs Claude Code 2026 (NxCode)](https://www.nxcode.io/resources/news/cursor-vs-windsurf-vs-claude-code-2026)
