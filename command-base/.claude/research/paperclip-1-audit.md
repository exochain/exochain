# Paperclip-1 Repository Audit

**Repository:** https://github.com/mstewartbz/paperclip-1
**Upstream:** https://github.com/paperclipai/paperclip
**Audit Date:** 2026-03-26
**Auditor:** Pax (Senior Researcher, The Team)

---

## 1. What Is This Project?

Paperclip is an **open-source orchestration platform for autonomous AI agent companies**. It is not an agent framework or chatbot -- it is a **control plane** that coordinates multiple AI agents (Claude Code, Codex, Cursor, OpenClaw, Gemini, etc.) into a structured organization with:

- Org charts with reporting hierarchies
- Goal alignment cascading from company mission to individual tasks
- Budget enforcement with hard-stop auto-pause
- Governance and approval gates
- Ticket/issue-based task management (Kanban, inbox, routines)
- Heartbeat-driven scheduled execution
- Full audit logging and cost tracking
- Multi-company isolation on a single deployment

**The tagline:** "If OpenClaw is an employee, Paperclip is the company."

**License:** MIT
**Version:** 0.3.1 (pre-1.0, actively developed)
**Created:** 2026-03-28 (very recent fork)

---

## 2. Technology Stack

### Backend (server/)
| Technology | Version | Purpose |
|---|---|---|
| **Node.js** | 20+ | Runtime |
| **Express 5** | ^5.1.0 | HTTP API framework |
| **TypeScript** | ^5.7.3 | Language |
| **Drizzle ORM** | ^0.38.4 | Database ORM and migrations |
| **PostgreSQL 17** | External or embedded | Primary database |
| **embedded-postgres** | ^18.1.0-beta.16 | Zero-config local dev DB |
| **WebSocket (ws)** | ^8.19.0 | Real-time live events |
| **Pino** | ^9.6.0 | Structured logging |
| **Sharp** | ^0.34.5 | Image processing |
| **better-auth** | 1.4.18 | Authentication (authenticated mode) |
| **Zod** | ^3.24.2 | Schema validation |
| **AWS S3 SDK** | ^3.888.0 | S3 storage provider |
| **multer** | ^2.0.2 | File upload handling |
| **DOMPurify + jsdom** | latest | HTML sanitization |

### Frontend (ui/)
| Technology | Version | Purpose |
|---|---|---|
| **React** | 19 | UI framework |
| **Vite** | ^6.1.0 | Build tooling and dev server |
| **TailwindCSS** | v4 | Styling |
| **Radix UI** | ^1.4.3 | Accessible UI primitives |
| **shadcn/ui** | Custom set | Component library (21 primitives) |
| **TanStack React Query** | ^5.90.21 | Server state management |
| **React Router DOM** | ^7.1.5 | Routing |
| **dnd-kit** | latest | Drag and drop (Kanban board) |
| **Lexical** | 0.35.0 | Rich text editing |
| **MDX Editor** | ^3.52.4 | Markdown editing |
| **Mermaid** | ^11.12.0 | Diagram rendering |
| **Lucide React** | ^0.574.0 | Icons |
| **cmdk** | ^1.1.1 | Command palette |
| **class-variance-authority** | ^0.7.1 | Variant-based component styling |
| **react-markdown** | ^10.1.0 | Markdown rendering |

### Infrastructure
| Technology | Purpose |
|---|---|
| **pnpm** | Package manager (monorepo workspaces) |
| **Docker** | Containerized deployment |
| **Playwright** | E2E testing |
| **Vitest** | Unit testing |
| **esbuild** | CLI and plugin bundling |
| **promptfoo** | Agent evaluation framework |

---

## 3. Architecture

### Monorepo Structure (pnpm workspaces)

```
paperclip/
  packages/
    db/                    -- Drizzle schema, migrations, DB client
    shared/                -- Types, constants, validators, API paths
    adapter-utils/         -- Shared adapter utilities
    adapters/
      claude-local/        -- Claude Code CLI adapter
      codex-local/         -- OpenAI Codex CLI adapter
      cursor-local/        -- Cursor CLI adapter
      gemini-local/        -- Gemini CLI adapter
      openclaw-gateway/    -- OpenClaw SSE gateway adapter
      opencode-local/      -- OpenCode CLI adapter
      pi-local/            -- Pi CLI adapter
    plugins/
      sdk/                 -- Plugin development SDK
      create-paperclip-plugin/  -- Plugin scaffolding tool
      examples/            -- Example plugins
  server/                  -- Express API server
  ui/                      -- React + Vite frontend
  cli/                     -- CLI tool (paperclipai)
  skills/                  -- Agent skills (injected at runtime)
  scripts/                 -- Build, release, backup scripts
  tests/                   -- E2E and release smoke tests
  evals/                   -- Agent evaluation suites (promptfoo)
  doc/                     -- Comprehensive documentation
  docker/                  -- Docker-specific configs
```

### Server Architecture

The server is a single Node.js process with these layers:

1. **Express App** (`app.ts`) -- HTTP server with JSON body parsing, hostname guard, actor middleware
2. **Routes** (`routes/`) -- 25 route modules covering companies, agents, issues, goals, costs, approvals, plugins, etc.
3. **Services** (`services/`) -- ~60 service modules covering domain logic, heartbeat scheduling, plugin lifecycle, workspace management
4. **Adapters** (`adapters/`) -- Registry pattern for plugging in different AI agent runtimes
5. **Storage** (`storage/`) -- Pluggable storage (local disk or S3)
6. **Realtime** (`realtime/`) -- WebSocket server for live event streaming
7. **Auth** (`auth/`) -- Dual-mode: local_trusted (implicit board user) or authenticated (better-auth)
8. **Secrets** (`secrets/`) -- Encrypted secret management with key rotation
9. **Middleware** -- Logger, error handler, actor resolution, hostname guard, board mutation guard

### Database Schema

**60+ tables** covering a comprehensive domain model:

- **Core entities:** companies, agents, projects, issues, goals, routines
- **Agent operations:** heartbeat_runs, heartbeat_run_events, agent_runtime_state, agent_task_sessions, agent_wakeup_requests, agent_config_revisions
- **Governance:** approvals, approval_comments, budget_policies, budget_incidents
- **Cost tracking:** cost_events, finance_events
- **Execution:** execution_workspaces, workspace_operations, workspace_runtime_services
- **Plugin system:** plugins, plugin_config, plugin_entities, plugin_jobs, plugin_logs, plugin_state, plugin_webhooks, plugin_company_settings
- **Auth/access:** auth users, company_memberships, instance_user_roles, agent_api_keys, board_api_keys, invites, join_requests
- **Content:** documents, document_revisions, issue_comments, issue_attachments, issue_documents, assets
- **Organization:** labels, issue_labels, issue_work_products, company_skills, company_secrets

### Frontend Architecture

- **Pages** (39 pages) -- Full-featured SPA with company-scoped routing (`/:companyPrefix/...`)
- **Components** (80+ components) -- Rich UI including Kanban board, org chart, command palette, transcript viewer, markdown editor, activity charts
- **Context providers** (8) -- Company, dialog, panel, sidebar, theme, toast, breadcrumb, live updates
- **API client** -- Clean fetch-based wrapper with typed endpoints
- **Plugin slots** -- Dynamic UI extension points for plugins
- **Real-time** -- WebSocket-based live event streaming with React Query cache invalidation

---

## 4. Key Features Already Built

### Agent Orchestration
- **Multi-adapter support:** Claude Code, Codex, Cursor, Gemini, OpenClaw, OpenCode, Pi, HTTP webhooks
- **Heartbeat system:** Scheduled agent execution with queuing, orphan recovery, and concurrent run limits
- **Session management:** Persistent agent task sessions across heartbeats with session compaction
- **Workspace management:** Git worktree-based execution workspaces with automatic clone, branch creation, and runtime service injection
- **Agent configuration revisions:** Full versioning of agent configs with rollback

### Task Management
- **Issue tracking:** Full lifecycle (backlog, todo, in_progress, in_review, blocked, done, cancelled)
- **Kanban board:** Drag-and-drop with dnd-kit
- **Priority system:** Priority levels with visual indicators
- **Assignee management:** Single-assignee atomic checkout semantics
- **Comment threads:** Threaded discussions on issues
- **Document attachments:** File attachments and linked documents
- **Inbox:** Personal task inbox with unread tracking
- **Work products:** Output tracking per issue

### Organizational Structure
- **Multi-company:** Complete data isolation between companies
- **Org chart:** Visual org chart with reporting hierarchies
- **Goal alignment:** Hierarchical goals (company > project > task) with automatic context propagation
- **Projects:** Project-scoped issue organization with workspace configuration

### Governance and Finance
- **Approval system:** Governed actions require board approval with comments
- **Budget enforcement:** Monthly budgets per agent/project with hard-stop auto-pause
- **Cost tracking:** Token-level cost event recording with dashboard analytics
- **Finance events:** Financial event streaming for accounting

### Plugin System (Sophisticated)
- **Plugin SDK:** Full development kit with RPC-based worker communication
- **Plugin lifecycle:** State machine (installed -> ready -> disabled -> error -> uninstalled)
- **Plugin UI slots:** Dynamic sidebar and dashboard extension points
- **Plugin jobs:** Scheduled and on-demand background jobs
- **Plugin tools:** Custom tool registration and dispatch
- **Plugin events:** Event bus for inter-plugin communication
- **Plugin state:** Persistent per-plugin key-value store
- **Plugin dev watcher:** Hot reload during development
- **Plugin marketplace planned:** "Clipmart" for downloadable company templates

### Company Portability
- **Export/import:** Full company export including agents, projects, issues, skills, routines
- **Collision strategies:** Configurable handling for conflicts during import
- **Secret scrubbing:** Automatic removal of sensitive data from exports
- **README generation:** Auto-generated documentation for exported companies

### Routines (Automated Workflows)
- **Cron scheduling:** Standard cron-based routine triggers
- **Webhook triggers:** HTTP webhook-triggered routines with signature verification
- **Catch-up policies:** Configurable missed-run catch-up behavior
- **Concurrency control:** Configurable concurrent execution limits

### Authentication and Access Control
- **Dual mode:** Local trusted (zero-config dev) or authenticated (production)
- **better-auth integration:** Full auth flow with session management
- **Agent API keys:** Hashed bearer tokens for agent-to-server communication
- **Board claim:** One-time ownership claim for transitioning deployments
- **Invite system:** Email-based user invitations
- **CLI auth:** CLI tool authentication flow
- **Role-based access:** Instance admin, company owner, member roles

### Developer Experience
- **Embedded PostgreSQL:** Zero-config database for local development
- **Auto-migration:** Automatic schema migration detection and application
- **Database backups:** Scheduled automated backups with retention policies
- **Skills system:** Runtime skill injection for agents (Paperclip-specific, agent creation, plugin creation)
- **AGENTS.md:** Comprehensive contributor guidance
- **E2E tests:** Playwright-based end-to-end testing
- **Evaluation suite:** promptfoo-based agent evaluation

---

## 5. Code Quality Assessment

### Strengths
1. **Well-architected monorepo:** Clean separation of concerns across packages with workspace references
2. **Comprehensive type safety:** Strict TypeScript throughout with Zod validation at boundaries
3. **Domain-driven design:** Services encapsulate domain logic cleanly (agents, heartbeats, budgets, goals)
4. **Atomic operations:** Careful attention to concurrent access (task checkout, budget enforcement)
5. **Thorough error handling:** Custom error types (conflict, notFound, unprocessable, forbidden) with consistent HTTP status codes
6. **Structured logging:** Pino-based logging with sensitive data redaction
7. **Extensive documentation:** 20+ doc files covering spec, implementation, deployment, development
8. **Database discipline:** Drizzle ORM with proper migrations, backup, and recovery
9. **Real-time architecture:** WebSocket-based live events with proper connection management
10. **Plugin architecture:** Production-quality plugin system with state machine lifecycle

### Areas of Concern
1. **Pre-1.0 maturity:** Version 0.3.1 -- APIs may change, some features are "coming soon"
2. **Single-process architecture:** Everything runs in one Node.js process (heartbeats, cron, backups, plugins)
3. **Limited test coverage:** Tests exist but coverage appears focused on integration/E2E rather than comprehensive unit testing
4. **Embedded Postgres complexity:** The embedded-postgres handling in `index.ts` is ~300 lines of edge-case management
5. **Large service files:** Some services (heartbeat.ts, company-portability.ts) are very large monolithic files

### Verdict: **High-quality experimental/early-production code.** The architecture is production-caliber but the version number and some rough edges indicate it is not yet battle-tested at scale. The code is well-organized, well-typed, and well-documented -- significantly above average for an open-source project at this stage.

---

## 6. Relevance to The Team Projects

### 6.1 The Team Dashboard

**HIGH RELEVANCE.** Paperclip's entire UI is essentially a sophisticated team/project dashboard.

**Directly reusable patterns:**

| Pattern | Location | Relevance |
|---|---|---|
| **Dashboard page with metric cards** | `ui/src/pages/Dashboard.tsx`, `ui/src/components/MetricCard.tsx` | Direct template for our dashboard metrics |
| **Kanban board** | `ui/src/components/KanbanBoard.tsx` | Drag-and-drop task management with dnd-kit |
| **Sidebar with navigation** | `ui/src/components/Sidebar.tsx`, `SidebarNavItem.tsx`, `SidebarSection.tsx` | Multi-section sidebar with badges and live counts |
| **Layout system** | `ui/src/components/Layout.tsx` | Company rail + sidebar + main content + properties panel |
| **Command palette** | `ui/src/components/CommandPalette.tsx` | cmdk-based search and navigation |
| **Activity feed** | `ui/src/components/ActivityRow.tsx`, `ui/src/pages/Activity.tsx` | Real-time activity stream with animation |
| **Activity charts** | `ui/src/components/ActivityCharts.tsx` | Run activity, priority distribution, status breakdown, success rate |
| **Breadcrumb system** | `ui/src/components/BreadcrumbBar.tsx`, `ui/src/context/BreadcrumbContext.tsx` | Context-aware breadcrumbs |
| **Company/workspace switcher** | `ui/src/components/CompanySwitcher.tsx`, `CompanyRail.tsx` | Multi-workspace selection rail |
| **Inbox with badge system** | `ui/src/pages/Inbox.tsx`, `ui/src/hooks/useInboxBadge.ts` | Notification inbox with unread counts |
| **Properties panel** | `ui/src/components/PropertiesPanel.tsx`, `IssueProperties.tsx` | Side panel for entity details |
| **Status badges and icons** | `ui/src/components/StatusBadge.tsx`, `StatusIcon.tsx`, `PriorityIcon.tsx` | Consistent status visualization |
| **Theme system** | `ui/src/context/ThemeContext.tsx` | Dark/light mode toggle |
| **Toast notifications** | `ui/src/context/ToastContext.tsx`, `ui/src/components/ToastViewport.tsx` | Toast notification system |
| **Mobile bottom nav** | `ui/src/components/MobileBottomNav.tsx` | Responsive mobile navigation |
| **Onboarding wizard** | `ui/src/components/OnboardingWizard.tsx` | Multi-step guided setup |
| **API client pattern** | `ui/src/api/client.ts` | Clean fetch wrapper with error handling |
| **Query key management** | `ui/src/lib/queryKeys.ts` | Organized React Query cache keys |
| **shadcn/ui primitives** | `ui/src/components/ui/` | 21 Radix-based components |
| **WebSocket live updates** | `ui/src/context/LiveUpdatesProvider.tsx` | Real-time data push to React Query cache |
| **Filter bar** | `ui/src/components/FilterBar.tsx` | Reusable data filtering |
| **Empty states** | `ui/src/components/EmptyState.tsx` | Consistent empty state patterns |

**Architecture patterns to adopt:**
- Company-scoped routing with `/:companyPrefix/` prefix pattern
- Context-driven state management (Company, Dialog, Panel, Sidebar, Theme, Toast)
- React Query for all server state with structured query keys
- WebSocket for live updates that invalidate/update React Query cache
- Plugin slot system for extensible UI regions

### 6.2 Clipper Engine (Media Processing)

**MODERATE RELEVANCE.** Not directly a media processing tool, but has relevant patterns:

| Pattern | Location | Relevance |
|---|---|---|
| **Storage abstraction** | `server/src/storage/` | Pluggable storage (local disk + S3) with provider registry |
| **Asset management** | `server/src/routes/assets.ts`, `server/src/services/assets.ts` | File upload, storage, and retrieval |
| **Sharp integration** | `server/package.json` (sharp ^0.34.5) | Image processing pipeline |
| **File upload handling** | multer integration | Multi-part form data handling |
| **Work product tracking** | `server/src/services/work-products.ts` | Output/artifact tracking per task |
| **Execution workspace pattern** | `server/src/services/workspace-runtime.ts` | Isolated execution environments for processing jobs |
| **Job scheduling** | `server/src/services/plugin-job-scheduler.ts`, `plugin-job-coordinator.ts` | Background job queue with scheduling |
| **Process management** | `server/src/adapters/process/` | Child process lifecycle management |

**Patterns to adopt for Clipper Engine:**
- Storage provider pattern (local disk for dev, S3 for production)
- Job scheduling and coordination system
- Process lifecycle management for external tool invocation
- Workspace isolation for parallel processing jobs

### 6.3 Animation Studio (AI Content Generation)

**HIGH RELEVANCE.** The AI agent orchestration patterns are directly applicable:

| Pattern | Location | Relevance |
|---|---|---|
| **Agent adapter system** | `packages/adapters/`, `packages/adapter-utils/` | Pluggable AI model/runtime integration |
| **Heartbeat execution** | `server/src/services/heartbeat.ts` | Scheduled AI task execution with queuing |
| **Session management** | Agent task sessions, session compaction | Persistent AI conversation context |
| **Budget enforcement** | `server/src/services/budgets.ts` | Cost control for AI operations |
| **Cost tracking** | `server/src/services/costs.ts`, `server/src/services/finance.ts` | Token-level cost accounting |
| **Goal-aligned prompting** | Goal ancestry injection into agent prompts | Context-aware AI generation |
| **Transcript viewer** | `ui/src/components/transcript/` | AI run transcript visualization |
| **Live run monitoring** | `ui/src/components/LiveRunWidget.tsx` | Real-time AI execution monitoring |
| **Skills injection** | `skills/` directory, `server/src/services/company-skills.ts` | Runtime capability injection |
| **Agent configuration** | `ui/src/components/AgentConfigForm.tsx`, `agent-config-defaults.ts` | Model selection, parameter tuning UI |
| **Plugin SDK** | `packages/plugins/sdk/` | Extensible tool/capability registration |
| **Approval workflows** | `server/src/services/approvals.ts` | Human-in-the-loop for AI outputs |
| **Run log storage** | `server/src/services/run-log-store.ts` | Execution trace persistence |

**Patterns to adopt for Animation Studio:**
- Adapter pattern for swappable AI models (different models for different generation tasks)
- Heartbeat-driven generation pipeline (schedule, queue, execute, review)
- Budget enforcement to prevent runaway AI costs
- Approval gates for generated content before publishing
- Transcript/run log visualization for debugging generation quality
- Skills system for injecting domain-specific generation capabilities

---

## 7. MCP and AI Integration Patterns

Paperclip does not directly implement MCP (Model Context Protocol) servers/clients in its core. Instead, it takes a different approach:

### Agent Integration Model
1. **Adapter pattern:** Each AI tool (Claude, Codex, Cursor, etc.) gets a dedicated adapter module that knows how to:
   - Spawn the tool's CLI process
   - Pass prompts and context
   - Parse output and cost data
   - Manage session state

2. **Skill injection:** Runtime markdown files injected into agent context at execution time, providing:
   - Paperclip API knowledge (how to create issues, update status, etc.)
   - Company-specific instructions
   - Project-specific context

3. **Agent API keys:** JWT-based authentication for agents to call back to the Paperclip API during execution

4. **Environment injection:** PAPERCLIP_WORKSPACE_* and PAPERCLIP_RUNTIME_* env vars injected into agent processes

### AI Patterns Worth Adopting
- **Adapter registry:** Central registry for discovering and selecting AI runtime adapters
- **Environment test system:** Each adapter can verify its runtime environment (is Claude installed? is the API key valid?)
- **Model catalog:** Per-adapter model lists with display labels
- **Prompt templates:** Configurable prompt template injection per agent
- **Max turns/timeout:** Safety limits on AI execution duration
- **Usage summary extraction:** Parsing token usage from CLI output for cost tracking

---

## 8. Specific Files/Modules to Extract and Integrate

### Priority 1: Directly Usable (Copy and Adapt)

| File | What to Take |
|---|---|
| `ui/src/api/client.ts` | API client wrapper pattern (51 lines, clean and reusable) |
| `ui/src/components/ui/*.tsx` | All 21 shadcn/ui primitives (we likely already have equivalents, but these are well-configured) |
| `ui/src/lib/queryKeys.ts` | Query key organization pattern |
| `ui/src/lib/utils.ts` | Utility functions (cn, formatCents, etc.) |
| `ui/src/lib/timeAgo.ts` | Relative time formatting |
| `ui/src/context/ThemeContext.tsx` | Theme toggle implementation |
| `ui/src/context/ToastContext.tsx` | Toast notification system |
| `ui/src/components/MetricCard.tsx` | Dashboard metric card component |
| `ui/src/components/EmptyState.tsx` | Empty state component |
| `ui/src/components/StatusBadge.tsx` | Status badge component |
| `ui/src/components/FilterBar.tsx` | Filter bar component |
| `ui/src/components/CommandPalette.tsx` | Command palette (cmdk-based) |

### Priority 2: Study and Adapt

| File/Module | What to Learn |
|---|---|
| `ui/src/components/KanbanBoard.tsx` | dnd-kit Kanban implementation |
| `ui/src/components/Layout.tsx` | Multi-panel layout architecture |
| `ui/src/components/Sidebar.tsx` | Navigation sidebar with badges and live counts |
| `ui/src/context/LiveUpdatesProvider.tsx` | WebSocket -> React Query cache integration |
| `ui/src/pages/Dashboard.tsx` | Dashboard composition pattern (metrics + charts + activity + recent items) |
| `ui/src/components/ActivityCharts.tsx` | Chart components for analytics |
| `ui/src/components/MarkdownEditor.tsx` | Rich markdown editing |
| `ui/src/components/OnboardingWizard.tsx` | Multi-step wizard pattern |
| `server/src/storage/` | Pluggable storage abstraction |
| `server/src/services/heartbeat.ts` | Scheduled job execution with queuing |
| `packages/adapter-utils/` | AI adapter abstraction pattern |
| `packages/plugins/sdk/` | Plugin system architecture |

### Priority 3: Reference Architecture

| Module | What to Reference |
|---|---|
| `packages/db/src/schema/` | 60-table Drizzle schema for complex multi-tenant SaaS |
| `server/src/services/budgets.ts` | Budget enforcement with threshold types and window kinds |
| `server/src/services/company-portability.ts` | Full export/import with collision handling |
| `server/src/services/plugin-lifecycle.ts` | State machine for plugin lifecycle management |
| `server/src/realtime/live-events-ws.ts` | WebSocket server with auth and company scoping |
| `packages/shared/src/types/` | 28 type definition files for comprehensive domain modeling |

---

## 9. Key Takeaways

### What Paperclip Does Exceptionally Well
1. **Multi-agent orchestration** -- The heartbeat + adapter + workspace system is a genuine innovation for coordinating multiple AI tools
2. **Plugin architecture** -- Production-quality plugin system with lifecycle management, sandboxing, and UI extension
3. **Company portability** -- Export/import entire organizations, a powerful feature for templates
4. **Budget enforcement** -- Atomic budget checking prevents runaway AI costs
5. **Dashboard UX** -- Clean, information-dense dashboard with real-time updates

### What We Can Learn From
1. **React Query + WebSocket pattern** -- Their LiveUpdatesProvider is an elegant way to keep UI current
2. **Adapter registry pattern** -- Clean abstraction for supporting multiple AI runtimes
3. **Company-scoped routing** -- URL prefix pattern for multi-tenant navigation
4. **Service layer discipline** -- Every domain operation goes through a typed service
5. **Schema-first development** -- Drizzle schema as the source of truth with generated migrations

### What We Should NOT Copy
1. **Single-process architecture** -- For production media processing (Clipper Engine), we need separate worker processes
2. **Embedded Postgres complexity** -- We should use standard Postgres or SQLite, not the embedded approach
3. **Express 5** -- This is still experimental; we should evaluate our own framework choice independently
4. **better-auth** -- Evaluate against our own auth requirements; may be more than we need

---

## 10. Recommended Integration Strategy

### Phase 1: UI Component Harvest
- Extract shadcn/ui primitives, MetricCard, StatusBadge, EmptyState, FilterBar
- Adapt the API client pattern
- Study and adapt the Layout and Sidebar architecture

### Phase 2: Dashboard Architecture
- Implement the dashboard composition pattern (metrics row + charts + activity feed + recent items)
- Adopt React Query + WebSocket live updates
- Build a command palette inspired by their implementation
- Implement breadcrumb and theme context patterns

### Phase 3: AI Integration Patterns (for Animation Studio)
- Design our adapter system based on their adapter-utils pattern
- Implement budget/cost tracking for AI operations
- Build approval workflows for generated content
- Create a skills injection system for domain-specific AI capabilities

### Phase 4: Infrastructure Patterns (for Clipper Engine)
- Adopt the storage provider abstraction (local + S3)
- Study the workspace runtime pattern for isolated processing jobs
- Implement the job scheduling pattern for media processing queues

---

## Appendix: Repository Statistics

- **Total packages:** 14 (monorepo workspaces)
- **Server routes:** 25 modules
- **Server services:** ~60 modules
- **UI pages:** 39
- **UI components:** 80+
- **DB schema tables:** 60+
- **Shared type files:** 28
- **Agent adapters:** 7 (Claude, Codex, Cursor, Gemini, OpenClaw, OpenCode, Pi)
- **Test frameworks:** Vitest (unit), Playwright (E2E), promptfoo (evals)
- **Documentation files:** 20+ in doc/

---

*End of audit. This report should be used as a reference for architectural decisions and component harvesting across The Team's projects.*
