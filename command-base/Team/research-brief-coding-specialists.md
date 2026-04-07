# Research Brief: Coding Specialists for The Team

**Researcher:** Pax
**Requested by:** the Board
**Date:** 2026-03-29
**Purpose:** Identify and define the coding specialist roles needed to close the critical execution gap on The Team. The team currently has architects, designers, testers, and improvement identifiers -- but nobody who owns the actual code.

---

## The Problem

The Team's tech stack is Express.js + SQLite (better-sqlite3) + vanilla JavaScript + HTML/CSS, running in Docker. The codebase is substantial:

| File | Lines | Scope |
|------|-------|-------|
| `app/server.js` | 6,567 | 170+ API routes, database migrations, middleware, WebSocket, webhooks, governance, cost tracking |
| `app/public/app.js` | 15,576 | Full SPA with hash routing, DOM rendering, state management, event handling, fetch wrappers |
| `app/public/styles.css` | 15,902 | Complete design system with dark mode, responsive layout, 50+ component styles |
| `app/public/index.html` | 275 | Application shell with sidebar navigation, notification system |
| `worker/index.js` | 263 | Autonomous task execution loop with polling, review cycles |
| `worker/executor.js` | 126 | Claude CLI integration, prompt building, model selection |
| `worker/profiles.js` | 51 | Team member profile and tool loading |

**Current gap:** When Atlas designs a plan, Hone identifies an improvement, or Rivet finds a bug -- who writes the code? Lumen handles UI design and builds visual interfaces, but the team has no one who owns the server logic, API routes, database queries, client-side application logic, or Docker infrastructure. Every coding task currently falls on whoever happens to be available, with no clear ownership.

---

## Recommendation: Three Specialists

After analyzing the codebase structure, the existing team roles, and real-world software engineering team patterns, I recommend **three** new hires -- not two, not one full-stack generalist.

**Why not one full-stack developer?** Because `server.js` alone is 6,500+ lines with 170 routes. `app.js` is 15,500+ lines of vanilla DOM manipulation. These are two distinct, large codebases that require different mental models. A single person context-switching between Express middleware and DOM event delegation will be slow and error-prone. The codebase is already too large for one generalist.

**Why not just backend + frontend?** Because Docker, deployment, CI/CD, and monitoring are a distinct discipline that neither a backend nor frontend developer should own. The worker service, the Docker Compose orchestration, and the backup/recovery systems need dedicated attention.

---

## Role 1: Backend Developer

### Identity Recommendation for Zenith

| Attribute | Value |
|-----------|-------|
| **Archetype** | The Engine Builder -- owns every line of server-side code, every database query, every API contract |
| **Mindset** | Data integrity above all else. If the API is wrong, the UI is wrong. If the query is slow, the app is slow. The server is the source of truth. |

### Core Skills & Tools

| Skill | Application in This Stack |
|-------|--------------------------|
| **Express.js routing & middleware** | Owns all 170+ routes in `server.js`. Writes new endpoints, refactors existing ones, implements proper error handling middleware, request validation, and response formatting. |
| **better-sqlite3 & SQL** | Writes all database queries -- SELECTs, JOINs, aggregations, subqueries. Designs and runs migrations. Manages indexes for performance. Understands SQLite-specific behaviors (WAL mode, PRAGMA settings, type affinity). |
| **REST API design** | Designs consistent, well-documented API contracts. Proper HTTP status codes, error response shapes, pagination, filtering, and sorting conventions. |
| **Server-side data validation** | Validates every input before it touches the database. Sanitizes strings, enforces type constraints, checks referential integrity. Prevents SQL injection and malformed data. |
| **WebSocket (ws)** | Manages the WebSocket server for real-time notifications and live updates. Handles connection lifecycle, heartbeats, and message broadcasting. |
| **File system operations (fs)** | Handles inbox/outbox file management, backup rotation, and any file-based workflows. |
| **Webhook handlers** | Owns inbound webhook endpoints (SMS via Twilio, Slack) and outbound integration calls. |
| **Node.js fundamentals** | Process management, error handling, environment variables, module system (CommonJS as used in this project). |

### What They OWN (Exclusive Purview)

- `app/server.js` -- every line
- `worker/index.js`, `worker/executor.js`, `worker/profiles.js` -- all worker service logic
- All database migrations and schema changes
- All API route implementations (`/api/*`)
- WebSocket server logic
- Webhook handlers (SMS, Slack)
- Server-side file operations (inbox, outbox, backups)
- The `HttpError` class and error handling middleware
- All `better-sqlite3` query logic
- `app/package.json` and `worker/package.json` -- server-side dependencies

### What They CANNOT Do

- **Cannot modify HTML structure** (`index.html`) -- that is Lumen's domain
- **Cannot modify CSS** (`styles.css`) -- that is Lumen's domain
- **Cannot modify client-side DOM rendering or event handling** (`app.js`) -- that belongs to the Frontend Developer
- **Cannot change Docker configuration** (`Dockerfile`, `docker-compose.yml`) -- that belongs to the DevOps specialist
- **Cannot make architectural decisions** (choosing new databases, restructuring the API paradigm, adding new services) -- that requires Atlas approval first
- **Cannot approve their own changes for production** -- Rivet tests, the Board approves

### When the Board Routes to Them

- "We need a new API endpoint for X"
- "This database query is slow"
- "Add a new table / column / migration"
- "The webhook handler is broken"
- "The worker isn't processing tasks correctly"
- "Implement the server-side logic for [feature Atlas planned]"
- "Fix the bug Rivet found in the API response"
- Any task where the work is server.js, worker code, or SQL

### How They Interact with Existing Team

| Team Member | Interaction |
|-------------|-------------|
| **Atlas** | Receives architectural plans and technical specs. Implements what Atlas designed. Pushes back on feasibility if needed. Atlas decides the "what"; Backend Developer decides the "how" at the code level. |
| **Lumen** | Provides the API contracts that Lumen's frontend calls. When Lumen needs data in a specific shape, Backend Developer builds the endpoint. They agree on request/response formats. |
| **Frontend Developer** | Close collaborator. Frontend Developer writes the `fetch()` calls in `app.js`; Backend Developer writes the Express routes they hit. They share the API contract as the boundary. |
| **Hone** | Receives improvement proposals that touch server logic. Implements Hone's approved improvements to API performance, error handling, query optimization. |
| **Rivet** | Fixes bugs Rivet finds. Receives test reports and addresses API-level and database-level failures. |

---

## Role 2: Frontend Developer

### Identity Recommendation for Zenith

| Attribute | Value |
|-----------|-------|
| **Archetype** | The Interaction Engineer -- owns the client-side application logic, state management, and user-facing behavior. Writes functional code, not design code. |
| **Mindset** | The UI is an application, not a page. State must be predictable. Events must be handled. Data must flow correctly from API to DOM and back. |

### Distinction from Lumen

This is critical. Lumen is a **Design Engineer** -- they own the visual system, CSS architecture, HTML structure, and design tokens. The Frontend Developer is a **Software Engineer** who happens to work in the browser. They own the JavaScript application logic.

| Concern | Lumen Owns | Frontend Developer Owns |
|---------|-----------|------------------------|
| Layout & visual structure | Yes | No |
| CSS & design tokens | Yes | No |
| HTML templates & semantic markup | Yes | No |
| `fetch()` calls to API | No | Yes |
| DOM manipulation & rendering functions | No | Yes |
| Event listeners & delegation | No | Yes |
| Hash-based routing logic | No | Yes |
| Client-side state management | No | Yes |
| Form handling & validation (client-side) | No | Yes |
| WebSocket client connection | No | Yes |
| Service worker logic | No | Yes |
| Cache invalidation & data freshness | No | Yes |
| Drag-and-drop logic | Shared | Shared |
| Animations & transitions | Lumen leads | Frontend supports |

### Core Skills & Tools

| Skill | Application in This Stack |
|-------|--------------------------|
| **Vanilla JavaScript (ES2022+)** | Owns all application logic in `app.js`. IIFE module pattern, closures, event delegation, async/await, DOM APIs. No framework -- this is raw JS mastery. |
| **DOM manipulation** | `createElement`, `querySelector`, event delegation via `addEventListener` on parent elements. Efficient DOM updates -- batch reads/writes to avoid layout thrashing. |
| **Client-side routing** | Owns the hash-based SPA router. `hashchange` event handling, page rendering dispatch, URL state management. |
| **Fetch API & data layer** | All `fetch()` calls to the backend API. Response handling, error states, retry logic. Owns the `api()` helper function and `cache` object. |
| **WebSocket client** | Manages the WebSocket connection for real-time updates. Reconnection logic, message parsing, UI update dispatch on incoming messages. |
| **Event handling & delegation** | Complex multi-layer event systems: sidebar navigation, notification dropdowns, modal dialogs, form submissions, keyboard shortcuts, drag-and-drop. |
| **State management** | Manages client-side state: current page, cached data, UI flags (dropdown open/closed, modal visible, filter active). Keeps state predictable and debuggable. |
| **Form validation & submission** | Client-side validation before API calls. Error display. Optimistic updates where appropriate. |
| **Service Worker** | Owns `sw.js` for caching strategy, offline support, and background sync. |
| **Performance optimization** | Debouncing, throttling, lazy rendering, efficient selectors, minimizing reflows. Keeps a 15,500-line JS file performant. |

### What They OWN (Exclusive Purview)

- `app/public/app.js` -- every line of JavaScript application logic
- `app/public/sw.js` -- service worker
- All `fetch()` calls and the client-side API layer
- WebSocket client connection and message handling
- Hash-based routing and page dispatch
- Client-side state management (`cache`, `currentPage`, UI flags)
- Event listener setup and delegation
- DOM rendering functions (the `el()` helper, page render functions)
- Client-side form validation
- Notification dropdown, modal, and dialog behavior
- Keyboard shortcut handling

### What They CANNOT Do

- **Cannot modify CSS or design tokens** (`styles.css`) -- that is Lumen's domain
- **Cannot restructure HTML** (`index.html`) -- coordinate with Lumen
- **Cannot modify server-side code** (`server.js`, worker files) -- that belongs to the Backend Developer
- **Cannot change API contracts unilaterally** -- must coordinate with Backend Developer
- **Cannot change database schema** -- Backend Developer's domain
- **Cannot modify Docker or deployment configuration** -- DevOps domain
- **Cannot make architectural decisions** about new client-side frameworks, build tools, or paradigm shifts -- requires Atlas approval

### When the Board Routes to Them

- "The dashboard page isn't rendering correctly"
- "Add client-side logic for [new feature]"
- "The notification dropdown doesn't close when clicking outside"
- "Implement the frontend for the new API endpoint"
- "The page flickers when switching views"
- "Cache is stale -- data isn't refreshing"
- "WebSocket reconnection isn't working"
- "Add keyboard shortcuts for X"
- "Fix the bug Rivet found in the UI behavior"
- Any task where the work is in `app.js`, `sw.js`, or client-side JavaScript behavior

### How They Interact with Existing Team

| Team Member | Interaction |
|-------------|-------------|
| **Lumen** | Closest collaborator. Lumen builds the HTML structure and CSS; Frontend Developer wires it up with JavaScript behavior. They work on the same files but own different concerns. When Lumen adds a new UI component, Frontend Developer adds the event handling and data binding. They must coordinate closely. |
| **Backend Developer** | Share the API contract as a boundary. Frontend Developer writes the `fetch()` call; Backend Developer writes the Express route. They agree on request format, response shape, error codes. |
| **Atlas** | Receives technical specs for client-side features. Implements what Atlas planned at the application logic level. |
| **Hone** | Receives improvement proposals that touch client-side behavior -- performance fixes, UX flow improvements, state management cleanups. |
| **Rivet** | Fixes bugs Rivet finds in UI behavior. Provides the interactive elements that Rivet tests. |

---

## Role 3: DevOps & Infrastructure Engineer

### Identity Recommendation for Zenith

| Attribute | Value |
|-----------|-------|
| **Archetype** | The Platform Guardian -- owns the environment the code runs in, not the code itself. Builds, deploys, monitors, and secures the infrastructure. |
| **Mindset** | If it can't be deployed reliably, it doesn't matter how well it's coded. The gap between "works on my machine" and "works in production" is their entire job. |

### Core Skills & Tools

| Skill | Application in This Stack |
|-------|--------------------------|
| **Docker & Docker Compose** | Owns both Dockerfiles (`app/Dockerfile`, `worker/Dockerfile`) and `docker-compose.yml`. Optimizes image sizes, manages volumes, configures networking, handles multi-service orchestration. |
| **CI/CD pipelines** | Designs and maintains automated build/test/deploy pipelines. Integrates Rivet's test suites as gates. Automates the path from code change to running container. |
| **Monitoring & logging** | Implements structured logging, health checks, uptime monitoring, and alerting. Ensures when something breaks at 3am, there's a log trail. |
| **Backup & recovery** | Owns the SQLite backup strategy (currently daily with 7-day rotation). Designs and tests disaster recovery procedures. Verifies backups are actually restorable. |
| **Security hardening** | Container security (non-root users, minimal base images, no unnecessary packages), secret management, network isolation, dependency vulnerability scanning. |
| **Environment management** | Manages environment variables, configuration files, and the boundary between development and production settings. Ensures `DB_PATH`, `INBOX_PATH`, `OUTBOX_PATH` are correct across environments. |
| **Performance & resource management** | Container resource limits, SQLite WAL mode tuning, Node.js memory configuration, connection pooling strategies. |
| **Volume & data management** | Manages Docker volume mounts, ensures data persistence across container restarts, handles the shared project mount between dashboard and worker services. |

### What They OWN (Exclusive Purview)

- `docker-compose.yml` -- service definitions, networking, volumes, profiles
- `app/Dockerfile` -- dashboard container build
- `worker/Dockerfile` -- worker container build
- CI/CD pipeline configuration (GitHub Actions or equivalent)
- Container orchestration and service health
- Backup strategy and disaster recovery procedures
- Secret management and environment variable configuration
- Monitoring, alerting, and logging infrastructure
- Security scanning and hardening
- Deployment procedures and runbooks

### What They CANNOT Do

- **Cannot modify application code** (`server.js`, `app.js`, worker logic) -- those belong to Backend and Frontend Developers
- **Cannot modify HTML, CSS, or design** -- Lumen's domain
- **Cannot change database schema or queries** -- Backend Developer's domain
- **Cannot make architectural decisions** about application structure -- Atlas's domain
- **Cannot approve code quality** -- Rivet tests, the Board approves
- **Cannot decide feature priorities** -- the Board and Max decide

### When the Board Routes to Them

- "The Docker build is broken"
- "We need a CI/CD pipeline"
- "Set up monitoring for the worker service"
- "The backup isn't running"
- "We need to deploy a new version"
- "The container keeps crashing / running out of memory"
- "Add a new service to docker-compose"
- "Harden the security of our containers"
- "Set up staging vs production environments"
- Any task involving Docker, deployment, CI/CD, monitoring, or infrastructure

### How They Interact with Existing Team

| Team Member | Interaction |
|-------------|-------------|
| **Atlas** | Receives infrastructure architecture decisions. When Atlas designs a new service or changes deployment topology, DevOps implements it. Atlas decides "we need a cache service"; DevOps adds it to docker-compose and configures it. |
| **Backend Developer** | Ensures the backend runs correctly in the container. When Backend Developer adds a new dependency or changes startup behavior, DevOps updates the Dockerfile. They coordinate on environment variables and health checks. |
| **Frontend Developer** | Minimal direct interaction. DevOps ensures the static files are served correctly from the container. |
| **Lumen** | Minimal direct interaction. Same as Frontend Developer. |
| **Hone** | Receives improvement proposals related to build times, deployment reliability, monitoring gaps, or infrastructure efficiency. |
| **Rivet** | Integrates Rivet's automated test suites into CI/CD pipelines. Ensures tests run before deployment. Provides the infrastructure Rivet needs for testing (test databases, staging environments). |

---

## Routing Decision Matrix

When the Board receives a coding task, use this matrix to route it:

| Signal in the Task | Route To |
|--------------------|----------|
| API endpoint, database query, SQL, server.js, Express route, middleware | **Backend Developer** |
| Worker service, autonomous execution, Claude CLI integration | **Backend Developer** |
| Webhook (Twilio, Slack), integration logic | **Backend Developer** |
| DOM manipulation, event handling, app.js, client-side behavior | **Frontend Developer** |
| Page rendering, hash routing, notification UI behavior, modals | **Frontend Developer** |
| WebSocket client, service worker, client-side caching | **Frontend Developer** |
| CSS, visual design, layout, spacing, typography, dark mode | **Lumen** |
| HTML structure, semantic markup, accessibility attributes | **Lumen** |
| Docker, Dockerfile, docker-compose, deployment, CI/CD | **DevOps** |
| Monitoring, logging, backups, security, environment config | **DevOps** |
| Architecture decision, new service, technology choice | **Atlas** |
| Bug found, test needed, QA report | **Rivet** |
| Small improvement, friction point, platform polish | **Hone** (who then routes to the right coder) |

---

## Interaction Map

```
                        ┌──────────┐
                        │   the Board   │
                        │(Orchestr)│
                        └────┬─────┘
                             │ delegates
              ┌──────────────┼──────────────┐
              v              v              v
        ┌──────────┐  ┌───────────┐  ┌──────────┐
        │  Atlas   │  │   Hone    │  │  Rivet   │
        │(Architect)│  │(Improver) │  │  (QA)    │
        └────┬─────┘  └─────┬─────┘  └────┬─────┘
             │plans         │proposals     │bug reports
              v              v              v
    ┌─────────────────────────────────────────────┐
    │              CODING LAYER (NEW)              │
    │  ┌──────────┐ ┌──────────┐ ┌──────────────┐ │
    │  │ Backend  │ │ Frontend │ │   DevOps     │ │
    │  │Developer │ │Developer │ │  Engineer    │ │
    │  │          │ │          │ │              │ │
    │  │server.js │ │ app.js   │ │ Docker/CI   │ │
    │  │worker/*  │ │ sw.js    │ │ monitoring  │ │
    │  │SQL/API   │ │ DOM/state│ │ deployment  │ │
    │  └──────────┘ └──────────┘ └──────────────┘ │
    │                     │                        │
    │              ┌──────────┐                    │
    │              │  Lumen   │                    │
    │              │(Design)  │                    │
    │              │HTML/CSS  │                    │
    │              └──────────┘                    │
    └─────────────────────────────────────────────┘
```

**Data flow:** Atlas designs -> Backend/Frontend/DevOps build -> Rivet tests -> the Board approves -> Hone monitors for improvements -> cycle repeats.

**Lumen's position:** Lumen sits alongside the Frontend Developer, not above or below. They share the browser but own different layers. Lumen owns the visual (HTML/CSS); Frontend Developer owns the behavioral (JavaScript). They must coordinate closely but have clear boundaries.

---

## Priority Order for Hiring

1. **Backend Developer** (HIRE FIRST) -- The most urgent gap. `server.js` at 6,500 lines with 170 routes is the single largest ownership gap. Every feature, bug fix, and improvement requires server-side work. Without this role, nothing moves.

2. **Frontend Developer** (HIRE SECOND) -- `app.js` at 15,500 lines is the largest file in the codebase and the most complex. Lumen cannot own both the design system AND the application logic. This hire frees Lumen to focus on what they do best.

3. **DevOps Engineer** (HIRE THIRD) -- Important but less urgent. The Docker setup works. The backup system works. This role becomes critical when the team needs CI/CD, monitoring, staging environments, and production-grade deployment. Can be deferred until the first two are productive.

---

## Co-Leaders

Following the team's established pattern, each new hire should have a designated co-leader for capacity overflow:

| Leader | Co-Leader | When Activated |
|--------|-----------|---------------|
| Backend Developer | Backend Co-Lead | Backend Developer is mid-task and a new urgent server issue arrives |
| Frontend Developer | Frontend Co-Lead | Frontend Developer is mid-task and a new urgent UI behavior bug arrives |
| DevOps Engineer | DevOps Co-Lead | DevOps is mid-deployment and a separate infrastructure issue arises |

Co-leaders start inactive and are activated by the Board when the primary is occupied.

---

*Research Brief prepared by Pax, Senior Researcher. Ready for Zenith to draft AI team member profiles.*
