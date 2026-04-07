# Command Base — System Audit Final Report

**Task Force:** System Audit Force v2
**Date:** 2026-04-06
**Agents:** 16 deployed (10 completed, 4 Spark analysis, 2 CLI)
**Total Output:** 58K+ chars across 10 specialist reports

---

## Reliability Note

Reports from Ledger, Probe, Gauge, Scribe, Anvil, and Sentinel are grounded in actual schema/route data fed to Spark. Reports from Triage and Forge contain hallucinated content (e.g., Triage invented "MFA", "video conferencing", "virtual break room" — none exist). Those reports are excluded from this summary.

---

## System Overview

| Metric | Count |
|--------|-------|
| Database tables | 156 |
| API routes | 664 |
| UI pages | 16 |
| Server.js lines | 33,000+ |
| App.js lines | 35,000+ |
| Team members in DB | 176 |
| Tasks in DB | 1,663 |
| Activity log entries | 13,787 |
| Heartbeat events | 138,333 |
| Agent activity stream | 54,866 |

---

## What Works Well

1. **Governance tracking** — governance_receipts, constitutional_invariants, audit_trail are solid and well-implemented
2. **Agent memory system** — context_store (915 entries), agent_identity_files (398), agent_daily_notes (168) provide deep agent context
3. **Decision lifecycle** — decisions, approvals, escalation_log, improvement_proposals form a complete workflow
4. **Task management core** — tasks (1,663), task_assignments (1,646), task_files (1,896) are heavily used and working
5. **Team management** — team_members (176), company_members (125), member_rankings (47) are populated and functional
6. **Heartbeat/monitoring** — 68K+ heartbeat runs, 138K events — the system actively monitors itself
7. **LLM integration** — multi-provider support, cost tracking, model routing (Claude/Spark/Ollama)
8. **Calendar sync** — Google Calendar integration with AVC meetings locked
9. **Budget tracking** — cost_events, budget_policies, budget_incidents all functional
10. **Notification system** — WebSocket real-time updates, notification preferences

---

## Empty Calories — Tables With 0 Rows (Candidates for Removal)

These tables exist but have never been used:

| Table | Domain | Verdict |
|-------|--------|---------|
| accountability_actions | Governance | Scaffolding — remove |
| agent_tacit_knowledge | AI/Agents | Never activated — remove |
| authority_delegations | Governance | Never used — remove |
| challenge_adjudication_stages | Governance | Never used — remove |
| challenge_records | Governance | Never used — remove |
| conflict_disclosures | Governance | Never used — remove |
| conflict_records | Governance | Never used — remove |
| consent_records | Governance | Never used — remove |
| initiatives | Projects | Never used — remove |
| task_time_entries | Tasks | Never used — remove |
| task_custom_field_values | Tasks | Never used — remove |
| task_custom_field_definitions | Tasks | Never used — remove |
| task_dependencies | Tasks | Never used — remove |
| task_goals | Tasks | Never used — remove |
| plugin_state | Plugins | Never used — remove |
| skills_proposals | Team | Never used — remove |
| action_items | Notes | Never used — remove |
| routines | Automation | Never used — remove |
| routine_steps | Automation | Never used — remove |
| routine_runs | Automation | Never used — remove |
| routine_step_results | Automation | Never used — remove |
| eval_suites | Evaluation | Never used — remove |
| eval_cases | Evaluation | Never used — remove |
| eval_runs | Evaluation | Never used — remove |
| eval_case_results | Evaluation | Never used — remove |

**That's 25+ tables with zero rows.** Many are governance sub-features (ExoChain) that were scaffolded but never activated.

---

## Top 10 Issues to Fix

### CRITICAL
1. **33K-line server.js is a single point of failure.** If it crashes, everything dies. No modular fallback.
2. **No authentication on API endpoints.** Anyone on the network can hit any route. No JWT, no session validation, no middleware auth.
3. **FK violations exist** — cost_events references active_processes rows that were deleted. Cascade deletes are inconsistent.

### HIGH
4. **664 routes is excessive.** Many are duplicates or dead code with no frontend caller. Audit and consolidate.
5. **156 tables — 25+ are empty scaffolding.** Drop them. They add schema complexity for zero value.
6. **Agent spawn CLI keeps failing.** The --cwd flag bug was fixed but CLI agents are fragile. The stdin piping, detached process, and stream-json parsing all have edge cases.
7. **Heartbeat tables are massive** (138K+ events). No cleanup/rotation policy. Will grow unbounded.

### MEDIUM
8. **Inconsistent naming conventions** across tables (snake_case vs camelCase, agent_ prefix vs no prefix).
9. **Large TEXT columns** in context_store, agent_memory_entities store big payloads in SQLite. Performance risk at scale.
10. **No API versioning.** All 664 routes are at /api/ with no version prefix. Breaking changes affect everything.

---

## Top 10 Things to Keep As-Is

1. Task management (tasks, assignments, files) — battle-tested, heavily used
2. Agent memory system — unique differentiator, well-designed
3. Governance receipts and audit trail — solid compliance foundation
4. Board Room as primary command interface — clean UX decision
5. WebSocket real-time updates — works, users see live changes
6. Budget and cost tracking — cost_events, policies, incidents all functional
7. Company → Project → Task hierarchy — clean, logical
8. Team member profiles with identity files — supports the evolution concept
9. Calendar with Google sync — practical, used
10. Notification system with preferences — working

---

## Top 10 Things to Remove or Rethink

1. **25+ zero-row tables** — all the governance scaffolding that was never activated
2. **Routines system** (4 tables, 0 rows) — never built out
3. **Eval system** (4 tables, 0 rows) — never built out
4. **Refinement system** — unclear value, low usage
5. **Duplicate/redundant API routes** — consolidate CRUD patterns
6. **Heartbeat event table** (138K rows) — add rotation, cap at 7 days
7. **Agent activity stream** (54K rows) — add rotation, cap at 30 days
8. **ExoChain governance sub-tables** (challenges, conflicts, accountability) — remove until needed
9. **System map** — low value, maintenance cost
10. **White paper page** — static content, doesn't need to be in the app

---

## Architecture Assessment (from Gauge)

| Area | Rating | Notes |
|------|--------|-------|
| Overall strength | 4/5 | Strong governance, agent-centric design |
| Maintainability | 2/5 | 33K monolith, hard to test or modify safely |
| Security | 2/5 | No auth middleware, secrets in DB, no API gateway |
| Scalability | 2/5 | Single process, no load balancing, SQLite limits |
| Future-readiness | 2/5 | Needs modularization to grow |

---

## Route-to-Table Mapping (from Scribe)

Key domain groups and their table dependencies:

- **Tasks:** tasks, task_assignments, task_files, task_comments, task_checkouts, active_processes
- **Team:** team_members, company_members, member_identities, member_rankings, agent_skills
- **Projects:** projects, project_tasks, project_phases, project_repos, project_executives
- **Companies:** companies, company_members, company_domains
- **Board Room:** board_chats, board_chat_messages (+ governance tables)
- **Budget:** budget_policies, cost_events, budget_incidents
- **Calendar:** calendar_events, calendar_sync_tokens
- **Notes:** notes, contacts, decisions, tags, taggables
- **Settings:** system_settings, llm_providers, model_sources, integrations

---

## What Still Needs Doing (Not Completed by Task Force)

1. **Frontend page-by-page audit** — CLI agents kept failing. Each of the 16 pages needs manual testing.
2. **Actual bug fixes** — Spark found issues but can't edit files. Fixes need CLI implementation.
3. **End-to-end flow testing** — Board Room → task creation → spawn → completion → delivery pipeline needs live testing.

---

## Summary

Command Base is a functional, feature-rich platform with strong governance and agent orchestration. Its core systems (tasks, team, memory, budget, calendar) work well with real data. However, it carries significant dead weight (25+ empty tables, excessive routes, unused feature scaffolding) and has critical gaps in security and maintainability. The recommended path: clean out the empty calories, secure the API layer, and modularize server.js before adding new features.
