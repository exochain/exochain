# Site Builder Audit Notes
**Date:** 2026-03-30
**Issues Fixed:** 3 critical

---

## Issue 1: Improvements Not Executing
**Root cause:** Execute endpoint referenced retired members (Hone, Atlas) by name. `WHERE name = 'Hone' AND status = 'active'` returned null after team rebuild, so `spawnMemberTerminal` was never called.
**Fix:** Created `findImprovementAssignee(category)` that maps categories to ACTIVE member IDs. Updated execute, autoStartNextQueued, recycle, and refine endpoints.
**Recurring risk:** Any future team rebuild that changes member names will break this again if hardcoded. The function now uses role-based lookup, not name-based.

## Issue 2: No Live Progress Updates in Site Builder
**Root cause:** WebSocket events (`process.progress`, `task.updated`) refreshed Workspace page but Site Builder had no listener.
**Fix:** Added `siteBuilderLiveRefresh()` triggered by WebSocket events + 10s polling fallback. Enhanced API to return member name and live process status for in-progress items.
**Recurring risk:** None — WebSocket wiring is event-based and doesn't depend on member names.

## Issue 3: Chamber Pool System Static
**Root cause:** Static array of 25 templates, filled to exactly 5, no refill mechanism.
**Fix:** Dynamic pool with system_settings config (pool_size=15, display_count=5, refill_threshold=10). 40+ seed templates plus variant generators for infinite unique ideas. 60-second periodic refill check. Auto-fills on startup.
**Recurring risk:** Pool could stagnate if all 40 seeds + variants are exhausted. Would need codebase-aware generation for truly dynamic ideas.

## Prevention Notes
- After ANY team rebuild, verify `findImprovementAssignee()` still maps to active members
- After ANY WebSocket changes, verify Site Builder refresh is still wired
- Chamber pool settings are in system_settings table — adjustable without code changes
