# Command Base — Full System Audit & Repair Guide

## Mission
Systematically test, fix, and catalog every feature in Command Base. Produce a comprehensive feature inventory and a report of what works, what's broken, what's empty calories, and what needs improvement.

## Principles
1. **Don't break anything.** Only fix. If a fix requires breaking something temporarily, finish the fix before moving on.
2. **Test when done, not halfway through.** Don't test mid-fix. Complete the fix, then verify.
3. **If you break it, keep working until it's fixed.** Never leave something in a worse state than you found it.
4. **Peer review everything.** No fix ships without another member verifying it works.
5. **Catalog everything.** Every feature, every endpoint, every page — documented.
6. **No fluff.** Important context only. No filler. Data-driven findings.

## Team Roles

### Audit Lead (1 member)
- Coordinates the audit sequence
- Maintains the master feature catalog
- Writes the final audit report
- Resolves conflicts between members

### Backend Auditor (1 member)  
- Tests every API endpoint in server.js
- Verifies request/response contracts
- Checks error handling (bad inputs, missing data, edge cases)
- Documents which endpoints work, which fail, which are dead code

### Frontend Auditor (1 member)
- Navigates every page in the UI (localhost:3000)
- Tests every button, form, modal, and interaction
- Checks WebSocket live updates work
- Documents which pages work, which are broken, which are empty shells

### Database Auditor (1 member)
- Catalogs all tables and their purposes
- Checks referential integrity (FK violations)
- Finds orphaned records, empty tables, unused columns
- Identifies "empty calories" — tables/columns that exist but serve no purpose

### Bug Fixer (2 members)
- Takes issues found by auditors
- Fixes them one at a time
- Tests each fix (backend: curl/API, frontend: verify in browser)
- Submits fix for peer review before moving to next

### Reviewer (1 member)
- Peer reviews every fix
- Verifies the fix works and didn't break anything else
- Signs off or sends back with notes
- Max 1 review per fix — no recursive review chains

## Audit Sequence

### Phase 1: Catalog (Database Auditor + Backend Auditor)
1. Database Auditor: Read the schema, list every table, its columns, row counts, and purpose
2. Backend Auditor: Read server.js, list every API route (method, path, what it does)
3. Both produce structured catalogs saved to `.claude/task-forces/`

### Phase 2: Frontend Inventory (Frontend Auditor)
1. List every page in the navigation
2. For each page: does it load? does it show data? do the buttons work?
3. Check Board Room command submission flow
4. Check WebSocket connection and live updates
5. Produce a page-by-page status report

### Phase 3: Systematic Testing (All Auditors)
1. Backend: Hit every endpoint with valid data, invalid data, missing data
2. Frontend: Submit forms, create tasks, navigate flows end-to-end
3. Database: Run integrity checks, find FK violations, count orphans
4. Log every failure with: what failed, expected behavior, actual behavior

### Phase 4: Fix & Verify (Bug Fixers + Reviewer)
1. Prioritize: crashes > broken features > cosmetic issues
2. Fix one issue at a time
3. Test the fix
4. Submit for review
5. Reviewer verifies, signs off
6. Move to next issue

### Phase 5: Final Report (Audit Lead)
Compile everything into a single report:
- **Feature Catalog**: Complete list of every feature (backend + frontend + DB)
- **Health Status**: What works, what's broken, what's partially working
- **Empty Calories**: Features/tables/code that exist but do nothing useful
- **Fixes Applied**: What was broken and how it was fixed
- **Recommendations**: What to improve, what to add, what to remove
- **Strengths**: What the system does well

## Output Files
All artifacts go in `.claude/task-forces/`:
- `feature-catalog.md` — Master list of every feature
- `api-audit.md` — Backend endpoint test results
- `frontend-audit.md` — Page-by-page UI test results  
- `database-audit.md` — Table inventory and integrity report
- `fixes-log.md` — Every bug found and fixed
- `final-report.md` — The comprehensive audit report

## Working Directory
`/Users/maxstewart/Desktop/The Team`

## Important Context
- Server: Express + SQLite + vanilla JS, runs at localhost:3000
- DB: `/Users/maxstewart/Desktop/The Team/the_team.db` (main), `task_forces.db` (task forces)
- Frontend: `app/public/app.js` (35K+ lines), `styles.css`, `index.html`
- Backend: `app/server.js` (33K+ lines)
- 50+ database tables, 80+ team members, 20+ pages
- The Board Room is the primary command interface
- WebSocket for real-time updates
