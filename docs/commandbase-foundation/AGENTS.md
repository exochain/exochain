# AGENTS.md - CommandBase Starter

Never stub, never skip, never postpone, never synthesize production behavior.
Always test first, keep tenant boundaries explicit, and preserve the trust
boundary between CommandBase and ExoChain.

## Product Boundary

CommandBase is the operational control plane for the AVC fractional CTO
collective and its client engagements.

ExoChain is the trust substrate. CommandBase may display, request, and cache
trust facts, but ExoChain must verify and record audit-critical facts.

ExoForge is a governed build engine. It may propose, implement, test, and open
PRs. It may not approve itself.

Decision Forum is the deliberation layer. It should be embedded in CommandBase
first, then launched standalone after it proves itself.

## Session Start Protocol

Every session starts by recording:

```text
Date:
Repo:
Branch:
Open PRs:
Changed files:
Current objective:
Authority level:
Risk classification:
Expected receipts:
Tests to run:
Rollback plan:
```

Append that record to `docs/execution-ledger/YYYY-MM-DD-commandbase.md`.

## Engineering Constraints

- Every domain object must be tenant-scoped.
- Every mutating action must identify actor, authority, tenant, object, risk,
  evidence, and expected receipt.
- Every agent action must be attributable to an agent passport.
- Every client-visible decision must be reviewable in Decision Forum.
- Every audit-critical action must have an ExoChain receipt or an explicit
  "receipt pending" state that blocks completion.
- Do not allow direct mutation of receipts or evidence records.
- Do not add cross-tenant queries without tests proving isolation.
- Do not let ExoForge merge or deploy without the staged authority policy.

## TDD Expectations

Before implementation, write or update tests for:

- tenant isolation
- role and authority enforcement
- approval gates
- receipt request and verification paths
- agent budget and tool restrictions
- API contract behavior
- UI critical flows
- deployment smoke checks

Required checks before handoff:

```bash
pnpm -r typecheck
pnpm test:run
pnpm build
pnpm test:e2e
```

If a command cannot run, state why and what risk remains.

## Default Human Approval Gates

Human approval is required for:

- creating or modifying agents
- granting authority
- accessing client data
- using sensitive or regulated data
- client-facing communication
- merge to main
- production deployment
- auth, billing, tenant, or permission changes
- budget increases
- legal or compliance claims
- destructive actions
- governance overrides
- health, safety, security, or regulated-domain recommendations

## ExoForge Authority

Phase 1:

- may create issues, plans, branches, PRs, tests, and proposed fixes
- may not merge, deploy, alter secrets, or approve itself

Phase 2:

- may merge only after human approval, green tests, receipt issuance, and
  rollback documentation

Phase 3:

- may deploy low-risk changes only after receipt-backed approval, smoke tests,
  canary or rollback confirmation, and environment classification

## First Build Target

Build CommandBase for AVC Customer Zero:

1. Setup AVC
2. Invite CTOs
3. Create client
4. Create engagement
5. Define governance model
6. Add agent roster
7. Create first project
8. Open decision
9. Assign agent task
10. Review output
11. Issue receipt
12. Generate weekly client brief
