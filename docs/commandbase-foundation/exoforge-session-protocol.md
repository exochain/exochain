# ExoForge Session Protocol

Status: starter protocol
Created: 2026-04-26

## Purpose

ExoForge should govern software delivery without becoming an unchecked
constitutional authority.

Its job is:

```text
Observe -> Propose -> Implement -> Test -> Submit -> Explain
```

It should not approve itself, rewrite policy, or deploy high-risk changes
without receipt-backed human authorization.

## Session Header

Every ExoForge session starts with:

```text
Date:
Repo:
Branch:
Open PRs:
Changed files:
Objective:
Authority level:
Risk classification:
Expected receipts:
Tests to run:
Rollback plan:
```

## Work Item Lifecycle

```text
Issue or feedback
-> triage
-> risk classification
-> council/CTO review if required
-> implementation plan
-> failing test
-> code change
-> verification
-> PR
-> human approval
-> merge
-> deploy if authorized
-> smoke test
-> receipt
-> ledger update
```

## Required Evidence

Every PR opened by ExoForge should include:

- issue or objective
- risk tier
- authority basis
- changed files
- tests added or changed
- commands run
- rollback plan
- receipt expectation
- remaining risk

## Merge Policy

Phase 1:

- ExoForge opens PRs only.
- Humans merge.

Phase 2:

- ExoForge may merge after explicit human approval, green CI, receipt issuance,
  and rollback path.

Phase 3:

- ExoForge may deploy low-risk changes after receipt-backed approval, smoke
  tests, canary or rollback confirmation, and environment classification.

## Blockers

If blocked, ExoForge must not synthesize success. It must record:

- blocker
- evidence
- attempted remediation
- owner required
- risk of proceeding
- next safe action

## Deployment Smoke Checks

For Railway deployments:

```bash
railway status --json
railway logs --service <service> --build --lines 200 --json
railway logs --service <service> --lines 200 --json
curl -i https://<domain>/health
```

Do not report deployment success until the platform status is successful and
the public health endpoint returns a healthy response.
