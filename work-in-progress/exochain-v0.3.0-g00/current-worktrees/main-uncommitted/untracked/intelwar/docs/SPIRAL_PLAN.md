# IntelWar Spiral Execution Plan — Veritas Cycle

**Date:** 2026-07-20 · **Source of truth for gaps:** `QUALITY_MATRIX.md`
(row IDs referenced below). Risk-driven spirals; each spiral has entry gates,
exit criteria, and bounded iteration.

## Loop bounds (required for autonomous execution)

```yaml
loop:
  max_iterations: 6            # spirals per cycle; finite and small
  per_spiral_max_attempts: 3   # a failing gate may be retried twice
  stop_condition: >
    All spiral exit criteria green, or an exit criterion fails twice with
    the same validation error, or an OWNER-classified blocker is reached.
  escalation_path: >
    Stop building, record the blocker in QUALITY_MATRIX.md with evidence,
    and hand the decision to the operator (owner decisions: secrets, legal,
    billing, brand, media budget). Never loop on the same failure a third
    time; never simulate success to pass a gate.
```

## Spiral V1 — Truth Loop (EXECUTED this cycle)

Goal: close the loop analysis → record → visible proof, and kill state
fragility. Rows: P-2, P-5(obs), P-7, NET-1/4, AI-1(iter), AI-2(delta),
AI-5, TV-2, ORG-2(CZ card), P-23(partial).

Exit criteria — all verified live 2026-07-20:
- [x] Consent survives restart (`durable: true`; restart test in CI).
- [x] `GET /api/0dentity/summary` serves mirror-derived signals; chain check
      true against 9 founding entries.
- [x] Promote on .ai performs a real consent-gated Kernel append (or fails
      closed with the exact reason).
- [x] Stress Test supports defend→iterate rounds on one cost meter.
- [x] Cross-Check renders convergence/friction delta, not stacked text.
- [x] Living Log rows carry shareable permalinks; `#log=<id>` highlights.
- [x] .tv shows Campaign Zero live from the Log beside the labeled demo.
- [x] .org Active Campaigns leads with the real founding campaign.
- [x] Structured `adversarial_run` cost observability line on every run.
- [x] Audit-reconciliation fixes: press contest → .ai claim handoff; fork-mode
      honesty on .tv (distinct micro/frame/challenge replies, "pending Kernel"
      bind labels); handoff claim-sync bug; Red Team error UI; `.surface-net`
      theme; footer constitution deep-link; Kernel-valid artifact entry kind.
- [x] Full test suites green (SPA 51, log-api 23); deployed; live-verified.

## Spiral V2 — Contract Hardening (NEXT)

Goal: the write path becomes a real versioned contract. Rows: P-10, P-11,
P-12, P-13, P-16, P-19, P-22, P-24, P-25, P-26.
Entry gate: none (code-only).
Exit criteria:
- [x] Interim write guard SHIPPED 2026-07-20: operator token (fail-closed
      when unconfigured) on all trust-mutating routes; CORS allowlist;
      per-IP rate limits; per-IP daily adversarial budget. Live-verified:
      anonymous writes 401, reads public, founding record intact.
- [ ] Full service-scoped bearer auth; scope table enforced (403
      out-of-scope) — replaces the single operator token (P-10).
- [ ] Idempotency-Key replay-safe append (also closes DAG DB retry
      split-brain — P-25).
- [ ] Append serialization / bridge state locking (P-24): 20 parallel
      appends → 20 chain-linked entries.
- [ ] Event registry validation on payload `event_type`.
- [ ] `GET /api/log/verify` full-chain endpoint + .net badge.
- [ ] RFC 9457 errors; rate limiting on write + adversarial routes.
- [ ] Mirror rows carry `event_type`/`payload_hash` (intelwar-core bridge
      change + Rust tests + workspace gates).

## Spiral V3 — Evidence Engine + Hardening (.ai deepening)

Rows: AI-9, P-17, P-18, AI-12, AI-8, AI-10.
Entry gate: P-8 (`OPENROUTER_API_KEY`) for live-cost validation — OWNER.
Exit criteria:
- [ ] Deep Dive mode: source-bound evidence maps; refuses major claims
      without excerpts; `analysis.deep_dive` events with cost.
- [ ] Injection-hardened ingestion (instruction stripping + excerpt gate).
- [ ] Prompt caching measurably cuts red-team session cost (observability).
- [ ] Iteration schema credits answered vulnerabilities.
- [ ] Model Masks consistent across all comparison UI.
- [ ] Local session history with export.

## Spiral V4 — Press Becomes Real

Rows: PRESS-2, PRESS-3, PRESS-4, PRESS-5(partial), NET-9(partial).
Entry gate: V2 auth (contest writes need scopes).
Exit criteria:
- [ ] Dispatch publish path writes `contribution.published`; .press renders
      from Log; provenance chip per dispatch.
- [ ] Contest state machine drives the contests panel end-to-end
      (participation-only; no prizes until X-4 legal).
- [ ] Dispatch → .ai pressure-test handoff with return chip.
- [ ] Sensitive-class analyses blocked from publish without human review.

## Spiral V5 — Social Becomes Honest

Rows: NET-5, NET-6, NET-7, ORG-3, ORG-4, ORG-5, X-3.
Entry gate: V2 identity (OIDC/actor union).
Exit criteria:
- [ ] Demo personas removed or explicitly quarantined behind a "fiction"
      label; real operator identity drives social panels.
- [ ] Standing derives only from Kernel-mirrored events; CZ dilution math
      unit-tested; no public leaderboard.
- [ ] .org training/role/deployment persist state and deep-link into a
      first real stress test + shared permalink (growth loop).
- [ ] Resolution metrics collected (correction rate, promote rate, share
      rate) — no engagement vanity metrics.

## Spiral V6 — Theatre Media (gated)

Rows: TV-4, TV-6, TV-7, P-15.
Entry gates: DP-F demand data from X-3 (OWNER), media budget (OWNER),
takedown path P-15 before public UGC.
Exit criteria:
- [ ] Scene/fork binds write real `scene.*`/`fork.*` events with receipts.
- [ ] Media generation metered under $15/filmstrip ceiling, budget tier
      default, hard caps enforced in code.
- [ ] Heat inputs from real events; demo labels removed only where true.

## Standing rules for every spiral

1. Fail closed; never simulate Kernel or provider success.
2. Every synthetic output carries model identity; disclosure text intact.
3. Tests + lints green before deploy; live verification after deploy.
4. Update `QUALITY_MATRIX.md` statuses in the same change set.
5. Imported evidence stays out of the repo; digests only.
6. Owner decisions are escalated, not guessed.
