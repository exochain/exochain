# Campaign Zero — The Founding of the Arena (archived plan digest)

**Source:** `intelwar-campaign-zero.zip` (imported evidence, 2026-07-19; zip not committed)
**Status:** executing — instruments + founding capture live on this branch

## Core strategy

The design and architectural contest of IntelWar is itself the first live
campaign. Record real decisions, tensions, and human–AI exchanges as
structured Living Log entries with provenance — authentic genesis content
instead of synthetic seeding.

## Hard rules

1. Design process = founding campaign; capture decisions/tensions/exchanges as Log entries.
2. Build the real instruments in parallel (Living Log + 0dentity v1, .ai Stress Test / Cross-Check).
3. Rigor over drama — record cleanly, do not perform.
4. Explicit transition path to external campaigns (not permanently self-referential).
5. Campaign Zero merit is sandboxed, labeled, non-portable until diluted.

## Implementation in this repo

| Requirement | Where |
|-------------|-------|
| Living Log headless service | `services/log-api` (Kernel-required, fail-closed) |
| .ai Stress Test / Cross-Check / Red Team via OpenRouter | `services/log-api/adversarial.js` + `.ai` workbench |
| Cost ceilings in code ($0.15 / $0.35 / $1.00, µUSD integers, 80% downgrade, 100% Command Review) | `adversarial.js` (`CEILINGS_MICRO_USD`, `ceilingDecision`) |
| Analysis events written to the Log (`analysis.*`, cost attested) | `server.js` `writeAnalysisEventToLog` — mandatory attempt, honest status |
| Founding entries flagged + sandboxed merit | `services/log-api/campaign-zero.js` (CZ-01…CZ-09, `merit_scope=sandboxed`) |
| Seed + read routes | `POST /api/campaign-zero/seed` (consent + Kernel bins required), `GET /api/campaign-zero` |
| Founding campaign surfaced | `.net` `#campaign-zero` (`CampaignZeroPanel`) |
| Unified shell maintained | single SPA, host-locked sections (no five-TLD split) |
| Non-goals honored | no new social/feed/leaderboard surface added in this loop |

## Success condition

A new participant sees a real founding campaign — actual intellectual combat
between human and AI about the design of the system itself — as the primordial
example of the arena working.
