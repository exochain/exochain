# IntelWar Quality Matrix — Exhaustive Unfinished-Work Inventory

**Date:** 2026-07-20 · **Branch:** `intelwar` · **Scope:** all five TLD
surfaces + platform (log-api, edge, deploy). Each row carries enough context
to write a standalone PRD: goal, requirements, acceptance criteria,
dependencies. Statuses: `SHIPPED` (live + tested), `PARTIAL`, `MISSING`,
`DEMO` (static data presented as demonstration), `OWNER` (non-code decision).

Honesty rule: nothing below may claim Kernel/constitutional enforcement
without a tested call path. Demo material must stay labeled as such.

---

## 0. Platform — log-api, Kernel bridge, edge, deploy

| # | Element | State | Gap / PRD context |
|---|---------|-------|-------------------|
| P-1 | Kernel-required append (fail-closed, no simulated success) | SHIPPED | Source guard + tests (`no-sim-success.test.js`). |
| P-2 | Durable consent across restarts | SHIPPED | `consent.json` on volume; `durable` flag on `/api/consent`; restart test. |
| P-3 | OpenRouter adversarial engine (3 modes, frontier roster) | SHIPPED | `adversarial.js`; model identity on every run. |
| P-4 | Cost ceilings enforced in code | SHIPPED | µUSD meter, 80% downgrade, Command Review at 100%; structured `adversarial_run` observability log line. |
| P-5 | Analysis events → Living Log (mandatory attempt, honest status) | SHIPPED | `writeAnalysisEventToLog`; `log_write` in every run response. |
| P-6 | Campaign Zero founding entries + seed/read routes | SHIPPED | 9/9 Kernel-seeded on durable volume. |
| P-7 | 0dentity summary surface (contract §13 direction) | SHIPPED (v0) | `GET /api/0dentity/summary` — counts + chain check from mirror. PRD next: per-actor summaries once actor identity exists (depends P-10). |
| P-8 | `OPENROUTER_API_KEY` unset in production | OWNER | Until set, .ai runs are labeled structure demos. Acceptance: catalog `configured:true`, live run returns frontier models + `log_write.ok:true`. |
| P-9 | Session cost meter is in-memory | PARTIAL | Acceptable v1 (single replica). PRD: persist per-session spend to state dir keyed by session_id with TTL; FIFO eviction at 1000 sessions can reset a live session (ceiling bypass) — evict by age not insertion; acceptance: meter survives restart mid-session; no double-spend reset exploit. |
| P-10 | API auth/scopes (contract §4: service → event-type table, OIDC identity) | MISSING | PRD: bearer service keys per emitting surface (ai/tv/press/net/seed), scope table enforcement (403 on out-of-scope event_type), operator OIDC for human writes. Acceptance: unauthed append rejected; ai key cannot emit `contest.*`. |
| P-11 | Idempotency keys (contract §3) | MISSING | PRD: `Idempotency-Key` header on append/seed; replay returns original receipt with `409`/`200-replay` semantics; store key→entry map in state dir. |
| P-12 | Typed event envelope + registry validation (contract §2/§7) | PARTIAL | Payloads are ad-hoc JSON strings. PRD: validate `event_type` against registry; reject unknown types per emitting service; envelope fields (`event_id`, `occurred_at` HLC, `actor`, `payload_schema_version`). |
| P-13 | Hash-chain verification endpoint | PARTIAL | Chain check inside 0dentity summary. PRD: `GET /api/log/verify` walking full mirror, returning first break point; UI badge on .net. |
| P-14 | `merit.signal` / `merit.reversed` events | MISSING | PRD: signed merit events with `signal_source`, `signal_basis`, `confidence`, `decay_period`, `challenge_status`; sandboxed for CZ; no public leaderboard (DP-C). |
| P-15 | `moderation.takedown` + retention/erasure path | MISSING | PRD per RETENTION_TAKEDOWN_POLICY digest: takedown event type, tombstone rendering (removal is itself recorded), crypto-erasure of payload with receipt preserved. Blocks public UGC. |
| P-16 | RFC 9457 problem-details errors + batch append | MISSING | PRD: error envelope with `type/title/status/detail/instance`; `POST /api/log/batch` with per-item results. |
| P-17 | Prompt-injection hardening (Spiral-2 defusal #6) | PARTIAL | Claims are quoted into user prompts; no sanitization layer or source-excerpt gate. PRD: strip instruction-like content from evidence blocks; block publish of analyses lacking raw source excerpts for major claims. |
| P-18 | Prompt caching (static rubric tokens) | MISSING | PRD: OpenRouter `cache_control` on system blocks where provider supports; measure 15–30% cost cut on red team; acceptance: cost per red-team session reduced vs baseline in observability logs. |
| P-19 | Rate limiting / abuse guard on adversarial + append routes | SHIPPED (v0) | See P-27. RFC 9457 problem-details shape still pending (P-16). |
| P-20 | DAG DB durable persist wired (`INTELWAR_DAGDB_*`) | OWNER | Env unset → `durable: local_kernel`. Acceptance: append returns `durable: dagdb` in prod. |
| P-21 | Edge worker covers only .org/.press titles | PARTIAL | PRD: extend `TITLE_BY_HOST` to .net/.ai/.tv (SPA sets titles client-side; edge gives crawlers correct titles), plus per-host meta description injection. |
| P-22 | Mirror rows lack payload/campaign fields | PARTIAL | CZ filtering uses summary prefix. PRD (intelwar-core bridge): add `payload_hash` + optional `campaign`/`event_type` to mirror row; Rust change + tests; keeps mirror lean while enabling structured filtering. |
| P-23 | Cost observability dashboard | PARTIAL | Structured log line ships; PRD: `GET /api/adversarial/spend` (aggregate µUSD by day/mode) + Railway log-based alert at 80% of monthly budget. |
| P-24 | Bridge state file locking | MISSING | Each append spawns the Kernel bin (load → append → save `bridge_state.json`) with no lock; concurrent appends can lose entries or break the receipt chain. PRD: advisory lockfile or serialize appends through a queue in log-api; acceptance: 20 parallel appends produce 20 linked entries. |
| P-25 | DAG DB split-brain on retry | MISSING | Kernel write succeeds → gateway persist fails → 503 returned; client retry duplicates the Kernel entry. PRD: return 201-with-warning instead of 503 once Kernel persisted, or idempotency key (P-11) covering the retry. |
| P-26 | Open CORS + unauthenticated writes | SHIPPED (interim) | Operator token (`INTELWAR_ADMIN_TOKEN`, timing-safe, fail-closed 503 when unconfigured) required on consent grant/revoke, log append, campaign-zero seed, crosscheck sign/sign-demo. CORS allowlisted to intelwar.* origins. Verified live: anonymous/wrong-token writes → 401; reads public. Full service-scoped auth remains P-10. |
| P-27 | Rate limits + per-IP daily budget | SHIPPED (v0) | Per-IP fixed-window buckets: writes 10/min, adversarial 6/min, verify 30/min (429 + Retry-After). Adversarial runs debit a per-IP daily budget (`INTELWAR_IP_DAILY_BUDGET_MICRO_USD`, default $2/day) once OpenRouter is configured. In-memory, single-replica — durable meters remain P-9. |

## 1. intelwar.org — Mind War Theatre

| # | Element | State | Gap / PRD context |
|---|---------|-------|-------------------|
| ORG-1 | Threshold hero + doctrine framing | SHIPPED | |
| ORG-2 | Active Campaigns board | PARTIAL/DEMO | Six conceptual campaigns are static copy. Campaign Zero card (live, links to .net record) SHIPPED. PRD: campaign registry API (`campaign.*` events) so board reads live campaigns with status/heat; acceptance: adding a campaign via Log reflects on .org without redeploy. |
| ORG-3 | Basic Training | PARTIAL | Static curriculum sections. PRD: interactive first-mission flow (read doctrine → run one stress test → view its Log receipt) with progress state in localStorage; acceptance: completing training deep-links user to .ai with a starter claim. |
| ORG-4 | Role Selection | PARTIAL | Role cards static; no persistence. PRD: chosen role stored (localStorage v1), reflected in .net social identity panel; acceptance: role chip visible across surfaces. |
| ORG-5 | Deployment CTA (combat-record share loop) | MISSING | PRD: deployment section offers "run your first stress test" + share permalink of resulting Log entry (growth loop from COST_MODEL §8). |
| ORG-6 | Cross-TLD Journey Map gate (Seat 2) | OWNER/MISSING | PRD: journey map doc + wireframes for Threshold→Training→Role→Deployment→(.ai/.tv/.press/.net) before further .org build. |
| ORG-7 | "How the Theatre Works" deep-tech fold | SHIPPED | |
| ORG-8 | Combatant role CTA routes to contests | SHIPPED | "Enter contest" now lands on .press (contests board) instead of the .net operational shell. |

## 2. intelwar.press — Fourth Estate

| # | Element | State | Gap / PRD context |
|---|---------|-------|-------------------|
| PRESS-1 | First Amendment / Fourth Estate framing + Record links | SHIPPED | |
| PRESS-2 | Dispatches | DEMO | Static dispatch cards. PRD: `contribution.published` events; dispatch detail view reads from Log; provenance chip per dispatch; acceptance: publishing via API surfaces on .press. |
| PRESS-3 | Contests | DEMO | Static contest copy. PRD: contest state machine (`contest.created→opened→entry_submitted→submissions_closed→judged→resolved→archived`) as Log events + panel rendering state; participation-only (no prize) until legal gate; acceptance: full lifecycle driven by API calls, each state visible. |
| PRESS-4 | Pre-publication pressure-test hook (.ai) | SHIPPED (v0) | Contest cards now stage the claim (`stageAdversarialHandoff`, mode cross) into the .ai workbench. Remaining PRD: return-path chip "pressure-tested · N vulnerabilities addressed" on the dispatch. |
| PRESS-5 | AI-content labeling + human-review gate for sensitive classes | MISSING | Spiral-2 legal: analyses about identifiable people/elections/misconduct blocked from .press publication until human review; visible AI labels. PRD ties to P-15 moderation fields. |
| PRESS-6 | Takedown/retention public policy page | MISSING | PRD: policy page rendering RETENTION_TAKEDOWN digest; linked from footer; required before public UGC. |

## 3. intelwar.net — Social + Living Log + Campaign Zero

| # | Element | State | Gap / PRD context |
|---|---------|-------|-------------------|
| NET-1 | Living Log viewer (Kernel rows, receipts) | SHIPPED | Permalinks + highlight SHIPPED this spiral. |
| NET-2 | Consent-gated append demo | SHIPPED | Durable consent now; UI unchanged. |
| NET-3 | Campaign Zero founding panel + seed | SHIPPED | 9/9 live. |
| NET-4 | Log-derived signals strip (0dentity v0) | SHIPPED | Counts + chain badge from `/api/0dentity/summary`. |
| NET-5 | Social layer (profiles, coalitions, discovery, notices) | DEMO | `social-data.js` personas presented as demonstration. PRD: real actor identity (P-10 OIDC) → replace personas with actual operators; coalitions as `coalition.*` Log events; acceptance: no fabricated persona shown as real. |
| NET-6 | Reputation mechanics panel | DEMO | Engine is real math over demo records. PRD: feed from real Log signals (analysis survival, CZ dilution rule); keep "no public leaderboard"; acceptance: standing derives only from Kernel-mirrored events. |
| NET-7 | Merit sandbox dilution mechanics | MISSING | PRD: portability formula — founding merit weight decays as external (non-CZ) entries accumulate; unit-tested integer bps math; surfaced honestly in ReputationPanel. |
| NET-8 | Receipt-chain verify badge (full log) | PARTIAL | Signals strip shows linked/broken; PRD: dedicated verify endpoint (P-13) + per-entry chain position tooltip. |
| NET-9 | Notifications / notices | DEMO | Static notices in social data. PRD: derive from Log events relevant to the operator (challenge on your entry, contest state change). |
| NET-10 | Campaign Zero → external-campaign transition mechanics | MISSING | Transition rule is text (CZ-09) only. PRD: `campaign.status_changed` API to close founding status and open external campaigns; merit-portability gate keyed to founding/external entry ratio; .net panel shows transition progress. Acceptance: opening the first external campaign flips founding status via a Log event, not a code edit. |

## 4. intelwar.ai — Adversarial Intelligence

| # | Element | State | Gap / PRD context |
|---|---------|-------|-------------------|
| AI-1 | Stress Test (structured schema, steelman-first) | SHIPPED | Iteration (defend→re-run, meter continuity) SHIPPED this spiral. |
| AI-2 | Cross-Check (5-model comparison) | SHIPPED | Delta view (convergence/friction, contradictions union) SHIPPED this spiral. |
| AI-3 | Multi-Model Red Team (role-assigned) | SHIPPED | Gated behind same ceilings; DP-E notes ship-after-cost-proof — ceilings are live. |
| AI-4 | Cost meter UI + Command Review state | SHIPPED | RunMeta strip on all panels. |
| AI-5 | Promote artifact → Living Log | SHIPPED | Consent-gated Kernel append; honest fail-closed messaging. |
| AI-6 | Kernel Attest tab (sign-demo + verify) | SHIPPED | Pre-existing CrossCheckPanel. |
| AI-7 | Frontier runs live | OWNER (P-8) | Blocked only on `OPENROUTER_API_KEY`. |
| AI-8 | Model Masks (visual identity per model) | PARTIAL | Model chips exist; PRD: consistent per-model color/typography tokens across compare cards, delta chips, red-team roles; acceptance: same model always same mask. |
| AI-9 | Deep Dive / Evidence Engine (spec §3.5) | MISSING | PRD: long-form mode combining claim cluster + provided sources; provenance-aware evaluation (each major claim must cite a supplied excerpt); output = structured evidence map; ceiling $1.00; writes `analysis.deep_dive`. Depends P-17. |
| AI-10 | Session history (persistent, model-attributed) | MISSING | PRD: local session archive (IndexedDB/localStorage) listing past runs with models, cost, log_write receipts; export JSON; acceptance: reload restores history; nothing claims server persistence. |
| AI-11 | In-situ .tv fork analysis | PARTIAL | Handoff ships (.tv → .ai staged claim). PRD: embedded mini stress panel inside fork studio rendering the same structured output in-place; writes fork-tagged analysis event. |
| AI-12 | Iteration credit in schema | PARTIAL | Round context is prompt-encoded. PRD: schema field `answered_prior_vulnerabilities[]` so round N+1 explicitly scores the defense. |

## 5. intelwar.tv — Filmstrip Theatre

| # | Element | State | Gap / PRD context |
|---|---------|-------|-------------------|
| TV-1 | Recursive filmstrip engine (scenes, branches, forks, heat) | SHIPPED (sim) | Deterministic seed campaign clearly labeled demonstration. |
| TV-2 | Campaign Zero live rail | SHIPPED | Kernel entries rendered beside the demo strip. |
| TV-3 | Fork → AI handoff | SHIPPED | Stages claim + navigates. |
| TV-4 | Scene → Log bind | PARTIAL | "Propose Log bind" simulates locally. PRD: real append (`scene.created`/`fork.created` events) via consent-gated API with fork content payload; acceptance: bound scene shows real receipt hash. |
| TV-5 | Live mode governance | PARTIAL | Live lock exists in UI; PRD: define live-session rules (who can open live, fork constraints) — owner input needed. |
| TV-6 | Media production pipeline (real video scenes) | MISSING/OWNER | PRD per COST_MODEL §3: budget-tier default, $15/filmstrip ceiling metered like sessions, no auto-generation per fork, 3/user/day cap. Big build; gated on demand (DP-F). |
| TV-7 | Heat from real engagement | DEMO | Heat computed from seeded numbers. PRD: heat inputs from real events (views can stay client-side; forks/binds from Log); label until then. |
| TV-8 | Fork modes render honestly | SHIPPED | `micro`/`frame` no longer collapse to a generic mode; distinct reply scenes per mode (tested). Bind labels say "proposed · pending Kernel" — no false "bound" claim. |

## 5b. Shell / cross-surface fixes (audit reconciliation, 2026-07-20)

| # | Element | State | Note |
|---|---------|-------|------|
| SH-1 | `.surface-net` accent theme | SHIPPED | .net no longer falls through to default vars. |
| SH-2 | Footer "Review the Constitution" deep-link | SHIPPED | Scrolls to `#constitutional-engine`. |
| SH-3 | Handoff claim sync bug (.tv/.press → .ai panels) | SHIPPED | Panels adopt late-arriving `initialClaim` unless user typed. |
| SH-4 | Red Team panel error UI | SHIPPED | Failed runs now render the fail-closed reason. |
| SH-5 | Artifact `entry_kind` alignment | SHIPPED | Drafts use Kernel-supported `Analysis` (was `AdversarialAnalysis`, not a bridge kind). |
| SH-6 | Empty model-catalog guard | SHIPPED | `{}` no longer renders an empty routing section. |
| SH-7 | Global log/consent fetch on every surface | PARTIAL | org/press pay an unused fetch; PRD: fetch on net/ai/tv only. |
| SH-8 | Recognition issuance UI (spec feature) | MISSING | Recognition is display-only in social demo; PRD with NET-5 identity work. |

## 5c. Monetization (non-extractive charter)

| # | Element | State | Gap / PRD context |
|---|---------|-------|-------------------|
| M-1 | Join — Frontier Pass ($3.69 — 3·6·9 — one-time, Stripe Checkout) | SHIPPED (fail-closed) | `POST /api/join/checkout` + `GET /api/join/claim` (server-side payment verification, double-claim safe, hashed pass store on volume) + `GET /api/join/economics` (integer-cent fee math: 369¢ − 41¢ ≈ 328¢ net; gross-up for $3.69 net = 411¢). Pass raises per-IP daily budget 5× for 30 days via `x-intelwar-pass`. Locked 503 until `STRIPE_SECRET_KEY` set (OWNER). Charter enforced: reads + baseline runs stay free. |
| M-2 | Stripe webhook (`checkout.session.completed`) | MISSING | Claim-on-return works without it; PRD: webhook with HMAC signature verify for claims that never return to the site + refund/dispute handling (revoke pass on `charge.refunded`). |
| M-3 | Pass recovery / receipt lookup | MISSING | Pass lives in one browser. PRD: re-claim by Stripe session id lookup (operator-assisted), or email receipt with claim link. |
| M-4 | Business billing entity | OWNER | Seat 4: move Stripe/OpenRouter/Railway billing to a dedicated entity before public "permanent record" claims. |

## 6. Cross-cutting

| # | Element | State | Gap / PRD context |
|---|---------|-------|-------------------|
| X-1 | Unified shell, host-locked surfaces | SHIPPED | Five-TLD split deferred (CF-8). |
| X-2 | Multi-Intelligence Transparency everywhere | SHIPPED | voice_kind + model ids on all synthetic output. |
| X-3 | Resolution/usefulness metrics (Seat 5 #9) | MISSING | PRD: count claim-corrections (iteration rounds that change verdicts), promote rate, permalink share rate — from observability lines + client pings; no engagement vanity metrics. |
| X-4 | Legal operating model (ToS, privacy, DMCA/DSA) | OWNER | Blocks public UGC + prize contests; participation-only until done. |
| X-5 | Business billing entity for OpenRouter/Railway | OWNER | Required before public "permanent record" claims (Seat 4). |
| X-6 | Demand gate metrics before .tv media build (DP-F) | OWNER | Use X-3 data. |
