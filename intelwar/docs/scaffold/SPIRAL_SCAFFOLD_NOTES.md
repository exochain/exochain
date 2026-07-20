# IntelWar Spiral Scaffold v1.0 → v1.2 (archived digest)

**Sources:** `intelwar-spiral-scaffold.zip` (v1.0 start) and
`intelwar-spiral-scaffold-v1.2.zip` (Council-of-Five debate + hardening),
imported evidence 2026-07-19; zips not committed.

## Spiral plan (v1.2)

| Spiral | Name | Goal |
|--------|------|------|
| 0 | Hygiene & Baseline | legal operating model, cost audit, unified-shell ratification, T&S kill switch |
| 0.5 | Living Log + 0dentity v1 | headless service + versioned contract, freeze-gated (not "frozen" by fiat) |
| 1 | Theatre Core (.org) | felt sense of entering the arena (Journey Map gated) |
| 2 | Adversarial Engine (.ai) | **primary product wedge**; cost-ceilinged in code |
| 3 | Filmstrip (.tv) | recursive debates; media cost ceiling $15/filmstrip |
| 4 | Publishing (.press) | dispatches + participation contests |
| 5 | Social + Merit UI (.net) | anti-Sybil-gated |
| 6–7+ | Integration, hardening | cross-domain heat, anti-gaming, scale |

## Council consensus applied in v1.2 (and how this repo tracks it)

1. **Contract v1.2 is DRAFT, freeze-gated** — typed envelope, event registry
   (`analysis.*`, `campaign.*`, `merit.reversed`, `moderation.takedown`…),
   `seed=true` cold-start exclusion, model_attestation with `cost_usd` and the
   disclosure "generated adversarial analysis — NOT certification of truth".
   → engine emits `analysis.<mode>` events with cost µUSD + disclosure.
2. **Binding session cost ceilings, enforced in code:** $0.15 Stress Test /
   $0.35 Cross-Check / $1.00 Red Team; live meter; auto-downgrade to budget
   tier at 80%; graceful **Command Review** stop at 100% (never raw 429);
   transparency messaging, not scarcity upsell.
   → implemented in `services/log-api/adversarial.js`.
3. **"Permanent record" → tiered retention + crypto-erasure + transparent
   takedown** (owner policy doc; recorded as founding tension CZ-04).
4. **Unified shell is the launch architecture**; five TLDs are earned later.
   → already how the SPA deploys (host-locked sections).
5. **Attestation is audit metadata, not verification** — signed provider
   metadata, never proof of accuracy/fair use/non-defamation.
6. **Red-team defusals:** no ephemeral actors writing merit, `merit.reversed`
   exists (merit is not monotonic-up), resolution metrics over engagement,
   prompt-injection hardening before publishable output.
7. **Legal front-loaded** (ToS/privacy/DMCA/DSA/takedown; billing on a
   business entity before public "permanent record" claims) — owner items,
   not code in this repo.

## Owner decisions left open (DECISION_POINTS.md)

Brand rename; degree of surface collapse; public vs private merit at launch;
Postgres event store; scope-cut list; demand-validation gate; EU/UGC legal
gating depth.

## Cold start

3–5 real campaigns through .ai + 1–2 hand-produced filmstrips + Log genesis
seeding under `seed=true`; direct-cash ceiling $450 (target ~$157); complete
within 8 weeks of Spiral 1 code-complete or escalate.
**Campaign Zero supersedes synthetic seeding** — see `CAMPAIGN_ZERO_PLAN.md`.
