# IntelWar Constitution (Living)

**Version:** 1.0.0-bootstrap  
**Substrate:** EXOCHAIN v0.2.3  
**Amendments:** Require IW-7 (`debate-before-doctrine`) + Living Log entry

This short compact is the governance root for IntelWar. Future changes to code,
docs, doctrine, or process MUST cite it (and the invariant IDs they affect) in
a Living Log artifact — even when the append is initially simulated.

---

## Article I — Purpose

IntelWar exists to compound strategic wisdom under consent, provenance, and
multi-intelligence transparency. Memory without consent is forbidden. Authority
without provenance is forbidden. Synthetic voices without attestation are
forbidden.

## Article II — Substrate

IntelWar is built **on** EXOCHAIN, not beside it as a parallel kernel.

1. The CGR Kernel (`exo-gatekeeper::Kernel`) adjudicates all append actions.
2. The eight EXOCHAIN constitutional invariants always apply.
3. The eight IntelWar invariants (`docs/INTELWAR_INVARIANTS_v1.md`) overlay
   domain rules for Living Log, crosscheck, debate, and multi-intelligence.
4. Patterns from `exoforge/`, `decision-forum`, `exo-consent`, `exo-proofs`,
   `exo-authority`, `exo-avc`, and `exochain-wasm` are preferred over reinvention.

## Article III — Living Log

1. The Living Log is the system of record for major artifacts, decisions, code
   changes, and agent handoffs.
2. Wire format and receipts follow `docs/LIVING_LOG_DATA_MODEL.md`.
3. Append path: consent → authority → CGR → IntelWar overlays → provenance
   receipt → DAG append (`intelwar_core::append_flow`).

## Article IV — Human Override & Consent

1. Human override is sacred (IW-5 / EXOCHAIN `HumanOverride`).
2. Consent is sacred (IW-2 / EXOCHAIN `ConsentRequired`).
3. AI/agent contributions MUST be attested (IW-4). Unattested agent prose is
   never constitutional authority.

## Article V — Separation of Powers

No actor may simultaneously exercise legislative, executive, and judicial power
over IntelWar doctrine (EXOCHAIN `SeparationOfPowers` + IW-7).

## Article VI — Self-Governance (ExoForge spirit)

1. Triage templates in `intelwar/tools/` classify work against invariants.
2. Proposed changes SHOULD emit LogEntry-shaped artifacts
   (`tools/emit-log-entry.js`).
3. After major work, agents MUST leave a Perpetual Motion Backlog
   (3–5 compounding tasks) in the handoff document.

## Article VII — Trust Claims

1. Adjacent surfaces (`apps/`, `services/`) may not claim constitutional
   enforcement by proximity.
2. Trust claims require a tested call into `intelwar-core` / EXOCHAIN APIs and
   fail-closed tests when the kernel denies.
3. Intake: `ADJACENT-SURFACE-INTAKE.md`.

## Article VIII — Amendment

Amendments are Doctrine/ConstitutionalAmendment Log entries referencing an
approved DebateSession. Spec files bump version; invariant ID renames are
breaking.

---

## Normative references

- `docs/INTELWAR_INVARIANTS_v1.md`
- `docs/LIVING_LOG_DATA_MODEL.md`
- `docs/INTELWAR_EXOCHAIN_v0.2.3_INTEGRATION.md`
- `docs/CURSOR_AGENT_HANDOFF.md`
- EXOCHAIN `AGENTS.md` (determinism, adjacent intake, core-first)
- EXOCHAIN crates: `exo-gatekeeper`, `exo-consent`, `exo-authority`, `exo-dag`,
  `exo-proofs`, `exo-avc`, `decision-forum`, `exochain-wasm`
- `exoforge/` triage & constitutional helpers
