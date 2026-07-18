# IntelWar ↔ EXOCHAIN v0.2.3 Integration Map

**Baseline commit:** `a50a15fd` (tag `v0.2.3`)  
**Classification:** Core runtime adapter (`intelwar-core`) + adjacent MVP shells

---

## Domain mapping

| IntelWar concept | EXOCHAIN primitive | Path |
|------------------|-------------------|------|
| Living Log ledger | `exo_dag::append` / `Dag` | `crates/exo-dag/src/dag.rs` |
| Consent gate | `BailmentState` + `ConsentRecord` + `ConsentRequired` | `crates/exo-gatekeeper` + `crates/exo-consent` |
| Authority | `AuthorityChain` / `AuthorityLink` | `crates/exo-gatekeeper/src/types.rs`, `crates/exo-authority` |
| Adjudication | `Kernel::adjudicate` | `crates/exo-gatekeeper/src/kernel.rs` |
| EXOCHAIN invariants | `ConstitutionalInvariant` (8) | `crates/exo-gatekeeper/src/invariants.rs` |
| IntelWar overlays | `IntelWarInvariant` (8) | `intelwar/crates/intelwar-core/src/invariants.rs` |
| Provenance / voice | `Provenance`, `VoiceKind`, … | `crates/exo-gatekeeper/src/types.rs` |
| Proof envelopes | `ProofEnvelope`, `ProofStatementKind` | `crates/exo-proofs/src/envelope.rs` |
| Multi-intelligence creds | AVC + `LlmUsageEvidence` | `crates/exo-avc` |
| Debate / doctrine | `DecisionObject`, human gate | `crates/decision-forum` |
| Browser / .ai / .tv | `wasm_enforce_invariants`, … | `crates/exochain-wasm` |
| Project triage | ExoForge panels | `exoforge/bin/exoforge-triage.js` |
| Full-stack patterns | demo services + React | `demo/` |

---

## Invariant alignment table

| # | IntelWar (adopted) | Primary EXOCHAIN hooks | Encode as |
|---|--------------------|------------------------|-----------|
| IW-1 | ConsentRequired | `ConsentRequired` | Bailment + scope `log:append` |
| IW-2 | ProvenanceVerifiable | `ProvenanceVerifiable` | Content hash + LivingLogReceipt chain |
| IW-3 | MultiIntelligenceTransparent | `VoiceKind` / AVC / quorum voice rules | Attestation fields on entry |
| IW-4 | EvidenceDisciplined | decision-forum + crosscheck | Payload / CrossCheck / DebateSession |
| IW-5 | HumanOverridePriority | `HumanOverride` | `human_override_preserved` |
| IW-6 | FailClosedEnforcement | Kernel denials / no bypass | Reject on any invariant miss |
| IW-7 | StrategicUtility | (policy overlay) | Non-empty strategic summary |
| IW-8 | LogIntegrity | DAG append-only / `KernelImmutability` spirit | Parent tips + content hash |

See also v0.2.3 Implementation Notes in `INTELWAR_INVARIANTS_v1.md`.

---

## Log model sketch (flows)

### Happy path append

```text
Human/Agent → Consent (bailment active)
           → Authority chain (log:append)
           → Provenance signed (VoiceKind explicit)
           → Kernel.adjudicate → Permitted
           → IntelWarInvariantEngine → Ok
           → exo_dag.append(CBOR entry)
           → LivingLogReceipt (chain previous)
```

### Denied path

```text
Any failed invariant → Verdict::Denied { violations }
                     → No DAG write
                     → Optional DevelopmentDecision Log of the denial (meta)
```

### Human override

```text
Verified human → entry_kind=HumanOverride
              → may install scoped hold
              → cannot erase prior entries
```

---

## Dependency strategy

See [`../DEPENDENCY_PLAN.md`](../DEPENDENCY_PLAN.md).

**Chosen for bootstrap:** path dependencies on workspace crates at `=0.2.3`,
with `intelwar/crates/intelwar-core` as a workspace member so CI gates compile
the adapter. Adjacent JS apps are **not** workspace members.

---

## What we deliberately do not reinvent

- New crypto / DID systems → use `exo-core`
- Parallel kernel → use CGR
- Parallel consent machine → use bailment + ConsentRequired
- Parallel debate engine → use decision-forum
- Parallel WASM kernel → wrap `exochain-wasm`

---

## Gaps vs production (honest)

| Gap | Status |
|-----|--------|
| Gateway DAG DB persistence for Living Log | Local multi-node + optional gateway (PM-002); live pool CI still pending |
| DebateSession ↔ decision-forum | **Done (PM-003):** Doctrine/Amendment require DecisionObject + human gate |
| WASM export of IntelWar overlays | Hook stubs in `intelwar/wasm/` |
| Real AVC minting for agent sessions | Scaffold via attestation fields |
| Railway production secrets / tenant | Fail closed until configured |

These gaps do **not** authorize stubs in the constitutional path: the Rust
append flow fails closed; the Node MVP labels simulated entries explicitly.
