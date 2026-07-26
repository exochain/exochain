<!--
Copyright 2026 Exochain Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
-->

# EXOCHAIN Holographic Perfecting Control (HPC-001)

**Control identifier:** `HPC-001`  
**Domain string:** `exo.governance.holographic_perfecting_control.v1`  
**Status:** Engineering process control (design record).  
**Not:** constitutional ratification, enacted amendment, credential issuance,
deployment authorization, package publication, or binding Council/AI-IRB
authority.

**Human Co-Principal Investigator and Chair:** Bob Stewart.  
**Design branch context:** DF-PROTOCOL-001 planning under PR #809 and any
successor EXOCHAIN delivery that adopts this control by hash.

## 0. Authority boundary

This control is an EXOCHAIN-native **process constitution for improvement**.
It constrains how agents, implementers, validators, and ledgers close waves.
It does **not**:

1. grant kernel permission, seat authority, or quorum;
2. invent D9 ratification, DIDs, keys, or credentials;
3. convert local GREEN into merge, deploy, ratify, release, or publish truth;
4. authorize production activation of Decision Forum binding mode.

A wave that violates HPC-001 is incomplete even if every L0 test is green.
A wave that satisfies HPC-001 still requires the ordinary truth-boundary
separation in §4 before any higher authority claim.

## 1. Decision and intended outcome

EXOCHAIN rejects **destination perfectionism**:

> perfect agent + perfect system + perfect end-state → stop improving

EXOCHAIN adopts **holographic perfecting**:

> every closed wave improves the artifact **and** the apparatus that improves
> artifacts, such that any fragment of work can regenerate the whole discipline

**Holographic** means: the perfecting law is encoded in each local emission
(plan edit, crate change, guard, review, AAR), not only in a distant meta-doc.
A single gate failure, residual-token forbid, or dual re-review is a shard that
still contains the whole pattern: RED → change → GREEN → independent check →
control ratchet → non-claim.

## 2. Perfecting levels (ordered, exhaustive)

Use ordered collections only (no unordered maps for inventories). Levels are
strictly layered:

| Level | Name | Object improved | EXOCHAIN native owners |
|------:|------|-----------------|------------------------|
| L0 | Artifact | Bytes under change: crates, schemas, plans, vectors, docs | Worktree paths, commits, plan SHA-256 |
| L1 | Verification | How L0 is proven: RED tests, source guards, clippy/fmt, cross-impl, tarpaulin | CI quality gates, focused cargo tests, `tools/cross-impl-test` |
| L2 | Process control | How L1 is forced next time: AAR-bound guards, inventory self-validation, dual review requirements | Wave AAR, plan self-validation, semantic guards (e.g. Wave-20 guard) |
| L3 | Meta-control | How L2 is measured for recurrence prevention | Ledger rows that prove a control would fail the old defect class without human memory |

**Invariant HPC-INV-1 (no L0-only closeout):**  
A wave may not be marked complete with only L0 deltas. It must emit at least one
L1 or L2 control that would have rejected the pre-repair defect class without
relying on author recollection.

**Invariant HPC-INV-2 (hologram honesty):**  
Every wave emission includes an explicit **NonClaimSet** naming which truth
boundaries were **not** advanced (§4). Silence is a claim of completeness and
is forbidden.

**Invariant HPC-INV-3 (fail-closed recursion):**  
Missing RED, missing independent review when required, missing AAR, or missing
NonClaimSet fails the wave closed. Defaults that invent GREEN are forbidden.

**Invariant HPC-INV-4 (deterministic process artifacts):**  
Process inventories, gate lists, NonClaimSet members, and AAR control IDs use
stable ordered presentation (sorted keys / fixed tables). No floating metrics
as authority; no wall-clock as logical order; caller-supplied or ledger HLC for
time-ordered evidence when required.

## 3. Wave emission contract (mandatory triple)

Every behavior-changing or plan-changing wave closes only when all three are
recorded in the durable ledger (`.superpowers/sdd/progress.md` and/or the
wave report under mode-0600 evidence):

### 3.1 `ArtifactDelta` (L0)

- Base SHA, head SHA, exact path list, path classification
  (core / adapter / proprietary-adjacent / imported-evidence / documentation).
- Content hashes for authoritative planning artifacts when the wave is plan-only
  (SHA-256 of each frozen plan/spec path).

### 3.2 `ControlDelta` (L1 and/or L2)

At least one of:

1. **New or hardened L1 gate** — focused RED command that failed before the
   fix and passes after, with exact exit code and transcript digest; or
2. **New or hardened L2 control** — source guard, plan self-validation needle,
   semantic contract guard, residual-token forbid, or review checklist item that
   rejects the pre-repair defect class on a clean re-injection.

ControlDelta must name:

- `control_id` (stable string, e.g. `W20-DOMAIN-RESIDUE-FORBID`);
- `defect_class` (what class is now rejected);
- `proof_of_ratchet` (command or guard that fails if the old bug is reintroduced).

### 3.3 `NonClaimSet` (hologram honesty)

Closed set of truth boundaries **not** claimed by this wave. Minimum members
when unclaimed (use exact labels):

```text
repository_state
local_test_truth
ci_truth
pr_merge_truth
deployment_control_plane_truth
runtime_probe_truth
constitutional_ratification_truth
publication_truth
```

A plan-only documentation wave must include at least
`deployment_control_plane_truth`, `runtime_probe_truth`,
`constitutional_ratification_truth`, and `publication_truth` in NonClaimSet
unless a human Chair record explicitly advances one of those boundaries with
external authenticated evidence.

## 4. Truth boundaries (EXOCHAIN native)

These are the same separations required by DF-PROTOCOL-001 delivery and
release ledgers. HPC-001 makes them **mandatory NonClaimSet vocabulary**:

| Boundary | What GREEN may mean | What GREEN never means alone |
|----------|---------------------|------------------------------|
| Repository | Path/bytes exist at a SHA | Deployed, ratified, published |
| Local test | Focused or full local cargo/npm suite | CI, merge, production |
| CI | Workflow checks on a commit | Merge authority or runtime |
| PR/merge | Review + merge policy satisfied | Constitutional binding or live traffic |
| Deployment/control-plane | Env/config actually updated | Correct semantics or legal force |
| Runtime probe | Live system answered under probe | Historical integrity forever |
| Constitutional ratification | Exact content-addressed amendment + credentials | Repo tests or package keys |
| Publication | Peer-reviewed package + manifests | Earlier planning GREEN |

**Holographic rule:** every report fragment must be readable without smuggling
a higher boundary into a lower one.

## 5. Bounded loop (finite perfecting)

Compatible with DF finite monitoring and agent wave discipline:

1. `max_iterations` is positive and declared (default engineering waves: **8**
   unless a plan sets a stricter bound).
2. Identical validation failure observed **twice** stops the loop and escalates;
   it does not authorize a third identical attempt.
3. Escalation produces a ControlDelta candidate or a Chair-scoped hold record,
   never a silent retry.
4. Rollback is reverse-order of commits/gates with re-run of focused RED that
   defined the wave.

This is **perfecting with a success/failure stop**, not infinite meta-churn.

## 6. Role separation (no self-grant of process authority)

Mirror constitutional NoSelfGrant at process level:

| Role | May do | May not do |
|------|--------|------------|
| Writer / implementer | L0 edits, propose ControlDelta, run RED | Self-approve critical/important findings |
| Specification validator | Read-only fidelity vs design/spec | Edit the same L0 under review |
| Technical validator | Reproduce gates, constitutional constraints | Soften RED or invent GREEN |
| Whole-slice / whole-plan reviewer | Cross-slice coherence, residual inventory | Replace dual independent review |
| Chair (human) | Scope decisions, external credentials, ratification gates | Be simulated by agents as production authority |

Critical and important findings require a **fresh writer** after FAIL, then
**original or fresh independent** re-review. Same-session self-approval is a
process defect under HPC-INV-3.

## 7. RED-first and ControlDelta grammar

Every behavior-changing task:

1. **RED** — deterministic failing test, source guard, or contract guard  
2. **CHANGE** — minimal L0 edit  
3. **GREEN** — same command passes  
4. **RATCHET** — ControlDelta that fails if RED is reintroduced  
5. **NONCLAIM** — NonClaimSet updated  
6. **REVIEW** — independent validation when the plan or severity requires it  
7. **LEDGER** — progress.md / wave report with identities and digests  

Plan/documentation tasks use the same grammar with **plan self-validation** or
semantic source guards as RED/GREEN (see DF Wave 20 / Slice 3 precedents).

## 8. After-action review (AAR) → L2 binding

A wave AAR is incomplete unless it records:

1. base/head SHA, paths, classification;
2. RED command and failure;
3. GREEN command and result;
4. validator identities and verdicts;
5. each finding and repair;
6. **process surprise** and root cause;
7. **ControlDelta** owner and next wave that must apply it;
8. NonClaimSet.

**HPC-INV-5 (AAR is not prose theater):**  
A lesson without a ControlDelta (or an explicit accepted residual with owner
and freeze hash) is not closed. Whole-slice review treats prose-only lessons as
open findings.

## 9. EXOCHAIN constitutional alignment

HPC-001 does not amend the eight constitutional invariants. It **implements
them for process**:

| Invariant | HPC expression |
|-----------|----------------|
| SeparationOfPowers | Writer ≠ sole approver for critical/important |
| ConsentRequired | No binding activation from process GREEN alone |
| NoSelfGrant | No self-approval of own critical repair |
| HumanOverride | Chair may freeze scope / demand external evidence |
| KernelImmutability | Process cannot rewrite kernel permission via docs |
| AuthorityChainValid | Review chain and evidence digests must be intact |
| QuorumLegitimate | Dual independent review where required; fixed severity rules |
| ProvenanceVerifiable | Base/head, hashes, commands, transcripts retained |

Determinism constraints from AGENTS.md still bind production code touched by
any wave: no floats, BTreeMap/BTreeSet only, canonical CBOR for hashed data,
HLC not system time, no unsafe, try_from not as-casts.

## 10. Binding to DF-PROTOCOL-001 and general EXOCHAIN delivery

### 10.1 DF-PROTOCOL-001

Every DF slice wave (plan or implementer) after adoption of this control:

- emits ArtifactDelta + ControlDelta + NonClaimSet;
- preserves the Wave-20 class of **downstream-interface semantic guard** as a
  durable L2 pattern (exact guard path may evolve by hash, not by vibes);
- refuses to claim Wave/Slice GREEN from a diagnostic shim;
- keeps Slice authority pure vs Slice runtime ownership (no hologram that
  pretends persistence was proven by a pure-engine plan).

### 10.2 General EXOCHAIN

Any non-DF crate wave may adopt HPC-001 by referencing this document's
content hash in the wave ledger entry. Quality gates in
`governance/quality_gates.md` remain L1 floor; HPC-001 is L2/L3 discipline
above them.

## 11. Wave closeout checklist (copy into ledgers)

```text
HPC-001 Wave Closeout
wave_id:
base_sha:
head_sha:
paths_ordered: []
path_class:
ArtifactDelta: yes|no  digest:
ControlDelta:
  control_id:
  defect_class:
  proof_of_ratchet:
NonClaimSet: [ ... exact labels from §4 ... ]
RED_command:
RED_exit:
GREEN_command:
GREEN_exit:
validators:
  specification: PASS|PASS_WITH_MINOR|FAIL|N/A
  technical: PASS|PASS_WITH_MINOR|FAIL|N/A
  whole_slice: PASS|PASS_WITH_MINOR|FAIL|N/A
AAR_control_bound_into_next_wave: yes|no
shim_used: forbidden_if_yes_for_GREEN_claim
hpc_complete: yes|no
```

`hpc_complete=yes` requires ArtifactDelta, ControlDelta, NonClaimSet, and
no forbidden shim GREEN claim.

## 12. Deterministic control self-validation

Validates **this document** only. Does not compile crates or claim deployment.

```bash
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
CTRL="$ROOT/docs/superpowers/specs/2026-07-26-exochain-holographic-perfecting-control.md"
test -f "$CTRL"

for needle in \
  HPC-001 \
  exo.governance.holographic_perfecting_control.v1 \
  ArtifactDelta \
  ControlDelta \
  NonClaimSet \
  HPC-INV-1 \
  HPC-INV-2 \
  HPC-INV-3 \
  HPC-INV-4 \
  HPC-INV-5 \
  constitutional_ratification_truth \
  publication_truth \
  max_iterations \
  proof_of_ratchet
do
  rg -q --fixed-strings "$needle" "$CTRL" || { echo "missing $needle" >&2; exit 1; }
done

# Forbid destination-perfection language as a claimed end-state for EXOCHAIN process
if rg -n 'destination perfectionism is the goal|stop improving after GREEN' "$CTRL"; then
  echo "forbidden destination-perfection claim" >&2
  exit 1
fi

python3 - "$CTRL" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
markers = sum(1 for line in text.splitlines() if line.strip().startswith("`" * 3))
if markers % 2 != 0:
    raise SystemExit(f"unbalanced fences markers={markers}")
print("fences_ok")
PY

echo "hpc001_control_self_validation=GREEN"
shasum -a 256 "$CTRL"
```

## 13. Worked EXOCHAIN precedents (illustrative, not authority)

These are evidence that EXOCHAIN already practices holographic perfecting;
they do not replace this control:

1. **DF Wave 20** — L0 plan repair + L2 semantic guard + forbid of diagnostic-shim
   GREEN claims + dual independent re-review.
2. **Slice 3 plan domain repair** — residual Wave-4 `68` / `ALL[26..]` became an
   L2 plan self-validation residue reject after FAIL triad (ControlDelta).
3. **Quality gates** — L1 floor (`governance/quality_gates.md`) independent of
   any single feature narrative.
4. **Truth-boundary ledgers** — release and dogfood records separate local,
   CI, PR, deploy, and runtime truth.

## 14. Adoption

1. Content-address this file (SHA-256 from §12).  
2. Reference that hash from `.superpowers/sdd/progress.md` wave entries and from
   DF delivery-map program gates.  
3. Require `hpc_complete=yes` before claiming a DF wave or EXOCHAIN engineering
   wave closed under agent orchestration.  
4. Do not treat adoption as D9 ratification or production activation.

---

**End of HPC-001.** Perfecting is the product; perfection is a momentary hash.
