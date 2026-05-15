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

# exo-consensus

`exo-consensus` is the deterministic AI-panel deliberation crate for EXOCHAIN
governance evidence. It runs model-panel rounds, binds structured model
responses to commitments, canonicalizes key claims, measures convergence,
records devil's-advocate review, emits minority reports, and produces a hashed
`DeliberationResult`.

## Classification

This crate is EXOCHAIN core. Its output can be used as evidence by governance
and adjudication flows, so it must preserve the same determinism constraints as
the rest of the Rust trust fabric.

The trust boundary is narrow: `exo-consensus` is not BFT finality. It does not
append DAG nodes, elect leaders, sign validator votes, update consent state, or
grant constitutional authority. A deliberation record is evidence for a caller
that still has to pass the gatekeeper, DAG, authority, consent, and provenance
checks required by the runtime path that consumes it.

## Deterministic Deliberation Flow

1. A caller constructs a `Panel` for the decision class and supplies a
   deterministic response provider.
2. Each panelist response is validated, committed, revealed, and verified before
   it becomes a `ModelPosition`.
3. The crate derives canonical key-claim sets by trimming, lowercasing, sorting,
   deduplicating, and removing empty claims.
4. Convergence is computed from structured key claims in basis points.
5. If the round converges or reaches the panel's maximum round count, the
   configured devil's advocate reviews the result.
6. Finalization derives consensus claims, minority reports, the Panel Confidence
   Index, and a canonical hash for the `DeliberationResult`.

Callers supply HLC timestamps through `RoundExecutionTiming` and
`FinalizationTiming`. The crate must not read system time inside production
logic.

## Panel Confidence Index

The Panel Confidence Index is a bounded basis-point score in the range
`0..=10000`. The score uses no floating-point arithmetic and is calculated from
integer components:

| Component | Weight | Source |
| --- | ---: | --- |
| Model agreement | 50% model agreement | `models_agreeing / total_models * 5000` |
| Convergence speed | 30% convergence speed | Faster convergence across the allowed round budget contributes up to 3000 bps. |
| Devil's advocate | 20% devil's advocate | A serious objection removes the 2000 bps advocate component. |

minority reports reduce the agreement component. During finalization, panelists
whose structured claims fall below the consensus-claim threshold are recorded as
minority reports; the session then sets `models_agreeing` to
`panelists_count - minority_reports_count` before calculating the Panel
Confidence Index.

All inputs are defensively bounded in `calculate_panel_confidence`: agreeing
models are capped at total models, convergence speed is capped by the maximum
round count, and the theoretical maximum remains 10000 bps.

## Constitutional Constraints

The crate follows the core EXOCHAIN constraints:

- no floating-point arithmetic in scoring or consensus logic;
- sorted deterministic collections for canonical claim handling;
- caller-provided HLC timestamps instead of system time;
- typed errors with enough context for diagnosis;
- no authority, consent, provenance, or governance outcome minted outside the
  consuming core runtime path.

Any adapter or adjacent surface that presents `exo-consensus` output as an
EXOCHAIN trust decision must prove the runtime call path into core enforcement
and must fail closed when that enforcement rejects, times out, or is
unavailable.
