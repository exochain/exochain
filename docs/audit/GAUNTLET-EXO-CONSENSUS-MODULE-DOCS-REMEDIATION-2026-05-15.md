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

# Gauntlet F-154 exo-consensus Module Docs Remediation - 2026-05-15

## Imported Evidence

- Source: Wally Fipps Gauntlet findings corpus.
- Finding: F-154, "AI consensus crate no module README".
- Reported path: `exo-consensus/src/lib.rs`.
- Severity: Medium.

The external corpus remains imported evidence. This remediation verifies the
claim against current owned source and commits only the source guard,
documentation, and this audit record.

## Path Classification

| Path | Classification | Notes |
| --- | --- | --- |
| `crates/exo-consensus/src/lib.rs` | EXOCHAIN core | Crate root for AI-panel deliberation evidence. |
| `crates/exo-consensus/README.md` | EXOCHAIN core | Crate documentation for deterministic deliberation and PCI weighting. |
| `tools/test_exo_consensus_module_docs.sh` | EXOCHAIN core CI/source guard | Prevents regression to undocumented PCI weighting and trust boundary. |
| `docs/audit/GAUNTLET-EXO-CONSENSUS-MODULE-DOCS-REMEDIATION-2026-05-15.md` | Imported-evidence triage record | Captures disposition and validation evidence. |

## Verification

Current `main` did not have `crates/exo-consensus/README.md`, and
`crates/exo-consensus/src/lib.rs` did not contain crate-level module docs. The
finding is valid for current owned EXOCHAIN core source.

## Remediation

- Added `tools/test_exo_consensus_module_docs.sh` before the documentation fix.
- Documented `exo-consensus` as deterministic AI-panel deliberation evidence,
  not BFT finality.
- Documented the Panel Confidence Index weighting:
  - 50% model agreement;
  - 30% convergence speed;
  - 20% devil's advocate.
- Documented basis-point arithmetic, no floating-point arithmetic, HLC caller
  timing, canonical claim handling, and minority-report treatment.

## TDD Evidence

RED:

```bash
bash tools/test_exo_consensus_module_docs.sh
# exo-consensus module docs test failed: crate README is required
```

GREEN commands are recorded after remediation.

```bash
bash tools/test_exo_consensus_module_docs.sh
cargo test -p exo-consensus panel_confidence -- --nocapture
cargo test -p exo-consensus minority_report -- --nocapture
cargo test -p exo-consensus -- --nocapture
cargo clippy -p exo-consensus --all-targets -- -D warnings
cargo doc -p exo-consensus --no-deps
cargo fmt --all -- --check
git diff --check
```
