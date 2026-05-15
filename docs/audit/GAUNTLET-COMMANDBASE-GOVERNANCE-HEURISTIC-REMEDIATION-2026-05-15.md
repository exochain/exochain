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

# Gauntlet CommandBase Governance Heuristic Remediation - 2026-05-15

This record covers the adjacent CommandBase remediation for Wally Fipps Gauntlet
F-042 and F-043. The external artifacts remain imported evidence and were not
committed as source files:

- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-findings.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-deep-analysis.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/da-findings.tsv`

## Path Classification

| Path | Classification | Notes |
| --- | --- | --- |
| `command-base/app/services/governance.js` | Adjacent surface | CommandBase-local governance receipt and heuristic invariant-check service. |
| `command-base/app/services/governance.test.js` | Adjacent surface | Regression coverage for the adjacent heuristic boundary. |
| `command-base/EXOCHAIN_SURFACE_INTAKE.md` | Adjacent surface | Ownership and trust-boundary intake record. |
| `docs/audit/GAUNTLET-COMMANDBASE-GOVERNANCE-HEURISTIC-REMEDIATION-2026-05-15.md` | EXOCHAIN core | Owned audit/triage governance artifact summarizing imported evidence and adjacent remediation without committing external artifacts. |

## Findings

| Finding | Disposition | Remediation |
| --- | --- | --- |
| F-042 governance receipts from regex scan of LLM output | Remediated for CommandBase adjacent surface | `validateAgainstInvariants` no longer calls `createReceipt` or appends to `governance_receipts` from heuristic scans of untrusted output. It writes an audit-trail record with `receipt_created: false` instead. |
| F-043 `validateAgainstInvariants` regex patterns trivially evaded | Remediated for CommandBase adjacent surface | Receipt-chain mutation detection now tokenizes output and catches normal `UPDATE governance_receipts SET receipt_hash = ...` wording rather than the previous literal `update.*receipt_hash` substring. |

This remediation does not claim EXOCHAIN core constitutional enforcement for
CommandBase. CommandBase-local heuristic checks remain adjacent audit signals.

## Red-Green Evidence

Red command:

```bash
node --test command-base/app/services/governance.test.js
```

Observed failures before the fix:

- `validateAgainstInvariants blocks receipt hash mutation without regex spelling`
  failed with `true !== false`.
- `validateAgainstInvariants does not append a governance receipt from heuristic
  output scan` failed with `1 !== 0`.

Green commands:

```bash
node --test command-base/app/services/governance.test.js
node --test command-base/app/services/governance.test.js command-base/app/lib/auth.security.test.js command-base/app/auth-bootstrap.test.js
npm --prefix command-base/app audit --audit-level=high
bash tools/test_repo_truth.sh
cargo fmt --all -- --check
git diff --check
```

All green commands completed with exit code 0. The combined CommandBase auth
test required local socket binding outside the sandbox; the sandboxed attempt
failed with `listen EPERM: operation not permitted 0.0.0.0`, and the approved
rerun passed.
