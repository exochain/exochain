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

# Gauntlet Agent Workflow Validation - 2026-05-15

This record validates Gauntlet agent-prompt, workflow-loop, and autonomous
dispatch findings against current `main`. The source artifacts remain imported
evidence only:

- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-findings.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-deep-analysis.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/da-findings.tsv`

Validation target:

- branch: `main`
- commit: `9c754477aad4937fcadd4feb85a7aa03b4137c54`

## Path Classification

| Path family | Classification | Notes |
| --- | --- | --- |
| `AGENTS.md` | EXOCHAIN core | Repository-wide AI agent safety and workflow intake contract. |
| `.archon/commands/`, `.archon/workflows/` | Core runtime adapter | Agent command/workflow prompts that can influence EXOCHAIN implementation paths. |
| `.github/workflows/exoforge-triage.yml` | Core runtime adapter | GitHub issue-to-ExoForge ingestion boundary. |
| `tools/test_agent_*`, `tools/test_github_issue_workflow_boundaries.sh`, `tools/test_syntaxis_workflow_input_boundary.sh` | EXOCHAIN core | CI source guards for agent prompt and workflow boundaries. |
| `tools/syntaxis/` | EXOCHAIN core | Workflow code generator and input-validation tests. |
| `exoforge/` | Core runtime adapter | Governed implementation/triage tooling around the trust fabric. |
| `command-base/` | Adjacent surface | Agent fleet and application shell; not canonical EXOCHAIN core. |
| `/private/tmp/exochain-gauntlet-findings/...` | Imported evidence | Read-only external assessment artifacts. |

## Dispositions

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-158 MCP prompt injection | Already validated separately | Covered by `GAUNTLET-AUTHZ-MCP-VALIDATION-2026-05-15.md`: MCP prompt templates use bounded `BEGIN_UNTRUSTED_USER_ARGUMENTS` markers. |
| F-159 Archon raw `$ARGUMENTS` in LLM prompt | Stale / already remediated | `.archon/commands/*.md` place `$ARGUMENTS` on its own line inside `BEGIN_UNTRUSTED_USER_ARGUMENTS` / `END_UNTRUSTED_USER_ARGUMENTS`, with explicit untrusted-data instructions. `tools/test_agent_prompt_boundaries.sh` enforces this. |
| F-160 self-improvement cycle has no iteration bound | Stale / already remediated | Autonomous/self-improvement `.archon/workflows/*.yaml` files declare finite `loop.max_iterations` values no greater than 25, exit conditions, repeated-failure stop conditions, and escalation paths. `tools/test_agent_workflow_bounds.sh` is wired into CI Gate 9. |
| F-161 agent dispatch lacks per-dispatch identity | Adjacent surface guard present | The reported broad agent fleet maps to CommandBase, an adjacent surface. `tools/test_commandbase_dispatch_identity.sh` verifies CommandBase requires a per-dispatch identity assertion and explicitly does not make adjacent agents EXOCHAIN core actors. |
| F-162 hash substituted for encryption | Already validated separately | Covered by `GAUNTLET-RUNTIME-HARDENING-VALIDATION-2026-05-15.md`: MCP messaging tools fail closed until real storage, key resolution, and transport are attached. |
| F-163 zero LLM call logging | Adjacent surface / current core path not found | Current matches for LLM provider/usage logging are under `command-base/`, classified adjacent. No current EXOCHAIN core LLM execution path was found in this cluster. |
| F-164 MCP provenance timestamp hardcoded | Already validated separately | Covered by `GAUNTLET-PROOFS-OBSERVABILITY-VALIDATION-2026-05-15.md`: MCP middleware no longer fabricates a fixed timestamp. |
| F-165 `constitutional_audit` unbounded user argument | Stale / already remediated | Agent command prompts and workflow escalation prompts use the required untrusted argument and workflow-output markers; the prompt-boundary guard rejects raw interpolation. |
| F-166 adjudicator selection `ORDER BY RANDOM()` | Adjacent surface | Current `ORDER BY RANDOM()` matches are in CommandBase adjacent code. No current EXOCHAIN core or `.archon` workflow path uses random adjudicator selection. |
| F-167 governance loop termination by LLM self-assessment | Stale / bounded | Current autonomous workflows are finite, require `max_iterations`, stop on repeated failure fingerprints, and define escalation paths. The remaining completion signal is bounded by these workflow controls rather than an unbounded recursive loop. |

## Commands Run

All commands below completed with exit code 0.

```bash
rg -n "F-15[8-9]|F-16[0-7]|BEGIN_UNTRUSTED|END_UNTRUSTED|\\$ARGUMENTS|ORDER BY RANDOM|self-improvement|loop|max_iterations|LLM call|llm" .github tools gap exoforge command-base AGENTS.md docs -g '!docs/superpowers/**' -g '!docs.zip'
bash tools/test_agent_prompt_boundaries.sh
bash tools/test_agent_workflow_bounds.sh
bash tools/test_github_issue_workflow_boundaries.sh
bash tools/test_syntaxis_workflow_input_boundary.sh
bash tools/test_commandbase_dispatch_identity.sh
```
