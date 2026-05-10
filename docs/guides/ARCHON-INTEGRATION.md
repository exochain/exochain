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

# ExoForge Integration Guide

## Overview

[ExoForge](https://github.com/exochain/exoforge) is the autonomous implementation engine for the ExoChain governance platform. Built on the [Archon](https://github.com/bob-stewart/remote-coding-agent) agentic coding framework (Claude Agent SDK, DAG workflow execution, Bun runtime), ExoForge establishes a **perpetual self-improvement cycle** governed by the AI-IRB council of five panels across five disciplines.

ExoForge is not a standalone tool — it is the execution arm of ExoChain's constitutional governance. Every artifact it produces must pass through the governance gate (8 constitutional invariants, 10 TNC controls) before it can be merged.

## Architecture

```
                    ┌─────────────────────────────────┐
                    │   ExoChain Configurator UI      │
                    │   (demo/web/ — React widgets)   │
                    └──────────────┬──────────────────┘
                                   │ POST /api/feedback
                                   v
                    ┌─────────────────────────────────┐
                    │   Gateway API (Node.js + WASM)   │
                    │   Feedback ingestion + hashing   │
                    └──────────────┬──────────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         │                         │                         │
         v                         v                         v
   GitHub Issues            Widget Feedback           Client Onboarding
   (exoforge:triage)        (AI help menus)           (PRD generation)
         │                         │                         │
         └─────────────────────────┼─────────────────────────┘
                                   │
                                   v
                    ┌─────────────────────────────────┐
                    │   ExoForge Triage               │
                    │   exochain-investigate-feedback  │
                    │   (severity, impact, invariants) │
                    └──────────────┬──────────────────┘
                                   │
                                   v
                    ┌─────────────────────────────────┐
                    │   AI-IRB Council Review          │
                    │   5 panels × 5 disciplines      │
                    │   exochain-council-review        │
                    └──────────────┬──────────────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
                    v              v              v
               Approved       Rejected       Deferred
                    │              │              │
                    v              │              v
            ┌──────────────┐      │       Backlog (re-evaluate)
            │ Syntaxis Gen │      │
            │ + Implement  │      v
            └──────┬───────┘  Feedback to UI
                   │
                   v
            ┌──────────────────────────────────┐
            │   Constitutional Validation      │
            │   8 invariants + 10 TNCs         │
            │   exochain-validate-constitution │
            └──────────┬───────────────────────┘
                       │
              ┌────────┼────────┐
              v                 v
           PASS              FAIL
              │                 │
              v                 v
         PR Created        Remediation → Re-validate
              │
              v
         Merge → Deploy
```

## Setup

### Prerequisites

- [Bun](https://bun.sh/) runtime (v1.0+)
- Claude API key with agent permissions
- Git access to `exochain/exochain` (target repo) and `exochain/exoforge`

### Installation

```bash
# Clone ExoForge
git clone https://github.com/exochain/exoforge.git
cd exoforge

# Install dependencies
bun install

# Configure environment
cp .env.example .env
```

Edit `.env`:

```env
ANTHROPIC_API_KEY=<your-claude-api-key>
TARGET_REPO=exochain/exochain
GITHUB_TOKEN=<github-pat-with-repo-scope>
EXOCHAIN_GATEWAY_URL=http://localhost:3000
```

### Verify Installation

```bash
# List available ExoChain commands
archon commands list --filter exochain

# List available workflows
archon workflows list --filter exochain
```

## Commands

ExoForge provides 7 ExoChain-specific commands in `.archon/commands/exochain/`:

| Command | Description |
|---------|-------------|
| `exochain-investigate-feedback` | Triage UI feedback or GitHub issues into structured backlog items with severity, impact, affected invariants, and required council panels |
| `exochain-council-review` | AI-IRB five-panel review producing structured voting output with approve/reject/defer/amend per panel |
| `exochain-generate-syntaxis` | Generate Syntaxis governance workflows from 23 node types (gates, transforms, validators, etc.) |
| `exochain-generate-prd` | Client onboarding PRD generation with requirements, acceptance criteria, and governance constraints |
| `exochain-implement-feature` | Full-stack implementation across Rust crates, WASM bindings, Node.js services, React widgets, and SQL migrations |
| `exochain-fix-bug` | Root cause analysis and fix with regression tests and invariant verification |
| `exochain-validate-constitution` | Governance gate enforcing all 8 constitutional invariants, 10 TNC controls, BCTS integrity, architectural compliance, and security posture |

## Workflows

Four DAG workflows in `.archon/workflows/exochain/`:

### Self-Improvement Cycle (`exochain-self-improvement-cycle.yaml`)

The primary feedback-to-PR pipeline:

```
ingest → council-review → generate-syntaxis → implement → validate → create-pr
                │
                ├── rejected → close with feedback
                └── amended → re-investigate with conditions
```

```bash
archon workflow run exochain-self-improvement-cycle \
  '{"feedback": "BCTS widget should show real-time transitions", "widget": "bcts-machine", "page": "dashboard"}'
```

### Client Onboarding (`exochain-client-onboarding.yaml`)

From client requirements to deployed, governed configuration:

```
generate-prd → council-review → generate-workflows → implement → validate → create-pr
```

```bash
archon workflow run exochain-client-onboarding \
  '{"client": "ACME Corp", "requirements": "Need identity verification with GDPR consent..."}'
```

### Issue Fix (`exochain-fix-issue-dag.yaml`)

GitHub issue to governed PR:

```
investigate → council-review → fix → validate → create-pr
```

```bash
archon workflow run exochain-fix-issue-dag '#42'
```

### Continuous Governance (`exochain-continuous-governance.yaml`)

Perpetual monitoring loop (max 25 iterations) scanning for:
- Constitutional drift (invariant degradation over time)
- Governance gaps (unreviewed code paths)
- Compliance drift (regulatory changes affecting data handling)

```bash
archon workflow run exochain-continuous-governance
```

## Five-by-Five Discipline Matrix

Every artifact ExoForge produces is reviewed across 5 council panels and 5 properties:

|  | Storable | Diffable | Transferable | Auditable | Contestable |
|--|----------|----------|--------------|-----------|-------------|
| **Governance** | Resolution serialized | Version-tracked | Authority chain | HLC timestamps | Challenge mechanism |
| **Legal** | Court-admissible format | Evidence diff | Jurisdiction transfer | Provenance chain | Contestation period |
| **Architecture** | CBOR canonical | Merkle root | DID-based routing | Receipt chain | State rollback |
| **Security** | Encrypted at rest | Tamper-evident | Delegation-scoped | Invariant log | Escalation path |
| **Operations** | Backup-ready | Rollback-safe | Multi-tenant | Health metrics | Incident response |

## Constitutional Invariants (Governance Gate)

Every ExoForge-generated PR must pass validation against all 8 invariants:

1. **DemocraticLegitimacy** — Democratic mandate preserved; changes authorized by council vote
2. **DelegationGovernance** — Chain-of-custody intact; authority properly delegated
3. **DualControl** — Critical paths require 2+ independent actors
4. **HumanOversight** — AI-generated changes have human escalation and review
5. **TransparencyAccountability** — Full audit trail from feedback to PR
6. **ConflictAdjudication** — Conflicts of interest surfaced and handled
7. **TechnologicalHumility** — Graceful degradation; no single points of failure
8. **ExistentialSafeguard** — No casual constitutional change; supermajority required

## Trust-Critical Non-Negotiable Controls (TNCs)

10 controls that cannot be bypassed:

1. Authority chain validation
2. Human gate for critical operations
3. Consent verification before data access
4. Quorum threshold enforcement
5. Audit completeness guarantee
6. Provenance chain integrity
7. Separation of concerns enforcement
8. Immutability of finalized records
9. Cryptographic signature verification
10. Constitutional amendment supermajority

## GitHub Issues Integration

ExoForge automatically picks up GitHub issues labeled `exoforge:triage`:

1. **Create an issue** using the Bug Report or Feature Request template at [exochain/exochain/issues](https://github.com/exochain/exochain/issues)
2. The `exoforge-triage.yml` GitHub Action fires, posting the issue to the ExoForge ingestion endpoint
3. ExoForge enters the self-improvement cycle (triage → council → implement → validate → PR)
4. A comment is posted on the issue tracking progress

To configure the triage endpoint, set the `EXOFORGE_GATEWAY_URL` repository variable in GitHub Settings → Secrets and Variables → Actions → Variables.

## API Integration

The ExoChain gateway-api provides endpoints for the feedback loop:

```bash
# Submit feedback from widget AI help
curl -X POST http://localhost:3000/api/feedback \
  -H 'Content-Type: application/json' \
  -d '{"widget": "bcts-machine", "page": "dashboard", "type": "suggestion", "message": "Add animation"}'

# List backlog items
curl http://localhost:3000/api/backlog

# Council vote on a backlog item
curl -X POST http://localhost:3000/api/backlog/vote \
  -H 'Content-Type: application/json' \
  -d '{"id": "FB-xxx", "vote": "approve", "panel": "Architecture", "rationale": "Sound design"}'

# Update item status (after ExoForge processing)
curl -X POST http://localhost:3000/api/backlog/status \
  -H 'Content-Type: application/json' \
  -d '{"id": "FB-xxx", "status": "implementing", "exoforge_run_id": "run-123"}'
```

## Security

ExoForge operates under strict security constraints:

- **Sandboxed Execution** — All code generation runs in isolated worktrees with scoped access
- **Audit Trail** — Every action is logged to the ExoChain audit-api
- **Scoped Credentials** — Short-lived, narrowly-scoped tokens for repository access
- **No Direct Merge** — ExoForge creates PRs only; merge authority is with the governance gate
- **Reproducibility** — Every workflow execution is deterministic given the same inputs
- **Constitutional Binding** — No output can bypass the 8-invariant validation gate
