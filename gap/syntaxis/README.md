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

# Syntaxis in GAP

Syntaxis is the machine-readable orchestration layer of the GAP incubator. It bridges high-level executive intent and strict constitutional doctrine into executable DAG-backed workflows. Every process in the `gap/` environment—from CEO onboarding to complex artifact generation—is codified as a Syntaxis protocol.

## How It Works

Syntaxis protocols define governance pipelines as Directed Acyclic Graphs (DAGs) of discrete operational nodes. These YAML-based blueprints dictate exactly what happens, who must approve it, and how it is cryptographically recorded.

- **Node Types**: Protocols utilize a standardized library of nodes defined in `node-registry.json`. Examples include `intake`, `identity-verify`, `acrc-facilitation`, `council-brief`, and `approval-gate`.
- **BCTS Mapping**: Every transition between major node phases strictly enforces the BCTS (Belief-Choice-Truth-State) state machine. A deliverable must progress linearly: `Draft` → `Submitted` → `Deliberated` → `Governed` → `Approved`.
- **Composition Patterns**: Protocols are composable. The master `gap-engagement.yaml` protocol natively calls out to the `council-review.yaml` protocol whenever a T1+ threshold is met, pausing primary execution until the sub-protocol resolves.

## Integration with Council Review

When a Syntaxis pipeline hits a `council-brief` or `council-review` node, execution halts. The protocol packages the current state context and submits a formal proposal to the Decision Forum. The 5-panel council (Governance, Legal, Architecture, Security, Operations) must then review and cryptographically sign the resolution. Only upon a successful `Governed` state return does the main pipeline resume.

## The CEO Approval Gate

The ultimate failsafe in Syntaxis is the `ceo-report` or `approval-gate` node. By doctrine, no final artifact or high-stakes structural change can bypass this node. The CEO is presented with the compiled data, the council's recommendation, and the immutable DAG trail. The system waits indefinitely for the CEO's explicit cryptographic approval before moving the engagement to the `Executed` or `Closed` state.