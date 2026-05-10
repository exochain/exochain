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

# Workflow: Continuous Quality Improvement (CQI)

This document outlines the exact, step-by-step execution of the CQI loop run by the Self-Development Team. This workflow corresponds directly to the `cqi-self-improvement.yaml` Syntaxis protocol.

## Step 1: Trigger and Aggregation
1. The **Governance Monitor** detects that a specific Syntaxis node (e.g., `phase3-policy-gates`) has a 40% failure rate across recent GAP engagements.
2. The Monitor aggregates the DAG logs, error messages, and latency metrics into a `performance_telemetry` payload.
3. The Monitor triggers the CQI pipeline.

## Step 2: Analysis and Hypothesis
1. The **CQI Lead** receives the telemetry.
2. The CQI Lead analyzes the data and determines the root cause (e.g., "The prompt given to the Artifact Builder lacks explicit constraints for NemoClaw deployment notes, causing validation failures.")
3. The CQI Lead generates an `improvement_hypothesis` detailing the problem and the proposed solution.

## Step 3: Proposal Drafting
1. Based on the hypothesis, the CQI Lead drafts a `syntaxis_patch_proposal`.
2. This proposal includes the exact diff required in `templates/policy-gate-library.md` and the updated `artifact_generation` node logic.
3. The CQI Lead submits the proposal to the BCTS `Deliberated` state.

## Step 4: Decision Forum Review
1. The main pipeline pauses and invokes `council-review.yaml`.
2. The 5-panel Council evaluates the patch:
   - *Architecture*: Checks if the YAML is valid.
   - *Security*: Ensures no invariants are bypassed.
   - *Operations*: Verifies the change will reduce latency.
3. Upon aggregate approval, the proposal is signed and moves to `Governed`.

## Step 5: ExoForge Compilation
1. The **ExoForge Liaison** takes the `Governed` proposal and sends it to the ExoForge compilation engine.
2. ExoForge processes the prompt/logic updates and returns a compiled, executable artifact.

## Step 6: Verification
1. The ExoForge Liaison runs the compiled artifact against the `gap/tests/test-invariant-coverage.md` and the specific test for the Policy Gate Library.
2. If tests pass, the Liaison signs the `verification_receipt`. The state moves to `Verified`.

## Step 7: Deployment and Anchoring
1. The new template/YAML replaces the old version in the active registry.
2. The `ledger_anchor` node writes the hash of the new state to the ExoChain DAG.
3. The CQI cycle closes, and the Governance Monitor resumes baseline observation.