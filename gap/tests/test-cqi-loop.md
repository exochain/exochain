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

# Test Spec: CQI Self-Improvement Loop

## Description
E2E verification of the `cqi-self-improvement.yaml` Syntaxis protocol. Simulates the Self-Development team detecting an issue and patching the system.

## Test Steps
1. **Initialize**: Mock an `event: threshold_alert` trigger representing a high latency bottleneck in the `artifact-builder` agent.
2. **Execute `collect-metrics`**: Inject mock DAG logs showing the latency.
3. **Execute `analyze-degradation`**: Verify the CQI Lead agent generates an `improvement_hypothesis`.
4. **Execute `generate-proposal`**: Verify the generation of a `syntaxis_patch_proposal`.
5. **Execute `internal-council-review`**: Inject 5/5 "Approve" votes (T2 operations require unanimity).
6. **Execute `exoforge-dispatch`**: **Mock this external call.** Return a dummy compiled artifact.
7. **Execute `verify-improvement`**: Inject a mock "Pass" result from the test suite.
8. **Execute `deploy-and-record`**: Verify the ledger anchoring.

## Expected Outputs
- The system must require a unanimous 5/5 council vote for this T2 protocol patch. (Test should fail if an injected 4/5 vote is accepted).
- The `exoforge_compiled_artifact` must be processed without throwing a type error.
- The final state must reach `Closed`.

## Pass Criteria
The full CQI lifecycle executes, enforcing the higher consensus threshold required for system modifications, and correctly records the patch to the DAG.