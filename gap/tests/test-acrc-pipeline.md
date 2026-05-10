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

# Test Spec: ACRC Pipeline

## Description
E2E verification of the `acrc-assessment.yaml` Syntaxis protocol. Simulates the intake, assessment, and scoring loop.

## Test Steps
1. **Initialize**: Mock an `event: ceo_check_in` trigger. Provide a valid `verified_identity_token`.
2. **Execute `consent-verify`**: Inject a signed `consent_receipt`.
3. **Execute `acrc-facilitation`**: Inject a pre-recorded mock transcript representing the CEO's answers to the 8 indicator questions.
4. **Execute `scoring`**: Allow the node to process the raw assessment data.
5. **Execute `council-brief`**: Monitor the sub-protocol call to `council-review.yaml`. Inject mock approvals from all 5 panels.
6. **Execute `ceo-report`**: Verify final payload generation.

## Expected Outputs
- The scoring node must output 8 integer values between 1 and 5.
- The readiness tier must map correctly based on the aggregated score.
- The protocol must successfully pause, route to the Decision Forum, and resume upon receiving the `council_resolution`.

## Pass Criteria
The pipeline reaches the `Closed` state. The generated `scored_indicators` payload must exactly match the expected schema defined in the node registry.