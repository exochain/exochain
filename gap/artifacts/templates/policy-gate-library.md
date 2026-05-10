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

# Template: Policy Gate Library

*Instructions for Artifact Builder: Translate human business rules into exact, executable conditional logic.*

## 1. Gate Categories
*Group gates by their primary function.*
- **Financial Constraints**
- **Data Privacy (PII) Checks**
- **Operational Rate Limits**

## 2. Gate Definitions
*Format: IF [condition] THEN [action] ELSE [fallback]*

### Gate: [Gate ID, e.g., FIN-01]
- **Description**: [Human readable rule, e.g., Prevent single transactions over $10,000]
- **Logic**: 
  ```yaml
  if: transaction.amount > 10000
  then: route_to_escalation(human_controller)
  else: approve_and_anchor
  ```
- **NemoClaw Deployment Notes**: [e.g., Requires integer parsing of the amount field before evaluation. Ensure currency conversion is applied.]

### Gate: [Gate ID, e.g., PRIV-01]
- **Description**: [Human readable rule, e.g., Scan outputs for SSNs before sending external email]
- **Logic**: 
  ```yaml
  if: regex_match(output_body, SSN_PATTERN) == true
  then: block_execution AND flag_security
  else: proceed_to_send
  ```
- **NemoClaw Deployment Notes**: [e.g., Use standard regex library; alert must include the agent ID attempting the send.]

---
**Approval Block**
- Prepared by: `artifact-builder`
- Council Status: `[Draft / Governed]`
- CEO Signature: `[Pending]`