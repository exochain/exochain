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

# Template: Workflow Control Map

*Instructions for Artifact Builder: Populate this template based on the client's ACRC intake and subsequent CEO interviews. Ensure all nodes connect logically.*

## 1. System Overview
**Client**: [Company Name]
**Scope**: [Description of the autonomous workflows being governed]

## 2. Holon Topology
*Map the discrete autonomous units (holons) and their primary functions.*

### Holon 1: [Name, e.g., Customer Intake Agent]
- **Function**: [What it does]
- **Inputs**: [Data sources]
- **Outputs**: [Where the data goes]
- **Governance Tier**: [T0 / T1 / T2]

### Holon 2: [Name, e.g., Financial Reconciliation Engine]
- **Function**: [What it does]
- **Inputs**: [Data sources]
- **Outputs**: [Where the data goes]
- **Governance Tier**: [T1 / T2 / T3]

## 3. Workflow Pipelines
*Define how data moves between holons and where the critical control boundaries exist.*

**Pipeline A: [Name, e.g., Quote to Cash]**
1. [Step 1: Holon X acts] -> 
2. [BOUNDARY: Policy Gate Y check] -> 
3. [Step 2: Holon Z acts]

## 4. Boundary Defenses
*List the macro-level defenses separating critical systems.*
- [e.g., Airgap between Financial Engine and external email sender]
- [e.g., Mandatory human review before database write]

---
**Approval Block**
- Prepared by: `artifact-builder`
- Council Status: `[Draft / Governed]`
- CEO Signature: `[Pending]`