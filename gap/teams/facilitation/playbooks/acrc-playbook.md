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

# Playbook: ACRC Facilitation

This playbook guides the ACRC Facilitator agent through the execution of the Autonomous Capability Readiness Check.

## Objective
Establish an accurate, unvarnished baseline of the client's current autonomous operations across 8 core indicators.

## Facilitation Schedule
The ACRC is designed to be completed asynchronously over a 2-day period, requiring roughly 8 hours of total engagement from the CEO/client team.

## The 8 Indicators
The Facilitator must evaluate the following:
1. **Strategic Mandate**: Is the use of AI explicitly authorized and bounded by leadership?
2. **Identity & Access**: Are agentic actions cryptographically tied to human authority?
3. **Data Provenance**: Can the system prove exactly what data influenced a specific decision?
4. **Policy Enforcement**: Are constraints written in natural language (weak) or machine code (strong)?
5. **Human-in-the-Loop**: Are escalation paths defined and tested?
6. **Error Recovery**: How does the system behave when it encounters unknown states?
7. **Auditability**: Is there an immutable ledger of agent actions?
8. **Doctrinal Alignment**: Do the deployments match the organization's stated risk tolerance?

## Execution Steps

### 1. Indicator Probing
For each indicator, ask the CEO 1-2 targeted questions. 
*Example for Data Provenance:* "If your autonomous agent approves a workflow tomorrow, can you produce a cryptographically verifiable log of exactly which internal documents it referenced to make that decision?"

### 2. Evidence Request
If the CEO answers affirmatively, ask for evidence. "Please link to the schema or describe the logging mechanism."

### 3. Scoring (1-5 Scale)
- **1 (Critical Risk)**: No controls. Ad-hoc deployment. Complete black box.
- **2 (Weak)**: Informal controls. Human policies exist but are not technically enforced.
- **3 (Baseline)**: Standard API logging. Post-incident audit is possible but painful.
- **4 (Strong)**: Pre-computation checks. Clear human escalation. Good data trails.
- **5 (ExoChain Standard)**: Immutable DAG anchoring, strict cryptographic delegations, machine-enforced Syntaxis boundaries.

### 4. Compiling the Brief
Format the output using the council brief template:
- **Executive Summary**: Overall readiness tier.
- **Indicator Scores**: Matrix of the 8 scores.
- **Vulnerability Highlights**: The top 3 most dangerous operational gaps identified.

### 5. Final Output
Submit the brief to the Decision Forum for architectural validation before passing the final report to the Engagement Lead.