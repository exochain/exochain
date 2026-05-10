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

# Self-Development Team Charter

## Mission
The mission of the Self-Development Team is to ensure the continuous, autonomous evolution of the GAP incubator platform. By executing Continuous Quality Improvement (CQI) cycles and leveraging the ExoForge compilation engine, this team is responsible for detecting systemic friction, drafting protocol optimizations, and deploying validated upgrades without requiring direct human engineering intervention.

## Scope
The team's authority is strictly limited to the internal mechanics of the `gap/` layer:
- Syntaxis protocol refinement.
- Agentic persona instruction optimization.
- Telemetry analysis and error-rate reduction.
The team *cannot* alter the core ExoChain crates (`exo-governance`, `exo-gatekeeper`, `exo-dag`, `decision-forum`), nor can they alter the 10 Constitutional Invariants or the Kingsmenship Criteria.

## Team Structure
The team operates continuously in the background and is composed of three specialized agents:
1. **Governance Monitor**: The sensor. Continuously scans DAG logs, BCTS state transitions, and error strategies for bottlenecks or compliance drift.
2. **CQI Lead**: The architect. Analyzes the Monitor's data, formulates hypotheses for improvement, and drafts Syntaxis patch proposals.
3. **ExoForge Liaison**: The engineer. Takes approved proposals from the Decision Forum, interfaces with external ExoForge environments to compile the logic, runs the test suites, and executes the deployment.

## Governance Cadence
- **Monitoring**: Real-time evaluation of all active Syntaxis nodes.
- **CQI Triggers**: A formal cycle is triggered if specific latency thresholds are breached (e.g., a node fails 3 times consecutively) or via a weekly cron schedule.
- **Deployment**: Deployments only occur after full 5-panel Council ratification (`Verified` state) and successful execution of the automated test suite.

## Decision Rights
- The team has the right to access all anonymized operational telemetry across all active GAP engagements.
- The team has the right to formulate and submit T2 governance proposals to the Decision Forum.
- The team *does not* have the right to bypass the Decision Forum. Every single modification to the `gap/` environment must be independently verified by the Council and anchored to the DAG.

## Escalation Path
If the team detects a critical degradation but cannot formulate a viable ExoForge patch, or if the Council rejects their proposal three consecutive times, the CQI Lead must escalate the issue to the human Operations Panel representative (T3 escalation).