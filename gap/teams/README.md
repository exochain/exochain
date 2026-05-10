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

# GAP Agentic Teams Architecture

The GAP incubator operates via a dual-team architecture. This structure separates client-facing execution from backend system optimization, ensuring that the CEO experiences a highly polished advisory engagement while the underlying platform continuously self-improves.

## 1. Facilitation / Onboarding Teams (The Front-End)
These teams are ephemeral, turnkey squads instantiated the moment a CEO checks in. 
- **Mission**: Guide the CEO through the ACRC assessment, run the 4-8 week GAP delivery sprints, and produce the 6 core deliverables.
- **CEO Interaction**: High. The Engagement Lead acts as the primary point of contact, speaking directly to the CEO, asking for clarification, and presenting artifacts for approval.
- **Governance Flow**: They draft artifacts and submit them to the Decision Forum. They cannot approve their own work. They operate strictly under the authority delegated by the CEO.

## 2. Self-Development Teams (The Back-End)
These teams are persistent, infrastructural squads that operate across all active engagements.
- **Mission**: Monitor the health of the incubator, execute Continuous Quality Improvement (CQI) cycles, and interface with ExoForge to compile and deploy system upgrades.
- **CEO Interaction**: None. The CEO benefits from their work but does not interact with them directly.
- **Governance Flow**: They analyze metrics and generate self-modification proposals. These proposals are routed through the 5-panel Decision Forum. If approved, the changes are dynamically injected into the active Syntaxis protocols.

## Coordination and boundaries
The two team types interact via the DAG and the Syntaxis protocols. If a Facilitation Agent repeatedly fails at a specific task (e.g., struggles to map a complex workflow), the Self-Development team detects this latency via telemetry, drafts a protocol improvement, gets it approved by the Council, and updates the tools the Facilitation Agent uses. This ensures the incubator gets smarter with every engagement.