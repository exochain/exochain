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

# The Decision Forum in GAP

The Decision Forum is the deliberative engine of the GAP incubator. It is where high-stakes proposals, GAP deliverables, and system upgrades are subjected to rigorous, multi-disciplinary review before they can be executed.

## What It Governs
The Forum does not micro-manage daily agentic tasks. It governs **Tier 1 (T1)** and higher proposals. In the context of the incubator, this includes:
- Finalization of any of the 6 core GAP deliverables.
- Syntaxis protocol modifications proposed by the Self-Development team.
- Major escalations or constitutional queries raised during an engagement.

## How Proposals Enter
Proposals do not enter the Forum informally. They are automatically submitted via Syntaxis protocol hooks (specifically, the `protocol_call` node invoking `council-review.yaml`). When a Facilitation Agent finishes drafting an *Authority Matrix*, the Syntaxis pipeline pauses, wraps the draft in a formal proposal, and drops it into the Forum's queue.

## The CEO Interaction
The CEO does not sit on the panels. Instead, the CEO sits *above* the Forum as the Executive Chair. 
1. The Forum deliberates and reaches a `Governed` resolution.
2. The resolution, along with the rationale from all 5 panels, is presented to the CEO.
3. The CEO reviews the Council's recommendation and provides the final cryptographic signature to move the proposal to `Approved` and `Executed`.

## DAG Anchoring
Every action in the Forum—the initial proposal, the individual panel votes, the written rationales, and the final resolution—is formatted by the AI-IRB mechanism and immutably recorded to the ExoChain DAG. This ensures complete transparency and accountability for all architectural decisions made during the engagement.