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

# ULTRAPLAN: GAP-003 — Multi-Model AI Consensus Engine

## 1. Multi-Model Independence (Commit-Reveal Scheme)
To ensure true cryptographic separation of independent AI panelists, the engine implements a commit-reveal scheme. In a standard setup, if models simply output their position to the engine, there is no proof that one model's position wasn't influenced by another before completion. 

To solve this, the deliberation round works as follows:
1. **Commitment Phase**: Each model processes the question and generates a position. It then locally (via the client/agent on its end) computes a BLAKE3 hash of its position, `position_hash`, and submits only the hash to the engine. The engine records `submitted_at` for each hash.
2. **Reveal Phase**: Once all commitments are received, the engine signals the models to reveal their full `position_text`.
3. **Verification**: The engine hashes the revealed `position_text` and checks that it perfectly matches the `position_hash` submitted during the commitment phase. If it matches, the position is accepted. This provides a cryptographic receipt of independence.

## 2. Deliberation Rounds
A single session of deliberation consists of multiple structured rounds. The overarching flow is:
1. **Round N starts**: The engine broadcasts the current state (or initial question) to all panelists.
2. **Commit-Reveal**: Models generate positions independently and use the commit-reveal scheme to submit them.
3. **Synthesis**: A designated "Synthesizer" model (or deterministic extraction process) gathers the revealed positions and identifies key claims, points of agreement, and points of divergence.
4. **Scoring**: The engine calculates the `convergence_score_bps` for the round.
5. **Termination Check**: If the `convergence_score_bps` meets or exceeds the `convergence_threshold_bps`, or if `max_rounds` is reached, the deliberation moves to the final stage. Otherwise, the synthesis is fed back to the models for Round N+1.

## 3. Convergence Scoring
Because the engine operates under EXOCHAIN's strict requirement of no floating point arithmetic, convergence scoring is done in basis points (0–10000). The scoring uses a categorical proxy for semantic similarity.
- From each position, a list of structured `key_claims` is extracted (either by the model itself as structured output, or by the Synthesizer).
- For a given claim, the engine checks how many models included a matching (or highly semantically equivalent, mapped categorically) claim.
- The `convergence_score_bps` is essentially: `(matching_claims / total_unique_claims) * 10000`.
- Example: If the models collectively put forward 10 unique claims, and 8 of them are shared by all models, the convergence score is 8000 bps.

## 4. Devil's Advocate
If configured, a specific model is designated as the `Devil's Advocate`. Its role is strictly adversarial.
- **Trigger**: Once a tentative consensus is reached (convergence threshold met), the consensus synthesis is sent to the Devil's Advocate.
- **Task**: The advocate must find the strongest counterarguments, logical flaws, or edge cases that break the consensus.
- **Outcome**: It returns a `devil_advocate_challenge`. If the challenge is deemed "serious" (measured categorically or by a secondary vote from the panel), it negatively impacts the Panel Confidence Index.

## 5. Minority Reports
EXOCHAIN preserves dissenting perspectives to avoid forced artificial consensus.
- After convergence scoring, any model whose position significantly diverges from the synthesized consensus (e.g., convergence with the consensus synthesis is below `10000 - threshold_bps`) is marked as dissenting.
- The dissenting model is prompted to generate a formal `MinorityReport`, explicitly stating its `dissenting_position` and a list of `reasons`.
- This report is embedded directly into the final `DeliberationResult`.

## 6. Panel Confidence Index (PCI)
The `panel_confidence_index_bps` is a composite score (0–10000) that gives a single health metric for the deliberation. It is calculated using weighted basis point math:
- **Model Agreement (50% weight)**: `(models_agreeing / total_models) * 5000`
- **Speed of Convergence (30% weight)**: `( (max_rounds - rounds_to_convergence + 1) / max_rounds ) * 3000`. Faster convergence yields a higher score. If max rounds hit without convergence, this component is lower.
- **Devil's Advocate Result (20% weight)**: If the Devil's Advocate found a serious objection, this component is `0`. If it found no serious objections, it is `2000`.

## 7. Deliberation Record (EvidenceBundle)
The entire deliberation session is verifiable.
- Every `DeliberationRound` is hashed (`round_hash`) using BLAKE3. The hash includes all commitments, revealed texts, and the convergence score.
- The `DeliberationResult` is hashed (`deliberation_hash`).
- This `DeliberationResult` and its hash map directly into `crates/exo-legal/src/bundle.rs` as an `EvidenceBundle` event, providing an immutable "receipt" of the AI decision-making process.

## 8. API Design
The API is designed for deterministic execution, separation of concerns, and feature-gated LLM client support.
- The engine itself is a pure state machine where possible.
- LLM clients (Anthropic, OpenAI, Google) are hidden behind feature flags (`anthropic`, `openai`, `google`).
- A `MockLlmClient` is included by default for unit tests. It is deterministic and responds based on BLAKE3 hashes of prompts to allow completely isolated CI testing without real API keys.
- The consumer constructs a `Panel`, creates a `Session`, runs `session.execute_round(llm_client)`, checks for convergence, and then calls `session.finalize()` to get the `DeliberationResult`.
