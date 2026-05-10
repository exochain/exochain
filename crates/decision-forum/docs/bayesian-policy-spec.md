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

# Formal Council Policy Spec: Advanced Neuro-Symbolic Governance

## 1. Core Doctrine
**"Trust (not latency) is the accelerator."**
The Exochain decision council relies on a multi-layered governance model ensuring that mathematical rigor and symbolic constitutional law are never superseded by probabilistic heuristics.

## 2. Architecture: The Tri-Layered Model
This policy enforces a balanced approach consisting of three distinct layers:
1. **Constitutional Inside (Symbolic Layer):** hard rules, TNCs, authority validations, quorum limits, ratification.
2. **Epistemic Engine (Bayesian Layer):** risk modeling, forecasting, evidence weighting, uncertainty measurement.
3. **Advisory Speed Layer (Neural Distillate):** optional proposal assistance trained on teacher-verified data.

## 3. Mandatory Requirements for Advanced Mode Claims
Every advanced-mode decision must carry:
- **Prior**
- **Evidence references** (URI or reproducible hash)
- **Posterior + confidence interval**
- **Symbolic rule trace hash**
- **Teacher/student disagreement score**
- **Human review status**
- **Policy version / threshold profile**

## 4. Hard Escalation and Abstention Thresholds (The Verifier Gate)
The current constitutional threshold profile is:
- **Minimum confidence interval:** `0.85`
- **Maximum sensitivity instability:** `0.10`
- **Maximum teacher/student disagreement:** `0.05`
- **Trace hash format:** 64 hex chars, optionally prefixed with `0x` or `sha256:`
- **Evidence references:** at least one entry, each either `http://`, `https://`, or a valid hash reference

If any of the above fail, `decision.forum` MUST reject or escalate the decision before approval.

## 5. Human Governance Requirements
- Advanced reasoning does **not** replace symbolic verification.
- Advanced reasoning does **not** replace human review.
- Policy and sovereignty decisions require explicit ratification before terminal approval.
- Humans must retain majority control over AI participants.

## 6. Recursive Fine-Tuning Constraints
Recursive supervised fine-tuning (SFT) is restricted to **teacher-verified, council-ratified** examples.

Important: this restriction is a **process/governance control**, not a runtime training-enforcement mechanism inside `decision.forum` itself.

## 7. Auditability
Every failed verifier-gate or TNC enforcement path must leave a structured audit event containing:
- timestamp
- event type
- reason
- escalation reason where applicable
- assessment snapshot where applicable

## 8. Documentation Integrity
Generated reports must not assert legal/evidentiary compliance unless the crate actually enforces it. Where full legal validation is out of scope, outputs must explicitly say review is still required.
