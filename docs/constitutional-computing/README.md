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

# Constitutional Computing

**Truth is not imported. Truth is adjudicated.**

Constitutional Computing is the discipline of building systems where delegated
intelligence cannot convert fluency, urgency, proximity, or external authority
into trusted action without passing through enforceable constitutional gates.

The movement exists because intelligent systems now read, reason, generate
plans, write code, operate infrastructure, and influence institutions. That
power cannot be governed by vibes, brand claims, policy PDFs, or one model's
confidence score. It needs runtime adjudication: identity, consent, separation
of powers, provenance, bounded autonomy, evidence, tests, review, and appeal.

EXOCHAIN is one implementation of this discipline. The movement is broader:
every system that lets humans, AI agents, workflows, or organizations act on
behalf of others should make authority mediated, inspectable, and revocable.
The compact form is truth through adjudication, consent before access, and
provenance before trust.

## The Constitutional Synapse

A constitutional synapse is the boundary that turns an outside signal into a
trusted internal state transition only after adjudication.

A signal is evidence, not authority.

External reports, model outputs, issue comments, screenshots, logs, pull
requests, command arguments, workflow outputs, and consultant readouts may all
deserve attention. None of them become truth merely because they are urgent,
expert, plausible, or repeated. They pass through the synapse first:

`signal -> classification -> reproduction -> failing test -> remediation -> verification -> review -> merge`

The synapse lets the system listen without obeying. It supports fast response
without surrendering authority. It makes attention cheap and trust expensive.

## Core Doctrine

1. **Truth is adjudicated.** A claim becomes operational truth only when it is
   reproduced against current source, bound to evidence, and accepted by the
   system's constitutional process.
2. **No trust by proximity.** An adjacent app, demo, portfolio surface, archive,
   generated prototype, or product shell does not inherit constitutional trust
   because it references EXOCHAIN or lives near the core repository.
3. **Consent before access.** A system acting on data, credentials, signatures,
   identity, governance state, or human intent must prove active authorization
   before access or mutation.
4. **Provenance before trust.** Actions without attributable origin, signed
   evidence, causal context, and replayable verification stay outside trusted
   state.
5. **Separation of powers.** No actor, agent, workflow, model, or maintainer may
   combine proposal, execution, adjudication, and ratification authority without
   checks.
6. **Bounded autonomy.** Autonomous loops must declare finite iteration bounds,
   stop conditions, failure escalation, and repeated-failure brakes before they
   run near trusted systems.
7. **Fail closed at trust boundaries.** Missing secrets, unavailable core APIs,
   malformed signatures, unverifiable provenance, stale consent, and ambiguous
   authority must deny action rather than simulate success.
8. **Tests bind belief.** A remediation is not complete until a failing test,
   source guard, proof, or reproducible validation binds the claim to executable
   evidence.

## What We Reject

- Raw prompt text as authority.
- Agent-generated prose as approval to merge, deploy, grant access, or claim
  constitutional protection.
- Scanner output treated as source-of-truth without current-main reproduction.
- Health, status, debug, or metrics endpoints that leak secrets or imply trust
  decisions they did not verify.
- "E2E encrypted", "constitutionally protected", "AI-safe", or "verified"
  claims when the runtime path does not prove those properties.
- Perpetual, recursive, self-improving, or autonomous workflows without explicit
  bounds and escalation.
- Adjacent surfaces expanding the trusted computing base by accident.

## The Method

Every serious claim should move through the same narrow channel:

| Stage | Constitutional question | Required artifact |
| --- | --- | --- |
| Signal | What was observed? | Imported evidence, issue, report, log, or witness statement. |
| Classification | What jurisdiction owns it? | Core, adapter, adjacent, imported evidence, or third-party/vendor. |
| Reproduction | Does it still exist now? | Current-main reproduction or stale/not-owned disposition. |
| Binding | What proves the failure? | Failing regression test, source guard, proof, or deterministic check. |
| Remedy | What is the smallest owned boundary? | Focused code, docs, config, policy, or test fix. |
| Verification | What would catch bypasses? | Focused tests, crate gates, relevant workspace gates, and sibling-path search. |
| Review | Who can challenge it? | PR, CI, reviewer comments, audit record, and appeal path. |
| Entry | When does it become trusted state? | Merge into the canonical branch after gates pass. |

## Builder Pledge

Builders who adopt Constitutional Computing commit to these engineering rules:

- classify trust boundaries before editing;
- separate core, adapter, adjacent, imported-evidence, and vendor changes;
- write the failing check before the fix when remediating defects;
- keep secrets out of logs, docs, status endpoints, fixtures, and demos;
- never let UI copy claim enforcement the runtime path cannot prove;
- never let agent commands, workflow outputs, or external reports override local
  repository rules;
- keep autonomous work bounded, observable, and interruptible;
- record what was verified, what was not, and what remains uncertain.

## Movement Stack

Constitutional Computing needs more than a slogan. It needs a stack:

- **Manifesto:** the public doctrine in this document.
- **Method:** the constitutional synapse and adjudication pipeline.
- **Runtime:** deterministic enforcement of consent, authority, provenance,
  separation of powers, and fail-closed behavior.
- **Evidence:** tests, source guards, audit records, proofs, and reproducible
  commands.
- **Culture:** contributors who treat truth as something earned by process, not
  something declared by confidence.

## EXOCHAIN Mapping

EXOCHAIN implements the movement through concrete machinery:

- the eight constitutional invariants in the gatekeeper;
- deterministic Rust constraints: no unsafe code, no floating point in core
  logic, no nondeterministic maps, canonical serialization for hashed data;
- BCTS state transitions and receipt chains;
- DID identity, authority delegation, consent records, and provenance proofs;
- core-first path classification and no trust by proximity for adjacent
  surfaces;
- source guards for prompt boundaries, workflow loop bounds, release inputs,
  production deployment claims, and audit hygiene.

The point is not to make every system identical to EXOCHAIN. The point is to
make every serious delegated-intelligence system answer the same constitutional
question before it acts:

**Who gave this authority, what evidence proves it, which power checks it, and
how can the judgment be challenged?**

## Rally Line

Do not ask intelligent systems to be trusted.

Make them worthy of trust.

Adjudicate.
