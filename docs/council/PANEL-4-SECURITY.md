---
title: "PANEL-4-SECURITY: Security Review of decision.forum PRD v1.1.0"
panel: Security
discipline: Threat Modeling, Anti-Sybil Architecture, Zero-Trust Design, Cryptographic Security
status: complete
date: 2026-03-18
reviewer: EXOCHAIN Council Security Panel
prd_version: 1.1.0-SUPERINTELLIGENT-PRIMARY
---
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


# SECURITY PANEL REVIEW: decision.forum PRD v1.1.0

## Scope

This review covers every security-relevant requirement in the PRD, mapped against the existing exochain crate defenses. Analysis methodology: for each requirement, we identify attack surfaces, map to defending crates and source modules, construct attack scenarios, propose hardened language, and specify adversarial test cases.

---

## TRUST-CRITICAL NON-NEGOTIABLE CONTROLS (TNC-01 through TNC-10)

### TNC-01 -- Authority Chain Verification

**Threat Assessment:** The authority chain is the single most critical trust primitive. Every action in the system derives legitimacy from an unbroken, cryptographically signed chain from constitutional root to acting entity. Compromise of any link permits unauthorized actions under the appearance of legitimate authority.

**Attack Scenarios:**
1. **Chain forgery:** Attacker constructs a plausible-looking chain with fabricated signatures, bypassing the kernel.
2. **Replay attack:** Attacker replays a valid historical authority chain for a delegation that has since expired or been revoked.
3. **Chain truncation:** Attacker presents a partial chain that omits intermediate links where scope was narrowed, effectively widening the apparent delegation.
4. **Key substitution at depth:** In chains of depth >3, attacker substitutes a compromised intermediate key that is hard to detect without full chain traversal.

**Exochain Defense:**
- `exo-gatekeeper::kernel.rs` -- `adjudicate()` calls `enforce_all()` which checks `AuthorityChainValid` invariant
- `exo-gatekeeper::invariants.rs` -- `check_authority_chain_valid()` verifies: non-empty chain, continuous link (grantee[i] == grantor[i+1]), terminal link matches actor
- `decision-forum::tnc_enforcer.rs` -- `tnc01_authority_chain()` enforces max depth (5), minimum key material length (8 chars), non-empty pubkey/signature at each link
- `exo-identity::did.rs` -- DID resolution filters revoked documents; key rotation leaves audit trail
- `exo-identity::key_management.rs` -- Key lifecycle with Active/Rotated/Revoked/Expired states prevents use of superseded keys

**Residual Risk:**
- The invariant checker validates chain topology but does not currently verify actual Ed25519 signatures on each link -- the signature field is checked for non-emptiness, not cryptographic validity. This is the highest-priority gap.
- No timestamp binding on individual chain links at the invariant level (TNC-05 handles expiry separately).
- Chain replay protection depends on external nonce/timestamp mechanisms not yet bound into the chain verification path.

**Hardened Requirement:**
> TNC-01: Every authority chain link SHALL contain: (a) grantor DID, (b) grantee DID, (c) Ed25519 or hybrid post-quantum signature verified against the grantor's active public key at chain evaluation time, (d) scope descriptor, (e) monotonic sequence number bound to the grantor's DID document. Chain verification SHALL fail if any signature is invalid, any key is revoked, any sequence number is non-monotonic, or chain depth exceeds MAX_AUTHORITY_CHAIN_DEPTH (5). Verification latency P99 < 200ms.

**Adversarial Tests:**
- `test_forged_signature_rejected`: Construct chain with valid topology but fabricated signatures; verify kernel denies.
- `test_replay_expired_chain`: Present a chain whose delegation has expired (TNC-05 cross-check); verify rejection.
- `test_truncated_chain_scope_widening`: Remove intermediate link that narrowed scope; verify scope check fails.
- `test_revoked_intermediate_key`: Rotate a mid-chain key, then present chain using the old key; verify rejection.
- `test_max_depth_exceeded`: Submit chain of depth 6; verify TNC-01 rejects.
- `test_empty_signature_rejected`: Submit chain link with non-empty pubkey but empty signature; verify rejection.

---

### TNC-02 -- Human Gate

**Threat Assessment:** The human gate is the primary defense against autonomous AI governance capture. An AI that can satisfy HUMAN_GATE_REQUIRED classifications without genuine human involvement can progressively accumulate authority until human oversight becomes ceremonial.

**Attack Scenarios:**
1. **Rubber-stamp attack:** AI pre-fills all decision content and presents it to a human who clicks "approve" without review. Technically satisfies the gate, substantively undermines it.
2. **Human impersonation:** AI forges a human DID signature or obtains a human's signing key through social engineering.
3. **Gate classification downgrade:** AI manipulates decision metadata to classify a Strategic decision as Routine, avoiding the human gate entirely.
4. **Delegation chain laundering:** AI agent creates a delegation chain through a compliant human intermediary, effectively gaining human-gated authority while the human has no understanding of what they authorized.

**Exochain Defense:**
- `exo-gatekeeper::mcp.rs` -- MCP rule 005 (Distinguishable) ensures AI output is marked; MCP rule 002 (NoSelfEscalation) blocks capability expansion
- `exo-gatekeeper::invariants.rs` -- `HumanOverride` invariant ensures human intervention capability is preserved
- `decision-forum::tnc_enforcer.rs` -- `tnc02_human_gate()` blocks Strategic/Constitutional decisions by AI signers; also checks `HumanReviewStatus.is_satisfied()` for decisions with `advanced_reasoning`

**Residual Risk:**
- No minimum engagement time or evidence-of-reading metric exists. A human can satisfy the gate in zero seconds.
- The AI/human distinction relies on `SignerType` and `is_ai` flags, which are self-declared. There is no TEE-backed attestation binding the signing device to a biometric human presence.
- Decision class downgrade is checked at TNC-09 (AI ceiling) but the classification itself could be manipulated before the TNC enforcer runs.

**Hardened Requirement:**
> TNC-02: HUMAN_GATE_REQUIRED decisions SHALL require: (a) human signer with DID NOT flagged as AI/agent, (b) minimum deliberation window of 60 seconds between information package delivery and approval, (c) cryptographic proof of information access (hash of opened attachments), (d) biometric or hardware-token attestation when available. The HUMAN_GATE_REQUIRED classification list SHALL be modifiable only via constitutional amendment (GOV-007). AI agents SHALL NOT hold original authority for any decision class above Routine.

**Adversarial Tests:**
- `test_ai_signer_strategic_blocked`: AI agent attempts to sign Strategic decision; verify TNC-02 rejection.
- `test_instant_approval_rejected`: Human approves within 1 second of package delivery; verify engagement check fails.
- `test_class_downgrade_detected`: Decision created as Routine but containing Strategic-level financial commitment; verify classification audit detects mismatch.
- `test_delegation_laundering_blocked`: AI creates delegation through human proxy who never reviewed scope; verify chain shows insufficient human engagement evidence.

---

### TNC-03 -- Audit Continuity

**Threat Assessment:** The audit chain is the evidentiary backbone. A broken audit chain means a gap in the fiduciary defense record, which is existentially threatening to the platform's legal value proposition.

**Attack Scenarios:**
1. **Audit gap injection:** Attacker deletes or corrupts intermediate audit entries, creating a gap that invalidates the hash chain.
2. **Audit rewriting:** Attacker with storage access rewrites audit entries and recomputes hashes forward.
3. **Timestamp manipulation:** Attacker backdates audit entries to make actions appear to have occurred in a different order.

**Exochain Defense:**
- `decision-forum::tnc_enforcer.rs` -- `tnc03_audit_continuity()` enforces: non-empty audit log for terminal statuses, chronological ordering, non-zero audit_sequence, non-empty prev_audit_hash
- `exo-gatekeeper::invariants.rs` -- `ProvenanceVerifiable` invariant requires signed provenance metadata on every action

**Residual Risk:**
- Audit chain integrity depends on hash chaining but there is no external anchoring (Bitcoin/Ethereum) at the TNC enforcement level. LEG-002 specifies this but it is not yet enforced as a hard gate.
- No Merkle inclusion proof for individual audit entries -- the chain is sequential, meaning verification requires O(n) traversal.

**Hardened Requirement:**
> TNC-03: Audit logs SHALL form a hash-chained append-only sequence where each entry includes: prev_hash, monotonic sequence number, RFC 3161 timestamp, and actor provenance signature. Terminal-status decisions SHALL NOT be accepted without verifiable audit chain from creation to terminal event. External timestamp anchoring (LEG-002) SHALL be mandatory, not optional.

**Adversarial Tests:**
- `test_audit_gap_detection`: Remove middle entry from audit chain; verify hash chain break detected.
- `test_audit_reorder_rejected`: Swap two audit entries; verify chronological ordering check fails.
- `test_terminal_status_without_audit_rejected`: Set status to Approved with empty audit log; verify TNC-03 blocks.

---

### TNC-04 -- Constitutional Binding (Sync Constraints)

**Threat Assessment:** Every decision must be bound to the specific constitutional version in force at creation time. Without this binding, decisions could be retroactively validated against more permissive constitutions.

**Attack Scenarios:**
1. **Constitution swap:** Attacker amends constitution to be more permissive, then retroactively claims decisions were made under the new version.
2. **Version race condition:** Two concurrent decisions reference different constitutional versions during an amendment window.

**Exochain Defense:**
- `decision-forum::tnc_enforcer.rs` -- `tnc04_sync_constraints()` verifies non-empty constitution_hash and constitution_version
- `exo-gatekeeper::kernel.rs` -- Kernel stores `constitution_hash` and `verify_kernel_integrity()` detects tampering

**Residual Risk:**
- The PRD (GOV-002) prohibits retroactive amendments "by default" but allows overrides. The override mechanism is not threat-modeled.
- Kernel integrity verification uses blake3 hash comparison but does not cryptographically sign the constitution binding.

**Hardened Requirement:**
> TNC-04: Every Decision Object SHALL embed the SHA-256 hash and semantic version of the constitutional corpus in force at `created_at`. Retroactive revalidation against a different constitution SHALL be prohibited without explicit constitutional amendment. The constitution hash SHALL be independently verifiable via the kernel's `verify_kernel_integrity()` and SHALL be signed by the constitutional root authority.

**Adversarial Tests:**
- `test_constitution_swap_rejected`: Create decision, amend constitution, attempt to revalidate under new version; verify rejection.
- `test_empty_constitution_hash_rejected`: Submit decision with empty constitution_hash; verify TNC-04 blocks.
- `test_kernel_integrity_tamper_detected`: Modify constitution bytes after kernel initialization; verify `verify_kernel_integrity()` returns false.

---

### TNC-05 -- Delegation Expiry

**Threat Assessment:** Time-bounded delegations are a critical containment mechanism. If expired delegations are accepted, the temporal scope limitation is meaningless.

**Attack Scenarios:**
1. **Clock skew exploitation:** Attacker manipulates system clock to make expired delegations appear valid.
2. **Grace period abuse:** Delegation used in the final seconds before expiry for a long-running action that completes after expiry.

**Exochain Defense:**
- `decision-forum::tnc_enforcer.rs` -- `tnc05_delegation_expiry()` compares `expires_at` against `created_at` (decision timestamp), not system clock
- GOV-004 mandates max 12-month standing authority with 90/60/30/14/7-day notifications

**Residual Risk:**
- Using `created_at` as the reference time is better than system clock, but `created_at` is set by the decision creator, not an authoritative time source. An attacker could backdate `created_at`.
- No enforcement that delegation expiry must include a renewal ceremony -- it could be auto-renewed by a script.

**Hardened Requirement:**
> TNC-05: Delegation expiry SHALL be evaluated against an RFC 3161 timestamp from a trusted TSA, not the decision object's self-reported `created_at`. Delegations within 24 hours of expiry SHALL trigger mandatory warning to all stakeholders. Renewal SHALL require affirmative human action (not auto-renewal).

**Adversarial Tests:**
- `test_expired_delegation_rejected`: Submit decision with delegation expired 1 second ago; verify rejection.
- `test_backdated_created_at_detected`: Submit decision with `created_at` set 2 hours in the past to exploit nearly-expired delegation; verify TSA timestamp check catches discrepancy.
- `test_auto_renewal_blocked`: Attempt programmatic renewal without human attestation; verify rejection.

---

### TNC-06 -- Conflict Disclosure

**Threat Assessment:** Undisclosed conflicts of interest are the primary vector for duty-of-loyalty breaches. The system must make disclosure the path of least resistance and non-disclosure the path of highest risk.

**Attack Scenarios:**
1. **Strategic omission:** Actor aware of conflict deliberately marks "no conflict" and faces no consequence until post-hoc review.
2. **Disclosure flooding:** Actor discloses trivial conflicts to create noise that obscures material ones.

**Exochain Defense:**
- `decision-forum::tnc_enforcer.rs` -- `tnc06_conflict_disclosure()` requires disclosure for Operational/Strategic/Constitutional decisions; also validates that conflicts declared as `has_conflict: true` include descriptions
- `exo-governance::challenge.rs` -- `ChallengeGround::UndisclosedConflict` allows stakeholders to challenge decisions where conflicts were not disclosed

**Residual Risk:**
- Disclosure is self-reported. There is no automated conflict detection (e.g., cross-referencing financial interests with decision subject matter).
- No penalty enforcement in the current codebase -- the challenge mechanism exists but the consequences of sustained undisclosed-conflict challenges are not codified.

**Hardened Requirement:**
> TNC-06: Conflict disclosure SHALL be mandatory for all decision classes above Routine. The system SHALL cross-reference the Standing Conflict Register (LEG-005) and auto-populate known conflicts. False negative disclosure (undisclosed conflict later discovered) SHALL automatically trigger GOV-012 accountability proceedings and retroactive decision review.

**Adversarial Tests:**
- `test_no_disclosure_operational_rejected`: Submit Operational decision with empty conflicts_disclosed; verify TNC-06 blocks.
- `test_declared_conflict_without_description_rejected`: Submit disclosure with `has_conflict: true` but no description; verify rejection.
- `test_challenge_undisclosed_conflict`: File challenge on ground UndisclosedConflict; verify decision paused.

---

### TNC-07 -- Quorum Integrity

**Threat Assessment:** Quorum is the democratic legitimacy mechanism. Sybil attacks, vote buying, and coordinated timing attacks all target quorum integrity.

**Attack Scenarios:**
1. **Sybil quorum stuffing:** Attacker uses multiple DIDs to reach quorum threshold with fake independence.
2. **Duplicate signer:** Same entity signs under the same DID twice, inflating vote count.
3. **Coerced quorum:** Entity with authority over multiple actors compels them to vote as a bloc.

**Exochain Defense:**
- `decision-forum::tnc_enforcer.rs` -- `tnc07_quorum()` checks vote count vs threshold, approval percentage vs threshold, and duplicate signer detection (HashSet on pubkeys)
- `exo-governance::quorum.rs` -- `compute_quorum()` performs independence-aware counting: votes without valid `IndependenceAttestation` are not counted toward `min_independent`
- `exo-governance::crosscheck.rs` -- `verify_independence()` detects shared signing keys, shared attestation roots, shared control metadata; `detect_coordination()` flags near-simultaneous identical actions

**Residual Risk:**
- Independence attestation is self-declared (`no_common_control`, `no_coordination`, `identity_verified` are booleans). A sophisticated attacker can lie on all three.
- The coordination detection threshold of 100ms may be too coarse -- automated bots can introduce random jitter beyond this threshold.
- No graph-based independence analysis (e.g., analyzing the social/attestation graph for collusion clusters beyond pairwise comparison).

**Hardened Requirement:**
> TNC-07: Quorum SHALL require both numerical threshold AND independence threshold (as in `exo-governance::quorum.rs`). Independence attestation SHALL be verified through multi-party crosscheck, not self-declaration alone. The system SHALL employ behavioral analysis (timing, voting pattern correlation) to detect coordinated actors with a confidence threshold of 70%. Duplicate DID detection SHALL use cryptographic identity, not string comparison.

**Adversarial Tests:**
- `test_sybil_quorum_stuffing_blocked`: Submit votes from 5 DIDs sharing same signing key; verify only 1 counted as independent.
- `test_duplicate_signer_rejected`: Submit two votes with same pubkey; verify duplicate detected.
- `test_coordination_detected`: Submit votes from different DIDs within 50ms with identical action hashes; verify coordination signal raised.
- `test_independence_without_crosscheck_rejected`: Submit vote with self-declared independence but no crosscheck verification; verify not counted toward independence threshold.

---

### TNC-08 -- Immutability of Terminal Decisions

**Threat Assessment:** Once a decision reaches terminal status (Approved/Rejected/Void), its evidentiary record must be immutable. Any modification post-terminal invalidates the fiduciary defense package.

**Attack Scenarios:**
1. **Post-approval evidence tampering:** Attacker modifies evidence records after approval to retroactively change the decision basis.
2. **Merkle root substitution:** Attacker recomputes Merkle root with modified evidence and substitutes it.

**Exochain Defense:**
- `decision-forum::tnc_enforcer.rs` -- `tnc08_immutability()` requires non-empty merkle_root and at least one evidence record for terminal statuses
- `exo-gatekeeper::invariants.rs` -- `KernelImmutability` invariant prevents modification of kernel configuration

**Residual Risk:**
- Merkle root is checked for non-emptiness, not verified against actual evidence hashes. A fabricated root would pass.
- No external Merkle root anchoring at the TNC level (LEG-002 blockchain anchoring is specified but not enforced as a hard gate).

**Hardened Requirement:**
> TNC-08: Terminal decisions SHALL have a Merkle root computed from all evidence hashes, and this root SHALL be verifiable against the actual evidence set. The Merkle root SHALL be anchored to at least two external timestamp authorities (RFC 3161) and one blockchain (LEG-002). Post-terminal modification of any field other than metadata annotations SHALL be cryptographically impossible.

**Adversarial Tests:**
- `test_terminal_without_merkle_root_rejected`: Set status to Approved with empty merkle_root; verify rejection.
- `test_terminal_without_evidence_rejected`: Set status to Approved with empty evidence; verify rejection.
- `test_post_terminal_modification_blocked`: Attempt to modify evidence after Approved status; verify immutability enforcement.
- `test_merkle_root_evidence_mismatch_detected`: Submit decision with merkle_root that does not match evidence hashes; verify verification failure.

---

### TNC-09 -- AI Ceiling

**Threat Assessment:** The AI ceiling prevents autonomous agents from accumulating authority beyond their designated level. This is the primary containment against AI governance capture.

**Attack Scenarios:**
1. **Ceiling declaration spoofing:** AI agent declares a higher ceiling_class than actually authorized.
2. **Gradual elevation:** AI operates at ceiling for extended period, then requests ceiling raise citing track record.
3. **Multi-agent collusion:** Multiple AI agents at Routine ceiling collaborate to achieve Strategic-level outcomes through coordinated Routine actions.

**Exochain Defense:**
- `decision-forum::tnc_enforcer.rs` -- `tnc09_ai_ceiling()` checks: (a) decision_class does not exceed ceiling_class for AI signers, (b) AI signer ratio does not exceed MAX_AI_SIGNER_RATIO (0.49)
- `exo-gatekeeper::mcp.rs` -- MCP rule 001 (BCTS scope) confines AI to declared scope; MCP rule 002 blocks self-escalation

**Residual Risk:**
- The ceiling_class is carried in the `SignerType::AiAgent` enum, which is set by the caller, not verified against a delegation registry. An AI agent could self-declare a higher ceiling.
- The 49% AI signer ratio is a strong control but does not account for the influence disparity (an AI might draft the decision content while humans merely rubber-stamp).
- Multi-agent coordination at sub-ceiling levels is not detected.

**Hardened Requirement:**
> TNC-09: AI ceiling_class SHALL be derived from the delegation chain, not self-declared. The ceiling SHALL be cryptographically bound to the delegation record with the delegator's signature. AI agents SHALL NOT sign more than 49% of authority chain links. The system SHALL detect and flag coordinated multi-agent action patterns that achieve effective authority beyond individual ceilings. AI delegation SHALL have a maximum duration of 90 days (GOV-007).

**Adversarial Tests:**
- `test_ai_exceeds_ceiling_rejected`: AI with Operational ceiling attempts Strategic decision; verify rejection.
- `test_ai_ratio_exceeded_rejected`: Authority chain with 3 AI and 2 human signers (60% AI); verify rejection.
- `test_self_declared_ceiling_ignored`: AI agent sets own ceiling to Constitutional; verify system uses delegation-derived ceiling.
- `test_multi_agent_coordination_detected`: 3 AI agents simultaneously submit Routine decisions that collectively implement a Strategic outcome; verify detection signal raised.

---

### TNC-10 -- Ratification

**Threat Assessment:** Emergency and policy decisions require retrospective ratification to maintain democratic legitimacy. If ratification deadlines pass without consequence, the emergency protocol becomes a permanent bypass.

**Attack Scenarios:**
1. **Perpetual emergency:** Actor invokes emergency protocol repeatedly to avoid normal governance, counting on ratification deadlines being missed without consequence.
2. **Ratification rubber-stamp:** Ratification happens automatically without genuine review.

**Exochain Defense:**
- `decision-forum::tnc_enforcer.rs` -- `tnc10_ratification()` requires: ratification for Policy/Sovereignty decisions; future deadline when ratification is required
- GOV-009 specifies 7-day ratification window and frequency tracking (>3/quarter triggers governance review)

**Residual Risk:**
- No enforcement of consequences when ratification deadline passes -- the decision may simply remain in effect.
- Frequency tracking (>3/quarter) is specified in GOV-009 but not enforced by the TNC enforcer.

**Hardened Requirement:**
> TNC-10: Ratification-required decisions SHALL auto-void if ratification deadline passes without affirmative ratification. Ratification SHALL require the same quorum as the original decision class. Emergency invocations exceeding 3/quarter SHALL automatically trigger constitutional review and temporary suspension of emergency authority for the invoking actor.

**Adversarial Tests:**
- `test_ratification_deadline_passed_auto_void`: Allow ratification deadline to expire; verify decision status transitions to Void.
- `test_ratification_without_deadline_rejected`: Set requires_ratification=true with no deadline; verify rejection.
- `test_emergency_frequency_triggers_review`: Invoke emergency protocol 4 times in one quarter; verify governance review triggered.

---

## GOVERNANCE REQUIREMENTS

### GOV-003 -- Delegated Authority Matrix

**Threat Assessment:** Delegation is the #1 attack surface in any governance system. Every delegation creates a new trust relationship that can be exploited. The delegation matrix must resist scope widening, temporal extension, unauthorized sub-delegation, and chain laundering.

**Attack Scenarios:**
1. **Scope widening through sub-delegation:** Actor A delegates "approve contracts < $10K" to B. B sub-delegates "approve contracts" (without the cap) to C.
2. **Expired delegation still honored:** Delegation expired but cached state has not been purged.
3. **Circular delegation:** A delegates to B, B delegates back to A, creating an authority loop.

**Exochain Defense:**
- `exo-gatekeeper::invariants.rs` -- `NoSelfGrant` prevents actors from expanding own permissions; `AuthorityChainValid` ensures continuous chain
- `exo-identity::key_management.rs` -- Key lifecycle prevents use of revoked/expired keys
- GOV-003 specifies: signed delegation records, auto-expiry, chain verification <2s, sub-delegation only if explicitly permitted and scope-capped

**Residual Risk:**
- No scope intersection check in the current invariant engine -- a sub-delegation could technically widen scope if the scope descriptor is not formally verified.
- Circular delegation detection is not present in the chain validator.
- Delegation records are signed but the scope descriptor format is not standardized, making machine-readable scope comparison impossible without a formal scope language.

**Hardened Requirement:**
> GOV-003: Sub-delegation SHALL compute scope as the intersection of parent delegation scope and requested sub-scope. Scope SHALL be expressed in a machine-readable format (e.g., RBAC permission sets). Circular delegation SHALL be detected via cycle detection on the delegation graph. All delegation records SHALL be Ed25519-signed by the delegator and include: scope, duration, sub-delegation permission (boolean), monetary cap, and decision class ceiling.

**Adversarial Tests:**
- `test_scope_widening_through_subdelegation_blocked`: A delegates scope X to B, B sub-delegates scope X+Y to C; verify C's effective scope is X only.
- `test_circular_delegation_detected`: A->B->A delegation cycle; verify cycle detection rejects.
- `test_expired_delegation_cached_state_rejected`: Expire delegation, verify it is not honored from cache.

---

### GOV-005 -- Authority Chain Verification

**Threat Assessment:** Every state change requires synchronous chain verification. The attack surface is the verification itself: if it can be bypassed, slowed to timeout, or spoofed, the entire system's integrity falls.

**Attack Scenarios:**
1. **Verification timeout exploitation:** Attacker constructs a chain that takes >2s to verify, causing the system to fail-open.
2. **MITM on verification:** Attacker intercepts verification request and returns a forged "valid" response.
3. **Offline verifier forgery:** The portable offline verifier tool produces a valid-looking verification against a forged chain.

**Exochain Defense:**
- `exo-gatekeeper::kernel.rs` -- Adjudication is synchronous and in-process (no network call to intercept)
- P99 <200ms target (PRD section 1) ensures verification is fast enough to not require timeouts

**Residual Risk:**
- The offline verifier tool is specified but not yet implemented. Its trust model is undefined -- it must carry its own copy of the constitutional root, which could be stale or tampered.
- No specification for what happens on verification timeout -- fail-open would be catastrophic.

**Hardened Requirement:**
> GOV-005: Chain verification SHALL be synchronous, in-process, and SHALL NOT depend on network calls. Verification timeout SHALL result in DENY (fail-closed), never PERMIT. The offline verifier SHALL carry a signed snapshot of the constitutional root and SHALL refuse to verify against roots older than a configurable maximum age. Chain verification SHALL complete in P99 <200ms for chains up to depth 5.

**Adversarial Tests:**
- `test_verification_timeout_denies`: Inject artificial delay into chain verification; verify system denies rather than permits.
- `test_offline_verifier_stale_root_rejected`: Use offline verifier with constitutional root from 30 days ago; verify rejection.
- `test_in_process_verification_no_network`: Verify that adjudication path makes zero network calls.

---

### GOV-007 -- AI Oversight (Human Gates)

**Threat Assessment:** This is the governance-level companion to TNC-02 and TNC-09. It defines the boundary conditions for AI participation in governance.

**Attack Scenarios:**
1. **AI privilege escalation via model upgrade:** New model version claims capabilities that justify expanded authority without going through constitutional amendment.
2. **HUMAN_GATE_REQUIRED list manipulation:** Actor downgrades a decision class to remove it from the gate-required list.

**Exochain Defense:**
- `exo-gatekeeper::mcp.rs` -- All 6 MCP rules enforce AI boundaries
- `decision-forum::tnc_enforcer.rs` -- TNC-02 (human gate) and TNC-09 (AI ceiling) provide enforcement
- GOV-013 requires model upgrades to be Decision Objects under the same governance rules

**Residual Risk:**
- MCP rules rely on the `is_ai` flag being accurately set. There is no hardware attestation mechanism to prove an action originated from an AI rather than a human.
- The 90-day max AI delegation (GOV-007) is specified but not enforced by TNC-05's expiry check (TNC-05 checks delegation expiry generically, not AI-specific 90-day max).

**Hardened Requirement:**
> GOV-007: AI signatures SHALL be cryptographically distinct (different key type or key prefix) so that AI origin is unforgeable. AI delegation maximum of 90 days SHALL be enforced by TNC-05 with an AI-specific sub-check. Model upgrades SHALL be treated as GOV-013 Decision Objects requiring the same quorum as constitutional amendments. The HUMAN_GATE_REQUIRED list SHALL be stored as part of the constitutional corpus and modification SHALL require supermajority quorum.

**Adversarial Tests:**
- `test_ai_signature_distinguishable`: Verify AI and human signatures use different key schemes and cannot be confused.
- `test_ai_delegation_91_days_rejected`: Create AI delegation with 91-day duration; verify rejection.
- `test_model_upgrade_requires_constitutional_quorum`: Attempt model upgrade without quorum; verify blocked.
- `test_gate_list_modification_requires_amendment`: Attempt to modify HUMAN_GATE_REQUIRED without constitutional amendment process; verify blocked.

---

### GOV-009 -- Emergency Protocol

**Threat Assessment:** Emergency protocols are the most dangerous governance feature because they intentionally bypass normal safeguards. Every emergency mechanism is a potential permanent bypass if not tightly constrained.

**Attack Scenarios:**
1. **Permanent emergency:** Attacker declares rolling emergencies to operate indefinitely outside normal governance.
2. **Scope creep:** Emergency declared for narrow purpose but used to take broad action.
3. **Emergency authority hoarding:** Actor accumulates emergency powers and does not surrender them after resolution.

**Exochain Defense:**
- GOV-009 specifies: limited scope, monetary caps, auto-creates RATIFICATION_REQUIRED follow-up, 7-day ratification window, frequency tracking (>3/quarter triggers review)
- `exo-governance::challenge.rs` -- Emergency decisions can be challenged
- `decision-forum::tnc_enforcer.rs` -- TNC-10 requires ratification for policy decisions

**Residual Risk:**
- No per-actor emergency invocation limit -- the >3/quarter threshold is global, not per-actor.
- Scope limitation is specified but no enforcement mechanism exists to prevent scope creep within a declared emergency.
- Emergency authority does not have a hard time-to-live at the enforcement level.

**Hardened Requirement:**
> GOV-009: Emergency authority SHALL have a hard TTL of 72 hours, non-renewable except by normal governance process. Per-actor emergency invocation SHALL be limited to 1/quarter. Emergency scope SHALL be machine-readable and enforced: actions outside declared scope SHALL be rejected even under emergency authority. Emergency decisions SHALL auto-void if not ratified within 7 days. All emergency actions SHALL generate elevated audit logging with mandatory independent review.

**Adversarial Tests:**
- `test_emergency_ttl_72h_expires`: Declare emergency, attempt action at 73 hours; verify rejected.
- `test_per_actor_emergency_limit`: Same actor declares second emergency in same quarter; verify rejected.
- `test_emergency_scope_enforced`: Declare emergency for "financial operations", attempt personnel action; verify rejected.
- `test_unratified_emergency_auto_voids`: Allow 7-day ratification window to expire; verify decision auto-voids.

---

## ARCHITECTURE REQUIREMENTS

### ARCH-002 -- Global Proof Layer (ZK-SNARK + ZK-STARK)

**Threat Assessment:** The ZK proof layer provides cryptographic integrity for the entire system. Soundness attacks against the proof system would allow forged proofs of compliance.

**Attack Scenarios:**
1. **Soundness attack:** Attacker finds a way to generate a valid proof for an invalid statement.
2. **Trusted setup compromise (SNARKs):** The SNARK trusted setup ceremony is compromised, allowing universal proof forgery.
3. **Proof grinding:** Attacker brute-forces proof generation for edge cases where the circuit has weak constraints.

**Exochain Defense:**
- `exo-proofs::snark.rs`, `exo-proofs::stark.rs` -- Dual proof system (SNARKs for efficiency, STARKs for quantum resistance)
- `exo-proofs::zkml.rs` -- zkML verification for AI inference provenance with model commitment hashing
- `exo-proofs::verifier.rs` -- Centralized verification interface

**Residual Risk:**
- The SNARK trusted setup is a single point of failure. If compromised, all SNARK proofs are worthless.
- zkML proofs verify model commitment but do not verify model quality or alignment -- a committed model that is biased still produces valid proofs.
- Batch proofs every 1K events create a window where individual events are unproven.

**Hardened Requirement:**
> ARCH-002: The system SHALL use STARKs (transparent setup) for all long-term proofs and SHALL use SNARKs only for ephemeral performance-critical proofs where the trusted setup ceremony has been independently audited. zkML proofs SHALL include model version, training data hash, and alignment assessment hash. Batch proof window SHALL not exceed 1K events or 60 seconds, whichever comes first. Individual event proofs SHALL be available on-demand within the batch window.

**Adversarial Tests:**
- `test_invalid_proof_rejected`: Submit proof generated for wrong statement; verify verifier rejects.
- `test_zkml_model_mismatch_detected`: Submit inference proof with model commitment that does not match registered model; verify rejection.
- `test_stark_quantum_resistant`: Verify STARK proofs use no algorithms vulnerable to Shor's or Grover's.

---

### ARCH-007 -- Zero-Trust Multi-Tenant

**Threat Assessment:** Multi-tenancy is the primary isolation boundary. A tenant breach that allows lateral movement to other tenants is a catastrophic security failure.

**Attack Scenarios:**
1. **Lateral movement:** Attacker compromises one tenant and uses shared infrastructure to access another.
2. **Enclave escape:** Attacker breaks out of the confidential computing enclave.
3. **Side-channel attacks:** Attacker in adjacent enclave extracts keys through cache timing or power analysis.
4. **Shared service exploitation:** Attacker exploits a shared service (e.g., cold storage, proof verifier) to inject data into another tenant's namespace.

**Exochain Defense:**
- `exo-gatekeeper::tee.rs` -- TEE attestation with platform verification (SGX, TrustZone, SEV), measurement hash binding, signature verification, age checking
- `exo-gatekeeper::holon.rs` -- Agent sandboxing with per-step kernel adjudication; denied actions terminate the holon
- ARCH-005 specifies hash-based tenant sharding with 3x geo-replication

**Residual Risk:**
- TEE attestation currently uses a deterministic blake3-based signature for testing, not actual hardware attestation in production. The `TeePlatform::Simulated` variant must not be accepted in production.
- No tenant namespace isolation at the storage layer is enforced in code -- ARCH-005 specifies hash-based sharding but the implementation gap between specification and code is not verified.
- Holon sandboxing is capability-checked but does not implement memory isolation or syscall filtering.

**Hardened Requirement:**
> ARCH-007: Per-tenant isolation SHALL be enforced at all layers: (a) separate TEE enclaves (SGX/SEV) with hardware attestation (Simulated platform SHALL be rejected in production), (b) namespace-isolated storage with tenant-specific encryption keys, (c) network-level isolation (mTLS with tenant-specific certificates), (d) separate proof verification contexts. Cross-tenant data flow SHALL be impossible without explicit, audited data-sharing agreements that are themselves Decision Objects. Side-channel mitigations (constant-time crypto, cache partitioning) SHALL be mandated.

**Adversarial Tests:**
- `test_simulated_tee_rejected_in_production`: Attempt attestation with TeePlatform::Simulated in production mode; verify rejection.
- `test_cross_tenant_access_denied`: Tenant A attempts to read Tenant B's data; verify denial at every layer.
- `test_enclave_measurement_tamper_detected`: Modify enclave binary; verify attestation measurement mismatch detected.
- `test_stale_attestation_rejected`: Present attestation older than policy max_age_ms; verify rejection.

---

### ARCH-009 -- Post-Quantum Migration

**Threat Assessment:** Harvest-now-decrypt-later (HNDL) is a present-day threat against governance data with 50-year retention requirements. Authority chains signed today with Ed25519 will be forgeable once quantum computers can run Shor's algorithm.

**Attack Scenarios:**
1. **HNDL attack:** Nation-state actor records all encrypted traffic today, waits for quantum capability, decrypts 50 years of governance records.
2. **Forged historical authority chains:** Quantum attacker forges Ed25519 signatures on historical authority chains, retroactively inserting fake governance decisions.
3. **Post-quantum migration downgrade:** Attacker forces system to fall back to classical-only mode by exploiting migration bugs.

**Exochain Defense:**
- ARCH-009 specifies hybrid Ed25519 + Kyber/ML-DSA signatures
- ARCH-002 specifies STARKs for long-term quantum resistance
- `exo-proofs::stark.rs` -- STARK proofs are hash-based and quantum-resistant

**Residual Risk:**
- The current codebase uses Ed25519 exclusively. Hybrid post-quantum support is specified but not implemented.
- Historical re-anchoring strategy is specified but the migration procedure is not threat-modeled (what prevents a forged re-anchoring?).
- Kyber/ML-DSA are NIST-standardized but implementation bugs are common in early post-quantum deployments.

**Hardened Requirement:**
> ARCH-009: All new signatures SHALL use hybrid Ed25519 + ML-DSA dual signatures from day 1. Verification SHALL require both signatures to be valid (AND, not OR). Historical records SHALL be re-anchored with STARK proofs that bind the original Ed25519 signature to a quantum-resistant hash chain. Re-anchoring SHALL be a one-way operation -- once re-anchored, the classical-only version SHALL be marked deprecated. Migration SHALL be tested against NIST PQC test vectors.

**Adversarial Tests:**
- `test_classical_only_signature_rejected_post_migration`: After migration, submit Ed25519-only signed chain; verify rejection.
- `test_hybrid_signature_both_required`: Submit chain with valid Ed25519 but invalid ML-DSA; verify rejection.
- `test_re_anchoring_irreversible`: Re-anchor a record, then attempt to use the classical-only version; verify deprecated.
- `test_pqc_test_vectors_pass`: Run NIST ML-DSA test vectors; verify all pass.

---

## LEGAL/COMPLIANCE REQUIREMENTS (Security-Relevant)

### LEG-002 -- Cryptographic Timestamp Anchoring

**Threat Assessment:** Timestamps are the temporal integrity mechanism. Without external anchoring, an attacker with storage access can rewrite history.

**Exochain Defense:** Specified in PRD (RFC 3161 + blockchain anchoring) but not yet enforced at the TNC level.

**Hardened Requirement:**
> LEG-002: Timestamp anchoring SHALL be a hard gate for all terminal-status decisions. At least 2 independent RFC 3161 TSA providers SHALL be used. Blockchain anchoring SHALL occur within 24 hours of terminal status. Anchoring failure SHALL prevent the decision from achieving terminal status.

---

### LEG-009 -- Attorney-Client Privilege Compartmentalization

**Threat Assessment:** Privilege compartmentalization is a security problem: the boundary between privileged and non-privileged data must be cryptographically enforced, not just logically tagged.

**Hardened Requirement:**
> LEG-009: Privileged data SHALL be encrypted with a separate key hierarchy accessible only to privilege-designated actors. The privilege boundary SHALL be enforced by TEE enclaves. Privilege designation SHALL be immutable once set. Inadvertent disclosure SHALL be prevented by a privilege-aware access control layer that blocks privilege-tagged content from non-privileged exports.

---

## SECURITY PANEL VERDICT

### Top 5 Security Risks in the Current Specification

**Risk 1: AUTHORITY CHAIN SIGNATURE VERIFICATION GAP (CRITICAL)**
The invariant engine (`exo-gatekeeper::invariants.rs`) validates authority chain topology (non-empty, continuous, terminates at actor) but does NOT verify the actual cryptographic signatures on each link. The `decision-forum::tnc_enforcer.rs` checks for non-empty signatures and minimum key material length but does not perform Ed25519 verification. This means a well-formed chain with plausible-looking but forged signatures would pass all current checks. This is the highest-priority gap and must be closed before production.

**Risk 2: AI IDENTITY IS SELF-DECLARED (HIGH)**
The MCP enforcement (`exo-gatekeeper::mcp.rs`) and TNC enforcer both rely on `is_ai` flags and `SignerType` enums that are set by the caller, not cryptographically verified. An AI agent that marks itself as human bypasses all AI-specific controls (TNC-02, TNC-09, GOV-007). The fix is to use cryptographically distinct key types for AI agents so that AI origin is unforgeable.

**Risk 3: POST-QUANTUM NOT YET IMPLEMENTED (HIGH)**
The entire codebase currently uses Ed25519 exclusively. Given the 50-year retention requirement and the harvest-now-decrypt-later threat model, the ARCH-009 hybrid post-quantum signature requirement must be prioritized. Every day of Ed25519-only operation increases the HNDL exposure window.

**Risk 4: EMERGENCY PROTOCOL LACKS HARD ENFORCEMENT (MEDIUM-HIGH)**
GOV-009 specifies emergency constraints (scope, duration, ratification, frequency) but the TNC enforcer only partially covers ratification (TNC-10). Per-actor limits, scope enforcement, TTL enforcement, and automatic voiding on missed ratification are all specified but not enforced in code.

**Risk 5: TEE ATTESTATION USES DETERMINISTIC MOCK IN CODEBASE (MEDIUM)**
`exo-gatekeeper::tee.rs` generates attestation signatures using blake3 hash (deterministic, not hardware-bound). While appropriate for testing, the `TeePlatform::Simulated` variant must be categorically rejected in production builds. No production-mode gate currently exists to prevent simulated attestation from being accepted.

### Overall Assessment

The exochain crate architecture is **well-designed for defense in depth**. The separation between the immutable kernel (judicial branch), the governance layer, and the identity layer follows sound zero-trust principles. The 8 constitutional invariants in `exo-gatekeeper::invariants.rs` map directly to the PRD's TNC controls, and the MCP enforcement layer adds AI-specific containment.

However, the gap between **specified security** and **implemented security** is material in three areas: (1) signature verification is topological, not cryptographic; (2) AI identity is honor-system, not cryptographically enforced; (3) post-quantum is specified but absent. These three gaps must be closed before the platform can be considered production-ready for the governance use case described in the PRD.

The existing anti-Sybil architecture (`exo-governance::crosscheck.rs`, `exo-governance::quorum.rs`, `exo-escalation::detector.rs`) is the strongest area of the codebase, with independence-aware quorum counting, behavioral coordination detection, and a 7-stage escalation pipeline. This provides genuine protection against the most likely attack vector (Sybil quorum manipulation).

**Recommendation: CONDITIONAL APPROVAL** -- The PRD security architecture is sound. Existing crate defenses cover approximately 75% of the attack surface. Close the three critical gaps (signature verification, AI identity binding, post-quantum implementation) and the specification-to-implementation gaps in emergency protocol enforcement, and the system will meet the security bar for constitutional governance.
