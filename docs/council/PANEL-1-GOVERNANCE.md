# PANEL-1-GOVERNANCE: Constitutional Governance Review

**Panel:** Governance
**Discipline:** Constitutional Governance, Sovereign Stewardship, Authority Theory
**PRD:** decision.forum v1.1.0
**Date:** 2026-03-18
**Reviewer:** EXOCHAIN Council Governance Panel

---

## Core Axioms Assessment

### Axiom 1: "Authority is held in trust, never owned."

**Assessment:** Sound
**Exochain Coverage:** `exo-governance/src/delegation.rs` models authority as time-bound, scoped, revocable delegation with mandatory expiry (`expires_at` field). `exo-authority/src/chain.rs` enforces scope-narrowing through the chain (scope can never widen). The `DelegationScope::is_subset_of()` method ensures sub-delegations cannot exceed parent authority.
**Gaps:** No explicit "trust relationship" object. The axiom implies a fiduciary framing where the delegation is explicitly labeled as a trust instrument, not a property right. The current `Delegation` struct has no `trust_purpose` or `beneficiary` field linking it to the principal on whose behalf authority is exercised. The code enforces the mechanics but not the semantics of trust.
**Recommendation:** Add a `trust_purpose: String` and `beneficiary_scope: Vec<Did>` to `Delegation` to make the trust relationship machine-readable, not merely aspirational.

### Axiom 2: "Decisions are first-class sovereign objects."

**Assessment:** Sound
**Exochain Coverage:** `decision-forum/src/decision_object.rs` implements `DecisionObject` with all five stated properties: storable (serializable), diffable (merkle root recomputation), transferable (authority chain), auditable (embedded `audit_log` and `audit_sequence`/`prev_audit_hash`), contestable (via `Status::Contested` and `exo-governance/src/challenge.rs`).
**Gaps:** "Transferable" is implicit through authority chain reassignment but lacks an explicit `transfer()` method with provenance tracking. Decision Objects lack a formal diff operation between versions.
**Recommendation:** Add `fn diff(a: &DecisionObject, b: &DecisionObject) -> DecisionDiff` and `fn transfer(obj: &mut DecisionObject, new_authority: AuthorityChain) -> Result<TransferRecord>`.

### Axiom 3: "Trust accumulation > speed."

**Assessment:** Sound
**Exochain Coverage:** `exo-governance/src/quorum.rs` implements independence-aware counting with the explicit constitutional principle encoded in the error message: "numerical multiplicity without attributable independence is theater, not legitimacy." `exo-governance/src/constitution.rs` evaluates constraints synchronously.
**Gaps:** No performance budget enforcement. The axiom says verification gates are "features, not bottlenecks" but the `<2s` latency requirement in GOV-001 creates a tension. There is no SLA monitoring or circuit breaker for when verification legitimately takes longer than 2s.
**Recommendation:** Define a `VerificationBudget` struct with `max_latency_ms`, `degradation_mode`, and `alert_threshold_ms` to manage this tension explicitly.

### Axiom 4: "Constitutional constraints must be machine-readable and enforced at runtime."

**Assessment:** Sound
**Exochain Coverage:** `exo-governance/src/constitution.rs` implements `ConstraintExpression` enum with 7 machine-evaluable variants. `evaluate_constraints()` and `check_blocking_constraints()` enforce synchronously. The `FailureAction::Block` path returns `Err(GovernanceError::ConstitutionalViolation)` which halts the action.
**Gaps:** `ConstraintExpression::Custom` variant returns `(true, "Custom constraint evaluation not yet implemented")` -- effectively a pass-through. This is a critical gap: any custom constraint silently passes. The `serde_json::Value` predicate has no evaluator.
**Recommendation:** Either implement a sandboxed predicate evaluator (e.g., WASM-based) or change `Custom` to default-deny: `(false, "Custom constraint evaluation not yet implemented")`.

### Axiom 5: "Authority without cryptographically verifiable provenance is void."

**Assessment:** Sound
**Exochain Coverage:** `exo-authority/src/chain.rs` `verify_chain()` rejects empty signatures (`AuthorityError::InvalidSignature`). `exo-governance/src/types.rs` `GovernanceSignature` includes Ed25519 signature, key version, and signer DID. `decision-forum/src/tnc_enforcer.rs` TNC-01 enforces non-empty pubkey/signature on every authority link.
**Gaps:** Signature verification is structural (non-empty check) not cryptographic (no `verify()` call against the actual public key). The `decision-forum` TNC-01 checks `pubkey.len() < MIN_KEY_MATERIAL_LEN` but does not verify the signature against the pubkey. `exo-authority/src/chain.rs` checks `link.signature.is_empty()` but does not call `ed25519_dalek::VerifyingKey::verify()`.
**Recommendation:** This is a **P0 critical gap**. Add actual cryptographic verification to both `verify_chain()` and `TNC-01`. Without it, Axiom 5 is not satisfied.

---

## GOV Requirements Assessment

### GOV-001 -- Machine-Readable Constitutional Framework

**Assessment:** Sound
**Exochain Coverage:** `exo-governance/src/constitution.rs` -- `Constitution` struct with `tenant_id`, `version: SemVer`, `hash: Blake3Hash`, `documents: Vec<ConstitutionalDocument>`, `constraints: Vec<Constraint>`, `signatures: Vec<GovernanceSignature>`. JSON content via `serde_json::Value`. Constraint evaluation via `evaluate_constraints()`. `decision-forum/src/constitution.rs` provides alternative with article-level granularity.
**Gaps:**
1. No dry-run mode for amendments. The `amend()` function in `decision-forum/src/constitution.rs` is immediately applied.
2. `<2s` real-time constraint eval has no benchmark or enforcement.
3. No YAML support (JSON only via `serde_json::Value`).
4. Two parallel `Constitution` types exist (`exo-governance` vs `decision-forum`) with incompatible schemas.
**Optimized Requirement:** "Per-tenant signed versioned machine-readable constitutional corpus. JSON serialization with semantic versioning. Constraint evaluation MUST complete synchronously within the action lifecycle. Decision Objects MUST store the Blake3 hash of the constitution version in force at each lifecycle event. A dry-run mode MUST exist for amendment impact analysis that does not mutate state."
**Test Specification:**
- test_constitution_per_tenant_isolation: Two tenants have different constitutions; tenant A's constraints do not apply to tenant B.
- test_constitution_hash_in_decision_object: Creating a decision stores the current constitution's Blake3 hash.
- test_dry_run_amendment_no_mutation: Running dry-run amendment returns impact analysis without modifying the constitution.
- test_constraint_eval_synchronous: Constraint evaluation completes before the action returns.

### GOV-002 -- Constitutional Versioning with Temporal Binding

**Assessment:** Sound
**Exochain Coverage:** `exo-governance/src/delegation.rs` `Delegation` struct stores `constitution_version: SemVer`. `decision-forum/src/decision_object.rs` stores `constitution_hash` and `constitution_version`. `exo-governance/src/types.rs` provides `SemVer` with compatibility checking.
**Gaps:**
1. No explicit prohibition of retroactive amendments at the code level. The `amend()` function does not check whether in-flight decisions would be affected.
2. Amendments are not themselves `DecisionObject` instances -- they are direct mutations via `amend()`.
3. No temporal binding log showing which constitution version was in force at each lifecycle event.
**Optimized Requirement:** "Every Decision Object MUST immutably record the constitution version hash at each lifecycle state transition. Retroactive amendment application MUST be rejected by the runtime. Constitutional amendments MUST be processed as Decision Objects subject to the same governance pipeline."
**Test Specification:**
- test_decision_records_constitution_at_each_transition: Decision moving from Draft to Pending to Approved records three constitution hashes (one per transition).
- test_retroactive_amendment_rejected: Amending constitution does not change the constitution_hash of already-created decisions.
- test_amendment_is_decision_object: Constitutional amendment creates a DecisionObject with class=Constitutional.

### GOV-003 -- Delegated Authority Matrix

**Assessment:** Sound
**Exochain Coverage:** `exo-governance/src/delegation.rs` -- `Delegation` with `delegator`, `delegatee`, `scope: DelegationScope`, `expires_at`, `revoked_at`, `sub_delegation_allowed`, `sub_delegation_scope_cap`, `signature`. `exo-authority/src/delegation.rs` -- `DelegationRegistry` with BTreeMap indexes, circular delegation detection, chain resolution. `exo-authority/src/cache.rs` -- LRU cache for chain lookups.
**Gaps:**
1. No "matrix view" -- a method to enumerate all current authorities for a given actor across all delegations.
2. No signed JSON export of the full authority matrix.
3. `<3s` retrieval requirement has no benchmark.
4. Revocation is not marked "irreversible" in the `exo-governance` Delegation -- `revoked_at` could theoretically be set to `None` again (no immutability guard).
**Optimized Requirement:** "Real-time authority matrix enumerating all actor-to-authority mappings. Signed JSON format. Auto-expiry enforced without grace period. Chain retrieval MUST complete within the action lifecycle. Sub-delegation permitted only when explicitly authorized by parent delegation and within parent scope. Revocation MUST be irreversible (append-only revocation record)."
**Test Specification:**
- test_authority_matrix_enumeration: Given 3 delegations, matrix correctly lists all authorities per actor.
- test_revocation_irreversible: Once `revoke()` is called, no method can restore the delegation.
- test_sub_delegation_within_cap: Sub-delegation within scope cap succeeds; exceeding cap fails.
- test_circular_delegation_rejected: A->B->C->A delegation attempt fails.

### GOV-004 -- Standing Authority Sunset and Renewal

**Assessment:** Needs Refinement
**Exochain Coverage:** `exo-governance/src/delegation.rs` `Delegation.expires_at` provides hard expiry. `Delegation.is_active()` enforces `current_time_ms < self.expires_at` (strict, no grace). `exo-authority/src/chain.rs` `verify_chain()` checks `link.expires.is_expired(now)`.
**Gaps:**
1. No max-12-month enforcement -- `expires_at` can be set to any future value.
2. No notification system (90/60/30/14/7-day warnings).
3. No sunset calendar or renewal workflow.
4. No concept of "standing authority" as distinct from one-time delegation.
**Optimized Requirement:** "All standing delegations MUST have an expiry no greater than 12 months from creation. The system MUST generate notification events at 90, 60, 30, 14, and 7 days before expiry. Expired delegations MUST immediately block all dependent actions. A sunset calendar MUST be queryable per tenant."
**Test Specification:**
- test_max_12_month_expiry_enforced: Attempting to create a delegation with expires_at > 12 months from now fails.
- test_expiry_notification_events: Delegation approaching expiry generates notification at each threshold.
- test_expired_blocks_immediately: Action using expired delegation returns DelegationExpired.
- test_sunset_calendar_query: Querying sunset calendar returns all delegations sorted by expiry date.

### GOV-005 -- Authority Chain Verification on Every State Change

**Assessment:** Sound
**Exochain Coverage:** `exo-authority/src/chain.rs` -- `build_chain()` validates continuity, depth limits, depth values. `verify_chain()` validates signatures non-empty, expiry, scope-narrowing. `decision-forum/src/tnc_enforcer.rs` TNC-01 runs on `enforce_all()` which is called during `seal()`.
**Gaps:**
1. Verification is called on `seal()` but not on every state change. Moving from Draft to Pending, or Pending to Contested, does not trigger `verify_chain()`.
2. `<2s for <=5 levels` has no benchmark.
3. CHAIN_BREAK rejection exists (`AuthorityError::ChainBroken`) but the error name does not match the spec's `CHAIN_BREAK` status code.
4. No bypass-prevention mechanism -- a code path could skip `enforce_all()`.
**Optimized Requirement:** "Full authority chain verification MUST execute synchronously on every Decision Object state transition, not only at seal time. Chain depth MUST NOT exceed the configured maximum (default 5). A broken chain MUST result in CHAIN_BREAK rejection. Verification MUST NOT be bypassable through any code path."
**Test Specification:**
- test_chain_verified_on_every_state_change: Moving a decision from Draft to Pending triggers chain verification.
- test_chain_break_rejects_state_change: Broken chain prevents any state transition.
- test_chain_depth_5_max: Chain of 6 links rejected with DepthExceeded.
- test_no_bypass_path: All public state-transition methods call verify_chain.

### GOV-006 -- Constitutional Conflict Resolution Hierarchy

**Assessment:** Sound
**Exochain Coverage:** `exo-governance/src/constitution.rs` -- `PrecedenceLevel` enum with Articles(5) > Bylaws(4) > Resolutions(3) > Charters(2) > Policies(1). Deterministic Ord derivation ensures consistent ordering.
**Gaps:**
1. No auto-block on conflict. No method detects when two constraints from different precedence levels conflict.
2. No Conflict Register or resolution trail.
3. `PrecedenceLevel` ordering exists but is not used in `evaluate_constraints()` -- constraints are evaluated in document order, not precedence order.
**Optimized Requirement:** "Constitutional documents MUST be evaluated in precedence order (Articles first). When constraints from different precedence levels conflict, the higher-precedence constraint MUST prevail and the conflict MUST be recorded in the Conflict Register. The Conflict Register MUST be append-only and include the resolution rationale."
**Test Specification:**
- test_precedence_ordering_enforced: Constraint from Articles overrides conflicting constraint from Policies.
- test_conflict_register_records_conflict: Conflicting constraints create a register entry.
- test_evaluation_order_by_precedence: Documents evaluated Articles-first regardless of insertion order.

### GOV-007 -- Human Oversight Gates for AI

**Assessment:** Sound
**Exochain Coverage:** `exo-governance/src/types.rs` -- `SignerType` enum with `Human` and `AiAgent { delegation_id, expires_at }` variants making human/AI cryptographically distinguishable. `DecisionClass::requires_human_gate()` returns true for Constitutional, Strategic, Emergency. `decision-forum/src/tnc_enforcer.rs` TNC-02 blocks AI signers on Strategic/Constitutional decisions. TNC-09 enforces AI ceiling class.
**Gaps:**
1. AI max delegation 90 days is not enforced -- `AiAgent.expires_at` has no maximum cap.
2. AI cannot create/modify delegations -- no code enforces this. The `AuthorizedAction::GrantDelegation` could be included in an AI agent's scope.
3. `HUMAN_GATE_REQUIRED` is not a first-class status in `ConstraintExpression` but is checked via `RequireHumanGate`.
**Optimized Requirement:** "AI agents MUST operate exclusively under delegated authority with a maximum expiry of 90 days. AI agents MUST NOT satisfy HUMAN_GATE_REQUIRED constraints. Human and AI signatures MUST be cryptographically distinguishable via the SignerType field. AI agents MUST NOT be granted GrantDelegation, RevokeDelegation, or AmendConstitution actions. Violation attempts MUST be logged as security incidents."
**Test Specification:**
- test_ai_delegation_max_90_days: AI delegation with expires_at > 90 days from now rejected.
- test_ai_cannot_satisfy_human_gate: AI signer on Strategic decision returns ConstitutionalViolation.
- test_ai_cannot_grant_delegation: AI agent attempting GrantDelegation returns error and logs security incident.
- test_signer_type_distinguishable: Serialized Human and AiAgent signatures have distinct type tags.

### GOV-008 -- Structured Contestation and Reversal

**Assessment:** Sound
**Exochain Coverage:** `exo-governance/src/challenge.rs` -- `Challenge` with `ChallengeGround` (6 grounds), `ChallengeStatus` (Filed, UnderReview, Sustained, Overruled, Withdrawn), `PauseOrder`, `file_challenge()`, `pause_action()`, `adjudicate()`. `decision-forum/src/decision_object.rs` includes `Status::Contested`. `exo-governance/src/deliberation.rs` provides structured voting for resolution.
**Gaps:**
1. No REVERSAL linkage type. Challenge resolution creates adjudication but no linked reversal Decision Object.
2. `Status::Contested` exists but no automatic transition from Contested back to execution upon resolution.
3. Challenge Object is not itself a Decision Object (the PRD says "Resolution is new Decision Object").
4. No `CONTESTED pauses execution` enforcement -- the `PauseOrder` is created but not enforced by any state machine.
**Optimized Requirement:** "Every Decision Object MUST support contestation. Filing a challenge MUST create a Challenge Object and transition the target to CONTESTED status, which MUST pause execution. Resolution MUST produce a new Decision Object. Reversal MUST create an immutable REVERSAL linkage to the original decision."
**Test Specification:**
- test_challenge_pauses_execution: Filing a challenge transitions target to Contested and blocks further advancement.
- test_resolution_creates_decision_object: Sustaining a challenge creates a new Decision Object with reversal linkage.
- test_reversal_linkage_immutable: Reversal linkage cannot be removed from either the original or reversal decision.
- test_overruled_resumes_execution: Overruling a challenge transitions target back to prior status.

### GOV-009 -- Emergency Action Protocol

**Assessment:** Sound
**Exochain Coverage:** `decision-forum/src/emergency.rs` -- `EmergencyAction` with caller-supplied deterministic IDs/timestamps, `ratification_deadline`, `RatificationStatus` (Required/Ratified/Expired), policy caps, and governance-review threshold checks. `exo-governance/src/constitution.rs` -- `EmergencySpec` with authorized_roles, scope, max_duration_hours, ratification_deadline_hours, max_per_quarter.
**Gaps:**
1. `>3/quarter triggers governance review` is tracked by `EmergencyFrequencyTracker` but no review action is auto-created.
2. `RATIFICATION_REQUIRED` auto-creation: `ratification_decision_id` is stored but the actual Decision Object must be created by the caller -- no automatic creation.
3. No enforcement of `max_duration_hours` from `EmergencySpec` -- the action has no built-in expiry.
**Optimized Requirement:** "Emergency actions MUST create a corresponding RATIFICATION_REQUIRED Decision Object automatically (not delegated to caller). Actions exceeding max_duration_hours MUST auto-expire. Exceeding the quarterly threshold MUST auto-create a governance review Decision Object."
**Test Specification:**
- test_emergency_auto_creates_ratification_decision: Creating EmergencyAction automatically creates a RATIFICATION_REQUIRED Decision Object.
- test_emergency_duration_enforced: Emergency action exceeding max_duration_hours transitions to expired.
- test_frequency_threshold_triggers_review: Fourth emergency action in quarter auto-creates governance review.
- test_unratified_expired_surfaced: Expired ratification is flagged as governance failure.

### GOV-010 -- Quorum Failure and Graceful Degradation

**Assessment:** Needs Refinement
**Exochain Coverage:** `exo-governance/src/quorum.rs` -- `QuorumResult::NotMet` with reason. `exo-governance/src/deliberation.rs` -- `DeliberationResult::NoQuorum`. No DEGRADED_GOVERNANCE mode exists.
**Gaps:**
1. No auto-detection of degraded governance state.
2. No restricted action set during degraded governance.
3. No mandatory ratification of actions taken during degraded governance.
4. No DEGRADED_GOVERNANCE status in any state machine.
**Optimized Requirement:** "When quorum cannot be achieved, the system MUST transition to DEGRADED_GOVERNANCE mode with a restricted action set (safety-critical only). All actions taken during degraded governance MUST be flagged for mandatory ratification once quorum is restored."
**Test Specification:**
- test_quorum_failure_triggers_degraded_mode: Three consecutive quorum failures transition tenant to DEGRADED_GOVERNANCE.
- test_degraded_mode_restricts_actions: Non-safety-critical actions rejected during degraded governance.
- test_degraded_actions_require_ratification: Actions taken during degradation are flagged for ratification.
- test_quorum_restored_exits_degraded: Achieving quorum transitions back to normal governance.

### GOV-011 -- Succession and Continuity

**Assessment:** Critical Gap
**Exochain Coverage:** None. No crate implements succession planning, role-based succession, or continuity guarantees.
**Gaps:**
1. No succession registry.
2. No minimum-2-successors enforcement.
3. No automatic succession activation.
4. No succession testing/dry-run.
**Optimized Requirement:** "Every key governance role MUST have at least 2 pre-defined successors stored in a signed succession registry. Succession activation MUST be triggered when the primary role holder's delegation expires or is revoked without renewal. Succession MUST be testable via dry-run."
**Test Specification:**
- test_succession_registry_min_2: Attempting to register fewer than 2 successors for a key role fails.
- test_succession_activates_on_expiry: Primary role holder's delegation expires, first successor is automatically activated.
- test_succession_dry_run: Dry-run succession does not mutate state but returns activation plan.
- test_succession_chain_priority: Successors activated in registered priority order.

### GOV-012 -- Accountability Mechanisms

**Assessment:** Needs Refinement
**Exochain Coverage:** `exo-governance/src/challenge.rs` provides the contestation mechanism. `exo-governance/src/clearance.rs` provides clearance levels that could be modified as sanctions. `exo-legal/src/conflict_disclosure.rs` provides disclosure tracking.
**Gaps:**
1. No Censure, Suspension, Revocation, or Recall as explicit Decision Object types.
2. No due-process timeline clocking.
3. No accountability-specific state machine.
**Optimized Requirement:** "Censure, Suspension, Revocation, and Recall MUST each be implemented as Decision Object subtypes with defined due-process timelines. The system MUST clock all due-process deadlines and auto-escalate on expiry. Each accountability action MUST create an immutable audit trail."
**Test Specification:**
- test_censure_creates_decision_object: Censure motion creates Decision Object with class=Accountability.
- test_due_process_timeline_clocked: Suspension due-process period is tracked and auto-escalates on deadline.
- test_accountability_audit_trail: All accountability actions recorded in append-only audit log.
- test_recall_requires_supermajority: Recall motion requires higher quorum threshold than normal decisions.

### GOV-013 -- Recursive Self-Governance

**Assessment:** Needs Refinement
**Exochain Coverage:** `decision-forum/src/constitution.rs` `amend()` modifies the constitution with signature requirements. `exo-governance/src/constitution.rs` models the constitution as a versioned, hashable, signed document.
**Gaps:**
1. No Governance Simulator.
2. "100% self-modification compliance" has no enforcement mechanism -- there is no guard preventing direct mutation of governance code outside the Decision Object pipeline.
3. Platform evolution (code changes) is not linked to Decision Objects.
**Optimized Requirement:** "All modifications to governance rules, constitutional documents, and platform behavior MUST be processed as Decision Objects. A Governance Simulator MUST exist to model amendment impact before ratification. The system MUST reject any governance mutation not routed through the Decision Object pipeline (enforced at the type system level, not runtime guard)."
**Test Specification:**
- test_governance_mutation_requires_decision_object: Direct mutation of Constitution without Decision Object pipeline fails at compile time or returns error.
- test_governance_simulator_impact_analysis: Simulator returns impact analysis of proposed amendment.
- test_self_modification_100_percent: Audit of all governance-modifying code paths confirms they route through Decision Objects.

---

## TNC Requirements Assessment

### TNC-01 -- Authority Chain Verification Gate

**Assessment:** Sound
**Exochain Coverage:** `decision-forum/src/tnc_enforcer.rs` TNC-01 validates non-empty chain, depth <= 5, non-empty pubkey/signature on each link. `exo-authority/src/chain.rs` `build_chain()` and `verify_chain()` validate continuity, depth, expiry, scope-narrowing.
**Gaps:** Verification is at seal-time only, not on every governed action. No bypass prevention.
**Optimized Requirement:** "Every governed action, without exception, MUST pass real-time authority chain verification synchronously before the action is executed. There MUST be no code path that skips verification. Bypass attempts MUST be logged as security incidents."
**Test Specification:**
- test_tnc01_no_skip_no_override: Every public state-transition method calls authority chain verification.
- test_tnc01_empty_chain_blocked: Action with empty authority chain is rejected.
- test_tnc01_depth_exceeded_blocked: Chain exceeding max depth is rejected.

### TNC-02 -- Human Gate Integrity

**Assessment:** Sound
**Exochain Coverage:** `exo-governance/src/types.rs` `DecisionClass::requires_human_gate()`. `decision-forum/src/tnc_enforcer.rs` TNC-02 blocks AI on Strategic/Constitutional. `exo-governance/src/constitution.rs` `ConstraintExpression::RequireHumanGate`.
**Gaps:** No enforcement that HUMAN_GATE_REQUIRED classification cannot be changed without constitutional amendment. It is a runtime check, not a structural guarantee.
**Optimized Requirement:** "HUMAN_GATE_REQUIRED MUST require cryptographically verified human approval. Reclassification of a decision class from human-gated to non-human-gated MUST require a Constitutional-class Decision Object (i.e., a constitutional amendment)."
**Test Specification:**
- test_tnc02_human_gate_crypto_verified: Human gate check verifies signature against known human key, not just type tag.
- test_tnc02_reclassification_requires_amendment: Removing human gate from Strategic class requires Constitutional Decision Object.

### TNC-03 -- Tamper-Evident Audit Log Continuity

**Assessment:** Sound
**Exochain Coverage:** `exo-governance/src/audit.rs` -- hash-chained `AuditLog` with `append()` rejecting wrong chain hash, `verify_chain()` detecting tampering. `decision-forum/src/decision_object.rs` embedded `audit_log` with chronological ordering enforcement.
**Gaps:**
1. No self-verify minimum hourly. The `verify_chain()` is available but no scheduler calls it.
2. No P0 incident generation on gap detection.
3. Two separate audit mechanisms exist (`exo-governance/audit.rs` Blake3-chained vs `decision-forum` chronological ordering) with no integration.
**Optimized Requirement:** "Audit hash chain MUST be continuous and verified automatically at minimum hourly. Any gap MUST generate a P0 security incident. Self-verification failures MUST block further actions until the chain is repaired or acknowledged by a Governor-level actor."
**Test Specification:**
- test_tnc03_hash_chain_continuous: Sequence of 100 audit entries maintains unbroken hash chain.
- test_tnc03_tamper_detected: Modifying any entry's field causes verify_chain to fail.
- test_tnc03_gap_generates_p0: Missing entry in sequence triggers P0 incident.
- test_tnc03_hourly_self_verify: Scheduled verification runs and reports status.

### TNC-04 -- Constitutional Constraint Enforcement Synchronicity

**Assessment:** Sound
**Exochain Coverage:** `exo-governance/src/constitution.rs` `check_blocking_constraints()` is synchronous -- returns `Result` before the caller can proceed. `decision-forum/src/tnc_enforcer.rs` `enforce_all()` is called within `seal()` and blocks on failure.
**Gaps:** Synchronous enforcement depends on callers using `check_blocking_constraints()`. No compile-time guarantee that all action paths call it.
**Optimized Requirement:** "Constitutional constraints MUST be evaluated synchronously as part of the action execution, never post-hoc. This MUST be enforced through the type system (actions require a `ConstraintClearance` token that can only be obtained from `check_blocking_constraints()`)."
**Test Specification:**
- test_tnc04_constraints_before_action: Action cannot complete without constraint evaluation.
- test_tnc04_blocking_constraint_halts: Block-level constraint failure prevents action.
- test_tnc04_custom_constraint_default_deny: Custom constraint with no evaluator blocks (not passes).

### TNC-05 -- Delegation Expiry Enforcement

**Assessment:** Sound
**Exochain Coverage:** `exo-governance/src/delegation.rs` `Delegation::is_active()` returns false when `current_time_ms >= expires_at` (strict, test `test_tnc05_immediate_expiry` confirms). `decision-forum/src/tnc_enforcer.rs` TNC-05 checks delegation chain expiry.
**Gaps:** No enforcement of "no auto-extension." A new delegation could be created to effectively extend an expired one.
**Optimized Requirement:** "Expired delegations MUST be immediately dead. No soft expiry, no auto-extension. Creating a new delegation to replace an expired one MUST be an explicit governance action, not an automatic renewal."
**Test Specification:**
- test_tnc05_expired_is_dead: Action using expired delegation returns DelegationExpired.
- test_tnc05_no_grace_period: Delegation at exactly expires_at is inactive.
- test_tnc05_no_auto_extension: No method extends expires_at on an existing delegation.

### TNC-06 -- Conflict Disclosure Prerequisite

**Assessment:** Sound
**Exochain Coverage:** `exo-governance/src/conflict.rs` `check_conflicts()` and `must_recuse()`. `exo-legal/src/conflict_disclosure.rs` `require_disclosure()` and `file_disclosure()`. `decision-forum/src/tnc_enforcer.rs` TNC-06 requires at least one conflict disclosure for Operational+ decisions.
**Gaps:** The system "blocks, not warns" per spec, but `exo-governance/src/constitution.rs` defers conflict disclosure check: `"Conflict disclosure check deferred to decision"`. This deferral creates a gap window.
**Optimized Requirement:** "No actor MAY participate in a governed action without first filing a conflict disclosure (positive or negative). The system MUST block participation, not merely warn. Disclosure MUST be checked at the action entry point, not deferred."
**Test Specification:**
- test_tnc06_no_disclosure_blocks: Actor without disclosure is blocked from voting.
- test_tnc06_system_blocks_not_warns: Undisclosed conflict returns hard error, not warning.
- test_tnc06_checked_at_entry: Disclosure check occurs before action begins, not at seal time.

### TNC-07 -- Quorum Enforcement Before Vote

**Assessment:** Sound
**Exochain Coverage:** `exo-governance/src/quorum.rs` `compute_quorum()` returns `QuorumResult::NotMet` when insufficient. `exo-governance/src/deliberation.rs` `close()` checks quorum before rendering a result. `decision-forum/src/tnc_enforcer.rs` TNC-07 verifies vote count meets quorum for terminal statuses.
**Gaps:** TNC-07 in decision-forum checks quorum at seal time (after votes), not before voting begins. The spec says "before vote" which implies quorum verification of eligible participants before the deliberation opens.
**Optimized Requirement:** "Quorum eligibility MUST be verified before a vote proceeds. A deliberation MUST NOT open unless minimum quorum-eligible participants are confirmed. Terminal status MUST re-verify actual votes against quorum threshold."
**Test Specification:**
- test_tnc07_pre_vote_quorum_check: Deliberation with fewer than minimum eligible participants cannot open.
- test_tnc07_post_vote_quorum_enforced: Approved decision with insufficient votes is rejected.
- test_tnc07_independence_counted: Quorum counts only independent attestations per policy.

### TNC-08 -- Decision Object Immutability After Terminal

**Assessment:** Sound
**Exochain Coverage:** `decision-forum/src/tnc_enforcer.rs` TNC-08 requires non-empty merkle root and evidence for terminal statuses (Approved, Rejected, Void).
**Gaps:** Immutability is asserted but not enforced at the type level. A `DecisionObject` with `Status::Approved` can still have its fields mutated via direct struct access. There is no `freeze()` mechanism.
**Optimized Requirement:** "Once a Decision Object reaches terminal status (Approved, Rejected, Void), its content MUST be immutable. Corrections MUST create new linked Decision Objects. Immutability SHOULD be enforced at the type level (consuming the mutable reference on terminal transition)."
**Test Specification:**
- test_tnc08_terminal_is_immutable: Attempting to modify an Approved decision's fields returns error.
- test_tnc08_correction_creates_new_object: Correcting a terminal decision creates a new linked Decision Object.
- test_tnc08_merkle_root_frozen: Merkle root cannot be recomputed after terminal status.

### TNC-09 -- AI Agent Delegation Ceiling

**Assessment:** Sound
**Exochain Coverage:** `decision-forum/src/tnc_enforcer.rs` TNC-09 enforces ceiling_class comparison. `decision-forum/src/decision_object.rs` `SignerType::AiAgent { ceiling_class }`. Also TNC-09 in the legacy enforcer path checks AI signer ratio <= 49%.
**Gaps:**
1. "Cannot delegate" -- no enforcement that AI agents cannot include `GrantDelegation` in their actions.
2. "Cannot self-modify" -- no enforcement that AI cannot modify its own delegation record.
3. "Attempt = security incident" -- no incident generation, just an error.
**Optimized Requirement:** "AI agents MUST NOT exceed their delegated authority ceiling. AI agents MUST NOT delegate to other agents or modify their own delegation. Any such attempt MUST be logged as a security incident and trigger immediate delegation revocation review."
**Test Specification:**
- test_tnc09_ai_exceeds_ceiling_blocked: AI with Operational ceiling attempting Strategic decision fails.
- test_tnc09_ai_cannot_delegate: AI agent attempting GrantDelegation returns SecurityIncident.
- test_tnc09_ai_cannot_self_modify: AI agent attempting to modify its own delegation record fails.
- test_tnc09_violation_logged_as_incident: TNC-09 violation creates a security incident audit entry.

### TNC-10 -- Emergency Action Ratification Tracking

**Assessment:** Sound
**Exochain Coverage:** `decision-forum/src/emergency.rs` `EmergencyAction` with `ratification_deadline`, `RatificationStatus`, `check_expiry()`, `ratify_emergency()`, and `needs_governance_review()` threshold checks.
**Gaps:**
1. "Unratified = governance failure surfaced by system" -- detection exists (`is_ratification_expired()`) but no automatic surfacing/notification.
2. Auto-creation of ratification Decision Object is caller responsibility.
**Optimized Requirement:** "Every emergency action MUST auto-generate a ratification requirement with a deadline. The system MUST surface unratified emergency actions as governance failures automatically (not on-demand). Unratified actions MUST be flagged in every governance dashboard and report."
**Test Specification:**
- test_tnc10_ratification_auto_generated: Creating emergency action creates ratification requirement.
- test_tnc10_unratified_surfaced: Expired ratification deadline triggers governance failure notification.
- test_tnc10_ratification_deadline_enforced: Ratification after deadline is rejected.
- test_tnc10_frequency_threshold_surfaced: Fourth emergency in quarter triggers governance review.

---

## GOVERNANCE PANEL VERDICT

### Ready to Build (Sound Implementation Exists)

The following requirements have solid implementations and can proceed to integration testing:

1. **TNC-05 (Delegation Expiry)** -- `exo-governance/src/delegation.rs` enforces strict immediate expiry with tests proving no grace period. Production-ready.
2. **GOV-003 (Delegated Authority Matrix)** -- Core delegation mechanics in both `exo-governance` and `exo-authority` are well-implemented with scope narrowing, sub-delegation caps, and circular detection.
3. **TNC-03 (Audit Log Continuity)** -- `exo-governance/src/audit.rs` provides a correct Blake3 hash-chained append-only log with tamper detection.
4. **GOV-008 (Contestation)** -- `exo-governance/src/challenge.rs` has a complete challenge lifecycle with 6 grounds, adjudication, and withdrawal.
5. **GOV-009 (Emergency Protocol)** -- `decision-forum/src/emergency.rs` handles ratification tracking and frequency monitoring.

### Needs Spec Work (Partial Implementation, Spec Gaps)

6. **GOV-001 (Constitutional Framework)** -- Two incompatible Constitution types exist across `exo-governance` and `decision-forum`. Must unify. Custom constraints default to pass-through (must be default-deny). No dry-run mode.
7. **GOV-002 (Constitutional Versioning)** -- Temporal binding exists at creation but not at each lifecycle event. Amendments not routed through Decision Object pipeline.
8. **GOV-004 (Sunset and Renewal)** -- Hard expiry exists but no max-12-month enforcement, no notification system, no sunset calendar.
9. **GOV-006 (Conflict Resolution)** -- Precedence hierarchy defined but not enforced in constraint evaluation order. No conflict register.
10. **GOV-007 (Human Oversight)** -- Type-level distinction exists but AI delegation constraints (90-day max, no GrantDelegation) not enforced.
11. **GOV-010 (Graceful Degradation)** -- No DEGRADED_GOVERNANCE mode exists anywhere.
12. **GOV-012 (Accountability)** -- No accountability-specific Decision Object subtypes.
13. **GOV-013 (Recursive Self-Governance)** -- No governance simulator, no compile-time enforcement of self-modification routing.
14. **TNC-04 (Synchronous Enforcement)** -- Synchronous by convention, not by type system. Custom constraints pass silently.
15. **TNC-07 (Quorum)** -- Checked at seal time, not before vote as spec requires.

### Architecturally Unsound (Requires Redesign)

16. **Axiom 5 / TNC-01 (Cryptographic Provenance)** -- **P0 CRITICAL.** Signature verification is structural (non-empty check) not cryptographic. Neither `exo-authority/src/chain.rs` nor `decision-forum/src/tnc_enforcer.rs` calls `ed25519_dalek::VerifyingKey::verify()`. This means a chain with fabricated signatures passes verification. This violates the foundational axiom that authority without cryptographically verifiable provenance is void. **Must be fixed before any production deployment.**
17. **GOV-011 (Succession)** -- **Zero implementation.** No crate, no struct, no method addresses succession or continuity. This is a hard governance requirement for any system claiming sovereign stewardship.
18. **TNC-08 (Immutability After Terminal)** -- Asserted but not enforced. `DecisionObject` is a mutable struct with no type-level freeze mechanism. Any code with a `&mut DecisionObject` can modify terminal decisions. Requires a `FrozenDecisionObject` wrapper or ownership-consuming terminal transition.
19. **Schema Divergence** -- `decision-forum/src/decision_object.rs` contains duplicate `DecisionClass` enum definitions and two overlapping schema designs that will not compile cleanly. This must be unified with `exo-governance/src/types.rs` before integration.

### Priority Actions

1. **Immediate (P0):** Implement actual Ed25519 signature verification in `verify_chain()` and TNC-01.
2. **Immediate (P0):** Unify the two Constitution/DecisionClass schemas between `exo-governance` and `decision-forum`.
3. **Week 1:** Change `ConstraintExpression::Custom` from default-pass to default-deny.
4. **Week 1:** Add type-level immutability for terminal Decision Objects.
5. **Week 2:** Implement succession registry (GOV-011).
6. **Week 2:** Add DEGRADED_GOVERNANCE mode (GOV-010).
7. **Week 3:** Implement governance simulator for GOV-013.
8. **Week 3:** Add AI delegation constraints (90-day max, no GrantDelegation).

---

*End of Governance Panel Assessment*
