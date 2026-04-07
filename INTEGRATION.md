# EXOCHAIN WASM Integration Contract

## Overview

The EXOCHAIN WASM bridge compiles the Rust CGR kernel (16 crates) into a WebAssembly module consumed by both CommandBase.ai (Node.js) and the Decision Forum (React/Vite). Every exported function calls real Rust crate logic -- zero stubs. The bridge exposes 110 functions across 9 binding modules, providing JavaScript consumers with deterministic, cryptographically verified governance operations.

## Bridge Architecture

- **Rust source:** `crates/exochain-wasm/src/` (9 binding modules)
- **WASM binary:** `packages/exochain-wasm/wasm/`
- **JS consumers:** `command-base/app/services/exochain.js`, `web/`

## Binding Modules (110 functions)

### Core Bindings (14 functions)
Source: `crates/exochain-wasm/src/core_bindings.rs`

1. `wasm_hash_bytes` -- BLAKE3 hash of raw bytes
2. `wasm_hash_structured` -- BLAKE3 hash of structured JSON
3. `wasm_merkle_root` -- Compute Merkle root from leaf hashes
4. `wasm_generate_keypair` -- Generate Ed25519 keypair (public key only returned)
5. `wasm_sign_with_ephemeral_key` -- Sign with ephemeral Ed25519 keypair (key never crosses boundary)
6. `wasm_sign` -- Sign a message with a secret key
7. `wasm_verify` -- Verify an Ed25519 signature
8. `wasm_merkle_proof` -- Compute Merkle inclusion proof for a leaf
9. `wasm_verify_merkle_proof` -- Verify a Merkle inclusion proof
10. `wasm_compute_event_id` -- Generate a fresh event correlation ID
11. `wasm_verify_event` -- Verify Ed25519 signature on a signed event
12. `wasm_bcts_valid_transitions` -- List valid BCTS state transitions
13. `wasm_bcts_is_terminal` -- Check if a BCTS state is terminal (Closed/Denied)
14. `wasm_create_signed_event` -- Create and sign a governance event

### Identity Bindings (7 functions)
Source: `crates/exochain-wasm/src/identity_bindings.rs`

1. `wasm_shamir_split` -- Split a secret using Shamir's Secret Sharing
2. `wasm_shamir_reconstruct` -- Reconstruct a secret from Shamir shares
3. `wasm_pace_resolve` -- Resolve PACE operator for current state
4. `wasm_pace_escalate` -- Escalate PACE state (Primary -> Alternate -> Contingency -> Emergency)
5. `wasm_pace_deescalate` -- De-escalate PACE state
6. `wasm_is_expired` -- Check if a risk attestation has expired
7. `wasm_assess_risk` -- Assess risk for an identity (creates signed risk attestation)

### Consent Bindings (4 functions)
Source: `crates/exochain-wasm/src/consent_bindings.rs`

1. `wasm_propose_bailment` -- Propose a new bailment (consent-conditioned data sharing)
2. `wasm_bailment_is_active` -- Check if a bailment is currently active
3. `wasm_accept_bailment` -- Accept a proposed bailment (bailee countersigns)
4. `wasm_terminate_bailment` -- Terminate an active bailment

### Authority Bindings (4 functions)
Source: `crates/exochain-wasm/src/authority_bindings.rs`

1. `wasm_build_authority_chain` -- Build and validate an authority chain from delegation links
2. `wasm_build_authority_chain_with_depth` -- Build authority chain with depth limit
3. `wasm_has_permission` -- Check if an authority chain has a specific permission
4. `wasm_verify_authority_chain` -- Verify an authority chain against a public-key lookup table

### Gatekeeper Bindings (5 functions)
Source: `crates/exochain-wasm/src/gatekeeper_bindings.rs`

1. `wasm_reduce_combinator` -- Reduce a CGR combinator expression with input
2. `wasm_enforce_invariants` -- Enforce all constitutional invariants against context
3. `wasm_spawn_holon` -- Spawn a Holon (governed agent runtime)
4. `wasm_step_combinator` -- Step a combinator forward with input
5. `wasm_mcp_rules` -- Retrieve MCP (Model Context Protocol) rule descriptions

### Governance Bindings (13 functions)
Source: `crates/exochain-wasm/src/governance_bindings.rs`

1. `wasm_compute_quorum` -- Compute quorum result from approvals and policy
2. `wasm_check_clearance` -- Check clearance level for an actor on an action
3. `wasm_check_conflicts` -- Check for conflicts of interest
4. `wasm_audit_append` -- Append to a hash-chained audit log
5. `wasm_audit_verify` -- Verify integrity of an audit log's hash chain
6. `wasm_open_deliberation` -- Open a new deliberation on a proposal
7. `wasm_cast_vote` -- Cast a vote in a deliberation
8. `wasm_close_deliberation` -- Close a deliberation and compute its result
9. `wasm_activate_succession` -- Activate a succession plan with a trigger
10. `wasm_verify_independence` -- Verify actor independence (Sybil resistance)
11. `wasm_detect_coordination` -- Detect coordination patterns in timestamped actions
12. `wasm_file_governance_challenge` -- File a governance challenge
13. `wasm_conflict_enforce` -- Enforcing conflict gate (blocks voting if actor must recuse)

### Escalation Bindings (8 functions)
Source: `crates/exochain-wasm/src/escalation_bindings.rs`

1. `wasm_evaluate_signals` -- Evaluate detection signals and produce threat assessment
2. `wasm_escalate` -- Escalate a detection signal to create a case
3. `wasm_record_feedback` -- Record feedback on an escalation case (learning loop)
4. `wasm_apply_learnings` -- Apply learnings from feedback to generate policy recommendations
5. `wasm_check_completeness` -- Check completeness of an escalation case
6. `wasm_triage` -- Triage a threat assessment to produce a response decision
7. `wasm_cases_by_priority` -- Sort escalation cases by priority (highest first)
8. `wasm_validate_kanban_column` -- Validate a kanban column value

### Legal Bindings (12 functions)
Source: `crates/exochain-wasm/src/legal_bindings.rs`

1. `wasm_create_evidence` -- Create a new piece of evidence with chain of custody
2. `wasm_verify_chain_of_custody` -- Verify chain of custody for evidence
3. `wasm_check_fiduciary_duty` -- Check fiduciary duty compliance
4. `wasm_ediscovery_search` -- Search evidence corpus (eDiscovery)
5. `wasm_assert_privilege` -- Assert a legal privilege over an evidence item
6. `wasm_challenge_privilege` -- File a challenge to a privilege assertion
7. `wasm_create_record` -- Create a new legal record from raw data
8. `wasm_apply_retention` -- Apply retention policy to records
9. `wasm_initiate_safe_harbor` -- Initiate a DGCL S144 safe harbor process
10. `wasm_complete_disclosure` -- Record material-facts disclosure for safe harbor
11. `wasm_record_disinterested_vote` -- Record a disinterested-party vote on safe harbor
12. `wasm_verify_safe_harbor` -- Verify safe harbor meets all S144 requirements

### Decision Forum Bindings (43 functions)
Source: `crates/exochain-wasm/src/decision_forum_bindings.rs`

**Decision Object Lifecycle (9)**
1. `wasm_create_decision` -- Create a new DecisionObject with BCTS lifecycle
2. `wasm_transition_decision` -- Transition a DecisionObject to a new BCTS state
3. `wasm_add_vote` -- Add a vote to a DecisionObject
4. `wasm_add_evidence` -- Add evidence to a DecisionObject
5. `wasm_decision_is_terminal` -- Check if a DecisionObject is in a terminal state
6. `wasm_decision_content_hash` -- Compute content hash (audit fingerprint)
7. `wasm_file_challenge` -- File a challenge against a decision (GOV-008)
8. `wasm_propose_accountability` -- Propose an accountability action (GOV-012)
9. `wasm_workflow_stages` -- Get all BCTS state names in lifecycle order

**Constitution (3)**
10. `wasm_ratify_constitution` -- Ratify a constitutional corpus with Ed25519 signatures
11. `wasm_amend_constitution` -- Amend a constitutional corpus
12. `wasm_dry_run_amendment` -- Dry-run a constitutional amendment (conflict check)

**TNC Enforcement (12)**
13. `wasm_enforce_tnc_01` -- Authority chain cryptographically verified
14. `wasm_enforce_tnc_02` -- Human gate satisfied
15. `wasm_enforce_tnc_03` -- Consent verified
16. `wasm_enforce_tnc_04` -- Identity verified
17. `wasm_enforce_tnc_05` -- Delegation expiry enforced
18. `wasm_enforce_tnc_06` -- Constitutional binding valid
19. `wasm_enforce_tnc_07` -- Quorum verified
20. `wasm_enforce_tnc_08` -- Terminal decisions immutable
21. `wasm_enforce_tnc_09` -- AI delegation ceiling enforced
22. `wasm_enforce_tnc_10` -- Evidence bundle complete
23. `wasm_enforce_all_tnc` -- Enforce all 10 TNCs (short-circuit)
24. `wasm_collect_tnc_violations` -- Collect all TNC violations (no short-circuit)

**Human Gate (5)**
25. `wasm_enforce_human_gate` -- Enforce human approval gate on a decision
26. `wasm_requires_human_approval` -- Check if decision class requires human approval
27. `wasm_ai_within_ceiling` -- Check if decision class is within AI delegation ceiling
28. `wasm_is_human_vote` -- Check if a vote was cast by a human actor
29. `wasm_is_ai_vote` -- Check if a vote was cast by an AI agent

**Quorum (2)**
30. `wasm_check_quorum` -- Check quorum requirement for a decision
31. `wasm_verify_quorum_precondition` -- Verify enough eligible voters exist

**Emergency Protocol (4)**
32. `wasm_create_emergency_action` -- Create an emergency action under policy
33. `wasm_ratify_emergency` -- Ratify an emergency action with a governance decision
34. `wasm_check_expiry` -- Check if ratification window has expired
35. `wasm_needs_governance_review` -- Check if emergency frequency requires review

**Contestation (3)**
36. `wasm_begin_review` -- Move challenge from Filed to UnderReview
37. `wasm_withdraw_challenge` -- Withdraw a challenge
38. `wasm_is_contested` -- Check if a decision is currently contested

**Accountability (4)**
39. `wasm_begin_due_process` -- Move accountability action to DueProcess
40. `wasm_enact_accountability` -- Enact an accountability action
41. `wasm_reverse_accountability` -- Reverse an enacted accountability action
42. `wasm_is_due_process_expired` -- Check if due-process deadline has passed

**Forum Authority (1)**
43. `wasm_verify_forum_authority` -- Verify integrity of a ForumAuthority object

## Building

```bash
wasm-pack build crates/exochain-wasm --target nodejs --out-dir ../../packages/exochain-wasm/wasm
```

## Testing

```bash
node packages/exochain-wasm/test/bridge_verification.mjs
```

## CI Quality Gates

- **Gate 20:** WASM build + 110-export verification
- **Gate 21:** Bridge verification (110/110 functions)
- **Gate 22:** Rust/JS export sync check
