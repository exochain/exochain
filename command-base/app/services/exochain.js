'use strict';

/**
 * ExoChain Service Layer
 *
 * Wraps all WASM exports from lib/exochain/exochain_wasm into named,
 * documented JavaScript functions organized by governance domain.
 *
 * Usage:
 *   const exochain = require('./services/exochain');
 *   const decision = exochain.createDecision(title, 'Operational', constitutionHash);
 *
 * Every function throws on WASM error — callers are responsible for try/catch.
 * JSON serialization helpers are used internally; callers pass plain JS objects.
 */

const wasm = require('../../packages/exochain-wasm/wasm');

// ── Internal helpers ─────────────────────────────────────────────────────────

/**
 * Serialize a value to a JSON string for WASM consumption.
 * Always calls JSON.stringify so that string enum values like 'Closed' become '"Closed"'
 * (the JSON representation the WASM parser expects), and objects become their JSON form.
 */
function s(v) {
  return JSON.stringify(v);
}

/** Convert a string or Buffer to Uint8Array. */
function toBytes(v) {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v);
  return new Uint8Array(Buffer.from(v));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 1: DECISION LIFECYCLE (BCTS — Bailment-Conditioned Transaction Set)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Create a new DecisionObject with full BCTS lifecycle.
 * @param {string} title - Human-readable title
 * @param {string} decisionClass - DecisionClass enum value ('Routine'|'Operational'|'Strategic'|'Constitutional')
 * @param {string} constitutionHashHex - Hex-encoded hash of the current constitutional corpus
 * @returns {object} DecisionObject
 */
function createDecision(title, decisionClass, constitutionHashHex) {
  return wasm.wasm_create_decision(title, s(decisionClass), constitutionHashHex);
}

/**
 * Transition a DecisionObject to a new BCTS state.
 * @param {object|string} decision - Current DecisionObject
 * @param {string} toState - Target DecisionState (e.g. 'Submitted', 'Approved')
 * @param {string} actorDid - DID of the actor performing the transition
 * @returns {object} Updated DecisionObject
 */
function transitionDecision(decision, toState, actorDid) {
  return wasm.wasm_transition_decision(s(decision), s(toState), actorDid);
}

/**
 * Check if a DecisionObject is in a terminal state (Closed, Denied, Remediated).
 * @param {object|string} decision
 * @returns {boolean}
 */
function decisionIsTerminal(decision) {
  return wasm.wasm_decision_is_terminal(s(decision));
}

/**
 * Compute the content hash of a DecisionObject (audit fingerprint).
 * @param {object|string} decision
 * @returns {string} Hex-encoded hash
 */
function decisionContentHash(decision) {
  return wasm.wasm_decision_content_hash(s(decision));
}

/**
 * Get all BCTS state names in lifecycle order.
 * @returns {string[]}
 */
function workflowStages() {
  return wasm.wasm_workflow_stages();
}

/**
 * Check if a BCTS state is terminal.
 * @param {string} state - BctsState value
 * @returns {boolean}
 */
function bctsIsTerminal(state) {
  return wasm.wasm_bcts_is_terminal(s(state));
}

/**
 * Get valid transitions from a BCTS state.
 * @param {string} state - BctsState value
 * @returns {string[]}
 */
function bctsValidTransitions(state) {
  return wasm.wasm_bcts_valid_transitions(s(state));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 2: VOTING
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Add a vote to a DecisionObject.
 * @param {object|string} decision
 * @param {object} vote - { voter: did, choice: 'Approve'|'Reject'|'Abstain', rationale?, signature?, timestamp_ms? }
 * @returns {object} Updated DecisionObject
 */
function addVote(decision, vote) {
  return wasm.wasm_add_vote(s(decision), s(vote));
}

/**
 * Add evidence to a DecisionObject.
 * @param {object|string} decision
 * @param {object} evidence - Evidence object
 * @returns {object} Updated DecisionObject
 */
function addEvidence(decision, evidence) {
  return wasm.wasm_add_evidence(s(decision), s(evidence));
}

/**
 * Return true if the given vote was cast by an AI agent.
 * @param {object|string} vote
 * @returns {boolean}
 */
function isAiVote(vote) {
  return wasm.wasm_is_ai_vote(s(vote));
}

/**
 * Return true if the given vote was cast by a human actor.
 * @param {object|string} vote
 * @returns {boolean}
 */
function isHumanVote(vote) {
  return wasm.wasm_is_human_vote(s(vote));
}

/**
 * Return true if the given decision is currently contested (has an active challenge).
 * @param {object[]|string} challenges - Array of Challenge objects
 * @param {string} decisionId
 * @returns {boolean}
 */
function isContested(challenges, decisionId) {
  return wasm.wasm_is_contested(s(challenges), decisionId);
}

/**
 * Cast a vote in a deliberation session.
 * @param {object|string} deliberation
 * @param {object} vote
 * @returns {object} Updated deliberation
 */
function castVote(deliberation, vote) {
  return wasm.wasm_cast_vote(s(deliberation), s(vote));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 3: QUORUM
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Check whether the quorum requirement for a decision is satisfied.
 * Returns { status, total_votes, approve_count, approve_pct } on Met,
 * or { status, reason } on NotMet / Degraded.
 * @param {object|string} registry - QuorumRegistry (policy + class configuration)
 * @param {object|string} decision
 * @returns {object}
 */
function checkQuorum(registry, decision) {
  return wasm.wasm_check_quorum(s(registry), s(decision));
}

/**
 * Verify quorum precondition — confirm enough eligible voters exist before voting opens.
 * @param {object|string} registry
 * @param {string} decisionClass - DecisionClass value
 * @param {number} eligibleVoters - Count of eligible voters
 * @returns {boolean}
 */
function verifyQuorumPrecondition(registry, decisionClass, eligibleVoters) {
  return wasm.wasm_verify_quorum_precondition(s(registry), s(decisionClass), eligibleVoters);
}

/**
 * Compute quorum result from a set of approvals and policy.
 * @param {object[]|string} approvals - Array of approval records
 * @param {object|string} policy - QuorumPolicy
 * @returns {object}
 */
function computeQuorum(approvals, policy) {
  return wasm.wasm_compute_quorum(s(approvals), s(policy));
}

/**
 * Return true if the given decision class requires human approval under the policy.
 * @param {object|string} policy - GovernancePolicy
 * @param {string} decisionClass - DecisionClass value
 * @returns {boolean}
 */
function requiresHumanApproval(policy, decisionClass) {
  return wasm.wasm_requires_human_approval(s(policy), s(decisionClass));
}

/**
 * Enforce the human gate — throws if human approval is required but not present.
 * @param {object|string} policy
 * @param {object|string} decision
 * @returns {object} Ok result or error
 */
function enforceHumanGate(policy, decision) {
  return wasm.wasm_enforce_human_gate(s(policy), s(decision));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 4: AUTHORITY CHAINS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Build and validate an authority chain from delegation links.
 * @param {object[]|string} links - Array of delegation link objects
 * @returns {object} AuthorityChain
 */
function buildAuthorityChain(links) {
  return wasm.wasm_build_authority_chain(s(links));
}

/**
 * Build authority chain with a maximum delegation depth limit.
 * @param {object[]|string} links
 * @param {number} maxDepth
 * @returns {object} AuthorityChain
 */
function buildAuthorityChainWithDepth(links, maxDepth) {
  return wasm.wasm_build_authority_chain_with_depth(s(links), maxDepth);
}

/**
 * Verify an authority chain against a public-key lookup table.
 * @param {object|string} chain - AuthorityChain
 * @param {bigint|number} nowMs - Current timestamp in milliseconds
 * @param {Array|string} keys - Array of [did_str, public_key_hex] pairs
 * @returns {{ ok: boolean, error?: string }}
 */
function verifyAuthorityChain(chain, nowMs, keys) {
  return wasm.wasm_verify_authority_chain(s(chain), BigInt(nowMs), s(keys));
}

/**
 * Check if an authority chain has a specific permission.
 * @param {object|string} chain - AuthorityChain
 * @param {string|object} permission - Permission enum value
 * @returns {boolean}
 */
function hasPermission(chain, permission) {
  return wasm.wasm_has_permission(s(chain), s(permission));
}

/**
 * Check clearance level for an actor on an action.
 * @param {string} actorDid
 * @param {string} action
 * @param {object|string} policy - ClearancePolicy
 * @returns {object} { status: 'Granted'|'Denied', ... }
 */
function checkClearance(actorDid, action, policy) {
  return wasm.wasm_check_clearance(actorDid, action, s(policy));
}

/**
 * Check for conflicts of interest for an actor.
 * @param {string} actorDid
 * @param {object|string} action
 * @param {object[]|string} declarations - Conflict-of-interest declarations
 * @returns {object} { must_recuse: boolean, conflicts: [] }
 */
function checkConflicts(actorDid, action, declarations) {
  return wasm.wasm_check_conflicts(actorDid, s(action), s(declarations || []));
}

/**
 * Enforce conflict-of-interest rules.
 * @param {object|string} request
 * @returns {object}
 */
function conflictEnforce(request) {
  return wasm.wasm_conflict_enforce(s(request));
}

/**
 * Verify the integrity and authenticity of a ForumAuthority object.
 * @param {object|string} authority
 * @returns {object}
 */
function verifyForumAuthority(authority) {
  return wasm.wasm_verify_forum_authority(s(authority));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 5: CONSTITUTIONAL EVALUATION (TNC Enforcement)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Enforce all 10 TNCs — returns Ok or the first violation.
 * @param {object|string} decision
 * @param {object|string} flags - TncFlags
 * @returns {object}
 */
function enforceAllTnc(decision, flags) {
  return wasm.wasm_enforce_all_tnc(s(decision), s(flags));
}

/**
 * Collect all TNC violations without short-circuiting.
 * Returns { violations: [...] } — empty array means all TNCs pass.
 * @param {object|string} decision
 * @param {object|string} flags
 * @returns {{ violations: object[] }}
 */
function collectTncViolations(decision, flags) {
  return wasm.wasm_collect_tnc_violations(s(decision), s(flags));
}

/** TNC-01: authority chain cryptographically verified. */
function enforceTnc01(decision, flags) { return wasm.wasm_enforce_tnc_01(s(decision), s(flags)); }

/** TNC-02: human gate satisfied. */
function enforceTnc02(decision, flags) { return wasm.wasm_enforce_tnc_02(s(decision), s(flags)); }

/** TNC-03: consent verified. */
function enforceTnc03(decision, flags) { return wasm.wasm_enforce_tnc_03(s(decision), s(flags)); }

/** TNC-04: identity verified. */
function enforceTnc04(decision, flags) { return wasm.wasm_enforce_tnc_04(s(decision), s(flags)); }

/** TNC-05: delegation expiry enforced. */
function enforceTnc05(decision, flags) { return wasm.wasm_enforce_tnc_05(s(decision), s(flags)); }

/** TNC-06: constitutional binding valid. */
function enforceTnc06(decision, flags) { return wasm.wasm_enforce_tnc_06(s(decision), s(flags)); }

/** TNC-07: quorum verified. */
function enforceTnc07(decision, flags) { return wasm.wasm_enforce_tnc_07(s(decision), s(flags)); }

/** TNC-08: terminal decisions immutable. */
function enforceTnc08(decision, flags) { return wasm.wasm_enforce_tnc_08(s(decision), s(flags)); }

/** TNC-09: AI delegation ceiling enforced. */
function enforceTnc09(decision, flags) { return wasm.wasm_enforce_tnc_09(s(decision), s(flags)); }

/** TNC-10: evidence bundle complete. */
function enforceTnc10(decision, flags) { return wasm.wasm_enforce_tnc_10(s(decision), s(flags)); }

/**
 * Return true if the given decision class is within the AI delegation ceiling.
 * @param {object|string} policy
 * @param {string} decisionClass
 * @returns {boolean}
 */
function aiWithinCeiling(policy, decisionClass) {
  return wasm.wasm_ai_within_ceiling(s(policy), s(decisionClass));
}

/**
 * Enforce all constitutional invariants for a request.
 * @param {object|string} request
 * @returns {object} { invariants: [], violations: [] }
 */
function enforceInvariants(request) {
  return wasm.wasm_enforce_invariants(s(request));
}

/**
 * Amend a constitutional corpus by adding or updating an article.
 * @param {object|string} corpus - ConstitutionalCorpus
 * @param {object|string} amendment - Article object
 * @param {Array|string} signatures - Array of [did_str, signature_hex] pairs
 * @returns {object} Updated corpus
 */
function amendConstitution(corpus, amendment, signatures) {
  return wasm.wasm_amend_constitution(s(corpus), s(amendment), s(signatures));
}

/**
 * Ratify a constitutional corpus with a set of Ed25519 signatures.
 * @param {object|string} corpus
 * @param {Array|string} signatures - Array of [did_str, signature_hex] pairs
 * @param {object|string} quorum - { required_signatures, required_fraction_pct }
 * @param {bigint|number} timestampMs
 * @returns {object} Ratified corpus
 */
function ratifyConstitution(corpus, signatures, quorum, timestampMs) {
  return wasm.wasm_ratify_constitution(s(corpus), s(signatures), s(quorum), BigInt(timestampMs));
}

/**
 * Dry-run a constitutional amendment — returns conflict descriptions without modifying.
 * @param {object|string} corpus
 * @param {object|string} proposed - Proposed Article
 * @returns {object} { conflicts: string[] }
 */
function dryRunAmendment(corpus, proposed) {
  return wasm.wasm_dry_run_amendment(s(corpus), s(proposed));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 6: HASH-CHAIN OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Hash raw bytes with the canonical ExoChain hash function (SHA-256).
 * @param {Uint8Array|Buffer|string} data
 * @returns {string} Hex-encoded hash
 */
function hashBytes(data) {
  return wasm.wasm_hash_bytes(toBytes(data));
}

/**
 * Hash a structured JSON value (canonical ExoChain content hash).
 * @param {object|string} data
 * @returns {string} Hex-encoded hash
 */
function hashStructured(data) {
  return wasm.wasm_hash_structured(s(data));
}

/**
 * Compute a Merkle root from an array of leaf hashes.
 * @param {string[]|string} leavesJson - JSON array of 32-byte leaf hashes as hex strings
 * @returns {string} Hex-encoded root hash
 */
function merkleRoot(leavesJson) {
  return wasm.wasm_merkle_root(s(leavesJson));
}

/**
 * Compute a Merkle inclusion proof for the leaf at `index`.
 * @param {string[]|string} leavesJson - JSON array of hex leaf hashes
 * @param {number} index
 * @returns {string[]} Proof path (hex sibling hashes)
 */
function merkleProof(leavesJson, index) {
  return wasm.wasm_merkle_proof(s(leavesJson), index);
}

/**
 * Verify a Merkle inclusion proof.
 * @param {string} rootHex - Hex-encoded root hash
 * @param {string} leafHex - Hex-encoded leaf hash
 * @param {string[]|string} proofJson - JSON array of hex sibling hashes
 * @param {number} index - Position of the leaf
 * @returns {boolean}
 */
function verifyMerkleProof(rootHex, leafHex, proofJson, index) {
  return wasm.wasm_verify_merkle_proof(rootHex, leafHex, s(proofJson), index);
}

/**
 * Generate a fresh event correlation ID.
 * @returns {string} UUID-like event ID
 */
function computeEventId() {
  return wasm.wasm_compute_event_id();
}

/**
 * Append an entry to the hash-chained audit log.
 * @param {string} actorDid
 * @param {string} action - Action type string
 * @param {string} result - 'success' | 'failure' | other
 * @param {string} evidenceHashHex - Hex-encoded evidence hash (use '0'.repeat(64) if none)
 * @returns {object} { entries: number, head_hash: string }
 */
function auditAppend(actorDid, action, result, evidenceHashHex) {
  return wasm.wasm_audit_append(actorDid, action, result, evidenceHashHex || '0'.repeat(64));
}

/**
 * Verify the integrity of a hash-chained audit log.
 * @param {object[]|string} entries - Array of audit entries
 * @returns {object} { intact: boolean, error?: string }
 */
function auditVerify(entries) {
  return wasm.wasm_audit_verify(s(entries));
}

/**
 * Get the MCP (Multi-Chain Protocol) governance rules.
 * @returns {object}
 */
function mcpRules() {
  return wasm.wasm_mcp_rules();
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 7: IDENTITY VERIFICATION (PACE, Shamir, Risk, Sybil)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Generate an Ed25519 keypair and return only the public key.
 * The secret key never crosses the Rust/JS boundary.
 * @returns {{ public_key: string }}
 */
function generateKeypair() {
  return wasm.wasm_generate_keypair();
}

/**
 * Sign a message with a known secret key (hex-encoded).
 * @param {Uint8Array|Buffer|string} message
 * @param {string} secretHex - Hex-encoded 32-byte Ed25519 secret key
 * @returns {string} Hex-encoded signature
 */
function sign(message, secretHex) {
  return wasm.wasm_sign(toBytes(message), secretHex);
}

/**
 * Sign a message with an ephemeral Ed25519 keypair.
 * The secret key is zeroized in Rust; caller receives { signature, public_key }.
 * @param {Uint8Array|Buffer|string} message
 * @returns {{ signature: string, public_key: string }}
 */
function signWithEphemeralKey(message) {
  return wasm.wasm_sign_with_ephemeral_key(toBytes(message));
}

/**
 * Verify an Ed25519 signature.
 * @param {Uint8Array|Buffer|string} message
 * @param {string|object} signatureJson - Signature JSON or hex
 * @param {string} publicHex - Hex-encoded 32-byte public key
 * @returns {boolean}
 */
function verify(message, signatureJson, publicHex) {
  return wasm.wasm_verify(toBytes(message), s(signatureJson), publicHex);
}

/**
 * Create a signed event with a known secret key.
 * @param {string|object} eventTypeJson - EventType enum value
 * @param {Uint8Array|Buffer|string} payload
 * @param {string} sourceDid
 * @param {string} secretHex
 * @returns {object} Signed Event
 */
function createSignedEvent(eventTypeJson, payload, sourceDid, secretHex) {
  return wasm.wasm_create_signed_event(s(eventTypeJson), toBytes(payload), sourceDid, secretHex);
}

/**
 * Verify the Ed25519 signature on a signed event.
 * @param {object|string} eventJson - Signed Event
 * @param {string} publicHex - Hex-encoded 32-byte public key of the event source
 * @returns {boolean}
 */
function verifyEvent(eventJson, publicHex) {
  return wasm.wasm_verify_event(s(eventJson), publicHex);
}

/**
 * Resolve the PACE operator for the current continuity state.
 * @param {object|string} config - PaceConfig
 * @param {object|string} state - PaceState
 * @returns {object} Resolved operator
 */
function paceResolve(config, state) {
  return wasm.wasm_pace_resolve(s(config), s(state));
}

/**
 * Escalate PACE state: Primary → Alternate → Contingency → Emergency.
 * @param {object|string} state - PaceState
 * @returns {object} New PaceState
 */
function paceEscalate(state) {
  return wasm.wasm_pace_escalate(s(state));
}

/**
 * De-escalate PACE state: Emergency → Contingency → Alternate → Normal.
 * @param {object|string} state
 * @returns {object} New PaceState
 */
function paceDeescalate(state) {
  return wasm.wasm_pace_deescalate(s(state));
}

/**
 * Split a secret using Shamir's Secret Sharing.
 * @param {Uint8Array|Buffer|string} secret
 * @param {number} threshold - Minimum shares needed to reconstruct
 * @param {number} shares - Total number of shares to generate
 * @returns {object[]} Array of shares
 */
function shamirSplit(secret, threshold, shares) {
  return wasm.wasm_shamir_split(toBytes(secret), threshold, shares);
}

/**
 * Reconstruct a secret from Shamir shares.
 * @param {object[]|string} shares
 * @param {number} threshold
 * @param {number} totalShares
 * @returns {object} Reconstructed secret
 */
function shamirReconstruct(shares, threshold, totalShares) {
  return wasm.wasm_shamir_reconstruct(s(shares), threshold, totalShares);
}

/**
 * Assess risk for an identity (creates a signed risk attestation).
 * @param {string} subjectDid
 * @param {string} attesterDid
 * @param {Uint8Array|Buffer|string} evidence
 * @param {string} level - RiskLevel ('Low'|'Medium'|'High'|'Critical')
 * @param {bigint|number} validityMs - How long the attestation is valid
 * @returns {object} Signed RiskAttestation
 */
function assessRisk(subjectDid, attesterDid, evidence, level, validityMs) {
  return wasm.wasm_assess_risk(subjectDid, attesterDid, toBytes(evidence), s(level), BigInt(validityMs));
}

/**
 * Check whether a risk attestation has expired.
 * @param {object|string} attestation
 * @param {bigint|number} nowMs
 * @returns {boolean}
 */
function isExpired(attestation, nowMs) {
  return wasm.wasm_is_expired(s(attestation), BigInt(nowMs));
}

/**
 * Detect coordination patterns in a set of timestamped actions (Sybil detection).
 * @param {object[]|string} actions
 * @returns {object} { coordinated: boolean, clusters: [] }
 */
function detectCoordination(actions) {
  return wasm.wasm_detect_coordination(s(actions));
}

/**
 * Verify independence attestation.
 * @param {object|string} attestation
 * @returns {object}
 */
function verifyIndependence(attestation) {
  return wasm.wasm_verify_independence(s(attestation));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 8: DELIBERATION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Open a new deliberation session on a proposal.
 * @param {string} proposalHex - Hex-encoded raw proposal bytes
 * @param {string[]|string} participantsJson - JSON array of DID strings
 * @returns {object} Deliberation session
 */
function openDeliberation(proposalHex, participantsJson) {
  return wasm.wasm_open_deliberation(proposalHex, s(participantsJson));
}

/**
 * Close a deliberation session.
 * @param {object|string} deliberation
 * @returns {object}
 */
function closeDeliberation(deliberation) {
  return wasm.wasm_close_deliberation(s(deliberation));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 9: ESCALATION & CHALLENGE
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * File a challenge against a decision (contestation — GOV-008).
 * @param {string} challengerDid
 * @param {string} decisionId
 * @param {string|object} ground - ChallengeGround enum value
 * @param {string} evidenceHashHex
 * @returns {object} Challenge record
 */
function fileChallenge(challengerDid, decisionId, ground, evidenceHashHex) {
  return wasm.wasm_file_challenge(challengerDid, decisionId, s(ground), evidenceHashHex);
}

/**
 * File a governance-level challenge (against a hash rather than a decision ID).
 * @param {string} challengerDid
 * @param {string} targetHashHex
 * @param {string|object} ground
 * @param {Uint8Array|Buffer|string} evidence
 * @returns {object}
 */
function fileGovernanceChallenge(challengerDid, targetHashHex, ground, evidence) {
  return wasm.wasm_file_governance_challenge(challengerDid, targetHashHex, s(ground), toBytes(evidence || ''));
}

/**
 * Move a challenge from Filed → UnderReview.
 * @param {object|string} challenge
 * @returns {object} Updated challenge
 */
function beginReview(challenge) {
  return wasm.wasm_begin_review(s(challenge));
}

/**
 * Withdraw a challenge (Filed or UnderReview → Withdrawn).
 * @param {object|string} challenge
 * @returns {object}
 */
function withdrawChallenge(challenge) {
  return wasm.wasm_withdraw_challenge(s(challenge));
}

/**
 * Check completeness of an escalation case.
 * @param {object|string} escalationCase
 * @returns {object} { complete: boolean, missing: string[] }
 */
function checkCompleteness(escalationCase) {
  return wasm.wasm_check_completeness(s(escalationCase));
}

/**
 * Evaluate detection signals and produce threat assessment.
 * @param {object[]|string} signals
 * @returns {object} ThreatAssessment
 */
function evaluateSignals(signals) {
  return wasm.wasm_evaluate_signals(s(signals));
}

/**
 * Triage a threat assessment to produce a response decision.
 * @param {object|string} assessment - ThreatAssessment (from evaluateSignals)
 * @returns {{ level, actions, timeout_ms, escalation_path }}
 */
function triage(assessment) {
  return wasm.wasm_triage(s(assessment));
}

/**
 * Escalate a signal through a prioritized path.
 * @param {object|string} signal
 * @param {string[]|string} path - Escalation path (array of DID strings)
 * @returns {object}
 */
function escalate(signal, path) {
  return wasm.wasm_escalate(s(signal), s(path));
}

/**
 * Return cases sorted by priority.
 * @param {object[]|string} cases
 * @returns {object[]}
 */
function casesByPriority(cases) {
  return wasm.wasm_cases_by_priority(s(cases));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 10: ACCOUNTABILITY (GOV-012)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Propose an accountability action (GOV-012).
 * @param {string} targetDid
 * @param {string} proposerDid
 * @param {string|object} actionType - AccountabilityType ('Censure'|'Suspension'|'Revocation'|'Recall')
 * @param {string} reason
 * @param {string} evidenceHashHex
 * @returns {object} AccountabilityAction
 */
function proposeAccountability(targetDid, proposerDid, actionType, reason, evidenceHashHex) {
  return wasm.wasm_propose_accountability(targetDid, proposerDid, s(actionType), reason, evidenceHashHex);
}

/**
 * Move an accountability action from Proposed → DueProcess.
 * @param {object|string} action
 * @returns {object}
 */
function beginDueProcess(action) {
  return wasm.wasm_begin_due_process(s(action));
}

/**
 * Return true if the due-process deadline has passed.
 * @param {object|string} action
 * @param {bigint|number} nowMs
 * @returns {boolean}
 */
function isDueProcessExpired(action, nowMs) {
  return wasm.wasm_is_due_process_expired(s(action), BigInt(nowMs));
}

/**
 * Enact an accountability action after due process completes.
 * @param {object|string} action
 * @param {string} decisionId
 * @param {bigint|number} timestampMs
 * @returns {object}
 */
function enactAccountability(action, decisionId, timestampMs) {
  return wasm.wasm_enact_accountability(s(action), decisionId, BigInt(timestampMs));
}

/**
 * Reverse an enacted accountability action.
 * @param {object|string} action
 * @returns {object}
 */
function reverseAccountability(action) {
  return wasm.wasm_reverse_accountability(s(action));
}

/**
 * Create an emergency action under the given policy.
 * @param {string|object} actionType - EmergencyActionType
 * @param {string} actorDid
 * @param {string} justification
 * @param {bigint|number} monetaryCapCents - Monetary cap in cents (0 if N/A)
 * @param {string} evidenceHashHex
 * @param {object|string} policy
 * @param {bigint|number} timestampMs
 * @returns {object} EmergencyAction
 */
function createEmergencyAction(actionType, actorDid, justification, monetaryCapCents, evidenceHashHex, policy, timestampMs) {
  return wasm.wasm_create_emergency_action(
    s(actionType), actorDid, justification,
    BigInt(monetaryCapCents), evidenceHashHex,
    s(policy), BigInt(timestampMs)
  );
}

/**
 * Ratify an emergency action with a governance decision.
 * @param {object|string} action
 * @param {string} decisionId
 * @param {bigint|number} timestampMs
 * @returns {object}
 */
function ratifyEmergency(action, decisionId, timestampMs) {
  return wasm.wasm_ratify_emergency(s(action), decisionId, BigInt(timestampMs));
}

/**
 * Check whether an emergency action's ratification window has expired.
 * @param {object|string} action
 * @param {bigint|number} nowMs
 * @returns {boolean}
 */
function checkExpiry(action, nowMs) {
  return wasm.wasm_check_expiry(s(action), BigInt(nowMs));
}

/**
 * Return true if the emergency action history requires a governance review.
 * @param {object[]|string} actions
 * @param {object|string} policy
 * @returns {boolean}
 */
function needsGovernanceReview(actions, policy) {
  return wasm.wasm_needs_governance_review(s(actions), s(policy));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 11: EVIDENCE & PROVENANCE
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Create a new piece of evidence with chain of custody.
 * @param {Uint8Array|Buffer|string} content
 * @param {string} typeTag - e.g. 'document', 'log', 'screenshot'
 * @param {string} creatorDid
 * @returns {object} Evidence record with chain of custody
 */
function createEvidence(content, typeTag, creatorDid) {
  return wasm.wasm_create_evidence(toBytes(content), typeTag, creatorDid);
}

/**
 * Verify the chain of custody for a piece of evidence.
 * @param {object|string} evidence
 * @returns {object} { valid: boolean, violations: [] }
 */
function verifyChainOfCustody(evidence) {
  return wasm.wasm_verify_chain_of_custody(s(evidence));
}

/**
 * Search evidence corpus (eDiscovery).
 * @param {object|string} request - eDiscovery search request
 * @param {object[]|string} corpus - Evidence corpus to search
 * @returns {object[]} Matching evidence items
 */
function ediscoverySearch(request, corpus) {
  return wasm.wasm_ediscovery_search(s(request), s(corpus));
}

/**
 * Check fiduciary duty compliance.
 * @param {object|string} duty - FiduciaryDuty spec
 * @param {object[]|string} actions - Array of actions to evaluate
 * @returns {object} { compliant: boolean, violations: [] }
 */
function checkFiduciaryDuty(duty, actions) {
  return wasm.wasm_check_fiduciary_duty(s(duty), s(actions));
}

/**
 * Create a new legal record from raw data.
 * @param {Uint8Array|Buffer|string} data
 * @param {string} classification - e.g. 'Public', 'Confidential', 'Restricted'
 * @param {bigint|number} retentionDays
 * @returns {object} Legal record
 */
function createRecord(data, classification, retentionDays) {
  return wasm.wasm_create_record(toBytes(data), classification, BigInt(retentionDays));
}

/**
 * Apply retention policy to a set of records, updating disposition fields.
 * @param {object[]|string} records
 * @param {object|string} policy - RetentionPolicy
 * @param {bigint|number} nowMs
 * @returns {object[]} Updated records
 */
function applyRetention(records, policy, nowMs) {
  return wasm.wasm_apply_retention(s(records), s(policy), BigInt(nowMs));
}

/**
 * Assert a legal privilege over an evidence item.
 * @param {string} evidenceId
 * @param {string|object} privilegeType - PrivilegeType enum
 * @param {string} asserterDid
 * @param {string} basis - Legal basis for the privilege claim
 * @returns {object} PrivilegeAssertion
 */
function assertPrivilege(evidenceId, privilegeType, asserterDid, basis) {
  return wasm.wasm_assert_privilege(evidenceId, s(privilegeType), asserterDid, basis);
}

/**
 * File a challenge to a privilege assertion.
 * @param {object|string} assertion - PrivilegeAssertion
 * @param {string} challengerDid
 * @param {string} grounds
 * @returns {object}
 */
function challengePrivilege(assertion, challengerDid, grounds) {
  return wasm.wasm_challenge_privilege(s(assertion), challengerDid, grounds);
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 12: CONSENT & BAILMENT
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Propose a new bailment (consent-conditioned data sharing).
 * @param {string} bailorDid
 * @param {string} baileeDid
 * @param {Uint8Array|Buffer|string} terms
 * @param {string|object} bailmentType - BailmentType enum
 * @returns {object} Proposed bailment
 */
function proposeBailment(bailorDid, baileeDid, terms, bailmentType) {
  return wasm.wasm_propose_bailment(bailorDid, baileeDid, toBytes(terms), s(bailmentType));
}

/**
 * Accept a proposed bailment (bailee countersigns, status → Active).
 * @param {object|string} bailment
 * @param {string|object} signatureJson - Ed25519 Signature from the bailee
 * @returns {object}
 */
function acceptBailment(bailment, signatureJson) {
  return wasm.wasm_accept_bailment(s(bailment), s(signatureJson));
}

/**
 * Terminate an active bailment. Actor must be the bailor or bailee.
 * @param {object|string} bailment
 * @param {string} actorDid
 * @returns {object}
 */
function terminateBailment(bailment, actorDid) {
  return wasm.wasm_terminate_bailment(s(bailment), actorDid);
}

/**
 * Check if a bailment is currently active.
 * @param {object|string} bailment
 * @returns {boolean}
 */
function bailmentIsActive(bailment) {
  return wasm.wasm_bailment_is_active(s(bailment));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 13: SAFE HARBOR (DGCL §144)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Initiate a DGCL §144 safe harbor process for an interested-party transaction.
 * @param {string} interestedPartyDid
 * @param {string} counterpartyDid
 * @param {string} interestDescription
 * @param {string} termsHashHex
 * @param {object[]|string} pathJson - Approval path (array of DIDs)
 * @param {bigint|number} nowMs
 * @returns {object} SafeHarborTransaction
 */
function initiateSafeHarbor(interestedPartyDid, counterpartyDid, interestDescription, termsHashHex, pathJson, nowMs) {
  return wasm.wasm_initiate_safe_harbor(
    interestedPartyDid, counterpartyDid, interestDescription,
    termsHashHex, s(pathJson), BigInt(nowMs)
  );
}

/**
 * Record the material-facts disclosure for a safe harbor transaction.
 * @param {object|string} txn - SafeHarborTransaction
 * @param {string} disclosedByDid
 * @param {string} materialFacts
 * @param {bigint|number} nowMs
 * @returns {object}
 */
function completeDisclosure(txn, disclosedByDid, materialFacts, nowMs) {
  return wasm.wasm_complete_disclosure(s(txn), disclosedByDid, materialFacts, BigInt(nowMs));
}

/**
 * Record a disinterested-party vote on a safe harbor transaction.
 * @param {object|string} txn
 * @param {string} voterDid
 * @param {boolean} approved
 * @param {bigint|number} nowMs
 * @returns {object}
 */
function recordDisinterestedVote(txn, voterDid, approved, nowMs) {
  return wasm.wasm_record_disinterested_vote(s(txn), voterDid, approved, BigInt(nowMs));
}

/**
 * Verify that a safe harbor transaction meets all §144 requirements.
 * @param {object|string} txn
 * @returns {object} { valid: boolean, violations: [] }
 */
function verifySafeHarbor(txn) {
  return wasm.wasm_verify_safe_harbor(s(txn));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 14: HOLON & SUCCESSION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Spawn a new holon (autonomous governance agent).
 * @param {string} did
 * @param {object|string} program
 * @returns {object}
 */
function spawnHolon(did, program) {
  return wasm.wasm_spawn_holon(did, s(program));
}

/**
 * Activate a succession plan when a trigger condition is met.
 * @param {object|string} plan
 * @param {object|string} trigger
 * @param {bigint|number} nowMs
 * @returns {object}
 */
function activateSuccession(plan, trigger, nowMs) {
  return wasm.wasm_activate_succession(s(plan), s(trigger), BigInt(nowMs));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 15: LEARNING & FEEDBACK PIPELINE
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Apply learnings from a set of feedback entries.
 * @param {object[]|string} feedbacks
 * @returns {object}
 */
function applyLearnings(feedbacks) {
  return wasm.wasm_apply_learnings(s(feedbacks));
}

/**
 * Record a new feedback entry into the feedback log.
 * @param {object[]|string} entries - Existing feedback entries
 * @param {object|string} entry - New entry
 * @returns {object[]} Updated entries
 */
function recordFeedback(entries, entry) {
  return wasm.wasm_record_feedback(s(entries), s(entry));
}

/**
 * Validate a Kanban column definition against governance rules.
 * @param {object|string} column
 * @returns {object} { valid: boolean, errors: [] }
 */
function validateKanbanColumn(column) {
  return wasm.wasm_validate_kanban_column(s(column));
}

/**
 * Apply a step combinator transformation.
 * @param {object|string} combinator
 * @param {object|string} input
 * @returns {object}
 */
function stepCombinator(combinator, input) {
  return wasm.wasm_step_combinator(s(combinator), s(input));
}

/**
 * Apply a reduce combinator transformation.
 * @param {object|string} combinator
 * @param {object|string} input
 * @returns {object}
 */
function reduceCombinator(combinator, input) {
  return wasm.wasm_reduce_combinator(s(combinator), s(input));
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = {
  // § Decision Lifecycle
  createDecision,
  transitionDecision,
  decisionIsTerminal,
  decisionContentHash,
  workflowStages,
  bctsIsTerminal,
  bctsValidTransitions,

  // § Voting
  addVote,
  addEvidence,
  isAiVote,
  isHumanVote,
  isContested,
  castVote,

  // § Quorum
  checkQuorum,
  verifyQuorumPrecondition,
  computeQuorum,
  requiresHumanApproval,
  enforceHumanGate,

  // § Authority Chains
  buildAuthorityChain,
  buildAuthorityChainWithDepth,
  verifyAuthorityChain,
  hasPermission,
  checkClearance,
  checkConflicts,
  conflictEnforce,
  verifyForumAuthority,

  // § Constitutional Evaluation (TNC)
  enforceAllTnc,
  collectTncViolations,
  enforceTnc01,
  enforceTnc02,
  enforceTnc03,
  enforceTnc04,
  enforceTnc05,
  enforceTnc06,
  enforceTnc07,
  enforceTnc08,
  enforceTnc09,
  enforceTnc10,
  aiWithinCeiling,
  enforceInvariants,
  amendConstitution,
  ratifyConstitution,
  dryRunAmendment,

  // § Hash-Chain Operations
  hashBytes,
  hashStructured,
  merkleRoot,
  merkleProof,
  verifyMerkleProof,
  computeEventId,
  auditAppend,
  auditVerify,
  mcpRules,

  // § Identity Verification
  generateKeypair,
  sign,
  signWithEphemeralKey,
  verify,
  createSignedEvent,
  verifyEvent,
  paceResolve,
  paceEscalate,
  paceDeescalate,
  shamirSplit,
  shamirReconstruct,
  assessRisk,
  isExpired,
  detectCoordination,
  verifyIndependence,

  // § Deliberation
  openDeliberation,
  closeDeliberation,

  // § Escalation & Challenge
  fileChallenge,
  fileGovernanceChallenge,
  beginReview,
  withdrawChallenge,
  checkCompleteness,
  evaluateSignals,
  triage,
  escalate,
  casesByPriority,

  // § Accountability
  proposeAccountability,
  beginDueProcess,
  isDueProcessExpired,
  enactAccountability,
  reverseAccountability,
  createEmergencyAction,
  ratifyEmergency,
  checkExpiry,
  needsGovernanceReview,

  // § Evidence & Provenance
  createEvidence,
  verifyChainOfCustody,
  ediscoverySearch,
  checkFiduciaryDuty,
  createRecord,
  applyRetention,
  assertPrivilege,
  challengePrivilege,

  // § Consent & Bailment
  proposeBailment,
  acceptBailment,
  terminateBailment,
  bailmentIsActive,

  // § Safe Harbor
  initiateSafeHarbor,
  completeDisclosure,
  recordDisinterestedVote,
  verifySafeHarbor,

  // § Holon & Succession
  spawnHolon,
  activateSuccession,

  // § Learning & Feedback
  applyLearnings,
  recordFeedback,
  validateKanbanColumn,
  stepCombinator,
  reduceCombinator,
};
