/**
 * Bridge Verification Test — WASM binding smoke-test harness
 *
 * Calls every one of the 110 exported wasm_ functions with valid minimal
 * inputs and verifies each returns without throwing.
 *
 * Run:  node packages/exochain-wasm/test/bridge_verification.mjs
 */

import { createRequire } from 'node:module';
import { randomUUID }    from 'node:crypto';
const require = createRequire(import.meta.url);
const wasm = require('../wasm/exochain_wasm.js');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  try {
    const result = fn();
    passed++;
    console.log(`  PASS  ${name}`);
    return result;
  } catch (err) {
    failed++;
    const msg = err instanceof Error ? err.message : String(err);
    failures.push({ name, msg });
    console.log(`  FAIL  ${name}  -->  ${msg}`);
    return undefined;
  }
}

/** Safe setup call — returns undefined on throw instead of crashing. */
function setup(fn) {
  try { return fn(); } catch { return undefined; }
}

// Convenience constants
const ZERO_32_HEX   = '0'.repeat(64);
const ZERO_32_BYTES = Array.from({ length: 32 }, () => 0);
const TEST_DID      = 'did:exo:test-actor';
const TEST_DID_2    = 'did:exo:test-actor-2';
const TEST_DID_3    = 'did:exo:test-actor-3';
const NOW_MS        = BigInt(Date.now());
const NOW_NUM       = Number(NOW_MS);
const NOW_TS        = { physical_ms: NOW_NUM, logical: 0 };  // HLC Timestamp
const TEXT_BYTES     = new TextEncoder().encode('hello');
const DUMMY_SECRET_HEX = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';
const UUID_1 = randomUUID();
const UUID_2 = randomUUID();

// Pre-compute a valid Ed25519 keypair result for reuse
const ephResult = wasm.wasm_sign_with_ephemeral_key(TEXT_BYTES);

// =========================================================================
// Module 1 — BCTS (Bounded-Context Transition System)
// =========================================================================

console.log('\n--- BCTS ---');

test('wasm_bcts_valid_transitions', () =>
  wasm.wasm_bcts_valid_transitions(JSON.stringify('Draft')));

test('wasm_bcts_is_terminal', () =>
  wasm.wasm_bcts_is_terminal(JSON.stringify('Draft')));

test('wasm_workflow_stages', () =>
  wasm.wasm_workflow_stages());

// =========================================================================
// Module 2 — Crypto / Merkle
// =========================================================================

console.log('\n--- Crypto / Merkle ---');

test('wasm_hash_bytes', () =>
  wasm.wasm_hash_bytes(TEXT_BYTES));

test('wasm_hash_structured', () =>
  wasm.wasm_hash_structured(JSON.stringify({ foo: 'bar' })));

test('wasm_generate_keypair', () =>
  wasm.wasm_generate_keypair());

test('wasm_sign_with_ephemeral_key', () =>
  wasm.wasm_sign_with_ephemeral_key(TEXT_BYTES));

const leafHex = wasm.wasm_hash_bytes(TEXT_BYTES);
const leaf2Hex = wasm.wasm_hash_bytes(new TextEncoder().encode('world'));
const leavesJson = JSON.stringify([leafHex, leaf2Hex]);

test('wasm_merkle_root', () =>
  wasm.wasm_merkle_root(leavesJson));

test('wasm_merkle_proof', () =>
  wasm.wasm_merkle_proof(leavesJson, 0));

const root = wasm.wasm_merkle_root(leavesJson);
const proof = wasm.wasm_merkle_proof(leavesJson, 0);

test('wasm_verify_merkle_proof', () =>
  wasm.wasm_verify_merkle_proof(root, leafHex, JSON.stringify(proof), 0));

test('wasm_verify', () =>
  wasm.wasm_verify(TEXT_BYTES, JSON.stringify(ephResult.signature), ephResult.public_key));

test('wasm_sign', () =>
  wasm.wasm_sign(TEXT_BYTES, DUMMY_SECRET_HEX));

test('wasm_compute_event_id', () =>
  wasm.wasm_compute_event_id());

// =========================================================================
// Module 3 — Events
// =========================================================================

console.log('\n--- Events ---');

test('wasm_create_signed_event', () =>
  wasm.wasm_create_signed_event(
    JSON.stringify('AuditEntry'),
    TEXT_BYTES,
    TEST_DID,
    DUMMY_SECRET_HEX
  ));

const signedEvent = setup(() =>
  wasm.wasm_create_signed_event(
    JSON.stringify('AuditEntry'),
    TEXT_BYTES,
    TEST_DID,
    DUMMY_SECRET_HEX
  ));

test('wasm_verify_event', () => {
  if (!signedEvent) throw new Error('skipped -- no signed event from setup');
  const pubKey = signedEvent.public_key || signedEvent.source_public_key || ephResult.public_key;
  return wasm.wasm_verify_event(JSON.stringify(signedEvent), pubKey);
});

// =========================================================================
// Module 4 — Legal / Records / Evidence
// =========================================================================

console.log('\n--- Legal / Records / Evidence ---');

test('wasm_create_record', () =>
  wasm.wasm_create_record(TEXT_BYTES, 'Confidential', BigInt(365)));

test('wasm_apply_retention', () => {
  const rec = wasm.wasm_create_record(TEXT_BYTES, 'Confidential', BigInt(365));
  const policy = {
    default_retention_days: 365,
    rules: { Confidential: 365 }
  };
  return wasm.wasm_apply_retention(
    JSON.stringify([rec]),
    JSON.stringify(policy),
    NOW_MS
  );
});

test('wasm_create_evidence', () =>
  wasm.wasm_create_evidence(TEXT_BYTES, 'Document', TEST_DID));

const evidence = setup(() =>
  wasm.wasm_create_evidence(TEXT_BYTES, 'Document', TEST_DID));

test('wasm_verify_chain_of_custody', () => {
  if (!evidence) throw new Error('skipped -- no evidence from setup');
  return wasm.wasm_verify_chain_of_custody(JSON.stringify(evidence));
});

const evidenceId = (evidence && evidence.evidence_id) || UUID_1;

test('wasm_assert_privilege', () =>
  wasm.wasm_assert_privilege(
    evidenceId,
    JSON.stringify('AttorneyClient'),
    TEST_DID,
    'Legal advice communication'
  ));

const assertion = setup(() =>
  wasm.wasm_assert_privilege(
    evidenceId,
    JSON.stringify('AttorneyClient'),
    TEST_DID,
    'Legal advice communication'
  ));

test('wasm_challenge_privilege', () => {
  if (!assertion) throw new Error('skipped -- no privilege assertion from setup');
  return wasm.wasm_challenge_privilege(
    JSON.stringify(assertion),
    TEST_DID_2,
    'Crime-fraud exception'
  );
});

test('wasm_check_fiduciary_duty', () => {
  const duty = {
    principal_did: TEST_DID,
    fiduciary_did: TEST_DID_2,
    duty_type: 'Care',
    scope: 'all',
    created: NOW_TS
  };
  const actions = [{ actor: TEST_DID_2, action: 'vote', action_type: 'vote', timestamp: NOW_TS }];
  return wasm.wasm_check_fiduciary_duty(
    JSON.stringify(duty),
    JSON.stringify(actions)
  );
});

test('wasm_ediscovery_search', () => {
  const ts0 = { physical_ms: 0, logical: 0 };
  const request = {
    requester: TEST_DID,
    scope: 'all',
    date_range: [ts0, NOW_TS],
    custodians: [],
    search_terms: ['test']
  };
  const corpus = [];
  return wasm.wasm_ediscovery_search(
    JSON.stringify(request),
    JSON.stringify(corpus)
  );
});

// =========================================================================
// Module 5 — Safe Harbor (DGCL 144)
// =========================================================================

console.log('\n--- Safe Harbor ---');

test('wasm_initiate_safe_harbor', () =>
  wasm.wasm_initiate_safe_harbor(
    TEST_DID,
    TEST_DID_2,
    'Board member is counterparty',
    ZERO_32_HEX,
    JSON.stringify('BoardApproval'),
    NOW_MS
  ));

const shTxn = setup(() =>
  wasm.wasm_initiate_safe_harbor(
    TEST_DID,
    TEST_DID_2,
    'Board member is counterparty',
    ZERO_32_HEX,
    JSON.stringify('BoardApproval'),
    NOW_MS
  ));

test('wasm_complete_disclosure', () => {
  if (!shTxn) throw new Error('skipped -- no safe harbor txn from setup');
  return wasm.wasm_complete_disclosure(
    JSON.stringify(shTxn),
    TEST_DID,
    'All material facts disclosed',
    NOW_MS
  );
});

const disclosedTxn = setup(() =>
  shTxn && wasm.wasm_complete_disclosure(
    JSON.stringify(shTxn),
    TEST_DID,
    'All material facts disclosed',
    NOW_MS
  ));

test('wasm_record_disinterested_vote', () => {
  if (!disclosedTxn) throw new Error('skipped -- no disclosed txn from setup');
  return wasm.wasm_record_disinterested_vote(
    JSON.stringify(disclosedTxn),
    TEST_DID_3,
    true,
    NOW_MS
  );
});

test('wasm_verify_safe_harbor', () => {
  if (!shTxn) throw new Error('skipped -- no safe harbor txn from setup');
  return wasm.wasm_verify_safe_harbor(JSON.stringify(shTxn));
});

// =========================================================================
// Module 6 — Bailment
// =========================================================================

console.log('\n--- Bailment ---');

test('wasm_propose_bailment', () =>
  wasm.wasm_propose_bailment(
    TEST_DID,
    TEST_DID_2,
    TEXT_BYTES,
    JSON.stringify('Custody')
  ));

const bailment = setup(() =>
  wasm.wasm_propose_bailment(
    TEST_DID,
    TEST_DID_2,
    TEXT_BYTES,
    JSON.stringify('Custody')
  ));

test('wasm_bailment_is_active', () => {
  if (!bailment) throw new Error('skipped -- no bailment from setup');
  return wasm.wasm_bailment_is_active(JSON.stringify(bailment));
});

// Build the canonical bailment signing payload and sign it with a
// fresh ephemeral bailee keypair. Since GAP-012 landed (PR #109),
// `wasm_accept_bailment` cryptographically verifies this signature;
// arbitrary bytes no longer flip the bailment Active.
const bailPayload = bailment
  ? wasm.wasm_bailment_signing_payload(JSON.stringify(bailment))
  : null;
const bailSig = bailPayload
  ? wasm.wasm_sign_with_ephemeral_key(bailPayload)
  : null;

// `bailSig.public_key` is hex-encoded (see wasm_sign_with_ephemeral_key
// in core_bindings.rs). `exo_core::PublicKey` deserializes from a byte
// array of length 32. Convert hex → number array for the accept call.
const bailPubKeyBytes = bailSig
  ? Array.from(Buffer.from(bailSig.public_key, 'hex'))
  : null;

test('wasm_bailment_signing_payload', () => {
  if (!bailment) throw new Error('skipped -- no bailment from setup');
  return wasm.wasm_bailment_signing_payload(JSON.stringify(bailment));
});

test('wasm_accept_bailment', () => {
  if (!bailment || !bailSig) throw new Error('skipped -- no bailment from setup');
  return wasm.wasm_accept_bailment(
    JSON.stringify(bailment),
    JSON.stringify(bailPubKeyBytes),
    JSON.stringify(bailSig.signature)
  );
});

const activeBailment = setup(() =>
  (bailment && bailSig) && wasm.wasm_accept_bailment(
    JSON.stringify(bailment),
    JSON.stringify(bailPubKeyBytes),
    JSON.stringify(bailSig.signature)
  ));

test('wasm_terminate_bailment', () => {
  if (!activeBailment) throw new Error('skipped -- no active bailment from setup');
  return wasm.wasm_terminate_bailment(
    JSON.stringify(activeBailment),
    TEST_DID
  );
});

// =========================================================================
// Module 7 — Shamir Secret Sharing
// =========================================================================

console.log('\n--- Shamir ---');

test('wasm_shamir_split', () =>
  wasm.wasm_shamir_split(TEXT_BYTES, 2, 3));

const shares = setup(() => wasm.wasm_shamir_split(TEXT_BYTES, 2, 3));

test('wasm_shamir_reconstruct', () => {
  if (!shares) throw new Error('skipped -- no shares from setup');
  return wasm.wasm_shamir_reconstruct(JSON.stringify(shares), 2, 3);
});

// =========================================================================
// Module 8 — PACE
// =========================================================================

console.log('\n--- PACE ---');

test('wasm_pace_escalate', () =>
  wasm.wasm_pace_escalate(JSON.stringify('Normal')));

test('wasm_pace_deescalate', () =>
  wasm.wasm_pace_deescalate(JSON.stringify('EmergencyActive')));

test('wasm_pace_resolve', () => {
  // primary is a single Did; alternates, contingency, emergency are arrays
  const config = {
    primary: TEST_DID,
    alternates: [TEST_DID_2],
    contingency: [TEST_DID_2],
    emergency: [TEST_DID_3]
  };
  return wasm.wasm_pace_resolve(
    JSON.stringify(config),
    JSON.stringify('Normal')
  );
});

// =========================================================================
// Module 9 — Risk Assessment
// =========================================================================

console.log('\n--- Risk Assessment ---');

test('wasm_assess_risk', () =>
  wasm.wasm_assess_risk(
    TEST_DID,
    TEST_DID_2,
    TEXT_BYTES,
    JSON.stringify('Low'),
    BigInt(3600000)
  ));

const riskAttestation = setup(() =>
  wasm.wasm_assess_risk(
    TEST_DID,
    TEST_DID_2,
    TEXT_BYTES,
    JSON.stringify('Low'),
    BigInt(3600000)
  ));

test('wasm_is_expired', () => {
  if (!riskAttestation) throw new Error('skipped -- no attestation from setup');
  return wasm.wasm_is_expired(JSON.stringify(riskAttestation), NOW_MS);
});

// =========================================================================
// Module 10 — Authority Chain
// =========================================================================

console.log('\n--- Authority Chain ---');

const dummyLink = {
  delegator_did: TEST_DID,
  delegate_did: TEST_DID_2,
  scope: ['Read'],
  created: NOW_TS,
  expires: null,
  signature: ephResult.signature,
  depth: 0
};

test('wasm_build_authority_chain', () =>
  wasm.wasm_build_authority_chain(JSON.stringify([dummyLink])));

test('wasm_build_authority_chain_with_depth', () =>
  wasm.wasm_build_authority_chain_with_depth(JSON.stringify([dummyLink]), 5));

const chain = setup(() =>
  wasm.wasm_build_authority_chain(JSON.stringify([dummyLink])));

test('wasm_has_permission', () => {
  if (!chain) throw new Error('skipped -- no chain from setup');
  return wasm.wasm_has_permission(
    JSON.stringify(chain),
    JSON.stringify('Read')
  );
});

test('wasm_verify_authority_chain', () => {
  if (!chain) throw new Error('skipped -- no chain from setup');
  return wasm.wasm_verify_authority_chain(
    JSON.stringify(chain),
    NOW_MS,
    JSON.stringify([])
  );
});

// =========================================================================
// Module 11 — Threat Detection / Escalation
// =========================================================================

console.log('\n--- Threat Detection / Escalation ---');

test('wasm_evaluate_signals', () =>
  wasm.wasm_evaluate_signals(JSON.stringify([])));

test('wasm_escalate', () => {
  const signal = {
    source: TEST_DID,
    signal_type: 'AnomalousPattern',
    confidence: 80,
    evidence_hash: ZERO_32_BYTES,
    timestamp: NOW_TS
  };
  // EscalationPath is an enum: Standard, SybilAdjudication, Emergency, Constitutional
  const path = JSON.stringify('Standard');
  return wasm.wasm_escalate(JSON.stringify(signal), path);
});

const escCase = setup(() => {
  const signal = {
    source: TEST_DID,
    signal_type: 'AnomalousPattern',
    confidence: 80,
    evidence_hash: ZERO_32_BYTES,
    timestamp: NOW_TS
  };
  // EscalationPath is an enum: Standard, SybilAdjudication, Emergency, Constitutional
  const path = JSON.stringify('Standard');
  return wasm.wasm_escalate(JSON.stringify(signal), path);
});

test('wasm_check_completeness', () => {
  if (!escCase) throw new Error('skipped -- no case from setup');
  return wasm.wasm_check_completeness(JSON.stringify(escCase));
});

test('wasm_cases_by_priority', () => {
  if (!escCase) throw new Error('skipped -- no case from setup');
  return wasm.wasm_cases_by_priority(JSON.stringify([escCase]));
});

test('wasm_validate_kanban_column', () =>
  wasm.wasm_validate_kanban_column(JSON.stringify('Triage')));

test('wasm_record_feedback', () => {
  const entry = {
    case_id: UUID_1,
    outcome: 'TruePositive',
    lessons_learned: 'Pattern confirmed',
    policy_recommendations: ['Increase monitoring threshold']
  };
  return wasm.wasm_record_feedback(JSON.stringify([]), JSON.stringify(entry));
});

test('wasm_apply_learnings', () =>
  wasm.wasm_apply_learnings(JSON.stringify([])));

test('wasm_triage', () => {
  const assessment = wasm.wasm_evaluate_signals(JSON.stringify([]));
  return wasm.wasm_triage(JSON.stringify(assessment));
});

// =========================================================================
// Module 12 — MCP / Invariants / Combinators / Holon
// =========================================================================

console.log('\n--- MCP / Invariants / Combinators / Holon ---');

test('wasm_mcp_rules', () =>
  wasm.wasm_mcp_rules());

test('wasm_enforce_invariants', () => {
  const request = {
    actor: TEST_DID,
    actor_roles: [],
    bailment_state: {
      Active: {
        bailor: 'did:exo:bailor',
        bailee: TEST_DID,
        scope: 'data'
      }
    },
    consent_records: [{
      subject: 'did:exo:subject',
      granted_to: TEST_DID,
      scope: 'data',
      active: true
    }],
    authority_chain: { links: [] }
  };
  return wasm.wasm_enforce_invariants(JSON.stringify(request));
});

// Identity combinator is a unit variant — just a string, no fields
test('wasm_reduce_combinator', () =>
  wasm.wasm_reduce_combinator(
    JSON.stringify('Identity'),
    JSON.stringify({ fields: {} })
  ));

test('wasm_step_combinator', () =>
  wasm.wasm_step_combinator(
    JSON.stringify('Identity'),
    JSON.stringify({ fields: {} })
  ));

test('wasm_spawn_holon', () =>
  wasm.wasm_spawn_holon(
    TEST_DID,
    JSON.stringify('Identity')
  ));

// =========================================================================
// Module 13 — Succession
// =========================================================================

console.log('\n--- Succession ---');

test('wasm_activate_succession', () => {
  const plan = {
    role: 'Administrator',
    current_holder: TEST_DID,
    successors: [TEST_DID_2],
    updated_at: NOW_TS
  };
  const trigger = JSON.stringify('Declaration');
  return wasm.wasm_activate_succession(
    JSON.stringify(plan),
    trigger,
    NOW_MS
  );
});

// =========================================================================
// Module 14 — Audit
// =========================================================================

console.log('\n--- Audit ---');

test('wasm_audit_append', () =>
  wasm.wasm_audit_append(TEST_DID, 'create', 'success', ZERO_32_HEX));

const auditEntry = setup(() =>
  wasm.wasm_audit_append(TEST_DID, 'create', 'success', ZERO_32_HEX));

test('wasm_audit_verify', () => {
  const entry = {
    id: UUID_1,
    timestamp: NOW_TS,
    actor: TEST_DID,
    action: 'create',
    result: 'success',
    evidence_hash: ZERO_32_BYTES,
    chain_hash: ZERO_32_BYTES
  };
  return wasm.wasm_audit_verify(JSON.stringify([entry]));
});

test('wasm_check_clearance', () => {
  // Clearance levels: None, ReadOnly, Contributor, Reviewer, Steward, Governor
  const policy = {
    default_level: 'ReadOnly',
    actions: {
      read: { required_level: 'ReadOnly' },
      write: { required_level: 'Contributor' }
    }
  };
  return wasm.wasm_check_clearance(TEST_DID, 'read', JSON.stringify(policy));
});

// =========================================================================
// Module 15 — Deliberation / Voting
// =========================================================================

console.log('\n--- Deliberation / Voting ---');

test('wasm_open_deliberation', () =>
  wasm.wasm_open_deliberation(
    Buffer.from('test proposal').toString('hex'),
    JSON.stringify([TEST_DID, TEST_DID_2])
  ));

const deliberation = setup(() =>
  wasm.wasm_open_deliberation(
    Buffer.from('test proposal').toString('hex'),
    JSON.stringify([TEST_DID, TEST_DID_2])
  ));

const testVote = {
  voter_did: TEST_DID,
  position: 'For',
  reasoning_hash: ZERO_32_BYTES,
  signature: ephResult.signature
};

test('wasm_cast_vote', () => {
  if (!deliberation) throw new Error('skipped -- no deliberation from setup');
  return wasm.wasm_cast_vote(JSON.stringify(deliberation), JSON.stringify(testVote));
});

test('wasm_close_deliberation', () => {
  if (!deliberation) throw new Error('skipped -- no deliberation from setup');
  const quorumPolicy = {
    min_approvals: 1,
    min_independent: 0,
    required_roles: [],
    timeout: { physical_ms: NOW_NUM + 86400000, logical: 0 }
  };
  return wasm.wasm_close_deliberation(
    JSON.stringify(deliberation),
    JSON.stringify(quorumPolicy)
  );
});

test('wasm_detect_coordination', () =>
  wasm.wasm_detect_coordination(JSON.stringify([])));

// =========================================================================
// Module 16 — Conflict of Interest
// =========================================================================

console.log('\n--- Conflict of Interest ---');

test('wasm_check_conflicts', () => {
  const action = {
    action_id: UUID_1,
    action_type: 'vote',
    actor_did: TEST_DID,
    target_id: 'dec-1',
    affected_dids: [TEST_DID_2],
    description: 'Governance vote on decision'
  };
  const declarations = [];
  return wasm.wasm_check_conflicts(
    TEST_DID,
    JSON.stringify(action),
    JSON.stringify(declarations)
  );
});

test('wasm_conflict_enforce', () => {
  const action = {
    action_id: UUID_1,
    action_type: 'vote',
    actor_did: TEST_DID,
    target_id: 'dec-1',
    affected_dids: [TEST_DID_2],
    description: 'Governance vote on decision'
  };
  const declarations = [];
  return wasm.wasm_conflict_enforce(
    TEST_DID,
    JSON.stringify(action),
    JSON.stringify(declarations)
  );
});

// =========================================================================
// Module 17 — Quorum
// =========================================================================

console.log('\n--- Quorum ---');

test('wasm_compute_quorum', () => {
  const approvals = [];
  const policy = {
    min_approvals: 1,
    min_independent: 0,
    required_roles: [],
    timeout: { physical_ms: NOW_NUM + 86400000, logical: 0 }
  };
  return wasm.wasm_compute_quorum(
    JSON.stringify(approvals),
    JSON.stringify(policy)
  );
});

// =========================================================================
// Module 18 — Governance Challenges
// =========================================================================

console.log('\n--- Governance Challenges ---');

test('wasm_file_governance_challenge', () =>
  wasm.wasm_file_governance_challenge(
    TEST_DID,
    ZERO_32_HEX,
    JSON.stringify('ProceduralError'),
    TEXT_BYTES
  ));

test('wasm_verify_independence', () => {
  const actors = [TEST_DID, TEST_DID_2];
  const registry = {
    signing_keys: [[TEST_DID, ZERO_32_HEX], [TEST_DID_2, 'ff'.repeat(32)]],
    attestation_roots: [],
    control_metadata: []
  };
  return wasm.wasm_verify_independence(
    JSON.stringify(actors),
    JSON.stringify(registry)
  );
});

// =========================================================================
// Module 19 — TNC Enforcement (01-10) + Aggregate
// =========================================================================

console.log('\n--- TNC Enforcement ---');

const minDecision = setup(() =>
  wasm.wasm_create_decision(
    'Test Decision',
    JSON.stringify('Operational'),
    ZERO_32_HEX
  ));

const tncFlags = {
  authority_chain_verified: true,
  human_gate_satisfied: true,
  consent_verified: true,
  identity_verified: true,
  delegation_unexpired: true,
  constitutional_binding_valid: true,
  quorum_verified: true,
  terminal_immutable: true,
  ai_ceiling_enforced: true,
  evidence_bundle_complete: true
};

const tncDecJson = minDecision ? JSON.stringify(minDecision) : '{}';
const tncFlagsJson = JSON.stringify(tncFlags);

test('wasm_enforce_tnc_01', () =>
  wasm.wasm_enforce_tnc_01(tncDecJson, tncFlagsJson));

test('wasm_enforce_tnc_02', () =>
  wasm.wasm_enforce_tnc_02(tncDecJson, tncFlagsJson));

test('wasm_enforce_tnc_03', () =>
  wasm.wasm_enforce_tnc_03(tncDecJson, tncFlagsJson));

test('wasm_enforce_tnc_04', () =>
  wasm.wasm_enforce_tnc_04(tncDecJson, tncFlagsJson));

test('wasm_enforce_tnc_05', () =>
  wasm.wasm_enforce_tnc_05(tncDecJson, tncFlagsJson));

test('wasm_enforce_tnc_06', () =>
  wasm.wasm_enforce_tnc_06(tncDecJson, tncFlagsJson));

test('wasm_enforce_tnc_07', () =>
  wasm.wasm_enforce_tnc_07(tncDecJson, tncFlagsJson));

test('wasm_enforce_tnc_08', () =>
  wasm.wasm_enforce_tnc_08(tncDecJson, tncFlagsJson));

test('wasm_enforce_tnc_09', () =>
  wasm.wasm_enforce_tnc_09(tncDecJson, tncFlagsJson));

test('wasm_enforce_tnc_10', () =>
  wasm.wasm_enforce_tnc_10(tncDecJson, tncFlagsJson));

test('wasm_enforce_all_tnc', () =>
  wasm.wasm_enforce_all_tnc(tncDecJson, tncFlagsJson));

test('wasm_collect_tnc_violations', () =>
  wasm.wasm_collect_tnc_violations(tncDecJson, tncFlagsJson));

// =========================================================================
// Module 20 — Forum Authority
// =========================================================================

console.log('\n--- Forum Authority ---');

test('wasm_verify_forum_authority', () => {
  const authority = {
    root_did: TEST_DID,
    constitution_hash: ZERO_32_BYTES,
    rules: [{ name: 'TestRule', hash: ZERO_32_BYTES }],
    signature: ephResult.signature
  };
  return wasm.wasm_verify_forum_authority(JSON.stringify(authority));
});

// =========================================================================
// Module 21 — Challenge Lifecycle
// =========================================================================

console.log('\n--- Challenge Lifecycle ---');

test('wasm_file_challenge', () =>
  wasm.wasm_file_challenge(
    TEST_DID,
    UUID_1,
    JSON.stringify('ProceduralError'),
    ZERO_32_HEX
  ));

const challenge = setup(() =>
  wasm.wasm_file_challenge(
    TEST_DID,
    UUID_1,
    JSON.stringify('ProceduralError'),
    ZERO_32_HEX
  ));

test('wasm_begin_review', () => {
  if (!challenge) throw new Error('skipped -- no challenge from setup');
  return wasm.wasm_begin_review(JSON.stringify(challenge));
});

test('wasm_withdraw_challenge', () => {
  if (!challenge) throw new Error('skipped -- no challenge from setup');
  return wasm.wasm_withdraw_challenge(JSON.stringify(challenge));
});

test('wasm_is_contested', () => {
  const challengeList = challenge ? [challenge] : [];
  return wasm.wasm_is_contested(JSON.stringify(challengeList), UUID_1);
});

// =========================================================================
// Module 22 — Decision Lifecycle
// =========================================================================

console.log('\n--- Decision Lifecycle ---');

test('wasm_create_decision', () =>
  wasm.wasm_create_decision(
    'Bridge Test Decision',
    JSON.stringify('Operational'),
    ZERO_32_HEX
  ));

const decision = setup(() =>
  wasm.wasm_create_decision(
    'Bridge Test Decision',
    JSON.stringify('Operational'),
    ZERO_32_HEX
  ));

const decJson = decision ? JSON.stringify(decision) : '{}';

test('wasm_decision_is_terminal', () =>
  wasm.wasm_decision_is_terminal(decJson));

test('wasm_decision_content_hash', () =>
  wasm.wasm_decision_content_hash(decJson));

test('wasm_add_evidence', () => {
  const ev = {
    evidence_type: 'Document',
    hash: ZERO_32_BYTES,
    description: 'test',
    attached_at: { physical_ms: NOW_NUM, logical: 0 }
  };
  return wasm.wasm_add_evidence(decJson, JSON.stringify(ev));
});

test('wasm_add_vote', () => {
  // decision_forum::decision_object::Vote
  const vote = {
    voter_did: TEST_DID,
    choice: 'Approve',
    actor_kind: 'Human',
    timestamp: NOW_TS,
    signature_hash: ZERO_32_BYTES
  };
  return wasm.wasm_add_vote(decJson, JSON.stringify(vote));
});

test('wasm_transition_decision', () =>
  wasm.wasm_transition_decision(
    decJson,
    JSON.stringify('Submitted'),
    TEST_DID
  ));

test('wasm_check_quorum', () => {
  const registry = {
    policies: {
      Operational: { min_votes: 1, min_approve_pct: 50, min_human_votes: 0 }
    }
  };
  return wasm.wasm_check_quorum(
    JSON.stringify(registry),
    decJson
  );
});

test('wasm_enforce_human_gate', () => {
  const policy = {
    human_required_classes: ['Constitutional'],
    ai_ceiling: 'Operational',
    min_approvals: 1,
    required_fraction_pct: 50,
    require_human: true
  };
  return wasm.wasm_enforce_human_gate(
    JSON.stringify(policy),
    decJson
  );
});

test('wasm_is_ai_vote', () => {
  // decision_forum::decision_object::Vote with ActorKind::AiAgent
  const vote = {
    voter_did: TEST_DID,
    choice: 'Approve',
    actor_kind: { AiAgent: { delegation_id: 'deleg-001', ceiling_class: 'Operational' } },
    timestamp: NOW_TS,
    signature_hash: ZERO_32_BYTES
  };
  return wasm.wasm_is_ai_vote(JSON.stringify(vote));
});

test('wasm_is_human_vote', () => {
  const vote = {
    voter_did: TEST_DID,
    choice: 'Approve',
    actor_kind: 'Human',
    timestamp: NOW_TS,
    signature_hash: ZERO_32_BYTES
  };
  return wasm.wasm_is_human_vote(JSON.stringify(vote));
});

test('wasm_verify_quorum_precondition', () => {
  const registry = {
    policies: {
      Operational: { min_votes: 1, min_approve_pct: 50, min_human_votes: 0 }
    }
  };
  return wasm.wasm_verify_quorum_precondition(
    JSON.stringify(registry),
    JSON.stringify('Operational'),
    3
  );
});

test('wasm_ai_within_ceiling', () => {
  const policy = {
    human_required_classes: ['Constitutional'],
    ai_ceiling: 'Operational',
    allowed_classes: ['Operational']
  };
  return wasm.wasm_ai_within_ceiling(
    JSON.stringify(policy),
    JSON.stringify('Operational')
  );
});

test('wasm_requires_human_approval', () => {
  const policy = {
    human_required_classes: ['Constitutional'],
    ai_ceiling: 'Operational',
    allowed_classes: ['Operational']
  };
  return wasm.wasm_requires_human_approval(
    JSON.stringify(policy),
    JSON.stringify('Constitutional')
  );
});

// =========================================================================
// Module 23 — Constitution
// =========================================================================

console.log('\n--- Constitution ---');

test('wasm_dry_run_amendment', () => {
  const corpus = { version: 1, hash: ZERO_32_BYTES, articles: [], ratified_at: null, amendment_count: 0 };
  const proposed = { id: 'art-1', title: 'Test', tier: 'Articles', text_hash: ZERO_32_BYTES, status: 'Active' };
  return wasm.wasm_dry_run_amendment(
    JSON.stringify(corpus),
    JSON.stringify(proposed)
  );
});

test('wasm_ratify_constitution', () => {
  const corpus = { version: 1, hash: ZERO_32_BYTES, articles: [], ratified_at: null, amendment_count: 0 };
  const sigs = [];
  const quorum = { required_signatures: 0, required_fraction_pct: 0 };
  return wasm.wasm_ratify_constitution(
    JSON.stringify(corpus),
    JSON.stringify(sigs),
    JSON.stringify(quorum),
    NOW_MS
  );
});

test('wasm_amend_constitution', () => {
  const corpus = { version: 1, hash: ZERO_32_BYTES, articles: [], ratified_at: NOW_TS, amendment_count: 0 };
  const amendment = { id: 'art-1', title: 'Test', tier: 'Articles', text_hash: ZERO_32_BYTES, status: 'Active' };
  // amend requires at least one non-empty signature — 64 bytes = 128 hex chars
  // All-zero is treated as empty, so set one byte to 01
  const dummySig64Hex = '01' + '00'.repeat(63);
  const sigs = [[TEST_DID, dummySig64Hex]];
  return wasm.wasm_amend_constitution(
    JSON.stringify(corpus),
    JSON.stringify(amendment),
    JSON.stringify(sigs)
  );
});

// =========================================================================
// Module 24 — Accountability
// =========================================================================

console.log('\n--- Accountability ---');

test('wasm_propose_accountability', () =>
  wasm.wasm_propose_accountability(
    TEST_DID_2,
    TEST_DID,
    JSON.stringify('Censure'),
    'Violation of governance protocol',
    ZERO_32_HEX
  ));

const accAction = setup(() =>
  wasm.wasm_propose_accountability(
    TEST_DID_2,
    TEST_DID,
    JSON.stringify('Censure'),
    'Violation of governance protocol',
    ZERO_32_HEX
  ));

test('wasm_begin_due_process', () => {
  if (!accAction) throw new Error('skipped -- no accountability action from setup');
  return wasm.wasm_begin_due_process(JSON.stringify(accAction));
});

const dpAction = setup(() =>
  accAction && wasm.wasm_begin_due_process(JSON.stringify(accAction)));

test('wasm_enact_accountability', () => {
  if (!dpAction) throw new Error('skipped -- no due-process action from setup');
  return wasm.wasm_enact_accountability(
    JSON.stringify(dpAction),
    UUID_1,
    NOW_MS
  );
});

const enactedAction = setup(() =>
  dpAction && wasm.wasm_enact_accountability(
    JSON.stringify(dpAction),
    UUID_1,
    NOW_MS
  ));

test('wasm_reverse_accountability', () => {
  if (!enactedAction) throw new Error('skipped -- no enacted action from setup');
  return wasm.wasm_reverse_accountability(JSON.stringify(enactedAction));
});

test('wasm_is_due_process_expired', () => {
  if (!dpAction) throw new Error('skipped -- no due-process action from setup');
  return wasm.wasm_is_due_process_expired(JSON.stringify(dpAction), NOW_MS);
});

// =========================================================================
// Module 25 — Emergency Actions
// =========================================================================

console.log('\n--- Emergency Actions ---');

const emergencyPolicy = {
  max_monetary_cap_cents: 100000,
  ratification_window_ms: 86400000,
  max_per_quarter: 10,
  max_per_quarter_per_actor: 5,
  require_evidence: true,
  review_frequency_threshold: 3,
  allowed_actions: ['SystemHalt', 'AccessRevocation', 'DataFreeze', 'EmergencyPatch', 'RoleEscalation']
};

test('wasm_create_emergency_action', () =>
  wasm.wasm_create_emergency_action(
    JSON.stringify('SystemHalt'),
    TEST_DID,
    'Critical security breach',
    BigInt(50000),
    ZERO_32_HEX,
    JSON.stringify(emergencyPolicy),
    NOW_MS
  ));

const emergencyAction = setup(() =>
  wasm.wasm_create_emergency_action(
    JSON.stringify('SystemHalt'),
    TEST_DID,
    'Critical security breach',
    BigInt(50000),
    ZERO_32_HEX,
    JSON.stringify(emergencyPolicy),
    NOW_MS
  ));

test('wasm_check_expiry', () => {
  if (!emergencyAction) throw new Error('skipped -- no emergency action from setup');
  return wasm.wasm_check_expiry(JSON.stringify(emergencyAction), NOW_MS);
});

test('wasm_ratify_emergency', () => {
  if (!emergencyAction) throw new Error('skipped -- no emergency action from setup');
  return wasm.wasm_ratify_emergency(JSON.stringify(emergencyAction), UUID_1, NOW_MS);
});

test('wasm_needs_governance_review', () =>
  wasm.wasm_needs_governance_review(
    JSON.stringify([]),
    JSON.stringify(emergencyPolicy)
  ));

// =========================================================================
// Final Report
// =========================================================================

console.log('\n' + '='.repeat(60));
const total = passed + failed;
console.log(`Bridge Verification: ${passed}/${total} passed, ${failed} failed`);

if (failures.length > 0) {
  console.log('\nFailures:');
  for (const f of failures) {
    console.log(`  - ${f.name}: ${f.msg}`);
  }
}

console.log('='.repeat(60));

// Exit with non-zero if any failures
process.exit(failed > 0 ? 1 : 0);
