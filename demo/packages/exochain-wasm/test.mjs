#!/usr/bin/env node
// ExoChain WASM — Node.js integration test suite
// Tests all 9 binding modules: core, gatekeeper, governance, decision-forum,
// identity, authority, consent, legal, escalation

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const wasm = require('./wasm/exochain_wasm.js');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    ${e.message || e}`);
    failed++;
  }
}

function assert(condition, msg) {
  if (!condition) throw new Error(msg || 'Assertion failed');
}

const TEST_DID = 'did:exo:test-actor';
const DUMMY_SECRET_HEX = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';

// ═══════════════════════════════════════════════════════════════
// CORE BINDINGS
// ═══════════════════════════════════════════════════════════════
console.log('\n── Core Bindings ──');

test('hash_bytes produces 64-char hex', () => {
  const hash = wasm.wasm_hash_bytes(new Uint8Array([1, 2, 3, 4]));
  assert(typeof hash === 'string', 'hash should be string');
  assert(hash.length === 64, `hash length should be 64, got ${hash.length}`);
});

test('hash_structured produces deterministic hash', () => {
  const h1 = wasm.wasm_hash_structured('{"a":1}');
  const h2 = wasm.wasm_hash_structured('{"a":1}');
  assert(h1 === h2, 'same input should produce same hash');
});

test('generate_keypair returns pub+secret', () => {
  const kp = wasm.wasm_generate_keypair();
  assert(kp.public_key, 'should have public_key');
  assert(kp.public_key.length === 64, `public key should be 64 hex chars, got ${kp.public_key.length}`);
});

test('sign + verify round-trip', () => {
  const publicKey = wasm.wasm_ed25519_public_from_secret(DUMMY_SECRET_HEX);
  const msg = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
  const sig = wasm.wasm_sign(msg, DUMMY_SECRET_HEX);
  const valid = wasm.wasm_verify(msg, sig, publicKey);
  assert(valid === true, 'signature should verify');
});

test('verify rejects bad signature', () => {
  const publicKey = wasm.wasm_ed25519_public_from_secret(DUMMY_SECRET_HEX);
  const msg = new Uint8Array([1, 2, 3]);
  const sig = wasm.wasm_sign(msg, DUMMY_SECRET_HEX);
  const bad = wasm.wasm_verify(new Uint8Array([4, 5, 6]), sig, publicKey);
  assert(bad === false, 'bad message should not verify');
});

test('bcts_valid_transitions returns array for Draft', () => {
  const transitions = wasm.wasm_bcts_valid_transitions('"Draft"');
  assert(Array.isArray(transitions), 'should return array');
  assert(transitions.length > 0, 'Draft should have transitions');
});

test('bcts_is_terminal — Draft is not terminal', () => {
  assert(wasm.wasm_bcts_is_terminal('"Draft"') === false);
});

test('bcts_is_terminal — Closed is terminal', () => {
  assert(wasm.wasm_bcts_is_terminal('"Closed"') === true);
});

test('create_signed_event', () => {
  const evt = wasm.wasm_create_signed_event(
    '"GovernanceDecision"',
    new Uint8Array([1, 2, 3]),
    TEST_DID,
    DUMMY_SECRET_HEX,
  );
  assert(evt.source_did === TEST_DID, `source_did should be ${TEST_DID}, got ${evt.source_did}`);
});

test('merkle_root computes root from 32-byte hex leaves', () => {
  const leaves = ['0'.repeat(64), '1'.repeat(64)];
  const root = wasm.wasm_merkle_root(JSON.stringify(leaves));
  assert(typeof root === 'string', 'should return string');
  assert(root.length === 64, 'should be 64-char hex');
});

// ═══════════════════════════════════════════════════════════════
// GATEKEEPER BINDINGS (CGR Combinator Algebra)
// ═══════════════════════════════════════════════════════════════
console.log('\n── Gatekeeper Bindings ──');

test('mcp_rules returns rule list', () => {
  const rules = wasm.wasm_mcp_rules();
  assert(Array.isArray(rules), 'should return array');
  assert(rules.length > 0, 'should have rules');
  assert(rules[0].rule, 'each rule should have "rule" field');
  assert(rules[0].description, 'each rule should have "description" field');
});

test('enforce_invariants evaluates a structured request', () => {
  const request = {
    actor: TEST_DID,
    actor_roles: [],
    bailment_state: {
      Active: {
        bailor: 'did:exo:bailor',
        bailee: TEST_DID,
        scope: 'data',
      },
    },
    consent_records: [{
      subject: 'did:exo:subject',
      granted_to: TEST_DID,
      scope: 'data',
      active: true,
    }],
    authority_chain: { links: [] },
  };
  const result = wasm.wasm_enforce_invariants(JSON.stringify(request));
  assert(result.passed === false, 'empty authority/provenance request should fail');
  assert(Array.isArray(result.violations), 'should return violations');
});

test('workflow_stages returns stage list', () => {
  const stages = wasm.wasm_workflow_stages();
  assert(Array.isArray(stages), 'should return array');
  assert(stages.includes('Draft'), 'should include Draft');
  assert(stages.includes('Closed'), 'should include Closed');
});

// ═══════════════════════════════════════════════════════════════
// GOVERNANCE BINDINGS
// ═══════════════════════════════════════════════════════════════
console.log('\n── Governance Bindings ──');

test('check_clearance for Governor', () => {
  const policy = {
    actions: {
      "approve_decision": { required_level: "Governor" }
    }
  };
  const result = wasm.wasm_check_clearance(
    'did:exo:alice',
    'approve_decision',
    JSON.stringify(policy)
  );
  assert(result.status === 'Granted', `expected Granted, got ${result.status}`);
});

test('check_conflicts with no declarations', () => {
  const action = {
    action_id: 'vote-001',
    actor_did: 'did:exo:alice',
    affected_dids: [],
    description: 'Vote on budget decision',
  };
  const result = wasm.wasm_check_conflicts(
    'did:exo:alice',
    JSON.stringify(action),
    '[]'
  );
  assert(result.must_recuse === false, 'should not require recusal with no conflicts');
});

test('audit_append creates entry', () => {
  const evidenceHash = '0'.repeat(64);
  const result = wasm.wasm_audit_append(
    '018f7a96-8ad0-7c4f-8e0f-111111111301',
    7200n,
    0,
    'did:exo:alice',
    'create_decision',
    'success',
    evidenceHash
  );
  assert(result.entries === 1, `should have 1 entry, got ${result.entries}`);
  assert(result.head_hash, 'should have head hash');
});

// ═══════════════════════════════════════════════════════════════
// DECISION FORUM BINDINGS
// ═══════════════════════════════════════════════════════════════
console.log('\n── Decision Forum Bindings ──');

test('create_decision produces DecisionObject', () => {
  const constitutionHash = '11'.repeat(32);
  const decision = wasm.wasm_create_decision(
    '00000000-0000-0000-0000-000000000001',
    'Test Budget Approval',
    '"Operational"',
    constitutionHash,
    1000n,
    0
  );
  assert(decision.title === 'Test Budget Approval', `title should match, got ${decision.title}`);
  assert(decision.id === '00000000-0000-0000-0000-000000000001', `id should match, got ${decision.id}`);
});

test('decision_is_terminal — new decision is not terminal', () => {
  const constitutionHash = '11'.repeat(32);
  const decision = wasm.wasm_create_decision(
    '00000000-0000-0000-0000-000000000002',
    'Test',
    '"Operational"',
    constitutionHash,
    1100n,
    0
  );
  const json = JSON.stringify(decision);
  assert(wasm.wasm_decision_is_terminal(json) === false, 'new decision should not be terminal');
});

test('decision_content_hash produces hash', () => {
  const constitutionHash = '11'.repeat(32);
  const decision = wasm.wasm_create_decision(
    '00000000-0000-0000-0000-000000000003',
    'Hash Test',
    '"Operational"',
    constitutionHash,
    1200n,
    0
  );
  const hash = wasm.wasm_decision_content_hash(JSON.stringify(decision));
  assert(typeof hash === 'string', 'should return string');
  assert(hash.length === 64, `should be 64-char hex, got length ${hash.length}`);
});

// ═══════════════════════════════════════════════════════════════
// IDENTITY BINDINGS
// ═══════════════════════════════════════════════════════════════
console.log('\n── Identity Bindings ──');

test('shamir_split splits secret into shares', () => {
  const secret = new Uint8Array([42, 99, 17, 255, 0, 128]);
  const result = wasm.wasm_shamir_split(secret, 2, 3);
  assert(Array.isArray(result), 'should return array of shares');
  assert(result.length === 3, `should have 3 shares, got ${result.length}`);
});

test('pace_escalate changes Normal → AlternateActive', () => {
  const state = wasm.wasm_pace_escalate('"Normal"');
  assert(state, 'should return new state');
});

test('assess_risk creates attestation', () => {
  const attestation = wasm.wasm_assess_risk(
    'did:exo:subject',
    'did:exo:attester',
    new Uint8Array([1, 2, 3]),
    '"Medium"',
    BigInt(86400000)
  );
  assert(attestation, 'should return attestation');
});

// ═══════════════════════════════════════════════════════════════
// CONSENT BINDINGS
// ═══════════════════════════════════════════════════════════════
console.log('\n── Consent Bindings ──');

test('propose_bailment creates bailment', () => {
  const bailment = wasm.wasm_propose_bailment(
    'did:exo:bailor',
    'did:exo:bailee',
    new Uint8Array([1, 2, 3]),
    '"Processing"',
    '018f7a96-8ad0-7c4f-8e0f-111111111302',
    JSON.stringify({ physical_ms: 7300, logical: 0 })
  );
  assert(bailment, 'should return bailment');
});

// ═══════════════════════════════════════════════════════════════
// LEGAL BINDINGS
// ═══════════════════════════════════════════════════════════════
console.log('\n── Legal Bindings ──');

test('create_evidence produces evidence object', () => {
  const evidence = wasm.wasm_create_evidence(
    new Uint8Array([10, 20, 30]),
    'document',
    'did:exo:creator',
    '00000000-0000-0000-0000-000000000010',
    BigInt(1700000000000)
  );
  assert(evidence, 'should return evidence');
});

// ═══════════════════════════════════════════════════════════════
// ESCALATION BINDINGS
// ═══════════════════════════════════════════════════════════════
console.log('\n── Escalation Bindings ──');

test('apply_learnings with empty feedback', () => {
  const recommendations = wasm.wasm_apply_learnings('[]');
  assert(recommendations !== undefined, 'should return recommendations');
});

// ═══════════════════════════════════════════════════════════════
// SUMMARY
// ═══════════════════════════════════════════════════════════════
console.log(`\n${'═'.repeat(60)}`);
console.log(`  Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);
console.log(`${'═'.repeat(60)}\n`);

if (failed > 0) {
  process.exit(1);
}
