/**
 * Bridge Verification Test — WASM binding smoke-test harness
 *
 * Calls the covered exported wasm_ bridge functions with valid minimal inputs
 * and verifies each returns without throwing.
 *
 * Run:  node packages/exochain-wasm/test/bridge_verification.mjs
 */

import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const wasm = require('../wasm/exochain_wasm.js');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;
const failures = [];
const coveredExports = new Set();

function test(name, fn) {
  try {
    for (const match of name.matchAll(/\bwasm_[A-Za-z0-9_]+\b/g)) {
      coveredExports.add(match[0]);
    }
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
const NONZERO_32_HEX = '11'.repeat(32);
const ZERO_32_BYTES = Array.from({ length: 32 }, () => 0);
const EVIDENCE_32_BYTES = Array.from({ length: 32 }, () => 0xee);
const TEST_DID      = 'did:exo:test-actor';
const TEST_DID_2    = 'did:exo:test-actor-2';
const TEST_DID_3    = 'did:exo:test-actor-3';
const NOW_MS        = BigInt(Date.now());
const NOW_NUM       = Number(NOW_MS);
const NOW_TS        = { physical_ms: NOW_NUM, logical: 0 };  // HLC Timestamp
const TEXT_BYTES     = new TextEncoder().encode('hello');
const DUMMY_SECRET_HEX = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';
const DUMMY_SECRET_HEX_2 = '1111111111111111111111111111111111111111111111111111111111111111';
const DUMMY_SECRET_HEX_3 = '2222222222222222222222222222222222222222222222222222222222222222';
const UUID_1 = '00000000-0000-0000-0000-000000000001';
const UUID_2 = '00000000-0000-0000-0000-000000000002';
const UUID_3 = '00000000-0000-0000-0000-000000000003';
const UUID_4 = '00000000-0000-0000-0000-000000000004';

// Pre-compute a valid Ed25519 keypair result for reuse
const ephResult = wasm.wasm_sign_with_ephemeral_key(TEXT_BYTES);

function publicKeyForSecret(secretHex) {
  return wasm.wasm_ed25519_public_from_secret(secretHex);
}

function signatureHexFromJson(signatureJson) {
  const signature = typeof signatureJson === 'string' ? JSON.parse(signatureJson) : signatureJson;
  const bytes = signature.Ed25519;
  if (!Array.isArray(bytes) || bytes.length !== 64) {
    throw new Error('expected Ed25519 signature bytes');
  }
  return Buffer.from(bytes).toString('hex');
}

function hashBytes(hashValue) {
  if (Array.isArray(hashValue)) return hashValue;
  if (hashValue && Array.isArray(hashValue[0])) return hashValue[0];
  if (hashValue && Array.isArray(hashValue.bytes)) return hashValue.bytes;
  throw new Error('expected serialized Hash256 bytes');
}

function assertNonZeroHash(hashValue, label) {
  const bytes = hashBytes(hashValue);
  if (bytes.length !== 32 || bytes.every((byte) => byte === 0)) {
    throw new Error(`${label} must be a nonzero Hash256`);
  }
}

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

test('wasm_ed25519_public_from_secret', () =>
  wasm.wasm_ed25519_public_from_secret(DUMMY_SECRET_HEX));

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
// Module 3b — Messaging / Death Verification
// =========================================================================

console.log('\n--- Messaging / Death Verification ---');

test('wasm_generate_x25519_keypair', () => {
  const keypair = wasm.wasm_generate_x25519_keypair();
  if (keypair.public_key_hex.length !== 64 || keypair.secret_key_hex.length !== 64) {
    throw new Error('X25519 keypair must return 32-byte public and secret keys');
  }
  return keypair;
});

const recipientKex = setup(() => wasm.wasm_generate_x25519_keypair());

test('wasm_x25519_public_from_secret', () => {
  if (!recipientKex) throw new Error('skipped -- no recipient X25519 keypair');
  const derived = wasm.wasm_x25519_public_from_secret(recipientKex.secret_key_hex);
  if (derived.public_key_hex !== recipientKex.public_key_hex) {
    throw new Error('derived X25519 public key must match generated keypair');
  }
  return derived;
});

test('wasm_encrypt_message', () => {
  if (!recipientKex) throw new Error('skipped -- no recipient X25519 keypair');
  const envelope = wasm.wasm_encrypt_message(
    'bridge encrypted message',
    JSON.stringify('Text'),
    TEST_DID,
    TEST_DID_2,
    DUMMY_SECRET_HEX,
    recipientKex.public_key_hex,
    '018f7a96-8ad0-7c4f-8e0f-111111111201',
    7000n,
    0,
    false,
    0
  );
  if (envelope.sender_did !== TEST_DID || envelope.recipient_did !== TEST_DID_2) {
    throw new Error('encrypted envelope must retain sender and recipient DIDs');
  }
  return envelope;
});

const encryptedEnvelope = setup(() =>
  recipientKex && wasm.wasm_encrypt_message(
    'bridge encrypted message',
    JSON.stringify('Text'),
    TEST_DID,
    TEST_DID_2,
    DUMMY_SECRET_HEX,
    recipientKex.public_key_hex,
    '018f7a96-8ad0-7c4f-8e0f-111111111202',
    7001n,
    0,
    false,
    0
  ));
const encryptedSenderPublicKey = setup(() => publicKeyForSecret(DUMMY_SECRET_HEX));

test('wasm_verify_message_signature', () => {
  if (!encryptedEnvelope || !encryptedSenderPublicKey) {
    throw new Error('skipped -- no encrypted envelope');
  }
  const ok = wasm.wasm_verify_message_signature(
    JSON.stringify(encryptedEnvelope),
    encryptedSenderPublicKey
  );
  if (!ok) throw new Error('message signature must verify with sender public key');
  return ok;
});

test('wasm_decrypt_message', () => {
  if (!encryptedEnvelope || !recipientKex || !encryptedSenderPublicKey) {
    throw new Error('skipped -- no encrypted envelope');
  }
  const decrypted = wasm.wasm_decrypt_message(
    JSON.stringify(encryptedEnvelope),
    recipientKex.secret_key_hex,
    encryptedSenderPublicKey
  );
  if (decrypted.plaintext !== 'bridge encrypted message') {
    throw new Error('decrypted plaintext mismatch');
  }
  return decrypted;
});

const initiatorPublicKey = setup(() => publicKeyForSecret(DUMMY_SECRET_HEX_2));
const trusteePublicKey = setup(() => publicKeyForSecret(DUMMY_SECRET_HEX_3));
const deathTrusteesJson = setup(() => {
  if (!initiatorPublicKey || !trusteePublicKey) {
    throw new Error('missing death-verification public keys');
  }
  return JSON.stringify([
    { did: TEST_DID_2, public_key_hex: initiatorPublicKey },
    { did: TEST_DID_3, public_key_hex: trusteePublicKey },
  ]);
});
const deathClaimNonceHex = Buffer.from('bridge-death-claim').toString('hex');

test('wasm_death_verification_initial_signing_payload', () => {
  if (!deathTrusteesJson) throw new Error('skipped -- no trustee set');
  return wasm.wasm_death_verification_initial_signing_payload(
    TEST_DID,
    TEST_DID_2,
    2,
    deathTrusteesJson,
    deathClaimNonceHex
  );
});

const deathInitialPayload = setup(() =>
  deathTrusteesJson && wasm.wasm_death_verification_initial_signing_payload(
    TEST_DID,
    TEST_DID_2,
    2,
    deathTrusteesJson,
    deathClaimNonceHex
  ));
const deathInitialSignatureHex = setup(() =>
  deathInitialPayload && signatureHexFromJson(wasm.wasm_sign(deathInitialPayload, DUMMY_SECRET_HEX_2)));

test('wasm_death_verification_new', () => {
  if (!deathTrusteesJson || !deathInitialSignatureHex) {
    throw new Error('skipped -- no signed initial payload');
  }
  const state = wasm.wasm_death_verification_new(
    TEST_DID,
    TEST_DID_2,
    2,
    deathTrusteesJson,
    deathClaimNonceHex,
    deathInitialSignatureHex,
    NOW_MS,
    0
  );
  if (state.created.physical_ms !== NOW_NUM || state.created.logical !== 0) {
    throw new Error('death verification created timestamp must be caller-supplied HLC');
  }
  if (state.confirmations[0].confirmed_at.physical_ms !== NOW_NUM) {
    throw new Error('initial confirmation timestamp must match caller-supplied creation HLC');
  }
  return state;
});

const deathState = setup(() =>
  deathTrusteesJson && deathInitialSignatureHex && wasm.wasm_death_verification_new(
    TEST_DID,
    TEST_DID_2,
    2,
    deathTrusteesJson,
    deathClaimNonceHex,
    deathInitialSignatureHex,
    NOW_MS,
    0
  ));

test('wasm_death_verification_confirmation_signing_payload', () => {
  if (!deathState) throw new Error('skipped -- no death-verification state');
  return wasm.wasm_death_verification_confirmation_signing_payload(
    JSON.stringify(deathState),
    TEST_DID_3
  );
});

const deathConfirmationPayload = setup(() =>
  deathState && wasm.wasm_death_verification_confirmation_signing_payload(
    JSON.stringify(deathState),
    TEST_DID_3
  ));
const deathConfirmationSignatureHex = setup(() =>
  deathConfirmationPayload && signatureHexFromJson(
    wasm.wasm_sign(deathConfirmationPayload, DUMMY_SECRET_HEX_3)
  ));

test('wasm_death_verification_confirm', () => {
  if (!deathState || !trusteePublicKey || !deathConfirmationSignatureHex) {
    throw new Error('skipped -- no signed confirmation payload');
  }
  const result = wasm.wasm_death_verification_confirm(
    JSON.stringify(deathState),
    TEST_DID_3,
    trusteePublicKey,
    deathConfirmationSignatureHex,
    BigInt(NOW_NUM + 1),
    0
  );
  const confirmation = result.state.confirmations[1];
  if (confirmation.confirmed_at.physical_ms !== NOW_NUM + 1 || confirmation.confirmed_at.logical !== 0) {
    throw new Error('trustee confirmation timestamp must be caller-supplied HLC');
  }
  if (result.state.resolved_at.physical_ms !== NOW_NUM + 1) {
    throw new Error('verified death claim resolution timestamp must match confirmation HLC');
  }
  return result;
});

// =========================================================================
// Module 4 — Legal / Records / Evidence
// =========================================================================

console.log('\n--- Legal / Records / Evidence ---');

test('wasm_create_record', () =>
  wasm.wasm_create_record(TEXT_BYTES, 'Confidential', BigInt(365), UUID_1, NOW_MS));

test('wasm_apply_retention', () => {
  const rec = wasm.wasm_create_record(TEXT_BYTES, 'Confidential', BigInt(365), UUID_2, NOW_MS);
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
  wasm.wasm_create_evidence(TEXT_BYTES, 'Document', TEST_DID, UUID_3, NOW_MS));

const evidence = setup(() =>
  wasm.wasm_create_evidence(TEXT_BYTES, 'Document', TEST_DID, UUID_3, NOW_MS));

test('wasm_verify_chain_of_custody', () => {
  if (!evidence) throw new Error('skipped -- no evidence from setup');
  return wasm.wasm_verify_chain_of_custody(JSON.stringify(evidence));
});

const evidenceId = (evidence && evidence.id) || UUID_3;

test('wasm_assert_privilege', () =>
  wasm.wasm_assert_privilege(
    evidenceId,
    JSON.stringify('AttorneyClient'),
    TEST_DID,
    'Legal advice communication',
    NOW_MS
  ));

const assertion = setup(() =>
  wasm.wasm_assert_privilege(
    evidenceId,
    JSON.stringify('AttorneyClient'),
    TEST_DID,
    'Legal advice communication',
    NOW_MS
  ));

test('wasm_challenge_privilege', () => {
  if (!assertion) throw new Error('skipped -- no privilege assertion from setup');
  return wasm.wasm_challenge_privilege(
    JSON.stringify(assertion),
    TEST_DID_2,
    'Crime-fraud exception',
    NOW_MS
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
    UUID_4,
    TEST_DID,
    TEST_DID_2,
    'Board member is counterparty',
    NONZERO_32_HEX,
    JSON.stringify('BoardApproval'),
    NOW_MS
  ));

const shTxn = setup(() =>
  wasm.wasm_initiate_safe_harbor(
    UUID_4,
    TEST_DID,
    TEST_DID_2,
    'Board member is counterparty',
    NONZERO_32_HEX,
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
    JSON.stringify('Custody'),
    UUID_1,
    JSON.stringify(NOW_TS)
  ));

const bailment = setup(() =>
  wasm.wasm_propose_bailment(
    TEST_DID,
    TEST_DID_2,
    TEXT_BYTES,
    JSON.stringify('Custody'),
    UUID_1,
    JSON.stringify(NOW_TS)
  ));

test('wasm_bailment_is_active', () => {
  if (!bailment) throw new Error('skipped -- no bailment from setup');
  return wasm.wasm_bailment_is_active(JSON.stringify(bailment), JSON.stringify(NOW_TS));
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
// Module 8b — Catapult
// =========================================================================

console.log('\n--- Catapult ---');

test('wasm_create_franchise_blueprint', () => {
  const blueprint = wasm.wasm_create_franchise_blueprint(
    'Bridge Franchise',
    JSON.stringify('SaaS'),
    NONZERO_32_HEX,
    UUID_4,
    'Bridge-test franchise blueprint',
    NOW_MS,
    1
  );
  if (blueprint.id !== UUID_4) throw new Error('blueprint id must be caller-supplied');
  assertNonZeroHash(blueprint.content_hash, 'blueprint content_hash');
  return blueprint;
});

const catapultBlueprint = setup(() =>
  wasm.wasm_create_franchise_blueprint(
    'Bridge Franchise',
    JSON.stringify('SaaS'),
    NONZERO_32_HEX,
    UUID_4,
    'Bridge-test franchise blueprint',
    NOW_MS,
    1
  ));

test('wasm_instantiate_newco', () => {
  if (!catapultBlueprint) throw new Error('skipped -- no Catapult blueprint from setup');
  const newco = wasm.wasm_instantiate_newco(
    JSON.stringify(catapultBlueprint),
    JSON.stringify({
      name: 'Bridge Newco',
      newco_id: UUID_1,
      tenant_id: UUID_2,
      dag_anchor_hex: '22'.repeat(32),
      created_physical_ms: NOW_NUM,
      created_logical: 2,
      hr_did: TEST_DID,
      researcher_did: TEST_DID_2
    })
  );
  if (newco.id !== UUID_1) throw new Error('newco id must be caller-supplied');
  if (newco.tenant_id !== UUID_2) throw new Error('tenant id must be caller-supplied');
  assertNonZeroHash(newco.constitution_hash, 'newco constitution_hash');
  assertNonZeroHash(newco.dag_anchor, 'newco dag_anchor');
  if (newco.created.physical_ms !== NOW_NUM || newco.created.logical !== 2) {
    throw new Error('newco created timestamp must be caller-supplied HLC');
  }
  return newco;
});

const catapultNewco = setup(() =>
  catapultBlueprint && wasm.wasm_instantiate_newco(
    JSON.stringify(catapultBlueprint),
    JSON.stringify({
      name: 'Bridge Newco',
      newco_id: UUID_1,
      tenant_id: UUID_2,
      dag_anchor_hex: '22'.repeat(32),
      created_physical_ms: NOW_NUM,
      created_logical: 2,
      hr_did: TEST_DID,
      researcher_did: TEST_DID_2
    })
  ));

test('wasm_list_franchise_blueprints', () => {
  if (!catapultBlueprint) throw new Error('skipped -- no Catapult blueprint from setup');
  const blueprints = wasm.wasm_list_franchise_blueprints(
    JSON.stringify({ blueprints: { [UUID_4]: catapultBlueprint } })
  );
  if (blueprints.length !== 1 || blueprints[0].id !== UUID_4) {
    throw new Error('franchise registry list did not return published blueprint');
  }
  return blueprints;
});

test('wasm_valid_phase_transitions', () => {
  const transitions = wasm.wasm_valid_phase_transitions(JSON.stringify('Assessment'));
  if (!transitions.includes('Selection')) {
    throw new Error('Assessment phase must allow Selection transition');
  }
  return transitions;
});

test('wasm_transition_newco_phase', () => {
  if (!catapultNewco) throw new Error('skipped -- no Catapult newco from setup');
  const transitioned = wasm.wasm_transition_newco_phase(
    JSON.stringify(catapultNewco),
    JSON.stringify('Selection')
  );
  if (transitioned.phase !== 'Selection') {
    throw new Error('newco phase did not transition to Selection');
  }
  return transitioned;
});

const ventureCommander = {
  did: TEST_DID_3,
  slot: 'VentureCommander',
  display_name: 'Bridge Venture Commander',
  capabilities: ['command', 'budget'],
  status: 'Active',
  last_heartbeat: { physical_ms: NOW_NUM + 50, logical: 0 },
  budget_spent_cents: 0,
  budget_limit_cents: 1000000,
  hired_at: { physical_ms: NOW_NUM + 50, logical: 0 },
  hired_by: TEST_DID,
  commandbase_profile: null
};

test('wasm_hire_agent', () => {
  if (!catapultNewco) throw new Error('skipped -- no Catapult newco from setup');
  const hired = wasm.wasm_hire_agent(
    JSON.stringify(catapultNewco),
    JSON.stringify(ventureCommander)
  );
  if (!hired.roster.agents.VentureCommander) {
    throw new Error('VentureCommander slot was not filled');
  }
  return hired;
});

test('wasm_release_agent', () => {
  if (!catapultNewco) throw new Error('skipped -- no Catapult newco from setup');
  const hired = wasm.wasm_hire_agent(
    JSON.stringify(catapultNewco),
    JSON.stringify(ventureCommander)
  );
  const released = wasm.wasm_release_agent(
    JSON.stringify(hired),
    JSON.stringify('VentureCommander')
  );
  if (released.released_agent.did !== TEST_DID_3) {
    throw new Error('released agent DID mismatch');
  }
  return released;
});

test('wasm_roster_status', () => {
  if (!catapultNewco) throw new Error('skipped -- no Catapult newco from setup');
  const status = wasm.wasm_roster_status(JSON.stringify(catapultNewco));
  if (status.filled < 2 || !status.has_founders) {
    throw new Error('newco roster status must include founding agents');
  }
  return status;
});

test('wasm_oda_authority_chain', () => {
  if (!catapultNewco) throw new Error('skipped -- no Catapult newco from setup');
  const hired = wasm.wasm_hire_agent(
    JSON.stringify(catapultNewco),
    JSON.stringify(ventureCommander)
  );
  const chain = wasm.wasm_oda_authority_chain(JSON.stringify(hired));
  if (chain.primary !== TEST_DID_3) {
    throw new Error('PACE primary authority should be the VentureCommander in bridge fixture');
  }
  return chain;
});

test('wasm_record_cost_event', () => {
  const ledger = wasm.wasm_record_cost_event(
    JSON.stringify({ policies: [], events: [] }),
    JSON.stringify({
      id: UUID_1,
      newco_id: UUID_2,
      agent_did: TEST_DID,
      slot: 'VentureCommander',
      amount: 1234,
      metric: 'BilledCents',
      description: 'Bridge cost event',
      timestamp: { physical_ms: NOW_NUM + 10, logical: 0 }
    })
  );
  if (ledger.events.length !== 1) throw new Error('cost event was not recorded');
  assertNonZeroHash(ledger.events[0].receipt_hash, 'cost event receipt_hash');
  return ledger;
});

const catapultLedger = setup(() =>
  wasm.wasm_record_cost_event(
    JSON.stringify({
      policies: [{
        id: UUID_4,
        scope: 'Company',
        metric: 'BilledCents',
        window: 'Lifetime',
        limit: 2000,
        warn_threshold_bps: 5000,
        hard_stop: true,
        is_active: true
      }],
      events: []
    }),
    JSON.stringify({
      id: UUID_1,
      newco_id: UUID_2,
      agent_did: TEST_DID,
      slot: 'VentureCommander',
      amount: 1234,
      metric: 'BilledCents',
      description: 'Bridge cost event',
      timestamp: { physical_ms: NOW_NUM + 10, logical: 0 }
    })
  ));

test('wasm_check_budget_status', () => {
  if (!catapultLedger) throw new Error('skipped -- no Catapult budget ledger');
  const status = wasm.wasm_check_budget_status(
    JSON.stringify(catapultLedger),
    JSON.stringify('Company')
  );
  if (status.status !== 'Warning') {
    throw new Error('budget status should warn after threshold crossing');
  }
  return status;
});

test('wasm_enforce_budget', () => {
  if (!catapultNewco) throw new Error('skipped -- no Catapult newco from setup');
  const enforcement = wasm.wasm_enforce_budget(JSON.stringify(catapultNewco));
  if (enforcement.status !== 'Ok') {
    throw new Error('fresh newco budget should be Ok');
  }
  return enforcement;
});

test('wasm_record_heartbeat', () => {
  const monitor = wasm.wasm_record_heartbeat(
    JSON.stringify({
      last_seen: {},
      history: {},
      warn_ms: 180000,
      timeout_ms: 300000
    }),
    JSON.stringify({
      id: UUID_2,
      newco_id: UUID_3,
      agent_did: TEST_DID,
      status: 'Completed',
      started: { physical_ms: NOW_NUM + 20, logical: 0 },
      finished: { physical_ms: NOW_NUM + 120, logical: 0 },
      usage: { tokens: 12 }
    })
  );
  if (monitor.last_seen[TEST_DID].physical_ms !== NOW_NUM + 20) {
    throw new Error('heartbeat last_seen was not recorded');
  }
  assertNonZeroHash(monitor.history[TEST_DID][0].receipt_hash, 'heartbeat receipt_hash');
  return monitor;
});

const catapultMonitor = setup(() =>
  wasm.wasm_record_heartbeat(
    JSON.stringify({
      last_seen: {},
      history: {},
      warn_ms: 180000,
      timeout_ms: 300000
    }),
    JSON.stringify({
      id: UUID_2,
      newco_id: UUID_3,
      agent_did: TEST_DID,
      status: 'Completed',
      started: { physical_ms: NOW_NUM + 20, logical: 0 },
      finished: { physical_ms: NOW_NUM + 120, logical: 0 },
      usage: { tokens: 12 }
    })
  ));

test('wasm_check_heartbeat_health', () => {
  if (!catapultMonitor) throw new Error('skipped -- no Catapult heartbeat monitor');
  const health = wasm.wasm_check_heartbeat_health(
    JSON.stringify(catapultMonitor),
    BigInt(NOW_NUM + 300000)
  );
  if (health.agent_count !== 1 || health.alerts.length !== 1) {
    throw new Error('heartbeat health should report one delayed agent');
  }
  return health;
});

test('wasm_create_goal and wasm_update_goal_status', () => {
  const tree = wasm.wasm_create_goal(
    JSON.stringify({ goals: {} }),
    JSON.stringify({
      id: UUID_3,
      title: 'Bridge goal',
      description: null,
      level: 'Company',
      status: 'Planned',
      parent_id: null,
      owner_slot: null,
      created: { physical_ms: NOW_NUM + 30, logical: 0 },
      updated: { physical_ms: NOW_NUM + 30, logical: 0 }
    })
  );
  const updated = wasm.wasm_update_goal_status(
    JSON.stringify(tree),
    UUID_3,
    JSON.stringify('Completed'),
    BigInt(NOW_NUM + 40),
    0
  );
  if (updated.goals[UUID_3].status !== 'Completed') {
    throw new Error('goal status was not updated');
  }
  if (updated.goals[UUID_3].updated.physical_ms !== NOW_NUM + 40) {
    throw new Error('goal updated timestamp was not caller-supplied HLC');
  }
  return updated;
});

const catapultGoalTree = setup(() =>
  wasm.wasm_create_goal(
    JSON.stringify({ goals: {} }),
    JSON.stringify({
      id: UUID_3,
      title: 'Bridge goal',
      description: null,
      level: 'Company',
      status: 'Completed',
      parent_id: null,
      owner_slot: null,
      created: { physical_ms: NOW_NUM + 30, logical: 0 },
      updated: { physical_ms: NOW_NUM + 30, logical: 0 }
    })
  ));

test('wasm_goal_alignment_score', () => {
  if (!catapultGoalTree) throw new Error('skipped -- no Catapult goal tree');
  const score = wasm.wasm_goal_alignment_score(JSON.stringify(catapultGoalTree));
  if (score !== 10000) {
    throw new Error('single completed goal should score 10000 basis points');
  }
  return score;
});

test('wasm_generate_franchise_receipt', () => {
  try {
    wasm.wasm_generate_franchise_receipt(UUID_1, JSON.stringify('Instantiate'), TEST_DID);
  } catch (err) {
    if (!String(err).includes('server-side Ed25519 signer')) throw err;
    return true;
  }
  throw new Error('franchise receipt generation must refuse without a server-side signer');
});

test('wasm_verify_franchise_receipt_chain', () => {
  const ok = wasm.wasm_verify_franchise_receipt_chain(JSON.stringify({ receipts: [] }));
  if (!ok) throw new Error('empty franchise receipt chain should verify');
  return ok;
});

// =========================================================================
// Module 9 — Risk Assessment
// =========================================================================

console.log('\n--- Risk Assessment ---');

test('wasm_assess_risk and wasm_verify_risk_attestation use caller signer and caller HLC', () => {
  const attesterPublicKey = publicKeyForSecret(DUMMY_SECRET_HEX);
  const attestation = wasm.wasm_assess_risk(
    TEST_DID,
    TEST_DID_2,
    TEXT_BYTES,
    JSON.stringify('Low'),
    JSON.stringify({
      validity_ms: 3600000,
      attester_secret_hex: DUMMY_SECRET_HEX,
      now_physical_ms: NOW_NUM,
      now_logical: 0
    })
  );
  if (!wasm.wasm_verify_risk_attestation(JSON.stringify(attestation), attesterPublicKey)) {
    throw new Error('risk attestation must verify against caller-supplied attester key');
  }
  if (attestation.timestamp.physical_ms !== NOW_NUM || attestation.timestamp.logical !== 0) {
    throw new Error('risk attestation timestamp must be caller-supplied HLC');
  }
  return attestation;
});

const riskAttestation = setup(() =>
  wasm.wasm_assess_risk(
    TEST_DID,
    TEST_DID_2,
    TEXT_BYTES,
    JSON.stringify('Low'),
    JSON.stringify({
      validity_ms: 3600000,
      attester_secret_hex: DUMMY_SECRET_HEX,
      now_physical_ms: NOW_NUM,
      now_logical: 0
    })
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
    evidence_hash: EVIDENCE_32_BYTES,
    timestamp: NOW_TS
  };
  const input = {
    id: '11111111-1111-1111-1111-111111111111',
    created: NOW_TS,
    signal,
    path: 'Standard'
  };
  return wasm.wasm_escalate(JSON.stringify(input));
});

const escCase = setup(() => {
  const signal = {
    source: TEST_DID,
    signal_type: 'AnomalousPattern',
    confidence: 80,
    evidence_hash: EVIDENCE_32_BYTES,
    timestamp: NOW_TS
  };
  const input = {
    id: '22222222-2222-2222-2222-222222222222',
    created: NOW_TS,
    signal,
    path: 'Standard'
  };
  return wasm.wasm_escalate(JSON.stringify(input));
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
  wasm.wasm_audit_append(UUID_1, NOW_MS, 0, TEST_DID, 'create', 'success', ZERO_32_HEX));

const auditEntry = setup(() =>
  wasm.wasm_audit_append(UUID_1, NOW_MS, 0, TEST_DID, 'create', 'success', ZERO_32_HEX));

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
    UUID_1,
    NOW_MS,
    0,
    Buffer.from('test proposal').toString('hex'),
    JSON.stringify([TEST_DID, TEST_DID_2])
  ));

const deliberation = setup(() =>
  wasm.wasm_open_deliberation(
    UUID_1,
    NOW_MS,
    0,
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
    UUID_1,
    NOW_MS,
    0,
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
    UUID_1,
    'Test Decision',
    JSON.stringify('Operational'),
    NONZERO_32_HEX,
    NOW_MS,
    0
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
    UUID_2,
    TEST_DID,
    UUID_1,
    JSON.stringify('ProceduralError'),
    NONZERO_32_HEX,
    NOW_MS,
    0
  ));

const challenge = setup(() =>
  wasm.wasm_file_challenge(
    UUID_2,
    TEST_DID,
    UUID_1,
    JSON.stringify('ProceduralError'),
    NONZERO_32_HEX,
    NOW_MS,
    0
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
    UUID_3,
    'Bridge Test Decision',
    JSON.stringify('Operational'),
    NONZERO_32_HEX,
    NOW_MS,
    0
  ));

const decision = setup(() =>
  wasm.wasm_create_decision(
    UUID_3,
    'Bridge Test Decision',
    JSON.stringify('Operational'),
    NONZERO_32_HEX,
    NOW_MS,
    0
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
    TEST_DID,
    BigInt(NOW_NUM + 1),
    0
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
    3,
    1
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
    UUID_4,
    TEST_DID_2,
    TEST_DID,
    JSON.stringify('Censure'),
    'Violation of governance protocol',
    NONZERO_32_HEX,
    NOW_MS,
    0
  ));

const accAction = setup(() =>
  wasm.wasm_propose_accountability(
    UUID_4,
    TEST_DID_2,
    TEST_DID,
    JSON.stringify('Censure'),
    'Violation of governance protocol',
    NONZERO_32_HEX,
    NOW_MS,
    0
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
    UUID_1,
    JSON.stringify('SystemHalt'),
    TEST_DID,
    'Critical security breach',
    BigInt(50000),
    NONZERO_32_HEX,
    JSON.stringify(emergencyPolicy),
    NOW_MS,
    0
  ));

const emergencyAction = setup(() =>
  wasm.wasm_create_emergency_action(
    UUID_1,
    JSON.stringify('SystemHalt'),
    TEST_DID,
    'Critical security breach',
    BigInt(50000),
    NONZERO_32_HEX,
    JSON.stringify(emergencyPolicy),
    NOW_MS,
    0
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
// Module 26 — Bridge Coverage Guard
// =========================================================================

console.log('\n--- Bridge Coverage Guard ---');

test('all wasm exports have bridge verification', () => {
  const exported = Object.keys(wasm).filter((name) => name.startsWith('wasm_')).sort();
  const missing = exported.filter((name) => !coveredExports.has(name));
  if (missing.length > 0) {
    throw new Error(`missing bridge verification for exports: ${missing.join(', ')}`);
  }
  return { exported: exported.length, covered: coveredExports.size };
});

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
