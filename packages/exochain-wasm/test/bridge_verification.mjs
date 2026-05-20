// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Bridge Verification Test — WASM binding smoke-test harness
 *
 * Calls the covered exported wasm_ bridge functions with valid minimal inputs,
 * and verifies intentionally disabled raw-secret entry points fail closed.
 *
 * Run:  node packages/exochain-wasm/test/bridge_verification.mjs
 */

import { createRequire } from 'node:module';
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as nodeSign } from 'node:crypto';
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

function expectErrorContains(label, fn, expected) {
  try {
    fn();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (!msg.includes(expected)) {
      throw new Error(`${label} returned unexpected error: ${msg}`);
    }
    return true;
  }
  throw new Error(`${label} must fail closed`);
}

function signatureJsonFromHex(signatureHex) {
  return { Ed25519: Array.from(Buffer.from(signatureHex, 'hex')) };
}

function publicKeyHexFromPublicKey(publicKey) {
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return Buffer.from(der).subarray(-32).toString('hex');
}

function signerFromPrivateKey(privateKey) {
  const publicKey = createPublicKey(privateKey);
  return {
    publicKeyHex: publicKeyHexFromPublicKey(publicKey),
    signHex: (message) => nodeSign(null, Buffer.from(message), privateKey).toString('hex')
  };
}

function randomEd25519Signer() {
  const { privateKey } = generateKeyPairSync('ed25519');
  return signerFromPrivateKey(privateKey);
}

function seededEd25519Signer(secretHex) {
  const pkcs8SeedPrefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const privateKey = createPrivateKey({
    key: Buffer.concat([pkcs8SeedPrefix, Buffer.from(secretHex, 'hex')]),
    format: 'der',
    type: 'pkcs8'
  });
  return signerFromPrivateKey(privateKey);
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
const signer1 = seededEd25519Signer(DUMMY_SECRET_HEX);
const signer2 = seededEd25519Signer(DUMMY_SECRET_HEX_2);
const signer3 = seededEd25519Signer(DUMMY_SECRET_HEX_3);

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

function hashHex(hashValue) {
  return Buffer.from(hashBytes(hashValue)).toString('hex');
}

function assertHex(value, bytes, label) {
  if (typeof value !== 'string' || !new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(value)) {
    throw new Error(`${label} must be ${bytes} hex bytes`);
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

test('wasm_sign rejects raw secret-key signing', () =>
  expectErrorContains(
    'wasm_sign',
    () => wasm.wasm_sign(TEXT_BYTES, DUMMY_SECRET_HEX),
    'raw secret-key signing is disabled'
  ));

test('wasm_ed25519_public_from_secret rejects raw secret-key derivation', () =>
  expectErrorContains(
    'wasm_ed25519_public_from_secret',
    () => wasm.wasm_ed25519_public_from_secret(DUMMY_SECRET_HEX),
    'raw secret-key public derivation is disabled'
  ));

const EVENT_SEED = new TextEncoder().encode('event-seed-1');
const EVENT_ID = wasm.wasm_compute_event_id(EVENT_SEED);

test('wasm_compute_event_id', () => {
  const again = wasm.wasm_compute_event_id(EVENT_SEED);
  if (EVENT_ID !== again) {
    throw new Error('event ID derivation must be deterministic for caller seed');
  }
  return EVENT_ID;
});

// =========================================================================
// Module 3 — Events
// =========================================================================

console.log('\n--- Events ---');

test('wasm_create_signed_event rejects raw secret-key event signing', () =>
  expectErrorContains(
    'wasm_create_signed_event',
    () => wasm.wasm_create_signed_event(
      JSON.stringify('AuditEntry'),
      TEXT_BYTES,
      TEST_DID,
      DUMMY_SECRET_HEX,
      EVENT_ID,
      NOW_MS,
      7
    ),
    'raw secret-key event signing is disabled'
  ));

const eventSigningPayloadHex = setup(() =>
  wasm.wasm_event_signing_payload(
    JSON.stringify('AuditEntry'),
    TEXT_BYTES,
    TEST_DID,
    EVENT_ID,
    NOW_MS,
    7
  ));
const eventSignatureJson = eventSigningPayloadHex
  ? signatureJsonFromHex(signer1.signHex(Buffer.from(eventSigningPayloadHex, 'hex')))
  : null;

test('wasm_event_signing_payload', () => {
  if (!eventSigningPayloadHex || eventSigningPayloadHex.length === 0) {
    throw new Error('event signing payload must be non-empty');
  }
  return eventSigningPayloadHex;
});

test('wasm_create_event_with_signature', () => {
  if (!eventSignatureJson) throw new Error('skipped -- no event signature');
  return wasm.wasm_create_event_with_signature(
    JSON.stringify('AuditEntry'),
    TEXT_BYTES,
    TEST_DID,
    JSON.stringify(eventSignatureJson),
    signer1.publicKeyHex,
    EVENT_ID,
    NOW_MS,
    7
  );
});

const signedEvent = setup(() =>
  eventSignatureJson && wasm.wasm_create_event_with_signature(
    JSON.stringify('AuditEntry'),
    TEXT_BYTES,
    TEST_DID,
    JSON.stringify(eventSignatureJson),
    signer1.publicKeyHex,
    EVENT_ID,
    NOW_MS,
    7
  ));

test('wasm_verify_event', () => {
  if (!signedEvent) throw new Error('skipped -- no signed event from setup');
  if (String(signedEvent.id) !== EVENT_ID) {
    throw new Error('signed event did not preserve caller-supplied event ID');
  }
  if (BigInt(signedEvent.timestamp?.physical_ms) !== NOW_MS || signedEvent.timestamp?.logical !== 7) {
    throw new Error('signed event did not preserve caller-supplied HLC timestamp');
  }
  return wasm.wasm_verify_event(JSON.stringify(signedEvent), signer1.publicKeyHex);
});

// =========================================================================
// Module 3b — Messaging / Death Verification
// =========================================================================

console.log('\n--- Messaging / Death Verification ---');

test('wasm_generate_x25519_keypair rejects internal X25519 key generation', () =>
  expectErrorContains(
    'wasm_generate_x25519_keypair',
    () => wasm.wasm_generate_x25519_keypair(),
    'external key management'
  ));

const recipientKex = { public_key_hex: NONZERO_32_HEX };

test('wasm_x25519_public_from_secret rejects raw X25519 secret derivation', () =>
  expectErrorContains(
    'wasm_x25519_public_from_secret',
    () => wasm.wasm_x25519_public_from_secret(DUMMY_SECRET_HEX),
    'raw X25519 secret public derivation is disabled'
  ));

test('wasm_encrypt_message rejects raw sender signing', () => {
  if (!recipientKex) throw new Error('skipped -- no recipient X25519 keypair');
  return expectErrorContains(
    'wasm_encrypt_message',
    () => wasm.wasm_encrypt_message(
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
    ),
    'raw Ed25519 sender signing is disabled'
  );
});

const preparedEnvelope = setup(() =>
  recipientKex && wasm.wasm_prepare_encrypted_message(
    'bridge encrypted message',
    JSON.stringify('Text'),
    TEST_DID,
    TEST_DID_2,
    recipientKex.public_key_hex,
    DUMMY_SECRET_HEX_2,
    '018f7a96-8ad0-7c4f-8e0f-111111111202',
    7001n,
    0,
    false,
    0
  ));
const encryptedEnvelopeSignatureHex = preparedEnvelope
  ? signer1.signHex(Buffer.from(preparedEnvelope.signing_payload_hex, 'hex'))
  : null;

test('wasm_prepare_encrypted_message', () => {
  if (!preparedEnvelope) throw new Error('skipped -- no prepared envelope');
  if (preparedEnvelope.envelope.sender_did !== TEST_DID || preparedEnvelope.envelope.recipient_did !== TEST_DID_2) {
    throw new Error('prepared envelope must retain sender and recipient DIDs');
  }
  if (!preparedEnvelope.signing_payload_hex) {
    throw new Error('prepared envelope must expose signing payload');
  }
  if (preparedEnvelope.envelope.kdf_version !== 2) {
    throw new Error('prepared envelope must expose explicit transcript-salted KDF version');
  }
  return preparedEnvelope;
});

test('wasm_attach_message_signature', () => {
  if (!preparedEnvelope || !encryptedEnvelopeSignatureHex) {
    throw new Error('skipped -- no prepared envelope signature');
  }
  return wasm.wasm_attach_message_signature(
    JSON.stringify(preparedEnvelope.envelope),
    signer1.publicKeyHex,
    encryptedEnvelopeSignatureHex
  );
});

const encryptedEnvelope = setup(() =>
  preparedEnvelope && encryptedEnvelopeSignatureHex && wasm.wasm_attach_message_signature(
    JSON.stringify(preparedEnvelope.envelope),
    signer1.publicKeyHex,
    encryptedEnvelopeSignatureHex
  ));

test('wasm_verify_message_signature', () => {
  if (!encryptedEnvelope) {
    throw new Error('skipped -- no encrypted envelope');
  }
  const ok = wasm.wasm_verify_message_signature(
    JSON.stringify(encryptedEnvelope),
    signer1.publicKeyHex
  );
  if (!ok) throw new Error('message signature must verify with sender public key');
  return ok;
});

test('wasm_decrypt_message', () => {
  if (!encryptedEnvelope) {
    throw new Error('skipped -- no encrypted envelope');
  }
  return expectErrorContains(
    'wasm_decrypt_message',
    () => wasm.wasm_decrypt_message(
      JSON.stringify(encryptedEnvelope),
      NONZERO_32_HEX,
      signer1.publicKeyHex
    ),
    'decryption failed'
  );
});

const initiatorPublicKey = signer2.publicKeyHex;
const trusteePublicKey = signer3.publicKeyHex;
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
    deathClaimNonceHex,
    NOW_MS,
    0
  );
});

const deathInitialPayload = setup(() =>
  deathTrusteesJson && wasm.wasm_death_verification_initial_signing_payload(
    TEST_DID,
    TEST_DID_2,
    2,
    deathTrusteesJson,
    deathClaimNonceHex,
    NOW_MS,
    0
  ));
const deathInitialSignatureHex = setup(() =>
  deathInitialPayload && signer2.signHex(deathInitialPayload));

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
    TEST_DID_3,
    BigInt(NOW_NUM + 1),
    0
  );
});

const deathConfirmationPayload = setup(() =>
  deathState && wasm.wasm_death_verification_confirmation_signing_payload(
    JSON.stringify(deathState),
    TEST_DID_3,
    BigInt(NOW_NUM + 1),
    0
  ));
const deathConfirmationSignatureHex = setup(() =>
  deathConfirmationPayload && signer3.signHex(deathConfirmationPayload));

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
// fresh ephemeral bailee keypair. WASM exposes the payload for external
// signing, but acceptance itself must go through a trusted core runtime
// adapter with DID resolution.
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

test('wasm_accept_bailment rejects caller-supplied bailee key material', () => {
  if (!bailment || !bailSig) throw new Error('skipped -- no bailment from setup');
  return expectErrorContains(
    'wasm_accept_bailment',
    () => wasm.wasm_accept_bailment(
      JSON.stringify(bailment),
      JSON.stringify(bailPubKeyBytes),
      JSON.stringify(bailSig.signature)
    ),
    'cannot trust caller-supplied DID key material'
  );
});

const terminationBailment = bailment;

test('wasm_bailment_termination_payload', () => {
  if (!terminationBailment) throw new Error('skipped -- no bailment from setup');
  const payload = wasm.wasm_bailment_termination_payload(
    JSON.stringify(terminationBailment),
    TEST_DID
  );
  if (!payload || payload.length === 0) {
    throw new Error('termination payload must be non-empty');
  }
  return payload;
});

test('wasm_terminate_bailment rejects unsigned termination', () => {
  if (!terminationBailment) throw new Error('skipped -- no bailment from setup');
  return expectErrorContains(
    'wasm_terminate_bailment',
    () => wasm.wasm_terminate_bailment(
      JSON.stringify(terminationBailment),
      TEST_DID
    ),
    'unsigned bailment termination is disabled'
  );
});

test('wasm_terminate_bailment_signed rejects caller-supplied DID key material', () => {
  if (!terminationBailment) throw new Error('skipped -- no bailment from setup');
  return expectErrorContains(
    'wasm_terminate_bailment_signed',
    () => wasm.wasm_terminate_bailment_signed(
      JSON.stringify(terminationBailment),
      TEST_DID,
      JSON.stringify([[TEST_DID, signer1.publicKeyHex]]),
      JSON.stringify(signatureJsonFromHex(signer1.signHex(TEXT_BYTES)))
    ),
    'cannot trust caller-supplied DID key material'
  );
});

// =========================================================================
// Module 7 — Shamir Secret Sharing
// =========================================================================

console.log('\n--- Shamir ---');

const SHAMIR_ENTROPY = new TextEncoder().encode('exo-wasm-shamir-entropy-v1-explicit');

test('wasm_shamir_split rejects missing caller entropy', () =>
  expectErrorContains(
    'wasm_shamir_split',
    () => wasm.wasm_shamir_split(TEXT_BYTES, 2, 3),
    'caller-supplied entropy'
  ));

test('wasm_shamir_split_with_entropy', () =>
  wasm.wasm_shamir_split_with_entropy(TEXT_BYTES, 2, 3, SHAMIR_ENTROPY));

const shares = setup(() => wasm.wasm_shamir_split_with_entropy(TEXT_BYTES, 2, 3, SHAMIR_ENTROPY));

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

function catapultAgent(slot, did, displayName, offsetMs) {
  return {
    did,
    slot,
    display_name: displayName,
    capabilities: ['command', 'operations'],
    status: 'Active',
    last_heartbeat: { physical_ms: NOW_NUM + offsetMs, logical: 0 },
    budget_spent_cents: 0,
    budget_limit_cents: 1000000,
    hired_at: { physical_ms: NOW_NUM + offsetMs, logical: 0 },
    hired_by: TEST_DID,
    commandbase_profile: null
  };
}

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
  const withCommander = wasm.wasm_hire_agent(
    JSON.stringify(catapultNewco),
    JSON.stringify(ventureCommander)
  );
  const withDeputy = wasm.wasm_hire_agent(
    JSON.stringify(withCommander),
    JSON.stringify(catapultAgent('OperationsDeputy', 'did:exo:operations-deputy', 'Bridge Operations Deputy', 55))
  );
  const completePaceRoster = wasm.wasm_hire_agent(
    JSON.stringify(withDeputy),
    JSON.stringify(catapultAgent('ProcessArchitect', 'did:exo:process-architect', 'Bridge Process Architect', 60))
  );
  const chain = wasm.wasm_oda_authority_chain(JSON.stringify(completePaceRoster));
  if (chain.primary !== TEST_DID_3) {
    throw new Error('PACE primary authority should be the VentureCommander in bridge fixture');
  }
  if (chain.alternates[0] !== 'did:exo:operations-deputy' || chain.contingency[0] !== 'did:exo:process-architect') {
    throw new Error('PACE authority chain must include staffed alternate and contingency slots');
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
  return expectErrorContains(
    'wasm_verify_franchise_receipt_chain',
    () => wasm.wasm_verify_franchise_receipt_chain(JSON.stringify({ receipts: [] })),
    'trusted core runtime adapter'
  );
});

test('wasm_verify_franchise_receipt_chain_with_keys', () => {
  return expectErrorContains(
    'wasm_verify_franchise_receipt_chain_with_keys',
    () => wasm.wasm_verify_franchise_receipt_chain_with_keys(
      JSON.stringify({ receipts: [] }),
      JSON.stringify([])
    ),
    'trusted core runtime adapter'
  );
});

// =========================================================================
// Module 9 — Risk Assessment
// =========================================================================

console.log('\n--- Risk Assessment ---');

test('wasm_assess_risk and wasm_verify_risk_attestation use caller signer and caller HLC', () => {
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
  if (!wasm.wasm_verify_risk_attestation(JSON.stringify(attestation), signer1.publicKeyHex)) {
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

test('wasm_verify_authority_chain rejects caller-supplied keys', () => {
  if (!chain) throw new Error('skipped -- no chain from setup');
  return expectErrorContains(
    'wasm_verify_authority_chain',
    () => wasm.wasm_verify_authority_chain(
      JSON.stringify(chain),
      NOW_MS,
      JSON.stringify([[TEST_DID, signer1.publicKeyHex]])
    ),
    'trusted core runtime adapter'
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

const governanceFindingsJson = JSON.stringify([
  { id: 'F-001', severity: 'critical', title: 'Unsigned injection' },
]);

test('wasm_governance_findings_digest is deterministic', () => {
  const a = wasm.wasm_governance_findings_digest(governanceFindingsJson);
  const b = wasm.wasm_governance_findings_digest(governanceFindingsJson);
  if (a !== b) throw new Error('findings digest must be deterministic');
  assertHex(a, 32, 'findings digest');
  return a;
});

test('wasm_verify_governance_attestation_with_trusted_keys accepts valid signatures', () => {
  const digestHex = wasm.wasm_governance_findings_digest(governanceFindingsJson);
  const signature = signatureJsonFromHex(signer1.signHex(Buffer.from(digestHex, 'hex')));
  return wasm.wasm_verify_governance_attestation_with_trusted_keys(
    'did:exo:monitor',
    governanceFindingsJson,
    JSON.stringify(signature),
    JSON.stringify({ 'did:exo:monitor': signer1.publicKeyHex }),
  );
});

test('wasm_verify_governance_attestation_with_trusted_keys rejects signatures replayed for substituted findings', () => {
  const signedFindingsJson = JSON.stringify([
    { id: 'F-001', severity: 'low', title: 'Benign finding' },
  ]);
  const substitutedFindingsJson = JSON.stringify([
    { id: 'F-999', severity: 'critical', title: 'Substituted critical finding' },
  ]);
  const digestHex = wasm.wasm_governance_findings_digest(signedFindingsJson);
  const signature = signatureJsonFromHex(signer1.signHex(Buffer.from(digestHex, 'hex')));

  return expectErrorContains(
    'wasm_verify_governance_attestation_with_trusted_keys',
    () => wasm.wasm_verify_governance_attestation_with_trusted_keys(
      'did:exo:monitor',
      substitutedFindingsJson,
      JSON.stringify(signature),
      JSON.stringify({ 'did:exo:monitor': signer1.publicKeyHex }),
    ),
    'governance attestation rejected',
  );
});

test('wasm_verify_governance_attestation_with_trusted_keys rejects invalid signatures', () =>
  expectErrorContains(
    'wasm_verify_governance_attestation_with_trusted_keys',
    () => wasm.wasm_verify_governance_attestation_with_trusted_keys(
      'did:exo:monitor',
      governanceFindingsJson,
      JSON.stringify({ Ed25519: Array.from({ length: 64 }, () => 0) }),
      JSON.stringify({ 'did:exo:monitor': signer1.publicKeyHex }),
    ),
    'governance attestation rejected',
  ));

test('wasm_verify_governance_attestation_with_trusted_keys rejects untrusted signers', () => {
  const digestHex = wasm.wasm_governance_findings_digest(governanceFindingsJson);
  const signature = signatureJsonFromHex(signer1.signHex(Buffer.from(digestHex, 'hex')));
  return expectErrorContains(
    'wasm_verify_governance_attestation_with_trusted_keys',
    () => wasm.wasm_verify_governance_attestation_with_trusted_keys(
      'did:exo:monitor',
      governanceFindingsJson,
      JSON.stringify(signature),
      JSON.stringify({ 'did:exo:other-monitor': signer1.publicKeyHex }),
    ),
    'governance attestation signer is not trusted',
  );
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
    actions: {
      read: { required_level: 'ReadOnly', quorum_policy: null, independence_required: false },
      write: { required_level: 'Contributor', quorum_policy: null, independence_required: false }
    },
    policy_hash: ZERO_32_BYTES
  };
  const registry = [{ did: TEST_DID, level: 'ReadOnly' }];
  return wasm.wasm_check_clearance(
    TEST_DID,
    'read',
    JSON.stringify(policy),
    JSON.stringify(registry)
  );
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
  return expectErrorContains(
    'wasm_close_deliberation',
    () => wasm.wasm_close_deliberation(
      JSON.stringify(deliberation),
      JSON.stringify(quorumPolicy),
      JSON.stringify([])
    ),
    'trusted core runtime adapter'
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
  return expectErrorContains(
    'wasm_compute_quorum',
    () => wasm.wasm_compute_quorum(
      JSON.stringify(approvals),
      JSON.stringify(policy),
      JSON.stringify([])
    ),
    'trusted core runtime adapter'
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
const canonicalAllTrueTncFlags = {
  constitutional_hash_valid: true,
  consent_verified: true,
  identity_verified: true,
  evidence_complete: true,
  quorum_met: true,
  human_gate_satisfied: true,
  authority_chain_verified: true,
  ai_ceilings_externally_verified: true
};
const structurallyCompleteTncDecision = minDecision ? {
  ...minDecision,
  authority_chain: [{
    actor_did: TEST_DID,
    actor_kind: 'Human',
    delegation_hash: ZERO_32_BYTES,
    timestamp: NOW_TS
  }],
  votes: [],
  evidence_bundle: [],
  receipt_chain: []
} : {};

test('wasm_enforce_all_tnc rejects self-asserted proof flags', () => {
  const result = wasm.wasm_enforce_all_tnc(
    JSON.stringify(structurallyCompleteTncDecision),
    JSON.stringify(canonicalAllTrueTncFlags)
  );
  if (result.ok !== false) {
    throw new Error('self-asserted TNC proof flags must fail closed');
  }
  if (!String(result.error).includes('authority chain not verified')) {
    throw new Error(`unexpected TNC error: ${result.error}`);
  }
  return result;
});

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

test('wasm_verify_forum_authority_with_key rejects untrusted signature', () => {
  const authority = {
    root_did: TEST_DID,
    constitution_hash: EVIDENCE_32_BYTES,
    rules: [{ name: 'TestRule', hash: EVIDENCE_32_BYTES }],
    signature: ephResult.signature
  };
  const result = wasm.wasm_verify_forum_authority_with_key(
    JSON.stringify(authority),
    ephResult.public_key
  );
  if (result.ok !== false) {
    throw new Error('forged forum authority signature must fail closed');
  }
  return result;
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

test('wasm_transition_decision rejects unadjudicated transition', () =>
  expectErrorContains(
    'wasm_transition_decision',
    () => wasm.wasm_transition_decision(
      decJson,
      JSON.stringify('Submitted'),
      TEST_DID,
      BigInt(NOW_NUM + 1),
      0
    ),
    'unadjudicated decision transitions are disabled'
  ));

function minimalDecisionTransitionRequest() {
  if (!decision) throw new Error('skipped -- no decision from setup');
  const transitionPermission = 'bcts:transition:Draft->Submitted';
  return {
    decision,
    to_state: 'Submitted',
    actor_did: TEST_DID,
    timestamp_ms: NOW_NUM + 1,
    timestamp_logical: 0,
    action: {
      actor: TEST_DID,
      action: transitionPermission,
      required_permissions: { permissions: [transitionPermission] },
      is_self_grant: false,
      modifies_kernel: false
    },
    context: {
      actor_roles: [],
      authority_chain: { links: [] },
      consent_records: [],
      bailment_state: 'None',
      human_override_preserved: true,
      actor_permissions: { permissions: [transitionPermission] },
      trusted_authority_keys: {},
      trusted_provenance_keys: {},
      provenance: null,
      quorum_evidence: null,
      active_challenge_reason: null
    }
  };
}

test('wasm_transition_decision_adjudicated rejects caller-supplied invariant set', () => {
  const request = minimalDecisionTransitionRequest();
  request.invariant_set = { invariants: [] };

  return expectErrorContains(
    'wasm_transition_decision_adjudicated',
    () => wasm.wasm_transition_decision_adjudicated(
      JSON.stringify(request),
      new TextEncoder().encode('bridge constitution')
    ),
    'caller-supplied invariant_set is rejected'
  );
});

test('wasm_transition_decision_adjudicated enforces canonical invariants', () => {
  const request = minimalDecisionTransitionRequest();

  return expectErrorContains(
    'wasm_transition_decision_adjudicated',
    () => wasm.wasm_transition_decision_adjudicated(
      JSON.stringify(request),
      new TextEncoder().encode('bridge constitution')
    ),
    'BCTS transition denied by kernel'
  );
});

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
  return expectErrorContains(
    'wasm_ratify_constitution',
    () => wasm.wasm_ratify_constitution(
      JSON.stringify(corpus),
      JSON.stringify(sigs),
      JSON.stringify(quorum),
      JSON.stringify([]),
      NOW_MS
    ),
    'trusted core runtime adapter'
  );
});

test('wasm_amend_constitution', () => {
  const corpus = { version: 1, hash: ZERO_32_BYTES, articles: [], ratified_at: NOW_TS, amendment_count: 0 };
  const amendment = { id: 'art-1', title: 'Test', tier: 'Articles', text_hash: ZERO_32_BYTES, status: 'Active' };
  const sigs = [];
  const quorum = { required_signatures: 0, required_fraction_pct: 0 };
  return expectErrorContains(
    'wasm_amend_constitution',
    () => wasm.wasm_amend_constitution(
      JSON.stringify(corpus),
      JSON.stringify(amendment),
      JSON.stringify(sigs),
      JSON.stringify(quorum),
      JSON.stringify([]),
      NOW_MS
    ),
    'trusted core runtime adapter'
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
    0,
    JSON.stringify([])
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
    0,
    JSON.stringify([])
  ));

test('wasm_create_emergency_action rejects repeated same-actor emergency history', () => {
  const onePerActorPolicy = {
    ...emergencyPolicy,
    max_per_quarter_per_actor: 1
  };
  const first = wasm.wasm_create_emergency_action(
    UUID_1,
    JSON.stringify('SystemHalt'),
    TEST_DID,
    'Critical security breach',
    BigInt(50000),
    NONZERO_32_HEX,
    JSON.stringify(onePerActorPolicy),
    NOW_MS,
    0,
    JSON.stringify([])
  );

  return expectErrorContains(
    'wasm_create_emergency_action',
    () => wasm.wasm_create_emergency_action(
      UUID_2,
      JSON.stringify('RoleEscalation'),
      TEST_DID,
      'Second same-actor emergency',
      BigInt(50000),
      NONZERO_32_HEX,
      JSON.stringify(onePerActorPolicy),
      NOW_MS + 1n,
      0,
      JSON.stringify([first])
    ),
    'Emergency error',
  );
});

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
// Module 26 — Economy / HonorGood
// =========================================================================

console.log('\n--- Economy / HonorGood ---');

const economyMission = {
  mission_id: ZERO_32_BYTES,
  name: 'HonorGood bridge mission',
  mission_type: 'UpstreamRecognition',
  owner_did: TEST_DID,
  principal_did: TEST_DID_2,
  purpose: {
    problem: 'WASM validation',
    served_party: 'EXOCHAIN',
    promised_outcome: 'deterministic economy anchor',
    expected_value: 'stable bridge output',
    risk_surface: 'WASM boundary',
    proof_required: 'canonical content hash',
    success_condition: 'nonzero anchor hash'
  },
  related_platforms: ['EXOCHAIN'],
  expected_value_micro_exo: null,
  ruleset_id: Array.from(Buffer.from('31'.repeat(32), 'hex')),
  status: 'Active',
  created_at: NOW_TS,
  content_hash: ZERO_32_BYTES
};

const missionAnchor = setup(() =>
  wasm.wasm_anchor_economy_mission(JSON.stringify(economyMission), ''));

test('wasm_anchor_economy_mission', () => {
  if (!missionAnchor) throw new Error('skipped -- no mission anchor from setup');
  assertNonZeroHash(missionAnchor.object.mission_id, 'mission id');
  assertNonZeroHash(missionAnchor.anchor.anchor_hash, 'mission economy anchor');
  if (missionAnchor.anchor.object_kind !== 'mission') {
    throw new Error('mission anchor object kind must be stable snake_case');
  }
  if (missionAnchor.local_settlement_authority !== false) {
    throw new Error('WASM bridge must not claim local settlement authority');
  }
  return missionAnchor;
});

const participantRef = {
  ProjectTreasury: {
    project: 'Archon',
    treasury_ref: 'public-project-treasury:Archon'
  }
};

const economyRuleset = {
  ruleset_id: ZERO_32_BYTES,
  applies_to: [{ ReceivingSystem: 'ExoForge' }],
  share_lines: [{
    recipient: participantRef,
    recipient_type: 'ProjectTreasury',
    basis: 'RecognitionOnly',
    share_bp: 0,
    source_receipt_id: null,
    legacy_receipt_id: null
  }],
  duration_policy: 'RecognitionOnly',
  review_frequency: 'None',
  requires_human_approval: true,
  allows_overlapping_bases: false,
  legal_effect_required: 'RatifiedAgreement',
  status: 'Offered',
  created_at: NOW_TS,
  content_hash: ZERO_32_BYTES
};

const rulesetAnchor = setup(() =>
  wasm.wasm_anchor_economy_ruleset(
    JSON.stringify(economyRuleset),
    missionAnchor ? hashHex(missionAnchor.anchor.anchor_hash) : ''
  ));

test('wasm_anchor_economy_ruleset', () => {
  if (!rulesetAnchor) throw new Error('skipped -- no ruleset anchor from setup');
  assertNonZeroHash(rulesetAnchor.object.ruleset_id, 'ruleset id');
  if (rulesetAnchor.anchor.object_kind !== 'honorgood_ruleset') {
    throw new Error('ruleset anchor object kind must be stable snake_case');
  }
  return rulesetAnchor;
});

const economyLegacyReceipt = {
  legacy_receipt_id: ZERO_32_BYTES,
  contributor: participantRef,
  contribution_name: 'Archon',
  contribution_type: 'open-source implementation automation',
  source_uri: 'https://github.com/coleam00/Archon',
  license: 'MIT',
  receiving_system: 'ExoForge',
  materiality_tier: 'Genesis',
  materiality_review: {
    tier: 'Genesis',
    reviewer_did: TEST_DID,
    evidence_hash: EVIDENCE_32_BYTES,
    rationale_hash: Array.from(Buffer.from('aa'.repeat(32), 'hex')),
    rationale_ref: 'docs/economy/examples/archon_exoforge_legacy_receipt.yml',
    reviewed_at: NOW_TS,
    status: 'EvidenceBacked'
  },
  attribution_required: true,
  settlement_eligible: false,
  economic_ruleset_id: null,
  beneficiary: {
    beneficiary_type: 'ProjectTreasury',
    reference: participantRef
  },
  active_while_materially_used: true,
  legal_effect: 'VoluntaryRecognitionOnly',
  status: 'Proposed',
  signed_contributor_acceptance_hash: null,
  human_ratifier_did: null,
  created_at: NOW_TS,
  content_hash: ZERO_32_BYTES
};

test('wasm_anchor_economy_legacy_receipt', () => {
  const receiptAnchor = wasm.wasm_anchor_economy_legacy_receipt(
    JSON.stringify(economyLegacyReceipt),
    rulesetAnchor ? hashHex(rulesetAnchor.anchor.anchor_hash) : ''
  );
  assertNonZeroHash(receiptAnchor.object.legacy_receipt_id, 'legacy receipt id');
  if (receiptAnchor.object.status !== 'Proposed') {
    throw new Error('legacy receipt bridge fixture must remain unratified');
  }
  return receiptAnchor;
});

const economyContributionNode = {
  contribution_node_id: ZERO_32_BYTES,
  contributor_ref: participantRef,
  contributor_type: 'Project',
  contribution_name: 'Archon',
  contribution_type: 'Code',
  source_uri: 'https://github.com/coleam00/Archon',
  evidence_hash: EVIDENCE_32_BYTES,
  provenance_hash: Array.from(Buffer.from('bb'.repeat(32), 'hex')),
  license_or_compact_ref: 'MIT',
  honor_good_terms_hash: Array.from(Buffer.from('bc'.repeat(32), 'hex')),
  bailment_terms_hash: Array.from(Buffer.from('bd'.repeat(32), 'hex')),
  settlement_ruleset_id: rulesetAnchor ? hashBytes(rulesetAnchor.object.ruleset_id) : Array.from(Buffer.from('be'.repeat(32), 'hex')),
  beneficiary_ref: participantRef,
  materiality_policy_id: Array.from(Buffer.from('bf'.repeat(32), 'hex')),
  adoption_policy_id: Array.from(Buffer.from('c0'.repeat(32), 'hex')),
  revocation_policy_id: Array.from(Buffer.from('c1'.repeat(32), 'hex')),
  dispute_policy_id: Array.from(Buffer.from('c2'.repeat(32), 'hex')),
  status: 'Active',
  created_at_hlc: NOW_TS,
  content_hash: ZERO_32_BYTES
};

test('wasm_anchor_economy_value_contribution_node', () => {
  const nodeAnchor = wasm.wasm_anchor_economy_value_contribution_node(
    JSON.stringify(economyContributionNode),
    rulesetAnchor ? hashHex(rulesetAnchor.anchor.anchor_hash) : ''
  );
  assertNonZeroHash(nodeAnchor.object.contribution_node_id, 'value contribution node id');
  if (nodeAnchor.anchor.object_kind !== 'value_contribution_node') {
    throw new Error('value contribution node anchor object kind must be stable snake_case');
  }
  return nodeAnchor;
});

test('wasm_validation_invariant_request', () => {
  const request = wasm.wasm_validation_invariant_request();
  const result = wasm.wasm_enforce_invariants(JSON.stringify(request));
  if (result.passed) {
    throw new Error('public invariant enforcement must reject replayed trusted key maps');
  }
  const descriptions = (result.violations || []).map((violation) => violation.description || '');
  if (!descriptions.some((description) => description.includes('trusted_authority_keys'))) {
    throw new Error('authority trusted-key boundary violation must be explicit');
  }
  if (!descriptions.some((description) => description.includes('trusted_provenance_keys'))) {
    throw new Error('provenance trusted-key boundary violation must be explicit');
  }
  return { request, result };
});

// =========================================================================
// Module 27 — Bridge Coverage Guard
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
