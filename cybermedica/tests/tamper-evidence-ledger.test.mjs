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

import assert from 'node:assert/strict';
import { test } from 'node:test';

const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const DIGEST_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const DIGEST_C = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const DIGEST_D = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const DIGEST_E = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const DIGEST_F = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

const REQUIRED_TAMPER_ACTIONS = Object.freeze([
  'audit_package_release',
  'capa_closure',
  'consent_policy_change',
  'enrollment_gate',
  'evidence_custody_transfer',
  'evidence_intake',
  'protocol_launch',
  'qms_control_approval',
  'sponsor_export',
  'support_access_policy',
]);

async function loadTamperEvidenceLedger() {
  try {
    return await import('../src/tamper-evidence-ledger.mjs');
  } catch (error) {
    assert.fail(`CyberMedica tamper evidence ledger module must exist and load: ${error.message}`);
  }
}

function tamperAction(actionType, index) {
  const even = index % 2 === 0;
  return {
    actionType,
    actionRef: `critical-action-${actionType}-${String(index + 1).padStart(2, '0')}`,
    sequence: index + 1,
    previousTamperRecordHash: index === 0 ? ZERO_HASH : `pending:${index}`,
    actionHash: even ? DIGEST_A : DIGEST_B,
    evidenceHash: even ? DIGEST_C : DIGEST_D,
    custodyDigest: even ? DIGEST_E : DIGEST_F,
    occurredAtHlc: { physicalMs: 1792000000000 + index * 1000, logical: index % 3 },
    receiptEvidence: {
      receiptId: `exo-receipt-${actionType}`,
      actionHash: even ? DIGEST_A : DIGEST_B,
      signerDid: 'did:exo:node-alpha',
      signatureAlgorithm: 'ed25519',
      signatureHash: even ? DIGEST_F : DIGEST_E,
      dagNodeHash: even ? DIGEST_D : DIGEST_C,
      dagPayloadHash: even ? DIGEST_A : DIGEST_B,
      verified: true,
      adapterVerified: false,
    },
    metadataOnly: true,
    protectedContentExcluded: true,
    rawPayloadExcluded: true,
  };
}

function tamperActions() {
  return REQUIRED_TAMPER_ACTIONS.map(tamperAction);
}

function ledgerInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:tamper-ledger-owner-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['tamper_evidence_review', 'govern'],
      authorityChainHash: DIGEST_D,
    },
    tamperEvidencePolicy: {
      policyRef: 'NFR-006-TAMPER-EVIDENCE-POLICY-ALPHA',
      policyHash: DIGEST_A,
      requiredActionTypes: REQUIRED_TAMPER_ACTIONS,
      hashChainRequired: true,
      receiptVerificationRequired: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      rawPayloadExcluded: true,
      humanReviewRequired: true,
      reviewedAtHlc: { physicalMs: 1791999999000, logical: 0 },
    },
    ledger: {
      ledgerRef: 'TAMPER-LEDGER-CARDIAC-ALPHA-001',
      protocolRef: 'protocol-cardiac-alpha',
      siteRef: 'site-alpha',
      status: 'reviewed',
      sourceSystemRef: 'cybermedica-critical-action-ledger',
      chainStartHash: ZERO_HASH,
      entries: tamperActions(),
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-auditor-alpha',
      reviewDecision: 'tamper_evidence_ready',
      reviewedAtHlc: { physicalMs: 1792000200000, logical: 0 },
      evidenceBundleHash: DIGEST_B,
      qualityApprovalHash: DIGEST_C,
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-tamper-evidence-alpha-001',
        workflowReceiptId: 'df-workflow-tamper-evidence-alpha-001',
      },
    },
    custodyDigest: DIGEST_E,
  };
  return {
    ...base,
    ...overrides,
  };
}

test('tamper evidence ledger creates deterministic NFR-006 inactive metadata receipts', async () => {
  const { evaluateTamperEvidenceLedger, verifyTamperEvidenceChain } = await loadTamperEvidenceLedger();

  const resultA = evaluateTamperEvidenceLedger(ledgerInput());
  const inputB = ledgerInput();
  inputB.tamperEvidencePolicy.requiredActionTypes = [...inputB.tamperEvidencePolicy.requiredActionTypes].reverse();
  inputB.ledger.entries = [...inputB.ledger.entries].reverse();
  const resultB = evaluateTamperEvidenceLedger(inputB);

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.ledger.tamperEvidenceStatus, 'ready');
  assert.equal(resultA.ledger.trustState, 'inactive');
  assert.equal(resultA.ledger.exochainProductionClaim, false);
  assert.equal(resultA.ledger.actionCoverageBasisPoints, 10000);
  assert.equal(resultA.ledger.receiptVerificationBasisPoints, 10000);
  assert.equal(resultA.ledger.chainVerified, true);
  assert.equal(resultA.ledger.records.length, REQUIRED_TAMPER_ACTIONS.length);
  assert.deepEqual(resultA.ledger.coveredActionTypes, [...REQUIRED_TAMPER_ACTIONS].sort());
  assert.equal(resultA.ledger.ledgerHash, resultB.ledger.ledgerHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'tamper_evidence_ledger');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);

  const verified = verifyTamperEvidenceChain(resultA.ledger.records);
  assert.equal(verified.valid, true);
  assert.equal(verified.failClosed, false);
  assert.equal(verified.headHash, resultA.ledger.chainHeadHash);
  assert.equal(verified.entriesVerified, REQUIRED_TAMPER_ACTIONS.length);
  assert.doesNotMatch(JSON.stringify(resultA), /source document|raw clinical note|participant alice|root-backed production authority/iu);
});

test('tamper evidence chain verification detects broken links and record mutations', async () => {
  const { evaluateTamperEvidenceLedger, verifyTamperEvidenceChain } = await loadTamperEvidenceLedger();

  const result = evaluateTamperEvidenceLedger(ledgerInput());
  const broken = verifyTamperEvidenceChain([
    result.ledger.records[0],
    {
      ...result.ledger.records[1],
      previousTamperRecordHash: DIGEST_A,
    },
    ...result.ledger.records.slice(2),
  ]);

  assert.equal(broken.valid, false);
  assert.equal(broken.failClosed, true);
  assert.ok(broken.reasons.includes('tamper_chain_broken_at_2'));

  const mutated = verifyTamperEvidenceChain([
    result.ledger.records[0],
    {
      ...result.ledger.records[1],
      evidenceHash: DIGEST_A,
    },
    ...result.ledger.records.slice(2),
  ]);

  assert.equal(mutated.valid, false);
  assert.equal(mutated.failClosed, true);
  assert.ok(mutated.reasons.includes('tamper_record_hash_mismatch_at_2'));
});

test('tamper evidence ledger fails closed for missing coverage governance receipt and chain defects', async () => {
  const { evaluateTamperEvidenceLedger } = await loadTamperEvidenceLedger();
  const input = ledgerInput();

  input.targetTenantId = 'tenant-site-beta';
  input.actor = { did: 'did:exo:ai-tamper-reviewer-alpha', kind: 'ai_agent' };
  input.authority = {
    valid: true,
    revoked: true,
    expired: true,
    permissions: ['read'],
    authorityChainHash: 'bad',
  };
  input.tamperEvidencePolicy.requiredActionTypes = input.tamperEvidencePolicy.requiredActionTypes.filter(
    (action) => action !== 'support_access_policy',
  );
  input.tamperEvidencePolicy.hashChainRequired = false;
  input.ledger.entries = input.ledger.entries
    .filter((entry) => entry.actionType !== 'sponsor_export')
    .map((entry) => {
      if (entry.actionType === 'qms_control_approval') {
        return { ...entry, previousTamperRecordHash: DIGEST_A };
      }
      if (entry.actionType === 'protocol_launch') {
        return { ...entry, sequence: 0 };
      }
      if (entry.actionType === 'enrollment_gate') {
        return {
          ...entry,
          occurredAtHlc: { physicalMs: 1791999990000, logical: 0 },
        };
      }
      if (entry.actionType === 'evidence_intake') {
        return {
          ...entry,
          receiptEvidence: {
            ...entry.receiptEvidence,
            verified: false,
            actionHash: DIGEST_C,
            dagPayloadHash: DIGEST_D,
          },
        };
      }
      if (entry.actionType === 'evidence_custody_transfer') {
        return { ...entry, metadataOnly: false };
      }
      return entry;
    });
  input.humanReview.decisionForum = {
    verified: false,
    state: 'pending',
    humanGate: { verified: false },
    quorum: { status: 'not_met' },
    openChallenge: true,
    decisionId: '',
    workflowReceiptId: '',
  };
  input.custodyDigest = 'bad';

  const denied = evaluateTamperEvidenceLedger(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.ledger.tamperEvidenceStatus, 'blocked');
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_chain_revoked'));
  assert.ok(denied.reasons.includes('authority_chain_expired'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('policy_required_action_missing:support_access_policy'));
  assert.ok(denied.reasons.includes('policy_hash_chain_not_required'));
  assert.ok(denied.reasons.includes('ledger_action_missing:sponsor_export'));
  assert.ok(denied.reasons.includes('tamper_chain_input_mismatch:qms_control_approval'));
  assert.ok(denied.reasons.includes('ledger_sequence_invalid:protocol_launch'));
  assert.ok(denied.reasons.includes('ledger_entry_before_policy_review:enrollment_gate'));
  assert.ok(denied.reasons.includes('receipt_evidence_not_verified:evidence_intake'));
  assert.ok(denied.reasons.includes('receipt_action_hash_mismatch:evidence_intake'));
  assert.ok(denied.reasons.includes('dag_payload_hash_mismatch:evidence_intake'));
  assert.ok(denied.reasons.includes('ledger_entry_metadata_boundary_invalid:evidence_custody_transfer'));
  assert.ok(denied.reasons.includes('decision_forum_unverified'));
  assert.ok(denied.reasons.includes('human_gate_unverified'));
  assert.ok(denied.reasons.includes('quorum_not_met'));
  assert.ok(denied.reasons.includes('challenge_open'));
  assert.ok(denied.reasons.includes('custody_digest_invalid'));
  assert.equal(denied.receipt, null);
});

test('tamper evidence ledger handles absent objects malformed clocks and empty chains as denial states', async () => {
  const { evaluateTamperEvidenceLedger, verifyTamperEvidenceChain } = await loadTamperEvidenceLedger();

  const absent = evaluateTamperEvidenceLedger({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:tamper-ledger-owner-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['tamper_evidence_review'],
      authorityChainHash: DIGEST_D,
    },
    ledger: {
      ledgerRef: 'TAMPER-LEDGER-ABSENT-001',
      chainStartHash: ZERO_HASH,
      entries: null,
      signingKey: [],
    },
    custodyDigest: DIGEST_E,
  });

  assert.equal(absent.decision, 'denied');
  assert.ok(absent.reasons.includes('policy_ref_absent'));
  assert.ok(absent.reasons.includes('policy_review_time_invalid'));
  assert.ok(absent.reasons.includes('ledger_entries_absent'));
  assert.ok(absent.reasons.includes('human_reviewer_absent'));
  assert.ok(absent.reasons.includes('tamper_chain_verification_failed'));
  assert.ok(absent.reasons.includes('ledger_action_missing:audit_package_release'));
  assert.equal(absent.ledger.records.length, 0);
  assert.equal(absent.receipt, null);

  const invalidTime = ledgerInput();
  invalidTime.ledger.entries = invalidTime.ledger.entries.map((entry) => {
    if (entry.actionType === 'audit_package_release') {
      return {
        ...entry,
        previousTamperRecordHash: DIGEST_A,
      };
    }
    if (entry.actionType === 'capa_closure') {
      return {
        ...entry,
        occurredAtHlc: { physicalMs: 1792000000000, logical: 0 },
      };
    }
    if (entry.actionType === 'consent_policy_change') {
      return {
        ...entry,
        sequence: Number.MAX_SAFE_INTEGER,
      };
    }
    return entry;
  });

  const malformed = evaluateTamperEvidenceLedger(invalidTime);
  assert.equal(malformed.decision, 'denied');
  assert.ok(malformed.reasons.includes('tamper_chain_start_mismatch:audit_package_release'));
  assert.ok(malformed.reasons.includes('ledger_entry_time_order_invalid:capa_closure'));
  assert.ok(malformed.reasons.includes('tamper_chain_verification_failed'));

  const empty = verifyTamperEvidenceChain([]);
  assert.equal(empty.valid, false);
  assert.equal(empty.failClosed, true);
  assert.deepEqual(empty.reasons, ['tamper_chain_empty']);
  assert.equal(empty.headHash, null);

  const nonArray = verifyTamperEvidenceChain(null);
  assert.equal(nonArray.valid, false);
  assert.deepEqual(nonArray.reasons, ['tamper_chain_empty']);
});

test('tamper evidence ledger rejects protected content and secret material before anchoring', async () => {
  const { evaluateTamperEvidenceLedger } = await loadTamperEvidenceLedger();

  assert.throws(
    () =>
      evaluateTamperEvidenceLedger({
        ...ledgerInput(),
        sourceDocumentBody: 'Participant Alice Example source document must not enter a tamper ledger.',
      }),
    /protected content|raw tamper evidence content/i,
  );

  assert.throws(
    () =>
      evaluateTamperEvidenceLedger({
        ...ledgerInput(),
        ledger: {
          ...ledgerInput().ledger,
          signingKey: 'secret signing key must remain outside CyberMedica tamper evidence',
        },
      }),
    /secret/i,
  );
});
