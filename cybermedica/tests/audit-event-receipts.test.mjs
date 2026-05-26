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
const DIGEST_A = '3d6f0a96f7c972d4f5b66a1c6b5177fe5a32cc0cbd27f7c67be4c11a4f7ce70a';
const DIGEST_B = '8cf4dfd546b712c3b21f0d61fd7c6b744dfc6d9c7d0c8758fb6c6db6e782a7f3';
const DIGEST_C = '54f6e9e53f0e6d9a6ce64b2d67b79d44a927f276e8916d34a2d3b942f575f1b7';
const DIGEST_D = 'f49d1c0d3b49201b6c91e6f63f1a4a1fc4e5c26f94d72c418f5a65fd8a76bc7d';
const DIGEST_E = 'b78df81ba1c0d7ce3fb3ad7f8412ab728af62f1f98a2cb11e7ac7d38d8d3f27c';
const DIGEST_F = 'cb6c8fe17614be0e9bbfb7c0f66cde48d086d64d6efbf93105fc9b4f7f4db739';

async function loadAuditEventReceipts() {
  try {
    return await import('../src/audit-event-receipts.mjs');
  } catch (error) {
    assert.fail(`CyberMedica audit event receipt module must exist and load: ${error.message}`);
  }
}

function auditEventInput(overrides = {}) {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-auditor-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['audit_append', 'govern'],
      authorityChainHash: DIGEST_C,
    },
    auditEvent: {
      eventId: 'CM-AUD-EVT-0001',
      eventType: 'qms_control_approval',
      action: 'qms.control.approve',
      result: 'approved',
      objectRef: 'CM-QMS-CONTROL-001',
      sequence: 1,
      previousAuditHash: ZERO_HASH,
      occurredAtHlc: { physicalMs: 1790000001000, logical: 3 },
      evidenceHash: DIGEST_A,
      decisionForumReceiptId: 'df-workflow-receipt-control-001',
    },
    operationalLog: {
      logId: 'oplog-qms-control-approval-0001',
      source: 'cybermedica-operational-db',
      mutable: true,
      retentionClass: 'regulated_quality_record',
      eventPayloadHash: DIGEST_B,
    },
    receiptEvidence: {
      receiptId: 'exo-trust-receipt-control-approval-0001',
      actionHash: DIGEST_E,
      signerDid: 'did:exo:node-alpha',
      signatureAlgorithm: 'ed25519',
      signatureHash: DIGEST_D,
    },
    dagEvidence: {
      nodeHash: DIGEST_F,
      payloadHash: DIGEST_E,
      parentNodeHashes: [DIGEST_C],
      nodeSignerDid: 'did:exo:node-alpha',
      nodeSignatureHash: DIGEST_D,
    },
    custodyDigest: DIGEST_B,
    ...overrides,
  };
}

test('audit event receipts separate mutable operational logs from immutable signed evidence', async () => {
  const { recordAuditEventReceipt } = await loadAuditEventReceipts();

  const recordedA = recordAuditEventReceipt(auditEventInput());
  const recordedB = recordAuditEventReceipt({
    ...auditEventInput(),
    authority: {
      authorityChainHash: DIGEST_C,
      permissions: ['govern', 'audit_append'],
      expired: false,
      revoked: false,
      valid: true,
    },
    dagEvidence: {
      nodeSignatureHash: DIGEST_D,
      nodeSignerDid: 'did:exo:node-alpha',
      parentNodeHashes: [DIGEST_C],
      payloadHash: DIGEST_E,
      nodeHash: DIGEST_F,
    },
    auditEvent: {
      decisionForumReceiptId: 'df-workflow-receipt-control-001',
      evidenceHash: DIGEST_A,
      occurredAtHlc: { logical: 3, physicalMs: 1790000001000 },
      previousAuditHash: ZERO_HASH,
      sequence: 1,
      objectRef: 'CM-QMS-CONTROL-001',
      result: 'approved',
      action: 'qms.control.approve',
      eventType: 'qms_control_approval',
      eventId: 'CM-AUD-EVT-0001',
    },
  });

  assert.equal(recordedA.decision, 'permitted');
  assert.equal(recordedA.failClosed, false);
  assert.equal(recordedA.operationalAuditRecord.operationalStateMutable, true);
  assert.equal(recordedA.operationalAuditRecord.immutableReceipt, false);
  assert.equal(recordedA.immutableAuditEvidence.immutableAuditReceipt, true);
  assert.equal(recordedA.immutableAuditEvidence.operationalLogHash, recordedA.operationalAuditRecord.operationalLogHash);
  assert.notEqual(recordedA.operationalAuditRecord.operationalLogHash, recordedA.receipt.actionHash);
  assert.equal(recordedA.immutableAuditEvidence.externalTrustReceipt.signed, true);
  assert.equal(recordedA.immutableAuditEvidence.externalTrustReceipt.signatureHash, DIGEST_D);
  assert.equal(recordedA.immutableAuditEvidence.dagNode.signed, true);
  assert.equal(recordedA.immutableAuditEvidence.auditEntry.chainHash, ZERO_HASH);
  assert.match(recordedA.immutableAuditEvidence.auditEntryHash, /^[0-9a-f]{64}$/u);
  assert.equal(recordedA.immutableAuditEvidence.auditEntryHash, recordedB.immutableAuditEvidence.auditEntryHash);
  assert.equal(recordedA.receipt.receiptId, recordedB.receipt.receiptId);
  assert.equal(recordedA.receipt.trustState, 'inactive');
  assert.equal(recordedA.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(recordedA), /source document|participant alice|medical record|signature bytes/iu);
});

test('audit event receipt chains verify deterministic previous-hash continuity', async () => {
  const { recordAuditEventReceipt, verifyAuditEventReceiptChain } = await loadAuditEventReceipts();

  const first = recordAuditEventReceipt(auditEventInput());
  const second = recordAuditEventReceipt(
    auditEventInput({
      auditEvent: {
        ...auditEventInput().auditEvent,
        eventId: 'CM-AUD-EVT-0002',
        action: 'audit.package.release',
        eventType: 'audit_readiness',
        objectRef: 'AUDIT-2026-SPONSOR-001',
        sequence: 2,
        previousAuditHash: first.immutableAuditEvidence.auditEntryHash,
        occurredAtHlc: { physicalMs: 1790000001100, logical: 0 },
      },
      operationalLog: {
        ...auditEventInput().operationalLog,
        logId: 'oplog-audit-readiness-0002',
        eventPayloadHash: DIGEST_C,
      },
    }),
  );

  const verified = verifyAuditEventReceiptChain([
    first.immutableAuditEvidence,
    second.immutableAuditEvidence,
  ]);

  assert.equal(verified.valid, true);
  assert.equal(verified.failClosed, false);
  assert.deepEqual(verified.reasons, []);
  assert.equal(verified.headHash, second.immutableAuditEvidence.auditEntryHash);
  assert.equal(verified.entriesVerified, 2);

  const broken = verifyAuditEventReceiptChain([
    first.immutableAuditEvidence,
    {
      ...second.immutableAuditEvidence,
      auditEntry: {
        ...second.immutableAuditEvidence.auditEntry,
        chainHash: DIGEST_A,
      },
    },
  ]);

  assert.equal(broken.valid, false);
  assert.equal(broken.failClosed, true);
  assert.ok(broken.reasons.includes('audit_chain_broken_at_2'));
});

test('audit event receipts fail closed for tenant authority signature DAG and evidence defects', async () => {
  const { recordAuditEventReceipt } = await loadAuditEventReceipts();

  const denied = recordAuditEventReceipt(
    auditEventInput({
      targetTenantId: 'tenant-site-beta',
      actor: { did: 'did:exo:ai-audit-summarizer-alpha', kind: 'ai_agent' },
      authority: {
        valid: true,
        revoked: true,
        expired: true,
        permissions: ['read'],
        authorityChainHash: 'not-a-digest',
      },
      auditEvent: {
        ...auditEventInput().auditEvent,
        eventId: '',
        eventType: 'unknown',
        result: 'maybe',
        sequence: 0,
        previousAuditHash: 'not-a-digest',
        evidenceHash: ZERO_HASH,
      },
      operationalLog: {
        ...auditEventInput().operationalLog,
        mutable: false,
        eventPayloadHash: 'not-a-digest',
      },
      receiptEvidence: {
        receiptId: '',
        actionHash: DIGEST_E,
        signerDid: '',
        signatureAlgorithm: 'none',
        signatureHash: ZERO_HASH,
      },
      dagEvidence: {
        nodeHash: '',
        payloadHash: DIGEST_A,
        parentNodeHashes: ['not-a-digest'],
        nodeSignerDid: '',
        nodeSignatureHash: '',
      },
      custodyDigest: 'not-a-digest',
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_chain_revoked'));
  assert.ok(denied.reasons.includes('authority_chain_expired'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('audit_event_id_absent'));
  assert.ok(denied.reasons.includes('audit_event_type_invalid'));
  assert.ok(denied.reasons.includes('audit_result_invalid'));
  assert.ok(denied.reasons.includes('audit_sequence_invalid'));
  assert.ok(denied.reasons.includes('previous_audit_hash_invalid'));
  assert.ok(denied.reasons.includes('audit_evidence_hash_invalid'));
  assert.ok(denied.reasons.includes('operational_log_must_be_mutable'));
  assert.ok(denied.reasons.includes('operational_payload_hash_invalid'));
  assert.ok(denied.reasons.includes('receipt_signature_missing'));
  assert.ok(denied.reasons.includes('receipt_signature_algorithm_invalid'));
  assert.ok(denied.reasons.includes('dag_node_hash_invalid'));
  assert.ok(denied.reasons.includes('dag_payload_hash_mismatch'));
  assert.ok(denied.reasons.includes('dag_parent_hash_invalid'));
  assert.ok(denied.reasons.includes('dag_signature_missing'));
  assert.equal(denied.operationalAuditRecord, null);
  assert.equal(denied.immutableAuditEvidence, null);
  assert.equal(denied.receipt, null);
});

test('audit event receipts fail closed for missing DAG parent lists and empty chains', async () => {
  const { recordAuditEventReceipt, verifyAuditEventReceiptChain } = await loadAuditEventReceipts();

  const denied = recordAuditEventReceipt(
    auditEventInput({
      dagEvidence: {
        ...auditEventInput().dagEvidence,
        parentNodeHashes: null,
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('dag_parent_hashes_invalid'));
  assert.equal(denied.immutableAuditEvidence, null);

  const emptyChain = verifyAuditEventReceiptChain([]);
  assert.equal(emptyChain.valid, false);
  assert.equal(emptyChain.failClosed, true);
  assert.deepEqual(emptyChain.reasons, ['audit_chain_empty']);
  assert.equal(emptyChain.headHash, null);
});

test('audit event receipts reject protected content and raw signature material', async () => {
  const { recordAuditEventReceipt } = await loadAuditEventReceipts();

  assert.throws(
    () =>
      recordAuditEventReceipt({
        ...auditEventInput(),
        sourceDocumentBody: 'Participant Alice Example source document content must not enter audit receipts.',
      }),
    /protected content/i,
  );

  assert.throws(
    () =>
      recordAuditEventReceipt({
        ...auditEventInput(),
        receiptEvidence: {
          ...auditEventInput().receiptEvidence,
          rawSignature: 'signature bytes must remain outside CyberMedica audit evidence',
        },
      }),
    /raw signature/i,
  );
});
