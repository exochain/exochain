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

import { sha256Hex } from '../src/qms-contracts.mjs';

const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const DIGEST_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const DIGEST_C = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const DIGEST_D = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const DIGEST_E = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const DIGEST_F = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

const REQUIRED_AUDIT_LOG_FAMILIES = Object.freeze([
  'access',
  'approvals',
  'authentication',
  'decisions',
  'delegations',
  'document_changes',
  'evidence',
  'exports',
  'privileged_actions',
]);

async function loadAuditLogs() {
  try {
    return await import('../src/audit-logs.mjs');
  } catch (error) {
    assert.fail(`CyberMedica FR-043 audit-log module must exist and load: ${error.message}`);
  }
}

function recordMaterial(entry) {
  return {
    action: entry.action,
    actorDid: entry.actorDid,
    custodyDigest: entry.custodyDigest,
    eventFamily: entry.eventFamily,
    eventHash: entry.eventHash,
    eventId: entry.eventId,
    objectRef: entry.objectRef,
    occurredAtHlc: entry.occurredAtHlc,
    previousEntryHash: entry.previousEntryHash,
    receiptHash: entry.receiptHash,
    result: entry.result,
    schema: 'cybermedica.audit_log_record_material.v1',
    sequence: entry.sequence,
  };
}

function chainAuditEntries(entries, priorHeadHash = ZERO_HASH) {
  let previousEntryHash = priorHeadHash;
  return entries.map((entry) => {
    const chained = {
      ...entry,
      previousEntryHash,
    };
    previousEntryHash = sha256Hex(recordMaterial(chained));
    return chained;
  });
}

function auditEntry(eventFamily, index) {
  const even = index % 2 === 0;
  return {
    eventId: `CM-AUD-LOG-${String(index + 1).padStart(4, '0')}`,
    eventFamily,
    sequence: index + 1,
    previousEntryHash: ZERO_HASH,
    eventHash: even ? DIGEST_A : DIGEST_B,
    actorDid: even ? 'did:exo:quality-auditor-alpha' : 'did:exo:site-quality-manager-alpha',
    action: `audit.${eventFamily}.record`,
    result: even ? 'logged' : 'approved',
    objectRef: `audit-object-${eventFamily}`,
    occurredAtHlc: { physicalMs: 1801000000000 + index * 1000, logical: index % 3 },
    retentionPolicyRef: `retention-${eventFamily}`,
    accessPolicyRef: `access-${eventFamily}`,
    storagePartitionRef: `tenant-site-alpha/audit-log/${eventFamily}`,
    receiptRef: `receipt-${eventFamily}`,
    receiptHash: even ? DIGEST_C : DIGEST_D,
    custodyDigest: even ? DIGEST_E : DIGEST_F,
    immutable: true,
    appendOnly: true,
    tamperEvident: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    rawPayloadExcluded: true,
    deletionMarker: false,
    correctionOfEventId: null,
  };
}

function auditEntries() {
  return chainAuditEntries(REQUIRED_AUDIT_LOG_FAMILIES.map(auditEntry));
}

function auditLogInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:audit-log-owner-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['audit_log_maintain', 'govern'],
      authorityChainHash: DIGEST_D,
    },
    auditLogPolicy: {
      policyRef: 'FR-043-AUDIT-LOG-POLICY-ALPHA',
      policyHash: DIGEST_A,
      status: 'active',
      requiredEventFamilies: REQUIRED_AUDIT_LOG_FAMILIES,
      appendOnlyRequired: true,
      tamperEvidenceRequired: true,
      immutableRecordRequired: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      rawPayloadExcluded: true,
      silentDeletionForbidden: true,
      supplementOnlyCorrections: true,
      reviewedAtHlc: { physicalMs: 1800999999000, logical: 0 },
    },
    auditLog: {
      logRef: 'FR043-AUDIT-LOG-CARDIAC-ALPHA-001',
      protocolRef: 'protocol-cardiac-alpha',
      siteRef: 'site-alpha',
      sourceSystemRef: 'cybermedica-operational-audit-store',
      status: 'reviewed',
      priorHeadHash: ZERO_HASH,
      priorSequence: 0,
      windowStartHlc: { physicalMs: 1801000000000, logical: 0 },
      windowEndHlc: { physicalMs: 1801000100000, logical: 0 },
      entries: auditEntries(),
      deletionControls: {
        silentDeleteDisabled: true,
        deleteRequiresSupersession: true,
        deletionEventsAudited: true,
        retentionOverrideHash: DIGEST_B,
      },
      correctionControls: {
        supplementCorrectionsOnly: true,
        supersessionAuditRequired: true,
        annotationAuditRequired: true,
        correctionPolicyHash: DIGEST_C,
      },
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-auditor-alpha',
      status: 'approved',
      reviewedAtHlc: { physicalMs: 1801000200000, logical: 0 },
      evidenceBundleHash: DIGEST_B,
      qualityApprovalHash: DIGEST_C,
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-audit-log-alpha-001',
        workflowReceiptId: 'df-workflow-audit-log-alpha-001',
      },
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      reviewedByHuman: true,
      scopeHash: DIGEST_E,
    },
    custodyDigest: DIGEST_F,
  };
  return {
    ...base,
    ...overrides,
  };
}

test('audit logs maintain deterministic inactive FR-043 append-only tamper-evident records', async () => {
  const { evaluateAuditLogMaintenance, verifyAuditLogChain } = await loadAuditLogs();

  const resultA = evaluateAuditLogMaintenance(auditLogInput());
  const inputB = auditLogInput();
  inputB.auditLogPolicy.requiredEventFamilies = [...inputB.auditLogPolicy.requiredEventFamilies].reverse();
  inputB.auditLog.entries = [...inputB.auditLog.entries].reverse();
  const resultB = evaluateAuditLogMaintenance(inputB);

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.auditLog.auditLogStatus, 'maintained');
  assert.equal(resultA.auditLog.trustState, 'inactive');
  assert.equal(resultA.auditLog.exochainProductionClaim, false);
  assert.equal(resultA.auditLog.immutableAuditLog, true);
  assert.equal(resultA.auditLog.appendOnly, true);
  assert.equal(resultA.auditLog.tamperEvident, true);
  assert.equal(resultA.auditLog.familyCoverageBasisPoints, 10000);
  assert.equal(resultA.auditLog.entryCount, REQUIRED_AUDIT_LOG_FAMILIES.length);
  assert.deepEqual(resultA.auditLog.coveredEventFamilies, [...REQUIRED_AUDIT_LOG_FAMILIES].sort());
  assert.match(resultA.auditLog.chainHeadHash, /^[0-9a-f]{64}$/u);
  assert.equal(resultA.auditLog.chainHeadHash, resultB.auditLog.chainHeadHash);
  assert.equal(resultA.auditLog.logHash, resultB.auditLog.logHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'audit_log_maintenance');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);

  const verified = verifyAuditLogChain(resultA.auditLog.records, {
    priorHeadHash: ZERO_HASH,
    priorSequence: 0,
  });
  assert.equal(verified.valid, true);
  assert.equal(verified.failClosed, false);
  assert.equal(verified.entriesVerified, REQUIRED_AUDIT_LOG_FAMILIES.length);
  assert.equal(verified.headHash, resultA.auditLog.chainHeadHash);
  assert.doesNotMatch(JSON.stringify(resultA), /source document|raw audit log|participant alice|root-backed production authority/iu);
});

test('audit log chain verification detects broken append-only links and record mutation', async () => {
  const { evaluateAuditLogMaintenance, verifyAuditLogChain } = await loadAuditLogs();
  const result = evaluateAuditLogMaintenance(auditLogInput());

  const brokenLink = verifyAuditLogChain([
    result.auditLog.records[0],
    {
      ...result.auditLog.records[1],
      previousEntryHash: DIGEST_A,
    },
    ...result.auditLog.records.slice(2),
  ]);

  assert.equal(brokenLink.valid, false);
  assert.equal(brokenLink.failClosed, true);
  assert.ok(brokenLink.reasons.includes('audit_log_chain_broken_at_2'));

  const mutated = verifyAuditLogChain([
    result.auditLog.records[0],
    {
      ...result.auditLog.records[1],
      action: 'audit.access.mutated',
    },
    ...result.auditLog.records.slice(2),
  ]);

  assert.equal(mutated.valid, false);
  assert.equal(mutated.failClosed, true);
  assert.ok(mutated.reasons.includes('audit_log_record_hash_mismatch_at_2'));
});

test('audit logs fail closed for policy authority family HLC deletion correction and review defects', async () => {
  const { evaluateAuditLogMaintenance } = await loadAuditLogs();
  const input = auditLogInput();

  input.targetTenantId = 'tenant-site-beta';
  input.actor = { did: 'did:exo:ai-audit-log-writer-alpha', kind: 'ai_agent' };
  input.authority = {
    valid: true,
    revoked: true,
    expired: true,
    permissions: ['read'],
    authorityChainHash: 'bad',
  };
  input.auditLogPolicy.requiredEventFamilies = input.auditLogPolicy.requiredEventFamilies.filter(
    (family) => family !== 'privileged_actions',
  );
  input.auditLogPolicy.appendOnlyRequired = false;
  input.auditLogPolicy.tamperEvidenceRequired = false;
  input.auditLogPolicy.status = 'draft';
  input.auditLog.entries = input.auditLog.entries
    .filter((entry) => entry.eventFamily !== 'exports')
    .map((entry) => {
      if (entry.eventFamily === 'authentication') {
        return { ...entry, sequence: 0 };
      }
      if (entry.eventFamily === 'access') {
        return { ...entry, previousEntryHash: DIGEST_A };
      }
      if (entry.eventFamily === 'evidence') {
        return { ...entry, occurredAtHlc: { physicalMs: 1800999990000, logical: 0 } };
      }
      if (entry.eventFamily === 'decisions') {
        return { ...entry, immutable: false, appendOnly: false, tamperEvident: false };
      }
      if (entry.eventFamily === 'approvals') {
        return { ...entry, deletionMarker: true };
      }
      if (entry.eventFamily === 'document_changes') {
        return { ...entry, metadataOnly: false, receiptHash: 'bad' };
      }
      return entry;
    });
  input.auditLog.deletionControls = {
    silentDeleteDisabled: false,
    deleteRequiresSupersession: false,
    deletionEventsAudited: false,
    retentionOverrideHash: 'bad',
  };
  input.auditLog.correctionControls = {
    supplementCorrectionsOnly: false,
    supersessionAuditRequired: false,
    annotationAuditRequired: false,
    correctionPolicyHash: 'bad',
  };
  input.humanReview.status = 'hold';
  input.humanReview.decisionForum = {
    verified: false,
    state: 'pending',
    humanGate: { verified: false },
    quorum: { status: 'not_met' },
    openChallenge: true,
    decisionId: '',
    workflowReceiptId: '',
  };
  input.aiAssistance.finalAuthority = true;
  input.custodyDigest = 'bad';

  const denied = evaluateAuditLogMaintenance(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.auditLog.auditLogStatus, 'blocked');
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_chain_revoked'));
  assert.ok(denied.reasons.includes('authority_chain_expired'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('policy_not_active'));
  assert.ok(denied.reasons.includes('policy_required_family_missing:privileged_actions'));
  assert.ok(denied.reasons.includes('policy_append_only_not_required'));
  assert.ok(denied.reasons.includes('policy_tamper_evidence_not_required'));
  assert.ok(denied.reasons.includes('audit_log_family_missing:exports'));
  assert.ok(denied.reasons.includes('audit_log_sequence_invalid:authentication'));
  assert.ok(denied.reasons.includes('audit_log_chain_input_mismatch:access'));
  assert.ok(denied.reasons.includes('audit_log_entry_before_window:evidence'));
  assert.ok(denied.reasons.includes('audit_log_entry_not_immutable:decisions'));
  assert.ok(denied.reasons.includes('audit_log_entry_not_append_only:decisions'));
  assert.ok(denied.reasons.includes('audit_log_entry_not_tamper_evident:decisions'));
  assert.ok(denied.reasons.includes('audit_log_deletion_marker_forbidden:approvals'));
  assert.ok(denied.reasons.includes('audit_log_entry_metadata_boundary_invalid:document_changes'));
  assert.ok(denied.reasons.includes('audit_log_receipt_hash_invalid:document_changes'));
  assert.ok(denied.reasons.includes('silent_delete_control_invalid'));
  assert.ok(denied.reasons.includes('correction_control_invalid'));
  assert.ok(denied.reasons.includes('human_review_not_approved'));
  assert.ok(denied.reasons.includes('decision_forum_unverified'));
  assert.ok(denied.reasons.includes('human_gate_unverified'));
  assert.ok(denied.reasons.includes('quorum_not_met'));
  assert.ok(denied.reasons.includes('challenge_open'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('custody_digest_invalid'));
  assert.equal(denied.receipt, null);
});

test('audit logs reject raw log content and secret material before receipt construction', async () => {
  const { evaluateAuditLogMaintenance } = await loadAuditLogs();

  assert.throws(
    () =>
      evaluateAuditLogMaintenance({
        ...auditLogInput(),
        rawAuditLog: 'Participant Alice Example source log content must not enter audit-log maintenance.',
      }),
    /raw audit-log content/i,
  );

  assert.throws(
    () =>
      evaluateAuditLogMaintenance({
        ...auditLogInput(),
        auditLog: {
          ...auditLogInput().auditLog,
          apiKey: 'secret material must remain outside audit-log contracts',
        },
      }),
    /audit-log secret/i,
  );
});
