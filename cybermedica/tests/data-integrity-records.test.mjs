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

const DIGEST_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const DIGEST_C = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const DIGEST_D = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const DIGEST_E = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const DIGEST_F = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

const REQUIRED_RECORD_FAMILIES = Object.freeze([
  'audit_exports',
  'case_report_forms',
  'consent_records',
  'controlled_documents',
  'decision_forum_records',
  'deviations_capa',
  'product_accountability',
  'safety_events',
  'source_data',
  'training_delegation',
]);

const REQUIRED_ALCOAC_DIMENSIONS = Object.freeze([
  'accurate',
  'attributable',
  'complete',
  'contemporaneous',
  'legible',
  'original',
]);

async function loadDataIntegrityRecords() {
  try {
    return await import('../src/data-integrity-records.mjs');
  } catch (error) {
    assert.fail(`CyberMedica data-integrity records module must exist and load: ${error.message}`);
  }
}

function alcoacControls() {
  return REQUIRED_ALCOAC_DIMENSIONS.map((dimension, index) => ({
    dimension,
    status: index === 2 ? 'validated' : 'verified',
    evidenceHash: index % 2 === 0 ? DIGEST_A : DIGEST_B,
    controlRef: `ALCOAC-${dimension.toUpperCase()}`,
    reviewedAtHlc: { physicalMs: 1790000000100 + index, logical: 0 },
  }));
}

function integrityRecords() {
  return REQUIRED_RECORD_FAMILIES.map((family, index) => {
    const changed = family === 'case_report_forms';
    return {
      recordFamily: family,
      recordRef: `DIR-${family.replaceAll('_', '-').toUpperCase()}-${String(index + 1).padStart(2, '0')}`,
      recordStatus: 'complete',
      reviewStatus: 'verified',
      attributableActorDid: `did:exo:${family.replaceAll('_', '-')}-owner`,
      sourceTraceabilityHash: index % 2 === 0 ? DIGEST_C : DIGEST_D,
      originalRecordHash: changed ? DIGEST_A : DIGEST_B,
      currentRecordHash: changed ? DIGEST_E : DIGEST_B,
      originalEvidenceHash: index % 2 === 0 ? DIGEST_D : DIGEST_E,
      accuracyEvidenceHash: index % 2 === 0 ? DIGEST_E : DIGEST_F,
      legibilityEvidenceHash: index % 2 === 0 ? DIGEST_A : DIGEST_C,
      completenessEvidenceHash: index % 2 === 0 ? DIGEST_B : DIGEST_D,
      versionHistoryHash: index % 2 === 0 ? DIGEST_F : DIGEST_A,
      auditEntryHash: index % 2 === 0 ? DIGEST_C : DIGEST_E,
      observedAtHlc: { physicalMs: 1790000000000 + index, logical: 0 },
      recordedAtHlc: { physicalMs: 1790000001000 + index, logical: 0 },
      correctionRef: changed ? 'CORR-CRF-ALPHA-001' : null,
      participantCodeBoundaryPreserved: true,
      metadataOnly: true,
      protectedContentExcluded: true,
    };
  });
}

function correctionLedger() {
  return [
    {
      correctionRef: 'CORR-CRF-ALPHA-001',
      recordRef: 'DIR-CASE-REPORT-FORMS-02',
      status: 'approved',
      reasonCode: 'transcription_error_resolved',
      originalRecordHash: DIGEST_A,
      correctedRecordHash: DIGEST_E,
      priorAuditHash: DIGEST_C,
      currentAuditHash: DIGEST_D,
      correctionAtHlc: { physicalMs: 1790000010000, logical: 0 },
      approvedAtHlc: { physicalMs: 1790000011000, logical: 0 },
      approvedByDid: 'did:exo:principal-investigator-alpha',
      rationaleHash: DIGEST_F,
      originalContentPreserved: true,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
  ];
}

function dataIntegrityInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:data-integrity-owner-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['data_integrity_review', 'govern'],
      authorityChainHash: DIGEST_F,
    },
    integrityPolicy: {
      policyRef: 'NFR-004-DATA-INTEGRITY-POLICY-ALPHA',
      requiredRecordFamilies: REQUIRED_RECORD_FAMILIES,
      requiredAlcoacDimensions: REQUIRED_ALCOAC_DIMENSIONS,
      maxRecordLagMs: 86_400_000,
      policyHash: DIGEST_A,
      reviewedAtHlc: { physicalMs: 1790000000000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      phiPiiExcludedFromReceipts: true,
    },
    recordSet: {
      recordSetRef: 'DIRSET-CARDIAC-ALPHA-001',
      protocolRef: 'protocol-cardiac-alpha',
      siteRef: 'site-alpha',
      sponsorRef: 'sponsor-alpha',
      sourceSystemRef: 'cybermedica-operational-record-store',
      status: 'validated',
      version: 4,
      openedAtHlc: { physicalMs: 1790000000000, logical: 1 },
      reviewedAtHlc: { physicalMs: 1790000020000, logical: 0 },
      closedAtHlc: { physicalMs: 1790000030000, logical: 0 },
      records: integrityRecords(),
      correctionLedger: correctionLedger(),
      alcoacControls: alcoacControls(),
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-reviewer-alpha',
      reviewDecision: 'data_integrity_ready',
      reviewedAtHlc: { physicalMs: 1790000035000, logical: 0 },
      evidenceBundleHash: DIGEST_B,
      qualityApprovalHash: DIGEST_C,
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-data-integrity-alpha-001',
        workflowReceiptId: 'df-workflow-data-integrity-alpha-001',
      },
    },
    custodyDigest: DIGEST_D,
  };
}

test('data integrity record set creates deterministic NFR-004 inactive metadata receipts', async () => {
  const { evaluateDataIntegrityRecordSet } = await loadDataIntegrityRecords();

  const resultA = evaluateDataIntegrityRecordSet(dataIntegrityInput());
  const inputB = dataIntegrityInput();
  inputB.integrityPolicy.requiredRecordFamilies = [...inputB.integrityPolicy.requiredRecordFamilies].reverse();
  inputB.integrityPolicy.requiredAlcoacDimensions = [...inputB.integrityPolicy.requiredAlcoacDimensions].reverse();
  inputB.recordSet.records = [...inputB.recordSet.records].reverse();
  inputB.recordSet.alcoacControls = [...inputB.recordSet.alcoacControls].reverse();
  const resultB = evaluateDataIntegrityRecordSet(inputB);

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.recordSet.integrityStatus, 'ready');
  assert.equal(resultA.recordSet.trustState, 'inactive');
  assert.equal(resultA.recordSet.exochainProductionClaim, false);
  assert.equal(resultA.recordSet.recordFamilyCoverageBasisPoints, 10000);
  assert.equal(resultA.recordSet.alcoacCoverageBasisPoints, 10000);
  assert.equal(resultA.recordSet.recordCompletenessBasisPoints, 10000);
  assert.equal(resultA.recordSet.correctionSummary.approvedCorrections, 1);
  assert.equal(resultA.recordSet.violationSummary.blockingDefects, 0);
  assert.deepEqual(resultA.recordSet.coveredAlcoacDimensions, [
    'accurate',
    'attributable',
    'complete',
    'contemporaneous',
    'legible',
    'original',
  ]);
  assert.equal(resultA.recordSet.recordSetHash, resultB.recordSet.recordSetHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'data_integrity_record_set');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(resultA), /source document|clinical note|participant alice|root-backed production authority/iu);
});

test('data integrity records fail closed for missing ALCOAC records traceability correction and HLC defects', async () => {
  const { evaluateDataIntegrityRecordSet } = await loadDataIntegrityRecords();
  const input = dataIntegrityInput();

  input.targetTenantId = 'tenant-site-beta';
  input.actor = { did: 'did:exo:ai-data-reviewer-alpha', kind: 'ai_agent' };
  input.authority = {
    valid: true,
    revoked: true,
    expired: true,
    permissions: ['read'],
    authorityChainHash: 'bad',
  };
  input.integrityPolicy.requiredRecordFamilies = input.integrityPolicy.requiredRecordFamilies.filter(
    (family) => family !== 'safety_events',
  );
  input.integrityPolicy.maxRecordLagMs = 0;
  input.recordSet.records = input.recordSet.records
    .filter((record) => record.recordFamily !== 'safety_events')
    .map((record) =>
      record.recordFamily === 'source_data'
        ? {
            ...record,
            sourceTraceabilityHash: '',
            observedAtHlc: { physicalMs: 1790000002000, logical: 0 },
            recordedAtHlc: { physicalMs: 1790000001000, logical: 0 },
          }
        : record,
    );
  input.recordSet.records = input.recordSet.records.map((record) =>
    record.recordFamily === 'consent_records'
      ? {
          ...record,
          recordedAtHlc: { physicalMs: 1790009001000, logical: 0 },
          currentRecordHash: DIGEST_F,
          correctionRef: '',
        }
      : record,
  );
  input.recordSet.alcoacControls = input.recordSet.alcoacControls.filter(
    (control) => control.dimension !== 'legible',
  );
  input.recordSet.correctionLedger = [
    {
      ...input.recordSet.correctionLedger[0],
      status: 'pending',
      approvedAtHlc: { physicalMs: 1790000000000, logical: 0 },
      originalContentPreserved: false,
    },
  ];
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

  const denied = evaluateDataIntegrityRecordSet(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.recordSet.integrityStatus, 'blocked');
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_chain_revoked'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('policy_required_family_missing:safety_events'));
  assert.ok(denied.reasons.includes('record_family_missing:safety_events'));
  assert.ok(denied.reasons.includes('alcoac_dimension_missing:legible'));
  assert.ok(denied.reasons.includes('record_observed_time_after_recorded:source_data'));
  assert.ok(denied.reasons.includes('record_contemporaneous_lag_exceeded:consent_records'));
  assert.ok(denied.reasons.includes('record_source_traceability_invalid:source_data'));
  assert.ok(denied.reasons.includes('record_correction_ref_missing:consent_records'));
  assert.ok(denied.reasons.includes('correction_not_approved:CORR-CRF-ALPHA-001'));
  assert.ok(denied.reasons.includes('correction_original_content_not_preserved:CORR-CRF-ALPHA-001'));
  assert.ok(denied.reasons.includes('decision_forum_unverified'));
  assert.ok(denied.reasons.includes('custody_digest_invalid'));
  assert.equal(denied.receipt, null);
});

test('data integrity records reject raw clinical content before anchoring', async () => {
  const { evaluateDataIntegrityRecordSet } = await loadDataIntegrityRecords();
  const input = dataIntegrityInput();
  input.recordSet.records[0].rawSourceData = 'patient Alice clinical note';

  assert.throws(
    () => evaluateDataIntegrityRecordSet(input),
    (error) => error.name === 'ProtectedContentError' && /raw data integrity content field/u.test(error.message),
  );
});
