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
const DIGEST_1 = '1111111111111111111111111111111111111111111111111111111111111111';
const DIGEST_2 = '2222222222222222222222222222222222222222222222222222222222222222';
const DIGEST_3 = '3333333333333333333333333333333333333333333333333333333333333333';

const REQUIRED_DISCREPANCY_DOMAINS = Object.freeze([
  'audit_trail',
  'closure_review',
  'correction_linkage',
  'discrepancy_intake',
  'medical_review',
  'monitor_review',
  'query_issuance',
  'query_response_review',
  'source_crf_linkage',
  'urgent_reporting',
]);

async function loadDataDiscrepancyManagement() {
  try {
    return await import('../src/data-discrepancy-management.mjs');
  } catch (error) {
    assert.fail(`CyberMedica data-discrepancy-management module must exist and load: ${error.message}`);
  }
}

function mergeDeep(base, overrides) {
  if (Array.isArray(base) || Array.isArray(overrides)) {
    return overrides === undefined ? base : overrides;
  }
  if (base === null || overrides === null || typeof base !== 'object' || typeof overrides !== 'object') {
    return overrides === undefined ? base : overrides;
  }
  return Object.fromEntries(
    [...new Set([...Object.keys(base), ...Object.keys(overrides)])].map((key) => [
      key,
      mergeDeep(base[key], overrides[key]),
    ]),
  );
}

function domainEvidence(domainRef, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3];
  return {
    domainRef,
    status: 'verified',
    evidenceHash: hashes[index % hashes.length],
    reviewedAtHlc: { physicalMs: 1803000100000 + index, logical: 0 },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function discrepancyRecord(overrides = {}) {
  return {
    discrepancyRef: 'disc-src-crf-alpha-001',
    sourceRecordRef: 'source-lab-result-001',
    crfFieldRef: 'crf-field-primary-endpoint',
    participantCodeHash: DIGEST_A,
    discrepancyHash: DIGEST_B,
    severity: 'major',
    category: 'source_crf_mismatch',
    status: 'resolved',
    detectedAtHlc: { physicalMs: 1803000010000, logical: 0 },
    dueAtHlc: { physicalMs: 1803000500000, logical: 0 },
    resolvedAtHlc: { physicalMs: 1803000300000, logical: 0 },
    assignedOwnerDid: 'did:exo:data-manager-alpha',
    requiresUrgentReporting: false,
    sourceTraceabilityRef: 'source-traceability-alpha',
    sourceTraceabilityHash: DIGEST_C,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function queryRecord(overrides = {}) {
  return {
    queryRef: 'query-src-crf-alpha-001',
    discrepancyRef: 'disc-src-crf-alpha-001',
    issuedByDid: 'did:exo:cro-monitor-alpha',
    responderDid: 'did:exo:data-manager-alpha',
    queryHash: DIGEST_D,
    responseHash: DIGEST_E,
    status: 'closed',
    issuedAtHlc: { physicalMs: 1803000020000, logical: 0 },
    respondedAtHlc: { physicalMs: 1803000200000, logical: 0 },
    reviewedAtHlc: { physicalMs: 1803000250000, logical: 0 },
    responseAccepted: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function correctionRecord(overrides = {}) {
  return {
    correctionRef: 'corr-src-crf-alpha-001',
    discrepancyRef: 'disc-src-crf-alpha-001',
    originalRecordHash: DIGEST_F,
    correctedRecordHash: DIGEST_1,
    correctionReasonHash: DIGEST_2,
    correctionAuditHash: DIGEST_3,
    correctedAtHlc: { physicalMs: 1803000260000, logical: 0 },
    approvedByDid: 'did:exo:principal-investigator-alpha',
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function dataDiscrepancyInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:data-manager-alpha',
      kind: 'human',
      roleRefs: ['data_manager', 'clinical_research_coordinator'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['manage_data_discrepancies', 'write'],
      authorityChainHash: DIGEST_A,
    },
    discrepancyPlan: {
      planRef: 'data-discrepancy-plan-alpha',
      protocolRef: 'protocol-cardiac-alpha',
      siteRef: 'site-alpha',
      studyRef: 'study-cardiac-alpha',
      status: 'active',
      requiredDomains: REQUIRED_DISCREPANCY_DOMAINS,
      discrepancyProcedureHash: DIGEST_B,
      queryProcedureHash: DIGEST_C,
      correctionProcedureHash: DIGEST_D,
      urgentReportingProcedureHash: DIGEST_E,
      sourceTraceabilityPlanRef: 'source-data-traceability-plan-alpha',
      informationManagementPlanRef: 'information-management-plan-alpha',
      evaluatedAtHlc: { physicalMs: 1803000000000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    domainEvidence: REQUIRED_DISCREPANCY_DOMAINS.map((domainRef, index) => domainEvidence(domainRef, index)),
    discrepancyRecords: [discrepancyRecord()],
    queryRecords: [queryRecord()],
    correctionRecords: [correctionRecord()],
    controls: {
      openQueryCount: 0,
      openCriticalQueryCount: 0,
      unresolvedDiscrepancyCount: 0,
      overdueDiscrepancyCount: 0,
      urgentReportsOutstanding: 0,
      sourceCrfReconciliationHash: DIGEST_E,
      monitorReviewHash: DIGEST_F,
      sponsorReportingHash: DIGEST_1,
      participantIdentifiersSuppressed: true,
      allCorrectionsApproved: true,
      allResponsesReviewed: true,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:principal-investigator-alpha',
      dataManagerDid: 'did:exo:data-manager-alpha',
      decision: 'data_discrepancies_reconciled',
      reviewedAtHlc: { physicalMs: 1803000600000, logical: 0 },
      evidenceBundleHash: DIGEST_2,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-data-discrepancy-alpha',
        workflowReceiptId: 'df-workflow-data-discrepancy-alpha',
      },
    },
    custodyDigest: DIGEST_3,
  };
  return mergeDeep(base, overrides);
}

test('data discrepancy management creates deterministic inactive query reconciliation receipts', async () => {
  const { evaluateDataDiscrepancyManagement } = await loadDataDiscrepancyManagement();

  const resultA = evaluateDataDiscrepancyManagement(dataDiscrepancyInput());
  const inputB = dataDiscrepancyInput();
  inputB.discrepancyPlan.requiredDomains = [...inputB.discrepancyPlan.requiredDomains].reverse();
  inputB.domainEvidence = [...inputB.domainEvidence].reverse();
  inputB.discrepancyRecords = [...inputB.discrepancyRecords].reverse();
  inputB.queryRecords = [...inputB.queryRecords].reverse();
  inputB.correctionRecords = [...inputB.correctionRecords].reverse();
  const resultB = evaluateDataDiscrepancyManagement(inputB);

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.dataDiscrepancyManagement.reconciliationStatus, 'reconciled');
  assert.equal(resultA.dataDiscrepancyManagement.trustState, 'inactive');
  assert.equal(resultA.dataDiscrepancyManagement.exochainProductionClaim, false);
  assert.equal(resultA.dataDiscrepancyManagement.discrepancyRecordCount, 1);
  assert.equal(resultA.dataDiscrepancyManagement.queryRecordCount, 1);
  assert.equal(resultA.dataDiscrepancyManagement.correctionRecordCount, 1);
  assert.deepEqual(resultA.dataDiscrepancyManagement.requiredDomains, REQUIRED_DISCREPANCY_DOMAINS);
  assert.deepEqual(resultA.dataDiscrepancyManagement.coveredDomains, REQUIRED_DISCREPANCY_DOMAINS);
  assert.equal(resultA.dataDiscrepancyManagement.openQueryCount, 0);
  assert.equal(resultA.dataDiscrepancyManagement.unresolvedDiscrepancyCount, 0);
  assert.equal(resultA.dataDiscrepancyManagement.aiFinalAuthority, false);
  assert.equal(resultA.dataDiscrepancyManagement.containsProtectedContent, false);
  assert.equal(
    resultA.dataDiscrepancyManagement.discrepancyManagementId,
    resultB.dataDiscrepancyManagement.discrepancyManagementId,
  );
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'data_discrepancy_management');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(resultA), /Participant Alice|raw CRF value|raw source|medical record/iu);
}
);

test('data discrepancy management fails closed for unresolved query and source traceability defects', async () => {
  const { evaluateDataDiscrepancyManagement } = await loadDataDiscrepancyManagement();

  const result = evaluateDataDiscrepancyManagement(
    dataDiscrepancyInput({
      discrepancyPlan: {
        requiredDomains: REQUIRED_DISCREPANCY_DOMAINS.filter((domainRef) => domainRef !== 'urgent_reporting'),
        productionTrustClaim: true,
      },
      domainEvidence: REQUIRED_DISCREPANCY_DOMAINS.filter((domainRef) => domainRef !== 'query_response_review').map(
        (domainRef, index) => domainEvidence(domainRef, index),
      ),
      discrepancyRecords: [
        discrepancyRecord({
          status: 'open',
          severity: 'critical',
          requiresUrgentReporting: true,
          sourceTraceabilityHash: 'bad',
        }),
      ],
      queryRecords: [
        queryRecord({
          status: 'open',
          responseAccepted: false,
          responseHash: null,
        }),
      ],
      correctionRecords: [correctionRecord({ approvedByDid: '' })],
      controls: {
        openQueryCount: 2,
        openCriticalQueryCount: 1,
        unresolvedDiscrepancyCount: 1,
        overdueDiscrepancyCount: 1,
        urgentReportsOutstanding: 1,
        participantIdentifiersSuppressed: false,
        allCorrectionsApproved: false,
        allResponsesReviewed: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.dataDiscrepancyManagement.reconciliationStatus, 'blocked');
  assert.ok(result.reasons.includes('required_domain_missing:urgent_reporting'));
  assert.ok(result.reasons.includes('domain_evidence_missing:query_response_review'));
  assert.ok(result.reasons.includes('open_critical_queries_present'));
  assert.ok(result.reasons.includes('unresolved_discrepancies_present'));
  assert.ok(result.reasons.includes('urgent_reports_outstanding'));
  assert.ok(result.reasons.includes('participant_identifier_boundary_broken'));
  assert.ok(result.reasons.includes('discrepancy_unresolved:disc-src-crf-alpha-001'));
  assert.ok(result.reasons.includes('discrepancy_source_traceability_hash_invalid:disc-src-crf-alpha-001'));
  assert.ok(result.reasons.includes('query_not_closed:query-src-crf-alpha-001'));
  assert.ok(result.reasons.includes('correction_approval_absent:corr-src-crf-alpha-001'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.equal(result.receipt.trustState, 'inactive');
});

test('data discrepancy management denies tenant authority human-review and HLC defects', async () => {
  const { evaluateDataDiscrepancyManagement } = await loadDataDiscrepancyManagement();

  const result = evaluateDataDiscrepancyManagement(
    dataDiscrepancyInput({
      targetTenantId: 'tenant-site-beta',
      actor: { did: 'did:exo:ai-data-reviewer-alpha', kind: 'ai_agent' },
      authority: {
        valid: true,
        revoked: true,
        expired: false,
        permissions: ['read'],
        authorityChainHash: 'bad',
      },
      discrepancyRecords: [
        discrepancyRecord({
          detectedAtHlc: { physicalMs: 1803000300000, logical: 0 },
          resolvedAtHlc: { physicalMs: 1803000200000, logical: 0 },
        }),
      ],
      queryRecords: [
        queryRecord({
          issuedAtHlc: { physicalMs: 1803000200000, logical: 0 },
          respondedAtHlc: { physicalMs: 1803000100000, logical: 0 },
        }),
      ],
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
        decisionForum: {
          verified: false,
          state: 'pending',
          humanGate: { verified: false },
          quorum: { status: 'not_met' },
          openChallenge: true,
        },
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('tenant_boundary_violation'));
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('authority_chain_revoked'));
  assert.ok(result.reasons.includes('data_discrepancy_authority_missing'));
  assert.ok(result.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(result.reasons.includes('discrepancy_resolved_before_detection:disc-src-crf-alpha-001'));
  assert.ok(result.reasons.includes('query_response_before_issue:query-src-crf-alpha-001'));
  assert.ok(result.reasons.includes('human_review_final_authority_invalid'));
  assert.ok(result.reasons.includes('decision_forum_not_verified'));
  assert.ok(result.reasons.includes('decision_forum_open_challenge'));
});

test('data discrepancy management rejects raw discrepancy content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateDataDiscrepancyManagement } = await loadDataDiscrepancyManagement();

  assert.throws(
    () =>
      evaluateDataDiscrepancyManagement(
        dataDiscrepancyInput({
          discrepancyRecords: [
            discrepancyRecord({
              rawCrfValue: 'Participant Alice raw CRF value',
            }),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDataDiscrepancyManagement(
        dataDiscrepancyInput({
          queryRecords: [
            queryRecord({
              apiKey: 'secret-token',
            }),
          ],
        }),
      ),
    ProtectedContentError,
  );
});
