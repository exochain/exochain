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
const DIGEST_4 = '4444444444444444444444444444444444444444444444444444444444444444';
const DIGEST_5 = '5555555555555555555555555555555555555555555555555555555555555555';
const DIGEST_6 = '6666666666666666666666666666666666666666666666666666666666666666';

const REQUIRED_FINAL_REPORT_DOMAINS = [
  'analysis_dataset_lock',
  'audit_trail_reconciliation',
  'data_query_closure',
  'deviation_capa_summary',
  'distribution_plan',
  'dsmb_recommendation_disposition',
  'final_report_document',
  'regulatory_reporting_reconciliation',
  'safety_event_reconciliation',
  'source_crf_reconciliation',
  'sponsor_cro_review',
  'statistical_outputs',
];

async function loadStudyFinalReportReadiness() {
  try {
    return await import('../src/study-final-report-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica study final-report readiness module must exist and load: ${error.message}`);
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

function domainEvidence(domain, index, overrides = {}) {
  const digests = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6];
  return {
    domain,
    status: 'verified',
    evidenceHash: digests[index],
    reviewerDid: 'did:exo:data-manager-alpha',
    reviewedAtHlc: { physicalMs: 1802030100000 + index, logical: 0 },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function recipient(recipientRef, roleRef, overrides = {}) {
  return {
    recipientRef,
    roleRef,
    authorized: true,
    accessGrantRef: `grant-${recipientRef}`,
    acknowledgementRequired: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function finalReportInput(overrides = {}) {
  return mergeDeep(
    {
      tenantId: 'tenant-site-alpha',
      targetTenantId: 'tenant-site-alpha',
      actor: {
        did: 'did:exo:data-manager-alpha',
        kind: 'human',
        roleRefs: ['data_manager', 'quality_manager'],
      },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['study_final_report', 'govern'],
        authorityChainHash: DIGEST_A,
      },
      reportPlan: {
        planRef: 'FINAL-REPORT-PLAN-STUDY-ALPHA',
        studyRef: 'study-alpha',
        protocolRef: 'protocol-alpha',
        siteRef: 'site-alpha',
        sponsorRef: 'sponsor-alpha',
        informationPlanRef: 'IMP-STUDY-ALPHA',
        informationPlanHash: DIGEST_B,
        finalReportRequirementHash: DIGEST_C,
        distributionRuleHash: DIGEST_D,
        retentionRuleHash: DIGEST_E,
        plannedAtHlc: { physicalMs: 1802030000000, logical: 0 },
        reportDueAtHlc: { physicalMs: 1802039000000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
        productionTrustClaim: false,
      },
      domainEvidence: REQUIRED_FINAL_REPORT_DOMAINS.map((domain, index) => domainEvidence(domain, index)),
      dataCloseout: {
        sourceCrfReconciled: true,
        queryClosureHash: DIGEST_F,
        openQueryCount: 0,
        unresolvedDiscrepancyCount: 0,
        analysisDatasetLocked: true,
        analysisDatasetHash: DIGEST_1,
        auditTrailReconciled: true,
        auditTrailHash: DIGEST_2,
        lockedAtHlc: { physicalMs: 1802031000000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      safetyCloseout: {
        safetyEventsReconciled: true,
        unresolvedSafetyEventCount: 0,
        dsmbRecommendationsClosed: true,
        regulatoryReportingReconciled: true,
        safetyReconciliationHash: DIGEST_3,
        dsmbDispositionHash: DIGEST_4,
        regulatoryReconciliationHash: DIGEST_5,
        reviewedAtHlc: { physicalMs: 1802031100000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      finalReport: {
        reportRef: 'FINAL-REPORT-STUDY-ALPHA-v1',
        version: 'v1',
        status: 'locked',
        reportHash: DIGEST_6,
        statisticalOutputHash: DIGEST_A,
        deviationCapaSummaryHash: DIGEST_B,
        sponsorCroReviewHash: DIGEST_C,
        approvedByPiDid: 'did:exo:principal-investigator-alpha',
        approvedByQualityDid: 'did:exo:quality-manager-alpha',
        approvedBySponsorDid: 'did:exo:sponsor-quality-alpha',
        lockedAtHlc: { physicalMs: 1802032000000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      distribution: {
        distributionPlanRef: 'FINAL-REPORT-DIST-STUDY-ALPHA',
        distributionPlanHash: DIGEST_D,
        authorizedRecipientRoles: ['monitor_cra', 'principal_investigator', 'sponsor_viewer'],
        recipients: [
          recipient('principal-investigator-alpha', 'principal_investigator'),
          recipient('sponsor-quality-alpha', 'sponsor_viewer'),
          recipient('monitor-cra-alpha', 'monitor_cra'),
        ],
        exportControlRef: 'export-control-final-report-alpha',
        exportControlHash: DIGEST_E,
        disclosureLogHash: DIGEST_F,
        scheduledAtHlc: { physicalMs: 1802033000000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      humanReview: {
        status: 'approved',
        reviewerDid: 'did:exo:quality-manager-alpha',
        decisionForumMatterRef: 'DF-FINAL-REPORT-ALPHA',
        workflowReceiptId: 'df-final-report-workflow-alpha',
        reviewHash: DIGEST_1,
        reviewedAtHlc: { physicalMs: 1802034000000, logical: 0 },
        aiAssisted: true,
        aiFinalAuthority: false,
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      receiptEvidence: {
        artifactHash: DIGEST_2,
        custodyDigest: DIGEST_3,
      },
    },
    overrides,
  );
}

test('study final-report readiness creates deterministic inactive distribution record', async () => {
  const { evaluateStudyFinalReportReadiness } = await loadStudyFinalReportReadiness();

  const first = evaluateStudyFinalReportReadiness(finalReportInput());
  const second = evaluateStudyFinalReportReadiness({
    ...finalReportInput(),
    domainEvidence: [...finalReportInput().domainEvidence].reverse(),
    distribution: {
      ...finalReportInput().distribution,
      authorizedRecipientRoles: [...finalReportInput().distribution.authorizedRecipientRoles].reverse(),
      recipients: [...finalReportInput().distribution.recipients].reverse(),
    },
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.finalReportRecord.trustState, 'inactive');
  assert.equal(first.finalReportRecord.exochainProductionClaim, false);
  assert.equal(first.finalReportRecord.finalReportReady, true);
  assert.equal(first.finalReportRecord.distributionReady, true);
  assert.deepEqual(first.finalReportRecord.domainCoverage.coveredDomains, REQUIRED_FINAL_REPORT_DOMAINS);
  assert.deepEqual(first.finalReportRecord.authorizedRecipientRoles, [
    'monitor_cra',
    'principal_investigator',
    'sponsor_viewer',
  ]);
  assert.equal(first.finalReportRecord.recordHash, second.finalReportRecord.recordHash);
  assert.equal(first.receipt.anchorPayload.artifactType, 'study_final_report_readiness');
});

test('study final-report readiness fails closed for missing domains and distribution defects', async () => {
  const { evaluateStudyFinalReportReadiness } = await loadStudyFinalReportReadiness();
  const input = finalReportInput({
    domainEvidence: finalReportInput().domainEvidence.filter((row) => row.domain !== 'statistical_outputs'),
    finalReport: {
      status: 'draft',
      reportHash: 'not-a-digest',
    },
    distribution: {
      authorizedRecipientRoles: ['sponsor_viewer'],
      recipients: [
        recipient('', 'sponsor_viewer', {
          authorized: false,
          acknowledgementRequired: false,
        }),
      ],
      disclosureLogHash: 'not-a-digest',
    },
  });

  const result = evaluateStudyFinalReportReadiness(input);

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.finalReportRecord, null);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('final_report_domain_missing:statistical_outputs'));
  assert.ok(result.reasons.includes('final_report_not_locked'));
  assert.ok(result.reasons.includes('final_report_hash_invalid'));
  assert.ok(result.reasons.includes('distribution_recipient_ref_absent:sponsor_viewer'));
  assert.ok(result.reasons.includes('distribution_recipient_not_authorized:sponsor_viewer'));
  assert.ok(result.reasons.includes('distribution_disclosure_log_hash_invalid'));
});

test('study final-report readiness denies unresolved data safety and review closeout defects', async () => {
  const { evaluateStudyFinalReportReadiness } = await loadStudyFinalReportReadiness();
  const input = finalReportInput({
    dataCloseout: {
      sourceCrfReconciled: false,
      openQueryCount: 2,
      unresolvedDiscrepancyCount: 1,
      analysisDatasetLocked: false,
      auditTrailReconciled: false,
    },
    safetyCloseout: {
      unresolvedSafetyEventCount: 1,
      dsmbRecommendationsClosed: false,
      regulatoryReportingReconciled: false,
    },
    finalReport: {
      approvedByPiDid: '',
      approvedByQualityDid: '',
      approvedBySponsorDid: '',
    },
    humanReview: {
      status: 'pending',
      aiFinalAuthority: true,
    },
  });

  const result = evaluateStudyFinalReportReadiness(input);

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('source_crf_not_reconciled'));
  assert.ok(result.reasons.includes('open_queries_present'));
  assert.ok(result.reasons.includes('analysis_dataset_not_locked'));
  assert.ok(result.reasons.includes('audit_trail_not_reconciled'));
  assert.ok(result.reasons.includes('unresolved_safety_events_present'));
  assert.ok(result.reasons.includes('dsmb_recommendations_open'));
  assert.ok(result.reasons.includes('regulatory_reporting_not_reconciled'));
  assert.ok(result.reasons.includes('pi_final_report_approval_absent'));
  assert.ok(result.reasons.includes('quality_final_report_approval_absent'));
  assert.ok(result.reasons.includes('sponsor_final_report_approval_absent'));
  assert.ok(result.reasons.includes('human_review_not_approved'));
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
});

test('study final-report readiness validates authority trust claims and HLC ordering', async () => {
  const { evaluateStudyFinalReportReadiness } = await loadStudyFinalReportReadiness();
  const input = finalReportInput({
    targetTenantId: 'tenant-site-beta',
    actor: {
      kind: 'ai_agent',
    },
    authority: {
      valid: false,
      permissions: ['read'],
      authorityChainHash: 'not-a-digest',
    },
    reportPlan: {
      productionTrustClaim: true,
      reportDueAtHlc: { physicalMs: 1802029000000, logical: 0 },
    },
    dataCloseout: {
      lockedAtHlc: { physicalMs: 1802033000000, logical: 0 },
    },
    finalReport: {
      lockedAtHlc: { physicalMs: 1802032000000, logical: 0 },
    },
    distribution: {
      scheduledAtHlc: { physicalMs: 1802031000000, logical: 0 },
    },
    humanReview: {
      reviewedAtHlc: { physicalMs: 1802030500000, logical: 0 },
    },
  });

  const result = evaluateStudyFinalReportReadiness(input);

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('tenant_boundary_violation'));
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('authority_chain_invalid'));
  assert.ok(result.reasons.includes('study_final_report_permission_missing'));
  assert.ok(result.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('report_due_before_plan'));
  assert.ok(result.reasons.includes('report_locked_before_data_lock'));
  assert.ok(result.reasons.includes('distribution_before_report_lock'));
  assert.ok(result.reasons.includes('human_review_before_distribution'));
});

test('study final-report readiness rejects raw report content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateStudyFinalReportReadiness } = await loadStudyFinalReportReadiness();

  assert.throws(
    () =>
      evaluateStudyFinalReportReadiness(
        finalReportInput({
          finalReport: {
            rawFinalReportBody: 'Narrative final report text must stay outside receipts.',
          },
        }),
      ),
    ProtectedContentError,
  );
  assert.throws(
    () =>
      evaluateStudyFinalReportReadiness(
        finalReportInput({
          distribution: {
            sessionSecret: 'secret-value',
          },
        }),
      ),
    ProtectedContentError,
  );
  assert.throws(
    () =>
      evaluateStudyFinalReportReadiness(
        finalReportInput({
          safetyCloseout: {
            participantName: 'Participant Example',
          },
        }),
      ),
    ProtectedContentError,
  );
});
