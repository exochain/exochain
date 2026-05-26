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

const REQUIRED_DSMB_DOMAINS = Object.freeze([
  'audit_trail',
  'board_charter',
  'data_cut_schedule',
  'independence_attestation',
  'participant_code_boundary',
  'recommendation_review',
  'reporting_timeline',
  'safety_event_feed',
  'sponsor_irb_regulatory_routing',
  'unblinding_boundary',
]);

async function loadDsmbReportingReadiness() {
  try {
    return await import('../src/dsmb-reporting-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica dsmb-reporting-readiness module must exist and load: ${error.message}`);
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
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2];
  return {
    domainRef,
    status: 'verified',
    evidenceHash: hashes[index % hashes.length],
    reviewedAtHlc: { physicalMs: 1804000100000 + index, logical: 0 },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function dataCutRecord(overrides = {}) {
  return {
    dataCutRef: 'dsmb-data-cut-alpha-001',
    periodStartAtHlc: { physicalMs: 1803900000000, logical: 0 },
    periodEndAtHlc: { physicalMs: 1803986400000, logical: 0 },
    lockedAtHlc: { physicalMs: 1803988200000, logical: 0 },
    dataCutHash: DIGEST_A,
    safetyEventSummaryHash: DIGEST_B,
    enrollmentExposureHash: DIGEST_C,
    discrepancySummaryHash: DIGEST_D,
    status: 'locked',
    participantIdentifiersSuppressed: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function reportPackage(overrides = {}) {
  return {
    reportRef: 'dsmb-report-alpha-001',
    dataCutRef: 'dsmb-data-cut-alpha-001',
    reportType: 'scheduled_review',
    reportHash: DIGEST_E,
    status: 'submitted',
    dueAtHlc: { physicalMs: 1803990000000, logical: 0 },
    submittedAtHlc: { physicalMs: 1803989000000, logical: 0 },
    recipientParties: ['data_safety_monitoring_board'],
    blinded: true,
    unblindingAuthorized: false,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function recommendation(overrides = {}) {
  return {
    recommendationRef: 'dsmb-recommendation-alpha-001',
    reportRef: 'dsmb-report-alpha-001',
    recommendationHash: DIGEST_F,
    recommendationType: 'continue_without_modification',
    status: 'reviewed',
    issuedAtHlc: { physicalMs: 1803989300000, logical: 0 },
    reviewedAtHlc: { physicalMs: 1803989600000, logical: 0 },
    materialProtocolImpact: false,
    decisionForumReceiptId: null,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function dsmbReportingInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:safety-oversight-manager-alpha',
      kind: 'human',
      roleRefs: ['safety_oversight_manager', 'quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['manage_dsmb_reporting', 'write'],
      authorityChainHash: DIGEST_A,
    },
    dsmbPlan: {
      planRef: 'dsmb-reporting-plan-alpha',
      protocolRef: 'protocol-cardiac-alpha',
      studyRef: 'study-cardiac-alpha',
      siteRef: 'site-alpha',
      informationManagementPlanRef: 'information-management-plan-alpha',
      status: 'active',
      requiredDomains: REQUIRED_DSMB_DOMAINS,
      charterHash: DIGEST_B,
      rosterHash: DIGEST_C,
      independenceAttestationHash: DIGEST_D,
      safetyThresholdPlanHash: DIGEST_E,
      reportingScheduleHash: DIGEST_F,
      unblindingBoundaryHash: DIGEST_1,
      reviewedAtHlc: { physicalMs: 1804000000000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    domainEvidence: REQUIRED_DSMB_DOMAINS.map((domainRef, index) => domainEvidence(domainRef, index)),
    dataCutRecords: [dataCutRecord()],
    reportPackages: [reportPackage()],
    recommendations: [recommendation()],
    controls: {
      openCriticalSafetySignalCount: 0,
      overdueReportCount: 0,
      unresolvedRecommendationCount: 0,
      participantIdentifiersSuppressed: true,
      unblindingBoundaryPreserved: true,
      allReportsSubmitted: true,
      materialRecommendationsRouted: true,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:principal-investigator-alpha',
      reviewerRoleRefs: ['principal_investigator', 'quality_manager'],
      decision: 'dsmb_reporting_ready',
      reviewedAtHlc: { physicalMs: 1804000200000, logical: 0 },
      evidenceBundleHash: DIGEST_2,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-dsmb-reporting-alpha',
        workflowReceiptId: 'df-workflow-dsmb-reporting-alpha',
      },
    },
    custodyDigest: DIGEST_1,
  };
  return mergeDeep(base, overrides);
}

test('DSMB reporting readiness creates deterministic inactive oversight receipts', async () => {
  const { evaluateDsmbReportingReadiness } = await loadDsmbReportingReadiness();

  const resultA = evaluateDsmbReportingReadiness(dsmbReportingInput());
  const inputB = dsmbReportingInput();
  inputB.dsmbPlan.requiredDomains = [...inputB.dsmbPlan.requiredDomains].reverse();
  inputB.domainEvidence = [...inputB.domainEvidence].reverse();
  inputB.dataCutRecords = [...inputB.dataCutRecords].reverse();
  inputB.reportPackages = [...inputB.reportPackages].reverse();
  inputB.recommendations = [...inputB.recommendations].reverse();
  const resultB = evaluateDsmbReportingReadiness(inputB);

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.dsmbReportingReadiness.reportingStatus, 'ready');
  assert.equal(resultA.dsmbReportingReadiness.trustState, 'inactive');
  assert.equal(resultA.dsmbReportingReadiness.exochainProductionClaim, false);
  assert.equal(resultA.dsmbReportingReadiness.dataCutCount, 1);
  assert.equal(resultA.dsmbReportingReadiness.reportPackageCount, 1);
  assert.equal(resultA.dsmbReportingReadiness.recommendationCount, 1);
  assert.deepEqual(resultA.dsmbReportingReadiness.requiredDomains, REQUIRED_DSMB_DOMAINS);
  assert.deepEqual(resultA.dsmbReportingReadiness.coveredDomains, REQUIRED_DSMB_DOMAINS);
  assert.equal(resultA.dsmbReportingReadiness.openCriticalSafetySignalCount, 0);
  assert.equal(resultA.dsmbReportingReadiness.overdueReportCount, 0);
  assert.equal(resultA.dsmbReportingReadiness.unresolvedRecommendationCount, 0);
  assert.equal(resultA.dsmbReportingReadiness.aiFinalAuthority, false);
  assert.equal(resultA.dsmbReportingReadiness.containsProtectedContent, false);
  assert.equal(resultA.dsmbReportingReadiness.dsmbReportingId, resultB.dsmbReportingReadiness.dsmbReportingId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'dsmb_reporting_readiness');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(resultA), /Participant Alice|raw DSMB report|unblinded listing|medical record/iu);
});

test('DSMB reporting readiness fails closed for missing reporting domains and unresolved safety oversight', async () => {
  const { evaluateDsmbReportingReadiness } = await loadDsmbReportingReadiness();

  const result = evaluateDsmbReportingReadiness(
    dsmbReportingInput({
      dsmbPlan: {
        requiredDomains: REQUIRED_DSMB_DOMAINS.filter((domainRef) => domainRef !== 'unblinding_boundary'),
        productionTrustClaim: true,
      },
      domainEvidence: REQUIRED_DSMB_DOMAINS.filter((domainRef) => domainRef !== 'recommendation_review').map(
        (domainRef, index) => domainEvidence(domainRef, index),
      ),
      dataCutRecords: [
        dataCutRecord({
          status: 'open',
          participantIdentifiersSuppressed: false,
        }),
      ],
      reportPackages: [
        reportPackage({
          status: 'draft',
          submittedAtHlc: { physicalMs: 1803991000000, logical: 0 },
          recipientParties: ['sponsor'],
          blinded: false,
          unblindingAuthorized: false,
        }),
      ],
      recommendations: [
        recommendation({
          recommendationType: 'pause_enrollment',
          status: 'open',
          materialProtocolImpact: true,
          decisionForumReceiptId: '',
        }),
      ],
      controls: {
        openCriticalSafetySignalCount: 1,
        overdueReportCount: 1,
        unresolvedRecommendationCount: 1,
        participantIdentifiersSuppressed: false,
        unblindingBoundaryPreserved: false,
        allReportsSubmitted: false,
        materialRecommendationsRouted: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.dsmbReportingReadiness.reportingStatus, 'blocked');
  assert.ok(result.reasons.includes('required_domain_missing:unblinding_boundary'));
  assert.ok(result.reasons.includes('domain_evidence_missing:recommendation_review'));
  assert.ok(result.reasons.includes('open_critical_safety_signals_present'));
  assert.ok(result.reasons.includes('overdue_reports_present'));
  assert.ok(result.reasons.includes('unresolved_recommendations_present'));
  assert.ok(result.reasons.includes('participant_identifier_boundary_broken'));
  assert.ok(result.reasons.includes('unblinding_boundary_broken'));
  assert.ok(result.reasons.includes('report_not_submitted:dsmb-report-alpha-001'));
  assert.ok(result.reasons.includes('report_dsmb_recipient_absent:dsmb-report-alpha-001'));
  assert.ok(result.reasons.includes('report_unblinded_without_authorization:dsmb-report-alpha-001'));
  assert.ok(result.reasons.includes('recommendation_unresolved:dsmb-recommendation-alpha-001'));
  assert.ok(result.reasons.includes('material_recommendation_not_routed:dsmb-recommendation-alpha-001'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.equal(result.receipt.trustState, 'inactive');
});

test('DSMB reporting readiness denies tenant authority human-review and HLC defects', async () => {
  const { evaluateDsmbReportingReadiness } = await loadDsmbReportingReadiness();

  const result = evaluateDsmbReportingReadiness(
    dsmbReportingInput({
      targetTenantId: 'tenant-site-beta',
      actor: { did: 'did:exo:ai-safety-reviewer-alpha', kind: 'ai_agent' },
      authority: {
        valid: true,
        revoked: true,
        expired: false,
        permissions: ['read'],
        authorityChainHash: 'bad',
      },
      dataCutRecords: [
        dataCutRecord({
          periodStartAtHlc: { physicalMs: 1803986400000, logical: 0 },
          periodEndAtHlc: { physicalMs: 1803900000000, logical: 0 },
        }),
      ],
      reportPackages: [
        reportPackage({
          submittedAtHlc: { physicalMs: 1803991000000, logical: 0 },
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
      custodyDigest: 'not-a-digest',
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('tenant_boundary_violation'));
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('authority_chain_revoked'));
  assert.ok(result.reasons.includes('dsmb_reporting_authority_missing'));
  assert.ok(result.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(result.reasons.includes('data_cut_period_order_invalid:dsmb-data-cut-alpha-001'));
  assert.ok(result.reasons.includes('report_submitted_after_due:dsmb-report-alpha-001'));
  assert.ok(result.reasons.includes('human_review_final_authority_invalid'));
  assert.ok(result.reasons.includes('decision_forum_unverified'));
  assert.ok(result.reasons.includes('human_gate_unverified'));
  assert.ok(result.reasons.includes('quorum_not_met'));
  assert.ok(result.reasons.includes('challenge_open'));
  assert.ok(result.reasons.includes('custody_digest_invalid'));
});

test('DSMB reporting readiness refuses raw safety reports unblinded listings and secrets', async () => {
  const { ProtectedContentError, evaluateDsmbReportingReadiness } = await loadDsmbReportingReadiness();

  assert.throws(
    () =>
      evaluateDsmbReportingReadiness({
        ...dsmbReportingInput(),
        rawDsmbReport: 'Participant Alice unblinded safety narrative',
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDsmbReportingReadiness({
        ...dsmbReportingInput(),
        reportPackages: [
          {
            ...reportPackage(),
            accessToken: 'secret-token-value',
          },
        ],
      }),
    ProtectedContentError,
  );
});
