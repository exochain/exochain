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

async function loadRiskAssessments() {
  try {
    return await import('../src/risk-assessments.mjs');
  } catch (error) {
    assert.fail(`CyberMedica risk assessment module must exist and load: ${error.message}`);
  }
}

function startupRiskAssessmentInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['govern'] },
    assessment: {
      assessmentRef: 'RISK-STARTUP-2026-0007',
      protocolRef: 'protocol-cm-001',
      siteRef: 'site-alpha',
      assessmentType: 'trial_startup',
      status: 'approved',
      createdAtHlc: { physicalMs: 1790000000000, logical: 2 },
      reviewFrequency: 'every_30_days_until_launch',
      qualityReviewRef: 'QR-STARTUP-RISK-0007',
      policyRefs: ['risk-management-framework-v1', 'trial-startup-risk-procedure-v1'],
    },
    risks: [
      {
        riskRef: 'RISK-0007-DATA',
        title: 'Data capture reconciliation delay',
        source: 'protocol_to_site_fit_review',
        category: 'data_integrity',
        participantSafetyImpact: 'minor',
        dataIntegrityImpact: 'high',
        ethicalImpact: 'minor',
        regulatoryImpact: 'moderate',
        operationalImpact: 'moderate',
        financialImpact: 'minor',
        sponsorImpact: 'moderate',
        croImpact: 'minor',
        probability: 3,
        severity: 4,
        detectability: 2,
        ownerDid: 'did:exo:data-manager-alpha',
        linkedControlIds: ['CTRL-DATA-RECON-001'],
        linkedEvidenceHashes: [DIGEST_A, DIGEST_B],
        mitigationPlanHash: DIGEST_C,
        mitigationStatus: 'implemented',
        safetyPlanHash: DIGEST_D,
        preventiveActionHash: DIGEST_E,
        correctiveActionHash: DIGEST_A,
        monitoringMetricRef: 'KPI-DATA-QUERY-LAG',
        triggerConditions: ['query_lag_above_threshold', 'edc_reconciliation_gap'],
        escalationThreshold: 'high',
        residualRisk: {
          probability: 2,
          severity: 3,
          detectability: 2,
          status: 'accepted',
          acceptanceRationaleHash: DIGEST_B,
          approverDid: 'did:exo:principal-investigator-alpha',
        },
      },
      {
        riskRef: 'RISK-0007-CONSENT',
        title: 'Consent version transition control',
        source: 'consent_process_review',
        category: 'consent',
        participantSafetyImpact: 'moderate',
        dataIntegrityImpact: 'minor',
        ethicalImpact: 'high',
        regulatoryImpact: 'high',
        operationalImpact: 'moderate',
        financialImpact: 'minor',
        sponsorImpact: 'moderate',
        croImpact: 'minor',
        probability: 2,
        severity: 5,
        detectability: 3,
        ownerDid: 'did:exo:principal-investigator-alpha',
        linkedControlIds: ['CTRL-CONSENT-VERSION-001'],
        linkedEvidenceHashes: [DIGEST_C, DIGEST_D],
        mitigationPlanHash: DIGEST_E,
        mitigationStatus: 'implemented',
        safetyPlanHash: DIGEST_A,
        preventiveActionHash: DIGEST_B,
        correctiveActionHash: DIGEST_C,
        monitoringMetricRef: 'KPI-CONSENT-VERSION-USE',
        triggerConditions: ['new_consent_version_effective'],
        escalationThreshold: 'high',
        residualRisk: {
          probability: 1,
          severity: 4,
          detectability: 2,
          status: 'accepted',
          acceptanceRationaleHash: DIGEST_D,
          approverDid: 'did:exo:principal-investigator-alpha',
        },
      },
      {
        riskRef: 'RISK-0007-FACILITY',
        title: 'Backup temperature excursion response',
        source: 'facility_readiness_review',
        category: 'facility',
        participantSafetyImpact: 'minor',
        dataIntegrityImpact: 'none',
        ethicalImpact: 'none',
        regulatoryImpact: 'moderate',
        operationalImpact: 'high',
        financialImpact: 'moderate',
        sponsorImpact: 'high',
        croImpact: 'moderate',
        probability: 2,
        severity: 4,
        detectability: 2,
        ownerDid: 'did:exo:facility-manager-alpha',
        linkedControlIds: ['CTRL-FACILITY-TEMP-001'],
        linkedEvidenceHashes: [DIGEST_D, DIGEST_E],
        mitigationPlanHash: DIGEST_A,
        mitigationStatus: 'implemented',
        safetyPlanHash: DIGEST_B,
        preventiveActionHash: DIGEST_C,
        correctiveActionHash: DIGEST_D,
        monitoringMetricRef: 'KPI-TEMP-EXCURSION-RESPONSE',
        triggerConditions: ['temperature_alarm_unacknowledged'],
        escalationThreshold: 'high',
        residualRisk: {
          probability: 1,
          severity: 3,
          detectability: 2,
          status: 'accepted',
          acceptanceRationaleHash: DIGEST_E,
          approverDid: 'did:exo:quality-manager-alpha',
        },
      },
      {
        riskRef: 'RISK-0007-PRODUCT',
        title: 'Investigational product handoff control',
        source: 'product_handling_review',
        category: 'product_handling',
        participantSafetyImpact: 'high',
        dataIntegrityImpact: 'minor',
        ethicalImpact: 'minor',
        regulatoryImpact: 'high',
        operationalImpact: 'moderate',
        financialImpact: 'moderate',
        sponsorImpact: 'high',
        croImpact: 'moderate',
        probability: 2,
        severity: 5,
        detectability: 2,
        ownerDid: 'did:exo:pharmacy-lead-alpha',
        linkedControlIds: ['CTRL-IP-HANDOFF-001'],
        linkedEvidenceHashes: [DIGEST_A, DIGEST_E],
        mitigationPlanHash: DIGEST_B,
        mitigationStatus: 'implemented',
        safetyPlanHash: DIGEST_C,
        preventiveActionHash: DIGEST_D,
        correctiveActionHash: DIGEST_E,
        monitoringMetricRef: 'KPI-IP-CHAIN-OF-CUSTODY',
        triggerConditions: ['handoff_log_gap'],
        escalationThreshold: 'critical',
        residualRisk: {
          probability: 1,
          severity: 4,
          detectability: 2,
          status: 'accepted',
          acceptanceRationaleHash: DIGEST_A,
          approverDid: 'did:exo:principal-investigator-alpha',
        },
      },
      {
        riskRef: 'RISK-0007-STAFFING',
        title: 'Delegated backup coordinator coverage',
        source: 'staffing_plan_review',
        category: 'staffing',
        participantSafetyImpact: 'moderate',
        dataIntegrityImpact: 'moderate',
        ethicalImpact: 'minor',
        regulatoryImpact: 'moderate',
        operationalImpact: 'high',
        financialImpact: 'minor',
        sponsorImpact: 'moderate',
        croImpact: 'moderate',
        probability: 3,
        severity: 3,
        detectability: 2,
        ownerDid: 'did:exo:site-director-alpha',
        linkedControlIds: ['CTRL-DELEGATION-COVERAGE-001'],
        linkedEvidenceHashes: [DIGEST_B, DIGEST_C],
        mitigationPlanHash: DIGEST_D,
        mitigationStatus: 'implemented',
        safetyPlanHash: DIGEST_E,
        preventiveActionHash: DIGEST_A,
        correctiveActionHash: DIGEST_B,
        monitoringMetricRef: 'KPI-TRAINED-BACKUP-COVERAGE',
        triggerConditions: ['coordinator_absence'],
        escalationThreshold: 'high',
        residualRisk: {
          probability: 1,
          severity: 3,
          detectability: 2,
          status: 'accepted',
          acceptanceRationaleHash: DIGEST_C,
          approverDid: 'did:exo:site-director-alpha',
        },
      },
      {
        riskRef: 'RISK-0007-VENDOR',
        title: 'Central lab pickup dependency',
        source: 'vendor_readiness_review',
        category: 'vendor',
        participantSafetyImpact: 'minor',
        dataIntegrityImpact: 'moderate',
        ethicalImpact: 'none',
        regulatoryImpact: 'moderate',
        operationalImpact: 'moderate',
        financialImpact: 'minor',
        sponsorImpact: 'moderate',
        croImpact: 'high',
        probability: 2,
        severity: 3,
        detectability: 3,
        ownerDid: 'did:exo:vendor-manager-alpha',
        linkedControlIds: ['CTRL-VENDOR-LAB-001'],
        linkedEvidenceHashes: [DIGEST_C, DIGEST_E],
        mitigationPlanHash: DIGEST_A,
        mitigationStatus: 'implemented',
        safetyPlanHash: DIGEST_B,
        preventiveActionHash: DIGEST_C,
        correctiveActionHash: DIGEST_D,
        monitoringMetricRef: 'KPI-LAB-PICKUP-ON-TIME',
        triggerConditions: ['pickup_delay'],
        escalationThreshold: 'high',
        residualRisk: {
          probability: 1,
          severity: 2,
          detectability: 2,
          status: 'accepted',
          acceptanceRationaleHash: DIGEST_D,
          approverDid: 'did:exo:vendor-manager-alpha',
        },
      },
      {
        riskRef: 'RISK-0007-REGULATORY',
        title: 'IRB approval packet completeness',
        source: 'regulatory_startup_review',
        category: 'regulatory',
        participantSafetyImpact: 'moderate',
        dataIntegrityImpact: 'minor',
        ethicalImpact: 'high',
        regulatoryImpact: 'high',
        operationalImpact: 'moderate',
        financialImpact: 'minor',
        sponsorImpact: 'high',
        croImpact: 'moderate',
        probability: 2,
        severity: 4,
        detectability: 3,
        ownerDid: 'did:exo:regulatory-lead-alpha',
        linkedControlIds: ['CTRL-IRB-PACKET-001'],
        linkedEvidenceHashes: [DIGEST_A, DIGEST_D],
        mitigationPlanHash: DIGEST_B,
        mitigationStatus: 'implemented',
        safetyPlanHash: DIGEST_C,
        preventiveActionHash: DIGEST_D,
        correctiveActionHash: DIGEST_E,
        monitoringMetricRef: 'KPI-IRB-PACKET-COMPLETE',
        triggerConditions: ['irb_packet_defect'],
        escalationThreshold: 'critical',
        residualRisk: {
          probability: 1,
          severity: 3,
          detectability: 2,
          status: 'accepted',
          acceptanceRationaleHash: DIGEST_E,
          approverDid: 'did:exo:regulatory-lead-alpha',
        },
      },
      {
        riskRef: 'RISK-0007-OPERATIONS',
        title: 'Visit window coordination pressure',
        source: 'operations_readiness_review',
        category: 'operational',
        participantSafetyImpact: 'minor',
        dataIntegrityImpact: 'moderate',
        ethicalImpact: 'none',
        regulatoryImpact: 'moderate',
        operationalImpact: 'high',
        financialImpact: 'moderate',
        sponsorImpact: 'moderate',
        croImpact: 'moderate',
        probability: 3,
        severity: 3,
        detectability: 2,
        ownerDid: 'did:exo:operations-lead-alpha',
        linkedControlIds: ['CTRL-VISIT-WINDOW-001'],
        linkedEvidenceHashes: [DIGEST_B, DIGEST_E],
        mitigationPlanHash: DIGEST_C,
        mitigationStatus: 'implemented',
        safetyPlanHash: DIGEST_D,
        preventiveActionHash: DIGEST_E,
        correctiveActionHash: DIGEST_A,
        monitoringMetricRef: 'KPI-VISIT-WINDOW-ADHERENCE',
        triggerConditions: ['visit_window_miss'],
        escalationThreshold: 'high',
        residualRisk: {
          probability: 1,
          severity: 3,
          detectability: 2,
          status: 'accepted',
          acceptanceRationaleHash: DIGEST_A,
          approverDid: 'did:exo:operations-lead-alpha',
        },
      },
    ],
    review: {
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-startup-risk-0007',
        workflowReceiptId: 'df-workflow-risk-0007',
      },
      evidenceBundle: { complete: true, phiBoundaryAttested: true },
      qualityReviewerDid: 'did:exo:quality-reviewer-alpha',
    },
    custodyDigest: DIGEST_D,
  };
}

test('startup risk assessment creates deterministic inactive metadata receipt', async () => {
  const { evaluateStartupRiskAssessment } = await loadRiskAssessments();

  const resultA = evaluateStartupRiskAssessment(startupRiskAssessmentInput());
  const resultB = evaluateStartupRiskAssessment({
    ...startupRiskAssessmentInput(),
    assessment: {
      ...startupRiskAssessmentInput().assessment,
      policyRefs: [...startupRiskAssessmentInput().assessment.policyRefs].reverse(),
    },
    risks: [...startupRiskAssessmentInput().risks].reverse(),
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.riskAssessment.startupReadinessStatus, 'approved');
  assert.equal(resultA.riskAssessment.blockingRiskPresent, false);
  assert.equal(resultA.riskAssessment.aiFinalAuthority, false);
  assert.equal(resultA.riskAssessment.exochainProductionClaim, false);
  assert.deepEqual(resultA.riskAssessment.coveredRiskCategories, [
    'consent',
    'data_integrity',
    'facility',
    'operational',
    'product_handling',
    'regulatory',
    'staffing',
    'vendor',
  ]);
  assert.equal(resultA.riskAssessment.risks[0].riskRef, 'RISK-0007-CONSENT');
  assert.equal(resultA.riskAssessment.risks[0].initialRiskScore, 30);
  assert.equal(resultA.riskAssessment.risks[0].initialRiskRating, 'high');
  assert.equal(resultA.riskAssessment.risks[0].residualRiskScore, 8);
  assert.equal(resultA.riskAssessment.risks[0].residualRiskRating, 'low');
  assert.equal(resultA.riskAssessment.assessmentId, resultB.riskAssessment.assessmentId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'startup_risk_assessment');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(resultA), /Participant Alice|source document|raw narrative|patient/iu);
});

test('unacceptable residual risk requires human governed escalation before startup readiness', async () => {
  const { evaluateStartupRiskAssessment } = await loadRiskAssessments();
  const input = startupRiskAssessmentInput();
  input.risks[0] = {
    ...input.risks[0],
    residualRisk: {
      probability: 4,
      severity: 5,
      detectability: 4,
      status: 'unacceptable',
      acceptanceRationaleHash: DIGEST_B,
      approverDid: 'did:exo:principal-investigator-alpha',
    },
  };
  input.review = {
    decisionForum: {
      verified: false,
      state: 'approved',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
      decisionId: 'df-startup-risk-0007',
      workflowReceiptId: 'df-workflow-risk-0007',
    },
    evidenceBundle: { complete: true, phiBoundaryAttested: true },
    qualityReviewerDid: 'did:exo:quality-reviewer-alpha',
  };

  const denied = evaluateStartupRiskAssessment(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('residual_risk_unacceptable'));
  assert.ok(denied.reasons.includes('decision_forum_unverified'));
  assert.equal(denied.riskAssessment.startupReadinessStatus, 'blocked');
  assert.equal(denied.riskAssessment.blockingRiskPresent, true);

  const aiAttempt = evaluateStartupRiskAssessment({
    ...startupRiskAssessmentInput(),
    actor: { did: 'did:exo:ai-quality-reviewer-alpha', kind: 'ai_agent' },
  });

  assert.equal(aiAttempt.decision, 'denied');
  assert.ok(aiAttempt.reasons.includes('ai_final_authority_forbidden'));
});

test('risk assessment fails closed for missing categories mitigation evidence and authority defects', async () => {
  const { evaluateStartupRiskAssessment } = await loadRiskAssessments();
  const input = startupRiskAssessmentInput();
  input.targetTenantId = 'tenant-site-beta';
  input.authority = { valid: true, revoked: false, expired: false, permissions: ['read'] };
  input.risks = input.risks
    .filter((risk) => risk.category !== 'vendor')
    .map((risk) =>
      risk.category === 'consent'
        ? {
            ...risk,
            ownerDid: '',
            linkedEvidenceHashes: ['bad'],
            mitigationPlanHash: '',
            mitigationStatus: 'planned',
            safetyPlanHash: '',
            monitoringMetricRef: '',
            triggerConditions: [],
            residualRisk: {
              probability: 0,
              severity: 6,
              detectability: 3,
              status: 'accepted',
              acceptanceRationaleHash: '',
              approverDid: '',
            },
          }
        : risk,
    );

  const denied = evaluateStartupRiskAssessment(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('required_risk_category_missing:vendor'));
  assert.ok(denied.reasons.includes('risk_owner_absent:RISK-0007-CONSENT'));
  assert.ok(denied.reasons.includes('risk_evidence_hash_invalid:RISK-0007-CONSENT'));
  assert.ok(denied.reasons.includes('mitigation_plan_invalid:RISK-0007-CONSENT'));
  assert.ok(denied.reasons.includes('mitigation_not_implemented:RISK-0007-CONSENT'));
  assert.ok(denied.reasons.includes('safety_plan_absent:RISK-0007-CONSENT'));
  assert.ok(denied.reasons.includes('monitoring_metric_absent:RISK-0007-CONSENT'));
  assert.ok(denied.reasons.includes('trigger_conditions_absent:RISK-0007-CONSENT'));
  assert.ok(denied.reasons.includes('residual_risk_score_invalid:RISK-0007-CONSENT'));
  assert.ok(denied.reasons.includes('acceptance_rationale_absent:RISK-0007-CONSENT'));
  assert.ok(denied.reasons.includes('risk_approver_absent:RISK-0007-CONSENT'));
});

test('risk assessment rejects raw risk descriptions and protected content before receipt creation', async () => {
  const { evaluateStartupRiskAssessment } = await loadRiskAssessments();

  assert.throws(
    () =>
      evaluateStartupRiskAssessment({
        ...startupRiskAssessmentInput(),
        risks: [
          {
            ...startupRiskAssessmentInput().risks[0],
            description: 'Participant Alice Example missed a consent-related source document entry.',
          },
        ],
      }),
    /protected content|raw risk narrative/i,
  );
});
