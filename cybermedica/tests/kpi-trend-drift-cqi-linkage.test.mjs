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
import { evaluateKpiManagementCycle } from '../src/kpi-management.mjs';

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
const AUTHORITY_HASH = 'abababababababababababababababababababababababababababababababab';
const CUSTODY_DIGEST = 'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd';

async function loadKpiTrendLinkage() {
  try {
    return await import('../src/kpi-trend-drift-cqi-linkage.mjs');
  } catch (error) {
    assert.fail(`CyberMedica KPI trend Drift/CQI linkage module must exist and load: ${error.message}`);
  }
}

function kpiCycleInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['kpi_manage', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    kpi: {
      kpiId: 'CM-KPI-CONSENT-READINESS-001',
      name: 'Consent readiness completion',
      sourceStrategyRef: 'site-quality-plan-2026',
      sourceControlIds: ['CM-QMS-CONSENT-003', 'CM-QMS-PARTICIPANT-002'],
      definition: 'Consent readiness artifacts complete before enrollment activity.',
      numeratorDefinition: 'Enrollment-ready consent packets with active approved materials',
      denominatorDefinition: 'Enrollment-ready consent packets due in the reporting period',
      collectionMethod: 'metadata_receipt_count',
      frequency: 'monthly',
      ownerDid: 'did:exo:quality-manager-alpha',
      thresholdBasisPoints: 8000,
      targetBasisPoints: 9000,
      alertRule: {
        warningBelowBasisPoints: 7500,
        criticalBelowBasisPoints: 6500,
      },
      riskRefs: ['risk-consent-version-use'],
      qualityObjectiveRef: 'CM-QO-PARTICIPANT-PROTECTION-2026',
      reportingAudience: ['site_quality_council', 'sponsor_monitor'],
      decisionUse: 'protocol_enrollment_readiness_review',
      lifecycleState: 'active',
    },
    collection: {
      periodRef: '2026-05',
      periodStartHlc: { physicalMs: 1790000000000, logical: 0 },
      periodEndHlc: { physicalMs: 1792592000000, logical: 0 },
      dataSourceRefs: ['consent-material-readiness', 'participant-consent-process'],
      collectionEvidenceHash: DIGEST_B,
      custodyDigest: DIGEST_C,
      boundary: {
        metadataOnly: true,
        phiBoundaryAttested: true,
        directIdentifiersExcluded: true,
        sourcePayloadAnchored: false,
      },
    },
    observations: [
      {
        observationId: 'obs-critical',
        numerator: 45,
        denominator: 100,
        measuredAtHlc: { physicalMs: 1792505600000, logical: 0 },
        evidenceHash: DIGEST_D,
        custodyDigest: DIGEST_E,
        sourceSystemRef: 'participant-consent-process',
      },
    ],
    previousCycle: {
      actualBasisPoints: 6000,
      periodEndHlc: { physicalMs: 1789913600000, logical: 0 },
    },
    monitoring: {
      reviewedAtHlc: { physicalMs: 1792678400000, logical: 0 },
      reviewerDid: 'did:exo:quality-reviewer-alpha',
      reviewEvidenceHash: DIGEST_2,
      monitoringState: 'reviewed',
      anomalyDisposition: 'investigate',
      thresholdBreachAcknowledged: true,
    },
    analysis: {
      analyzedAtHlc: { physicalMs: 1792764800000, logical: 0 },
      methodRef: 'integer-basis-point-cycle-analysis',
      analysisEvidenceHash: DIGEST_A,
      assumptionHash: DIGEST_B,
      limitationHash: DIGEST_C,
      aiAssistance: {
        used: true,
        advisoryOnly: true,
        finalAuthority: false,
        modelRef: 'cm-advisory-quality-reviewer',
        promptHash: DIGEST_D,
        outputHash: DIGEST_E,
        humanReviewed: true,
      },
    },
    report: {
      reportId: 'kpi-report-2026-05-consent-readiness',
      reportedAtHlc: { physicalMs: 1792851200000, logical: 0 },
      reportHash: DIGEST_F,
      dashboardRefs: ['quality-manager-dashboard', 'site-leader-dashboard'],
      recipients: ['sponsor_monitor', 'site_quality_council'],
      distributedEvidenceHash: DIGEST_1,
      phiBoundaryAttested: true,
    },
    decisionUse: {
      decisionMatterRef: 'dfm-consent-readiness-2026-05',
      action: 'open_capa',
      capaRef: 'CAPA-KPI-CONSENT-READINESS-2026-05',
      rationaleHash: DIGEST_2,
      usedAtHlc: { physicalMs: 1792937600000, logical: 0 },
      ownerDid: 'did:exo:principal-investigator-alpha',
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        receiptRef: 'df-receipt-kpi-escalation',
      },
    },
  };
  return { ...base, ...overrides };
}

function permittedKpiDecision(overrides = {}) {
  const result = evaluateKpiManagementCycle(kpiCycleInput(overrides));
  assert.equal(result.decision, 'permitted');
  return result;
}

function linkageInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    checkedAtHlc: { physicalMs: 1793024000000, logical: 0 },
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['kpi_linkage_manage', 'govern'],
      authorityChainHash: AUTHORITY_HASH,
    },
    linkagePolicy: {
      policyRef: 'POLICY-15-KPI-DRIFT-CQI-LINKAGE',
      policyHash: DIGEST_A,
      status: 'active',
      triggerAlertLevels: ['warning', 'critical'],
      triggerTrends: ['declining'],
      driftSignalRequired: true,
      cqiSourceRequired: true,
      observeOnlyAllowed: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1793023000000, logical: 0 },
    },
    kpiDecision: permittedKpiDecision(),
    driftRouting: {
      signalRef: 'signal-kpi-consent-readiness-critical',
      driftCycleRef: 'drift-cycle-consent-readiness-alpha',
      reviewPathHash: DIGEST_B,
      ownerRoleRef: 'quality_manager',
      ownerDidHash: DIGEST_C,
      assignmentHash: DIGEST_D,
      assignedAtHlc: { physicalMs: 1793024100000, logical: 0 },
      dueAtHlc: { physicalMs: 1793628800000, logical: 0 },
      decisionForumMatterRef: 'df-drift-kpi-consent-readiness',
      stateUpdateTargets: ['quality_state', 'readiness'],
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    cqiRouting: {
      sourceRef: 'cqi-source-kpi-consent-readiness',
      improvementRef: 'CQI-KPI-CONSENT-READINESS-2026-05',
      cqiPolicyRef: 'POLICY-15-CQI-2026',
      problemStatementHash: DIGEST_E,
      proposedChangeHash: DIGEST_F,
      expectedBenefitHash: DIGEST_1,
      verificationMethodHash: DIGEST_2,
      decisionForumMatterRef: 'df-cqi-kpi-consent-readiness',
      relatedProcessRefs: ['participant-consent-process'],
      impactDomains: ['training', 'sop', 'stakeholder'],
      evidenceRequirementRefs: ['evidence-consent-training-update', 'evidence-sop-acknowledgement'],
      custodyDigest: CUSTODY_DIGEST,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    humanReview: {
      verified: true,
      reviewerDid: 'did:exo:site-leader-alpha',
      reviewHash: DIGEST_3,
      decision: 'linkage_accepted',
      reviewedAtHlc: { physicalMs: 1793024200000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    aiAssistance: {
      used: true,
      advisoryOnly: true,
      finalAuthority: false,
      outputHash: DIGEST_4,
      limitationHash: DIGEST_5,
      humanReviewed: true,
    },
  };
  return { ...base, ...overrides };
}

test('KPI trend linkage maps critical declining KPI evidence into Drift and CQI metadata', async () => {
  const { evaluateKpiTrendDriftCqiLinkage } = await loadKpiTrendLinkage();

  const first = evaluateKpiTrendDriftCqiLinkage(linkageInput());
  const second = evaluateKpiTrendDriftCqiLinkage(
    linkageInput({
      linkagePolicy: {
        ...linkageInput().linkagePolicy,
        triggerAlertLevels: [...linkageInput().linkagePolicy.triggerAlertLevels].reverse(),
        triggerTrends: [...linkageInput().linkagePolicy.triggerTrends].reverse(),
      },
      driftRouting: {
        ...linkageInput().driftRouting,
        stateUpdateTargets: [...linkageInput().driftRouting.stateUpdateTargets].reverse(),
      },
      cqiRouting: {
        ...linkageInput().cqiRouting,
        impactDomains: [...linkageInput().cqiRouting.impactDomains].reverse(),
        evidenceRequirementRefs: [...linkageInput().cqiRouting.evidenceRequirementRefs].reverse(),
      },
    }),
  );

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.linkage.triggered, true);
  assert.deepEqual(first.linkage.triggerReasons, [
    'alert_level:critical',
    'status:below_threshold',
    'trend:declining',
  ]);
  assert.equal(first.linkage.kpi.actualBasisPoints, 4500);
  assert.equal(first.linkage.driftSignal.signalFamily, 'kpi_trend');
  assert.equal(first.linkage.driftSignal.sourceRef, first.linkage.kpi.receiptId);
  assert.equal(first.linkage.driftSignal.sourceHash, first.linkage.kpi.receiptActionHash);
  assert.deepEqual(first.linkage.driftSignal.affectedControlRefs, [
    'CM-QMS-CONSENT-003',
    'CM-QMS-PARTICIPANT-002',
  ]);
  assert.equal(first.linkage.cqiSource.sourceFamily, 'kpi_trend');
  assert.equal(first.linkage.cqiImprovementSeed.improvementSource, 'kpi_trend');
  assert.deepEqual(first.linkage.cqiImprovementSeed.impactDomains, ['sop', 'stakeholder', 'training']);
  assert.deepEqual(first.linkage.dashboardUpdate.routeTo, ['continuous_quality_improvement', 'drift_improvement']);
  assert.equal(first.linkage.trustState, 'inactive');
  assert.equal(first.linkage.exochainProductionClaim, false);
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.equal(first.receipt.anchorPayload.artifactType, 'kpi_trend_drift_cqi_linkage');
  assert.equal(first.linkage.linkageId, second.linkage.linkageId);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
});

test('KPI trend linkage permits observe-only metadata when no Drift or CQI trigger exists', async () => {
  const { evaluateKpiTrendDriftCqiLinkage } = await loadKpiTrendLinkage();

  const healthyKpiDecision = permittedKpiDecision({
    observations: [
      {
        ...kpiCycleInput().observations[0],
        observationId: 'obs-healthy',
        numerator: 91,
        denominator: 100,
      },
    ],
    previousCycle: {
      actualBasisPoints: 8200,
      periodEndHlc: { physicalMs: 1789913600000, logical: 0 },
    },
    decisionUse: {
      decisionMatterRef: kpiCycleInput().decisionUse.decisionMatterRef,
      action: 'continue_monitoring',
      rationaleHash: kpiCycleInput().decisionUse.rationaleHash,
      usedAtHlc: kpiCycleInput().decisionUse.usedAtHlc,
      ownerDid: kpiCycleInput().decisionUse.ownerDid,
    },
  });

  const result = evaluateKpiTrendDriftCqiLinkage(
    linkageInput({
      kpiDecision: healthyKpiDecision,
      driftRouting: null,
      cqiRouting: null,
      humanReview: {
        ...linkageInput().humanReview,
        decision: 'observe_only_accepted',
      },
      aiAssistance: { used: false },
    }),
  );

  assert.equal(result.decision, 'permitted');
  assert.equal(result.linkage.triggered, false);
  assert.deepEqual(result.linkage.triggerReasons, []);
  assert.equal(result.linkage.driftSignal, null);
  assert.equal(result.linkage.cqiSource, null);
  assert.equal(result.linkage.cqiImprovementSeed, null);
  assert.deepEqual(result.linkage.dashboardUpdate.routeTo, []);
  assert.equal(result.receipt.anchorPayload.artifactType, 'kpi_trend_drift_cqi_linkage');
});

test('KPI trend linkage fails closed when triggered evidence lacks routing human review or receipt proof', async () => {
  const { evaluateKpiTrendDriftCqiLinkage } = await loadKpiTrendLinkage();
  const defectiveKpiDecision = {
    ...permittedKpiDecision(),
    receipt: null,
  };

  const denied = evaluateKpiTrendDriftCqiLinkage(
    linkageInput({
      kpiDecision: defectiveKpiDecision,
      driftRouting: {
        signalRef: '',
        reviewPathHash: '',
        metadataOnly: false,
      },
      cqiRouting: {
        sourceRef: '',
        improvementRef: '',
        cqiPolicyRef: '',
        custodyDigest: '',
        metadataOnly: false,
      },
      humanReview: {
        verified: false,
        reviewerDid: '',
        reviewHash: '',
        decision: 'pending',
        reviewedAtHlc: { physicalMs: 1793024100000, logical: 0 },
        metadataOnly: false,
      },
      aiAssistance: {
        used: true,
        advisoryOnly: false,
        finalAuthority: true,
        outputHash: '',
        humanReviewed: false,
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('kpi_receipt_absent'));
  assert.ok(denied.reasons.includes('drift_signal_ref_absent'));
  assert.ok(denied.reasons.includes('drift_review_path_hash_invalid'));
  assert.ok(denied.reasons.includes('cqi_source_ref_absent'));
  assert.ok(denied.reasons.includes('cqi_policy_ref_absent'));
  assert.ok(denied.reasons.includes('human_review_unverified'));
  assert.ok(denied.reasons.includes('human_review_hash_invalid'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.equal(denied.linkage, null);
  assert.equal(denied.receipt, null);
});

test('KPI trend linkage rejects raw trend content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateKpiTrendDriftCqiLinkage } = await loadKpiTrendLinkage();

  assert.throws(
    () =>
      evaluateKpiTrendDriftCqiLinkage(
        linkageInput({
          rawTrendNarrative: 'Free-text KPI trend analysis belongs outside receipt anchors.',
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateKpiTrendDriftCqiLinkage(
        linkageInput({
          participantName: 'Participant Alice Example',
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateKpiTrendDriftCqiLinkage(
        linkageInput({
          adapterSecret: DIGEST_A,
        }),
      ),
    ProtectedContentError,
  );
});
