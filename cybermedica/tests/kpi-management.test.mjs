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

async function loadKpiManagement() {
  try {
    return await import('../src/kpi-management.mjs');
  } catch (error) {
    assert.fail(`CyberMedica KPI management module must exist and load: ${error.message}`);
  }
}

function kpiCycleInput() {
  return {
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
        observationId: 'obs-002',
        numerator: 23,
        denominator: 25,
        measuredAtHlc: { physicalMs: 1792505600000, logical: 0 },
        evidenceHash: DIGEST_D,
        custodyDigest: DIGEST_E,
        sourceSystemRef: 'participant-consent-process',
      },
      {
        observationId: 'obs-001',
        numerator: 62,
        denominator: 75,
        measuredAtHlc: { physicalMs: 1792419200000, logical: 0 },
        evidenceHash: DIGEST_F,
        custodyDigest: DIGEST_1,
        sourceSystemRef: 'consent-material-readiness',
      },
    ],
    previousCycle: {
      actualBasisPoints: 8200,
      periodEndHlc: { physicalMs: 1789913600000, logical: 0 },
    },
    monitoring: {
      reviewedAtHlc: { physicalMs: 1792678400000, logical: 0 },
      reviewerDid: 'did:exo:quality-reviewer-alpha',
      reviewEvidenceHash: DIGEST_2,
      monitoringState: 'reviewed',
      anomalyDisposition: 'none',
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
      action: 'continue_monitoring',
      rationaleHash: DIGEST_2,
      usedAtHlc: { physicalMs: 1792937600000, logical: 0 },
      ownerDid: 'did:exo:principal-investigator-alpha',
    },
  };
}

test('KPI management cycle collects monitors analyzes reports and trends metadata-only receipts', async () => {
  const { evaluateKpiManagementCycle } = await loadKpiManagement();

  const resultA = evaluateKpiManagementCycle(kpiCycleInput());
  const resultB = evaluateKpiManagementCycle({
    ...kpiCycleInput(),
    kpi: {
      ...kpiCycleInput().kpi,
      sourceControlIds: [...kpiCycleInput().kpi.sourceControlIds].reverse(),
      riskRefs: [...kpiCycleInput().kpi.riskRefs].reverse(),
      reportingAudience: [...kpiCycleInput().kpi.reportingAudience].reverse(),
    },
    collection: {
      ...kpiCycleInput().collection,
      dataSourceRefs: [...kpiCycleInput().collection.dataSourceRefs].reverse(),
    },
    observations: [...kpiCycleInput().observations].reverse(),
    report: {
      ...kpiCycleInput().report,
      dashboardRefs: [...kpiCycleInput().report.dashboardRefs].reverse(),
      recipients: [...kpiCycleInput().report.recipients].reverse(),
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.kpiCycle.actualBasisPoints, 8500);
  assert.equal(resultA.kpiCycle.status, 'within_threshold');
  assert.equal(resultA.kpiCycle.alertLevel, 'none');
  assert.equal(resultA.kpiCycle.trend, 'improving');
  assert.equal(resultA.kpiCycle.observationCount, 2);
  assert.equal(resultA.kpiCycle.totalNumerator, 85);
  assert.equal(resultA.kpiCycle.totalDenominator, 100);
  assert.equal(resultA.kpiCycle.monitoringState, 'reviewed');
  assert.equal(resultA.dashboardItem.alertLevel, 'none');
  assert.equal(resultA.dashboardItem.trend, 'improving');
  assert.equal(resultA.dashboardItem.exochainProductionClaim, false);
  assert.deepEqual(resultA.kpiCycle.sourceControlIds, ['CM-QMS-CONSENT-003', 'CM-QMS-PARTICIPANT-002']);
  assert.deepEqual(resultA.kpiCycle.reportingAudience, ['site_quality_council', 'sponsor_monitor']);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.deepEqual(Object.keys(resultA.receipt.anchorPayload), [
    'actorDid',
    'artifactHash',
    'artifactType',
    'artifactVersion',
    'classification',
    'custodyDigest',
    'hlcTimestamp',
    'schema',
    'sensitivityTags',
    'sourceSystem',
    'tenantId',
  ]);
});

test('KPI management fails closed for collection monitoring reporting and decision-use defects', async () => {
  const { evaluateKpiManagementCycle } = await loadKpiManagement();

  const denied = evaluateKpiManagementCycle({
    ...kpiCycleInput(),
    actor: { did: 'did:exo:ai-quality-analyst-alpha', kind: 'ai_agent' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['write'], authorityChainHash: '' },
    kpi: {
      ...kpiCycleInput().kpi,
      sourceControlIds: [],
      qualityObjectiveRef: '',
      targetBasisPoints: 10001,
      alertRule: {
        warningBelowBasisPoints: 6500,
        criticalBelowBasisPoints: 7000,
      },
    },
    collection: {
      ...kpiCycleInput().collection,
      dataSourceRefs: [],
      collectionEvidenceHash: '',
      boundary: {
        metadataOnly: false,
        phiBoundaryAttested: false,
        directIdentifiersExcluded: false,
        sourcePayloadAnchored: true,
      },
    },
    observations: [
      {
        observationId: 'obs-defective',
        numerator: 12,
        denominator: 0,
        measuredAtHlc: { physicalMs: 1792505600000, logical: -1 },
        evidenceHash: '',
        custodyDigest: '',
        sourceSystemRef: '',
      },
    ],
    previousCycle: {
      actualBasisPoints: 7000,
      periodEndHlc: { physicalMs: 1790000000000, logical: 0 },
    },
    monitoring: {
      reviewedAtHlc: { physicalMs: 1792505600000, logical: 0 },
      reviewerDid: '',
      reviewEvidenceHash: '',
      monitoringState: 'pending',
      anomalyDisposition: 'unknown',
      thresholdBreachAcknowledged: false,
    },
    analysis: {
      analyzedAtHlc: { physicalMs: 1792505600000, logical: 0 },
      methodRef: '',
      analysisEvidenceHash: '',
      aiAssistance: {
        used: true,
        advisoryOnly: false,
        finalAuthority: true,
        modelRef: '',
        promptHash: '',
        outputHash: '',
        humanReviewed: false,
      },
    },
    report: {
      reportId: '',
      reportedAtHlc: { physicalMs: 1792505600000, logical: 0 },
      reportHash: '',
      dashboardRefs: [],
      recipients: [],
      distributedEvidenceHash: '',
      phiBoundaryAttested: false,
    },
    decisionUse: {
      decisionMatterRef: '',
      action: 'unreviewed',
      rationaleHash: '',
      usedAtHlc: { physicalMs: 1792505600000, logical: 0 },
      ownerDid: '',
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.kpiCycle, null);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('kpi_source_control_linkage_absent'));
  assert.ok(denied.reasons.includes('quality_objective_ref_absent'));
  assert.ok(denied.reasons.includes('target_basis_points_invalid'));
  assert.ok(denied.reasons.includes('alert_threshold_order_invalid'));
  assert.ok(denied.reasons.includes('collection_data_source_absent'));
  assert.ok(denied.reasons.includes('collection_metadata_boundary_invalid'));
  assert.ok(denied.reasons.includes('observation_denominator_invalid:obs-defective'));
  assert.ok(denied.reasons.includes('monitoring_state_invalid'));
  assert.ok(denied.reasons.includes('analysis_method_absent'));
  assert.ok(denied.reasons.includes('ai_assistance_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('report_dashboard_refs_absent'));
  assert.ok(denied.reasons.includes('reporting_audience_not_notified:site_quality_council'));
  assert.ok(denied.reasons.includes('decision_use_action_invalid'));
});

test('critical declining KPIs require governed escalation action before reporting as usable', async () => {
  const { evaluateKpiManagementCycle } = await loadKpiManagement();

  const criticalInput = {
    ...kpiCycleInput(),
    observations: [
      {
        ...kpiCycleInput().observations[0],
        numerator: 45,
        denominator: 100,
      },
    ],
    previousCycle: {
      actualBasisPoints: 6000,
      periodEndHlc: { physicalMs: 1789913600000, logical: 0 },
    },
  };

  const denied = evaluateKpiManagementCycle(criticalInput);
  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('critical_kpi_requires_escalating_decision_use'));

  const permitted = evaluateKpiManagementCycle({
    ...criticalInput,
    decisionUse: {
      ...criticalInput.decisionUse,
      action: 'open_capa',
      capaRef: 'CAPA-KPI-CONSENT-READINESS-2026-05',
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        receiptRef: 'tnc-receipt-kpi-escalation',
      },
    },
  });

  assert.equal(permitted.decision, 'permitted');
  assert.equal(permitted.kpiCycle.actualBasisPoints, 4500);
  assert.equal(permitted.kpiCycle.alertLevel, 'critical');
  assert.equal(permitted.kpiCycle.trend, 'declining');
  assert.deepEqual(permitted.kpiCycle.requiredEscalationRoles, [
    'decision_forum',
    'principal_investigator',
    'quality_manager',
  ]);
  assert.equal(permitted.dashboardItem.actionRequired, true);
});

test('KPI management accepts same-tick monotonic logical clocks and rejects unsafe ordering', async () => {
  const { evaluateKpiManagementCycle } = await loadKpiManagement();

  const sameTick = evaluateKpiManagementCycle({
    ...kpiCycleInput(),
    collection: {
      ...kpiCycleInput().collection,
      periodStartHlc: { physicalMs: 1790000000000, logical: 0 },
      periodEndHlc: { physicalMs: 1790000000000, logical: 4 },
    },
    observations: [
      {
        ...kpiCycleInput().observations[0],
        measuredAtHlc: { physicalMs: 1790000000000, logical: 2 },
      },
    ],
    monitoring: {
      ...kpiCycleInput().monitoring,
      reviewedAtHlc: { physicalMs: 1790000000000, logical: 5 },
    },
    analysis: {
      ...kpiCycleInput().analysis,
      analyzedAtHlc: { physicalMs: 1790000000000, logical: 6 },
    },
    report: {
      ...kpiCycleInput().report,
      reportedAtHlc: { physicalMs: 1790000000000, logical: 7 },
    },
    decisionUse: {
      ...kpiCycleInput().decisionUse,
      usedAtHlc: { physicalMs: 1790000000000, logical: 8 },
    },
  });

  assert.equal(sameTick.decision, 'permitted');

  const unsafe = evaluateKpiManagementCycle({
    ...kpiCycleInput(),
    monitoring: {
      ...kpiCycleInput().monitoring,
      reviewedAtHlc: { physicalMs: 1789000000000, logical: 0 },
    },
  });

  assert.equal(unsafe.decision, 'denied');
  assert.ok(unsafe.reasons.includes('monitoring_before_collection_end'));
});

test('KPI management covers no-AI warning unchanged and unsafe-total branches', async () => {
  const { evaluateKpiManagementCycle } = await loadKpiManagement();

  const warning = evaluateKpiManagementCycle({
    ...kpiCycleInput(),
    previousCycle: null,
    observations: [
      {
        ...kpiCycleInput().observations[0],
        numerator: 70,
        denominator: 100,
      },
    ],
    analysis: {
      ...kpiCycleInput().analysis,
      aiAssistance: { used: false },
    },
  });

  assert.equal(warning.decision, 'permitted');
  assert.equal(warning.kpiCycle.alertLevel, 'warning');
  assert.equal(warning.kpiCycle.trend, 'not_established');
  assert.deepEqual(warning.kpiCycle.requiredEscalationRoles, ['quality_manager']);

  const unchanged = evaluateKpiManagementCycle({
    ...kpiCycleInput(),
    previousCycle: {
      actualBasisPoints: 8200,
      periodEndHlc: { physicalMs: 1789913600000, logical: 0 },
    },
    observations: [
      {
        ...kpiCycleInput().observations[0],
        numerator: 82,
        denominator: 100,
      },
    ],
  });

  assert.equal(unchanged.decision, 'permitted');
  assert.equal(unchanged.kpiCycle.trend, 'unchanged');

  const unsafeTotals = evaluateKpiManagementCycle({
    ...kpiCycleInput(),
    observations: [
      {
        ...kpiCycleInput().observations[0],
        observationId: 'obs-max-001',
        numerator: Number.MAX_SAFE_INTEGER,
        denominator: Number.MAX_SAFE_INTEGER,
      },
      {
        ...kpiCycleInput().observations[1],
        observationId: 'obs-max-002',
        numerator: Number.MAX_SAFE_INTEGER,
        denominator: Number.MAX_SAFE_INTEGER,
      },
    ],
  });

  assert.equal(unsafeTotals.decision, 'denied');
  assert.ok(unsafeTotals.reasons.includes('observation_numerator_total_unsafe'));
  assert.ok(unsafeTotals.reasons.includes('observation_denominator_total_unsafe'));
});

test('KPI management requires verified Decision Forum evidence for escalation review actions', async () => {
  const { evaluateKpiManagementCycle } = await loadKpiManagement();

  const denied = evaluateKpiManagementCycle({
    ...kpiCycleInput(),
    observations: [
      {
        ...kpiCycleInput().observations[0],
        numerator: 45,
        denominator: 100,
      },
    ],
    previousCycle: {
      actualBasisPoints: 6000,
      periodEndHlc: { physicalMs: 1789913600000, logical: 0 },
    },
    decisionUse: {
      ...kpiCycleInput().decisionUse,
      action: 'decision_forum_review',
      decisionForum: {
        verified: false,
        state: 'pending',
        humanGate: { verified: false },
        quorum: { status: 'not_met' },
        openChallenge: false,
        receiptRef: '',
      },
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('decision_forum_escalation_unverified'));
});

test('KPI management rejects raw KPI analysis and protected content before receipts', async () => {
  const { evaluateKpiManagementCycle } = await loadKpiManagement();

  assert.throws(
    () =>
      evaluateKpiManagementCycle({
        ...kpiCycleInput(),
        rawKpiNarrative: 'Free-text KPI analysis belongs outside receipt anchors.',
      }),
    /raw KPI content/i,
  );

  assert.throws(
    () =>
      evaluateKpiManagementCycle({
        ...kpiCycleInput(),
        participantName: 'Participant Alice Example',
      }),
    /protected content/i,
  );
});
