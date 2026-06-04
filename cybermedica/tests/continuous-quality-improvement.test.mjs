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
const DIGEST_7 = '7777777777777777777777777777777777777777777777777777777777777777';
const DIGEST_8 = '8888888888888888888888888888888888888888888888888888888888888888';
const DIGEST_9 = '9999999999999999999999999999999999999999999999999999999999999999';
const AUTHORITY_HASH = 'abababababababababababababababababababababababababababababababab';
const CUSTODY_DIGEST = 'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd';

const REQUIRED_SOURCE_FAMILIES = [
  'analysis',
  'audit',
  'complaint',
  'innovation_project',
  'internal_audit',
  'lessons_learned',
  'nonconformity',
  'self_assessment',
  'staff_feedback',
  'stakeholder_feedback',
  'training',
];

async function loadContinuousQualityImprovement() {
  try {
    return await import('../src/continuous-quality-improvement.mjs');
  } catch (error) {
    assert.fail(`CyberMedica continuous-quality-improvement module must exist and load: ${error.message}`);
  }
}

function sourceFor(family, index, overrides = {}) {
  return {
    sourceRef: `cqi-source-${family}`,
    sourceFamily: family,
    sourceHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F][index % 6],
    capturedAtHlc: { physicalMs: 1798100000000 + index, logical: 0 },
    reviewedByHuman: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    relatedEvidenceRefs: [`evidence-${family}`],
    ...overrides,
  };
}

function cqiInput(overrides = {}) {
  const sources = REQUIRED_SOURCE_FAMILIES.map((family, index) => sourceFor(family, index));
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    siteId: 'site-alpha',
    checkedAtHlc: { physicalMs: 1798200000000, logical: 9 },
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['cqi_manage', 'govern'],
      authorityChainHash: AUTHORITY_HASH,
    },
    cqiPolicy: {
      policyRef: 'POLICY-15-CQI-2026',
      policyHash: DIGEST_A,
      status: 'active',
      requiredSourceFamilies: [...REQUIRED_SOURCE_FAMILIES],
      requiredImpactDomains: ['budget', 'sop', 'stakeholder', 'technology', 'training'],
      decisionForumMaterialityRequired: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1798000000000, logical: 0 },
    },
    improvement: {
      improvementId: 'CQI-2026-CONSENT-READINESS-001',
      improvementSource: 'policy_15_continuous_quality_improvement',
      problemStatementHash: DIGEST_B,
      relatedControlRefs: ['CM-QMS-CONSENT-003'],
      relatedProcessRefs: ['participant-consent-process'],
      relatedRiskRefs: ['risk-consent-version-mismatch'],
      relatedDeviationRefs: ['deviation-consent-version-gap'],
      relatedComplaintRefs: ['complaint-consent-instructions'],
      rootCauseAnalysisHash: DIGEST_C,
      proposedChangeHash: DIGEST_D,
      expectedBenefitHash: DIGEST_E,
      potentialRiskHash: DIGEST_F,
      requiredResourceRefs: ['training-owner-hours', 'document-control-review'],
      ownerDid: 'did:exo:quality-manager-alpha',
      approverDid: 'did:exo:site-leader-alpha',
      implementationPlanHash: DIGEST_1,
      dueAtHlc: { physicalMs: 1799000000000, logical: 0 },
      trainingImpactHash: DIGEST_2,
      sopImpactHash: DIGEST_3,
      technologyImpactHash: DIGEST_4,
      budgetImpactHash: DIGEST_5,
      stakeholderImpactHash: DIGEST_6,
      evidenceRequirementRefs: ['evidence-consent-training-update', 'evidence-sop-acknowledgement'],
      verificationMethodHash: DIGEST_A,
      effectivenessCheckHash: DIGEST_B,
      decisionForumMatterRef: 'df-cqi-consent-readiness-alpha',
      closureStatus: 'closed_effective',
      lessonsLearnedHash: DIGEST_C,
      metadataOnly: true,
      protectedContentExcluded: true,
      exochainProductionClaim: false,
    },
    sources,
    impactAssessment: {
      domains: ['budget', 'stakeholder', 'sop', 'technology', 'training'],
      participantSafetyImpact: false,
      dataIntegrityImpact: true,
      sponsorCroImpact: true,
      riskLevel: 'major',
      mitigationEvidenceHash: DIGEST_D,
      assessedAtHlc: { physicalMs: 1798100100000, logical: 0 },
      metadataOnly: true,
    },
    implementationPlan: {
      approvedAtHlc: { physicalMs: 1798100200000, logical: 0 },
      implementedAtHlc: { physicalMs: 1798100300000, logical: 0 },
      taskRefs: ['task-update-consent-sop', 'task-train-coordinators', 'task-refresh-consent-checklist'],
      resourcePlanHash: DIGEST_E,
      trainingUpdateRefs: ['training-consent-version-control'],
      sopUpdateRefs: ['SOP-CONSENT-004@v7'],
      technologyChangeRefs: ['workflow-consent-version-check'],
      budgetReviewHash: DIGEST_F,
      ownerAccepted: true,
      approverApproved: true,
      metadataOnly: true,
    },
    effectivenessCheck: {
      checkedAtHlc: { physicalMs: 1798100400000, logical: 0 },
      status: 'effective',
      verificationEvidenceHash: DIGEST_1,
      expectedBenefitMet: true,
      recurrenceObserved: false,
      followUpRequired: false,
      residualRiskBasisPoints: 1200,
      reviewerDid: 'did:exo:quality-reviewer-alpha',
      metadataOnly: true,
    },
    decisionForum: {
      invoked: true,
      matterRef: 'df-cqi-consent-readiness-alpha',
      receiptId: 'df-receipt-cqi-consent-alpha',
      quorumStatus: 'met',
      humanGateVerified: true,
      openChallenge: false,
      decidedAtHlc: { physicalMs: 1798100250000, logical: 0 },
    },
    humanReview: {
      verified: true,
      reviewedByDid: 'did:exo:site-leader-alpha',
      reviewEvidenceHash: DIGEST_2,
      decision: 'cqi_closed_effective',
      reviewedAtHlc: { physicalMs: 1798100500000, logical: 0 },
    },
    aiAssistance: {
      used: true,
      advisoryOnly: true,
      finalAuthority: false,
      promptHash: DIGEST_3,
      outputHash: DIGEST_4,
      humanReviewed: true,
    },
    auditRecord: {
      auditRecordRef: 'audit-cqi-consent-alpha',
      auditRecordHash: DIGEST_5,
      recordedAtHlc: { physicalMs: 1798100600000, logical: 0 },
      metadataOnly: true,
    },
    inquiryCqiBacklog: {
      receiptHash: DIGEST_7,
      backlogDigest: DIGEST_8,
      ready: true,
      trustState: 'inactive',
      exochainProductionClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
      sourceFamilies: [
        'accessibility_barrier',
        'ai_orientation_question',
        'manual_confusion',
        'missing_documentation',
        'product_gap',
        'repeated_inquiry',
        'search_zero_result',
        'workflow_exit',
      ],
      improvementCategories: [
        'cqi_review',
        'documentation_update',
        'manual_crosslink_refresh',
        'system_change',
        'training_update',
        'workflow_change',
      ],
      linkedBacklogItemRefs: ['cqi-item-manual_confusion', 'cqi-item-search_zero_result'],
      cqiRequiredSignalRefs: ['inquiry-manual_confusion', 'inquiry-search_zero_result'],
      driftSignalRefs: ['drift-inquiry-manual_confusion', 'drift-inquiry-search_zero_result'],
      userAssistanceReceiptHash: DIGEST_9,
      userAssistanceAnalyticsDigest: DIGEST_6,
      contextualManualDrawerHash: DIGEST_A,
      contextualManualDrawerReceiptHash: DIGEST_B,
      controlledDocumentDistributionReceiptHash: DIGEST_C,
      documentationPublicationReceiptHash: DIGEST_D,
      manualExportReceiptHash: DIGEST_E,
      roleManualCoverageReceiptHash: DIGEST_F,
      acknowledgementRosterHash: DIGEST_1,
      manualNavigationReady: true,
      manualNavigationEffectiveUseAcknowledged: true,
      manualNavigationCurrentVersionOnly: true,
      manualNavigationObsoleteVersionUseBlocked: true,
      reviewedAtHlc: { physicalMs: 1798100150000, logical: 0 },
    },
    custodyDigest: CUSTODY_DIGEST,
  };

  return { ...base, ...overrides };
}

test('continuous quality improvement cycle closes a metadata-only Policy 15 improvement deterministically', async () => {
  const { evaluateContinuousQualityImprovementCycle } = await loadContinuousQualityImprovement();
  const input = cqiInput();
  const resultA = evaluateContinuousQualityImprovementCycle(input);
  const resultB = evaluateContinuousQualityImprovementCycle({
    ...input,
    cqiPolicy: {
      ...input.cqiPolicy,
      requiredSourceFamilies: [...input.cqiPolicy.requiredSourceFamilies].reverse(),
      requiredImpactDomains: [...input.cqiPolicy.requiredImpactDomains].reverse(),
    },
    improvement: {
      ...input.improvement,
      relatedControlRefs: [...input.improvement.relatedControlRefs].reverse(),
      relatedProcessRefs: [...input.improvement.relatedProcessRefs].reverse(),
      requiredResourceRefs: [...input.improvement.requiredResourceRefs].reverse(),
      evidenceRequirementRefs: [...input.improvement.evidenceRequirementRefs].reverse(),
    },
    sources: [...input.sources].reverse(),
    impactAssessment: {
      ...input.impactAssessment,
      domains: [...input.impactAssessment.domains].reverse(),
    },
    implementationPlan: {
      ...input.implementationPlan,
      taskRefs: [...input.implementationPlan.taskRefs].reverse(),
      trainingUpdateRefs: [...input.implementationPlan.trainingUpdateRefs].reverse(),
      sopUpdateRefs: [...input.implementationPlan.sopUpdateRefs].reverse(),
      technologyChangeRefs: [...input.implementationPlan.technologyChangeRefs].reverse(),
    },
    inquiryCqiBacklog: {
      ...input.inquiryCqiBacklog,
      sourceFamilies: [...input.inquiryCqiBacklog.sourceFamilies].reverse(),
      improvementCategories: [...input.inquiryCqiBacklog.improvementCategories].reverse(),
      linkedBacklogItemRefs: [...input.inquiryCqiBacklog.linkedBacklogItemRefs].reverse(),
      cqiRequiredSignalRefs: [...input.inquiryCqiBacklog.cqiRequiredSignalRefs].reverse(),
      driftSignalRefs: [...input.inquiryCqiBacklog.driftSignalRefs].reverse(),
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.cqiCycle.status, 'closed_effective');
  assert.deepEqual(resultA.cqiCycle.sourceFamilies, REQUIRED_SOURCE_FAMILIES);
  assert.deepEqual(resultA.cqiCycle.impactDomains, ['budget', 'sop', 'stakeholder', 'technology', 'training']);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.equal(resultA.receipt.containsProtectedContent, false);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'continuous_quality_improvement');
  assert.deepEqual(resultA.receipt.anchorPayload.sensitivityTags, [
    'continuous_quality_improvement',
    'human_governance',
    'inquiry_cqi_backlog',
    'manual_navigation_readiness',
    'metadata_only',
    'policy_15',
  ]);
  assert.equal(resultA.cqiCycle.inquiryCqiBacklogReceiptHash, DIGEST_7);
  assert.equal(resultA.cqiCycle.inquiryCqiBacklogDigest, DIGEST_8);
  assert.equal(resultA.cqiCycle.manualNavigationReady, true);
  assert.equal(resultA.cqiCycle.manualNavigationEffectiveUseAcknowledged, true);
  assert.deepEqual(resultA.cqiCycle.inquiryCqiBacklogImprovementCategories, [
    'cqi_review',
    'documentation_update',
    'manual_crosslink_refresh',
    'system_change',
    'training_update',
    'workflow_change',
  ]);
  assert.equal(resultA.cqiCycle.cycleHash, resultB.cqiCycle.cycleHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
});

test('continuous quality improvement requires inquiry-to-CQI backlog and manual-navigation lineage', async () => {
  const { evaluateContinuousQualityImprovementCycle } = await loadContinuousQualityImprovement();
  const result = evaluateContinuousQualityImprovementCycle(cqiInput({
    inquiryCqiBacklog: {
      receiptHash: 'bad',
      backlogDigest: '',
      ready: false,
      trustState: 'verified',
      exochainProductionClaim: true,
      metadataOnly: false,
      protectedContentExcluded: false,
      sourceFamilies: ['manual_confusion'],
      improvementCategories: ['cqi_review'],
      linkedBacklogItemRefs: [],
      cqiRequiredSignalRefs: [],
      driftSignalRefs: [],
      userAssistanceReceiptHash: '',
      userAssistanceAnalyticsDigest: 'bad',
      contextualManualDrawerHash: '',
      contextualManualDrawerReceiptHash: '',
      controlledDocumentDistributionReceiptHash: '',
      documentationPublicationReceiptHash: '',
      manualExportReceiptHash: '',
      roleManualCoverageReceiptHash: '',
      acknowledgementRosterHash: '',
      manualNavigationReady: false,
      manualNavigationEffectiveUseAcknowledged: false,
      manualNavigationCurrentVersionOnly: false,
      manualNavigationObsoleteVersionUseBlocked: false,
      reviewedAtHlc: { physicalMs: 1798100300001, logical: 0 },
    },
  }));

  assert.equal(result.decision, 'hold_for_cqi_gap');
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_receipt_hash_invalid'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_digest_invalid'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_not_ready'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_trust_state_invalid'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_production_claim_forbidden'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_metadata_boundary_invalid'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_protected_boundary_invalid'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_source_family_missing:accessibility_barrier'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_improvement_category_missing:documentation_update'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_item_refs_absent'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_cqi_signal_refs_absent'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_drift_signal_refs_absent'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_user_assistance_receipt_hash_invalid'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_user_assistance_analytics_digest_invalid'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_manual_drawer_receipt_hash_invalid'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_distribution_receipt_hash_invalid'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_publication_receipt_hash_invalid'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_manual_export_receipt_hash_invalid'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_role_manual_coverage_receipt_hash_invalid'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_acknowledgement_roster_hash_invalid'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_manual_navigation_ready_absent'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_effective_use_absent'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_current_version_boundary_invalid'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_obsolete_version_boundary_invalid'));
  assert.ok(result.reasons.includes('inquiry_cqi_backlog_review_after_implementation_approval'));
});

test('continuous quality improvement fails closed for incomplete source coverage implementation and effectiveness evidence', async () => {
  const { evaluateContinuousQualityImprovementCycle } = await loadContinuousQualityImprovement();
  const input = cqiInput({
    sources: cqiInput().sources.filter((source) => source.sourceFamily !== 'staff_feedback'),
    implementationPlan: {
      ...cqiInput().implementationPlan,
      taskRefs: [],
      ownerAccepted: false,
      technologyChangeRefs: [],
    },
    effectivenessCheck: {
      ...cqiInput().effectivenessCheck,
      status: 'pending',
      verificationEvidenceHash: '',
      expectedBenefitMet: false,
      recurrenceObserved: true,
    },
  });

  const result = evaluateContinuousQualityImprovementCycle(input);

  assert.equal(result.decision, 'hold_for_cqi_gap');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('cqi_source_family_missing:staff_feedback'));
  assert.ok(result.reasons.includes('implementation_task_refs_absent'));
  assert.ok(result.reasons.includes('implementation_owner_acceptance_absent'));
  assert.ok(result.reasons.includes('technology_impact_without_change_ref'));
  assert.ok(result.reasons.includes('effectiveness_status_invalid'));
  assert.ok(result.reasons.includes('effectiveness_evidence_hash_invalid'));
  assert.ok(result.reasons.includes('effectiveness_expected_benefit_unmet'));
  assert.ok(result.reasons.includes('effectiveness_recurrence_observed'));
  assert.equal(result.receipt, null);
});

test('continuous quality improvement requires human governance and Decision Forum routing for material changes', async () => {
  const { evaluateContinuousQualityImprovementCycle } = await loadContinuousQualityImprovement();
  const input = cqiInput({
    impactAssessment: {
      ...cqiInput().impactAssessment,
      riskLevel: 'critical',
      participantSafetyImpact: true,
    },
    decisionForum: {
      ...cqiInput().decisionForum,
      invoked: false,
      quorumStatus: 'not_met',
      humanGateVerified: false,
    },
    humanReview: {
      ...cqiInput().humanReview,
      verified: false,
      decision: 'hold_for_cqi_gap',
    },
    aiAssistance: {
      ...cqiInput().aiAssistance,
      finalAuthority: true,
      advisoryOnly: false,
      humanReviewed: false,
    },
  });

  const result = evaluateContinuousQualityImprovementCycle(input);

  assert.equal(result.decision, 'hold_for_cqi_gap');
  assert.ok(result.reasons.includes('material_cqi_decision_forum_required'));
  assert.ok(result.reasons.includes('decision_forum_quorum_not_met'));
  assert.ok(result.reasons.includes('decision_forum_human_gate_unverified'));
  assert.ok(result.reasons.includes('human_review_unverified'));
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('ai_human_review_absent'));
});

test('continuous quality improvement validates HLC ordering and safe integer residual risk', async () => {
  const { evaluateContinuousQualityImprovementCycle } = await loadContinuousQualityImprovement();
  const result = evaluateContinuousQualityImprovementCycle(cqiInput({
    improvement: {
      ...cqiInput().improvement,
      dueAtHlc: { physicalMs: 1798100100000, logical: 0 },
    },
    implementationPlan: {
      ...cqiInput().implementationPlan,
      approvedAtHlc: { physicalMs: 1798100300000, logical: 1 },
      implementedAtHlc: { physicalMs: 1798100300000, logical: 0 },
    },
    effectivenessCheck: {
      ...cqiInput().effectivenessCheck,
      checkedAtHlc: { physicalMs: 1798100300000, logical: 0 },
      residualRiskBasisPoints: 10_001,
    },
    humanReview: {
      ...cqiInput().humanReview,
      reviewedAtHlc: { physicalMs: 1798100200000, logical: 0 },
    },
    auditRecord: {
      ...cqiInput().auditRecord,
      recordedAtHlc: { physicalMs: 1798100100000, logical: 0 },
    },
  }));

  assert.equal(result.decision, 'hold_for_cqi_gap');
  assert.ok(result.reasons.includes('improvement_due_before_approval'));
  assert.ok(result.reasons.includes('implementation_before_approval'));
  assert.ok(result.reasons.includes('effectiveness_before_implementation'));
  assert.ok(result.reasons.includes('human_review_before_effectiveness'));
  assert.ok(result.reasons.includes('audit_record_before_human_review'));
  assert.ok(result.reasons.includes('residual_risk_basis_points_invalid'));
});

test('continuous quality improvement rejects raw improvement content protected content and secrets before receipts', async () => {
  const { evaluateContinuousQualityImprovementCycle, ProtectedContentError } = await loadContinuousQualityImprovement();

  assert.throws(
    () => evaluateContinuousQualityImprovementCycle(cqiInput({
      improvement: {
        ...cqiInput().improvement,
        rawProblemStatement: 'Participant Jane Example described a consent issue.',
      },
    })),
    ProtectedContentError,
  );

  assert.throws(
    () => evaluateContinuousQualityImprovementCycle(cqiInput({
      adapterSecret: 'secret-value',
    })),
    ProtectedContentError,
  );
});
