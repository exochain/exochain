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

const REQUIRED_FRAMEWORK_DOMAINS = Object.freeze([
  'assessment_method',
  'criteria',
  'escalation',
  'mitigation_tracking',
  'risk_identification',
  'safety_planning',
  'staff_training',
  'treatment_controls',
]);

const REQUIRED_REGISTER_CATEGORIES = Object.freeze([
  'consent',
  'data_integrity',
  'facility',
  'operational',
  'participant_safety',
  'product_handling',
  'regulatory',
  'staffing',
  'vendor',
]);

async function loadRiskManagementFramework() {
  try {
    return await import('../src/risk-management-framework.mjs');
  } catch (error) {
    assert.fail(`CyberMedica risk-management-framework module must exist and load: ${error.message}`);
  }
}

function domainEvidence() {
  return REQUIRED_FRAMEWORK_DOMAINS.map((domain, index) => ({
    domain,
    status: 'implemented',
    evidenceHash: index % 2 === 0 ? DIGEST_A : DIGEST_B,
    ownerDid: `did:exo:${domain.replaceAll('_', '-')}-owner-alpha`,
    reviewedAtHlc: { physicalMs: 1798200000000 + index, logical: 0 },
  }));
}

function registerEntries() {
  return REQUIRED_REGISTER_CATEGORIES.map((category, index) => ({
    riskRef: `risk-register-${category}`,
    category,
    status: index === 3 ? 'monitoring' : 'controlled',
    ownerDid: `did:exo:${category.replaceAll('_', '-')}-owner-alpha`,
    initialRiskScore: index === 3 ? 42 : 24,
    residualRiskScore: index === 3 ? 18 : 12,
    treatmentPlanHash: index % 2 === 0 ? DIGEST_C : DIGEST_D,
    controlEvidenceHash: index % 2 === 0 ? DIGEST_E : DIGEST_F,
    mitigationTrackerRef: `mitigation-${category}`,
    escalationRequired: category === 'participant_safety',
    escalationRef: category === 'participant_safety' ? 'risk-escalation-participant-safety' : null,
    lastReviewedAtHlc: { physicalMs: 1798300000000 + index, logical: 0 },
  }));
}

function frameworkInput() {
  return {
    requestId: 'risk-management-framework-alpha',
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    siteId: 'site-alpha',
    checkedAtHlc: { physicalMs: 1799000000000, logical: 0 },
    actor: { did: 'did:exo:quality-risk-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['govern', 'risk_framework_manage'],
      authorityChainHash: DIGEST_F,
    },
    framework: {
      frameworkRef: 'RMF-SITE-ALPHA-2026',
      policyRef: 'POLICY-16-RISK-MANAGEMENT',
      version: 'v1',
      status: 'active',
      frameworkHash: DIGEST_A,
      approvedAtHlc: { physicalMs: 1798000000000, logical: 0 },
      reviewDueHlc: { physicalMs: 1801000000000, logical: 0 },
      domainEvidence: domainEvidence(),
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    criteria: {
      criteriaRef: 'RISK-CRITERIA-SITE-ALPHA',
      criteriaHash: DIGEST_B,
      probabilityScaleMin: 1,
      probabilityScaleMax: 5,
      severityScaleMin: 1,
      severityScaleMax: 5,
      detectabilityScaleMin: 1,
      detectabilityScaleMax: 5,
      acceptanceThresholdScore: 20,
      escalationThresholdScore: 40,
      reviewFrequencyDays: 90,
      metadataOnly: true,
    },
    riskRegister: {
      registerRef: 'RISK-REGISTER-SITE-ALPHA',
      status: 'current',
      reviewedAtHlc: { physicalMs: 1798400000000, logical: 0 },
      registerHash: DIGEST_C,
      entries: registerEntries(),
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    trainingProgram: {
      trainingMatrixRef: 'TRAINING-RISK-MANAGEMENT-ALPHA',
      trainingEvidenceHash: DIGEST_D,
      requiredRoleRefs: ['clinical_research_coordinator', 'principal_investigator', 'quality_manager'],
      coverageDomains: ['assessment_method', 'escalation', 'mitigation_tracking', 'safety_planning'],
      acknowledgementHash: DIGEST_E,
      completedAtHlc: { physicalMs: 1798500000000, logical: 0 },
      metadataOnly: true,
    },
    safetyPlanning: {
      planRef: 'SAFETY-PLAN-RISK-FRAMEWORK-ALPHA',
      planHash: DIGEST_E,
      participantSafetyCovered: true,
      rightsWellbeingCovered: true,
      urgentEscalationPathHash: DIGEST_F,
      medicalReviewOwnerDid: 'did:exo:principal-investigator-alpha',
      reviewedAtHlc: { physicalMs: 1798600000000, logical: 0 },
      metadataOnly: true,
    },
    mitigationTracking: {
      trackerRef: 'MITIGATION-TRACKER-SITE-ALPHA',
      trackerHash: DIGEST_F,
      openMitigationCount: 3,
      overdueMitigationCount: 0,
      unassignedMitigationCount: 0,
      highRiskWithoutOwnerCount: 0,
      reviewEvidenceHash: DIGEST_A,
      reviewedAtHlc: { physicalMs: 1798700000000, logical: 0 },
      metadataOnly: true,
    },
    escalationPath: {
      pathRef: 'RISK-ESCALATION-PATH-SITE-ALPHA',
      pathHash: DIGEST_B,
      requiredRoleRefs: ['decision_forum_chair', 'principal_investigator', 'quality_manager'],
      decisionForumRequiredFor: ['critical_residual_risk', 'participant_safety_risk', 'unmitigated_high_risk'],
      exerciseEvidenceHash: DIGEST_C,
      reviewedAtHlc: { physicalMs: 1798800000000, logical: 0 },
      metadataOnly: true,
    },
    humanGovernance: {
      verified: true,
      approvedByDid: 'did:exo:quality-director-alpha',
      decisionForumReceiptId: 'df-risk-framework-alpha',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
    },
    aiAssistance: { used: true, finalAuthority: false, recommendationHash: DIGEST_D },
    custodyDigest: DIGEST_E,
  };
}

test('risk management framework creates deterministic inactive Policy 16 readiness receipts', async () => {
  const { evaluateRiskManagementFramework } = await loadRiskManagementFramework();
  const input = frameworkInput();

  const first = evaluateRiskManagementFramework(input);
  const second = evaluateRiskManagementFramework({
    ...input,
    framework: {
      ...input.framework,
      domainEvidence: [...input.framework.domainEvidence].reverse(),
    },
    riskRegister: {
      ...input.riskRegister,
      entries: [...input.riskRegister.entries].reverse(),
    },
    trainingProgram: {
      ...input.trainingProgram,
      requiredRoleRefs: [...input.trainingProgram.requiredRoleRefs].reverse(),
      coverageDomains: [...input.trainingProgram.coverageDomains].reverse(),
    },
    escalationPath: {
      ...input.escalationPath,
      requiredRoleRefs: [...input.escalationPath.requiredRoleRefs].reverse(),
      decisionForumRequiredFor: [...input.escalationPath.decisionForumRequiredFor].reverse(),
    },
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.deepEqual(first.reasons, []);
  assert.equal(first.trustState, 'inactive');
  assert.equal(first.exochainProductionClaim, false);
  assert.equal(first.riskManagementFramework.frameworkHash, second.riskManagementFramework.frameworkHash);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.receipt.anchorPayload.artifactType, 'risk_management_framework');
  assert.equal(first.receipt.trustState, 'inactive');
  assert.deepEqual(first.riskManagementFramework.frameworkDomains, REQUIRED_FRAMEWORK_DOMAINS);
  assert.deepEqual(first.riskManagementFramework.registerCategories, REQUIRED_REGISTER_CATEGORIES);
  assert.deepEqual(first.riskManagementFramework.requiredEscalationRoles, [
    'decision_forum_chair',
    'principal_investigator',
    'quality_manager',
  ]);
  assert.equal(first.riskManagementFramework.maxResidualRiskScore, 18);
  assert.equal(first.riskManagementFramework.overdueMitigationCount, 0);
  assert.doesNotMatch(JSON.stringify(first), /root-backed production authority|Participant Alice|medical record/iu);
});

test('risk management framework fails closed for missing domains register gaps and mitigation defects', async () => {
  const { evaluateRiskManagementFramework } = await loadRiskManagementFramework();
  const input = frameworkInput();

  const result = evaluateRiskManagementFramework({
    ...input,
    framework: {
      ...input.framework,
      domainEvidence: input.framework.domainEvidence.filter((row) => row.domain !== 'criteria'),
    },
    riskRegister: {
      ...input.riskRegister,
      entries: input.riskRegister.entries.filter((entry) => entry.category !== 'vendor'),
    },
    mitigationTracking: {
      ...input.mitigationTracking,
      overdueMitigationCount: 1,
      highRiskWithoutOwnerCount: 1,
    },
  });

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.riskManagementFramework, null);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('framework_domain_missing:criteria'));
  assert.ok(result.reasons.includes('risk_register_category_missing:vendor'));
  assert.ok(result.reasons.includes('overdue_mitigations_present'));
  assert.ok(result.reasons.includes('high_risk_without_owner_present'));
});

test('risk management framework requires criteria training safety escalation and human governance', async () => {
  const { evaluateRiskManagementFramework } = await loadRiskManagementFramework();
  const input = frameworkInput();

  const result = evaluateRiskManagementFramework({
    ...input,
    actor: { did: 'did:exo:risk-ai-alpha', kind: 'ai_agent' },
    authority: {
      ...input.authority,
      permissions: ['read'],
      expired: true,
    },
    criteria: {
      ...input.criteria,
      acceptanceThresholdScore: 50,
      escalationThresholdScore: 25,
      reviewFrequencyDays: 0,
    },
    trainingProgram: {
      ...input.trainingProgram,
      coverageDomains: ['assessment_method'],
      completedAtHlc: { physicalMs: 1797900000000, logical: 0 },
    },
    safetyPlanning: {
      ...input.safetyPlanning,
      participantSafetyCovered: false,
      urgentEscalationPathHash: '',
    },
    escalationPath: {
      ...input.escalationPath,
      decisionForumRequiredFor: ['critical_residual_risk'],
      exerciseEvidenceHash: '',
    },
    humanGovernance: {
      ...input.humanGovernance,
      verified: false,
      humanGate: { verified: false },
      quorum: { status: 'missing' },
      openChallenge: true,
    },
    aiAssistance: { used: true, finalAuthority: true, recommendationHash: DIGEST_D },
  });

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('authority_chain_expired'));
  assert.ok(result.reasons.includes('authority_permission_missing'));
  assert.ok(result.reasons.includes('risk_acceptance_threshold_above_escalation_threshold'));
  assert.ok(result.reasons.includes('risk_review_frequency_invalid'));
  assert.ok(result.reasons.includes('training_domain_missing:escalation'));
  assert.ok(result.reasons.includes('training_completed_before_framework_approval'));
  assert.ok(result.reasons.includes('participant_safety_plan_absent'));
  assert.ok(result.reasons.includes('urgent_escalation_path_hash_invalid'));
  assert.ok(result.reasons.includes('escalation_trigger_missing:participant_safety_risk'));
  assert.ok(result.reasons.includes('escalation_exercise_evidence_invalid'));
  assert.ok(result.reasons.includes('human_governance_unverified'));
  assert.ok(result.reasons.includes('human_gate_unverified'));
  assert.ok(result.reasons.includes('quorum_not_met'));
  assert.ok(result.reasons.includes('challenge_open'));
});

test('risk management framework rejects raw risk content and secrets before receipts', async () => {
  const { evaluateRiskManagementFramework, ProtectedContentError } = await loadRiskManagementFramework();
  const input = frameworkInput();

  assert.throws(
    () =>
      evaluateRiskManagementFramework({
        ...input,
        framework: {
          ...input.framework,
          rawRiskFrameworkText: 'Participant Alice medical record and sponsor-confidential risk detail',
        },
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateRiskManagementFramework({
        ...input,
        escalationPath: {
          ...input.escalationPath,
          rootSigningKey: 'not-for-cybermedica',
        },
      }),
    ProtectedContentError,
  );
});
