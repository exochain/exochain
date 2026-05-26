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

const REQUIRED_ROLES = [
  'auditor',
  'coordinator',
  'cro_portfolio_manager',
  'decision_forum',
  'principal_investigator',
  'quality_manager',
  'site_leader',
  'sponsor_viewer',
];

const REQUIRED_WORKFLOWS = [
  'audit_assessment_response',
  'decision_forum_review',
  'deviation_capa_closure',
  'evidence_intake_review',
  'participant_consent_reconsent',
  'safety_event_reporting',
  'sponsor_diligence_export',
  'trial_startup_launch',
];

const REQUIRED_INDICATORS = [
  'blocked',
  'complete',
  'due_soon',
  'escalated',
  'in_progress',
  'not_started',
  'overdue',
  'pending_human_review',
];

const REQUIRED_CHECKLISTS = [
  'approval_gates',
  'completeness',
  'freshness',
  'missing_evidence',
  'owner_assignment',
  'privacy_boundary',
  'receipt_readiness',
  'required_evidence',
];

async function loadGuidedWorkflowUsability() {
  try {
    return await import('../src/guided-workflow-usability.mjs');
  } catch (error) {
    assert.fail(`CyberMedica guided workflow usability module must exist and load: ${error.message}`);
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

function roleView(roleRef, index) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2];
  return {
    roleRef,
    dashboardRef: `dashboard-${roleRef}`,
    guidedWorkflowRefs: REQUIRED_WORKFLOWS.slice(index % 2, index % 2 + 4),
    statusIndicatorRefs: REQUIRED_INDICATORS.slice(index % 3, index % 3 + 4),
    checklistRefs: REQUIRED_CHECKLISTS.slice(index % 2, index % 2 + 4),
    plainLanguageExplanationHash: hashes[index],
    accessibilityEvidenceHash: hashes[(index + 1) % hashes.length],
    canEscalateToHuman: true,
    productionTrustClaim: false,
    metadataOnly: true,
  };
}

function workflowGuide(workflowType, index) {
  const hashes = [DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6, DIGEST_A, DIGEST_B, DIGEST_C];
  return {
    workflowType,
    guideRef: `guide-${workflowType}`,
    stepRefs: [`${workflowType}-step-1`, `${workflowType}-step-2`, `${workflowType}-step-3`],
    gateRefs: [`${workflowType}-gate-human`, `${workflowType}-gate-privacy`],
    ownerRoleRefs: [REQUIRED_ROLES[index % REQUIRED_ROLES.length], 'quality_manager'],
    evidenceChecklistRef: `checklist-${REQUIRED_CHECKLISTS[index % REQUIRED_CHECKLISTS.length]}`,
    statusModelRef: `status-model-${workflowType}`,
    fallbackRouteRef: `fallback-human-${workflowType}`,
    humanEscalationRef: `escalation-${workflowType}`,
    metadataOnly: true,
    guideEvidenceHash: hashes[index],
  };
}

function statusIndicator(indicatorFamily, index) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2];
  return {
    indicatorFamily,
    indicatorRef: `indicator-${indicatorFamily}`,
    visibleLabelHash: hashes[index],
    accessibleNameHash: hashes[(index + 2) % hashes.length],
    colorIndependent: true,
    iconOrShapeCue: true,
    mappedWorkflowTypes: [REQUIRED_WORKFLOWS[index % REQUIRED_WORKFLOWS.length]],
    metadataOnly: true,
  };
}

function evidenceChecklist(checklistFamily, index) {
  const hashes = [DIGEST_F, DIGEST_E, DIGEST_D, DIGEST_C, DIGEST_B, DIGEST_A, DIGEST_3, DIGEST_4];
  return {
    checklistFamily,
    checklistRef: `checklist-${checklistFamily}`,
    requiredEvidenceRefs: [`evidence-${checklistFamily}-1`, `evidence-${checklistFamily}-2`],
    missingEvidenceVisible: true,
    freshnessPolicyRef: `freshness-${checklistFamily}`,
    completionBasisPoints: 10000,
    ownerRoleRef: REQUIRED_ROLES[index % REQUIRED_ROLES.length],
    checklistEvidenceHash: hashes[index],
    metadataOnly: true,
  };
}

function guidedInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:usability-lead-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'site_leader'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['usability_govern', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    usabilityPlan: {
      planRef: 'usability-plan-alpha',
      planVersion: 'v1',
      schemaVersion: 'cybermedica.guided_workflow_usability.v1',
      status: 'approved',
      roleDashboardRef: 'role-dashboards-alpha@v1',
      tenantConfigurationRef: 'tenant-config-alpha@v1',
      accessibilityPolicyHash: DIGEST_B,
      contentStyleGuideHash: DIGEST_C,
      statusTaxonomyHash: DIGEST_D,
      checklistModelHash: DIGEST_E,
      productionTrustClaim: false,
      metadataOnly: true,
    },
    governanceReview: {
      status: 'approved',
      reviewerDid: 'did:exo:quality-director-alpha',
      approvedAtHlc: { physicalMs: 1796620000000, logical: 0 },
      reviewedAtHlc: { physicalMs: 1796620600000, logical: 0 },
      reviewEvidenceHash: DIGEST_F,
      quorumVerified: true,
      aiFinalAuthorityRejected: true,
    },
    roleViews: REQUIRED_ROLES.map(roleView).reverse(),
    workflowGuides: REQUIRED_WORKFLOWS.map(workflowGuide).reverse(),
    statusIndicators: REQUIRED_INDICATORS.map(statusIndicator).reverse(),
    evidenceChecklists: REQUIRED_CHECKLISTS.map(evidenceChecklist).reverse(),
    explanationSet: {
      audienceRoles: REQUIRED_ROLES.toReversed(),
      plainLanguageSummaryHashes: [DIGEST_1, DIGEST_2, DIGEST_3],
      jargonGlossaryHash: DIGEST_4,
      aiGenerated: true,
      aiFinalAuthority: false,
      humanApproved: true,
      reviewedAtHlc: { physicalMs: 1796620700000, logical: 0 },
      metadataOnly: true,
    },
    accessibilityReview: {
      standard: 'wcag_2_2_aa',
      evidenceHash: DIGEST_5,
      keyboardNavigationVerified: true,
      screenReaderLabelsVerified: true,
      colorIndependentStatusVerified: true,
      focusOrderVerified: true,
      reducedMotionSupported: true,
      contrastMinimumBasisPoints: 4500,
      plainLanguageVerified: true,
      humanReviewed: true,
      testedAtHlc: { physicalMs: 1796620800000, logical: 0 },
      metadataOnly: true,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      evidenceRefs: ['role-dashboard-ref', 'accessibility-policy-hash'],
      reasoningSummaryHash: DIGEST_6,
      confidenceBasisPoints: 7600,
      limitationHashes: [DIGEST_A],
      unresolvedAssumptionHashes: [DIGEST_B],
      recommendedHumanReviewerDids: ['did:exo:quality-director-alpha'],
    },
    custodyDigest: DIGEST_C,
  };

  return mergeDeep(base, overrides);
}

test('guided workflow usability creates deterministic NFR-010 inactive receipts', async () => {
  const { evaluateGuidedWorkflowUsability } = await loadGuidedWorkflowUsability();

  const resultA = evaluateGuidedWorkflowUsability(guidedInput());
  const resultB = evaluateGuidedWorkflowUsability(guidedInput({
    roleViews: REQUIRED_ROLES.map(roleView),
    workflowGuides: REQUIRED_WORKFLOWS.map(workflowGuide),
    statusIndicators: REQUIRED_INDICATORS.map(statusIndicator),
    evidenceChecklists: REQUIRED_CHECKLISTS.map(evidenceChecklist),
  }));

  assert.equal(resultA.permitted, true);
  assert.deepEqual(resultA.reasons, []);
  assert.equal(resultA.usabilityRecord.schema, 'cybermedica.guided_workflow_usability_record.v1');
  assert.equal(resultA.usabilityRecord.status, 'approved');
  assert.equal(resultA.usabilityRecord.trustState, 'inactive');
  assert.equal(resultA.usabilityRecord.exochainProductionClaim, false);
  assert.deepEqual(resultA.usabilityRecord.roleCoverage, REQUIRED_ROLES);
  assert.deepEqual(resultA.usabilityRecord.workflowCoverage, REQUIRED_WORKFLOWS);
  assert.deepEqual(resultA.usabilityRecord.indicatorCoverage, REQUIRED_INDICATORS);
  assert.deepEqual(resultA.usabilityRecord.checklistCoverage, REQUIRED_CHECKLISTS);
  assert.equal(resultA.usabilityRecord.accessibilityProfile.standard, 'wcag_2_2_aa');
  assert.equal(resultA.usabilityRecord.explanationCoverageBasisPoints, 10000);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.containsProtectedContent, false);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'guided_workflow_usability');
  assert.equal(resultA.receipt.anchorPayload.classification, 'restricted_metadata_only');
  assert.equal(resultA.usabilityRecord.usabilityHash, resultB.usabilityRecord.usabilityHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
});

test('guided workflow usability fails closed for missing role workflow and checklist coverage', async () => {
  const { evaluateGuidedWorkflowUsability } = await loadGuidedWorkflowUsability();

  const absent = evaluateGuidedWorkflowUsability({});

  assert.equal(absent.permitted, false);
  assert.ok(absent.reasons.includes('tenant_absent'));
  assert.ok(absent.reasons.includes('usability_plan_ref_absent'));
  assert.ok(absent.reasons.includes('role_views_absent'));
  assert.ok(absent.reasons.includes('workflow_guides_absent'));
  assert.ok(absent.reasons.includes('status_indicators_absent'));
  assert.ok(absent.reasons.includes('evidence_checklists_absent'));
  assert.ok(absent.reasons.includes('accessibility_standard_invalid'));
  assert.equal(absent.usabilityRecord, null);
  assert.equal(absent.receipt, null);

  const result = evaluateGuidedWorkflowUsability(guidedInput({
    roleViews: REQUIRED_ROLES.filter((role) => role !== 'sponsor_viewer').map(roleView),
    workflowGuides: REQUIRED_WORKFLOWS.filter((workflow) => workflow !== 'safety_event_reporting').map(workflowGuide),
    statusIndicators: REQUIRED_INDICATORS.filter((indicator) => indicator !== 'overdue').map(statusIndicator),
    evidenceChecklists: REQUIRED_CHECKLISTS.filter((checklist) => checklist !== 'privacy_boundary').map(evidenceChecklist),
    accessibilityReview: {
      colorIndependentStatusVerified: false,
      contrastMinimumBasisPoints: 3200,
    },
    explanationSet: {
      audienceRoles: REQUIRED_ROLES.filter((role) => role !== 'auditor'),
      humanApproved: false,
    },
  }));

  assert.equal(result.permitted, false);
  assert.ok(result.reasons.includes('required_role_view_missing:sponsor_viewer'));
  assert.ok(result.reasons.includes('required_workflow_guide_missing:safety_event_reporting'));
  assert.ok(result.reasons.includes('required_status_indicator_missing:overdue'));
  assert.ok(result.reasons.includes('required_evidence_checklist_missing:privacy_boundary'));
  assert.ok(result.reasons.includes('accessibility_color_independence_missing'));
  assert.ok(result.reasons.includes('accessibility_contrast_below_minimum'));
  assert.ok(result.reasons.includes('plain_language_audience_missing:auditor'));
  assert.ok(result.reasons.includes('plain_language_human_approval_missing'));
  assert.equal(result.usabilityRecord, null);
  assert.equal(result.receipt, null);
});

test('guided workflow usability enforces HLC ordering and AI non-finality', async () => {
  const { evaluateGuidedWorkflowUsability } = await loadGuidedWorkflowUsability();

  const noAi = evaluateGuidedWorkflowUsability(guidedInput({
    aiAssistance: { used: false },
    explanationSet: {
      aiGenerated: false,
      aiFinalAuthority: false,
    },
  }));

  assert.equal(noAi.permitted, true);
  assert.equal(noAi.usabilityRecord.aiAssistance.used, false);
  assert.equal(noAi.usabilityRecord.explanationSet.aiGenerated, false);

  const unsafeOrdering = evaluateGuidedWorkflowUsability(guidedInput({
    governanceReview: {
      approvedAtHlc: { physicalMs: 1796620000000, logical: 0 },
      reviewedAtHlc: { physicalMs: 1796619999999, logical: 0 },
    },
    accessibilityReview: {
      testedAtHlc: { physicalMs: 1796619999998, logical: 0 },
    },
    explanationSet: {
      reviewedAtHlc: { physicalMs: 1796619999998, logical: 0 },
    },
    aiAssistance: {
      finalAuthority: true,
    },
  }));

  assert.equal(unsafeOrdering.permitted, false);
  assert.ok(unsafeOrdering.reasons.includes('governance_review_before_approval'));
  assert.ok(unsafeOrdering.reasons.includes('accessibility_test_before_governance_review'));
  assert.ok(unsafeOrdering.reasons.includes('plain_language_review_before_governance_review'));
  assert.ok(unsafeOrdering.reasons.includes('ai_final_authority_forbidden'));

  const sameTickEqual = evaluateGuidedWorkflowUsability(guidedInput({
    governanceReview: {
      approvedAtHlc: { physicalMs: 1796620000000, logical: 0 },
      reviewedAtHlc: { physicalMs: 1796620000000, logical: 0 },
    },
    explanationSet: {
      reviewedAtHlc: { physicalMs: 1796620000000, logical: 0 },
    },
    accessibilityReview: {
      testedAtHlc: { physicalMs: 1796620000000, logical: 0 },
    },
  }));

  assert.equal(sameTickEqual.permitted, true);

  const sameTickAdvancing = evaluateGuidedWorkflowUsability(guidedInput({
    governanceReview: {
      approvedAtHlc: { physicalMs: 1796620000000, logical: 0 },
      reviewedAtHlc: { physicalMs: 1796620000000, logical: 1 },
    },
    explanationSet: {
      reviewedAtHlc: { physicalMs: 1796620000000, logical: 2 },
    },
    accessibilityReview: {
      testedAtHlc: { physicalMs: 1796620000000, logical: 3 },
    },
  }));

  assert.equal(sameTickAdvancing.permitted, true);
});

test('guided workflow usability rejects raw copy protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateGuidedWorkflowUsability } = await loadGuidedWorkflowUsability();

  assert.throws(
    () => evaluateGuidedWorkflowUsability(guidedInput({
      workflowGuides: [
        {
          ...workflowGuide('trial_startup_launch', 7),
          rawWorkflowCopy: 'Participant Jane Example should see the launch checklist.',
        },
      ],
    })),
    ProtectedContentError,
  );

  assert.throws(
    () => evaluateGuidedWorkflowUsability(guidedInput({
      accessibilityReview: {
        apiKey: { vaultRef: 'secret-ref-alpha' },
      },
    })),
    ProtectedContentError,
  );

  assert.throws(
    () => evaluateGuidedWorkflowUsability(guidedInput({
      explanationSet: {
        plainLanguageText: [false, 1],
      },
    })),
    ProtectedContentError,
  );

  const inertRawMarker = evaluateGuidedWorkflowUsability(guidedInput({
    explanationSet: {
      plainLanguageText: false,
    },
  }));

  assert.equal(inertRawMarker.permitted, true);
});
