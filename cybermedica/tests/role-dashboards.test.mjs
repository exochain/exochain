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

async function loadRoleDashboards() {
  try {
    return await import('../src/role-dashboards.mjs');
  } catch (error) {
    assert.fail(`CyberMedica role dashboards module must exist and load: ${error.message}`);
  }
}

const REQUIRED_WIDGETS = Object.freeze({
  auditor: [
    'evidence_traceability',
    'document_version_history',
    'access_logs',
    'chain_of_custody',
    'decision_rationale',
    'issue_history',
    'corrective_actions',
    'staff_training_records',
    'role_delegation_records',
    'inspection_audit_packet',
  ],
  coordinator: [
    'assigned_tasks',
    'training_requirements',
    'protocol_procedures',
    'active_consent_version',
    'deviation_reporting_shortcut',
    'participant_visit_requirements',
    'document_access',
    'upcoming_due_dates',
    'concern_reporting',
  ],
  cro_portfolio_manager: [
    'sites_by_readiness_status',
    'studies_by_startup_status',
    'site_gaps',
    'critical_findings',
    'capa_aging',
    'training_coverage',
    'risk_heatmap',
    'sponsor_exports',
    'monitoring_findings',
    'cross_site_trends',
  ],
  decision_forum: [
    'pending_matters',
    'required_quorum',
    'conflict_disclosures',
    'evidence_bundles',
    'ai_review_summaries',
    'votes',
    'conditions',
    'dissent',
    'decisions',
    'follow_up_actions',
  ],
  principal_investigator: [
    'protocol_readiness',
    'delegation_log',
    'training_completion',
    'consent_form_status',
    'active_deviations',
    'safety_events',
    'participant_protection_tasks',
    'launch_enrollment_gate_status',
    'required_approvals',
    'study_action_items',
  ],
  quality_manager: [
    'control_status',
    'evidence_completeness',
    'evidence_freshness',
    'findings_by_severity',
    'capa_aging',
    'deviation_trends',
    'audit_schedule',
    'risk_register',
    'document_review_queue',
    'training_gap_trends',
  ],
  site_leader: [
    'site_qms_passport_status',
    'critical_gaps',
    'open_risks',
    'open_capas',
    'training_gaps',
    'upcoming_reviews',
    'audit_status',
    'protocol_startup_status',
    'decision_forum_matters',
    'sponsor_cro_requests',
  ],
  sponsor_viewer: [
    'authorized_site_readiness_view',
    'evidence_summary',
    'open_critical_major_gaps',
    'capa_status',
    'training_summary',
    'facility_equipment_status',
    'consent_readiness',
    'deviation_trends',
    'audit_assessment_reports',
    'decision_certificates',
  ],
});

const ROLE_REFS = Object.freeze({
  auditor: ['auditor'],
  coordinator: ['clinical_research_coordinator'],
  cro_portfolio_manager: ['cro_portfolio_manager'],
  decision_forum: ['decision_forum'],
  principal_investigator: ['principal_investigator'],
  quality_manager: ['quality_manager'],
  site_leader: ['site_leader'],
  sponsor_viewer: ['sponsor_viewer'],
});

const DIGESTS = [
  DIGEST_A,
  DIGEST_B,
  DIGEST_C,
  DIGEST_D,
  DIGEST_E,
  DIGEST_F,
  DIGEST_1,
  DIGEST_2,
  DIGEST_3,
  DIGEST_4,
  DIGEST_5,
  DIGEST_6,
  DIGEST_7,
  DIGEST_8,
  DIGEST_9,
];

function roleDashboardInput(role = 'quality_manager', overrides = {}) {
  const roleRefs = ROLE_REFS[role];
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: `did:exo:${role.replaceAll('_', '-')}-alpha`,
      kind: 'human',
      roleRefs,
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['dashboard_view', 'read'],
      authorityChainHash: DIGEST_A,
    },
    dashboard: {
      dashboardRef: `dashboard-${role}-site-alpha`,
      role,
      generatedAtHlc: { physicalMs: 1795000000000, logical: 30 },
      sourceIndexHash: DIGEST_B,
      schemaVersion: 'cybermedica.role_dashboard.v1',
      metadataOnly: true,
      rawPayloadExcluded: true,
      productionTrustClaim: false,
      widgetManifestHash: DIGEST_C,
    },
    productionTrustActivation: inactiveProductionTrustActivation(),
    accessPolicy: {
      policyRef: `dashboard-policy-${role}`,
      policyHash: DIGEST_D,
      evaluatedAtHlc: { physicalMs: 1795000000000, logical: 2 },
      allowedDashboardRoles: Object.keys(REQUIRED_WIDGETS),
      allowedRoleRefs: roleRefs,
      allowedSiteRefs: ['site-alpha'],
      allowedSensitivityTags: ['metadata_only', 'qms', 'sponsor_confidential_metadata', 'audit_metadata'],
      metadataOnly: true,
      sourcePayloadAccessible: false,
      disclosureLogRequired: true,
    },
    disclosureLog: {
      logId: `dashboard-disclosure-${role}`,
      loggedAtHlc: { physicalMs: 1795000000000, logical: 3 },
      disclosureLogHash: DIGEST_E,
      purpose: 'role_dashboard_view',
      recipientClass: role,
      includesRawContent: false,
    },
    widgets: dashboardWidgets(role),
    ...overrides,
  };
}

function inactiveProductionTrustActivation(overrides = {}) {
  return {
    schema: 'cybermedica.production_trust_activation.v1',
    claimId: 'PTAG-001',
    allowed: false,
    state: 'inactive',
    failClosed: true,
    blockedBy: [
      'root_bundle_absent',
      'root_certifier_roster_absent',
      'root_dkg_transcript_absent',
      'root_threshold_signature_absent',
      'root_verifier_absent',
    ],
    exochainProductionClaim: false,
    publicClaimReviewReceiptHash: DIGEST_1,
    publicClaimReviewPackageHash: DIGEST_2,
    publicClaimReviewStatus: 'approved_for_public_use',
    publicClaimReviewTrustState: 'inactive',
    publicClaimReviewPublicUseAuthorized: true,
    publicClaimReviewProductionClaimLiftReceiptHash: DIGEST_3,
    publicClaimReviewProductionClaimLiftTrustState: 'inactive',
    publicClaimReviewProductionClaimLiftCanLiftProductionClaim: false,
    publicClaimReviewProductionClaimLiftRoleDashboardProviderReceiptHash: DIGEST_B,
    publicClaimReviewProductionClaimLiftRoleDashboardProviderSummaryHash: DIGEST_C,
    publicClaimReviewProductionClaimLiftRoleDashboardProviderTrustStateViewHash: DIGEST_D,
    publicClaimReviewProductionClaimLiftRoleDashboardReadinessReceiptHash: DIGEST_E,
    publicClaimReviewProductionClaimLiftRoleDashboardReadinessSummaryHash: DIGEST_F,
    publicClaimReviewProductionClaimLiftRoleDashboardReadinessTrustStateViewHash: DIGEST_1,
    publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_B,
    publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_C,
    publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_D,
    publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_E,
    publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_F,
    publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_1,
    publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_B,
    publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_C,
    publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_D,
    publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_E,
    publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_F,
    publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_1,
    publicClaimReviewProductionClaimLiftRoleDashboardRoles: Object.keys(REQUIRED_WIDGETS).sort(),
    displayLabel: 'Trust fabric inactive',
    claimLanguage: 'Exochain production trust is not active for this CyberMedica action.',
    ...overrides,
  };
}

function dashboardWidgets(role) {
  return REQUIRED_WIDGETS[role].map((metricKey, index) => widget(metricKey, index, role));
}

function widget(metricKey, index, role = 'quality_manager', overrides = {}) {
  return {
    widgetRef: `${role}-${metricKey}-widget`,
    metricKey,
    evidenceHash: DIGESTS[index % DIGESTS.length],
    custodyDigest: DIGESTS[(index + 1) % DIGESTS.length],
    sourceIndexHash: DIGESTS[(index + 2) % DIGESTS.length],
    updatedAtHlc: { physicalMs: 1795000000000, logical: index + 4 },
    siteRefs: ['site-alpha'],
    roleVisibility: ROLE_REFS[role],
    sensitivityTags: ['metadata_only', 'qms'],
    sourceFamilies: ['controls', 'evidence', 'risks'],
    statusBasisPoints: 10_000 - index * 250,
    recordCount: index + 1,
    criticalCount: index % 3 === 0 ? 1 : 0,
    overdueCount: index % 4 === 0 ? 1 : 0,
    boundary: {
      metadataOnly: true,
      rawContentExcluded: true,
      sourcePayloadAnchored: false,
    },
    manualNavigation: {
      drawerContextFamily: 'dashboard_card',
      manualSectionRef: `manual-section-${role}-${metricKey}`,
      manualSectionHash: DIGESTS[(index + 3) % DIGESTS.length],
      manualDrawerPolicyHash: DIGESTS[(index + 4) % DIGESTS.length],
      crosslinkMatrixHash: DIGESTS[(index + 5) % DIGESTS.length],
      roleManualRef: `role-manual-${role}`,
      instructionSlotRefs: [
        'approval_required',
        'audit_export_result',
        'common_failure_modes',
        'evidence_needed',
        'step_by_step',
        'what_this_is',
        'when_to_use_it',
        'who_owns_it',
      ],
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    documentationReadiness: {
      controlledDocumentDistributionRecordId: `cmdist-${role}-${metricKey}`,
      controlledDocumentDistributionReceiptHash: DIGEST_6,
      documentationPublicationReceiptHash: DIGEST_7,
      manualExportReceiptHash: DIGEST_8,
      orientationAssistantReceiptHash: DIGEST_9,
      acknowledgementRosterHash: DIGEST_5,
      requiredAcknowledgementRoleRefs: ROLE_REFS[role],
      acknowledgedRoleRefs: ROLE_REFS[role],
      distributionPublishedAtHlc: { physicalMs: 1794999999900, logical: index + 1 },
      effectiveUseAcknowledged: true,
      currentVersionOnly: true,
      obsoleteVersionUseBlocked: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    ...(metricKey === 'sponsor_cro_requests' ? { sponsorCroRequestEvidence: sponsorCroRequestEvidence() } : {}),
    ...overrides,
  };
}

function sponsorCroRequestEvidence(overrides = {}) {
  return {
    requestRef: 'sponsor-cro-request-alpha',
    requestHash: DIGEST_A,
    requesterClass: 'sponsor',
    workItemRef: 'sponsor-cro-work-item-alpha',
    workItemStatus: 'queued_for_site_review',
    disclosureEventRef: 'disclosure-event-sponsor-cro-alpha',
    disclosureLogHash: DIGEST_B,
    decisionForumMatterRef: 'df-sponsor-cro-request-alpha',
    humanReviewHash: DIGEST_C,
    responseWorkflowRef: 'workflow-sponsor-cro-request-response',
    linkedAtHlc: { physicalMs: 1795000000000, logical: 10 },
    metadataOnly: true,
    sourcePayloadExcluded: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

test('role dashboards render deterministic inactive metadata-only dashboards for all PRD roles', async () => {
  const { evaluateRoleDashboard } = await loadRoleDashboards();

  for (const [role, requiredWidgets] of Object.entries(REQUIRED_WIDGETS)) {
    const roleRefs = ROLE_REFS[role];
    const input = roleDashboardInput(role);
    const reversedInput = { ...input, widgets: [...input.widgets].reverse() };
    const resultA = evaluateRoleDashboard(input);
    const resultB = evaluateRoleDashboard(reversedInput);

    assert.equal(resultA.status, 'ready', role);
    assert.deepEqual(resultA.denialReasons, [], role);
    assert.equal(resultA.trustState, 'inactive', role);
    assert.equal(resultA.exochainProductionClaim, false, role);
    assert.equal(resultA.canShowProductionTrustClaim, false, role);
    assert.equal(resultA.trustStateView.status, 'inactive', role);
    assert.equal(resultA.trustStateView.actionsDisabled, true, role);
    assert.equal(resultA.trustStateView.activationLineageAccepted, true, role);
    assert.equal(resultA.trustStateView.productionTrustActivationLineage.claimId, 'PTAG-001', role);
    assert.equal(resultA.trustStateView.productionTrustActivationLineage.activationState, 'inactive', role);
    assert.equal(resultA.trustStateView.productionTrustActivationLineage.exochainProductionClaim, false, role);
    assert.equal(resultA.trustStateView.productionTrustActivationLineage.publicClaimReviewReceiptHash, DIGEST_1, role);
    assert.equal(resultA.trustStateView.productionTrustActivationLineage.publicClaimReviewPackageHash, DIGEST_2, role);
    assert.equal(resultA.trustStateView.productionTrustActivationLineage.publicClaimReviewStatus, 'approved_for_public_use', role);
    assert.equal(resultA.trustStateView.productionTrustActivationLineage.publicClaimReviewTrustState, 'inactive', role);
    assert.equal(
      resultA.trustStateView.productionTrustActivationLineage.publicClaimReviewProductionClaimLiftReceiptHash,
      DIGEST_3,
      role,
    );
    assert.equal(
      resultA.trustStateView.productionTrustActivationLineage.publicClaimReviewProductionClaimLiftCanLiftProductionClaim,
      false,
      role,
    );
    assert.equal(
      resultA.trustStateView.productionTrustActivationLineage
        .publicClaimReviewProductionClaimLiftRoleDashboardProviderReceiptHash,
      DIGEST_B,
      role,
    );
    assert.equal(
      resultA.trustStateView.productionTrustActivationLineage
        .publicClaimReviewProductionClaimLiftRoleDashboardProviderSummaryHash,
      DIGEST_C,
      role,
    );
    assert.equal(
      resultA.trustStateView.productionTrustActivationLineage
        .publicClaimReviewProductionClaimLiftRoleDashboardProviderTrustStateViewHash,
      DIGEST_D,
      role,
    );
    assert.equal(
      resultA.trustStateView.productionTrustActivationLineage
        .publicClaimReviewProductionClaimLiftRoleDashboardReadinessReceiptHash,
      DIGEST_E,
      role,
    );
    assert.equal(
      resultA.trustStateView.productionTrustActivationLineage
        .publicClaimReviewProductionClaimLiftRoleDashboardReadinessSummaryHash,
      DIGEST_F,
      role,
    );
    assert.equal(
      resultA.trustStateView.productionTrustActivationLineage
        .publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
      DIGEST_D,
      role,
    );
    assert.equal(
      resultA.trustStateView.productionTrustActivationLineage
        .publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardReceiptHash,
      DIGEST_B,
      role,
    );
    assert.equal(
      resultA.trustStateView.productionTrustActivationLineage
        .publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardSummaryHash,
      DIGEST_C,
      role,
    );
    assert.equal(
      resultA.trustStateView.productionTrustActivationLineage
        .publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash,
      DIGEST_D,
      role,
    );
    assert.equal(
      resultA.trustStateView.productionTrustActivationLineage
        .publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
      DIGEST_1,
      role,
    );
    assert.equal(
      resultA.trustStateView.productionTrustActivationLineage
        .publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash,
      DIGEST_E,
      role,
    );
    assert.equal(
      resultA.trustStateView.productionTrustActivationLineage
        .publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash,
      DIGEST_F,
      role,
    );
    assert.equal(
      resultA.trustStateView.productionTrustActivationLineage
        .publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
      DIGEST_1,
      role,
    );
    assert.deepEqual(
      resultA.trustStateView.productionTrustActivationLineage.publicClaimReviewProductionClaimLiftRoleDashboardRoles,
      Object.keys(REQUIRED_WIDGETS).sort(),
      role,
    );
    assert.deepEqual(resultA.trustStateView.bobEscalations, [
      'ESC-ROOT-ARTIFACT-STORE',
      'ESC-ROOT-DEPLOYMENT',
      'ESC-ROOT-ROSTER',
    ]);
    assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('production_trust_activation'), role);
    assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('public_claim_review_lineage'), role);
    assert.ok(
      resultA.receipt.anchorPayload.sensitivityTags.includes('production_claim_lift_role_dashboard_lineage'),
      role,
    );
    assert.deepEqual(resultA.requiredWidgetKeys, requiredWidgets, role);
    assert.deepEqual(
      resultA.visibleWidgets.map((visibleWidget) => visibleWidget.metricKey),
      requiredWidgets,
      role,
    );
    assert.deepEqual(
      resultA.visibleWidgets.map((visibleWidget) => visibleWidget.manualNavigation.drawerContextFamily),
      requiredWidgets.map(() => 'dashboard_card'),
      role,
    );
    assert.deepEqual(
      resultA.visibleWidgets[0].manualNavigation.instructionSlotRefs,
      [
        'approval_required',
        'audit_export_result',
        'common_failure_modes',
        'evidence_needed',
        'step_by_step',
        'what_this_is',
        'when_to_use_it',
        'who_owns_it',
      ],
      role,
    );
    assert.equal(
      resultA.visibleWidgets[0].documentationReadiness.controlledDocumentDistributionReceiptHash,
      DIGEST_6,
      role,
    );
    assert.equal(resultA.visibleWidgets[0].documentationReadiness.currentVersionOnly, true, role);
    assert.equal(resultA.visibleWidgets[0].documentationReadiness.effectiveUseAcknowledged, true, role);
    assert.deepEqual(resultA.visibleWidgets[0].documentationReadiness.requiredAcknowledgementRoleRefs, roleRefs, role);
    assert.deepEqual(resultA.visibleWidgets[0].documentationReadiness.acknowledgedRoleRefs, roleRefs, role);
    assert.deepEqual(resultA.visibleWidgets, resultB.visibleWidgets, role);
    assert.equal(resultA.dashboardHash, resultB.dashboardHash, role);
    assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId, role);
    assert.equal(resultA.receipt.trustState, 'inactive', role);
    assert.equal(resultA.summary.visibleWidgetCount, requiredWidgets.length, role);
    assert.equal(resultA.summary.suppressedWidgetCount, 0, role);
    assert.ok(Number.isSafeInteger(resultA.summary.averageStatusBasisPoints), role);
    assert.doesNotMatch(JSON.stringify(resultA), /AI-IRB approval|Participant Alice|MRN A-123/iu);
  }
});

test('role dashboard requires inactive trust-state activation and public-claim-review lineage', async () => {
  const { evaluateRoleDashboard, ProtectedContentError } = await loadRoleDashboards();
  const missingLineage = roleDashboardInput('quality_manager', {
    productionTrustActivation: null,
  });
  const unsafeLineage = roleDashboardInput('quality_manager', {
    productionTrustActivation: inactiveProductionTrustActivation({
      state: 'verified',
      allowed: true,
      failClosed: false,
      blockedBy: ['root_verifier_absent'],
      exochainProductionClaim: true,
      publicClaimReviewReceiptHash: 'not-a-digest',
      publicClaimReviewStatus: 'approved_for_root_backed_language',
      publicClaimReviewTrustState: 'verified',
      publicClaimReviewProductionClaimLiftReceiptHash: 'bad-lift-receipt',
      publicClaimReviewProductionClaimLiftTrustState: 'verified',
      publicClaimReviewProductionClaimLiftCanLiftProductionClaim: true,
      publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_D,
      publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_2,
      publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_2,
      publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_3,
      publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_4,
      publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_5,
      publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_6,
      publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_7,
      publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_8,
      publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_9,
      publicClaimReviewProductionClaimLiftRoleDashboardRoles: Object.keys(REQUIRED_WIDGETS)
        .filter((role) => role !== 'sponsor_viewer')
        .concat('marketing_admin')
        .sort(),
      claimLanguage: 'root-backed production authority attempted before activation gates verified',
    }),
  });
  const activeClaimAttempt = roleDashboardInput('quality_manager', {
    productionTrustActivation: inactiveProductionTrustActivation({
      state: 'verified',
      allowed: true,
      failClosed: false,
      blockedBy: [],
      exochainProductionClaim: true,
      claimLanguage: 'Exochain receipt path verified for this CyberMedica action.',
    }),
  });

  const missingResult = evaluateRoleDashboard(missingLineage);
  const unsafeResult = evaluateRoleDashboard(unsafeLineage);
  const activeResult = evaluateRoleDashboard(activeClaimAttempt);

  assert.equal(missingResult.status, 'denied');
  assert.equal(missingResult.receipt, null);
  assert.ok(missingResult.denialReasons.includes('trust_state_view_lineage_not_accepted'));
  assert.ok(missingResult.denialReasons.includes('trust_state_view_block:production_trust_activation_lineage_absent'));
  assert.ok(missingResult.denialReasons.includes('trust_state_view_block:public_claim_review_lineage_absent'));

  assert.equal(unsafeResult.status, 'denied');
  assert.equal(unsafeResult.receipt, null);
  assert.ok(unsafeResult.denialReasons.includes('trust_state_view_status_not_inactive:denied'));
  assert.ok(unsafeResult.denialReasons.includes('trust_state_view_lineage_not_accepted'));
  assert.ok(unsafeResult.denialReasons.includes('trust_state_view_block:public_claim_review_receipt_hash_invalid'));
  assert.ok(unsafeResult.denialReasons.includes('trust_state_view_block:public_claim_review_status_invalid'));
  assert.ok(unsafeResult.denialReasons.includes('trust_state_view_block:public_claim_review_trust_state_invalid'));
  assert.ok(
    unsafeResult.denialReasons.includes('trust_state_view_block:public_claim_review_production_claim_lift_receipt_hash_invalid'),
  );
  assert.ok(unsafeResult.denialReasons.includes('trust_state_view_block:public_claim_review_production_claim_lift_state_invalid'));
  assert.ok(
    unsafeResult.denialReasons.includes('trust_state_view_block:public_claim_review_production_claim_lift_public_claim_forbidden'),
  );
  assert.ok(
    unsafeResult.denialReasons.includes(
      'trust_state_view_block:public_claim_review_production_claim_lift_role_dashboard_role_missing:sponsor_viewer',
    ),
  );
  assert.ok(
    unsafeResult.denialReasons.includes(
      'trust_state_view_block:public_claim_review_production_claim_lift_role_dashboard_role_unsupported:marketing_admin',
    ),
  );
  assert.ok(
    unsafeResult.denialReasons.includes(
      'trust_state_view_block:public_claim_review_production_claim_lift_runtime_source_provider_role_dashboard_receipt_mismatch',
    ),
  );
  assert.ok(
    unsafeResult.denialReasons.includes(
      'trust_state_view_block:public_claim_review_production_claim_lift_runtime_source_provider_role_dashboard_trust_state_view_mismatch',
    ),
  );
  assert.ok(
    unsafeResult.denialReasons.includes(
      'trust_state_view_block:public_claim_review_production_claim_lift_runtime_source_readiness_role_dashboard_trust_state_view_mismatch',
    ),
  );
  assert.ok(
    unsafeResult.denialReasons.includes(
      'trust_state_view_block:public_claim_review_production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_receipt_mismatch',
    ),
  );
  assert.ok(
    unsafeResult.denialReasons.includes(
      'trust_state_view_block:public_claim_review_production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_summary_mismatch',
    ),
  );
  assert.ok(
    unsafeResult.denialReasons.includes(
      'trust_state_view_block:public_claim_review_production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_trust_state_view_mismatch',
    ),
  );
  assert.ok(
    unsafeResult.denialReasons.includes(
      'trust_state_view_block:public_claim_review_production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_receipt_mismatch',
    ),
  );
  assert.ok(
    unsafeResult.denialReasons.includes(
      'trust_state_view_block:public_claim_review_production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_summary_mismatch',
    ),
  );
  assert.ok(
    unsafeResult.denialReasons.includes(
      'trust_state_view_block:public_claim_review_production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_trust_state_view_mismatch',
    ),
  );
  assert.doesNotMatch(JSON.stringify(unsafeResult), /Participant Alice|MRN: A-123|root-backed production authority/iu);

  assert.equal(activeResult.status, 'denied');
  assert.equal(activeResult.receipt, null);
  assert.ok(activeResult.denialReasons.includes('trust_state_view_status_not_inactive:verified'));
  assert.ok(activeResult.denialReasons.includes('trust_state_view_claim_display_forbidden'));

  assert.throws(
    () =>
      evaluateRoleDashboard(
        roleDashboardInput('quality_manager', {
          productionTrustActivation: inactiveProductionTrustActivation({
            blockedBy: ['Participant Alice Example MRN: A-123'],
            claimLanguage: 'root-backed production authority for Participant Alice Example MRN: A-123',
          }),
        }),
      ),
    ProtectedContentError,
  );
});

test('role dashboard fails closed when visible widgets lack contextual manual drawer linkage', async () => {
  const { evaluateRoleDashboard } = await loadRoleDashboards();
  const missingManualNavigation = roleDashboardInput('quality_manager', {
    widgets: roleDashboardInput('quality_manager').widgets.map((dashboardWidget, index) =>
      index === 0 ? Object.fromEntries(Object.entries(dashboardWidget).filter(([key]) => key !== 'manualNavigation')) : dashboardWidget,
    ),
  });
  const wrongContext = roleDashboardInput('quality_manager', {
    widgets: roleDashboardInput('quality_manager').widgets.map((dashboardWidget, index) =>
      index === 1
        ? {
            ...dashboardWidget,
            manualNavigation: {
              ...dashboardWidget.manualNavigation,
              drawerContextFamily: 'workflow',
            },
          }
        : dashboardWidget,
    ),
  });

  const missingResult = evaluateRoleDashboard(missingManualNavigation);
  const wrongContextResult = evaluateRoleDashboard(wrongContext);

  assert.equal(missingResult.status, 'denied');
  assert.equal(missingResult.receipt, null);
  assert.ok(missingResult.denialReasons.includes('widget_manual_section_ref_absent:control_status'));
  assert.ok(missingResult.denialReasons.includes('widget_manual_section_hash_invalid:control_status'));
  assert.ok(missingResult.denialReasons.includes('widget_manual_drawer_policy_hash_invalid:control_status'));
  assert.ok(missingResult.denialReasons.includes('widget_manual_crosslink_matrix_hash_invalid:control_status'));
  assert.ok(missingResult.denialReasons.includes('widget_manual_instruction_slots_missing:control_status'));
  assert.equal(wrongContextResult.status, 'denied');
  assert.ok(wrongContextResult.denialReasons.includes('widget_manual_context_invalid:evidence_completeness'));
});

test('role dashboard requires controlled document distribution readiness signals for visible widgets', async () => {
  const { evaluateRoleDashboard } = await loadRoleDashboards();
  const missingReadiness = roleDashboardInput('quality_manager', {
    widgets: roleDashboardInput('quality_manager').widgets.map((dashboardWidget, index) =>
      index === 0
        ? Object.fromEntries(Object.entries(dashboardWidget).filter(([key]) => key !== 'documentationReadiness'))
        : dashboardWidget,
    ),
  });
  const unsafeReadiness = roleDashboardInput('quality_manager', {
    widgets: roleDashboardInput('quality_manager').widgets.map((dashboardWidget, index) =>
      index === 1
        ? {
            ...dashboardWidget,
            documentationReadiness: {
              ...dashboardWidget.documentationReadiness,
              controlledDocumentDistributionReceiptHash: 'not-a-digest',
              documentationPublicationReceiptHash: '',
              manualExportReceiptHash: null,
              orientationAssistantReceiptHash: 'bad',
              effectiveUseAcknowledged: false,
              currentVersionOnly: false,
              obsoleteVersionUseBlocked: false,
              metadataOnly: false,
              protectedContentExcluded: false,
              productionTrustClaim: true,
              distributionPublishedAtHlc: { physicalMs: 1795000000000, logical: 31 },
            },
          }
        : dashboardWidget,
    ),
  });

  const missingResult = evaluateRoleDashboard(missingReadiness);
  const unsafeResult = evaluateRoleDashboard(unsafeReadiness);

  assert.equal(missingResult.status, 'denied');
  assert.equal(missingResult.receipt, null);
  assert.ok(
    missingResult.denialReasons.includes('widget_document_distribution_receipt_hash_invalid:control_status'),
  );
  assert.ok(missingResult.denialReasons.includes('widget_document_publication_receipt_hash_invalid:control_status'));
  assert.ok(missingResult.denialReasons.includes('widget_manual_export_receipt_hash_invalid:control_status'));
  assert.ok(missingResult.denialReasons.includes('widget_orientation_assistant_receipt_hash_invalid:control_status'));
  assert.ok(missingResult.denialReasons.includes('widget_document_acknowledgement_roles_missing:control_status'));

  assert.equal(unsafeResult.status, 'denied');
  assert.equal(unsafeResult.receipt, null);
  assert.ok(
    unsafeResult.denialReasons.includes('widget_document_distribution_receipt_hash_invalid:evidence_completeness'),
  );
  assert.ok(unsafeResult.denialReasons.includes('widget_document_publication_receipt_hash_invalid:evidence_completeness'));
  assert.ok(unsafeResult.denialReasons.includes('widget_manual_export_receipt_hash_invalid:evidence_completeness'));
  assert.ok(unsafeResult.denialReasons.includes('widget_orientation_assistant_receipt_hash_invalid:evidence_completeness'));
  assert.ok(unsafeResult.denialReasons.includes('widget_effective_use_acknowledgement_absent:evidence_completeness'));
  assert.ok(unsafeResult.denialReasons.includes('widget_current_document_version_boundary_invalid:evidence_completeness'));
  assert.ok(unsafeResult.denialReasons.includes('widget_obsolete_document_boundary_invalid:evidence_completeness'));
  assert.ok(unsafeResult.denialReasons.includes('widget_document_readiness_metadata_boundary_invalid:evidence_completeness'));
  assert.ok(
    unsafeResult.denialReasons.includes('widget_document_readiness_protected_content_boundary_invalid:evidence_completeness'),
  );
  assert.ok(unsafeResult.denialReasons.includes('widget_document_readiness_production_claim_forbidden:evidence_completeness'));
  assert.ok(unsafeResult.denialReasons.includes('widget_document_distribution_after_dashboard:evidence_completeness'));
});

test('role dashboard fails closed for unsafe authority role widget and production trust defects', async () => {
  const { evaluateRoleDashboard } = await loadRoleDashboards();
  const input = roleDashboardInput('quality_manager', {
    actor: { did: 'did:exo:ai-quality-agent', kind: 'ai_agent', roleRefs: ['quality_manager'] },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['read'],
      authorityChainHash: DIGEST_A,
    },
    dashboard: {
      ...roleDashboardInput('quality_manager').dashboard,
      productionTrustClaim: true,
    },
    accessPolicy: {
      ...roleDashboardInput('quality_manager').accessPolicy,
      allowedDashboardRoles: ['site_leader'],
    },
    widgets: roleDashboardInput('quality_manager').widgets.slice(1).map((dashboardWidget, index) =>
      index === 0
        ? {
            ...dashboardWidget,
            boundary: {
              metadataOnly: false,
              rawContentExcluded: false,
              sourcePayloadAnchored: true,
            },
          }
        : dashboardWidget,
    ),
  });

  const result = evaluateRoleDashboard(input);

  assert.equal(result.status, 'denied');
  assert.equal(result.receipt, null);
  assert.equal(result.summary.visibleWidgetCount, 0);
  assert.ok(result.denialReasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.denialReasons.includes('human_actor_required'));
  assert.ok(result.denialReasons.includes('dashboard_authority_missing'));
  assert.ok(result.denialReasons.includes('dashboard_role_not_allowed:quality_manager'));
  assert.ok(result.denialReasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.denialReasons.includes('required_widget_missing:control_status'));
  assert.ok(result.denialReasons.includes('widget_metadata_boundary_invalid:evidence_completeness'));
  assert.ok(result.denialReasons.includes('widget_raw_content_boundary_invalid:evidence_completeness'));
  assert.ok(result.denialReasons.includes('widget_source_payload_anchor_forbidden:evidence_completeness'));
});

test('role dashboard suppresses inaccessible extra widgets without leaking suppressed widget refs', async () => {
  const { evaluateRoleDashboard } = await loadRoleDashboards();
  const input = roleDashboardInput('sponsor_viewer', {
    widgets: [
      ...roleDashboardInput('sponsor_viewer').widgets,
      widget('internal_quality_only_signal', 12, 'quality_manager', {
        widgetRef: 'restricted-quality-widget-ref',
        roleVisibility: ['quality_manager'],
      }),
      widget('other_site_equipment_gap', 13, 'sponsor_viewer', {
        widgetRef: 'restricted-site-widget-ref',
        siteRefs: ['site-beta'],
      }),
      widget('source_payload_signal', 14, 'sponsor_viewer', {
        widgetRef: 'restricted-sensitivity-widget-ref',
        sensitivityTags: ['metadata_only', 'raw_source_payload'],
      }),
    ],
  });

  const result = evaluateRoleDashboard(input);
  const serialized = JSON.stringify(result);

  assert.equal(result.status, 'ready');
  assert.equal(result.summary.visibleWidgetCount, REQUIRED_WIDGETS.sponsor_viewer.length);
  assert.equal(result.summary.suppressedWidgetCount, 3);
  assert.equal(result.suppressedWidgetRefs, undefined);
  assert.doesNotMatch(serialized, /restricted-quality-widget-ref|restricted-site-widget-ref|restricted-sensitivity-widget-ref/u);
  assert.deepEqual(
    result.visibleWidgets.map((visibleWidget) => visibleWidget.metricKey),
    REQUIRED_WIDGETS.sponsor_viewer,
  );
});

test('role dashboard requires controlled Sponsor/CRO request evidence before showing request widgets', async () => {
  const { evaluateRoleDashboard, ProtectedContentError } = await loadRoleDashboards();
  const withEvidence = roleDashboardInput('site_leader', {
    widgets: roleDashboardInput('site_leader').widgets.map((dashboardWidget) =>
      dashboardWidget.metricKey === 'sponsor_cro_requests'
        ? { ...dashboardWidget, sponsorCroRequestEvidence: sponsorCroRequestEvidence() }
        : dashboardWidget,
    ),
  });
  const missingEvidence = roleDashboardInput('site_leader', {
    widgets: roleDashboardInput('site_leader').widgets.map((dashboardWidget) =>
      dashboardWidget.metricKey === 'sponsor_cro_requests'
        ? Object.fromEntries(Object.entries(dashboardWidget).filter(([key]) => key !== 'sponsorCroRequestEvidence'))
        : dashboardWidget,
    ),
  });
  const unsafeEvidence = roleDashboardInput('site_leader', {
    widgets: roleDashboardInput('site_leader').widgets.map((dashboardWidget) =>
      dashboardWidget.metricKey === 'sponsor_cro_requests'
        ? {
            ...dashboardWidget,
            sponsorCroRequestEvidence: sponsorCroRequestEvidence({
              requestHash: '',
              requesterClass: 'public_observer',
              workItemStatus: 'draft',
              disclosureLogHash: 'not-a-digest',
              linkedAtHlc: { physicalMs: 1795000000000, logical: 31 },
              metadataOnly: false,
              sourcePayloadExcluded: false,
              protectedContentExcluded: false,
            }),
          }
        : dashboardWidget,
    ),
  });

  const readyResult = evaluateRoleDashboard(withEvidence);
  const missingResult = evaluateRoleDashboard(missingEvidence);
  const unsafeResult = evaluateRoleDashboard(unsafeEvidence);

  assert.equal(readyResult.status, 'ready');
  assert.deepEqual(readyResult.denialReasons, []);
  const requestWidget = readyResult.visibleWidgets.find((visibleWidget) => visibleWidget.metricKey === 'sponsor_cro_requests');
  assert.deepEqual(requestWidget.sponsorCroRequestEvidence, {
    decisionForumMatterRef: 'df-sponsor-cro-request-alpha',
    disclosureEventRef: 'disclosure-event-sponsor-cro-alpha',
    disclosureLogHash: DIGEST_B,
    humanReviewHash: DIGEST_C,
    linkedAtHlc: { physicalMs: 1795000000000, logical: 10 },
    metadataOnly: true,
    protectedContentExcluded: true,
    requestHash: DIGEST_A,
    requesterClass: 'sponsor',
    requestRef: 'sponsor-cro-request-alpha',
    responseWorkflowRef: 'workflow-sponsor-cro-request-response',
    sourcePayloadExcluded: true,
    workItemRef: 'sponsor-cro-work-item-alpha',
    workItemStatus: 'queued_for_site_review',
  });
  assert.doesNotMatch(JSON.stringify(readyResult), /raw sponsor request|Participant Alice/iu);

  assert.equal(missingResult.status, 'denied');
  assert.equal(missingResult.receipt, null);
  assert.ok(missingResult.denialReasons.includes('sponsor_cro_request_evidence_absent:sponsor_cro_requests'));

  assert.equal(unsafeResult.status, 'denied');
  assert.equal(unsafeResult.receipt, null);
  assert.ok(unsafeResult.denialReasons.includes('sponsor_cro_request_hash_invalid:sponsor_cro_requests'));
  assert.ok(unsafeResult.denialReasons.includes('sponsor_cro_requester_class_invalid:sponsor_cro_requests'));
  assert.ok(unsafeResult.denialReasons.includes('sponsor_cro_work_item_status_invalid:sponsor_cro_requests'));
  assert.ok(unsafeResult.denialReasons.includes('sponsor_cro_disclosure_log_hash_invalid:sponsor_cro_requests'));
  assert.ok(unsafeResult.denialReasons.includes('sponsor_cro_request_link_after_dashboard:sponsor_cro_requests'));
  assert.ok(unsafeResult.denialReasons.includes('sponsor_cro_request_metadata_boundary_invalid:sponsor_cro_requests'));
  assert.ok(unsafeResult.denialReasons.includes('sponsor_cro_request_source_payload_boundary_invalid:sponsor_cro_requests'));
  assert.ok(unsafeResult.denialReasons.includes('sponsor_cro_request_protected_boundary_invalid:sponsor_cro_requests'));

  assert.throws(
    () =>
      evaluateRoleDashboard(
        roleDashboardInput('site_leader', {
          widgets: roleDashboardInput('site_leader').widgets.map((dashboardWidget) =>
            dashboardWidget.metricKey === 'sponsor_cro_requests'
              ? {
                  ...dashboardWidget,
                  sponsorCroRequestEvidence: sponsorCroRequestEvidence(),
                  rawSponsorRequestBody: 'Participant Alice raw sponsor request text',
                }
              : dashboardWidget,
          ),
        }),
      ),
    ProtectedContentError,
  );
});

test('role dashboard validates HLC ordering and same-tick dashboard clocks', async () => {
  const { evaluateRoleDashboard } = await loadRoleDashboards();
  const valid = roleDashboardInput('site_leader', {
    dashboard: {
      ...roleDashboardInput('site_leader').dashboard,
      generatedAtHlc: { physicalMs: 1795000000000, logical: 20 },
    },
    disclosureLog: {
      ...roleDashboardInput('site_leader').disclosureLog,
      loggedAtHlc: { physicalMs: 1795000000000, logical: 3 },
    },
  });
  const invalid = roleDashboardInput('site_leader', {
    dashboard: {
      ...roleDashboardInput('site_leader').dashboard,
      generatedAtHlc: { physicalMs: 1795000000000, logical: 10 },
    },
    accessPolicy: {
      ...roleDashboardInput('site_leader').accessPolicy,
      evaluatedAtHlc: { physicalMs: 1795000000000, logical: 5 },
    },
    disclosureLog: {
      ...roleDashboardInput('site_leader').disclosureLog,
      loggedAtHlc: { physicalMs: 1795000000000, logical: 4 },
    },
    widgets: roleDashboardInput('site_leader').widgets.map((dashboardWidget, index) =>
      index === 0
        ? {
            ...dashboardWidget,
            updatedAtHlc: { physicalMs: 1795000000000, logical: 11 },
          }
        : dashboardWidget,
    ),
  });

  assert.equal(evaluateRoleDashboard(valid).status, 'ready');

  const invalidResult = evaluateRoleDashboard(invalid);
  assert.equal(invalidResult.status, 'denied');
  assert.ok(invalidResult.denialReasons.includes('disclosure_log_before_policy'));
  assert.ok(invalidResult.denialReasons.includes('widget_updated_after_dashboard:site_qms_passport_status'));

  const physicalOrdering = roleDashboardInput('site_leader', {
    dashboard: {
      ...roleDashboardInput('site_leader').dashboard,
      generatedAtHlc: { physicalMs: 1795000000000, logical: 0 },
    },
    accessPolicy: {
      ...roleDashboardInput('site_leader').accessPolicy,
      evaluatedAtHlc: { physicalMs: 1795000000001, logical: 0 },
    },
    disclosureLog: {
      ...roleDashboardInput('site_leader').disclosureLog,
      loggedAtHlc: { physicalMs: 1795000000000, logical: 0 },
    },
    widgets: roleDashboardInput('site_leader').widgets.map((dashboardWidget, index) =>
      index === 0
        ? {
            ...dashboardWidget,
            updatedAtHlc: { physicalMs: 1795000000002, logical: 0 },
          }
        : dashboardWidget,
    ),
  });

  const physicalOrderingResult = evaluateRoleDashboard(physicalOrdering);
  assert.equal(physicalOrderingResult.status, 'denied');
  assert.ok(physicalOrderingResult.denialReasons.includes('disclosure_log_before_policy'));
  assert.ok(physicalOrderingResult.denialReasons.includes('widget_updated_after_dashboard:site_qms_passport_status'));

  const malformedClock = roleDashboardInput('site_leader', {
    dashboard: {
      ...roleDashboardInput('site_leader').dashboard,
      generatedAtHlc: { physicalMs: 1795000000000, logical: -1 },
    },
  });
  const malformedClockResult = evaluateRoleDashboard(malformedClock);
  assert.equal(malformedClockResult.status, 'denied');
  assert.ok(malformedClockResult.denialReasons.includes('dashboard_generated_time_invalid'));
});

test('role dashboard rejects raw dashboard widget and protected content before receipts', async () => {
  const { evaluateRoleDashboard, ProtectedContentError } = await loadRoleDashboards();

  assert.throws(
    () =>
      evaluateRoleDashboard({
        ...roleDashboardInput('auditor'),
        rawDashboardText: 'source document body must not be anchored in a dashboard',
      }),
    ProtectedContentError,
  );
  assert.throws(
    () =>
      evaluateRoleDashboard({
        ...roleDashboardInput('coordinator'),
        widgets: [
          ...roleDashboardInput('coordinator').widgets,
          widget('coordinator_raw_note', 1, 'coordinator', {
            rawWidgetText: 'participant Jane Example visit details',
          }),
        ],
      }),
    ProtectedContentError,
  );
});
