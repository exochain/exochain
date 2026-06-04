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

async function loadRoleResponsibilityMatrix() {
  try {
    return await import('../src/role-responsibility-matrix.mjs');
  } catch (error) {
    assert.fail(`CyberMedica role-responsibility-matrix module must exist and load: ${error.message}`);
  }
}

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
const CUSTODY_DIGEST = 'abababababababababababababababababababababababababababababababab';
const AUTHORITY_HASH = 'f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0';

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

const REQUIRED_ROLE_RESPONSIBILITIES = Object.freeze({
  ai_quality_reviewer: [
    'map_evidence_to_controls',
    'identify_missing_evidence',
    'identify_contradictions',
    'identify_risk_signals',
    'draft_review_summaries',
    'recommend_escalation',
    'provide_confidence_and_limitations',
    'preserve_evidence_references',
    'never_final_authority',
  ],
  auditor: [
    'define_audit_scope',
    'review_evidence',
    'conduct_interviews',
    'identify_findings',
    'classify_severity',
    'recommend_capa',
    'produce_audit_report',
    'verify_closure',
  ],
  clinical_lead_study_manager: [
    'manage_study_startup_checklist',
    'coordinate_staff_assignments',
    'coordinate_training_completion',
    'coordinate_sponsor_cro_communication',
    'track_protocol_milestones',
    'track_monitoring_actions',
    'track_deviations',
    'ensure_staff_communication',
    'support_participant_visit_readiness',
    'maintain_study_information_management_plan',
  ],
  clinical_research_coordinator: [
    'complete_required_training',
    'execute_delegated_tasks',
    'document_source_data_and_study_records',
    'support_consent_process_if_delegated',
    'report_deviations_and_concerns',
    'support_participant_communications',
    'maintain_required_logs',
    'support_monitoring_visits',
    'follow_protocol_specific_procedures',
  ],
  clinical_research_site_leader: [
    'maintain_site_qms_passport',
    'ensure_role_assignments',
    'ensure_communication_plan',
    'ensure_ethical_framework_implementation',
    'ensure_staff_training_and_competency',
    'ensure_risk_management',
    'ensure_quality_planning',
    'ensure_stakeholder_communication',
    'review_open_findings',
    'support_audits_and_assessments',
  ],
  cro_portfolio_manager: [
    'monitor_site_readiness_across_portfolio',
    'compare_sites',
    'track_startup_status',
    'track_findings_and_capas',
    'manage_sponsor_reports',
    'escalate_systemic_risk',
    'identify_training_and_quality_trends',
  ],
  data_manager: [
    'maintain_source_data_traceability',
    'track_crf_requirements',
    'manage_data_discrepancy_workflows',
    'support_alcoac_expectations',
    'maintain_data_access_controls',
    'support_final_report_data_requirements',
  ],
  decision_forum_chair: [
    'confirm_matter_scope',
    'confirm_required_quorum',
    'confirm_required_roles',
    'confirm_conflict_disclosure',
    'manage_deliberation',
    'ensure_rationale_capture',
    'close_decision',
    'ensure_follow_up_actions',
    'ensure_receipt_generation',
  ],
  facility_manager: [
    'maintain_facility_inventory',
    'maintain_infrastructure_evidence',
    'maintain_equipment_lists',
    'track_calibration',
    'quarantine_defective_equipment',
    'provide_readiness_evidence',
    'support_audits_and_inspections',
  ],
  monitor_cra: [
    'review_site_records',
    'review_source_crf_consistency',
    'review_protocol_adherence',
    'review_consent_records',
    'review_safety_reporting',
    'issue_findings',
    'track_action_items',
    'support_sponsor_cro_oversight',
  ],
  pharmacy_investigational_product_manager: [
    'record_product_receipt',
    'maintain_storage_controls',
    'maintain_access_controls',
    'track_batch_serial_expiration',
    'manage_stock_reconciliation',
    'manage_dispensing_records',
    'manage_return_disposal',
    'report_nonconformities',
  ],
  principal_investigator: [
    'confirm_protocol_understanding',
    'confirm_delegation_log',
    'confirm_staff_qualifications',
    'confirm_participant_protection_procedures',
    'confirm_consent_process',
    'manage_participant_safety_obligations',
    'review_safety_events',
    'manage_protocol_deviations',
    'ensure_data_integrity',
    'sign_investigator_readiness',
    'participate_launch_authorization',
  ],
  quality_manager: [
    'maintain_control_library_applicability',
    'maintain_document_control_process',
    'manage_self_assessment',
    'manage_internal_audit',
    'manage_nonconformance_process',
    'manage_capa_process',
    'maintain_risk_register',
    'review_quality_metrics',
    'approve_quality_evidence',
    'recommend_readiness_decisions',
    'escalate_critical_gaps',
  ],
  regulatory_coordinator: [
    'maintain_regulatory_document_inventory',
    'track_iec_irb_approvals',
    'track_protocol_amendments',
    'track_consent_form_approvals',
    'track_continuing_reviews',
    'maintain_investigator_documents',
    'support_sponsor_regulatory_exports',
    'manage_document_versioning',
  ],
  site_executive_sponsor: [
    'approve_mission_vision_values',
    'approve_site_strategy',
    'ensure_qms_resources',
    'appoint_quality_leadership',
    'review_major_quality_risks',
    'support_open_inclusive_leadership',
    'review_major_sponsor_cro_diligence_outputs',
    'approve_major_policy_changes',
    'participate_decision_forum_when_required',
  ],
  sponsor_viewer: [
    'review_readiness_packets',
    'review_open_findings',
    'review_capa_status',
    'review_risk_summaries',
    'request_clarification',
    'receive_authorized_exports',
    'respect_access_limitations',
  ],
  system_administrator: [
    'configure_tenant',
    'configure_roles',
    'configure_access_policies',
    'configure_integrations',
    'manage_identity_provider_settings',
    'monitor_security_logs',
    'support_backup_recovery',
    'enforce_access_revocation',
  ],
  training_manager: [
    'maintain_role_based_training_requirements',
    'assign_required_training',
    'track_completion',
    'track_expiration',
    'verify_competency_evidence',
    'report_training_gaps',
    'block_delegation_when_training_missing',
  ],
});

const REQUIRED_ROLE_REFS = Object.freeze(Object.keys(REQUIRED_ROLE_RESPONSIBILITIES).sort());
const GOVERNANCE_ROLE_REFS = new Set([
  'decision_forum_chair',
  'principal_investigator',
  'quality_manager',
  'site_executive_sponsor',
]);

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function roleProfile(roleRef, index, overrides = {}) {
  const mode = roleRef === 'ai_quality_reviewer'
    ? 'ai_assistant'
    : GOVERNANCE_ROLE_REFS.has(roleRef)
      ? 'governance_role'
      : 'operational_permission';
  return {
    roleRef,
    authorityMode: mode,
    responsibilityRefs: REQUIRED_ROLE_RESPONSIBILITIES[roleRef],
    ownerDomainRefs: [`owner_domain_${roleRef}`, 'qms_governance'],
    dashboardRefs: [`dashboard_${roleRef}`],
    manualSectionRefs: [`manual_role_${roleRef}`],
    supportPathRefs: [`support_path_${roleRef}`],
    evidenceHash: DIGESTS[index % DIGESTS.length],
    sourceSectionRef: `cybermedica_2_0_sandy_seven_layer_master_prd.md:Roles and responsibilities:${roleRef}`,
    updatedAtHlc: { physicalMs: 1805000000000 + index, logical: index % 4 },
    humanOwnerDid: roleRef === 'ai_quality_reviewer' ? 'did:exo:quality-manager-alpha' : `did:exo:${roleRef.replaceAll('_', '-')}-owner`,
    aiFinalAuthority: false,
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function matrixInput(overrides = {}) {
  const base = {
    requestId: 'role-responsibility-matrix-alpha',
    tenantId: 'tenant-site-alpha',
    siteId: 'site-alpha',
    checkedAtHlc: { physicalMs: 1805000100000, logical: 10 },
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['role_responsibility_review', 'govern'],
      authorityChainHash: AUTHORITY_HASH,
    },
    roleResponsibilityPolicy: {
      policyRef: 'role-responsibility-policy-alpha',
      version: 'v1',
      status: 'active',
      policyHash: DIGEST_A,
      sourceRefs: [
        'cybermedica_2_0_sandy_seven_layer_master_prd.md:1392-1671',
        'cyber_medica_qms_prd_master.md:Target users and stakeholders',
      ],
      requiredRoleRefs: REQUIRED_ROLE_REFS,
      requiredGovernanceRoleRefs: [...GOVERNANCE_ROLE_REFS].sort(),
      activationGateIds: ['PTAG-010'],
      allowedBobEscalationIds: ['ESC-ROLE-MATRIX'],
      metadataOnly: true,
      productionTrustClaim: false,
      evaluatedAtHlc: { physicalMs: 1804990000000, logical: 0 },
    },
    roleProfiles: REQUIRED_ROLE_REFS.map(roleProfile),
    humanGovernance: {
      verified: true,
      approvedByDid: 'did:exo:site-executive-sponsor-alpha',
      decisionForumReceiptId: 'df-role-responsibility-alpha',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
    },
    aiAssistance: { used: true, finalAuthority: false, recommendationHash: DIGEST_B },
    custodyDigest: CUSTODY_DIGEST,
  };
  return { ...base, ...overrides };
}

test('role responsibility matrix creates deterministic inactive PRD role coverage receipts', async () => {
  const { evaluateRoleResponsibilityMatrix } = await loadRoleResponsibilityMatrix();
  const input = matrixInput();

  const readyA = evaluateRoleResponsibilityMatrix(input);
  const readyB = evaluateRoleResponsibilityMatrix({
    ...input,
    roleResponsibilityPolicy: {
      ...input.roleResponsibilityPolicy,
      sourceRefs: [...input.roleResponsibilityPolicy.sourceRefs].reverse(),
      requiredRoleRefs: [...input.roleResponsibilityPolicy.requiredRoleRefs].reverse(),
      requiredGovernanceRoleRefs: [...input.roleResponsibilityPolicy.requiredGovernanceRoleRefs].reverse(),
    },
    roleProfiles: input.roleProfiles.map((profile) => ({
      ...profile,
      responsibilityRefs: [...profile.responsibilityRefs].reverse(),
      dashboardRefs: [...profile.dashboardRefs].reverse(),
      manualSectionRefs: [...profile.manualSectionRefs].reverse(),
      supportPathRefs: [...profile.supportPathRefs].reverse(),
      ownerDomainRefs: [...profile.ownerDomainRefs].reverse(),
    })).reverse(),
  });

  assert.equal(readyA.decision, 'permitted');
  assert.equal(readyA.failClosed, false);
  assert.deepEqual(readyA.reasons, []);
  assert.equal(readyA.trustState, 'inactive');
  assert.equal(readyA.exochainProductionClaim, false);
  assert.equal(readyA.roleResponsibilityMatrix.matrixHash, readyB.roleResponsibilityMatrix.matrixHash);
  assert.equal(readyA.receipt.receiptId, readyB.receipt.receiptId);
  assert.equal(readyA.receipt.anchorPayload.artifactType, 'role_responsibility_matrix');
  assert.equal(readyA.receipt.trustState, 'inactive');
  assert.deepEqual(readyA.roleResponsibilityMatrix.roleRefs, REQUIRED_ROLE_REFS);
  assert.equal(readyA.roleResponsibilityMatrix.roleCount, 18);
  assert.deepEqual(readyA.roleResponsibilityMatrix.authorityModeCounts, {
    aiAssistant: 1,
    governanceRole: 4,
    operationalPermission: 13,
  });
  assert.deepEqual(readyA.roleResponsibilityMatrix.sourceRefs, [
    'cyber_medica_qms_prd_master.md:Target users and stakeholders',
    'cybermedica_2_0_sandy_seven_layer_master_prd.md:1392-1671',
  ]);

  const systemAdministrator = readyA.roleResponsibilityMatrix.roleProfiles.find(
    (profile) => profile.roleRef === 'system_administrator',
  );
  assert.deepEqual(systemAdministrator.responsibilityRefs, [
    'configure_access_policies',
    'configure_integrations',
    'configure_roles',
    'configure_tenant',
    'enforce_access_revocation',
    'manage_identity_provider_settings',
    'monitor_security_logs',
    'support_backup_recovery',
  ]);
  assert.equal(systemAdministrator.finalAuthorityProhibited, false);

  const aiReviewer = readyA.roleResponsibilityMatrix.roleProfiles.find(
    (profile) => profile.roleRef === 'ai_quality_reviewer',
  );
  assert.equal(aiReviewer.authorityMode, 'ai_assistant');
  assert.equal(aiReviewer.finalAuthorityProhibited, true);
  assert.ok(aiReviewer.responsibilityRefs.includes('never_final_authority'));
  assert.doesNotMatch(JSON.stringify(readyA), /root-backed production authority/i);
});

test('role responsibility matrix fails closed for missing role and responsibility coverage', async () => {
  const { evaluateRoleResponsibilityMatrix } = await loadRoleResponsibilityMatrix();
  const input = matrixInput();
  const principalInvestigator = input.roleProfiles.find((profile) => profile.roleRef === 'principal_investigator');

  const denied = evaluateRoleResponsibilityMatrix({
    ...input,
    actor: { did: 'did:exo:role-matrix-ai-alpha', kind: 'ai_agent' },
    authority: {
      ...input.authority,
      permissions: ['read'],
    },
    roleResponsibilityPolicy: {
      ...input.roleResponsibilityPolicy,
      sourceRefs: ['cybermedica_2_0_sandy_seven_layer_master_prd.md:1392-1671'],
      requiredRoleRefs: input.roleResponsibilityPolicy.requiredRoleRefs.filter(
        (roleRef) => roleRef !== 'training_manager',
      ),
    },
    roleProfiles: input.roleProfiles
      .filter((profile) => profile.roleRef !== 'system_administrator')
      .map((profile) => profile.roleRef === 'principal_investigator'
        ? {
            ...principalInvestigator,
            responsibilityRefs: principalInvestigator.responsibilityRefs.filter(
              (ref) => ref !== 'participate_launch_authorization',
            ),
            dashboardRefs: [],
            manualSectionRefs: [],
            aiFinalAuthority: true,
          }
        : profile),
    humanGovernance: {
      ...input.humanGovernance,
      verified: false,
      humanGate: { verified: false },
      quorum: { status: 'not_met' },
      openChallenge: true,
    },
    aiAssistance: { used: true, finalAuthority: true, recommendationHash: DIGEST_C },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.roleResponsibilityMatrix, null);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('policy_required_role_missing:training_manager'));
  assert.ok(denied.reasons.includes('role_profile_missing:system_administrator'));
  assert.ok(denied.reasons.includes('role_responsibility_missing:principal_investigator:participate_launch_authorization'));
  assert.ok(denied.reasons.includes('role_dashboard_link_absent:principal_investigator'));
  assert.ok(denied.reasons.includes('role_manual_link_absent:principal_investigator'));
  assert.ok(denied.reasons.includes('role_final_authority_forbidden:principal_investigator'));
  assert.ok(denied.reasons.includes('human_governance_unverified'));
  assert.ok(denied.reasons.includes('human_gate_unverified'));
  assert.ok(denied.reasons.includes('quorum_not_met'));
  assert.ok(denied.reasons.includes('challenge_open'));
});

test('role responsibility matrix rejects raw protected role content and secret material before receipts', async () => {
  const { ProtectedContentError, evaluateRoleResponsibilityMatrix } = await loadRoleResponsibilityMatrix();

  assert.throws(
    () => evaluateRoleResponsibilityMatrix({
      ...matrixInput(),
      rawRoleNarrative: 'Narrative role notes belong outside immutable receipt anchors.',
    }),
    ProtectedContentError,
  );

  assert.throws(
    () => evaluateRoleResponsibilityMatrix({
      ...matrixInput(),
      roleProfiles: [
        ...matrixInput().roleProfiles,
        roleProfile('quality_manager', 0, {
          roleRef: 'quality_manager_duplicate',
          privateKey: 'root signing material',
        }),
      ],
    }),
    ProtectedContentError,
  );
});
