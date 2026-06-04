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

import { ProtectedContentError, canonicalize, createEvidenceReceipt, sha256Hex } from './qms-contracts.mjs';

export { ProtectedContentError };

const HEX_64 = /^[0-9a-f]{64}$/u;
const REQUIRED_PERMISSION = 'role_responsibility_review';
const MATRIX_SCHEMA = 'cybermedica.role_responsibility_matrix.v1';
const DECISION_SCHEMA = 'cybermedica.role_responsibility_matrix_decision.v1';
const REQUIRED_ACTIVATION_GATE = 'PTAG-010';
const REQUIRED_BOB_ESCALATION = 'ESC-ROLE-MATRIX';

const REQUIRED_POLICY_SOURCE_REFS = Object.freeze([
  'cyber_medica_qms_prd_master.md:Target users and stakeholders',
  'cybermedica_2_0_sandy_seven_layer_master_prd.md:1392-1671',
]);

const REQUIRED_ROLE_RESPONSIBILITIES = Object.freeze({
  ai_quality_reviewer: Object.freeze([
    'map_evidence_to_controls',
    'identify_missing_evidence',
    'identify_contradictions',
    'identify_risk_signals',
    'draft_review_summaries',
    'recommend_escalation',
    'provide_confidence_and_limitations',
    'preserve_evidence_references',
    'never_final_authority',
  ]),
  auditor: Object.freeze([
    'define_audit_scope',
    'review_evidence',
    'conduct_interviews',
    'identify_findings',
    'classify_severity',
    'recommend_capa',
    'produce_audit_report',
    'verify_closure',
  ]),
  clinical_lead_study_manager: Object.freeze([
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
  ]),
  clinical_research_coordinator: Object.freeze([
    'complete_required_training',
    'execute_delegated_tasks',
    'document_source_data_and_study_records',
    'support_consent_process_if_delegated',
    'report_deviations_and_concerns',
    'support_participant_communications',
    'maintain_required_logs',
    'support_monitoring_visits',
    'follow_protocol_specific_procedures',
  ]),
  clinical_research_site_leader: Object.freeze([
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
  ]),
  cro_portfolio_manager: Object.freeze([
    'monitor_site_readiness_across_portfolio',
    'compare_sites',
    'track_startup_status',
    'track_findings_and_capas',
    'manage_sponsor_reports',
    'escalate_systemic_risk',
    'identify_training_and_quality_trends',
  ]),
  data_manager: Object.freeze([
    'maintain_source_data_traceability',
    'track_crf_requirements',
    'manage_data_discrepancy_workflows',
    'support_alcoac_expectations',
    'maintain_data_access_controls',
    'support_final_report_data_requirements',
  ]),
  decision_forum_chair: Object.freeze([
    'confirm_matter_scope',
    'confirm_required_quorum',
    'confirm_required_roles',
    'confirm_conflict_disclosure',
    'manage_deliberation',
    'ensure_rationale_capture',
    'close_decision',
    'ensure_follow_up_actions',
    'ensure_receipt_generation',
  ]),
  facility_manager: Object.freeze([
    'maintain_facility_inventory',
    'maintain_infrastructure_evidence',
    'maintain_equipment_lists',
    'track_calibration',
    'quarantine_defective_equipment',
    'provide_readiness_evidence',
    'support_audits_and_inspections',
  ]),
  monitor_cra: Object.freeze([
    'review_site_records',
    'review_source_crf_consistency',
    'review_protocol_adherence',
    'review_consent_records',
    'review_safety_reporting',
    'issue_findings',
    'track_action_items',
    'support_sponsor_cro_oversight',
  ]),
  pharmacy_investigational_product_manager: Object.freeze([
    'record_product_receipt',
    'maintain_storage_controls',
    'maintain_access_controls',
    'track_batch_serial_expiration',
    'manage_stock_reconciliation',
    'manage_dispensing_records',
    'manage_return_disposal',
    'report_nonconformities',
  ]),
  principal_investigator: Object.freeze([
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
  ]),
  quality_manager: Object.freeze([
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
  ]),
  regulatory_coordinator: Object.freeze([
    'maintain_regulatory_document_inventory',
    'track_iec_irb_approvals',
    'track_protocol_amendments',
    'track_consent_form_approvals',
    'track_continuing_reviews',
    'maintain_investigator_documents',
    'support_sponsor_regulatory_exports',
    'manage_document_versioning',
  ]),
  site_executive_sponsor: Object.freeze([
    'approve_mission_vision_values',
    'approve_site_strategy',
    'ensure_qms_resources',
    'appoint_quality_leadership',
    'review_major_quality_risks',
    'support_open_inclusive_leadership',
    'review_major_sponsor_cro_diligence_outputs',
    'approve_major_policy_changes',
    'participate_decision_forum_when_required',
  ]),
  sponsor_viewer: Object.freeze([
    'review_readiness_packets',
    'review_open_findings',
    'review_capa_status',
    'review_risk_summaries',
    'request_clarification',
    'receive_authorized_exports',
    'respect_access_limitations',
  ]),
  system_administrator: Object.freeze([
    'configure_tenant',
    'configure_roles',
    'configure_access_policies',
    'configure_integrations',
    'manage_identity_provider_settings',
    'monitor_security_logs',
    'support_backup_recovery',
    'enforce_access_revocation',
  ]),
  training_manager: Object.freeze([
    'maintain_role_based_training_requirements',
    'assign_required_training',
    'track_completion',
    'track_expiration',
    'verify_competency_evidence',
    'report_training_gaps',
    'block_delegation_when_training_missing',
  ]),
});

const REQUIRED_ROLE_REFS = Object.freeze(Object.keys(REQUIRED_ROLE_RESPONSIBILITIES).sort());
const GOVERNANCE_ROLE_REFS = Object.freeze([
  'decision_forum_chair',
  'principal_investigator',
  'quality_manager',
  'site_executive_sponsor',
]);
const AUTHORITY_MODES = new Set(['ai_assistant', 'governance_role', 'operational_permission']);

const RAW_ROLE_FIELDS = new Set([
  'directrolenotes',
  'freetextresponsibility',
  'rawresponsibility',
  'rawresponsibilitybody',
  'rawrolenarrative',
  'rawrolenotes',
  'rawroster',
  'responsibilitynarrative',
  'rolebody',
  'rolenarrative',
  'sourcedocumentbody',
]);

const SECRET_ROLE_FIELDS = new Set([
  'accesstoken',
  'adaptersecret',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'bootstrapsecret',
  'clientsecret',
  'credentialsecret',
  'password',
  'privatekey',
  'refreshtoken',
  'rootkey',
  'rootsigningkey',
  'secret',
  'sessionsecret',
  'signaturesecret',
  'signingkey',
  'token',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function sensitiveValuePresent(value) {
  if (value === null || value === undefined || value === false) {
    return false;
  }
  if (typeof value === 'string') {
    return value.trim().length > 0;
  }
  if (Array.isArray(value)) {
    return value.some((item) => sensitiveValuePresent(item));
  }
  if (typeof value === 'object') {
    return Object.keys(value).length > 0;
  }
  return true;
}

function assertNoRoleProtectedContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRoleProtectedContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_ROLE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`role responsibility raw content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_ROLE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`role responsibility secret field is not allowed at ${path}.${key}`);
    }
    assertNoRoleProtectedContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRoleProtectedContent(input ?? {});
  canonicalize(input ?? {});
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [BigInt(hlc.physicalMs), BigInt(hlc.logical)];
}

function compareHlc(left, right) {
  if (left[0] < right[0]) {
    return -1;
  }
  if (left[0] > right[0]) {
    return 1;
  }
  if (left[1] < right[1]) {
    return -1;
  }
  if (left[1] > right[1]) {
    return 1;
  }
  return 0;
}

function hlcBefore(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) < 0;
}

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function hasAuthorityPermission(authority) {
  return Array.isArray(authority?.permissions) &&
    (authority.permissions.includes(REQUIRED_PERMISSION) || authority.permissions.includes('govern'));
}

function expectedAuthorityMode(roleRef) {
  if (roleRef === 'ai_quality_reviewer') {
    return 'ai_assistant';
  }
  if (GOVERNANCE_ROLE_REFS.includes(roleRef)) {
    return 'governance_role';
  }
  return 'operational_permission';
}

function validateBase(input, checkedAt, reasons) {
  addReason(reasons, !hasText(input?.requestId), 'request_id_absent');
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, !hasText(input?.siteId), 'site_absent');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(
    reasons,
    input?.actor?.kind === 'ai_agent' || input?.aiAssistance?.finalAuthority === true,
    'ai_final_authority_forbidden',
  );
  addReason(reasons, checkedAt === null, 'checked_time_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function validateAuthority(authority, reasons) {
  addReason(reasons, authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !hasAuthorityPermission(authority), 'authority_permission_missing');
  addReason(reasons, !isDigest(authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function validatePolicy(policy, checkedAt, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'role_responsibility_policy_ref_absent');
  addReason(reasons, !hasText(policy?.version), 'role_responsibility_policy_version_absent');
  addReason(reasons, policy?.status !== 'active', 'role_responsibility_policy_not_active');
  addReason(reasons, !isDigest(policy?.policyHash), 'role_responsibility_policy_hash_invalid');
  addReason(reasons, policy?.metadataOnly !== true, 'role_responsibility_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'role_responsibility_policy_time_invalid');
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, checkedAt), 'role_responsibility_policy_after_check');

  const sourceRefs = sortedTextList(policy?.sourceRefs);
  const requiredRoleRefs = sortedTextList(policy?.requiredRoleRefs);
  const requiredGovernanceRoleRefs = sortedTextList(policy?.requiredGovernanceRoleRefs);
  const activationGateIds = sortedTextList(policy?.activationGateIds);
  const escalationIds = sortedTextList(policy?.allowedBobEscalationIds);

  for (const sourceRef of REQUIRED_POLICY_SOURCE_REFS) {
    addReason(reasons, !sourceRefs.includes(sourceRef), `policy_source_ref_missing:${sourceRef}`);
  }
  for (const roleRef of REQUIRED_ROLE_REFS) {
    addReason(reasons, !requiredRoleRefs.includes(roleRef), `policy_required_role_missing:${roleRef}`);
  }
  for (const roleRef of GOVERNANCE_ROLE_REFS) {
    addReason(reasons, !requiredGovernanceRoleRefs.includes(roleRef), `policy_governance_role_missing:${roleRef}`);
  }
  addReason(reasons, !activationGateIds.includes(REQUIRED_ACTIVATION_GATE), 'ptag_010_activation_gate_absent');
  addReason(reasons, !escalationIds.includes(REQUIRED_BOB_ESCALATION), 'esc_role_matrix_absent');
}

function normalizeRoleProfiles(input, checkedAt, reasons) {
  const roleProfiles = Array.isArray(input?.roleProfiles) ? input.roleProfiles : [];
  addReason(reasons, roleProfiles.length === 0, 'role_profiles_absent');

  const seenRoles = new Set();
  const normalized = [];

  for (const profile of roleProfiles) {
    const roleRef = profile?.roleRef;
    const reasonRole = roleRef ?? 'unknown';
    const expectedResponsibilities = REQUIRED_ROLE_RESPONSIBILITIES[roleRef] ?? [];
    const responsibilityRefs = sortedTextList(profile?.responsibilityRefs);
    const ownerDomainRefs = sortedTextList(profile?.ownerDomainRefs);
    const dashboardRefs = sortedTextList(profile?.dashboardRefs);
    const manualSectionRefs = sortedTextList(profile?.manualSectionRefs);
    const supportPathRefs = sortedTextList(profile?.supportPathRefs);

    addReason(reasons, !hasText(roleRef), 'role_profile_ref_absent');
    addReason(reasons, hasText(roleRef) && seenRoles.has(roleRef), `role_profile_duplicate:${roleRef}`);
    if (hasText(roleRef)) {
      seenRoles.add(roleRef);
    }
    addReason(reasons, hasText(roleRef) && !REQUIRED_ROLE_REFS.includes(roleRef), `role_profile_unsupported:${roleRef}`);
    addReason(reasons, !AUTHORITY_MODES.has(profile?.authorityMode), `role_authority_mode_invalid:${reasonRole}`);
    addReason(
      reasons,
      REQUIRED_ROLE_REFS.includes(roleRef) && profile?.authorityMode !== expectedAuthorityMode(roleRef),
      `role_authority_mode_mismatch:${reasonRole}`,
    );
    addReason(reasons, !isDigest(profile?.evidenceHash), `role_evidence_hash_invalid:${reasonRole}`);
    addReason(reasons, hlcTuple(profile?.updatedAtHlc) === null, `role_updated_time_invalid:${reasonRole}`);
    addReason(reasons, hlcAfter(profile?.updatedAtHlc, checkedAt), `role_updated_after_check:${reasonRole}`);
    addReason(reasons, !hasText(profile?.humanOwnerDid), `role_human_owner_absent:${reasonRole}`);
    addReason(reasons, profile?.aiFinalAuthority === true, `role_final_authority_forbidden:${reasonRole}`);
    addReason(reasons, profile?.metadataOnly !== true, `role_metadata_boundary_invalid:${reasonRole}`);
    addReason(reasons, profile?.protectedContentExcluded !== true, `role_protected_boundary_invalid:${reasonRole}`);
    addReason(reasons, profile?.productionTrustClaim === true, `role_production_trust_claim_forbidden:${reasonRole}`);
    addReason(reasons, ownerDomainRefs.length === 0, `role_owner_domain_absent:${reasonRole}`);
    addReason(reasons, dashboardRefs.length === 0, `role_dashboard_link_absent:${reasonRole}`);
    addReason(reasons, manualSectionRefs.length === 0, `role_manual_link_absent:${reasonRole}`);
    addReason(reasons, supportPathRefs.length === 0, `role_support_path_absent:${reasonRole}`);
    addReason(reasons, !hasText(profile?.sourceSectionRef), `role_source_section_absent:${reasonRole}`);

    for (const responsibility of expectedResponsibilities) {
      addReason(
        reasons,
        !responsibilityRefs.includes(responsibility),
        `role_responsibility_missing:${roleRef}:${responsibility}`,
      );
    }
    for (const responsibility of responsibilityRefs) {
      addReason(
        reasons,
        expectedResponsibilities.length > 0 && !expectedResponsibilities.includes(responsibility),
        `role_responsibility_unsupported:${roleRef}:${responsibility}`,
      );
    }

    normalized.push({
      authorityMode: profile?.authorityMode ?? null,
      dashboardRefs,
      evidenceHash: profile?.evidenceHash ?? null,
      finalAuthorityProhibited: roleRef === 'ai_quality_reviewer',
      humanOwnerDid: profile?.humanOwnerDid ?? null,
      manualSectionRefs,
      ownerDomainRefs,
      protectedContentExcluded: profile?.protectedContentExcluded === true,
      responsibilityRefs,
      roleRef: roleRef ?? null,
      sourceSectionRef: profile?.sourceSectionRef ?? null,
      supportPathRefs,
      updatedAtHlc: profile?.updatedAtHlc ?? null,
    });
  }

  for (const roleRef of REQUIRED_ROLE_REFS) {
    addReason(reasons, !seenRoles.has(roleRef), `role_profile_missing:${roleRef}`);
  }

  return normalized.sort((left, right) => String(left.roleRef).localeCompare(String(right.roleRef)));
}

function validateHumanGovernance(input, reasons) {
  const governance = input?.humanGovernance;
  addReason(reasons, governance?.verified !== true, 'human_governance_unverified');
  addReason(reasons, !hasText(governance?.approvedByDid), 'human_governance_approver_absent');
  addReason(reasons, !hasText(governance?.decisionForumReceiptId), 'decision_forum_receipt_absent');
  addReason(reasons, governance?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, governance?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, governance?.openChallenge === true, 'challenge_open');
}

function authorityModeCounts(roleProfiles) {
  return {
    aiAssistant: roleProfiles.filter((profile) => profile.authorityMode === 'ai_assistant').length,
    governanceRole: roleProfiles.filter((profile) => profile.authorityMode === 'governance_role').length,
    operationalPermission: roleProfiles.filter((profile) => profile.authorityMode === 'operational_permission').length,
  };
}

function matrixDigestMaterial(input, roleProfiles) {
  return {
    matrixSchema: MATRIX_SCHEMA,
    policyHash: input.roleResponsibilityPolicy.policyHash,
    policyRef: input.roleResponsibilityPolicy.policyRef,
    policyVersion: input.roleResponsibilityPolicy.version,
    requiredRoleRefs: REQUIRED_ROLE_REFS,
    roleProfiles,
    siteId: input.siteId,
    sourceRefs: REQUIRED_POLICY_SOURCE_REFS,
    tenantId: input.tenantId,
  };
}

function buildRoleResponsibilityMatrix(input, roleProfiles, matrixHash) {
  return {
    schema: MATRIX_SCHEMA,
    matrixId: `cmrrm_${matrixHash.slice(0, 32)}`,
    matrixHash,
    tenantId: input.tenantId,
    siteId: input.siteId,
    checkedAtHlc: input.checkedAtHlc,
    policyRef: input.roleResponsibilityPolicy.policyRef,
    policyVersion: input.roleResponsibilityPolicy.version,
    roleCount: roleProfiles.length,
    roleRefs: roleProfiles.map((profile) => profile.roleRef).sort(),
    governanceRoleRefs: [...GOVERNANCE_ROLE_REFS],
    authorityModeCounts: authorityModeCounts(roleProfiles),
    sourceRefs: [...REQUIRED_POLICY_SOURCE_REFS],
    roleProfiles,
    authorityChainHash: input.authority.authorityChainHash,
    decisionForumReceiptId: input.humanGovernance.decisionForumReceiptId,
  };
}

function buildReceipt(input, matrixHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: matrixHash,
    artifactType: 'role_responsibility_matrix',
    artifactVersion: `${input.roleResponsibilityPolicy.policyRef}@${input.roleResponsibilityPolicy.version}`,
    classification: 'qms_governance_metadata',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.checkedAtHlc,
    sensitivityTags: ['human_governance', 'metadata_only', 'role_responsibility'],
    sourceSystem: 'cybermedica',
    tenantId: input.tenantId,
  });
}

function deniedDecision(reasons) {
  return {
    schema: DECISION_SCHEMA,
    decision: 'denied',
    failClosed: true,
    reasons: uniqueSorted(reasons),
    trustState: 'inactive',
    exochainProductionClaim: false,
    roleResponsibilityMatrix: null,
    receipt: null,
  };
}

export function evaluateRoleResponsibilityMatrix(input) {
  assertMetadataOnly(input ?? {});

  const reasons = [];
  const checkedAt = hlcTuple(input?.checkedAtHlc);

  validateBase(input, checkedAt, reasons);
  validateAuthority(input?.authority, reasons);
  validatePolicy(input?.roleResponsibilityPolicy, checkedAt, reasons);
  const roleProfiles = normalizeRoleProfiles(input, checkedAt, reasons);
  validateHumanGovernance(input, reasons);

  if (reasons.length > 0) {
    return deniedDecision(reasons);
  }

  const matrixHash = sha256Hex(matrixDigestMaterial(input, roleProfiles));
  const receipt = buildReceipt(input, matrixHash);
  const roleResponsibilityMatrix = {
    ...buildRoleResponsibilityMatrix(input, roleProfiles, matrixHash),
    receiptId: receipt.receiptId,
  };

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    trustState: 'inactive',
    exochainProductionClaim: false,
    roleResponsibilityMatrix,
    receipt,
  };
}
