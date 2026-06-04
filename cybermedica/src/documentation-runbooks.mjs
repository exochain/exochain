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
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const DOCUMENTATION_SCHEMA = 'cybermedica.documentation_runbook_readiness.v1';
const REQUIRED_PERMISSION = 'documentation_runbook_review';

const REQUIRED_DOCUMENTATION_DOMAINS = Object.freeze([
  'administrator_runbook',
  'ai_orientation_assistant',
  'audit_inspector_mode',
  'contextual_manual_drawer',
  'evidence_checklists',
  'inquiry_cqi_reporting',
  'policy_procedure_crosslinks',
  'role_manuals',
  'version_governance',
  'workflow_guides',
]);

const REQUIRED_ROLE_MANUALS = Object.freeze([
  'administrator',
  'auditor_inspector',
  'clinical_research_coordinator',
  'cro_portfolio_manager',
  'decision_forum_member',
  'principal_investigator',
  'quality_manager',
  'site_leader',
  'sponsor_viewer',
]);

const REQUIRED_INSPECTION_EVIDENCE = Object.freeze([
  'access_logs',
  'chain_of_custody',
  'corrective_actions',
  'decision_rationale',
  'document_version_history',
  'evidence_traceability',
  'exportable_audit_packet',
  'issue_history',
  'role_delegation_records',
  'staff_training_records',
]);

const REQUIRED_DOCUMENTATION_ARTIFACTS = Object.freeze([
  'cybermedica_user_manual',
  'site_leader_manual',
  'principal_investigator_manual',
  'coordinator_site_staff_manual',
  'quality_manager_manual',
  'cro_portfolio_manual',
  'sponsor_viewer_manual',
  'auditor_monitor_inspector_manual',
  'decision_forum_manual',
  'ai_quality_review_manual',
  'tenant_administrator_manual',
  'system_administrator_manual',
  'evidence_chain_of_custody_manual',
  'protocol_readiness_launch_gate_manual',
  'consent_participant_protection_manual',
  'deviation_capa_manual',
  'training_delegation_manual',
  'clinical_trial_product_accountability_manual',
  'exochain_receipts_privacy_anchoring_guide',
  'support_access_break_glass_emergency_runbook',
  'sponsor_cro_diligence_packet_guide',
  'audit_inspection_packet_guide',
  'ai_governance_model_use_policy',
  'deployment_backup_recovery_incident_response_runbook',
]);

const ACTIVE_POLICY_STATUSES = new Set(['active']);
const READY_DOMAIN_STATUSES = new Set(['ready']);
const HUMAN_DECISIONS = new Set(['documentation_pack_ready', 'hold_for_documentation_gap']);

const RAW_DOCUMENTATION_FIELDS = new Set([
  'assistantbody',
  'artifactbody',
  'artifactcontent',
  'artifacttext',
  'body',
  'content',
  'freetext',
  'freetextnote',
  'guidebody',
  'manualbody',
  'manualcontent',
  'manualtext',
  'notes',
  'orientationcopy',
  'rawassistantcontent',
  'rawartifact',
  'rawartifactcontent',
  'rawartifacttext',
  'rawcontent',
  'rawguidecontent',
  'rawinspectionguide',
  'rawmanualcontent',
  'rawmanualtext',
  'rawpolicytext',
  'rawproceduretext',
  'rawrunbookcontent',
  'rawrunbooktext',
  'reviewnotes',
  'runbookbody',
  'runbookcontent',
  'runbooktext',
  'sourcebody',
  'sourcedocumentbody',
]);

const SECRET_DOCUMENTATION_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credential',
  'credentialsecret',
  'password',
  'privatekey',
  'railwaytoken',
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
  return hasText(value) && HEX_64.test(value) && value !== ZERO_HASH;
}

function isBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 10_000;
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
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

function assertNoRawDocumentationContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawDocumentationContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_DOCUMENTATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw documentation content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_DOCUMENTATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`documentation secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawDocumentationContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawDocumentationContent(input ?? {});
  canonicalize(input ?? {});
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [hlc.physicalMs, hlc.logical];
}

function compareHlc(left, right) {
  if (left[0] !== right[0]) {
    return left[0] < right[0] ? -1 : 1;
  }
  if (left[1] !== right[1]) {
    return left[1] < right[1] ? -1 : 1;
  }
  return 0;
}

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function latestHlc(values) {
  const tuples = values.map((value) => hlcTuple(value)).filter((value) => value !== null);
  if (tuples.length === 0) {
    return null;
  }
  return tuples.reduce((latest, candidate) => (compareHlc(latest, candidate) >= 0 ? latest : candidate));
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateRequiredSet(actual, expected, missingPrefix, unsupportedPrefix, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !expected.includes(value), `${unsupportedPrefix}:${value}`);
  }
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_documentation_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'documentation_runbook_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateDocumentationPolicy(policy, reasons) {
  const requiredDocumentationDomains = sortedTextList(policy?.requiredDocumentationDomains);
  const requiredRoleManuals = sortedTextList(policy?.requiredRoleManuals);
  const requiredInspectionEvidenceKinds = sortedTextList(policy?.requiredInspectionEvidenceKinds);
  const requiredDocumentationArtifacts = sortedTextList(policy?.requiredDocumentationArtifacts);

  addReason(reasons, !hasText(policy?.policyRef), 'documentation_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'documentation_policy_hash_invalid');
  addReason(reasons, !ACTIVE_POLICY_STATUSES.has(policy?.status), 'documentation_policy_not_active');
  addReason(reasons, policy?.manualVersionGovernanceRequired !== true, 'manual_version_governance_policy_absent');
  addReason(reasons, policy?.aiOrientationAdvisoryOnly !== true, 'ai_orientation_policy_not_advisory_only');
  addReason(reasons, policy?.inquiryCqiRoutingRequired !== true, 'inquiry_cqi_policy_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'documentation_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'documentation_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'documentation_policy_time_invalid');

  evaluateRequiredSet(
    requiredDocumentationDomains,
    REQUIRED_DOCUMENTATION_DOMAINS,
    'policy_documentation_domain_missing',
    'policy_documentation_domain_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    requiredRoleManuals,
    REQUIRED_ROLE_MANUALS,
    'policy_role_manual_missing',
    'policy_role_manual_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    requiredInspectionEvidenceKinds,
    REQUIRED_INSPECTION_EVIDENCE,
    'policy_inspection_evidence_missing',
    'policy_inspection_evidence_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    requiredDocumentationArtifacts,
    REQUIRED_DOCUMENTATION_ARTIFACTS,
    'policy_documentation_artifact_missing',
    'policy_documentation_artifact_unsupported',
    reasons,
  );
}

function evaluateDocumentationCycle(cycle, reasons) {
  addReason(reasons, !hasText(cycle?.cycleRef), 'documentation_cycle_ref_absent');
  addReason(reasons, cycle?.metadataOnly !== true, 'documentation_cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'documentation_cycle_protected_boundary_invalid');
  addReason(reasons, cycle?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(cycle?.openedAtHlc) === null, 'documentation_cycle_open_time_invalid');
  addReason(reasons, hlcTuple(cycle?.manualReviewAtHlc) === null, 'manual_review_time_invalid');
  addReason(reasons, hlcTuple(cycle?.humanApprovedAtHlc) === null, 'documentation_human_approval_time_invalid');
  addReason(reasons, hlcTuple(cycle?.publishedAtHlc) === null, 'documentation_publication_time_invalid');
  addReason(reasons, !hlcAfter(cycle?.manualReviewAtHlc, cycle?.openedAtHlc), 'manual_review_time_not_after_open');
  addReason(
    reasons,
    !hlcAfter(cycle?.humanApprovedAtHlc, cycle?.manualReviewAtHlc),
    'human_approval_time_not_after_manual_review',
  );
  addReason(
    reasons,
    !hlcAfter(cycle?.publishedAtHlc, cycle?.humanApprovedAtHlc),
    'publication_time_not_after_human_approval',
  );
}

function evaluateDocumentationDomains(domains, reasons) {
  const rows = Array.isArray(domains) ? domains : [];
  const actualDomains = uniqueSorted(rows.map((row) => row?.domain));
  evaluateRequiredSet(
    actualDomains,
    REQUIRED_DOCUMENTATION_DOMAINS,
    'documentation_domain_missing',
    'documentation_domain_unsupported',
    reasons,
  );

  for (const row of rows) {
    const prefix = `documentation_domain_invalid:${row?.domain ?? 'unknown'}`;
    addReason(reasons, !hasText(row?.artifactRef), `${prefix}:artifact_ref_absent`);
    addReason(reasons, !isDigest(row?.artifactHash), `${prefix}:artifact_hash_invalid`);
    addReason(reasons, !READY_DOMAIN_STATUSES.has(row?.status), `${prefix}:status_not_ready`);
    addReason(reasons, !hasText(row?.ownerDid), `${prefix}:owner_absent`);
    addReason(reasons, !hasText(row?.reviewerDid), `${prefix}:reviewer_absent`);
    addReason(reasons, row?.reviewedByHuman !== true, `${prefix}:human_review_missing`);
    addReason(reasons, hlcTuple(row?.reviewedAtHlc) === null, `${prefix}:review_time_invalid`);
    addReason(reasons, row?.metadataOnly !== true, `${prefix}:metadata_boundary_invalid`);
    addReason(reasons, row?.protectedContentExcluded !== true, `${prefix}:protected_boundary_invalid`);
    addReason(reasons, row?.productionTrustClaim === true, `${prefix}:production_trust_claim_forbidden`);
  }

  return actualDomains;
}

function evaluateRoleManuals(manuals, reasons) {
  const rows = Array.isArray(manuals) ? manuals : [];
  const actualRoles = uniqueSorted(rows.map((row) => row?.role));
  evaluateRequiredSet(actualRoles, REQUIRED_ROLE_MANUALS, 'role_manual_missing', 'role_manual_unsupported', reasons);

  for (const row of rows) {
    const prefix = `role_manual_invalid:${row?.role ?? 'unknown'}`;
    addReason(reasons, !hasText(row?.manualRef), `${prefix}:manual_ref_absent`);
    addReason(reasons, !hasText(row?.versionRef), `${prefix}:version_ref_absent`);
    addReason(reasons, !isDigest(row?.versionHash), `${prefix}:version_hash_invalid`);
    addReason(
      reasons,
      !Array.isArray(row?.workflowGuideRefs) || row.workflowGuideRefs.filter(hasText).length === 0,
      `${prefix}:workflow_guide_refs_absent`,
    );
    addReason(
      reasons,
      !Array.isArray(row?.evidenceChecklistRefs) || row.evidenceChecklistRefs.filter(hasText).length === 0,
      `${prefix}:evidence_checklist_refs_absent`,
    );
    addReason(reasons, !isDigest(row?.accessPolicyHash), `${prefix}:access_policy_hash_invalid`);
    addReason(reasons, !isDigest(row?.plainLanguageSummaryHash), `${prefix}:plain_language_hash_invalid`);
    addReason(reasons, row?.approvedForUse !== true, `${prefix}:not_approved_for_use`);
    addReason(reasons, hlcTuple(row?.reviewedAtHlc) === null, `${prefix}:review_time_invalid`);
    addReason(reasons, row?.metadataOnly !== true, `${prefix}:metadata_boundary_invalid`);
    addReason(reasons, row?.protectedContentExcluded !== true, `${prefix}:protected_boundary_invalid`);
  }

  return actualRoles;
}

function evaluateDocumentationArtifacts(artifacts, reasons) {
  const rows = Array.isArray(artifacts) ? artifacts : [];
  const actualArtifacts = uniqueSorted(rows.map((row) => row?.artifact));
  evaluateRequiredSet(
    actualArtifacts,
    REQUIRED_DOCUMENTATION_ARTIFACTS,
    'documentation_artifact_missing',
    'documentation_artifact_unsupported',
    reasons,
  );

  for (const row of rows) {
    const prefix = `documentation_artifact_invalid:${row?.artifact ?? 'unknown'}`;
    addReason(reasons, !hasText(row?.artifactRef), `${prefix}:artifact_ref_absent`);
    addReason(reasons, !hasText(row?.versionRef), `${prefix}:version_ref_absent`);
    addReason(reasons, !isDigest(row?.artifactHash), `${prefix}:artifact_hash_invalid`);
    addReason(reasons, !hasText(row?.ownerRoleRef), `${prefix}:owner_role_absent`);
    addReason(
      reasons,
      !Array.isArray(row?.targetAudienceRoleRefs) || row.targetAudienceRoleRefs.filter(hasText).length === 0,
      `${prefix}:target_audience_roles_absent`,
    );
    addReason(
      reasons,
      !Array.isArray(row?.crosslinkRefs) || row.crosslinkRefs.filter(hasText).length === 0,
      `${prefix}:crosslink_refs_absent`,
    );
    addReason(reasons, row?.approvedForSandyReview !== true, `${prefix}:not_approved_for_sandy_review`);
    addReason(reasons, row?.reviewedByHuman !== true, `${prefix}:human_review_missing`);
    addReason(reasons, hlcTuple(row?.reviewedAtHlc) === null, `${prefix}:review_time_invalid`);
    addReason(reasons, row?.metadataOnly !== true, `${prefix}:metadata_boundary_invalid`);
    addReason(reasons, row?.protectedContentExcluded !== true, `${prefix}:protected_boundary_invalid`);
    addReason(reasons, row?.productionTrustClaim === true, `${prefix}:production_trust_claim_forbidden`);
  }

  return actualArtifacts;
}

function evaluateCrosslinkMatrix(matrix, reasons) {
  addReason(reasons, !hasText(matrix?.matrixRef), 'manual_crosslink_matrix_ref_absent');
  addReason(reasons, !isDigest(matrix?.matrixHash), 'manual_crosslink_matrix_hash_invalid');
  addReason(reasons, matrix?.linksControls !== true, 'crosslink_controls_missing');
  addReason(reasons, matrix?.linksEvidence !== true, 'crosslink_evidence_missing');
  addReason(reasons, matrix?.linksProcedures !== true, 'crosslink_procedures_missing');
  addReason(reasons, matrix?.linksWorkflows !== true, 'crosslink_workflows_missing');
  addReason(reasons, matrix?.linksPolicies !== true, 'crosslink_policies_missing');
  addReason(
    reasons,
    !Number.isSafeInteger(matrix?.brokenLinkCount) || matrix.brokenLinkCount !== 0,
    'manual_crosslink_matrix_has_broken_links',
  );
  addReason(reasons, hlcTuple(matrix?.reviewedAtHlc) === null, 'manual_crosslink_review_time_invalid');
  addReason(reasons, matrix?.metadataOnly !== true, 'manual_crosslink_metadata_boundary_invalid');
  addReason(reasons, matrix?.protectedContentExcluded !== true, 'manual_crosslink_protected_boundary_invalid');
}

function evaluateInspectionGuide(guide, reasons) {
  const rows = Array.isArray(guide?.evidenceKinds) ? guide.evidenceKinds : [];
  const actualKinds = uniqueSorted(rows.map((row) => row?.kind));

  addReason(reasons, !hasText(guide?.guideRef), 'inspection_guide_ref_absent');
  addReason(reasons, !isDigest(guide?.guideHash), 'inspection_guide_hash_invalid');
  addReason(reasons, guide?.modeEnabledForAuthorizedAuditorsOnly !== true, 'inspection_mode_not_authorized_auditor_only');
  addReason(reasons, !isDigest(guide?.accessPolicyHash), 'inspection_access_policy_hash_invalid');
  addReason(reasons, !isDigest(guide?.exportPolicyHash), 'inspection_export_policy_hash_invalid');
  addReason(reasons, guide?.suppressedProtectedContent !== true, 'inspection_protected_content_suppression_missing');
  addReason(reasons, guide?.disclosureLogRequired !== true, 'inspection_disclosure_log_missing');
  addReason(reasons, hlcTuple(guide?.reviewedAtHlc) === null, 'inspection_guide_review_time_invalid');
  addReason(reasons, guide?.metadataOnly !== true, 'inspection_guide_metadata_boundary_invalid');
  addReason(reasons, guide?.protectedContentExcluded !== true, 'inspection_guide_protected_boundary_invalid');
  evaluateRequiredSet(
    actualKinds,
    REQUIRED_INSPECTION_EVIDENCE,
    'inspection_evidence_missing',
    'inspection_evidence_unsupported',
    reasons,
  );

  for (const row of rows) {
    const prefix = `inspection_evidence_invalid:${row?.kind ?? 'unknown'}`;
    addReason(reasons, !hasText(row?.packetRef), `${prefix}:packet_ref_absent`);
    addReason(reasons, !isDigest(row?.packetHash), `${prefix}:packet_hash_invalid`);
    addReason(reasons, !hasText(row?.accessPolicyRef), `${prefix}:access_policy_ref_absent`);
    addReason(reasons, row?.exportEligible !== true, `${prefix}:export_not_eligible`);
    addReason(reasons, row?.retainedForInspection !== true, `${prefix}:retention_missing`);
    addReason(reasons, row?.metadataOnly !== true, `${prefix}:metadata_boundary_invalid`);
    addReason(reasons, row?.protectedContentExcluded !== true, `${prefix}:protected_boundary_invalid`);
    addReason(reasons, hlcTuple(row?.reviewedAtHlc) === null, `${prefix}:review_time_invalid`);
  }

  return actualKinds;
}

function evaluateAiOrientation(orientation, reasons) {
  addReason(reasons, !hasText(orientation?.assistantRef), 'ai_orientation_assistant_ref_absent');
  addReason(reasons, !isDigest(orientation?.promptPolicyHash), 'ai_orientation_prompt_policy_hash_invalid');
  addReason(reasons, !isDigest(orientation?.scopeHash), 'ai_orientation_scope_hash_invalid');
  addReason(reasons, orientation?.finalAuthority === true, 'ai_orientation_final_authority_forbidden');
  addReason(reasons, orientation?.advisoryOnly !== true, 'ai_orientation_not_advisory_only');
  addReason(reasons, orientation?.routesUnresolvedQuestionsToHuman !== true, 'ai_orientation_human_routing_missing');
  addReason(reasons, !isBasisPoints(orientation?.confidenceFloorBasisPoints), 'ai_orientation_confidence_floor_invalid');
  addReason(reasons, orientation?.reviewedByHuman !== true, 'ai_orientation_human_review_missing');
  addReason(reasons, hlcTuple(orientation?.reviewedAtHlc) === null, 'ai_orientation_review_time_invalid');
  addReason(reasons, orientation?.metadataOnly !== true, 'ai_orientation_metadata_boundary_invalid');
  addReason(reasons, orientation?.protectedContentExcluded !== true, 'ai_orientation_protected_boundary_invalid');
}

function evaluateInquiryCqiReporting(reporting, reasons) {
  addReason(reasons, !hasText(reporting?.intakeRef), 'inquiry_cqi_intake_ref_absent');
  addReason(reasons, !isDigest(reporting?.intakeHash), 'inquiry_cqi_intake_hash_invalid');
  addReason(reasons, !isDigest(reporting?.frictionTagSetHash), 'inquiry_cqi_friction_tag_set_hash_invalid');
  addReason(reasons, !isDigest(reporting?.cqiActionPolicyHash), 'inquiry_cqi_action_policy_hash_invalid');
  addReason(reasons, reporting?.routesToQualityOwner !== true, 'inquiry_cqi_quality_owner_route_missing');
  addReason(reasons, reporting?.permitsAnonymousInquiry !== true, 'inquiry_cqi_anonymous_route_missing');
  addReason(reasons, !isDigest(reporting?.noRetaliationReminderHash), 'inquiry_cqi_no_retaliation_hash_invalid');
  addReason(reasons, hlcTuple(reporting?.reviewedAtHlc) === null, 'inquiry_cqi_review_time_invalid');
  addReason(reasons, reporting?.metadataOnly !== true, 'inquiry_cqi_metadata_boundary_invalid');
  addReason(reasons, reporting?.protectedContentExcluded !== true, 'inquiry_cqi_protected_boundary_invalid');
}

function evaluateVersionGovernance(versionGovernance, reviewHlcValues, reasons) {
  const latestReview = latestHlc(reviewHlcValues);
  const latestReviewObject =
    latestReview === null ? null : { physicalMs: latestReview[0], logical: latestReview[1] };

  addReason(reasons, !isDigest(versionGovernance?.currentManualSetHash), 'current_manual_set_hash_invalid');
  addReason(reasons, !isDigest(versionGovernance?.priorManualSetHash), 'prior_manual_set_hash_invalid');
  addReason(reasons, !hasText(versionGovernance?.changeControlRef), 'manual_change_control_ref_absent');
  addReason(reasons, versionGovernance?.supersededVersionRetained !== true, 'manual_superseded_retention_missing');
  addReason(
    reasons,
    versionGovernance?.effectiveUseAcknowledgementRequired !== true,
    'manual_effective_use_acknowledgement_missing',
  );
  addReason(reasons, !isDigest(versionGovernance?.distributionEvidenceHash), 'manual_distribution_hash_invalid');
  addReason(reasons, versionGovernance?.approvedByHuman !== true, 'manual_version_human_approval_missing');
  addReason(reasons, hlcTuple(versionGovernance?.approvedAtHlc) === null, 'manual_version_approval_time_invalid');
  addReason(
    reasons,
    latestReviewObject !== null && !hlcAfter(versionGovernance?.approvedAtHlc, latestReviewObject),
    'manual_version_approval_time_not_after_review',
  );
  addReason(reasons, versionGovernance?.metadataOnly !== true, 'manual_version_metadata_boundary_invalid');
  addReason(reasons, versionGovernance?.protectedContentExcluded !== true, 'manual_version_protected_boundary_invalid');
}

function evaluateValidationEvidence(validationEvidence, reasons) {
  addReason(
    reasons,
    !Array.isArray(validationEvidence?.commandRefs) || validationEvidence.commandRefs.filter(hasText).length === 0,
    'validation_command_refs_absent',
  );
  addReason(reasons, validationEvidence?.commandsPassed !== true, 'validation_commands_not_passed');
  addReason(reasons, validationEvidence?.sourceGuardPassed !== true, 'validation_source_guard_not_passed');
  addReason(reasons, validationEvidence?.noExochainSourceModified !== true, 'exochain_source_modification_forbidden');
  addReason(reasons, hlcTuple(validationEvidence?.recordedAtHlc) === null, 'validation_record_time_invalid');
  addReason(reasons, validationEvidence?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
}

function evaluateHumanReview(review, cycle, reasons) {
  addReason(reasons, !hasText(review?.reviewerDid), 'human_review_reviewer_absent');
  addReason(reasons, !Array.isArray(review?.reviewerRoleRefs) || review.reviewerRoleRefs.filter(hasText).length === 0, 'human_review_roles_absent');
  addReason(reasons, !HUMAN_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_final_authority_missing');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, !hlcAfter(review?.reviewedAtHlc, cycle?.manualReviewAtHlc), 'human_review_time_not_after_manual_review');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
}

function missingValues(required, actual) {
  return required.filter((value) => !actual.includes(value));
}

function createDocumentationDigest(input, actualDomains, actualRoles, actualInspectionKinds, actualDocumentationArtifacts) {
  return sha256Hex({
    schema: DOCUMENTATION_SCHEMA,
    tenantId: input?.tenantId ?? null,
    cycleRef: input?.documentationCycle?.cycleRef ?? null,
    documentationDomains: actualDomains,
    roleManuals: actualRoles,
    inspectionEvidenceKinds: actualInspectionKinds,
    documentationArtifacts: actualDocumentationArtifacts,
    crosslinkMatrixHash: input?.crosslinkMatrix?.matrixHash ?? null,
    inspectionGuideHash: input?.inspectionGuide?.guideHash ?? null,
    aiOrientationScopeHash: input?.aiOrientation?.scopeHash ?? null,
    inquiryCqiPolicyHash: input?.inquiryCqiReporting?.cqiActionPolicyHash ?? null,
    currentManualSetHash: input?.versionGovernance?.currentManualSetHash ?? null,
  });
}

function createReadinessSummary(
  input,
  reasons,
  actualDomains,
  actualRoles,
  actualInspectionKinds,
  actualDocumentationArtifacts,
  documentationDigest,
) {
  const ready = reasons.length === 0;
  return {
    schema: DOCUMENTATION_SCHEMA,
    ready,
    trustState: 'inactive',
    exochainProductionClaim: false,
    documentationDigest,
    domainCount: actualDomains.length,
    roleManualCount: actualRoles.length,
    inspectionEvidenceCount: actualInspectionKinds.length,
    documentationArtifactCount: actualDocumentationArtifacts.length,
    missingDocumentationDomains: missingValues(REQUIRED_DOCUMENTATION_DOMAINS, actualDomains),
    missingRoleManuals: missingValues(REQUIRED_ROLE_MANUALS, actualRoles),
    missingInspectionEvidenceKinds: missingValues(REQUIRED_INSPECTION_EVIDENCE, actualInspectionKinds),
    missingDocumentationArtifacts: missingValues(REQUIRED_DOCUMENTATION_ARTIFACTS, actualDocumentationArtifacts),
    publishedAtHlc: input?.documentationCycle?.publishedAtHlc ?? null,
    reviewerDid: input?.humanReview?.reviewerDid ?? null,
    sourceEvidence: [
      'cybermedica_2_0_sandy_seven_layer_master_prd.md',
      'cyber_medica_qms_prd_master.md',
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
    ],
  };
}

export function evaluateDocumentationRunbookReadiness(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateDocumentationPolicy(input?.documentationPolicy, reasons);
  evaluateDocumentationCycle(input?.documentationCycle, reasons);
  const actualDomains = evaluateDocumentationDomains(input?.documentationDomains, reasons);
  const actualRoles = evaluateRoleManuals(input?.roleManuals, reasons);
  const actualDocumentationArtifacts = evaluateDocumentationArtifacts(input?.documentationArtifacts, reasons);
  evaluateCrosslinkMatrix(input?.crosslinkMatrix, reasons);
  const actualInspectionKinds = evaluateInspectionGuide(input?.inspectionGuide, reasons);
  evaluateAiOrientation(input?.aiOrientation, reasons);
  evaluateInquiryCqiReporting(input?.inquiryCqiReporting, reasons);
  evaluateVersionGovernance(
    input?.versionGovernance,
    [
      input?.documentationCycle?.manualReviewAtHlc,
      input?.crosslinkMatrix?.reviewedAtHlc,
      input?.inspectionGuide?.reviewedAtHlc,
      input?.aiOrientation?.reviewedAtHlc,
      input?.inquiryCqiReporting?.reviewedAtHlc,
      ...(Array.isArray(input?.documentationDomains) ? input.documentationDomains.map((row) => row?.reviewedAtHlc) : []),
      ...(Array.isArray(input?.roleManuals) ? input.roleManuals.map((row) => row?.reviewedAtHlc) : []),
      ...(Array.isArray(input?.documentationArtifacts)
        ? input.documentationArtifacts.map((row) => row?.reviewedAtHlc)
        : []),
    ],
    reasons,
  );
  evaluateValidationEvidence(input?.validationEvidence, reasons);
  evaluateHumanReview(input?.humanReview, input?.documentationCycle, reasons);

  const finalReasons = uniqueReasons(reasons);
  const documentationDigest = createDocumentationDigest(
    input,
    actualDomains,
    actualRoles,
    actualInspectionKinds,
    actualDocumentationArtifacts,
  );
  const documentationReadiness = createReadinessSummary(
    input,
    finalReasons,
    actualDomains,
    actualRoles,
    actualInspectionKinds,
    actualDocumentationArtifacts,
    documentationDigest,
  );

  if (finalReasons.length > 0) {
    return {
      schema: DOCUMENTATION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: finalReasons,
      documentationReadiness,
      receipt: null,
    };
  }

  const receipt = createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'documentation_runbook_readiness',
    artifactVersion: input.documentationCycle.cycleRef,
    artifactHash: documentationDigest,
    classification: 'metadata_only_documentation_runbook',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.documentationCycle.publishedAtHlc,
    sensitivityTags: ['documentation_metadata', 'inspection_metadata', 'no_raw_content'],
    sourceSystem: 'cybermedica',
  });

  return {
    schema: DOCUMENTATION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    documentationReadiness,
    receipt,
  };
}
