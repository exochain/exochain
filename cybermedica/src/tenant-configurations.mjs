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
const TENANT_CONFIGURATION_SCHEMA = 'cybermedica.tenant_configuration.v1';
const TENANT_CONFIGURATION_RECORD_SCHEMA = 'cybermedica.tenant_configuration_record.v1';

const REQUIRED_WORKFLOWS = Object.freeze([
  'capa',
  'decision_forum',
  'deviation',
  'document_control',
  'enrollment_gate',
  'evidence_intake',
  'internal_audit',
  'launch_gate',
  'safety_event',
]);

const REQUIRED_ROLES = Object.freeze([
  'auditor',
  'coordinator',
  'decision_forum',
  'principal_investigator',
  'quality_manager',
  'site_leader',
  'sponsor_viewer',
  'system_administrator',
]);

const REQUIRED_REVIEW_FAMILIES = Object.freeze(['controls', 'evidence', 'reports', 'sops', 'training']);

const REQUIRED_REPORT_DOMAINS = Object.freeze([
  'audit',
  'capa',
  'consent_readiness',
  'deviations',
  'equipment',
  'product_accountability',
  'qms_status',
  'risk',
  'site_readiness',
  'sponsor_diligence',
  'training',
]);

const TEMPLATE_KINDS = new Set(['custom', 'standard']);
const METADATA_CLASSIFICATIONS = new Set([
  'confidential_metadata_only',
  'restricted_metadata_only',
  'sponsor_confidential_metadata_only',
]);

const RAW_CONFIGURATION_FIELDS = new Set([
  'displayname',
  'evidencerequirementtext',
  'freetextrationale',
  'rawconfiguration',
  'rawconfigurationpayload',
  'rawevidencerequirement',
  'rawpolicy',
  'rawroletext',
  'rawsop',
  'rawsopbody',
  'rawsoptext',
  'rawtemplate',
  'rawworkflow',
  'requirementtext',
  'sopbody',
  'sopnarrative',
  'sopsourcebody',
  'soptext',
  'workflowbody',
]);

const SECRET_CONFIGURATION_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credential',
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

function isPositiveSafeInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
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

function assertNoRawConfigurationContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawConfigurationContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_CONFIGURATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw tenant configuration content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_CONFIGURATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`tenant configuration secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawConfigurationContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawConfigurationContent(input ?? {});
  canonicalize(input ?? {});
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [hlc.physicalMs, hlc.logical];
}

function compareHlcTuple(left, right) {
  if (left[0] !== right[0]) {
    return left[0] < right[0] ? -1 : 1;
  }
  if (left[1] !== right[1]) {
    return left[1] < right[1] ? -1 : 1;
  }
  return 0;
}

function hlcBefore(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlcTuple(leftTuple, rightTuple) < 0;
}

function hlcBeforeOrEqual(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlcTuple(leftTuple, rightTuple) <= 0;
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function includesAll(required, present) {
  const presentSet = new Set(present);
  return required.every((value) => presentSet.has(value));
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function sortByField(fieldName) {
  return (left, right) => String(left[fieldName]).localeCompare(String(right[fieldName]));
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_configuration_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, 'tenant_configuration_manage') && !hasAuthorityPermission(input?.authority, 'govern'),
    'configuration_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function normalizeConfigurationPackage(input, reasons) {
  const pkg = input?.configurationPackage;
  addReason(reasons, !hasText(pkg?.configRef), 'configuration_ref_absent');
  addReason(reasons, !hasText(pkg?.configVersion), 'configuration_version_absent');
  addReason(reasons, pkg?.schemaVersion !== TENANT_CONFIGURATION_SCHEMA, 'configuration_schema_invalid');
  addReason(reasons, pkg?.status !== 'approved', 'configuration_package_not_approved');
  addReason(reasons, !isDigest(pkg?.tenantProfileHash), 'tenant_profile_hash_invalid');
  addReason(reasons, !isDigest(pkg?.siteProfileHash), 'site_profile_hash_invalid');
  addReason(reasons, pkg?.previousConfigHash !== null && pkg?.previousConfigHash !== undefined && !isDigest(pkg?.previousConfigHash), 'previous_configuration_hash_invalid');
  addReason(reasons, !isDigest(pkg?.packageHash), 'configuration_package_hash_invalid');
  addReason(reasons, pkg?.metadataOnly !== true, 'configuration_package_metadata_boundary_invalid');
  addReason(reasons, pkg?.productionTrustClaim === true, 'production_trust_claim_forbidden');

  return {
    configRef: hasText(pkg?.configRef) ? pkg.configRef : 'CONFIG-UNKNOWN',
    configVersion: hasText(pkg?.configVersion) ? pkg.configVersion : 'VERSION-UNKNOWN',
    packageHash: pkg?.packageHash ?? null,
    previousConfigHash: pkg?.previousConfigHash ?? null,
    schemaVersion: pkg?.schemaVersion ?? null,
    siteProfileHash: pkg?.siteProfileHash ?? null,
    status: pkg?.status ?? null,
    tenantProfileHash: pkg?.tenantProfileHash ?? null,
  };
}

function normalizeChangeControl(input, reasons) {
  const change = input?.changeControl;
  addReason(reasons, !hasText(change?.changeRef), 'change_control_ref_absent');
  addReason(reasons, !hasText(change?.requestedByDid), 'change_control_requester_absent');
  addReason(reasons, !hasText(change?.approvedByDid), 'change_control_approver_absent');
  addReason(
    reasons,
    hasText(change?.requestedByDid) && change.requestedByDid === change?.approvedByDid,
    'change_control_self_approval_forbidden',
  );
  addReason(reasons, hlcTuple(change?.requestedAtHlc) === null, 'change_request_time_invalid');
  addReason(reasons, hlcTuple(change?.approvedAtHlc) === null, 'change_approval_time_invalid');
  addReason(reasons, hlcTuple(change?.effectiveAtHlc) === null, 'change_effective_time_invalid');
  addReason(reasons, hlcBefore(change?.approvedAtHlc, change?.requestedAtHlc), 'change_approval_before_request');
  addReason(reasons, hlcBefore(change?.effectiveAtHlc, change?.approvedAtHlc), 'change_effective_before_approval');
  addReason(reasons, !isDigest(change?.rationaleHash), 'change_rationale_hash_invalid');
  addReason(reasons, !isDigest(change?.impactAssessmentHash), 'change_impact_assessment_hash_invalid');
  addReason(reasons, !isDigest(change?.rollbackPlanHash), 'change_rollback_plan_hash_invalid');
  addReason(reasons, !isDigest(change?.testEvidenceHash), 'change_test_evidence_hash_invalid');
  addReason(reasons, change?.metadataOnly !== true, 'change_control_metadata_boundary_invalid');

  return {
    approvedAtHlc: change?.approvedAtHlc ?? null,
    approvedByDid: change?.approvedByDid ?? null,
    changeRef: hasText(change?.changeRef) ? change.changeRef : 'CHANGE-UNKNOWN',
    effectiveAtHlc: change?.effectiveAtHlc ?? null,
    impactAssessmentHash: change?.impactAssessmentHash ?? null,
    rationaleHash: change?.rationaleHash ?? null,
    requestedAtHlc: change?.requestedAtHlc ?? null,
    requestedByDid: change?.requestedByDid ?? null,
    rollbackPlanHash: change?.rollbackPlanHash ?? null,
    testEvidenceHash: change?.testEvidenceHash ?? null,
  };
}

function normalizeControlSets(input, reasons) {
  const controlSets = Array.isArray(input?.controlSets) ? [...input.controlSets].sort(sortByField('controlSetRef')) : [];
  addReason(reasons, controlSets.length === 0, 'control_sets_absent');

  return controlSets.map((controlSet) => {
    const controlSetRef = hasText(controlSet?.controlSetRef) ? controlSet.controlSetRef : 'CONTROL-SET-UNKNOWN';
    const controlRefs = sortedTextList(controlSet?.controlRefs);
    addReason(reasons, !hasText(controlSet?.controlSetRef), 'control_set_ref_absent');
    addReason(reasons, controlSet?.status !== 'active', `control_set_not_active:${controlSetRef}`);
    addReason(reasons, controlRefs.length === 0, `control_set_controls_absent:${controlSetRef}`);
    addReason(reasons, !isDigest(controlSet?.applicabilityProfileHash), `control_set_applicability_hash_invalid:${controlSetRef}`);
    addReason(reasons, !isDigest(controlSet?.standardsCrosswalkHash), `control_set_crosswalk_hash_invalid:${controlSetRef}`);
    addReason(reasons, !isDigest(controlSet?.waiverPolicyHash), `control_set_waiver_policy_hash_invalid:${controlSetRef}`);
    addReason(reasons, controlSet?.metadataOnly !== true, `control_set_metadata_boundary_invalid:${controlSetRef}`);

    return {
      applicabilityProfileHash: controlSet?.applicabilityProfileHash ?? null,
      controlRefs,
      controlSetRef,
      standardsCrosswalkHash: controlSet?.standardsCrosswalkHash ?? null,
      status: controlSet?.status ?? null,
      waiverPolicyHash: controlSet?.waiverPolicyHash ?? null,
    };
  });
}

function normalizeWorkflows(input, reasons) {
  const workflows = Array.isArray(input?.workflows) ? [...input.workflows].sort(sortByField('workflowFamily')) : [];
  const workflowFamilies = uniqueSorted(workflows.map((workflow) => workflow?.workflowFamily).filter(hasText));
  addReason(reasons, workflows.length === 0, 'workflows_absent');
  for (const required of REQUIRED_WORKFLOWS) {
    addReason(reasons, !workflowFamilies.includes(required), `required_workflow_missing:${required}`);
  }

  return workflows.map((workflow) => {
    const workflowFamily = hasText(workflow?.workflowFamily) ? workflow.workflowFamily : 'workflow_unknown';
    const requiredRoleRefs = sortedTextList(workflow?.requiredRoleRefs);
    addReason(reasons, !REQUIRED_WORKFLOWS.includes(workflowFamily), `workflow_family_invalid:${workflowFamily}`);
    addReason(reasons, !hasText(workflow?.workflowRef), `workflow_ref_absent:${workflowFamily}`);
    addReason(reasons, !hasText(workflow?.workflowVersion), `workflow_version_absent:${workflowFamily}`);
    addReason(reasons, workflow?.status !== 'active', `workflow_not_active:${workflowFamily}`);
    addReason(reasons, !isDigest(workflow?.definitionHash), `workflow_definition_hash_invalid:${workflowFamily}`);
    addReason(reasons, requiredRoleRefs.length === 0, `workflow_roles_absent:${workflowFamily}`);
    addReason(reasons, !hasText(workflow?.decisionGateRef), `workflow_decision_gate_absent:${workflowFamily}`);
    addReason(reasons, workflow?.failClosedOnMissingEvidence !== true, `workflow_fail_closed_absent:${workflowFamily}`);
    addReason(reasons, workflow?.metadataOnly !== true, `workflow_metadata_boundary_invalid:${workflowFamily}`);

    return {
      decisionGateRef: workflow?.decisionGateRef ?? null,
      definitionHash: workflow?.definitionHash ?? null,
      failClosedOnMissingEvidence: workflow?.failClosedOnMissingEvidence === true,
      requiredRoleRefs,
      status: workflow?.status ?? null,
      workflowFamily,
      workflowRef: workflow?.workflowRef ?? null,
      workflowVersion: workflow?.workflowVersion ?? null,
    };
  });
}

function normalizeRoles(input, reasons) {
  const roles = Array.isArray(input?.roles) ? [...input.roles].sort(sortByField('roleRef')) : [];
  const roleRefs = uniqueSorted(roles.map((role) => role?.roleRef).filter(hasText));
  addReason(reasons, roles.length === 0, 'roles_absent');
  for (const required of REQUIRED_ROLES) {
    addReason(reasons, !roleRefs.includes(required), `required_role_missing:${required}`);
  }

  return roles.map((role) => {
    const roleRef = hasText(role?.roleRef) ? role.roleRef : 'role_unknown';
    const permissionRefs = sortedTextList(role?.permissionRefs);
    addReason(reasons, !REQUIRED_ROLES.includes(roleRef), `role_ref_invalid:${roleRef}`);
    addReason(reasons, role?.status !== 'active', `role_not_active:${roleRef}`);
    addReason(reasons, !isDigest(role?.displayNameHash), `role_display_name_hash_invalid:${roleRef}`);
    addReason(reasons, permissionRefs.length === 0, `role_permissions_absent:${roleRef}`);
    addReason(reasons, !isDigest(role?.authorityPolicyHash), `role_authority_policy_hash_invalid:${roleRef}`);
    addReason(reasons, !isDigest(role?.delegationPolicyHash), `role_delegation_policy_hash_invalid:${roleRef}`);
    addReason(reasons, !isDigest(role?.accessPolicyHash), `role_access_policy_hash_invalid:${roleRef}`);
    addReason(reasons, !hasText(role?.separationOfPowersGroup), `role_separation_group_absent:${roleRef}`);
    addReason(
      reasons,
      permissionRefs.includes('tenant_configuration_manage') && permissionRefs.includes('configuration_approve'),
      `role_combines_configuration_and_approval:${roleRef}`,
    );
    addReason(reasons, role?.metadataOnly !== true, `role_metadata_boundary_invalid:${roleRef}`);

    return {
      accessPolicyHash: role?.accessPolicyHash ?? null,
      authorityPolicyHash: role?.authorityPolicyHash ?? null,
      delegationPolicyHash: role?.delegationPolicyHash ?? null,
      displayNameHash: role?.displayNameHash ?? null,
      humanOwnerRequired: role?.humanOwnerRequired === true,
      permissionRefs,
      roleRef,
      separationOfPowersGroup: role?.separationOfPowersGroup ?? null,
      status: role?.status ?? null,
    };
  });
}

function normalizeSopMappings(input, reasons) {
  const mappings = Array.isArray(input?.sopMappings) ? [...input.sopMappings].sort(sortByField('mappingRef')) : [];
  addReason(reasons, mappings.length === 0, 'sop_mappings_absent');

  return mappings.map((mapping) => {
    const mappingRef = hasText(mapping?.mappingRef) ? mapping.mappingRef : 'SOP-MAPPING-UNKNOWN';
    const controlRefs = sortedTextList(mapping?.controlRefs);
    const roleRefs = sortedTextList(mapping?.roleRefs);
    const workflowRefs = sortedTextList(mapping?.workflowRefs);
    addReason(reasons, !hasText(mapping?.mappingRef), 'sop_mapping_ref_absent');
    addReason(reasons, !hasText(mapping?.sopRef), `sop_ref_absent:${mappingRef}`);
    addReason(reasons, !hasText(mapping?.sopVersion), `sop_version_absent:${mappingRef}`);
    addReason(reasons, !isDigest(mapping?.sopHash), `sop_hash_invalid:${mappingRef}`);
    addReason(reasons, controlRefs.length === 0, `sop_control_refs_absent:${mappingRef}`);
    addReason(reasons, workflowRefs.length === 0, `sop_workflow_refs_absent:${mappingRef}`);
    addReason(reasons, roleRefs.length === 0, `sop_role_refs_absent:${mappingRef}`);
    addReason(reasons, hlcTuple(mapping?.effectiveAtHlc) === null, `sop_effective_time_invalid:${mappingRef}`);
    addReason(reasons, mapping?.metadataOnly !== true, `sop_mapping_metadata_boundary_invalid:${mappingRef}`);

    return {
      controlRefs,
      effectiveAtHlc: mapping?.effectiveAtHlc ?? null,
      mappingRef,
      roleRefs,
      sopHash: mapping?.sopHash ?? null,
      sopRef: mapping?.sopRef ?? null,
      sopVersion: mapping?.sopVersion ?? null,
      workflowRefs,
    };
  });
}

function normalizeEvidenceRequirements(input, reasons) {
  const requirements = Array.isArray(input?.evidenceRequirements)
    ? [...input.evidenceRequirements].sort(sortByField('requirementRef'))
    : [];
  addReason(reasons, requirements.length === 0, 'evidence_requirements_absent');

  return requirements.map((requirement) => {
    const requirementRef = hasText(requirement?.requirementRef) ? requirement.requirementRef : 'EVIDENCE-REQ-UNKNOWN';
    const requiredForControlRefs = sortedTextList(requirement?.requiredForControlRefs);
    const reviewRoleRefs = sortedTextList(requirement?.reviewRoleRefs);
    addReason(reasons, !hasText(requirement?.requirementRef), 'evidence_requirement_ref_absent');
    addReason(reasons, !hasText(requirement?.artifactType), `evidence_requirement_artifact_type_absent:${requirementRef}`);
    addReason(
      reasons,
      !METADATA_CLASSIFICATIONS.has(requirement?.classification),
      `evidence_requirement_classification_invalid:${requirementRef}`,
    );
    addReason(reasons, requiredForControlRefs.length === 0, `evidence_requirement_control_refs_absent:${requirementRef}`);
    addReason(reasons, reviewRoleRefs.length === 0, `evidence_requirement_review_roles_absent:${requirementRef}`);
    addReason(reasons, !isPositiveSafeInteger(requirement?.freshnessDays), `evidence_requirement_freshness_invalid:${requirementRef}`);
    addReason(reasons, !isDigest(requirement?.retentionRuleHash), `evidence_requirement_retention_hash_invalid:${requirementRef}`);
    addReason(reasons, requirement?.custodyRequired !== true, `evidence_requirement_custody_not_required:${requirementRef}`);
    addReason(reasons, requirement?.metadataOnly !== true, `evidence_requirement_metadata_boundary_invalid:${requirementRef}`);

    return {
      artifactType: requirement?.artifactType ?? null,
      classification: requirement?.classification ?? null,
      custodyRequired: requirement?.custodyRequired === true,
      freshnessDays: requirement?.freshnessDays ?? null,
      requiredForControlRefs,
      requirementRef,
      retentionRuleHash: requirement?.retentionRuleHash ?? null,
      reviewRoleRefs,
    };
  });
}

function normalizeReviewFrequencies(input, reasons) {
  const frequencies = Array.isArray(input?.reviewFrequencies)
    ? [...input.reviewFrequencies].sort(sortByField('objectFamily'))
    : [];
  const objectFamilies = uniqueSorted(frequencies.map((frequency) => frequency?.objectFamily).filter(hasText));
  addReason(reasons, frequencies.length === 0, 'review_frequencies_absent');
  for (const required of REQUIRED_REVIEW_FAMILIES) {
    addReason(reasons, !objectFamilies.includes(required), `required_review_frequency_missing:${required}`);
  }

  return frequencies.map((frequency) => {
    const objectFamily = hasText(frequency?.objectFamily) ? frequency.objectFamily : 'review_family_unknown';
    addReason(reasons, !REQUIRED_REVIEW_FAMILIES.includes(objectFamily), `review_frequency_family_invalid:${objectFamily}`);
    addReason(
      reasons,
      !isPositiveSafeInteger(frequency?.frequencyDays) || frequency.frequencyDays > 3650,
      `review_frequency_days_invalid:${objectFamily}`,
    );
    addReason(reasons, !hasText(frequency?.ownerRoleRef), `review_frequency_owner_absent:${objectFamily}`);
    addReason(reasons, !isDigest(frequency?.escalationRuleHash), `review_frequency_escalation_hash_invalid:${objectFamily}`);
    addReason(reasons, !isPositiveSafeInteger(frequency?.reviewWindowDays), `review_frequency_window_invalid:${objectFamily}`);
    addReason(reasons, frequency?.metadataOnly !== true, `review_frequency_metadata_boundary_invalid:${objectFamily}`);

    return {
      escalationRuleHash: frequency?.escalationRuleHash ?? null,
      frequencyDays: frequency?.frequencyDays ?? null,
      objectFamily,
      ownerRoleRef: frequency?.ownerRoleRef ?? null,
      reviewWindowDays: frequency?.reviewWindowDays ?? null,
    };
  });
}

function normalizeReportingTemplates(input, reasons) {
  const templates = Array.isArray(input?.reportingTemplates)
    ? [...input.reportingTemplates].sort(sortByField('templateRef'))
    : [];
  const supportedDomains = uniqueSorted(templates.flatMap((template) => sortedTextList(template?.supportedDomains)));
  addReason(reasons, templates.length === 0, 'reporting_templates_absent');
  for (const domain of REQUIRED_REPORT_DOMAINS) {
    addReason(reasons, !supportedDomains.includes(domain), `required_report_domain_missing:${domain}`);
  }

  return templates.map((template) => {
    const templateRef = hasText(template?.templateRef) ? template.templateRef : 'REPORT-TEMPLATE-UNKNOWN';
    const domains = sortedTextList(template?.supportedDomains);
    addReason(reasons, !hasText(template?.templateRef), 'reporting_template_ref_absent');
    addReason(reasons, !TEMPLATE_KINDS.has(template?.templateKind), `reporting_template_kind_invalid:${templateRef}`);
    addReason(reasons, template?.status !== 'approved', `reporting_template_not_approved:${templateRef}`);
    addReason(reasons, !isDigest(template?.templateHash), `reporting_template_hash_invalid:${templateRef}`);
    addReason(reasons, !isDigest(template?.outputProfileHash), `reporting_output_profile_hash_invalid:${templateRef}`);
    addReason(reasons, !isDigest(template?.accessPolicyHash), `reporting_access_policy_hash_invalid:${templateRef}`);
    addReason(reasons, domains.length === 0, `reporting_domains_absent:${templateRef}`);
    addReason(reasons, template?.metadataOnly !== true, `reporting_template_metadata_boundary_invalid:${templateRef}`);
    addReason(reasons, template?.productionTrustClaim === true, `reporting_template_production_trust_claim_forbidden:${templateRef}`);

    return {
      accessPolicyHash: template?.accessPolicyHash ?? null,
      outputProfileHash: template?.outputProfileHash ?? null,
      status: template?.status ?? null,
      supportedDomains: domains,
      templateHash: template?.templateHash ?? null,
      templateKind: template?.templateKind ?? null,
      templateRef,
    };
  });
}

function normalizeGovernanceReview(input, changeControl, reasons) {
  const review = input?.governanceReview;
  addReason(reasons, review?.status !== 'approved', 'governance_review_not_approved');
  addReason(reasons, !hasText(review?.reviewerDid), 'governance_reviewer_absent');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'governance_review_time_invalid');
  addReason(
    reasons,
    hlcTuple(review?.reviewedAtHlc) !== null && hlcTuple(changeControl.approvedAtHlc) !== null && hlcBefore(review.reviewedAtHlc, changeControl.approvedAtHlc),
    'governance_review_before_change_approval',
  );
  addReason(
    reasons,
    hlcTuple(review?.reviewedAtHlc) !== null && hlcTuple(changeControl.effectiveAtHlc) !== null && hlcBefore(changeControl.effectiveAtHlc, review.reviewedAtHlc),
    'configuration_effective_before_governance_review',
  );
  addReason(reasons, !isDigest(review?.reviewEvidenceHash), 'governance_review_evidence_hash_invalid');
  addReason(reasons, review?.quorumVerified !== true, 'governance_quorum_unverified');
  addReason(reasons, review?.aiFinalAuthorityRejected !== true, 'governance_ai_final_authority_not_rejected');

  return {
    aiFinalAuthorityRejected: review?.aiFinalAuthorityRejected === true,
    quorumVerified: review?.quorumVerified === true,
    reviewEvidenceHash: review?.reviewEvidenceHash ?? null,
    reviewedAtHlc: review?.reviewedAtHlc ?? null,
    reviewerDid: review?.reviewerDid ?? null,
    status: review?.status ?? null,
  };
}

function normalizeAiAssistance(input, reasons) {
  const ai = input?.aiAssistance;
  if (ai === null || ai === undefined || ai?.used !== true) {
    return {
      confidenceBasisPoints: null,
      evidenceRefs: [],
      finalAuthority: false,
      limitationHashes: [],
      reasoningSummaryHash: null,
      recommendedHumanReviewerDids: [],
      unresolvedAssumptionHashes: [],
      used: false,
    };
  }

  const evidenceRefs = sortedTextList(ai.evidenceRefs);
  const limitationHashes = sortedTextList(ai.limitationHashes);
  const unresolvedAssumptionHashes = sortedTextList(ai.unresolvedAssumptionHashes);
  const recommendedHumanReviewerDids = sortedTextList(ai.recommendedHumanReviewerDids);
  addReason(reasons, ai.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, evidenceRefs.length === 0, 'ai_evidence_refs_absent');
  addReason(reasons, !isDigest(ai.reasoningSummaryHash), 'ai_reasoning_summary_hash_invalid');
  addReason(reasons, !isBasisPoints(ai.confidenceBasisPoints), 'ai_confidence_basis_points_invalid');
  addReason(reasons, limitationHashes.some((hash) => !isDigest(hash)), 'ai_limitation_hash_invalid');
  addReason(reasons, unresolvedAssumptionHashes.some((hash) => !isDigest(hash)), 'ai_assumption_hash_invalid');
  addReason(reasons, recommendedHumanReviewerDids.length === 0, 'ai_human_reviewers_absent');

  return {
    confidenceBasisPoints: ai.confidenceBasisPoints ?? null,
    evidenceRefs,
    finalAuthority: ai.finalAuthority === true,
    limitationHashes,
    reasoningSummaryHash: ai.reasoningSummaryHash ?? null,
    recommendedHumanReviewerDids,
    unresolvedAssumptionHashes,
    used: true,
  };
}

function sectionCoverage(sections) {
  return {
    controlSets: sections.controlSets.length,
    evidenceRequirements: sections.evidenceRequirements.length,
    reportingTemplates: sections.reportingTemplates.length,
    reviewFrequencies: sections.reviewFrequencies.length,
    roles: sections.roles.length,
    sopMappings: sections.sopMappings.length,
    workflows: sections.workflows.length,
  };
}

function configurationMaterial(input, sections) {
  const workflowFamilies = uniqueSorted(sections.workflows.map((workflow) => workflow.workflowFamily));
  const roleRefs = uniqueSorted(sections.roles.map((role) => role.roleRef));
  const reportDomains = uniqueSorted(sections.reportingTemplates.flatMap((template) => template.supportedDomains));

  return {
    aiAssistance: sections.aiAssistance,
    changeControl: sections.changeControl,
    configurationPackage: sections.configurationPackage,
    controlSets: sections.controlSets,
    evidenceRequirements: sections.evidenceRequirements,
    governanceReview: sections.governanceReview,
    recordSchema: TENANT_CONFIGURATION_RECORD_SCHEMA,
    reportDomains,
    reportingTemplates: sections.reportingTemplates,
    reviewFrequencies: sections.reviewFrequencies,
    roleRefs,
    roles: sections.roles,
    sectionCoverage: sectionCoverage(sections),
    sopMappings: sections.sopMappings,
    targetTenantId: input.targetTenantId,
    tenantId: input.tenantId,
    workflowFamilies,
    workflows: sections.workflows,
  };
}

function buildConfigurationRecord(input, materialHash, sections) {
  const material = configurationMaterial(input, sections);
  return {
    schema: TENANT_CONFIGURATION_RECORD_SCHEMA,
    aiAssistance: sections.aiAssistance,
    changeControl: sections.changeControl,
    configurationHash: materialHash,
    configRef: sections.configurationPackage.configRef,
    configVersion: sections.configurationPackage.configVersion,
    exochainProductionClaim: false,
    governanceReview: sections.governanceReview,
    reportDomains: material.reportDomains,
    roleRefs: material.roleRefs,
    sectionCoverage: material.sectionCoverage,
    status: 'approved',
    tenantId: input.tenantId,
    trustState: 'inactive',
    workflowFamilies: material.workflowFamilies,
  };
}

function buildReceipt(input, sections, materialHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'tenant_configuration',
    artifactVersion: `${sections.configurationPackage.configRef}@${sections.configurationPackage.configVersion}`,
    artifactHash: materialHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: sections.changeControl.effectiveAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['configuration_metadata', 'tenant_boundary', 'qms_controls'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function evaluateTenantConfiguration(input) {
  assertMetadataOnly(input ?? {});

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const configurationPackage = normalizeConfigurationPackage(input, reasons);
  const changeControl = normalizeChangeControl(input, reasons);
  const controlSets = normalizeControlSets(input, reasons);
  const workflows = normalizeWorkflows(input, reasons);
  const roles = normalizeRoles(input, reasons);
  const sopMappings = normalizeSopMappings(input, reasons);
  const evidenceRequirements = normalizeEvidenceRequirements(input, reasons);
  const reviewFrequencies = normalizeReviewFrequencies(input, reasons);
  const reportingTemplates = normalizeReportingTemplates(input, reasons);
  const governanceReview = normalizeGovernanceReview(input, changeControl, reasons);
  const aiAssistance = normalizeAiAssistance(input, reasons);

  const finalReasons = uniqueSorted(reasons);
  if (finalReasons.length > 0) {
    return {
      permitted: false,
      reasons: finalReasons,
      configurationRecord: null,
      receipt: null,
    };
  }

  const sections = {
    aiAssistance,
    changeControl,
    configurationPackage,
    controlSets,
    evidenceRequirements,
    governanceReview,
    reportingTemplates,
    reviewFrequencies,
    roles,
    sopMappings,
    workflows,
  };
  const material = configurationMaterial(input, sections);
  addReason(finalReasons, !includesAll(REQUIRED_WORKFLOWS, material.workflowFamilies), 'workflow_coverage_incomplete');
  addReason(finalReasons, !includesAll(REQUIRED_ROLES, material.roleRefs), 'role_coverage_incomplete');
  addReason(finalReasons, !includesAll(REQUIRED_REPORT_DOMAINS, material.reportDomains), 'report_domain_coverage_incomplete');
  addReason(finalReasons, hlcBeforeOrEqual(changeControl.effectiveAtHlc, changeControl.requestedAtHlc), 'configuration_effective_not_after_request');

  if (finalReasons.length > 0) {
    return {
      permitted: false,
      reasons: uniqueSorted(finalReasons),
      configurationRecord: null,
      receipt: null,
    };
  }

  const configurationHash = sha256Hex(material);
  const configurationRecord = buildConfigurationRecord(input, configurationHash, sections);
  return {
    permitted: true,
    reasons: [],
    configurationRecord,
    receipt: buildReceipt(input, sections, configurationHash),
  };
}
