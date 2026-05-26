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
const POLICY_SCHEMA = 'cybermedica.clinical_authority_policy.v1';
const DECISION_SCHEMA = 'cybermedica.clinical_authority_policy_decision.v1';
const REQUIRED_ACTIVATION_GATE = 'PTAG-010';
const REQUIRED_BOB_ESCALATION = 'ESC-ROLE-MATRIX';

const REQUIRED_PERMISSION_DIMENSIONS = Object.freeze([
  'action_type',
  'confidentiality_classification',
  'cro_visibility',
  'decision_matter',
  'delegation',
  'emergency_access',
  'evidence_type',
  'expiration',
  'phi_pii_classification',
  'protocol',
  'role',
  'site',
  'sponsor_visibility',
  'study',
  'tenant',
]);

const REQUIRED_AUTHORITY_ACTIONS = Object.freeze([
  'access_sensitive_participant_linked_evidence',
  'audit_report_finalization',
  'capa_closure',
  'clinical_trial_product_release_use_authorization',
  'consent_form_activation',
  'control_library_publication',
  'critical_risk_acceptance',
  'delegation_approval',
  'deviation_closure',
  'emergency_override',
  'enrollment_authorization',
  'evidence_disclosure',
  'policy_approval',
  'site_qms_passport_approval',
  'sop_approval',
  'sponsor_export_release',
  'trial_acceptance',
  'trial_launch_authorization',
]);

const REQUIRED_CLINICAL_ROLES = Object.freeze([
  'ai_quality_reviewer',
  'auditor',
  'clinical_research_coordinator',
  'clinical_research_site_leader',
  'cro_portfolio_manager',
  'data_manager',
  'decision_forum_chair',
  'facility_manager',
  'monitor_cra',
  'pharmacy_investigational_product_manager',
  'principal_investigator',
  'quality_manager',
  'regulatory_coordinator',
  'site_executive_sponsor',
  'sponsor_viewer',
  'system_administrator',
  'training_manager',
]);

const AUTHORITY_MODES = new Set(['ai_assistant', 'governance_role', 'operational_permission']);
const SAFE_VISIBILITY_VALUES = new Set(['limited', 'none', 'not_applicable', 'role_scoped']);
const SAFE_CONFIDENTIALITY_VALUES = new Set(['confidential_metadata_only', 'regulated_metadata_only']);
const SAFE_PHI_VALUES = new Set(['coded_metadata_only', 'not_participant_linked', 'none']);

const RAW_AUTHORITY_FIELDS = new Set([
  'body',
  'content',
  'freetext',
  'freetextauthority',
  'freetextrolematrix',
  'narrative',
  'rawauthority',
  'rawauthoritypolicy',
  'rawmatrix',
  'rawpolicy',
  'rawrolematrix',
  'rawrolematrixnarrative',
  'reviewnotes',
  'rolematrixbody',
  'rolematrixnarrative',
  'sourcebody',
]);

const SECRET_AUTHORITY_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'bootstrapsecret',
  'bootstraptoken',
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

function assertNoRawAuthorityPolicyContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawAuthorityPolicyContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_AUTHORITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw clinical authority policy field is not allowed at ${path}.${key}`);
    }
    if (SECRET_AUTHORITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`clinical authority policy secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawAuthorityPolicyContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawAuthorityPolicyContent(input ?? {});
  canonicalize(input ?? {});
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
}

function sortedDigestList(value) {
  return Array.isArray(value) ? uniqueSorted(value.filter(isDigest)) : [];
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

function hlcBefore(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) < 0;
}

function hasAuthorityPermission(authority, permission) {
  return hasText(permission) && Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_authority_reviewer_required');
  addReason(reasons, !hasText(input?.requestedAction), 'requested_action_absent');
  addReason(reasons, hlcTuple(input?.requestedAtHlc) === null, 'requested_time_invalid');
  addReason(reasons, input?.authorityChain?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authorityChain?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authorityChain?.expired === true, 'authority_chain_expired');
  addReason(reasons, !isDigest(input?.authorityChain?.authorityChainHash), 'authority_chain_hash_invalid');
}

function validatePolicyHeader(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'authority_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'authority_policy_hash_invalid');
  addReason(reasons, policy?.status !== 'active', 'authority_policy_not_active');
  addReason(reasons, policy?.metadataOnly !== true, 'authority_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'authority_policy_evaluation_time_invalid');

  const activationGateIds = sortedTextList(policy?.activationGateIds);
  const escalationIds = sortedTextList(policy?.allowedBobEscalationIds);
  addReason(reasons, !activationGateIds.includes(REQUIRED_ACTIVATION_GATE), 'ptag_010_activation_gate_absent');
  addReason(reasons, !escalationIds.includes(REQUIRED_BOB_ESCALATION), 'esc_role_matrix_absent');
}

function validateRequiredCoverage(policy, reasons) {
  const dimensions = sortedTextList(policy?.requiredPermissionDimensions);
  const actions = sortedTextList(policy?.requiredAuthorityActions);
  const roles = sortedTextList(policy?.requiredClinicalRoles);

  for (const dimension of REQUIRED_PERMISSION_DIMENSIONS) {
    addReason(reasons, !dimensions.includes(dimension), `permission_dimension_missing:${dimension}`);
  }
  for (const action of REQUIRED_AUTHORITY_ACTIONS) {
    addReason(reasons, !actions.includes(action), `authority_action_missing:${action}`);
  }
  for (const role of REQUIRED_CLINICAL_ROLES) {
    addReason(reasons, !roles.includes(role), `clinical_role_missing:${role}`);
  }
}

function normalizeRoleMappings(policy, reasons) {
  const roleMappings = Array.isArray(policy?.roleMappings) ? policy.roleMappings : [];
  const governanceRoleRefs = sortedTextList(policy?.governanceRoleRefs);
  const seenRoles = new Set();

  addReason(reasons, roleMappings.length === 0, 'role_mappings_absent');
  const normalized = roleMappings.map((mapping) => {
    const roleRef = mapping?.roleRef;
    const authorityMode = mapping?.authorityMode;
    const exochainRoleRefs = sortedTextList(mapping?.exochainRoleRefs);
    const permissionRefs = sortedTextList(mapping?.permissionRefs);

    addReason(reasons, !hasText(roleRef), 'role_mapping_ref_absent');
    addReason(reasons, hasText(roleRef) && seenRoles.has(roleRef), `role_mapping_duplicate:${roleRef}`);
    if (hasText(roleRef)) {
      seenRoles.add(roleRef);
    }
    addReason(reasons, !AUTHORITY_MODES.has(authorityMode), `role_mapping_mode_invalid:${roleRef ?? 'unknown'}`);
    addReason(reasons, !isDigest(mapping?.evidenceHash), `role_mapping_evidence_hash_invalid:${roleRef ?? 'unknown'}`);
    addReason(reasons, hlcTuple(mapping?.mappedAtHlc) === null, `role_mapping_time_invalid:${roleRef ?? 'unknown'}`);
    addReason(reasons, mapping?.metadataOnly !== true, `role_mapping_metadata_boundary_invalid:${roleRef ?? 'unknown'}`);

    const blended =
      (authorityMode === 'governance_role' && permissionRefs.length > 0) ||
      ((authorityMode === 'operational_permission' || authorityMode === 'ai_assistant') && exochainRoleRefs.length > 0);
    addReason(reasons, blended, `role_mapping_mode_blended:${roleRef ?? 'unknown'}`);

    if (authorityMode === 'governance_role') {
      addReason(reasons, exochainRoleRefs.length === 0, `governance_role_mapping_absent:${roleRef ?? 'unknown'}`);
      addReason(reasons, !governanceRoleRefs.includes(roleRef), `governance_role_not_listed:${roleRef ?? 'unknown'}`);
      addReason(reasons, mapping?.decisionForumEligible !== true, `governance_role_forum_eligibility_absent:${roleRef ?? 'unknown'}`);
      addReason(reasons, mapping?.humanFinalAuthority !== true, `governance_role_human_final_absent:${roleRef ?? 'unknown'}`);
    }
    if (authorityMode === 'operational_permission') {
      addReason(reasons, permissionRefs.length === 0, `operational_permission_mapping_absent:${roleRef ?? 'unknown'}`);
      addReason(reasons, mapping?.humanFinalAuthority !== true, `operational_permission_human_final_absent:${roleRef ?? 'unknown'}`);
    }
    if (authorityMode === 'ai_assistant') {
      addReason(reasons, !permissionRefs.includes('assist'), `ai_assistant_permission_absent:${roleRef ?? 'unknown'}`);
      addReason(reasons, mapping?.humanFinalAuthority !== false, `ai_assistant_human_final_forbidden:${roleRef ?? 'unknown'}`);
    }

    return {
      authorityMode: authorityMode ?? null,
      decisionForumEligible: mapping?.decisionForumEligible === true,
      evidenceHash: mapping?.evidenceHash ?? null,
      exochainRoleRefs,
      humanFinalAuthority: mapping?.humanFinalAuthority === true,
      mappedAtHlc: mapping?.mappedAtHlc ?? null,
      permissionRefs,
      roleRef: roleRef ?? null,
    };
  });

  for (const role of REQUIRED_CLINICAL_ROLES) {
    addReason(reasons, !seenRoles.has(role), `role_mapping_missing:${role}`);
  }

  return normalized.sort((left, right) => String(left.roleRef).localeCompare(String(right.roleRef)));
}

function normalizeActionMappings(policy, reasons) {
  const actionMappings = Array.isArray(policy?.actionMappings) ? policy.actionMappings : [];
  const seenActions = new Set();
  addReason(reasons, actionMappings.length === 0, 'authority_action_mappings_absent');

  const normalized = actionMappings.map((mapping) => {
    const actionRef = mapping?.actionRef;
    const requiredRoleRefs = sortedTextList(mapping?.requiredRoleRefs);

    addReason(reasons, !hasText(actionRef), 'authority_action_ref_absent');
    addReason(reasons, hasText(actionRef) && seenActions.has(actionRef), `authority_action_mapping_duplicate:${actionRef}`);
    if (hasText(actionRef)) {
      seenActions.add(actionRef);
    }
    addReason(reasons, !hasText(mapping?.requiredPermissionRef), `authority_action_permission_absent:${actionRef ?? 'unknown'}`);
    addReason(reasons, !AUTHORITY_MODES.has(mapping?.requiredAuthorityMode), `authority_action_mode_invalid:${actionRef ?? 'unknown'}`);
    addReason(reasons, requiredRoleRefs.length === 0, `authority_action_roles_absent:${actionRef ?? 'unknown'}`);
    addReason(reasons, !isDigest(mapping?.evidenceHash), `authority_action_evidence_hash_invalid:${actionRef ?? 'unknown'}`);
    addReason(reasons, mapping?.metadataOnly !== true, `authority_action_metadata_boundary_invalid:${actionRef ?? 'unknown'}`);
    if (mapping?.decisionForumRequired === true) {
      addReason(
        reasons,
        mapping?.requiredAuthorityMode !== 'governance_role',
        `authority_action_forum_mode_invalid:${actionRef ?? 'unknown'}`,
      );
    }

    return {
      actionRef: actionRef ?? null,
      consentRequired: mapping?.consentRequired === true,
      decisionForumRequired: mapping?.decisionForumRequired === true,
      evidenceHash: mapping?.evidenceHash ?? null,
      participantLinked: mapping?.participantLinked === true,
      requiredAuthorityMode: mapping?.requiredAuthorityMode ?? null,
      requiredPermissionRef: mapping?.requiredPermissionRef ?? null,
      requiredRoleRefs,
    };
  });

  for (const action of REQUIRED_AUTHORITY_ACTIONS) {
    addReason(reasons, !seenActions.has(action), `authority_action_mapping_missing:${action}`);
  }

  return normalized.sort((left, right) => String(left.actionRef).localeCompare(String(right.actionRef)));
}

function evaluateRequestedAction(input, actionMappings, reasons) {
  const action = actionMappings.find((mapping) => mapping.actionRef === input?.requestedAction) ?? null;
  addReason(reasons, action === null, 'requested_action_mapping_absent');
  if (action === null) {
    return null;
  }

  const actorRoleRefs = sortedTextList(input?.actor?.roleRefs);
  const actorHasRequiredRole = action.requiredRoleRefs.some((roleRef) => actorRoleRefs.includes(roleRef));
  addReason(reasons, !actorHasRequiredRole, 'requested_role_not_authorized');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authorityChain, action.requiredPermissionRef),
    `authority_permission_missing:${action.requiredPermissionRef}`,
  );

  return action;
}

function evaluateDelegation(input, reasons) {
  const delegation = input?.delegation;
  addReason(reasons, delegation?.status !== 'active', 'delegation_not_active');
  addReason(reasons, !hasText(delegation?.delegationRef), 'delegation_ref_absent');
  addReason(reasons, !hasText(delegation?.grantorDid), 'delegation_grantor_absent');
  addReason(reasons, !hasText(delegation?.granteeDid), 'delegation_grantee_absent');
  addReason(
    reasons,
    hasText(delegation?.granteeDid) && hasText(input?.actor?.did) && delegation.granteeDid !== input.actor.did,
    'delegation_grantee_actor_mismatch',
  );
  addReason(
    reasons,
    hasText(delegation?.grantorDid) && hasText(delegation?.granteeDid) && delegation.grantorDid === delegation.granteeDid,
    'delegation_self_grant_forbidden',
  );
  addReason(reasons, delegation?.revoked === true || delegation?.status === 'revoked', 'delegation_revoked');
  addReason(reasons, !Array.isArray(delegation?.scopeActionRefs), 'delegation_scope_absent');
  addReason(
    reasons,
    Array.isArray(delegation?.scopeActionRefs) && !delegation.scopeActionRefs.includes(input?.requestedAction),
    'delegation_action_scope_missing',
  );
  addReason(reasons, !isDigest(delegation?.evidenceHash), 'delegation_evidence_hash_invalid');
  addReason(reasons, hlcTuple(delegation?.startsAtHlc) === null, 'delegation_start_time_invalid');
  addReason(reasons, hlcTuple(delegation?.expiresAtHlc) === null, 'delegation_expiry_time_invalid');
  addReason(reasons, hlcBefore(input?.requestedAtHlc, delegation?.startsAtHlc), 'delegation_not_started');
  addReason(reasons, hlcBefore(delegation?.expiresAtHlc, input?.requestedAtHlc), 'delegation_expired');
  addReason(reasons, delegation?.metadataOnly !== true, 'delegation_metadata_boundary_invalid');
}

function evaluateAccessScope(input, action, reasons) {
  const scope = input?.accessScope;
  addReason(reasons, scope?.tenantRef !== input?.tenantId, 'scope_tenant_mismatch');
  addReason(reasons, !hasText(scope?.siteRef), 'scope_site_absent');
  addReason(reasons, !hasText(scope?.studyRef), 'scope_study_absent');
  addReason(reasons, !hasText(scope?.protocolRef), 'scope_protocol_absent');
  addReason(reasons, !SAFE_VISIBILITY_VALUES.has(scope?.sponsorVisibility), 'sponsor_visibility_unrestricted');
  addReason(reasons, !SAFE_VISIBILITY_VALUES.has(scope?.croVisibility), 'cro_visibility_unrestricted');
  addReason(reasons, !SAFE_CONFIDENTIALITY_VALUES.has(scope?.confidentialityClassification), 'confidentiality_scope_invalid');
  addReason(reasons, !SAFE_PHI_VALUES.has(scope?.phiPiiClassification), 'direct_identifier_scope_forbidden');
  addReason(reasons, !hasText(scope?.evidenceType), 'evidence_type_absent');
  addReason(reasons, action?.decisionForumRequired === true && !hasText(scope?.decisionMatterRef), 'decision_matter_absent');
  addReason(reasons, scope?.emergencyAccess === true && input?.requestedAction !== 'emergency_override', 'emergency_scope_invalid');
  addReason(reasons, hlcTuple(scope?.expiresAtHlc) === null, 'requested_scope_expiry_invalid');
  addReason(reasons, hlcBefore(scope?.expiresAtHlc, input?.requestedAtHlc), 'requested_scope_expired');
}

function evaluateConsentBoundary(input, action, reasons) {
  const consentRequired = action?.consentRequired === true || action?.participantLinked === true;
  const consent = input?.consentBoundary;
  if (!consentRequired && (consent === null || consent === undefined)) {
    return;
  }
  addReason(reasons, consentRequired && (consent === null || consent === undefined), 'consent_absent');
  addReason(reasons, consent?.status !== 'active', 'consent_not_active');
  addReason(reasons, consent?.revoked === true || consent?.status === 'revoked', 'consent_revoked');
  addReason(reasons, !hasText(consent?.consentRef), 'consent_ref_absent');
  addReason(reasons, !isDigest(consent?.evidenceHash), 'consent_evidence_hash_invalid');
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, sortedTextList(review?.reviewerRoleRefs).length === 0, 'human_reviewer_role_absent');
  addReason(reasons, review?.decision !== 'accepted_inactive_authority_policy', 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, input?.authorityPolicy?.evaluatedAtHlc), 'human_review_before_policy_eval');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, review?.decisionForum?.verified !== true, 'decision_forum_unverified');
  addReason(reasons, review?.decisionForum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, review?.decisionForum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, review?.decisionForum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, review?.decisionForum?.openChallenge === true, 'challenge_open');
}

function roleModeCounts(roleMappings) {
  return {
    aiAssistant: roleMappings.filter((mapping) => mapping.authorityMode === 'ai_assistant').length,
    governanceRole: roleMappings.filter((mapping) => mapping.authorityMode === 'governance_role').length,
    operationalPermission: roleMappings.filter((mapping) => mapping.authorityMode === 'operational_permission').length,
  };
}

function authorityPolicyDigestMaterial(input, roleMappings, actionMappings) {
  return {
    actionMappings,
    activationGateIds: [REQUIRED_ACTIVATION_GATE],
    bobEscalationIds: [REQUIRED_BOB_ESCALATION],
    policyHash: input.authorityPolicy.policyHash,
    policyRef: input.authorityPolicy.policyRef,
    permissionDimensions: REQUIRED_PERMISSION_DIMENSIONS,
    requestedAction: input.requestedAction,
    roleMappings,
    schema: POLICY_SCHEMA,
    targetTenantId: input.targetTenantId,
    tenantId: input.tenantId,
  };
}

function buildAuthorityPolicy(input, roleMappings, actionMappings, action, policyDigest, receiptId) {
  const scopeDigest = sha256Hex({
    accessScope: {
      confidentialityClassification: input.accessScope.confidentialityClassification,
      croVisibility: input.accessScope.croVisibility,
      decisionMatterRef: input.accessScope.decisionMatterRef,
      emergencyAccess: input.accessScope.emergencyAccess,
      evidenceType: input.accessScope.evidenceType,
      expiresAtHlc: input.accessScope.expiresAtHlc,
      phiPiiClassification: input.accessScope.phiPiiClassification,
      protocolRef: input.accessScope.protocolRef,
      siteRef: input.accessScope.siteRef,
      sponsorVisibility: input.accessScope.sponsorVisibility,
      studyRef: input.accessScope.studyRef,
      tenantRef: input.accessScope.tenantRef,
    },
    schema: 'cybermedica.clinical_authority_scope.v1',
  });

  return {
    schema: POLICY_SCHEMA,
    activationGateIds: [REQUIRED_ACTIVATION_GATE],
    authorityActions: [...REQUIRED_AUTHORITY_ACTIONS],
    bobEscalationIds: [REQUIRED_BOB_ESCALATION],
    clinicalRoles: [...REQUIRED_CLINICAL_ROLES],
    consentBoundaryRef: input.consentBoundary?.consentRef ?? null,
    exochainProductionClaim: false,
    metadataOnly: true,
    permissionDimensions: [...REQUIRED_PERMISSION_DIMENSIONS],
    policyDigest,
    policyHash: input.authorityPolicy.policyHash,
    policyRef: input.authorityPolicy.policyRef,
    receiptId,
    requestedActionAuthorized: action !== null,
    requestedActionRef: input.requestedAction,
    roleMatrixApprovalState: 'requires_bob_approval',
    roleModeCounts: roleModeCounts(roleMappings),
    scopeDigest,
    trustState: 'inactive',
  };
}

function buildReceipt(input, policyDigest) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'clinical_authority_policy',
    artifactVersion: `${input.authorityPolicy.policyRef}@${input.requestedAction}`,
    artifactHash: policyDigest,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['authority', 'clinical_role_matrix', 'metadata_only', 'ptag_010'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function evaluateClinicalAuthorityPolicy(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  validatePolicyHeader(input?.authorityPolicy, reasons);
  validateRequiredCoverage(input?.authorityPolicy, reasons);
  const roleMappings = normalizeRoleMappings(input?.authorityPolicy, reasons);
  const actionMappings = normalizeActionMappings(input?.authorityPolicy, reasons);
  const requestedAction = evaluateRequestedAction(input, actionMappings, reasons);
  evaluateDelegation(input, reasons);
  evaluateAccessScope(input, requestedAction, reasons);
  evaluateConsentBoundary(input, requestedAction, reasons);
  evaluateHumanReview(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const uniqueReasons = uniqueSorted(reasons);
  const denied = uniqueReasons.length > 0;
  if (denied) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      authorityPolicy: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const policyDigest = sha256Hex(authorityPolicyDigestMaterial(input, roleMappings, actionMappings));
  const receipt = buildReceipt(input, policyDigest);
  const authorityPolicy = buildAuthorityPolicy(input, roleMappings, actionMappings, requestedAction, policyDigest, receipt.receiptId);

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    authorityPolicy,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
