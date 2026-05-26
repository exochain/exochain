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
const SECURITY_PRIVACY_SCHEMA = 'cybermedica.security_privacy_readiness.v1';
const REQUIRED_PERMISSION = 'security_privacy_review';

const REQUIRED_SECURITY_CONTROLS = Object.freeze([
  'abac',
  'audit_logging',
  'encryption_at_rest',
  'encryption_in_transit',
  'identity_provider_integration',
  'least_privilege',
  'mfa_support',
  'rbac',
  'secrets_management',
  'security_monitoring',
  'session_controls',
]);

const REQUIRED_PRIVACY_CONTROLS = Object.freeze([
  'access_restrictions',
  'consent_tracking',
  'data_minimization',
  'disclosure_logging',
  'gdpr_configuration',
  'hipaa_configuration',
  'protected_data_classification',
  'retention_policy',
]);

const REQUIRED_SECURITY_SIGNALS = Object.freeze([
  'adapter_failure',
  'authentication',
  'authorization',
  'export_disclosure',
  'privileged_action',
  'secret_rotation',
]);

const VERIFIED_STATUSES = new Set(['verified']);
const ACTIVE_STATUSES = new Set(['active']);
const POLICY_STATUSES = new Set(['active']);
const HUMAN_REVIEW_DECISIONS = new Set(['accepted_inactive_trust', 'hold_for_security_privacy_gap']);
const SECRET_SCOPES = new Set(['cybermedica_only', 'tenant_scoped_cybermedica']);
const DEPENDENCY_AUDIT_STATUSES = new Set(['passed']);
const SECRET_SCAN_STATUSES = new Set(['passed']);
const MAX_SESSION_EXPIRY_MINUTES = 480;

const RAW_SECURITY_PRIVACY_FIELDS = new Set([
  'body',
  'content',
  'freetext',
  'privacyassessmentbody',
  'privacynarrative',
  'rawaccesslog',
  'rawauditlog',
  'rawclassification',
  'rawconfiguration',
  'rawcontrol',
  'rawcontrolbody',
  'rawevidence',
  'rawincident',
  'rawmonitoringdata',
  'rawprivacycontent',
  'rawprivacynarrative',
  'rawsecuritycontent',
  'rawsecuritynarrative',
  'rawsessionlog',
  'rawsourcecontent',
  'reviewnotes',
  'securitynarrative',
  'sourcebody',
  'sourcedocumentbody',
]);

const SECRET_SECURITY_PRIVACY_FIELDS = new Set([
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

function assertNoRawSecurityPrivacyContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawSecurityPrivacyContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_SECURITY_PRIVACY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw security privacy content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_SECURITY_PRIVACY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`security privacy secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawSecurityPrivacyContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawSecurityPrivacyContent(input ?? {});
  canonicalize(input ?? {});
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function integerBasisPoints(present, total) {
  if (!Number.isSafeInteger(present) || !Number.isSafeInteger(total) || total <= 0 || present <= 0) {
    return 0;
  }
  return Number((BigInt(present) * 10000n) / BigInt(total));
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
  let latest = null;
  for (const hlc of values) {
    const tuple = hlcTuple(hlc);
    if (tuple === null) {
      continue;
    }
    if (latest === null || compareHlc(tuple, latest) > 0) {
      latest = tuple;
    }
  }
  return latest === null ? null : { physicalMs: latest[0], logical: latest[1] };
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_security_privacy_reviewer_required');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'security_privacy_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateSecurityPolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'security_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'security_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'security_policy_not_active');
  addReason(reasons, policy?.encryptionInTransitRequired !== true, 'security_policy_encryption_in_transit_absent');
  addReason(reasons, policy?.encryptionAtRestRequired !== true, 'security_policy_encryption_at_rest_absent');
  addReason(reasons, policy?.secretManagerRequired !== true, 'security_policy_secret_manager_absent');
  addReason(reasons, policy?.roleBasedAccessRequired !== true, 'security_policy_rbac_absent');
  addReason(reasons, policy?.attributeBasedAccessRequired !== true, 'security_policy_abac_absent');
  addReason(reasons, policy?.leastPrivilegeRequired !== true, 'security_policy_least_privilege_absent');
  addReason(reasons, policy?.mfaSupported !== true, 'security_policy_mfa_absent');
  addReason(reasons, policy?.identityProviderRequired !== true, 'security_policy_identity_provider_absent');
  addReason(reasons, policy?.sessionControlRequired !== true, 'security_policy_session_controls_absent');
  addReason(reasons, policy?.auditLoggingRequired !== true, 'security_policy_audit_logging_absent');
  addReason(reasons, policy?.securityMonitoringRequired !== true, 'security_policy_monitoring_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'security_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'security_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'security_policy_time_invalid');
}

function evaluatePrivacyPolicy(policy, reasons) {
  const frameworks = sortedTextList(policy?.supportedFrameworks);
  addReason(reasons, !hasText(policy?.policyRef), 'privacy_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'privacy_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'privacy_policy_not_active');
  addReason(reasons, !frameworks.includes('hipaa'), 'privacy_policy_hipaa_absent');
  addReason(reasons, !frameworks.includes('gdpr'), 'privacy_policy_gdpr_absent');
  addReason(reasons, policy?.dataMinimizationRequired !== true, 'privacy_policy_data_minimization_absent');
  addReason(reasons, policy?.accessRestrictionsRequired !== true, 'privacy_policy_access_restrictions_absent');
  addReason(reasons, policy?.consentTrackingRequired !== true, 'privacy_policy_consent_tracking_absent');
  addReason(reasons, policy?.retentionPolicyRequired !== true, 'privacy_policy_retention_absent');
  addReason(reasons, policy?.disclosureLoggingRequired !== true, 'privacy_policy_disclosure_logging_absent');
  addReason(reasons, policy?.protectedDataClassificationRequired !== true, 'privacy_policy_classification_absent');
  addReason(reasons, policy?.rawPhiAnchoringAllowed !== false, 'privacy_policy_raw_phi_anchoring_not_denied');
  addReason(reasons, policy?.metadataOnly !== true, 'privacy_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'privacy_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'privacy_policy_time_invalid');
}

function evaluateControlSet(controls, requiredControls, prefix, reasons) {
  const byFamily = new Map();
  for (const control of Array.isArray(controls) ? controls : []) {
    if (hasText(control?.controlFamily) && !byFamily.has(control.controlFamily)) {
      byFamily.set(control.controlFamily, control);
    }
  }

  for (const controlFamily of requiredControls) {
    const control = byFamily.get(controlFamily);
    addReason(reasons, control === undefined, `missing_${prefix}_control:${controlFamily}`);
    if (control === undefined) {
      continue;
    }
    addReason(reasons, !hasText(control.controlRef), `${prefix}_control_ref_absent:${controlFamily}`);
    addReason(reasons, !isDigest(control.controlHash), `${prefix}_control_hash_invalid:${controlFamily}`);
    addReason(reasons, !isDigest(control.evidenceHash), `${prefix}_control_evidence_hash_invalid:${controlFamily}`);
    addReason(reasons, !VERIFIED_STATUSES.has(control.status), `${prefix}_control_not_verified:${controlFamily}`);
    addReason(reasons, !hasText(control.ownerDid), `${prefix}_control_owner_absent:${controlFamily}`);
    addReason(reasons, control.failClosed !== true, `${prefix}_control_fail_closed_absent:${controlFamily}`);
    addReason(reasons, control.metadataOnly !== true, `${prefix}_control_metadata_boundary_invalid:${controlFamily}`);
    addReason(reasons, control.productionTrustClaim === true, `${prefix}_control_production_claim_forbidden:${controlFamily}`);
    addReason(reasons, hlcTuple(control.reviewedAtHlc) === null, `${prefix}_control_review_time_invalid:${controlFamily}`);
  }

  for (const controlFamily of byFamily.keys()) {
    addReason(reasons, !requiredControls.includes(controlFamily), `unsupported_${prefix}_control:${controlFamily}`);
  }

  return [...requiredControls].filter((controlFamily) => {
    const control = byFamily.get(controlFamily);
    return (
      control !== undefined &&
      isDigest(control.controlHash) &&
      isDigest(control.evidenceHash) &&
      VERIFIED_STATUSES.has(control.status) &&
      hasText(control.ownerDid) &&
      control.failClosed === true &&
      control.metadataOnly === true &&
      control.productionTrustClaim !== true &&
      hlcTuple(control.reviewedAtHlc) !== null
    );
  });
}

function evaluateAccessModel(model, reasons) {
  addReason(reasons, !VERIFIED_STATUSES.has(model?.status), 'access_model_not_verified');
  addReason(reasons, !isDigest(model?.rbacPolicyHash), 'rbac_policy_hash_invalid');
  addReason(reasons, !isDigest(model?.abacPolicyHash), 'abac_policy_hash_invalid');
  addReason(reasons, !isDigest(model?.leastPrivilegeMatrixHash), 'least_privilege_matrix_hash_invalid');
  addReason(reasons, !isDigest(model?.privilegedRoleReviewHash), 'privileged_role_review_hash_invalid');
  addReason(reasons, !isDigest(model?.separationOfPowersHash), 'separation_of_powers_hash_invalid');
  addReason(reasons, !isDigest(model?.emergencyAccessPolicyHash), 'emergency_access_policy_hash_invalid');
  addReason(reasons, model?.noSharedRootCredentials !== true, 'shared_root_credentials_not_denied');
  addReason(reasons, model?.metadataOnly !== true, 'access_model_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(model?.reviewedAtHlc) === null, 'access_model_time_invalid');
}

function evaluateIdentitySession(identitySession, reasons) {
  addReason(reasons, !VERIFIED_STATUSES.has(identitySession?.status), 'identity_session_not_verified');
  addReason(reasons, !hasText(identitySession?.identityProviderRef), 'identity_provider_ref_absent');
  addReason(reasons, !isDigest(identitySession?.identityProviderEvidenceHash), 'identity_provider_evidence_hash_invalid');
  addReason(reasons, !isDigest(identitySession?.mfaPolicyHash), 'mfa_policy_hash_invalid');
  addReason(reasons, !isDigest(identitySession?.sessionPolicyHash), 'session_policy_hash_invalid');
  addReason(
    reasons,
    !isPositiveSafeInteger(identitySession?.sessionExpiryMinutes) ||
      identitySession.sessionExpiryMinutes > MAX_SESSION_EXPIRY_MINUTES,
    'session_expiry_invalid',
  );
  addReason(reasons, identitySession?.staleSessionRevocation !== true, 'stale_session_revocation_absent');
  addReason(reasons, !isDigest(identitySession?.serviceAccountInventoryHash), 'service_account_inventory_hash_invalid');
  addReason(reasons, identitySession?.metadataOnly !== true, 'identity_session_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(identitySession?.reviewedAtHlc) === null, 'identity_session_time_invalid');
}

function evaluateSecretsOperations(secrets, reasons) {
  addReason(reasons, !VERIFIED_STATUSES.has(secrets?.status), 'secrets_operations_not_verified');
  addReason(reasons, !hasText(secrets?.secretManagerRef), 'secret_manager_ref_absent');
  addReason(reasons, !SECRET_SCOPES.has(secrets?.secretScope), 'secret_scope_invalid');
  addReason(reasons, secrets?.rootSigningKeysSeparated !== true, 'root_signing_keys_not_separated');
  addReason(reasons, secrets?.bootstrapTokensAbsentFromRuntime !== true, 'bootstrap_tokens_not_excluded');
  addReason(reasons, secrets?.missingSecretsFailClosed !== true, 'missing_secrets_fail_closed_absent');
  addReason(reasons, !isDigest(secrets?.rotationPolicyHash), 'rotation_policy_hash_invalid');
  addReason(reasons, !isDigest(secrets?.lastRotationEvidenceHash), 'last_rotation_evidence_hash_invalid');
  addReason(reasons, secrets?.secretScanPassed !== true, 'secret_scan_not_passed');
  addReason(reasons, secrets?.metadataOnly !== true, 'secrets_operations_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(secrets?.reviewedAtHlc) === null, 'secrets_operations_time_invalid');
}

function evaluatePrivacyBoundary(boundary, reasons) {
  addReason(reasons, !VERIFIED_STATUSES.has(boundary?.status), 'privacy_boundary_not_verified');
  addReason(reasons, !isDigest(boundary?.classificationModelHash), 'classification_model_hash_invalid');
  addReason(reasons, !isDigest(boundary?.dataMinimizationHash), 'data_minimization_hash_invalid');
  addReason(reasons, !isDigest(boundary?.consentTrackingHash), 'consent_tracking_hash_invalid');
  addReason(reasons, !isDigest(boundary?.retentionRuleHash), 'retention_rule_hash_invalid');
  addReason(reasons, !isDigest(boundary?.disclosureLogHash), 'disclosure_log_hash_invalid');
  addReason(reasons, !isDigest(boundary?.accessRestrictionHash), 'access_restriction_hash_invalid');
  addReason(reasons, !isDigest(boundary?.deidentificationPolicyHash), 'deidentification_policy_hash_invalid');
  addReason(reasons, !isDigest(boundary?.anchorMetadataPolicyHash), 'anchor_metadata_policy_hash_invalid');
  addReason(reasons, boundary?.rawPhiAnchoringAllowed !== false, 'privacy_boundary_raw_phi_anchoring_not_denied');
  addReason(reasons, boundary?.protectedContentExcluded !== true, 'privacy_boundary_protected_content_not_excluded');
  addReason(reasons, boundary?.payloadsRemainExternal !== true, 'privacy_boundary_payload_externality_absent');
  addReason(reasons, boundary?.metadataOnly !== true, 'privacy_boundary_metadata_invalid');
  addReason(reasons, hlcTuple(boundary?.reviewedAtHlc) === null, 'privacy_boundary_time_invalid');
}

function evaluateMonitoring(monitoring, reasons) {
  const signals = sortedTextList(monitoring?.securitySignalCoverage);
  addReason(reasons, !ACTIVE_STATUSES.has(monitoring?.status), 'security_monitoring_not_active');
  addReason(reasons, !hasText(monitoring?.monitorRef), 'security_monitor_ref_absent');
  for (const signal of REQUIRED_SECURITY_SIGNALS) {
    addReason(reasons, !signals.includes(signal), `missing_security_signal:${signal}`);
  }
  for (const signal of signals) {
    addReason(reasons, !REQUIRED_SECURITY_SIGNALS.includes(signal), `unsupported_security_signal:${signal}`);
  }
  addReason(reasons, !isDigest(monitoring?.alertRouteHash), 'security_alert_route_hash_invalid');
  addReason(reasons, !isDigest(monitoring?.incidentResponseHash), 'security_incident_response_hash_invalid');
  addReason(reasons, !isDigest(monitoring?.auditEventHash), 'security_audit_event_hash_invalid');
  addReason(reasons, monitoring?.protectedContentExcluded !== true, 'security_monitoring_protected_boundary_invalid');
  addReason(reasons, monitoring?.metadataOnly !== true, 'security_monitoring_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(monitoring?.evaluatedAtHlc) === null, 'security_monitoring_time_invalid');
}

function evaluateValidationEvidence(validation, reasons) {
  const commandRefs = sortedTextList(validation?.commandRefs);
  addReason(reasons, !commandRefs.includes('npm test'), 'validation_npm_test_absent');
  addReason(reasons, !commandRefs.includes('npm run quality'), 'validation_quality_gate_absent');
  addReason(reasons, !commandRefs.includes('secret scan'), 'validation_secret_scan_command_absent');
  addReason(reasons, !commandRefs.includes('dependency audit'), 'validation_dependency_audit_command_absent');
  addReason(reasons, validation?.commandsPassed !== true, 'validation_commands_not_passed');
  addReason(reasons, !DEPENDENCY_AUDIT_STATUSES.has(validation?.dependencyAuditStatus), 'dependency_audit_not_passed');
  addReason(reasons, !SECRET_SCAN_STATUSES.has(validation?.secretScanStatus), 'validation_secret_scan_not_passed');
  addReason(reasons, validation?.sourceGuardPassed !== true, 'validation_source_guard_not_passed');
  addReason(reasons, !isBasisPoints(validation?.coverageLineBasisPoints), 'validation_coverage_invalid');
  addReason(reasons, validation?.coverageLineBasisPoints < 9000, 'validation_coverage_below_threshold');
  addReason(reasons, !isDigest(validation?.testEvidenceHash), 'validation_test_evidence_hash_invalid');
  addReason(reasons, validation?.noExochainSourceModified !== true, 'validation_exochain_source_modified');
  addReason(reasons, validation?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(validation?.recordedAtHlc) === null, 'validation_time_invalid');
}

function evaluateHumanReview(review, reasons) {
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, !Array.isArray(review?.reviewerRoleRefs) || review.reviewerRoleRefs.length === 0, 'human_review_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'production_trust_claim_forbidden');
  addReason(reasons, review?.aiFinalAuthority === true, 'human_review_ai_final_authority_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance === null || aiAssistance === undefined || aiAssistance.used !== true) {
    return;
  }
  addReason(reasons, aiAssistance.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, aiAssistance.reviewedByHuman !== true, 'ai_recommendation_without_human_review');
  addReason(reasons, !isDigest(aiAssistance.recommendationHash), 'ai_recommendation_hash_invalid');
  for (const hash of Array.isArray(aiAssistance.limitationHashes) ? aiAssistance.limitationHashes : []) {
    addReason(reasons, !isDigest(hash), 'ai_limitation_hash_invalid');
  }
}

function evaluateHlcOrdering(input, latestReview, reasons) {
  addReason(
    reasons,
    !hlcAfter(input?.monitoringEvidence?.evaluatedAtHlc, input?.securityPolicy?.evaluatedAtHlc),
    'monitoring_before_security_policy',
  );
  addReason(
    reasons,
    latestReview === null || !hlcAfter(input?.validationEvidence?.recordedAtHlc, latestReview),
    'validation_before_evidence_reviews',
  );
  addReason(
    reasons,
    !hlcAfter(input?.humanReview?.reviewedAtHlc, input?.validationEvidence?.recordedAtHlc),
    'human_review_before_validation',
  );
}

function buildLatestReviewHlc(input) {
  return latestHlc([
    ...(Array.isArray(input?.securityControls) ? input.securityControls.map((control) => control?.reviewedAtHlc) : []),
    ...(Array.isArray(input?.privacyControls) ? input.privacyControls.map((control) => control?.reviewedAtHlc) : []),
    input?.accessModel?.reviewedAtHlc,
    input?.identitySession?.reviewedAtHlc,
    input?.secretsOperations?.reviewedAtHlc,
    input?.privacyBoundary?.reviewedAtHlc,
    input?.monitoringEvidence?.evaluatedAtHlc,
  ]);
}

function buildReadinessRecord(input, securityCovered, privacyCovered, blockedBy, securityReadinessBasisPoints, privacyReadinessBasisPoints) {
  return {
    schema: SECURITY_PRIVACY_SCHEMA,
    tenantId: input?.tenantId ?? null,
    securityPolicyRef: input?.securityPolicy?.policyRef ?? null,
    privacyPolicyRef: input?.privacyPolicy?.policyRef ?? null,
    coveredSecurityControls: uniqueSorted(securityCovered),
    coveredPrivacyControls: uniqueSorted(privacyCovered),
    securityReadinessBasisPoints,
    privacyReadinessBasisPoints,
    securitySignalCoverage: sortedTextList(input?.monitoringEvidence?.securitySignalCoverage),
    validationCommandRefs: sortedTextList(input?.validationEvidence?.commandRefs),
    blockedBy: uniqueSorted(blockedBy),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

export function evaluateSecurityPrivacyReadiness(input = {}) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateSecurityPolicy(input?.securityPolicy, reasons);
  evaluatePrivacyPolicy(input?.privacyPolicy, reasons);
  const securityCovered = evaluateControlSet(input?.securityControls, REQUIRED_SECURITY_CONTROLS, 'security', reasons);
  const privacyCovered = evaluateControlSet(input?.privacyControls, REQUIRED_PRIVACY_CONTROLS, 'privacy', reasons);
  evaluateAccessModel(input?.accessModel, reasons);
  evaluateIdentitySession(input?.identitySession, reasons);
  evaluateSecretsOperations(input?.secretsOperations, reasons);
  evaluatePrivacyBoundary(input?.privacyBoundary, reasons);
  evaluateMonitoring(input?.monitoringEvidence, reasons);
  evaluateValidationEvidence(input?.validationEvidence, reasons);
  evaluateHumanReview(input?.humanReview, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const latestReview = buildLatestReviewHlc(input);
  evaluateHlcOrdering(input, latestReview, reasons);

  const blockedBy = uniqueSorted(reasons);
  const securityReadinessBasisPoints = integerBasisPoints(securityCovered.length, REQUIRED_SECURITY_CONTROLS.length);
  const privacyReadinessBasisPoints = integerBasisPoints(privacyCovered.length, REQUIRED_PRIVACY_CONTROLS.length);
  const readinessRecord = buildReadinessRecord(
    input,
    securityCovered,
    privacyCovered,
    blockedBy,
    securityReadinessBasisPoints,
    privacyReadinessBasisPoints,
  );
  const readinessHash = sha256Hex(readinessRecord);
  const allowed = blockedBy.length === 0;

  return {
    schema: SECURITY_PRIVACY_SCHEMA,
    allowed,
    state: allowed ? 'ready_inactive_trust' : 'denied',
    trustState: 'inactive',
    exochainProductionClaim: false,
    blockedBy,
    readinessHash,
    securityReadinessBasisPoints,
    privacyReadinessBasisPoints,
    security: {
      requiredControlFamilies: [...REQUIRED_SECURITY_CONTROLS],
      coveredControlFamilies: uniqueSorted(securityCovered),
      missingControlFamilies: REQUIRED_SECURITY_CONTROLS.filter((controlFamily) => !securityCovered.includes(controlFamily)),
    },
    privacy: {
      requiredControlFamilies: [...REQUIRED_PRIVACY_CONTROLS],
      coveredControlFamilies: uniqueSorted(privacyCovered),
      missingControlFamilies: REQUIRED_PRIVACY_CONTROLS.filter((controlFamily) => !privacyCovered.includes(controlFamily)),
    },
    monitoring: {
      requiredSignalFamilies: [...REQUIRED_SECURITY_SIGNALS],
      coveredSignalFamilies: sortedTextList(input?.monitoringEvidence?.securitySignalCoverage),
    },
    receipt: allowed
      ? createEvidenceReceipt({
          tenantId: input.tenantId,
          actorDid: input.actor.did,
          artifactType: 'security_privacy_readiness',
          artifactVersion: 'security-privacy-readiness:v1',
          artifactHash: readinessHash,
          custodyDigest: input.custodyDigest,
          classification: 'confidential_metadata_only',
          sensitivityTags: ['privacy_metadata', 'security_metadata'],
          sourceSystem: 'cybermedica-qms',
          hlcTimestamp: input.humanReview.reviewedAtHlc,
        })
      : null,
  };
}
