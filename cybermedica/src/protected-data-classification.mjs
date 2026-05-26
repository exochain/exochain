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
const CLASSIFICATION_SCHEMA = 'cybermedica.protected_data_classification.v1';
const REQUIRED_PERMISSION = 'classify_data';

const REQUIRED_DATA_CLASSES = Object.freeze([
  'decision_governance',
  'immutable_receipt',
  'participant_linked_phi_pii',
  'public_non_sensitive',
  'quality_evidence',
  'sponsor_cro_confidential',
  'tenant_operational',
]);

const REQUIRED_DIMENSIONS = Object.freeze([
  'access_policy',
  'confidentiality',
  'export_eligibility',
  'participant_linkage',
  'phi_pii_status',
  'retention_rule',
  'sponsor_confidentiality',
]);

const POLICY_STATUSES = new Set(['active']);
const ACTOR_KINDS = new Set(['human', 'service_account']);
const HUMAN_REVIEW_DECISIONS = new Set(['classification_model_ready', 'classification_model_hold']);

const PARTICIPANT_EXPORT_GUARDS = new Set(['consent_and_disclosure_grant_required', 'consent_required']);
const PARTICIPANT_ANCHOR_POLICIES = new Set(['no_raw_anchor_hash_reference_only', 'receipt_metadata_only']);
const SPONSOR_CONFIDENTIALITY_VALUES = new Set(['restricted', 'study_scoped', 'tenant_scoped']);
const SPONSOR_ANCHOR_POLICIES = new Set(['no_sponsor_body_anchor', 'hash_only_receipt_allowed']);
const IMMUTABLE_RECEIPT_ANCHOR_POLICIES = new Set(['receipt_metadata_only']);

const RAW_CLASSIFICATION_FIELDS = new Set([
  'body',
  'clinicalnote',
  'content',
  'freetext',
  'participantlisting',
  'participantnarrative',
  'participantnote',
  'protectedcontent',
  'rawclassification',
  'rawclinicalrecord',
  'rawcontent',
  'rawparticipant',
  'rawparticipantnote',
  'rawphipayload',
  'rawpiipayload',
  'rawsponsorbody',
  'rawsourcecontent',
  'reviewnotes',
  'sourcebody',
  'sourcedocumentbody',
  'sponsorbudgettext',
  'sponsorconfidentialbody',
]);

const SECRET_CLASSIFICATION_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'bootstrapsecret',
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

function assertNoRawClassificationContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawClassificationContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_CLASSIFICATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw protected classification content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_CLASSIFICATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`classification secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawClassificationContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawClassificationContent(input ?? {});
  canonicalize(input ?? {});
}

function sortedTextList(values) {
  return Array.isArray(values) ? [...new Set(values.filter(hasText))].sort() : [];
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
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

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlcTuple(leftTuple, rightTuple) > 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function includesAll(needles, haystack) {
  const haystackValues = sortedTextList(haystack);
  return needles.every((needle) => haystackValues.includes(needle));
}

function firstRulesByDataClass(rules, reasons) {
  const output = {};
  if (!Array.isArray(rules)) {
    return output;
  }
  for (const rule of rules) {
    if (!hasText(rule?.dataClass)) {
      reasons.push('data_class_absent');
      continue;
    }
    if (output[rule.dataClass] !== undefined) {
      reasons.push(`data_class_duplicate:${rule.dataClass}`);
      continue;
    }
    output[rule.dataClass] = rule;
  }
  return output;
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, !ACTOR_KINDS.has(input?.actor?.kind), 'actor_kind_invalid');
  addReason(
    reasons,
    input?.actor?.kind === 'service_account' && !hasText(input?.actor?.humanOwnerDid),
    'service_account_human_owner_absent',
  );
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'classification_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateClassificationPolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'classification_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'classification_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'classification_policy_not_active');
  addReason(reasons, policy?.defaultDenyUnclassified !== true, 'default_deny_unclassified_absent');
  addReason(reasons, policy?.rawProtectedContentForbidden !== true, 'raw_protected_content_policy_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'classification_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'classification_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'classification_policy_evaluation_time_invalid');

  for (const dataClass of REQUIRED_DATA_CLASSES) {
    addReason(
      reasons,
      !sortedTextList(policy?.requiredDataClasses).includes(dataClass),
      `policy_required_data_class_missing:${dataClass}`,
    );
  }
  for (const dimension of REQUIRED_DIMENSIONS) {
    addReason(
      reasons,
      !sortedTextList(policy?.requiredDimensions).includes(dimension),
      `policy_required_dimension_missing:${dimension}`,
    );
  }
}

function evaluateClassificationModel(input, reasons) {
  const model = input?.classificationModel;
  addReason(reasons, !hasText(model?.modelRef), 'classification_model_ref_absent');
  addReason(reasons, !hasText(model?.modelVersion), 'classification_model_version_absent');
  addReason(reasons, !isDigest(model?.modelHash), 'classification_model_hash_invalid');
  addReason(reasons, model?.approvedByHuman !== true, 'classification_model_human_approval_absent');
  addReason(reasons, hlcTuple(model?.approvedAtHlc) === null, 'classification_model_approval_time_invalid');
  addReason(
    reasons,
    hlcBefore(model?.approvedAtHlc, input?.classificationPolicy?.evaluatedAtHlc),
    'model_approval_before_policy',
  );
  addReason(reasons, !hasText(model?.rollbackVersionRef), 'classification_model_rollback_ref_absent');
  addReason(reasons, model?.noProductionTrustClaim !== true, 'production_trust_claim_forbidden');
  addReason(reasons, model?.metadataOnly !== true, 'classification_model_metadata_boundary_invalid');
  addReason(reasons, model?.protectedContentExcluded !== true, 'classification_model_protected_boundary_invalid');
}

function evaluateGenericClassRule(rule, reasons) {
  const dataClass = rule?.dataClass;
  addReason(reasons, !hasText(rule?.classificationId), `class_id_absent:${dataClass}`);
  addReason(reasons, !hasText(rule?.confidentialityLevel), `class_confidentiality_absent:${dataClass}`);
  addReason(reasons, !hasText(rule?.phiPiiStatus), `class_phi_pii_status_absent:${dataClass}`);
  addReason(reasons, !hasText(rule?.sponsorConfidentiality), `class_sponsor_confidentiality_absent:${dataClass}`);
  addReason(reasons, !hasText(rule?.participantLinkage), `class_participant_linkage_absent:${dataClass}`);
  addReason(reasons, !hasText(rule?.exportEligibility), `class_export_eligibility_absent:${dataClass}`);
  addReason(reasons, !hasText(rule?.retentionRuleRef), `class_retention_rule_absent:${dataClass}`);
  addReason(reasons, !hasText(rule?.accessPolicyRef), `class_access_policy_absent:${dataClass}`);
  addReason(reasons, !hasText(rule?.anchoringPolicy), `class_anchor_policy_absent:${dataClass}`);
  addReason(reasons, !isDigest(rule?.evidenceHash), `class_evidence_hash_invalid:${dataClass}`);
  addReason(reasons, rule?.metadataOnly !== true, `class_metadata_boundary_invalid:${dataClass}`);
  addReason(reasons, rule?.protectedContentExcluded !== true, `class_protected_boundary_invalid:${dataClass}`);
  addReason(reasons, rule?.rawContentInReceiptAllowed === true, `class_receipt_raw_content_allowed:${dataClass}`);
  addReason(reasons, rule?.externalPayloadsRemainControlled !== true, `class_payload_boundary_invalid:${dataClass}`);
  addReason(reasons, hlcTuple(rule?.reviewedAtHlc) === null, `class_review_time_invalid:${dataClass}`);
  for (const dimension of REQUIRED_DIMENSIONS) {
    addReason(
      reasons,
      !sortedTextList(rule?.dimensionCoverage).includes(dimension),
      `class_dimension_missing:${dataClass}:${dimension}`,
    );
  }
}

function evaluateParticipantClass(rule, reasons) {
  if (rule === undefined) {
    return;
  }
  addReason(reasons, rule.rawContentInReceiptAllowed === true, 'participant_class_receipt_raw_content_allowed');
  addReason(reasons, rule.externalPayloadsRemainControlled !== true, 'participant_class_payload_boundary_invalid');
  addReason(
    reasons,
    !PARTICIPANT_EXPORT_GUARDS.has(rule.exportEligibility),
    'participant_class_export_guard_invalid',
  );
  addReason(
    reasons,
    !PARTICIPANT_ANCHOR_POLICIES.has(rule.anchoringPolicy),
    'participant_class_anchor_policy_invalid',
  );
  addReason(reasons, !hasText(rule.accessPolicyRef), 'participant_class_access_policy_absent');
  addReason(reasons, !hasText(rule.retentionRuleRef), 'participant_class_retention_rule_absent');
}

function evaluateSponsorClass(rule, reasons) {
  if (rule === undefined) {
    return;
  }
  addReason(
    reasons,
    !SPONSOR_CONFIDENTIALITY_VALUES.has(rule.sponsorConfidentiality),
    'sponsor_class_confidentiality_invalid',
  );
  addReason(reasons, !SPONSOR_ANCHOR_POLICIES.has(rule.anchoringPolicy), 'sponsor_class_anchor_policy_invalid');
}

function evaluateImmutableReceiptClass(rule, reasons) {
  if (rule === undefined) {
    return;
  }
  addReason(reasons, rule.metadataOnly !== true, 'immutable_receipt_metadata_boundary_invalid');
  addReason(
    reasons,
    !IMMUTABLE_RECEIPT_ANCHOR_POLICIES.has(rule.anchoringPolicy),
    'immutable_receipt_anchor_policy_invalid',
  );
  addReason(reasons, rule.rawContentInReceiptAllowed === true, 'immutable_receipt_raw_content_allowed');
}

function evaluateClassRules(input, reasons) {
  const byDataClass = firstRulesByDataClass(input?.classRules, reasons);
  for (const dataClass of REQUIRED_DATA_CLASSES) {
    const rule = byDataClass[dataClass];
    addReason(reasons, rule === undefined, `data_class_missing:${dataClass}`);
    if (rule !== undefined) {
      evaluateGenericClassRule(rule, reasons);
    }
  }
  evaluateParticipantClass(byDataClass.participant_linked_phi_pii, reasons);
  evaluateSponsorClass(byDataClass.sponsor_cro_confidential, reasons);
  evaluateImmutableReceiptClass(byDataClass.immutable_receipt, reasons);
  return byDataClass;
}

function evaluateReceiptBoundary(boundary, reasons) {
  addReason(reasons, !hasText(boundary?.boundaryRef), 'receipt_boundary_ref_absent');
  addReason(reasons, !isDigest(boundary?.boundaryHash), 'receipt_boundary_hash_invalid');
  addReason(reasons, boundary?.directIdentifierAnchorForbidden !== true, 'receipt_direct_identifier_anchor_not_forbidden');
  addReason(
    reasons,
    boundary?.sponsorConfidentialBodyAnchorForbidden !== true,
    'receipt_sponsor_confidential_anchor_not_forbidden',
  );
  addReason(reasons, boundary?.privilegedContentAnchorForbidden !== true, 'receipt_privileged_anchor_not_forbidden');
  addReason(reasons, boundary?.immutableReceiptsMetadataOnly !== true, 'receipt_metadata_only_boundary_absent');
  addReason(reasons, boundary?.payloadsRemainExternal !== true, 'receipt_payload_boundary_invalid');
  addReason(reasons, boundary?.metadataOnly !== true, 'receipt_boundary_metadata_invalid');
  addReason(reasons, boundary?.protectedContentExcluded !== true, 'receipt_boundary_protected_invalid');
  addReason(reasons, hlcTuple(boundary?.reviewedAtHlc) === null, 'receipt_boundary_review_time_invalid');
}

function evaluateExportPolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'export_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'export_policy_hash_invalid');
  addReason(reasons, policy?.participantLinkedRequiresConsent !== true, 'export_participant_consent_gate_absent');
  addReason(
    reasons,
    policy?.sponsorConfidentialRequiresDisclosureGrant !== true,
    'export_sponsor_disclosure_gate_absent',
  );
  addReason(
    reasons,
    policy?.suppressedRecordsDoNotRevealIdentifiers !== true,
    'export_suppression_identifier_boundary_invalid',
  );
  addReason(reasons, policy?.defaultExportEligibility !== false, 'export_default_allow_forbidden');
  addReason(reasons, policy?.metadataOnly !== true, 'export_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'export_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.reviewedAtHlc) === null, 'export_policy_review_time_invalid');
}

function evaluateAccessPolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'access_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'access_policy_hash_invalid');
  addReason(reasons, policy?.roleBased !== true, 'access_policy_rbac_absent');
  addReason(reasons, policy?.attributeBased !== true, 'access_policy_abac_absent');
  addReason(reasons, policy?.authorityChainRequired !== true, 'access_policy_authority_chain_absent');
  addReason(reasons, policy?.leastPrivilege !== true, 'access_policy_least_privilege_absent');
  addReason(reasons, policy?.timeBound !== true, 'access_policy_time_bound_absent');
  addReason(reasons, policy?.revocationImmediate !== true, 'access_policy_revocation_absent');
  addReason(
    reasons,
    policy?.emergencyAccessRequiresRetrospectiveReview !== true,
    'access_policy_emergency_review_absent',
  );
  addReason(reasons, policy?.metadataOnly !== true, 'access_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'access_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.reviewedAtHlc) === null, 'access_policy_review_time_invalid');
}

function evaluateRetentionPolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'retention_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'retention_policy_hash_invalid');
  addReason(reasons, policy?.longestApplicableRetentionWins !== true, 'retention_longest_rule_absent');
  addReason(reasons, policy?.legalHoldOverridesDisposition !== true, 'retention_legal_hold_override_absent');
  addReason(
    reasons,
    policy?.protocolSponsorRegulatoryInstitutionalCoverage !== true,
    'retention_source_coverage_absent',
  );
  addReason(reasons, policy?.metadataOnly !== true, 'retention_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'retention_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.reviewedAtHlc) === null, 'retention_policy_review_time_invalid');
}

function evaluateAiAssistance(ai, reasons) {
  if (ai === null || ai === undefined || ai.used !== true) {
    return;
  }
  addReason(reasons, ai.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, ai.advisoryOnly !== true, 'ai_advisory_only_absent');
  addReason(reasons, !isDigest(ai.recommendationHash), 'ai_recommendation_hash_invalid');
  addReason(reasons, sortedTextList(ai.limitationHashes).length === 0, 'ai_limitation_hashes_absent');
  addReason(reasons, !ai.limitationHashes?.every((hash) => isDigest(hash)), 'ai_limitation_hash_invalid');
  addReason(reasons, ai.reviewedByHuman !== true, 'ai_human_review_absent');
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, sortedTextList(review?.reviewerRoleRefs).length === 0, 'human_reviewer_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_final_authority_absent');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(
    reasons,
    hlcBefore(review?.reviewedAtHlc, input?.classificationModel?.approvedAtHlc),
    'human_review_before_model_approval',
  );
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
}

function evaluateValidationEvidence(input, reasons) {
  const evidence = input?.validationEvidence;
  addReason(reasons, sortedTextList(evidence?.commandRefs).length === 0, 'validation_command_refs_absent');
  addReason(reasons, evidence?.commandsPassed !== true, 'validation_commands_not_passed');
  addReason(reasons, evidence?.sourceGuardPassed !== true, 'source_guard_not_passed');
  addReason(reasons, evidence?.noExochainSourceModified !== true, 'exochain_source_modification_forbidden');
  addReason(reasons, hlcTuple(evidence?.recordedAtHlc) === null, 'validation_record_time_invalid');
  addReason(reasons, evidence?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
}

function evaluateHlcOrdering(input, reasons) {
  addReason(
    reasons,
    hlcAfter(input?.classificationPolicy?.evaluatedAtHlc, input?.receiptBoundary?.reviewedAtHlc),
    'receipt_boundary_before_policy',
  );
  addReason(
    reasons,
    hlcAfter(input?.classificationPolicy?.evaluatedAtHlc, input?.exportPolicy?.reviewedAtHlc),
    'export_policy_before_classification_policy',
  );
  addReason(
    reasons,
    hlcAfter(input?.classificationModel?.approvedAtHlc, input?.humanReview?.reviewedAtHlc),
    'human_review_before_model_approval',
  );
  addReason(
    reasons,
    hlcAfter(input?.humanReview?.reviewedAtHlc, input?.validationEvidence?.recordedAtHlc),
    'validation_before_human_review',
  );
}

function buildClassSummary(byDataClass) {
  return REQUIRED_DATA_CLASSES.map((dataClass) => {
    const rule = byDataClass[dataClass];
    return {
      accessPolicyRef: rule.accessPolicyRef,
      anchoringPolicy: rule.anchoringPolicy,
      classificationId: rule.classificationId,
      confidentialityLevel: rule.confidentialityLevel,
      dataClass,
      evidenceHash: rule.evidenceHash,
      exportEligibility: rule.exportEligibility,
      externalPayloadsRemainControlled: rule.externalPayloadsRemainControlled === true,
      metadataOnly: rule.metadataOnly === true,
      participantLinkage: rule.participantLinkage,
      phiPiiStatus: rule.phiPiiStatus,
      protectedContentExcluded: rule.protectedContentExcluded === true,
      retentionRuleRef: rule.retentionRuleRef,
      sponsorConfidentiality: rule.sponsorConfidentiality,
    };
  });
}

function buildClassificationModel(input, byDataClass) {
  const classSummary = buildClassSummary(byDataClass);
  const classificationDigest = sha256Hex({
    accessPolicyHash: input.accessPolicy.policyHash,
    classSummary,
    classificationPolicyHash: input.classificationPolicy.policyHash,
    custodyDigest: input.custodyDigest,
    dimensions: REQUIRED_DIMENSIONS,
    exportPolicyHash: input.exportPolicy.policyHash,
    modelHash: input.classificationModel.modelHash,
    receiptBoundaryHash: input.receiptBoundary.boundaryHash,
    retentionPolicyHash: input.retentionPolicy.policyHash,
    schema: CLASSIFICATION_SCHEMA,
    tenantId: input.tenantId,
  });

  return {
    schema: CLASSIFICATION_SCHEMA,
    modelRef: input.classificationModel.modelRef,
    modelVersion: input.classificationModel.modelVersion,
    tenantId: input.tenantId,
    trustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    dataClasses: [...REQUIRED_DATA_CLASSES],
    dimensions: [...REQUIRED_DIMENSIONS],
    classSummary,
    classificationDigest,
    defaultDenyUnclassified: input.classificationPolicy.defaultDenyUnclassified === true,
    participantLinkedExportGuard: input.exportPolicy.participantLinkedRequiresConsent === true,
    sponsorConfidentialExportGuard: input.exportPolicy.sponsorConfidentialRequiresDisclosureGrant === true,
    receiptBoundaryRef: input.receiptBoundary.boundaryRef,
    accessPolicyRef: input.accessPolicy.policyRef,
    retentionPolicyRef: input.retentionPolicy.policyRef,
    humanReviewerDid: input.humanReview.reviewerDid,
    validationCommandRefs: sortedTextList(input.validationEvidence.commandRefs),
    approvedAtHlc: input.classificationModel.approvedAtHlc,
  };
}

function buildClassificationReceipt(input, classificationModel) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: classificationModel.classificationDigest,
    artifactType: 'protected_data_classification_model',
    artifactVersion: `${input.classificationModel.modelRef}@${input.classificationModel.modelVersion}`,
    classification: 'metadata_only_data_classification',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    sensitivityTags: [
      'access_policy_metadata',
      'classification_model_metadata',
      'export_policy_metadata',
      'retention_policy_metadata',
    ],
    sourceSystem: 'cybermedica.protected_data_classification',
    tenantId: input.tenantId,
  });
}

export function evaluateProtectedDataClassification(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateClassificationPolicy(input?.classificationPolicy, reasons);
  evaluateClassificationModel(input, reasons);
  const byDataClass = evaluateClassRules(input, reasons);
  evaluateReceiptBoundary(input?.receiptBoundary, reasons);
  evaluateExportPolicy(input?.exportPolicy, reasons);
  evaluateAccessPolicy(input?.accessPolicy, reasons);
  evaluateRetentionPolicy(input?.retentionPolicy, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  evaluateHumanReview(input, reasons);
  evaluateValidationEvidence(input, reasons);
  evaluateHlcOrdering(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const blockedBy = uniqueSorted(reasons);
  if (blockedBy.length > 0) {
    return {
      decision: 'denied',
      failClosed: true,
      reasons: blockedBy,
      classificationModel: null,
      receipt: null,
    };
  }

  const classificationModel = buildClassificationModel(input, byDataClass);
  return {
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    classificationModel,
    receipt: buildClassificationReceipt(input, classificationModel),
  };
}
