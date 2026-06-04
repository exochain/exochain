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
const ORGANIZATION_REGISTRY_SCHEMA = 'cybermedica.organization_lifecycle_registry.v1';
const ORGANIZATION_REGISTRY_RECORD_SCHEMA = 'cybermedica.organization_lifecycle_registry_record.v1';

const REQUIRED_PERMISSION = 'organization_lifecycle_manage';

const REQUIRED_ORGANIZATION_CLASSES = Object.freeze([
  'clinical_site_operator',
  'cro',
  'iec_irb',
  'sponsor',
]);

const REQUIRED_LIFECYCLE_DOMAINS = Object.freeze([
  'authority_boundary',
  'confidentiality_boundary',
  'ethics_independence',
  'identity_registry',
  'lifecycle_control',
  'ownership_accountability',
  'receipt_boundary',
  'tenant_boundary',
  'visibility_policy',
]);

const REQUIRED_RECEIPT_FAMILIES = Object.freeze([
  'audit',
  'authority',
  'disclosure',
  'evidence',
  'organization_lifecycle',
]);

const CHANGE_TYPES = new Set(['register', 'retire', 'suspend', 'update']);
const CONFIDENTIALITY_CLASSES = new Set([
  'decision_governance',
  'sponsor_cro_confidential',
  'tenant_operational',
]);
const HUMAN_REVIEW_DECISIONS = new Set(['organization_lifecycle_hold', 'organization_lifecycle_ready']);
const LIFECYCLE_STATES = new Set(['active', 'onboarding', 'retired', 'suspended']);
const SPONSOR_CRO_CLASSES = new Set(['cro', 'sponsor']);

const RAW_ORGANIZATION_FIELDS = new Set([
  'boardminutesbody',
  'contractbody',
  'directidentifier',
  'directidentifiers',
  'facilityprofilebody',
  'freetextorganization',
  'freetextprofile',
  'irbletterbody',
  'legalentitybody',
  'participantidentifier',
  'participantlisting',
  'participantname',
  'patientname',
  'rawethicsbody',
  'rawirbletter',
  'raworganization',
  'raworganizationprofile',
  'rawparticipant',
  'rawprofile',
  'rawsponsor',
  'sourcebody',
  'sourcedocumentbody',
  'sponsorconfidentialbody',
  'sponsorcontractbody',
]);

const SECRET_ORGANIZATION_FIELDS = new Set([
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

function assertNoRawOrganizationContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawOrganizationContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_ORGANIZATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw organization lifecycle content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_ORGANIZATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`organization lifecycle secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawOrganizationContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawOrganizationContent(input ?? {});
  canonicalize(input ?? {});
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
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

function sortOrganization(left, right) {
  return String(left.organizationClass).localeCompare(String(right.organizationClass)) ||
    String(left.organizationRef).localeCompare(String(right.organizationRef));
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_organization_lifecycle_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'organization_lifecycle_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateRegistryPolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'registry_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'registry_policy_hash_invalid');
  addReason(reasons, policy?.status !== 'active', 'registry_policy_not_active');
  addReason(reasons, policy?.defaultDenyUnknownOrganizationClasses !== true, 'unknown_organization_class_default_deny_absent');
  addReason(reasons, policy?.sponsorCroVisibilityDefault !== 'controlled_request_only', 'sponsor_cro_visibility_default_uncontrolled');
  addReason(reasons, policy?.directParticipantAccessDefault !== 'none', 'direct_participant_access_default_forbidden');
  addReason(reasons, policy?.aiFinalAuthorityForbidden !== true, 'ai_final_authority_guard_absent');
  addReason(reasons, policy?.rawProtectedContentForbidden !== true, 'raw_protected_content_guard_absent');
  addReason(reasons, policy?.noProductionTrustClaim !== true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'registry_policy_evaluation_time_invalid');
  addReason(reasons, policy?.metadataOnly !== true, 'registry_policy_metadata_boundary_invalid');

  const requiredClasses = sortedTextList(policy?.requiredOrganizationClasses);
  for (const organizationClass of REQUIRED_ORGANIZATION_CLASSES) {
    addReason(reasons, !requiredClasses.includes(organizationClass), `required_organization_class_missing:${organizationClass}`);
  }

  const lifecycleDomains = sortedTextList(policy?.requiredLifecycleDomains);
  for (const domain of REQUIRED_LIFECYCLE_DOMAINS) {
    addReason(reasons, !lifecycleDomains.includes(domain), `lifecycle_domain_missing:${domain}`);
  }
}

function normalizeOrganizationRecords(input, reasons) {
  const organizations = Array.isArray(input?.organizations) ? [...input.organizations].sort(sortOrganization) : [];
  addReason(reasons, organizations.length === 0, 'organization_records_absent');

  const classCounts = new Map();
  for (const organization of organizations) {
    const organizationClass = hasText(organization?.organizationClass) ? organization.organizationClass : 'unknown';
    classCounts.set(organizationClass, (classCounts.get(organizationClass) ?? 0) + 1);
  }
  for (const organizationClass of REQUIRED_ORGANIZATION_CLASSES) {
    addReason(reasons, (classCounts.get(organizationClass) ?? 0) === 0, `organization_class_missing:${organizationClass}`);
    addReason(reasons, (classCounts.get(organizationClass) ?? 0) > 1, `organization_class_duplicate:${organizationClass}`);
  }

  return organizations.map((organization) => normalizeOrganizationRecord(organization, input, reasons));
}

function normalizeOrganizationRecord(organization, input, reasons) {
  const organizationClass = hasText(organization?.organizationClass) ? organization.organizationClass : 'unknown';
  const sponsorCro = SPONSOR_CRO_CLASSES.has(organizationClass);
  const ethicsBody = organizationClass === 'iec_irb';

  addReason(reasons, !REQUIRED_ORGANIZATION_CLASSES.includes(organizationClass), `organization_class_invalid:${organizationClass}`);
  addReason(reasons, !hasText(organization?.organizationRef), `organization_ref_absent:${organizationClass}`);
  addReason(reasons, !hasText(organization?.organizationVersion), `organization_version_absent:${organizationClass}`);
  addReason(reasons, !LIFECYCLE_STATES.has(organization?.lifecycleState), `organization_lifecycle_state_invalid:${organizationClass}`);
  addReason(reasons, organization?.tenantRef !== input?.tenantId, `organization_tenant_ref_mismatch:${organizationClass}`);
  addReason(reasons, !hasText(organization?.ownerDid), `organization_owner_absent:${organizationClass}`);
  addReason(reasons, !hasText(organization?.accountableMaintainerDid), `organization_maintainer_absent:${organizationClass}`);
  addReason(reasons, !hasText(organization?.identityRegistryRef), `identity_registry_ref_absent:${organizationClass}`);
  addReason(reasons, !isDigest(organization?.identityRegistryHash), `identity_registry_hash_invalid:${organizationClass}`);
  addReason(reasons, !isDigest(organization?.legalEntityHash), `legal_entity_hash_invalid:${organizationClass}`);
  addReason(reasons, !isDigest(organization?.authorityBoundaryHash), `authority_boundary_hash_invalid:${organizationClass}`);
  addReason(reasons, !hasText(organization?.accessPolicyRef), `access_policy_ref_absent:${organizationClass}`);
  addReason(reasons, !hasText(organization?.retentionRuleRef), `retention_rule_ref_absent:${organizationClass}`);
  addReason(reasons, !isDigest(organization?.disclosurePolicyHash), `disclosure_policy_hash_invalid:${organizationClass}`);
  addReason(reasons, !CONFIDENTIALITY_CLASSES.has(organization?.confidentialityClass), `confidentiality_class_invalid:${organizationClass}`);
  addReason(reasons, sortedTextList(organization?.dataClassifications).length === 0, `data_classifications_absent:${organizationClass}`);
  addReason(reasons, organization?.directParticipantAccess === true, `direct_participant_access_forbidden:${organizationClass}`);
  addReason(reasons, hlcTuple(organization?.activeAtHlc) === null, `organization_active_time_invalid:${organizationClass}`);
  addReason(reasons, hlcTuple(organization?.reviewedAtHlc) === null, `organization_review_time_invalid:${organizationClass}`);
  addReason(reasons, hlcBefore(organization?.reviewedAtHlc, organization?.activeAtHlc), `organization_review_before_active:${organizationClass}`);
  addReason(reasons, organization?.metadataOnly !== true, `organization_metadata_boundary_invalid:${organizationClass}`);
  addReason(reasons, organization?.protectedContentExcluded !== true, `organization_protected_boundary_invalid:${organizationClass}`);
  addReason(reasons, organization?.productionTrustClaim === true, 'production_trust_claim_forbidden');

  if (sponsorCro) {
    addReason(reasons, organization?.sponsorConfidentialBodyExcluded !== true, `sponsor_confidential_body_guard_absent:${organizationClass}`);
    addReason(
      reasons,
      !hasText(organization?.sponsorCroVisibilityPolicyRef) || organization.sponsorCroVisibilityPolicyRef === 'not_applicable',
      `sponsor_cro_visibility_policy_absent:${organizationClass}`,
    );
    addReason(
      reasons,
      !sortedTextList(organization?.dataClassifications).includes('sponsor_cro_confidential'),
      `sponsor_cro_confidential_class_absent:${organizationClass}`,
    );
  }

  if (ethicsBody) {
    addReason(reasons, organization?.ethicsAuthorityAttested !== true, `ethics_authority_absent:${organizationClass}`);
    addReason(reasons, organization?.independentReviewBody !== true, `ethics_independence_absent:${organizationClass}`);
    addReason(reasons, organization?.noSponsorControlAttested !== true, `ethics_body_sponsor_control_absent:${organizationClass}`);
    addReason(reasons, organization?.aiRepresentedAsIrb === true, `ai_irb_confusion_forbidden:${organizationClass}`);
    addReason(
      reasons,
      !sortedTextList(organization?.dataClassifications).includes('decision_governance'),
      `ethics_governance_class_absent:${organizationClass}`,
    );
  }

  return {
    accessPolicyRef: organization?.accessPolicyRef ?? null,
    accountableMaintainerDid: organization?.accountableMaintainerDid ?? null,
    activeAtHlc: organization?.activeAtHlc ?? null,
    aiRepresentedAsIrb: organization?.aiRepresentedAsIrb === true,
    authorityBoundaryHash: organization?.authorityBoundaryHash ?? null,
    confidentialityClass: organization?.confidentialityClass ?? null,
    dataClassifications: sortedTextList(organization?.dataClassifications),
    directParticipantAccess: organization?.directParticipantAccess === true,
    disclosurePolicyHash: organization?.disclosurePolicyHash ?? null,
    ethicsAuthorityAttested: organization?.ethicsAuthorityAttested === true,
    identityRegistryHash: organization?.identityRegistryHash ?? null,
    identityRegistryRef: organization?.identityRegistryRef ?? null,
    independentReviewBody: organization?.independentReviewBody === true,
    legalEntityHash: organization?.legalEntityHash ?? null,
    lifecycleState: organization?.lifecycleState ?? null,
    metadataOnly: organization?.metadataOnly === true,
    noSponsorControlAttested: organization?.noSponsorControlAttested === true,
    organizationClass,
    organizationHash: sha256Hex({
      authorityBoundaryHash: organization?.authorityBoundaryHash ?? null,
      identityRegistryHash: organization?.identityRegistryHash ?? null,
      legalEntityHash: organization?.legalEntityHash ?? null,
      organizationClass,
      organizationRef: organization?.organizationRef ?? null,
      organizationVersion: organization?.organizationVersion ?? null,
      tenantRef: organization?.tenantRef ?? null,
    }),
    organizationRef: organization?.organizationRef ?? null,
    organizationVersion: organization?.organizationVersion ?? null,
    ownerDid: organization?.ownerDid ?? null,
    protectedContentExcluded: organization?.protectedContentExcluded === true,
    retentionRuleRef: organization?.retentionRuleRef ?? null,
    reviewedAtHlc: organization?.reviewedAtHlc ?? null,
    sponsorConfidentialBodyExcluded: organization?.sponsorConfidentialBodyExcluded === true,
    sponsorCroVisibilityPolicyRef: organization?.sponsorCroVisibilityPolicyRef ?? null,
    tenantRef: organization?.tenantRef ?? null,
  };
}

function normalizeChangeControl(change, reasons) {
  addReason(reasons, !hasText(change?.changeRef), 'change_control_ref_absent');
  addReason(reasons, !CHANGE_TYPES.has(change?.changeType), 'change_type_invalid');
  addReason(reasons, !hasText(change?.requestedByDid), 'change_requester_absent');
  addReason(reasons, !hasText(change?.reviewedByDid), 'change_reviewer_absent');
  addReason(reasons, !hasText(change?.approvedByDid), 'change_approver_absent');
  addReason(
    reasons,
    hasText(change?.requestedByDid) && change.requestedByDid === change?.reviewedByDid,
    'change_review_self_approval_forbidden',
  );
  addReason(
    reasons,
    hasText(change?.requestedByDid) && change.requestedByDid === change?.approvedByDid,
    'change_approval_self_approval_forbidden',
  );
  addReason(reasons, hlcTuple(change?.requestedAtHlc) === null, 'change_request_time_invalid');
  addReason(reasons, hlcTuple(change?.reviewedAtHlc) === null, 'change_review_time_invalid');
  addReason(reasons, hlcTuple(change?.approvedAtHlc) === null, 'change_approval_time_invalid');
  addReason(reasons, hlcTuple(change?.effectiveAtHlc) === null, 'change_effective_time_invalid');
  addReason(reasons, hlcBefore(change?.reviewedAtHlc, change?.requestedAtHlc), 'change_review_before_request');
  addReason(reasons, hlcBefore(change?.approvedAtHlc, change?.reviewedAtHlc), 'change_approval_before_review');
  addReason(reasons, hlcBefore(change?.effectiveAtHlc, change?.approvedAtHlc), 'change_effective_before_approval');
  addReason(reasons, !isDigest(change?.rationaleHash), 'change_rationale_hash_invalid');
  addReason(reasons, !isDigest(change?.impactAssessmentHash), 'change_impact_assessment_hash_invalid');
  addReason(reasons, !isDigest(change?.rollbackPlanHash), 'change_rollback_plan_hash_invalid');
  addReason(reasons, change?.metadataOnly !== true, 'change_control_metadata_boundary_invalid');

  return {
    approvedAtHlc: change?.approvedAtHlc ?? null,
    approvedByDid: change?.approvedByDid ?? null,
    changeRef: change?.changeRef ?? null,
    changeType: change?.changeType ?? null,
    effectiveAtHlc: change?.effectiveAtHlc ?? null,
    impactAssessmentHash: change?.impactAssessmentHash ?? null,
    rationaleHash: change?.rationaleHash ?? null,
    requestedAtHlc: change?.requestedAtHlc ?? null,
    requestedByDid: change?.requestedByDid ?? null,
    reviewedAtHlc: change?.reviewedAtHlc ?? null,
    reviewedByDid: change?.reviewedByDid ?? null,
    rollbackPlanHash: change?.rollbackPlanHash ?? null,
  };
}

function evaluateReceiptBoundary(receiptBoundary, reasons) {
  const receiptFamilies = sortedTextList(receiptBoundary?.requiredReceiptFamilies);
  for (const family of REQUIRED_RECEIPT_FAMILIES) {
    addReason(reasons, !receiptFamilies.includes(family), `receipt_family_missing:${family}`);
  }
  addReason(reasons, receiptBoundary?.exochainReceiptCapable !== true, 'receipt_capability_absent');
  addReason(reasons, receiptBoundary?.rawPayloadAnchoringForbidden !== true, 'raw_payload_anchor_guard_absent');
  addReason(reasons, receiptBoundary?.productionTrustState !== 'inactive', 'production_trust_state_not_inactive');
  addReason(reasons, receiptBoundary?.rootTrustVerified === true, 'root_trust_verified_before_activation');
  addReason(reasons, receiptBoundary?.metadataOnly !== true, 'receipt_boundary_metadata_invalid');
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, sortedTextList(review?.reviewerRoleRefs).length === 0, 'human_reviewer_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, review?.decision === 'organization_lifecycle_hold', 'organization_lifecycle_human_hold');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_final_authority_absent');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'production_trust_claim_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, input?.changeControl?.effectiveAtHlc), 'human_review_before_change_effective');
}

function buildOrganizationRegistry(input, organizationRecords, changeControl) {
  const material = {
    changeRef: changeControl.changeRef,
    organizationHashes: organizationRecords.map((record) => record.organizationHash),
    policyHash: input.registryPolicy.policyHash,
    tenantId: input.tenantId,
  };

  return {
    schema: ORGANIZATION_REGISTRY_RECORD_SCHEMA,
    registryId: `cm_org_lifecycle_${sha256Hex(material).slice(0, 32)}`,
    tenantId: input.tenantId,
    policyRef: input.registryPolicy.policyRef,
    policyHash: input.registryPolicy.policyHash,
    policySchema: ORGANIZATION_REGISTRY_SCHEMA,
    registryChangeRef: changeControl.changeRef,
    organizationClasses: [...REQUIRED_ORGANIZATION_CLASSES],
    lifecycleDomains: [...REQUIRED_LIFECYCLE_DOMAINS],
    requiredReceiptFamilies: [...REQUIRED_RECEIPT_FAMILIES],
    organizationRecords,
    boundaryDefaults: {
      directParticipantAccessDefault: 'none',
      sponsorCroVisibilityDefault: 'controlled_request_only',
      rawProtectedContentForbidden: true,
    },
    receiptBoundary: {
      exochainReceiptCapable: true,
      productionTrustState: 'inactive',
      rawPayloadAnchoringForbidden: true,
      rootTrustVerified: false,
    },
    trustState: 'inactive',
    exochainProductionClaim: false,
    containsProtectedContent: false,
    metadataOnly: true,
    humanReviewerDid: input.humanReview.reviewerDid,
    custodyDigest: input.custodyDigest,
    sourceEvidence: [
      'cybermedica_2_0_sandy_seven_layer_master_prd.md#Data-model-overview',
      'cybermedica_2_0_sandy_seven_layer_master_prd.md#FR-001',
      'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
    ],
  };
}

function createOrganizationRegistryReceipt(input, organizationRegistry, artifactHash, changeControl) {
  return createEvidenceReceipt({
    actorDid: input.humanReview.reviewerDid,
    artifactHash,
    artifactType: 'organization_lifecycle_registry',
    artifactVersion: `${input.registryPolicy.policyRef}:${changeControl.changeRef}`,
    classification: 'metadata_only_organization_lifecycle_registry',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    sensitivityTags: [
      'metadata_only',
      'organization_lifecycle',
      'sponsor_cro_confidential_metadata',
      'ethics_governance_metadata',
    ],
    sourceSystem: 'cybermedica.organization_lifecycle_registry',
    tenantId: input.tenantId,
  });
}

export function evaluateOrganizationLifecycleRegistry(input = {}) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateRegistryPolicy(input?.registryPolicy, reasons);
  const organizationRecords = normalizeOrganizationRecords(input, reasons);
  const changeControl = normalizeChangeControl(input?.changeControl, reasons);
  evaluateReceiptBoundary(input?.receiptBoundary, reasons);
  evaluateHumanReview(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const uniqueReasons = uniqueSorted(reasons);
  if (uniqueReasons.length > 0) {
    return {
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      organizationRegistry: null,
      receipt: null,
    };
  }

  const organizationRegistry = buildOrganizationRegistry(input, organizationRecords, changeControl);
  const artifactHash = sha256Hex(organizationRegistry);
  const receipt = createOrganizationRegistryReceipt(input, organizationRegistry, artifactHash, changeControl);

  return {
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    organizationRegistry,
    receipt,
  };
}
