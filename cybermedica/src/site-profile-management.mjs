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
const SITE_PROFILE_SCHEMA = 'cybermedica.site_profile.v1';
const SITE_PROFILE_RECORD_SCHEMA = 'cybermedica.site_profile_record.v1';

const REQUIRED_PROFILE_DOMAINS = Object.freeze([
  'configuration',
  'control_set',
  'evidence_index',
  'organization',
  'role_matrix',
  'site_identity',
  'study_portfolio',
  'tenant',
  'user_roster',
]);

const APPROVED_STATUSES = new Set(['approved', 'approved_with_conditions']);
const CHANGE_TYPES = new Set(['approve', 'create', 'maintain', 'review', 'update']);

const RAW_SITE_PROFILE_FIELDS = new Set([
  'facilityaddress',
  'freetextprofile',
  'freetextsiteprofile',
  'legalentityname',
  'organizationname',
  'participantdetails',
  'patientdetails',
  'principalinvestigatoremail',
  'principalinvestigatorname',
  'rawlocation',
  'raworganization',
  'rawprofile',
  'rawsiteprofile',
  'rawsiteprofilebody',
  'siteaddress',
  'sitename',
  'siteprofilenarrative',
]);

const SECRET_SITE_PROFILE_FIELDS = new Set([
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

function assertNoRawSiteProfileContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawSiteProfileContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_SITE_PROFILE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw site profile content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_SITE_PROFILE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`site profile secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawSiteProfileContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawSiteProfileContent(input ?? {});
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

function sortedDigestList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(isDigest))].sort() : [];
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

function sortByField(fieldName) {
  return (left, right) => String(left[fieldName]).localeCompare(String(right[fieldName]));
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_profile_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, 'site_profile_manage') && !hasAuthorityPermission(input?.authority, 'govern'),
    'site_profile_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function normalizeProfile(profile, input, reasons) {
  addReason(reasons, !hasText(profile?.profileRef), 'profile_ref_absent');
  addReason(reasons, !hasText(profile?.profileVersion), 'profile_version_absent');
  addReason(reasons, profile?.schemaVersion !== SITE_PROFILE_SCHEMA, 'profile_schema_invalid');
  addReason(reasons, !APPROVED_STATUSES.has(profile?.status), 'profile_not_approved');
  addReason(reasons, profile?.tenantRef !== input?.tenantId, 'profile_tenant_ref_mismatch');
  addReason(reasons, !hasText(profile?.organizationRef), 'organization_ref_absent');
  addReason(reasons, !hasText(profile?.siteRef), 'site_ref_absent');
  addReason(reasons, !isDigest(profile?.legalEntityHash), 'legal_entity_hash_invalid');
  addReason(reasons, !isDigest(profile?.ownershipStructureHash), 'ownership_structure_hash_invalid');
  addReason(reasons, !isDigest(profile?.siteIdentityHash), 'site_identity_hash_invalid');
  addReason(reasons, !isDigest(profile?.studyPortfolioHash), 'study_portfolio_hash_invalid');
  addReason(reasons, !isDigest(profile?.userRosterHash), 'user_roster_hash_invalid');
  addReason(reasons, !isDigest(profile?.roleMatrixHash), 'role_matrix_hash_invalid');
  addReason(reasons, !isDigest(profile?.controlSetHash), 'control_set_hash_invalid');
  addReason(reasons, !isDigest(profile?.evidenceIndexHash), 'evidence_index_hash_invalid');
  addReason(reasons, !isDigest(profile?.configurationHash), 'configuration_hash_invalid');
  addReason(
    reasons,
    profile?.previousProfileHash !== null && profile?.previousProfileHash !== undefined && !isDigest(profile?.previousProfileHash),
    'previous_profile_hash_invalid',
  );
  addReason(reasons, sortedDigestList(profile?.siteLocationHashes).length === 0, 'site_location_hashes_absent');
  addReason(reasons, Array.isArray(profile?.siteLocationHashes) && profile.siteLocationHashes.some((hash) => !isDigest(hash)), 'site_location_hash_invalid');
  addReason(reasons, profile?.metadataOnly !== true, 'profile_metadata_boundary_invalid');
  addReason(reasons, profile?.productionTrustClaim === true, 'production_trust_claim_forbidden');

  return {
    configurationHash: profile?.configurationHash ?? null,
    controlSetHash: profile?.controlSetHash ?? null,
    evidenceIndexHash: profile?.evidenceIndexHash ?? null,
    legalEntityHash: profile?.legalEntityHash ?? null,
    organizationRef: profile?.organizationRef ?? null,
    ownershipStructureHash: profile?.ownershipStructureHash ?? null,
    previousProfileHash: profile?.previousProfileHash ?? null,
    profileRef: hasText(profile?.profileRef) ? profile.profileRef : 'SITE-PROFILE-UNKNOWN',
    profileVersion: hasText(profile?.profileVersion) ? profile.profileVersion : 'VERSION-UNKNOWN',
    roleMatrixHash: profile?.roleMatrixHash ?? null,
    schemaVersion: profile?.schemaVersion ?? null,
    siteIdentityHash: profile?.siteIdentityHash ?? null,
    siteLocationHashes: sortedDigestList(profile?.siteLocationHashes),
    siteRef: profile?.siteRef ?? null,
    status: profile?.status ?? null,
    studyPortfolioHash: profile?.studyPortfolioHash ?? null,
    tenantRef: profile?.tenantRef ?? null,
    userRosterHash: profile?.userRosterHash ?? null,
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
    changeRef: hasText(change?.changeRef) ? change.changeRef : 'CHANGE-UNKNOWN',
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

function normalizeProfileDomains(input, reasons) {
  const domains = Array.isArray(input?.profileDomains) ? [...input.profileDomains].sort(sortByField('domain')) : [];
  const domainNames = uniqueSorted(domains.map((domain) => domain?.domain).filter(hasText));
  addReason(reasons, domains.length === 0, 'profile_domains_absent');
  for (const required of REQUIRED_PROFILE_DOMAINS) {
    addReason(reasons, !domainNames.includes(required), `required_profile_domain_missing:${required}`);
  }

  return domains.map((domain) => {
    const domainName = hasText(domain?.domain) ? domain.domain : 'profile_domain_unknown';
    const evidenceRefs = sortedTextList(domain?.evidenceRefs);
    const controlRefs = sortedTextList(domain?.controlRefs);
    addReason(reasons, !REQUIRED_PROFILE_DOMAINS.includes(domainName), `profile_domain_invalid:${domainName}`);
    addReason(reasons, !APPROVED_STATUSES.has(domain?.status), `profile_domain_not_approved:${domainName}`);
    addReason(reasons, !hasText(domain?.ownerDid), `profile_domain_owner_absent:${domainName}`);
    addReason(reasons, !isDigest(domain?.artifactHash), `profile_domain_artifact_hash_invalid:${domainName}`);
    addReason(reasons, evidenceRefs.length === 0, `profile_domain_evidence_absent:${domainName}`);
    addReason(reasons, controlRefs.length === 0, `profile_domain_control_absent:${domainName}`);
    addReason(reasons, hlcTuple(domain?.reviewedAtHlc) === null, `profile_domain_review_time_invalid:${domainName}`);
    addReason(reasons, domain?.metadataOnly !== true, `profile_domain_metadata_boundary_invalid:${domainName}`);

    return {
      artifactHash: domain?.artifactHash ?? null,
      controlRefs,
      domain: domainName,
      evidenceRefs,
      ownerDid: domain?.ownerDid ?? null,
      reviewedAtHlc: domain?.reviewedAtHlc ?? null,
      status: domain?.status ?? null,
    };
  });
}

function normalizeSiteApproval(approval, reasons) {
  addReason(reasons, approval === null || approval === undefined, 'site_approval_absent');
  addReason(reasons, !APPROVED_STATUSES.has(approval?.status), 'site_approval_not_approved');
  addReason(reasons, !hasText(approval?.reviewerDid), 'site_approval_reviewer_absent');
  addReason(reasons, !hasText(approval?.reviewerRole), 'site_approval_reviewer_role_absent');
  addReason(reasons, approval?.humanVerified !== true, 'human_review_unverified');
  addReason(reasons, approval?.evidenceBundleComplete !== true, 'evidence_bundle_incomplete');
  addReason(reasons, approval?.phiBoundaryAttested !== true, 'phi_boundary_unattested');
  addReason(reasons, !isDigest(approval?.reviewEvidenceHash), 'review_evidence_hash_invalid');
  addReason(reasons, !isDigest(approval?.approvalRationaleHash), 'approval_rationale_hash_invalid');

  if (approval?.decisionForumRequired === true) {
    const forum = approval?.decisionForum;
    addReason(reasons, forum?.verified !== true, 'decision_forum_unverified');
    addReason(reasons, forum?.state !== 'approved', 'decision_forum_not_approved');
    addReason(reasons, !hasText(forum?.decisionId), 'decision_forum_id_absent');
    addReason(reasons, !hasText(forum?.workflowReceiptId), 'decision_forum_receipt_absent');
    addReason(reasons, forum?.quorum?.status !== 'met', 'quorum_not_met');
    addReason(reasons, forum?.humanGate?.verified !== true, 'human_gate_unverified');
    addReason(reasons, forum?.openChallenge === true, 'challenge_open');
  }

  return {
    approvalRationaleHash: approval?.approvalRationaleHash ?? null,
    decisionForum: {
      decisionId: approval?.decisionForum?.decisionId ?? null,
      state: approval?.decisionForum?.state ?? null,
      verified: approval?.decisionForum?.verified === true,
      workflowReceiptId: approval?.decisionForum?.workflowReceiptId ?? null,
    },
    decisionForumRequired: approval?.decisionForumRequired === true,
    evidenceBundleComplete: approval?.evidenceBundleComplete === true,
    humanVerified: approval?.humanVerified === true,
    phiBoundaryAttested: approval?.phiBoundaryAttested === true,
    reviewEvidenceHash: approval?.reviewEvidenceHash ?? null,
    reviewerDid: approval?.reviewerDid ?? null,
    reviewerRole: approval?.reviewerRole ?? null,
    status: approval?.status ?? null,
  };
}

function buildSiteProfileRecord(input, profile, changeControl, profileDomains, siteApproval) {
  const profileDomainNames = uniqueSorted(profileDomains.map((domain) => domain.domain));
  const profileHash = sha256Hex({
    changeControl,
    profile,
    profileDomains,
    schema: SITE_PROFILE_RECORD_SCHEMA,
    siteApproval,
    tenantId: input.tenantId,
  });

  return {
    schema: SITE_PROFILE_RECORD_SCHEMA,
    profileRef: profile.profileRef,
    profileVersion: profile.profileVersion,
    profileStatus: profile.status,
    profileHash,
    trustState: 'inactive',
    exochainProductionClaim: false,
    containsProtectedContent: false,
    tenantBoundary: {
      tenantId: input.tenantId,
      targetTenantId: input.targetTenantId,
      organizationRef: profile.organizationRef,
      siteRef: profile.siteRef,
    },
    domainCoverage: {
      domainCount: profileDomainNames.length,
      profileDomains: profileDomainNames,
    },
    profile,
    changeControl,
    profileDomains,
    siteApproval,
    sourceRequirements: ['FR-001', 'FR-002'],
  };
}

export function evaluateSiteProfileManagement(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const profile = normalizeProfile(input?.profile, input, reasons);
  const changeControl = normalizeChangeControl(input?.changeControl, reasons);
  const profileDomains = normalizeProfileDomains(input, reasons);
  const siteApproval = normalizeSiteApproval(input?.siteApproval, reasons);

  if (reasons.length > 0) {
    return {
      permitted: false,
      reasons: uniqueSorted(reasons),
      siteProfile: null,
      receipt: null,
    };
  }

  const siteProfile = buildSiteProfileRecord(input, profile, changeControl, profileDomains, siteApproval);
  const receipt = createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: siteProfile.profileHash,
    artifactType: 'site_profile',
    artifactVersion: `${siteProfile.profileRef}:${siteProfile.profileVersion}`,
    classification: 'confidential_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: changeControl.effectiveAtHlc,
    sensitivityTags: ['metadata_only', 'organization', 'site_profile', 'tenant'],
    sourceSystem: 'cybermedica.site_profile_management',
    tenantId: input.tenantId,
  });

  return {
    permitted: true,
    reasons: [],
    siteProfile,
    receipt,
  };
}
