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
const DID_EXO = /^did:exo:[a-z0-9][a-z0-9-]{2,127}$/u;
const ROSTER_SCHEMA = 'cybermedica.actor_identity_roster.v1';
const DECISION_SCHEMA = 'cybermedica.actor_identity_roster_decision.v1';
const REQUIRED_PERMISSION = 'actor_identity_roster_review';
const EXOCHAIN_DID_REGISTRY_SOURCE = 'exochain_did_registry';

const REQUIRED_ACTOR_CLASSES = Object.freeze([
  'ai_agent',
  'auditor',
  'clinical_research_coordinator',
  'cro_monitor',
  'principal_investigator',
  'quality_assurance',
  'sponsor_monitor',
  'sub_investigator',
  'support_engineer',
  'system_administrator',
  'tenant_administrator',
]);

const REQUIRED_SOURCE_REFS = Object.freeze([
  'cyber_medica_qms_prd_master.md#target-users-and-stakeholders',
  'cybermedica_2_0_sandy_seven_layer_master_prd.md#data-layer',
  'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  'docs/context/EXOCHAIN_COUNCIL_REVIEW_FOR_CYBERMEDICA_OPEN_QUESTIONS.md',
  'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
]);

const ACTOR_CLASSES = new Set(REQUIRED_ACTOR_CLASSES);
const ACTOR_KINDS = new Set(['ai_agent', 'human', 'service_account']);
const HUMAN_REVIEW_DECISIONS = new Set([
  'actor_identity_roster_accepted_inactive_trust',
  'hold_for_actor_identity_gap',
]);
const POLICY_STATUSES = new Set(['active']);
const VERIFIED_STATUSES = new Set(['active', 'verified']);
const ADMIN_ACTOR_CLASSES = new Set(['system_administrator', 'tenant_administrator']);

const RAW_ACTOR_IDENTITY_FIELDS = new Set([
  'body',
  'contactemail',
  'directidentifier',
  'directidentifiers',
  'freetext',
  'identitypacket',
  'identityworksheet',
  'participantidentifier',
  'participantname',
  'proofingbody',
  'rawactor',
  'rawactoridentity',
  'rawcredential',
  'rawdidregistry',
  'rawidentity',
  'rawidentitycontent',
  'rawidentitypacket',
  'rawidentityproof',
  'rawidentityworksheet',
  'rawpayload',
  'rawproofingbody',
  'rawproofingdocument',
  'rawreview',
  'rawsourcecontent',
  'reviewnotes',
  'sourcebody',
  'sourcedocumentbody',
]);

const SECRET_ACTOR_IDENTITY_FIELDS = new Set([
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

function isDid(value) {
  return hasText(value) && DID_EXO.test(value);
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

function assertNoRawActorIdentityContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawActorIdentityContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_ACTOR_IDENTITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw actor identity content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_ACTOR_IDENTITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`actor identity secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawActorIdentityContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawActorIdentityContent(input ?? {});
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

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
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

function hlcBefore(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) < 0;
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_identity_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'actor_identity_roster_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateRequiredSet(actual, expected, missingPrefix, unsupportedPrefix, supportedSet, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !supportedSet.has(value), `${unsupportedPrefix}:${value}`);
  }
}

function evaluatePolicy(policy, checkedAtHlc, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'actor_identity_policy_ref_absent');
  addReason(reasons, !hasText(policy?.policyVersion), 'actor_identity_policy_version_absent');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'actor_identity_policy_not_active');
  addReason(reasons, !isDigest(policy?.policyHash), 'actor_identity_policy_hash_invalid');
  addReason(reasons, policy?.didMappingRequired !== true, 'did_mapping_requirement_absent');
  addReason(reasons, policy?.didRegistrySource !== EXOCHAIN_DID_REGISTRY_SOURCE, 'did_registry_policy_source_unverified');
  addReason(reasons, policy?.identityProofingRequired !== true, 'identity_proofing_requirement_absent');
  addReason(reasons, policy?.gatewayAuthRequired !== true, 'gateway_auth_requirement_absent');
  addReason(reasons, policy?.aiFinalAuthorityProhibited !== true, 'ai_final_authority_policy_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'actor_identity_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'actor_identity_policy_protected_boundary_invalid');
  addReason(reasons, policy?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'actor_identity_policy_time_invalid');
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, checkedAtHlc), 'actor_identity_policy_after_check');

  evaluateRequiredSet(
    sortedTextList(policy?.requiredActorClasses),
    REQUIRED_ACTOR_CLASSES,
    'policy_required_actor_class_missing',
    'policy_required_actor_class_unsupported',
    ACTOR_CLASSES,
    reasons,
  );

  const sourceRefs = sortedTextList(policy?.requiredSourceRefs);
  const supportedSources = new Set(REQUIRED_SOURCE_REFS);
  for (const sourceRef of REQUIRED_SOURCE_REFS) {
    addReason(reasons, !sourceRefs.includes(sourceRef), `policy_required_source_ref_missing:${sourceRef}`);
  }
  for (const sourceRef of sourceRefs) {
    addReason(reasons, !supportedSources.has(sourceRef), `policy_required_source_ref_unsupported:${sourceRef}`);
  }
}

function validateProfile(profile, tenantId, checkedAtHlc, reasons) {
  const actorClass = hasText(profile?.actorClass) ? profile.actorClass : 'unknown_actor_class';
  const roleRefs = sortedTextList(profile?.roleRefs);
  const allowedTenantIds = sortedTextList(profile?.allowedTenantIds);

  addReason(reasons, !hasText(profile?.actorClass), 'actor_profile_class_absent');
  addReason(reasons, hasText(profile?.actorClass) && !ACTOR_CLASSES.has(profile.actorClass), `actor_class_unsupported:${actorClass}`);
  addReason(reasons, !isDid(profile?.did), `actor_did_invalid:${actorClass}`);
  addReason(reasons, !ACTOR_KINDS.has(profile?.kind), `actor_kind_invalid:${actorClass}`);
  addReason(reasons, actorClass === 'ai_agent' && profile?.kind !== 'ai_agent', `ai_agent_kind_invalid:${actorClass}`);
  addReason(reasons, actorClass !== 'ai_agent' && profile?.kind !== 'human', `human_actor_kind_invalid:${actorClass}`);
  addReason(reasons, !VERIFIED_STATUSES.has(profile?.status), `actor_identity_not_verified:${actorClass}`);
  addReason(reasons, profile?.didRegistrySource !== EXOCHAIN_DID_REGISTRY_SOURCE, `did_registry_source_unverified:${actorClass}`);
  addReason(reasons, !isDigest(profile?.didRegistryEvidenceHash), `did_registry_evidence_hash_invalid:${actorClass}`);
  addReason(reasons, !isDigest(profile?.identityProofHash), `identity_proof_hash_invalid:${actorClass}`);
  addReason(reasons, !isDigest(profile?.authorityPolicyHash), `authority_policy_hash_invalid:${actorClass}`);
  addReason(reasons, roleRefs.length === 0, `actor_role_refs_absent:${actorClass}`);
  addReason(reasons, !allowedTenantIds.includes(tenantId), `actor_tenant_not_allowed:${actorClass}`);
  addReason(reasons, !isDigest(profile?.custodyDigest), `actor_custody_digest_invalid:${actorClass}`);
  addReason(reasons, hlcTuple(profile?.updatedAtHlc) === null, `actor_profile_updated_time_invalid:${actorClass}`);
  addReason(reasons, hlcAfter(profile?.updatedAtHlc, checkedAtHlc), `actor_profile_updated_after_check:${actorClass}`);
  addReason(reasons, profile?.metadataOnly !== true, `actor_metadata_boundary_invalid:${actorClass}`);
  addReason(reasons, profile?.protectedContentExcluded !== true, `actor_protected_boundary_invalid:${actorClass}`);
  addReason(reasons, profile?.productionTrustClaim === true, `actor_production_trust_claim_forbidden:${actorClass}`);
  addReason(reasons, profile?.aiFinalAuthority === true, `actor_ai_final_authority_forbidden:${actorClass}`);
  addReason(reasons, actorClass === 'ai_agent' && !hasText(profile?.humanOwnerDid), `ai_agent_human_owner_absent:${actorClass}`);
  addReason(reasons, actorClass === 'support_engineer' && !hasText(profile?.supportAccessPolicyRef), 'support_access_policy_ref_absent:support_engineer');
  addReason(
    reasons,
    ADMIN_ACTOR_CLASSES.has(actorClass) && !isDigest(profile?.privilegedAccessReviewHash),
    `privileged_access_review_hash_invalid:${actorClass}`,
  );

  return {
    actorClass,
    allowedTenantIds,
    authorityPolicyHash: profile?.authorityPolicyHash ?? null,
    custodyDigest: profile?.custodyDigest ?? null,
    did: profile?.did ?? null,
    didRegistryEvidenceHash: profile?.didRegistryEvidenceHash ?? null,
    didRegistrySource: profile?.didRegistrySource ?? null,
    humanOwnerDid: hasText(profile?.humanOwnerDid) ? profile.humanOwnerDid : null,
    identityProofHash: profile?.identityProofHash ?? null,
    kind: profile?.kind ?? null,
    metadataOnly: profile?.metadataOnly === true,
    productionTrustClaim: profile?.productionTrustClaim === true,
    protectedContentExcluded: profile?.protectedContentExcluded === true,
    roleRefs,
    status: profile?.status ?? null,
    updatedAtHlc: profile?.updatedAtHlc ?? null,
  };
}

function normalizeProfiles(input, checkedAtHlc, reasons) {
  const profiles = Array.isArray(input?.actorProfiles) ? input.actorProfiles : [];
  addReason(reasons, profiles.length === 0, 'actor_profiles_absent');

  const seen = new Set();
  const normalized = [];
  for (const profile of profiles) {
    const actorClass = hasText(profile?.actorClass) ? profile.actorClass : 'unknown_actor_class';
    addReason(reasons, hasText(profile?.actorClass) && seen.has(actorClass), `actor_profile_duplicate:${actorClass}`);
    if (hasText(profile?.actorClass)) {
      seen.add(actorClass);
    }
    normalized.push(validateProfile(profile, input?.tenantId, checkedAtHlc, reasons));
  }

  for (const actorClass of REQUIRED_ACTOR_CLASSES) {
    addReason(reasons, !seen.has(actorClass), `actor_profile_missing:${actorClass}`);
  }

  return normalized.sort((left, right) => String(left.actorClass).localeCompare(String(right.actorClass)));
}

function evaluateHumanReview(input, checkedAtHlc, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'human_review_reviewer_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.reviewHash), 'human_review_hash_invalid');
  addReason(reasons, review?.aiFinalAuthority === true, 'human_review_ai_final_authority_forbidden');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'human_review_production_trust_claim_absent');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, checkedAtHlc), 'human_review_before_roster_check');
}

function evaluateAiAssistance(input, reasons) {
  const ai = input?.aiAssistance;
  if (ai === null || ai === undefined) {
    return;
  }
  addReason(reasons, ai.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, ai.used === true && !isDigest(ai.recommendationHash), 'ai_recommendation_hash_invalid');
  addReason(reasons, ai.used === true && ai.reviewedByHuman !== true, 'ai_human_review_absent');
}

function evaluateValidationEvidence(validationEvidence, reasons) {
  addReason(reasons, validationEvidence?.sourceGuardPassed !== true, 'source_guard_not_passed');
  addReason(reasons, validationEvidence?.noExochainSourceModified !== true, 'exochain_source_modification_guard_absent');
  addReason(reasons, !isDigest(validationEvidence?.validationHash), 'validation_hash_invalid');
  addReason(reasons, sortedTextList(validationEvidence?.commandRefs).length === 0, 'validation_command_refs_absent');
  addReason(reasons, validationEvidence?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(validationEvidence?.recordedAtHlc) === null, 'validation_recorded_time_invalid');
}

function failure(reasons) {
  return {
    decision: 'denied',
    failClosed: true,
    reasons: uniqueReasons(reasons),
    actorIdentityRoster: null,
    receipt: null,
    exochainProductionClaim: false,
    sourceEvidence: [
      'docs/context/EXOCHAIN_COUNCIL_REVIEW_FOR_CYBERMEDICA_OPEN_QUESTIONS.md',
      'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
    ],
  };
}

function rosterDigestMaterial(input, profiles) {
  return {
    actorClasses: profiles.map((profile) => profile.actorClass),
    policyHash: input.rosterPolicy.policyHash,
    policyRef: input.rosterPolicy.policyRef,
    policyVersion: input.rosterPolicy.policyVersion,
    profiles,
    schema: ROSTER_SCHEMA,
    sourceRefs: sortedTextList(input.rosterPolicy.requiredSourceRefs),
    tenantId: input.tenantId,
  };
}

function buildActorIdentityRoster(input, profiles, rosterHash) {
  const actorClasses = profiles.map((profile) => profile.actorClass).sort();
  return {
    schema: ROSTER_SCHEMA,
    rosterRef: input.rosterPolicy.policyRef,
    policyVersion: input.rosterPolicy.policyVersion,
    status: 'ready',
    trustState: 'inactive',
    tenantId: input.tenantId,
    actorClasses,
    profileCount: profiles.length,
    aiAgentClasses: profiles.filter((profile) => profile.kind === 'ai_agent').map((profile) => profile.actorClass).sort(),
    humanActorClasses: profiles.filter((profile) => profile.kind === 'human').map((profile) => profile.actorClass).sort(),
    sourceRefs: sortedTextList(input.rosterPolicy.requiredSourceRefs),
    rosterHash,
    metadataOnly: true,
    exochainProductionClaim: false,
    checkedAtHlc: input.rosterCheckedAtHlc,
    profiles,
  };
}

function buildReceipt(input, rosterHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: rosterHash,
    artifactType: 'actor_identity_roster',
    artifactVersion: `${input.rosterPolicy.policyRef}@${input.rosterPolicy.policyVersion}`,
    classification: 'metadata_only_actor_identity_roster',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.rosterCheckedAtHlc,
    sensitivityTags: ['actor_identity', 'did_mapping', 'metadata_only'],
    sourceSystem: 'CyberMedica',
    tenantId: input.tenantId,
  });
}

export function evaluateActorIdentityRoster(input) {
  assertMetadataOnly(input);

  const reasons = [];
  const checkedAtHlc = input?.rosterCheckedAtHlc;
  addReason(reasons, hlcTuple(checkedAtHlc) === null, 'roster_checked_time_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  evaluateTenantActorAuthority(input, reasons);
  evaluatePolicy(input?.rosterPolicy, checkedAtHlc, reasons);
  const profiles = normalizeProfiles(input, checkedAtHlc, reasons);
  evaluateHumanReview(input, checkedAtHlc, reasons);
  evaluateAiAssistance(input, reasons);
  evaluateValidationEvidence(input?.validationEvidence, reasons);

  if (reasons.length > 0) {
    return failure(reasons);
  }

  const rosterHash = sha256Hex(rosterDigestMaterial(input, profiles));
  const actorIdentityRoster = buildActorIdentityRoster(input, profiles, rosterHash);
  const decisionHash = sha256Hex({
    actorIdentityRosterHash: rosterHash,
    decision: 'actor_identity_roster_ready_inactive_trust',
    humanReviewHash: input.humanReview.reviewHash,
    schema: DECISION_SCHEMA,
    tenantId: input.tenantId,
  });

  return {
    decision: 'permitted',
    decisionHash,
    failClosed: false,
    reasons: [],
    actorIdentityRoster,
    receipt: buildReceipt(input, rosterHash),
    exochainProductionClaim: false,
  };
}
