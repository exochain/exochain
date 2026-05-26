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

import { canonicalize, createEvidenceReceipt, ProtectedContentError, sha256Hex } from './qms-contracts.mjs';

const HEX_64 = /^[0-9a-f]{64}$/u;
const REQUIRED_PERMISSION = 'workforce_profile_review';

const PROFILE_DOMAINS = Object.freeze([
  'leadership_development',
  'orientation_integration',
  'people_centered_culture',
  'performance_review',
  'skill_mix',
  'wellbeing_safeguards',
]);

const REQUIRED_ORIENTATION_TOPICS = Object.freeze([
  'access_methods',
  'concern_reporting',
  'innovation_participation',
  'policies',
  'procedures',
  'rights',
  'role_expectations',
]);

const REQUIRED_CULTURE_DOMAINS = Object.freeze([
  'ethics',
  'inclusivity',
  'knowledge_sharing',
  'problem_solving',
  'societal_responsibility',
  'teamwork',
]);

const DIRECT_IDENTIFIER_FIELDS = new Set([
  'familyname',
  'firstname',
  'fullname',
  'givenname',
  'hometelephone',
  'lastname',
  'legalname',
  'personname',
  'staffname',
  'workemail',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function assertNoDirectStaffIdentifiers(value, path = '$') {
  if (value === null || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    for (const [index, item] of value.entries()) {
      assertNoDirectStaffIdentifiers(item, `${path}[${index}]`);
    }
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    if (DIRECT_IDENTIFIER_FIELDS.has(normalizeFieldName(key)) && hasText(nested)) {
      throw new ProtectedContentError(`protected content is not allowed at ${path}.${key}`);
    }
    assertNoDirectStaffIdentifiers(nested, `${path}.${key}`);
  }
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function addGap(gaps, domain, reason) {
  gaps.push({ domain, reason });
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical)) {
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

function afterCheck(checkedAt, value) {
  const tuple = hlcTuple(value);
  return checkedAt !== null && tuple !== null && compareHlc(tuple, checkedAt) > 0;
}

function notAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) <= 0;
}

function checkedPastDue(checkedAt, dueAt) {
  const dueTuple = hlcTuple(dueAt);
  return checkedAt !== null && dueTuple !== null && compareHlc(checkedAt, dueTuple) > 0;
}

function hasAuthorityPermission(authority) {
  return Array.isArray(authority?.permissions) &&
    (authority.permissions.includes(REQUIRED_PERMISSION) || authority.permissions.includes('govern'));
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

function validateStaffProfile(input, reasons) {
  const profile = input?.staffProfile;
  if (profile === null || typeof profile !== 'object') {
    reasons.push('staff_profile_absent');
    return;
  }

  addReason(reasons, !hasText(profile.profileId), 'staff_profile_id_absent');
  addReason(reasons, !isDigest(profile.staffIdHash), 'staff_id_hash_invalid');
  addReason(reasons, !hasText(profile.actorDid), 'staff_actor_did_absent');
  addReason(reasons, profile.tenantId !== input?.tenantId, 'staff_profile_tenant_mismatch');
  addReason(reasons, profile.siteId !== input?.siteId, 'staff_profile_site_mismatch');
  addReason(reasons, !hasText(profile.role), 'staff_profile_role_absent');
  addReason(
    reasons,
    profile.employmentStatus !== 'active' || profile.contractStatus !== 'active',
    'staff_profile_not_active',
  );
  addReason(reasons, hlcTuple(profile.startAtHlc) === null, 'staff_profile_start_time_invalid');
  addReason(
    reasons,
    profile.endAtHlc !== null && checkedPastDue(hlcTuple(input?.checkedAtHlc), profile.endAtHlc),
    'staff_profile_ended',
  );
  addReason(reasons, sortedTextList(profile.accessRightRefs).length === 0, 'staff_access_rights_absent');
  addReason(reasons, sortedTextList(profile.systemPrivilegeRefs).length === 0, 'staff_privileges_absent');
  addReason(reasons, profile.conflictDisclosureStatus === 'active', 'staff_profile_conflict_active');
  addReason(reasons, profile.recusalStatus === 'recused', 'staff_profile_recused');
  addReason(reasons, !isDigest(profile.exochainIdentityRefHash), 'staff_identity_ref_hash_invalid');
}

function assignedRoleMap(assignedRoleCounts) {
  const roleCounts = new Map();
  if (!Array.isArray(assignedRoleCounts)) {
    return roleCounts;
  }
  for (const item of assignedRoleCounts) {
    if (!hasText(item?.role)) {
      continue;
    }
    roleCounts.set(item.role, {
      assignedCount: Number.isSafeInteger(item.assignedCount) ? item.assignedCount : -1,
      requiredCount: Number.isSafeInteger(item.requiredCount) ? item.requiredCount : -1,
    });
  }
  return roleCounts;
}

function validateSkillMix(input, checkedAt, reasons, gaps) {
  const review = input?.skillMixReview;
  if (review === null || typeof review !== 'object') {
    reasons.push('skill_mix_review_absent');
    addGap(gaps, 'skill_mix', 'skill_mix_review_absent');
    return [];
  }

  const requiredRoles = sortedTextList(review.requiredRoles);
  const counts = assignedRoleMap(review.assignedRoleCounts);

  addReason(reasons, review.status !== 'approved', 'skill_mix_review_not_approved');
  addReason(reasons, review.reviewedByHuman !== true, 'skill_mix_human_review_absent');
  addReason(reasons, review.staffingAdequate !== true, 'skill_mix_staffing_inadequate');
  addReason(reasons, !isDigest(review.evidenceHash), 'skill_mix_evidence_hash_invalid');
  addReason(reasons, hlcTuple(review.reviewedAtHlc) === null, 'skill_mix_review_time_invalid');
  addReason(reasons, afterCheck(checkedAt, review.reviewedAtHlc), 'skill_mix_review_after_check');
  addReason(reasons, requiredRoles.length === 0, 'skill_mix_required_roles_absent');
  addReason(
    reasons,
    hasText(input?.staffProfile?.role) && !requiredRoles.includes(input.staffProfile.role),
    'skill_mix_staff_role_missing',
  );

  for (const role of requiredRoles) {
    const count = counts.get(role);
    if (count === undefined || count.requiredCount < 1 || count.assignedCount < count.requiredCount) {
      const reason = `skill_mix_role_shortfall:${role}`;
      reasons.push(reason);
      addGap(gaps, 'skill_mix', reason);
    }
  }

  return requiredRoles;
}

function validateOrientation(input, checkedAt, reasons, gaps) {
  const orientation = input?.orientationIntegration;
  if (orientation === null || typeof orientation !== 'object') {
    reasons.push('orientation_absent');
    addGap(gaps, 'orientation', 'orientation_absent');
    return [];
  }

  const topics = sortedTextList(orientation.topics);

  addReason(reasons, orientation.status !== 'complete', 'orientation_not_complete');
  addReason(reasons, orientation.verifiedByHuman !== true, 'orientation_human_verification_absent');
  addReason(reasons, !isDigest(orientation.evidenceHash), 'orientation_evidence_hash_invalid');
  addReason(reasons, hlcTuple(orientation.completedAtHlc) === null, 'orientation_completed_time_invalid');
  addReason(reasons, afterCheck(checkedAt, orientation.completedAtHlc), 'orientation_completed_after_check');

  for (const topic of REQUIRED_ORIENTATION_TOPICS) {
    if (!topics.includes(topic)) {
      const reason = `orientation_topic_missing:${topic}`;
      reasons.push(reason);
      addGap(gaps, 'orientation', reason);
    }
  }

  return topics;
}

function validatePerformanceReview(input, checkedAt, reasons) {
  const review = input?.performanceReview;
  if (review === null || typeof review !== 'object') {
    reasons.push('performance_review_absent');
    return;
  }

  addReason(reasons, review.status !== 'current', 'performance_review_overdue');
  addReason(reasons, review.reviewedByHuman !== true, 'performance_human_review_absent');
  addReason(reasons, !isDigest(review.evidenceHash), 'performance_evidence_hash_invalid');
  addReason(reasons, !isDigest(review.developmentPlanHash), 'performance_development_plan_absent');
  addReason(reasons, review.qualityCultureReviewed !== true, 'performance_quality_culture_absent');
  addReason(reasons, hlcTuple(review.lastReviewAtHlc) === null, 'performance_review_time_invalid');
  addReason(reasons, hlcTuple(review.nextReviewDueHlc) === null, 'performance_next_review_time_invalid');
  addReason(reasons, afterCheck(checkedAt, review.lastReviewAtHlc), 'performance_review_after_check');
  addReason(reasons, notAfter(review.nextReviewDueHlc, review.lastReviewAtHlc), 'performance_next_review_not_after_last');
  addReason(reasons, checkedPastDue(checkedAt, review.nextReviewDueHlc), 'performance_review_overdue');
}

function validateLeadershipDevelopment(input, reasons) {
  const leadership = input?.leadershipDevelopment;
  if (leadership === null || typeof leadership !== 'object') {
    reasons.push('leadership_development_absent');
    return;
  }
  if (leadership.required !== true) {
    return;
  }

  addReason(reasons, leadership.status !== 'complete', 'leadership_development_incomplete');
  addReason(reasons, leadership.reviewedByHuman !== true, 'leadership_human_review_absent');
  addReason(reasons, !isDigest(leadership.evidenceHash), 'leadership_evidence_hash_invalid');
  addReason(reasons, !isDigest(leadership.successionPlanHash), 'leadership_succession_plan_absent');
  addReason(
    reasons,
    leadership.riskCqiCommunicationCovered !== true,
    'leadership_risk_cqi_communication_absent',
  );
}

function validateWellbeing(input, checkedAt, reasons) {
  const wellbeing = input?.wellbeingSafeguards;
  if (wellbeing === null || typeof wellbeing !== 'object') {
    reasons.push('wellbeing_safeguards_absent');
    return;
  }

  addReason(reasons, wellbeing.status !== 'active', 'wellbeing_safeguards_inactive');
  addReason(reasons, wellbeing.reviewedByHuman !== true, 'wellbeing_human_review_absent');
  addReason(reasons, !isDigest(wellbeing.riskAssessmentHash), 'wellbeing_risk_assessment_absent');
  addReason(reasons, !isDigest(wellbeing.noBlameMechanismHash), 'wellbeing_no_blame_mechanism_absent');
  addReason(reasons, !isDigest(wellbeing.complaintMechanismHash), 'wellbeing_complaint_mechanism_absent');
  addReason(reasons, !isDigest(wellbeing.communicationEvidenceHash), 'wellbeing_communication_evidence_absent');
  addReason(reasons, wellbeing.confidentialConcernRouteActive !== true, 'wellbeing_confidential_route_absent');
  addReason(reasons, hlcTuple(wellbeing.reviewedAtHlc) === null, 'wellbeing_review_time_invalid');
  addReason(reasons, afterCheck(checkedAt, wellbeing.reviewedAtHlc), 'wellbeing_review_after_check');
}

function validateCulture(input, reasons, gaps) {
  const culture = input?.peopleCenteredCulture;
  if (culture === null || typeof culture !== 'object') {
    reasons.push('people_centered_culture_absent');
    addGap(gaps, 'culture', 'people_centered_culture_absent');
    return [];
  }

  const domains = sortedTextList(culture.domains);

  addReason(reasons, culture.reviewedByHuman !== true, 'culture_human_review_absent');
  addReason(reasons, !isDigest(culture.evidenceHash), 'culture_evidence_hash_invalid');

  for (const domain of REQUIRED_CULTURE_DOMAINS) {
    if (!domains.includes(domain)) {
      const reason = `culture_domain_missing:${domain}`;
      reasons.push(reason);
      addGap(gaps, 'culture', reason);
    }
  }

  return domains;
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

function collectEvidenceHashes(input) {
  return [
    input.staffProfile?.staffIdHash,
    input.staffProfile?.titleHash,
    input.staffProfile?.departmentHash,
    input.staffProfile?.exochainIdentityRefHash,
    input.skillMixReview?.evidenceHash,
    input.orientationIntegration?.evidenceHash,
    input.performanceReview?.evidenceHash,
    input.performanceReview?.developmentPlanHash,
    input.leadershipDevelopment?.evidenceHash,
    input.leadershipDevelopment?.successionPlanHash,
    input.wellbeingSafeguards?.riskAssessmentHash,
    input.wellbeingSafeguards?.noBlameMechanismHash,
    input.wellbeingSafeguards?.complaintMechanismHash,
    input.wellbeingSafeguards?.communicationEvidenceHash,
    input.peopleCenteredCulture?.evidenceHash,
    input.aiAssistance?.recommendationHash,
  ].filter(isDigest).sort();
}

function buildWorkforceProfile(input, requiredRoleCoverage, orientationTopics, cultureDomains, receiptId) {
  const evidenceHashes = collectEvidenceHashes(input);
  const material = {
    actorDid: input.staffProfile.actorDid,
    authorityChainHash: input.authority.authorityChainHash,
    checkedAtHlc: input.checkedAtHlc,
    cultureDomains,
    employmentStatus: input.staffProfile.employmentStatus,
    evidenceHashes,
    orientationTopics,
    profileDomains: PROFILE_DOMAINS,
    profileId: input.staffProfile.profileId,
    requiredRoleCoverage,
    role: input.staffProfile.role,
    schema: 'cybermedica.workforce_profile_readiness_material.v1',
    siteId: input.siteId,
    staffIdHash: input.staffProfile.staffIdHash,
    tenantId: input.tenantId,
  };
  const profileHash = sha256Hex(material);

  return {
    schema: 'cybermedica.workforce_profile_readiness.v1',
    profileReadinessId: `cmwpr_${profileHash.slice(0, 32)}`,
    profileHash,
    tenantId: input.tenantId,
    siteId: input.siteId,
    profileId: input.staffProfile.profileId,
    staffIdHash: input.staffProfile.staffIdHash,
    actorDid: input.staffProfile.actorDid,
    role: input.staffProfile.role,
    employmentStatus: input.staffProfile.employmentStatus,
    checkedAtHlc: input.checkedAtHlc,
    profileDomains: [...PROFILE_DOMAINS],
    requiredRoleCoverage,
    orientationTopics,
    cultureDomains,
    evidenceHashes,
    authorityChainHash: input.authority.authorityChainHash,
    receiptId,
  };
}

function buildReceipt(input, profileHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'workforce_profile_readiness',
    artifactVersion: `${input.siteId}@${input.staffProfile.profileId}`,
    artifactHash: profileHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.checkedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['human_governance', 'metadata_only', 'staff_profile', 'workforce'],
    sourceSystem: 'cybermedica-qms',
  });
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function uniqueGaps(gaps) {
  return [...new Map(
    gaps
      .sort((left, right) => {
        const domainOrder = left.domain.localeCompare(right.domain);
        return domainOrder === 0 ? left.reason.localeCompare(right.reason) : domainOrder;
      })
      .map((gap) => [`${gap.domain}:${gap.reason}`, gap]),
  ).values()];
}

export function evaluateWorkforceProfileReadiness(input) {
  canonicalize(input ?? {});
  assertNoDirectStaffIdentifiers(input ?? {});

  const reasons = [];
  const gaps = [];
  const checkedAt = hlcTuple(input?.checkedAtHlc);

  validateBase(input, checkedAt, reasons);
  validateAuthority(input?.authority, reasons);
  validateStaffProfile(input, reasons);
  const requiredRoleCoverage = validateSkillMix(input, checkedAt, reasons, gaps);
  const orientationTopics = validateOrientation(input, checkedAt, reasons, gaps);
  validatePerformanceReview(input, checkedAt, reasons);
  validateLeadershipDevelopment(input, reasons);
  validateWellbeing(input, checkedAt, reasons);
  const cultureDomains = validateCulture(input, reasons, gaps);
  validateHumanGovernance(input, reasons);

  const normalizedReasons = uniqueReasons(reasons);
  if (normalizedReasons.length > 0) {
    return {
      schema: 'cybermedica.workforce_profile_readiness_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: normalizedReasons,
      gaps: uniqueGaps(gaps),
      workforceProfile: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const materialProfile = buildWorkforceProfile(input, requiredRoleCoverage, orientationTopics, cultureDomains, null);
  const receipt = buildReceipt(input, materialProfile.profileHash);
  const workforceProfile = {
    ...materialProfile,
    receiptId: receipt.receiptId,
  };

  return {
    schema: 'cybermedica.workforce_profile_readiness_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    gaps: [],
    workforceProfile,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
