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
const REQUIRED_PERMISSION = 'site_governance_review';

const READINESS_DOMAINS = Object.freeze([
  'communication_governance',
  'mission_vision_values',
  'quality_policy',
  'site_strategy',
]);

const REQUIRED_VALUE_DOMAINS = Object.freeze([
  'ethical',
  'innovation_improvement',
  'people_centered',
  'quality_oriented',
]);

const REQUIRED_STRATEGY_DOMAINS = Object.freeze([
  'budgets',
  'mission_vision_values_realization',
  'organizational_structure',
  'quality_management_scope',
  'resource_needs',
  'stakeholder_expectations',
  'supporting_policies',
  'technology_needs',
]);

const REQUIRED_INTERNAL_AUDIENCES = Object.freeze([
  'investigators',
  'quality_team',
  'site_leadership',
  'staff',
]);

const REQUIRED_EXTERNAL_AUDIENCES = Object.freeze([
  'auditors',
  'cro',
  'iec_irb',
  'monitors',
  'regulators',
  'sponsors',
  'stakeholders',
]);

const REQUIRED_COMMUNICATION_TOPICS = Object.freeze([
  'ae_sae_lessons_learned',
  'deviations',
  'feedback',
  'protocol_requirements',
  'quality_improvement_results',
  'regulatory_changes',
  'safety_governance_updates',
  'strategy_updates',
]);

const RAW_GOVERNANCE_FIELDS = new Set([
  'communicationbody',
  'directcommunication',
  'freetextmission',
  'freetextstrategy',
  'freetextvalues',
  'missionnarrative',
  'rawcommunication',
  'rawcommunicationbody',
  'rawmission',
  'rawmissionstatement',
  'rawstrategy',
  'rawstrategynarrative',
  'rawvalues',
  'rawvision',
  'sponsorconfidentialupdate',
  'strategynarrative',
  'valuesnarrative',
  'visionnarrative',
]);

const SECRET_GOVERNANCE_FIELDS = new Set([
  'accesstoken',
  'adaptersecret',
  'apikey',
  'authorizationheader',
  'bearertoken',
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

function assertNoGovernanceProtectedContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoGovernanceProtectedContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_GOVERNANCE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`site governance raw content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_GOVERNANCE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`site governance secret field is not allowed at ${path}.${key}`);
    }
    assertNoGovernanceProtectedContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoGovernanceProtectedContent(input ?? {});
  canonicalize(input ?? {});
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

function hasAuthorityPermission(authority) {
  return Array.isArray(authority?.permissions) &&
    (authority.permissions.includes(REQUIRED_PERMISSION) || authority.permissions.includes('govern'));
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

function validateLeadershipApproval(prefix, approval, checkedAt, reasons) {
  addReason(reasons, !hasText(approval?.approvedByDid), `${prefix}_leadership_approver_absent`);
  addReason(reasons, !isDigest(approval?.approvalEvidenceHash), `${prefix}_approval_evidence_hash_invalid`);
  addReason(reasons, hlcTuple(approval?.approvedAtHlc) === null, `${prefix}_approval_time_invalid`);
  addReason(reasons, afterCheck(checkedAt, approval?.approvedAtHlc), `${prefix}_approval_after_check`);
}

function validateAnnualReview(prefix, review, checkedAt, reasons) {
  addReason(reasons, review?.status !== 'current', `${prefix}_review_not_current`);
  addReason(reasons, !isDigest(review?.evidenceHash), `${prefix}_review_evidence_hash_invalid`);
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, `${prefix}_review_time_invalid`);
  addReason(reasons, hlcTuple(review?.nextReviewDueHlc) === null, `${prefix}_next_review_time_invalid`);
  addReason(reasons, afterCheck(checkedAt, review?.reviewedAtHlc), `${prefix}_review_after_check`);
  addReason(reasons, notAfter(review?.nextReviewDueHlc, review?.reviewedAtHlc), `${prefix}_next_review_not_after_last`);
  addReason(reasons, checkedPastDue(checkedAt, review?.nextReviewDueHlc), `${prefix}_review_overdue`);
}

function validateRequiredCoverage(actualValues, requiredValues, reasons, gaps, reasonPrefix, gapDomain) {
  const actual = sortedTextList(actualValues);
  for (const required of requiredValues) {
    if (!actual.includes(required)) {
      const reason = `${reasonPrefix}:${required}`;
      reasons.push(reason);
      addGap(gaps, gapDomain, reason);
    }
  }
  return actual;
}

function validateQualityPolicy(input, checkedAt, reasons, gaps) {
  const policy = input?.qualityPolicy;
  if (policy === null || typeof policy !== 'object') {
    reasons.push('quality_policy_absent');
    addGap(gaps, 'quality_policy', 'quality_policy_absent');
    return null;
  }

  addReason(reasons, !hasText(policy.policyRef), 'quality_policy_ref_absent');
  addReason(reasons, !hasText(policy.version), 'quality_policy_version_absent');
  addReason(reasons, policy.status !== 'approved', 'quality_policy_not_approved');
  addReason(reasons, !isDigest(policy.policyHash), 'quality_policy_hash_invalid');
  validateLeadershipApproval('quality_policy', policy.leadershipApproval, checkedAt, reasons);
  validateAnnualReview('quality_policy', policy.annualReview, checkedAt, reasons);
  addReason(reasons, !isDigest(policy.staffCommunicationEvidenceHash), 'quality_policy_staff_communication_absent');
  addReason(reasons, !isDigest(policy.strategyLinkHash), 'quality_policy_strategy_link_absent');
  addReason(reasons, !isDigest(policy.evidenceHash), 'quality_policy_evidence_hash_invalid');
  return policy.policyRef;
}

function validateMissionVisionValues(input, checkedAt, reasons, gaps) {
  const mvv = input?.missionVisionValues;
  if (mvv === null || typeof mvv !== 'object') {
    reasons.push('mission_vision_values_absent');
    addGap(gaps, 'mission_vision_values', 'mission_vision_values_absent');
    return { ref: null, valueDomains: [] };
  }

  addReason(reasons, !hasText(mvv.statementRef), 'mvv_ref_absent');
  addReason(reasons, !hasText(mvv.version), 'mvv_version_absent');
  addReason(reasons, mvv.status !== 'approved', 'mission_vision_values_not_approved');
  addReason(reasons, !isDigest(mvv.missionHash), 'mvv_mission_hash_invalid');
  addReason(reasons, !isDigest(mvv.visionHash), 'mvv_vision_hash_invalid');
  addReason(reasons, !isDigest(mvv.valuesHash), 'mvv_values_hash_invalid');
  addReason(reasons, !isDigest(mvv.stakeholderConsultationHash), 'mvv_stakeholder_consultation_absent');
  addReason(reasons, !isDigest(mvv.communicationEvidenceHash), 'mvv_communication_evidence_absent');
  validateLeadershipApproval('mvv', mvv.leadershipApproval, checkedAt, reasons);
  validateAnnualReview('mvv', mvv.reviewCadence, checkedAt, reasons);
  const valueDomains = validateRequiredCoverage(
    mvv.valueDomains,
    REQUIRED_VALUE_DOMAINS,
    reasons,
    gaps,
    'mvv_value_domain_missing',
    'mission_vision_values',
  );
  return { ref: mvv.statementRef, valueDomains };
}

function validateSiteStrategy(input, checkedAt, reasons, gaps) {
  const strategy = input?.siteStrategy;
  if (strategy === null || typeof strategy !== 'object') {
    reasons.push('site_strategy_absent');
    addGap(gaps, 'site_strategy', 'site_strategy_absent');
    return { ref: null, strategyDomains: [] };
  }

  addReason(reasons, !hasText(strategy.strategyRef), 'strategy_ref_absent');
  addReason(reasons, !hasText(strategy.version), 'strategy_version_absent');
  addReason(reasons, strategy.status !== 'approved', 'strategy_not_approved');
  addReason(reasons, !isDigest(strategy.strategyHash), 'strategy_hash_invalid');
  validateAnnualReview('strategy', strategy.annualReview, checkedAt, reasons);
  const strategyDomains = validateRequiredCoverage(
    strategy.coveredDomains,
    REQUIRED_STRATEGY_DOMAINS,
    reasons,
    gaps,
    'strategy_domain_missing',
    'site_strategy',
  );
  addReason(reasons, !isDigest(strategy.lessonsLearnedHash), 'strategy_lessons_learned_absent');
  addReason(reasons, !isDigest(strategy.resourcePlanningHash), 'strategy_resource_planning_absent');
  addReason(reasons, sortedTextList(strategy.qualityObjectiveRefs).length === 0, 'strategy_quality_objectives_absent');
  addReason(reasons, sortedTextList(strategy.supportingPolicyRefs).length === 0, 'strategy_supporting_policies_absent');
  return { ref: strategy.strategyRef, strategyDomains };
}

function validateCommunicationGovernance(input, checkedAt, reasons, gaps) {
  const communication = input?.communicationGovernance;
  if (communication === null || typeof communication !== 'object') {
    reasons.push('communication_governance_absent');
    addGap(gaps, 'communication_governance', 'communication_governance_absent');
    return { ref: null, internalAudiences: [], externalAudiences: [], topics: [] };
  }

  addReason(reasons, !hasText(communication.planRef), 'communication_plan_ref_absent');
  addReason(reasons, !hasText(communication.version), 'communication_plan_version_absent');
  addReason(reasons, communication.status !== 'approved', 'communication_governance_not_approved');
  addReason(reasons, !isDigest(communication.planHash), 'communication_plan_hash_invalid');
  addReason(reasons, communication.reviewedByHuman !== true, 'communication_human_review_absent');
  addReason(reasons, hlcTuple(communication.reviewedAtHlc) === null, 'communication_review_time_invalid');
  addReason(reasons, hlcTuple(communication.nextReviewDueHlc) === null, 'communication_next_review_time_invalid');
  addReason(reasons, afterCheck(checkedAt, communication.reviewedAtHlc), 'communication_review_after_check');
  addReason(
    reasons,
    notAfter(communication.nextReviewDueHlc, communication.reviewedAtHlc),
    'communication_next_review_not_after_last',
  );
  addReason(reasons, checkedPastDue(checkedAt, communication.nextReviewDueHlc), 'communication_review_overdue');
  const internalAudiences = validateRequiredCoverage(
    communication.internalAudienceRefs,
    REQUIRED_INTERNAL_AUDIENCES,
    reasons,
    gaps,
    'communication_internal_audience_missing',
    'communication_governance',
  );
  const externalAudiences = validateRequiredCoverage(
    communication.externalAudienceRefs,
    REQUIRED_EXTERNAL_AUDIENCES,
    reasons,
    gaps,
    'communication_external_audience_missing',
    'communication_governance',
  );
  const topics = validateRequiredCoverage(
    communication.topicRefs,
    REQUIRED_COMMUNICATION_TOPICS,
    reasons,
    gaps,
    'communication_topic_missing',
    'communication_governance',
  );
  addReason(
    reasons,
    sortedTextList(communication.channelPolicyRefs).length === 0,
    'communication_channel_policies_absent',
  );
  addReason(reasons, !hasText(communication.escalationOwnerDid), 'communication_escalation_owner_absent');
  addReason(reasons, !isDigest(communication.escalationPathHash), 'communication_escalation_path_absent');
  addReason(reasons, !isDigest(communication.stakeholderFeedbackHash), 'communication_stakeholder_feedback_absent');
  return { ref: communication.planRef, internalAudiences, externalAudiences, topics };
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
    input.qualityPolicy?.policyHash,
    input.qualityPolicy?.leadershipApproval?.approvalEvidenceHash,
    input.qualityPolicy?.annualReview?.evidenceHash,
    input.qualityPolicy?.staffCommunicationEvidenceHash,
    input.qualityPolicy?.strategyLinkHash,
    input.qualityPolicy?.evidenceHash,
    input.missionVisionValues?.missionHash,
    input.missionVisionValues?.visionHash,
    input.missionVisionValues?.valuesHash,
    input.missionVisionValues?.stakeholderConsultationHash,
    input.missionVisionValues?.leadershipApproval?.approvalEvidenceHash,
    input.missionVisionValues?.reviewCadence?.evidenceHash,
    input.missionVisionValues?.communicationEvidenceHash,
    input.siteStrategy?.strategyHash,
    input.siteStrategy?.annualReview?.evidenceHash,
    input.siteStrategy?.lessonsLearnedHash,
    input.siteStrategy?.resourcePlanningHash,
    input.communicationGovernance?.planHash,
    input.communicationGovernance?.escalationPathHash,
    input.communicationGovernance?.stakeholderFeedbackHash,
    input.aiAssistance?.recommendationHash,
  ].filter(isDigest).sort();
}

function buildSiteGovernance(
  input,
  qualityPolicyRef,
  missionVisionValuesRef,
  strategyRef,
  communicationPlanRef,
  strategyDomains,
  valueDomains,
  internalAudiences,
  externalAudiences,
  communicationTopics,
  receiptId,
) {
  const evidenceHashes = collectEvidenceHashes(input);
  const material = {
    authorityChainHash: input.authority.authorityChainHash,
    checkedAtHlc: input.checkedAtHlc,
    communicationAudiences: {
      external: externalAudiences,
      internal: internalAudiences,
    },
    communicationPlanRef,
    communicationTopics,
    evidenceHashes,
    missionVisionValuesRef,
    qualityPolicyRef,
    readinessDomains: READINESS_DOMAINS,
    schema: 'cybermedica.site_governance_readiness_material.v1',
    siteId: input.siteId,
    strategyDomains,
    strategyRef,
    tenantId: input.tenantId,
    valueDomains,
  };
  const governanceHash = sha256Hex(material);

  return {
    schema: 'cybermedica.site_governance_readiness.v1',
    readinessId: `cmsg_${governanceHash.slice(0, 32)}`,
    governanceHash,
    tenantId: input.tenantId,
    siteId: input.siteId,
    checkedAtHlc: input.checkedAtHlc,
    readinessDomains: [...READINESS_DOMAINS],
    qualityPolicyRef,
    missionVisionValuesRef,
    strategyRef,
    communicationPlanRef,
    strategyDomains,
    valueDomains,
    communicationAudiences: {
      internal: internalAudiences,
      external: externalAudiences,
    },
    communicationTopics,
    evidenceHashes,
    authorityChainHash: input.authority.authorityChainHash,
    receiptId,
  };
}

function buildReceipt(input, governanceHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'site_governance_readiness',
    artifactVersion: `${input.siteId}@${input.siteStrategy.strategyRef}@${input.communicationGovernance.planRef}`,
    artifactHash: governanceHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.checkedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['human_governance', 'metadata_only', 'site_governance', 'strategy_communications'],
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

export function evaluateSiteGovernanceReadiness(input) {
  assertMetadataOnly(input ?? {});

  const reasons = [];
  const gaps = [];
  const checkedAt = hlcTuple(input?.checkedAtHlc);

  validateBase(input, checkedAt, reasons);
  validateAuthority(input?.authority, reasons);
  const qualityPolicyRef = validateQualityPolicy(input, checkedAt, reasons, gaps);
  const { ref: missionVisionValuesRef, valueDomains } = validateMissionVisionValues(input, checkedAt, reasons, gaps);
  const { ref: strategyRef, strategyDomains } = validateSiteStrategy(input, checkedAt, reasons, gaps);
  const { ref: communicationPlanRef, internalAudiences, externalAudiences, topics } = validateCommunicationGovernance(
    input,
    checkedAt,
    reasons,
    gaps,
  );
  validateHumanGovernance(input, reasons);

  const normalizedReasons = uniqueReasons(reasons);
  if (normalizedReasons.length > 0) {
    return {
      schema: 'cybermedica.site_governance_readiness_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: normalizedReasons,
      gaps: uniqueGaps(gaps),
      siteGovernance: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const materialGovernance = buildSiteGovernance(
    input,
    qualityPolicyRef,
    missionVisionValuesRef,
    strategyRef,
    communicationPlanRef,
    strategyDomains,
    valueDomains,
    internalAudiences,
    externalAudiences,
    topics,
    null,
  );
  const receipt = buildReceipt(input, materialGovernance.governanceHash);
  const siteGovernance = {
    ...materialGovernance,
    receiptId: receipt.receiptId,
  };

  return {
    schema: 'cybermedica.site_governance_readiness_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    gaps: [],
    siteGovernance,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
