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
const REQUIRED_PERMISSION = 'manage_recruitment_feasibility';
const RECRUITMENT_SCHEMA = 'cybermedica.recruitment_feasibility.v1';
const DECISION_SCHEMA = 'cybermedica.recruitment_feasibility_decision.v1';

const REQUIRED_RECRUITMENT_CHANNELS = Object.freeze([
  'clinic_referral',
  'community_outreach',
  'database_prescreen',
  'participant_registry',
]);

const REQUIRED_SCREENING_DOMAINS = Object.freeze([
  'eligibility_precheck',
  'inclusion_exclusion_review',
  'privacy_prescreen_boundary',
  'source_traceability',
]);

const ACTIVE_STATUSES = new Set(['active']);
const CHANNEL_STATUSES = new Set(['active']);
const SCREENING_STATUSES = new Set(['ready']);

const RAW_RECRUITMENT_FIELDS = new Set([
  'advertisingcopy',
  'contactdetails',
  'contactemail',
  'contactphone',
  'directidentifier',
  'medicalrecordnumber',
  'participantidentifier',
  'participantname',
  'patientdetails',
  'patientname',
  'phone',
  'rawadcopy',
  'rawcontact',
  'rawoutreach',
  'rawpayload',
  'rawrecruitmentcopy',
  'rawrecruitmentmaterial',
  'rawscreeningnote',
  'screenernotes',
  'sourcedocumentbody',
  'subjectidentifier',
]);

const SECRET_RECRUITMENT_FIELDS = new Set([
  'accesstoken',
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
  return hasText(value) && HEX_64.test(value) && value !== ZERO_HASH;
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

function assertNoRawRecruitmentContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawRecruitmentContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_RECRUITMENT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw recruitment or participant-screening content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_RECRUITMENT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`recruitment secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawRecruitmentContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawRecruitmentContent(input ?? {});
  canonicalize(input ?? {});
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function sortedDigestList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(isDigest))].sort() : [];
}

function positiveSafeInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function safeNonNegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
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

function hlcBeforeOrEqual(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) <= 0;
}

function basisPoints(numerator, denominator) {
  if (!safeNonNegativeInteger(numerator) || !positiveSafeInteger(denominator)) {
    return 0;
  }
  const value = Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
  return Math.min(value, 10_000);
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
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
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'recruitment_feasibility_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePlan(plan, reasons) {
  addReason(reasons, !hasText(plan?.planRef), 'recruitment_plan_ref_absent');
  addReason(reasons, !hasText(plan?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(plan?.siteRef), 'site_ref_absent');
  addReason(reasons, !ACTIVE_STATUSES.has(plan?.status), 'recruitment_plan_not_active');
  addReason(reasons, !positiveSafeInteger(plan?.targetEnrollmentCount), 'target_enrollment_count_invalid');
  addReason(reasons, !positiveSafeInteger(plan?.recruitmentWindowDays), 'recruitment_window_days_invalid');
  addReason(reasons, !positiveSafeInteger(plan?.minimumScreeningCapacityCount), 'minimum_screening_capacity_invalid');
  addReason(
    reasons,
    !safeNonNegativeInteger(plan?.expectedScreenFailureBasisPoints) ||
      plan.expectedScreenFailureBasisPoints > 10_000,
    'screen_failure_basis_points_invalid',
  );
  addReason(reasons, !isDigest(plan?.populationEvidenceHash), 'population_evidence_hash_invalid');
  addReason(reasons, !isDigest(plan?.feasibilityProcedureHash), 'feasibility_procedure_hash_invalid');
  addReason(reasons, !hasText(plan?.consentReadinessRef), 'consent_readiness_ref_absent');
  addReason(reasons, !hasText(plan?.protocolFeasibilityRef), 'protocol_feasibility_ref_absent');
  addReason(reasons, !hasText(plan?.startupRiskAssessmentRef), 'startup_risk_assessment_ref_absent');
  addReason(reasons, hlcTuple(plan?.reviewedAtHlc) === null, 'recruitment_plan_review_time_invalid');
  addReason(reasons, plan?.metadataOnly !== true, 'recruitment_plan_metadata_boundary_invalid');
  addReason(reasons, plan?.protectedContentExcluded !== true, 'recruitment_plan_protected_boundary_invalid');
  addReason(reasons, plan?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function channelIdentity(channel) {
  return hasText(channel?.channelRef) ? channel.channelRef : 'unclassified_channel';
}

function evaluateChannel(channel, reviewedAtHlc, reasons) {
  const channelRef = channelIdentity(channel);
  addReason(reasons, !hasText(channel?.channelRef), 'channel_ref_absent');
  addReason(reasons, !REQUIRED_RECRUITMENT_CHANNELS.includes(channel?.channelRef), `recruitment_channel_unsupported:${channelRef}`);
  addReason(reasons, !CHANNEL_STATUSES.has(channel?.status), `channel_not_active:${channelRef}`);
  addReason(reasons, !safeNonNegativeInteger(channel?.forecastCount), `channel_forecast_count_invalid:${channelRef}`);
  addReason(reasons, !isDigest(channel?.evidenceHash), `channel_evidence_hash_invalid:${channelRef}`);
  addReason(reasons, !isDigest(channel?.iecIrbApprovalHash), `channel_iec_irb_approval_invalid:${channelRef}`);
  addReason(reasons, !isDigest(channel?.privacyBoundaryHash), `channel_privacy_boundary_invalid:${channelRef}`);
  addReason(reasons, !hasText(channel?.ownerDid), `channel_owner_absent:${channelRef}`);
  addReason(reasons, hlcTuple(channel?.lastReviewedAtHlc) === null, `channel_review_time_invalid:${channelRef}`);
  addReason(
    reasons,
    hlcTuple(channel?.lastReviewedAtHlc) !== null &&
      hlcTuple(reviewedAtHlc) !== null &&
      !hlcBeforeOrEqual(channel.lastReviewedAtHlc, reviewedAtHlc),
    `channel_review_after_plan_review:${channelRef}`,
  );
  addReason(reasons, !isDigest(channel?.nonCoercionReviewHash), `channel_non_coercion_review_invalid:${channelRef}`);
  addReason(reasons, channel?.metadataOnly !== true, `channel_metadata_boundary_invalid:${channelRef}`);
  addReason(reasons, channel?.protectedContentExcluded !== true, `channel_protected_boundary_invalid:${channelRef}`);
  addReason(
    reasons,
    channel?.vulnerablePopulationTargeted === true && sortedTextList(channel?.safeguardRefs).length === 0,
    `channel_vulnerable_safeguard_absent:${channelRef}`,
  );

  return {
    channelRef,
    forecastCount: safeNonNegativeInteger(channel?.forecastCount) ? channel.forecastCount : 0,
  };
}

function evaluateChannels(input, reasons) {
  const channels = Array.isArray(input?.recruitmentChannels) ? input.recruitmentChannels : [];
  addReason(reasons, channels.length === 0, 'recruitment_channel_inventory_absent');
  const summaries = channels.map((channel) => evaluateChannel(channel, input?.recruitmentPlan?.reviewedAtHlc, reasons));
  const channelsCovered = sortedTextList(summaries.map((summary) => summary.channelRef)).filter((channelRef) =>
    REQUIRED_RECRUITMENT_CHANNELS.includes(channelRef),
  );
  evaluateRequiredSet(
    channelsCovered,
    REQUIRED_RECRUITMENT_CHANNELS,
    'required_recruitment_channel_missing',
    'recruitment_channel_unsupported',
    reasons,
  );

  return {
    channelsCovered,
    forecastRecruitmentCount: summaries.reduce((total, summary) => total + summary.forecastCount, 0),
  };
}

function evaluateScreeningDomain(domain, reasons) {
  const domainRef = hasText(domain?.domainRef) ? domain.domainRef : 'unclassified_screening_domain';
  addReason(reasons, !hasText(domain?.domainRef), 'screening_domain_ref_absent');
  addReason(reasons, !REQUIRED_SCREENING_DOMAINS.includes(domain?.domainRef), `screening_domain_unsupported:${domainRef}`);
  addReason(reasons, !SCREENING_STATUSES.has(domain?.status), `screening_domain_not_ready:${domainRef}`);
  addReason(reasons, !isDigest(domain?.evidenceHash), `screening_domain_evidence_hash_invalid:${domainRef}`);
  addReason(reasons, !isDigest(domain?.policyHash), `screening_domain_policy_hash_invalid:${domainRef}`);
  addReason(reasons, !hasText(domain?.ownerDid), `screening_domain_owner_absent:${domainRef}`);
  addReason(reasons, domain?.participantIdentifierSuppressed !== true, `screening_domain_participant_identifier_not_suppressed:${domainRef}`);
  addReason(reasons, domain?.metadataOnly !== true, `screening_domain_metadata_boundary_invalid:${domainRef}`);
  addReason(reasons, domain?.protectedContentExcluded !== true, `screening_domain_protected_boundary_invalid:${domainRef}`);
  return domainRef;
}

function evaluateScreeningDomains(input, reasons) {
  const domains = Array.isArray(input?.screeningDomains) ? input.screeningDomains : [];
  addReason(reasons, domains.length === 0, 'screening_domain_inventory_absent');
  const covered = sortedTextList(domains.map((domain) => evaluateScreeningDomain(domain, reasons))).filter((domainRef) =>
    REQUIRED_SCREENING_DOMAINS.includes(domainRef),
  );
  evaluateRequiredSet(
    covered,
    REQUIRED_SCREENING_DOMAINS,
    'required_screening_domain_missing',
    'screening_domain_unsupported',
    reasons,
  );
  return covered;
}

function evaluateParticipantProtections(protections, reasons) {
  addReason(reasons, protections?.vulnerablePopulationSafeguardsApproved !== true, 'vulnerable_population_safeguards_not_approved');
  addReason(
    reasons,
    sortedDigestList(protections?.safeguardEvidenceHashes).length === 0,
    'vulnerable_population_safeguard_evidence_absent',
  );
  addReason(reasons, !hasText(protections?.consentMaterialRef), 'consent_material_ref_absent');
  addReason(reasons, !isDigest(protections?.nonCoercionPolicyHash), 'non_coercion_policy_hash_invalid');
  addReason(reasons, protections?.noRecruitmentBeforeLaunch !== true, 'recruitment_before_launch_guard_absent');
  addReason(reasons, protections?.noSupersededMaterials !== true, 'superseded_material_guard_absent');
  addReason(reasons, protections?.participantFacingMaterialIecIrbApproved !== true, 'participant_facing_material_approval_absent');
  addReason(reasons, protections?.privacyPrescreeningAttested !== true, 'privacy_prescreening_unattested');
  addReason(reasons, protections?.updatedInformationReconsentGate !== true, 'updated_information_reconsent_gate_absent');
  addReason(reasons, !isDigest(protections?.dataSharingConsentBoundaryHash), 'data_sharing_consent_boundary_hash_invalid');
  addReason(reasons, protections?.metadataOnly !== true, 'participant_protection_metadata_boundary_invalid');
  addReason(reasons, protections?.protectedContentExcluded !== true, 'participant_protection_protected_boundary_invalid');
}

function evaluateCapacityEvidence(input, channelSummary, reasons) {
  const capacity = input?.capacityEvidence;
  const plan = input?.recruitmentPlan;
  addReason(reasons, !safeNonNegativeInteger(capacity?.activeStaffCount), 'active_staff_count_invalid');
  addReason(reasons, !safeNonNegativeInteger(capacity?.trainedStaffCount), 'trained_staff_count_invalid');
  addReason(reasons, !safeNonNegativeInteger(capacity?.delegatedStaffCount), 'delegated_staff_count_invalid');
  addReason(reasons, !safeNonNegativeInteger(capacity?.screeningSlotCount), 'screening_slot_count_invalid');
  addReason(reasons, !safeNonNegativeInteger(capacity?.retentionSupportCapacityCount), 'retention_support_capacity_invalid');
  addReason(reasons, !isDigest(capacity?.staffTrainingMatrixHash), 'staff_training_matrix_hash_invalid');
  addReason(reasons, !isDigest(capacity?.delegationLogHash), 'delegation_log_hash_invalid');
  addReason(reasons, !isDigest(capacity?.facilityCapacityHash), 'facility_capacity_hash_invalid');
  addReason(reasons, !isDigest(capacity?.referralVolumeHash), 'referral_volume_hash_invalid');
  addReason(reasons, !isDigest(capacity?.monitoringMetricHash), 'monitoring_metric_hash_invalid');
  addReason(reasons, capacity?.metadataOnly !== true, 'capacity_metadata_boundary_invalid');
  addReason(
    reasons,
    safeNonNegativeInteger(capacity?.trainedStaffCount) &&
      safeNonNegativeInteger(capacity?.activeStaffCount) &&
      capacity.trainedStaffCount < capacity.activeStaffCount,
    'trained_staff_below_active_staff',
  );
  addReason(
    reasons,
    safeNonNegativeInteger(capacity?.delegatedStaffCount) &&
      safeNonNegativeInteger(capacity?.trainedStaffCount) &&
      capacity.delegatedStaffCount < capacity.trainedStaffCount,
    'delegated_staff_below_trained_staff',
  );
  addReason(
    reasons,
    safeNonNegativeInteger(capacity?.screeningSlotCount) &&
      positiveSafeInteger(plan?.minimumScreeningCapacityCount) &&
      capacity.screeningSlotCount < plan.minimumScreeningCapacityCount,
    'screening_capacity_below_required',
  );
  addReason(
    reasons,
    safeNonNegativeInteger(capacity?.retentionSupportCapacityCount) &&
      positiveSafeInteger(plan?.targetEnrollmentCount) &&
      capacity.retentionSupportCapacityCount < plan.targetEnrollmentCount,
    'retention_support_below_target_enrollment',
  );
  addReason(
    reasons,
    positiveSafeInteger(plan?.targetEnrollmentCount) &&
      channelSummary.forecastRecruitmentCount < plan.targetEnrollmentCount,
    'forecast_below_target_enrollment',
  );
}

function evaluateHumanGovernance(review, reasons) {
  const forum = review?.decisionForum;
  addReason(reasons, forum?.verified !== true, 'decision_forum_unverified');
  addReason(reasons, forum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, forum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, forum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, forum?.openChallenge === true, 'challenge_open');
  addReason(reasons, !hasText(forum?.decisionId), 'decision_forum_id_absent');
  addReason(reasons, !hasText(forum?.workflowReceiptId), 'decision_forum_receipt_absent');
  addReason(reasons, review?.evidenceBundle?.complete !== true, 'evidence_bundle_incomplete');
  addReason(reasons, review?.evidenceBundle?.phiBoundaryAttested !== true, 'phi_boundary_unattested');
  addReason(reasons, !hasText(review?.humanReviewerDid), 'human_reviewer_absent');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_final_authority_required');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
}

function buildRecruitmentFeasibility(input, channelSummary, screeningDomainsCovered, reasons) {
  const plan = input?.recruitmentPlan;
  const capacity = input?.capacityEvidence;
  const material = {
    schema: RECRUITMENT_SCHEMA,
    tenantId: input?.tenantId ?? '',
    planRef: plan?.planRef ?? '',
    protocolRef: plan?.protocolRef ?? '',
    siteRef: plan?.siteRef ?? '',
    channelsCovered: channelSummary.channelsCovered,
    screeningDomainsCovered,
    forecastRecruitmentCount: channelSummary.forecastRecruitmentCount,
    screeningCapacityCount: safeNonNegativeInteger(capacity?.screeningSlotCount) ? capacity.screeningSlotCount : 0,
    targetEnrollmentCount: positiveSafeInteger(plan?.targetEnrollmentCount) ? plan.targetEnrollmentCount : 0,
    reviewedAtHlc: plan?.reviewedAtHlc ?? null,
  };
  const screeningCapacityCount = material.screeningCapacityCount;
  const minimumScreeningCapacityCount = positiveSafeInteger(plan?.minimumScreeningCapacityCount)
    ? plan.minimumScreeningCapacityCount
    : 0;
  const permitted = reasons.length === 0;

  return {
    ...material,
    feasibilityId: `recruitment_feas_${sha256Hex(material).slice(0, 32)}`,
    readinessStatus: permitted ? 'ready_for_recruitment' : 'not_ready',
    trustState: 'inactive',
    exochainProductionClaim: false,
    aiFinalAuthority: input?.review?.aiFinalAuthority === true,
    safeguardStatus: input?.participantProtections?.vulnerablePopulationSafeguardsApproved === true && permitted ? 'approved' : 'blocked',
    screeningCoverageBasisPoints: basisPoints(screeningCapacityCount, minimumScreeningCapacityCount),
    minimumScreeningCapacityCount,
    recruitmentWindowDays: plan?.recruitmentWindowDays ?? null,
    expectedScreenFailureBasisPoints: plan?.expectedScreenFailureBasisPoints ?? null,
    activeStaffCount: capacity?.activeStaffCount ?? null,
    trainedStaffCount: capacity?.trainedStaffCount ?? null,
    delegatedStaffCount: capacity?.delegatedStaffCount ?? null,
    retentionSupportCapacityCount: capacity?.retentionSupportCapacityCount ?? null,
    decisionForum: {
      decisionId: input?.review?.decisionForum?.decisionId ?? null,
      workflowReceiptId: input?.review?.decisionForum?.workflowReceiptId ?? null,
      verified: input?.review?.decisionForum?.verified === true,
      humanGateVerified: input?.review?.decisionForum?.humanGate?.verified === true,
      quorumStatus: input?.review?.decisionForum?.quorum?.status ?? null,
    },
    metadataOnly: true,
    protectedContentExcluded: true,
  };
}

function createRecruitmentReceipt(input, recruitmentFeasibility) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: sha256Hex(recruitmentFeasibility),
    artifactType: 'recruitment_feasibility',
    artifactVersion: `${input.recruitmentPlan.planRef}@${input.recruitmentPlan.reviewedAtHlc.physicalMs}.${input.recruitmentPlan.reviewedAtHlc.logical}`,
    classification: 'participant-recruitment-metadata-only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.recruitmentPlan.reviewedAtHlc,
    sensitivityTags: ['metadata_only', 'participant_protection', 'protocol_startup', 'recruitment_feasibility'],
    sourceSystem: 'cybermedica-qms',
    tenantId: input.tenantId,
  });
}

export function evaluateRecruitmentFeasibility(input = {}) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluatePlan(input?.recruitmentPlan, reasons);
  const channelSummary = evaluateChannels(input, reasons);
  const screeningDomainsCovered = evaluateScreeningDomains(input, reasons);
  evaluateParticipantProtections(input?.participantProtections, reasons);
  evaluateCapacityEvidence(input, channelSummary, reasons);
  evaluateHumanGovernance(input?.review, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  const recruitmentFeasibility = buildRecruitmentFeasibility(input, channelSummary, screeningDomainsCovered, unique);
  const permitted = unique.length === 0;

  return {
    schema: DECISION_SCHEMA,
    decision: permitted ? 'permitted' : 'denied',
    failClosed: !permitted,
    recruitmentFeasibility,
    receipt: permitted ? createRecruitmentReceipt(input, recruitmentFeasibility) : null,
    reasons: unique,
    denialReasons: unique,
  };
}
