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
const REQUIRED_DOMAINS = Object.freeze([
  'equipment',
  'facility',
  'financial',
  'insurance',
  'participant_population',
  'privacy_data',
  'product_handling',
  'recruitment',
  'reporting',
  'staffing',
  'training',
  'vendor',
]);
const REVIEW_TYPES = new Set(['protocol_feasibility']);
const REVIEW_STATUSES = new Set(['accepted', 'accepted_with_conditions', 'deferred', 'rejected']);
const LEADERSHIP_DECISIONS = new Set(['accept', 'accept_with_conditions', 'defer', 'reject']);
const DOMAIN_STATUSES = new Set(['feasible', 'feasible_with_conditions', 'deferred', 'not_feasible']);
const GAP_SEVERITIES = new Set(['minor', 'major', 'critical']);
const GAP_STATUSES = new Set(['open', 'accepted', 'mitigated', 'closed', 'deferred']);
const RAW_PROTOCOL_FIELDS = new Set([
  'clinicaltrialagreementbody',
  'freetextfeasibilitynotes',
  'investigatorbrochurebody',
  'patientdetails',
  'participantdetails',
  'protocolbody',
  'protocolnarrative',
  'rawfeasibilityreview',
  'rawprotocol',
  'rawprotocolbody',
  'recruitmentnarrative',
  'sourcedocumentbody',
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

function assertNoRawProtocolText(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawProtocolText(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    if (RAW_PROTOCOL_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`raw protocol content field is not allowed at ${path}.${key}`);
    }
    assertNoRawProtocolText(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawProtocolText(input ?? {});
  canonicalize(input ?? {});
}

function hlcPresent(hlc) {
  return Number.isSafeInteger(hlc?.physicalMs) && Number.isSafeInteger(hlc?.logical);
}

function sortedTextList(value) {
  return Array.isArray(value) ? value.filter(hasText).sort() : [];
}

function sortedDigestList(value) {
  return Array.isArray(value) ? value.filter(isDigest).sort() : [];
}

function uniqueSorted(value) {
  return [...new Set(value)].sort();
}

function hasPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function basisPoints(numerator, denominator) {
  return Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
}

function domainSort(left, right) {
  return String(left.domain).localeCompare(String(right.domain));
}

function gapSort(left, right) {
  return String(left.gapRef).localeCompare(String(right.gapRef));
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
  addReason(reasons, !hasPermission(input?.authority, 'govern'), 'authority_permission_missing');
}

function evaluateReviewMetadata(review, reasons) {
  addReason(reasons, !hasText(review?.reviewRef), 'review_ref_absent');
  addReason(reasons, !hasText(review?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(review?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(review?.sponsorRef), 'sponsor_ref_absent');
  addReason(reasons, !hasText(review?.croRef), 'cro_ref_absent');
  addReason(reasons, !REVIEW_TYPES.has(review?.reviewType), 'review_type_invalid');
  addReason(reasons, !REVIEW_STATUSES.has(review?.status), 'review_status_invalid');
  addReason(reasons, !hlcPresent(review?.createdAtHlc), 'review_time_invalid');
  addReason(reasons, !hasText(review?.qualityReviewRef), 'quality_review_ref_absent');
  addReason(reasons, sortedTextList(review?.policyRefs).length === 0, 'policy_refs_absent');
  addReason(reasons, review?.status === 'deferred', 'protocol_feasibility_deferred');
  addReason(reasons, review?.status === 'rejected', 'protocol_feasibility_rejected');
}

function evaluateIntake(intake, reasons) {
  addReason(reasons, !isDigest(intake?.protocolHash), 'protocol_hash_invalid');
  addReason(reasons, !isDigest(intake?.investigatorBrochureHash), 'investigator_brochure_hash_invalid');
  addReason(reasons, !isDigest(intake?.productInformationHash), 'product_information_hash_invalid');
  addReason(reasons, !isDigest(intake?.sponsorQuestionnaireHash), 'sponsor_questionnaire_hash_invalid');
  addReason(reasons, !isDigest(intake?.clinicalTrialAgreementHash), 'clinical_trial_agreement_hash_invalid');
  addReason(
    reasons,
    !Array.isArray(intake?.regulatoryRequirementHashes) ||
      intake.regulatoryRequirementHashes.length === 0 ||
      intake.regulatoryRequirementHashes.some((hash) => !isDigest(hash)),
    'regulatory_requirements_absent',
  );
}

function evaluateHumanGovernance(input, reasons) {
  const forum = input?.review?.decisionForum;
  addReason(reasons, forum?.verified !== true, 'decision_forum_unverified');
  addReason(reasons, forum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, forum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, forum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, forum?.openChallenge === true, 'challenge_open');
  addReason(reasons, !hasText(forum?.decisionId), 'decision_forum_id_absent');
  addReason(reasons, !hasText(forum?.workflowReceiptId), 'decision_forum_receipt_absent');
  addReason(reasons, input?.review?.evidenceBundle?.complete !== true, 'evidence_bundle_incomplete');
  addReason(reasons, input?.review?.evidenceBundle?.phiBoundaryAttested !== true, 'phi_boundary_unattested');
  addReason(reasons, !hasText(input?.review?.qualityReviewerDid), 'quality_reviewer_absent');
}

function evaluateAiFitReview(aiFitReview, reasons) {
  addReason(reasons, aiFitReview?.completed !== true, 'ai_fit_review_incomplete');
  addReason(reasons, aiFitReview?.advisoryOnly !== true || aiFitReview?.finalAuthority === true, 'ai_fit_review_must_be_advisory');
  addReason(reasons, aiFitReview?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, !hasText(aiFitReview?.reviewerRole), 'ai_fit_review_human_reviewer_role_absent');
  addReason(reasons, !isDigest(aiFitReview?.outputHash), 'ai_fit_review_output_invalid');
  addReason(
    reasons,
    !Array.isArray(aiFitReview?.evidenceUsedHashes) ||
      aiFitReview.evidenceUsedHashes.length === 0 ||
      aiFitReview.evidenceUsedHashes.some((hash) => !isDigest(hash)),
    'ai_fit_review_evidence_hash_invalid',
  );
}

function evaluateStartupRiskAssessment(startupRiskAssessment, reasons) {
  addReason(reasons, !hasText(startupRiskAssessment?.assessmentRef), 'startup_risk_assessment_ref_absent');
  addReason(
    reasons,
    startupRiskAssessment?.status !== 'approved' && startupRiskAssessment?.status !== 'approved_with_conditions',
    'startup_risk_assessment_not_approved',
  );
  addReason(reasons, !hasText(startupRiskAssessment?.receiptId), 'startup_risk_receipt_absent');
  addReason(reasons, !isDigest(startupRiskAssessment?.artifactHash), 'startup_risk_artifact_hash_invalid');
}

function evaluateLeadershipDecision(leadershipDecision, reasons) {
  addReason(reasons, !LEADERSHIP_DECISIONS.has(leadershipDecision?.decision), 'leadership_decision_invalid');
  addReason(reasons, leadershipDecision?.decision === 'defer', 'protocol_feasibility_deferred');
  addReason(reasons, leadershipDecision?.decision === 'reject', 'protocol_feasibility_rejected');
  addReason(reasons, !hasText(leadershipDecision?.decisionMakerDid), 'leadership_decision_maker_absent');
  addReason(reasons, !isDigest(leadershipDecision?.rationaleHash), 'leadership_rationale_invalid');
  addReason(reasons, !hlcPresent(leadershipDecision?.signedAtHlc), 'leadership_decision_time_invalid');
}

function evaluateRequiredDomains(domainReviews, reasons) {
  const present = new Set(
    domainReviews.map((review) => review.domain).filter((domain) => REQUIRED_DOMAINS.includes(domain)),
  );
  for (const domain of REQUIRED_DOMAINS) {
    addReason(reasons, !present.has(domain), `required_feasibility_domain_missing:${domain}`);
  }
  return [...present].sort();
}

function evaluateDomainReview(review, reasons) {
  const domain = hasText(review?.domain) ? review.domain : 'unknown';
  const evidenceHashes = sortedDigestList(review?.evidenceHashes);
  const controlRefs = sortedTextList(review?.controlRefs);
  const gapRefs = sortedTextList(review?.gapRefs);
  const ready = review?.status === 'feasible' || review?.status === 'feasible_with_conditions';

  addReason(reasons, !REQUIRED_DOMAINS.includes(review?.domain), `feasibility_domain_invalid:${domain}`);
  addReason(reasons, !DOMAIN_STATUSES.has(review?.status), `feasibility_domain_status_invalid:${domain}`);
  addReason(reasons, DOMAIN_STATUSES.has(review?.status) && !ready, `feasibility_domain_not_ready:${domain}`);
  addReason(reasons, !hasText(review?.ownerDid), `feasibility_domain_owner_absent:${domain}`);
  addReason(
    reasons,
    !Array.isArray(review?.evidenceHashes) || review.evidenceHashes.length === 0 || review.evidenceHashes.some((hash) => !isDigest(hash)),
    `feasibility_domain_evidence_invalid:${domain}`,
  );
  addReason(reasons, controlRefs.length === 0, `feasibility_domain_control_absent:${domain}`);
  addReason(reasons, !isDigest(review?.decisionRationaleHash), `feasibility_domain_rationale_invalid:${domain}`);

  return {
    schema: 'cybermedica.protocol_feasibility_domain.v1',
    domain,
    status: review?.status,
    ready,
    ownerDid: review?.ownerDid,
    evidenceHashes,
    controlRefs,
    gapRefs,
    decisionRationaleHash: review?.decisionRationaleHash,
  };
}

function openGapSummary(gaps) {
  const summary = { critical: 0, major: 0, minor: 0 };
  for (const gap of gaps) {
    if (GAP_SEVERITIES.has(gap.severity) && gap.status !== 'closed' && gap.status !== 'mitigated') {
      summary[gap.severity] += 1;
    }
  }
  return summary;
}

function evaluateGap(gap, reasons) {
  const gapRef = hasText(gap?.gapRef) ? gap.gapRef : 'unknown';
  const needsMitigation = gap?.status !== 'closed';
  const normalizedGap = {
    schema: 'cybermedica.protocol_feasibility_gap.v1',
    gapRef,
    severity: gap?.severity,
    status: gap?.status,
    ownerDid: gap?.ownerDid,
    mitigationHash: gap?.mitigationHash,
    openForAcceptanceCondition: GAP_SEVERITIES.has(gap?.severity) && gap?.status !== 'closed' && gap?.status !== 'mitigated',
  };

  addReason(reasons, !hasText(gap?.gapRef), 'gap_ref_absent');
  addReason(reasons, !GAP_SEVERITIES.has(gap?.severity), `gap_severity_invalid:${gapRef}`);
  addReason(reasons, !GAP_STATUSES.has(gap?.status), `gap_status_invalid:${gapRef}`);
  addReason(reasons, !hasText(gap?.ownerDid), `gap_owner_absent:${gapRef}`);
  addReason(reasons, needsMitigation && !isDigest(gap?.mitigationHash), `gap_mitigation_invalid:${gapRef}`);
  addReason(
    reasons,
    gap?.severity === 'critical' && gap?.status !== 'closed' && gap?.status !== 'mitigated',
    `critical_gap_unresolved:${gapRef}`,
  );
  addReason(
    reasons,
    gap?.severity === 'major' && gap?.status !== 'closed' && gap?.status !== 'mitigated' && !isDigest(gap?.mitigationHash),
    `major_gap_unmitigated:${gapRef}`,
  );

  if (gap?.targetResolutionHlc !== undefined) {
    normalizedGap.targetResolutionHlc = gap.targetResolutionHlc;
  }

  return normalizedGap;
}

function requiredEscalationRoles(gaps) {
  const roles = [];
  for (const gap of gaps) {
    if (!gap.openForAcceptanceCondition) {
      continue;
    }
    if (gap.severity === 'major' || gap.severity === 'critical') {
      roles.push('decision_forum', 'principal_investigator', 'site_quality_lead');
    }
  }
  return uniqueSorted(roles);
}

function normalizeDomainReviews(input, reasons) {
  const reviews = Array.isArray(input?.domainReviews) ? [...input.domainReviews].sort(domainSort) : [];
  addReason(reasons, reviews.length === 0, 'feasibility_domain_inventory_empty');
  const coveredDomains = evaluateRequiredDomains(reviews, reasons);
  const normalizedDomains = reviews.map((review) => evaluateDomainReview(review, reasons));
  return { coveredDomains, normalizedDomains };
}

function normalizeGaps(input, reasons) {
  const gaps = Array.isArray(input?.gaps) ? [...input.gaps].sort(gapSort) : [];
  const normalizedGaps = gaps.map((gap) => evaluateGap(gap, reasons));
  return normalizedGaps;
}

function buildFeasibilityReview(input, normalizedDomains, coveredDomains, normalizedGaps, reasons) {
  const sortedReasons = uniqueSorted(reasons);
  const readyDomainCount = normalizedDomains.filter((review) => review.ready && REQUIRED_DOMAINS.includes(review.domain)).length;
  const openSummary = openGapSummary(normalizedGaps);
  const cleanAcceptance =
    sortedReasons.length === 0 && input?.feasibilityReview?.status === 'accepted'
      ? 'accepted'
      : sortedReasons.length === 0 && input?.feasibilityReview?.status === 'accepted_with_conditions'
        ? 'accepted_with_conditions'
        : 'blocked';
  const escalationRoles = requiredEscalationRoles(normalizedGaps);
  const material = {
    acceptanceStatus: cleanAcceptance,
    coveredDomains,
    gaps: normalizedGaps,
    protocolRef: input?.feasibilityReview?.protocolRef,
    reviewRef: input?.feasibilityReview?.reviewRef,
    reviews: normalizedDomains,
    siteRef: input?.feasibilityReview?.siteRef,
    tenantId: input?.tenantId,
  };

  return {
    schema: 'cybermedica.protocol_feasibility_review.v1',
    tenantId: input?.tenantId,
    reviewRef: input?.feasibilityReview?.reviewRef,
    protocolRef: input?.feasibilityReview?.protocolRef,
    siteRef: input?.feasibilityReview?.siteRef,
    sponsorRef: input?.feasibilityReview?.sponsorRef,
    croRef: input?.feasibilityReview?.croRef,
    acceptanceStatus: cleanAcceptance,
    blockingGapPresent: sortedReasons.length > 0 || openSummary.critical > 0,
    aiFinalAuthority: false,
    exochainProductionClaim: false,
    trustState: 'inactive',
    coveredDomains,
    domainReadinessBasisPoints: basisPoints(readyDomainCount, REQUIRED_DOMAINS.length),
    domainReviews: normalizedDomains,
    gaps: normalizedGaps,
    openGapSummary: openSummary,
    requiredEscalationRoles: escalationRoles,
    aiFitReview: {
      completed: input?.aiFitReview?.completed === true,
      advisoryOnly: input?.aiFitReview?.advisoryOnly === true && input?.aiFitReview?.finalAuthority !== true,
      reviewerRole: input?.aiFitReview?.reviewerRole,
      outputHash: input?.aiFitReview?.outputHash,
      evidenceUsedHashes: sortedDigestList(input?.aiFitReview?.evidenceUsedHashes),
      unresolvedAssumptions: sortedTextList(input?.aiFitReview?.unresolvedAssumptions),
    },
    startupRiskAssessment: {
      assessmentRef: input?.startupRiskAssessment?.assessmentRef,
      status: input?.startupRiskAssessment?.status,
      artifactHash: input?.startupRiskAssessment?.artifactHash,
      receiptId: input?.startupRiskAssessment?.receiptId,
    },
    decisionForum: {
      decisionId: input?.review?.decisionForum?.decisionId,
      workflowReceiptId: input?.review?.decisionForum?.workflowReceiptId,
      verified: input?.review?.decisionForum?.verified === true,
      humanGateVerified: input?.review?.decisionForum?.humanGate?.verified === true,
      quorumStatus: input?.review?.decisionForum?.quorum?.status,
    },
    reviewId: `cmfeas_${sha256Hex(material).slice(0, 32)}`,
  };
}

function buildReceipt(input, feasibilityReview) {
  const artifactHash = sha256Hex({
    acceptanceStatus: feasibilityReview.acceptanceStatus,
    coveredDomains: feasibilityReview.coveredDomains,
    domainReadinessBasisPoints: feasibilityReview.domainReadinessBasisPoints,
    gaps: feasibilityReview.gaps,
    protocolRef: feasibilityReview.protocolRef,
    reviewId: feasibilityReview.reviewId,
    siteRef: feasibilityReview.siteRef,
    startupRiskAssessment: feasibilityReview.startupRiskAssessment,
  });

  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'protocol_feasibility_review',
    artifactVersion: `${input.feasibilityReview.reviewRef}@${input.feasibilityReview.createdAtHlc.physicalMs}.${input.feasibilityReview.createdAtHlc.logical}`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.feasibilityReview.createdAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['protocol_feasibility', 'site_fit', 'startup_readiness', 'metadata_only'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function evaluateProtocolFeasibilityReview(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateReviewMetadata(input?.feasibilityReview, reasons);
  evaluateIntake(input?.intake, reasons);
  evaluateAiFitReview(input?.aiFitReview, reasons);
  evaluateStartupRiskAssessment(input?.startupRiskAssessment, reasons);
  evaluateLeadershipDecision(input?.leadershipDecision, reasons);
  evaluateHumanGovernance(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
  const { coveredDomains, normalizedDomains } = normalizeDomainReviews(input, reasons);
  const normalizedGaps = normalizeGaps(input, reasons);
  const feasibilityReview = buildFeasibilityReview(input, normalizedDomains, coveredDomains, normalizedGaps, reasons);
  const sortedReasons = uniqueSorted(reasons);

  if (sortedReasons.length > 0) {
    return {
      decision: 'denied',
      failClosed: true,
      reasons: sortedReasons,
      feasibilityReview,
    };
  }

  return {
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    feasibilityReview,
    receipt: buildReceipt(input, feasibilityReview),
  };
}
