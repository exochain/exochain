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
const REQUIRED_PERMISSION = 'independent_ethics_review';
const ETHICS_SCHEMA = 'cybermedica.independent_ethics_review.v1';

const REQUIRED_MATERIAL_FAMILIES = Object.freeze([
  'amendment_package',
  'consent_form',
  'participant_information',
  'protocol_document',
  'recruitment_material',
]);

const REQUIRED_NOTIFICATION_AUDIENCES = Object.freeze([
  'cro',
  'investigator',
  'site_quality',
  'sponsor',
  'study_staff',
]);

const COMMITTEE_TYPES = new Set(['central_irb', 'ethics_committee', 'iec', 'irb']);
const MATERIAL_STATUSES = new Set(['approved', 'not_applicable']);

const RAW_ETHICS_FIELDS = new Set([
  'approvalletterbody',
  'consentformbody',
  'ethicsreviewletterbody',
  'freetextreview',
  'irbletterbody',
  'participantname',
  'protocolbody',
  'rawapprovalletter',
  'rawconsentform',
  'rawethicsreview',
  'rawirb',
  'rawirbletter',
  'rawprotocol',
  'rawrecruitmentmaterial',
  'sourcedocumentbody',
]);

const SECRET_ETHICS_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'apitoken',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credentialsecret',
  'integrationsecret',
  'password',
  'privatekey',
  'refreshtoken',
  'rootkey',
  'rootsigningkey',
  'secret',
  'servicetoken',
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

function assertNoEthicsPayloadOrSecrets(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoEthicsPayloadOrSecrets(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_ETHICS_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`independent ethics review source content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_ETHICS_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`independent ethics review secret field is not allowed at ${path}.${key}`);
    }
    assertNoEthicsPayloadOrSecrets(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoEthicsPayloadOrSecrets(input ?? {});
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

function uniqueSortedReasons(reasons) {
  return [...new Set(reasons)].sort();
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

function hlcBefore(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) < 0;
}

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function hasAuthorityPermission(authority) {
  return Array.isArray(authority?.permissions) &&
    (authority.permissions.includes(REQUIRED_PERMISSION) || authority.permissions.includes('govern'));
}

function basisPoints(numerator, denominator) {
  return Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
}

function materialSort(left, right) {
  return String(left.family).localeCompare(String(right.family)) ||
    String(left.materialRef).localeCompare(String(right.materialRef));
}

function notificationSort(left, right) {
  return String(left.audience).localeCompare(String(right.audience)) ||
    String(left.notificationRef).localeCompare(String(right.notificationRef));
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
  addReason(reasons, !hasAuthorityPermission(input?.authority), 'independent_ethics_review_authority_missing');
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateEthicsReview(review, reasons) {
  addReason(reasons, !hasText(review?.reviewRef), 'ethics_review_ref_absent');
  addReason(reasons, !hasText(review?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(review?.protocolVersionRef), 'protocol_version_ref_absent');
  addReason(reasons, !hasText(review?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(review?.studyRef), 'study_ref_absent');
  addReason(reasons, !hasText(review?.committeeRef), 'committee_ref_absent');
  addReason(reasons, !COMMITTEE_TYPES.has(review?.committeeType), 'committee_type_invalid');
  addReason(reasons, review?.status !== 'approved', 'ethics_review_not_approved');
  addReason(reasons, review?.independentCommitteeAttested !== true, 'committee_independence_absent');
  addReason(reasons, review?.aiRepresentedAsEthicsApproval === true, 'ai_irb_confusion_forbidden');
  addReason(reasons, !isDigest(review?.approvalEvidenceHash), 'approval_evidence_hash_invalid');
  addReason(reasons, !isDigest(review?.approvalLetterHash), 'approval_letter_hash_invalid');
  addReason(reasons, hlcTuple(review?.approvedAtHlc) === null, 'approval_time_invalid');
  addReason(reasons, hlcTuple(review?.effectiveAtHlc) === null, 'effective_time_invalid');
  addReason(reasons, hlcTuple(review?.expiresAtHlc) === null, 'expiration_time_invalid');
  addReason(reasons, hlcTuple(review?.evaluatedAtHlc) === null, 'evaluation_time_invalid');
  addReason(reasons, hlcBefore(review?.effectiveAtHlc, review?.approvedAtHlc), 'effective_before_approval');
  addReason(reasons, hlcBefore(review?.expiresAtHlc, review?.effectiveAtHlc), 'expiration_before_effective');
  addReason(reasons, hlcBefore(review?.expiresAtHlc, review?.evaluatedAtHlc), 'approval_expires_before_evaluation');
  addReason(reasons, review?.metadataOnly !== true, 'ethics_review_metadata_boundary_invalid');
  addReason(reasons, review?.protectedContentExcluded !== true, 'ethics_review_protected_boundary_invalid');
  addReason(reasons, review?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function normalizeApprovedMaterials(input, reasons) {
  const materials = Array.isArray(input?.approvedMaterials) ? [...input.approvedMaterials].sort(materialSort) : [];
  addReason(reasons, materials.length === 0, 'approved_materials_absent');

  const coveredFamilies = new Set();
  for (const material of materials) {
    const family = hasText(material?.family) ? material.family : 'unknown';
    addReason(reasons, !REQUIRED_MATERIAL_FAMILIES.includes(family), `approved_material_family_unsupported:${family}`);
    if (REQUIRED_MATERIAL_FAMILIES.includes(family)) {
      coveredFamilies.add(family);
    }
    addReason(reasons, !hasText(material?.materialRef), `material_ref_absent:${family}`);
    addReason(reasons, !hasText(material?.versionRef), `material_version_ref_absent:${family}`);
    addReason(reasons, !MATERIAL_STATUSES.has(material?.status), `material_status_invalid:${family}`);
    addReason(reasons, !isDigest(material?.artifactHash), `material_artifact_hash_invalid:${family}`);
    addReason(reasons, material?.metadataOnly !== true, `material_metadata_boundary_invalid:${family}`);
    addReason(reasons, material?.protectedContentExcluded !== true, `material_protected_boundary_invalid:${family}`);

    if (material?.status === 'approved') {
      addReason(reasons, !isDigest(material?.approvalEvidenceHash), `material_approval_evidence_invalid:${family}`);
      addReason(reasons, hlcTuple(material?.approvedAtHlc) === null, `material_approval_time_invalid:${family}`);
      addReason(reasons, hlcAfter(material?.approvedAtHlc, input?.ethicsReview?.effectiveAtHlc), `material_approved_after_effective:${family}`);
    }
    if (material?.status === 'not_applicable') {
      addReason(reasons, !isDigest(material?.notApplicableRationaleHash), `material_not_applicable_rationale_invalid:${family}`);
    }
    if (material?.status !== 'approved' && material?.status !== 'not_applicable') {
      addReason(reasons, REQUIRED_MATERIAL_FAMILIES.includes(family), `material_not_approved:${family}`);
    }
    if (material?.status !== 'approved' && material?.status !== 'not_applicable') {
      continue;
    }
  }

  for (const family of REQUIRED_MATERIAL_FAMILIES) {
    addReason(reasons, !coveredFamilies.has(family), `approved_material_family_missing:${family}`);
  }

  return {
    approvedMaterialFamilies: [...coveredFamilies].sort(),
    materialCoverageBasisPoints: basisPoints(coveredFamilies.size, REQUIRED_MATERIAL_FAMILIES.length),
    normalizedMaterials: materials.map((material) => ({
      family: hasText(material?.family) ? material.family : 'unknown',
      materialRef: hasText(material?.materialRef) ? material.materialRef : null,
      status: hasText(material?.status) ? material.status : 'unknown',
      versionRef: hasText(material?.versionRef) ? material.versionRef : null,
    })),
  };
}

function evaluateContinuingReview(input, reasons) {
  const continuing = input?.continuingReview;
  addReason(reasons, continuing?.required !== true, 'continuing_review_requirement_absent');
  addReason(reasons, continuing?.status !== 'current', 'continuing_review_not_current');
  addReason(reasons, hlcTuple(continuing?.lastCompletedAtHlc) === null, 'continuing_review_completed_time_invalid');
  addReason(reasons, hlcTuple(continuing?.nextDueAtHlc) === null, 'continuing_review_due_time_invalid');
  addReason(reasons, !isDigest(continuing?.reviewEvidenceHash), 'continuing_review_evidence_invalid');
  addReason(reasons, !isDigest(continuing?.dependencyHash), 'continuing_review_dependency_hash_invalid');
  addReason(reasons, hlcBefore(continuing?.lastCompletedAtHlc, input?.ethicsReview?.approvedAtHlc), 'continuing_review_before_initial_approval');
  addReason(reasons, hlcBefore(continuing?.nextDueAtHlc, input?.ethicsReview?.evaluatedAtHlc), 'continuing_review_due_before_evaluation');
}

function normalizeNotifications(input, reasons) {
  const notifications = Array.isArray(input?.requiredNotifications)
    ? [...input.requiredNotifications].sort(notificationSort)
    : [];
  addReason(reasons, notifications.length === 0, 'ethics_notifications_absent');

  const presentAudiences = new Set();
  for (const notification of notifications) {
    const audience = hasText(notification?.audience) ? notification.audience : 'unknown';
    addReason(reasons, !REQUIRED_NOTIFICATION_AUDIENCES.includes(audience), `notification_audience_unsupported:${audience}`);
    if (REQUIRED_NOTIFICATION_AUDIENCES.includes(audience)) {
      presentAudiences.add(audience);
    }
    addReason(reasons, !hasText(notification?.notificationRef), `notification_ref_absent:${audience}`);
    addReason(reasons, !isDigest(notification?.notificationHash), `notification_hash_invalid:${audience}`);
    addReason(reasons, hlcTuple(notification?.deliveredAtHlc) === null, `notification_time_invalid:${audience}`);
    addReason(reasons, hlcBefore(notification?.deliveredAtHlc, input?.ethicsReview?.effectiveAtHlc), `notification_before_effective:${audience}`);
    addReason(reasons, notification?.disclosureLogged !== true, `notification_disclosure_log_absent:${audience}`);
    addReason(reasons, notification?.metadataOnly !== true, `notification_metadata_boundary_invalid:${audience}`);
    addReason(reasons, notification?.protectedContentExcluded !== true, `notification_protected_boundary_invalid:${audience}`);
  }

  for (const audience of REQUIRED_NOTIFICATION_AUDIENCES) {
    addReason(reasons, !presentAudiences.has(audience), `notification_audience_missing:${audience}`);
  }

  return {
    notifiedAudiences: [...presentAudiences].sort(),
    normalizedNotifications: notifications.map((notification) => ({
      audience: hasText(notification?.audience) ? notification.audience : 'unknown',
      notificationRef: hasText(notification?.notificationRef) ? notification.notificationRef : null,
    })),
  };
}

function evaluateProtocolDependencies(input, reasons) {
  const dependencies = input?.protocolDependencies;
  addReason(reasons, !hasText(dependencies?.protocolIntakeRef), 'protocol_intake_ref_absent');
  addReason(reasons, !isDigest(dependencies?.protocolIntakeHash), 'protocol_intake_hash_invalid');
  addReason(reasons, sortedTextList(dependencies?.consentMaterialRefs).length === 0, 'consent_material_refs_absent');
  addReason(reasons, !hasText(dependencies?.launchGateRef), 'launch_gate_ref_absent');
  addReason(reasons, !isDigest(dependencies?.launchGateHash), 'launch_gate_hash_invalid');
}

function evaluateReviewGovernance(input, reasons) {
  const governance = input?.reviewGovernance;
  const forum = governance?.decisionForum;
  addReason(reasons, !hasText(governance?.humanReviewerDid), 'human_reviewer_absent');
  addReason(reasons, governance?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, typeof governance?.aiAssisted !== 'boolean', 'ai_assistance_state_invalid');
  addReason(reasons, forum?.required !== true, 'decision_forum_required_absent');
  addReason(reasons, forum?.verified !== true, 'decision_forum_not_verified');
  addReason(reasons, forum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, forum?.humanGate?.verified !== true, 'decision_forum_human_gate_unverified');
  addReason(reasons, forum?.quorum?.status !== 'met', 'decision_forum_quorum_not_met');
  addReason(reasons, forum?.openChallenge === true, 'decision_forum_open_challenge');
  addReason(reasons, !hasText(forum?.decisionId), 'decision_forum_id_absent');
  addReason(reasons, !hasText(forum?.workflowReceiptId), 'decision_forum_receipt_absent');
}

function buildEthicsRecord(input, materialSummary, notificationSummary, reviewHash, ready) {
  const review = input?.ethicsReview ?? {};
  return {
    schema: ETHICS_SCHEMA,
    reviewReady: ready,
    approvalStatus: ready ? review.status : 'blocked',
    reviewRef: hasText(review.reviewRef) ? review.reviewRef : null,
    protocolRef: hasText(review.protocolRef) ? review.protocolRef : null,
    protocolVersionRef: hasText(review.protocolVersionRef) ? review.protocolVersionRef : null,
    committeeRef: hasText(review.committeeRef) ? review.committeeRef : null,
    committeeType: hasText(review.committeeType) ? review.committeeType : 'unknown',
    independentCommitteeAttested: review.independentCommitteeAttested === true,
    aiReviewNotEthicsApproval: review.aiRepresentedAsEthicsApproval !== true,
    continuingReviewState: hasText(input?.continuingReview?.status) ? input.continuingReview.status : 'unknown',
    approvedMaterialFamilies: materialSummary.approvedMaterialFamilies,
    materialCoverageBasisPoints: materialSummary.materialCoverageBasisPoints,
    notifiedAudiences: notificationSummary.notifiedAudiences,
    aiAssisted: input?.reviewGovernance?.aiAssisted === true,
    trustState: 'inactive',
    exochainProductionClaim: false,
    reviewHash,
  };
}

function buildReceipt(input, reviewHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: reviewHash,
    artifactType: 'independent_ethics_review',
    artifactVersion: input.ethicsReview.reviewRef,
    classification: 'ethics_review_metadata',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: `${input.ethicsReview.evaluatedAtHlc.physicalMs}:${input.ethicsReview.evaluatedAtHlc.logical}`,
    sensitivityTags: ['ethics_review', 'metadata_only', 'qms_policy_5'],
    sourceSystem: 'cybermedica.independent_ethics_review',
    tenantId: input.tenantId,
  });
}

export function evaluateIndependentEthicsReview(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateEthicsReview(input?.ethicsReview, reasons);
  const materialSummary = normalizeApprovedMaterials(input, reasons);
  evaluateContinuingReview(input, reasons);
  const notificationSummary = normalizeNotifications(input, reasons);
  evaluateProtocolDependencies(input, reasons);
  evaluateReviewGovernance(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const denialReasons = uniqueSortedReasons(reasons);
  if (denialReasons.length > 0) {
    return {
      decision: 'denied',
      failClosed: true,
      reasons: denialReasons,
      ethicsReview: buildEthicsRecord(input, materialSummary, notificationSummary, null, false),
      receipt: null,
    };
  }

  const normalizedReview = {
    committeeRef: input.ethicsReview.committeeRef,
    committeeType: input.ethicsReview.committeeType,
    continuingReviewState: input.continuingReview.status,
    materialFamilies: materialSummary.approvedMaterialFamilies,
    materials: materialSummary.normalizedMaterials,
    notifiedAudiences: notificationSummary.notifiedAudiences,
    notifications: notificationSummary.normalizedNotifications,
    protocolRef: input.ethicsReview.protocolRef,
    protocolVersionRef: input.ethicsReview.protocolVersionRef,
    reviewRef: input.ethicsReview.reviewRef,
    siteRef: input.ethicsReview.siteRef,
    studyRef: input.ethicsReview.studyRef,
    tenantId: input.tenantId,
  };
  const reviewHash = sha256Hex(normalizedReview);
  const receipt = buildReceipt(input, reviewHash);

  return {
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    ethicsReview: buildEthicsRecord(input, materialSummary, notificationSummary, reviewHash, true),
    receipt,
  };
}
