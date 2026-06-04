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
const REQUIRED_PERMISSION = 'protocol_milestone_manage';
const MILESTONE_TRACKING_SCHEMA = 'cybermedica.protocol_milestone_tracking.v1';

const MILESTONE_STATUSES = new Set(['completed', 'on_track', 'at_risk', 'blocked', 'missed', 'waived']);
const STUDY_STATUSES = new Set(['active', 'closing', 'startup']);
const REVIEW_DECISIONS = new Set(['hold_for_milestone_gap', 'milestones_current_inactive_trust']);

const RAW_MILESTONE_FIELDS = new Set([
  'clinicalnotebody',
  'directidentifier',
  'freetextmilestone',
  'freetextnote',
  'medicalrecord',
  'milestonebody',
  'milestonecontent',
  'milestonenarrative',
  'participantname',
  'patientname',
  'rawmilestone',
  'rawmilestonecontent',
  'rawmilestonenarrative',
  'rawprotocol',
  'rawsource',
  'rawsourcecontent',
  'sourcedocumentbody',
  'sourcedocumenttext',
]);

const SECRET_MILESTONE_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'apitoken',
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

function assertNoRawMilestoneContentOrSecrets(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawMilestoneContentOrSecrets(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_MILESTONE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw protocol milestone content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_MILESTONE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`protocol milestone secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawMilestoneContentOrSecrets(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawMilestoneContentOrSecrets(input ?? {});
  canonicalize(input ?? {});
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function orderedUniqueTextList(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  const seen = new Set();
  const output = [];
  for (const item of value) {
    if (hasText(item) && !seen.has(item)) {
      seen.add(item);
      output.push(item);
    }
  }
  return output;
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function basisPoints(numerator, denominator) {
  if (denominator === 0) {
    return 0;
  }
  return Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
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

function hasAuthorityPermission(authority) {
  return Array.isArray(authority?.permissions) &&
    (authority.permissions.includes(REQUIRED_PERMISSION) ||
      authority.permissions.includes('govern') ||
      authority.permissions.includes('write'));
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
  addReason(reasons, !hasAuthorityPermission(input?.authority), 'protocol_milestone_authority_missing');
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'milestone_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'milestone_policy_hash_invalid');
  addReason(reasons, orderedUniqueTextList(policy?.requiredFamilies).length === 0, 'milestone_required_families_absent');
  addReason(reasons, orderedUniqueTextList(policy?.criticalFamilies).length === 0, 'milestone_critical_families_absent');
  addReason(reasons, policy?.requireDependencyCompletion !== true, 'milestone_dependency_completion_policy_absent');
  addReason(reasons, policy?.requireHumanReviewForBlockedCritical !== true, 'blocked_critical_human_review_policy_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'milestone_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'milestone_policy_protected_boundary_invalid');
  addReason(reasons, policy?.noProductionTrustClaim !== true, 'milestone_policy_production_claim_forbidden');
  addReason(reasons, hlcTuple(policy?.approvedAtHlc) === null, 'milestone_policy_approval_time_invalid');

  const requiredSet = new Set(orderedUniqueTextList(policy?.requiredFamilies));
  for (const family of orderedUniqueTextList(policy?.criticalFamilies)) {
    addReason(reasons, !requiredSet.has(family), `critical_family_not_required:${family}`);
  }
}

function evaluateStudy(study, reasons) {
  addReason(reasons, !hasText(study?.studyRef), 'study_ref_absent');
  addReason(reasons, !hasText(study?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(study?.activeProtocolVersionRef), 'active_protocol_version_absent');
  addReason(reasons, !hasText(study?.siteRef), 'site_ref_absent');
  addReason(reasons, !isDigest(study?.milestonePlanHash), 'milestone_plan_hash_invalid');
  addReason(reasons, !hasText(study?.informationManagementPlanRef), 'information_management_plan_ref_absent');
  addReason(reasons, !isDigest(study?.informationManagementPlanHash), 'information_management_plan_hash_invalid');
  addReason(reasons, !STUDY_STATUSES.has(study?.status), 'study_status_invalid');
  addReason(reasons, study?.metadataOnly !== true, 'study_metadata_boundary_invalid');
  addReason(reasons, study?.protectedContentExcluded !== true, 'study_protected_boundary_invalid');
}

function milestoneLabel(milestone, index) {
  return hasText(milestone?.milestoneRef) ? milestone.milestoneRef : `milestone_index_${index}`;
}

function normalizeMilestones(input, reasons) {
  const milestones = Array.isArray(input?.milestones) ? input.milestones : [];
  addReason(reasons, milestones.length === 0, 'milestones_absent');

  const byRef = new Map();
  const byFamily = new Map();
  const requiredFamilies = orderedUniqueTextList(input?.milestonePolicy?.requiredFamilies);
  const criticalFamilies = new Set(orderedUniqueTextList(input?.milestonePolicy?.criticalFamilies));
  const checkedAt = input?.checkedAtHlc;

  for (const [index, milestone] of milestones.entries()) {
    const ref = milestoneLabel(milestone, index);
    const family = milestone?.family;
    addReason(reasons, !hasText(milestone?.milestoneRef), `milestone_ref_absent:${ref}`);
    addReason(reasons, !hasText(family), `milestone_family_absent:${ref}`);
    addReason(reasons, byRef.has(ref), `milestone_ref_duplicate:${ref}`);
    if (hasText(ref)) {
      byRef.set(ref, milestone);
    }
    if (hasText(family)) {
      addReason(reasons, byFamily.has(family), `milestone_family_duplicate:${family}`);
      byFamily.set(family, milestone);
    }
  }

  for (const family of requiredFamilies) {
    addReason(reasons, !byFamily.has(family), `milestone_family_missing:${family}`);
  }
  for (const family of byFamily.keys()) {
    addReason(reasons, !requiredFamilies.includes(family), `milestone_family_unsupported:${family}`);
  }

  for (const [index, milestone] of milestones.entries()) {
    const ref = milestoneLabel(milestone, index);
    const family = milestone?.family;
    const dueAtValid = hlcTuple(milestone?.dueAtHlc) !== null;
    const completedAtValid = milestone?.completedAtHlc === null || hlcTuple(milestone?.completedAtHlc) !== null;
    const dependencyRefs = sortedTextList(milestone?.dependencyRefs);
    const blockerRefs = sortedTextList(milestone?.blockerRefs);

    addReason(reasons, !hasText(milestone?.ownerDid), `milestone_owner_absent:${ref}`);
    addReason(reasons, !MILESTONE_STATUSES.has(milestone?.status), `milestone_status_invalid:${ref}`);
    addReason(reasons, !dueAtValid, `milestone_due_time_invalid:${ref}`);
    addReason(reasons, !completedAtValid, `milestone_completion_time_invalid:${ref}`);
    addReason(reasons, !isDigest(milestone?.evidenceHash), `milestone_evidence_hash_invalid:${ref}`);
    addReason(reasons, !isDigest(milestone?.sourceArtifactHash), `milestone_source_artifact_hash_invalid:${ref}`);
    addReason(reasons, !isDigest(milestone?.receiptHash), `milestone_receipt_hash_invalid:${ref}`);
    addReason(reasons, milestone?.metadataOnly !== true, `milestone_metadata_boundary_invalid:${ref}`);
    addReason(reasons, milestone?.protectedContentExcluded !== true, `milestone_protected_boundary_invalid:${ref}`);
    addReason(
      reasons,
      hlcBefore(milestone?.dueAtHlc, input?.milestonePolicy?.approvedAtHlc),
      `milestone_due_before_policy_approval:${ref}`,
    );
    addReason(
      reasons,
      milestone?.status === 'completed' && milestone?.completedAtHlc === null,
      `milestone_completion_time_absent:${ref}`,
    );
    addReason(
      reasons,
      milestone?.status === 'completed' && hlcBefore(checkedAt, milestone?.completedAtHlc),
      `milestone_completion_after_checked_at:${ref}`,
    );
    addReason(
      reasons,
      milestone?.status === 'completed' && hlcBefore(milestone?.completedAtHlc, input?.milestonePolicy?.approvedAtHlc),
      `milestone_completion_before_policy_approval:${ref}`,
    );
    addReason(reasons, milestone?.status === 'blocked' && blockerRefs.length === 0, `milestone_blocker_refs_absent:${ref}`);

    for (const dependencyRef of dependencyRefs) {
      const dependency = byRef.get(dependencyRef);
      addReason(reasons, dependency === undefined, `milestone_dependency_missing:${ref}:${dependencyRef}`);
      addReason(
        reasons,
        dependency !== undefined && dependency.status !== 'completed',
        `milestone_dependency_incomplete:${ref}:${dependencyRef}`,
      );
    }

    const overdue = dueAtValid && hlcBefore(milestone?.dueAtHlc, checkedAt) &&
      !['completed', 'waived'].includes(milestone?.status);
    addReason(reasons, overdue, `milestone_overdue:${ref}`);
    addReason(reasons, overdue && criticalFamilies.has(family), `critical_milestone_overdue:${ref}`);
    addReason(reasons, milestone?.status === 'blocked', `milestone_blocked:${ref}`);
    addReason(
      reasons,
      milestone?.status === 'blocked' && criticalFamilies.has(family),
      `critical_milestone_blocked:${ref}`,
    );
    addReason(
      reasons,
      milestone?.status === 'missed' && criticalFamilies.has(family),
      `critical_milestone_missed:${ref}`,
    );
  }

  return { byFamily, byRef, milestones };
}

function evaluateReview(review, policy, checkedAtHlc, reasons) {
  addReason(reasons, !hasText(review?.reviewerDid), 'reviewer_did_absent');
  addReason(reasons, !REVIEW_DECISIONS.has(review?.decision), 'review_decision_invalid');
  addReason(reasons, !isDigest(review?.reviewHash), 'review_hash_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'review_time_invalid');
  addReason(reasons, review?.aiFinalAuthority === true, 'review_ai_final_authority_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'review_metadata_boundary_invalid');
  addReason(reasons, review?.protectedContentExcluded !== true, 'review_protected_boundary_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, policy?.approvedAtHlc), 'review_before_policy_approval');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, checkedAtHlc), 'review_before_checked_at');
}

function milestoneProjection(milestone) {
  return {
    completedAtHlc: milestone.completedAtHlc ?? null,
    dependencyRefs: sortedTextList(milestone.dependencyRefs),
    dueAtHlc: milestone.dueAtHlc,
    evidenceHash: milestone.evidenceHash,
    family: milestone.family,
    milestoneRef: milestone.milestoneRef,
    ownerDid: milestone.ownerDid,
    receiptHash: milestone.receiptHash,
    sourceArtifactHash: milestone.sourceArtifactHash,
    status: milestone.status,
  };
}

function statusFor(milestones, checkedAtHlc, criticalFamilies) {
  const hasBlockedCritical = milestones.some(
    (milestone) => milestone.status === 'blocked' && criticalFamilies.has(milestone.family),
  );
  if (hasBlockedCritical) {
    return 'blocked';
  }
  const hasOverdue = milestones.some((milestone) =>
    hlcBefore(milestone.dueAtHlc, checkedAtHlc) && !['completed', 'waived'].includes(milestone.status),
  );
  if (hasOverdue) {
    return 'overdue';
  }
  if (milestones.some((milestone) => milestone.status === 'at_risk')) {
    return 'at_risk';
  }
  if (milestones.length > 0 && milestones.every((milestone) => milestone.status === 'completed')) {
    return 'completed';
  }
  return 'on_track';
}

function buildTrackingHash(input, requiredFamilies, criticalFamilies, milestones) {
  return sha256Hex({
    activeProtocolVersionRef: input.study.activeProtocolVersionRef,
    checkedAtHlc: input.checkedAtHlc,
    criticalFamilies,
    informationManagementPlanHash: input.study.informationManagementPlanHash,
    milestonePlanHash: input.study.milestonePlanHash,
    milestones: [...milestones].map(milestoneProjection).sort((left, right) =>
      `${left.family}:${left.milestoneRef}`.localeCompare(`${right.family}:${right.milestoneRef}`),
    ),
    policyHash: input.milestonePolicy.policyHash,
    requiredFamilies,
    siteRef: input.study.siteRef,
    studyRef: input.study.studyRef,
    tenantId: input.tenantId,
  });
}

function buildProtocolMilestoneTracking(input, milestoneSummary) {
  const requiredFamilies = orderedUniqueTextList(input.milestonePolicy.requiredFamilies);
  const criticalFamilies = orderedUniqueTextList(input.milestonePolicy.criticalFamilies);
  const milestones = [...milestoneSummary.milestones].sort((left, right) =>
    `${left.family}:${left.milestoneRef}`.localeCompare(`${right.family}:${right.milestoneRef}`),
  );
  const coveredFamilies = requiredFamilies.filter((family) => milestoneSummary.byFamily.has(family));
  const blockedMilestoneRefs = sortedTextList(
    milestones.filter((milestone) => milestone.status === 'blocked').map((milestone) => milestone.milestoneRef),
  );
  const overdueMilestoneRefs = sortedTextList(
    milestones
      .filter((milestone) => hlcBefore(milestone.dueAtHlc, input.checkedAtHlc) && !['completed', 'waived'].includes(milestone.status))
      .map((milestone) => milestone.milestoneRef),
  );
  const trackingHash = buildTrackingHash(input, requiredFamilies, criticalFamilies, milestones);

  return {
    schema: MILESTONE_TRACKING_SCHEMA,
    trackingHash,
    trackingRef: `cmmilestone_${trackingHash.slice(0, 32)}`,
    tenantId: input.tenantId,
    studyRef: input.study.studyRef,
    protocolRef: input.study.protocolRef,
    activeProtocolVersionRef: input.study.activeProtocolVersionRef,
    siteRef: input.study.siteRef,
    informationManagementPlanRef: input.study.informationManagementPlanRef,
    policyRef: input.milestonePolicy.policyRef,
    status: statusFor(milestones, input.checkedAtHlc, new Set(criticalFamilies)),
    requiredFamilies,
    coveredFamilies,
    criticalFamilies,
    milestoneCount: milestones.length,
    coverageBasisPoints: basisPoints(coveredFamilies.length, requiredFamilies.length),
    blockedMilestoneRefs,
    overdueMilestoneRefs,
    atRiskMilestoneRefs: sortedTextList(
      milestones.filter((milestone) => milestone.status === 'at_risk').map((milestone) => milestone.milestoneRef),
    ),
    completedMilestoneRefs: sortedTextList(
      milestones.filter((milestone) => milestone.status === 'completed').map((milestone) => milestone.milestoneRef),
    ),
    reviewerDid: input.review.reviewerDid,
    reviewedAtHlc: input.review.reviewedAtHlc,
    checkedAtHlc: input.checkedAtHlc,
    trustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    protectedContentExcluded: true,
  };
}

function buildReceipt(input, protocolMilestoneTracking) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'protocol_milestone_tracking',
    artifactVersion: `${input.study.studyRef}@${input.study.activeProtocolVersionRef}`,
    artifactHash: protocolMilestoneTracking.trackingHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.checkedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: [
      'metadata_only',
      'protocol_execution',
      'study_milestone',
    ],
    sourceSystem: 'cybermedica-qms',
  });
}

export function evaluateProtocolMilestoneTracking(input) {
  assertMetadataOnly(input);

  const reasons = [];
  addReason(reasons, hlcTuple(input?.checkedAtHlc) === null, 'checked_time_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
  evaluateTenantActorAuthority(input, reasons);
  evaluatePolicy(input?.milestonePolicy, reasons);
  evaluateStudy(input?.study, reasons);
  const milestoneSummary = normalizeMilestones(input, reasons);
  evaluateReview(input?.review, input?.milestonePolicy, input?.checkedAtHlc, reasons);

  const finalReasons = uniqueReasons(reasons);
  if (finalReasons.length > 0) {
    return {
      schema: 'cybermedica.protocol_milestone_tracking_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: finalReasons,
      protocolMilestoneTracking: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const protocolMilestoneTracking = buildProtocolMilestoneTracking(input, milestoneSummary);
  return {
    schema: 'cybermedica.protocol_milestone_tracking_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    protocolMilestoneTracking,
    receipt: buildReceipt(input, protocolMilestoneTracking),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
