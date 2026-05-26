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

import { canonicalize, createEvidenceReceipt, sha256Hex } from './qms-contracts.mjs';

const HEX_64 = /^[0-9a-f]{64}$/u;
const REQUIRED_PERMISSION = 'evidence_scoring';
const REQUIRED_SCOPES = Object.freeze(['control', 'diligence_packet', 'protocol', 'site', 'study']);
const EVIDENCE_STATUSES = new Set(['approved', 'pending', 'rejected', 'superseded']);
const HUMAN_REVIEW_DECISIONS = new Set(['score_approved', 'score_approved_with_conditions']);
const SCOPE_FOLLOW_UP_ROLE = Object.freeze({
  control: 'quality_manager',
  diligence_packet: 'sponsor_cro_owner',
  protocol: 'principal_investigator',
  site: 'site_quality_lead',
  study: 'study_owner',
});

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

function sortedTextList(values) {
  if (!Array.isArray(values)) {
    return [];
  }
  return values.filter(hasText).sort();
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

function compareHlc(left, right) {
  if (left[0] !== right[0]) {
    return left[0] - right[0];
  }
  return left[1] - right[1];
}

function basisPoints(numerator, denominator) {
  if (denominator === 0) {
    return 0;
  }
  return Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
}

function hasPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function requirementSort(left, right) {
  return `${left.scope}:${left.ownerRef}:${left.requiredFamily}`.localeCompare(
    `${right.scope}:${right.ownerRef}:${right.requiredFamily}`,
  );
}

function evidenceSort(left, right) {
  return `${left.scope}:${left.ownerRef}:${left.family}:${left.evidenceRef}`.localeCompare(
    `${right.scope}:${right.ownerRef}:${right.family}:${right.evidenceRef}`,
  );
}

function evaluateAuthority(input, reasons) {
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !hasPermission(input?.authority, REQUIRED_PERMISSION), 'authority_permission_missing');
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateScoringPolicy(input, reasons) {
  const scopes = sortedTextList(input?.scoringPolicy?.requiredScopes);
  addReason(reasons, !hasText(input?.scoringPolicy?.policyRef), 'scoring_policy_ref_absent');
  addReason(reasons, !isDigest(input?.scoringPolicy?.policyHash), 'scoring_policy_hash_invalid');
  addReason(reasons, input?.scoringPolicy?.metadataOnly !== true, 'policy_metadata_boundary_invalid');
  addReason(
    reasons,
    input?.scoringPolicy?.protectedContentExcluded !== true,
    'policy_protected_content_boundary_invalid',
  );

  for (const scope of REQUIRED_SCOPES) {
    addReason(reasons, !scopes.includes(scope), `required_scope_absent:${scope}`);
  }
}

function evaluateScoreSet(input, reasons) {
  addReason(reasons, !hasText(input?.scoreSet?.scoreSetRef), 'score_set_ref_absent');
  addReason(reasons, !hasText(input?.scoreSet?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(input?.scoreSet?.studyRef), 'study_ref_absent');
  addReason(reasons, !hasText(input?.scoreSet?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(input?.scoreSet?.diligencePacketRef), 'diligence_packet_ref_absent');
  addReason(
    reasons,
    !Array.isArray(input?.scoreSet?.requirements) || input.scoreSet.requirements.length === 0,
    'scoring_requirements_absent',
  );
  addReason(
    reasons,
    !Array.isArray(input?.scoreSet?.evidenceItems) || input.scoreSet.evidenceItems.length === 0,
    'evidence_inventory_absent',
  );
}

function evaluateHumanReview(input, reasons) {
  addReason(reasons, !hasText(input?.humanReview?.reviewerDid), 'human_reviewer_absent');
  addReason(
    reasons,
    !HUMAN_REVIEW_DECISIONS.has(input?.humanReview?.reviewDecision),
    'human_review_decision_invalid',
  );
  addReason(reasons, !isDigest(input?.humanReview?.evidenceBundleHash), 'evidence_bundle_hash_invalid');
  addReason(reasons, !isDigest(input?.humanReview?.rationaleHash), 'review_rationale_hash_invalid');
  addReason(reasons, input?.humanReview?.decisionForum?.verified !== true, 'decision_forum_unverified');
  addReason(reasons, input?.humanReview?.decisionForum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, input?.humanReview?.decisionForum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, input?.humanReview?.decisionForum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, input?.humanReview?.decisionForum?.openChallenge === true, 'challenge_open');
  addReason(reasons, !hasText(input?.humanReview?.decisionForum?.decisionId), 'decision_forum_id_absent');
  addReason(reasons, !hasText(input?.humanReview?.decisionForum?.workflowReceiptId), 'workflow_receipt_absent');
}

function evaluateHlc(input, reasons) {
  const policyReviewedAt = hlcTuple(input?.scoringPolicy?.reviewedAtHlc);
  const evaluatedAt = hlcTuple(input?.scoreSet?.evaluatedAtHlc);
  const humanReviewedAt = hlcTuple(input?.humanReview?.reviewedAtHlc);

  addReason(reasons, policyReviewedAt === null, 'policy_review_time_invalid');
  addReason(reasons, evaluatedAt === null, 'evaluation_time_invalid');
  addReason(reasons, humanReviewedAt === null, 'human_review_time_invalid');
  addReason(
    reasons,
    policyReviewedAt !== null && evaluatedAt !== null && compareHlc(evaluatedAt, policyReviewedAt) <= 0,
    'evaluation_time_before_policy_review',
  );
  addReason(
    reasons,
    evaluatedAt !== null && humanReviewedAt !== null && compareHlc(humanReviewedAt, evaluatedAt) < 0,
    'human_review_before_evaluation',
  );
}

function evaluateBoundary(input, reasons) {
  canonicalize(input ?? {});
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
  evaluateAuthority(input, reasons);
  evaluateScoringPolicy(input, reasons);
  evaluateScoreSet(input, reasons);
  evaluateHumanReview(input, reasons);
  evaluateHlc(input, reasons);
}

function normalizeRequirement(requirement) {
  return {
    scope: requirement?.scope,
    ownerRef: requirement?.ownerRef,
    requiredFamily: requirement?.requiredFamily,
    controlRef: requirement?.controlRef ?? null,
    criticality: requirement?.criticality ?? 'standard',
  };
}

function normalizeEvidence(item) {
  return {
    evidenceRef: item?.evidenceRef,
    scope: item?.scope,
    ownerRef: item?.ownerRef,
    family: item?.family,
    status: item?.status,
    artifactHash: item?.artifactHash,
    custodyDigest: item?.custodyDigest,
    observedAtHlc: item?.observedAtHlc,
    freshnessWindowMs: item?.freshnessWindowMs,
    reviewReceiptHash: item?.reviewReceiptHash,
    metadataOnly: item?.metadataOnly,
    protectedContentExcluded: item?.protectedContentExcluded,
  };
}

function evidenceMatchesRequirement(evidence, requirement) {
  return (
    evidence.scope === requirement.scope &&
    evidence.ownerRef === requirement.ownerRef &&
    evidence.family === requirement.requiredFamily
  );
}

function evidenceIsStructurallyValid(evidence) {
  return (
    hasText(evidence.evidenceRef) &&
    hasText(evidence.scope) &&
    hasText(evidence.ownerRef) &&
    hasText(evidence.family) &&
    EVIDENCE_STATUSES.has(evidence.status) &&
    isDigest(evidence.artifactHash) &&
    isDigest(evidence.custodyDigest) &&
    isDigest(evidence.reviewReceiptHash) &&
    evidence.metadataOnly === true &&
    evidence.protectedContentExcluded === true &&
    hlcTuple(evidence.observedAtHlc) !== null &&
    Number.isSafeInteger(evidence.freshnessWindowMs) &&
    evidence.freshnessWindowMs >= 0
  );
}

function evidenceFresh(evidence, evaluatedAt) {
  const observedAt = hlcTuple(evidence.observedAtHlc);
  if (observedAt === null || !Number.isSafeInteger(evidence.freshnessWindowMs) || evidence.freshnessWindowMs < 0) {
    return false;
  }
  return observedAt[0] + evidence.freshnessWindowMs >= evaluatedAt[0];
}

function defectForScope(defects, scope, family, reason) {
  defects.push(`${reason}:${scope}:${family}`);
}

function scoreRequirement(requirement, evidenceItems, evaluatedAt, defects) {
  const matchingEvidence = evidenceItems.filter((item) => evidenceMatchesRequirement(item, requirement));
  if (matchingEvidence.length === 0) {
    defectForScope(defects, requirement.scope, requirement.requiredFamily, 'required_evidence_missing');
    return { complete: false, fresh: false, evidenceRefs: [] };
  }

  const validEvidence = matchingEvidence.filter(evidenceIsStructurallyValid);
  if (validEvidence.length === 0) {
    defectForScope(defects, requirement.scope, requirement.requiredFamily, 'evidence_metadata_invalid');
    return {
      complete: false,
      fresh: false,
      evidenceRefs: matchingEvidence.map((item) => item.evidenceRef).filter(hasText).sort(),
    };
  }

  const approvedEvidence = validEvidence.filter((item) => item.status === 'approved');
  if (approvedEvidence.length === 0) {
    defectForScope(defects, requirement.scope, requirement.requiredFamily, 'evidence_not_approved');
    return {
      complete: false,
      fresh: false,
      evidenceRefs: validEvidence.map((item) => item.evidenceRef).sort(),
    };
  }

  const freshEvidence = approvedEvidence.filter((item) => evidenceFresh(item, evaluatedAt));
  if (freshEvidence.length === 0) {
    defectForScope(defects, requirement.scope, requirement.requiredFamily, 'evidence_stale');
  }

  return {
    complete: true,
    fresh: freshEvidence.length > 0,
    evidenceRefs: approvedEvidence.map((item) => item.evidenceRef).sort(),
  };
}

function buildScopeScores(requirements, evidenceItems, evaluatedAtTuple) {
  const defects = [];
  const scopeScores = REQUIRED_SCOPES.map((scope) => {
    const scopeRequirements = requirements.filter((requirement) => requirement.scope === scope).sort(requirementSort);
    let completeCount = 0;
    let freshCount = 0;
    const coveredFamilies = [];
    const missingFamilies = [];
    const evidenceRefs = [];

    if (scopeRequirements.length === 0) {
      defects.push(`required_scope_requirements_missing:${scope}`);
    }

    for (const requirement of scopeRequirements) {
      if (!hasText(requirement.ownerRef) || !hasText(requirement.requiredFamily)) {
        defects.push(`scoring_requirement_invalid:${scope}`);
        continue;
      }
      const score = scoreRequirement(requirement, evidenceItems, evaluatedAtTuple, defects);
      evidenceRefs.push(...score.evidenceRefs);
      if (score.complete) {
        completeCount += 1;
        coveredFamilies.push(requirement.requiredFamily);
      } else {
        missingFamilies.push(requirement.requiredFamily);
      }
      if (score.fresh) {
        freshCount += 1;
      }
    }

    return {
      schema: 'cybermedica.evidence_scope_score.v1',
      scope,
      requiredEvidenceCount: scopeRequirements.length,
      completeEvidenceCount: completeCount,
      freshEvidenceCount: freshCount,
      completenessBasisPoints: basisPoints(completeCount, scopeRequirements.length),
      freshnessBasisPoints: basisPoints(freshCount, scopeRequirements.length),
      coveredFamilies: uniqueSorted(coveredFamilies),
      missingFamilies: uniqueSorted(missingFamilies),
      evidenceRefs: uniqueSorted(evidenceRefs),
    };
  });

  return { scopeScores, defects: uniqueSorted(defects) };
}

function buildEvidenceScore(input) {
  const requirements = [...input.scoreSet.requirements].map(normalizeRequirement).sort(requirementSort);
  const evidenceItems = [...input.scoreSet.evidenceItems].map(normalizeEvidence).sort(evidenceSort);
  const evaluatedAtTuple = hlcTuple(input.scoreSet.evaluatedAtHlc);
  const { scopeScores, defects } = buildScopeScores(requirements, evidenceItems, evaluatedAtTuple);
  const totalRequired = scopeScores.reduce((total, scope) => total + scope.requiredEvidenceCount, 0);
  const totalComplete = scopeScores.reduce((total, scope) => total + scope.completeEvidenceCount, 0);
  const totalFresh = scopeScores.reduce((total, scope) => total + scope.freshEvidenceCount, 0);
  const requiredFollowUpRoles = uniqueSorted(
    defects
      .map((defect) => defect.split(':')[1])
      .filter((scope) => REQUIRED_SCOPES.includes(scope))
      .map((scope) => SCOPE_FOLLOW_UP_ROLE[scope]),
  );
  const scoreMaterial = {
    schema: 'cybermedica.evidence_score_material.v1',
    custodyDigest: input.custodyDigest,
    evaluatedAtHlc: input.scoreSet.evaluatedAtHlc,
    policyHash: input.scoringPolicy.policyHash,
    requirements,
    scopeScores,
    scoreSetRef: input.scoreSet.scoreSetRef,
    tenantId: input.tenantId,
  };
  const scoreSetHash = sha256Hex(scoreMaterial);

  return {
    schema: 'cybermedica.evidence_scoring.v1',
    scoreSetRef: input.scoreSet.scoreSetRef,
    tenantId: input.tenantId,
    siteRef: input.scoreSet.siteRef,
    studyRef: input.scoreSet.studyRef,
    protocolRef: input.scoreSet.protocolRef,
    diligencePacketRef: input.scoreSet.diligencePacketRef,
    scoreStatus: defects.length === 0 ? 'ready' : 'attention_required',
    completenessBasisPoints: basisPoints(totalComplete, totalRequired),
    freshnessBasisPoints: basisPoints(totalFresh, totalRequired),
    requiredEvidenceCount: totalRequired,
    completeEvidenceCount: totalComplete,
    freshEvidenceCount: totalFresh,
    scopeScores,
    defects,
    requiredFollowUpRoles,
    readyForReadinessGate: defects.length === 0,
    scoreSetHash,
    scoreDigest: sha256Hex({ scoreSetHash, defects, requiredFollowUpRoles }),
    evaluatedAtHlc: input.scoreSet.evaluatedAtHlc,
    reviewedAtHlc: input.humanReview.reviewedAtHlc,
    reviewerDid: input.humanReview.reviewerDid,
    decisionForumRef: input.humanReview.decisionForum.decisionId,
    workflowReceiptId: input.humanReview.decisionForum.workflowReceiptId,
    trustState: 'inactive',
    exochainProductionClaim: false,
    operationalStateMutable: true,
    immutableReceipt: true,
  };
}

function buildReceipt(input, evidenceScore) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'evidence_scoring',
    artifactVersion: `${input.scoreSet.scoreSetRef}:v1`,
    artifactHash: evidenceScore.scoreSetHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['evidence_scoring', 'fr_006', 'fr_007', 'metadata_only'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function evaluateEvidenceScoring(input) {
  const reasons = [];
  evaluateBoundary(input, reasons);

  if (reasons.length > 0) {
    return {
      decision: 'denied',
      failClosed: true,
      reasons: uniqueSorted(reasons),
      evidenceScore: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const evidenceScore = buildEvidenceScore(input);
  const receipt = buildReceipt(input, evidenceScore);

  return {
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    evidenceScore,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
