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
const DISCLOSURE_STATUSES = new Set(['clear', 'managed', 'active', 'unresolved']);
const RECUSAL_STATUSES = new Set(['active', 'accepted']);
const RECUSAL_SCOPES = new Set(['decision', 'review', 'decision_and_review']);
const ACTIVE_CONFLICT_STATUSES = new Set(['active', 'unresolved']);

const RAW_CONFLICT_FIELDS = new Set([
  'conflictdescription',
  'conflictnarrative',
  'conflicttext',
  'financialinterestdetails',
  'financialinteresttext',
  'privilegedconflictnotes',
  'privilegednotes',
  'rawconflict',
  'rawconflictdescription',
  'rawconflictnarrative',
  'rawrecusalreason',
  'recusalexplanation',
  'recusalreasontext',
  'relationshipdetails',
  'verbatimdisclosure',
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

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function assertNoRawConflictContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawConflictContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    if (RAW_CONFLICT_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`raw conflict or recusal content field is not allowed at ${path}.${key}`);
    }
    assertNoRawConflictContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawConflictContent(input ?? {});
  canonicalize(input ?? {});
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

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function basisPoints(numerator, denominator) {
  if (denominator === 0) {
    return 0;
  }
  return Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
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
    !hasAuthorityPermission(input?.authority, 'manage_conflicts') &&
      !hasAuthorityPermission(input?.authority, 'govern') &&
      !hasAuthorityPermission(input?.authority, 'write'),
    'conflict_disclosure_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateMatter(input, reasons) {
  const matter = input?.decisionMatter;
  addReason(reasons, !hasText(matter?.matterRef), 'decision_matter_ref_absent');
  addReason(reasons, !hasText(matter?.decisionType), 'decision_type_absent');
  addReason(reasons, matter?.material !== true, 'material_decision_required');
  addReason(reasons, !hasText(matter?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(matter?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, hlcTuple(matter?.scheduledAtHlc) === null, 'decision_matter_time_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function participantDids(input) {
  return Array.isArray(input?.participants)
    ? uniqueSorted(input.participants.map((participant) => participant?.did))
    : [];
}

function participantMap(input, reasons) {
  const byDid = new Map();
  const participants = Array.isArray(input?.participants) ? input.participants : [];
  addReason(reasons, participants.length === 0, 'decision_participants_absent');

  for (const participant of participants) {
    const did = participant?.did ?? 'unknown';
    addReason(reasons, !hasText(participant?.did), 'decision_participant_did_absent');
    addReason(reasons, !hasText(participant?.role), `decision_participant_role_absent:${did}`);
    addReason(reasons, !hasText(participant?.decisionRole), `decision_participant_decision_role_absent:${did}`);
    addReason(reasons, byDid.has(participant?.did), `decision_participant_duplicate:${did}`);
    if (hasText(participant?.did) && !byDid.has(participant.did)) {
      byDid.set(participant.did, participant);
    }
  }

  return byDid;
}

function disclosureMap(input, reasons) {
  const byDid = new Map();
  if (!Array.isArray(input?.disclosures)) {
    return byDid;
  }

  const disclosures = [...input.disclosures].sort((left, right) =>
    String(left?.disclosureRef ?? '').localeCompare(String(right?.disclosureRef ?? '')),
  );
  for (const disclosure of disclosures) {
    const did = disclosure?.participantDid ?? 'unknown';
    addReason(reasons, !hasText(disclosure?.disclosureRef), `disclosure_ref_absent:${did}`);
    addReason(reasons, !hasText(disclosure?.participantDid), 'disclosure_participant_absent');
    addReason(reasons, byDid.has(disclosure?.participantDid), `conflict_disclosure_duplicate:${did}`);
    if (hasText(disclosure?.participantDid) && !byDid.has(disclosure.participantDid)) {
      byDid.set(disclosure.participantDid, disclosure);
    }
  }
  return byDid;
}

function recusalMap(input, reasons) {
  const byDid = new Map();
  if (!Array.isArray(input?.recusals)) {
    return byDid;
  }

  const recusals = [...input.recusals].sort((left, right) =>
    String(left?.recusalRef ?? '').localeCompare(String(right?.recusalRef ?? '')),
  );
  for (const recusal of recusals) {
    const did = recusal?.participantDid ?? 'unknown';
    addReason(reasons, !hasText(recusal?.recusalRef), `recusal_ref_absent:${did}`);
    addReason(reasons, !hasText(recusal?.participantDid), 'recusal_participant_absent');
    addReason(reasons, recusal?.matterRef !== input?.decisionMatter?.matterRef, `recusal_matter_mismatch:${did}`);
    addReason(reasons, byDid.has(recusal?.participantDid), `recusal_duplicate:${did}`);
    if (hasText(recusal?.participantDid) && !byDid.has(recusal.participantDid)) {
      byDid.set(recusal.participantDid, recusal);
    }
  }
  return byDid;
}

function evaluateDisclosure(disclosure, participant, matter, reasons) {
  const did = participant?.did ?? disclosure?.participantDid ?? 'unknown';
  if (disclosure === undefined) {
    reasons.push(`conflict_disclosure_missing:${did}`);
    return;
  }

  addReason(reasons, !DISCLOSURE_STATUSES.has(disclosure?.status), `disclosure_status_invalid:${did}`);
  addReason(reasons, disclosure?.current !== true, `disclosure_not_current:${did}`);
  addReason(reasons, disclosure?.appliesToMatter !== true, `disclosure_not_matter_specific:${did}`);
  addReason(reasons, !isDigest(disclosure?.evidenceHash), `disclosure_evidence_hash_invalid:${did}`);
  addReason(reasons, !hasText(disclosure?.reviewedByDid), `disclosure_reviewer_absent:${did}`);
  addReason(reasons, hlcTuple(disclosure?.disclosedAtHlc) === null, `disclosure_time_invalid:${did}`);
  addReason(reasons, hlcTuple(disclosure?.reviewedAtHlc) === null, `disclosure_review_time_invalid:${did}`);
  addReason(
    reasons,
    hlcBefore(disclosure?.reviewedAtHlc, disclosure?.disclosedAtHlc),
    `disclosure_review_before_disclosure:${did}`,
  );
  addReason(
    reasons,
    hlcAfter(disclosure?.reviewedAtHlc, matter?.scheduledAtHlc),
    `disclosure_review_after_matter_start:${did}`,
  );
  addReason(
    reasons,
    disclosure?.status === 'managed' && !isDigest(disclosure?.managementPlanHash),
    `managed_conflict_plan_hash_invalid:${did}`,
  );
  addReason(
    reasons,
    ACTIVE_CONFLICT_STATUSES.has(disclosure?.status) &&
      hasText(disclosure?.managementPlanHash) &&
      !isDigest(disclosure.managementPlanHash),
    `active_conflict_plan_hash_invalid:${did}`,
  );
}

function recusalCoversParticipant(recusal, participant) {
  if (recusal === undefined || !RECUSAL_STATUSES.has(recusal?.status)) {
    return false;
  }
  if (recusal.scope === 'decision_and_review') {
    return true;
  }
  if (participant?.votingEligible === true || participant?.decisionRole === 'voter') {
    return recusal.scope === 'decision';
  }
  if (participant?.reviewer === true || participant?.decisionRole === 'reviewer') {
    return recusal.scope === 'review';
  }
  return recusal.scope === 'decision' || recusal.scope === 'review';
}

function evaluateRecusal(recusal, participant, matter, reasons) {
  const did = participant?.did ?? recusal?.participantDid ?? 'unknown';
  if (recusal === undefined) {
    return;
  }

  addReason(reasons, !RECUSAL_STATUSES.has(recusal?.status), `recusal_status_invalid:${did}`);
  addReason(reasons, !RECUSAL_SCOPES.has(recusal?.scope), `recusal_scope_invalid:${did}`);
  addReason(reasons, !isDigest(recusal?.reasonHash), `recusal_reason_hash_invalid:${did}`);
  addReason(reasons, !hasText(recusal?.replacementDid), `recusal_replacement_absent:${did}`);
  addReason(reasons, !hasText(recusal?.acceptedByDid), `recusal_acceptance_absent:${did}`);
  addReason(reasons, hlcTuple(recusal?.effectiveAtHlc) === null, `recusal_effective_time_invalid:${did}`);
  addReason(reasons, hlcAfter(recusal?.effectiveAtHlc, matter?.scheduledAtHlc), `recusal_after_matter_start:${did}`);
  addReason(reasons, participant?.votingEligible === true, `recused_participant_still_active:${did}`);
}

function evaluateParticipantConflicts(input, participants, disclosures, recusals, reasons) {
  const matter = input?.decisionMatter;

  for (const participant of [...participants.values()].sort((left, right) => left.did.localeCompare(right.did))) {
    const disclosure = disclosures.get(participant.did);
    const recusal = recusals.get(participant.did);
    evaluateDisclosure(disclosure, participant, matter, reasons);
    evaluateRecusal(recusal, participant, matter, reasons);

    addReason(
      reasons,
      disclosure !== undefined &&
        ACTIVE_CONFLICT_STATUSES.has(disclosure?.status) &&
        !recusalCoversParticipant(recusal, participant),
      `active_conflict_without_recusal:${participant.did}`,
    );
  }
}

function evaluateAiReview(input, participants, reasons) {
  const aiReview = input?.aiReview;
  addReason(reasons, aiReview?.completed !== true, 'ai_review_incomplete');
  addReason(reasons, aiReview?.advisoryOnly !== true, 'ai_review_must_be_advisory');
  addReason(reasons, aiReview?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, !isDigest(aiReview?.outputHash), 'ai_review_output_hash_invalid');

  const evidenceHashes = Array.isArray(aiReview?.evidenceUsedHashes) ? aiReview.evidenceUsedHashes : [];
  addReason(reasons, evidenceHashes.length === 0, 'ai_review_evidence_absent');
  for (const evidenceHash of evidenceHashes) {
    addReason(reasons, !isDigest(evidenceHash), 'ai_review_evidence_hash_invalid');
  }

  const dids = new Set(participants.keys());
  for (const flaggedDid of sortedTextList(aiReview?.flaggedParticipantDids)) {
    addReason(reasons, !dids.has(flaggedDid), `ai_review_flagged_unknown_participant:${flaggedDid}`);
  }
}

function evaluateGovernance(input, reasons) {
  const governance = input?.governance;
  addReason(reasons, governance?.verified !== true, 'decision_forum_unverified');
  addReason(reasons, governance?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, governance?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, governance?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, governance?.openChallenge === true, 'challenge_open');
  addReason(reasons, !hasText(governance?.decisionId), 'decision_id_absent');
  addReason(reasons, !hasText(governance?.workflowReceiptId), 'workflow_receipt_absent');
  addReason(reasons, input?.evidenceBundle?.complete !== true, 'evidence_bundle_incomplete');
  addReason(reasons, input?.evidenceBundle?.phiBoundaryAttested !== true, 'phi_boundary_unattested');
}

function disclosureRefs(disclosures) {
  return uniqueSorted([...disclosures.values()].map((disclosure) => disclosure?.disclosureRef));
}

function recusalRefs(recusals) {
  return uniqueSorted([...recusals.values()].map((recusal) => recusal?.recusalRef));
}

function managedConflictDids(disclosures) {
  return uniqueSorted(
    [...disclosures.entries()]
      .filter(([, disclosure]) => disclosure?.status === 'managed')
      .map(([did]) => did),
  );
}

function recusedParticipantDids(recusals) {
  return uniqueSorted(
    [...recusals.entries()]
      .filter(([, recusal]) => RECUSAL_STATUSES.has(recusal?.status))
      .map(([did]) => did),
  );
}

function blockedParticipantDids(participants, disclosures, recusals) {
  const blocked = [];
  for (const did of participants.keys()) {
    const disclosure = disclosures.get(did);
    const recusal = recusals.get(did);
    if (disclosure === undefined || (ACTIVE_CONFLICT_STATUSES.has(disclosure?.status) && !recusalCoversParticipant(recusal, participants.get(did)))) {
      blocked.push(did);
    }
  }
  return uniqueSorted(blocked);
}

function clearedParticipantDids(participants, disclosures, recusals) {
  const recused = new Set(recusedParticipantDids(recusals));
  const cleared = [];
  for (const did of participants.keys()) {
    const disclosure = disclosures.get(did);
    if (recused.has(did)) {
      continue;
    }
    if (disclosure?.status === 'clear' || disclosure?.status === 'managed') {
      cleared.push(did);
    }
  }
  return uniqueSorted(cleared);
}

function buildConflictReview(input, participants, disclosures, recusals, reasons, receiptId = null) {
  const participantIds = participantDids(input);
  const coveredParticipantDids = uniqueSorted(
    participantIds.filter((did) => disclosures.has(did) && disclosures.get(did)?.current === true),
  );
  const reviewMaterial = {
    actorDid: input?.actor?.did ?? null,
    aiFlaggedParticipantDids: sortedTextList(input?.aiReview?.flaggedParticipantDids),
    blockedParticipantDids: blockedParticipantDids(participants, disclosures, recusals),
    clearedParticipantDids: clearedParticipantDids(participants, disclosures, recusals),
    coveredParticipantDids,
    decisionType: input?.decisionMatter?.decisionType ?? null,
    disclosureRefs: disclosureRefs(disclosures),
    managedConflictDids: managedConflictDids(disclosures),
    matterRef: input?.decisionMatter?.matterRef ?? null,
    participantDids: participantIds,
    protocolRef: input?.decisionMatter?.protocolRef ?? null,
    recusalRefs: recusalRefs(recusals),
    recusedParticipantDids: recusedParticipantDids(recusals),
    schema: 'cybermedica.conflict_disclosure_review_material.v1',
    siteRef: input?.decisionMatter?.siteRef ?? null,
    tenantId: input?.tenantId ?? null,
  };
  const reviewHash = sha256Hex(reviewMaterial);

  return {
    schema: 'cybermedica.conflict_disclosure_review.v1',
    reviewId: `cmcoi_${reviewHash.slice(0, 32)}`,
    reviewHash,
    status: reasons.length === 0 ? 'cleared_for_participation' : 'blocked',
    tenantId: input?.tenantId ?? null,
    matterRef: input?.decisionMatter?.matterRef ?? null,
    decisionType: input?.decisionMatter?.decisionType ?? null,
    materialDecision: input?.decisionMatter?.material === true,
    participantDids: participantIds,
    coveredParticipantDids,
    disclosureCoverageBasisPoints: basisPoints(coveredParticipantDids.length, participantIds.length),
    clearedParticipantDids: reviewMaterial.clearedParticipantDids,
    blockedParticipantDids: reviewMaterial.blockedParticipantDids,
    managedConflictDids: reviewMaterial.managedConflictDids,
    recusedParticipantDids: reviewMaterial.recusedParticipantDids,
    aiFlaggedParticipantDids: reviewMaterial.aiFlaggedParticipantDids,
    aiFinalAuthority: input?.aiReview?.finalAuthority === true,
    trustState: 'inactive',
    exochainProductionClaim: false,
    receiptId,
  };
}

function buildReceipt(input, conflictReview) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'conflict_disclosure_review',
    artifactVersion: `${input.decisionMatter.matterRef}@${conflictReview.reviewId}`,
    artifactHash: conflictReview.reviewHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.decisionMatter.scheduledAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['conflict_disclosure', 'governance', 'metadata_only', 'recusal'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function evaluateConflictDisclosureReview(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateMatter(input, reasons);
  const participants = participantMap(input, reasons);
  const disclosures = disclosureMap(input, reasons);
  const recusals = recusalMap(input, reasons);
  evaluateParticipantConflicts(input, participants, disclosures, recusals, reasons);
  evaluateAiReview(input, participants, reasons);
  evaluateGovernance(input, reasons);

  const preliminaryReview = buildConflictReview(input ?? {}, participants, disclosures, recusals, reasons);
  if (reasons.length > 0) {
    return {
      decision: 'denied',
      failClosed: true,
      reasons: uniqueSorted(reasons),
      conflictReview: preliminaryReview,
      receipt: null,
    };
  }

  const receipt = buildReceipt(input, preliminaryReview);
  const conflictReview = { ...preliminaryReview, receiptId: receipt.receiptId };

  return {
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    conflictReview,
    receipt,
  };
}
