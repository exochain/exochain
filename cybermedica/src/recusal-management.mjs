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
const REQUIRED_PERMISSION = 'manage_recusals';

const POLICY_STATUSES = new Set(['active']);
const FINDING_STATUSES = new Set(['clear', 'managed', 'active', 'unresolved']);
const ACTIVE_CONFLICT_STATUSES = new Set(['active', 'unresolved']);
const RECUSAL_ACTION_STATUSES = new Set(['active', 'accepted']);
const RECUSAL_SCOPES = new Set(['decision', 'review', 'decision_and_review']);
const HUMAN_REVIEW_DECISIONS = new Set(['recusal_plan_accepted_inactive_trust', 'hold_for_recusal_gap']);

const RAW_RECUSAL_FIELDS = new Set([
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
  'rawrecusal',
  'rawrecusalcontent',
  'rawrecusalreason',
  'recusalexplanation',
  'recusalreasontext',
  'relationshipdetails',
  'verbatimdisclosure',
]);

const SECRET_RECUSAL_FIELDS = new Set([
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

function assertNoRawRecusalContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawRecusalContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_RECUSAL_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw recusal content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_RECUSAL_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`recusal secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawRecusalContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawRecusalContent(input ?? {});
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

function basisPoints(numerator, denominator) {
  if (denominator === 0) {
    return 10000;
  }
  return Number((BigInt(numerator) * 10000n) / BigInt(denominator));
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
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
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) &&
      !hasAuthorityPermission(input?.authority, 'govern') &&
      !hasAuthorityPermission(input?.authority, 'write'),
    'recusal_management_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateDecisionMatter(input, reasons) {
  const matter = input?.decisionMatter;
  addReason(reasons, !hasText(matter?.matterRef), 'decision_matter_ref_absent');
  addReason(reasons, !hasText(matter?.decisionType), 'decision_type_absent');
  addReason(reasons, matter?.material !== true, 'material_decision_required');
  addReason(reasons, !hasText(matter?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(matter?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, hlcTuple(matter?.scheduledAtHlc) === null, 'decision_matter_time_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function evaluateRecusalPolicy(input, reasons) {
  const policy = input?.recusalPolicy;
  if (policy === undefined) {
    reasons.push('recusal_policy_missing');
    return;
  }

  addReason(reasons, !hasText(policy?.policyRef), 'recusal_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'recusal_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'recusal_policy_inactive');
  addReason(reasons, policy?.metadataOnly !== true, 'recusal_policy_not_metadata_only');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'recusal_policy_protected_boundary_unattested');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'recusal_policy_time_invalid');
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, input?.decisionMatter?.scheduledAtHlc), 'recusal_policy_after_matter_start');

  const requiredScopes = new Set(sortedTextList(policy?.requiredScopes));
  addReason(reasons, !requiredScopes.has('decision'), 'recusal_policy_decision_scope_absent');
  addReason(reasons, !requiredScopes.has('review'), 'recusal_policy_review_scope_absent');
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
    addReason(reasons, typeof participant?.activeOnMatter !== 'boolean', `decision_participant_active_state_invalid:${did}`);
    addReason(reasons, byDid.has(participant?.did), `decision_participant_duplicate:${did}`);
    if (hasText(participant?.did) && !byDid.has(participant.did)) {
      byDid.set(participant.did, participant);
    }
  }

  return byDid;
}

function conflictFindingMap(input, participants, reasons) {
  const byDid = new Map();
  const findings = Array.isArray(input?.conflictFindings) ? input.conflictFindings : [];
  addReason(reasons, findings.length === 0, 'conflict_findings_absent');

  for (const finding of [...findings].sort((left, right) => String(left?.findingRef ?? '').localeCompare(String(right?.findingRef ?? '')))) {
    const did = finding?.participantDid ?? 'unknown';
    addReason(reasons, !hasText(finding?.findingRef), `conflict_finding_ref_absent:${did}`);
    addReason(reasons, !hasText(finding?.participantDid), 'conflict_finding_participant_absent');
    addReason(reasons, hasText(finding?.participantDid) && !participants.has(finding.participantDid), `conflict_finding_unknown_participant:${did}`);
    addReason(reasons, byDid.has(finding?.participantDid), `conflict_finding_duplicate:${did}`);
    addReason(reasons, !FINDING_STATUSES.has(finding?.status), `conflict_finding_status_invalid:${did}`);
    addReason(reasons, !isDigest(finding?.evidenceHash), `conflict_finding_evidence_hash_invalid:${did}`);
    addReason(reasons, hlcTuple(finding?.assessedAtHlc) === null, `conflict_finding_time_invalid:${did}`);
    addReason(reasons, hlcAfter(finding?.assessedAtHlc, input?.decisionMatter?.scheduledAtHlc), `conflict_finding_after_matter_start:${did}`);
    addReason(
      reasons,
      finding?.status === 'managed' && !isDigest(finding?.managementPlanHash),
      `managed_conflict_plan_hash_invalid:${did}`,
    );
    addReason(
      reasons,
      ACTIVE_CONFLICT_STATUSES.has(finding?.status) && finding?.requiresRecusal !== true,
      `active_conflict_must_require_recusal:${did}`,
    );
    if (hasText(finding?.participantDid) && !byDid.has(finding.participantDid)) {
      byDid.set(finding.participantDid, finding);
    }
  }

  return byDid;
}

function recusalActionMap(input, participants, findings, reasons) {
  const byDid = new Map();
  const actions = Array.isArray(input?.recusalActions) ? input.recusalActions : [];

  for (const action of [...actions].sort((left, right) => String(left?.recusalRef ?? '').localeCompare(String(right?.recusalRef ?? '')))) {
    const did = action?.participantDid ?? 'unknown';
    addReason(reasons, !hasText(action?.recusalRef), `recusal_ref_absent:${did}`);
    addReason(reasons, !hasText(action?.participantDid), 'recusal_participant_absent');
    addReason(reasons, hasText(action?.participantDid) && !participants.has(action.participantDid), `recusal_unknown_participant:${did}`);
    addReason(reasons, byDid.has(action?.participantDid), `recusal_duplicate:${did}`);
    addReason(reasons, action?.matterRef !== input?.decisionMatter?.matterRef, `recusal_matter_mismatch:${did}`);
    addReason(
      reasons,
      action?.conflictFindingRef !== findings.get(action?.participantDid)?.findingRef,
      `recusal_conflict_finding_mismatch:${did}`,
    );
    addReason(reasons, !RECUSAL_ACTION_STATUSES.has(action?.status), `recusal_status_invalid:${did}`);
    addReason(reasons, !RECUSAL_SCOPES.has(action?.scope), `recusal_scope_invalid:${did}`);
    addReason(reasons, !isDigest(action?.reasonHash), `recusal_reason_hash_invalid:${did}`);
    addReason(reasons, !isDigest(action?.acknowledgementHash), `recusal_acknowledgement_hash_invalid:${did}`);
    addReason(reasons, !isDigest(action?.notificationHash), `recusal_notification_hash_invalid:${did}`);
    addReason(reasons, !hasText(action?.replacementDid), `recusal_replacement_absent:${did}`);
    addReason(reasons, !hasText(action?.acceptedByDid), `recusal_acceptance_absent:${did}`);
    addReason(reasons, hlcTuple(action?.effectiveAtHlc) === null, `recusal_effective_time_invalid:${did}`);
    addReason(reasons, hlcAfter(action?.effectiveAtHlc, input?.decisionMatter?.scheduledAtHlc), `recusal_after_matter_start:${did}`);
    if (hasText(action?.participantDid) && !byDid.has(action.participantDid)) {
      byDid.set(action.participantDid, action);
    }
  }

  return byDid;
}

function replacementMap(input, actions, reasons) {
  const byDid = new Map();
  const replacements = Array.isArray(input?.replacementEvidence) ? input.replacementEvidence : [];

  for (const replacement of [...replacements].sort((left, right) =>
    String(left?.replacedParticipantDid ?? '').localeCompare(String(right?.replacedParticipantDid ?? '')),
  )) {
    const did = replacement?.replacedParticipantDid ?? 'unknown';
    const action = actions.get(replacement?.replacedParticipantDid);
    addReason(reasons, !hasText(replacement?.replacedParticipantDid), 'replacement_participant_absent');
    addReason(reasons, byDid.has(replacement?.replacedParticipantDid), `replacement_duplicate:${did}`);
    addReason(
      reasons,
      action !== undefined && replacement?.replacementDid !== action?.replacementDid,
      `replacement_did_mismatch:${did}`,
    );
    addReason(reasons, !hasText(replacement?.replacementDid), `replacement_did_absent:${did}`);
    addReason(reasons, !hasText(replacement?.role), `replacement_role_absent:${did}`);
    addReason(reasons, !isDigest(replacement?.authorityHash), `replacement_authority_hash_invalid:${did}`);
    addReason(
      reasons,
      !isDigest(replacement?.disclosureClearanceHash),
      `replacement_disclosure_clearance_hash_invalid:${did}`,
    );
    addReason(reasons, hlcTuple(replacement?.acceptedAtHlc) === null, `replacement_acceptance_time_invalid:${did}`);
    addReason(
      reasons,
      action !== undefined && !hlcAfter(replacement?.acceptedAtHlc, action?.effectiveAtHlc),
      `replacement_accepted_before_recusal:${did}`,
    );
    if (hasText(replacement?.replacedParticipantDid) && !byDid.has(replacement.replacedParticipantDid)) {
      byDid.set(replacement.replacedParticipantDid, replacement);
    }
  }

  return byDid;
}

function requiredRecusalDids(findings) {
  return uniqueSorted(
    [...findings.entries()]
      .filter(([, finding]) => finding?.requiresRecusal === true || ACTIVE_CONFLICT_STATUSES.has(finding?.status))
      .map(([did]) => did),
  );
}

function recusalScopeCovers(action, requiredScope) {
  if (!RECUSAL_ACTION_STATUSES.has(action?.status)) {
    return false;
  }
  if (requiredScope === 'decision_and_review') {
    return action?.scope === 'decision_and_review';
  }
  if (requiredScope === 'decision') {
    return action?.scope === 'decision' || action?.scope === 'decision_and_review';
  }
  if (requiredScope === 'review') {
    return action?.scope === 'review' || action?.scope === 'decision_and_review';
  }
  return RECUSAL_SCOPES.has(action?.scope);
}

function evaluateRequiredRecusals(input, participants, findings, actions, replacements, reasons) {
  const roster = input?.matterRoster ?? {};
  const activeVotingDids = new Set(sortedTextList(roster?.activeVotingDids));
  const activeReviewDids = new Set(sortedTextList(roster?.activeReviewDids));
  const excludedVotingDids = new Set(sortedTextList(roster?.excludedVotingDids));
  const excludedReviewDids = new Set(sortedTextList(roster?.excludedReviewDids));

  for (const did of requiredRecusalDids(findings)) {
    const participant = participants.get(did);
    const finding = findings.get(did);
    const action = actions.get(did);
    const replacement = replacements.get(did);
    const requiredScope = finding?.requiredScope ?? 'decision_and_review';

    addReason(reasons, action === undefined || !recusalScopeCovers(action, requiredScope), `required_recusal_missing:${did}`);
    addReason(reasons, action !== undefined && !recusalScopeCovers(action, requiredScope), `recusal_scope_insufficient:${did}`);
    addReason(reasons, participant?.votingEligible === true && activeVotingDids.has(did), `recused_participant_active_voter:${did}`);
    addReason(reasons, participant?.reviewer === true && activeReviewDids.has(did), `recused_participant_active_reviewer:${did}`);
    addReason(reasons, participant?.votingEligible === true && !excludedVotingDids.has(did), `recused_participant_not_excluded_from_vote:${did}`);
    addReason(reasons, participant?.reviewer === true && !excludedReviewDids.has(did), `recused_participant_not_excluded_from_review:${did}`);
    addReason(reasons, action !== undefined && replacement === undefined, `replacement_evidence_missing:${did}`);
  }
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.humanGateVerified !== true, 'human_gate_unverified');
  addReason(reasons, review?.quorumStatus !== 'met', 'quorum_not_met');
  addReason(reasons, review?.openChallenge === true, 'challenge_open');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_not_metadata_only');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcAfter(review?.reviewedAtHlc, input?.decisionMatter?.scheduledAtHlc), 'human_review_after_matter_start');
}

function participantDids(participants) {
  return uniqueSorted([...participants.keys()]);
}

function coveredFindingDids(participants, findings) {
  return uniqueSorted([...participants.keys()].filter((did) => findings.has(did)));
}

function activeRecusedParticipantDids(actions) {
  return uniqueSorted(
    [...actions.entries()]
      .filter(([, action]) => RECUSAL_ACTION_STATUSES.has(action?.status))
      .map(([did]) => did),
  );
}

function replacementDids(replacements) {
  return uniqueSorted([...replacements.values()].map((replacement) => replacement?.replacementDid));
}

function clearedParticipantDids(participants, findings, actions) {
  const recused = new Set(activeRecusedParticipantDids(actions));
  const cleared = [];
  for (const did of participants.keys()) {
    if (recused.has(did)) {
      continue;
    }
    const finding = findings.get(did);
    if (finding?.status === 'clear' || finding?.status === 'managed') {
      cleared.push(did);
    }
  }
  return uniqueSorted(cleared);
}

function buildRecusalPlan(input, participants, findings, actions, replacements, reasons, receiptId = null) {
  const requiredDids = requiredRecusalDids(findings);
  const recusedDids = activeRecusedParticipantDids(actions).filter((did) => requiredDids.includes(did));
  const material = {
    actorDid: input?.actor?.did ?? null,
    clearedParticipantDids: clearedParticipantDids(participants, findings, actions),
    conflictFindingRefs: uniqueSorted([...findings.values()].map((finding) => finding?.findingRef)),
    decisionType: input?.decisionMatter?.decisionType ?? null,
    excludedReviewDids: sortedTextList(input?.matterRoster?.excludedReviewDids),
    excludedVotingDids: sortedTextList(input?.matterRoster?.excludedVotingDids),
    matterRef: input?.decisionMatter?.matterRef ?? null,
    participantDids: participantDids(participants),
    protocolRef: input?.decisionMatter?.protocolRef ?? null,
    recusalRefs: uniqueSorted([...actions.values()].map((action) => action?.recusalRef)),
    recusedParticipantDids: uniqueSorted(recusedDids),
    replacementDids: replacementDids(replacements),
    requiredRecusalDids: requiredDids,
    schema: 'cybermedica.recusal_management_plan_material.v1',
    siteRef: input?.decisionMatter?.siteRef ?? null,
    tenantId: input?.tenantId ?? null,
  };
  const planHash = sha256Hex(material);

  return {
    schema: 'cybermedica.recusal_management_plan.v1',
    planId: `cmrec_${planHash.slice(0, 32)}`,
    planHash,
    status: reasons.length === 0 ? 'ready_for_matter' : 'blocked',
    tenantId: input?.tenantId ?? null,
    matterRef: input?.decisionMatter?.matterRef ?? null,
    decisionType: input?.decisionMatter?.decisionType ?? null,
    materialDecision: input?.decisionMatter?.material === true,
    participantDids: material.participantDids,
    coveredFindingDids: coveredFindingDids(participants, findings),
    requiredRecusalDids: requiredDids,
    recusedParticipantDids: material.recusedParticipantDids,
    clearedParticipantDids: material.clearedParticipantDids,
    replacementDids: material.replacementDids,
    excludedVotingDids: material.excludedVotingDids,
    excludedReviewDids: material.excludedReviewDids,
    recusalCoverageBasisPoints: basisPoints(material.recusedParticipantDids.length, requiredDids.length),
    aiFinalAuthority: input?.humanReview?.aiFinalAuthority === true || input?.actor?.kind === 'ai_agent',
    trustState: 'inactive',
    exochainProductionClaim: false,
    receiptId,
  };
}

function buildReceipt(input, recusalPlan) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'recusal_management_plan',
    artifactVersion: `${input.decisionMatter.matterRef}:${recusalPlan.planId}`,
    artifactHash: recusalPlan.planHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['decision_forum', 'metadata_only', 'recusal_management'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function evaluateRecusalManagement(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateDecisionMatter(input, reasons);
  evaluateRecusalPolicy(input, reasons);
  const participants = participantMap(input, reasons);
  const findings = conflictFindingMap(input, participants, reasons);
  const actions = recusalActionMap(input, participants, findings, reasons);
  const replacements = replacementMap(input, actions, reasons);
  evaluateRequiredRecusals(input, participants, findings, actions, replacements, reasons);
  evaluateHumanReview(input, reasons);

  const preliminaryPlan = buildRecusalPlan(input ?? {}, participants, findings, actions, replacements, reasons);
  if (reasons.length > 0) {
    return {
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons(reasons),
      recusalPlan: preliminaryPlan,
      receipt: null,
    };
  }

  const receipt = buildReceipt(input, preliminaryPlan);
  const recusalPlan = { ...preliminaryPlan, receiptId: receipt.receiptId };

  return {
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    recusalPlan,
    receipt,
  };
}
