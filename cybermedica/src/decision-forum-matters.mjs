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
const DECISION_CLASSES = new Set(['routine', 'operational', 'strategic', 'constitutional']);
const DISCLOSURE_STATUSES = new Set(['clear', 'managed', 'active', 'unresolved']);
const VOTES = new Set([
  'abstain',
  'approve',
  'approve_with_conditions',
  'defer',
  'emergency_authorize',
  'escalate',
  'reject',
  'revoke',
]);
const OUTCOMES = new Set([
  'approve',
  'approve_with_conditions',
  'contest',
  'defer',
  'emergency_authorize',
  'escalate',
  'reject',
  'revoke',
]);
const CONTEST_STATUSES = new Set(['filed', 'under_review']);
const CONTEST_STANDING_ROLES = new Set([
  'affected_participant',
  'affected_site_governance',
  'authorized_support_security',
  'auditor',
  'qa',
  'sponsor_cro_oversight',
]);
const APPROVAL_VOTES = new Set(['approve', 'approve_with_conditions', 'emergency_authorize']);
const RAW_DECISION_FORUM_FIELDS = new Set([
  'conditiontext',
  'decisionrationaletext',
  'deliberationnotes',
  'dissenttext',
  'minorityviewtext',
  'rawcondition',
  'rawdecisionrationale',
  'rawdeliberation',
  'rawdeliberationnotes',
  'rawdissent',
  'rawminorityview',
  'rawvote',
  'rawvoterationale',
  'verbatimdeliberation',
  'voterationaletext',
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

function assertNoRawDecisionForumContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawDecisionForumContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    if (RAW_DECISION_FORUM_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`raw decision forum content field is not allowed at ${path}.${key}`);
    }
    assertNoRawDecisionForumContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawDecisionForumContent(input ?? {});
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

function validateDigestList(reasons, values, absentReason, invalidReason) {
  if (!Array.isArray(values) || values.length === 0) {
    reasons.push(absentReason);
    return [];
  }
  for (const value of values) {
    addReason(reasons, !isDigest(value), invalidReason);
  }
  return uniqueSorted(values);
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
  addReason(reasons, !hasAuthorityPermission(input?.authority, 'govern'), 'decision_forum_authority_missing');
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateMatter(input, reasons) {
  const matter = input?.matter;
  addReason(reasons, !hasText(matter?.matterRef), 'matter_ref_absent');
  addReason(reasons, !isDigest(matter?.titleHash), 'matter_title_hash_invalid');
  addReason(reasons, !hasText(matter?.decisionType), 'decision_type_absent');
  addReason(reasons, !DECISION_CLASSES.has(matter?.decisionClass), 'decision_class_invalid');
  addReason(reasons, matter?.material !== true, 'material_decision_required');
  addReason(reasons, !hasText(matter?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(matter?.protocolRef), 'protocol_ref_absent');

  addReason(reasons, hlcTuple(matter?.createdAtHlc) === null, 'created_time_invalid');
  addReason(reasons, hlcTuple(matter?.reviewOpenedAtHlc) === null, 'review_time_invalid');
  addReason(reasons, hlcTuple(matter?.deliberationOpenedAtHlc) === null, 'deliberation_time_invalid');
  addReason(reasons, hlcTuple(matter?.voteOpenedAtHlc) === null, 'vote_opened_time_invalid');
  addReason(reasons, hlcTuple(matter?.closedAtHlc) === null, 'closed_time_invalid');
  addReason(reasons, hlcBefore(matter?.reviewOpenedAtHlc, matter?.createdAtHlc), 'review_before_creation');
  addReason(reasons, hlcBefore(matter?.deliberationOpenedAtHlc, matter?.reviewOpenedAtHlc), 'deliberation_before_review');
  addReason(reasons, hlcBefore(matter?.voteOpenedAtHlc, matter?.deliberationOpenedAtHlc), 'vote_opened_before_deliberation');
  addReason(reasons, hlcBefore(matter?.closedAtHlc, matter?.voteOpenedAtHlc), 'closed_before_vote_opened');
  addReason(reasons, hlcBefore(matter?.expirationAtHlc, matter?.closedAtHlc), 'expiration_before_closure');
}

function evaluateEvidenceBundle(input, reasons) {
  const evidence = input?.evidenceBundle;
  addReason(reasons, evidence?.complete !== true, 'evidence_bundle_incomplete');
  addReason(reasons, evidence?.phiBoundaryAttested !== true, 'phi_boundary_unattested');
  addReason(reasons, !isDigest(evidence?.bundleHash), 'evidence_bundle_hash_invalid');
  validateDigestList(reasons, evidence?.sourceArtifactHashes, 'source_artifact_hashes_absent', 'source_artifact_hash_invalid');
  addReason(
    reasons,
    !Array.isArray(evidence?.controlRefs) || evidence.controlRefs.filter(hasText).length === 0,
    'control_refs_absent',
  );
  addReason(reasons, !isDigest(evidence?.authorityChainHash), 'evidence_authority_chain_hash_invalid');
  addReason(
    reasons,
    !Array.isArray(evidence?.consentRefs) || evidence.consentRefs.filter(hasText).length === 0,
    'consent_refs_absent',
  );
  addReason(reasons, !hasText(evidence?.riskAssessmentRef), 'risk_assessment_ref_absent');
  addReason(reasons, !isDigest(evidence?.alternativesHash), 'alternatives_hash_invalid');
  addReason(reasons, !isDigest(evidence?.noActionRationaleHash), 'no_action_rationale_hash_invalid');
  addReason(reasons, !isDigest(evidence?.humanReviewEvidenceHash), 'human_review_evidence_hash_invalid');
}

function evaluateAiAnalysis(input, reasons) {
  const ai = input?.aiAnalysis;
  addReason(reasons, ai?.attached !== true, 'ai_analysis_absent');
  addReason(reasons, ai?.advisoryOnly !== true, 'ai_analysis_must_be_advisory');
  addReason(reasons, ai?.finalAuthority === true, 'ai_analysis_final_authority_forbidden');
  addReason(reasons, !isDigest(ai?.promptHash), 'ai_analysis_prompt_hash_invalid');
  addReason(reasons, !isDigest(ai?.outputHash), 'ai_analysis_output_hash_invalid');
  validateDigestList(reasons, ai?.evidenceUsedHashes, 'ai_analysis_evidence_absent', 'ai_analysis_evidence_hash_invalid');
  addReason(
    reasons,
    !Number.isSafeInteger(ai?.confidenceBasisPoints) ||
      ai.confidenceBasisPoints < 0 ||
      ai.confidenceBasisPoints > 10_000,
    'ai_analysis_confidence_invalid',
  );
  addReason(reasons, !isDigest(ai?.limitsHash), 'ai_analysis_limits_hash_invalid');
  if (Array.isArray(ai?.unresolvedAssumptionHashes)) {
    for (const hash of ai.unresolvedAssumptionHashes) {
      addReason(reasons, !isDigest(hash), 'ai_analysis_assumption_hash_invalid');
    }
  }
  addReason(reasons, !hasText(ai?.recommendedHumanReviewerRole), 'ai_analysis_reviewer_role_absent');
}

function participantMap(input, reasons) {
  const participants = Array.isArray(input?.participants) ? input.participants : [];
  const byDid = new Map();
  addReason(reasons, participants.length === 0, 'decision_participants_absent');
  for (const participant of participants) {
    const did = participant?.did ?? 'unknown';
    addReason(reasons, !hasText(participant?.did), 'decision_participant_did_absent');
    addReason(reasons, !hasText(participant?.role), `decision_participant_role_absent:${did}`);
    addReason(reasons, !DISCLOSURE_STATUSES.has(participant?.disclosureStatus), `disclosure_status_invalid:${did}`);
    addReason(reasons, participant?.recused === true && !hasText(participant?.recusalRef), `recusal_ref_absent:${did}`);
    addReason(reasons, byDid.has(participant?.did), `decision_participant_duplicate:${did}`);
    if (hasText(participant?.did) && !byDid.has(participant.did)) {
      byDid.set(participant.did, participant);
    }
  }
  return byDid;
}

function evaluateConflictReview(input, participants, reasons) {
  const review = input?.conflictReview;
  addReason(reasons, review?.verified !== true, 'conflict_review_unverified');
  addReason(reasons, !hasText(review?.reviewRef), 'conflict_review_ref_absent');
  addReason(reasons, review?.coverageBasisPoints !== 10_000, 'conflict_review_incomplete');
  addReason(reasons, !isDigest(review?.evidenceHash), 'conflict_review_evidence_hash_invalid');

  const recused = new Set(sortedTextList(review?.recusedParticipantDids));
  for (const did of sortedTextList(review?.unresolvedConflictDids)) {
    reasons.push(`unresolved_conflict:${did}`);
  }
  for (const did of sortedTextList(review?.activeConflictDids)) {
    addReason(reasons, !recused.has(did), `active_conflict_without_recusal:${did}`);
  }
  for (const participant of participants.values()) {
    addReason(
      reasons,
      participant?.disclosureStatus === 'active' && participant?.recused !== true,
      `active_conflict_without_recusal:${participant.did}`,
    );
  }
}

function evaluateQuorum(input, reasons) {
  const quorum = input?.quorum;
  addReason(reasons, quorum?.verified !== true, 'quorum_unverified');
  addReason(reasons, quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, !isDigest(quorum?.policyHash), 'quorum_policy_hash_invalid');
  addReason(
    reasons,
    !Array.isArray(quorum?.requiredVotingRoles) || quorum.requiredVotingRoles.filter(hasText).length === 0,
    'required_voting_roles_absent',
  );
  addReason(
    reasons,
    !Number.isSafeInteger(quorum?.approvalsNeeded) || quorum.approvalsNeeded < 1,
    'approval_threshold_invalid',
  );
}

function voteMap(input, participants, reasons) {
  const byDid = new Map();
  const votes = Array.isArray(input?.votes) ? input.votes : [];
  addReason(reasons, votes.length === 0, 'votes_absent');
  for (const vote of votes) {
    const did = vote?.voterDid ?? 'unknown';
    const participant = participants.get(vote?.voterDid);
    addReason(reasons, !hasText(vote?.voterDid), 'vote_voter_absent');
    addReason(reasons, byDid.has(vote?.voterDid), `duplicate_vote:${did}`);
    addReason(reasons, participant === undefined, `vote_unknown_participant:${did}`);
    addReason(reasons, !hasText(vote?.role), `vote_role_absent:${did}`);
    addReason(reasons, participant !== undefined && vote?.role !== participant?.role, `vote_role_mismatch:${did}`);
    addReason(reasons, !VOTES.has(vote?.vote), `vote_value_invalid:${did}`);
    if (vote?.vote === 'abstain') {
      addReason(reasons, !isDigest(vote?.rationaleHash), `abstention_rationale_hash_invalid:${did}`);
    } else {
      addReason(reasons, !isDigest(vote?.rationaleHash), `vote_rationale_hash_invalid:${did}`);
    }
    addReason(reasons, !isDigest(vote?.signatureHash), `vote_signature_hash_invalid:${did}`);
    addReason(reasons, hlcTuple(vote?.castAtHlc) === null, `vote_time_invalid:${did}`);
    addReason(reasons, hlcBefore(vote?.castAtHlc, input?.matter?.voteOpenedAtHlc), `vote_before_vote_opened:${did}`);
    addReason(reasons, hlcAfter(vote?.castAtHlc, input?.matter?.closedAtHlc), `vote_after_matter_closed:${did}`);
    addReason(
      reasons,
      participant?.recused === true && vote?.vote !== 'abstain',
      `recused_participant_cast_binding_vote:${did}`,
    );
    if (hasText(vote?.voterDid) && !byDid.has(vote.voterDid)) {
      byDid.set(vote.voterDid, vote);
    }
  }
  return byDid;
}

function evaluateRequiredVotes(input, participants, votes, reasons) {
  const requiredRoles = sortedTextList(input?.quorum?.requiredVotingRoles);
  for (const role of requiredRoles) {
    const roleVotes = [...votes.values()].filter((vote) => vote?.role === role);
    addReason(reasons, roleVotes.length === 0, `vote_missing_for_role:${role}`);
  }

  const approvals = [...votes.values()].filter((vote) => APPROVAL_VOTES.has(vote?.vote)).length;
  addReason(reasons, approvals < input?.quorum?.approvalsNeeded, 'approval_threshold_not_met');

  for (const participant of participants.values()) {
    if (participant?.votingEligible !== true) {
      continue;
    }
    addReason(reasons, !votes.has(participant.did), `eligible_voter_missing_vote:${participant.did}`);
  }
}

function evaluateDisposition(input, reasons) {
  const disposition = input?.disposition;
  const outcome = disposition?.outcome;
  addReason(reasons, !OUTCOMES.has(outcome), 'decision_outcome_invalid');
  addReason(reasons, !isDigest(disposition?.rationaleHash), 'decision_rationale_hash_invalid');

  for (const hash of sortedTextList(disposition?.minorityViewHashes)) {
    addReason(reasons, !isDigest(hash), 'minority_view_hash_invalid');
  }
  for (const hash of sortedTextList(disposition?.dissentHashes)) {
    addReason(reasons, !isDigest(hash), 'dissent_hash_invalid');
  }
  for (const hash of sortedTextList(disposition?.conditionHashes)) {
    addReason(reasons, !isDigest(hash), 'condition_hash_invalid');
  }

  const conditionHashes = sortedTextList(disposition?.conditionHashes);
  addReason(reasons, outcome === 'approve_with_conditions' && conditionHashes.length === 0, 'conditions_required_for_outcome');
  addReason(reasons, outcome !== 'approve_with_conditions' && conditionHashes.length > 0, 'conditions_not_allowed_for_outcome');

  const followUps = Array.isArray(disposition?.followUpActions) ? disposition.followUpActions : [];
  addReason(reasons, outcome === 'approve_with_conditions' && followUps.length === 0, 'follow_up_required_for_conditions');
  for (const followUp of followUps) {
    const ref = followUp?.actionRef ?? 'unknown';
    addReason(reasons, !hasText(followUp?.actionRef), 'follow_up_action_ref_absent');
    addReason(reasons, !hasText(followUp?.ownerDid), `follow_up_owner_absent:${ref}`);
    addReason(reasons, hlcTuple(followUp?.dueAtHlc) === null, `follow_up_due_time_invalid:${ref}`);
    addReason(reasons, hlcBefore(followUp?.dueAtHlc, input?.matter?.closedAtHlc), `follow_up_due_before_closure:${ref}`);
    addReason(reasons, !isDigest(followUp?.evidenceHash), `follow_up_evidence_hash_invalid:${ref}`);
  }

  evaluateNotificationRequirement(
    reasons,
    disposition?.sponsorNotificationRequired,
    disposition?.sponsorNotificationEvidenceHash,
    disposition?.sponsorNotificationRationaleHash,
    'sponsor',
  );
  evaluateNotificationRequirement(
    reasons,
    disposition?.irbIecNotificationRequired,
    disposition?.irbIecNotificationEvidenceHash,
    disposition?.irbIecNotificationRationaleHash,
    'irb_iec',
  );
  evaluateNotificationRequirement(
    reasons,
    disposition?.regulatoryNotificationRequired,
    disposition?.regulatoryNotificationEvidenceHash,
    disposition?.regulatoryNotificationRationaleHash,
    'regulatory',
  );
}

function evaluateNotificationRequirement(reasons, required, evidenceHash, rationaleHash, prefix) {
  addReason(reasons, required !== true && required !== false, `${prefix}_notification_requirement_absent`);
  addReason(reasons, required === true && !isDigest(evidenceHash), `${prefix}_notification_evidence_missing`);
  addReason(reasons, required === false && !isDigest(rationaleHash), `${prefix}_notification_rationale_missing`);
}

function evaluateContestation(input, reasons) {
  const contest = input?.contestation;
  const outcome = input?.disposition?.outcome;
  if (outcome !== 'contest') {
    addReason(reasons, contest?.open === true, 'unexpected_open_contestation');
    return;
  }

  addReason(reasons, contest?.open !== true, 'contestation_not_open');
  addReason(reasons, !CONTEST_STATUSES.has(contest?.status), 'contestation_status_invalid');
  addReason(reasons, sortedTextList(contest?.contestRefs).length === 0, 'contestation_ref_absent');
  addReason(reasons, !hasText(contest?.filedByDid), 'contestation_filer_absent');
  addReason(reasons, !CONTEST_STANDING_ROLES.has(contest?.standingRole), 'contestation_standing_invalid');
  addReason(reasons, !isDigest(contest?.reasonHash), 'contestation_reason_hash_invalid');
  addReason(reasons, hlcTuple(contest?.filedAtHlc) === null, 'contestation_time_invalid');
  addReason(reasons, hlcBefore(contest?.filedAtHlc, input?.matter?.closedAtHlc), 'contestation_before_decision_closure');
  addReason(reasons, !hasText(contest?.independentReviewerDid), 'contestation_independent_reviewer_absent');
}

function evaluateReceipts(input, reasons) {
  addReason(reasons, !hasText(input?.receipts?.workflowReceiptId), 'workflow_receipt_absent');
  addReason(reasons, !isDigest(input?.receipts?.auditEntryHash), 'audit_entry_hash_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function voteSummary(votes) {
  const summary = {
    abstain: 0,
    approve: 0,
    approve_with_conditions: 0,
    defer: 0,
    emergency_authorize: 0,
    escalate: 0,
    reject: 0,
    revoke: 0,
  };
  for (const vote of votes.values()) {
    if (Object.hasOwn(summary, vote?.vote)) {
      summary[vote.vote] += 1;
    }
  }
  return summary;
}

function notificationRequirementCount(disposition) {
  return [
    disposition?.sponsorNotificationRequired,
    disposition?.irbIecNotificationRequired,
    disposition?.regulatoryNotificationRequired,
  ].filter((required) => required === true).length;
}

function matterStatus(input, reasons) {
  if (reasons.length > 0) {
    return 'blocked';
  }
  if (input?.disposition?.outcome === 'contest' || input?.contestation?.open === true) {
    return 'contested';
  }
  return 'closed';
}

function lifecycleStepsFor(status) {
  if (status === 'blocked') {
    return ['created', 'reviewed', 'blocked'];
  }
  if (status === 'contested') {
    return ['created', 'reviewed', 'deliberated', 'voted', 'contested', 'receipt_prepared'];
  }
  return ['created', 'reviewed', 'deliberated', 'voted', 'closed', 'receipt_prepared'];
}

function buildMatterRecord(input, participants, votes, reasons, receiptId = null) {
  const status = matterStatus(input, reasons);
  const finalClosure = status === 'closed';
  const conditionHashes = sortedTextList(input?.disposition?.conditionHashes);
  const matterMaterial = {
    actorDid: input?.actor?.did ?? null,
    aiOutputHash: input?.aiAnalysis?.outputHash ?? null,
    conditionHashes,
    contestRefs: sortedTextList(input?.contestation?.contestRefs),
    controlRefs: sortedTextList(input?.evidenceBundle?.controlRefs),
    decisionClass: input?.matter?.decisionClass ?? null,
    decisionType: input?.matter?.decisionType ?? null,
    dissentHashes: sortedTextList(input?.disposition?.dissentHashes),
    evidenceBundleHash: input?.evidenceBundle?.bundleHash ?? null,
    finalClosure,
    lifecycleSteps: lifecycleStepsFor(status),
    matterRef: input?.matter?.matterRef ?? null,
    minorityViewHashes: sortedTextList(input?.disposition?.minorityViewHashes),
    outcome: input?.disposition?.outcome ?? null,
    participantDids: uniqueSorted([...participants.keys()]),
    requiredVotingRoles: sortedTextList(input?.quorum?.requiredVotingRoles),
    schema: 'cybermedica.decision_forum_matter_material.v1',
    status,
    tenantId: input?.tenantId ?? null,
    voteSummary: voteSummary(votes),
  };
  const matterHash = sha256Hex(matterMaterial);

  return {
    schema: 'cybermedica.decision_forum_matter.v1',
    matterId: `cmdf_${matterHash.slice(0, 32)}`,
    matterHash,
    status,
    finalClosure,
    tenantId: input?.tenantId ?? null,
    matterRef: input?.matter?.matterRef ?? null,
    decisionType: input?.matter?.decisionType ?? null,
    decisionClass: input?.matter?.decisionClass ?? null,
    materialDecision: input?.matter?.material === true,
    lifecycleSteps: matterMaterial.lifecycleSteps,
    requiredVotingRoles: matterMaterial.requiredVotingRoles,
    votingParticipantDids: uniqueSorted(
      [...participants.values()]
        .filter((participant) => participant?.votingEligible === true)
        .map((participant) => participant?.did),
    ),
    recusedParticipantDids: uniqueSorted(
      [...participants.values()]
        .filter((participant) => participant?.recused === true)
        .map((participant) => participant?.did),
    ),
    voteSummary: matterMaterial.voteSummary,
    outcome: input?.disposition?.outcome ?? null,
    conditions: conditionHashes,
    followUpActionCount: Array.isArray(input?.disposition?.followUpActions) ? input.disposition.followUpActions.length : 0,
    notificationRequirementCount: notificationRequirementCount(input?.disposition),
    openChallenge: status === 'contested',
    aiFinalAuthority: input?.aiAnalysis?.finalAuthority === true,
    trustState: 'inactive',
    exochainProductionClaim: false,
    receiptId,
  };
}

function buildDashboardItem(input, matterRecord) {
  return {
    schema: 'cybermedica.decision_forum_dashboard_item.v1',
    matterRef: matterRecord.matterRef,
    status: matterRecord.status,
    decisionType: matterRecord.decisionType,
    requiredQuorumStatus: input?.quorum?.status ?? 'unknown',
    conflictReviewRef: input?.conflictReview?.reviewRef ?? null,
    evidenceBundleHash: input?.evidenceBundle?.bundleHash ?? null,
    aiReviewSummaryHash: input?.aiAnalysis?.outputHash ?? null,
    voteSummary: matterRecord.voteSummary,
    conditions: matterRecord.conditions,
    dissentHashes: sortedTextList(input?.disposition?.dissentHashes),
    decisionOutcome: matterRecord.outcome,
    followUpActionCount: matterRecord.followUpActionCount,
    openChallenge: matterRecord.openChallenge,
    trustState: matterRecord.trustState,
    exochainProductionClaim: false,
  };
}

function buildReceipt(input, matterRecord) {
  const timestamp =
    matterRecord.status === 'contested' && hlcTuple(input?.contestation?.filedAtHlc) !== null
      ? input.contestation.filedAtHlc
      : input.matter.closedAtHlc;

  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'decision_forum_matter',
    artifactVersion: `${input.matter.matterRef}@${matterRecord.status}`,
    artifactHash: matterRecord.matterHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: timestamp,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['decision_forum', 'governance', 'metadata_only', 'human_gate'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function evaluateDecisionForumMatter(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateMatter(input, reasons);
  evaluateEvidenceBundle(input, reasons);
  evaluateAiAnalysis(input, reasons);
  const participants = participantMap(input, reasons);
  evaluateConflictReview(input, participants, reasons);
  evaluateQuorum(input, reasons);
  const votes = voteMap(input, participants, reasons);
  evaluateRequiredVotes(input, participants, votes, reasons);
  evaluateDisposition(input, reasons);
  evaluateContestation(input, reasons);
  evaluateReceipts(input, reasons);

  const preliminaryRecord = buildMatterRecord(input ?? {}, participants, votes, reasons);
  const dashboardItem = buildDashboardItem(input ?? {}, preliminaryRecord);
  if (reasons.length > 0) {
    return {
      decision: 'denied',
      failClosed: true,
      reasons: uniqueSorted(reasons),
      matterRecord: preliminaryRecord,
      dashboardItem,
      receipt: null,
    };
  }

  const receipt = buildReceipt(input, preliminaryRecord);
  const matterRecord = { ...preliminaryRecord, receiptId: receipt.receiptId };

  return {
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    matterRecord,
    dashboardItem: buildDashboardItem(input, matterRecord),
    receipt,
  };
}
