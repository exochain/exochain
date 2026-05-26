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

const CODE_STATUSES = new Set(['active', 'reserved']);
const PARTICIPANT_PRIOR_STATUSES = new Set(['active', 'enrolled', 'follow_up', 'screened']);
const DISPOSITION_KINDS = new Set(['withdrawal', 'lost_to_follow_up', 'early_termination', 'suspension']);
const REASON_STATUSES = new Set(['provided', 'refused', 'not_applicable', 'not_requested_due_to_safety']);
const REQUIRED_NOTIFICATION_PARTIES = Object.freeze(['principal_investigator', 'site_quality_lead', 'sponsor_contact']);
const RAW_PARTICIPANT_FIELDS = new Set([
  'contactattemptbody',
  'directidentifier',
  'homeaddress',
  'medicalrecordnumber',
  'participantidentifier',
  'participantname',
  'participantphone',
  'phone',
  'rawcontact',
  'rawparticipantcode',
  'rawparticipantidentifier',
  'rawparticipantnote',
  'rawreason',
  'rawwithdrawalreason',
  'sourceparticipantrecord',
  'subjectidentifier',
  'withdrawalreasontext',
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
  return [...new Set(values)].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function sortedDigestList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(isDigest))].sort() : [];
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function assertNoParticipantProtectedContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoParticipantProtectedContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    if (RAW_PARTICIPANT_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`participant protected content field is not allowed at ${path}.${key}`);
    }
    assertNoParticipantProtectedContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoParticipantProtectedContent(input ?? {});
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

function hlcAfterOrEqual(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) >= 0;
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
    !hasAuthorityPermission(input?.authority, 'manage_participants') && !hasAuthorityPermission(input?.authority, 'write'),
    'participant_management_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateParticipantCodeAssignment(input, reasons) {
  const assignment = input?.codeAssignment;
  const existingHashes = Array.isArray(assignment?.existingParticipantCodeHashes) ? assignment.existingParticipantCodeHashes : [];

  addReason(reasons, !hasText(assignment?.studyRef), 'study_ref_absent');
  addReason(reasons, !hasText(assignment?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(assignment?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(assignment?.codeNamespace), 'code_namespace_absent');
  addReason(reasons, !isDigest(assignment?.participantCodeHash), 'participant_code_hash_invalid');
  addReason(reasons, !isDigest(assignment?.codeListHash), 'code_list_hash_invalid');
  addReason(reasons, !Number.isSafeInteger(assignment?.sequenceNumber) || assignment.sequenceNumber < 1, 'sequence_number_invalid');
  addReason(reasons, hlcTuple(assignment?.assignedAtHlc) === null, 'code_assignment_time_invalid');
  addReason(reasons, !hasText(assignment?.sourceConsentProcessReceiptId), 'consent_process_receipt_absent');
  addReason(reasons, !hasText(assignment?.consentBailmentRef), 'consent_bailment_ref_absent');
  addReason(reasons, !isDigest(assignment?.privacyBoundaryHash), 'privacy_boundary_hash_invalid');
  addReason(reasons, !CODE_STATUSES.has(assignment?.status), 'participant_code_status_invalid');
  addReason(reasons, existingHashes.some((hash) => !isDigest(hash)), 'existing_participant_code_hash_invalid');
  addReason(
    reasons,
    isDigest(assignment?.participantCodeHash) && existingHashes.includes(assignment.participantCodeHash),
    'participant_code_duplicate',
  );
}

function evaluateIdentitySeparation(input, reasons) {
  const separation = input?.identitySeparation;
  addReason(reasons, separation?.directIdentifiersStored !== false, 'direct_identifier_storage_forbidden');
  addReason(reasons, separation?.linkingKeyEscrowed !== true, 'linking_key_escrow_absent');
  addReason(reasons, !hasText(separation?.linkingKeyCustodianDid), 'linking_key_custodian_absent');
  addReason(reasons, !isDigest(separation?.linkingKeyDigest), 'linking_key_digest_invalid');
  addReason(reasons, !isDigest(separation?.reidentificationPolicyHash), 'reidentification_policy_hash_invalid');
  addReason(reasons, sortedTextList(separation?.accessRoleRefs).length === 0, 'identity_access_roles_absent');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function participantCodeRecordId(input) {
  const assignment = input?.codeAssignment;
  return `cmpcode_${sha256Hex({
    codeNamespace: assignment?.codeNamespace ?? null,
    participantCodeHash: assignment?.participantCodeHash ?? null,
    protocolRef: assignment?.protocolRef ?? null,
    sequenceNumber: assignment?.sequenceNumber ?? null,
    siteRef: assignment?.siteRef ?? null,
    studyRef: assignment?.studyRef ?? null,
    tenantId: input?.tenantId ?? null,
  }).slice(0, 32)}`;
}

function buildParticipantCodeRecord(input, status, receiptId = null) {
  const assignment = input?.codeAssignment;
  const separation = input?.identitySeparation;

  return {
    schema: 'cybermedica.participant_code_record.v1',
    participantCodeRecordId: participantCodeRecordId(input),
    tenantId: input?.tenantId ?? null,
    studyRef: assignment?.studyRef ?? null,
    protocolRef: assignment?.protocolRef ?? null,
    siteRef: assignment?.siteRef ?? null,
    codeNamespace: assignment?.codeNamespace ?? null,
    participantCodeHash: assignment?.participantCodeHash ?? null,
    codeListHash: assignment?.codeListHash ?? null,
    sequenceNumber: assignment?.sequenceNumber ?? null,
    status,
    directIdentifiersStored: separation?.directIdentifiersStored === true,
    linkingKeyEscrowed: separation?.linkingKeyEscrowed === true,
    linkingKeyCustodianDid: separation?.linkingKeyCustodianDid ?? null,
    accessRoleRefs: sortedTextList(separation?.accessRoleRefs),
    assignedAtHlc: assignment?.assignedAtHlc ?? null,
    sourceConsentProcessReceiptId: assignment?.sourceConsentProcessReceiptId ?? null,
    consentBailmentRef: assignment?.consentBailmentRef ?? null,
    privacyBoundaryHash: assignment?.privacyBoundaryHash ?? null,
    receiptId,
    trustState: 'inactive',
    exochainProductionClaim: false,
    containsProtectedContent: false,
  };
}

function createParticipantCodeReceipt(input, record, artifactHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash,
    artifactType: 'participant_code_assignment',
    artifactVersion: `${record.siteRef}@${record.sequenceNumber}`,
    classification: 'participant_code_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.codeAssignment.assignedAtHlc,
    sensitivityTags: ['participant_code', 'metadata_only', 'participant_rights'],
    sourceSystem: 'cybermedica.participant_protection',
    tenantId: input.tenantId,
  });
}

export function assignParticipantCode(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateParticipantCodeAssignment(input, reasons);
  evaluateIdentitySeparation(input, reasons);
  const uniqueReasons = uniqueSorted(reasons);

  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.participant_code_assignment_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      participantCodeRecord: buildParticipantCodeRecord(input, 'blocked'),
      receipt: null,
    };
  }

  const record = buildParticipantCodeRecord(input, input.codeAssignment.status);
  const artifactHash = sha256Hex({
    accessRoleRefs: record.accessRoleRefs,
    codeListHash: record.codeListHash,
    codeNamespace: record.codeNamespace,
    consentBailmentRef: record.consentBailmentRef,
    existingParticipantCodeHashes: sortedDigestList(input.codeAssignment.existingParticipantCodeHashes),
    participantCodeHash: record.participantCodeHash,
    participantCodeRecordId: record.participantCodeRecordId,
    privacyBoundaryHash: record.privacyBoundaryHash,
    protocolRef: record.protocolRef,
    sequenceNumber: record.sequenceNumber,
    sourceConsentProcessReceiptId: record.sourceConsentProcessReceiptId,
    tenantId: input.tenantId,
  });
  const receipt = createParticipantCodeReceipt(input, record, artifactHash);

  return {
    schema: 'cybermedica.participant_code_assignment_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    participantCodeRecord: {
      ...record,
      receiptId: receipt.receiptId,
    },
    receipt,
  };
}

function evaluateParticipantForDisposition(input, reasons) {
  const participant = input?.participant;
  addReason(reasons, !hasText(participant?.participantCodeRecordId), 'participant_code_record_id_absent');
  addReason(reasons, !isDigest(participant?.participantCodeHash), 'participant_code_hash_invalid');
  addReason(reasons, !hasText(participant?.studyRef), 'study_ref_absent');
  addReason(reasons, !hasText(participant?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(participant?.siteRef), 'site_ref_absent');
  addReason(reasons, !PARTICIPANT_PRIOR_STATUSES.has(participant?.statusBefore), 'participant_prior_status_invalid');
  addReason(reasons, !hasText(participant?.consentBailmentRef), 'consent_bailment_ref_absent');
}

function dispositionStatusMatches(disposition) {
  if (disposition?.kind === 'withdrawal') {
    return disposition?.status === 'withdrawn';
  }
  if (disposition?.kind === 'lost_to_follow_up') {
    return disposition?.status === 'lost_to_follow_up';
  }
  if (disposition?.kind === 'early_termination') {
    return disposition?.status === 'early_terminated';
  }
  if (disposition?.kind === 'suspension') {
    return disposition?.status === 'suspended';
  }
  return false;
}

function evaluateDispositionShape(input, reasons) {
  const disposition = input?.disposition;
  addReason(reasons, !DISPOSITION_KINDS.has(disposition?.kind), 'participant_disposition_kind_invalid');
  addReason(reasons, !dispositionStatusMatches(disposition), 'participant_disposition_status_invalid');
  addReason(reasons, hlcTuple(disposition?.requestedAtHlc) === null, 'disposition_request_time_invalid');
  addReason(reasons, hlcTuple(disposition?.effectiveAtHlc) === null, 'disposition_effective_time_invalid');
  addReason(
    reasons,
    hlcTuple(disposition?.requestedAtHlc) !== null &&
      hlcTuple(disposition?.effectiveAtHlc) !== null &&
      !hlcAfterOrEqual(disposition.effectiveAtHlc, disposition.requestedAtHlc),
    'disposition_effective_before_request',
  );
  addReason(reasons, !REASON_STATUSES.has(disposition?.reasonStatus), 'reason_status_invalid');
  addReason(reasons, !isDigest(disposition?.sourceEvidenceHash), 'disposition_source_evidence_invalid');
  addReason(reasons, !isDigest(disposition?.participantRightsNotificationHash), 'participant_rights_notification_invalid');

  if (disposition?.kind === 'withdrawal') {
    addReason(
      reasons,
      disposition?.reasonStatus !== 'provided' && disposition?.reasonStatus !== 'refused',
      'withdrawal_reason_status_invalid',
    );
    addReason(reasons, disposition?.reasonStatus === 'provided' && !isDigest(disposition?.reasonHash), 'withdrawal_reason_hash_absent');
    addReason(
      reasons,
      disposition?.reasonStatus === 'refused' && disposition?.refusalDocumented !== true,
      'withdrawal_reason_refusal_not_documented',
    );
  }
}

function evaluateLostToFollowUp(disposition, reasons) {
  if (disposition?.kind !== 'lost_to_follow_up') {
    return;
  }

  const attempts = Array.isArray(disposition?.contactAttempts) ? disposition.contactAttempts : [];
  addReason(reasons, !hasText(disposition?.contactPolicyRef), 'lost_to_follow_up_contact_policy_absent');
  addReason(reasons, attempts.length < 3, 'lost_to_follow_up_attempts_insufficient');

  for (const attempt of attempts) {
    addReason(reasons, !hasText(attempt?.methodRef), 'contact_attempt_method_absent');
    addReason(reasons, hlcTuple(attempt?.attemptedAtHlc) === null, 'contact_attempt_time_invalid');
    addReason(reasons, !isDigest(attempt?.evidenceHash), 'contact_attempt_evidence_invalid');
    addReason(
      reasons,
      hlcTuple(attempt?.attemptedAtHlc) !== null &&
        hlcTuple(disposition?.requestedAtHlc) !== null &&
        !hlcAfterOrEqual(attempt.attemptedAtHlc, disposition.requestedAtHlc),
      'contact_attempt_before_lost_to_follow_up_start',
    );
    addReason(
      reasons,
      hlcTuple(attempt?.attemptedAtHlc) !== null &&
        hlcTuple(disposition?.effectiveAtHlc) !== null &&
        !hlcAfterOrEqual(disposition.effectiveAtHlc, attempt.attemptedAtHlc),
      'contact_attempt_after_lost_to_follow_up_closure',
    );
  }
}

function evaluatePostDispositionDataUse(disposition, reasons) {
  const dataUse = disposition?.postDispositionDataUse;
  addReason(reasons, dataUse?.consentLimited !== true, 'post_disposition_consent_limit_absent');
  addReason(reasons, sortedTextList(dataUse?.scopeRefs).length === 0, 'post_disposition_scope_refs_absent');
  addReason(reasons, !isDigest(dataUse?.policyHash), 'post_disposition_policy_hash_invalid');
}

function evaluateSafetyFollowUp(disposition, reasons) {
  const followUp = disposition?.safetyFollowUp;
  addReason(reasons, typeof followUp?.required !== 'boolean', 'safety_follow_up_requirement_invalid');

  if (followUp?.required === true) {
    addReason(reasons, !isDigest(followUp?.planHash), 'safety_follow_up_plan_absent');
    addReason(reasons, !hasText(followUp?.ownerDid), 'safety_follow_up_owner_absent');
    addReason(reasons, hlcTuple(followUp?.dueAtHlc) === null, 'safety_follow_up_due_time_invalid');
    addReason(
      reasons,
      hlcTuple(followUp?.dueAtHlc) !== null &&
        hlcTuple(disposition?.effectiveAtHlc) !== null &&
        !hlcAfterOrEqual(followUp.dueAtHlc, disposition.effectiveAtHlc),
      'safety_follow_up_due_before_disposition',
    );
    return;
  }

  if (followUp?.required === false) {
    addReason(reasons, !isDigest(followUp?.rationaleHash), 'safety_follow_up_rationale_absent');
    addReason(reasons, !hasText(followUp?.ownerDid), 'safety_follow_up_owner_absent');
  }
}

function evaluateNotifications(input, reasons) {
  const notifications = Array.isArray(input?.notifications) ? input.notifications : [];
  for (const party of REQUIRED_NOTIFICATION_PARTIES) {
    const notification = notifications.find((entry) => entry?.party === party);
    const missing =
      notification?.status !== 'notified' ||
      hlcTuple(notification?.notifiedAtHlc) === null ||
      !isDigest(notification?.evidenceHash) ||
      (hlcTuple(notification?.notifiedAtHlc) !== null &&
        hlcTuple(input?.disposition?.requestedAtHlc) !== null &&
        !hlcAfterOrEqual(notification.notifiedAtHlc, input.disposition.requestedAtHlc));
    addReason(reasons, missing, 'required_notification_absent');
  }
}

function evaluateDispositionReview(input, reasons) {
  addReason(reasons, !hasText(input?.review?.humanReviewerDid), 'human_review_absent');
  addReason(reasons, input?.review?.phiBoundaryAttested !== true, 'phi_boundary_unattested');
  addReason(reasons, input?.review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function dispositionRecordId(input) {
  const disposition = input?.disposition;
  return `cmpdisp_${sha256Hex({
    effectiveAtHlc: disposition?.effectiveAtHlc ?? null,
    kind: disposition?.kind ?? null,
    participantCodeHash: input?.participant?.participantCodeHash ?? null,
    participantCodeRecordId: input?.participant?.participantCodeRecordId ?? null,
    protocolRef: input?.participant?.protocolRef ?? null,
    requestedAtHlc: disposition?.requestedAtHlc ?? null,
    tenantId: input?.tenantId ?? null,
  }).slice(0, 32)}`;
}

function contactAttemptCount(disposition) {
  return Array.isArray(disposition?.contactAttempts) ? disposition.contactAttempts.length : 0;
}

function contactAttemptIsTracked(attempt, disposition) {
  if (!hasText(attempt?.methodRef) || !isDigest(attempt?.evidenceHash)) {
    return false;
  }

  const attemptedAt = hlcTuple(attempt?.attemptedAtHlc);
  const requestedAt = hlcTuple(disposition?.requestedAtHlc);
  const effectiveAt = hlcTuple(disposition?.effectiveAtHlc);
  if (attemptedAt === null || requestedAt === null || effectiveAt === null) {
    return false;
  }

  return hlcAfterOrEqual(attempt.attemptedAtHlc, disposition.requestedAtHlc) &&
    hlcAfterOrEqual(disposition.effectiveAtHlc, attempt.attemptedAtHlc);
}

function safetyFollowUpStatus(disposition) {
  if (disposition?.safetyFollowUp?.required === true) {
    return isDigest(disposition.safetyFollowUp.planHash) ? 'required_ready' : 'required_incomplete';
  }
  if (disposition?.safetyFollowUp?.required === false) {
    return isDigest(disposition.safetyFollowUp.rationaleHash) ? 'not_required_documented' : 'not_required_incomplete';
  }
  return 'unknown';
}

function lostToFollowUpProcessStatus(disposition) {
  if (disposition?.kind !== 'lost_to_follow_up') {
    return 'not_applicable';
  }
  const attempts = Array.isArray(disposition?.contactAttempts) ? disposition.contactAttempts : [];
  return hasText(disposition?.contactPolicyRef) &&
    attempts.length >= 3 &&
    attempts.every((attempt) => contactAttemptIsTracked(attempt, disposition))
    ? 'tracked'
    : 'incomplete';
}

function buildDispositionRecord(input, status, receiptId = null) {
  const disposition = input?.disposition;
  const participant = input?.participant;

  return {
    schema: 'cybermedica.participant_disposition_record.v1',
    dispositionRecordId: dispositionRecordId(input),
    tenantId: input?.tenantId ?? null,
    participantCodeRecordId: participant?.participantCodeRecordId ?? null,
    participantCodeHash: participant?.participantCodeHash ?? null,
    studyRef: participant?.studyRef ?? null,
    protocolRef: participant?.protocolRef ?? null,
    siteRef: participant?.siteRef ?? null,
    kind: disposition?.kind ?? null,
    status,
    statusBefore: participant?.statusBefore ?? null,
    continuationAllowed: false,
    enrollmentConsentGate: 'blocked',
    reasonStatus: disposition?.reasonStatus ?? null,
    reasonStored: isDigest(disposition?.reasonHash),
    refusalDocumented: disposition?.refusalDocumented === true,
    contactPolicyRef: disposition?.contactPolicyRef ?? null,
    contactAttemptCount: contactAttemptCount(disposition),
    lostToFollowUpProcessStatus: lostToFollowUpProcessStatus(disposition),
    postDispositionScopeRefs: sortedTextList(disposition?.postDispositionDataUse?.scopeRefs),
    safetyFollowUpStatus: safetyFollowUpStatus(disposition),
    requestedAtHlc: disposition?.requestedAtHlc ?? null,
    effectiveAtHlc: disposition?.effectiveAtHlc ?? null,
    notifiedParties: sortedTextList((Array.isArray(input?.notifications) ? input.notifications : []).map((entry) => entry?.party)),
    humanReviewerDid: input?.review?.humanReviewerDid ?? null,
    consentBailmentRef: participant?.consentBailmentRef ?? null,
    receiptId,
    trustState: 'inactive',
    exochainProductionClaim: false,
    containsProtectedContent: false,
  };
}

function createDispositionReceipt(input, record, artifactHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash,
    artifactType: 'participant_disposition',
    artifactVersion: `${record.participantCodeRecordId}@${record.kind}`,
    classification: 'participant_disposition_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.disposition.effectiveAtHlc,
    sensitivityTags: ['participant_disposition', 'metadata_only', 'participant_rights'],
    sourceSystem: 'cybermedica.participant_protection',
    tenantId: input.tenantId,
  });
}

export function recordParticipantDisposition(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateParticipantForDisposition(input, reasons);
  evaluateDispositionShape(input, reasons);
  evaluateLostToFollowUp(input?.disposition, reasons);
  evaluatePostDispositionDataUse(input?.disposition, reasons);
  evaluateSafetyFollowUp(input?.disposition, reasons);
  evaluateNotifications(input, reasons);
  evaluateDispositionReview(input, reasons);
  const uniqueReasons = uniqueSorted(reasons);

  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.participant_disposition_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      dispositionRecord: buildDispositionRecord(input, 'blocked'),
      receipt: null,
    };
  }

  const record = buildDispositionRecord(input, input.disposition.status);
  const contactAttemptHashes = Array.isArray(input.disposition.contactAttempts)
    ? input.disposition.contactAttempts.map((attempt) => attempt.evidenceHash).filter(isDigest).sort()
    : [];
  const notificationEvidenceHashes = Array.isArray(input.notifications)
    ? input.notifications.map((notification) => notification.evidenceHash).filter(isDigest).sort()
    : [];
  const artifactHash = sha256Hex({
    contactAttemptCount: record.contactAttemptCount,
    contactAttemptHashes,
    dispositionRecordId: record.dispositionRecordId,
    dispositionSourceEvidenceHash: input.disposition.sourceEvidenceHash,
    effectiveAtHlc: record.effectiveAtHlc,
    kind: record.kind,
    notificationEvidenceHashes,
    participantCodeHash: record.participantCodeHash,
    participantRightsNotificationHash: input.disposition.participantRightsNotificationHash,
    postDispositionScopeRefs: record.postDispositionScopeRefs,
    reasonHash: input.disposition.reasonHash ?? null,
    reasonStatus: record.reasonStatus,
    safetyFollowUpStatus: record.safetyFollowUpStatus,
    tenantId: input.tenantId,
  });
  const receipt = createDispositionReceipt(input, record, artifactHash);

  return {
    schema: 'cybermedica.participant_disposition_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    dispositionRecord: {
      ...record,
      receiptId: receipt.receiptId,
    },
    receipt,
  };
}
