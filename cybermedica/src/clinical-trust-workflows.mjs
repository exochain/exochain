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

function assertMetadataOnly(input) {
  canonicalize(input ?? {});
}

function hlcPresent(hlc) {
  return Number.isSafeInteger(hlc?.physicalMs) && Number.isSafeInteger(hlc?.logical);
}

function hlcOrder(left, right) {
  if (left.physicalMs !== right.physicalMs) {
    return left.physicalMs < right.physicalMs ? -1 : 1;
  }
  if (left.logical !== right.logical) {
    return left.logical < right.logical ? -1 : 1;
  }
  return 0;
}

function sortedTextList(value) {
  return Array.isArray(value) ? value.filter(hasText).sort() : [];
}

function evaluateTenantActorAuthority(input, actorField, requiredPermission, reasons) {
  const actor = input?.[actorField];
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(actor?.did), 'actor_did_absent');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !Array.isArray(input?.authority?.permissions) || !input.authority.permissions.includes(requiredPermission),
    'authority_permission_missing',
  );
}

function evaluateConsentGrant(input, reasons) {
  evaluateTenantActorAuthority(input, 'actor', 'write', reasons);
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, !hasText(input?.participant?.tenantScopedPseudonym), 'participant_pseudonym_absent');
  addReason(reasons, !hasText(input?.consentVersion?.id), 'consent_version_id_absent');
  addReason(reasons, input?.consentVersion?.status !== 'active', 'consent_version_not_active');
  addReason(reasons, !isDigest(input?.consentVersion?.artifactHash), 'consent_artifact_hash_invalid');
  addReason(reasons, input?.consentVersion?.legalApproval?.status !== 'approved', 'legal_approval_absent');
  addReason(reasons, !hasText(input?.consentVersion?.legalApproval?.actorDid), 'legal_approval_actor_absent');
  addReason(reasons, !hasText(input?.consentVersion?.clinicalPolicyRef), 'clinical_policy_ref_absent');
  addReason(reasons, !hasText(input?.consentVersion?.revocationPath), 'revocation_path_absent');
  addReason(reasons, input?.acknowledgement?.participantUnderstands !== true, 'participant_acknowledgement_absent');
  addReason(reasons, input?.acknowledgement?.capacityAttested !== true, 'capacity_attestation_absent');
  addReason(reasons, !hlcPresent(input?.acknowledgement?.signedAtHlc), 'consent_signed_time_invalid');
  addReason(reasons, sortedTextList(input?.consentRefs).length === 0, 'consent_refs_absent');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function participantHash(input) {
  return sha256Hex({
    tenantId: input.tenantId,
    tenantScopedPseudonym: input.participant.tenantScopedPseudonym,
  });
}

function buildConsentGrantReceipt(input, consentParticipantHash) {
  const consentRefs = sortedTextList(input.consentRefs);
  const artifactHash = sha256Hex({
    participantHash: consentParticipantHash,
    consentVersionId: input.consentVersion.id,
    consentArtifactHash: input.consentVersion.artifactHash,
    legalApprovalActorDid: input.consentVersion.legalApproval.actorDid,
    clinicalPolicyRef: input.consentVersion.clinicalPolicyRef,
    revocationPath: input.consentVersion.revocationPath,
    consentRefs,
    signedAtHlc: input.acknowledgement.signedAtHlc,
  });

  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'participant_consent_grant',
    artifactVersion: `${input.consentVersion.id}@grant`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.acknowledgement.signedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['participant_consent', 'metadata_only', 'revocation_capable'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function recordParticipantConsentGrant(input) {
  assertMetadataOnly(input);
  const reasons = [];
  evaluateConsentGrant(input, reasons);
  const denied = reasons.length > 0;

  if (denied) {
    return {
      schema: 'cybermedica.participant_consent_grant_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: [...new Set(reasons)].sort(),
      consentRecord: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const consentParticipantHash = participantHash(input);
  const consentRefs = sortedTextList(input.consentRefs);
  const receipt = buildConsentGrantReceipt(input, consentParticipantHash);
  const consentId = `cmcons_${sha256Hex({
    tenantId: input.tenantId,
    participantHash: consentParticipantHash,
    consentVersionId: input.consentVersion.id,
    consentRefs,
  }).slice(0, 32)}`;

  return {
    schema: 'cybermedica.participant_consent_grant_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    consentRecord: {
      schema: 'cybermedica.participant_consent_record.v1',
      consentId,
      tenantId: input.tenantId,
      participantHash: consentParticipantHash,
      consentVersionId: input.consentVersion.id,
      consentRefs,
      status: 'active',
      grantedAtHlc: input.acknowledgement.signedAtHlc,
      receiptId: receipt.receiptId,
      revocationAvailable: true,
      futureAccessPermitted: true,
      supportAccessTerminated: false,
      operationalStateMutable: true,
      immutableGrantReceipt: true,
    },
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function evaluateConsentRevocation(input, reasons) {
  evaluateTenantActorAuthority(input, 'actor', 'write', reasons);
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.consentRecord?.status !== 'active', 'consent_record_not_active');
  addReason(reasons, !hasText(input?.consentRecord?.consentId), 'consent_id_absent');
  addReason(reasons, !hasText(input?.consentRecord?.participantHash), 'participant_hash_absent');
  addReason(reasons, !hasText(input?.revocation?.reasonCode), 'revocation_reason_absent');
  addReason(reasons, !hlcPresent(input?.revocation?.revokedAtHlc), 'revocation_time_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function buildConsentRevocationReceipt(input) {
  const artifactHash = sha256Hex({
    consentId: input.consentRecord.consentId,
    participantHash: input.consentRecord.participantHash,
    previousReceiptId: input.consentRecord.receiptId,
    reasonCode: input.revocation.reasonCode,
    revokedAtHlc: input.revocation.revokedAtHlc,
  });

  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'participant_consent_revocation',
    artifactVersion: `${input.consentRecord.consentId}@revocation`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.revocation.revokedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['participant_consent', 'revocation', 'metadata_only'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function revokeParticipantConsent(input) {
  assertMetadataOnly(input);
  const reasons = [];
  evaluateConsentRevocation(input, reasons);
  const denied = reasons.length > 0;

  if (denied) {
    return {
      schema: 'cybermedica.participant_consent_revocation_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: [...new Set(reasons)].sort(),
      revokedConsentRecord: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const receipt = buildConsentRevocationReceipt(input);
  return {
    schema: 'cybermedica.participant_consent_revocation_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    revokedConsentRecord: {
      ...input.consentRecord,
      status: 'revoked',
      revokedAtHlc: input.revocation.revokedAtHlc,
      revocationReasonCode: input.revocation.reasonCode,
      revocationReceiptId: receipt.receiptId,
      futureAccessPermitted: false,
      supportAccessTerminated: true,
      historicalReceiptsImmutable: true,
      operationalStateMutable: true,
    },
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function evaluateSupportAccess(input, reasons) {
  evaluateTenantActorAuthority(input, 'supportActor', 'read', reasons);
  addReason(reasons, input?.supportActor?.kind !== 'human', 'human_support_actor_required');
  addReason(reasons, input?.consent === null || input?.consent === undefined, 'consent_absent');
  addReason(reasons, input?.consent?.required !== true, 'support_consent_not_required');
  addReason(reasons, input?.consent?.status !== 'active', 'consent_not_active');
  addReason(reasons, input?.consent?.revoked === true || input?.consent?.status === 'revoked', 'consent_revoked');
  addReason(reasons, input?.consent?.expired === true || input?.consent?.status === 'expired', 'consent_expired');
  addReason(reasons, input?.supportGrant?.status !== 'active', 'support_grant_not_active');
  addReason(reasons, input?.supportGrant?.scope !== 'support_access', 'support_grant_scope_invalid');
  addReason(reasons, !hasText(input?.supportGrant?.reasonCode), 'support_reason_absent');
  addReason(reasons, !hasText(input?.supportGrant?.grantId), 'support_grant_id_absent');
  addReason(reasons, !hasText(input?.supportGrant?.approvedByDid), 'support_grant_approval_absent');
  addReason(reasons, !hlcPresent(input?.requestedAtHlc), 'support_requested_time_invalid');
  addReason(reasons, !hlcPresent(input?.expiresAtHlc), 'support_expiry_time_invalid');
  addReason(
    reasons,
    hlcPresent(input?.requestedAtHlc) && hlcPresent(input?.expiresAtHlc) && hlcOrder(input.requestedAtHlc, input.expiresAtHlc) >= 0,
    'support_grant_not_time_boxed',
  );
  addReason(reasons, !isDigest(input?.ticketDigest), 'ticket_digest_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function buildSupportAccessReceipt(input, sessionId) {
  const artifactHash = sha256Hex({
    sessionId,
    supportActorDid: input.supportActor.did,
    supportGrantId: input.supportGrant.grantId,
    consentRef: input.consent.consentRef,
    requestedAtHlc: input.requestedAtHlc,
    expiresAtHlc: input.expiresAtHlc,
    ticketDigest: input.ticketDigest,
  });

  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.supportActor.did,
    artifactType: 'support_access_session',
    artifactVersion: `${input.supportGrant.grantId}@${input.requestedAtHlc.physicalMs}.${input.requestedAtHlc.logical}`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.requestedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['support_access', 'metadata_only', 'time_boxed'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function authorizeSupportAccess(input) {
  assertMetadataOnly(input);
  const reasons = [];
  evaluateSupportAccess(input, reasons);
  const denied = reasons.length > 0;

  if (denied) {
    return {
      schema: 'cybermedica.support_access_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: [...new Set(reasons)].sort(),
      accessSession: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const sessionId = `cmsas_${sha256Hex({
    tenantId: input.tenantId,
    supportActorDid: input.supportActor.did,
    supportGrantId: input.supportGrant.grantId,
    requestedAtHlc: input.requestedAtHlc,
    expiresAtHlc: input.expiresAtHlc,
    ticketDigest: input.ticketDigest,
  }).slice(0, 32)}`;
  const receipt = buildSupportAccessReceipt(input, sessionId);

  return {
    schema: 'cybermedica.support_access_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    accessSession: {
      schema: 'cybermedica.support_access_session.v1',
      sessionId,
      tenantId: input.tenantId,
      supportActorDid: input.supportActor.did,
      supportGrantId: input.supportGrant.grantId,
      status: 'active',
      startedAtHlc: input.requestedAtHlc,
      expiresAtHlc: input.expiresAtHlc,
      timeBoxed: true,
      readOnly: true,
      consentRef: input.consent.consentRef,
      receiptId: receipt.receiptId,
    },
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function evaluateAiReview(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.aiActor?.did), 'ai_actor_did_absent');
  addReason(reasons, input?.aiActor?.kind !== 'ai_agent', 'ai_actor_required');
  addReason(reasons, !hasText(input?.reviewClass), 'review_class_absent');
  addReason(reasons, !hasText(input?.modelRef), 'model_ref_absent');
  addReason(reasons, !isDigest(input?.promptDigest), 'prompt_digest_invalid');
  addReason(reasons, !isDigest(input?.inputManifestDigest), 'input_manifest_digest_invalid');
  addReason(reasons, !isDigest(input?.outputDigest), 'output_digest_invalid');
  addReason(reasons, !hlcPresent(input?.reviewedAtHlc), 'review_time_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  if (input?.humanDisposition?.final === true) {
    addReason(reasons, input.humanDisposition.actorKind === 'ai_agent', 'ai_final_authority_forbidden');
    addReason(
      reasons,
      input.humanDisposition.status !== 'approved' || !hasText(input.humanDisposition.verifiedHumanDid),
      'human_disposition_unverified',
    );
  }
}

function buildAiReviewReceipt(input, reviewId, humanFinalAuthority) {
  const artifactHash = sha256Hex({
    reviewId,
    reviewClass: input.reviewClass,
    modelRef: input.modelRef,
    promptDigest: input.promptDigest,
    inputManifestDigest: input.inputManifestDigest,
    outputDigest: input.outputDigest,
    humanDispositionStatus: input.humanDisposition?.status ?? 'pending',
    humanFinalAuthority,
  });

  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.aiActor.did,
    artifactType: 'ai_review_provenance',
    artifactVersion: `${input.reviewClass}@${input.reviewedAtHlc.physicalMs}.${input.reviewedAtHlc.logical}`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.reviewedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['ai_review', 'metadata_only', 'human_final_authority_required'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function recordAiReviewProvenance(input) {
  assertMetadataOnly(input);
  const reasons = [];
  evaluateAiReview(input, reasons);
  const denied = reasons.length > 0;

  if (denied) {
    return {
      schema: 'cybermedica.ai_review_provenance_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: [...new Set(reasons)].sort(),
      aiReview: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const humanFinalAuthority =
    input?.humanDisposition?.final === true &&
    input.humanDisposition.status === 'approved' &&
    hasText(input.humanDisposition.verifiedHumanDid);
  const reviewId = `cmair_${sha256Hex({
    tenantId: input.tenantId,
    aiActorDid: input.aiActor.did,
    reviewClass: input.reviewClass,
    modelRef: input.modelRef,
    inputManifestDigest: input.inputManifestDigest,
    outputDigest: input.outputDigest,
    reviewedAtHlc: input.reviewedAtHlc,
  }).slice(0, 32)}`;
  const receipt = buildAiReviewReceipt(input, reviewId, humanFinalAuthority);

  return {
    schema: 'cybermedica.ai_review_provenance_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    aiReview: {
      schema: 'cybermedica.ai_review_provenance.v1',
      reviewId,
      tenantId: input.tenantId,
      aiActorDid: input.aiActor.did,
      reviewClass: input.reviewClass,
      modelRef: input.modelRef,
      finalAuthority: false,
      humanFinalAuthority,
      requiresHumanDisposition: !humanFinalAuthority,
      clinicalDecisionFinal: humanFinalAuthority,
      receiptId: receipt.receiptId,
    },
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
