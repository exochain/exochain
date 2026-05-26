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
const REQUIRED_PERMISSION = 'evidence_intake';
const ALLOWED_CLASSIFICATIONS = new Set([
  'audit_metadata_only',
  'participant_related_metadata_only',
  'qms_metadata_only',
  'sponsor_confidential_metadata_only',
  'training_metadata_only',
]);
const PARTICIPANT_RELATED_CLASSIFICATIONS = new Set(['participant_related_metadata_only']);

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

function isParticipantRelated(input) {
  return PARTICIPANT_RELATED_CLASSIFICATIONS.has(input?.evidence?.classification) || isDigest(input?.evidence?.subjectCodeHash);
}

function evaluateAuthority(input, reasons) {
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !Array.isArray(input?.authority?.permissions) || !input.authority.permissions.includes(REQUIRED_PERMISSION),
    'authority_permission_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateEvidence(input, reasons) {
  addReason(reasons, !hasText(input?.evidence?.evidenceId), 'evidence_id_absent');
  addReason(reasons, !hasText(input?.evidence?.evidenceType), 'evidence_type_absent');
  addReason(reasons, !isDigest(input?.evidence?.artifactHash), 'evidence_artifact_hash_invalid');
  addReason(reasons, !hasText(input?.evidence?.artifactVersion), 'artifact_version_absent');
  addReason(reasons, !hasText(input?.evidence?.documentVersionRef), 'document_version_ref_absent');
  addReason(reasons, !isDigest(input?.evidence?.originatingSystemHash), 'originating_system_hash_invalid');
  addReason(reasons, !isDigest(input?.evidence?.storageObjectHash), 'storage_object_hash_invalid');
  addReason(
    reasons,
    !Number.isSafeInteger(input?.evidence?.byteSize) || input.evidence.byteSize < 1,
    'byte_size_invalid',
  );
  addReason(
    reasons,
    !ALLOWED_CLASSIFICATIONS.has(input?.evidence?.classification),
    'evidence_classification_invalid',
  );
  addReason(reasons, isParticipantRelated(input) && !isDigest(input?.evidence?.subjectCodeHash), 'subject_code_hash_invalid');
  addReason(reasons, !hasText(input?.evidence?.retentionPolicyRef), 'retention_policy_absent');
  addReason(
    reasons,
    isParticipantRelated(input) && !hasText(input?.evidence?.consentOrBailmentRef),
    'participant_consent_or_bailment_absent',
  );
  addReason(reasons, sortedTextList(input?.evidence?.evidenceRefIds).length === 0, 'evidence_refs_absent');
  addReason(reasons, sortedTextList(input?.evidence?.sensitivityTags).length === 0, 'sensitivity_tags_absent');
  addReason(
    reasons,
    !sortedTextList(input?.evidence?.sensitivityTags).includes('metadata_only'),
    'metadata_only_tag_absent',
  );
}

function evaluateIntake(input, reasons) {
  addReason(reasons, !hasText(input?.intake?.uploadChannel), 'upload_channel_absent');
  addReason(reasons, !hasText(input?.intake?.uploaderDid), 'uploader_did_absent');
  addReason(reasons, input?.intake?.uploaderDid !== input?.actor?.did, 'uploader_actor_mismatch');
  addReason(reasons, !hasText(input?.intake?.initialCustodianDid), 'initial_custodian_absent');
  addReason(reasons, !isDigest(input?.intake?.manifestHash), 'upload_manifest_hash_invalid');
  addReason(reasons, input?.intake?.payloadStoredOutsideReceipt !== true, 'payload_storage_boundary_invalid');
}

function evaluateReview(input, reasons) {
  addReason(reasons, !hasText(input?.review?.reviewerDid), 'classification_reviewer_absent');
  addReason(reasons, input?.review?.reviewerKind !== 'human', 'human_classification_review_absent');
  addReason(reasons, input?.review?.classificationDecision !== 'accepted', 'classification_not_accepted');
  addReason(reasons, input?.review?.phiBoundaryAttested !== true, 'phi_boundary_unattested');
  addReason(reasons, input?.review?.piiBoundaryAttested !== true, 'pii_boundary_unattested');
  addReason(
    reasons,
    input?.review?.sponsorConfidentialBoundaryAttested !== true,
    'sponsor_confidential_boundary_unattested',
  );
  addReason(reasons, input?.review?.privilegedBoundaryAttested !== true, 'privileged_boundary_unattested');
  addReason(reasons, input?.review?.metadataMinimized !== true, 'metadata_minimization_absent');
  addReason(reasons, input?.review?.payloadOpenForInspection === true, 'payload_exposure_forbidden');
  addReason(reasons, input?.review?.versionAnchorApproved !== true, 'version_anchor_not_approved');
  addReason(reasons, input?.review?.custodyStartApproved !== true, 'custody_start_not_approved');
  addReason(reasons, !isDigest(input?.review?.rationaleHash), 'classification_rationale_hash_invalid');
}

function evaluateHlc(input, reasons) {
  const uploadedAt = hlcTuple(input?.intake?.uploadedAtHlc);
  const reviewedAt = hlcTuple(input?.review?.reviewedAtHlc);
  const recordedAt = hlcTuple(input?.recordedAtHlc);

  addReason(reasons, uploadedAt === null, 'upload_time_invalid');
  addReason(reasons, reviewedAt === null, 'review_time_invalid');
  addReason(reasons, recordedAt === null, 'recorded_time_invalid');
  addReason(
    reasons,
    uploadedAt !== null && reviewedAt !== null && compareHlc(reviewedAt, uploadedAt) <= 0,
    'review_time_not_after_upload',
  );
  addReason(
    reasons,
    reviewedAt !== null && recordedAt !== null && compareHlc(recordedAt, reviewedAt) < 0,
    'recorded_time_before_review',
  );
}

function evaluateAiAssistance(input, reasons) {
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');

  if (input?.aiAssistance === null || input?.aiAssistance === undefined || input.aiAssistance.used !== true) {
    return;
  }

  addReason(reasons, input.aiAssistance.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, !isDigest(input.aiAssistance.recommendationHash), 'ai_recommendation_hash_invalid');
  addReason(reasons, !isDigest(input.aiAssistance.modelRefHash), 'ai_model_ref_hash_invalid');
  addReason(
    reasons,
    input.aiAssistance.disposition !== 'human_reviewed_advisory',
    'ai_advisory_disposition_invalid',
  );
}

function evaluateEvidenceIntakeDecision(input, reasons) {
  canonicalize(input ?? {});
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  evaluateAuthority(input, reasons);
  evaluateEvidence(input, reasons);
  evaluateIntake(input, reasons);
  evaluateReview(input, reasons);
  evaluateHlc(input, reasons);
  evaluateAiAssistance(input, reasons);
}

function buildInitialCustodyMaterial(input) {
  return {
    schema: 'cybermedica.evidence_intake_custody_material.v1',
    actorDid: input.actor.did,
    artifactHash: input.evidence.artifactHash,
    artifactVersion: input.evidence.artifactVersion,
    authorityChainHash: input.authority.authorityChainHash,
    classification: input.evidence.classification,
    consentOrBailmentRef: input.evidence.consentOrBailmentRef ?? null,
    documentVersionRef: input.evidence.documentVersionRef,
    evidenceId: input.evidence.evidenceId,
    evidenceRefIds: sortedTextList(input.evidence.evidenceRefIds),
    evidenceType: input.evidence.evidenceType,
    initialCustodianDid: input.intake.initialCustodianDid,
    manifestHash: input.intake.manifestHash,
    originatingSystemHash: input.evidence.originatingSystemHash,
    recordedAtHlc: input.recordedAtHlc,
    reviewedAtHlc: input.review.reviewedAtHlc,
    reviewerDid: input.review.reviewerDid,
    sensitivityTags: sortedTextList(input.evidence.sensitivityTags),
    storageObjectHash: input.evidence.storageObjectHash,
    subjectCodeHash: input.evidence.subjectCodeHash ?? null,
    tenantId: input.tenantId,
    uploadedAtHlc: input.intake.uploadedAtHlc,
  };
}

function buildReceipt(input, intakeId, initialCustodyDigest) {
  const artifactHash = sha256Hex({
    schema: 'cybermedica.evidence_intake_artifact.v1',
    artifactHash: input.evidence.artifactHash,
    classification: input.evidence.classification,
    documentVersionRef: input.evidence.documentVersionRef,
    evidenceId: input.evidence.evidenceId,
    evidenceRefIds: sortedTextList(input.evidence.evidenceRefIds),
    initialCustodyDigest,
    intakeId,
    retentionPolicyRef: input.evidence.retentionPolicyRef,
    sensitivityTags: sortedTextList(input.evidence.sensitivityTags),
    storageObjectHash: input.evidence.storageObjectHash,
  });

  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'evidence_intake_classification',
    artifactVersion: `${input.evidence.evidenceId}@${input.evidence.artifactVersion}`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.recordedAtHlc,
    custodyDigest: initialCustodyDigest,
    sensitivityTags: ['evidence_intake', 'classification_review', 'metadata_only'],
    sourceSystem: 'cybermedica-qms',
  });
}

function buildEvidenceIntake(input, intakeId, initialCustodyDigest, evidenceRefDigest, receipt) {
  return {
    schema: 'cybermedica.evidence_intake.v1',
    evidenceIntakeId: intakeId,
    tenantId: input.tenantId,
    evidenceId: input.evidence.evidenceId,
    evidenceType: input.evidence.evidenceType,
    artifactHash: input.evidence.artifactHash,
    artifactVersion: input.evidence.artifactVersion,
    documentVersionRef: input.evidence.documentVersionRef,
    originatingSystemHash: input.evidence.originatingSystemHash,
    storageObjectHash: input.evidence.storageObjectHash,
    byteSize: input.evidence.byteSize,
    classification: input.evidence.classification,
    subjectCodeHash: input.evidence.subjectCodeHash ?? null,
    retentionPolicyRef: input.evidence.retentionPolicyRef,
    consentOrBailmentRef: input.evidence.consentOrBailmentRef ?? null,
    evidenceRefDigest,
    sensitivityTagDigest: sha256Hex(sortedTextList(input.evidence.sensitivityTags)),
    uploadChannel: input.intake.uploadChannel,
    uploaderDid: input.intake.uploaderDid,
    initialCustodianDid: input.intake.initialCustodianDid,
    initialCustodyDigest,
    uploadedAtHlc: input.intake.uploadedAtHlc,
    reviewedAtHlc: input.review.reviewedAtHlc,
    recordedAtHlc: input.recordedAtHlc,
    classificationReviewerDid: input.review.reviewerDid,
    classificationDecision: input.review.classificationDecision,
    readyForDocumentVersioning: true,
    readyForCustodyChain: true,
    payloadStoredOutsideReceipt: true,
    aiAssistanceRecorded: input.aiAssistance?.used === true,
    aiFinalAuthority: false,
    operationalStateMutable: true,
    immutableClassificationReceipt: true,
    receiptId: receipt.receiptId,
  };
}

export function evaluateEvidenceIntake(input) {
  const reasons = [];
  evaluateEvidenceIntakeDecision(input, reasons);
  const uniqueReasons = [...new Set(reasons)].sort();

  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.evidence_intake_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      evidenceIntake: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const initialCustodyDigest = sha256Hex(buildInitialCustodyMaterial(input));
  const intakeId = `cmei_${sha256Hex({
    tenantId: input.tenantId,
    evidenceId: input.evidence.evidenceId,
    artifactHash: input.evidence.artifactHash,
    initialCustodyDigest,
  }).slice(0, 32)}`;
  const evidenceRefDigest = sha256Hex({
    tenantId: input.tenantId,
    evidenceId: input.evidence.evidenceId,
    evidenceRefIds: sortedTextList(input.evidence.evidenceRefIds),
  });
  const receipt = buildReceipt(input, intakeId, initialCustodyDigest);

  return {
    schema: 'cybermedica.evidence_intake_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    evidenceIntake: buildEvidenceIntake(input, intakeId, initialCustodyDigest, evidenceRefDigest, receipt),
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
