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
const DISTRIBUTION_PERMISSION = 'document_distribute';
const WITHDRAWAL_PERMISSION = 'document_withdraw';
const REQUIRED_DISTRIBUTION_ACTIONS = new Set(['acknowledge_effective_use', 'read_current_version']);
const WITHDRAWAL_REASON_CODES = new Set([
  'obsolete_retired',
  'quality_update_replacement',
  'regulatory_replacement',
  'superseded_by_new_effective_version',
]);
const PROTECTED_DOCUMENT_FIELDS = new Set([
  'controlleddocumenttext',
  'documentbody',
  'rawacknowledgementsignature',
  'rawdocument',
  'rawdocumentbody',
  'verbatimdocumentcontent',
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
  return Array.isArray(value) ? uniqueSorted(value.filter(hasText)) : [];
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function assertNoDocumentProtectedContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoDocumentProtectedContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    if (PROTECTED_DOCUMENT_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`controlled document protected content field is not allowed at ${path}.${key}`);
    }
    assertNoDocumentProtectedContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoDocumentProtectedContent(input ?? {});
  canonicalize(input ?? {});
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [hlc.physicalMs, hlc.logical];
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

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons, permission) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !hasAuthorityPermission(input?.authority, permission), 'authority_permission_missing');
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateDocumentVersionShape(documentVersion, reasons) {
  addReason(reasons, !hasText(documentVersion?.documentId), 'document_id_absent');
  addReason(reasons, !hasText(documentVersion?.documentVersionId), 'document_version_id_absent');
  addReason(reasons, !hasText(documentVersion?.documentType), 'document_type_absent');
  addReason(reasons, !hasText(documentVersion?.versionId), 'version_id_absent');
  addReason(reasons, documentVersion?.lifecycleState !== 'approved', 'document_version_not_approved');
  addReason(reasons, !isDigest(documentVersion?.artifactHash), 'document_artifact_hash_invalid');
  addReason(reasons, !hasText(documentVersion?.documentVersionReceiptId), 'document_version_receipt_absent');
  addReason(reasons, hlcTuple(documentVersion?.effectiveAtHlc) === null, 'effective_time_invalid');
}

function evaluateDistributionDocument(input, reasons, controlRefs) {
  const documentVersion = input?.documentVersion;
  const effectiveAt = hlcTuple(documentVersion?.effectiveAtHlc);
  const reviewDueAt = hlcTuple(documentVersion?.reviewDueAtHlc);

  evaluateDocumentVersionShape(documentVersion, reasons);
  addReason(reasons, reviewDueAt === null, 'review_due_time_invalid');
  addReason(
    reasons,
    effectiveAt !== null && reviewDueAt !== null && compareHlc(reviewDueAt, effectiveAt) <= 0,
    'review_due_not_after_effective_time',
  );
  addReason(reasons, !hasText(documentVersion?.retentionPolicyRef), 'retention_policy_absent');
  addReason(reasons, !hasText(documentVersion?.accessControlProfileRef), 'access_control_profile_absent');
  addReason(reasons, controlRefs.length === 0, 'document_control_refs_absent');
}

function evaluateDistribution(input, reasons, audienceRoleRefs, requiredAcknowledgementRoleRefs) {
  const distribution = input?.distribution;
  const effectiveAt = hlcTuple(input?.documentVersion?.effectiveAtHlc);
  const publishedAt = hlcTuple(distribution?.publishedAtHlc);

  addReason(reasons, !hasText(distribution?.distributionRef), 'distribution_ref_absent');
  addReason(reasons, !hasText(distribution?.publishedByDid), 'publisher_did_absent');
  addReason(reasons, hasText(distribution?.publishedByDid) && distribution.publishedByDid !== input?.actor?.did, 'publisher_actor_mismatch');
  addReason(reasons, publishedAt === null, 'distribution_time_invalid');
  addReason(
    reasons,
    effectiveAt !== null && publishedAt !== null && compareHlc(publishedAt, effectiveAt) < 0,
    'distribution_time_before_effective_time',
  );
  addReason(reasons, !isDigest(distribution?.distributionEvidenceHash), 'distribution_evidence_hash_invalid');
  addReason(reasons, !isDigest(distribution?.releaseNotesHash), 'release_notes_hash_invalid');
  addReason(reasons, !isDigest(distribution?.trainingImpactAssessmentHash), 'training_impact_assessment_hash_invalid');
  addReason(reasons, !isDigest(distribution?.accessGrantPolicyHash), 'access_grant_policy_hash_invalid');
  addReason(reasons, !isDigest(distribution?.notificationEvidenceHash), 'notification_evidence_hash_invalid');
  addReason(reasons, !isDigest(distribution?.staffCommunicationEvidenceHash), 'staff_communication_evidence_hash_invalid');
  addReason(reasons, audienceRoleRefs.length === 0, 'distribution_audience_absent');
  addReason(reasons, requiredAcknowledgementRoleRefs.length === 0, 'required_acknowledgement_roles_absent');
  addReason(reasons, distribution?.payloadStoredOutsideReceipt !== true, 'payload_storage_boundary_invalid');
}

function evaluateAccessControl(accessControl, reasons, permittedActionRefs) {
  addReason(reasons, accessControl?.leastPrivilege !== true, 'least_privilege_not_attested');
  addReason(reasons, accessControl?.revocable !== true, 'revocable_access_not_attested');
  addReason(reasons, accessControl?.audited !== true, 'access_audit_not_attested');
  addReason(reasons, accessControl?.timeBound !== true, 'time_bound_access_not_attested');
  addReason(reasons, accessControl?.deniedObsoleteVersionUse !== true, 'obsolete_version_use_not_blocked');
  for (const requiredAction of REQUIRED_DISTRIBUTION_ACTIONS) {
    addReason(reasons, !permittedActionRefs.includes(requiredAction), 'permitted_action_missing');
  }
}

function normalizeAcknowledgements(input, reasons) {
  const acknowledgements = Array.isArray(input?.acknowledgements) ? input.acknowledgements : [];
  const publishedAt = hlcTuple(input?.distribution?.publishedAtHlc);
  const versionId = input?.documentVersion?.versionId;

  addReason(reasons, acknowledgements.length === 0, 'acknowledgements_absent');

  return acknowledgements
    .map((acknowledgement) => {
      const acknowledgedAt = hlcTuple(acknowledgement?.acknowledgedAtHlc);

      addReason(reasons, !hasText(acknowledgement?.staffDid), 'acknowledgement_staff_absent');
      addReason(reasons, !hasText(acknowledgement?.roleRef), 'acknowledgement_role_absent');
      addReason(reasons, acknowledgement?.acknowledgedVersionId !== versionId, 'acknowledgement_version_mismatch');
      addReason(reasons, acknowledgedAt === null, 'acknowledgement_time_invalid');
      addReason(
        reasons,
        acknowledgedAt !== null && publishedAt !== null && compareHlc(acknowledgedAt, publishedAt) < 0,
        'acknowledgement_time_before_distribution',
      );
      addReason(reasons, !isDigest(acknowledgement?.acknowledgementEvidenceHash), 'acknowledgement_evidence_hash_invalid');
      addReason(reasons, acknowledgement?.trainingImpactReviewed !== true, 'training_impact_not_reviewed');
      addReason(reasons, acknowledgement?.effectiveUseAttested !== true, 'effective_use_not_attested');

      return {
        acknowledgedAtHlc: acknowledgement?.acknowledgedAtHlc ?? null,
        acknowledgementEvidenceHash: acknowledgement?.acknowledgementEvidenceHash ?? null,
        acknowledgedVersionId: acknowledgement?.acknowledgedVersionId ?? null,
        effectiveUseAttested: acknowledgement?.effectiveUseAttested === true,
        roleRef: acknowledgement?.roleRef ?? null,
        staffDid: acknowledgement?.staffDid ?? null,
        trainingImpactReviewed: acknowledgement?.trainingImpactReviewed === true,
      };
    })
    .sort((left, right) => `${left.roleRef ?? ''}:${left.staffDid ?? ''}`.localeCompare(`${right.roleRef ?? ''}:${right.staffDid ?? ''}`));
}

function evaluateAcknowledgementCoverage(requiredAcknowledgementRoleRefs, normalizedAcknowledgements, reasons) {
  const acknowledgedRoles = new Set(
    normalizedAcknowledgements
      .filter((acknowledgement) => acknowledgement.effectiveUseAttested && acknowledgement.trainingImpactReviewed)
      .map((acknowledgement) => acknowledgement.roleRef)
      .filter(hasText),
  );

  for (const requiredRole of requiredAcknowledgementRoleRefs) {
    addReason(reasons, !acknowledgedRoles.has(requiredRole), 'required_acknowledgement_role_missing');
  }
}

function distributionRecordId(input) {
  return `cmdist_${sha256Hex({
    distributionRef: input?.distribution?.distributionRef ?? null,
    documentVersionId: input?.documentVersion?.documentVersionId ?? null,
    publishedAtHlc: input?.distribution?.publishedAtHlc ?? null,
    tenantId: input?.tenantId ?? null,
  }).slice(0, 32)}`;
}

function buildDistributionReceipt(input, recordId, artifactHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'controlled_document_distribution',
    artifactVersion: `${input.documentVersion.documentId}@${input.documentVersion.versionId}:${input.distribution.distributionRef}`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.distribution.publishedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['controlled_document', 'effective_use', 'metadata_only'],
    sourceSystem: 'cybermedica-qms',
  });
}

function buildDistributionRecord(
  input,
  recordId,
  controlRefs,
  audienceRoleRefs,
  requiredAcknowledgementRoleRefs,
  permittedActionRefs,
  normalizedAcknowledgements,
  receiptId,
) {
  const acknowledgedRoleRefs = uniqueSorted(
    normalizedAcknowledgements
      .filter((acknowledgement) => acknowledgement.effectiveUseAttested && acknowledgement.trainingImpactReviewed)
      .map((acknowledgement) => acknowledgement.roleRef)
      .filter(hasText),
  );

  return {
    schema: 'cybermedica.controlled_document_distribution.v1',
    distributionRecordId: recordId,
    tenantId: input.tenantId,
    documentId: input.documentVersion.documentId,
    documentVersionId: input.documentVersion.documentVersionId,
    documentType: input.documentVersion.documentType,
    versionId: input.documentVersion.versionId,
    status: 'distributed_for_effective_use',
    lifecycleState: input.documentVersion.lifecycleState,
    effectiveAtHlc: input.documentVersion.effectiveAtHlc,
    reviewDueAtHlc: input.documentVersion.reviewDueAtHlc,
    publishedAtHlc: input.distribution.publishedAtHlc,
    retentionPolicyRef: input.documentVersion.retentionPolicyRef,
    accessControlProfileRef: input.documentVersion.accessControlProfileRef,
    controlRefs,
    audienceRoleRefs,
    requiredAcknowledgementRoleRefs,
    acknowledgedRoleRefs,
    acknowledgementRosterHash: sha256Hex(normalizedAcknowledgements),
    permittedActionRefs,
    effectiveForUse: true,
    accessControlled: true,
    obsoleteVersionUseBlocked: true,
    staffCommunicationEvidenceHash: input.distribution.staffCommunicationEvidenceHash,
    receiptId,
    operationalStateMutable: true,
    immutableDistributionReceipt: true,
  };
}

export function recordControlledDocumentDistribution(input) {
  assertMetadataOnly(input);

  const reasons = [];
  const controlRefs = sortedTextList(input?.documentVersion?.controlRefs);
  const audienceRoleRefs = sortedTextList(input?.distribution?.audienceRoleRefs);
  const requiredAcknowledgementRoleRefs = sortedTextList(input?.distribution?.requiredAcknowledgementRoleRefs);
  const permittedActionRefs = sortedTextList(input?.accessControl?.permittedActionRefs);

  evaluateTenantActorAuthority(input, reasons, DISTRIBUTION_PERMISSION);
  evaluateDistributionDocument(input, reasons, controlRefs);
  evaluateDistribution(input, reasons, audienceRoleRefs, requiredAcknowledgementRoleRefs);
  evaluateAccessControl(input?.accessControl, reasons, permittedActionRefs);
  const normalizedAcknowledgements = normalizeAcknowledgements(input, reasons);
  evaluateAcknowledgementCoverage(requiredAcknowledgementRoleRefs, normalizedAcknowledgements, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const uniqueReasons = uniqueSorted(reasons);
  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.controlled_document_distribution_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      distributionRecord: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const recordId = distributionRecordId(input);
  const artifactHash = sha256Hex({
    accessControlProfileRef: input.documentVersion.accessControlProfileRef,
    acknowledgements: normalizedAcknowledgements,
    audienceRoleRefs,
    controlRefs,
    distributionEvidenceHash: input.distribution.distributionEvidenceHash,
    distributionRef: input.distribution.distributionRef,
    documentVersionId: input.documentVersion.documentVersionId,
    notificationEvidenceHash: input.distribution.notificationEvidenceHash,
    permittedActionRefs,
    recordId,
    requiredAcknowledgementRoleRefs,
    staffCommunicationEvidenceHash: input.distribution.staffCommunicationEvidenceHash,
    tenantId: input.tenantId,
    trainingImpactAssessmentHash: input.distribution.trainingImpactAssessmentHash,
    versionId: input.documentVersion.versionId,
  });
  const receipt = buildDistributionReceipt(input, recordId, artifactHash);

  return {
    schema: 'cybermedica.controlled_document_distribution_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    distributionRecord: buildDistributionRecord(
      input,
      recordId,
      controlRefs,
      audienceRoleRefs,
      requiredAcknowledgementRoleRefs,
      permittedActionRefs,
      normalizedAcknowledgements,
      receipt.receiptId,
    ),
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function evaluateObsoleteVersion(obsoleteVersion, reasons) {
  evaluateDocumentVersionShape(obsoleteVersion, reasons);
  addReason(reasons, !hasText(obsoleteVersion?.supersededByDocumentVersionId), 'superseding_document_version_absent');
  addReason(reasons, !hasText(obsoleteVersion?.supersededByReceiptId), 'superseding_receipt_absent');
  addReason(reasons, !hasText(obsoleteVersion?.retainedUnderPolicyRef), 'retention_policy_absent');
}

function evaluateWithdrawal(input, reasons, affectedAudienceRoleRefs, removedAccessProfileRefs) {
  const withdrawal = input?.withdrawal;
  const withdrawnAt = hlcTuple(withdrawal?.withdrawnAtHlc);
  const effectiveAt = hlcTuple(input?.obsoleteVersion?.effectiveAtHlc);

  addReason(reasons, !hasText(withdrawal?.withdrawalRef), 'withdrawal_ref_absent');
  addReason(reasons, !WITHDRAWAL_REASON_CODES.has(withdrawal?.reasonCode), 'withdrawal_reason_invalid');
  addReason(reasons, !hasText(withdrawal?.withdrawnByDid), 'withdrawn_by_absent');
  addReason(reasons, hasText(withdrawal?.withdrawnByDid) && withdrawal.withdrawnByDid !== input?.actor?.did, 'withdrawn_by_actor_mismatch');
  addReason(reasons, withdrawnAt === null, 'withdrawal_time_invalid');
  addReason(
    reasons,
    effectiveAt !== null && withdrawnAt !== null && compareHlc(withdrawnAt, effectiveAt) < 0,
    'withdrawal_time_before_obsolete_effective_time',
  );
  addReason(reasons, !isDigest(withdrawal?.withdrawalEvidenceHash), 'withdrawal_evidence_hash_invalid');
  addReason(reasons, !isDigest(withdrawal?.communicationEvidenceHash), 'communication_evidence_hash_invalid');
  addReason(reasons, !isDigest(withdrawal?.activeCopyInventoryHash), 'active_copy_inventory_hash_invalid');
  addReason(reasons, !isDigest(withdrawal?.accessRevocationEvidenceHash), 'access_revocation_evidence_hash_invalid');
  addReason(reasons, affectedAudienceRoleRefs.length === 0, 'affected_audience_absent');
  addReason(reasons, removedAccessProfileRefs.length === 0, 'removed_access_profile_absent');
  addReason(reasons, withdrawal?.noActiveUseAttested !== true, 'active_use_attestation_absent');
  addReason(reasons, withdrawal?.retainedForInspection !== true, 'retention_preservation_absent');
  addReason(
    reasons,
    !Number.isSafeInteger(withdrawal?.exceptionCount) || withdrawal.exceptionCount < 0,
    'withdrawal_exception_count_invalid',
  );
  addReason(
    reasons,
    Number.isSafeInteger(withdrawal?.exceptionCount) &&
      withdrawal.exceptionCount > 0 &&
      !isDigest(withdrawal?.exceptionRationaleHash),
    'withdrawal_exception_rationale_absent',
  );
}

function withdrawalRecordId(input) {
  return `cmdw_${sha256Hex({
    documentVersionId: input?.obsoleteVersion?.documentVersionId ?? null,
    tenantId: input?.tenantId ?? null,
    withdrawalRef: input?.withdrawal?.withdrawalRef ?? null,
    withdrawnAtHlc: input?.withdrawal?.withdrawnAtHlc ?? null,
  }).slice(0, 32)}`;
}

function buildWithdrawalReceipt(input, artifactHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'controlled_document_withdrawal',
    artifactVersion: `${input.obsoleteVersion.documentId}@${input.obsoleteVersion.versionId}:${input.withdrawal.withdrawalRef}`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.withdrawal.withdrawnAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['controlled_document', 'metadata_only', 'obsolete_withdrawal'],
    sourceSystem: 'cybermedica-qms',
  });
}

function buildWithdrawalRecord(input, recordId, affectedAudienceRoleRefs, removedAccessProfileRefs, receiptId) {
  return {
    schema: 'cybermedica.controlled_document_withdrawal.v1',
    withdrawalRecordId: recordId,
    tenantId: input.tenantId,
    documentId: input.obsoleteVersion.documentId,
    documentVersionId: input.obsoleteVersion.documentVersionId,
    documentType: input.obsoleteVersion.documentType,
    versionId: input.obsoleteVersion.versionId,
    status: 'obsolete_withdrawn',
    reasonCode: input.withdrawal.reasonCode,
    supersededByDocumentVersionId: input.obsoleteVersion.supersededByDocumentVersionId,
    supersededByReceiptId: input.obsoleteVersion.supersededByReceiptId,
    withdrawnAtHlc: input.withdrawal.withdrawnAtHlc,
    affectedAudienceRoleRefs,
    removedAccessProfileRefs,
    exceptionCount: input.withdrawal.exceptionCount,
    exceptionRationaleHash: input.withdrawal.exceptionRationaleHash,
    effectiveForUse: false,
    accessWithdrawn: true,
    noActiveUseAttested: true,
    retentionPreserved: true,
    retainedUnderPolicyRef: input.obsoleteVersion.retainedUnderPolicyRef,
    retainedForInspection: true,
    communicationEvidenceHash: input.withdrawal.communicationEvidenceHash,
    receiptId,
    operationalStateMutable: true,
    immutableWithdrawalReceipt: true,
  };
}

export function withdrawObsoleteDocumentVersion(input) {
  assertMetadataOnly(input);

  const reasons = [];
  const affectedAudienceRoleRefs = sortedTextList(input?.withdrawal?.affectedAudienceRoleRefs);
  const removedAccessProfileRefs = sortedTextList(input?.withdrawal?.removedAccessProfileRefs);

  evaluateTenantActorAuthority(input, reasons, WITHDRAWAL_PERMISSION);
  evaluateObsoleteVersion(input?.obsoleteVersion, reasons);
  evaluateWithdrawal(input, reasons, affectedAudienceRoleRefs, removedAccessProfileRefs);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const uniqueReasons = uniqueSorted(reasons);
  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.controlled_document_withdrawal_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      withdrawalRecord: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const recordId = withdrawalRecordId(input);
  const artifactHash = sha256Hex({
    accessRevocationEvidenceHash: input.withdrawal.accessRevocationEvidenceHash,
    activeCopyInventoryHash: input.withdrawal.activeCopyInventoryHash,
    affectedAudienceRoleRefs,
    communicationEvidenceHash: input.withdrawal.communicationEvidenceHash,
    documentVersionId: input.obsoleteVersion.documentVersionId,
    exceptionCount: input.withdrawal.exceptionCount,
    exceptionRationaleHash: input.withdrawal.exceptionRationaleHash,
    recordId,
    removedAccessProfileRefs,
    supersededByDocumentVersionId: input.obsoleteVersion.supersededByDocumentVersionId,
    supersededByReceiptId: input.obsoleteVersion.supersededByReceiptId,
    tenantId: input.tenantId,
    withdrawalEvidenceHash: input.withdrawal.withdrawalEvidenceHash,
    withdrawalRef: input.withdrawal.withdrawalRef,
  });
  const receipt = buildWithdrawalReceipt(input, artifactHash);

  return {
    schema: 'cybermedica.controlled_document_withdrawal_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    withdrawalRecord: buildWithdrawalRecord(input, recordId, affectedAudienceRoleRefs, removedAccessProfileRefs, receipt.receiptId),
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
