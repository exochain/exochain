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
const EVIDENCE_LINKING_SCHEMA = 'cybermedica.evidence_linking.v1';
const REQUIRED_PERMISSION = 'evidence_linking';
const ACTIVE_POLICY_STATUSES = new Set(['active']);
const ACTOR_KINDS = new Set(['human']);
const APPROVED_STATUSES = new Set(['approved']);
const ALLOWED_CLASSIFICATIONS = new Set([
  'audit_metadata_only',
  'participant_related_metadata_only',
  'qms_metadata_only',
  'sponsor_confidential_metadata_only',
  'training_metadata_only',
]);
const REQUIRED_LINK_FAMILIES = Object.freeze([
  'control',
  'decision_matter',
  'document_version',
  'equipment',
  'facility',
  'participant_status',
  'protocol',
  'site',
  'staff_member',
  'study',
  'vendor',
]);

const RAW_LINKING_FIELDS = new Set([
  'body',
  'content',
  'evidencebody',
  'evidencecontent',
  'linkedcontent',
  'rawevidence',
  'rawevidencepayload',
  'rawlinkcontent',
  'rawpayload',
  'rawsource',
  'rawsourcedocument',
  'sourcedocument',
  'sourcedocumentbody',
  'targetbody',
]);

const SECRET_LINKING_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credential',
  'credentialsecret',
  'password',
  'privatekey',
  'refreshtoken',
  'secret',
  'sessionsecret',
  'signaturesecret',
  'signerprivatekey',
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

function assertNoRawLinkingContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawLinkingContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_LINKING_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw evidence linking content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_LINKING_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`evidence linking secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawLinkingContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawLinkingContent(input ?? {});
  canonicalize(input ?? {});
}

function sortedTextList(values) {
  return Array.isArray(values) ? [...new Set(values.filter(hasText))].sort() : [];
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

function hlcBefore(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) < 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, !ACTOR_KINDS.has(input?.actor?.kind), 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'write'),
    'evidence_linking_permission_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateEvidenceRecord(record, reasons) {
  addReason(reasons, !hasText(record?.evidenceId), 'evidence_id_absent');
  addReason(reasons, !hasText(record?.evidenceType), 'evidence_type_absent');
  addReason(reasons, !isDigest(record?.artifactHash), 'evidence_artifact_hash_invalid');
  addReason(reasons, !ALLOWED_CLASSIFICATIONS.has(record?.classification), 'evidence_classification_invalid');
  addReason(reasons, !hasText(record?.documentVersionRef), 'document_version_ref_absent');
  addReason(reasons, !hasText(record?.intakeReceiptId), 'intake_receipt_id_absent');
  addReason(reasons, !isDigest(record?.custodyDigest), 'evidence_custody_digest_invalid');
  addReason(reasons, !APPROVED_STATUSES.has(record?.reviewStatus), 'evidence_review_not_approved');
  addReason(reasons, !APPROVED_STATUSES.has(record?.approvalStatus), 'evidence_approval_not_approved');
  addReason(reasons, record?.retainedOutsideReceipt !== true, 'evidence_payload_storage_boundary_invalid');
  addReason(reasons, record?.metadataOnly !== true, 'evidence_metadata_boundary_absent');
  addReason(reasons, record?.protectedContentExcluded !== true, 'evidence_protected_boundary_absent');
  addReason(reasons, hlcTuple(record?.recordedAtHlc) === null, 'evidence_recorded_time_invalid');
}

function evaluateLinkPolicy(policy, evidenceRecord, reasons) {
  const requiredFamilies = sortedTextList(policy?.requiredLinkFamilies);
  addReason(reasons, !hasText(policy?.policyRef), 'link_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'link_policy_hash_invalid');
  addReason(reasons, !ACTIVE_POLICY_STATUSES.has(policy?.status), 'link_policy_inactive');
  addReason(reasons, policy?.participantCodeOnly !== true, 'link_policy_participant_code_boundary_absent');
  addReason(reasons, policy?.leastPrivilege !== true, 'link_policy_least_privilege_absent');
  addReason(reasons, policy?.disclosureLogRequired !== true, 'link_policy_disclosure_log_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'link_policy_metadata_boundary_absent');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'link_policy_protected_boundary_absent');
  addReason(reasons, hlcTuple(policy?.reviewedAtHlc) === null, 'link_policy_review_time_invalid');
  addReason(reasons, hlcBefore(policy?.reviewedAtHlc, evidenceRecord?.recordedAtHlc), 'link_policy_review_before_evidence_record');

  for (const family of requiredFamilies) {
    addReason(reasons, !REQUIRED_LINK_FAMILIES.includes(family), `link_policy_family_unsupported:${family}`);
  }
  for (const family of REQUIRED_LINK_FAMILIES) {
    addReason(reasons, !requiredFamilies.includes(family), `required_link_family_missing:${family}`);
  }

  return requiredFamilies;
}

function normalizeLinkTargets(input, requiredFamilies, reasons) {
  const rows = Array.isArray(input?.linkTargets) ? [...input.linkTargets] : [];
  addReason(reasons, !Array.isArray(input?.linkTargets) || input.linkTargets.length === 0, 'link_targets_absent');

  const byFamily = new Map();
  for (const row of rows) {
    if (hasText(row?.family) && byFamily.has(row.family)) {
      reasons.push(`link_family_duplicate:${row.family}`);
    }
    if (hasText(row?.family)) {
      byFamily.set(row.family, row);
    }
  }

  for (const family of requiredFamilies) {
    addReason(reasons, !byFamily.has(family), `link_target_missing:${family}`);
  }

  return rows
    .sort((left, right) => String(left?.family ?? '').localeCompare(String(right?.family ?? '')))
    .map((row) => {
      const family = hasText(row?.family) ? row.family : 'unknown_link_family';
      addReason(reasons, !hasText(row?.family), 'link_family_absent');
      addReason(reasons, !REQUIRED_LINK_FAMILIES.includes(family), `link_family_unsupported:${family}`);
      addReason(reasons, !hasText(row?.targetRef), `link_target_ref_absent:${family}`);
      addReason(reasons, !isDigest(row?.targetHash), `link_target_hash_invalid:${family}`);
      addReason(reasons, row?.tenantId !== input?.tenantId, `link_target_tenant_mismatch:${family}`);
      addReason(reasons, !hasText(row?.accessPolicyRef), `link_target_access_policy_absent:${family}`);
      addReason(reasons, !isDigest(row?.relationshipHash), `link_relationship_hash_invalid:${family}`);
      addReason(reasons, row?.metadataOnly !== true, `link_target_metadata_boundary_absent:${family}`);
      addReason(reasons, row?.protectedContentExcluded !== true, `link_target_protected_boundary_absent:${family}`);
      addReason(
        reasons,
        family === 'participant_status' && row?.disclosureAllowed === true,
        'participant_status_disclosure_not_allowed',
      );
      return {
        accessPolicyRef: row?.accessPolicyRef ?? null,
        disclosureAllowed: row?.disclosureAllowed === true,
        family,
        relationshipHash: row?.relationshipHash ?? null,
        requiredForReadiness: row?.requiredForReadiness === true,
        targetHash: row?.targetHash ?? null,
        targetRef: row?.targetRef ?? null,
      };
    });
}

function evaluateHumanReview(review, policy, reasons) {
  addReason(reasons, review === null || review === undefined, 'human_review_absent');
  addReason(reasons, !APPROVED_STATUSES.has(review?.status), 'human_link_review_not_approved');
  addReason(reasons, !hasText(review?.reviewerDid), 'human_link_reviewer_absent');
  addReason(reasons, !isDigest(review?.reviewHash), 'human_link_review_hash_invalid');
  addReason(reasons, hlcTuple(review?.approvedAtHlc) === null, 'human_link_review_time_invalid');
  addReason(reasons, hlcBefore(review?.approvedAtHlc, policy?.reviewedAtHlc), 'human_link_review_before_policy_review');
  addReason(reasons, review?.metadataOnly !== true, 'human_link_review_metadata_boundary_absent');
  addReason(reasons, review?.protectedContentExcluded !== true, 'human_link_review_protected_boundary_absent');
}

function evaluateReceiptEvidence(receiptEvidence, reasons) {
  addReason(reasons, !isDigest(receiptEvidence?.artifactHash), 'receipt_artifact_hash_invalid');
  addReason(reasons, !isDigest(receiptEvidence?.custodyDigest), 'receipt_custody_digest_invalid');
}

function createEvidenceLinking(input, linkTargets) {
  const linkFamilies = sortedTextList(linkTargets.map((target) => target.family).filter((family) => REQUIRED_LINK_FAMILIES.includes(family)));
  const targetRefs = sortedTextList(linkTargets.map((target) => target.targetRef));
  const evidenceLinkingId = `cmel_${sha256Hex({
    evidenceId: input.evidenceRecord.evidenceId,
    linkFamilies,
    targetRefs,
    tenantId: input.tenantId,
  }).slice(0, 32)}`;
  const linkDigest = sha256Hex({
    evidenceId: input.evidenceRecord.evidenceId,
    linkTargets: linkTargets.map((target) => ({
      family: target.family,
      relationshipHash: target.relationshipHash,
      targetHash: target.targetHash,
      targetRef: target.targetRef,
    })),
    schema: EVIDENCE_LINKING_SCHEMA,
    tenantId: input.tenantId,
  });

  return {
    schema: EVIDENCE_LINKING_SCHEMA,
    evidenceLinkingId,
    actorDid: input.actor.did,
    custodyDigest: input.evidenceRecord.custodyDigest,
    documentVersionRef: input.evidenceRecord.documentVersionRef,
    evidenceId: input.evidenceRecord.evidenceId,
    evidenceType: input.evidenceRecord.evidenceType,
    linkDigest,
    linkFamilies,
    metadataOnly: true,
    productionTrustClaim: false,
    readyForCompletenessScoring:
      linkFamilies.includes('control') &&
      linkFamilies.includes('site') &&
      linkFamilies.includes('protocol') &&
      linkFamilies.includes('study'),
    readyForCustodyReview: isDigest(input.evidenceRecord.custodyDigest) && linkFamilies.includes('document_version'),
    targetRefs,
    trustState: 'inactive',
  };
}

function createLinkingReceipt(input, evidenceLinking) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: input.receiptEvidence.artifactHash,
    artifactType: 'evidence_link_registry',
    artifactVersion: 'v1',
    classification: 'metadata_only_evidence_link_registry',
    custodyDigest: input.receiptEvidence.custodyDigest,
    hlcTimestamp: input.humanReview.approvedAtHlc,
    sensitivityTags: [
      'evidence_linking',
      'metadata_only',
      'no_raw_evidence_payload',
      'participant_code_only',
    ],
    sourceSystem: 'CyberMedica',
    tenantId: input.tenantId,
  });
}

export function evaluateEvidenceLinking(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateEvidenceRecord(input?.evidenceRecord, reasons);
  const requiredFamilies = evaluateLinkPolicy(input?.linkPolicy, input?.evidenceRecord, reasons);
  const linkTargets = normalizeLinkTargets(input, requiredFamilies, reasons);
  evaluateHumanReview(input?.humanReview, input?.linkPolicy, reasons);
  evaluateReceiptEvidence(input?.receiptEvidence, reasons);

  const sortedReasons = uniqueReasons(reasons);
  if (sortedReasons.length > 0) {
    return {
      status: 'denied',
      failClosed: true,
      reasons: sortedReasons,
      evidenceLinking: null,
      receipt: null,
      sourceEvidence: [
        'cyber_medica_qms_prd_master.md:FR-005',
        'cyber_medica_qms_prd_master.md:Evidence and Chain-of-Custody Layer',
      ],
    };
  }

  const evidenceLinking = createEvidenceLinking(input, linkTargets);
  const receipt = createLinkingReceipt(input, evidenceLinking);
  return {
    status: 'linked',
    failClosed: false,
    reasons: [],
    evidenceLinking,
    receipt,
    sourceEvidence: [
      'cyber_medica_qms_prd_master.md:FR-005',
      'cyber_medica_qms_prd_master.md:Evidence and Chain-of-Custody Layer',
    ],
  };
}

export const evidenceLinkingRequirements = Object.freeze({
  schema: EVIDENCE_LINKING_SCHEMA,
  requiredLinkFamilies: REQUIRED_LINK_FAMILIES,
  requiredPermission: REQUIRED_PERMISSION,
});
