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
const LEGAL_DEFENSIBILITY_SCHEMA = 'cybermedica.legal_defensibility_pack.v1';
const REQUIRED_PERMISSION = 'legal_defensibility_pack';
const ACTOR_KINDS = new Set(['human', 'service_account']);
const PACK_PURPOSES = new Set(['audit', 'diligence', 'dispute_resolution', 'inspection']);
const PROFILE_STATUSES = new Set(['approved']);
const ACCESS_POLICY_STATUSES = new Set(['active']);
const LEGAL_REVIEW_STATUSES = new Set(['approved']);
const LEGAL_HOLD_STATUSES = new Set(['active']);
const REQUIRED_PRESERVATION_DOMAINS = new Set([
  'access_logs',
  'custody',
  'decision_rationale',
  'provenance',
  'timestamps',
  'version_history',
]);

const RAW_LEGAL_DEFENSIBILITY_FIELDS = new Set([
  'accesslogbody',
  'auditnarrative',
  'content',
  'decisionrationaletext',
  'directidentifierlist',
  'disputenarrative',
  'evidencebody',
  'freetext',
  'freetextnote',
  'inspectionnotes',
  'inspectionpacket',
  'legalnarrative',
  'participantlisting',
  'rawauditpacket',
  'rawdecisionrationale',
  'rawevidence',
  'rawinspectionpacket',
  'rawlegalpacket',
  'rawpack',
  'rawsource',
  'rawsourcedata',
  'reviewnarrative',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'sourcepayload',
]);

const SECRET_LEGAL_DEFENSIBILITY_FIELDS = new Set([
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
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
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

function assertNoRawLegalDefensibilityContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawLegalDefensibilityContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_LEGAL_DEFENSIBILITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw legal defensibility content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_LEGAL_DEFENSIBILITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`legal defensibility secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawLegalDefensibilityContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawLegalDefensibilityContent(input ?? {});
  canonicalize(input ?? {});
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [hlc.physicalMs, hlc.logical];
}

function compareHlcTuple(left, right) {
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
  return leftTuple !== null && rightTuple !== null && compareHlcTuple(leftTuple, rightTuple) < 0;
}

function hlcBeforeOrEqual(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlcTuple(leftTuple, rightTuple) <= 0;
}

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlcTuple(leftTuple, rightTuple) > 0;
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, !ACTOR_KINDS.has(input?.actor?.kind), 'legal_pack_actor_kind_invalid');
  addReason(
    reasons,
    input?.actor?.kind === 'service_account' && !hasText(input?.actor?.humanOwnerDid),
    'service_account_human_owner_absent',
  );
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'legal_pack_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePackRequest(request, purposes, reasons) {
  addReason(reasons, !hasText(request?.requestRef), 'legal_pack_request_ref_absent');
  addReason(reasons, !hasText(request?.subjectRef), 'legal_pack_subject_ref_absent');
  addReason(reasons, purposes.length === 0, 'legal_pack_purposes_absent');
  addReason(reasons, request?.metadataOnly !== true, 'legal_pack_metadata_boundary_invalid');
  addReason(reasons, request?.protectedContentExcluded !== true, 'legal_pack_protected_boundary_invalid');
  addReason(reasons, request?.exochainProductionClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(request?.requestedAtHlc) === null, 'legal_pack_requested_time_invalid');
  addReason(reasons, hlcTuple(request?.assembledAtHlc) === null, 'legal_pack_assembled_time_invalid');
  addReason(reasons, hlcBefore(request?.assembledAtHlc, request?.requestedAtHlc), 'legal_pack_assembled_before_request');

  for (const purpose of purposes) {
    addReason(reasons, !PACK_PURPOSES.has(purpose), `legal_pack_purpose_unsupported:${purpose}`);
  }
}

function evaluatePreservationProfile(profile, request, requiredDomains, reasons) {
  addReason(reasons, !hasText(profile?.profileRef), 'preservation_profile_ref_absent');
  addReason(reasons, !isDigest(profile?.profileHash), 'preservation_profile_hash_invalid');
  addReason(reasons, !PROFILE_STATUSES.has(profile?.status), 'preservation_profile_not_approved');
  addReason(reasons, profile?.metadataOnly !== true, 'preservation_profile_metadata_boundary_invalid');
  addReason(reasons, profile?.rawContentForbidden !== true, 'preservation_profile_raw_content_policy_absent');
  addReason(reasons, profile?.appendOnlyEvidenceRequired !== true, 'preservation_profile_append_only_absent');
  addReason(reasons, profile?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(profile?.approvedAtHlc) === null, 'preservation_profile_approval_time_invalid');
  addReason(reasons, hlcAfter(profile?.approvedAtHlc, request?.requestedAtHlc), 'preservation_profile_approved_after_request');

  for (const domain of requiredDomains) {
    addReason(reasons, !REQUIRED_PRESERVATION_DOMAINS.has(domain), `preservation_domain_unsupported:${domain}`);
  }
  for (const domain of [...REQUIRED_PRESERVATION_DOMAINS].sort()) {
    addReason(reasons, !requiredDomains.includes(domain), `preservation_domain_missing:${domain}`);
  }
}

function evaluateAccessPolicy(policy, purposes, evidenceItems, assembledAtHlc, reasons) {
  const allowedPurposes = sortedTextList(policy?.allowedPurposes);
  const allowedFamilies = sortedTextList(policy?.allowedObjectFamilies);
  const allowedSensitivityTags = sortedTextList(policy?.allowedSensitivityTags);

  addReason(reasons, !hasText(policy?.policyRef), 'access_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'access_policy_hash_invalid');
  addReason(reasons, !ACCESS_POLICY_STATUSES.has(policy?.status), 'access_policy_not_active');
  addReason(reasons, policy?.sourcePayloadAccessible === true, 'access_policy_source_payload_boundary_invalid');
  addReason(reasons, policy?.metadataOnly !== true, 'access_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.disclosureLogRequired !== true, 'access_policy_disclosure_log_absent');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'access_policy_evaluated_time_invalid');
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, assembledAtHlc), 'access_policy_evaluated_after_assembly');

  for (const purpose of purposes) {
    addReason(reasons, !allowedPurposes.includes(purpose), `requested_purpose_not_allowed:${purpose}`);
  }
  for (const evidence of evidenceItems) {
    addReason(reasons, !allowedFamilies.includes(evidence?.objectFamily), `evidence_family_not_allowed:${evidenceLabel(evidence)}`);
    for (const tag of sortedTextList(evidence?.sensitivityTags)) {
      addReason(reasons, !allowedSensitivityTags.includes(tag), `evidence_sensitivity_not_allowed:${evidenceLabel(evidence)}`);
    }
  }
}

function evidenceLabel(evidence, index = null) {
  if (hasText(evidence?.evidenceRef)) {
    return evidence.evidenceRef;
  }
  return index === null ? 'unknown' : `index_${index}`;
}

function evaluateEvidenceItems(items, assembledAtHlc, reasons) {
  addReason(reasons, !Array.isArray(items) || items.length === 0, 'evidence_items_absent');
  if (!Array.isArray(items)) {
    return;
  }

  const seen = new Set();
  items.forEach((evidence, index) => {
    const label = evidenceLabel(evidence, index);
    addReason(reasons, !hasText(evidence?.evidenceRef), `evidence_ref_absent:${label}`);
    addReason(reasons, seen.has(evidence?.evidenceRef), `evidence_ref_duplicate:${label}`);
    if (hasText(evidence?.evidenceRef)) {
      seen.add(evidence.evidenceRef);
    }
    addReason(reasons, !hasText(evidence?.objectFamily), `evidence_family_absent:${label}`);
    addReason(reasons, !isDigest(evidence?.artifactHash), `evidence_artifact_hash_invalid:${label}`);
    addReason(reasons, !isDigest(evidence?.metadataHash), `evidence_metadata_hash_invalid:${label}`);
    addReason(reasons, !isDigest(evidence?.provenanceHash), `evidence_provenance_hash_invalid:${label}`);
    addReason(reasons, !isDigest(evidence?.custodyDigest), `evidence_custody_digest_invalid:${label}`);
    addReason(reasons, !isDigest(evidence?.timestampHash), `evidence_timestamp_hash_invalid:${label}`);
    addReason(reasons, !isDigest(evidence?.accessLogHash), `evidence_access_log_hash_invalid:${label}`);
    addReason(reasons, !isDigest(evidence?.decisionRationaleHash), `evidence_decision_rationale_hash_invalid:${label}`);
    addReason(reasons, !isDigest(evidence?.versionHistoryHash), `evidence_version_history_hash_invalid:${label}`);
    addReason(reasons, !isDigest(evidence?.correctionHistoryHash), `evidence_correction_history_hash_invalid:${label}`);
    addReason(reasons, !hasText(evidence?.retentionRuleRef), `evidence_retention_rule_absent:${label}`);
    addReason(reasons, !hasText(evidence?.classification), `evidence_classification_absent:${label}`);
    addReason(reasons, sortedTextList(evidence?.sensitivityTags).length === 0, `evidence_sensitivity_tags_absent:${label}`);
    addReason(reasons, evidence?.metadataOnly !== true, `evidence_metadata_boundary_invalid:${label}`);
    addReason(reasons, evidence?.rawContentExcluded !== true, `evidence_raw_content_boundary_invalid:${label}`);
    addReason(reasons, evidence?.sourcePayloadExcluded !== true, `evidence_source_payload_boundary_invalid:${label}`);
    addReason(reasons, hlcTuple(evidence?.recordedAtHlc) === null, `evidence_recorded_time_invalid:${label}`);
    addReason(reasons, hlcTuple(evidence?.reviewedAtHlc) === null, `evidence_reviewed_time_invalid:${label}`);
    addReason(reasons, hlcBefore(evidence?.reviewedAtHlc, evidence?.recordedAtHlc), `evidence_reviewed_before_recorded:${label}`);
    addReason(reasons, hlcAfter(evidence?.reviewedAtHlc, assembledAtHlc), `evidence_reviewed_after_assembly:${label}`);
  });
}

function evaluateAccessLog(accessLog, request, reasons) {
  addReason(reasons, !hasText(accessLog?.logRef), 'access_log_ref_absent');
  addReason(reasons, !isDigest(accessLog?.accessLogHash), 'access_log_hash_invalid');
  addReason(
    reasons,
    !Number.isSafeInteger(accessLog?.includedEventCount) || accessLog.includedEventCount <= 0,
    'access_log_event_count_invalid',
  );
  addReason(reasons, accessLog?.includesRawContent === true, 'access_log_raw_content_boundary_invalid');
  addReason(reasons, hlcTuple(accessLog?.loggedAtHlc) === null, 'access_log_time_invalid');
  addReason(reasons, hlcAfter(accessLog?.loggedAtHlc, request?.assembledAtHlc), 'access_log_after_assembly');
}

function evaluateDecisionRationaleIndex(index, reasons) {
  addReason(reasons, !hasText(index?.indexRef), 'decision_rationale_index_ref_absent');
  addReason(reasons, !isDigest(index?.indexHash), 'decision_rationale_index_hash_invalid');
  addReason(reasons, sortedTextList(index?.decisionRefs).length === 0, 'decision_rationale_decisions_absent');
  addReason(reasons, sortedTextList(index?.rationaleHashes).filter(isDigest).length === 0, 'decision_rationale_index_empty');
  addReason(reasons, index?.metadataOnly !== true, 'decision_rationale_metadata_boundary_invalid');
  addReason(
    reasons,
    !Number.isSafeInteger(index?.unresolvedChallengeCount) || index.unresolvedChallengeCount < 0,
    'decision_rationale_challenge_count_invalid',
  );
}

function evaluateLegalReview(review, request, reasons) {
  addReason(reasons, !hasText(review?.reviewerDid), 'legal_reviewer_absent');
  addReason(reasons, !hasText(review?.reviewerRoleRef), 'legal_reviewer_role_absent');
  addReason(reasons, !LEGAL_REVIEW_STATUSES.has(review?.status), 'legal_review_not_approved');
  addReason(reasons, !isDigest(review?.reviewHash), 'legal_review_hash_invalid');
  addReason(reasons, review?.aiFinalAuthorityRejected !== true, 'legal_review_rejected_ai_finality_absent');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'legal_review_time_invalid');
  addReason(reasons, hlcAfter(review?.reviewedAtHlc, request?.assembledAtHlc), 'legal_review_after_assembly');
}

function evaluateDisclosureLog(disclosureLog, request, reasons) {
  addReason(reasons, !hasText(disclosureLog?.disclosureRef), 'disclosure_log_ref_absent');
  addReason(reasons, !isDigest(disclosureLog?.disclosureLogHash), 'disclosure_log_hash_invalid');
  addReason(reasons, !hasText(disclosureLog?.recipientClass), 'disclosure_log_recipient_absent');
  addReason(reasons, !isDigest(disclosureLog?.purposeHash), 'disclosure_log_purpose_hash_invalid');
  addReason(reasons, disclosureLog?.includesRawContent === true, 'disclosure_log_raw_content_boundary_invalid');
  addReason(reasons, hlcTuple(disclosureLog?.loggedAtHlc) === null, 'disclosure_log_time_invalid');
  addReason(reasons, hlcAfter(disclosureLog?.loggedAtHlc, request?.assembledAtHlc), 'disclosure_log_after_assembly');
}

function evaluateRetentionHold(retentionHold, request, purposes, reasons) {
  if (!purposes.includes('dispute_resolution')) {
    return;
  }

  addReason(reasons, !hasText(retentionHold?.holdRef), 'legal_hold_ref_absent');
  addReason(reasons, !isDigest(retentionHold?.holdHash), 'legal_hold_hash_invalid');
  addReason(reasons, !LEGAL_HOLD_STATUSES.has(retentionHold?.status), 'legal_hold_not_active');
  addReason(
    reasons,
    retentionHold?.appliesToDisputeResolution !== true || !LEGAL_HOLD_STATUSES.has(retentionHold?.status),
    'retention_hold_dispute_coverage_absent',
  );
  addReason(reasons, !isDigest(retentionHold?.retentionRuleHash), 'legal_hold_retention_rule_hash_invalid');
  addReason(reasons, hlcTuple(retentionHold?.expiresAtHlc) === null, 'legal_hold_expiry_invalid');
  addReason(reasons, hlcBeforeOrEqual(retentionHold?.expiresAtHlc, request?.assembledAtHlc), 'legal_hold_expired');
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance === null || aiAssistance === undefined || aiAssistance?.used !== true) {
    return;
  }

  addReason(reasons, aiAssistance.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, aiAssistance.reviewedByHuman !== true, 'ai_human_review_absent');
  addReason(reasons, !isDigest(aiAssistance.scopeHash), 'ai_scope_hash_invalid');
  addReason(reasons, sortedTextList(aiAssistance.evidenceRefs).length === 0, 'ai_evidence_refs_absent');
  addReason(reasons, sortedTextList(aiAssistance.limitationHashes).filter(isDigest).length === 0, 'ai_limitation_hashes_absent');
}

function preservationMatrix(evidenceItems, accessLog, decisionRationaleIndex) {
  const evidence = Array.isArray(evidenceItems) ? evidenceItems : [];
  return {
    access_logs: evidence.length > 0 && isDigest(accessLog?.accessLogHash) && evidence.every((item) => isDigest(item?.accessLogHash)),
    custody: evidence.length > 0 && evidence.every((item) => isDigest(item?.custodyDigest)),
    decision_rationale:
      evidence.length > 0 &&
      sortedTextList(decisionRationaleIndex?.rationaleHashes).filter(isDigest).length > 0 &&
      evidence.every((item) => isDigest(item?.decisionRationaleHash)),
    provenance: evidence.length > 0 && evidence.every((item) => isDigest(item?.provenanceHash)),
    timestamps:
      evidence.length > 0 &&
      evidence.every((item) => isDigest(item?.timestampHash) && hlcTuple(item?.recordedAtHlc) !== null && hlcTuple(item?.reviewedAtHlc) !== null),
    version_history: evidence.length > 0 && evidence.every((item) => isDigest(item?.versionHistoryHash)),
  };
}

function buildEvidenceItem(evidence) {
  return {
    accessLogHash: evidence.accessLogHash,
    artifactHash: evidence.artifactHash,
    classification: evidence.classification,
    correctionHistoryHash: evidence.correctionHistoryHash,
    custodyDigest: evidence.custodyDigest,
    decisionRationaleHash: evidence.decisionRationaleHash,
    evidenceRef: evidence.evidenceRef,
    metadataHash: evidence.metadataHash,
    objectFamily: evidence.objectFamily,
    provenanceHash: evidence.provenanceHash,
    recordedAtHlc: evidence.recordedAtHlc,
    retentionRuleRef: evidence.retentionRuleRef,
    timestampHash: evidence.timestampHash,
    versionHistoryHash: evidence.versionHistoryHash,
  };
}

function buildLegalPack(input, purposes, preservedDomains, matrix) {
  const evidenceItems = [...input.evidenceItems].sort((left, right) => left.evidenceRef.localeCompare(right.evidenceRef)).map(buildEvidenceItem);
  const packBasis = {
    accessLogHash: input.accessLog.accessLogHash,
    decisionRationaleIndexHash: input.decisionRationaleIndex.indexHash,
    disclosureLogHash: input.disclosureLog.disclosureLogHash,
    evidenceItems,
    legalReviewHash: input.legalReview.reviewHash,
    purposes,
    schema: LEGAL_DEFENSIBILITY_SCHEMA,
    subjectRef: input.packRequest.subjectRef,
    tenantId: input.tenantId,
  };

  return {
    schema: LEGAL_DEFENSIBILITY_SCHEMA,
    packageId: `cmld_${sha256Hex(packBasis).slice(0, 32)}`,
    trustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    legalDefensibilitySubjectToHumanReview: true,
    subjectRef: input.packRequest.subjectRef,
    purposes,
    preservedDomains,
    preservationMatrix: matrix,
    evidenceItems,
    accessLogHash: input.accessLog.accessLogHash,
    decisionRationaleIndexHash: input.decisionRationaleIndex.indexHash,
    disclosureLogHash: input.disclosureLog.disclosureLogHash,
    legalReviewHash: input.legalReview.reviewHash,
    retentionHoldHash: input.retentionHold?.holdHash ?? null,
    assembledAtHlc: input.packRequest.assembledAtHlc,
  };
}

function buildReceipt(input, legalPack) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: sha256Hex(legalPack),
    artifactType: 'legal_defensibility_pack',
    artifactVersion: 'v1',
    classification: 'restricted_metadata_only',
    custodyDigest: sha256Hex({
      evidenceCustodyDigests: legalPack.evidenceItems.map((item) => item.custodyDigest),
      legalReviewHash: legalPack.legalReviewHash,
      retentionHoldHash: legalPack.retentionHoldHash,
    }),
    hlcTimestamp: input.packRequest.assembledAtHlc,
    sensitivityTags: ['legal_defensibility', 'metadata_only'],
    sourceSystem: 'cybermedica',
    tenantId: input.tenantId,
  });
}

export function evaluateLegalDefensibilityPack(input) {
  assertMetadataOnly(input);

  const reasons = [];
  const purposes = sortedTextList(input?.packRequest?.purposes);
  const requiredDomains = sortedTextList(input?.preservationProfile?.requiredDomains);
  const evidenceItems = Array.isArray(input?.evidenceItems) ? input.evidenceItems : [];

  evaluateTenantActorAuthority(input, reasons);
  evaluatePackRequest(input?.packRequest, purposes, reasons);
  evaluatePreservationProfile(input?.preservationProfile, input?.packRequest, requiredDomains, reasons);
  evaluateAccessPolicy(input?.accessPolicy, purposes, evidenceItems, input?.packRequest?.assembledAtHlc, reasons);
  evaluateEvidenceItems(input?.evidenceItems, input?.packRequest?.assembledAtHlc, reasons);
  evaluateAccessLog(input?.accessLog, input?.packRequest, reasons);
  evaluateDecisionRationaleIndex(input?.decisionRationaleIndex, reasons);
  evaluateLegalReview(input?.legalReview, input?.packRequest, reasons);
  evaluateDisclosureLog(input?.disclosureLog, input?.packRequest, reasons);
  evaluateRetentionHold(input?.retentionHold, input?.packRequest, purposes, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      decision: 'denied',
      failClosed: true,
      reasons: unique,
    };
  }

  const matrix = preservationMatrix(input.evidenceItems, input.accessLog, input.decisionRationaleIndex);
  const legalPack = buildLegalPack(input, purposes, [...REQUIRED_PRESERVATION_DOMAINS].sort(), matrix);

  return {
    decision: 'permitted',
    failClosed: false,
    legalPack,
    receipt: buildReceipt(input, legalPack),
  };
}
