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
const INSPECTION_MODE_SCHEMA = 'cybermedica.inspection_mode_session.v1';
const REQUIRED_PERMISSION = 'inspection_mode';
const ACTIVE_POLICY_STATUSES = new Set(['active']);
const ACTOR_KINDS = new Set(['human']);
const HUMAN_AUTHORIZATION_STATUSES = new Set(['approved']);
const INSPECTION_PURPOSES = new Set(['cro_audit', 'internal_audit', 'regulatory_inspection', 'sponsor_audit']);
const INSPECTION_ROLES = new Set(['auditor_inspector', 'cro_monitor', 'regulatory_inspector', 'sponsor_monitor']);
const INSPECTION_SCOPES = new Set([
  'access_logs',
  'chain_of_custody',
  'decision_rationale',
  'evidence_index',
  'issue_history',
  'staff_training',
  'training_delegation',
  'version_history',
]);

const RAW_INSPECTION_FIELDS = new Set([
  'body',
  'content',
  'freetext',
  'freetextnote',
  'inspectionbody',
  'inspectioncontent',
  'inspectionnotes',
  'inspectionpacket',
  'inspectionrawcontent',
  'inspectiontext',
  'packetbody',
  'packetcontent',
  'rawcontent',
  'rawinspectioncontent',
  'rawinspectionnotes',
  'rawinspectionpacket',
  'rawinspectiontext',
  'rawsource',
  'rawsourcedocument',
  'renderedcontent',
  'sourcedocumentbody',
]);

const SECRET_INSPECTION_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credential',
  'credentialsecret',
  'password',
  'privatekey',
  'railwaytoken',
  'refreshtoken',
  'rootkey',
  'rootsigningkey',
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

function isPositiveSafeInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
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

function assertNoRawInspectionContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawInspectionContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_INSPECTION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw inspection content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_INSPECTION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`inspection secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawInspectionContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawInspectionContent(input ?? {});
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

function hlcAfterOrEqual(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) >= 0;
}

function hlcDurationMs(start, end) {
  const startTuple = hlcTuple(start);
  const endTuple = hlcTuple(end);
  if (startTuple === null || endTuple === null || compareHlc(endTuple, startTuple) <= 0) {
    return null;
  }
  return endTuple[0] - startTuple[0];
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, !ACTOR_KINDS.has(input?.actor?.kind), 'human_inspection_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'inspection_authority_permission_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'inspection_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'inspection_policy_hash_invalid');
  addReason(reasons, !ACTIVE_POLICY_STATUSES.has(policy?.status), 'inspection_policy_inactive');
  addReason(reasons, policy?.metadataOnly !== true, 'inspection_policy_metadata_only_absent');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'inspection_policy_protected_boundary_absent');
  addReason(reasons, policy?.exportDisabledByDefault !== true, 'inspection_export_not_disabled_by_default');
  addReason(reasons, policy?.disclosureLogRequired !== true, 'inspection_policy_disclosure_log_not_required');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'inspection_policy_evaluated_hlc_invalid');
  addReason(reasons, !isPositiveSafeInteger(policy?.maxSessionDurationMs), 'inspection_policy_max_duration_invalid');

  for (const purpose of sortedTextList(policy?.allowedPurposes)) {
    addReason(reasons, !INSPECTION_PURPOSES.has(purpose), `inspection_purpose_unsupported:${purpose}`);
  }
  for (const role of sortedTextList(policy?.allowedViewerRoles)) {
    addReason(reasons, !INSPECTION_ROLES.has(role), `inspection_viewer_role_unsupported:${role}`);
  }
}

function evaluateSessionRequest(input, reasons) {
  const request = input?.sessionRequest;
  const policy = input?.inspectionPolicy;
  const requestedScopes = sortedTextList(request?.requestedScopes);
  const actorRoles = sortedTextList(input?.actor?.roleRefs);
  const allowedPurposes = sortedTextList(policy?.allowedPurposes);
  const allowedRoles = sortedTextList(policy?.allowedViewerRoles);
  const durationMs = hlcDurationMs(request?.startsAtHlc, request?.expiresAtHlc);

  addReason(reasons, !hasText(request?.requestRef), 'inspection_request_ref_absent');
  addReason(reasons, !INSPECTION_PURPOSES.has(request?.purpose), 'inspection_purpose_invalid');
  addReason(
    reasons,
    hasText(request?.purpose) && !allowedPurposes.includes(request.purpose),
    `inspection_purpose_not_allowed:${request?.purpose}`,
  );
  addReason(reasons, !INSPECTION_ROLES.has(request?.requestedViewerRole), 'inspection_viewer_role_invalid');
  addReason(
    reasons,
    hasText(request?.requestedViewerRole) && !allowedRoles.includes(request.requestedViewerRole),
    `inspection_viewer_role_not_allowed:${request?.requestedViewerRole}`,
  );
  addReason(
    reasons,
    hasText(request?.requestedViewerRole) && !actorRoles.includes(request.requestedViewerRole),
    'inspection_actor_role_unauthorized',
  );
  addReason(reasons, !hasText(request?.siteRef), 'inspection_site_ref_absent');
  addReason(reasons, !hasText(request?.protocolRef), 'inspection_protocol_ref_absent');
  addReason(reasons, requestedScopes.length === 0, 'inspection_scopes_absent');
  for (const scope of requestedScopes) {
    addReason(reasons, !INSPECTION_SCOPES.has(scope), `inspection_scope_unsupported:${scope}`);
  }
  addReason(reasons, request?.metadataOnly !== true, 'inspection_request_metadata_only_absent');
  addReason(reasons, request?.protectedContentExcluded !== true, 'inspection_request_protected_boundary_absent');
  addReason(reasons, request?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(request?.requestedAtHlc) === null, 'inspection_requested_hlc_invalid');
  addReason(reasons, hlcTuple(request?.startsAtHlc) === null, 'inspection_start_hlc_invalid');
  addReason(reasons, hlcTuple(request?.expiresAtHlc) === null, 'inspection_expiry_hlc_invalid');
  addReason(reasons, !hlcAfterOrEqual(request?.startsAtHlc, request?.requestedAtHlc), 'inspection_start_before_request');
  addReason(reasons, !hlcAfter(request?.expiresAtHlc, request?.startsAtHlc), 'inspection_expiry_not_after_start');
  addReason(
    reasons,
    durationMs !== null &&
      isPositiveSafeInteger(policy?.maxSessionDurationMs) &&
      durationMs > policy.maxSessionDurationMs,
    'inspection_session_duration_exceeds_policy',
  );
}

function evaluateEvidencePackage(evidencePackage, policy, reasons) {
  if (evidencePackage === null || evidencePackage === undefined || typeof evidencePackage !== 'object') {
    reasons.push('inspection_evidence_package_absent');
  }

  addReason(reasons, evidencePackage?.metadataOnly !== true, 'inspection_evidence_metadata_only_absent');
  addReason(
    reasons,
    evidencePackage?.protectedContentExcluded !== true,
    'inspection_evidence_protected_boundary_absent',
  );
  addReason(reasons, !isDigest(evidencePackage?.auditPackageReceiptHash), 'audit_package_receipt_hash_invalid');
  addReason(reasons, !isDigest(evidencePackage?.legalPackReceiptHash), 'legal_pack_receipt_hash_invalid');
  addReason(reasons, !isDigest(evidencePackage?.qmsPassportReceiptHash), 'qms_passport_receipt_hash_invalid');
  addReason(reasons, !isDigest(evidencePackage?.manualGuideReceiptHash), 'manual_guide_receipt_hash_invalid');
  addReason(reasons, !isDigest(evidencePackage?.dashboardSnapshotHash), 'dashboard_snapshot_hash_invalid');

  const families = Array.isArray(evidencePackage?.evidenceFamilies) ? evidencePackage.evidenceFamilies : [];
  addReason(reasons, families.length === 0, 'inspection_evidence_families_absent');
  const familyNames = [];

  for (const row of families) {
    const family = row?.family;
    addReason(reasons, !hasText(family), 'inspection_evidence_family_absent');
    addReason(reasons, hasText(family) && !INSPECTION_SCOPES.has(family), `inspection_evidence_family_unsupported:${family}`);
    addReason(reasons, !isDigest(row?.manifestHash), `inspection_evidence_manifest_hash_invalid:${family ?? 'unknown'}`);
    addReason(reasons, !isDigest(row?.receiptHash), `inspection_evidence_receipt_hash_invalid:${family ?? 'unknown'}`);
    addReason(reasons, !isDigest(row?.custodyDigest), `inspection_evidence_custody_digest_invalid:${family ?? 'unknown'}`);
    addReason(reasons, !hasText(row?.accessPolicyRef), `inspection_evidence_access_policy_absent:${family ?? 'unknown'}`);
    addReason(reasons, row?.metadataOnly !== true, `inspection_evidence_metadata_only_absent:${family ?? 'unknown'}`);
    addReason(
      reasons,
      row?.protectedContentExcluded !== true,
      `inspection_evidence_protected_boundary_absent:${family ?? 'unknown'}`,
    );
    if (hasText(family)) {
      familyNames.push(family);
    }
  }

  const actualFamilies = uniqueSorted(familyNames);
  for (const family of sortedTextList(policy?.requiredEvidenceFamilies)) {
    addReason(reasons, !actualFamilies.includes(family), `inspection_evidence_family_missing:${family}`);
  }

  return actualFamilies;
}

function evaluateBoundaryAttestation(attestation, reasons) {
  if (attestation === null || attestation === undefined || typeof attestation !== 'object') {
    reasons.push('boundary_attestation_absent');
  }

  addReason(reasons, !isDigest(attestation?.accessPolicyHash), 'access_policy_hash_invalid');
  addReason(reasons, !isDigest(attestation?.exportPolicyHash), 'export_policy_hash_invalid');
  addReason(reasons, !isDigest(attestation?.disclosureLogHash), 'disclosure_log_hash_invalid');
  addReason(reasons, !isDigest(attestation?.suppressionLogHash), 'suppression_log_hash_invalid');
  addReason(reasons, !isDigest(attestation?.filteredViewHash), 'filtered_view_hash_invalid');
  addReason(reasons, attestation?.protectedContentSuppressed !== true, 'protected_content_suppression_missing');
  addReason(reasons, attestation?.directIdentifiersSuppressed !== true, 'direct_identifier_suppression_missing');
  addReason(
    reasons,
    attestation?.sponsorConfidentialSuppressed !== true,
    'sponsor_confidential_suppression_missing',
  );
  addReason(reasons, attestation?.rawSourceDocumentsExcluded !== true, 'raw_source_document_exclusion_missing');
  addReason(reasons, attestation?.disclosureLogRequired !== true, 'disclosure_log_not_required');
  addReason(reasons, attestation?.metadataOnly !== true, 'boundary_metadata_only_absent');
  addReason(reasons, attestation?.protectedContentExcluded !== true, 'boundary_protected_content_absent');
}

function evaluateHumanAuthorization(authorization, request, reasons) {
  if (authorization === null || authorization === undefined || typeof authorization !== 'object') {
    reasons.push('human_authorization_absent');
  }

  addReason(reasons, !HUMAN_AUTHORIZATION_STATUSES.has(authorization?.status), 'human_authorization_not_approved');
  addReason(reasons, !hasText(authorization?.reviewerDid), 'human_authorization_reviewer_absent');
  addReason(reasons, !isDigest(authorization?.reviewHash), 'human_authorization_hash_invalid');
  addReason(reasons, hlcTuple(authorization?.approvedAtHlc) === null, 'human_authorization_hlc_invalid');
  addReason(
    reasons,
    !hlcAfterOrEqual(authorization?.approvedAtHlc, request?.requestedAtHlc),
    'human_authorization_before_request',
  );
  addReason(reasons, authorization?.metadataOnly !== true, 'human_authorization_metadata_only_absent');
  addReason(
    reasons,
    authorization?.protectedContentExcluded !== true,
    'human_authorization_protected_content_boundary_absent',
  );
}

function evaluateReceiptEvidence(receiptEvidence, reasons) {
  addReason(reasons, !isDigest(receiptEvidence?.artifactHash), 'receipt_artifact_hash_invalid');
  addReason(reasons, !isDigest(receiptEvidence?.custodyDigest), 'receipt_custody_digest_invalid');
}

function createInspectionModeSession(input, evidenceFamilies) {
  const requestedScopes = sortedTextList(input.sessionRequest.requestedScopes);
  const artifactHash = sha256Hex({
    accessPolicyHash: input.boundaryAttestation.accessPolicyHash,
    evidenceFamilies,
    filteredViewHash: input.boundaryAttestation.filteredViewHash,
    protocolRef: input.sessionRequest.protocolRef,
    requestedScopes,
    requestRef: input.sessionRequest.requestRef,
    schema: INSPECTION_MODE_SCHEMA,
    siteRef: input.sessionRequest.siteRef,
    tenantId: input.tenantId,
  });

  return {
    schema: INSPECTION_MODE_SCHEMA,
    sessionId: `cmims_${sha256Hex({
      artifactHash,
      requestRef: input.sessionRequest.requestRef,
      tenantId: input.tenantId,
    }).slice(0, 32)}`,
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    purpose: input.sessionRequest.purpose,
    viewerRole: input.sessionRequest.requestedViewerRole,
    siteRef: input.sessionRequest.siteRef,
    protocolRef: input.sessionRequest.protocolRef,
    requestedScopes,
    evidenceFamilies,
    accessMode: 'read_only_inspection',
    exportDisabledByDefault: true,
    disclosureLogRequired: true,
    metadataOnly: true,
    protectedContentSuppressed: true,
    protectedContentExcluded: true,
    directIdentifiersSuppressed: true,
    sponsorConfidentialSuppressed: true,
    rawSourceDocumentsExcluded: true,
    productionTrustClaim: false,
    trustState: 'inactive',
    requestedAtHlc: input.sessionRequest.requestedAtHlc,
    startsAtHlc: input.sessionRequest.startsAtHlc,
    expiresAtHlc: input.sessionRequest.expiresAtHlc,
    disclosureLogHash: input.boundaryAttestation.disclosureLogHash,
    suppressionLogHash: input.boundaryAttestation.suppressionLogHash,
    filteredViewHash: input.boundaryAttestation.filteredViewHash,
    auditPackageReceiptHash: input.evidencePackage.auditPackageReceiptHash,
    legalPackReceiptHash: input.evidencePackage.legalPackReceiptHash,
    manualGuideReceiptHash: input.evidencePackage.manualGuideReceiptHash,
    qmsPassportReceiptHash: input.evidencePackage.qmsPassportReceiptHash,
    sessionHash: artifactHash,
  };
}

function createInspectionModeReceipt(input) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: input.receiptEvidence.artifactHash,
    artifactType: 'inspection_mode_session',
    artifactVersion: `${input.sessionRequest.requestRef}@${input.sessionRequest.startsAtHlc.physicalMs}.${input.sessionRequest.startsAtHlc.logical}`,
    classification: 'metadata_only_inspection_mode_session',
    custodyDigest: input.receiptEvidence.custodyDigest,
    hlcTimestamp: input.sessionRequest.startsAtHlc,
    schema: INSPECTION_MODE_SCHEMA,
    sensitivityTags: [
      'audit_inspection_metadata',
      'metadata_only',
      'read_only_inspection',
      'protected_content_suppressed',
    ],
    sourceSystem: 'cybermedica.doors_layer',
    tenantId: input.tenantId,
  });
}

export function evaluateInspectionModeSession(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluatePolicy(input?.inspectionPolicy, reasons);
  evaluateSessionRequest(input, reasons);
  const evidenceFamilies = evaluateEvidencePackage(input?.evidencePackage, input?.inspectionPolicy, reasons);
  evaluateBoundaryAttestation(input?.boundaryAttestation, reasons);
  evaluateHumanAuthorization(input?.humanAuthorization, input?.sessionRequest, reasons);
  evaluateReceiptEvidence(input?.receiptEvidence, reasons);

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: 'cybermedica.inspection_mode_decision.v1',
      status: 'denied',
      failClosed: true,
      reasons: unique,
      inspectionModeSession: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const inspectionModeSession = createInspectionModeSession(input, evidenceFamilies);
  const receipt = createInspectionModeReceipt(input);

  return {
    schema: 'cybermedica.inspection_mode_decision.v1',
    status: 'ready',
    failClosed: false,
    reasons: [],
    inspectionModeSession,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
