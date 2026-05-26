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
const MANUAL_EXPORT_SCHEMA = 'cybermedica.manual_export_packet.v1';
const REQUIRED_PERMISSION = 'manual_export';
const ACTIVE_POLICY_STATUSES = new Set(['active']);
const ACTOR_KINDS = new Set(['human', 'service_account']);
const HUMAN_AUTHORIZATION_STATUSES = new Set(['approved']);

const REQUIRED_FORMATS = Object.freeze(['markdown', 'pdf', 'print', 'word']);
const REQUIRED_PACKET_SCOPES = Object.freeze([
  'audit_training_packet',
  'role_manual_packet',
  'workflow_manual_packet',
]);
const REQUIRED_BOUNDARY_CONTROLS = Object.freeze([
  'metadata_only_manifest',
  'no_raw_manual_content',
  'no_unapproved_claims',
  'print_watermark',
  'role_access_filtering',
  'version_history_included',
]);

const RAW_MANUAL_EXPORT_FIELDS = new Set([
  'body',
  'content',
  'exportbody',
  'exportpayload',
  'freetext',
  'freetextnote',
  'manualbody',
  'manualcontent',
  'manualtext',
  'packetbody',
  'packetcontent',
  'rawcontent',
  'rawexportcontent',
  'rawmanualcontent',
  'rawmanualpacket',
  'rawmanualtext',
  'rawpacketcontent',
  'rawsource',
  'rawsourcedocument',
  'renderedcontent',
  'sourcedocumentbody',
]);

const SECRET_MANUAL_EXPORT_FIELDS = new Set([
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

function assertNoRawManualExportContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawManualExportContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_MANUAL_EXPORT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw manual export content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_MANUAL_EXPORT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`manual export secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawManualExportContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawManualExportContent(input ?? {});
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

function latestHlc(values) {
  const tuples = values.map((value) => hlcTuple(value)).filter((value) => value !== null);
  if (tuples.length === 0) {
    return null;
  }
  const latest = tuples.reduce((current, candidate) => (compareHlc(current, candidate) > 0 ? current : candidate));
  return { physicalMs: latest[0], logical: latest[1] };
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, !ACTOR_KINDS.has(input?.actor?.kind), 'manual_export_actor_kind_invalid');
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
    'manual_export_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'manual_export_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'manual_export_policy_hash_invalid');
  addReason(reasons, !ACTIVE_POLICY_STATUSES.has(policy?.status), 'manual_export_policy_inactive');
  addReason(reasons, policy?.humanAuthorizationRequired !== true, 'human_authorization_policy_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'policy_metadata_only_absent');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'policy_protected_content_boundary_absent');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'policy_evaluated_hlc_invalid');

  const allowedFormats = sortedTextList(policy?.allowedFormats);
  for (const format of REQUIRED_FORMATS) {
    addReason(reasons, !allowedFormats.includes(format), `policy_format_missing:${format}`);
  }

  const packetScopes = sortedTextList(policy?.requiredPacketScopes);
  for (const scope of REQUIRED_PACKET_SCOPES) {
    addReason(reasons, !packetScopes.includes(scope), `policy_packet_scope_missing:${scope}`);
  }
}

function evaluateExportRequest(request, policy, reasons) {
  addReason(reasons, !hasText(request?.requestRef), 'manual_export_request_ref_absent');
  addReason(reasons, request?.metadataOnly !== true, 'request_metadata_only_absent');
  addReason(reasons, request?.protectedContentExcluded !== true, 'request_protected_content_boundary_absent');
  addReason(reasons, request?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(request?.requestedAtHlc) === null, 'requested_hlc_invalid');
  addReason(reasons, hlcTuple(request?.generatedAtHlc) === null, 'generated_hlc_invalid');
  addReason(
    reasons,
    !hlcAfter(request?.generatedAtHlc, request?.requestedAtHlc),
    'generated_hlc_not_after_requested_hlc',
  );

  const requestedFormats = sortedTextList(request?.requestedFormats);
  const allowedFormats = sortedTextList(policy?.allowedFormats);
  for (const format of requestedFormats) {
    addReason(reasons, !REQUIRED_FORMATS.includes(format), `format_unsupported:${format}`);
    addReason(reasons, !allowedFormats.includes(format), `format_not_allowed:${format}`);
  }
  for (const format of REQUIRED_FORMATS) {
    addReason(reasons, !requestedFormats.includes(format), `required_format_missing:${format}`);
  }

  const requestedScopes = sortedTextList(request?.requestedPacketScopes);
  for (const scope of REQUIRED_PACKET_SCOPES) {
    addReason(reasons, !requestedScopes.includes(scope), `required_packet_scope_missing:${scope}`);
  }
}

function evaluateSourceManualSet(sourceManualSet, reasons) {
  addReason(reasons, !isDigest(sourceManualSet?.runbookReceiptHash), 'runbook_receipt_hash_invalid');
  addReason(reasons, !isDigest(sourceManualSet?.publicationReceiptHash), 'publication_receipt_hash_invalid');
  addReason(reasons, !isDigest(sourceManualSet?.manualSetHash), 'manual_set_hash_invalid');
  addReason(reasons, !isDigest(sourceManualSet?.manualIndexHash), 'manual_index_hash_invalid');
  addReason(reasons, !hasText(sourceManualSet?.documentationVersionRef), 'documentation_version_ref_absent');
  addReason(reasons, !isDigest(sourceManualSet?.rollbackVersionHash), 'rollback_version_hash_invalid');
  addReason(reasons, sourceManualSet?.metadataOnly !== true, 'source_manual_set_metadata_only_absent');
  addReason(
    reasons,
    sourceManualSet?.protectedContentExcluded !== true,
    'source_manual_set_protected_content_boundary_absent',
  );
}

function evaluateManualArtifacts(input, reasons) {
  const artifacts = Array.isArray(input?.manualArtifacts) ? input.manualArtifacts : [];
  const requestedRoles = sortedTextList(input?.exportRequest?.requestedRoleRefs);
  const requestedWorkflows = sortedTextList(input?.exportRequest?.requestedWorkflowRefs);
  const actorRoles = sortedTextList(input?.actor?.roleRefs);
  const artifactsByRole = new Map(artifacts.filter((artifact) => hasText(artifact?.roleRef)).map((artifact) => [artifact.roleRef, artifact]));

  for (const role of requestedRoles) {
    const artifact = artifactsByRole.get(role);
    addReason(reasons, !actorRoles.includes(role), `requested_role_not_authorized:${role}`);
    addReason(reasons, artifact === undefined, `manual_artifact_missing:${role}`);
  }

  for (const artifact of artifacts) {
    const manualRef = hasText(artifact?.manualRef) ? artifact.manualRef : 'unknown_manual';
    addReason(reasons, !hasText(artifact?.manualRef), 'manual_ref_absent');
    addReason(reasons, !hasText(artifact?.roleRef), `manual_role_ref_absent:${manualRef}`);
    addReason(reasons, !isDigest(artifact?.sectionIndexHash), `manual_section_index_hash_invalid:${manualRef}`);
    addReason(reasons, !isDigest(artifact?.manualVersionHash), `manual_version_hash_invalid:${manualRef}`);
    addReason(reasons, !isDigest(artifact?.crosslinkMatrixHash), `manual_crosslink_hash_invalid:${manualRef}`);
    addReason(reasons, !isDigest(artifact?.publicationReceiptHash), `manual_publication_receipt_hash_invalid:${manualRef}`);
    addReason(reasons, artifact?.approvedForExport !== true, `manual_not_approved_for_export:${manualRef}`);
    addReason(reasons, artifact?.currentVersion !== true, `manual_not_current_version:${manualRef}`);
    addReason(reasons, artifact?.highRiskClaimsReviewed !== true, `manual_high_risk_claim_review_missing:${manualRef}`);
    addReason(reasons, artifact?.metadataOnly !== true, `manual_metadata_only_absent:${manualRef}`);
    addReason(reasons, artifact?.protectedContentExcluded !== true, `manual_protected_content_boundary_absent:${manualRef}`);
    addReason(reasons, hlcTuple(artifact?.lastReviewedAtHlc) === null, `manual_review_hlc_invalid:${manualRef}`);

    const eligibleFormats = sortedTextList(artifact?.exportEligibleFormats);
    for (const format of REQUIRED_FORMATS) {
      addReason(reasons, !eligibleFormats.includes(format), `manual_format_missing:${manualRef}:${format}`);
    }

    const workflowRefs = sortedTextList(artifact?.workflowRefs);
    for (const workflowRef of requestedWorkflows) {
      addReason(reasons, !workflowRefs.includes(workflowRef), `manual_workflow_missing:${manualRef}:${workflowRef}`);
    }
  }
}

function evaluateExportManifest(input, reasons) {
  const entries = Array.isArray(input?.exportManifest) ? input.exportManifest : [];
  const scopes = sortedTextList(entries.map((entry) => entry?.scope));
  for (const scope of REQUIRED_PACKET_SCOPES) {
    addReason(reasons, !scopes.includes(scope), `manifest_packet_scope_missing:${scope}`);
  }

  for (const entry of entries) {
    const scope = hasText(entry?.scope) ? entry.scope : 'unknown_scope';
    addReason(reasons, !REQUIRED_PACKET_SCOPES.includes(scope), `manifest_packet_scope_unsupported:${scope}`);
    addReason(reasons, !hasText(entry?.manifestRef), `manifest_ref_absent:${scope}`);
    addReason(reasons, !isDigest(entry?.manifestHash), `manifest_hash_invalid:${scope}`);
    addReason(reasons, entry?.includesVersionHistory !== true, `manifest_version_history_absent:${scope}`);
    addReason(reasons, entry?.includesRoleAccessSummary !== true, `manifest_role_access_absent:${scope}`);
    addReason(reasons, entry?.includesTrainingUseStatement !== true, `manifest_training_use_absent:${scope}`);
    addReason(reasons, entry?.includesAuditUseStatement !== true, `manifest_audit_use_absent:${scope}`);
    addReason(reasons, entry?.metadataOnly !== true, `manifest_metadata_only_absent:${scope}`);
    addReason(reasons, entry?.protectedContentExcluded !== true, `manifest_protected_content_boundary_absent:${scope}`);
  }
}

function evaluateBoundaryAttestation(attestation, reasons) {
  const controls = sortedTextList(attestation?.controls);
  for (const control of REQUIRED_BOUNDARY_CONTROLS) {
    addReason(reasons, !controls.includes(control), `boundary_control_missing:${control}`);
  }
  addReason(reasons, !isDigest(attestation?.suppressionLogHash), 'suppression_log_hash_invalid');
  addReason(reasons, attestation?.watermarkedForPrint !== true, 'print_watermark_absent');
  addReason(reasons, attestation?.noRawManualContent !== true, 'raw_manual_content_boundary_absent');
  addReason(reasons, attestation?.noUnapprovedClaims !== true, 'unapproved_claim_boundary_absent');
  addReason(reasons, attestation?.protectedContentExcluded !== true, 'boundary_protected_content_absent');
  addReason(reasons, attestation?.metadataOnly !== true, 'boundary_metadata_only_absent');

  for (const format of REQUIRED_FORMATS) {
    addReason(reasons, !isDigest(attestation?.formatRenderHashes?.[format]), `format_render_hash_invalid:${format}`);
  }
}

function evaluateHumanAuthorization(authorization, reasons) {
  addReason(
    reasons,
    !HUMAN_AUTHORIZATION_STATUSES.has(authorization?.status),
    'human_authorization_not_approved',
  );
  addReason(reasons, !hasText(authorization?.reviewerDid), 'human_authorization_reviewer_absent');
  addReason(reasons, !isDigest(authorization?.reviewHash), 'human_authorization_hash_invalid');
  addReason(reasons, hlcTuple(authorization?.approvedAtHlc) === null, 'human_authorization_hlc_invalid');
  addReason(reasons, authorization?.metadataOnly !== true, 'human_authorization_metadata_only_absent');
  addReason(
    reasons,
    authorization?.protectedContentExcluded !== true,
    'human_authorization_protected_content_boundary_absent',
  );
}

function evaluateReceiptEvidence(receiptEvidence, reasons) {
  addReason(reasons, !isDigest(receiptEvidence?.custodyDigest), 'custody_digest_invalid');
  addReason(reasons, !isDigest(receiptEvidence?.artifactHash), 'artifact_hash_invalid');
  addReason(reasons, !isDigest(receiptEvidence?.evidenceHash), 'evidence_hash_invalid');
}

function createManualExportPacket(input) {
  const requestedRoles = sortedTextList(input?.exportRequest?.requestedRoleRefs);
  const requestedWorkflows = sortedTextList(input?.exportRequest?.requestedWorkflowRefs);
  const formats = sortedTextList(input?.exportRequest?.requestedFormats);
  const packetScopes = sortedTextList(input?.exportRequest?.requestedPacketScopes);
  const manualRefs = uniqueSorted(
    (Array.isArray(input?.manualArtifacts) ? input.manualArtifacts : []).map((artifact) => artifact?.manualRef),
  );
  const manifestRefs = uniqueSorted(
    (Array.isArray(input?.exportManifest) ? input.exportManifest : []).map((entry) => entry?.manifestRef),
  );
  const suppressionCount = Array.isArray(input?.boundaryAttestation?.suppressedSectionRefs)
    ? input.boundaryAttestation.suppressedSectionRefs.filter(hasText).length
    : 0;
  const latestManualReviewHlc = latestHlc(
    (Array.isArray(input?.manualArtifacts) ? input.manualArtifacts : []).map((artifact) => artifact?.lastReviewedAtHlc),
  );

  return {
    schema: MANUAL_EXPORT_SCHEMA,
    packetRef: input.exportRequest.requestRef,
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    purpose: input.exportRequest.purpose,
    documentationVersionRef: input.sourceManualSet.documentationVersionRef,
    formats,
    packetScopes,
    roleRefs: requestedRoles,
    workflowRefs: requestedWorkflows,
    manualRefs,
    manifestRefs,
    suppressionCount,
    printReady: formats.includes('print') && input.boundaryAttestation.watermarkedForPrint === true,
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    latestManualReviewHlc,
    generatedAtHlc: input.exportRequest.generatedAtHlc,
    packetHash: sha256Hex({
      formats,
      manualRefs,
      manifestRefs,
      packetRef: input.exportRequest.requestRef,
      packetScopes,
      roleRefs: requestedRoles,
      schema: MANUAL_EXPORT_SCHEMA,
      tenantId: input.tenantId,
      workflowRefs: requestedWorkflows,
    }),
  };
}

function createManualExportReceipt(input, manualExportPacket) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: input.receiptEvidence.artifactHash,
    artifactType: 'manual_export_packet',
    artifactVersion: input.sourceManualSet.documentationVersionRef,
    classification: 'metadata_only_manual_export_packet',
    custodyDigest: input.receiptEvidence.custodyDigest,
    hlcTimestamp: input.exportRequest.generatedAtHlc,
    schema: MANUAL_EXPORT_SCHEMA,
    sensitivityTags: [
      'audit_training_manuals',
      'manual_export_metadata',
      'metadata_only',
      'no_raw_manual_content',
    ],
    sourceSystem: 'cybermedica.documentation_layer',
    tenantId: input.tenantId,
    packetHash: manualExportPacket.packetHash,
  });
}

export function evaluateManualExportPacket(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluatePolicy(input?.exportPolicy, reasons);
  evaluateExportRequest(input?.exportRequest, input?.exportPolicy, reasons);
  evaluateSourceManualSet(input?.sourceManualSet, reasons);
  evaluateManualArtifacts(input, reasons);
  evaluateExportManifest(input, reasons);
  evaluateBoundaryAttestation(input?.boundaryAttestation, reasons);
  evaluateHumanAuthorization(input?.humanAuthorization, reasons);
  evaluateReceiptEvidence(input?.receiptEvidence, reasons);

  const sortedReasons = uniqueReasons(reasons);
  if (sortedReasons.length > 0) {
    return {
      status: 'denied',
      reasons: sortedReasons,
      manualExportPacket: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const manualExportPacket = createManualExportPacket(input);
  const receipt = createManualExportReceipt(input, manualExportPacket);

  return {
    status: 'ready',
    reasons: [],
    manualExportPacket,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
    sourceEvidence: [
      'cybermedica_2_0_sandy_seven_layer_master_prd.md:DOC-008',
      'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
    ],
  };
}

export const manualExportPacketRequirements = Object.freeze({
  schema: MANUAL_EXPORT_SCHEMA,
  requiredFormats: REQUIRED_FORMATS,
  requiredPacketScopes: REQUIRED_PACKET_SCOPES,
  requiredBoundaryControls: REQUIRED_BOUNDARY_CONTROLS,
});
