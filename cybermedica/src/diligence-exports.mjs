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

import {
  ProtectedContentError,
  canonicalize,
  createEvidenceReceipt,
  evaluateGovernedAction,
  sha256Hex,
} from './qms-contracts.mjs';

export { ProtectedContentError };

const HEX_64 = /^[0-9a-f]{64}$/u;
const SPONSOR_CRO_REQUESTER_CLASSES = new Set(['cro', 'sponsor']);
const SPONSOR_CRO_WORK_ITEM_STATUSES = new Set([
  'queued_for_site_review',
  'routed_to_decision_forum',
  'approved_for_response',
]);

const RAW_DILIGENCE_EXPORT_FIELDS = new Set([
  'clinicalnarrative',
  'exportbody',
  'exportpayload',
  'participantlisting',
  'rawcrorequest',
  'rawdiligenceexport',
  'rawdiligencepacket',
  'rawexport',
  'rawrequest',
  'rawrequestbody',
  'rawrequestcontent',
  'rawrequestnarrative',
  'rawresponsepackage',
  'rawsponsorrequest',
  'rawsponsorrequestbody',
  'sourcecontent',
  'sourcedocument',
  'sourcedocumentbody',
  'sourcepayload',
]);

const SECRET_DILIGENCE_EXPORT_FIELDS = new Set([
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

function assertNoRawDiligenceExportContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawDiligenceExportContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_DILIGENCE_EXPORT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`protected content/raw sponsor/cro request content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_DILIGENCE_EXPORT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`diligence export secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawDiligenceExportContent(nested, `${path}.${key}`);
  }
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

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlcTuple(leftTuple, rightTuple) > 0;
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function sameTextSet(left, right) {
  if (left.length !== right.length) {
    return false;
  }
  return left.every((item, index) => item === right[index]);
}

function validateProtectedContentBoundary(input) {
  assertNoRawDiligenceExportContent(input ?? {});
  canonicalize(input ?? {});
}

function normalizeManifestArtifacts(artifacts) {
  if (!Array.isArray(artifacts)) {
    return [];
  }
  return artifacts
    .map((artifact) => {
      if (!isDigest(artifact.artifactHash)) {
        throw new Error('artifactHash must be a non-zero lowercase 64 hex character digest');
      }
      return {
        artifactHash: artifact.artifactHash,
        artifactType: artifact.artifactType,
        artifactVersion: artifact.artifactVersion,
        classification: artifact.classification,
        controlId: artifact.controlId,
        evidenceId: artifact.evidenceId,
        tenantScopedPseudonym: artifact.tenantScopedPseudonym,
      };
    })
    .sort((left, right) => `${left.controlId}:${left.evidenceId}`.localeCompare(`${right.controlId}:${right.evidenceId}`));
}

function evaluateExportGrant(input, reasons) {
  addReason(reasons, input?.exportGrant?.status !== 'active', 'export_grant_not_active');
  addReason(reasons, input?.exportGrant?.scope !== 'sponsor_diligence_export', 'export_grant_scope_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
  addReason(reasons, !Array.isArray(input?.artifacts) || input.artifacts.length === 0, 'export_artifacts_absent');
}

function evaluateResponsePackage(input, manifestArtifacts, reasons) {
  const responsePackage = input?.responsePackage;
  const artifactEvidenceIds = sortedTextList(responsePackage?.artifactEvidenceIds);
  const manifestEvidenceIds = sortedTextList(manifestArtifacts.map((artifact) => artifact.evidenceId));

  addReason(reasons, responsePackage === null || responsePackage === undefined, 'sponsor_cro_response_package_absent');
  addReason(reasons, !hasText(responsePackage?.packageRef), 'sponsor_cro_response_package_ref_absent');
  addReason(reasons, !isDigest(responsePackage?.packageHash), 'sponsor_cro_response_package_hash_invalid');
  addReason(
    reasons,
    responsePackage?.requestRef !== input?.sponsorCroRequestEvidence?.requestRef,
    'sponsor_cro_response_package_request_mismatch',
  );
  addReason(
    reasons,
    responsePackage?.workItemRef !== input?.sponsorCroRequestEvidence?.workItemRef,
    'sponsor_cro_response_package_work_item_mismatch',
  );
  addReason(
    reasons,
    responsePackage?.recipientTenantId !== input?.recipientTenantId,
    'sponsor_cro_response_package_recipient_mismatch',
  );
  addReason(
    reasons,
    !sameTextSet(artifactEvidenceIds, manifestEvidenceIds),
    'sponsor_cro_response_package_artifact_scope_mismatch',
  );
  addReason(reasons, hlcTuple(responsePackage?.generatedAtHlc) === null, 'sponsor_cro_response_package_time_invalid');
  addReason(
    reasons,
    hlcAfter(responsePackage?.generatedAtHlc, input?.manifestHlc),
    'sponsor_cro_response_package_after_manifest',
  );
  addReason(
    reasons,
    responsePackage?.metadataOnly !== true,
    'sponsor_cro_response_package_metadata_boundary_invalid',
  );
  addReason(
    reasons,
    responsePackage?.rawContentExcluded !== true,
    'sponsor_cro_response_package_raw_content_boundary_invalid',
  );
  addReason(
    reasons,
    responsePackage?.protectedContentExcluded !== true,
    'sponsor_cro_response_package_protected_boundary_invalid',
  );

  return {
    artifactEvidenceIds,
    generatedAtHlc: responsePackage?.generatedAtHlc ?? null,
    packageHash: hasText(responsePackage?.packageHash) ? responsePackage.packageHash : null,
    packageRef: hasText(responsePackage?.packageRef) ? responsePackage.packageRef : null,
    recipientTenantId: hasText(responsePackage?.recipientTenantId) ? responsePackage.recipientTenantId : null,
    requestRef: hasText(responsePackage?.requestRef) ? responsePackage.requestRef : null,
    workItemRef: hasText(responsePackage?.workItemRef) ? responsePackage.workItemRef : null,
  };
}

function evaluateSponsorCroRequestEvidence(input, responsePackage, reasons) {
  const evidence = input?.sponsorCroRequestEvidence;

  addReason(reasons, evidence === null || evidence === undefined, 'sponsor_cro_request_evidence_absent');
  addReason(reasons, !hasText(evidence?.requestRef), 'sponsor_cro_request_ref_absent');
  addReason(reasons, !isDigest(evidence?.requestHash), 'sponsor_cro_request_hash_invalid');
  addReason(
    reasons,
    !SPONSOR_CRO_REQUESTER_CLASSES.has(evidence?.requesterClass),
    'sponsor_cro_requester_class_invalid',
  );
  addReason(reasons, !hasText(evidence?.workItemRef), 'sponsor_cro_work_item_ref_absent');
  addReason(
    reasons,
    !SPONSOR_CRO_WORK_ITEM_STATUSES.has(evidence?.workItemStatus),
    'sponsor_cro_work_item_status_invalid',
  );
  addReason(reasons, !hasText(evidence?.disclosureEventRef), 'sponsor_cro_disclosure_event_ref_absent');
  addReason(reasons, !isDigest(evidence?.disclosureLogHash), 'sponsor_cro_disclosure_log_hash_invalid');
  addReason(reasons, !hasText(evidence?.decisionForumMatterRef), 'sponsor_cro_decision_forum_matter_absent');
  addReason(reasons, !isDigest(evidence?.humanReviewHash), 'sponsor_cro_human_review_hash_invalid');
  addReason(reasons, !isDigest(evidence?.responsePackageHash), 'sponsor_cro_response_package_hash_invalid');
  addReason(
    reasons,
    hasText(evidence?.responsePackageHash) && evidence.responsePackageHash !== responsePackage.packageHash,
    'sponsor_cro_response_package_hash_mismatch',
  );
  addReason(
    reasons,
    evidence?.linkedRecipientTenantId !== input?.recipientTenantId,
    'sponsor_cro_request_recipient_mismatch',
  );
  addReason(reasons, evidence?.metadataOnly !== true, 'sponsor_cro_request_metadata_boundary_invalid');
  addReason(
    reasons,
    evidence?.sourcePayloadExcluded !== true,
    'sponsor_cro_request_source_payload_boundary_invalid',
  );
  addReason(
    reasons,
    evidence?.protectedContentExcluded !== true,
    'sponsor_cro_request_protected_boundary_invalid',
  );
  addReason(reasons, evidence?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(evidence?.linkedAtHlc) === null, 'sponsor_cro_request_link_time_invalid');
  addReason(
    reasons,
    hlcAfter(evidence?.linkedAtHlc, input?.manifestHlc),
    'sponsor_cro_request_link_after_manifest',
  );

  return {
    decisionForumMatterRef: hasText(evidence?.decisionForumMatterRef) ? evidence.decisionForumMatterRef : null,
    disclosureEventRef: hasText(evidence?.disclosureEventRef) ? evidence.disclosureEventRef : null,
    disclosureLogHash: hasText(evidence?.disclosureLogHash) ? evidence.disclosureLogHash : null,
    humanReviewHash: hasText(evidence?.humanReviewHash) ? evidence.humanReviewHash : null,
    linkedAtHlc: evidence?.linkedAtHlc ?? null,
    linkedRecipientTenantId: hasText(evidence?.linkedRecipientTenantId) ? evidence.linkedRecipientTenantId : null,
    requestHash: hasText(evidence?.requestHash) ? evidence.requestHash : null,
    requesterClass: hasText(evidence?.requesterClass) ? evidence.requesterClass : null,
    requestRef: hasText(evidence?.requestRef) ? evidence.requestRef : null,
    responsePackageHash: hasText(evidence?.responsePackageHash) ? evidence.responsePackageHash : null,
    workItemRef: hasText(evidence?.workItemRef) ? evidence.workItemRef : null,
    workItemStatus: hasText(evidence?.workItemStatus) ? evidence.workItemStatus : null,
  };
}

function buildReceipt(input, manifestId, manifestArtifacts, sponsorCroRequestEvidence, responsePackage) {
  const artifactHash = sha256Hex({
    manifestId,
    recipientTenantId: input.recipientTenantId,
    artifacts: manifestArtifacts,
    responsePackageHash: responsePackage.packageHash,
    sponsorCroRequestEvidence,
  });

  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'sponsor_cro_diligence_export',
    artifactVersion: `${input.recipientTenantId}@${input.manifestHlc.physicalMs}.${input.manifestHlc.logical}`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.manifestHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['sponsor_diligence', 'metadata_only', 'quality_evidence'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function buildDiligenceExportManifest(input) {
  validateProtectedContentBoundary(input);
  const manifestArtifacts = normalizeManifestArtifacts(input?.artifacts);
  const governedDecision = evaluateGovernedAction({
    action: 'sponsor_export',
    tenantId: input?.tenantId,
    targetTenantId: input?.targetTenantId,
    actor: input?.actor,
    authority: input?.authority,
    consent: input?.consent,
    evidenceBundle: { complete: true, phiBoundaryAttested: true },
  });
  const reasons = [...governedDecision.reasons];
  const normalizedResponsePackage = evaluateResponsePackage(input, manifestArtifacts, reasons);
  const sponsorCroRequestEvidence = evaluateSponsorCroRequestEvidence(input, normalizedResponsePackage, reasons);
  evaluateExportGrant(input, reasons);

  const denied = reasons.length > 0;
  const manifestId = `cmde_${sha256Hex({
    tenantId: input?.tenantId,
    recipientTenantId: input?.recipientTenantId,
    manifestHlc: input?.manifestHlc,
    artifacts: manifestArtifacts,
    responsePackageHash: normalizedResponsePackage.packageHash,
    sponsorCroRequestRef: sponsorCroRequestEvidence.requestRef,
    sponsorCroWorkItemRef: sponsorCroRequestEvidence.workItemRef,
  }).slice(0, 32)}`;

  return {
    schema: 'cybermedica.diligence_export_manifest.v1',
    manifestId,
    decision: denied ? 'denied' : 'permitted',
    failClosed: denied,
    reasons: [...new Set(reasons)].sort(),
    tenantId: input?.tenantId,
    recipientTenantId: input?.recipientTenantId,
    manifestArtifacts,
    responsePackageHash: sponsorCroRequestEvidence.responsePackageHash,
    sponsorCroRequestRefs: sponsorCroRequestEvidence.requestRef === null ? [] : [sponsorCroRequestEvidence.requestRef],
    sponsorCroWorkItemRefs: sponsorCroRequestEvidence.workItemRef === null ? [] : [sponsorCroRequestEvidence.workItemRef],
    controlledRequestEvidence: sponsorCroRequestEvidence,
    trustState: 'inactive',
    exochainProductionClaim: false,
    receipt: denied ? null : buildReceipt(input, manifestId, manifestArtifacts, sponsorCroRequestEvidence, normalizedResponsePackage),
  };
}
