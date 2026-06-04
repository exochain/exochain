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
const REGULATORY_SUPPORT_SCHEMA = 'cybermedica.regulatory_submission_support.v1';
const REQUIRED_PERMISSION = 'regulatory_submission_support';

const REQUIRED_READINESS_DOMAINS = Object.freeze([
  'consent_form_approvals',
  'continuing_reviews',
  'document_versioning',
  'iec_irb_approvals',
  'investigator_documents',
  'protocol_amendments',
  'regulatory_document_inventory',
  'sponsor_regulatory_exports',
]);

const REQUIRED_DOCUMENT_FAMILIES = Object.freeze([
  'consent_form',
  'continuing_review',
  'iec_irb_approval',
  'investigator_document',
  'protocol_amendment',
  'protocol_document',
  'sponsor_export_manifest',
]);

const REQUIRED_EXPORT_FAMILIES = Object.freeze([
  'amendment_packet',
  'consent_form_packet',
  'continuing_review_packet',
  'ethics_approval_packet',
  'investigator_document_packet',
  'sponsor_regulatory_export_manifest',
]);

const POLICY_STATUSES = new Set(['active']);
const READINESS_STATUSES = new Set(['complete']);
const DOCUMENT_STATUSES = new Set(['current_approved']);
const ETHICS_TRACKING_STATUSES = new Set(['current']);
const VERSIONING_STATUSES = new Set(['controlled']);
const EXPORT_GRANT_STATUSES = new Set(['active']);
const HUMAN_AUTHORIZATION_STATUSES = new Set(['approved']);
const ALLOWED_EXPORT_PURPOSES = new Set(['regulatory_document_readiness', 'sponsor_regulatory_support']);
const EXPORT_CONTROL_TYPES = new Set([
  'sponsor_diligence_packet',
  'sponsor_regulatory_export_manifest',
  'structured_data_export',
]);
const SPONSOR_CRO_REQUESTER_CLASSES = new Set(['cro', 'sponsor']);
const SPONSOR_CRO_WORK_ITEM_STATUSES = new Set([
  'approved_for_response',
  'disclosure_logged',
  'human_reviewed',
  'response_packaged',
]);

const RAW_REGULATORY_SUPPORT_FIELDS = new Set([
  'approvalletterbody',
  'consentformbody',
  'documentbody',
  'documentcontent',
  'documenttext',
  'freetext',
  'freetextnote',
  'investigatordocumentbody',
  'participantlisting',
  'protocolbody',
  'rawapprovalletter',
  'rawconsentform',
  'rawdocument',
  'rawdocumentbody',
  'rawexportcontent',
  'rawirbletter',
  'rawprotocol',
  'rawprotocolbody',
  'rawrequest',
  'rawresponsepackage',
  'rawregulatorycontent',
  'rawsponsorrequest',
  'rawsponsorrequestbody',
  'rawsubmission',
  'rawsubmissionpacket',
  'responsepackagebody',
  'rawsourcedocument',
  'regulatorynarrative',
  'sourcebody',
  'sourcedocumentbody',
  'submissionbody',
  'submissioncontent',
  'submissionpacketbody',
]);

const SECRET_REGULATORY_SUPPORT_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credential',
  'credentialsecret',
  'integrationsecret',
  'password',
  'privatekey',
  'railwaytoken',
  'refreshtoken',
  'rootkey',
  'rootsigningkey',
  'secret',
  'servicetoken',
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

function assertNoRawRegulatorySupportContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawRegulatorySupportContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_REGULATORY_SUPPORT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw regulatory submission support content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_REGULATORY_SUPPORT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`regulatory submission support secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawRegulatorySupportContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawRegulatorySupportContent(input ?? {});
  canonicalize(input ?? {});
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function optionalTextList(value) {
  return hasText(value) ? [value] : [];
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

function hlcBefore(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) < 0;
}

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent' || input?.aiAssistance?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'regulatory_submission_support_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateRequiredSet(actual, expected, missingPrefix, unsupportedPrefix, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !expected.includes(value), `${unsupportedPrefix}:${value}`);
  }
}

function evaluatePolicy(policy, reasons) {
  const requiredReadinessDomains = sortedTextList(policy?.requiredReadinessDomains);
  const requiredExportFamilies = sortedTextList(policy?.requiredExportFamilies);
  const allowedExportPurposes = sortedTextList(policy?.allowedExportPurposes);

  addReason(reasons, !hasText(policy?.policyRef), 'readiness_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'readiness_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'readiness_policy_not_active');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'readiness_policy_time_invalid');
  addReason(reasons, policy?.metadataOnly !== true, 'readiness_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'readiness_policy_protected_boundary_invalid');
  evaluateRequiredSet(
    requiredReadinessDomains,
    REQUIRED_READINESS_DOMAINS,
    'policy_readiness_domain_missing',
    'policy_readiness_domain_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    requiredExportFamilies,
    REQUIRED_EXPORT_FAMILIES,
    'policy_export_family_missing',
    'policy_export_family_unsupported',
    reasons,
  );
  for (const purpose of allowedExportPurposes) {
    addReason(reasons, !ALLOWED_EXPORT_PURPOSES.has(purpose), `policy_export_purpose_unsupported:${purpose}`);
  }

  return { allowedExportPurposes };
}

function evaluateRegulatoryCycle(input, reasons) {
  const cycle = input?.regulatoryCycle;
  addReason(reasons, !hasText(cycle?.cycleRef), 'cycle_ref_absent');
  addReason(reasons, !hasText(cycle?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(cycle?.studyRef), 'study_ref_absent');
  addReason(reasons, !hasText(cycle?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, hlcTuple(cycle?.openedAtHlc) === null, 'cycle_open_time_invalid');
  addReason(reasons, hlcTuple(cycle?.inventoryLockedAtHlc) === null, 'cycle_inventory_lock_time_invalid');
  addReason(reasons, hlcTuple(cycle?.packageCompiledAtHlc) === null, 'cycle_package_compile_time_invalid');
  addReason(reasons, hlcTuple(cycle?.humanReviewedAtHlc) === null, 'cycle_human_review_time_invalid');
  addReason(reasons, hlcBefore(cycle?.openedAtHlc, input?.readinessPolicy?.evaluatedAtHlc), 'cycle_opened_before_policy');
  addReason(reasons, hlcBefore(cycle?.inventoryLockedAtHlc, cycle?.openedAtHlc), 'cycle_inventory_lock_before_open');
  addReason(reasons, hlcBefore(cycle?.packageCompiledAtHlc, cycle?.inventoryLockedAtHlc), 'cycle_package_before_inventory_lock');
  addReason(reasons, hlcBefore(cycle?.humanReviewedAtHlc, cycle?.packageCompiledAtHlc), 'cycle_human_review_before_package');
  addReason(reasons, cycle?.metadataOnly !== true, 'cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'cycle_protected_boundary_invalid');
  addReason(reasons, cycle?.noRegulatoryStrategyClaim !== true, 'regulatory_strategy_boundary_absent');
  addReason(reasons, cycle?.statutoryAuthorityNotReplaced !== true, 'statutory_authority_boundary_absent');
  addReason(reasons, cycle?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function evaluateReadinessEvidence(input, reasons) {
  const rows = Array.isArray(input?.readinessEvidence) ? input.readinessEvidence : [];
  const sortedRows = [...rows].sort((left, right) => String(left?.domain ?? '').localeCompare(String(right?.domain ?? '')));
  const presentDomains = sortedTextList(sortedRows.map((row) => row?.domain));

  evaluateRequiredSet(
    presentDomains,
    REQUIRED_READINESS_DOMAINS,
    'readiness_domain_missing',
    'readiness_domain_unsupported',
    reasons,
  );
  for (const row of sortedRows) {
    const domain = row?.domain ?? 'unknown';
    addReason(reasons, !READINESS_STATUSES.has(row?.status), `readiness_domain_not_complete:${domain}`);
    addReason(reasons, !isDigest(row?.evidenceHash), `readiness_evidence_hash_invalid:${domain}`);
    addReason(reasons, !hasText(row?.reviewedByDid), `readiness_reviewer_absent:${domain}`);
    addReason(reasons, hlcTuple(row?.reviewedAtHlc) === null, `readiness_review_time_invalid:${domain}`);
    addReason(reasons, row?.metadataOnly !== true, `readiness_metadata_boundary_invalid:${domain}`);
    addReason(reasons, row?.protectedContentExcluded !== true, `readiness_protected_boundary_invalid:${domain}`);
  }

  return presentDomains;
}

function evaluateDocumentInventory(input, reasons) {
  const documents = Array.isArray(input?.documentInventory) ? input.documentInventory : [];
  const sortedDocuments = [...documents].sort((left, right) =>
    String(left?.family ?? '').localeCompare(String(right?.family ?? '')) ||
    String(left?.documentRef ?? '').localeCompare(String(right?.documentRef ?? '')),
  );
  const presentFamilies = sortedTextList(sortedDocuments.map((document) => document?.family));

  evaluateRequiredSet(
    presentFamilies,
    REQUIRED_DOCUMENT_FAMILIES,
    'document_family_missing',
    'document_family_unsupported',
    reasons,
  );
  for (const document of sortedDocuments) {
    const ref = document?.documentRef ?? document?.family ?? 'unknown';
    addReason(reasons, !hasText(document?.documentRef), 'document_ref_absent');
    addReason(reasons, !hasText(document?.currentVersionRef), `document_current_version_absent:${ref}`);
    addReason(reasons, !DOCUMENT_STATUSES.has(document?.status), `document_status_not_current_approved:${ref}`);
    addReason(reasons, !isDigest(document?.artifactHash), `document_artifact_hash_invalid:${ref}`);
    addReason(reasons, !isDigest(document?.approvalEvidenceHash), `document_approval_hash_invalid:${ref}`);
    addReason(reasons, !hasText(document?.ownerDid), `document_owner_absent:${ref}`);
    addReason(reasons, hlcTuple(document?.reviewedAtHlc) === null, `document_review_time_invalid:${ref}`);
    addReason(reasons, document?.metadataOnly !== true, `document_metadata_boundary_invalid:${ref}`);
    addReason(reasons, document?.protectedContentExcluded !== true, `document_protected_boundary_invalid:${ref}`);
  }

  return presentFamilies;
}

function evaluateEthicsTracking(tracking, reasons) {
  addReason(reasons, !ETHICS_TRACKING_STATUSES.has(tracking?.status), 'ethics_tracking_not_current');
  addReason(reasons, sortedTextList(tracking?.approvalRefs).length === 0, 'ethics_approval_refs_absent');
  addReason(reasons, sortedTextList(tracking?.amendmentRefs).length === 0, 'protocol_amendment_refs_absent');
  addReason(reasons, sortedTextList(tracking?.consentFormRefs).length === 0, 'consent_form_approval_refs_absent');
  addReason(reasons, sortedTextList(tracking?.continuingReviewRefs).length === 0, 'continuing_review_refs_absent');
  addReason(reasons, !isDigest(tracking?.trackingHash), 'ethics_tracking_hash_invalid');
  addReason(reasons, hlcTuple(tracking?.evaluatedAtHlc) === null, 'ethics_tracking_time_invalid');
  addReason(reasons, tracking?.metadataOnly !== true, 'ethics_tracking_metadata_boundary_invalid');
  addReason(reasons, tracking?.protectedContentExcluded !== true, 'ethics_tracking_protected_boundary_invalid');
}

function evaluateDocumentVersioning(versioning, reasons) {
  addReason(reasons, !VERSIONING_STATUSES.has(versioning?.status), 'document_versioning_not_controlled');
  addReason(reasons, !isDigest(versioning?.lineageHash), 'document_versioning_lineage_hash_invalid');
  addReason(reasons, !isDigest(versioning?.supersessionLogHash), 'document_versioning_supersession_hash_invalid');
  addReason(reasons, versioning?.obsoleteUseBlocked !== true, 'obsolete_document_use_not_blocked');
  addReason(reasons, versioning?.currentApprovedVersionsOnly !== true, 'current_approved_versions_only_absent');
  addReason(reasons, versioning?.versionControlActive !== true, 'version_control_not_active');
  addReason(reasons, hlcTuple(versioning?.reviewedAtHlc) === null, 'document_versioning_review_time_invalid');
  addReason(reasons, versioning?.metadataOnly !== true, 'document_versioning_metadata_boundary_invalid');
  addReason(reasons, versioning?.protectedContentExcluded !== true, 'document_versioning_protected_boundary_invalid');
}

function evaluateExportPackage(input, allowedExportPurposes, reasons) {
  const pkg = input?.exportPackage;
  const exportFamilies = Array.isArray(pkg?.exportFamilies) ? pkg.exportFamilies : [];
  const sortedFamilies = [...exportFamilies].sort((left, right) =>
    String(left?.family ?? '').localeCompare(String(right?.family ?? '')) ||
    String(left?.sourcePackageRef ?? '').localeCompare(String(right?.sourcePackageRef ?? '')),
  );
  const presentFamilies = sortedTextList(sortedFamilies.map((family) => family?.family));

  addReason(reasons, !hasText(pkg?.packageRef), 'export_package_ref_absent');
  addReason(reasons, !allowedExportPurposes.includes(pkg?.purpose), 'export_purpose_not_allowed');
  addReason(reasons, !hasText(pkg?.recipientTenantId), 'export_recipient_tenant_absent');
  addReason(reasons, !EXPORT_GRANT_STATUSES.has(pkg?.exportGrantStatus), 'export_grant_not_active');
  addReason(reasons, !isDigest(pkg?.manifestHash), 'export_manifest_hash_invalid');
  addReason(reasons, !isDigest(pkg?.disclosureLogHash), 'export_disclosure_log_hash_invalid');
  addReason(reasons, !isDigest(pkg?.suppressionLogHash), 'export_suppression_log_hash_invalid');
  addReason(reasons, pkg?.regulatoryStrategyClaim === true, 'regulatory_strategy_claim_forbidden');
  addReason(reasons, pkg?.statutoryFilingClaim === true, 'statutory_submission_authority_claim_forbidden');
  addReason(reasons, pkg?.protectedContentSuppressed !== true, 'export_protected_content_not_suppressed');
  addReason(reasons, pkg?.directIdentifiersSuppressed !== true, 'export_direct_identifiers_not_suppressed');
  addReason(reasons, pkg?.sponsorConfidentialMinimized !== true, 'export_sponsor_confidential_not_minimized');
  addReason(reasons, pkg?.metadataOnly !== true, 'export_package_metadata_boundary_invalid');
  addReason(reasons, pkg?.protectedContentExcluded !== true, 'export_package_protected_boundary_invalid');
  evaluateRequiredSet(presentFamilies, REQUIRED_EXPORT_FAMILIES, 'export_family_missing', 'export_family_unsupported', reasons);

  for (const family of sortedFamilies) {
    const ref = family?.sourcePackageRef ?? family?.family ?? 'unknown';
    addReason(reasons, !isDigest(family?.manifestHash), `export_family_manifest_hash_invalid:${ref}`);
    addReason(reasons, !hasText(family?.sourcePackageRef), `export_family_source_ref_absent:${family?.family ?? 'unknown'}`);
    addReason(reasons, family?.metadataOnly !== true, `export_family_metadata_boundary_invalid:${ref}`);
    addReason(reasons, family?.protectedContentExcluded !== true, `export_family_protected_boundary_invalid:${ref}`);
  }

  return presentFamilies;
}

function requiresExportControlEvidence(input, exportFamilies) {
  return (
    input?.exportPackage?.purpose === 'sponsor_regulatory_support' ||
    exportFamilies.includes('sponsor_regulatory_export_manifest')
  );
}

function evaluateHumanAuthorization(input, reasons) {
  const authorization = input?.humanAuthorization;
  addReason(reasons, !HUMAN_AUTHORIZATION_STATUSES.has(authorization?.status), 'human_authorization_invalid');
  addReason(reasons, !hasText(authorization?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, !isDigest(authorization?.reviewHash), 'human_review_hash_invalid');
  addReason(reasons, hlcTuple(authorization?.approvedAtHlc) === null, 'human_authorization_time_invalid');
  addReason(
    reasons,
    hlcAfter(authorization?.approvedAtHlc, input?.regulatoryCycle?.packageCompiledAtHlc),
    'human_authorization_after_package_compile',
  );
  addReason(reasons, authorization?.metadataOnly !== true, 'human_authorization_metadata_boundary_invalid');
  addReason(reasons, authorization?.protectedContentExcluded !== true, 'human_authorization_protected_boundary_invalid');
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance?.used !== true) {
    return;
  }
  addReason(reasons, aiAssistance?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, !isDigest(aiAssistance?.scopeHash), 'ai_scope_hash_invalid');
  addReason(reasons, sortedTextList(aiAssistance?.evidenceRefs).length === 0, 'ai_evidence_refs_absent');
  addReason(reasons, sortedTextList(aiAssistance?.limitationHashes).some((hash) => !isDigest(hash)), 'ai_limitation_hash_invalid');
}

function evaluateSponsorCroRequestEvidence(input, exportControlEvidence, required, reasons) {
  const evidence = exportControlEvidence?.controlledRequestEvidence;
  if (!required && (evidence === null || evidence === undefined)) {
    return null;
  }

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
  addReason(
    reasons,
    hasText(evidence?.disclosureLogHash) && evidence.disclosureLogHash !== input?.exportPackage?.disclosureLogHash,
    'sponsor_cro_disclosure_log_hash_mismatch',
  );
  addReason(reasons, !hasText(evidence?.decisionForumMatterRef), 'sponsor_cro_decision_forum_matter_absent');
  addReason(reasons, !isDigest(evidence?.humanReviewHash), 'sponsor_cro_human_review_hash_invalid');
  addReason(
    reasons,
    hasText(evidence?.humanReviewHash) && evidence.humanReviewHash !== input?.humanAuthorization?.reviewHash,
    'sponsor_cro_human_review_hash_mismatch',
  );
  addReason(reasons, !isDigest(evidence?.responsePackageHash), 'sponsor_cro_response_package_hash_invalid');
  addReason(
    reasons,
    hasText(evidence?.responsePackageHash) && evidence.responsePackageHash !== exportControlEvidence?.responsePackageHash,
    'sponsor_cro_response_package_hash_mismatch',
  );
  addReason(
    reasons,
    evidence?.linkedRecipientTenantId !== input?.exportPackage?.recipientTenantId,
    'sponsor_cro_request_recipient_mismatch',
  );
  addReason(
    reasons,
    evidence?.linkedExportRef !== exportControlEvidence?.packageRef,
    'sponsor_cro_linked_export_mismatch',
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
    hlcAfter(evidence?.linkedAtHlc, exportControlEvidence?.generatedAtHlc),
    'sponsor_cro_request_link_after_export_control',
  );

  return {
    decisionForumMatterRef: hasText(evidence?.decisionForumMatterRef) ? evidence.decisionForumMatterRef : null,
    disclosureEventRef: hasText(evidence?.disclosureEventRef) ? evidence.disclosureEventRef : null,
    disclosureLogHash: hasText(evidence?.disclosureLogHash) ? evidence.disclosureLogHash : null,
    humanReviewHash: hasText(evidence?.humanReviewHash) ? evidence.humanReviewHash : null,
    linkedAtHlc: evidence?.linkedAtHlc ?? null,
    linkedExportRef: hasText(evidence?.linkedExportRef) ? evidence.linkedExportRef : null,
    linkedRecipientTenantId: hasText(evidence?.linkedRecipientTenantId) ? evidence.linkedRecipientTenantId : null,
    requestHash: hasText(evidence?.requestHash) ? evidence.requestHash : null,
    requesterClass: hasText(evidence?.requesterClass) ? evidence.requesterClass : null,
    requestRef: hasText(evidence?.requestRef) ? evidence.requestRef : null,
    responsePackageHash: hasText(evidence?.responsePackageHash) ? evidence.responsePackageHash : null,
    workItemRef: hasText(evidence?.workItemRef) ? evidence.workItemRef : null,
    workItemStatus: hasText(evidence?.workItemStatus) ? evidence.workItemStatus : null,
  };
}

function evaluateExportControlEvidence(input, required, reasons) {
  const evidence = input?.exportControlEvidence;
  if (!required && (evidence === null || evidence === undefined)) {
    return null;
  }

  addReason(reasons, evidence === null || evidence === undefined, 'export_control_evidence_absent');
  addReason(reasons, !hasText(evidence?.packageRef), 'export_control_package_ref_absent');
  addReason(reasons, !isDigest(evidence?.packageHash), 'export_control_package_hash_invalid');
  addReason(reasons, !hasText(evidence?.exportRef), 'export_control_ref_absent');
  addReason(reasons, evidence?.exportRef !== evidence?.packageRef, 'export_control_ref_mismatch');
  addReason(reasons, !EXPORT_CONTROL_TYPES.has(evidence?.exportType), 'export_control_type_invalid');
  addReason(reasons, evidence?.purpose !== input?.exportPackage?.purpose, 'export_control_purpose_mismatch');
  addReason(
    reasons,
    evidence?.recipientTenantId !== input?.exportPackage?.recipientTenantId,
    'export_control_recipient_mismatch',
  );
  addReason(reasons, !isDigest(evidence?.disclosureLogHash), 'export_control_disclosure_log_hash_invalid');
  addReason(
    reasons,
    hasText(evidence?.disclosureLogHash) && evidence.disclosureLogHash !== input?.exportPackage?.disclosureLogHash,
    'export_control_disclosure_log_hash_mismatch',
  );
  addReason(reasons, !isDigest(evidence?.suppressionLogHash), 'export_control_suppression_log_hash_invalid');
  addReason(
    reasons,
    hasText(evidence?.suppressionLogHash) && evidence.suppressionLogHash !== input?.exportPackage?.suppressionLogHash,
    'export_control_suppression_log_hash_mismatch',
  );
  addReason(reasons, !hasText(evidence?.responsePackageRef), 'sponsor_cro_response_package_ref_absent');
  addReason(reasons, !isDigest(evidence?.responsePackageHash), 'sponsor_cro_response_package_hash_invalid');
  addReason(reasons, hlcTuple(evidence?.generatedAtHlc) === null, 'export_control_time_invalid');
  addReason(
    reasons,
    hlcAfter(evidence?.generatedAtHlc, input?.regulatoryCycle?.packageCompiledAtHlc),
    'export_control_after_package_compile',
  );
  addReason(reasons, evidence?.metadataOnly !== true, 'export_control_metadata_boundary_invalid');
  addReason(
    reasons,
    evidence?.sourcePayloadExcluded !== true,
    'export_control_source_payload_boundary_invalid',
  );
  addReason(reasons, evidence?.rawContentExcluded !== true, 'export_control_raw_content_boundary_invalid');
  addReason(reasons, evidence?.protectedContentExcluded !== true, 'export_control_protected_boundary_invalid');
  addReason(reasons, evidence?.productionTrustClaim === true, 'production_trust_claim_forbidden');

  const controlledRequestEvidence = evaluateSponsorCroRequestEvidence(input, evidence, required, reasons);

  return {
    controlledRequestEvidence,
    disclosureLogHash: hasText(evidence?.disclosureLogHash) ? evidence.disclosureLogHash : null,
    exportRef: hasText(evidence?.exportRef) ? evidence.exportRef : null,
    exportType: hasText(evidence?.exportType) ? evidence.exportType : null,
    generatedAtHlc: evidence?.generatedAtHlc ?? null,
    packageHash: hasText(evidence?.packageHash) ? evidence.packageHash : null,
    packageRef: hasText(evidence?.packageRef) ? evidence.packageRef : null,
    purpose: hasText(evidence?.purpose) ? evidence.purpose : null,
    recipientTenantId: hasText(evidence?.recipientTenantId) ? evidence.recipientTenantId : null,
    responsePackageHash: hasText(evidence?.responsePackageHash) ? evidence.responsePackageHash : null,
    responsePackageRef: hasText(evidence?.responsePackageRef) ? evidence.responsePackageRef : null,
    suppressionLogHash: hasText(evidence?.suppressionLogHash) ? evidence.suppressionLogHash : null,
  };
}

function buildPackage(input, readinessDomains, documentFamilies, exportFamilies, exportControlEvidence) {
  const cycle = input?.regulatoryCycle ?? {};
  const controlledRequestEvidence = exportControlEvidence?.controlledRequestEvidence ?? null;
  return {
    schema: REGULATORY_SUPPORT_SCHEMA,
    cycleRef: cycle.cycleRef,
    tenantId: input?.tenantId,
    siteRef: cycle.siteRef,
    studyRef: cycle.studyRef,
    protocolRef: cycle.protocolRef,
    readinessDomains,
    documentFamilies,
    exportFamilies,
    ethicsTrackingHash: input?.ethicsTracking?.trackingHash ?? null,
    versionLineageHash: input?.documentVersioning?.lineageHash ?? null,
    exportManifestHash: input?.exportPackage?.manifestHash ?? null,
    exportControlPackageRef: exportControlEvidence?.packageRef ?? null,
    exportControlPackageHash: exportControlEvidence?.packageHash ?? null,
    exportControlRef: exportControlEvidence?.exportRef ?? null,
    responsePackageRef: exportControlEvidence?.responsePackageRef ?? null,
    responsePackageHash: exportControlEvidence?.responsePackageHash ?? null,
    sponsorCroRequestRefs: optionalTextList(controlledRequestEvidence?.requestRef),
    sponsorCroWorkItemRefs: optionalTextList(controlledRequestEvidence?.workItemRef),
    controlledRequestEvidence,
    noRegulatoryStrategyClaim: cycle.noRegulatoryStrategyClaim === true && input?.exportPackage?.regulatoryStrategyClaim !== true,
    statutoryAuthorityNotReplaced: cycle.statutoryAuthorityNotReplaced === true && input?.exportPackage?.statutoryFilingClaim !== true,
    metadataOnly: true,
    productionTrustClaim: false,
  };
}

function buildReceipt(input, pkg, packageHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'regulatory_submission_support',
    artifactVersion: `${pkg.cycleRef}@${input.regulatoryCycle.packageCompiledAtHlc.physicalMs}.${input.regulatoryCycle.packageCompiledAtHlc.logical}`,
    artifactHash: packageHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.regulatoryCycle.packageCompiledAtHlc,
    custodyDigest: input.receiptEvidence.custodyDigest,
    sensitivityTags: ['metadata_only', 'regulatory_support', 'submission_readiness'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function evaluateRegulatorySubmissionSupport(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const { allowedExportPurposes } = evaluatePolicy(input?.readinessPolicy, reasons);
  evaluateRegulatoryCycle(input, reasons);
  const readinessDomains = evaluateReadinessEvidence(input, reasons);
  const documentFamilies = evaluateDocumentInventory(input, reasons);
  evaluateEthicsTracking(input?.ethicsTracking, reasons);
  evaluateDocumentVersioning(input?.documentVersioning, reasons);
  const exportFamilies = evaluateExportPackage(input, allowedExportPurposes, reasons);
  const exportControlEvidence = evaluateExportControlEvidence(
    input,
    requiresExportControlEvidence(input, exportFamilies),
    reasons,
  );
  evaluateHumanAuthorization(input, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.receiptEvidence?.custodyDigest), 'receipt_custody_digest_invalid');
  addReason(reasons, input?.receiptEvidence?.artifactHash !== undefined && !isDigest(input.receiptEvidence.artifactHash), 'receipt_artifact_hash_invalid');

  const packageRecord = buildPackage(input, readinessDomains, documentFamilies, exportFamilies, exportControlEvidence);
  const packageHash = sha256Hex(packageRecord);
  const denied = reasons.length > 0;
  const regulatorySubmissionSupport = {
    ...packageRecord,
    ready: !denied,
    packageHash,
    trustState: 'inactive',
  };

  return {
    schema: REGULATORY_SUPPORT_SCHEMA,
    status: denied ? 'denied' : 'ready',
    failClosed: denied,
    reasons: uniqueReasons(reasons),
    regulatorySubmissionSupport,
    receipt: denied ? null : buildReceipt(input, packageRecord, packageHash),
  };
}
