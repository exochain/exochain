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
const REPORTING_SCHEMA = 'cybermedica.governed_reporting.v1';

const ACTOR_KINDS = new Set(['human', 'service_account']);
const TEMPLATE_KINDS = new Set(['standard', 'custom']);
const TEMPLATE_STATUSES = new Set(['approved']);
const EXPORT_FORMATS = new Set(['csv', 'json', 'markdown', 'pdf', 'word']);
const REQUIRED_REPORT_DOMAINS = new Set([
  'audit',
  'capa',
  'consent_readiness',
  'deviations',
  'equipment',
  'product_accountability',
  'qms_status',
  'risk',
  'site_readiness',
  'sponsor_diligence',
  'training',
]);

const RAW_REPORTING_FIELDS = new Set([
  'analysisnarrative',
  'dashboardpayload',
  'exportbody',
  'exportpayload',
  'freetextreport',
  'participantlisting',
  'rawdataset',
  'rawexport',
  'rawreport',
  'rawreportbody',
  'rawreporttext',
  'rawsource',
  'rawsourcedata',
  'reportbody',
  'reportnarrative',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'sourcepayload',
]);

const SECRET_REPORTING_FIELDS = new Set([
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

function isBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 10_000;
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

function assertNoRawReportingContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawReportingContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_REPORTING_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw reporting content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_REPORTING_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`reporting secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawReportingContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawReportingContent(input ?? {});
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

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function includesAll(needles, haystack) {
  const haystackSet = new Set(haystack);
  return needles.every((needle) => haystackSet.has(needle));
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, !ACTOR_KINDS.has(input?.actor?.kind), 'report_actor_kind_invalid');
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
    !hasAuthorityPermission(input?.authority, 'report_generate') && !hasAuthorityPermission(input?.authority, 'govern'),
    'report_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateApiAccess(apiAccess, reportRequest, reasons) {
  addReason(reasons, !hasText(apiAccess?.accessId), 'api_access_id_absent');
  addReason(reasons, !isDigest(apiAccess?.accessHash), 'api_access_hash_invalid');
  addReason(reasons, apiAccess?.accessHash !== reportRequest?.apiAccessHash, 'api_access_hash_mismatch');
  addReason(reasons, apiAccess?.status !== 'authorized' || apiAccess?.failClosedApiAccess === true, 'api_access_not_authorized');
  addReason(reasons, apiAccess?.family !== 'reporting', 'api_access_family_not_reporting');
  addReason(reasons, apiAccess?.purpose !== 'reporting', 'api_access_purpose_invalid');
  addReason(reasons, !hasText(apiAccess?.endpointRef), 'api_access_endpoint_ref_absent');
  addReason(reasons, !Array.isArray(apiAccess?.scopes) || !apiAccess.scopes.includes('report:generate'), 'api_access_report_scope_absent');
  addReason(reasons, apiAccess?.metadataOnly !== true, 'api_access_metadata_boundary_invalid');
  addReason(reasons, apiAccess?.sourcePayloadsStayExternal !== true, 'api_access_source_payload_boundary_invalid');
  addReason(reasons, apiAccess?.exochainProductionClaim === true, 'production_trust_claim_forbidden');
}

function evaluateTemplate(input, requestedDomains, reasons) {
  const template = input?.reportTemplate;
  const templateDomains = sortedTextList(template?.supportedDomains);

  addReason(reasons, !hasText(template?.templateRef), 'report_template_ref_absent');
  addReason(reasons, !hasText(template?.templateVersion), 'report_template_version_absent');
  addReason(reasons, !TEMPLATE_KINDS.has(template?.templateKind), 'report_template_kind_invalid');
  addReason(reasons, !TEMPLATE_STATUSES.has(template?.status), 'report_template_not_approved');
  addReason(reasons, template?.schemaVersion !== 'cybermedica.governed_report_template.v1', 'report_template_schema_invalid');
  addReason(reasons, !hasText(template?.approvedByDid), 'report_template_approver_absent');
  addReason(reasons, hlcTuple(template?.approvedAtHlc) === null, 'report_template_approval_time_invalid');
  addReason(reasons, !isDigest(template?.templateHash), 'report_template_hash_invalid');
  addReason(reasons, !isDigest(template?.outputProfileHash), 'report_output_profile_hash_invalid');
  addReason(reasons, !isDigest(template?.accessPolicyHash), 'report_access_policy_hash_invalid');
  addReason(reasons, !isDigest(template?.retentionPolicyHash), 'report_retention_policy_hash_invalid');
  addReason(reasons, templateDomains.length === 0, 'report_template_domains_absent');
  addReason(reasons, sortedTextList(template?.supportedFormats).length === 0, 'report_template_formats_absent');
  addReason(reasons, template?.metadataOnly !== true, 'report_template_metadata_boundary_invalid');
  addReason(reasons, template?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcAfter(template?.approvedAtHlc, input?.reportRequest?.requestedAtHlc), 'report_template_approved_after_request');

  for (const domain of requestedDomains) {
    addReason(reasons, !REQUIRED_REPORT_DOMAINS.has(domain), `report_domain_unsupported:${domain}`);
    addReason(reasons, !templateDomains.includes(domain), `template_domain_missing:${domain}`);
  }

  if (template?.templateKind === 'custom') {
    evaluateCustomDefinition(input?.customDefinition, template, requestedDomains, input?.reportRequest, reasons);
  }
}

function evaluateCustomDefinition(customDefinition, template, requestedDomains, request, reasons) {
  const customDomains = sortedTextList(customDefinition?.domains);

  addReason(reasons, customDefinition === null || customDefinition === undefined, 'custom_report_definition_absent');
  addReason(reasons, !hasText(customDefinition?.definitionRef), 'custom_report_definition_ref_absent');
  addReason(reasons, customDefinition?.status !== 'approved', 'custom_report_definition_not_approved');
  addReason(reasons, !hasText(customDefinition?.ownerDid), 'custom_report_owner_absent');
  addReason(reasons, !hasText(customDefinition?.approvedByDid), 'custom_report_approver_absent');
  addReason(reasons, hlcTuple(customDefinition?.approvedAtHlc) === null, 'custom_report_approval_time_invalid');
  addReason(reasons, customDefinition?.sourceTemplateRef !== template?.templateRef, 'custom_report_template_ref_mismatch');
  addReason(reasons, !isDigest(customDefinition?.definitionHash), 'custom_report_definition_hash_invalid');
  addReason(reasons, customDomains.length === 0, 'custom_report_domains_absent');
  addReason(reasons, hlcAfter(customDefinition?.approvedAtHlc, request?.requestedAtHlc), 'custom_report_approved_after_request');

  for (const domain of requestedDomains) {
    addReason(reasons, !customDomains.includes(domain), `custom_report_domain_missing:${domain}`);
  }
}

function evaluateReportRequest(input, requestedDomains, reasons) {
  const request = input?.reportRequest;
  const audienceRefs = sortedTextList(request?.audienceRefs);
  const supportedFormats = sortedTextList(input?.reportTemplate?.supportedFormats);

  addReason(reasons, !hasText(request?.requestRef), 'report_request_ref_absent');
  addReason(reasons, !hasText(request?.reportRef), 'report_ref_absent');
  addReason(reasons, request?.purpose !== 'reporting', 'report_purpose_invalid');
  addReason(reasons, requestedDomains.length === 0, 'report_domains_absent');
  addReason(reasons, !EXPORT_FORMATS.has(request?.requestedFormat), 'report_format_unsupported');
  addReason(reasons, hasText(request?.requestedFormat) && !supportedFormats.includes(request.requestedFormat), 'report_format_not_template_supported');
  addReason(reasons, audienceRefs.length === 0, 'report_audience_absent');
  addReason(reasons, hlcTuple(request?.requestedAtHlc) === null, 'report_request_time_invalid');
  addReason(reasons, hlcTuple(request?.generatedAtHlc) === null, 'report_generation_time_invalid');
  addReason(reasons, hlcTuple(request?.periodStartHlc) === null, 'report_period_start_invalid');
  addReason(reasons, hlcTuple(request?.periodEndHlc) === null, 'report_period_end_invalid');
  addReason(reasons, request?.metadataOnly !== true, 'report_request_metadata_boundary_invalid');
  addReason(reasons, hlcBeforeOrEqual(request?.periodEndHlc, request?.periodStartHlc), 'report_period_not_monotonic');
  addReason(reasons, hlcBeforeOrEqual(request?.generatedAtHlc, request?.requestedAtHlc), 'report_generated_before_request');
  addReason(reasons, hlcBeforeOrEqual(request?.generatedAtHlc, request?.periodEndHlc), 'report_generated_before_period_end');
}

function normalizeDomainRows(rows, requestedDomains, reasons) {
  const requested = new Set(requestedDomains);
  const byDomain = new Map();
  const sourceRows = Array.isArray(rows) ? rows : [];
  addReason(reasons, sourceRows.length === 0, 'report_domain_manifests_absent');

  for (const row of sourceRows) {
    const domain = hasText(row?.domain) ? row.domain : 'unknown';
    addReason(reasons, !hasText(row?.domain), 'domain_ref_absent');
    addReason(reasons, hasText(row?.domain) && !REQUIRED_REPORT_DOMAINS.has(row.domain), `domain_unsupported:${row.domain}`);
    addReason(reasons, byDomain.has(domain), `domain_manifest_duplicate:${domain}`);
    addReason(reasons, !hasText(row?.sourceFamilyRef), `domain_source_family_absent:${domain}`);
    addReason(reasons, !isDigest(row?.sourceManifestHash), `domain_source_manifest_hash_invalid:${domain}`);
    addReason(reasons, !isDigest(row?.evidenceIndexHash), `domain_evidence_index_hash_invalid:${domain}`);
    addReason(reasons, !isDigest(row?.auditTrailHash), `domain_audit_trail_hash_invalid:${domain}`);
    addReason(reasons, !isDigest(row?.custodyDigest), `domain_custody_digest_invalid:${domain}`);
    addReason(reasons, hlcTuple(row?.freshnessHlc) === null, `domain_freshness_time_invalid:${domain}`);
    addReason(reasons, row?.accessDecision !== 'permitted', `domain_access_not_permitted:${domain}`);
    addReason(reasons, !hasText(row?.accessPolicyRef), `domain_access_policy_absent:${domain}`);
    addReason(reasons, row?.metadataOnly !== true, `domain_metadata_boundary_invalid:${domain}`);
    addReason(reasons, row?.phiPiiExcluded !== true, `domain_phi_pii_boundary_invalid:${domain}`);
    addReason(reasons, row?.sponsorConfidentialMinimized !== true, `domain_sponsor_confidential_boundary_invalid:${domain}`);
    addReason(reasons, row?.sourcePayloadExcluded !== true, `domain_source_payload_boundary_invalid:${domain}`);
    addReason(reasons, row?.containsRawContent === true, `domain_raw_content_forbidden:${domain}`);
    byDomain.set(domain, row);
  }

  for (const domain of requested) {
    addReason(reasons, !byDomain.has(domain), `domain_manifest_missing:${domain}`);
  }

  return [...byDomain.entries()]
    .filter(([domain]) => requested.has(domain))
    .map(([domain, row]) => ({
      domain,
      sourceFamilyRef: hasText(row?.sourceFamilyRef) ? row.sourceFamilyRef : null,
      sourceManifestHash: hasText(row?.sourceManifestHash) ? row.sourceManifestHash : null,
      evidenceIndexHash: hasText(row?.evidenceIndexHash) ? row.evidenceIndexHash : null,
      auditTrailHash: hasText(row?.auditTrailHash) ? row.auditTrailHash : null,
      custodyDigest: hasText(row?.custodyDigest) ? row.custodyDigest : null,
      freshnessHlc: row?.freshnessHlc ?? null,
      accessPolicyRef: hasText(row?.accessPolicyRef) ? row.accessPolicyRef : null,
    }))
    .sort((left, right) => left.domain.localeCompare(right.domain));
}

function evaluateDataManifest(input, requestedDomains, reasons) {
  const manifest = input?.dataManifest;
  addReason(reasons, manifest?.schema !== 'cybermedica.report_data_manifest.v1', 'report_data_manifest_schema_invalid');
  addReason(reasons, !isDigest(manifest?.manifestHash), 'report_data_manifest_hash_invalid');
  addReason(reasons, !isDigest(manifest?.custodyDigest), 'report_data_manifest_custody_digest_invalid');
  addReason(reasons, manifest?.metadataOnly !== true, 'report_data_manifest_metadata_boundary_invalid');
  addReason(reasons, manifest?.sourcePayloadsExcluded !== true, 'report_data_manifest_source_payload_boundary_invalid');
  addReason(reasons, manifest?.directIdentifiersExcluded !== true, 'report_data_manifest_identifier_boundary_invalid');

  const domainRows = normalizeDomainRows(manifest?.domainRows, requestedDomains, reasons);
  for (const row of domainRows) {
    addReason(reasons, hlcAfter(row.freshnessHlc, input?.reportRequest?.generatedAtHlc), `domain_freshness_after_report:${row.domain}`);
  }
  return domainRows;
}

function evaluatePrivacyBoundary(boundary, reasons) {
  addReason(reasons, !hasText(boundary?.boundaryRef), 'privacy_boundary_ref_absent');
  addReason(reasons, !isDigest(boundary?.boundaryHash), 'privacy_boundary_hash_invalid');
  addReason(reasons, boundary?.metadataOnly !== true, 'privacy_metadata_boundary_invalid');
  addReason(reasons, boundary?.phiPiiExcluded !== true, 'privacy_phi_pii_boundary_invalid');
  addReason(reasons, boundary?.participantDirectIdentifiersExcluded !== true, 'privacy_participant_identifier_boundary_invalid');
  addReason(reasons, boundary?.sponsorConfidentialMinimized !== true, 'privacy_sponsor_confidential_boundary_invalid');
  addReason(reasons, boundary?.sourcePayloadsStayExternal !== true, 'privacy_source_payload_boundary_invalid');
  addReason(reasons, boundary?.disclosureLogRequired !== true, 'privacy_disclosure_log_requirement_absent');
}

function evaluateDisclosureLog(input, reasons) {
  const log = input?.disclosureLog;
  const audienceRefs = sortedTextList(input?.reportRequest?.audienceRefs);
  const recipientClasses = sortedTextList(log?.recipientClasses);

  addReason(reasons, !hasText(log?.logRef), 'disclosure_log_ref_absent');
  addReason(reasons, !isDigest(log?.disclosureLogHash), 'disclosure_log_hash_invalid');
  addReason(reasons, hlcTuple(log?.loggedAtHlc) === null, 'disclosure_log_time_invalid');
  addReason(reasons, recipientClasses.length === 0, 'disclosure_log_recipient_classes_absent');
  addReason(reasons, !includesAll(audienceRefs, recipientClasses), 'disclosure_log_audience_mismatch');
  addReason(reasons, log?.purpose !== input?.reportRequest?.purpose, 'disclosure_log_purpose_mismatch');
  addReason(reasons, log?.includesRawContent === true, 'disclosure_log_raw_content_forbidden');
  addReason(reasons, hlcBeforeOrEqual(log?.loggedAtHlc, input?.reportRequest?.generatedAtHlc), 'disclosure_log_before_report_generation');
}

function evaluateExportPlan(input, requestedDomains, reasons) {
  const plan = input?.exportPlan;
  addReason(reasons, !hasText(plan?.exportRef), 'export_ref_absent');
  addReason(reasons, plan?.format !== input?.reportRequest?.requestedFormat, 'export_format_mismatch');
  addReason(reasons, !EXPORT_FORMATS.has(plan?.format), 'export_format_unsupported');
  addReason(reasons, !isDigest(plan?.artifactHash), 'export_artifact_hash_invalid');
  addReason(reasons, !isDigest(plan?.evidenceIndexHash), 'export_evidence_index_hash_invalid');
  addReason(reasons, !isDigest(plan?.auditTrailHash), 'export_audit_trail_hash_invalid');
  addReason(reasons, !isDigest(plan?.versionHistoryHash), 'export_version_history_hash_invalid');
  addReason(reasons, !isDigest(plan?.accessLogHash), 'export_access_log_hash_invalid');
  addReason(reasons, !hasText(plan?.retentionRuleRef), 'export_retention_rule_absent');
  addReason(reasons, plan?.structuredExport !== true, 'export_structured_boundary_invalid');
  addReason(reasons, plan?.portableExportSubjectToAccessPolicy !== true, 'export_access_policy_boundary_invalid');
  addReason(reasons, plan?.metadataOnly !== true, 'export_metadata_boundary_invalid');
  addReason(reasons, plan?.rawContentExcluded !== true, 'export_raw_content_boundary_invalid');
  addReason(reasons, plan?.productionTrustClaim === true, 'production_trust_claim_forbidden');

  if (requestedDomains.includes('sponsor_diligence')) {
    evaluateSponsorExportGrant(input?.sponsorExportGrant, reasons);
  }
}

function evaluateSponsorExportGrant(grant, reasons) {
  addReason(reasons, grant === null || grant === undefined, 'sponsor_export_grant_absent');
  addReason(reasons, !hasText(grant?.grantRef), 'sponsor_export_grant_ref_absent');
  addReason(reasons, !isDigest(grant?.grantHash), 'sponsor_export_grant_hash_invalid');
  addReason(reasons, grant?.status !== 'active', 'sponsor_export_grant_not_active');
  addReason(reasons, grant?.scope !== 'sponsor_diligence_report', 'sponsor_export_grant_scope_invalid');
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance === null || aiAssistance === undefined || aiAssistance?.used !== true) {
    return;
  }

  addReason(reasons, aiAssistance.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, sortedTextList(aiAssistance.evidenceRefs).length === 0, 'ai_evidence_refs_absent');
  addReason(reasons, !isDigest(aiAssistance.reasoningSummaryHash), 'ai_reasoning_summary_hash_invalid');
  addReason(reasons, !isBasisPoints(aiAssistance.confidenceBasisPoints), 'ai_confidence_basis_points_invalid');
  addReason(reasons, sortedTextList(aiAssistance.limitationHashes).length === 0, 'ai_limitations_absent');
  for (const hash of sortedTextList(aiAssistance.limitationHashes)) {
    addReason(reasons, !isDigest(hash), 'ai_limitation_hash_invalid');
  }
  for (const hash of sortedTextList(aiAssistance.unresolvedAssumptionHashes)) {
    addReason(reasons, !isDigest(hash), 'ai_unresolved_assumption_hash_invalid');
  }
  addReason(
    reasons,
    sortedTextList(aiAssistance.recommendedHumanReviewerDids).length === 0,
    'ai_recommended_human_reviewers_absent',
  );
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'human_report_reviewer_absent');
  addReason(reasons, review?.status !== 'approved', 'human_report_review_not_approved');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, !isDigest(review?.reviewEvidenceHash), 'human_review_evidence_hash_invalid');
  addReason(reasons, review?.aiFinalAuthorityRejected !== true, 'ai_final_authority_not_rejected');
  addReason(reasons, hlcBeforeOrEqual(review?.reviewedAtHlc, input?.reportRequest?.generatedAtHlc), 'human_review_before_report_generation');
}

function buildReport(input, requestedDomains, domainRows, reasons) {
  const audienceRefs = sortedTextList(input?.reportRequest?.audienceRefs);
  const aiEvidenceRefs = sortedTextList(input?.aiAssistance?.evidenceRefs);
  const aiRecommendedHumanReviewerDids = sortedTextList(input?.aiAssistance?.recommendedHumanReviewerDids);
  const status = reasons.length === 0 ? 'generated' : 'blocked';
  const material = {
    actorDid: hasText(input?.actor?.did) ? input.actor.did : null,
    apiAccessHash: hasText(input?.apiAccess?.accessHash) ? input.apiAccess.accessHash : null,
    audienceRefs,
    customDefinitionHash: hasText(input?.customDefinition?.definitionHash) ? input.customDefinition.definitionHash : null,
    dataManifestHash: hasText(input?.dataManifest?.manifestHash) ? input.dataManifest.manifestHash : null,
    domainRows,
    exportArtifactHash: hasText(input?.exportPlan?.artifactHash) ? input.exportPlan.artifactHash : null,
    format: hasText(input?.reportRequest?.requestedFormat) ? input.reportRequest.requestedFormat : null,
    generatedAtHlc: input?.reportRequest?.generatedAtHlc ?? null,
    periodEndHlc: input?.reportRequest?.periodEndHlc ?? null,
    periodStartHlc: input?.reportRequest?.periodStartHlc ?? null,
    reportRef: hasText(input?.reportRequest?.reportRef) ? input.reportRequest.reportRef : null,
    requestedDomains,
    requestRef: hasText(input?.reportRequest?.requestRef) ? input.reportRequest.requestRef : null,
    templateHash: hasText(input?.reportTemplate?.templateHash) ? input.reportTemplate.templateHash : null,
    templateRef: hasText(input?.reportTemplate?.templateRef) ? input.reportTemplate.templateRef : null,
    templateVersion: hasText(input?.reportTemplate?.templateVersion) ? input.reportTemplate.templateVersion : null,
    tenantId: hasText(input?.tenantId) ? input.tenantId : null,
  };
  const reportHash = sha256Hex(material);

  return {
    schema: 'cybermedica.governed_report_record.v1',
    reportId: `cmgr_${reportHash.slice(0, 32)}`,
    reportHash,
    status,
    tenantId: material.tenantId,
    actorDid: material.actorDid,
    requestRef: material.requestRef,
    reportRef: material.reportRef,
    templateRef: material.templateRef,
    templateKind: hasText(input?.reportTemplate?.templateKind) ? input.reportTemplate.templateKind : null,
    customDefinitionRef: hasText(input?.customDefinition?.definitionRef) ? input.customDefinition.definitionRef : null,
    reportFormat: material.format,
    includedDomains: requestedDomains,
    audienceRefs,
    sourceManifestHashes: domainRows.map((row) => `${row.domain}:${row.sourceManifestHash}`),
    evidenceIndexHashes: domainRows.map((row) => `${row.domain}:${row.evidenceIndexHash}`),
    exportRef: hasText(input?.exportPlan?.exportRef) ? input.exportPlan.exportRef : null,
    exportArtifactHash: material.exportArtifactHash,
    apiAccessId: hasText(input?.apiAccess?.accessId) ? input.apiAccess.accessId : null,
    metadataOnly:
      input?.reportRequest?.metadataOnly === true &&
      input?.dataManifest?.metadataOnly === true &&
      input?.privacyBoundary?.metadataOnly === true &&
      input?.exportPlan?.metadataOnly === true,
    sourcePayloadsStayExternal:
      input?.apiAccess?.sourcePayloadsStayExternal === true &&
      input?.privacyBoundary?.sourcePayloadsStayExternal === true &&
      input?.dataManifest?.sourcePayloadsExcluded === true,
    aiAssisted: input?.aiAssistance?.used === true,
    aiEvidenceRefs,
    aiConfidenceBasisPoints: input?.aiAssistance?.used === true ? input.aiAssistance.confidenceBasisPoints : null,
    aiRecommendedHumanReviewerDids,
    humanReviewerDid: hasText(input?.humanReview?.reviewerDid) ? input.humanReview.reviewerDid : null,
    failClosedReporting: status !== 'generated',
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function buildReceipt(input, report) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: report.reportHash,
    artifactType: 'governed_report',
    artifactVersion: `${input.reportTemplate.templateRef}@${input.reportTemplate.templateVersion}:${input.reportRequest.reportRef}`,
    classification: 'governed_report_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.reportRequest.generatedAtHlc,
    sensitivityTags: [
      'governed_reporting',
      'metadata_only',
      'qms_metadata',
      'sponsor_confidential_metadata',
      'structured_export',
    ],
    sourceSystem: 'cybermedica.governed_reporting',
    tenantId: input.tenantId,
  });
}

export function evaluateGovernedReport(input) {
  assertMetadataOnly(input);

  const reasons = [];
  const requestedDomains = sortedTextList(input?.reportRequest?.requestedDomains);

  evaluateTenantActorAuthority(input, reasons);
  evaluateApiAccess(input?.apiAccess, input?.reportRequest, reasons);
  evaluateTemplate(input, requestedDomains, reasons);
  evaluateReportRequest(input, requestedDomains, reasons);
  const domainRows = evaluateDataManifest(input, requestedDomains, reasons);
  evaluatePrivacyBoundary(input?.privacyBoundary, reasons);
  evaluateDisclosureLog(input, reasons);
  evaluateExportPlan(input, requestedDomains, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  evaluateHumanReview(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'receipt_custody_digest_invalid');

  const uniqueReasons = uniqueSorted(reasons);
  const report = buildReport(input, requestedDomains, domainRows, uniqueReasons);

  if (uniqueReasons.length > 0) {
    return {
      schema: REPORTING_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      denialReasons: uniqueReasons,
      report,
      receipt: null,
    };
  }

  return {
    schema: REPORTING_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    denialReasons: [],
    report,
    receipt: buildReceipt(input, report),
  };
}
