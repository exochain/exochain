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

import { canonicalize, createEvidenceReceipt, ProtectedContentError, sha256Hex } from './qms-contracts.mjs';

const HEX_64 = /^[0-9a-f]{64}$/u;
const REQUIRED_PERMISSION = 'search_retrieve';
const SEARCH_FAMILIES = new Set(['audits', 'capas', 'controls', 'decisions', 'documents', 'evidence', 'risks', 'sites']);
const RAW_SEARCH_FIELDS = new Set([
  'body',
  'content',
  'documenttext',
  'freetextquery',
  'matchedtext',
  'querystring',
  'querytext',
  'rawquery',
  'rawresult',
  'rawresulttext',
  'resultbody',
  'resultsnippet',
  'snippet',
  'sourcebody',
  'sourcedocumenttext',
  'summary',
  'text',
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

function assertNoRawSearchContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawSearchContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    if (RAW_SEARCH_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`raw search content field is not allowed at ${path}.${key}`);
    }
    assertNoRawSearchContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawSearchContent(input ?? {});
  canonicalize(input ?? {});
}

function hlcPresent(hlc) {
  return Number.isSafeInteger(hlc?.physicalMs) && Number.isSafeInteger(hlc?.logical) && hlc.logical >= 0;
}

function hlcComparable(hlc) {
  return Number.isSafeInteger(hlc?.physicalMs) && Number.isSafeInteger(hlc?.logical);
}

function compareHlc(left, right) {
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

function uniqueSorted(value) {
  return [...new Set(value.filter(hasText))].sort();
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
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION), 'authority_permission_missing');
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateQuery(input, reasons) {
  const query = input?.query;
  const requestedFamilies = sortedTextList(query?.requestedFamilies);
  addReason(reasons, !hasText(query?.queryId), 'query_id_absent');
  addReason(reasons, !isDigest(query?.queryHash), 'query_hash_invalid');
  addReason(reasons, !hlcPresent(query?.requestedAtHlc), 'query_request_time_invalid');
  addReason(reasons, requestedFamilies.length === 0, 'requested_families_absent');
  addReason(reasons, !Number.isSafeInteger(query?.maxResults) || query.maxResults <= 0 || query.maxResults > 100, 'query_max_results_invalid');
  addReason(reasons, !hasText(query?.purpose), 'query_purpose_absent');

  for (const family of requestedFamilies) {
    addReason(reasons, !SEARCH_FAMILIES.has(family), `requested_family_unsupported:${family}`);
  }

  const index = query?.searchIndex;
  addReason(reasons, !hasText(index?.indexRef), 'search_index_ref_absent');
  addReason(reasons, !isDigest(index?.indexHash), 'search_index_hash_invalid');
  addReason(reasons, !hlcPresent(index?.builtAtHlc), 'search_index_built_time_invalid');
  addReason(reasons, index?.schemaVersion !== 'cybermedica.search_index.v1', 'search_index_schema_invalid');
  addReason(reasons, index?.metadataOnly !== true, 'search_index_metadata_boundary_invalid');
  addReason(reasons, index?.payloadsExcluded !== true, 'search_index_payload_boundary_invalid');
  addReason(
    reasons,
    hlcComparable(index?.builtAtHlc) &&
      hlcComparable(query?.requestedAtHlc) &&
      compareHlc(index.builtAtHlc, query.requestedAtHlc) > 0,
    'search_index_built_after_query',
  );
}

function evaluateAccessPolicy(input, reasons) {
  const policy = input?.accessPolicy;
  const allowedFamilies = sortedTextList(policy?.allowedFamilies);
  const allowedRoles = sortedTextList(policy?.allowedRoleRefs);
  addReason(reasons, !hasText(policy?.policyRef), 'access_policy_ref_absent');
  addReason(reasons, !hlcPresent(policy?.evaluatedAtHlc), 'access_policy_time_invalid');
  addReason(reasons, allowedFamilies.length === 0, 'access_policy_families_absent');
  addReason(reasons, sortedTextList(policy?.allowedSiteRefs).length === 0, 'access_policy_site_refs_absent');
  addReason(reasons, allowedRoles.length === 0, 'access_policy_role_refs_absent');
  addReason(reasons, sortedTextList(policy?.allowedSensitivityTags).length === 0, 'access_policy_sensitivity_tags_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'access_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.sourcePayloadAccessible !== false, 'access_policy_payload_access_forbidden');
  addReason(reasons, policy?.resultDisclosureRequired !== true, 'access_policy_disclosure_required_absent');

  for (const family of sortedTextList(input?.query?.requestedFamilies)) {
    addReason(reasons, !allowedFamilies.includes(family), `requested_family_not_allowed:${family}`);
  }

  addReason(
    reasons,
    hlcComparable(policy?.evaluatedAtHlc) &&
      hlcComparable(input?.query?.requestedAtHlc) &&
      compareHlc(policy.evaluatedAtHlc, input.query.requestedAtHlc) < 0,
    'access_policy_before_query',
  );
}

function evaluateDisclosureLog(input, reasons) {
  const log = input?.disclosureLog;
  addReason(reasons, !hasText(log?.logId), 'disclosure_log_id_absent');
  addReason(reasons, !hlcPresent(log?.loggedAtHlc), 'disclosure_log_time_invalid');
  addReason(reasons, !isDigest(log?.disclosureLogHash), 'disclosure_log_hash_invalid');
  addReason(reasons, !hasText(log?.purpose), 'disclosure_log_purpose_absent');
  addReason(reasons, log?.purpose !== input?.query?.purpose, 'disclosure_log_purpose_mismatch');
  addReason(reasons, !hasText(log?.recipientClass), 'disclosure_log_recipient_absent');
  addReason(reasons, log?.includesRawContent !== false, 'disclosure_log_raw_content_forbidden');
  addReason(
    reasons,
    hlcComparable(log?.loggedAtHlc) &&
      hlcComparable(input?.accessPolicy?.evaluatedAtHlc) &&
      compareHlc(log.loggedAtHlc, input.accessPolicy.evaluatedAtHlc) < 0,
    'disclosure_log_before_access_policy',
  );
}

function validateRecord(record, query, reasons) {
  const recordId = hasText(record?.recordId) ? record.recordId : 'unknown';
  addReason(reasons, !hasText(record?.recordId), 'record_id_absent');
  addReason(reasons, !SEARCH_FAMILIES.has(record?.family), `record_family_unsupported:${recordId}`);
  addReason(reasons, !hasText(record?.siteRef), `record_site_ref_absent:${recordId}`);
  addReason(reasons, !isDigest(record?.artifactHash), `record_artifact_hash_invalid:${recordId}`);
  addReason(reasons, !isDigest(record?.metadataHash), `record_metadata_hash_invalid:${recordId}`);
  addReason(reasons, !isDigest(record?.custodyDigest), `record_custody_digest_invalid:${recordId}`);
  addReason(reasons, !isDigest(record?.titleHash), `record_title_hash_invalid:${recordId}`);
  addReason(reasons, !hlcPresent(record?.updatedAtHlc), `record_updated_time_invalid:${recordId}`);
  addReason(reasons, record?.matchedQueryHash !== query?.queryHash, `record_match_hash_mismatch:${recordId}`);
  addReason(reasons, !isBasisPoints(record?.matchBasisPoints), `record_match_basis_points_invalid:${recordId}`);
  addReason(reasons, sortedTextList(record?.sensitivityTags).length === 0, `record_sensitivity_tags_absent:${recordId}`);
  addReason(reasons, sortedTextList(record?.allowedRoleRefs).length === 0, `record_allowed_roles_absent:${recordId}`);
  addReason(reasons, record?.boundary?.metadataOnly !== true, `record_metadata_boundary_invalid:${recordId}`);
  addReason(
    reasons,
    record?.boundary?.sourcePayloadAnchored !== false || record?.boundary?.rawContentExcluded !== true,
    `record_payload_boundary_invalid:${recordId}`,
  );
}

function normalizeRecord(record) {
  return {
    artifactHash: record.artifactHash,
    custodyDigest: record.custodyDigest,
    family: record.family,
    linkedAuditRefs: sortedTextList(record.linkedAuditRefs),
    linkedCapaRefs: sortedTextList(record.linkedCapaRefs),
    linkedControlRefs: sortedTextList(record.linkedControlRefs),
    linkedDecisionRefs: sortedTextList(record.linkedDecisionRefs),
    linkedDocumentRefs: sortedTextList(record.linkedDocumentRefs),
    linkedEvidenceRefs: sortedTextList(record.linkedEvidenceRefs),
    linkedRiskRefs: sortedTextList(record.linkedRiskRefs),
    linkedSiteRefs: sortedTextList(record.linkedSiteRefs),
    matchBasisPoints: record.matchBasisPoints,
    metadataHash: record.metadataHash,
    recordId: record.recordId,
    sensitivityTags: sortedTextList(record.sensitivityTags),
    siteRef: record.siteRef,
    updatedAtHlc: record.updatedAtHlc,
  };
}

function normalizeRecords(input, reasons) {
  const records = Array.isArray(input?.records) ? input.records : [];
  addReason(reasons, records.length === 0, 'search_records_absent');
  for (const record of records) {
    validateRecord(record, input?.query, reasons);
  }
  return records.map(normalizeRecord);
}

function intersects(left, right) {
  const rightSet = new Set(right);
  return left.some((value) => rightSet.has(value));
}

function includesAllAllowed(values, allowed) {
  const allowedSet = new Set(allowed);
  return values.every((value) => allowedSet.has(value));
}

function consentActive(consent) {
  if (consent?.required === false && consent?.status === 'not_required') {
    return true;
  }
  return consent?.status === 'active' && consent?.revoked !== true && hasText(consent?.consentRef);
}

function increment(breakdown, key) {
  return {
    ...breakdown,
    [key]: breakdown[key] + 1,
  };
}

function accessDecision(input, record) {
  const policy = input?.accessPolicy ?? {};
  const actorRoles = sortedTextList(input?.actor?.roleRefs);
  const allowedFamilies = sortedTextList(policy.allowedFamilies);
  const allowedSiteRefs = sortedTextList(policy.allowedSiteRefs);
  const allowedRoleRefs = sortedTextList(policy.allowedRoleRefs);
  const allowedSensitivityTags = sortedTextList(policy.allowedSensitivityTags);

  if (!allowedFamilies.includes(record.family)) {
    return 'family';
  }
  if (!allowedSiteRefs.includes(record.siteRef) && !intersects(record.linkedSiteRefs, allowedSiteRefs)) {
    return 'site';
  }
  if (!includesAllAllowed(record.sensitivityTags, allowedSensitivityTags)) {
    return 'sensitivity';
  }
  if (!intersects(actorRoles, allowedRoleRefs) || !intersects(actorRoles, sortedTextList(record.allowedRoleRefs))) {
    return 'role';
  }
  if (record.participantLinked === true && (policy.allowParticipantLinked !== true || !consentActive(input?.consent))) {
    return 'participant';
  }
  return 'permitted';
}

function hasFilter(values) {
  return Array.isArray(values) && values.filter(hasText).length > 0;
}

function recordMatchesFilters(input, record) {
  const filters = input?.query?.filters ?? {};
  if (hasFilter(filters.siteRefs)) {
    const siteRefs = sortedTextList(filters.siteRefs);
    if (!siteRefs.includes(record.siteRef) && !intersects(sortedTextList(record.linkedSiteRefs), siteRefs)) {
      return false;
    }
  }
  if (hasFilter(filters.controlRefs) && !intersects(sortedTextList(record.linkedControlRefs), sortedTextList(filters.controlRefs))) {
    return false;
  }
  if (
    hasFilter(filters.protocolRefs) &&
    !intersects(sortedTextList(record.linkedProtocolRefs), sortedTextList(filters.protocolRefs))
  ) {
    return false;
  }
  if (hasFilter(filters.lifecycleStates) && !sortedTextList(filters.lifecycleStates).includes(record.lifecycleState)) {
    return false;
  }
  return true;
}

function resultSort(left, right) {
  if (left.matchBasisPoints !== right.matchBasisPoints) {
    return right.matchBasisPoints - left.matchBasisPoints;
  }
  return left.recordId.localeCompare(right.recordId);
}

function selectResults(input, records) {
  let suppressedBreakdown = { family: 0, participant: 0, role: 0, sensitivity: 0, site: 0 };
  let omittedByFilterCount = 0;
  const requestedFamilies = sortedTextList(input?.query?.requestedFamilies);
  const candidates = [];

  for (const record of records) {
    if (!requestedFamilies.includes(record.family)) {
      suppressedBreakdown = increment(suppressedBreakdown, 'family');
      continue;
    }

    const restriction = accessDecision(input, record);
    if (restriction !== 'permitted') {
      suppressedBreakdown = increment(suppressedBreakdown, restriction);
      continue;
    }

    if (!recordMatchesFilters(input, record)) {
      omittedByFilterCount += 1;
      continue;
    }

    candidates.push(normalizeRecord(record));
  }

  const maxResults = Number.isSafeInteger(input?.query?.maxResults) && input.query.maxResults > 0 ? input.query.maxResults : 0;
  const results = candidates.sort(resultSort).slice(0, maxResults);
  const objectFamiliesCovered = uniqueSorted(results.map((record) => record.family));

  return {
    objectFamiliesCovered,
    omittedByFilterCount,
    results,
    suppressedBreakdown,
    suppressedResultCount: Object.values(suppressedBreakdown).reduce((total, count) => total + count, 0),
  };
}

function buildResultSetHash(input, selected) {
  return sha256Hex({
    queryHash: input?.query?.queryHash ?? null,
    policyRef: input?.accessPolicy?.policyRef ?? null,
    results: selected.results,
    suppressedBreakdown: selected.suppressedBreakdown,
    omittedByFilterCount: selected.omittedByFilterCount,
  });
}

function buildReceipt(input, resultSetHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'search_retrieval_result_set',
    artifactVersion: `${input.query.queryId}@${input.disclosureLog.loggedAtHlc.physicalMs}.${input.disclosureLog.loggedAtHlc.logical}`,
    artifactHash: sha256Hex({
      disclosureLogHash: input.disclosureLog.disclosureLogHash,
      queryHash: input.query.queryHash,
      resultSetHash,
      searchIndexHash: input.query.searchIndex.indexHash,
    }),
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.disclosureLog.loggedAtHlc,
    custodyDigest: input.disclosureLog.disclosureLogHash,
    sensitivityTags: ['metadata_only', 'search_retrieval', 'quality_evidence'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function evaluateSearchRetrieval(input) {
  assertMetadataOnly(input);
  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateQuery(input, reasons);
  evaluateAccessPolicy(input, reasons);
  evaluateDisclosureLog(input, reasons);
  normalizeRecords(input, reasons);

  const selected = selectResults(input ?? {}, Array.isArray(input?.records) ? input.records : []);
  const resultSetHash = buildResultSetHash(input ?? {}, selected);
  const denied = reasons.length > 0;

  return {
    schema: 'cybermedica.search_retrieval.v1',
    decision: denied ? 'denied' : 'permitted',
    failClosed: denied,
    reasons: uniqueReasons(reasons),
    tenantId: input?.tenantId ?? null,
    queryId: input?.query?.queryId ?? null,
    requestedFamilies: sortedTextList(input?.query?.requestedFamilies),
    objectFamiliesCovered: selected.objectFamiliesCovered,
    resultCount: denied ? 0 : selected.results.length,
    suppressedResultCount: selected.suppressedResultCount,
    suppressedBreakdown: selected.suppressedBreakdown,
    omittedByFilterCount: selected.omittedByFilterCount,
    resultSetHash,
    results: denied ? [] : selected.results,
    disclosureLogRef: input?.disclosureLog?.logId ?? null,
    trustState: 'inactive',
    exochainProductionClaim: false,
    receipt: denied ? null : buildReceipt(input, resultSetHash),
  };
}
