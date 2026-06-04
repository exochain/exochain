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
const REQUIRED_PERMISSION = 'protocol_service_provider_readiness';
const PROVIDER_READINESS_SCHEMA = 'cybermedica.protocol_service_provider_readiness.v1';

const REQUIRED_PROVIDER_CATEGORIES = Object.freeze(['imaging', 'laboratory', 'logistics', 'pharmacy']);

const REQUIRED_REVIEW_DOMAINS = Object.freeze([
  'access_policy',
  'chain_of_custody',
  'contract_scope',
  'data_minimization',
  'privacy_boundary',
  'protocol_fit',
  'qualification',
  'service_level',
]);

const READY_PROVIDER_STATUSES = new Set(['ready']);
const REVIEW_STATUSES = new Set(['verified']);
const PACKAGE_STATUSES = new Set(['ready']);

const RAW_PROVIDER_FIELDS = new Set([
  'couriermanifestbody',
  'directidentifier',
  'drugaccountabilitybody',
  'freetextprovidernote',
  'imagingreportbody',
  'labresultbody',
  'participantname',
  'patientname',
  'pharmacynote',
  'rawcouriermanifest',
  'rawdrugaccountability',
  'rawimagereport',
  'rawlabreport',
  'rawpharmacynote',
  'rawprovidercontent',
  'sourcedocumentbody',
  'specimenresultbody',
]);

const SECRET_PROVIDER_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'apitoken',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'courierapitoken',
  'credentialsecret',
  'integrationsecret',
  'password',
  'privatekey',
  'refreshtoken',
  'rootkey',
  'rootsigningkey',
  'secret',
  'servicetoken',
  'sessionsecret',
  'signaturesecret',
  'signingkey',
  'token',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && value !== ZERO_HASH;
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

function assertNoProviderPayloadsOrSecrets(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoProviderPayloadsOrSecrets(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_PROVIDER_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`protocol service provider source content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_PROVIDER_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`protocol service provider secret field is not allowed at ${path}.${key}`);
    }
    assertNoProviderPayloadsOrSecrets(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoProviderPayloadsOrSecrets(input ?? {});
  canonicalize(input ?? {});
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function uniqueSortedReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function basisPoints(numerator, denominator) {
  if (denominator === 0) {
    return 0;
  }
  return Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [BigInt(hlc.physicalMs), BigInt(hlc.logical)];
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

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function hasAuthorityPermission(authority) {
  return Array.isArray(authority?.permissions) &&
    (authority.permissions.includes(REQUIRED_PERMISSION) || authority.permissions.includes('govern'));
}

function categorySort(left, right) {
  return String(left.category).localeCompare(String(right.category));
}

function domainSort(left, right) {
  return String(left.domain).localeCompare(String(right.domain));
}

function byCategory(providers) {
  const map = new Map();
  for (const provider of Array.isArray(providers) ? providers : []) {
    if (hasText(provider?.category) && !map.has(provider.category)) {
      map.set(provider.category, provider);
    }
  }
  return map;
}

function duplicateCategories(providers) {
  const seen = new Set();
  const duplicates = new Set();
  for (const provider of Array.isArray(providers) ? providers : []) {
    if (!hasText(provider?.category)) {
      continue;
    }
    if (seen.has(provider.category)) {
      duplicates.add(provider.category);
    }
    seen.add(provider.category);
  }
  return [...duplicates].sort();
}

function byDomain(entries) {
  const map = new Map();
  for (const entry of Array.isArray(entries) ? entries : []) {
    if (hasText(entry?.domain) && !map.has(entry.domain)) {
      map.set(entry.domain, entry);
    }
  }
  return map;
}

function duplicateDomains(entries) {
  const seen = new Set();
  const duplicates = new Set();
  for (const entry of Array.isArray(entries) ? entries : []) {
    if (!hasText(entry?.domain)) {
      continue;
    }
    if (seen.has(entry.domain)) {
      duplicates.add(entry.domain);
    }
    seen.add(entry.domain);
  }
  return [...duplicates].sort();
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
  addReason(reasons, !hasAuthorityPermission(input?.authority), 'provider_readiness_authority_missing');
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateReadinessPackage(pkg, reasons) {
  addReason(reasons, !hasText(pkg?.packageRef), 'readiness_package_ref_absent');
  addReason(reasons, !hasText(pkg?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(pkg?.studyRef), 'study_ref_absent');
  addReason(reasons, !hasText(pkg?.siteRef), 'site_ref_absent');
  addReason(reasons, !PACKAGE_STATUSES.has(pkg?.status), 'readiness_package_not_ready');
  addReason(reasons, pkg?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, pkg?.metadataOnly !== true, 'readiness_package_metadata_boundary_invalid');
  addReason(reasons, pkg?.protectedContentExcluded !== true, 'readiness_package_protected_boundary_invalid');
  addReason(reasons, hlcTuple(pkg?.evaluatedAtHlc) === null, 'readiness_package_evaluation_time_invalid');
}

function evaluateProvider(provider, packageHlc, reasons) {
  const category = hasText(provider?.category) ? provider.category : 'unknown';
  addReason(reasons, !REQUIRED_PROVIDER_CATEGORIES.includes(category), `provider_category_unsupported:${category}`);
  addReason(reasons, !hasText(provider?.providerRef), `provider_ref_absent:${category}`);
  addReason(reasons, !READY_PROVIDER_STATUSES.has(provider?.status), `provider_not_ready:${category}`);
  addReason(reasons, !isDigest(provider?.protocolScopeHash), `provider_protocol_scope_hash_invalid:${category}`);
  addReason(reasons, !isDigest(provider?.qualificationEvidenceHash), `provider_qualification_hash_invalid:${category}`);
  addReason(reasons, !isDigest(provider?.contractAgreementHash), `provider_contract_hash_invalid:${category}`);
  addReason(reasons, !isDigest(provider?.serviceLevelHash), `provider_service_level_hash_invalid:${category}`);
  addReason(reasons, !isDigest(provider?.chainOfCustodyHash), `provider_chain_of_custody_hash_invalid:${category}`);
  addReason(reasons, !isDigest(provider?.privacyBoundaryHash), `provider_privacy_boundary_hash_invalid:${category}`);
  addReason(reasons, !isDigest(provider?.accessPolicyHash), `provider_access_policy_hash_invalid:${category}`);
  addReason(reasons, !isDigest(provider?.dataMinimizationHash), `provider_data_minimization_hash_invalid:${category}`);
  addReason(reasons, !isDigest(provider?.escalationPathHash), `provider_escalation_path_hash_invalid:${category}`);
  addReason(reasons, !isDigest(provider?.businessContinuityHash), `provider_business_continuity_hash_invalid:${category}`);
  addReason(
    reasons,
    !isDigest(provider?.sponsorVisibilityPolicyHash),
    `provider_sponsor_visibility_policy_hash_invalid:${category}`,
  );
  addReason(reasons, provider?.metadataOnly !== true, `provider_metadata_boundary_invalid:${category}`);
  addReason(reasons, provider?.protectedContentExcluded !== true, `provider_protected_boundary_invalid:${category}`);
  addReason(reasons, hlcTuple(provider?.reviewedAtHlc) === null, `provider_review_time_invalid:${category}`);
  addReason(
    reasons,
    hlcTuple(packageHlc) !== null && hlcAfter(provider?.reviewedAtHlc, packageHlc),
    `provider_review_after_package_evaluation:${category}`,
  );
}

function normalizeProviders(input, reasons) {
  const providers = Array.isArray(input?.serviceProviders) ? [...input.serviceProviders].sort(categorySort) : [];
  addReason(reasons, providers.length === 0, 'service_providers_absent');

  const providerMap = byCategory(providers);
  for (const category of REQUIRED_PROVIDER_CATEGORIES) {
    addReason(reasons, !providerMap.has(category), `provider_category_missing:${category}`);
  }
  for (const category of duplicateCategories(providers)) {
    addReason(reasons, true, `provider_category_duplicate:${category}`);
  }

  for (const provider of providers) {
    evaluateProvider(provider, input?.readinessPackage?.evaluatedAtHlc, reasons);
  }

  return providers.map((provider) => ({
    category: provider.category,
    providerRef: provider.providerRef,
    status: provider.status,
    reviewedAtHlc: provider.reviewedAtHlc ?? null,
    metadataOnly: provider.metadataOnly === true,
    protectedContentExcluded: provider.protectedContentExcluded === true,
  }));
}

function normalizeReviewDomains(input, reasons) {
  const domains = Array.isArray(input?.reviewDomains) ? [...input.reviewDomains].sort(domainSort) : [];
  addReason(reasons, domains.length === 0, 'review_domains_absent');

  const domainMap = byDomain(domains);
  for (const domain of REQUIRED_REVIEW_DOMAINS) {
    addReason(reasons, !domainMap.has(domain), `review_domain_missing:${domain}`);
  }
  for (const domain of duplicateDomains(domains)) {
    addReason(reasons, true, `review_domain_duplicate:${domain}`);
  }
  for (const entry of domains) {
    const domain = hasText(entry?.domain) ? entry.domain : 'unknown';
    addReason(reasons, !REQUIRED_REVIEW_DOMAINS.includes(domain), `review_domain_unsupported:${domain}`);
    addReason(reasons, !REVIEW_STATUSES.has(entry?.status), `review_domain_not_verified:${domain}`);
    addReason(reasons, !isDigest(entry?.evidenceHash), `review_domain_evidence_hash_invalid:${domain}`);
    addReason(reasons, entry?.metadataOnly !== true, `review_domain_metadata_boundary_invalid:${domain}`);
  }

  return domains.map((entry) => ({
    domain: entry.domain,
    evidenceHash: entry.evidenceHash,
    status: entry.status,
  }));
}

function evaluateDependencyEvidence(dependencyEvidence, reasons) {
  addReason(reasons, !hasText(dependencyEvidence?.protocolControlReceiptId), 'protocol_control_receipt_absent');
  addReason(reasons, !hasText(dependencyEvidence?.protocolFeasibilityReceiptId), 'protocol_feasibility_receipt_absent');
  addReason(reasons, !hasText(dependencyEvidence?.vendorSubcontractorReceiptId), 'vendor_subcontractor_receipt_absent');
  addReason(
    reasons,
    !hasText(dependencyEvidence?.facilityProductReadinessReceiptId),
    'facility_product_readiness_receipt_absent',
  );
  addReason(
    reasons,
    !hasText(dependencyEvidence?.participantProtectionReceiptId),
    'participant_protection_receipt_absent',
  );
  addReason(reasons, !isDigest(dependencyEvidence?.privacyBoundaryHash), 'privacy_boundary_hash_invalid');
  addReason(reasons, !isDigest(dependencyEvidence?.custodyDigest), 'dependency_custody_digest_invalid');
}

function evaluateReviewGovernance(input, reasons) {
  const governance = input?.reviewGovernance;
  const decisionForum = governance?.decisionForum;
  addReason(reasons, !hasText(governance?.humanReviewerDid), 'human_reviewer_absent');
  addReason(reasons, governance?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, hlcTuple(governance?.reviewedAtHlc) === null, 'governance_review_time_invalid');
  addReason(
    reasons,
    hlcTuple(input?.readinessPackage?.evaluatedAtHlc) !== null &&
      !hlcAfter(governance?.reviewedAtHlc, input.readinessPackage.evaluatedAtHlc),
    'governance_review_before_package_evaluation',
  );
  addReason(reasons, decisionForum?.required !== true, 'decision_forum_required_absent');
  addReason(reasons, decisionForum?.verified !== true, 'decision_forum_unverified');
  addReason(reasons, decisionForum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, decisionForum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, decisionForum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, decisionForum?.openChallenge === true, 'challenge_open');
  addReason(reasons, !hasText(decisionForum?.decisionId), 'decision_forum_decision_id_absent');
  addReason(reasons, !hasText(decisionForum?.workflowReceiptId), 'decision_forum_workflow_receipt_absent');
}

function requiredProviderReadyCount(providerSummaries) {
  const readyCategories = new Set(
    providerSummaries
      .filter((provider) => REQUIRED_PROVIDER_CATEGORIES.includes(provider.category) && provider.status === 'ready')
      .map((provider) => provider.category),
  );
  return REQUIRED_PROVIDER_CATEGORIES.filter((category) => readyCategories.has(category)).length;
}

function buildProviderReadiness(input, providerSummaries, reviewDomains, reasons) {
  const denied = reasons.length > 0;
  const coveredProviderCategories = sortedTextList(providerSummaries.map((provider) => provider.category)).filter((category) =>
    REQUIRED_PROVIDER_CATEGORIES.includes(category),
  );
  const coveredReviewDomains = sortedTextList(reviewDomains.map((entry) => entry.domain)).filter((domain) =>
    REQUIRED_REVIEW_DOMAINS.includes(domain),
  );
  const readinessBasisPoints = basisPoints(requiredProviderReadyCount(providerSummaries), REQUIRED_PROVIDER_CATEGORIES.length);
  const readinessCore = {
    coveredProviderCategories,
    coveredReviewDomains,
    dependencyEvidence: {
      facilityProductReadinessReceiptId: input?.dependencyEvidence?.facilityProductReadinessReceiptId ?? null,
      participantProtectionReceiptId: input?.dependencyEvidence?.participantProtectionReceiptId ?? null,
      protocolControlReceiptId: input?.dependencyEvidence?.protocolControlReceiptId ?? null,
      protocolFeasibilityReceiptId: input?.dependencyEvidence?.protocolFeasibilityReceiptId ?? null,
      vendorSubcontractorReceiptId: input?.dependencyEvidence?.vendorSubcontractorReceiptId ?? null,
    },
    packageRef: input?.readinessPackage?.packageRef ?? null,
    providerReadinessBasisPoints: readinessBasisPoints,
    providers: providerSummaries,
    protocolRef: input?.readinessPackage?.protocolRef ?? null,
    reviewDomains: coveredReviewDomains,
    siteRef: input?.readinessPackage?.siteRef ?? null,
    studyRef: input?.readinessPackage?.studyRef ?? null,
    tenantId: input?.tenantId ?? null,
  };

  return {
    schema: PROVIDER_READINESS_SCHEMA,
    packageId: hasText(input?.readinessPackage?.packageRef)
      ? `protocol_service_provider_readiness_${sha256Hex(readinessCore).slice(0, 32)}`
      : null,
    packageRef: input?.readinessPackage?.packageRef ?? null,
    protocolRef: input?.readinessPackage?.protocolRef ?? null,
    studyRef: input?.readinessPackage?.studyRef ?? null,
    siteRef: input?.readinessPackage?.siteRef ?? null,
    requiredProviderCategories: [...REQUIRED_PROVIDER_CATEGORIES],
    coveredProviderCategories,
    requiredReviewDomains: [...REQUIRED_REVIEW_DOMAINS],
    reviewDomains: coveredReviewDomains,
    providerCount: providerSummaries.length,
    providerReadinessBasisPoints: readinessBasisPoints,
    readinessHash: sha256Hex(readinessCore),
    status: denied ? 'blocked' : 'ready',
    trustState: 'inactive',
    exochainProductionClaim: false,
    containsProtectedContent: false,
    aiFinalAuthority: input?.reviewGovernance?.aiFinalAuthority === true,
    failClosedProviderReadiness: denied,
  };
}

function buildReceipt(input, providerReadiness) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: sha256Hex(providerReadiness),
    artifactType: 'protocol_service_provider_readiness',
    artifactVersion: input.readinessPackage.packageRef,
    classification: 'metadata-only protocol service provider readiness',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.readinessPackage.evaluatedAtHlc,
    sensitivityTags: ['clinical_operations', 'metadata_only', 'protocol_readiness', 'service_provider_readiness'],
    sourceSystem: 'cybermedica-qms-contracts',
    tenantId: input.tenantId,
  });
}

export function evaluateProtocolServiceProviderReadiness(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateReadinessPackage(input?.readinessPackage, reasons);
  const providerSummaries = normalizeProviders(input, reasons);
  const reviewDomains = normalizeReviewDomains(input, reasons);
  evaluateDependencyEvidence(input?.dependencyEvidence, reasons);
  evaluateReviewGovernance(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const uniqueReasons = uniqueSortedReasons(reasons);
  const providerReadiness = buildProviderReadiness(input, providerSummaries, reviewDomains, uniqueReasons);

  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.protocol_service_provider_readiness_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      providerReadiness,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  return {
    schema: 'cybermedica.protocol_service_provider_readiness_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    providerReadiness,
    receipt: buildReceipt(input, providerReadiness),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
