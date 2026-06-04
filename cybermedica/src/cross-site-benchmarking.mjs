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
const BENCHMARK_SCHEMA = 'cybermedica.cross_site_benchmarking.v1';
const REQUIRED_PERMISSION = 'cross_site_benchmark_view';

const REQUIRED_BENCHMARK_FAMILIES = Object.freeze([
  'audit_findings',
  'capa_aging',
  'consent_readiness',
  'deviation_rate',
  'site_readiness',
  'training_coverage',
]);

const AUDIENCE_CLASSES = new Set(['cro', 'quality_manager', 'site_leader', 'sponsor']);
const EXTERNAL_AUDIENCES = new Set(['cro', 'sponsor']);
const SPONSOR_CRO_REQUESTER_CLASSES = new Set(['cro', 'sponsor']);
const SPONSOR_CRO_WORK_ITEM_STATUSES = new Set([
  'approved_for_response',
  'queued_for_site_review',
  'routed_to_decision_forum',
]);

const RAW_BENCHMARK_FIELDS = new Set([
  'benchmarkbody',
  'benchmarknarrative',
  'benchmarkpayload',
  'benchmarktext',
  'freeformbenchmark',
  'participantlisting',
  'rawbenchmark',
  'rawbenchmarkdata',
  'rawbenchmarkpayload',
  'rawbenchmarktext',
  'rawdataset',
  'rawmetricdata',
  'rawobservation',
  'rawsitecontent',
  'rawsitedata',
  'rawsource',
  'rawsourcedata',
  'sourcebody',
  'sourcedocumentbody',
  'sourcedocumenttext',
]);

const SECRET_BENCHMARK_FIELDS = new Set([
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

function isNonNegativeSafeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
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

function assertNoRawBenchmarkContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawBenchmarkContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_BENCHMARK_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw benchmark content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_BENCHMARK_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`benchmark secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawBenchmarkContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawBenchmarkContent(input ?? {});
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

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlcTuple(leftTuple, rightTuple) > 0;
}

function hlcBefore(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlcTuple(leftTuple, rightTuple) < 0;
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

function basisPoints(numerator, denominator) {
  if (!isNonNegativeSafeInteger(numerator) || !isPositiveSafeInteger(denominator)) {
    return null;
  }
  return Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
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
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'benchmark_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateBenchmarkPlan(input, reasons) {
  const plan = input?.benchmarkPlan;
  const families = sortedTextList(plan?.requiredFamilies);
  const familySet = new Set(families);

  addReason(reasons, !hasText(plan?.benchmarkRef), 'benchmark_ref_absent');
  addReason(reasons, !hasText(plan?.purpose), 'benchmark_purpose_absent');
  addReason(reasons, !isDigest(plan?.methodHash), 'benchmark_method_hash_invalid');
  addReason(reasons, !isDigest(plan?.baselineHash), 'benchmark_baseline_hash_invalid');
  addReason(reasons, !hasText(plan?.approvedByDid), 'benchmark_approver_absent');
  addReason(reasons, hlcTuple(plan?.approvedAtHlc) === null, 'benchmark_approval_time_invalid');
  addReason(reasons, !isPositiveSafeInteger(plan?.minCellCount), 'benchmark_min_cell_count_invalid');
  addReason(reasons, plan?.metadataOnly !== true, 'benchmark_metadata_boundary_invalid');
  addReason(reasons, plan?.sourcePayloadsExcluded !== true, 'benchmark_source_payload_boundary_invalid');
  addReason(reasons, plan?.productionTrustClaim === true, 'production_trust_claim_forbidden');

  for (const family of REQUIRED_BENCHMARK_FAMILIES) {
    addReason(reasons, !familySet.has(family), `required_benchmark_family_missing:${family}`);
  }
  for (const family of families) {
    addReason(reasons, !REQUIRED_BENCHMARK_FAMILIES.includes(family), `benchmark_family_unsupported:${family}`);
  }

  return families;
}

function evaluateComparisonWindow(input, reasons) {
  const window = input?.comparisonWindow;
  addReason(reasons, !hasText(window?.windowRef), 'comparison_window_ref_absent');
  addReason(reasons, hlcTuple(window?.startsAtHlc) === null, 'comparison_window_start_invalid');
  addReason(reasons, hlcTuple(window?.endsAtHlc) === null, 'comparison_window_end_invalid');
  addReason(
    reasons,
    hlcTuple(window?.startsAtHlc) !== null && hlcTuple(window?.endsAtHlc) !== null && !hlcAfter(window.endsAtHlc, window.startsAtHlc),
    'comparison_window_not_monotonic',
  );
  addReason(reasons, hlcTuple(window?.extractedAtHlc) === null, 'comparison_extraction_time_invalid');
  addReason(
    reasons,
    hlcTuple(window?.endsAtHlc) !== null && hlcTuple(window?.extractedAtHlc) !== null && hlcBefore(window.extractedAtHlc, window.endsAtHlc),
    'comparison_extraction_before_window_end',
  );
  addReason(reasons, !isDigest(window?.extractionManifestHash), 'comparison_manifest_hash_invalid');
  addReason(reasons, !isDigest(window?.custodyDigest), 'comparison_custody_digest_invalid');
}

function evaluateVisibilityPolicy(input, reasons) {
  const policy = input?.visibilityPolicy;
  const dashboardRefs = sortedTextList(policy?.dashboardRefs);
  const audienceClass = hasText(policy?.audienceClass) ? policy.audienceClass : 'unclassified';
  const externalVisibility = policy?.sponsorCroBoundary?.externalAudience === true || EXTERNAL_AUDIENCES.has(audienceClass);

  addReason(reasons, !AUDIENCE_CLASSES.has(audienceClass), 'visibility_audience_class_invalid');
  addReason(reasons, dashboardRefs.length === 0, 'visibility_dashboard_refs_absent');
  addReason(reasons, policy?.phiPiiExcluded !== true, 'visibility_phi_boundary_invalid');
  addReason(reasons, policy?.siteAliasOnly !== true, 'site_alias_boundary_invalid');
  addReason(reasons, policy?.metadataOnly !== true, 'visibility_metadata_boundary_invalid');
  addReason(
    reasons,
    externalVisibility && policy?.sponsorCroBoundary?.controlledRequestRequired !== true,
    'external_visibility_controlled_request_not_required',
  );

  return { audienceClass, dashboardRefs, externalVisibility };
}

function evaluateSponsorCroRequest(input, benchmarkRef, externalVisibility, reasons) {
  if (!externalVisibility) {
    return null;
  }

  const evidence = input?.sponsorCroRequestEvidence;
  if (evidence === null || evidence === undefined) {
    reasons.push('external_visibility_request_evidence_absent');
    return null;
  }

  addReason(reasons, !hasText(evidence?.requestRef), 'external_visibility_request_ref_absent');
  addReason(reasons, !isDigest(evidence?.requestHash), 'external_visibility_request_hash_invalid');
  addReason(reasons, !SPONSOR_CRO_REQUESTER_CLASSES.has(evidence?.requesterClass), 'external_visibility_requester_class_invalid');
  addReason(reasons, !hasText(evidence?.workItemRef), 'external_visibility_work_item_absent');
  addReason(reasons, !SPONSOR_CRO_WORK_ITEM_STATUSES.has(evidence?.workItemStatus), 'external_visibility_work_item_status_invalid');
  addReason(reasons, !isDigest(evidence?.disclosureLogHash), 'external_visibility_disclosure_hash_invalid');
  addReason(reasons, !isDigest(evidence?.humanReviewHash), 'external_visibility_human_review_hash_invalid');
  addReason(reasons, !isDigest(evidence?.responsePackageHash), 'external_visibility_response_package_hash_invalid');
  addReason(reasons, evidence?.linkedBenchmarkRef !== benchmarkRef, 'external_visibility_benchmark_ref_mismatch');
  addReason(reasons, evidence?.metadataOnly !== true, 'external_visibility_metadata_boundary_invalid');
  addReason(reasons, evidence?.sourcePayloadExcluded !== true, 'external_visibility_source_payload_boundary_invalid');
  addReason(reasons, evidence?.protectedContentExcluded !== true, 'external_visibility_protected_content_boundary_invalid');
  addReason(reasons, evidence?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(evidence?.linkedAtHlc) === null, 'external_visibility_link_time_invalid');

  return hasText(evidence?.requestRef) ? evidence.requestRef : null;
}

function observationSort(left, right) {
  return [left.siteAliasHash, left.family, left.siteTenantRef].join('|').localeCompare(
    [right.siteAliasHash, right.family, right.siteTenantRef].join('|'),
  );
}

function normalizeObservations(input, requiredFamilies, reasons) {
  const observations = Array.isArray(input?.observations) ? [...input.observations].sort(observationSort) : [];
  const requiredFamilySet = new Set(requiredFamilies);
  const observedFamilies = new Set();
  const minCellCount = input?.benchmarkPlan?.minCellCount;
  const window = input?.comparisonWindow;

  addReason(reasons, observations.length === 0, 'benchmark_observations_absent');

  return observations.map((observation) => {
    const family = hasText(observation?.family) ? observation.family : 'unclassified';
    const siteTenantRef = hasText(observation?.siteTenantRef) ? observation.siteTenantRef : 'unknown';
    if (REQUIRED_BENCHMARK_FAMILIES.includes(family)) {
      observedFamilies.add(family);
    }

    addReason(reasons, !hasText(observation?.siteTenantRef), `observation_site_ref_absent:${family}`);
    addReason(reasons, !isDigest(observation?.siteAliasHash), `observation_site_alias_hash_invalid:${family}:${siteTenantRef}`);
    addReason(reasons, !requiredFamilySet.has(family), `observation_family_not_required:${family}:${siteTenantRef}`);
    addReason(reasons, !isNonNegativeSafeInteger(observation?.numerator), `observation_numerator_invalid:${family}:${siteTenantRef}`);
    addReason(reasons, !isPositiveSafeInteger(observation?.denominator), `observation_denominator_invalid:${family}:${siteTenantRef}`);
    addReason(
      reasons,
      isNonNegativeSafeInteger(observation?.numerator) &&
        isPositiveSafeInteger(observation?.denominator) &&
        observation.numerator > observation.denominator,
      `observation_numerator_exceeds_denominator:${family}:${siteTenantRef}`,
    );
    addReason(reasons, !isDigest(observation?.evidenceHash), `observation_evidence_hash_invalid:${family}:${siteTenantRef}`);
    addReason(reasons, !isDigest(observation?.custodyDigest), `observation_custody_digest_invalid:${family}:${siteTenantRef}`);
    addReason(reasons, hlcTuple(observation?.measuredAtHlc) === null, `observation_time_invalid:${family}:${siteTenantRef}`);
    addReason(
      reasons,
      hlcTuple(window?.startsAtHlc) !== null && hlcTuple(observation?.measuredAtHlc) !== null && hlcBefore(observation.measuredAtHlc, window.startsAtHlc),
      `observation_before_window:${family}:${siteTenantRef}`,
    );
    addReason(
      reasons,
      hlcTuple(window?.endsAtHlc) !== null && hlcTuple(observation?.measuredAtHlc) !== null && hlcAfter(observation.measuredAtHlc, window.endsAtHlc),
      `observation_after_window:${family}:${siteTenantRef}`,
    );
    addReason(reasons, sortedTextList(observation?.sourceControlIds).length === 0, `observation_source_control_absent:${family}:${siteTenantRef}`);
    addReason(
      reasons,
      isPositiveSafeInteger(minCellCount) && (!isPositiveSafeInteger(observation?.cellCount) || observation.cellCount < minCellCount),
      `observation_cell_count_below_minimum:${family}:${siteTenantRef}`,
    );
    addReason(reasons, observation?.privacy?.metadataOnly !== true, `observation_metadata_boundary_invalid:${family}:${siteTenantRef}`);
    addReason(reasons, observation?.privacy?.directIdentifiersExcluded !== true, `observation_identifier_boundary_invalid:${family}:${siteTenantRef}`);
    addReason(reasons, observation?.privacy?.sourcePayloadExcluded !== true, `observation_source_payload_boundary_invalid:${family}:${siteTenantRef}`);
    addReason(
      reasons,
      observation?.privacy?.sponsorConfidentialMinimized !== true,
      `observation_sponsor_confidential_boundary_invalid:${family}:${siteTenantRef}`,
    );
    addReason(reasons, observation?.privacy?.aggregateCellCountOnly !== true, `observation_cell_count_boundary_invalid:${family}:${siteTenantRef}`);

    return {
      cellCount: observation?.cellCount ?? null,
      custodyDigest: observation?.custodyDigest ?? null,
      denominator: observation?.denominator ?? null,
      evidenceHash: observation?.evidenceHash ?? null,
      family,
      measuredAtHlc: observation?.measuredAtHlc ?? null,
      numerator: observation?.numerator ?? null,
      siteAliasHash: observation?.siteAliasHash ?? null,
      siteTenantRef,
      sourceControlIds: sortedTextList(observation?.sourceControlIds),
    };
  }).map((observation) => ({
    ...observation,
    basisPoints: basisPoints(observation.numerator, observation.denominator),
  })).map((observation) => {
    addReason(reasons, observation.basisPoints === null, `observation_basis_points_invalid:${observation.family}:${observation.siteTenantRef}`);
    return observation;
  }).concat(requiredFamilies.flatMap((family) => {
    if (observedFamilies.has(family)) {
      return [];
    }
    reasons.push(`observed_benchmark_family_missing:${family}`);
    return [];
  }));
}

function aggregateByFamily(observations) {
  const grouped = new Map();
  for (const observation of observations) {
    if (observation.basisPoints === null) {
      continue;
    }
    const existing = grouped.get(observation.family) ?? {
      denominator: 0,
      evidenceHashes: [],
      family: observation.family,
      numerator: 0,
      siteCount: 0,
    };
    existing.denominator += observation.denominator;
    existing.evidenceHashes.push(observation.evidenceHash);
    existing.numerator += observation.numerator;
    existing.siteCount += 1;
    grouped.set(observation.family, existing);
  }

  return [...grouped.values()]
    .map((family) => ({
      basisPoints: basisPoints(family.numerator, family.denominator),
      denominator: family.denominator,
      evidenceHashes: sortedTextList(family.evidenceHashes),
      family: family.family,
      numerator: family.numerator,
      siteCount: family.siteCount,
    }))
    .sort((left, right) => left.family.localeCompare(right.family));
}

function aggregateBySite(observations) {
  const grouped = new Map();
  for (const observation of observations) {
    if (observation.basisPoints === null) {
      continue;
    }
    const existing = grouped.get(observation.siteAliasHash) ?? {
      denominator: 0,
      familyScores: [],
      numerator: 0,
      siteAliasHash: observation.siteAliasHash,
    };
    existing.denominator += observation.denominator;
    existing.familyScores.push({
      basisPoints: observation.basisPoints,
      family: observation.family,
    });
    existing.numerator += observation.numerator;
    grouped.set(observation.siteAliasHash, existing);
  }

  return [...grouped.values()]
    .map((site) => ({
      familyScores: site.familyScores.sort((left, right) => left.family.localeCompare(right.family)),
      overallBasisPoints: basisPoints(site.numerator, site.denominator),
      siteAliasHash: site.siteAliasHash,
      siteTenantRef: 'suppressed',
    }))
    .sort((left, right) => left.siteAliasHash.localeCompare(right.siteAliasHash));
}

function lowestFamilySummary(familySummaries) {
  const summaries = familySummaries.filter((summary) => summary.basisPoints !== null);
  if (summaries.length === 0) {
    return null;
  }
  return summaries.reduce((lowest, candidate) => {
    if (candidate.basisPoints < lowest.basisPoints) {
      return candidate;
    }
    if (candidate.basisPoints === lowest.basisPoints && candidate.family < lowest.family) {
      return candidate;
    }
    return lowest;
  });
}

function evaluateAiAssistance(input, reasons) {
  const assistance = input?.aiAssistance;
  if (assistance === null || assistance === undefined || assistance.used !== true) {
    return;
  }
  addReason(reasons, assistance.advisoryOnly !== true, 'ai_advisory_boundary_invalid');
  addReason(reasons, assistance.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, !isDigest(assistance.recommendationHash), 'ai_recommendation_hash_invalid');
  addReason(reasons, assistance.humanReviewed !== true, 'ai_human_review_missing');
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, review?.status !== 'approved', 'human_review_not_approved');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, !isDigest(review?.reviewEvidenceHash), 'human_review_evidence_hash_invalid');
  addReason(reasons, review?.aiFinalAuthorityRejected !== true, 'ai_final_authority_rejection_missing');
  addReason(
    reasons,
    hlcTuple(input?.comparisonWindow?.extractedAtHlc) !== null &&
      hlcTuple(review?.reviewedAtHlc) !== null &&
      !hlcAfter(review.reviewedAtHlc, input.comparisonWindow.extractedAtHlc),
    'human_review_not_after_extraction',
  );
}

function createDeniedResult(reasons) {
  return {
    schema: BENCHMARK_SCHEMA,
    benchmark: null,
    decision: 'denied',
    exochainProductionClaim: false,
    failClosed: true,
    reasons: uniqueReasons(reasons),
    receipt: null,
    trustState: 'inactive',
  };
}

export function evaluateCrossSiteBenchmarking(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const requiredFamilies = evaluateBenchmarkPlan(input, reasons);
  evaluateComparisonWindow(input, reasons);
  const visibility = evaluateVisibilityPolicy(input, reasons);
  const sponsorCroRequestRef = evaluateSponsorCroRequest(
    input,
    input?.benchmarkPlan?.benchmarkRef,
    visibility.externalVisibility,
    reasons,
  );
  const observations = normalizeObservations(input, requiredFamilies, reasons);
  evaluateAiAssistance(input, reasons);
  evaluateHumanReview(input, reasons);

  if (reasons.length > 0) {
    return createDeniedResult(reasons);
  }

  const familySummaries = aggregateByFamily(observations);
  const siteSummaries = aggregateBySite(observations);
  const totalNumerator = observations.reduce((sum, observation) => sum + observation.numerator, 0);
  const totalDenominator = observations.reduce((sum, observation) => sum + observation.denominator, 0);
  const benchmark = {
    schema: BENCHMARK_SCHEMA,
    benchmarkRef: input.benchmarkPlan.benchmarkRef,
    dashboardRefs: visibility.dashboardRefs,
    exochainProductionClaim: false,
    externalVisibility: visibility.externalVisibility,
    familySummaries,
    lowestFamily: lowestFamilySummary(familySummaries),
    metadataOnly: true,
    observationCount: observations.length,
    overallBasisPoints: basisPoints(totalNumerator, totalDenominator),
    requiredFamilies,
    siteCount: siteSummaries.length,
    siteSummaries,
    sponsorCroRequestRef,
    trustState: 'inactive',
    visibilityAudience: visibility.audienceClass,
    windowRef: input.comparisonWindow.windowRef,
  };

  const receipt = createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: sha256Hex(benchmark),
    artifactType: 'cross_site_benchmark',
    artifactVersion: input.benchmarkPlan.benchmarkRef,
    classification: 'confidential_metadata_only',
    custodyDigest: input.comparisonWindow.custodyDigest,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    sensitivityTags: ['cross_site_benchmark_metadata', 'qms_quality_trend_metadata'],
    sourceSystem: 'cybermedica-qms',
    tenantId: input.tenantId,
  });

  return {
    schema: BENCHMARK_SCHEMA,
    benchmark,
    decision: 'permitted',
    exochainProductionClaim: false,
    failClosed: false,
    reasons: [],
    receipt,
    trustState: 'inactive',
  };
}
