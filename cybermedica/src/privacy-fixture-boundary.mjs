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

import { createHash } from 'node:crypto';
import { ProtectedContentError, canonicalize, createEvidenceReceipt, sha256Hex } from './qms-contracts.mjs';

export { ProtectedContentError };

const HEX_64 = /^[0-9a-f]{64}$/u;
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const PRIVACY_FIXTURE_SCHEMA = 'cybermedica.privacy_fixture_boundary.v1';
const DECISION_SCHEMA = 'cybermedica.privacy_fixture_boundary_decision.v1';
const REQUIRED_PERMISSION = 'privacy_fixture_review';
const PRIVACY_FIXTURE_ACTIVATION_GATE_ID = 'PTAG-009';

const REQUIRED_SURFACE_FAMILIES = Object.freeze([
  'audit_log_record',
  'dag_payload',
  'debug_response',
  'export_manifest',
  'health_response',
  'receipt_anchor',
  'telemetry_event',
]);

const REQUIRED_DETECTOR_RULE_IDS = Object.freeze([
  'hash_only_metadata_required',
  'protected_field_name',
  'protected_text_pattern',
  'secret_field_name',
  'secret_text_pattern',
  'unscoped_payload_field',
]);

const POLICY_STATUSES = new Set(['active']);
const SCAN_STATUSES = new Set(['passed']);
const SURFACE_FAMILY_SET = new Set(REQUIRED_SURFACE_FAMILIES);
const DETECTOR_RULE_SET = new Set(REQUIRED_DETECTOR_RULE_IDS);
const HUMAN_REVIEW_DECISIONS = new Set([
  'hold_for_privacy_fixture_gap',
  'privacy_fixture_boundary_accepted_inactive_trust',
]);

const RAW_PRIVACY_FIXTURE_FIELDS = new Set([
  'body',
  'clinicalnotes',
  'content',
  'freetext',
  'freetextnote',
  'negativeprobebody',
  'participantlisting',
  'privacyfixturebody',
  'rawanchorpayload',
  'rawdagpayload',
  'rawdebugresponse',
  'rawexportbody',
  'rawfixture',
  'rawfixturebody',
  'rawhealthresponse',
  'rawlogpayload',
  'rawpayload',
  'rawphi',
  'rawpii',
  'rawprivacyfixture',
  'rawsource',
  'rawsourcedata',
  'rawtelemetrypayload',
  'reviewnotes',
  'sourcedocumentbody',
  'sponsorconfidentialbody',
  'validationlog',
]);

const SECRET_PRIVACY_FIXTURE_FIELDS = new Set([
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
  'sessiontoken',
  'signaturesecret',
  'signingkey',
  'token',
]);

const SCANNER_PROTECTED_FIELD_NAMES = new Set([
  'address',
  'dateofbirth',
  'dob',
  'email',
  'medicalrecordnumber',
  'mrn',
  'participantid',
  'participantname',
  'patientid',
  'patientname',
  'phone',
  'rawphi',
  'rawpii',
  'sourcedocumentbody',
  'sponsorconfidentialbody',
  'ssn',
]);

const SCANNER_SECRET_FIELD_NAMES = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'password',
  'privatekey',
  'rootkey',
  'rootsigningkey',
  'secret',
  'sessiontoken',
  'signaturematerial',
  'signingkey',
  'token',
]);

const SCANNER_UNSCOPED_PAYLOAD_FIELD_NAMES = new Set([
  'anchorpayload',
  'body',
  'dagpayload',
  'debugpayload',
  'healthpayload',
  'logpayload',
  'payload',
  'telemetrypayload',
]);

const PROTECTED_TEXT_PATTERNS = [
  /\b\d{3}-\d{2}-\d{4}\b/u,
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/iu,
  /\b(?:patient|participant)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/iu,
  /\b(?:mrn|medical record)\s*[:#]\s*[A-Z0-9-]+\b/iu,
];

const SECRET_TEXT_PATTERNS = [
  /\bauthorization\s*:\s*bearer\s+\S+/iu,
  /\bbearer\s+\S+/iu,
  /\bapi[_-]?key\s*[:=]\s*\S+/iu,
  /\bclient[_-]?secret\s*[:=]\s*\S+/iu,
  /\b(?:access|auth|refresh|session|railway)[_-]?token\s*[:=]\s*\S+/iu,
  /\b(?:private|root|signing)[_-]?key\s*[:=]\s*\S+/iu,
  /\bpassword\s*[:=]\s*\S+/iu,
];

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && value !== ZERO_HASH;
}

function isNonNegativeSafeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
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

function assertNoRawPrivacyFixtureContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawPrivacyFixtureContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_PRIVACY_FIXTURE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw privacy fixture content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_PRIVACY_FIXTURE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`privacy fixture secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawPrivacyFixtureContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawPrivacyFixtureContent(input ?? {});
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

function rawDigest(value) {
  return createHash('sha256').update(String(value), 'utf8').digest('hex');
}

function finding(ruleId, pathRef, value, severity = 'high') {
  return {
    ruleId,
    pathRefDigest: rawDigest(pathRef),
    matchDigest: rawDigest(`${ruleId}:${pathRef}:${String(value)}`),
    severity,
    metadataOnly: true,
  };
}

function scanStringValue(findings, pathRef, value) {
  for (const pattern of PROTECTED_TEXT_PATTERNS) {
    if (pattern.test(value)) {
      findings.push(finding('protected_text_pattern', pathRef, value));
      break;
    }
  }
  for (const pattern of SECRET_TEXT_PATTERNS) {
    if (pattern.test(value)) {
      findings.push(finding('secret_text_pattern', pathRef, value));
      break;
    }
  }
}

function scanFixtureValue(findings, pathRef, value) {
  if (value === null || value === undefined) {
    return;
  }
  if (typeof value === 'string') {
    scanStringValue(findings, pathRef, value);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => scanFixtureValue(findings, `${pathRef}[${index}]`, item));
    return;
  }
  if (typeof value !== 'object') {
    return;
  }

  for (const key of Object.keys(value).sort()) {
    const nested = value[key];
    const nestedPath = `${pathRef}.${key}`;
    const normalized = normalizeFieldName(key);
    if (SCANNER_PROTECTED_FIELD_NAMES.has(normalized) && sensitiveValuePresent(nested)) {
      findings.push(finding('protected_field_name', nestedPath, normalized));
    }
    if (SCANNER_SECRET_FIELD_NAMES.has(normalized) && sensitiveValuePresent(nested)) {
      findings.push(finding('secret_field_name', nestedPath, normalized));
    }
    if (SCANNER_UNSCOPED_PAYLOAD_FIELD_NAMES.has(normalized) && sensitiveValuePresent(nested)) {
      findings.push(finding('unscoped_payload_field', nestedPath, normalized));
    }
    scanFixtureValue(findings, nestedPath, nested);
  }
}

export function scanPrivacyFixtureEnvelope(pathRef, envelope) {
  const findings = [];
  scanFixtureValue(findings, hasText(pathRef) ? pathRef : '$', envelope);
  return findings;
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

function evaluateRequiredSet(actual, expected, missingPrefix, unsupportedPrefix, allowedSet, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !allowedSet.has(value), `${unsupportedPrefix}:${value}`);
  }
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_privacy_fixture_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'privacy_fixture_review_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePrivacyPolicy(policy, reasons) {
  const requiredSurfaces = sortedTextList(policy?.requiredSurfaceFamilies);
  const requiredDetectorRules = sortedTextList(policy?.requiredDetectorRuleIds);

  addReason(reasons, !hasText(policy?.policyRef), 'privacy_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'privacy_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'privacy_policy_inactive');
  evaluateRequiredSet(
    requiredSurfaces,
    REQUIRED_SURFACE_FAMILIES,
    'policy_surface_family_missing',
    'policy_surface_family_unsupported',
    SURFACE_FAMILY_SET,
    reasons,
  );
  evaluateRequiredSet(
    requiredDetectorRules,
    REQUIRED_DETECTOR_RULE_IDS,
    'policy_detector_rule_missing',
    'policy_detector_rule_unsupported',
    DETECTOR_RULE_SET,
    reasons,
  );
  addReason(reasons, policy?.requireHashOnlyMetadata !== true, 'policy_hash_only_metadata_not_required');
  addReason(reasons, policy?.requirePayloadSuppression !== true, 'policy_payload_suppression_not_required');
  addReason(reasons, policy?.requireNoProductionTrustClaim !== true, 'policy_no_production_trust_claim_not_required');
  addReason(reasons, policy?.metadataOnly !== true, 'privacy_policy_not_metadata_only');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'privacy_policy_protected_content_not_excluded');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'privacy_policy_evaluated_hlc_invalid');
}

function evaluateFixtureSuite(suite, policy, reasons) {
  addReason(reasons, !hasText(suite?.suiteRef), 'fixture_suite_ref_absent');
  addReason(reasons, !hasText(suite?.sourceRef), 'fixture_suite_source_ref_absent');
  addReason(reasons, suite?.metadataOnly !== true, 'fixture_suite_not_metadata_only');
  addReason(reasons, suite?.protectedContentExcluded !== true, 'fixture_suite_protected_content_not_excluded');
  addReason(reasons, suite?.productionTrustClaim === true, 'fixture_suite_production_trust_claim_attempted');
  addReason(reasons, hlcTuple(suite?.openedAtHlc) === null, 'fixture_suite_opened_hlc_invalid');
  addReason(reasons, hlcTuple(suite?.compiledAtHlc) === null, 'fixture_suite_compiled_hlc_invalid');
  addReason(reasons, !hlcAfter(suite?.compiledAtHlc, suite?.openedAtHlc), 'fixture_suite_compiled_before_open');
  addReason(reasons, !hlcAfter(suite?.openedAtHlc, policy?.evaluatedAtHlc), 'fixture_suite_opened_before_policy');
}

function evaluateFixtureCases(cases, suite, reasons) {
  addReason(reasons, !Array.isArray(cases) || cases.length === 0, 'fixture_cases_absent');
  const caseList = Array.isArray(cases) ? cases : [];
  const surfaceFamilies = sortedTextList(caseList.map((fixture) => fixture?.surfaceFamily));
  evaluateRequiredSet(
    surfaceFamilies,
    REQUIRED_SURFACE_FAMILIES,
    'surface_family_missing',
    'surface_family_unsupported',
    SURFACE_FAMILY_SET,
    reasons,
  );

  const seenFixtureRefs = new Set();
  for (const fixture of caseList) {
    const fixtureRef = hasText(fixture?.fixtureRef) ? fixture.fixtureRef : 'unknown_fixture';
    addReason(reasons, !hasText(fixture?.fixtureRef), 'fixture_ref_absent');
    addReason(reasons, seenFixtureRefs.has(fixtureRef), `fixture_ref_duplicate:${fixtureRef}`);
    seenFixtureRefs.add(fixtureRef);
    addReason(reasons, !SURFACE_FAMILY_SET.has(fixture?.surfaceFamily), `fixture_surface_family_unsupported:${fixtureRef}`);
    addReason(reasons, !hasText(fixture?.scannerRef), `fixture_scanner_ref_absent:${fixtureRef}`);
    addReason(reasons, !isDigest(fixture?.scannerVersionHash), `fixture_scanner_version_hash_invalid:${fixtureRef}`);
    addReason(reasons, !isDigest(fixture?.fixtureHash), `fixture_hash_invalid:${fixtureRef}`);
    addReason(reasons, !isDigest(fixture?.negativeProbeHash), `fixture_negative_probe_hash_invalid:${fixtureRef}`);
    addReason(reasons, !SCAN_STATUSES.has(fixture?.scanStatus), `fixture_scan_not_passed:${fixtureRef}`);
    addReason(reasons, fixture?.findingsCount !== 0, `fixture_findings_present:${fixtureRef}`);
    addReason(reasons, fixture?.rawSensitiveContentAbsent !== true, `fixture_raw_sensitive_content_present:${fixtureRef}`);
    addReason(reasons, fixture?.secretMaterialAbsent !== true, `fixture_secret_material_present:${fixtureRef}`);
    addReason(reasons, fixture?.payloadSuppressed !== true, `fixture_payload_not_suppressed:${fixtureRef}`);
    addReason(reasons, fixture?.hashOnlyMetadata !== true, `fixture_hash_only_metadata_missing:${fixtureRef}`);
    addReason(reasons, fixture?.metadataOnly !== true, `fixture_not_metadata_only:${fixtureRef}`);
    addReason(reasons, fixture?.protectedContentExcluded !== true, `fixture_protected_content_not_excluded:${fixtureRef}`);
    addReason(reasons, fixture?.productionTrustClaim === true, `fixture_production_trust_claim_attempted:${fixtureRef}`);
    addReason(reasons, hlcTuple(fixture?.scannedAtHlc) === null, `fixture_scanned_hlc_invalid:${fixtureRef}`);
    addReason(reasons, !hlcAfter(fixture?.scannedAtHlc, suite?.compiledAtHlc), `fixture_scanned_before_suite_compile:${fixtureRef}`);

    const detectorRules = sortedTextList(fixture?.detectorRuleIds);
    for (const requiredRule of REQUIRED_DETECTOR_RULE_IDS) {
      addReason(
        reasons,
        !detectorRules.includes(requiredRule),
        `fixture_detector_rule_missing:${fixtureRef}:${requiredRule}`,
      );
    }
    for (const ruleId of detectorRules) {
      addReason(reasons, !DETECTOR_RULE_SET.has(ruleId), `fixture_detector_rule_unsupported:${fixtureRef}:${ruleId}`);
    }
  }
}

function evaluateScanEvidence(scanEvidence, suite, reasons) {
  const commandRefs = sortedTextList(scanEvidence?.commandRefs);
  addReason(reasons, !hasText(scanEvidence?.scannerRef), 'scan_evidence_scanner_ref_absent');
  addReason(reasons, !isDigest(scanEvidence?.scannerVersionHash), 'scan_evidence_scanner_version_hash_invalid');
  addReason(reasons, scanEvidence?.allFixturesPassed !== true, 'scan_evidence_fixtures_not_passed');
  addReason(reasons, scanEvidence?.findingsCount !== 0, 'scan_evidence_findings_present');
  addReason(reasons, scanEvidence?.rawSensitiveFixturesAbsent !== true, 'scan_evidence_raw_sensitive_fixtures_present');
  addReason(reasons, scanEvidence?.secretFixturesAbsent !== true, 'scan_evidence_secret_fixtures_present');
  addReason(reasons, scanEvidence?.exochainSourceExcluded !== true, 'scan_evidence_exochain_source_not_excluded');
  addReason(reasons, scanEvidence?.metadataOnly !== true, 'scan_evidence_not_metadata_only');
  addReason(reasons, scanEvidence?.protectedContentExcluded !== true, 'scan_evidence_protected_content_not_excluded');
  addReason(reasons, !isDigest(scanEvidence?.scanHash), 'scan_evidence_hash_invalid');
  addReason(reasons, hlcTuple(scanEvidence?.scannedAtHlc) === null, 'scan_evidence_hlc_invalid');
  addReason(reasons, !hlcAfter(scanEvidence?.scannedAtHlc, suite?.compiledAtHlc), 'scan_evidence_before_suite_compile');
  addReason(
    reasons,
    !commandRefs.includes('node --test tests/privacy-fixture-boundary.test.mjs'),
    'scan_evidence_focused_test_command_missing',
  );
}

function evaluateHumanReview(review, scanEvidence, reasons) {
  addReason(reasons, !hasText(review?.reviewerDid), 'human_review_reviewer_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.reviewHash), 'human_review_hash_invalid');
  addReason(reasons, review?.aiFinalAuthority === true, 'human_review_ai_final_authority');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'human_review_production_trust_claim_attempted');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_not_metadata_only');
  addReason(reasons, review?.protectedContentExcluded !== true, 'human_review_protected_content_not_excluded');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_hlc_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, scanEvidence?.scannedAtHlc), 'human_review_before_scan');
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance === undefined) {
    return;
  }
  addReason(reasons, aiAssistance?.finalAuthority === true, 'ai_assistance_final_authority_attempted');
  addReason(reasons, aiAssistance?.used === true && !isDigest(aiAssistance?.recommendationHash), 'ai_recommendation_hash_invalid');
  addReason(reasons, aiAssistance?.metadataOnly !== true, 'ai_assistance_not_metadata_only');
  addReason(reasons, aiAssistance?.protectedContentExcluded !== true, 'ai_assistance_protected_content_not_excluded');
}

function buildFixtureProofHash(input, surfaceFamilies, detectorRuleIds) {
  const fixtures = [...(Array.isArray(input?.fixtureCases) ? input.fixtureCases : [])]
    .map((fixture) => ({
      detectorRuleIds: sortedTextList(fixture?.detectorRuleIds),
      fixtureHash: fixture?.fixtureHash,
      fixtureRef: fixture?.fixtureRef,
      negativeProbeHash: fixture?.negativeProbeHash,
      surfaceFamily: fixture?.surfaceFamily,
    }))
    .sort((left, right) => `${left.surfaceFamily}:${left.fixtureRef}`.localeCompare(`${right.surfaceFamily}:${right.fixtureRef}`));

  return sha256Hex({
    detectorRuleIds,
    fixtures,
    scanHash: input?.scanEvidence?.scanHash,
    schema: PRIVACY_FIXTURE_SCHEMA,
    suiteRef: input?.fixtureSuite?.suiteRef,
    surfaceFamilies,
  });
}

function buildBoundary(input, reasons) {
  const surfaceFamilies = REQUIRED_SURFACE_FAMILIES.filter((family) =>
    sortedTextList((input?.fixtureCases ?? []).map((fixture) => fixture?.surfaceFamily)).includes(family),
  );
  const detectorRuleIds = REQUIRED_DETECTOR_RULE_IDS.filter((ruleId) =>
    (input?.fixtureCases ?? []).every((fixture) => sortedTextList(fixture?.detectorRuleIds).includes(ruleId)),
  );

  return {
    schema: PRIVACY_FIXTURE_SCHEMA,
    status: reasons.length === 0 ? 'verified_metadata_only' : 'blocked',
    suiteRef: input?.fixtureSuite?.suiteRef ?? null,
    sourceRef: input?.fixtureSuite?.sourceRef ?? null,
    surfaceFamilies,
    detectorRuleIds,
    fixtureCount: Array.isArray(input?.fixtureCases) ? input.fixtureCases.length : 0,
    scanHash: isDigest(input?.scanEvidence?.scanHash) ? input.scanEvidence.scanHash : null,
    fixtureProofHash: reasons.length === 0 ? buildFixtureProofHash(input, surfaceFamilies, detectorRuleIds) : null,
    exochainProductionClaim: false,
    activationGateIds: [PRIVACY_FIXTURE_ACTIVATION_GATE_ID],
    metadataOnly: true,
    protectedContentExcluded: true,
  };
}

export function evaluatePrivacyFixtureBoundary(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluatePrivacyPolicy(input?.privacyPolicy, reasons);
  evaluateFixtureSuite(input?.fixtureSuite, input?.privacyPolicy, reasons);
  evaluateFixtureCases(input?.fixtureCases, input?.fixtureSuite, reasons);
  evaluateScanEvidence(input?.scanEvidence, input?.fixtureSuite, reasons);
  evaluateHumanReview(input?.humanReview, input?.scanEvidence, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  const boundary = buildBoundary(input, unique);
  const permitted = unique.length === 0;
  const receipt = permitted
    ? createEvidenceReceipt({
        tenantId: input.tenantId,
        actorDid: input.actor.did,
        artifactType: 'privacy_fixture_boundary',
        artifactVersion: input.fixtureSuite.suiteRef,
        artifactHash: boundary.fixtureProofHash,
        classification: 'confidential_metadata_only',
        hlcTimestamp: input.humanReview.reviewedAtHlc,
        custodyDigest: input.custodyDigest,
        sensitivityTags: ['metadata_only', 'privacy_fixture', 'ptag_009'],
        sourceSystem: 'cybermedica-qms',
      })
    : null;

  return {
    schema: DECISION_SCHEMA,
    decision: permitted ? 'permitted' : 'denied',
    failClosed: !permitted,
    reasons: unique,
    privacyFixtureBoundary: boundary,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    protectedContentExcluded: true,
  };
}
