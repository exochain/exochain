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
const CI_CD_SCHEMA = 'cybermedica.ci_cd_quality_gates.v1';
const REQUIRED_PERMISSION = 'ci_cd_gate_review';
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

const REQUIRED_GATE_FAMILIES = Object.freeze([
  'adapter_contract_tests',
  'authority_rbac_tests',
  'build_artifact',
  'consent_revocation_tests',
  'decision_forum_human_gate_tests',
  'dependency_audit',
  'integration_tests',
  'lint_typecheck',
  'privacy_fixture_tests',
  'receipt_determinism_tests',
  'secret_scan',
  'source_guard_tests',
  'tenant_isolation_tests',
  'unit_tests',
]);

const REQUIRED_SOURCE_REFS = Object.freeze([
  'README.md',
  'docs/context/CYBERMEDICA_ADJACENT_SURFACE_DECISIONS.md',
  'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
  'docs/implementation/PATH_CLASSIFICATION.md',
  'package.json',
]);

const REQUIRED_SECRET_SCAN_SCOPES = Object.freeze([
  'README.md',
  'docs/context',
  'docs/implementation',
  'package.json',
  'package-lock.json',
  'scripts',
  'src',
  'tests',
]);

const LINT_TYPECHECK_COMMAND_REF = 'npm run lint:typecheck';
const BUILD_ARTIFACT_COMMAND_REF = 'npm run build:artifact';
const SOURCE_HAZARD_SCAN_COMMAND_REF = 'npm run scan:hazards';

const REQUIRED_LINT_TYPECHECK_SCOPES = Object.freeze(['package.json', 'scripts', 'src', 'tests']);

const REQUIRED_BUILD_ARTIFACT_SCOPES = Object.freeze([
  'README.md',
  'docs/context',
  'docs/implementation',
  'package.json',
  'scripts',
  'src',
  'tests',
]);

const REQUIRED_BUILD_ARTIFACT_FILE_REFS = Object.freeze([
  'CyberMedica_QMS_PRD_Master.docx',
  'CyberMedica_QMS_PRD_Master.pdf',
  'README.md',
  'cyber_medica_qms_prd_master.md',
  'cybermedica_2_0_sandy_seven_layer_master_prd.md',
  'docs/context/CYBERMEDICA_ADJACENT_SURFACE_DECISIONS.md',
  'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
  'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
  'docs/implementation/PATH_CLASSIFICATION.md',
  'package.json',
  'scripts/source-activation-gate-guard.mjs',
  'scripts/source-council-escalation-guard.mjs',
  'scripts/source-hazard-scan.mjs',
  'scripts/source-secret-scan.mjs',
  'src/ci-cd-quality-gates.mjs',
  'src/qms-contracts.mjs',
  'tests/ci-cd-quality-gates.test.mjs',
  'tests/source-council-escalation-guard.test.mjs',
  'tests/source-hazard-scan.test.mjs',
  'tests/source-guards.test.mjs',
  'tests/source-secret-scan.test.mjs',
]);

const BUILD_ARTIFACT_ROOT_FILE_REFS = new Set([
  'CyberMedica_QMS_PRD_Master.docx',
  'CyberMedica_QMS_PRD_Master.pdf',
  'README.md',
  'cyber_medica_qms_prd_master.md',
  'cybermedica_2_0_sandy_seven_layer_master_prd.md',
  'package.json',
]);

const REQUIRED_SOURCE_HAZARD_SCAN_SCOPES = Object.freeze([
  'README.md',
  'docs/context',
  'docs/implementation',
  'package.json',
  'scripts',
  'src',
  'tests',
]);

const POLICY_STATUSES = new Set(['active']);
const GATE_STATUSES = new Set(['passed']);
const HUMAN_REVIEW_DECISIONS = new Set(['release_gate_accepted_inactive_trust', 'hold_for_release_gate_gap']);
const TRUST_STATES = new Set(['inactive', 'verified']);
const DEPENDENCY_AUDIT_PACKAGE_MANAGERS = new Set(['npm']);
const PATH_CLASSIFICATIONS = new Set([
  'Adjacent surface',
  'Adjacent surface documentation',
  'Adjacent surface tests',
  'Core runtime adapter',
]);

const RAW_CI_FIELDS = new Set([
  'body',
  'buildlog',
  'content',
  'freetext',
  'pipelinebody',
  'pipelinenarrative',
  'rawartifact',
  'rawbuildlog',
  'rawcommandoutput',
  'rawcoverage',
  'rawdeployoutput',
  'rawdiff',
  'rawevidence',
  'rawpipeline',
  'rawpipelinelog',
  'rawreleaseevidence',
  'rawsecretfinding',
  'rawsecretmatch',
  'rawsecretoutput',
  'rawtestoutput',
  'reviewnotes',
  'secretfindingsnippet',
  'secretfindingvalue',
  'secretmatch',
  'secretpayload',
  'sourcebody',
  'sourcedocumentbody',
  'testlog',
]);

const SECRET_CI_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'bootstrapsecret',
  'bootstraptoken',
  'clientsecret',
  'credential',
  'credentialsecret',
  'password',
  'privatekey',
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

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && value !== ZERO_HASH;
}

function isBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 10_000;
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

function assertNoRawCiContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawCiContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_CI_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw CI/CD quality gate content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_CI_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`CI/CD quality gate secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawCiContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawCiContent(input ?? {});
  canonicalize(input ?? {});
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function hasParentOrAbsolutePathRef(pathRef) {
  return (
    !hasText(pathRef) ||
    pathRef.startsWith('/') ||
    pathRef.startsWith('..') ||
    pathRef.includes('/../') ||
    pathRef.includes('\\')
  );
}

function isGeneratedDependencyTreePath(pathRef) {
  return pathRef === 'node_modules' || pathRef.startsWith('node_modules/') || pathRef.includes('/node_modules/');
}

function isAllowedBuildArtifactFileRef(pathRef) {
  if (hasParentOrAbsolutePathRef(pathRef) || isGeneratedDependencyTreePath(pathRef)) {
    return false;
  }
  if (BUILD_ARTIFACT_ROOT_FILE_REFS.has(pathRef)) {
    return true;
  }
  if (pathRef.startsWith('docs/context/') && pathRef.endsWith('.md')) {
    return true;
  }
  if (pathRef.startsWith('docs/implementation/') && pathRef.endsWith('.md')) {
    return true;
  }
  if (pathRef.startsWith('scripts/') && pathRef.endsWith('.mjs')) {
    return true;
  }
  if (pathRef.startsWith('src/') && pathRef.endsWith('.mjs')) {
    return true;
  }
  return pathRef.startsWith('tests/') && pathRef.endsWith('.test.mjs');
}

function coveredRequiredBuildArtifactFileRefs(artifactFileRefs) {
  const fileRefSet = new Set(artifactFileRefs);
  return REQUIRED_BUILD_ARTIFACT_FILE_REFS.filter((pathRef) => fileRefSet.has(pathRef));
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

function latestHlc(values) {
  let latest = null;
  for (const hlc of values) {
    const tuple = hlcTuple(hlc);
    if (tuple === null) {
      continue;
    }
    if (latest === null || compareHlc(tuple, latest) > 0) {
      latest = tuple;
    }
  }
  return latest === null ? null : { physicalMs: latest[0], logical: latest[1] };
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateRequiredSet(actual, expected, missingPrefix, unsupportedPrefix, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !expected.includes(value), `${unsupportedPrefix}:${value}`);
  }
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_release_gate_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'ci_cd_gate_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateGatePolicy(policy, reasons) {
  const requiredGateFamilies = sortedTextList(policy?.requiredGateFamilies);
  const requiredSourceRefs = sortedTextList(policy?.requiredSourceRefs);

  addReason(reasons, !hasText(policy?.policyRef), 'gate_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'gate_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'gate_policy_not_active');
  addReason(reasons, !isBasisPoints(policy?.minimumLineCoverageBasisPoints), 'line_coverage_threshold_invalid');
  addReason(
    reasons,
    !isBasisPoints(policy?.minimumTrustBoundaryCoverageBasisPoints),
    'trust_boundary_coverage_threshold_invalid',
  );
  addReason(
    reasons,
    policy?.blocksProductionTrustClaimsWithoutActivation !== true,
    'production_trust_claim_blocker_absent',
  );
  addReason(reasons, policy?.requiresNoExochainSourceModified !== true, 'exochain_source_firewall_absent');
  addReason(
    reasons,
    policy?.requiresDeterministicSourceControls !== true,
    'deterministic_source_control_policy_absent',
  );
  addReason(reasons, policy?.requiresMetadataOnlyArtifacts !== true, 'metadata_only_gate_absent');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'gate_policy_protected_boundary_invalid');
  addReason(reasons, policy?.metadataOnly !== true, 'gate_policy_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'gate_policy_time_invalid');

  evaluateRequiredSet(
    requiredGateFamilies,
    REQUIRED_GATE_FAMILIES,
    'policy_missing_gate_family',
    'policy_unsupported_gate_family',
    reasons,
  );
  evaluateRequiredSet(
    requiredSourceRefs,
    REQUIRED_SOURCE_REFS,
    'policy_missing_source_ref',
    'policy_unsupported_source_ref',
    reasons,
  );

  return {
    requiredGateFamilies,
    requiredSourceRefs,
  };
}

function evaluateReleaseCandidate(releaseCandidate, activationGateReview, reasons) {
  addReason(reasons, !hasText(releaseCandidate?.releaseCandidateRef), 'release_candidate_ref_absent');
  addReason(reasons, !isDigest(releaseCandidate?.commitHash), 'release_candidate_commit_hash_invalid');
  addReason(reasons, !hasText(releaseCandidate?.branchRef), 'release_candidate_branch_absent');
  addReason(reasons, releaseCandidate?.metadataOnly !== true, 'release_candidate_metadata_boundary_invalid');
  addReason(
    reasons,
    releaseCandidate?.protectedContentExcluded !== true,
    'release_candidate_protected_boundary_invalid',
  );
  addReason(reasons, hlcTuple(releaseCandidate?.openedAtHlc) === null, 'release_candidate_open_time_invalid');
  addReason(reasons, hlcTuple(releaseCandidate?.gatesStartedAtHlc) === null, 'gates_started_time_invalid');
  addReason(reasons, hlcTuple(releaseCandidate?.gatesCompletedAtHlc) === null, 'gates_completed_time_invalid');

  const activationVerified = activationGateReview?.trustState === 'verified';
  addReason(
    reasons,
    releaseCandidate?.productionTrustClaim === true && !activationVerified,
    'production_trust_claim_before_activation',
  );
  addReason(
    reasons,
    releaseCandidate?.exochainBackedLanguageActive === true && !activationVerified,
    'exochain_backed_language_before_activation',
  );
  addReason(
    reasons,
    releaseCandidate?.rootBackedAuthorityClaimActive === true && !activationVerified,
    'root_backed_authority_claim_before_activation',
  );
}

function evaluateChangedPaths(paths, reasons) {
  const pathRows = [];
  for (const row of Array.isArray(paths) ? paths : []) {
    const path = hasText(row?.path) ? row.path : 'unknown';
    const classification = hasText(row?.classification) ? row.classification : 'unclassified';
    addReason(reasons, !hasText(row?.path), 'changed_path_absent');
    addReason(reasons, !PATH_CLASSIFICATIONS.has(classification), `path_classification_invalid:${path}`);
    addReason(reasons, row?.documentedInPathClassification !== true, `source_path_missing_classification:${path}`);
    addReason(
      reasons,
      path.startsWith('src/') && row?.documentedInReadme !== true,
      `source_path_missing_readme_row:${path}`,
    );
    addReason(reasons, row?.coveredBySourceGuard !== true, `path_source_guard_missing:${path}`);
    addReason(reasons, row?.exochainCoreModified === true, `exochain_source_modified:${path}`);
    addReason(reasons, row?.importedEvidence === true, `imported_evidence_committed:${path}`);
    addReason(reasons, row?.metadataOnly !== true, `path_metadata_boundary_invalid:${path}`);
    pathRows.push({
      path,
      classification,
      exochainCoreModified: row?.exochainCoreModified === true,
      importedEvidence: row?.importedEvidence === true,
    });
  }
  addReason(reasons, pathRows.length === 0, 'changed_paths_absent');
  return [...pathRows].sort((left, right) => left.path.localeCompare(right.path));
}

function evaluateGateResults(gateResults, expectedGateFamilies, reasons) {
  const gateByFamily = new Map();
  for (const gate of Array.isArray(gateResults) ? gateResults : []) {
    if (hasText(gate?.family) && !gateByFamily.has(gate.family)) {
      gateByFamily.set(gate.family, gate);
    }
  }

  const gateFamilies = [...gateByFamily.keys()].sort();
  evaluateRequiredSet(gateFamilies, expectedGateFamilies, 'missing_gate_family', 'unsupported_gate_family', reasons);

  for (const [family, gate] of gateByFamily.entries()) {
    addReason(reasons, !GATE_STATUSES.has(gate?.status), `gate_not_passed:${family}`);
    addReason(reasons, !hasText(gate?.commandRef), `gate_command_ref_absent:${family}`);
    addReason(reasons, !isDigest(gate?.evidenceHash), `gate_evidence_hash_invalid:${family}`);
    addReason(reasons, gate?.blocksRelease !== true, `gate_not_release_blocking:${family}`);
    addReason(reasons, gate?.metadataOnly !== true, `gate_metadata_boundary_invalid:${family}`);
    addReason(reasons, gate?.protectedContentExcluded !== true, `gate_protected_boundary_invalid:${family}`);
    addReason(reasons, hlcTuple(gate?.startedAtHlc) === null, `gate_start_time_invalid:${family}`);
    addReason(reasons, hlcTuple(gate?.completedAtHlc) === null, `gate_completion_time_invalid:${family}`);
    addReason(
      reasons,
      hlcBefore(gate?.completedAtHlc, gate?.startedAtHlc) || compareEqualHlc(gate?.completedAtHlc, gate?.startedAtHlc),
      `gate_completed_before_started:${family}`,
    );
  }

  return gateFamilies.filter((family) => {
    const gate = gateByFamily.get(family);
    return (
      gate !== undefined &&
      GATE_STATUSES.has(gate.status) &&
      hasText(gate.commandRef) &&
      isDigest(gate.evidenceHash) &&
      gate.blocksRelease === true &&
      gate.metadataOnly === true &&
      gate.protectedContentExcluded === true &&
      hlcTuple(gate.startedAtHlc) !== null &&
      hlcAfter(gate.completedAtHlc, gate.startedAtHlc)
    );
  });
}

function compareEqualHlc(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) === 0;
}

function evaluateCoverage(coverage, policy, reasons) {
  addReason(reasons, !isBasisPoints(coverage?.lineCoverageBasisPoints), 'line_coverage_invalid');
  addReason(reasons, !isBasisPoints(coverage?.branchCoverageBasisPoints), 'branch_coverage_invalid');
  addReason(reasons, !isBasisPoints(coverage?.functionCoverageBasisPoints), 'function_coverage_invalid');
  addReason(reasons, !isBasisPoints(coverage?.trustBoundaryCoverageBasisPoints), 'trust_boundary_coverage_invalid');
  addReason(
    reasons,
    isBasisPoints(coverage?.lineCoverageBasisPoints) &&
      isBasisPoints(policy?.minimumLineCoverageBasisPoints) &&
      coverage.lineCoverageBasisPoints < policy.minimumLineCoverageBasisPoints,
    'line_coverage_below_threshold',
  );
  addReason(
    reasons,
    isBasisPoints(coverage?.trustBoundaryCoverageBasisPoints) &&
      isBasisPoints(policy?.minimumTrustBoundaryCoverageBasisPoints) &&
      coverage.trustBoundaryCoverageBasisPoints < policy.minimumTrustBoundaryCoverageBasisPoints,
    'trust_boundary_coverage_below_threshold',
  );
  addReason(reasons, !isDigest(coverage?.coverageReportHash), 'coverage_report_hash_invalid');
  addReason(reasons, coverage?.deterministicHazardsAbsent !== true, 'deterministic_hazard_guard_failed');
  addReason(reasons, coverage?.systemTimeSourceAbsent !== true, 'system_time_source_guard_failed');
  addReason(reasons, coverage?.randomnessSourceAbsent !== true, 'randomness_source_guard_failed');
  addReason(reasons, coverage?.floatingPointArithmeticAbsent !== true, 'floating_point_arithmetic_guard_failed');
  addReason(reasons, coverage?.dynamicCodeExecutionAbsent !== true, 'dynamic_code_execution_guard_failed');
  addReason(reasons, coverage?.unboundedWorkflowLoopAbsent !== true, 'unbounded_workflow_loop_guard_failed');
  addReason(reasons, !isDigest(coverage?.sourceHazardScanHash), 'source_hazard_scan_hash_invalid');
  addReason(reasons, coverage?.placeholderLanguageAbsent !== true, 'placeholder_language_guard_failed');
  addReason(reasons, coverage?.rawSensitiveFixtureAbsent !== true, 'raw_sensitive_fixture_guard_failed');
  addReason(reasons, coverage?.metadataOnly !== true, 'coverage_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(coverage?.recordedAtHlc) === null, 'coverage_record_time_invalid');
}

function evaluateSourceGuard(sourceGuard, reasons) {
  addReason(reasons, !GATE_STATUSES.has(sourceGuard?.status), 'source_guard_not_passed');
  addReason(reasons, !hasText(sourceGuard?.commandRef), 'source_guard_command_ref_absent');
  addReason(reasons, sourceGuard?.readmeUpdated !== true, 'source_guard_readme_not_updated');
  addReason(reasons, sourceGuard?.pathClassificationUpdated !== true, 'source_guard_path_classification_not_updated');
  addReason(reasons, sourceGuard?.implementedContractsCovered !== true, 'source_guard_contract_inventory_incomplete');
  addReason(reasons, sourceGuard?.noImportedEvidenceCommitted !== true, 'source_guard_imported_evidence_committed');
  addReason(reasons, sourceGuard?.noExochainSourceModified !== true, 'source_guard_exochain_source_modified');
  addReason(reasons, sourceGuard?.noSystemTimeInSource !== true, 'source_guard_system_time_not_verified');
  addReason(reasons, sourceGuard?.noRandomnessInSource !== true, 'source_guard_randomness_not_verified');
  addReason(
    reasons,
    sourceGuard?.noFloatingPointArithmeticInSource !== true,
    'source_guard_float_arithmetic_not_verified',
  );
  addReason(
    reasons,
    sourceGuard?.noDynamicCodeExecutionInSource !== true,
    'source_guard_dynamic_code_execution_not_verified',
  );
  addReason(reasons, sourceGuard?.boundedWorkflowLoopsVerified !== true, 'source_guard_bounded_loops_not_verified');
  addReason(reasons, !isDigest(sourceGuard?.evidenceHash), 'source_guard_evidence_hash_invalid');
  addReason(reasons, sourceGuard?.metadataOnly !== true, 'source_guard_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(sourceGuard?.evaluatedAtHlc) === null, 'source_guard_time_invalid');
}

function evaluateSourceHazardScanEvidence(sourceHazardScan, coverage, releaseCandidate, reasons) {
  const scannedPathRefs = sortedTextList(sourceHazardScan?.scannedPathRefs);

  addReason(reasons, !GATE_STATUSES.has(sourceHazardScan?.status), 'source_hazard_scan_not_passed');
  addReason(reasons, !hasText(sourceHazardScan?.commandRef), 'source_hazard_scan_command_ref_absent');
  addReason(
    reasons,
    hasText(sourceHazardScan?.commandRef) && sourceHazardScan.commandRef !== SOURCE_HAZARD_SCAN_COMMAND_REF,
    'source_hazard_scan_command_ref_invalid',
  );
  addReason(reasons, !isDigest(sourceHazardScan?.scanReportHash), 'source_hazard_scan_report_hash_invalid');
  addReason(
    reasons,
    isDigest(sourceHazardScan?.scanReportHash) &&
      isDigest(coverage?.sourceHazardScanHash) &&
      sourceHazardScan.scanReportHash !== coverage.sourceHazardScanHash,
    'source_hazard_scan_hash_mismatch',
  );
  evaluateRequiredSet(
    scannedPathRefs,
    REQUIRED_SOURCE_HAZARD_SCAN_SCOPES,
    'source_hazard_scan_scope_missing',
    'source_hazard_scan_scope_unsupported',
    reasons,
  );
  addReason(reasons, sourceHazardScan?.exochainSourceExcluded !== true, 'source_hazard_scan_exochain_source_not_excluded');
  addReason(
    reasons,
    sourceHazardScan?.deterministicHazardsAbsent !== true,
    'source_hazard_scan_deterministic_hazards_present',
  );
  addReason(reasons, sourceHazardScan?.metadataOnly !== true, 'source_hazard_scan_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(sourceHazardScan?.recordedAtHlc) === null, 'source_hazard_scan_time_invalid');
  addReason(
    reasons,
    !hlcAfter(sourceHazardScan?.recordedAtHlc, releaseCandidate?.gatesCompletedAtHlc),
    'source_hazard_scan_before_gates_completed',
  );
}

function evaluateDependencyAuditEvidence(dependencyAudit, releaseCandidate, reasons) {
  const vulnerabilityCounts = [
    dependencyAudit?.totalVulnerabilities,
    dependencyAudit?.criticalVulnerabilities,
    dependencyAudit?.highVulnerabilities,
    dependencyAudit?.moderateVulnerabilities,
  ];

  addReason(reasons, !GATE_STATUSES.has(dependencyAudit?.status), 'dependency_audit_not_passed');
  addReason(reasons, !hasText(dependencyAudit?.commandRef), 'dependency_audit_command_ref_absent');
  addReason(
    reasons,
    !DEPENDENCY_AUDIT_PACKAGE_MANAGERS.has(dependencyAudit?.packageManager),
    'dependency_audit_package_manager_invalid',
  );
  addReason(reasons, dependencyAudit?.packageManifestRef !== 'package.json', 'dependency_audit_manifest_ref_invalid');
  addReason(reasons, dependencyAudit?.lockfileRef !== 'package-lock.json', 'dependency_audit_lockfile_ref_invalid');
  addReason(reasons, !isDigest(dependencyAudit?.lockfileHash), 'dependency_audit_lockfile_hash_invalid');
  addReason(reasons, !hasText(dependencyAudit?.advisoryDatabaseRef), 'dependency_audit_database_ref_absent');
  addReason(reasons, !isDigest(dependencyAudit?.auditReportHash), 'dependency_audit_report_hash_invalid');
  addReason(
    reasons,
    dependencyAudit?.productionDependenciesAudited !== true,
    'dependency_audit_production_scope_absent',
  );
  addReason(
    reasons,
    dependencyAudit?.developmentDependenciesAudited !== true,
    'dependency_audit_development_scope_absent',
  );
  addReason(
    reasons,
    vulnerabilityCounts.some((count) => !isNonNegativeSafeInteger(count)),
    'dependency_audit_vulnerability_count_invalid',
  );
  addReason(
    reasons,
    vulnerabilityCounts.some((count) => isNonNegativeSafeInteger(count) && count > 0),
    'dependency_audit_vulnerabilities_present',
  );
  addReason(reasons, dependencyAudit?.metadataOnly !== true, 'dependency_audit_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(dependencyAudit?.recordedAtHlc) === null, 'dependency_audit_time_invalid');
  addReason(
    reasons,
    !hlcAfter(dependencyAudit?.recordedAtHlc, releaseCandidate?.gatesCompletedAtHlc),
    'dependency_audit_before_gates_completed',
  );
}

function evaluateLintTypecheckEvidence(lintTypecheck, releaseCandidate, reasons) {
  const checkedPathRefs = sortedTextList(lintTypecheck?.checkedPathRefs);

  addReason(reasons, !GATE_STATUSES.has(lintTypecheck?.status), 'lint_typecheck_not_passed');
  addReason(reasons, !hasText(lintTypecheck?.commandRef), 'lint_typecheck_command_ref_absent');
  addReason(
    reasons,
    hasText(lintTypecheck?.commandRef) && lintTypecheck.commandRef !== LINT_TYPECHECK_COMMAND_REF,
    'lint_typecheck_command_ref_invalid',
  );
  addReason(reasons, !isDigest(lintTypecheck?.reportHash), 'lint_typecheck_report_hash_invalid');
  evaluateRequiredSet(
    checkedPathRefs,
    REQUIRED_LINT_TYPECHECK_SCOPES,
    'lint_typecheck_scope_missing',
    'lint_typecheck_scope_unsupported',
    reasons,
  );
  addReason(reasons, lintTypecheck?.moduleSyntaxChecked !== true, 'lint_typecheck_module_syntax_not_verified');
  addReason(reasons, lintTypecheck?.typeBoundaryReviewed !== true, 'lint_typecheck_type_boundary_not_reviewed');
  addReason(reasons, lintTypecheck?.metadataOnly !== true, 'lint_typecheck_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(lintTypecheck?.recordedAtHlc) === null, 'lint_typecheck_time_invalid');
  addReason(
    reasons,
    !hlcAfter(lintTypecheck?.recordedAtHlc, releaseCandidate?.gatesCompletedAtHlc),
    'lint_typecheck_before_gates_completed',
  );
}

function evaluateBuildArtifactEvidence(buildArtifact, releaseCandidate, reasons) {
  const includedPathRefs = sortedTextList(buildArtifact?.includedPathRefs);
  const artifactFileRefs = sortedTextList(buildArtifact?.artifactFileRefs);

  addReason(reasons, !GATE_STATUSES.has(buildArtifact?.status), 'build_artifact_not_passed');
  addReason(reasons, !hasText(buildArtifact?.commandRef), 'build_artifact_command_ref_absent');
  addReason(
    reasons,
    hasText(buildArtifact?.commandRef) && buildArtifact.commandRef !== BUILD_ARTIFACT_COMMAND_REF,
    'build_artifact_command_ref_invalid',
  );
  addReason(reasons, !isDigest(buildArtifact?.artifactManifestHash), 'build_artifact_manifest_hash_invalid');
  addReason(reasons, !isDigest(buildArtifact?.artifactFileManifestHash), 'build_artifact_file_manifest_hash_invalid');
  addReason(reasons, artifactFileRefs.length === 0, 'build_artifact_file_refs_absent');
  for (const pathRef of REQUIRED_BUILD_ARTIFACT_FILE_REFS) {
    addReason(reasons, !artifactFileRefs.includes(pathRef), `build_artifact_file_ref_missing:${pathRef}`);
  }
  for (const pathRef of artifactFileRefs) {
    addReason(reasons, !isAllowedBuildArtifactFileRef(pathRef), `build_artifact_file_ref_forbidden:${pathRef}`);
    addReason(
      reasons,
      hasParentOrAbsolutePathRef(pathRef),
      `build_artifact_parent_or_absolute_path_ref:${pathRef}`,
    );
  }
  addReason(reasons, !isPositiveSafeInteger(buildArtifact?.artifactFileCount), 'build_artifact_file_count_invalid');
  addReason(
    reasons,
    isPositiveSafeInteger(buildArtifact?.artifactFileCount) &&
      artifactFileRefs.length > 0 &&
      buildArtifact.artifactFileCount !== artifactFileRefs.length,
    'build_artifact_file_count_mismatch',
  );
  addReason(reasons, !isDigest(buildArtifact?.packageManifestHash), 'build_artifact_package_manifest_hash_invalid');
  evaluateRequiredSet(
    includedPathRefs,
    REQUIRED_BUILD_ARTIFACT_SCOPES,
    'build_artifact_scope_missing',
    'build_artifact_scope_unsupported',
    reasons,
  );
  addReason(reasons, buildArtifact?.dryRunOnly !== true, 'build_artifact_dry_run_only_absent');
  addReason(reasons, buildArtifact?.tarballWritten !== false, 'build_artifact_tarball_written');
  addReason(reasons, buildArtifact?.packagePrivate !== true, 'build_artifact_package_not_private');
  addReason(reasons, buildArtifact?.exochainSourceExcluded !== true, 'build_artifact_exochain_source_not_excluded');
  addReason(reasons, buildArtifact?.importedEvidenceExcluded !== true, 'build_artifact_imported_evidence_not_excluded');
  addReason(
    reasons,
    buildArtifact?.generatedDependencyTreeExcluded !== true,
    'build_artifact_generated_dependency_tree_not_excluded',
  );
  addReason(
    reasons,
    buildArtifact?.parentOrAbsolutePathRefsExcluded !== true,
    'build_artifact_parent_or_absolute_path_refs_not_excluded',
  );
  addReason(
    reasons,
    buildArtifact?.protectedFixtureFilesExcluded !== true,
    'build_artifact_protected_fixture_files_not_excluded',
  );
  addReason(reasons, buildArtifact?.secretFilesExcluded !== true, 'build_artifact_secret_files_not_excluded');
  addReason(reasons, buildArtifact?.protectedContentExcluded !== true, 'build_artifact_protected_boundary_invalid');
  addReason(reasons, buildArtifact?.metadataOnly !== true, 'build_artifact_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(buildArtifact?.recordedAtHlc) === null, 'build_artifact_time_invalid');
  addReason(
    reasons,
    !hlcAfter(buildArtifact?.recordedAtHlc, releaseCandidate?.gatesCompletedAtHlc),
    'build_artifact_before_gates_completed',
  );
}

function evaluateSecretScanEvidence(secretScan, releaseCandidate, reasons) {
  const scannedPathRefs = sortedTextList(secretScan?.scannedPathRefs);

  addReason(reasons, !GATE_STATUSES.has(secretScan?.status), 'secret_scan_not_passed');
  addReason(reasons, !hasText(secretScan?.commandRef), 'secret_scan_command_ref_absent');
  addReason(reasons, !hasText(secretScan?.scannerRef), 'secret_scan_scanner_ref_absent');
  addReason(reasons, !isDigest(secretScan?.scannerVersionHash), 'secret_scan_scanner_version_hash_invalid');
  addReason(reasons, !isDigest(secretScan?.scanReportHash), 'secret_scan_report_hash_invalid');
  evaluateRequiredSet(
    scannedPathRefs,
    REQUIRED_SECRET_SCAN_SCOPES,
    'secret_scan_scope_missing',
    'secret_scan_scope_unsupported',
    reasons,
  );
  addReason(reasons, secretScan?.exochainSourceExcluded !== true, 'secret_scan_exochain_source_not_excluded');
  addReason(reasons, secretScan?.secretMaterialAbsent !== true, 'secret_scan_secret_material_present');
  addReason(reasons, secretScan?.rootKeyMaterialAbsent !== true, 'secret_scan_root_key_material_present');
  addReason(reasons, secretScan?.bootstrapTokenAbsent !== true, 'secret_scan_bootstrap_token_present');
  addReason(reasons, !isNonNegativeSafeInteger(secretScan?.findingsCount), 'secret_scan_findings_count_invalid');
  addReason(
    reasons,
    !isNonNegativeSafeInteger(secretScan?.highRiskFindingsCount),
    'secret_scan_high_risk_findings_count_invalid',
  );
  addReason(
    reasons,
    isNonNegativeSafeInteger(secretScan?.findingsCount) && secretScan.findingsCount > 0,
    'secret_scan_findings_present',
  );
  addReason(
    reasons,
    isNonNegativeSafeInteger(secretScan?.highRiskFindingsCount) && secretScan.highRiskFindingsCount > 0,
    'secret_scan_high_risk_findings_present',
  );
  addReason(reasons, secretScan?.metadataOnly !== true, 'secret_scan_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(secretScan?.recordedAtHlc) === null, 'secret_scan_time_invalid');
  addReason(
    reasons,
    !hlcAfter(secretScan?.recordedAtHlc, releaseCandidate?.gatesCompletedAtHlc),
    'secret_scan_before_gates_completed',
  );
}

function evaluateActivationGates(activationGateReview, reasons) {
  addReason(reasons, !TRUST_STATES.has(activationGateReview?.trustState), 'activation_gate_trust_state_invalid');
  addReason(
    reasons,
    activationGateReview?.productionTrustClaimsActive === true &&
      activationGateReview?.trustState !== 'verified',
    'production_trust_claims_active_without_activation',
  );
  addReason(reasons, activationGateReview?.noBrowserPhiTrustPath !== true, 'browser_phi_trust_path_not_disabled');
  addReason(reasons, activationGateReview?.noRootBackedProductionClaim !== true, 'root_authority_claim_not_disabled');
  addReason(reasons, !isDigest(activationGateReview?.evidenceHash), 'activation_gate_evidence_hash_invalid');
  addReason(reasons, activationGateReview?.metadataOnly !== true, 'activation_gate_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(activationGateReview?.reviewedAtHlc) === null, 'activation_gate_review_time_invalid');
}

function evaluateHumanReview(review, reasons) {
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, !Array.isArray(review?.reviewerRoleRefs) || review.reviewerRoleRefs.length === 0, 'human_review_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_final_authority_required');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'production_trust_claim_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance === null || aiAssistance === undefined || aiAssistance.used !== true) {
    return;
  }
  addReason(reasons, aiAssistance.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, aiAssistance.reviewedByHuman !== true, 'ai_recommendation_without_human_review');
  addReason(reasons, !isDigest(aiAssistance.recommendationHash), 'ai_recommendation_hash_invalid');
  for (const hash of Array.isArray(aiAssistance.limitationHashes) ? aiAssistance.limitationHashes : []) {
    addReason(reasons, !isDigest(hash), 'ai_limitation_hash_invalid');
  }
}

function evaluateHlcOrdering(input, reasons) {
  addReason(
    reasons,
    !hlcAfter(input?.releaseCandidate?.openedAtHlc, input?.gatePolicy?.evaluatedAtHlc),
    'release_opened_before_policy',
  );
  addReason(
    reasons,
    !hlcAfter(input?.releaseCandidate?.gatesStartedAtHlc, input?.releaseCandidate?.openedAtHlc),
    'gates_started_before_release_opened',
  );
  addReason(
    reasons,
    !hlcAfter(input?.releaseCandidate?.gatesCompletedAtHlc, input?.releaseCandidate?.gatesStartedAtHlc),
    'gates_completed_before_started',
  );
  addReason(
    reasons,
    !hlcAfter(input?.coverageEvidence?.recordedAtHlc, input?.releaseCandidate?.gatesCompletedAtHlc),
    'coverage_recorded_before_gates_completed',
  );
  addReason(
    reasons,
    !hlcAfter(input?.sourceGuardEvidence?.evaluatedAtHlc, input?.releaseCandidate?.gatesCompletedAtHlc),
    'source_guard_before_gates_completed',
  );

  const gateEvidenceHlc = latestHlc([
    input?.releaseCandidate?.gatesCompletedAtHlc,
    input?.coverageEvidence?.recordedAtHlc,
    input?.sourceHazardScanEvidence?.recordedAtHlc,
    input?.sourceGuardEvidence?.evaluatedAtHlc,
    input?.dependencyAuditEvidence?.recordedAtHlc,
    input?.lintTypecheckEvidence?.recordedAtHlc,
    input?.buildArtifactEvidence?.recordedAtHlc,
    input?.secretScanEvidence?.recordedAtHlc,
    input?.activationGateReview?.reviewedAtHlc,
  ]);
  addReason(
    reasons,
    gateEvidenceHlc === null || !hlcAfter(input?.humanReview?.reviewedAtHlc, gateEvidenceHlc),
    'human_review_before_gate_evidence',
  );
}

function buildGateRecord(input, coveredFamilies, changedPathRows, blockedBy) {
  const gateRecordBase = {
    schema: CI_CD_SCHEMA,
    tenantId: input.tenantId,
    releaseCandidateRef: input.releaseCandidate.releaseCandidateRef,
    commitHash: input.releaseCandidate.commitHash,
    gateFamiliesCovered: uniqueSorted(coveredFamilies),
    requiredSourceRefs: sortedTextList(input.gatePolicy.requiredSourceRefs),
    changedPaths: changedPathRows,
    lineCoverageBasisPoints: input.coverageEvidence.lineCoverageBasisPoints,
    branchCoverageBasisPoints: input.coverageEvidence.branchCoverageBasisPoints,
    functionCoverageBasisPoints: input.coverageEvidence.functionCoverageBasisPoints,
    trustBoundaryCoverageBasisPoints: input.coverageEvidence.trustBoundaryCoverageBasisPoints,
    deterministicSourceControls: {
      boundedWorkflowLoopsVerified: input.sourceGuardEvidence.boundedWorkflowLoopsVerified === true,
      dynamicCodeExecutionAbsent:
        input.coverageEvidence.dynamicCodeExecutionAbsent === true &&
        input.sourceGuardEvidence.noDynamicCodeExecutionInSource === true,
      floatingPointArithmeticAbsent:
        input.coverageEvidence.floatingPointArithmeticAbsent === true &&
        input.sourceGuardEvidence.noFloatingPointArithmeticInSource === true,
      randomnessSourceAbsent:
        input.coverageEvidence.randomnessSourceAbsent === true && input.sourceGuardEvidence.noRandomnessInSource === true,
      sourceHazardScanCommandRef: input.sourceHazardScanEvidence.commandRef,
      sourceHazardScanHash: input.coverageEvidence.sourceHazardScanHash,
      sourceHazardScanReportHash: input.sourceHazardScanEvidence.scanReportHash,
      sourceHazardScanScopes: sortedTextList(input.sourceHazardScanEvidence.scannedPathRefs),
      systemTimeSourceAbsent:
        input.coverageEvidence.systemTimeSourceAbsent === true && input.sourceGuardEvidence.noSystemTimeInSource === true,
    },
    releaseSecurityEvidence: {
      dependencyAuditCommandRef: input.dependencyAuditEvidence.commandRef,
      dependencyAuditReportHash: input.dependencyAuditEvidence.auditReportHash,
      lockfileHash: input.dependencyAuditEvidence.lockfileHash,
      secretScanCommandRef: input.secretScanEvidence.commandRef,
      secretScanReportHash: input.secretScanEvidence.scanReportHash,
      secretScanScopes: sortedTextList(input.secretScanEvidence.scannedPathRefs),
    },
    releaseCommandEvidence: {
      buildArtifactCommandRef: input.buildArtifactEvidence.commandRef,
      buildArtifactDryRunOnly: input.buildArtifactEvidence.dryRunOnly === true,
      buildArtifactFileCount: input.buildArtifactEvidence.artifactFileCount,
      buildArtifactFileManifestHash: input.buildArtifactEvidence.artifactFileManifestHash,
      buildArtifactManifestHash: input.buildArtifactEvidence.artifactManifestHash,
      buildArtifactRequiredFileRefs: coveredRequiredBuildArtifactFileRefs(
        sortedTextList(input.buildArtifactEvidence.artifactFileRefs),
      ),
      buildArtifactTarballWritten: input.buildArtifactEvidence.tarballWritten === true,
      buildIncludedScopes: sortedTextList(input.buildArtifactEvidence.includedPathRefs),
      lintTypecheckCommandRef: input.lintTypecheckEvidence.commandRef,
      lintTypecheckReportHash: input.lintTypecheckEvidence.reportHash,
      lintTypecheckScopes: sortedTextList(input.lintTypecheckEvidence.checkedPathRefs),
      moduleSyntaxChecked: input.lintTypecheckEvidence.moduleSyntaxChecked === true,
      packageManifestHash: input.buildArtifactEvidence.packageManifestHash,
      packagePrivate: input.buildArtifactEvidence.packagePrivate === true,
      typeBoundaryReviewed: input.lintTypecheckEvidence.typeBoundaryReviewed === true,
    },
    sourceGuardCommandRef: input.sourceGuardEvidence.commandRef,
    activationGateState: input.activationGateReview.trustState,
    unverifiedActivationGateIds: sortedTextList(input.activationGateReview.unverifiedActivationGateIds),
    verifiedActivationGateIds: sortedTextList(input.activationGateReview.verifiedActivationGateIds),
    productionTrustClaimsActive: input.activationGateReview.productionTrustClaimsActive === true,
    blockedBy: uniqueSorted(blockedBy),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
  return {
    ...gateRecordBase,
    gateHash: sha256Hex(gateRecordBase),
  };
}

export function evaluateCiCdQualityGates(input = {}) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policy = evaluateGatePolicy(input?.gatePolicy, reasons);
  evaluateReleaseCandidate(input?.releaseCandidate, input?.activationGateReview, reasons);
  const changedPathRows = evaluateChangedPaths(input?.changedPaths, reasons);
  const coveredFamilies = evaluateGateResults(input?.gateResults, policy.requiredGateFamilies, reasons);
  evaluateCoverage(input?.coverageEvidence, input?.gatePolicy, reasons);
  evaluateSourceHazardScanEvidence(input?.sourceHazardScanEvidence, input?.coverageEvidence, input?.releaseCandidate, reasons);
  evaluateSourceGuard(input?.sourceGuardEvidence, reasons);
  evaluateDependencyAuditEvidence(input?.dependencyAuditEvidence, input?.releaseCandidate, reasons);
  evaluateLintTypecheckEvidence(input?.lintTypecheckEvidence, input?.releaseCandidate, reasons);
  evaluateBuildArtifactEvidence(input?.buildArtifactEvidence, input?.releaseCandidate, reasons);
  evaluateSecretScanEvidence(input?.secretScanEvidence, input?.releaseCandidate, reasons);
  evaluateActivationGates(input?.activationGateReview, reasons);
  evaluateHumanReview(input?.humanReview, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
  evaluateHlcOrdering(input, reasons);

  const blockedBy = uniqueReasons(reasons);
  const allowed = blockedBy.length === 0;
  const gateRecord = allowed ? buildGateRecord(input, coveredFamilies, changedPathRows, blockedBy) : null;

  return {
    schema: CI_CD_SCHEMA,
    allowed,
    state: allowed ? 'release_allowed_inactive_trust' : 'release_blocked',
    trustState: 'inactive',
    exochainProductionClaim: false,
    blockedBy,
    requiredGateFamilies: [...REQUIRED_GATE_FAMILIES],
    gateFamiliesCovered: uniqueSorted(coveredFamilies),
    gateRecord,
    receipt: allowed
      ? createEvidenceReceipt({
          tenantId: input.tenantId,
          actorDid: input.actor.did,
          artifactType: 'ci_cd_quality_gates',
          artifactVersion: 'ci-cd-quality-gates:v1',
          artifactHash: gateRecord.gateHash,
          custodyDigest: input.custodyDigest,
          classification: 'release_gate_metadata_only',
          sensitivityTags: ['ci_cd_metadata', 'release_readiness_metadata'],
          sourceSystem: 'cybermedica.ci_cd_quality_gates',
          hlcTimestamp: input.humanReview.reviewedAtHlc,
        })
      : null,
  };
}
