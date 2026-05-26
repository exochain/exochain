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
const MANIFEST_SCHEMA = 'cybermedica.deployment_readiness_manifest.v1';
const DECISION_SCHEMA = 'cybermedica.deployment_readiness_manifest_decision.v1';
const REQUIRED_PERMISSION = 'deployment_readiness_review';
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

const REQUIRED_ARTIFACT_FAMILIES = Object.freeze([
  'activation_gate_register',
  'council_escalation_register',
  'inactive_trust_state',
  'path_classification',
  'release_readiness_matrix',
  'requirement_traceability_matrix',
  'validation_evidence',
]);

const DEFAULT_ACTIVATION_BLOCKER_IDS = Object.freeze([
  'PTAG-001',
  'PTAG-008',
  'PTAG-015',
  'PTAG-016',
  'PTAG-017',
]);

const DEFAULT_BOB_ESCALATION_IDS = Object.freeze([
  'ESC-HUMAN-PROOFING',
  'ESC-OPS-SECRETS',
  'ESC-ROOT-ARTIFACT-STORE',
  'ESC-ROOT-DEPLOYMENT',
  'ESC-ROOT-OWNER',
  'ESC-ROOT-ROSTER',
  'ESC-RUNTIME',
]);

const REQUIRED_SOURCE_REFS = Object.freeze([
  'README.md',
  'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  'docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md',
  'docs/implementation/PATH_CLASSIFICATION.md',
]);

const POLICY_STATUSES = new Set(['active']);
const ARTIFACT_FAMILIES = new Set(REQUIRED_ARTIFACT_FAMILIES);
const GATE_STATUSES = new Set(['denied', 'inactive', 'pending', 'verified']);
const RELEASE_DECISIONS = new Set(['baseline_ready_inactive_trust', 'hold_inactive_trust']);
const HUMAN_REVIEW_DECISIONS = new Set(['manifest_accepted_inactive_trust', 'hold_for_deployment_gap']);

const RAW_MANIFEST_FIELDS = new Set([
  'body',
  'content',
  'deploymentnotes',
  'freetext',
  'manifestbody',
  'manifestnarrative',
  'rawactivationevidence',
  'rawconfiguration',
  'rawdeploymentconfig',
  'rawdeploymentevidence',
  'rawevidence',
  'rawmanifest',
  'rawmanifestcontent',
  'rawpathclassification',
  'rawreleaseevidence',
  'rawvalidationoutput',
  'reviewnotes',
  'sourcebody',
  'sourcedocumentbody',
  'validationlog',
]);

const SECRET_MANIFEST_FIELDS = new Set([
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
  return hasText(value) && HEX_64.test(value) && value !== ZERO_HASH;
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

function assertNoRawManifestContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawManifestContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_MANIFEST_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw deployment readiness manifest content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_MANIFEST_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`deployment readiness manifest secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawManifestContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawManifestContent(input ?? {});
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
  addReason(reasons, input?.actor?.kind !== 'human', 'human_deployment_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'deployment_readiness_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateManifestPolicy(policy, reasons) {
  const requiredArtifactFamilies = sortedTextList(policy?.requiredArtifactFamilies);
  const allowedActivationBlockerIds = sortedTextList(policy?.allowedActivationBlockerIds);
  const allowedBobEscalationIds = sortedTextList(policy?.allowedBobEscalationIds);
  const requiredSourceRefs = sortedTextList(policy?.requiredSourceRefs);

  addReason(reasons, !hasText(policy?.policyRef), 'manifest_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'manifest_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'manifest_policy_not_active');
  addReason(reasons, policy?.rootVerificationRequiredForTrustClaims !== true, 'root_verification_gate_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'manifest_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'manifest_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'manifest_policy_time_invalid');

  evaluateRequiredSet(
    requiredArtifactFamilies,
    REQUIRED_ARTIFACT_FAMILIES,
    'policy_artifact_family_missing',
    'policy_artifact_family_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    requiredSourceRefs,
    REQUIRED_SOURCE_REFS,
    'policy_source_ref_missing',
    'policy_source_ref_unsupported',
    reasons,
  );

  return {
    allowedActivationBlockerIds:
      allowedActivationBlockerIds.length > 0 ? allowedActivationBlockerIds : [...DEFAULT_ACTIVATION_BLOCKER_IDS],
    allowedBobEscalationIds:
      allowedBobEscalationIds.length > 0 ? allowedBobEscalationIds : [...DEFAULT_BOB_ESCALATION_IDS],
    requiredArtifactFamilies:
      requiredArtifactFamilies.length > 0 ? requiredArtifactFamilies : [...REQUIRED_ARTIFACT_FAMILIES],
    requiredSourceRefs: requiredSourceRefs.length > 0 ? requiredSourceRefs : [...REQUIRED_SOURCE_REFS],
  };
}

function evaluateManifestCycle(cycle, policy, reasons) {
  addReason(reasons, !hasText(cycle?.manifestRef), 'manifest_cycle_ref_absent');
  addReason(reasons, !hasText(cycle?.releaseCandidateRef), 'release_candidate_ref_absent');
  addReason(reasons, cycle?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, cycle?.metadataOnly !== true, 'manifest_cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'manifest_cycle_protected_boundary_invalid');

  const ordered = [
    ['openedAtHlc', cycle?.openedAtHlc],
    ['evidenceImportedAtHlc', cycle?.evidenceImportedAtHlc],
    ['validationRecordedAtHlc', cycle?.validationRecordedAtHlc],
    ['manifestCompiledAtHlc', cycle?.manifestCompiledAtHlc],
    ['humanReviewedAtHlc', cycle?.humanReviewedAtHlc],
    ['auditRecordedAtHlc', cycle?.auditRecordedAtHlc],
  ];

  for (const [label, value] of ordered) {
    addReason(reasons, hlcTuple(value) === null, `manifest_cycle_${label}_invalid`);
  }
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, cycle?.openedAtHlc), 'manifest_policy_after_cycle_open');
  for (let index = 1; index < ordered.length; index += 1) {
    const [previousLabel, previousValue] = ordered[index - 1];
    const [currentLabel, currentValue] = ordered[index];
    addReason(
      reasons,
      hlcBefore(currentValue, previousValue),
      `manifest_cycle_${currentLabel}_before_${previousLabel}`,
    );
  }
}

function evaluateArtifacts(artifacts, policySummary, cycle, reasons) {
  addReason(reasons, !Array.isArray(artifacts) || artifacts.length === 0, 'manifest_artifacts_absent');
  if (!Array.isArray(artifacts)) {
    return { artifactFamilies: [], artifactSummaries: [], pathClassificationIncluded: false };
  }

  const families = sortedTextList(artifacts.map((artifact) => artifact?.family));
  const artifactSummaries = [];
  const seenFamilies = new Set();

  evaluateRequiredSet(
    families,
    policySummary.requiredArtifactFamilies,
    'artifact_family_missing',
    'artifact_family_unsupported',
    reasons,
  );

  artifacts.forEach((artifact, index) => {
    const label = hasText(artifact?.family) ? artifact.family : `index_${index}`;
    addReason(reasons, !hasText(artifact?.family), `artifact_family_absent:${label}`);
    addReason(reasons, seenFamilies.has(artifact?.family), `artifact_family_duplicate:${label}`);
    if (hasText(artifact?.family)) {
      seenFamilies.add(artifact.family);
    }
    addReason(reasons, !ARTIFACT_FAMILIES.has(artifact?.family), `artifact_family_invalid:${label}`);
    addReason(reasons, !hasText(artifact?.artifactRef), `artifact_ref_absent:${label}`);
    addReason(reasons, !isDigest(artifact?.artifactHash), `artifact_hash_invalid:${label}`);
    addReason(reasons, !hasText(artifact?.sourceRef), `artifact_source_ref_absent:${label}`);
    addReason(reasons, !hasText(artifact?.schemaRef), `artifact_schema_ref_absent:${label}`);
    addReason(reasons, artifact?.metadataOnly !== true, `artifact_metadata_boundary_invalid:${label}`);
    addReason(reasons, artifact?.protectedContentExcluded !== true, `artifact_protected_boundary_invalid:${label}`);
    addReason(reasons, artifact?.productionTrustClaim === true, `artifact_production_claim_forbidden:${label}`);
    addReason(reasons, artifact?.trustState !== 'inactive', `artifact_trust_state_not_inactive:${label}`);
    addReason(reasons, hlcTuple(artifact?.generatedAtHlc) === null, `artifact_generated_time_invalid:${label}`);
    addReason(reasons, hlcAfter(artifact?.generatedAtHlc, cycle?.evidenceImportedAtHlc), `artifact_after_evidence_import:${label}`);

    artifactSummaries.push({
      artifactHash: artifact?.artifactHash ?? null,
      artifactRef: artifact?.artifactRef ?? null,
      family: label,
      schemaRef: artifact?.schemaRef ?? null,
      sourceRef: artifact?.sourceRef ?? null,
      trustState: artifact?.trustState ?? 'invalid',
    });
  });

  return {
    artifactFamilies: families,
    artifactSummaries: artifactSummaries.sort(
      (left, right) => left.family.localeCompare(right.family) || left.artifactRef.localeCompare(right.artifactRef),
    ),
    pathClassificationIncluded: families.includes('path_classification'),
  };
}

function evaluateReleaseReadiness(releaseReadiness, cycle, reasons) {
  addReason(reasons, releaseReadiness === null || releaseReadiness === undefined, 'release_readiness_absent');
  addReason(reasons, !hasText(releaseReadiness?.matrixId), 'release_readiness_matrix_id_absent');
  addReason(reasons, !isDigest(releaseReadiness?.matrixHash), 'release_readiness_matrix_hash_invalid');
  addReason(reasons, !RELEASE_DECISIONS.has(releaseReadiness?.decision), 'release_readiness_decision_invalid');
  addReason(reasons, releaseReadiness?.noProductionTrustClaim !== true, 'release_readiness_production_claim_forbidden');
  addReason(reasons, releaseReadiness?.metadataOnly !== true, 'release_readiness_metadata_boundary_invalid');
  addReason(reasons, sortedTextList(releaseReadiness?.acceptanceDomainsCovered).length === 0, 'acceptance_domains_absent');
  addReason(
    reasons,
    !Number.isSafeInteger(releaseReadiness?.unverifiedProductionGateCount) ||
      releaseReadiness.unverifiedProductionGateCount < 0,
    'release_unverified_gate_count_invalid',
  );
  addReason(
    reasons,
    !Number.isSafeInteger(releaseReadiness?.verifiedGateCount) || releaseReadiness.verifiedGateCount < 0,
    'release_verified_gate_count_invalid',
  );
  addReason(reasons, hlcTuple(releaseReadiness?.reviewedAtHlc) === null, 'release_readiness_review_time_invalid');
  addReason(
    reasons,
    hlcBefore(releaseReadiness?.reviewedAtHlc, cycle?.manifestCompiledAtHlc),
    'release_readiness_review_before_manifest_compile',
  );
}

function evaluateRequirementTraceability(traceability, policySummary, cycle, reasons) {
  addReason(reasons, traceability === null || traceability === undefined, 'requirement_traceability_absent');
  addReason(reasons, !hasText(traceability?.matrixId), 'traceability_matrix_id_absent');
  addReason(reasons, !isDigest(traceability?.matrixHash), 'traceability_matrix_hash_invalid');
  addReason(
    reasons,
    !Number.isSafeInteger(traceability?.requirementCount) || traceability.requirementCount <= 0,
    'traceability_requirement_count_invalid',
  );
  addReason(
    reasons,
    !Number.isSafeInteger(traceability?.implementedCount) || traceability.implementedCount < 0,
    'traceability_implemented_count_invalid',
  );
  addReason(reasons, sortedTextList(traceability?.validationCommandRefs).length === 0, 'traceability_validation_commands_absent');
  addReason(reasons, traceability?.noExochainSourceModified !== true, 'traceability_exochain_read_only_absent');
  addReason(reasons, traceability?.metadataOnly !== true, 'traceability_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(traceability?.reviewedAtHlc) === null, 'traceability_review_time_invalid');
  addReason(
    reasons,
    hlcBefore(traceability?.reviewedAtHlc, cycle?.manifestCompiledAtHlc),
    'traceability_review_before_manifest_compile',
  );

  const activationOnlyBlockerIds = sortedTextList(traceability?.activationOnlyBlockerIds);
  const bobEscalationIds = sortedTextList(traceability?.bobEscalationIds);

  for (const blockerId of activationOnlyBlockerIds) {
    addReason(
      reasons,
      !policySummary.allowedActivationBlockerIds.includes(blockerId),
      `activation_blocker_not_allowed:${blockerId}`,
    );
  }
  for (const escalationId of bobEscalationIds) {
    addReason(
      reasons,
      !policySummary.allowedBobEscalationIds.includes(escalationId),
      `bob_escalation_not_allowed:${escalationId}`,
    );
  }

  return { activationOnlyBlockerIds, bobEscalationIds };
}

function evaluateActivationGates(gates, requiredGateIds, reasons) {
  addReason(reasons, !Array.isArray(gates) || gates.length === 0, 'activation_gates_absent');
  if (!Array.isArray(gates)) {
    return {
      activeClaimGateIds: [],
      gateIds: [],
      totalGateCount: 0,
      unverifiedProductionGateCount: requiredGateIds.length,
      verifiedGateCount: 0,
    };
  }

  const gateIds = sortedTextList(gates.map((gate) => gate?.gateId));
  const activeClaimGateIds = [];
  const seenGateIds = new Set();
  let verifiedGateCount = 0;
  let unverifiedProductionGateCount = 0;

  for (const gateId of requiredGateIds) {
    addReason(reasons, !gateIds.includes(gateId), `activation_gate_missing:${gateId}`);
    if (!gateIds.includes(gateId)) {
      unverifiedProductionGateCount += 1;
    }
  }

  gates.forEach((gate, index) => {
    const label = hasText(gate?.gateId) ? gate.gateId : `index_${index}`;
    addReason(reasons, !hasText(gate?.gateId), `activation_gate_id_absent:${label}`);
    addReason(reasons, seenGateIds.has(gate?.gateId), `activation_gate_duplicate:${label}`);
    if (hasText(gate?.gateId)) {
      seenGateIds.add(gate.gateId);
    }
    addReason(reasons, !requiredGateIds.includes(gate?.gateId), `activation_gate_unsupported:${label}`);
    addReason(reasons, !GATE_STATUSES.has(gate?.status), `activation_gate_status_invalid:${label}`);
    addReason(reasons, gate?.requiredForProductionTrustClaim !== true, `activation_gate_production_rule_absent:${label}`);
    addReason(reasons, gate?.blocksBaselineDevelopment === true, `activation_gate_blocks_baseline:${label}`);
    addReason(reasons, gate?.metadataOnly !== true, `activation_gate_metadata_boundary_invalid:${label}`);
    addReason(reasons, hlcTuple(gate?.reviewedAtHlc) === null, `activation_gate_review_time_invalid:${label}`);

    if (gate?.status === 'verified') {
      verifiedGateCount += 1;
      addReason(reasons, !isDigest(gate?.evidenceHash), `activation_gate_verification_evidence_missing:${label}`);
    } else if (gate?.requiredForProductionTrustClaim === true) {
      unverifiedProductionGateCount += 1;
    }

    if (gate?.productionClaimActive === true) {
      activeClaimGateIds.push(label);
      addReason(reasons, true, `activation_gate_active_claim_forbidden:${label}`);
    }
  });

  return {
    activeClaimGateIds: uniqueSorted(activeClaimGateIds),
    gateIds,
    totalGateCount: gates.length,
    unverifiedProductionGateCount,
    verifiedGateCount,
  };
}

function evaluateDeploymentConfiguration(config, cycle, reasons) {
  addReason(reasons, config === null || config === undefined, 'deployment_configuration_absent');
  addReason(reasons, !hasText(config?.topologyRef), 'deployment_topology_ref_absent');
  addReason(reasons, !isDigest(config?.topologyHash), 'deployment_topology_hash_invalid');
  addReason(reasons, typeof config?.runtimeEndpointSelected !== 'boolean', 'runtime_endpoint_selection_invalid');
  addReason(reasons, typeof config?.rootBundleProviderSelected !== 'boolean', 'root_bundle_provider_selection_invalid');
  addReason(reasons, config?.secretScopeSeparated !== true, 'secret_scope_not_separated');
  addReason(reasons, config?.missingSecretsFailClosed !== true, 'missing_secret_fail_closed_absent');
  addReason(reasons, config?.browserPhiTrustPathDisabled !== true, 'browser_phi_trust_path_enabled');
  addReason(reasons, !hasText(config?.rollbackPathRef), 'rollback_path_ref_absent');
  addReason(reasons, !isDigest(config?.rollbackPathHash), 'rollback_path_hash_invalid');
  addReason(reasons, config?.metadataOnly !== true, 'deployment_configuration_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(config?.reviewedAtHlc) === null, 'deployment_configuration_review_time_invalid');
  addReason(
    reasons,
    hlcBefore(config?.reviewedAtHlc, cycle?.manifestCompiledAtHlc),
    'deployment_configuration_review_before_manifest_compile',
  );
}

function evaluateValidationEvidence(validation, cycle, reasons) {
  addReason(reasons, validation === null || validation === undefined, 'validation_evidence_absent');
  addReason(reasons, sortedTextList(validation?.commandRefs).length === 0, 'validation_command_refs_absent');
  addReason(reasons, validation?.commandsPassed !== true, 'validation_commands_not_passed');
  addReason(reasons, !Number.isSafeInteger(validation?.testCount) || validation.testCount <= 0, 'validation_test_count_invalid');
  addReason(reasons, !isBasisPoints(validation?.coverageLineBasisPoints), 'validation_coverage_invalid');
  addReason(reasons, validation?.sourceGuardPassed !== true, 'validation_source_guard_absent');
  addReason(reasons, !isDigest(validation?.pathClassificationHash), 'validation_path_classification_hash_invalid');
  addReason(reasons, !isDigest(validation?.moduleManifestHash), 'validation_module_manifest_hash_invalid');
  addReason(reasons, !isDigest(validation?.testManifestHash), 'validation_test_manifest_hash_invalid');
  addReason(reasons, validation?.noExochainSourceModified !== true, 'validation_exochain_read_only_absent');
  addReason(reasons, validation?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(validation?.recordedAtHlc) === null, 'validation_time_invalid');
  addReason(reasons, hlcBefore(validation?.recordedAtHlc, cycle?.validationRecordedAtHlc), 'validation_before_cycle_validation_step');
}

function evaluateHumanReview(review, cycle, traceabilitySummary, reasons) {
  addReason(reasons, review === null || review === undefined, 'human_review_absent');
  addReason(reasons, !hasText(review?.reviewerDid), 'human_review_reviewer_absent');
  addReason(reasons, sortedTextList(review?.reviewerRoleRefs).length === 0, 'human_review_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'human_review_production_trust_forbidden');
  addReason(reasons, review?.activationOnlyBlockersAccepted !== true, 'activation_only_blockers_not_accepted');
  addReason(reasons, review?.bobEscalationsNarrowed !== true, 'bob_escalations_not_narrowed');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_review_authority_absent');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, cycle?.humanReviewedAtHlc), 'human_review_before_cycle_review_step');
  addReason(
    reasons,
    traceabilitySummary.activationOnlyBlockerIds.length > 0 && review?.decision !== 'manifest_accepted_inactive_trust',
    'activation_only_blockers_require_inactive_acceptance',
  );
}

function evaluateAuditRecord(auditRecord, cycle, review, reasons) {
  addReason(reasons, !hasText(auditRecord?.auditRecordRef), 'manifest_audit_record_ref_absent');
  addReason(reasons, !isDigest(auditRecord?.auditRecordHash), 'manifest_audit_record_hash_invalid');
  addReason(reasons, auditRecord?.metadataOnly !== true, 'manifest_audit_record_metadata_boundary_invalid');
  addReason(reasons, auditRecord?.includesProtectedContent === true, 'manifest_audit_record_protected_content_forbidden');
  addReason(reasons, hlcTuple(auditRecord?.receiptRecordedAtHlc) === null, 'manifest_audit_record_time_invalid');
  addReason(reasons, hlcBefore(auditRecord?.receiptRecordedAtHlc, cycle?.auditRecordedAtHlc), 'manifest_audit_before_cycle_audit_step');
  addReason(reasons, hlcBefore(auditRecord?.receiptRecordedAtHlc, review?.reviewedAtHlc), 'manifest_audit_before_review');
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance === null || aiAssistance === undefined || aiAssistance?.used !== true) {
    return;
  }
  addReason(reasons, aiAssistance.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, aiAssistance.reviewedByHuman !== true, 'ai_human_review_absent');
  addReason(reasons, !isDigest(aiAssistance.recommendationHash), 'ai_recommendation_hash_invalid');
  addReason(reasons, sortedTextList(aiAssistance.limitationHashes).filter(isDigest).length === 0, 'ai_limitation_hashes_absent');
}

function buildManifest(input, policySummary, artifactSummary, traceabilitySummary, activationSummary) {
  const validationSummary = {
    commandRefs: sortedTextList(input.validationEvidence.commandRefs),
    coverageLineBasisPoints: input.validationEvidence.coverageLineBasisPoints,
    sourceGuardPassed: true,
    testCount: input.validationEvidence.testCount,
  };
  const deploymentSummary = {
    browserPhiTrustPathDisabled: input.deploymentConfiguration.browserPhiTrustPathDisabled,
    missingSecretsFailClosed: input.deploymentConfiguration.missingSecretsFailClosed,
    rollbackPathHash: input.deploymentConfiguration.rollbackPathHash,
    rollbackPathRef: input.deploymentConfiguration.rollbackPathRef,
    rootBundleProviderSelected: input.deploymentConfiguration.rootBundleProviderSelected,
    runtimeEndpointSelected: input.deploymentConfiguration.runtimeEndpointSelected,
    secretScopeSeparated: input.deploymentConfiguration.secretScopeSeparated,
    topologyHash: input.deploymentConfiguration.topologyHash,
    topologyRef: input.deploymentConfiguration.topologyRef,
  };
  const productionActivationReady =
    activationSummary.unverifiedProductionGateCount === 0 &&
    input.deploymentConfiguration.runtimeEndpointSelected === true &&
    input.deploymentConfiguration.rootBundleProviderSelected === true;
  const manifestHash = sha256Hex({
    activationOnlyBlockerIds: traceabilitySummary.activationOnlyBlockerIds,
    activationSummary,
    artifactSummaries: artifactSummary.artifactSummaries,
    auditRecordHash: input.auditRecord.auditRecordHash,
    bobEscalationIds: traceabilitySummary.bobEscalationIds,
    deploymentSummary,
    humanDecisionHash: input.humanReview.decisionHash,
    manifestRef: input.manifestCycle.manifestRef,
    releaseReadinessHash: input.releaseReadiness.matrixHash,
    requirementTraceabilityHash: input.requirementTraceability.matrixHash,
    tenantId: input.tenantId,
    validationEvidenceHash: input.validationEvidence.moduleManifestHash,
  });

  return {
    schema: MANIFEST_SCHEMA,
    manifestId: `cmdrm_${sha256Hex({
      manifestHash,
      manifestRef: input.manifestCycle.manifestRef,
      tenantId: input.tenantId,
    }).slice(0, 32)}`,
    tenantId: input.tenantId,
    releaseCandidateRef: input.manifestCycle.releaseCandidateRef,
    trustState: 'inactive',
    productionTrustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    baselineEvidencePackReady: true,
    productionActivationReady,
    artifactFamiliesCovered: artifactSummary.artifactFamilies,
    artifactSourceRefsRequired: policySummary.requiredSourceRefs,
    artifacts: artifactSummary.artifactSummaries,
    pathClassificationIncluded: artifactSummary.pathClassificationIncluded,
    activationOnlyBlockerIds: traceabilitySummary.activationOnlyBlockerIds,
    bobEscalationIds: traceabilitySummary.bobEscalationIds,
    activationSummary,
    deploymentSummary,
    releaseReadinessSummary: {
      decision: input.releaseReadiness.decision,
      matrixHash: input.releaseReadiness.matrixHash,
      matrixId: input.releaseReadiness.matrixId,
      unverifiedProductionGateCount: input.releaseReadiness.unverifiedProductionGateCount,
      verifiedGateCount: input.releaseReadiness.verifiedGateCount,
    },
    requirementTraceabilitySummary: {
      implementedCount: input.requirementTraceability.implementedCount,
      matrixHash: input.requirementTraceability.matrixHash,
      matrixId: input.requirementTraceability.matrixId,
      requirementCount: input.requirementTraceability.requirementCount,
    },
    validationSummary,
    manifestHash,
    auditRecordHash: input.auditRecord.auditRecordHash,
    auditRecordedAtHlc: input.auditRecord.receiptRecordedAtHlc,
  };
}

function buildReceipt(input, manifest) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: manifest.manifestHash,
    artifactType: 'deployment_readiness_manifest',
    artifactVersion: input.manifestCycle.releaseCandidateRef,
    classification: 'restricted_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.auditRecord.receiptRecordedAtHlc,
    sensitivityTags: ['deployment_readiness', 'metadata_only', 'inactive_trust_state'],
    sourceSystem: 'cybermedica-qms',
    tenantId: input.tenantId,
  });
}

export function evaluateDeploymentReadinessManifest(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policySummary = evaluateManifestPolicy(input?.manifestPolicy, reasons);
  evaluateManifestCycle(input?.manifestCycle, input?.manifestPolicy, reasons);
  const artifactSummary = evaluateArtifacts(input?.artifacts, policySummary, input?.manifestCycle, reasons);
  evaluateReleaseReadiness(input?.releaseReadiness, input?.manifestCycle, reasons);
  const traceabilitySummary = evaluateRequirementTraceability(
    input?.requirementTraceability,
    policySummary,
    input?.manifestCycle,
    reasons,
  );
  const activationSummary = evaluateActivationGates(input?.activationGates, policySummary.allowedActivationBlockerIds, reasons);
  evaluateDeploymentConfiguration(input?.deploymentConfiguration, input?.manifestCycle, reasons);
  evaluateValidationEvidence(input?.validationEvidence, input?.manifestCycle, reasons);
  evaluateHumanReview(input?.humanReview, input?.manifestCycle, traceabilitySummary, reasons);
  evaluateAuditRecord(input?.auditRecord, input?.manifestCycle, input?.humanReview, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: unique,
      manifest: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const manifest = buildManifest(input, policySummary, artifactSummary, traceabilitySummary, activationSummary);

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    manifest,
    receipt: buildReceipt(input, manifest),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
