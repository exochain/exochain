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
const REPOSITORY_SCAFFOLD_SCHEMA = 'cybermedica.repository_scaffold_readiness.v1';
const REPOSITORY_SCAFFOLD_DECISION = 'cybermedica.repository_scaffold_readiness_decision.v1';
const REQUIRED_PERMISSION = 'repository_scaffold_review';

const REQUIRED_CURRENT_ARTIFACT_FAMILIES = Object.freeze([
  'context_docs',
  'contract_tests',
  'dependency_lockfile',
  'implementation_docs',
  'package_manifest',
  'prd_sources',
  'quality_gate',
  'readme',
  'source_contracts',
  'source_guard',
]);

const REQUIRED_TARGET_ARTIFACT_FAMILIES = Object.freeze([
  'ai_governance_doc',
  'api_surface',
  'app_surface',
  'audit_inspection_guide',
  'docs_architecture',
  'docs_controls',
  'docs_evidence',
  'docs_manuals',
  'docs_policies',
  'docs_procedures',
  'exochain_receipts_doc',
  'migrations',
  'ops_backup_restore',
  'ops_ci',
  'ops_incident_response',
  'ops_monitoring',
  'packages',
  'repository_root',
  'schemas',
  'tests_access_control',
  'tests_ai_governance',
  'tests_e2e',
  'tests_evidence',
  'tests_exochain_receipts',
  'tests_workflow_gates',
  'workflows',
]);

const REQUIRED_REPOSITORY_CONTROLS = Object.freeze([
  'branch_protection',
  'codeowners',
  'dependency_alerts',
  'private_visibility',
  'required_ci',
  'secret_scanning',
  'separate_secret_scope',
]);

const POLICY_STATUSES = new Set(['active']);
const CURRENT_INVENTORY_STATUSES = new Set(['active']);
const TARGET_ARTIFACT_STATUSES = new Set(['contracted', 'implemented']);
const REPOSITORY_CONTROL_STATUSES = new Set(['documented_pending_repository_creation', 'verified']);
const HUMAN_REVIEW_DECISIONS = new Set(['scaffold_ready_inactive_trust', 'hold_for_repository_gap']);

const RAW_REPOSITORY_FIELDS = new Set([
  'body',
  'content',
  'filebody',
  'filecontent',
  'freetext',
  'freetextnote',
  'manualbody',
  'rawartifact',
  'rawconfiguration',
  'rawfile',
  'rawpathclassification',
  'rawrepositorycontent',
  'rawrepositoryfile',
  'rawsource',
  'rawsourcecontent',
  'rawvalidationoutput',
  'repositorybody',
  'repositorycontent',
  'reviewnotes',
  'sourcebody',
  'sourcedocumentbody',
  'validationlog',
]);

const SECRET_REPOSITORY_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'bootstrapsecret',
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
  'signaturesecret',
  'signingkey',
  'token',
]);

const SOURCE_REFS = Object.freeze([
  'README.md',
  'cybermedica_2_0_sandy_seven_layer_master_prd.md#6.1',
  'docs/context/CYBERMEDICA_ADJACENT_SURFACE_DECISIONS.md',
  'docs/implementation/PATH_CLASSIFICATION.md',
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

function assertNoRawRepositoryContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawRepositoryContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_REPOSITORY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw repository content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_REPOSITORY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`repository secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawRepositoryContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawRepositoryContent(input ?? {});
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
  addReason(reasons, input?.actor?.kind !== 'human', 'human_repository_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'repository_scaffold_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicyList(list, expected, missingPrefix, unsupportedPrefix, reasons) {
  const actual = sortedTextList(list);
  evaluateRequiredSet(actual, expected, missingPrefix, unsupportedPrefix, reasons);
  return actual;
}

function evaluateScaffoldPolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'scaffold_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'scaffold_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'scaffold_policy_not_active');
  addReason(reasons, policy?.requirePrivateRepositoryBeforePush !== true, 'private_repository_push_gate_absent');
  addReason(reasons, policy?.requireNoExochainImport !== true, 'exochain_import_gate_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'scaffold_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'scaffold_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'scaffold_policy_time_invalid');
  evaluatePolicyList(
    policy?.requiredCurrentArtifactFamilies,
    REQUIRED_CURRENT_ARTIFACT_FAMILIES,
    'policy_current_artifact_family_missing',
    'policy_current_artifact_family_unsupported',
    reasons,
  );
  evaluatePolicyList(
    policy?.requiredTargetArtifactFamilies,
    REQUIRED_TARGET_ARTIFACT_FAMILIES,
    'policy_target_artifact_family_missing',
    'policy_target_artifact_family_unsupported',
    reasons,
  );
  evaluatePolicyList(
    policy?.requiredRepositoryControls,
    REQUIRED_REPOSITORY_CONTROLS,
    'policy_repository_control_missing',
    'policy_repository_control_unsupported',
    reasons,
  );
}

function currentArtifactFamily(entry) {
  return hasText(entry?.family) ? entry.family : null;
}

function targetArtifactFamily(entry) {
  return hasText(entry?.family) ? entry.family : null;
}

function repositoryControlId(entry) {
  return hasText(entry?.controlId) ? entry.controlId : null;
}

function evaluateCurrentArtifact(entry, reasons) {
  const family = currentArtifactFamily(entry) ?? 'unknown';
  addReason(reasons, !hasText(entry?.pathRef), `current_artifact_path_ref_absent:${family}`);
  addReason(reasons, !isDigest(entry?.artifactHash), `current_artifact_hash_invalid:${family}`);
  addReason(reasons, !isDigest(entry?.evidenceHash), `current_artifact_evidence_hash_invalid:${family}`);
  addReason(reasons, entry?.implemented !== true, `current_artifact_not_implemented:${family}`);
  addReason(reasons, entry?.classified !== true, `current_artifact_not_classified:${family}`);
  addReason(reasons, entry?.coveredBySourceGuard !== true, `current_artifact_source_guard_absent:${family}`);
  addReason(reasons, entry?.metadataOnly !== true, `current_artifact_metadata_boundary_invalid:${family}`);
  addReason(reasons, entry?.protectedContentExcluded !== true, `current_artifact_protected_boundary_invalid:${family}`);
  addReason(reasons, entry?.exochainSourceModified === true, `current_artifact_exochain_source_modified:${family}`);
  addReason(reasons, hlcTuple(entry?.reviewedAtHlc) === null, `current_artifact_review_time_invalid:${family}`);
}

function evaluateCurrentInventory(inventory, reasons) {
  addReason(reasons, !hasText(inventory?.inventoryRef), 'current_inventory_ref_absent');
  addReason(reasons, !isDigest(inventory?.inventoryHash), 'current_inventory_hash_invalid');
  addReason(reasons, !CURRENT_INVENTORY_STATUSES.has(inventory?.status), 'current_inventory_not_active');
  addReason(reasons, !hasText(inventory?.packageRoot), 'package_root_absent');
  addReason(reasons, !hasText(inventory?.sourceGuardCommand), 'source_guard_command_absent');
  addReason(reasons, !hasText(inventory?.qualityGateCommand), 'quality_gate_command_absent');
  addReason(reasons, inventory?.sourceGuardPassed !== true, 'source_guard_not_passed');
  addReason(reasons, inventory?.qualityGatePassed !== true, 'quality_gate_not_passed');
  addReason(reasons, inventory?.noExochainSourceModified !== true, 'exochain_source_modification_detected');
  addReason(reasons, inventory?.noExochainSourceImported !== true, 'exochain_source_import_detected');
  addReason(reasons, inventory?.packagePrivate !== true, 'package_private_flag_absent');
  addReason(reasons, inventory?.metadataOnly !== true, 'current_inventory_metadata_boundary_invalid');
  addReason(reasons, inventory?.protectedContentExcluded !== true, 'current_inventory_protected_boundary_invalid');
  addReason(reasons, hlcTuple(inventory?.capturedAtHlc) === null, 'current_inventory_time_invalid');

  const artifacts = Array.isArray(inventory?.artifacts) ? inventory.artifacts : [];
  addReason(reasons, artifacts.length === 0, 'current_artifacts_absent');
  const families = uniqueSorted(artifacts.map(currentArtifactFamily).filter(hasText));
  evaluateRequiredSet(
    families,
    REQUIRED_CURRENT_ARTIFACT_FAMILIES,
    'current_artifact_family_missing',
    'current_artifact_family_unsupported',
    reasons,
  );
  artifacts.forEach((entry) => evaluateCurrentArtifact(entry, reasons));
  return families;
}

function evaluateTargetArtifact(entry, reasons) {
  const family = targetArtifactFamily(entry) ?? 'unknown';
  addReason(reasons, !hasText(entry?.sourcePrdRef), `target_artifact_source_prd_ref_absent:${family}`);
  addReason(reasons, !hasText(entry?.accountabilityRef), `target_artifact_accountability_ref_absent:${family}`);
  addReason(reasons, !hasText(entry?.ownerRoleRef), `target_artifact_owner_role_absent:${family}`);
  addReason(reasons, !isDigest(entry?.evidenceHash), `target_artifact_evidence_hash_invalid:${family}`);
  addReason(reasons, !TARGET_ARTIFACT_STATUSES.has(entry?.status), `target_artifact_status_invalid:${family}`);
  addReason(reasons, entry?.blocksProductionReleaseWhenAbsent !== true, `target_artifact_release_block_absent:${family}`);
  addReason(reasons, entry?.metadataOnly !== true, `target_artifact_metadata_boundary_invalid:${family}`);
  addReason(reasons, entry?.protectedContentExcluded !== true, `target_artifact_protected_boundary_invalid:${family}`);
}

function evaluateTargetStructure(targetStructure, reasons) {
  addReason(reasons, !hasText(targetStructure?.targetRef), 'target_structure_ref_absent');
  addReason(reasons, !isDigest(targetStructure?.targetHash), 'target_structure_hash_invalid');
  addReason(reasons, !hasText(targetStructure?.sourcePrdRef), 'target_structure_source_prd_ref_absent');
  addReason(reasons, targetStructure?.allFamiliesAccounted !== true, 'target_structure_families_not_accounted');
  addReason(reasons, targetStructure?.appRuntimeActivationRequired !== true, 'app_runtime_activation_gate_absent');
  addReason(reasons, targetStructure?.metadataOnly !== true, 'target_structure_metadata_boundary_invalid');
  addReason(reasons, targetStructure?.protectedContentExcluded !== true, 'target_structure_protected_boundary_invalid');
  addReason(reasons, hlcTuple(targetStructure?.reviewedAtHlc) === null, 'target_structure_review_time_invalid');

  const artifacts = Array.isArray(targetStructure?.artifacts) ? targetStructure.artifacts : [];
  addReason(reasons, artifacts.length === 0, 'target_artifacts_absent');
  const families = uniqueSorted(artifacts.map(targetArtifactFamily).filter(hasText));
  evaluateRequiredSet(
    families,
    REQUIRED_TARGET_ARTIFACT_FAMILIES,
    'target_artifact_family_missing',
    'target_artifact_family_unsupported',
    reasons,
  );
  artifacts.forEach((entry) => evaluateTargetArtifact(entry, reasons));
  return families;
}

function evaluateRepositoryControlEntry(entry, reasons) {
  const controlId = repositoryControlId(entry) ?? 'unknown';
  addReason(reasons, !isDigest(entry?.evidenceHash), `repository_control_evidence_hash_invalid:${controlId}`);
  addReason(reasons, !REPOSITORY_CONTROL_STATUSES.has(entry?.status), `repository_control_status_invalid:${controlId}`);
  addReason(reasons, entry?.requiredBeforeExternalPush !== true, `repository_control_push_gate_absent:${controlId}`);
  addReason(reasons, entry?.metadataOnly !== true, `repository_control_metadata_boundary_invalid:${controlId}`);
  addReason(reasons, entry?.protectedContentExcluded !== true, `repository_control_protected_boundary_invalid:${controlId}`);
}

function repositoryActivationBlockers(repositoryControls) {
  const blockers = [];
  addReason(blockers, repositoryControls?.branchProtectionVerified !== true, 'repo_branch_protection_unverified');
  addReason(blockers, repositoryControls?.codeownersVerified !== true, 'repo_codeowners_unverified');
  addReason(blockers, repositoryControls?.dependencyAlertsVerified !== true, 'repo_dependency_alerts_unverified');
  addReason(blockers, repositoryControls?.privateVisibilityVerified !== true, 'repo_private_visibility_unverified');
  addReason(blockers, repositoryControls?.requiredCiVerified !== true, 'repo_required_ci_unverified');
  addReason(blockers, repositoryControls?.secretScanningVerified !== true, 'repo_secret_scanning_unverified');
  return uniqueReasons(blockers);
}

function evaluateRepositoryControls(repositoryControls, reasons) {
  addReason(reasons, !hasText(repositoryControls?.controlsRef), 'repository_controls_ref_absent');
  addReason(reasons, !isDigest(repositoryControls?.controlsHash), 'repository_controls_hash_invalid');
  addReason(reasons, !hasText(repositoryControls?.githubRepository), 'github_repository_ref_absent');
  addReason(reasons, repositoryControls?.separateSecretScopeVerified !== true, 'separate_secret_scope_unverified');
  addReason(reasons, repositoryControls?.exochainSourceImportBlocked !== true, 'exochain_source_import_block_absent');
  addReason(reasons, repositoryControls?.metadataOnly !== true, 'repository_controls_metadata_boundary_invalid');
  addReason(reasons, repositoryControls?.protectedContentExcluded !== true, 'repository_controls_protected_boundary_invalid');
  addReason(reasons, hlcTuple(repositoryControls?.reviewedAtHlc) === null, 'repository_controls_review_time_invalid');

  const controls = Array.isArray(repositoryControls?.controls) ? repositoryControls.controls : [];
  addReason(reasons, controls.length === 0, 'repository_control_entries_absent');
  const controlIds = uniqueSorted(controls.map(repositoryControlId).filter(hasText));
  evaluateRequiredSet(
    controlIds,
    REQUIRED_REPOSITORY_CONTROLS,
    'repository_control_missing',
    'repository_control_unsupported',
    reasons,
  );
  controls.forEach((entry) => evaluateRepositoryControlEntry(entry, reasons));
  return controlIds;
}

function allRepositoryControlsVerified(repositoryControls) {
  const controls = Array.isArray(repositoryControls?.controls) ? repositoryControls.controls : [];
  return (
    controls.length === REQUIRED_REPOSITORY_CONTROLS.length &&
    controls.every((entry) => entry.status === 'verified') &&
    repositoryControls?.repositoryCreated === true &&
    repositoryControls?.privateVisibilityVerified === true &&
    repositoryControls?.branchProtectionVerified === true &&
    repositoryControls?.requiredCiVerified === true &&
    repositoryControls?.secretScanningVerified === true &&
    repositoryControls?.dependencyAlertsVerified === true &&
    repositoryControls?.codeownersVerified === true &&
    repositoryControls?.separateSecretScopeVerified === true &&
    repositoryControls?.exochainSourceImportBlocked === true
  );
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, review === null || review === undefined, 'human_review_absent');
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_did_absent');
  addReason(reasons, sortedTextList(review?.reviewerRoleRefs).length === 0, 'human_reviewer_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.reviewHash), 'human_review_hash_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, review?.protectedContentExcluded !== true, 'human_review_protected_boundary_invalid');
  addReason(
    reasons,
    hlcBefore(review?.reviewedAtHlc, input?.repositoryControls?.reviewedAtHlc),
    'human_review_before_repository_controls',
  );
}

function evaluateValidationEvidence(input, reasons) {
  const validation = input?.validationEvidence;
  addReason(reasons, validation === null || validation === undefined, 'validation_evidence_absent');
  addReason(reasons, sortedTextList(validation?.commandRefs).length === 0, 'validation_commands_absent');
  addReason(reasons, validation?.commandsPassed !== true, 'validation_commands_not_passed');
  addReason(reasons, validation?.sourceGuardPassed !== true, 'validation_source_guard_not_passed');
  addReason(reasons, validation?.pathClassificationUpdated !== true, 'path_classification_not_updated');
  addReason(reasons, validation?.readmeUpdated !== true, 'readme_not_updated');
  addReason(reasons, validation?.noExochainSourceModified !== true, 'validation_exochain_source_modified');
  addReason(reasons, !isDigest(validation?.validationHash), 'validation_hash_invalid');
  addReason(reasons, hlcTuple(validation?.validatedAtHlc) === null, 'validation_time_invalid');
  addReason(reasons, validation?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
  addReason(reasons, validation?.protectedContentExcluded !== true, 'validation_protected_boundary_invalid');
}

function evaluateTrustBoundary(input, productionRepositoryReady, reasons) {
  const boundary = input?.trustBoundary;
  addReason(reasons, boundary === null || boundary === undefined, 'trust_boundary_absent');
  addReason(reasons, boundary?.trustState !== 'inactive', 'trust_state_must_remain_inactive');
  addReason(reasons, boundary?.exochainProductionClaim !== false, 'exochain_production_claim_forbidden');
  addReason(reasons, boundary?.rootTrustVerified === true, 'root_trust_claim_out_of_scope');
  addReason(reasons, boundary?.runtimeEndpointVerified === true, 'runtime_endpoint_claim_out_of_scope');
  addReason(reasons, boundary?.appSurfaceProductionReady === true, 'app_surface_production_ready_claim_forbidden');
  addReason(reasons, boundary?.protectedContentExcluded !== true, 'trust_boundary_protected_content_invalid');
  addReason(reasons, boundary?.secretsExcluded !== true, 'trust_boundary_secret_invalid');
  addReason(reasons, boundary?.metadataOnly !== true, 'trust_boundary_metadata_invalid');
  addReason(
    reasons,
    boundary?.privateRepositoryPushReady === true && productionRepositoryReady !== true,
    'private_repository_push_ready_claim_unverified',
  );
}

function implementedTargetFamilies(targetStructure) {
  const artifacts = Array.isArray(targetStructure?.artifacts) ? targetStructure.artifacts : [];
  return uniqueSorted(
    artifacts
      .filter((entry) => entry.status === 'implemented')
      .map((entry) => entry.family)
      .filter(hasText),
  );
}

function contractedTargetFamilies(targetStructure) {
  const artifacts = Array.isArray(targetStructure?.artifacts) ? targetStructure.artifacts : [];
  return uniqueSorted(
    artifacts
      .filter((entry) => entry.status === 'contracted')
      .map((entry) => entry.family)
      .filter(hasText),
  );
}

function buildScaffoldHash(input, currentFamilies, targetFamilies, controlIds, blockers, productionRepositoryReady) {
  return sha256Hex({
    currentFamilies,
    inventoryHash: input.currentInventory.inventoryHash,
    policyHash: input.scaffoldPolicy.policyHash,
    productionRepositoryReady,
    repositoryBlockers: blockers,
    repositoryControlsHash: input.repositoryControls.controlsHash,
    repositoryControlIds: controlIds,
    schema: REPOSITORY_SCAFFOLD_SCHEMA,
    targetFamilies,
    targetHash: input.targetStructure.targetHash,
    tenantId: input.tenantId,
    trustState: 'inactive',
    validationHash: input.validationEvidence.validationHash,
  });
}

function buildRepositoryScaffold(input, currentFamilies, targetFamilies, controlIds, blockers, productionRepositoryReady) {
  const privateRepositoryPushReady = input.trustBoundary?.privateRepositoryPushReady === true && productionRepositoryReady;
  const scaffoldHash = buildScaffoldHash(
    input,
    currentFamilies,
    targetFamilies,
    controlIds,
    blockers,
    productionRepositoryReady,
  );

  return {
    schema: REPOSITORY_SCAFFOLD_SCHEMA,
    scaffoldRef: input.currentInventory.inventoryRef,
    packageRoot: input.currentInventory.packageRoot,
    sourcePrdRef: input.targetStructure.sourcePrdRef,
    trustState: 'inactive',
    exochainProductionClaim: false,
    baselineScaffoldReady: true,
    productionRepositoryReady,
    privateRepositoryPushReady,
    currentArtifactFamiliesCovered: currentFamilies,
    targetArtifactFamiliesAccounted: targetFamilies,
    implementedTargetArtifactFamilies: implementedTargetFamilies(input.targetStructure),
    contractedTargetArtifactFamilies: contractedTargetFamilies(input.targetStructure),
    repositoryControlIds: controlIds,
    activationBlockerIds: blockers,
    githubRepository: input.repositoryControls.githubRepository,
    repositoryCreated: input.repositoryControls.repositoryCreated === true,
    noExochainSourceImported: input.currentInventory.noExochainSourceImported === true,
    noExochainSourceModified: input.currentInventory.noExochainSourceModified === true,
    sourceGuardCommand: input.currentInventory.sourceGuardCommand,
    qualityGateCommand: input.currentInventory.qualityGateCommand,
    validationCommandRefs: sortedTextList(input.validationEvidence.commandRefs),
    auditRecordRef: input.auditRecordRef,
    scaffoldHash,
    metadataOnly: true,
    protectedContentExcluded: true,
    sourceRefs: SOURCE_REFS,
  };
}

function buildReceipt(input, scaffold) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: scaffold.scaffoldHash,
    artifactType: 'repository_scaffold_readiness',
    artifactVersion: `${input.currentInventory.inventoryRef}@${input.targetStructure.targetRef}`,
    classification: 'repository_scaffold_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.validationEvidence.validatedAtHlc,
    sensitivityTags: ['metadata_only', 'repository_readiness', 'deployment_backlog'],
    sourceSystem: 'cybermedica.repository_scaffold_readiness',
    tenantId: input.tenantId,
  });
}

export function evaluateRepositoryScaffoldReadiness(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateScaffoldPolicy(input?.scaffoldPolicy, reasons);
  const currentFamilies = evaluateCurrentInventory(input?.currentInventory, reasons);
  const targetFamilies = evaluateTargetStructure(input?.targetStructure, reasons);
  const controlIds = evaluateRepositoryControls(input?.repositoryControls, reasons);
  const productionRepositoryReady = allRepositoryControlsVerified(input?.repositoryControls);
  evaluateHumanReview(input, reasons);
  evaluateValidationEvidence(input, reasons);
  evaluateTrustBoundary(input, productionRepositoryReady, reasons);
  addReason(reasons, !hasText(input?.auditRecordRef), 'audit_record_ref_absent');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const blockers = repositoryActivationBlockers(input?.repositoryControls);
  const finalReasons = uniqueReasons(reasons);

  if (finalReasons.length > 0) {
    return {
      schema: REPOSITORY_SCAFFOLD_DECISION,
      decision: 'denied',
      failClosed: true,
      reasons: finalReasons,
      repositoryScaffold: null,
      receipt: null,
    };
  }

  const repositoryScaffold = buildRepositoryScaffold(
    input,
    currentFamilies,
    targetFamilies,
    controlIds,
    blockers,
    productionRepositoryReady,
  );
  const receipt = buildReceipt(input, repositoryScaffold);

  return {
    schema: REPOSITORY_SCAFFOLD_DECISION,
    decision: 'repository_scaffold_ready_inactive_trust',
    failClosed: false,
    reasons: [],
    repositoryScaffold,
    receipt,
  };
}
