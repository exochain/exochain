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

import { ProtectedContentError, canonicalize, sha256Hex } from './qms-contracts.mjs';

export { ProtectedContentError };

const HEX_64 = /^[0-9a-f]{64}$/u;
const GIT_COMMIT = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/u;
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const EXOCHAIN_SOURCE_PATH = '/Users/bobstewart/dev/exochain/exochain';
const DECISION_SCHEMA = 'cybermedica.production_claim_lift_decision.v1';
const RECEIPT_SCHEMA = 'cybermedica.production_claim_lift_receipt.v1';
const REQUIRED_PERMISSION = 'production_claim_lift';

const CRITERIA = Object.freeze([
  'adapter_boundary',
  'claim_mapping',
  'context_review',
  'deployment_configuration',
  'privacy_boundary',
  'runtime_path',
  'source_truth',
  'test_matrix',
]);

const REQUIRED_CONTEXT_REFS = Object.freeze([
  'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
  'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
]);

const REQUIRED_TEST_COMMAND_REFS = Object.freeze(['cargo test --workspace', 'npm run quality']);
const CLAIM_GATE_IDS = new Set(Array.from({ length: 18 }, (_, index) => `PTAG-${String(index + 1).padStart(3, '0')}`));
const CLAIM_ARTIFACT_TYPES = new Set(['custody_digest', 'decision', 'governance_outcome', 'receipt']);

const RAW_CLAIM_FIELDS = new Set([
  'activationevidencebody',
  'claimbody',
  'claimlanguage',
  'claimtext',
  'consoleoutput',
  'debugoutput',
  'freetext',
  'healthoutput',
  'logpayload',
  'rawactivationevidence',
  'rawclaim',
  'rawclaimtext',
  'rawcontextreview',
  'rawdeploymentconfig',
  'rawmapping',
  'rawreceiptpayload',
  'rawruntimepayload',
  'rawtestoutput',
  'reviewnotes',
  'sourcedocumentbody',
  'telemetrypayload',
]);

const SECRET_CLAIM_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'bootstraptoken',
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

function addIssue(issues, criterion, condition, reason) {
  if (condition) {
    issues.push({ criterion, reason });
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

function assertNoRawClaimLiftContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawClaimLiftContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_CLAIM_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`production claim lift raw content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_CLAIM_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`production claim lift secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawClaimLiftContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawClaimLiftContent(input ?? {});
  canonicalize(input ?? {});
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
}

function uniqueReasonList(issues) {
  return uniqueSorted(issues.map((issue) => issue.reason));
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

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, issues) {
  addIssue(issues, 'context_review', !hasText(input?.tenantId), 'tenant_absent');
  addIssue(issues, 'context_review', input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addIssue(issues, 'context_review', !hasText(input?.actor?.did), 'actor_did_absent');
  addIssue(issues, 'context_review', input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addIssue(issues, 'context_review', input?.actor?.kind !== 'human', 'human_claim_lift_reviewer_required');
  addIssue(issues, 'context_review', input?.authority?.valid !== true, 'authority_chain_invalid');
  addIssue(issues, 'context_review', input?.authority?.revoked === true, 'authority_chain_revoked');
  addIssue(issues, 'context_review', input?.authority?.expired === true, 'authority_chain_expired');
  addIssue(
    issues,
    'context_review',
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'production_claim_lift_authority_missing',
  );
  addIssue(issues, 'context_review', !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateSourceTruth(sourceTruth, issues) {
  addIssue(issues, 'source_truth', sourceTruth?.exochainSourcePath !== EXOCHAIN_SOURCE_PATH, 'exochain_source_path_unverified');
  addIssue(issues, 'source_truth', !hasText(sourceTruth?.branchRef), 'source_branch_ref_absent');
  addIssue(issues, 'source_truth', !hasText(sourceTruth?.commitHash) || !GIT_COMMIT.test(sourceTruth.commitHash), 'source_commit_hash_invalid');
  addIssue(issues, 'source_truth', !hasText(sourceTruth?.repoTruthCommandRef), 'repo_truth_command_ref_absent');
  addIssue(issues, 'source_truth', !isDigest(sourceTruth?.repoTruthHash), 'repo_truth_hash_invalid');
  addIssue(issues, 'source_truth', sourceTruth?.currentAgainstLocalCommit !== true, 'source_not_current_against_local_commit');
  addIssue(issues, 'source_truth', sourceTruth?.workingTreeClean !== true, 'source_working_tree_not_clean');
  addIssue(issues, 'source_truth', sourceTruth?.noExochainSourceModified !== true, 'exochain_source_modified');
  addIssue(issues, 'source_truth', sourceTruth?.metadataOnly !== true, 'source_truth_metadata_boundary_invalid');
  addIssue(issues, 'source_truth', hlcTuple(sourceTruth?.checkedAtHlc) === null, 'source_truth_time_invalid');
}

function evaluateRuntimePath(runtimePath, issues) {
  addIssue(issues, 'runtime_path', !hasText(runtimePath?.runtimePathRef), 'runtime_path_ref_absent');
  addIssue(issues, 'runtime_path', !isDigest(runtimePath?.runtimePathHash), 'runtime_path_hash_invalid');
  addIssue(issues, 'runtime_path', runtimePath?.enabled !== true, 'runtime_path_not_enabled');
  addIssue(issues, 'runtime_path', runtimePath?.serverSideOnly !== true, 'runtime_path_not_server_side');
  addIssue(issues, 'runtime_path', runtimePath?.browserAuthoritative === true, 'browser_authoritative_runtime_forbidden');
  addIssue(issues, 'runtime_path', runtimePath?.gatewayAdapterVerified !== true, 'gateway_adapter_path_unverified');
  addIssue(issues, 'runtime_path', runtimePath?.nodeReceiptPathVerified !== true, 'node_receipt_path_unverified');
  addIssue(issues, 'runtime_path', runtimePath?.decisionForumPathVerified !== true, 'decision_forum_path_unverified');
  addIssue(issues, 'runtime_path', runtimePath?.rootVerifierPathVerified !== true, 'root_verifier_path_unverified');
  addIssue(issues, 'runtime_path', runtimePath?.metadataOnly !== true, 'runtime_path_metadata_boundary_invalid');
  addIssue(issues, 'runtime_path', hlcTuple(runtimePath?.identifiedAtHlc) === null, 'runtime_path_time_invalid');
}

function evaluateDeploymentConfiguration(deploymentConfiguration, issues) {
  addIssue(issues, 'deployment_configuration', !hasText(deploymentConfiguration?.deploymentConfigRef), 'deployment_config_ref_absent');
  addIssue(issues, 'deployment_configuration', !isDigest(deploymentConfiguration?.deploymentConfigHash), 'deployment_config_hash_invalid');
  addIssue(
    issues,
    'deployment_configuration',
    deploymentConfiguration?.productionEnvironmentIdentified !== true,
    'production_deployment_configuration_absent',
  );
  addIssue(issues, 'deployment_configuration', !hasText(deploymentConfiguration?.endpointRef), 'deployment_endpoint_ref_absent');
  addIssue(issues, 'deployment_configuration', !hasText(deploymentConfiguration?.rootBundleProviderRef), 'root_bundle_provider_absent');
  addIssue(issues, 'deployment_configuration', deploymentConfiguration?.secretScopeSeparated !== true, 'secret_scope_not_separated');
  addIssue(issues, 'deployment_configuration', deploymentConfiguration?.missingSecretsFailClosed !== true, 'missing_secrets_not_fail_closed');
  addIssue(issues, 'deployment_configuration', !hasText(deploymentConfiguration?.rollbackDisablementRef), 'rollback_disablement_ref_absent');
  addIssue(issues, 'deployment_configuration', deploymentConfiguration?.metadataOnly !== true, 'deployment_config_metadata_boundary_invalid');
  addIssue(issues, 'deployment_configuration', hlcTuple(deploymentConfiguration?.identifiedAtHlc) === null, 'deployment_config_time_invalid');
}

function evaluateAdapterBoundary(adapterBoundary, issues) {
  addIssue(issues, 'adapter_boundary', !hasText(adapterBoundary?.boundaryRef), 'adapter_boundary_ref_absent');
  addIssue(issues, 'adapter_boundary', !isDigest(adapterBoundary?.boundaryHash), 'adapter_boundary_hash_invalid');
  addIssue(issues, 'adapter_boundary', adapterBoundary?.cannotSimulateCoreOutcome !== true, 'adapter_simulated_outcome_possible');
  addIssue(issues, 'adapter_boundary', adapterBoundary?.cannotCacheCoreOutcome !== true, 'adapter_cached_outcome_possible');
  addIssue(issues, 'adapter_boundary', adapterBoundary?.cannotOverrideCoreOutcome !== true, 'adapter_override_possible');
  addIssue(issues, 'adapter_boundary', adapterBoundary?.failsClosedOnUnavailable !== true, 'adapter_unavailable_not_fail_closed');
  addIssue(issues, 'adapter_boundary', adapterBoundary?.failsClosedOnReject !== true, 'adapter_reject_not_fail_closed');
  addIssue(issues, 'adapter_boundary', adapterBoundary?.failsClosedOnTimeout !== true, 'adapter_timeout_not_fail_closed');
  addIssue(issues, 'adapter_boundary', adapterBoundary?.failsClosedOnMalformed !== true, 'adapter_malformed_not_fail_closed');
  addIssue(issues, 'adapter_boundary', adapterBoundary?.immutableExternalReceiptRequired !== true, 'external_receipt_not_required');
  addIssue(issues, 'adapter_boundary', adapterBoundary?.metadataOnly !== true, 'adapter_boundary_metadata_invalid');
  addIssue(issues, 'adapter_boundary', hlcTuple(adapterBoundary?.verifiedAtHlc) === null, 'adapter_boundary_time_invalid');
}

function evaluateTestMatrix(testMatrix, issues) {
  const commandRefs = sortedTextList(testMatrix?.commandRefs);
  addIssue(issues, 'test_matrix', !hasText(testMatrix?.matrixRef), 'test_matrix_ref_absent');
  addIssue(issues, 'test_matrix', !isDigest(testMatrix?.matrixHash), 'test_matrix_hash_invalid');
  addIssue(issues, 'test_matrix', testMatrix?.positiveCasePassed !== true, 'positive_case_missing');
  addIssue(issues, 'test_matrix', testMatrix?.negativeCasePassed !== true, 'negative_case_missing');
  addIssue(issues, 'test_matrix', testMatrix?.unavailableCasePassed !== true, 'unavailable_case_missing');
  addIssue(issues, 'test_matrix', testMatrix?.malformedCasePassed !== true, 'malformed_case_missing');
  addIssue(issues, 'test_matrix', testMatrix?.timeoutCasePassed !== true, 'timeout_case_missing');
  addIssue(issues, 'test_matrix', testMatrix?.crossTenantCasePassed !== true, 'cross_tenant_case_missing');
  addIssue(issues, 'test_matrix', testMatrix?.privacyNonAnchoringCasePassed !== true, 'privacy_non_anchoring_case_missing');
  for (const commandRef of REQUIRED_TEST_COMMAND_REFS) {
    addIssue(issues, 'test_matrix', !commandRefs.includes(commandRef), `test_command_missing:${commandRef}`);
  }
  addIssue(issues, 'test_matrix', testMatrix?.metadataOnly !== true, 'test_matrix_metadata_boundary_invalid');
  addIssue(issues, 'test_matrix', hlcTuple(testMatrix?.testsRecordedAtHlc) === null, 'test_matrix_time_invalid');
}

function evaluatePrivacyBoundary(privacyBoundary, issues) {
  addIssue(issues, 'privacy_boundary', !hasText(privacyBoundary?.privacyBoundaryRef), 'privacy_boundary_ref_absent');
  addIssue(issues, 'privacy_boundary', !isDigest(privacyBoundary?.privacyBoundaryHash), 'privacy_boundary_hash_invalid');
  addIssue(issues, 'privacy_boundary', privacyBoundary?.noRawSensitiveInReceipts !== true, 'receipt_sensitive_content_boundary_unverified');
  addIssue(issues, 'privacy_boundary', privacyBoundary?.noRawSensitiveInDag !== true, 'dag_sensitive_content_boundary_unverified');
  addIssue(issues, 'privacy_boundary', privacyBoundary?.noRawSensitiveInLogs !== true, 'log_sensitive_content_boundary_unverified');
  addIssue(issues, 'privacy_boundary', privacyBoundary?.noRawSensitiveInTelemetry !== true, 'telemetry_sensitive_content_boundary_unverified');
  addIssue(issues, 'privacy_boundary', privacyBoundary?.noRawSensitiveInHealth !== true, 'health_sensitive_content_boundary_unverified');
  addIssue(issues, 'privacy_boundary', privacyBoundary?.noRawSensitiveInDebug !== true, 'debug_sensitive_content_boundary_unverified');
  addIssue(issues, 'privacy_boundary', privacyBoundary?.noRawSensitiveInExports !== true, 'export_sensitive_content_boundary_unverified');
  addIssue(issues, 'privacy_boundary', privacyBoundary?.fixtureScanPassed !== true, 'privacy_fixture_scan_failed');
  addIssue(issues, 'privacy_boundary', !isDigest(privacyBoundary?.classificationHash), 'privacy_classification_hash_invalid');
  addIssue(issues, 'privacy_boundary', privacyBoundary?.metadataOnly !== true, 'privacy_boundary_metadata_invalid');
  addIssue(issues, 'privacy_boundary', hlcTuple(privacyBoundary?.scannedAtHlc) === null, 'privacy_boundary_time_invalid');
}

function evaluateClaimMapping(claimMapping, issues) {
  const hasAnyClaimEvidenceRef =
    hasText(claimMapping?.receiptId) ||
    hasText(claimMapping?.decisionId) ||
    isDigest(claimMapping?.custodyDigest) ||
    hasText(claimMapping?.governanceOutcomeRef);

  addIssue(issues, 'claim_mapping', !CLAIM_GATE_IDS.has(claimMapping?.gateId), 'claim_gate_id_unsupported');
  addIssue(issues, 'claim_mapping', !isDigest(claimMapping?.claimTextHash), 'claim_text_hash_invalid');
  addIssue(issues, 'claim_mapping', !CLAIM_ARTIFACT_TYPES.has(claimMapping?.mappedArtifactType), 'claim_mapping_artifact_type_unsupported');
  addIssue(issues, 'claim_mapping', !isDigest(claimMapping?.mappedArtifactHash), 'claim_artifact_hash_invalid');
  addIssue(issues, 'claim_mapping', !hasAnyClaimEvidenceRef, 'receipt_mapping_absent');
  addIssue(
    issues,
    'claim_mapping',
    claimMapping?.mappedArtifactType === 'receipt' && !hasText(claimMapping?.receiptId),
    'receipt_mapping_absent',
  );
  addIssue(
    issues,
    'claim_mapping',
    claimMapping?.mappedArtifactType === 'decision' && !hasText(claimMapping?.decisionId),
    'decision_mapping_absent',
  );
  addIssue(
    issues,
    'claim_mapping',
    claimMapping?.mappedArtifactType === 'custody_digest' && !isDigest(claimMapping?.custodyDigest),
    'custody_digest_mapping_absent',
  );
  addIssue(
    issues,
    'claim_mapping',
    claimMapping?.mappedArtifactType === 'governance_outcome' && !hasText(claimMapping?.governanceOutcomeRef),
    'governance_outcome_mapping_absent',
  );
  addIssue(issues, 'claim_mapping', claimMapping?.noMarketingOverclaim !== true, 'marketing_overclaim_not_denied');
  addIssue(issues, 'claim_mapping', claimMapping?.metadataOnly !== true, 'claim_mapping_metadata_invalid');
  addIssue(issues, 'claim_mapping', hlcTuple(claimMapping?.mappedAtHlc) === null, 'claim_mapping_time_invalid');
}

function evaluateContextReview(contextReview, issues) {
  const contextRefs = sortedTextList(contextReview?.contextRefs);
  addIssue(issues, 'context_review', !hasText(contextReview?.reviewRef), 'context_review_ref_absent');
  addIssue(issues, 'context_review', !isDigest(contextReview?.reviewHash), 'context_review_hash_invalid');
  for (const contextRef of REQUIRED_CONTEXT_REFS) {
    addIssue(issues, 'context_review', !contextRefs.includes(contextRef), `context_ref_missing:${contextRef}`);
  }
  addIssue(issues, 'context_review', contextReview?.reviewedAgainstOriginalPrd !== true, 'context_prd_review_absent');
  addIssue(issues, 'context_review', contextReview?.activationGateRegisterReviewed !== true, 'activation_gate_register_review_absent');
  addIssue(issues, 'context_review', contextReview?.finalAuthority !== 'human', 'ai_final_authority_forbidden');
  addIssue(issues, 'context_review', contextReview?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addIssue(issues, 'context_review', !hasText(contextReview?.reviewerDid), 'context_reviewer_did_absent');
  addIssue(issues, 'context_review', contextReview?.metadataOnly !== true, 'context_review_metadata_invalid');
  addIssue(issues, 'context_review', hlcTuple(contextReview?.reviewedAtHlc) === null, 'context_review_time_invalid');
}

function evaluateHumanDecision(humanDecision, issues) {
  addIssue(issues, 'context_review', !hasText(humanDecision?.decisionRef), 'human_claim_lift_decision_ref_absent');
  addIssue(issues, 'context_review', !isDigest(humanDecision?.decisionHash), 'human_claim_lift_decision_hash_invalid');
  addIssue(
    issues,
    'context_review',
    humanDecision?.decision !== 'approve_production_claim_lift' || humanDecision?.finalAuthority !== 'human',
    'human_claim_lift_decision_invalid',
  );
  addIssue(issues, 'context_review', !hasText(humanDecision?.reviewerDid), 'human_claim_lift_reviewer_absent');
  addIssue(issues, 'context_review', humanDecision?.metadataOnly !== true, 'human_claim_lift_decision_metadata_invalid');
  addIssue(issues, 'context_review', hlcTuple(humanDecision?.decidedAtHlc) === null, 'human_claim_lift_decision_time_invalid');
}

function evaluateAuditRecord(auditRecord, issues) {
  addIssue(issues, 'context_review', !hasText(auditRecord?.auditRecordRef), 'claim_lift_audit_ref_absent');
  addIssue(issues, 'context_review', !isDigest(auditRecord?.auditRecordHash), 'claim_lift_audit_hash_invalid');
  addIssue(issues, 'context_review', auditRecord?.metadataOnly !== true, 'claim_lift_audit_metadata_invalid');
  addIssue(issues, 'context_review', auditRecord?.includesProtectedContent === true, 'claim_lift_audit_protected_content');
  addIssue(issues, 'context_review', hlcTuple(auditRecord?.receiptRecordedAtHlc) === null, 'claim_lift_audit_time_invalid');
}

function evaluateChronology(input, issues) {
  const ordered = [
    ['source_truth', input?.sourceTruth?.checkedAtHlc],
    ['runtime_path', input?.runtimePath?.identifiedAtHlc],
    ['deployment_configuration', input?.deploymentConfiguration?.identifiedAtHlc],
    ['adapter_boundary', input?.adapterBoundary?.verifiedAtHlc],
    ['test_matrix', input?.testMatrix?.testsRecordedAtHlc],
    ['privacy_boundary', input?.privacyBoundary?.scannedAtHlc],
    ['claim_mapping', input?.claimMapping?.mappedAtHlc],
    ['context_review', input?.contextReview?.reviewedAtHlc],
    ['context_review', input?.humanDecision?.decidedAtHlc],
    ['context_review', input?.auditRecord?.receiptRecordedAtHlc],
  ];

  for (let index = 1; index < ordered.length; index += 1) {
    const [criterion, current] = ordered[index];
    const [, previous] = ordered[index - 1];
    if (hlcTuple(current) !== null && hlcTuple(previous) !== null && !hlcAfter(current, previous)) {
      addIssue(issues, criterion, true, `claim_lift_hlc_order_invalid:${criterion}`);
    }
  }
}

function verifiedCriteria(issues) {
  return CRITERIA.filter((criterion) => !issues.some((issue) => issue.criterion === criterion));
}

function buildReceipt(input, blockedBy, criteria, allowed) {
  const anchorPayload = {
    schema: `${RECEIPT_SCHEMA}.anchor`,
    claimGateId: hasText(input?.claimMapping?.gateId) ? input.claimMapping.gateId : 'unclassified',
    claimTextHash: isDigest(input?.claimMapping?.claimTextHash) ? input.claimMapping.claimTextHash : null,
    mappedArtifactType: hasText(input?.claimMapping?.mappedArtifactType) ? input.claimMapping.mappedArtifactType : 'unclassified',
    mappedArtifactHash: isDigest(input?.claimMapping?.mappedArtifactHash) ? input.claimMapping.mappedArtifactHash : null,
    sourceCommitHash: hasText(input?.sourceTruth?.commitHash) ? input.sourceTruth.commitHash : null,
    runtimePathHash: isDigest(input?.runtimePath?.runtimePathHash) ? input.runtimePath.runtimePathHash : null,
    deploymentConfigHash: isDigest(input?.deploymentConfiguration?.deploymentConfigHash)
      ? input.deploymentConfiguration.deploymentConfigHash
      : null,
    adapterBoundaryHash: isDigest(input?.adapterBoundary?.boundaryHash) ? input.adapterBoundary.boundaryHash : null,
    testMatrixHash: isDigest(input?.testMatrix?.matrixHash) ? input.testMatrix.matrixHash : null,
    privacyBoundaryHash: isDigest(input?.privacyBoundary?.privacyBoundaryHash) ? input.privacyBoundary.privacyBoundaryHash : null,
    contextReviewHash: isDigest(input?.contextReview?.reviewHash) ? input.contextReview.reviewHash : null,
    humanDecisionHash: isDigest(input?.humanDecision?.decisionHash) ? input.humanDecision.decisionHash : null,
    auditRecordHash: isDigest(input?.auditRecord?.auditRecordHash) ? input.auditRecord.auditRecordHash : null,
    custodyDigest: isDigest(input?.custodyDigest) ? input.custodyDigest : null,
    blockedBy,
    verifiedCriteria: criteria,
    canLiftProductionClaim: allowed,
  };
  const actionHash = sha256Hex({
    schema: 'cybermedica.production_claim_lift_action.v1',
    claimGateId: anchorPayload.claimGateId,
    mappedArtifactHash: anchorPayload.mappedArtifactHash,
    sourceCommitHash: anchorPayload.sourceCommitHash,
    deploymentConfigHash: anchorPayload.deploymentConfigHash,
  });

  return {
    schema: RECEIPT_SCHEMA,
    receiptId: `cmclaim_${sha256Hex(anchorPayload).slice(0, 32)}`,
    actionHash,
    trustState: allowed ? 'verified' : 'inactive',
    exochainProductionClaim: allowed,
    containsProtectedContent: false,
    metadataOnly: true,
    immutableReceipt: true,
    operationalStateMutable: true,
    anchorPayload,
  };
}

export function evaluateProductionClaimLift(input) {
  assertMetadataOnly(input ?? {});

  const issues = [];
  evaluateTenantActorAuthority(input, issues);
  evaluateSourceTruth(input?.sourceTruth, issues);
  evaluateRuntimePath(input?.runtimePath, issues);
  evaluateDeploymentConfiguration(input?.deploymentConfiguration, issues);
  evaluateAdapterBoundary(input?.adapterBoundary, issues);
  evaluateTestMatrix(input?.testMatrix, issues);
  evaluatePrivacyBoundary(input?.privacyBoundary, issues);
  evaluateClaimMapping(input?.claimMapping, issues);
  evaluateContextReview(input?.contextReview, issues);
  evaluateHumanDecision(input?.humanDecision, issues);
  evaluateAuditRecord(input?.auditRecord, issues);
  addIssue(issues, 'context_review', !isDigest(input?.custodyDigest), 'claim_lift_custody_digest_invalid');
  evaluateChronology(input, issues);

  const blockedBy = uniqueReasonList(issues);
  const allowed = blockedBy.length === 0;
  const criteria = verifiedCriteria(issues);

  return {
    schema: DECISION_SCHEMA,
    allowed,
    state: allowed ? 'verified' : 'denied',
    failClosed: !allowed,
    canLiftProductionClaim: allowed,
    exochainProductionClaim: allowed,
    baselineDevelopmentBlocked: false,
    claimGateId: hasText(input?.claimMapping?.gateId) ? input.claimMapping.gateId : 'unclassified',
    blockedBy,
    verifiedCriteria: criteria,
    receipt: buildReceipt(input ?? {}, blockedBy, criteria, allowed),
  };
}
