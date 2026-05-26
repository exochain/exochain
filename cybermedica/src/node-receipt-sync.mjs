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
const SYNC_SCHEMA = 'cybermedica.node_receipt_sync.v1';
const DECISION_SCHEMA = 'cybermedica.node_receipt_sync_decision.v1';
const REQUIRED_PERMISSION = 'node_receipt_sync_review';
const REQUIRED_ACTIVATION_GATE = 'PTAG-017';

const REQUIRED_NODE_OPERATIONS = Object.freeze([
  'insert',
  'load',
  'provenance_query',
  'query_by_actor',
]);

const REQUIRED_SOURCE_PATHS = Object.freeze([
  'crates/exo-node/src/api.rs',
  'crates/exo-node/src/provenance.rs',
  'crates/exo-node/src/store.rs',
]);

const POLICY_STATUSES = new Set(['active']);
const OPERATION_STATUSES = new Set(['verified']);
const INSERT_STATUSES = new Set(['inserted']);
const LOAD_STATUSES = new Set(['loaded']);
const QUERY_MODES = new Set(['by_actor']);
const HUMAN_REVIEW_DECISIONS = new Set([
  'hold_for_node_receipt_sync_gap',
  'node_receipt_sync_ready_inactive_trust',
]);

const RAW_NODE_RECEIPT_FIELDS = new Set([
  'anchorpayload',
  'body',
  'content',
  'freetext',
  'payload',
  'payloadbody',
  'provenancebody',
  'rawanchorpayload',
  'rawnodepayload',
  'rawpayload',
  'rawprovenancepayload',
  'rawreceipt',
  'rawreceiptbody',
  'receiptbody',
  'sourcebody',
  'sourcedocumentbody',
  'validationlog',
]);

const SECRET_NODE_RECEIPT_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'apitoken',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credential',
  'credentialsecret',
  'nodeprivatekey',
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

function assertNoNodeReceiptPayloadOrSecrets(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoNodeReceiptPayloadOrSecrets(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_NODE_RECEIPT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`node receipt raw payload field is not allowed at ${path}.${key}`);
    }
    if (SECRET_NODE_RECEIPT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`node receipt secret field is not allowed at ${path}.${key}`);
    }
    assertNoNodeReceiptPayloadOrSecrets(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoNodeReceiptPayloadOrSecrets(input ?? {});
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
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION), 'authority_permission_missing');
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(input, reasons) {
  const policy = input?.syncPolicy;
  addReason(reasons, !hasText(policy?.policyRef), 'sync_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'sync_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'sync_policy_not_active');
  addReason(reasons, policy?.actionHashSyncRequired !== true, 'action_hash_sync_not_required');
  addReason(reasons, policy?.signatureEvidenceRequired !== true, 'signature_evidence_not_required');
  addReason(
    reasons,
    policy?.provenancePayloadSuppressionRequired !== true,
    'provenance_payload_suppression_not_required',
  );
  addReason(reasons, policy?.queryByActorRequired !== true, 'query_by_actor_not_required');
  addReason(reasons, policy?.metadataOnly !== true, 'sync_policy_metadata_boundary_missing');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'sync_policy_protected_content_boundary_missing');

  evaluateRequiredSet(
    sortedTextList(policy?.requiredNodeOperations),
    REQUIRED_NODE_OPERATIONS,
    'required_node_operation_missing',
    'required_node_operation_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    sortedTextList(policy?.requiredSourcePaths),
    REQUIRED_SOURCE_PATHS,
    'required_source_path_missing',
    'required_source_path_unsupported',
    reasons,
  );
}

function evaluateCycle(input, reasons) {
  const cycle = input?.syncCycle;
  addReason(reasons, !hasText(cycle?.syncRef), 'sync_ref_absent');
  addReason(reasons, cycle?.activationGateId !== REQUIRED_ACTIVATION_GATE, 'activation_gate_not_ptag_017');
  addReason(reasons, !hasText(cycle?.selectedDeploymentMode), 'selected_deployment_mode_absent');
  addReason(
    reasons,
    hasText(cycle?.selectedDeploymentMode) && !sortedTextList(input?.syncPolicy?.allowedDeploymentModes).includes(cycle.selectedDeploymentMode),
    'selected_deployment_mode_unsupported',
  );
  addReason(reasons, cycle?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, cycle?.metadataOnly !== true, 'sync_cycle_metadata_boundary_missing');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'sync_cycle_protected_content_boundary_missing');
  addReason(reasons, hlcTuple(cycle?.openedAtHlc) === null, 'sync_cycle_openedAtHlc_invalid');
  addReason(reasons, hlcTuple(cycle?.evidenceRecordedAtHlc) === null, 'sync_cycle_evidenceRecordedAtHlc_invalid');
  addReason(reasons, hlcTuple(cycle?.validationRecordedAtHlc) === null, 'sync_cycle_validationRecordedAtHlc_invalid');
  addReason(reasons, hlcTuple(cycle?.humanReviewedAtHlc) === null, 'sync_cycle_humanReviewedAtHlc_invalid');
  addReason(
    reasons,
    hlcBefore(cycle?.evidenceRecordedAtHlc, cycle?.openedAtHlc),
    'sync_cycle_evidenceRecordedAtHlc_before_openedAtHlc',
  );
}

function evaluateNodeOperations(input, reasons) {
  if (!Array.isArray(input?.nodeOperations)) {
    reasons.push('node_operations_absent');
    return [];
  }

  const operations = [];
  for (const [index, operation] of input.nodeOperations.entries()) {
    addReason(reasons, !REQUIRED_NODE_OPERATIONS.includes(operation?.operation), `node_operation_unsupported:${operation?.operation ?? index}`);
    addReason(reasons, !OPERATION_STATUSES.has(operation?.status), `node_operation_status_unverified:${operation?.operation ?? index}`);
    addReason(reasons, !hasText(operation?.evidenceRef), `node_operation_evidence_ref_absent:${operation?.operation ?? index}`);
    addReason(reasons, !isDigest(operation?.evidenceHash), `node_operation_evidence_hash_invalid:${operation?.operation ?? index}`);
    addReason(reasons, !REQUIRED_SOURCE_PATHS.includes(operation?.sourcePath), `node_operation_source_path_invalid:${operation?.operation ?? index}`);
    addReason(reasons, operation?.metadataOnly !== true, `node_operation_metadata_boundary_missing:${operation?.operation ?? index}`);
    if (REQUIRED_NODE_OPERATIONS.includes(operation?.operation)) {
      operations.push(operation.operation);
    }
  }

  evaluateRequiredSet(
    uniqueSorted(operations),
    REQUIRED_NODE_OPERATIONS,
    'node_operation_missing',
    'node_operation_extra',
    reasons,
  );
  return uniqueSorted(operations);
}

function evaluateInsertEvidence(input, reasons) {
  const insert = input?.insertEvidence;
  addReason(reasons, !hasText(insert?.receiptId), 'insert_receipt_id_absent');
  addReason(reasons, !isDigest(insert?.actionHash), 'insert_action_hash_invalid');
  addReason(reasons, !hasText(insert?.receiptStoreRef), 'receipt_store_ref_absent');
  addReason(reasons, !hasText(insert?.signerDid), 'receipt_signer_absent');
  addReason(reasons, !isDigest(insert?.signatureHash), 'receipt_signature_missing');
  addReason(reasons, !INSERT_STATUSES.has(insert?.status), 'insert_status_not_inserted');
  addReason(reasons, insert?.metadataOnly !== true, 'insert_metadata_boundary_missing');
  addReason(reasons, insert?.protectedContentExcluded !== true, 'insert_protected_content_boundary_missing');
  addReason(reasons, hlcTuple(insert?.insertedAtHlc) === null, 'insert_hlc_invalid');
}

function evaluateLoadEvidence(input, reasons) {
  const insert = input?.insertEvidence;
  const load = input?.loadEvidence;
  addReason(reasons, !hasText(load?.receiptId), 'load_receipt_id_absent');
  addReason(
    reasons,
    hasText(load?.receiptId) && hasText(insert?.receiptId) && load.receiptId !== insert.receiptId,
    'load_receipt_id_mismatch',
  );
  addReason(reasons, !isDigest(load?.actionHash), 'load_action_hash_invalid');
  addReason(
    reasons,
    isDigest(load?.actionHash) && isDigest(insert?.actionHash) && load.actionHash !== insert.actionHash,
    'load_action_hash_mismatch',
  );
  addReason(reasons, !LOAD_STATUSES.has(load?.status), 'load_status_not_loaded');
  addReason(reasons, load?.metadataOnly !== true, 'load_metadata_boundary_missing');
  addReason(reasons, load?.protectedContentExcluded !== true, 'load_protected_content_boundary_missing');
  addReason(reasons, hlcTuple(load?.loadedAtHlc) === null, 'load_hlc_invalid');
  addReason(reasons, hlcBefore(load?.loadedAtHlc, insert?.insertedAtHlc), 'load_hlc_before_insert_hlc');
}

function evaluateQueryEvidence(input, reasons) {
  const insert = input?.insertEvidence;
  const load = input?.loadEvidence;
  const query = input?.queryEvidence;
  addReason(reasons, !hasText(query?.actorDid), 'query_actor_absent');
  addReason(reasons, !QUERY_MODES.has(query?.queryMode), 'query_mode_not_by_actor');
  addReason(
    reasons,
    !Array.isArray(query?.returnedReceiptIds) || !query.returnedReceiptIds.includes(insert?.receiptId),
    'query_receipt_id_missing',
  );
  addReason(
    reasons,
    !Array.isArray(query?.returnedActionHashes) || !query.returnedActionHashes.includes(insert?.actionHash),
    'query_action_hash_missing',
  );
  addReason(reasons, query?.metadataOnly !== true, 'query_metadata_boundary_missing');
  addReason(reasons, query?.protectedContentExcluded !== true, 'query_protected_content_boundary_missing');
  addReason(reasons, hlcTuple(query?.queriedAtHlc) === null, 'query_hlc_invalid');
  addReason(reasons, hlcBefore(query?.queriedAtHlc, load?.loadedAtHlc), 'query_hlc_before_load_hlc');
}

function evaluateProvenanceEvidence(input, reasons) {
  const insert = input?.insertEvidence;
  const query = input?.queryEvidence;
  const provenance = input?.provenanceEvidence;
  addReason(reasons, !isDigest(provenance?.provenanceResponseHash), 'provenance_response_hash_invalid');
  addReason(reasons, !isDigest(provenance?.nodeHash), 'provenance_node_hash_invalid');
  addReason(reasons, !isDigest(provenance?.payloadHash), 'provenance_payload_hash_invalid');
  addReason(reasons, !isDigest(provenance?.actionHash), 'provenance_action_hash_invalid');
  addReason(
    reasons,
    isDigest(provenance?.actionHash) && isDigest(insert?.actionHash) && provenance.actionHash !== insert.actionHash,
    'provenance_action_hash_mismatch',
  );
  addReason(
    reasons,
    isDigest(provenance?.payloadHash) && isDigest(insert?.actionHash) && provenance.payloadHash !== insert.actionHash,
    'provenance_payload_hash_mismatch',
  );
  addReason(reasons, provenance?.responseIncludesRawPayload === true, 'provenance_raw_payload_disclosure');
  addReason(reasons, provenance?.anchorPayloadSuppressed !== true, 'provenance_anchor_payload_not_suppressed');
  addReason(
    reasons,
    provenance?.healthDebugTelemetryPayloadSuppressed !== true,
    'observability_payload_not_suppressed',
  );
  addReason(reasons, provenance?.apiSourcePath !== 'crates/exo-node/src/api.rs', 'provenance_api_source_path_invalid');
  addReason(
    reasons,
    provenance?.provenanceSourcePath !== 'crates/exo-node/src/provenance.rs',
    'provenance_source_path_invalid',
  );
  addReason(reasons, provenance?.metadataOnly !== true, 'provenance_metadata_boundary_missing');
  addReason(reasons, provenance?.protectedContentExcluded !== true, 'provenance_protected_content_boundary_missing');
  addReason(reasons, hlcTuple(provenance?.queriedAtHlc) === null, 'provenance_hlc_invalid');
  addReason(reasons, hlcBefore(provenance?.queriedAtHlc, query?.queriedAtHlc), 'provenance_hlc_before_query_hlc');
}

function evaluateValidationAndReview(input, reasons) {
  const provenance = input?.provenanceEvidence;
  const validation = input?.validationEvidence;
  const review = input?.humanReview;

  addReason(reasons, !Array.isArray(validation?.commandRefs) || validation.commandRefs.length === 0, 'validation_command_refs_absent');
  addReason(reasons, validation?.commandsPassed !== true, 'validation_commands_failed');
  addReason(reasons, !isDigest(validation?.testManifestHash), 'test_manifest_hash_invalid');
  addReason(reasons, !isDigest(validation?.receiptSyncFixtureHash), 'receipt_sync_fixture_hash_invalid');
  addReason(reasons, !isDigest(validation?.noRawPayloadFixtureHash), 'no_raw_payload_fixture_hash_invalid');
  addReason(reasons, validation?.noExochainSourceModified !== true, 'exochain_source_modified');
  addReason(reasons, validation?.metadataOnly !== true, 'validation_metadata_boundary_missing');
  addReason(reasons, hlcTuple(validation?.recordedAtHlc) === null, 'validation_hlc_invalid');
  addReason(
    reasons,
    hlcBefore(validation?.recordedAtHlc, provenance?.queriedAtHlc),
    'validation_hlc_before_provenance_hlc',
  );

  addReason(reasons, !hasText(review?.reviewerDid), 'human_review_reviewer_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.reviewHash), 'human_review_hash_invalid');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_missing');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_hlc_invalid');
  addReason(
    reasons,
    hlcBefore(review?.reviewedAtHlc, validation?.recordedAtHlc),
    'human_review_hlc_before_validation_hlc',
  );
}

function buildNodeReceiptSync(input, operationsCovered) {
  const sourcePathsVerified = REQUIRED_SOURCE_PATHS.filter((sourcePath) => {
    if (input.syncPolicy.requiredSourcePaths.includes(sourcePath)) {
      return true;
    }
    if (sourcePath === input.provenanceEvidence.apiSourcePath || sourcePath === input.provenanceEvidence.provenanceSourcePath) {
      return true;
    }
    return input.nodeOperations.some((operation) => operation.sourcePath === sourcePath);
  }).sort();

  const validationCommandRefs = sortedTextList(input.validationEvidence.commandRefs);
  const syncEvidenceHash = sha256Hex({
    actionHash: input.insertEvidence.actionHash,
    activationGateId: input.syncCycle.activationGateId,
    nodeHash: input.provenanceEvidence.nodeHash,
    operationsCovered,
    provenanceResponseHash: input.provenanceEvidence.provenanceResponseHash,
    receiptId: input.insertEvidence.receiptId,
    schema: SYNC_SCHEMA,
    selectedDeploymentMode: input.syncCycle.selectedDeploymentMode,
    sourcePathsVerified,
    validationCommandRefs,
  });

  return {
    schema: SYNC_SCHEMA,
    syncRef: input.syncCycle.syncRef,
    activationGateId: input.syncCycle.activationGateId,
    selectedDeploymentMode: input.syncCycle.selectedDeploymentMode,
    syncStatus: 'ready_inactive_trust',
    receiptId: input.insertEvidence.receiptId,
    actionHash: input.insertEvidence.actionHash,
    nodeHash: input.provenanceEvidence.nodeHash,
    provenanceResponseHash: input.provenanceEvidence.provenanceResponseHash,
    requiredOperationsCovered: operationsCovered,
    sourcePathsVerified,
    actionHashSynced: true,
    receiptSignatureVerified: true,
    queryByActorVerified: true,
    provenancePayloadSuppressed: true,
    validationCommandRefs,
    reviewedAtHlc: input.humanReview.reviewedAtHlc,
    trustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    syncEvidenceHash,
  };
}

function buildReceipt(input, nodeReceiptSync) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'node_receipt_sync',
    artifactHash: nodeReceiptSync.syncEvidenceHash,
    artifactVersion: input.syncCycle.syncRef,
    classification: 'metadata_only',
    custodyDigest: input.validationEvidence.receiptSyncFixtureHash,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    sensitivityTags: ['metadata_only', 'node_receipt_sync', input.syncCycle.activationGateId],
    sourceSystem: 'cybermedica-node-receipt-sync',
  });
}

export function evaluateNodeReceiptSyncReadiness(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluatePolicy(input, reasons);
  evaluateCycle(input, reasons);
  const operationsCovered = evaluateNodeOperations(input, reasons);
  evaluateInsertEvidence(input, reasons);
  evaluateLoadEvidence(input, reasons);
  evaluateQueryEvidence(input, reasons);
  evaluateProvenanceEvidence(input, reasons);
  evaluateValidationAndReview(input, reasons);

  const deniedReasons = uniqueReasons(reasons);
  if (deniedReasons.length > 0) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: deniedReasons,
      nodeReceiptSync: null,
      receipt: null,
    };
  }

  const nodeReceiptSync = buildNodeReceiptSync(input, operationsCovered);
  const receipt = buildReceipt(input, nodeReceiptSync);

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    nodeReceiptSync,
    receipt,
  };
}
