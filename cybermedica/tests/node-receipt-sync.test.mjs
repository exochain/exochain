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

import assert from 'node:assert/strict';
import { test } from 'node:test';

const DIGEST_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const DIGEST_C = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const DIGEST_D = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const DIGEST_E = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const DIGEST_F = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
const DIGEST_1 = '1111111111111111111111111111111111111111111111111111111111111111';
const DIGEST_2 = '2222222222222222222222222222222222222222222222222222222222222222';
const DIGEST_3 = '3333333333333333333333333333333333333333333333333333333333333333';
const DIGEST_4 = '4444444444444444444444444444444444444444444444444444444444444444';
const DIGEST_5 = '5555555555555555555555555555555555555555555555555555555555555555';
const DIGEST_6 = '6666666666666666666666666666666666666666666666666666666666666666';

const REQUIRED_NODE_OPERATIONS = ['insert', 'load', 'provenance_query', 'query_by_actor'];

async function loadNodeReceiptSync() {
  try {
    return await import('../src/node-receipt-sync.mjs');
  } catch (error) {
    assert.fail(`CyberMedica node receipt sync module must exist and load: ${error.message}`);
  }
}

function mergeDeep(base, overrides) {
  if (Array.isArray(base) || Array.isArray(overrides)) {
    return overrides === undefined ? base : overrides;
  }
  if (base === null || overrides === null || typeof base !== 'object' || typeof overrides !== 'object') {
    return overrides === undefined ? base : overrides;
  }
  return Object.fromEntries(
    [...new Set([...Object.keys(base), ...Object.keys(overrides)])].map((key) => [
      key,
      mergeDeep(base[key], overrides[key]),
    ]),
  );
}

function nodeOperation(operation, index, overrides = {}) {
  const operationHashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D];
  return {
    operation,
    evidenceRef: `node-receipt-${operation}-evidence-alpha`,
    evidenceHash: operationHashes[index],
    sourcePath:
      operation === 'provenance_query'
        ? 'crates/exo-node/src/provenance.rs'
        : 'crates/exo-node/src/store.rs',
    commandRef: `node receipt ${operation} contract test`,
    status: 'verified',
    metadataOnly: true,
    reviewedAtHlc: { physicalMs: 1800015000000, logical: index },
    ...overrides,
  };
}

function nodeOperations() {
  return REQUIRED_NODE_OPERATIONS.map((operation, index) => nodeOperation(operation, index));
}

function syncInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:receipt-sync-owner-alpha',
      kind: 'human',
      roleRefs: ['deployment_owner', 'quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['node_receipt_sync_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    syncPolicy: {
      policyRef: 'node-receipt-sync-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      allowedDeploymentModes: ['exo_node_server', 'gateway_node_adapter'],
      requiredNodeOperations: REQUIRED_NODE_OPERATIONS,
      requiredSourcePaths: [
        'crates/exo-node/src/store.rs',
        'crates/exo-node/src/api.rs',
        'crates/exo-node/src/provenance.rs',
      ],
      actionHashSyncRequired: true,
      signatureEvidenceRequired: true,
      provenancePayloadSuppressionRequired: true,
      queryByActorRequired: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800014900000, logical: 0 },
    },
    syncCycle: {
      syncRef: 'node-receipt-sync-alpha',
      activationGateId: 'PTAG-017',
      selectedDeploymentMode: 'exo_node_server',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      openedAtHlc: { physicalMs: 1800014950000, logical: 0 },
      evidenceRecordedAtHlc: { physicalMs: 1800015000000, logical: 5 },
      validationRecordedAtHlc: { physicalMs: 1800015100000, logical: 0 },
      humanReviewedAtHlc: { physicalMs: 1800015200000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    nodeOperations: nodeOperations(),
    insertEvidence: {
      receiptId: 'exo-node-receipt-doc-version-alpha',
      actionHash: DIGEST_C,
      receiptStoreRef: 'exo-node-store-alpha',
      signerDid: 'did:exo:node-alpha',
      signatureHash: DIGEST_D,
      insertedAtHlc: { physicalMs: 1800015010000, logical: 0 },
      status: 'inserted',
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    loadEvidence: {
      receiptId: 'exo-node-receipt-doc-version-alpha',
      actionHash: DIGEST_C,
      loadedAtHlc: { physicalMs: 1800015020000, logical: 0 },
      status: 'loaded',
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    queryEvidence: {
      actorDid: 'did:exo:quality-manager-alpha',
      queryMode: 'by_actor',
      returnedReceiptIds: ['exo-node-receipt-doc-version-alpha'],
      returnedActionHashes: [DIGEST_C],
      queriedAtHlc: { physicalMs: 1800015030000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    provenanceEvidence: {
      provenanceResponseHash: DIGEST_E,
      nodeHash: DIGEST_F,
      payloadHash: DIGEST_C,
      actionHash: DIGEST_C,
      responseIncludesRawPayload: false,
      anchorPayloadSuppressed: true,
      healthDebugTelemetryPayloadSuppressed: true,
      apiSourcePath: 'crates/exo-node/src/api.rs',
      provenanceSourcePath: 'crates/exo-node/src/provenance.rs',
      queriedAtHlc: { physicalMs: 1800015040000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    validationEvidence: {
      commandRefs: ['node --test tests/node-receipt-sync.test.mjs', 'npm run quality'],
      commandsPassed: true,
      testManifestHash: DIGEST_1,
      receiptSyncFixtureHash: DIGEST_2,
      noRawPayloadFixtureHash: DIGEST_3,
      noExochainSourceModified: true,
      metadataOnly: true,
      recordedAtHlc: { physicalMs: 1800015100000, logical: 0 },
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-manager-alpha',
      decision: 'node_receipt_sync_ready_inactive_trust',
      reviewHash: DIGEST_4,
      reviewedAtHlc: { physicalMs: 1800015200000, logical: 0 },
      metadataOnly: true,
    },
  };

  return mergeDeep(base, overrides);
}

test('node receipt sync creates deterministic PTAG-017 inactive readiness evidence', async () => {
  const { evaluateNodeReceiptSyncReadiness } = await loadNodeReceiptSync();

  const first = evaluateNodeReceiptSyncReadiness(syncInput());
  const second = evaluateNodeReceiptSyncReadiness(
    syncInput({
      nodeOperations: [...nodeOperations()].reverse(),
      queryEvidence: {
        returnedReceiptIds: ['exo-node-receipt-doc-version-alpha'],
        returnedActionHashes: [DIGEST_C],
      },
    }),
  );

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.nodeReceiptSync.syncStatus, 'ready_inactive_trust');
  assert.equal(first.nodeReceiptSync.activationGateId, 'PTAG-017');
  assert.equal(first.nodeReceiptSync.selectedDeploymentMode, 'exo_node_server');
  assert.equal(first.nodeReceiptSync.actionHashSynced, true);
  assert.equal(first.nodeReceiptSync.receiptSignatureVerified, true);
  assert.equal(first.nodeReceiptSync.queryByActorVerified, true);
  assert.equal(first.nodeReceiptSync.provenancePayloadSuppressed, true);
  assert.deepEqual(first.nodeReceiptSync.requiredOperationsCovered, REQUIRED_NODE_OPERATIONS);
  assert.deepEqual(first.nodeReceiptSync.sourcePathsVerified, [
    'crates/exo-node/src/api.rs',
    'crates/exo-node/src/provenance.rs',
    'crates/exo-node/src/store.rs',
  ]);
  assert.equal(first.receipt.anchorPayload.artifactType, 'node_receipt_sync');
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.deepEqual(first.nodeReceiptSync, second.nodeReceiptSync);
  assert.doesNotMatch(JSON.stringify(first), /Participant Alice|source document body|private key|raw payload/iu);
});

test('node receipt sync fails closed for missing operations deployment selection and hash mismatches', async () => {
  const { evaluateNodeReceiptSyncReadiness } = await loadNodeReceiptSync();

  const denied = evaluateNodeReceiptSyncReadiness(
    syncInput({
      targetTenantId: 'tenant-site-beta',
      actor: { kind: 'ai_agent' },
      authority: {
        revoked: true,
        expired: true,
        permissions: ['read'],
        authorityChainHash: 'not-a-digest',
      },
      syncCycle: {
        selectedDeploymentMode: 'browser_wasm',
        productionTrustClaim: true,
      },
      syncPolicy: {
        status: 'draft',
        requiredNodeOperations: REQUIRED_NODE_OPERATIONS,
      },
      nodeOperations: nodeOperations().filter((operation) => operation.operation !== 'query_by_actor'),
      insertEvidence: {
        actionHash: DIGEST_C,
        signatureHash: '',
        status: 'pending',
      },
      loadEvidence: {
        actionHash: DIGEST_D,
        status: 'missing',
      },
      queryEvidence: {
        queryMode: 'by_tenant',
        returnedReceiptIds: [],
        returnedActionHashes: [DIGEST_D],
      },
      provenanceEvidence: {
        actionHash: DIGEST_E,
        payloadHash: DIGEST_5,
        responseIncludesRawPayload: true,
        anchorPayloadSuppressed: false,
        healthDebugTelemetryPayloadSuppressed: false,
      },
      validationEvidence: {
        commandsPassed: false,
        noExochainSourceModified: false,
      },
      humanReview: {
        decision: 'approved_for_production_trust',
        reviewHash: 'not-a-digest',
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.nodeReceiptSync, null);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_chain_revoked'));
  assert.ok(denied.reasons.includes('authority_chain_expired'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('sync_policy_not_active'));
  assert.ok(denied.reasons.includes('selected_deployment_mode_unsupported'));
  assert.ok(denied.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(denied.reasons.includes('node_operation_missing:query_by_actor'));
  assert.ok(denied.reasons.includes('insert_status_not_inserted'));
  assert.ok(denied.reasons.includes('receipt_signature_missing'));
  assert.ok(denied.reasons.includes('load_status_not_loaded'));
  assert.ok(denied.reasons.includes('load_action_hash_mismatch'));
  assert.ok(denied.reasons.includes('query_mode_not_by_actor'));
  assert.ok(denied.reasons.includes('query_receipt_id_missing'));
  assert.ok(denied.reasons.includes('query_action_hash_missing'));
  assert.ok(denied.reasons.includes('provenance_action_hash_mismatch'));
  assert.ok(denied.reasons.includes('provenance_payload_hash_mismatch'));
  assert.ok(denied.reasons.includes('provenance_raw_payload_disclosure'));
  assert.ok(denied.reasons.includes('provenance_anchor_payload_not_suppressed'));
  assert.ok(denied.reasons.includes('observability_payload_not_suppressed'));
  assert.ok(denied.reasons.includes('validation_commands_failed'));
  assert.ok(denied.reasons.includes('exochain_source_modified'));
  assert.ok(denied.reasons.includes('human_review_decision_invalid'));
  assert.ok(denied.reasons.includes('human_review_hash_invalid'));
});

test('node receipt sync validates HLC ordering and absent collections as denial states', async () => {
  const { evaluateNodeReceiptSyncReadiness } = await loadNodeReceiptSync();

  const denied = evaluateNodeReceiptSyncReadiness(
    syncInput({
      nodeOperations: null,
      syncCycle: {
        evidenceRecordedAtHlc: { physicalMs: 1800014890000, logical: 0 },
      },
      insertEvidence: {
        insertedAtHlc: { physicalMs: 1800015300000, logical: 0 },
      },
      loadEvidence: {
        loadedAtHlc: { physicalMs: 1800015200000, logical: 0 },
      },
      queryEvidence: {
        queriedAtHlc: { physicalMs: 1800015100000, logical: 0 },
      },
      provenanceEvidence: {
        queriedAtHlc: { physicalMs: 1800015000000, logical: 0 },
      },
      validationEvidence: {
        recordedAtHlc: { physicalMs: 1800014990000, logical: 0 },
      },
      humanReview: {
        reviewedAtHlc: { physicalMs: 1800014980000, logical: 0 },
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('node_operations_absent'));
  assert.ok(denied.reasons.includes('sync_cycle_evidenceRecordedAtHlc_before_openedAtHlc'));
  assert.ok(denied.reasons.includes('load_hlc_before_insert_hlc'));
  assert.ok(denied.reasons.includes('query_hlc_before_load_hlc'));
  assert.ok(denied.reasons.includes('provenance_hlc_before_query_hlc'));
  assert.ok(denied.reasons.includes('validation_hlc_before_provenance_hlc'));
  assert.ok(denied.reasons.includes('human_review_hlc_before_validation_hlc'));
});

test('node receipt sync rejects raw payload protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateNodeReceiptSyncReadiness } = await loadNodeReceiptSync();

  for (const unsafeInput of [
    syncInput({ provenanceEvidence: { rawPayload: 'source document body for Participant Alice Example' } }),
    syncInput({ insertEvidence: { receiptBody: { participantName: 'Participant Alice Example' } } }),
    syncInput({ validationEvidence: { validationLog: 'medical record: MRN-12345' } }),
    syncInput({ syncCycle: { privateKey: 'node-private-key-material' } }),
    syncInput({ queryEvidence: { apiKey: 'node-api-key-material' } }),
  ]) {
    assert.throws(() => evaluateNodeReceiptSyncReadiness(unsafeInput), ProtectedContentError);
  }
});
