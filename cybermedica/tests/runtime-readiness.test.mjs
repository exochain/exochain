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

async function loadRuntimeReadiness() {
  try {
    return await import('../src/runtime-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica runtime readiness module must exist and load: ${error.message}`);
  }
}

const verifiedRootBundle = Object.freeze({
  status: 'verified',
  verified: true,
  certifierCount: 13,
  dkgParticipantCount: 13,
  thresholdSignature: '7-of-13',
  verifierReceiptId: 'root-verifier-receipt-alpha',
  artifactRegistryHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  operationsRunbookHash: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  rootTrustBundleHash: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
  rosterHash: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
});

const verifiedDependency = Object.freeze({ verified: true });

function verifiedRuntimeInput() {
  return {
    service: {
      serviceId: 'cybermedica-qms-api',
      releaseId: 'cm-build-2026-05-23-alpha',
      process: { status: 'ready', buildHash: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824' },
    },
    trust: {
      claimId: 'PTAG-016',
      rootBundle: verifiedRootBundle,
      gatewayAdapter: verifiedDependency,
      receiptPath: verifiedDependency,
      privacyBoundary: verifiedDependency,
      decisionForum: verifiedDependency,
    },
    dependencies: {
      gateway: { status: 'ready', checkedBy: 'did:exo:ops-runtime-alpha' },
      nodeReceiptStore: { status: 'ready', checkedBy: 'did:exo:ops-runtime-alpha' },
      decisionForum: { status: 'ready', checkedBy: 'did:exo:ops-runtime-alpha' },
      rootBundleProvider: { status: 'ready', checkedBy: 'did:exo:ops-runtime-alpha' },
    },
    privacyBoundary: {
      anchors: { verified: true },
      logs: { verified: true },
      telemetry: { verified: true },
      health: { verified: true },
      exports: { verified: true },
    },
    healthPayload: {
      serviceId: 'cybermedica-qms-api',
      releaseId: 'cm-build-2026-05-23-alpha',
      dependencySummary: 'metadata_only',
    },
  };
}

test('runtime readiness separates process health from inactive trust readiness and fails closed', async () => {
  const { buildRuntimeReadinessSnapshot } = await loadRuntimeReadiness();

  const snapshot = buildRuntimeReadinessSnapshot({
    service: {
      serviceId: 'cybermedica-qms-api',
      releaseId: 'cm-build-2026-05-23-alpha',
      process: { status: 'ready', buildHash: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824' },
    },
    trust: {
      claimId: 'PTAG-016',
      rootBundle: null,
      gatewayAdapter: null,
      receiptPath: null,
      privacyBoundary: null,
      decisionForum: null,
    },
    dependencies: {
      gateway: { status: 'ready', checkedBy: 'did:exo:ops-runtime-alpha' },
      nodeReceiptStore: { status: 'ready', checkedBy: 'did:exo:ops-runtime-alpha' },
      decisionForum: { status: 'ready', checkedBy: 'did:exo:ops-runtime-alpha' },
      rootBundleProvider: { status: 'ready', checkedBy: 'did:exo:ops-runtime-alpha' },
    },
    privacyBoundary: {
      anchors: { verified: true },
      logs: { verified: true },
      telemetry: { verified: true },
      health: { verified: true },
      exports: { verified: true },
    },
    healthPayload: {
      serviceId: 'cybermedica-qms-api',
      releaseId: 'cm-build-2026-05-23-alpha',
    },
  });

  assert.equal(snapshot.schema, 'cybermedica.runtime_readiness_snapshot.v1');
  assert.equal(snapshot.processState, 'ready');
  assert.equal(snapshot.dependencyState, 'ready');
  assert.equal(snapshot.rootReadinessState, 'inactive');
  assert.equal(snapshot.trustState, 'inactive');
  assert.equal(snapshot.overallState, 'inactive');
  assert.equal(snapshot.canServeRegulatedTraffic, false);
  assert.equal(snapshot.canShowProductionTrustClaim, false);
  assert.equal(snapshot.failClosed, true);
  assert.ok(snapshot.blockedBy.includes('root_bundle_absent'));
  assert.ok(snapshot.blockedBy.includes('gateway_adapter_unverified'));
  assert.doesNotMatch(JSON.stringify(snapshot.safeHealthPayload), /root-backed production authority/i);
});

test('runtime readiness is deterministic when root adapter receipt and privacy evidence verify', async () => {
  const { buildRuntimeReadinessSnapshot } = await loadRuntimeReadiness();

  const snapshotA = buildRuntimeReadinessSnapshot(verifiedRuntimeInput());
  const snapshotB = buildRuntimeReadinessSnapshot({
    ...verifiedRuntimeInput(),
    dependencies: {
      rootBundleProvider: { status: 'ready', checkedBy: 'did:exo:ops-runtime-alpha' },
      decisionForum: { status: 'ready', checkedBy: 'did:exo:ops-runtime-alpha' },
      nodeReceiptStore: { status: 'ready', checkedBy: 'did:exo:ops-runtime-alpha' },
      gateway: { status: 'ready', checkedBy: 'did:exo:ops-runtime-alpha' },
    },
  });

  assert.equal(snapshotA.snapshotHash, snapshotB.snapshotHash);
  assert.equal(snapshotA.overallState, 'ready');
  assert.equal(snapshotA.trustState, 'verified');
  assert.equal(snapshotA.rootReadinessState, 'verified');
  assert.equal(snapshotA.receiptReadinessState, 'ready');
  assert.equal(snapshotA.decisionForumReadinessState, 'ready');
  assert.equal(snapshotA.privacyBoundaryState, 'verified');
  assert.equal(snapshotA.canServeRegulatedTraffic, true);
  assert.equal(snapshotA.canShowProductionTrustClaim, true);
  assert.equal(snapshotA.failClosed, false);
  assert.deepEqual(snapshotA.blockedBy, []);
  assert.equal(snapshotA.safeHealthPayload.dependencySummary, 'metadata_only');
});

test('runtime readiness denies health output that includes protected fields or secret material', async () => {
  const { buildRuntimeReadinessSnapshot } = await loadRuntimeReadiness();

  const snapshot = buildRuntimeReadinessSnapshot({
    ...verifiedRuntimeInput(),
    runtimeConfig: {
      endpointRef: 'cybermedica-prod-runtime',
      token: 'redacted-config-value',
    },
    healthPayload: {
      serviceId: 'cybermedica-qms-api',
      rawPhi: 'redacted-health-field',
      nested: { privateKey: 'redacted-key-field' },
    },
  });

  const serializedHealthPayload = JSON.stringify(snapshot.safeHealthPayload);

  assert.equal(snapshot.overallState, 'denied');
  assert.equal(snapshot.canServeRegulatedTraffic, false);
  assert.equal(snapshot.failClosed, true);
  assert.ok(snapshot.blockedBy.includes('health_payload_disclosure'));
  assert.ok(snapshot.blockedBy.includes('runtime_secret_material_prohibited'));
  assert.doesNotMatch(serializedHealthPayload, /redacted-health-field/);
  assert.doesNotMatch(serializedHealthPayload, /redacted-key-field/);
  assert.deepEqual(snapshot.safeHealthPayload, {
    redacted: true,
    reason: 'health_payload_disclosure',
  });
});

test('runtime readiness reports degraded dependencies separately from verified trust evidence', async () => {
  const { buildRuntimeReadinessSnapshot } = await loadRuntimeReadiness();

  const snapshot = buildRuntimeReadinessSnapshot({
    ...verifiedRuntimeInput(),
    dependencies: {
      gateway: { status: 'pending', checkedBy: 'did:exo:ops-runtime-alpha' },
      nodeReceiptStore: { status: 'unavailable', checkedBy: 'did:exo:ops-runtime-alpha' },
      decisionForum: { status: 'degraded', checkedBy: 'did:exo:ops-runtime-alpha' },
      rootBundleProvider: { status: 'ready', checkedBy: 'did:exo:ops-runtime-alpha' },
    },
    healthPayload: {
      bigCount: 9n,
      list: ['zeta', 'alpha'],
      marker: Symbol('runtime-marker'),
      mixedList: [2, 'beta'],
      nullable: null,
      unsafeNumber: Number.MAX_SAFE_INTEGER + 2,
    },
  });

  assert.equal(snapshot.trustState, 'verified');
  assert.equal(snapshot.dependencyState, 'degraded');
  assert.equal(snapshot.receiptReadinessState, 'degraded');
  assert.equal(snapshot.decisionForumReadinessState, 'degraded');
  assert.equal(snapshot.overallState, 'degraded');
  assert.equal(snapshot.canServeRegulatedTraffic, false);
  assert.ok(snapshot.blockedBy.includes('gateway_dependency_unready'));
  assert.ok(snapshot.blockedBy.includes('node_receipt_store_unready'));
  assert.ok(snapshot.blockedBy.includes('decision_forum_dependency_unready'));
  assert.deepEqual(snapshot.safeHealthPayload.list, ['alpha', 'zeta']);
  assert.deepEqual(snapshot.safeHealthPayload.mixedList, [2, 'beta']);
  assert.equal(snapshot.safeHealthPayload.bigCount, '9');
  assert.equal(snapshot.safeHealthPayload.marker, 'Symbol(runtime-marker)');
  assert.equal(snapshot.safeHealthPayload.unsafeNumber, '9007199254740992');
});

test('runtime readiness denies missing dependency checks and privacy boundary failures', async () => {
  const { buildRuntimeReadinessSnapshot } = await loadRuntimeReadiness();

  const snapshot = buildRuntimeReadinessSnapshot({
    ...verifiedRuntimeInput(),
    dependencies: {},
    privacyBoundary: {
      anchors: { verified: true },
      logs: { verified: false },
      telemetry: { verified: true },
      health: { verified: true },
      exports: { verified: false },
    },
    healthPayload: null,
  });

  assert.equal(snapshot.processState, 'ready');
  assert.equal(snapshot.dependencyState, 'denied');
  assert.equal(snapshot.privacyBoundaryState, 'denied');
  assert.equal(snapshot.overallState, 'denied');
  assert.equal(snapshot.safeHealthPayload.redacted, undefined);
  assert.ok(snapshot.blockedBy.includes('gateway_dependency_unready'));
  assert.ok(snapshot.blockedBy.includes('gateway_dependency_checker_absent'));
  assert.ok(snapshot.blockedBy.includes('nodeReceiptStore_dependency_checker_absent'));
  assert.ok(snapshot.blockedBy.includes('privacy_log_boundary_unverified'));
  assert.ok(snapshot.blockedBy.includes('privacy_export_boundary_unverified'));
});

test('runtime readiness degrades process health and blocks patterned health disclosures', async () => {
  const { buildRuntimeReadinessSnapshot } = await loadRuntimeReadiness();

  const snapshot = buildRuntimeReadinessSnapshot({
    service: {
      process: { status: 'unavailable' },
    },
    trust: {
      claimId: 'PTAG-016',
      rootBundle: {
        ...verifiedRootBundle,
        status: 'pending',
        verified: false,
      },
      gatewayAdapter: verifiedDependency,
      receiptPath: verifiedDependency,
      privacyBoundary: verifiedDependency,
      decisionForum: verifiedDependency,
    },
    dependencies: {
      gateway: { status: 'ready' },
      nodeReceiptStore: { status: 'ready' },
      decisionForum: { status: 'ready' },
      rootBundleProvider: { status: 'ready' },
    },
    privacyBoundary: {
      anchors: { verified: true },
      logs: { verified: true },
      telemetry: { verified: true },
      health: { verified: true },
      exports: { verified: true },
    },
    healthPayload: {
      publicSummary: 'participant Example health output must be redacted',
    },
  });

  assert.equal(snapshot.processState, 'degraded');
  assert.equal(snapshot.rootReadinessState, 'pending');
  assert.equal(snapshot.trustState, 'pending');
  assert.equal(snapshot.overallState, 'denied');
  assert.ok(snapshot.blockedBy.includes('service_id_absent'));
  assert.ok(snapshot.blockedBy.includes('release_id_absent'));
  assert.ok(snapshot.blockedBy.includes('process_unready'));
  assert.ok(snapshot.blockedBy.includes('health_payload_disclosure'));
  assert.ok(snapshot.blockedBy.includes('root_verifier_pending'));
  assert.ok(snapshot.blockedBy.includes('gateway_dependency_checker_absent'));
  assert.deepEqual(snapshot.safeHealthPayload, {
    redacted: true,
    reason: 'health_payload_disclosure',
  });
});
