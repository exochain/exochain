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

async function loadBrowserTrustPath() {
  try {
    return await import('../src/browser-trust-path.mjs');
  } catch (error) {
    assert.fail(`CyberMedica browser trust path module must exist and load: ${error.message}`);
  }
}

const DIGEST_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const DIGEST_C = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const DIGEST_D = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const DIGEST_E = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';

function verifiedBrowserPathInput() {
  return {
    client: {
      appId: 'cybermedica-site-portal',
      kind: 'browser',
      releaseId: 'cm-browser-2026-05-24-alpha',
      tenantId: 'tenant-site-alpha',
    },
    workflow: {
      action: 'participant_record_access',
      involvesPhi: true,
      regulated: true,
      expectedServerActionHash: DIGEST_A,
    },
    serverTrustPath: {
      decisionForum: { verified: true, status: 'verified', receiptId: 'df-receipt-browser-alpha' },
      gateway: { verified: true, status: 'verified', receiptId: 'gateway-receipt-browser-alpha' },
      privacyBoundary: { verified: true, status: 'verified', receiptId: 'privacy-receipt-browser-alpha' },
      receiptPath: { verified: true, status: 'verified', receiptId: 'node-receipt-browser-alpha' },
      rootBundleProvider: { verified: true, status: 'verified', receiptId: 'root-verifier-browser-alpha' },
    },
    payloadBoundary: {
      clientAnchoringDisabled: true,
      healthDebugMetadataOnly: true,
      metadataOnly: true,
      rawPayloadSentToBrowser: false,
      sourceDocumentsInBrowser: false,
      telemetryMetadataOnly: true,
    },
    publicConfig: {
      apiBasePath: '/api/cybermedica/trust-adapter',
      configHash: DIGEST_B,
      runtimeConfigSource: 'server_rendered_metadata',
    },
    wasm: {
      adapterMode: 'client_request_only',
      exportManifestHash: DIGEST_C,
      holdsRootOrSigningSecrets: false,
    },
  };
}

test('browser trust path verifies server adjudication while keeping the client non-authoritative', async () => {
  const { evaluateBrowserTrustPath } = await loadBrowserTrustPath();

  const resultA = evaluateBrowserTrustPath(verifiedBrowserPathInput());
  const resultB = evaluateBrowserTrustPath({
    ...verifiedBrowserPathInput(),
    serverTrustPath: {
      rootBundleProvider: { verified: true, status: 'verified', receiptId: 'root-verifier-browser-alpha' },
      receiptPath: { verified: true, status: 'verified', receiptId: 'node-receipt-browser-alpha' },
      privacyBoundary: { verified: true, status: 'verified', receiptId: 'privacy-receipt-browser-alpha' },
      gateway: { verified: true, status: 'verified', receiptId: 'gateway-receipt-browser-alpha' },
      decisionForum: { verified: true, status: 'verified', receiptId: 'df-receipt-browser-alpha' },
    },
  });

  assert.equal(resultA.schema, 'cybermedica.browser_trust_path.v1');
  assert.equal(resultA.allowed, true);
  assert.equal(resultA.pathState, 'verified');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.clientMayRequestRegulatedWorkflow, true);
  assert.equal(resultA.clientMayEnforceTrust, false);
  assert.equal(resultA.serverSideAdjudicationRequired, true);
  assert.equal(resultA.exochainProductionClaim, false);
  assert.equal(resultA.productionTrustClaimAllowed, false);
  assert.equal(resultA.clientTrustAuthority, 'none');
  assert.deepEqual(resultA.blockedBy, []);
  assert.equal(resultA.pathHash, resultB.pathHash);
  assert.ok(resultA.sourceEvidence.includes('docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md#ptag-018'));
});

test('browser trust path denies missing server trust fabric and client enforcement attempts', async () => {
  const { evaluateBrowserTrustPath } = await loadBrowserTrustPath();

  const denied = evaluateBrowserTrustPath({
    ...verifiedBrowserPathInput(),
    clientTrustClaimRequested: true,
    serverTrustPath: {
      gateway: { verified: false, status: 'denied' },
      receiptPath: null,
      decisionForum: { verified: false, status: 'pending' },
      privacyBoundary: { verified: true, status: 'verified', receiptId: 'privacy-receipt-browser-alpha' },
      rootBundleProvider: { verified: false, status: 'pending' },
    },
    wasm: {
      adapterMode: 'enforcement_authority',
      exportManifestHash: DIGEST_C,
      holdsRootOrSigningSecrets: false,
    },
  });

  assert.equal(denied.allowed, false);
  assert.equal(denied.pathState, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.clientMayRequestRegulatedWorkflow, false);
  assert.equal(denied.clientMayEnforceTrust, false);
  assert.ok(denied.blockedBy.includes('gateway_server_path_unverified'));
  assert.ok(denied.blockedBy.includes('receipt_server_path_unverified'));
  assert.ok(denied.blockedBy.includes('decision_forum_server_path_unverified'));
  assert.ok(denied.blockedBy.includes('root_bundle_provider_server_path_unverified'));
  assert.ok(denied.blockedBy.includes('client_enforcement_authority_forbidden'));
  assert.ok(denied.blockedBy.includes('client_trust_claim_forbidden'));
});

test('browser trust path denies client secrets and protected payload disclosure without echoing values', async () => {
  const { evaluateBrowserTrustPath } = await loadBrowserTrustPath();

  const denied = evaluateBrowserTrustPath({
    ...verifiedBrowserPathInput(),
    browserPayload: {
      rawPhi: 'Participant Alice Example MRN: A-123',
      sponsorFacingMetadataHash: DIGEST_D,
    },
    healthDebugPayload: {
      nested: { email: 'alice@example.test' },
    },
    publicConfig: {
      apiBasePath: '/api/cybermedica/trust-adapter',
      rootSigningKey: 'must-never-ship-to-browser',
    },
    wasm: {
      adapterMode: 'client_request_only',
      exportManifestHash: DIGEST_C,
      holdsRootOrSigningSecrets: true,
      exportedSecretRefs: ['rootSigningKey'],
    },
  });

  const serialized = JSON.stringify(denied);

  assert.equal(denied.allowed, false);
  assert.equal(denied.pathState, 'denied');
  assert.ok(denied.blockedBy.includes('browser_secret_material_prohibited'));
  assert.ok(denied.blockedBy.includes('browser_payload_disclosure'));
  assert.ok(denied.blockedBy.includes('browser_health_debug_disclosure'));
  assert.ok(denied.blockedBy.includes('wasm_secret_material_prohibited'));
  assert.deepEqual(denied.safeClientManifest, {
    redacted: true,
    reason: 'browser_payload_disclosure',
  });
  assert.doesNotMatch(serialized, /Alice|A-123|alice@example\.test|must-never-ship/);
});

test('browser trust path denies client anchoring source documents and telemetry payloads', async () => {
  const { evaluateBrowserTrustPath } = await loadBrowserTrustPath();

  const denied = evaluateBrowserTrustPath({
    ...verifiedBrowserPathInput(),
    payloadBoundary: {
      clientAnchoringDisabled: false,
      healthDebugMetadataOnly: false,
      metadataOnly: false,
      rawPayloadSentToBrowser: true,
      sourceDocumentsInBrowser: true,
      telemetryMetadataOnly: false,
    },
    telemetryPayload: {
      sourceDocumentBody: 'controlled consent source material',
      telemetryHash: DIGEST_E,
    },
  });

  assert.equal(denied.allowed, false);
  assert.equal(denied.pathState, 'denied');
  assert.ok(denied.blockedBy.includes('browser_metadata_only_boundary_absent'));
  assert.ok(denied.blockedBy.includes('browser_raw_payload_forbidden'));
  assert.ok(denied.blockedBy.includes('browser_source_documents_forbidden'));
  assert.ok(denied.blockedBy.includes('browser_client_anchoring_forbidden'));
  assert.ok(denied.blockedBy.includes('browser_telemetry_boundary_unverified'));
  assert.ok(denied.blockedBy.includes('browser_health_debug_boundary_unverified'));
  assert.ok(denied.blockedBy.includes('browser_telemetry_disclosure'));
});

test('browser trust path reports malformed empty inputs without protected disclosure', async () => {
  const { evaluateBrowserTrustPath } = await loadBrowserTrustPath();

  const empty = evaluateBrowserTrustPath(null);
  assert.equal(empty.allowed, false);
  assert.equal(empty.safeClientManifest.redacted, undefined);
  assert.ok(empty.blockedBy.includes('browser_client_kind_invalid'));
  assert.ok(empty.blockedBy.includes('browser_workflow_action_absent'));
  assert.ok(empty.blockedBy.includes('browser_expected_server_action_hash_invalid'));
  assert.ok(empty.blockedBy.includes('gateway_server_path_unverified'));

  const malformed = evaluateBrowserTrustPath({
    client: { appId: '', kind: 'wasm_browser', releaseId: '', tenantId: '' },
    workflow: {
      action: '',
      expectedServerActionHash: '0000000000000000000000000000000000000000000000000000000000000000',
      involvesPhi: false,
      regulated: false,
    },
    serverTrustPath: {},
    payloadBoundary: {},
    publicConfig: ['public-client-metadata'],
    browserPayload: 'metadata only',
    healthDebugPayload: 7,
    telemetryPayload: ['metadata only', { artifactHash: DIGEST_D }],
    wasm: {
      adapterMode: 'view_only',
      exportedSecretRefs: [],
    },
  });

  assert.equal(malformed.allowed, false);
  assert.deepEqual(malformed.safeClientManifest, {
    appId: 'unclassified',
    clientKind: 'wasm_browser',
    releaseId: 'unreleased',
    tenantId: 'unclassified',
    workflowAction: 'unclassified',
    publicConfig: {
      apiBasePath: null,
      configHash: null,
      runtimeConfigSource: null,
    },
    wasm: {
      adapterMode: 'view_only',
      exportManifestHash: null,
    },
  });
  assert.ok(malformed.blockedBy.includes('browser_app_id_absent'));
  assert.ok(malformed.blockedBy.includes('browser_tenant_absent'));
  assert.ok(malformed.blockedBy.includes('browser_regulated_workflow_absent'));
  assert.ok(malformed.blockedBy.includes('browser_phi_workflow_flag_absent'));
  assert.ok(malformed.blockedBy.includes('browser_metadata_only_boundary_absent'));
});

test('browser trust path redacts health public-config and WASM secret-only failures', async () => {
  const { evaluateBrowserTrustPath } = await loadBrowserTrustPath();

  const healthOnly = evaluateBrowserTrustPath({
    ...verifiedBrowserPathInput(),
    healthDebugPayload: { phone: 'metadata-field-present' },
  });
  assert.equal(healthOnly.allowed, false);
  assert.deepEqual(healthOnly.safeClientManifest, {
    redacted: true,
    reason: 'browser_health_debug_disclosure',
  });

  const configSecretOnly = evaluateBrowserTrustPath({
    ...verifiedBrowserPathInput(),
    publicConfig: {
      apiBasePath: '/api/cybermedica/trust-adapter',
      apiKey: 1,
    },
  });
  assert.equal(configSecretOnly.allowed, false);
  assert.deepEqual(configSecretOnly.safeClientManifest, {
    redacted: true,
    reason: 'browser_secret_material_prohibited',
  });

  const wasmSecretOnly = evaluateBrowserTrustPath({
    ...verifiedBrowserPathInput(),
    publicConfig: null,
    wasm: {
      adapterMode: 'client_request_only',
      exportManifestHash: DIGEST_C,
      exportedSecretRefs: ['signingKey'],
      holdsRootOrSigningSecrets: false,
    },
  });
  assert.equal(wasmSecretOnly.allowed, false);
  assert.deepEqual(wasmSecretOnly.safeClientManifest, {
    redacted: true,
    reason: 'wasm_secret_material_prohibited',
  });
});
