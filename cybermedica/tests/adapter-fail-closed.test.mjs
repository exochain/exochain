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
import {
  evaluateDecisionForumTransitionResponse,
  evaluateGatewayAdjudicationResponse,
  evaluateReceiptCommitmentResponse,
} from '../src/trust-adapter.mjs';

const expectedActionHash = 'a93f20a17b9e93f9cd6335f75d72f06ec7d9897ed8269e6226532323293aa524';

test('receipt adapter fails closed when service is unavailable malformed mismatched or discloses payload', () => {
  assert.deepEqual(evaluateReceiptCommitmentResponse(null, { expectedActionHash }), {
    schema: 'cybermedica.receipt_commitment_response.v1',
    allowed: false,
    state: 'degraded',
    failClosed: true,
    blockedBy: ['receipt_service_unavailable'],
    receiptId: null,
  });

  const missingSignature = evaluateReceiptCommitmentResponse(
    {
      receiptId: 'receipt-alpha',
      actionHash: expectedActionHash,
      signature: '',
      anchorPayload: { artifactHash: expectedActionHash },
    },
    { expectedActionHash },
  );
  assert.equal(missingSignature.allowed, false);
  assert.equal(missingSignature.state, 'denied');
  assert.ok(missingSignature.blockedBy.includes('receipt_signature_absent'));

  const mismatch = evaluateReceiptCommitmentResponse(
    {
      receiptId: 'receipt-alpha',
      actionHash: 'b93f20a17b9e93f9cd6335f75d72f06ec7d9897ed8269e6226532323293aa524',
      signature: 'sig-root-adapter-alpha',
      anchorPayload: { artifactHash: expectedActionHash },
    },
    { expectedActionHash },
  );
  assert.equal(mismatch.allowed, false);
  assert.ok(mismatch.blockedBy.includes('receipt_action_hash_mismatch'));

  const disclosedPayload = evaluateReceiptCommitmentResponse(
    {
      receiptId: 'receipt-alpha',
      actionHash: expectedActionHash,
      signature: 'sig-root-adapter-alpha',
      anchorPayload: { sourceDocumentBody: 'Participant Alice Example consent source document body.' },
    },
    { expectedActionHash },
  );
  assert.equal(disclosedPayload.allowed, false);
  assert.ok(disclosedPayload.blockedBy.includes('receipt_payload_disclosure'));

  const verified = evaluateReceiptCommitmentResponse(
    {
      receiptId: 'receipt-alpha',
      actionHash: expectedActionHash,
      signature: 'sig-root-adapter-alpha',
      receiptSource: 'exochain_node_receipt_store',
      anchorPayload: { artifactHash: expectedActionHash, artifactType: 'qms_control_evidence' },
    },
    { expectedActionHash },
  );
  assert.equal(verified.allowed, true);
  assert.equal(verified.state, 'verified');
  assert.deepEqual(verified.blockedBy, []);
});

test('receipt adapter reports structural receipt defects without requiring protected payload fields', () => {
  const malformed = evaluateReceiptCommitmentResponse(
    {
      receiptId: '',
      actionHash: 'not-a-hash',
      signature: 'sig-root-adapter-alpha',
      anchorPayload: [0, { artifactType: 'qms_control_evidence' }],
    },
    { expectedActionHash: 'not-a-hash' },
  );

  assert.equal(malformed.allowed, false);
  assert.equal(malformed.state, 'denied');
  assert.ok(malformed.blockedBy.includes('receipt_id_absent'));
  assert.ok(malformed.blockedBy.includes('receipt_action_hash_invalid'));
  assert.ok(malformed.blockedBy.includes('expected_action_hash_invalid'));
  assert.equal(malformed.receiptId, null);

  const verifiedWithoutPayload = evaluateReceiptCommitmentResponse(
    {
      receiptId: 'receipt-alpha',
      actionHash: expectedActionHash,
      signature: 'sig-root-adapter-alpha',
      receiptSource: 'exochain_node_receipt_store',
    },
    { expectedActionHash },
  );

  assert.equal(verifiedWithoutPayload.allowed, true);
  assert.equal(verifiedWithoutPayload.state, 'verified');
});

test('receipt adapter fails closed for explicit timeout and non-ok service status', () => {
  const timedOut = evaluateReceiptCommitmentResponse(
    {
      timeout: true,
      receiptId: 'receipt-alpha',
      actionHash: expectedActionHash,
      signature: 'sig-root-adapter-alpha',
      receiptSource: 'exochain_node_receipt_store',
      anchorPayload: { artifactHash: expectedActionHash, artifactType: 'qms_control_evidence' },
    },
    { expectedActionHash },
  );

  assert.equal(timedOut.allowed, false);
  assert.equal(timedOut.state, 'degraded');
  assert.deepEqual(timedOut.blockedBy, ['receipt_timeout']);
  assert.equal(timedOut.receiptId, null);

  const errored = evaluateReceiptCommitmentResponse(
    {
      status: 'error',
      receiptId: 'receipt-alpha',
      actionHash: expectedActionHash,
      signature: 'sig-root-adapter-alpha',
      receiptSource: 'exochain_node_receipt_store',
      anchorPayload: { artifactHash: expectedActionHash, artifactType: 'qms_control_evidence' },
    },
    { expectedActionHash },
  );

  assert.equal(errored.allowed, false);
  assert.equal(errored.state, 'denied');
  assert.ok(errored.blockedBy.includes('receipt_status_unverified'));
  assert.equal(errored.receiptId, 'receipt-alpha');
});

test('receipt adapter denies locally simulated cached or missing node receipt source', () => {
  const missingSource = evaluateReceiptCommitmentResponse(
    {
      receiptId: 'receipt-alpha',
      actionHash: expectedActionHash,
      signature: 'sig-root-adapter-alpha',
      anchorPayload: { artifactHash: expectedActionHash, artifactType: 'qms_control_evidence' },
    },
    { expectedActionHash },
  );

  assert.equal(missingSource.allowed, false);
  assert.equal(missingSource.state, 'denied');
  assert.ok(missingSource.blockedBy.includes('receipt_source_unverified'));

  const localSource = evaluateReceiptCommitmentResponse(
    {
      receiptId: 'receipt-alpha',
      actionHash: expectedActionHash,
      signature: 'sig-root-adapter-alpha',
      receiptSource: 'cybermedica_local_receipt_builder',
      locallySimulated: true,
      cacheHit: true,
      overrideApplied: true,
      anchorPayload: { artifactHash: expectedActionHash, artifactType: 'qms_control_evidence' },
    },
    { expectedActionHash },
  );

  assert.equal(localSource.allowed, false);
  assert.ok(localSource.blockedBy.includes('receipt_source_unverified'));
  assert.ok(localSource.blockedBy.includes('receipt_local_simulation_forbidden'));
  assert.ok(localSource.blockedBy.includes('receipt_cached_outcome_forbidden'));
  assert.ok(localSource.blockedBy.includes('receipt_override_forbidden'));
});

test('receipt adapter rejects protected health debug telemetry and log payloads', () => {
  const observabilityPayload = evaluateReceiptCommitmentResponse(
    {
      receiptId: 'receipt-alpha',
      actionHash: expectedActionHash,
      signature: 'sig-root-adapter-alpha',
      receiptSource: 'exochain_node_receipt_store',
      anchorPayload: { artifactHash: expectedActionHash, artifactType: 'qms_control_evidence' },
      healthPayload: { status: 'ok', medicalRecordNumber: 'MRN: A-123' },
      debugPayload: { participantName: 'Participant Alice Example' },
      telemetryPayload: { email: 'alice@example.test' },
      logPayload: { rawPhi: 'Participant Alice Example source detail' },
    },
    { expectedActionHash },
  );

  assert.equal(observabilityPayload.allowed, false);
  assert.equal(observabilityPayload.state, 'denied');
  assert.ok(observabilityPayload.blockedBy.includes('receipt_observability_payload_disclosure'));
});

test('adapters reject token and key material in observability and adapter payloads', () => {
  const receiptSecretPayload = evaluateReceiptCommitmentResponse(
    {
      receiptId: 'receipt-alpha',
      actionHash: expectedActionHash,
      signature: 'sig-root-adapter-alpha',
      receiptSource: 'exochain_node_receipt_store',
      anchorPayload: { artifactHash: expectedActionHash, artifactType: 'qms_control_evidence' },
      healthPayload: { bootstrapToken: 'redacted-token-placeholder' },
    },
    { expectedActionHash },
  );

  assert.equal(receiptSecretPayload.allowed, false);
  assert.equal(receiptSecretPayload.state, 'denied');
  assert.ok(receiptSecretPayload.blockedBy.includes('receipt_observability_payload_disclosure'));

  const gatewaySecretPayload = evaluateGatewayAdjudicationResponse(
    {
      ...gatewayResponse,
      requestPayload: { apiKey: 'redacted-api-key-placeholder' },
    },
    gatewayOptions,
  );

  assert.equal(gatewaySecretPayload.allowed, false);
  assert.equal(gatewaySecretPayload.state, 'denied');
  assert.ok(gatewaySecretPayload.blockedBy.includes('gateway_payload_disclosure'));

  const decisionForumSecretPayload = evaluateDecisionForumTransitionResponse(
    {
      ...decisionForumResponse,
      debugPayload: { clientSecret: 'redacted-client-secret-placeholder' },
    },
    decisionForumOptions,
  );

  assert.equal(decisionForumSecretPayload.allowed, false);
  assert.equal(decisionForumSecretPayload.state, 'denied');
  assert.ok(decisionForumSecretPayload.blockedBy.includes('decision_forum_observability_payload_disclosure'));
});

test('adapters reject token and key material embedded in generic text payload values', () => {
  const receiptTextSecret = evaluateReceiptCommitmentResponse(
    {
      receiptId: 'receipt-alpha',
      actionHash: expectedActionHash,
      signature: 'sig-root-adapter-alpha',
      receiptSource: 'exochain_node_receipt_store',
      anchorPayload: { artifactHash: expectedActionHash, artifactType: 'qms_control_evidence' },
      receiptPayload: { integrationConfig: 'api_key=redacted-placeholder' },
    },
    { expectedActionHash },
  );

  assert.equal(receiptTextSecret.allowed, false);
  assert.equal(receiptTextSecret.state, 'denied');
  assert.ok(receiptTextSecret.blockedBy.includes('receipt_payload_disclosure'));

  const gatewayTextSecret = evaluateGatewayAdjudicationResponse(
    {
      ...gatewayResponse,
      payload: { upstreamHeader: 'Authorization: Bearer redacted-token-placeholder' },
    },
    gatewayOptions,
  );

  assert.equal(gatewayTextSecret.allowed, false);
  assert.equal(gatewayTextSecret.state, 'denied');
  assert.ok(gatewayTextSecret.blockedBy.includes('gateway_payload_disclosure'));

  const decisionForumTextSecret = evaluateDecisionForumTransitionResponse(
    {
      ...decisionForumResponse,
      rationalePayload: { runtimeSetting: 'client_secret=redacted-placeholder' },
    },
    decisionForumOptions,
  );

  assert.equal(decisionForumTextSecret.allowed, false);
  assert.equal(decisionForumTextSecret.state, 'denied');
  assert.ok(decisionForumTextSecret.blockedBy.includes('decision_forum_payload_disclosure'));
});

test('adapters reject semantic protected and secret field variants inside payloads', () => {
  const receiptPrivilegedVariant = evaluateReceiptCommitmentResponse(
    {
      receiptId: 'receipt-alpha',
      actionHash: expectedActionHash,
      signature: 'sig-root-adapter-alpha',
      receiptSource: 'exochain_node_receipt_store',
      anchorPayload: { artifactHash: expectedActionHash, artifactType: 'qms_control_evidence' },
      receiptPayload: { privilegedContent: 'counsel review narrative must remain referenced only' },
    },
    { expectedActionHash },
  );

  assert.equal(receiptPrivilegedVariant.allowed, false);
  assert.equal(receiptPrivilegedVariant.state, 'denied');
  assert.ok(receiptPrivilegedVariant.blockedBy.includes('receipt_payload_disclosure'));

  const gatewaySponsorVariant = evaluateGatewayAdjudicationResponse(
    {
      ...gatewayResponse,
      requestPayload: { sponsorConfidentialNotes: 'commercial sponsor review narrative' },
      debugPayload: { clientSecretValue: 'redacted-client-secret-placeholder' },
    },
    gatewayOptions,
  );

  assert.equal(gatewaySponsorVariant.allowed, false);
  assert.equal(gatewaySponsorVariant.state, 'denied');
  assert.ok(gatewaySponsorVariant.blockedBy.includes('gateway_payload_disclosure'));
  assert.ok(gatewaySponsorVariant.blockedBy.includes('gateway_observability_payload_disclosure'));

  const decisionForumRawPiiVariant = evaluateDecisionForumTransitionResponse(
    {
      ...decisionForumResponse,
      votePayload: { rawPiiAttachment: { digest: expectedActionHash } },
    },
    decisionForumOptions,
  );

  assert.equal(decisionForumRawPiiVariant.allowed, false);
  assert.equal(decisionForumRawPiiVariant.state, 'denied');
  assert.ok(decisionForumRawPiiVariant.blockedBy.includes('decision_forum_payload_disclosure'));
});

test('adapters reject source document and clinical note field variants inside payloads', () => {
  const receiptSourceDocumentText = evaluateReceiptCommitmentResponse(
    {
      receiptId: 'receipt-alpha',
      actionHash: expectedActionHash,
      signature: 'sig-root-adapter-alpha',
      receiptSource: 'exochain_node_receipt_store',
      anchorPayload: { artifactHash: expectedActionHash, artifactType: 'qms_control_evidence' },
      receiptPayload: { sourceDocumentText: 'source excerpt without direct participant identifiers' },
    },
    { expectedActionHash },
  );

  assert.equal(receiptSourceDocumentText.allowed, false);
  assert.equal(receiptSourceDocumentText.state, 'denied');
  assert.ok(receiptSourceDocumentText.blockedBy.includes('receipt_payload_disclosure'));

  const gatewaySourceDocumentContent = evaluateGatewayAdjudicationResponse(
    {
      ...gatewayResponse,
      requestPayload: { sourceDocumentContent: 'monitoring source excerpt without direct identifiers' },
    },
    gatewayOptions,
  );

  assert.equal(gatewaySourceDocumentContent.allowed, false);
  assert.equal(gatewaySourceDocumentContent.state, 'denied');
  assert.ok(gatewaySourceDocumentContent.blockedBy.includes('gateway_payload_disclosure'));

  const decisionForumClinicalNote = evaluateDecisionForumTransitionResponse(
    {
      ...decisionForumResponse,
      evidencePayload: { clinicalNote: 'clinical observation text without direct identifiers' },
    },
    decisionForumOptions,
  );

  assert.equal(decisionForumClinicalNote.allowed, false);
  assert.equal(decisionForumClinicalNote.state, 'denied');
  assert.ok(decisionForumClinicalNote.blockedBy.includes('decision_forum_payload_disclosure'));
});

test('receipt adapter rejects protected receipt body and DAG payloads', () => {
  const protectedReceiptPayload = evaluateReceiptCommitmentResponse(
    {
      receiptId: 'receipt-alpha',
      actionHash: expectedActionHash,
      signature: 'sig-root-adapter-alpha',
      receiptSource: 'exochain_node_receipt_store',
      anchorPayload: { artifactHash: expectedActionHash, artifactType: 'qms_control_evidence' },
      receiptPayload: { sourceDocumentBody: 'Participant Alice Example consent source document body.' },
    },
    { expectedActionHash },
  );

  assert.equal(protectedReceiptPayload.allowed, false);
  assert.equal(protectedReceiptPayload.state, 'denied');
  assert.ok(protectedReceiptPayload.blockedBy.includes('receipt_payload_disclosure'));

  const protectedDagPayload = evaluateReceiptCommitmentResponse(
    {
      receiptId: 'receipt-alpha',
      actionHash: expectedActionHash,
      signature: 'sig-root-adapter-alpha',
      receiptSource: 'exochain_node_receipt_store',
      anchorPayload: { artifactHash: expectedActionHash, artifactType: 'qms_control_evidence' },
      dagPayload: { privilegedLegalMaterial: 'Internal counsel review notes.' },
    },
    { expectedActionHash },
  );

  assert.equal(protectedDagPayload.allowed, false);
  assert.equal(protectedDagPayload.state, 'denied');
  assert.ok(protectedDagPayload.blockedBy.includes('receipt_payload_disclosure'));
});

test('receipt adapter rejects unscoped protected or secret material on the response object', () => {
  const topLevelProtectedField = evaluateReceiptCommitmentResponse(
    {
      receiptId: 'receipt-alpha',
      actionHash: expectedActionHash,
      signature: 'sig-root-adapter-alpha',
      receiptSource: 'exochain_node_receipt_store',
      rawPhi: 'Participant Alice Example MRN: A-123',
    },
    { expectedActionHash },
  );

  assert.equal(topLevelProtectedField.allowed, false);
  assert.equal(topLevelProtectedField.state, 'denied');
  assert.ok(topLevelProtectedField.blockedBy.includes('receipt_response_payload_disclosure'));

  const topLevelSecretField = evaluateReceiptCommitmentResponse(
    {
      receiptId: 'receipt-alpha',
      actionHash: expectedActionHash,
      signature: 'sig-root-adapter-alpha',
      receiptSource: 'exochain_node_receipt_store',
      apiKey: 'redacted-api-key-placeholder',
    },
    { expectedActionHash },
  );

  assert.equal(topLevelSecretField.allowed, false);
  assert.equal(topLevelSecretField.state, 'denied');
  assert.ok(topLevelSecretField.blockedBy.includes('receipt_response_payload_disclosure'));
});

const gatewayResponse = Object.freeze({
  status: 'ok',
  enforcementSource: 'exochain_gateway',
  decision: 'permitted',
  action: 'protocol_launch',
  actorDid: 'did:exo:principal-investigator-alpha',
  tenantId: 'tenant-site-alpha',
  auth: { verified: true, status: 'verified' },
  consent: { verified: true, status: 'active' },
  authority: { verified: true, status: 'valid' },
  quorum: { verified: true, status: 'met' },
  invariants: { verified: true, status: 'passed' },
  provenance: {
    receiptId: 'receipt-protocol-launch-alpha',
    actionHash: expectedActionHash,
    signature: 'sig-gateway-alpha',
    receiptSource: 'exochain_node_receipt_store',
    anchorPayload: { artifactHash: expectedActionHash, artifactType: 'protocol_launch_gate' },
  },
});

const gatewayOptions = Object.freeze({
  expectedAction: 'protocol_launch',
  expectedActorDid: 'did:exo:principal-investigator-alpha',
  expectedTenantId: 'tenant-site-alpha',
  expectedActionHash,
  requiresConsent: true,
  requiresQuorum: true,
});

test('gateway adjudication adapter fails closed for unavailable timeout rejected or unverifiable decisions', () => {
  assert.deepEqual(evaluateGatewayAdjudicationResponse(null, gatewayOptions), {
    schema: 'cybermedica.gateway_adjudication_response.v1',
    allowed: false,
    state: 'degraded',
    failClosed: true,
    blockedBy: ['gateway_service_unavailable'],
    decision: null,
    receiptId: null,
  });

  const timedOut = evaluateGatewayAdjudicationResponse({ status: 'timeout' }, gatewayOptions);
  assert.equal(timedOut.allowed, false);
  assert.equal(timedOut.state, 'degraded');
  assert.deepEqual(timedOut.blockedBy, ['gateway_timeout']);

  const rejected = evaluateGatewayAdjudicationResponse(
    {
      ...gatewayResponse,
      decision: 'denied',
      auth: { verified: false, status: 'rejected' },
      consent: { verified: false, status: 'revoked' },
      authority: { verified: false, status: 'revoked' },
      quorum: { verified: false, status: 'not_met' },
      invariants: { verified: false, status: 'failed' },
      provenance: null,
    },
    gatewayOptions,
  );

  assert.equal(rejected.allowed, false);
  assert.equal(rejected.state, 'denied');
  assert.ok(rejected.blockedBy.includes('gateway_decision_not_permitted'));
  assert.ok(rejected.blockedBy.includes('did_auth_unverified'));
  assert.ok(rejected.blockedBy.includes('consent_unverified'));
  assert.ok(rejected.blockedBy.includes('authority_chain_unverified'));
  assert.ok(rejected.blockedBy.includes('quorum_unverified'));
  assert.ok(rejected.blockedBy.includes('invariants_unverified'));
  assert.ok(rejected.blockedBy.includes('gateway_receipt_absent'));
});

test('gateway adjudication adapter verifies action tenant actor receipt hash and protected-content boundary', () => {
  const mismatch = evaluateGatewayAdjudicationResponse(
    {
      ...gatewayResponse,
      tenantId: 'tenant-site-beta',
      action: 'support_access',
      actorDid: 'did:exo:wrong-actor',
      provenance: {
        ...gatewayResponse.provenance,
        actionHash: 'b93f20a17b9e93f9cd6335f75d72f06ec7d9897ed8269e6226532323293aa524',
      },
    },
    gatewayOptions,
  );

  assert.equal(mismatch.allowed, false);
  assert.ok(mismatch.blockedBy.includes('gateway_tenant_mismatch'));
  assert.ok(mismatch.blockedBy.includes('gateway_action_mismatch'));
  assert.ok(mismatch.blockedBy.includes('gateway_actor_mismatch'));
  assert.ok(mismatch.blockedBy.includes('gateway_receipt_action_hash_mismatch'));

  const disclosedPayload = evaluateGatewayAdjudicationResponse(
    {
      ...gatewayResponse,
      provenance: {
        ...gatewayResponse.provenance,
        anchorPayload: { rawPhi: 'Participant Alice Example MRN: A-123' },
      },
    },
    gatewayOptions,
  );

  assert.equal(disclosedPayload.allowed, false);
  assert.ok(disclosedPayload.blockedBy.includes('gateway_payload_disclosure'));

  const verified = evaluateGatewayAdjudicationResponse(gatewayResponse, gatewayOptions);
  assert.equal(verified.allowed, true);
  assert.equal(verified.state, 'verified');
  assert.deepEqual(verified.blockedBy, []);
  assert.equal(verified.decision, 'permitted');
  assert.equal(verified.receiptId, 'receipt-protocol-launch-alpha');
});

test('gateway adjudication adapter denies missing cached or locally simulated enforcement source', () => {
  const missingSource = evaluateGatewayAdjudicationResponse(
    {
      ...gatewayResponse,
      enforcementSource: undefined,
      provenance: { ...gatewayResponse.provenance, receiptSource: undefined },
    },
    gatewayOptions,
  );

  assert.equal(missingSource.allowed, false);
  assert.equal(missingSource.state, 'denied');
  assert.ok(missingSource.blockedBy.includes('gateway_enforcement_source_unverified'));
  assert.ok(missingSource.blockedBy.includes('gateway_receipt_source_unverified'));

  const localSource = evaluateGatewayAdjudicationResponse(
    {
      ...gatewayResponse,
      enforcementSource: 'cybermedica_local_decision_builder',
      locallySimulated: true,
      cacheHit: true,
      overrideApplied: true,
      provenance: {
        ...gatewayResponse.provenance,
        receiptSource: 'cybermedica_local_receipt_builder',
      },
    },
    gatewayOptions,
  );

  assert.equal(localSource.allowed, false);
  assert.ok(localSource.blockedBy.includes('gateway_enforcement_source_unverified'));
  assert.ok(localSource.blockedBy.includes('gateway_local_simulation_forbidden'));
  assert.ok(localSource.blockedBy.includes('gateway_cached_outcome_forbidden'));
  assert.ok(localSource.blockedBy.includes('gateway_override_forbidden'));
  assert.ok(localSource.blockedBy.includes('gateway_receipt_source_unverified'));
});

test('gateway adjudication adapter rejects locally simulated cached or override dependency proofs', () => {
  const replayedDependencies = evaluateGatewayAdjudicationResponse(
    {
      ...gatewayResponse,
      auth: { verified: true, status: 'verified', cachedOutcome: true },
      consent: { verified: true, status: 'active', locallySimulated: true },
      authority: { verified: true, status: 'valid', cacheHit: true },
      quorum: { verified: true, status: 'met', overrideUsed: true },
      invariants: { verified: true, status: 'passed', overrideApplied: true },
    },
    gatewayOptions,
  );

  assert.equal(replayedDependencies.allowed, false);
  assert.equal(replayedDependencies.state, 'denied');
  assert.ok(replayedDependencies.blockedBy.includes('did_auth_cached_outcome_forbidden'));
  assert.ok(replayedDependencies.blockedBy.includes('consent_local_simulation_forbidden'));
  assert.ok(replayedDependencies.blockedBy.includes('authority_cached_outcome_forbidden'));
  assert.ok(replayedDependencies.blockedBy.includes('quorum_override_forbidden'));
  assert.ok(replayedDependencies.blockedBy.includes('invariants_override_forbidden'));
});

test('gateway adjudication adapter rejects protected or secret material inside dependency proofs', () => {
  const dependencyPayloads = evaluateGatewayAdjudicationResponse(
    {
      ...gatewayResponse,
      auth: { verified: true, status: 'verified', providerPayload: { authorizationHeader: 'Bearer redacted-token' } },
      consent: { verified: true, status: 'active', evidencePayload: { participantName: 'Participant Alice Example' } },
      authority: { verified: true, status: 'valid', proofPayload: { signingKey: 'redacted-signing-key' } },
      quorum: { verified: true, status: 'met', votePayload: { rawPhi: 'Participant Alice Example MRN: A-123' } },
      invariants: { verified: true, status: 'passed', debugPayload: { clientSecret: 'redacted-client-secret' } },
    },
    gatewayOptions,
  );

  assert.equal(dependencyPayloads.allowed, false);
  assert.equal(dependencyPayloads.state, 'denied');
  assert.ok(dependencyPayloads.blockedBy.includes('did_auth_dependency_payload_disclosure'));
  assert.ok(dependencyPayloads.blockedBy.includes('consent_dependency_payload_disclosure'));
  assert.ok(dependencyPayloads.blockedBy.includes('authority_dependency_payload_disclosure'));
  assert.ok(dependencyPayloads.blockedBy.includes('quorum_dependency_payload_disclosure'));
  assert.ok(dependencyPayloads.blockedBy.includes('invariants_dependency_payload_disclosure'));
});

test('gateway adjudication adapter reports malformed receipt fields and boolean timeout signals', () => {
  const timedOut = evaluateGatewayAdjudicationResponse({ timeout: true, decision: 'permitted' }, gatewayOptions);
  assert.equal(timedOut.allowed, false);
  assert.equal(timedOut.state, 'degraded');
  assert.equal(timedOut.decision, 'permitted');
  assert.deepEqual(timedOut.blockedBy, ['gateway_timeout']);

  const malformedReceipt = evaluateGatewayAdjudicationResponse(
    {
      ...gatewayResponse,
      provenance: {
        receiptId: '',
        actionHash: 'not-a-hash',
        signature: '',
        anchorPayload: [0, { artifactType: 'protocol_launch_gate' }],
      },
    },
    { ...gatewayOptions, expectedActionHash: 'not-a-hash' },
  );

  assert.equal(malformedReceipt.allowed, false);
  assert.equal(malformedReceipt.state, 'denied');
  assert.ok(malformedReceipt.blockedBy.includes('gateway_receipt_id_absent'));
  assert.ok(malformedReceipt.blockedBy.includes('gateway_receipt_action_hash_invalid'));
  assert.ok(malformedReceipt.blockedBy.includes('expected_action_hash_invalid'));
  assert.ok(malformedReceipt.blockedBy.includes('gateway_receipt_signature_absent'));
  assert.equal(malformedReceipt.receiptId, null);
});

test('gateway adjudication adapter rejects timed out or non-ok nested receipt provenance', () => {
  const timedOutReceipt = evaluateGatewayAdjudicationResponse(
    {
      ...gatewayResponse,
      provenance: {
        ...gatewayResponse.provenance,
        timeout: true,
      },
    },
    gatewayOptions,
  );

  assert.equal(timedOutReceipt.allowed, false);
  assert.equal(timedOutReceipt.state, 'denied');
  assert.ok(timedOutReceipt.blockedBy.includes('gateway_receipt_timeout'));

  const erroredReceipt = evaluateGatewayAdjudicationResponse(
    {
      ...gatewayResponse,
      provenance: {
        ...gatewayResponse.provenance,
        status: 'error',
      },
    },
    gatewayOptions,
  );

  assert.equal(erroredReceipt.allowed, false);
  assert.equal(erroredReceipt.state, 'denied');
  assert.ok(erroredReceipt.blockedBy.includes('gateway_receipt_status_unverified'));
});

test('gateway adjudication adapter rejects protected health debug telemetry and log payloads', () => {
  const observabilityPayload = evaluateGatewayAdjudicationResponse(
    {
      ...gatewayResponse,
      healthPayload: { status: 'ok', medicalRecordNumber: 'MRN: A-123' },
      debugPayload: { participantName: 'Participant Alice Example' },
      telemetryPayload: { email: 'alice@example.test' },
      logPayload: { rawPhi: 'Participant Alice Example source detail' },
    },
    gatewayOptions,
  );

  assert.equal(observabilityPayload.allowed, false);
  assert.equal(observabilityPayload.state, 'denied');
  assert.ok(observabilityPayload.blockedBy.includes('gateway_observability_payload_disclosure'));
});

test('gateway adjudication adapter rejects protected request and adjudication payloads', () => {
  const protectedRequestPayload = evaluateGatewayAdjudicationResponse(
    {
      ...gatewayResponse,
      requestPayload: { sourceDocumentBody: 'Participant Alice Example protocol source document body.' },
    },
    gatewayOptions,
  );

  assert.equal(protectedRequestPayload.allowed, false);
  assert.equal(protectedRequestPayload.state, 'denied');
  assert.ok(protectedRequestPayload.blockedBy.includes('gateway_payload_disclosure'));

  const protectedAdjudicationPayload = evaluateGatewayAdjudicationResponse(
    {
      ...gatewayResponse,
      adjudicationPayload: { sponsorConfidential: 'Protocol exception narrative for participant cohort.' },
    },
    gatewayOptions,
  );

  assert.equal(protectedAdjudicationPayload.allowed, false);
  assert.equal(protectedAdjudicationPayload.state, 'denied');
  assert.ok(protectedAdjudicationPayload.blockedBy.includes('gateway_payload_disclosure'));
});

test('gateway adjudication adapter rejects unscoped protected or secret material on the response object', () => {
  const topLevelProtectedField = evaluateGatewayAdjudicationResponse(
    {
      ...gatewayResponse,
      participantName: 'Participant Alice Example',
    },
    gatewayOptions,
  );

  assert.equal(topLevelProtectedField.allowed, false);
  assert.equal(topLevelProtectedField.state, 'denied');
  assert.ok(topLevelProtectedField.blockedBy.includes('gateway_response_payload_disclosure'));

  const topLevelSecretField = evaluateGatewayAdjudicationResponse(
    {
      ...gatewayResponse,
      apiKey: 'redacted-api-key-placeholder',
    },
    gatewayOptions,
  );

  assert.equal(topLevelSecretField.allowed, false);
  assert.equal(topLevelSecretField.state, 'denied');
  assert.ok(topLevelSecretField.blockedBy.includes('gateway_response_payload_disclosure'));
});

const decisionHash = '7b3f20a17b9e93f9cd6335f75d72f06ec7d9897ed8269e6226532323293aa524';

const decisionForumResponse = Object.freeze({
  status: 'ok',
  enforcementSource: 'exochain_decision_forum',
  decisionId: 'df-protocol-launch-alpha',
  decisionState: 'approved',
  transitionPath: 'adjudicated',
  action: 'protocol_launch',
  actorDid: 'did:exo:principal-investigator-alpha',
  actorKind: 'human',
  tenantId: 'tenant-site-alpha',
  humanGate: { verified: true, status: 'verified', actorKind: 'human' },
  quorum: { verified: true, status: 'met' },
  tnc: { verified: true, status: 'passed' },
  authority: { verified: true, status: 'valid' },
  kernelVerdict: { verified: true, status: 'permitted' },
  invariants: { verified: true, status: 'passed' },
  openChallenge: false,
  provenance: {
    receiptId: 'df-receipt-protocol-launch-alpha',
    decisionHash,
    signature: 'sig-decision-forum-alpha',
    receiptSource: 'exochain_decision_forum_receipts',
    anchorPayload: { artifactHash: decisionHash, artifactType: 'decision_forum_transition' },
  },
});

const decisionForumOptions = Object.freeze({
  expectedDecisionId: 'df-protocol-launch-alpha',
  expectedAction: 'protocol_launch',
  expectedActorDid: 'did:exo:principal-investigator-alpha',
  expectedTenantId: 'tenant-site-alpha',
  expectedDecisionHash: decisionHash,
});

test('Decision Forum adapter fails closed for unavailable timeout raw or non-human transitions', () => {
  assert.deepEqual(evaluateDecisionForumTransitionResponse(null, decisionForumOptions), {
    schema: 'cybermedica.decision_forum_transition_response.v1',
    allowed: false,
    state: 'degraded',
    failClosed: true,
    blockedBy: ['decision_forum_service_unavailable'],
    decisionId: null,
    receiptId: null,
  });

  const timedOut = evaluateDecisionForumTransitionResponse({ status: 'timeout' }, decisionForumOptions);
  assert.equal(timedOut.allowed, false);
  assert.equal(timedOut.state, 'degraded');
  assert.deepEqual(timedOut.blockedBy, ['decision_forum_timeout']);

  const rawTransition = evaluateDecisionForumTransitionResponse(
    {
      ...decisionForumResponse,
      transitionPath: 'raw',
      kernelVerdict: null,
      invariants: null,
    },
    decisionForumOptions,
  );
  assert.equal(rawTransition.allowed, false);
  assert.equal(rawTransition.state, 'denied');
  assert.ok(rawTransition.blockedBy.includes('decision_forum_raw_transition_forbidden'));
  assert.ok(rawTransition.blockedBy.includes('kernel_verdict_unverified'));
  assert.ok(rawTransition.blockedBy.includes('invariants_unverified'));

  const aiFinalAuthority = evaluateDecisionForumTransitionResponse(
    {
      ...decisionForumResponse,
      actorDid: 'did:exo:ai-quality-reviewer-alpha',
      actorKind: 'ai_agent',
      humanGate: { verified: true, status: 'verified', actorKind: 'ai_agent' },
    },
    { ...decisionForumOptions, expectedActorDid: 'did:exo:ai-quality-reviewer-alpha' },
  );
  assert.equal(aiFinalAuthority.allowed, false);
  assert.ok(aiFinalAuthority.blockedBy.includes('ai_final_authority_forbidden'));
});

test('Decision Forum adapter verifies adjudicated human quorum TNC receipt and privacy boundaries', () => {
  const challenged = evaluateDecisionForumTransitionResponse(
    {
      ...decisionForumResponse,
      decisionState: 'approved',
      openChallenge: true,
      quorum: { verified: false, status: 'not_met' },
      tnc: { verified: false, status: 'failed' },
    },
    decisionForumOptions,
  );
  assert.equal(challenged.allowed, false);
  assert.ok(challenged.blockedBy.includes('decision_forum_open_challenge'));
  assert.ok(challenged.blockedBy.includes('quorum_unverified'));
  assert.ok(challenged.blockedBy.includes('tnc_unverified'));

  const mismatched = evaluateDecisionForumTransitionResponse(
    {
      ...decisionForumResponse,
      tenantId: 'tenant-site-beta',
      action: 'enrollment_gate',
      provenance: {
        ...decisionForumResponse.provenance,
        decisionHash: '8b3f20a17b9e93f9cd6335f75d72f06ec7d9897ed8269e6226532323293aa524',
      },
    },
    decisionForumOptions,
  );
  assert.equal(mismatched.allowed, false);
  assert.ok(mismatched.blockedBy.includes('decision_forum_tenant_mismatch'));
  assert.ok(mismatched.blockedBy.includes('decision_forum_action_mismatch'));
  assert.ok(mismatched.blockedBy.includes('decision_forum_receipt_hash_mismatch'));

  const disclosedPayload = evaluateDecisionForumTransitionResponse(
    {
      ...decisionForumResponse,
      transitionPayload: { sourceDocumentBody: 'Participant Alice Example MRN: A-123' },
    },
    decisionForumOptions,
  );
  assert.equal(disclosedPayload.allowed, false);
  assert.ok(disclosedPayload.blockedBy.includes('decision_forum_payload_disclosure'));

  const verified = evaluateDecisionForumTransitionResponse(decisionForumResponse, decisionForumOptions);
  assert.equal(verified.allowed, true);
  assert.equal(verified.state, 'verified');
  assert.deepEqual(verified.blockedBy, []);
  assert.equal(verified.decisionId, 'df-protocol-launch-alpha');
  assert.equal(verified.receiptId, 'df-receipt-protocol-launch-alpha');
});

test('Decision Forum adapter denies missing cached or locally simulated adjudication source', () => {
  const missingSource = evaluateDecisionForumTransitionResponse(
    {
      ...decisionForumResponse,
      enforcementSource: undefined,
      provenance: { ...decisionForumResponse.provenance, receiptSource: undefined },
    },
    decisionForumOptions,
  );

  assert.equal(missingSource.allowed, false);
  assert.equal(missingSource.state, 'denied');
  assert.ok(missingSource.blockedBy.includes('decision_forum_enforcement_source_unverified'));
  assert.ok(missingSource.blockedBy.includes('decision_forum_receipt_source_unverified'));

  const localSource = evaluateDecisionForumTransitionResponse(
    {
      ...decisionForumResponse,
      enforcementSource: 'cybermedica_local_decision_builder',
      locallySimulated: true,
      cacheHit: true,
      overrideApplied: true,
      provenance: {
        ...decisionForumResponse.provenance,
        receiptSource: 'cybermedica_local_receipt_builder',
      },
    },
    decisionForumOptions,
  );

  assert.equal(localSource.allowed, false);
  assert.ok(localSource.blockedBy.includes('decision_forum_enforcement_source_unverified'));
  assert.ok(localSource.blockedBy.includes('decision_forum_local_simulation_forbidden'));
  assert.ok(localSource.blockedBy.includes('decision_forum_cached_outcome_forbidden'));
  assert.ok(localSource.blockedBy.includes('decision_forum_override_forbidden'));
  assert.ok(localSource.blockedBy.includes('decision_forum_receipt_source_unverified'));
});

test('Decision Forum adapter rejects locally simulated cached or override dependency proofs', () => {
  const replayedDependencies = evaluateDecisionForumTransitionResponse(
    {
      ...decisionForumResponse,
      humanGate: { verified: true, status: 'verified', actorKind: 'human', locallySimulated: true },
      quorum: { verified: true, status: 'met', cachedOutcome: true },
      tnc: { verified: true, status: 'passed', cacheHit: true },
      authority: { verified: true, status: 'valid', simulated: true },
      kernelVerdict: { verified: true, status: 'permitted', overrideApplied: true },
      invariants: { verified: true, status: 'passed', overrideUsed: true },
    },
    decisionForumOptions,
  );

  assert.equal(replayedDependencies.allowed, false);
  assert.equal(replayedDependencies.state, 'denied');
  assert.ok(replayedDependencies.blockedBy.includes('human_gate_local_simulation_forbidden'));
  assert.ok(replayedDependencies.blockedBy.includes('quorum_cached_outcome_forbidden'));
  assert.ok(replayedDependencies.blockedBy.includes('tnc_cached_outcome_forbidden'));
  assert.ok(replayedDependencies.blockedBy.includes('authority_local_simulation_forbidden'));
  assert.ok(replayedDependencies.blockedBy.includes('kernel_verdict_override_forbidden'));
  assert.ok(replayedDependencies.blockedBy.includes('invariants_override_forbidden'));
});

test('Decision Forum adapter rejects protected or secret material inside dependency proofs', () => {
  const dependencyPayloads = evaluateDecisionForumTransitionResponse(
    {
      ...decisionForumResponse,
      humanGate: {
        verified: true,
        status: 'verified',
        actorKind: 'human',
        proofPayload: { accessToken: 'redacted-access-token' },
      },
      quorum: { verified: true, status: 'met', votePayload: { sponsorConfidential: 'Sponsor-only vote note.' } },
      tnc: { verified: true, status: 'passed', evidencePayload: { rawPii: 'Participant Alice Example' } },
      authority: { verified: true, status: 'valid', chainPayload: { privateKey: 'redacted-private-key' } },
      consent: { verified: true, status: 'active', attestationPayload: { dateOfBirth: '1970-01-01' } },
      kernelVerdict: { verified: true, status: 'permitted', debugPayload: { apiKey: 'redacted-api-key' } },
      invariants: { verified: true, status: 'passed', tracePayload: { sourceDocumentBody: 'Participant notes.' } },
    },
    { ...decisionForumOptions, requiresConsent: true },
  );

  assert.equal(dependencyPayloads.allowed, false);
  assert.equal(dependencyPayloads.state, 'denied');
  assert.ok(dependencyPayloads.blockedBy.includes('human_gate_dependency_payload_disclosure'));
  assert.ok(dependencyPayloads.blockedBy.includes('quorum_dependency_payload_disclosure'));
  assert.ok(dependencyPayloads.blockedBy.includes('tnc_dependency_payload_disclosure'));
  assert.ok(dependencyPayloads.blockedBy.includes('authority_dependency_payload_disclosure'));
  assert.ok(dependencyPayloads.blockedBy.includes('consent_dependency_payload_disclosure'));
  assert.ok(dependencyPayloads.blockedBy.includes('kernel_verdict_dependency_payload_disclosure'));
  assert.ok(dependencyPayloads.blockedBy.includes('invariants_dependency_payload_disclosure'));
});

test('Decision Forum adapter rejects timed out or non-ok nested receipt provenance', () => {
  const timedOutReceipt = evaluateDecisionForumTransitionResponse(
    {
      ...decisionForumResponse,
      provenance: {
        ...decisionForumResponse.provenance,
        timeout: true,
      },
    },
    decisionForumOptions,
  );

  assert.equal(timedOutReceipt.allowed, false);
  assert.equal(timedOutReceipt.state, 'denied');
  assert.ok(timedOutReceipt.blockedBy.includes('decision_forum_receipt_timeout'));

  const erroredReceipt = evaluateDecisionForumTransitionResponse(
    {
      ...decisionForumResponse,
      provenance: {
        ...decisionForumResponse.provenance,
        status: 'error',
      },
    },
    decisionForumOptions,
  );

  assert.equal(erroredReceipt.allowed, false);
  assert.equal(erroredReceipt.state, 'denied');
  assert.ok(erroredReceipt.blockedBy.includes('decision_forum_receipt_status_unverified'));
});

test('Decision Forum adapter rejects protected health debug telemetry and log payloads', () => {
  const observabilityPayload = evaluateDecisionForumTransitionResponse(
    {
      ...decisionForumResponse,
      healthPayload: { status: 'ok', medicalRecordNumber: 'MRN: A-123' },
      debugPayload: { participantName: 'Participant Alice Example' },
      telemetryPayload: { email: 'alice@example.test' },
      logPayload: { rawPhi: 'Participant Alice Example source detail' },
    },
    decisionForumOptions,
  );

  assert.equal(observabilityPayload.allowed, false);
  assert.equal(observabilityPayload.state, 'denied');
  assert.ok(observabilityPayload.blockedBy.includes('decision_forum_observability_payload_disclosure'));
});

test('Decision Forum adapter rejects protected decision provenance receipt and vote payloads', () => {
  const protectedDecisionPayload = evaluateDecisionForumTransitionResponse(
    {
      ...decisionForumResponse,
      decisionPayload: { sponsorConfidential: 'Protocol exception narrative for sponsor review.' },
    },
    decisionForumOptions,
  );

  assert.equal(protectedDecisionPayload.allowed, false);
  assert.equal(protectedDecisionPayload.state, 'denied');
  assert.ok(protectedDecisionPayload.blockedBy.includes('decision_forum_payload_disclosure'));

  const protectedProvenancePayload = evaluateDecisionForumTransitionResponse(
    {
      ...decisionForumResponse,
      provenancePayload: { sourceDocumentBody: 'Participant Alice Example decision source document body.' },
    },
    decisionForumOptions,
  );

  assert.equal(protectedProvenancePayload.allowed, false);
  assert.equal(protectedProvenancePayload.state, 'denied');
  assert.ok(protectedProvenancePayload.blockedBy.includes('decision_forum_payload_disclosure'));

  const protectedReceiptPayload = evaluateDecisionForumTransitionResponse(
    {
      ...decisionForumResponse,
      receiptPayload: { privilegedLegalMaterial: 'Internal counsel review notes.' },
    },
    decisionForumOptions,
  );

  assert.equal(protectedReceiptPayload.allowed, false);
  assert.equal(protectedReceiptPayload.state, 'denied');
  assert.ok(protectedReceiptPayload.blockedBy.includes('decision_forum_payload_disclosure'));

  const protectedVotePayload = evaluateDecisionForumTransitionResponse(
    {
      ...decisionForumResponse,
      votePayload: { rawPhi: 'Participant Alice Example MRN: A-123' },
    },
    decisionForumOptions,
  );

  assert.equal(protectedVotePayload.allowed, false);
  assert.equal(protectedVotePayload.state, 'denied');
  assert.ok(protectedVotePayload.blockedBy.includes('decision_forum_payload_disclosure'));
});

test('Decision Forum adapter rejects unscoped protected or secret material on the response object', () => {
  const topLevelProtectedField = evaluateDecisionForumTransitionResponse(
    {
      ...decisionForumResponse,
      rawPhi: 'Participant Alice Example MRN: A-123',
    },
    decisionForumOptions,
  );

  assert.equal(topLevelProtectedField.allowed, false);
  assert.equal(topLevelProtectedField.state, 'denied');
  assert.ok(topLevelProtectedField.blockedBy.includes('decision_forum_response_payload_disclosure'));

  const topLevelSecretField = evaluateDecisionForumTransitionResponse(
    {
      ...decisionForumResponse,
      clientSecret: 'redacted-client-secret-placeholder',
    },
    decisionForumOptions,
  );

  assert.equal(topLevelSecretField.allowed, false);
  assert.equal(topLevelSecretField.state, 'denied');
  assert.ok(topLevelSecretField.blockedBy.includes('decision_forum_response_payload_disclosure'));
});
