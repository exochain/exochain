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

const DIGEST_A = '3d6f0a96f7c972d4f5b66a1c6b5177fe5a32cc0cbd27f7c67be4c11a4f7ce70a';
const DIGEST_B = '8cf4dfd546b712c3b21f0d61fd7c6b744dfc6d9c7d0c8758fb6c6db6e782a7f3';
const DIGEST_C = '54f6e9e53f0e6d9a6ce64b2d67b79d44a927f276e8916d34a2d3b942f575f1b7';
const DIGEST_D = 'd9470f1f6f89a8836e46c21ffcf84f544f8b70a54156f8380dfd5bdf8c5f9693';
const DIGEST_E = 'f50b82f55e509c9fb872d064d8e513ba60b74a5925c16f70b96c41d727fcb2cc';
const DIGEST_F = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_G = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

async function loadAiProviderAbstraction() {
  try {
    return await import('../src/ai-provider-abstraction.mjs');
  } catch (error) {
    assert.fail(`CyberMedica AI provider abstraction module must exist and load: ${error.message}`);
  }
}

function providerInput(overrides = {}) {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['ai_provider_boundary_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    providerConfig: {
      providerRef: 'ai-provider-cm-controlled-alpha',
      providerKind: 'external_llm',
      bindingStatus: 'verified',
      endpointMode: 'server_side',
      modelRefHash: DIGEST_G,
      modelVersionHash: DIGEST_A,
      modelConfigurationHash: DIGEST_B,
      configuredByHuman: true,
      noBrowserRuntime: true,
      noRootSecrets: true,
      noSharedExochainCredentials: true,
      credentialVaultRefHash: DIGEST_B,
      contractHash: DIGEST_C,
      dataProcessingAgreementHash: DIGEST_D,
      zeroRetentionPolicyHash: DIGEST_E,
      tenantPolicyRef: 'TENANT-AI-POLICY-ALPHA',
      tenantPolicyHash: DIGEST_F,
    },
    runtimeHealth: {
      status: 'verified',
      checkedAtHlc: { physicalMs: 1799000000000, logical: 0 },
      requestTimeoutMs: 30_000,
      retryPolicyHash: DIGEST_G,
      telemetryBoundaryHash: DIGEST_A,
    },
    requestPolicy: {
      policyRef: 'AI-PROVIDER-REQUEST-POLICY-2026-05',
      promptPolicyHash: DIGEST_B,
      inputBoundaryHash: DIGEST_C,
      outputRetentionPolicyHash: DIGEST_D,
      metadataOnlyInputs: true,
      protectedContentExcluded: true,
      providerMayTrainOnInputs: false,
      rawPromptOrOutputStored: false,
      aiFinalAuthorityAllowed: false,
      allowedUseCases: ['ai_control_review', 'orientation_guidance'],
      allowedToolScopes: [
        'control_crosswalk_lookup',
        'finding_recommendation_generation',
        'metadata_evidence_retrieval',
      ],
    },
    request: {
      requestId: 'AI-PROVIDER-REQ-0001',
      useCase: 'ai_control_review',
      promptManifestHash: DIGEST_E,
      inputManifestHash: DIGEST_F,
      outputSchemaHash: DIGEST_G,
      evidenceRefs: ['evidence-ref-beta', 'evidence-ref-alpha'],
      contextRefs: ['control-library-v3', 'tenant-policy-alpha'],
      toolScopes: [
        'metadata_evidence_retrieval',
        'finding_recommendation_generation',
      ],
      requestedAtHlc: { physicalMs: 1799000000000, logical: 1 },
      responseDueAtHlc: { physicalMs: 1799000000000, logical: 3 },
    },
    humanReviewGate: {
      required: true,
      reviewerRoles: ['principal_investigator', 'quality_manager'],
      contestable: true,
      finalDecisionBy: 'human',
      routeHash: DIGEST_A,
    },
    custodyDigest: DIGEST_G,
    ...overrides,
  };
}

test('AI provider abstraction creates deterministic metadata-only provider requests without production trust claims', async () => {
  const { evaluateAiProviderAbstraction } = await loadAiProviderAbstraction();

  const resultA = evaluateAiProviderAbstraction(providerInput());
  const resultB = evaluateAiProviderAbstraction(providerInput({
    requestPolicy: {
      ...providerInput().requestPolicy,
      allowedUseCases: [...providerInput().requestPolicy.allowedUseCases].reverse(),
      allowedToolScopes: [...providerInput().requestPolicy.allowedToolScopes].reverse(),
    },
    request: {
      ...providerInput().request,
      evidenceRefs: [...providerInput().request.evidenceRefs].reverse(),
      contextRefs: [...providerInput().request.contextRefs].reverse(),
      toolScopes: [...providerInput().request.toolScopes].reverse(),
    },
    humanReviewGate: {
      ...providerInput().humanReviewGate,
      reviewerRoles: [...providerInput().humanReviewGate.reviewerRoles].reverse(),
    },
  }));

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.aiProviderRequest.schema, 'cybermedica.ai_provider_request.v1');
  assert.equal(resultA.aiProviderRequest.providerRef, 'ai-provider-cm-controlled-alpha');
  assert.equal(resultA.aiProviderRequest.providerKind, 'external_llm');
  assert.equal(resultA.aiProviderRequest.endpointMode, 'server_side');
  assert.equal(resultA.aiProviderRequest.modelRefHash, DIGEST_G);
  assert.equal(resultA.aiProviderRequest.modelVersionHash, DIGEST_A);
  assert.equal(resultA.aiProviderRequest.modelConfigurationHash, DIGEST_B);
  assert.equal(resultA.aiProviderRequest.assistanceOnly, true);
  assert.equal(resultA.aiProviderRequest.aiFinalAuthority, false);
  assert.equal(resultA.aiProviderRequest.metadataOnlyInputs, true);
  assert.equal(resultA.aiProviderRequest.rawPromptOrOutputStored, false);
  assert.equal(resultA.aiProviderRequest.trustState, 'inactive');
  assert.equal(resultA.aiProviderRequest.exochainProductionClaim, false);
  assert.deepEqual(resultA.aiProviderRequest.evidenceRefs, ['evidence-ref-alpha', 'evidence-ref-beta']);
  assert.deepEqual(resultA.aiProviderRequest.contextRefs, ['control-library-v3', 'tenant-policy-alpha']);
  assert.deepEqual(resultA.aiProviderRequest.toolScopes, [
    'finding_recommendation_generation',
    'metadata_evidence_retrieval',
  ]);
  assert.deepEqual(resultA.aiProviderRequest.humanReviewRoles, ['principal_investigator', 'quality_manager']);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'ai_provider_request_boundary');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);

  const changedModelVersion = evaluateAiProviderAbstraction(providerInput({
    providerConfig: {
      ...providerInput().providerConfig,
      modelVersionHash: DIGEST_C,
    },
  }));

  assert.notEqual(resultA.aiProviderRequest.requestHash, changedModelVersion.aiProviderRequest.requestHash);
  assert.notEqual(resultA.receipt.actionHash, changedModelVersion.receipt.actionHash);
});

test('AI provider abstraction fails closed for unsafe provider runtime policy and missing human gate', async () => {
  const { evaluateAiProviderAbstraction } = await loadAiProviderAbstraction();

  const denied = evaluateAiProviderAbstraction(providerInput({
    actor: { did: 'did:exo:ai-reviewer-alpha', kind: 'ai_agent' },
    providerConfig: {
      ...providerInput().providerConfig,
      bindingStatus: 'login_required',
      endpointMode: 'browser_client',
      modelRefHash: '',
      modelVersionHash: 'not-a-digest',
      modelConfigurationHash: '',
      configuredByHuman: false,
      noBrowserRuntime: false,
      noRootSecrets: false,
      noSharedExochainCredentials: false,
      credentialVaultRefHash: '',
    },
    runtimeHealth: {
      ...providerInput().runtimeHealth,
      status: 'timeout',
      requestTimeoutMs: 0,
    },
    requestPolicy: {
      ...providerInput().requestPolicy,
      metadataOnlyInputs: false,
      protectedContentExcluded: false,
      providerMayTrainOnInputs: true,
      rawPromptOrOutputStored: true,
      aiFinalAuthorityAllowed: true,
    },
    humanReviewGate: {
      required: false,
      reviewerRoles: [],
      contestable: false,
      finalDecisionBy: 'ai',
      routeHash: '',
    },
  }));

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('provider_binding_unverified'));
  assert.ok(denied.reasons.includes('browser_authoritative_ai_path_forbidden'));
  assert.ok(denied.reasons.includes('model_ref_hash_invalid'));
  assert.ok(denied.reasons.includes('model_version_hash_invalid'));
  assert.ok(denied.reasons.includes('model_configuration_hash_invalid'));
  assert.ok(denied.reasons.includes('provider_human_configuration_absent'));
  assert.ok(denied.reasons.includes('root_secret_scope_not_separated'));
  assert.ok(denied.reasons.includes('shared_exochain_credentials_forbidden'));
  assert.ok(denied.reasons.includes('provider_runtime_not_verified'));
  assert.ok(denied.reasons.includes('provider_timeout_invalid'));
  assert.ok(denied.reasons.includes('metadata_only_inputs_absent'));
  assert.ok(denied.reasons.includes('protected_content_boundary_absent'));
  assert.ok(denied.reasons.includes('provider_training_on_inputs_forbidden'));
  assert.ok(denied.reasons.includes('raw_prompt_or_output_storage_forbidden'));
  assert.ok(denied.reasons.includes('policy_allows_ai_final_authority'));
  assert.ok(denied.reasons.includes('human_review_gate_absent'));
  assert.ok(denied.reasons.includes('human_review_roles_absent'));
  assert.ok(denied.reasons.includes('human_final_decision_absent'));
});

test('AI provider abstraction validates use case scope manifests evidence refs and HLC ordering', async () => {
  const { evaluateAiProviderAbstraction } = await loadAiProviderAbstraction();

  const denied = evaluateAiProviderAbstraction(providerInput({
    requestPolicy: {
      ...providerInput().requestPolicy,
      allowedUseCases: ['orientation_guidance'],
      allowedToolScopes: ['metadata_evidence_retrieval'],
    },
    request: {
      ...providerInput().request,
      useCase: 'unsupported_freeform_answer',
      promptManifestHash: '',
      inputManifestHash: 'not-a-digest',
      outputSchemaHash: '',
      evidenceRefs: [],
      toolScopes: ['metadata_evidence_retrieval', 'raw_source_document_reader'],
      requestedAtHlc: { physicalMs: 1799000000000, logical: 3 },
      responseDueAtHlc: { physicalMs: 1799000000000, logical: 2 },
    },
  }));

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('request_use_case_not_allowed:unsupported_freeform_answer'));
  assert.ok(denied.reasons.includes('request_prompt_manifest_hash_invalid'));
  assert.ok(denied.reasons.includes('request_input_manifest_hash_invalid'));
  assert.ok(denied.reasons.includes('request_output_schema_hash_invalid'));
  assert.ok(denied.reasons.includes('request_evidence_refs_absent'));
  assert.ok(denied.reasons.includes('request_tool_scope_not_allowed:raw_source_document_reader'));
  assert.ok(denied.reasons.includes('request_response_due_not_after_request'));
});

test('AI provider abstraction rejects raw prompts protected source content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateAiProviderAbstraction } = await loadAiProviderAbstraction();

  assert.throws(
    () => evaluateAiProviderAbstraction(providerInput({
      request: {
        ...providerInput().request,
        promptBody: 'Summarize this source material.',
      },
    })),
    ProtectedContentError,
  );

  assert.throws(
    () => evaluateAiProviderAbstraction(providerInput({
      request: {
        ...providerInput().request,
        sourceDocumentBody: 'Participant Alice Example has a visit exception.',
      },
    })),
    ProtectedContentError,
  );

  assert.throws(
    () => evaluateAiProviderAbstraction(providerInput({
      providerConfig: {
        ...providerInput().providerConfig,
        apiKey: { vaultRef: 'secret-ref-alpha' },
      },
    })),
    ProtectedContentError,
  );

  const inertSecretMarker = evaluateAiProviderAbstraction(providerInput({
    providerConfig: {
      ...providerInput().providerConfig,
      token: false,
    },
  }));

  assert.equal(inertSecretMarker.decision, 'permitted');
});
