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
const DIGEST_7 = '7777777777777777777777777777777777777777777777777777777777777777';
const DIGEST_8 = '8888888888888888888888888888888888888888888888888888888888888888';
const DIGEST_9 = '9999999999999999999999999999999999999999999999999999999999999999';

const REQUIRED_INTEGRATION_FAMILIES = [
  'ctms',
  'data_warehouse',
  'document_system',
  'econsent',
  'edc',
  'eisf',
  'etmf',
  'hris',
  'identity_provider',
  'irb_system',
  'lms',
  'qms',
  'sponsor_portal',
];

const REQUIRED_CONTRACT_EVIDENCE = [
  'access_policy',
  'authn_authz',
  'contract_fixture',
  'error_mapping',
  'fail_closed_negative_tests',
  'health_check',
  'idempotency_replay',
  'metadata_schema',
  'payload_boundary',
  'rate_limit',
  'rollback_disablement',
  'webhook_signature',
];

const REQUIRED_DEPENDENCY_REFS = [
  'src/governed-integrations.mjs',
  'src/governed-api-access.mjs',
  'src/interoperability-readiness.mjs',
  'src/structured-data-exports.mjs',
];

async function loadIntegrationContractReadiness() {
  try {
    return await import('../src/integration-contract-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica integration contract readiness module must exist and load: ${error.message}`);
  }
}

function digestFor(index) {
  return (index + 1).toString(16).padStart(2, '0').repeat(32);
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

function contractEvidence(evidenceType, index, overrides = {}) {
  return {
    evidenceType,
    evidenceRef: `integration-contract-${evidenceType}`,
    evidenceHash: digestFor(index + 30),
    status: 'verified',
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function integrationBoundary(family, index, overrides = {}) {
  const mode = family === 'identity_provider' ? 'inbound' : 'bidirectional';

  return {
    family,
    boundaryRef: `deployment-integration-${family}`,
    ownerRoleRef: family === 'identity_provider' ? 'security_owner' : 'integration_owner',
    systemRef: `external-system-${family}`,
    endpointRouteRef: `server-route-${family}`,
    authPolicyRef: `auth-policy-${family}`,
    contractHash: digestFor(index),
    fixtureHash: digestFor(index + 60),
    negativeTestHash: digestFor(index + 90),
    healthCheckHash: digestFor(index + 120),
    rollbackRef: `disable-${family}-connector`,
    dataFlowMode: mode,
    runtimeLocation: 'server_side',
    status: 'contracted',
    governedIntegrationRef: `fr048-${family}`,
    governedApiAccessRef: `fr049-${family}`,
    interoperabilityRef: `nfr007-${family}`,
    structuredExportRef: `nfr013-${family}`,
    contractEvidence: REQUIRED_CONTRACT_EVIDENCE.map((evidenceType, evidenceIndex) =>
      contractEvidence(evidenceType, index + evidenceIndex),
    ).reverse(),
    failClosedOnUnavailable: true,
    failClosedOnTimeout: true,
    failClosedOnMalformedResponse: true,
    failClosedOnRejectedDecision: true,
    tenantScoped: true,
    serviceAccountHumanOwnerRequired: true,
    secretsExternalized: true,
    rawPayloadLoggingDisabled: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    lastReviewedAtHlc: { physicalMs: 1806500000000, logical: index + 10 },
    ...overrides,
  };
}

function integrationContractInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-cybermedica-alpha',
    targetTenantId: 'tenant-cybermedica-alpha',
    actor: {
      did: 'did:exo:deployment-integration-owner-alpha',
      kind: 'human',
      roleRefs: ['deployment_owner', 'integration_owner'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['integration_contract_review', 'manage_integrations'],
      authorityChainHash: DIGEST_A,
    },
    contractPolicy: {
      policyRef: 'deployment-integration-contract-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      sourcePrdRef: 'cybermedica_2_0_sandy_seven_layer_master_prd.md#deployment-backlog-integration-stubs',
      requiredIntegrationFamilies: REQUIRED_INTEGRATION_FAMILIES,
      requiredContractEvidence: REQUIRED_CONTRACT_EVIDENCE,
      requiredDependencyRefs: REQUIRED_DEPENDENCY_REFS,
      requireServerSideRuntime: true,
      requireFailClosedBoundaries: true,
      requireNoProductionTrustClaim: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1806500000000, logical: 0 },
    },
    dependencyReadiness: {
      readinessRef: 'integration-contract-dependencies-alpha',
      readinessHash: DIGEST_C,
      governedIntegrationsReady: true,
      governedApiAccessReady: true,
      interoperabilityReady: true,
      structuredExportsReady: true,
      refs: REQUIRED_DEPENDENCY_REFS,
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1806500000100, logical: 0 },
    },
    integrationBoundaries: REQUIRED_INTEGRATION_FAMILIES.map(integrationBoundary).reverse(),
    validationEvidence: {
      commandRefs: [
        'node --test tests/integration-contract-readiness.test.mjs',
        'node --test tests/source-guards.test.mjs',
        'npm run quality',
      ],
      contractTestsPassed: true,
      negativePathTestsPassed: true,
      sourceGuardPassed: true,
      privacyFixturePassed: true,
      tenantIsolationPassed: true,
      replayProtectionPassed: true,
      validationHash: DIGEST_D,
      metadataOnly: true,
      protectedContentExcluded: true,
      validatedAtHlc: { physicalMs: 1806500000200, logical: 0 },
    },
    humanReview: {
      reviewerDid: 'did:exo:deployment-owner-alpha',
      reviewerRoleRefs: ['deployment_owner', 'quality_manager'],
      decision: 'integration_contracts_ready_inactive_trust',
      reviewHash: DIGEST_E,
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1806500000300, logical: 0 },
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_F,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    custodyDigest: DIGEST_1,
  };

  return mergeDeep(base, overrides);
}

test('integration contract readiness creates deterministic inactive deployment evidence', async () => {
  const { evaluateIntegrationContractReadiness } = await loadIntegrationContractReadiness();

  const first = evaluateIntegrationContractReadiness(integrationContractInput());
  const second = evaluateIntegrationContractReadiness({
    ...integrationContractInput(),
    integrationBoundaries: [...integrationContractInput().integrationBoundaries].reverse(),
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.integrationContractReadiness.status, 'ready');
  assert.deepEqual(first.integrationContractReadiness.integrationFamilies, REQUIRED_INTEGRATION_FAMILIES);
  assert.deepEqual(first.integrationContractReadiness.contractEvidenceTypes, REQUIRED_CONTRACT_EVIDENCE);
  assert.deepEqual(first.integrationContractReadiness.dependencyRefs, REQUIRED_DEPENDENCY_REFS);
  assert.equal(first.integrationContractReadiness.boundaryCount, REQUIRED_INTEGRATION_FAMILIES.length);
  assert.equal(first.integrationContractReadiness.metadataOnly, true);
  assert.equal(first.integrationContractReadiness.exochainProductionClaim, false);
  assert.equal(first.integrationContractReadiness.readinessHash, second.integrationContractReadiness.readinessHash);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.anchorPayload.artifactType, 'integration_contract_readiness');
  assert.doesNotMatch(JSON.stringify(first), /Participant Alice|raw payload|client_secret|source document/iu);
});

test('integration contract readiness fails closed for missing families evidence and dependencies', async () => {
  const { evaluateIntegrationContractReadiness } = await loadIntegrationContractReadiness();

  const input = integrationContractInput({
    contractPolicy: {
      requiredDependencyRefs: REQUIRED_DEPENDENCY_REFS,
    },
    dependencyReadiness: {
      governedApiAccessReady: false,
      refs: REQUIRED_DEPENDENCY_REFS.filter((ref) => ref !== 'src/governed-api-access.mjs'),
    },
    integrationBoundaries: integrationContractInput().integrationBoundaries
      .filter((boundary) => boundary.family !== 'edc' && boundary.family !== 'identity_provider')
      .map((boundary) =>
        boundary.family === 'ctms'
          ? {
              ...boundary,
              contractEvidence: boundary.contractEvidence.filter(
                (evidence) => evidence.evidenceType !== 'fail_closed_negative_tests',
              ),
            }
          : boundary,
      ),
  });

  const denied = evaluateIntegrationContractReadiness(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.integrationContractReadiness.status, 'blocked');
  assert.ok(denied.reasons.includes('integration_family_missing:edc'));
  assert.ok(denied.reasons.includes('integration_family_missing:identity_provider'));
  assert.ok(denied.reasons.includes('contract_evidence_missing:ctms:fail_closed_negative_tests'));
  assert.ok(denied.reasons.includes('dependency_governed_api_access_not_ready'));
  assert.ok(denied.reasons.includes('dependency_ref_missing:src/governed-api-access.mjs'));
});

test('integration contract readiness denies unsafe runtime boundaries and trust claims', async () => {
  const { evaluateIntegrationContractReadiness } = await loadIntegrationContractReadiness();

  const input = integrationContractInput({
    integrationBoundaries: [
      integrationBoundary('ctms', 0, {
        runtimeLocation: 'browser_client',
        failClosedOnUnavailable: false,
        failClosedOnTimeout: false,
        failClosedOnMalformedResponse: false,
        failClosedOnRejectedDecision: false,
        tenantScoped: false,
        serviceAccountHumanOwnerRequired: false,
        secretsExternalized: false,
        rawPayloadLoggingDisabled: false,
        metadataOnly: false,
        protectedContentExcluded: false,
        status: 'unreviewed',
      }),
      ...integrationContractInput().integrationBoundaries.filter((boundary) => boundary.family !== 'ctms'),
    ],
    humanReview: {
      noProductionTrustClaim: false,
    },
  });

  const denied = evaluateIntegrationContractReadiness(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('boundary_runtime_not_server_side:ctms'));
  assert.ok(denied.reasons.includes('boundary_unavailable_not_fail_closed:ctms'));
  assert.ok(denied.reasons.includes('boundary_timeout_not_fail_closed:ctms'));
  assert.ok(denied.reasons.includes('boundary_malformed_response_not_fail_closed:ctms'));
  assert.ok(denied.reasons.includes('boundary_rejected_decision_not_fail_closed:ctms'));
  assert.ok(denied.reasons.includes('boundary_tenant_scope_absent:ctms'));
  assert.ok(denied.reasons.includes('boundary_service_account_owner_absent:ctms'));
  assert.ok(denied.reasons.includes('boundary_secret_externalization_absent:ctms'));
  assert.ok(denied.reasons.includes('boundary_raw_payload_logging_enabled:ctms'));
  assert.ok(denied.reasons.includes('boundary_metadata_boundary_invalid:ctms'));
  assert.ok(denied.reasons.includes('boundary_protected_content_boundary_invalid:ctms'));
  assert.ok(denied.reasons.includes('boundary_status_invalid:ctms'));
  assert.ok(denied.reasons.includes('human_review_production_trust_claim_forbidden'));
});

test('integration contract readiness validates tenant authority HLC human review and AI boundaries', async () => {
  const { evaluateIntegrationContractReadiness } = await loadIntegrationContractReadiness();

  const denied = evaluateIntegrationContractReadiness(
    integrationContractInput({
      targetTenantId: 'tenant-other',
      actor: {
        kind: 'ai_agent',
      },
      authority: {
        valid: false,
        permissions: ['read'],
        authorityChainHash: 'bad',
      },
      contractPolicy: {
        status: 'draft',
        metadataOnly: false,
        protectedContentExcluded: false,
        evaluatedAtHlc: { physicalMs: 1806500000400, logical: 0 },
      },
      validationEvidence: {
        contractTestsPassed: false,
        negativePathTestsPassed: false,
        sourceGuardPassed: false,
        privacyFixturePassed: false,
        tenantIsolationPassed: false,
        replayProtectionPassed: false,
        validationHash: 'bad',
        validatedAtHlc: { physicalMs: 1806500000200, logical: 0 },
      },
      humanReview: {
        reviewerDid: '',
        decision: 'approved',
        reviewHash: 'bad',
        aiFinalAuthority: true,
        reviewedAtHlc: { physicalMs: 1806500000100, logical: 0 },
      },
      aiAssistance: {
        used: true,
        finalAuthority: true,
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('human_integration_reviewer_required'));
  assert.ok(denied.reasons.includes('authority_chain_invalid'));
  assert.ok(denied.reasons.includes('integration_contract_authority_missing'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('contract_policy_not_active'));
  assert.ok(denied.reasons.includes('contract_policy_metadata_boundary_invalid'));
  assert.ok(denied.reasons.includes('contract_policy_protected_content_boundary_invalid'));
  assert.ok(denied.reasons.includes('validation_before_policy_review'));
  assert.ok(denied.reasons.includes('human_review_before_validation'));
  assert.ok(denied.reasons.includes('validation_contract_tests_not_passed'));
  assert.ok(denied.reasons.includes('validation_negative_path_tests_not_passed'));
  assert.ok(denied.reasons.includes('validation_source_guard_not_passed'));
  assert.ok(denied.reasons.includes('validation_privacy_fixture_not_passed'));
  assert.ok(denied.reasons.includes('validation_tenant_isolation_not_passed'));
  assert.ok(denied.reasons.includes('validation_replay_protection_not_passed'));
  assert.ok(denied.reasons.includes('validation_hash_invalid'));
  assert.ok(denied.reasons.includes('human_review_reviewer_absent'));
  assert.ok(denied.reasons.includes('human_review_decision_invalid'));
  assert.ok(denied.reasons.includes('human_review_hash_invalid'));
  assert.ok(denied.reasons.includes('human_review_ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('ai_assistance_final_authority_forbidden'));
});

test('integration contract readiness handles absent objects as fail-closed denial states', async () => {
  const { evaluateIntegrationContractReadiness } = await loadIntegrationContractReadiness();

  const denied = evaluateIntegrationContractReadiness({});

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('tenant_absent'));
  assert.ok(denied.reasons.includes('contract_policy_ref_absent'));
  assert.ok(denied.reasons.includes('dependency_readiness_ref_absent'));
  assert.ok(denied.reasons.includes('integration_boundaries_absent'));
  assert.ok(denied.reasons.includes('human_review_reviewer_absent'));
});

test('integration contract readiness rejects raw payload content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateIntegrationContractReadiness } = await loadIntegrationContractReadiness();

  assert.throws(
    () =>
      evaluateIntegrationContractReadiness({
        ...integrationContractInput(),
        integrationBoundaries: [
          {
            ...integrationBoundary('ctms', 0),
            rawPayload: 'source document body',
          },
          ...integrationContractInput().integrationBoundaries.filter((boundary) => boundary.family !== 'ctms'),
        ],
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateIntegrationContractReadiness({
        ...integrationContractInput(),
        contractPolicy: {
          ...integrationContractInput().contractPolicy,
          clientSecret: 'client_secret',
        },
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateIntegrationContractReadiness({
        ...integrationContractInput(),
        validationEvidence: {
          ...integrationContractInput().validationEvidence,
          endpointRawResponse: { status: 500 },
        },
      }),
    ProtectedContentError,
  );
});
