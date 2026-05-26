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

const REQUIRED_BINDING_DOMAINS = [
  'deployment_owner',
  'dns_tls_binding',
  'environment_binding',
  'health_readiness',
  'monitoring_linkage',
  'project_binding',
  'provider_account',
  'rollback_binding',
  'root_bundle_provider_binding',
  'runtime_adapter_binding',
  'secret_scope_binding',
  'service_binding',
];

const ALLOWED_ACTIVATION_BLOCKERS = [
  'ESC-OPS-SECRETS',
  'ESC-ROOT-DEPLOYMENT',
  'ESC-ROOT-OWNER',
  'ESC-RUNTIME',
];

async function loadDeploymentProviderBinding() {
  try {
    return await import('../src/deployment-provider-binding.mjs');
  } catch (error) {
    assert.fail(`CyberMedica deployment provider binding module must exist and load: ${error.message}`);
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

function bindingDomain(domain, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6];
  const activationBlocked = ['dns_tls_binding', 'root_bundle_provider_binding', 'runtime_adapter_binding'].includes(domain);
  return {
    domain,
    status: activationBlocked ? 'activation_blocked' : 'ready',
    evidenceRef: `provider-binding-evidence-${domain}`,
    evidenceHash: hashes[index],
    ownerDid: `did:exo:${domain.replaceAll('_', '-')}-owner`,
    activationBlockerId: activationBlocked ? (domain === 'dns_tls_binding' ? 'ESC-ROOT-DEPLOYMENT' : 'ESC-RUNTIME') : null,
    productionActivationOnly: activationBlocked,
    blocksBaselineDevelopment: false,
    reviewedByHuman: true,
    reviewedAtHlc: { physicalMs: 1800003200000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function bindingDomains() {
  return REQUIRED_BINDING_DOMAINS.map((domain, index) => bindingDomain(domain, index));
}

function providerBindingInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:deployment-owner-alpha',
      kind: 'human',
      roleRefs: ['deployment_owner', 'quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['deployment_provider_binding_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    providerPolicy: {
      policyRef: 'deployment-provider-binding-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      allowedProviders: ['railway'],
      requiredBindingDomains: REQUIRED_BINDING_DOMAINS,
      allowedActivationBlockerIds: ALLOWED_ACTIVATION_BLOCKERS,
      rootVerificationRequiredForTrustClaims: true,
      noCredentialDisclosure: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800003000000, logical: 0 },
    },
    bindingCycle: {
      bindingRef: 'deployment-provider-binding-alpha',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      openedAtHlc: { physicalMs: 1800003100000, logical: 0 },
      evidenceCollectedAtHlc: { physicalMs: 1800003200000, logical: 12 },
      validationRecordedAtHlc: { physicalMs: 1800003300000, logical: 0 },
      humanReviewedAtHlc: { physicalMs: 1800003400000, logical: 0 },
      auditRecordedAtHlc: { physicalMs: 1800003500000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    providerBinding: {
      provider: 'railway',
      accountHash: DIGEST_C,
      workspaceHash: null,
      projectHash: null,
      serviceHash: null,
      environmentHash: null,
      domainHash: null,
      publicEndpointHash: null,
      endpointSelected: false,
      projectLinked: false,
      serviceBound: false,
      environmentBound: false,
      dashboardAccessVerified: false,
      providerHealthVerified: false,
      checkedAtHlc: { physicalMs: 1800003200000, logical: 12 },
      metadataOnly: true,
      credentialShared: false,
      tokenStored: false,
    },
    runtimeBinding: {
      topologyRef: 'server-side-gateway-node-baseline',
      topologyHash: DIGEST_D,
      gatewayAdapterHash: DIGEST_E,
      nodeReceiptAdapterHash: DIGEST_F,
      decisionForumAdapterHash: DIGEST_1,
      rootBundleProviderHash: null,
      rootBundleProviderVerified: false,
      browserAuthoritativePathEnabled: false,
      healthEndpointSeparatesProcessAndTrust: true,
      unavailableAdaptersFailClosed: true,
      receiptPayloadBoundaryVerified: true,
      productionTrustClaim: false,
      metadataOnly: true,
      checkedAtHlc: { physicalMs: 1800003200000, logical: 11 },
    },
    bindingDomains: bindingDomains(),
    operationsReadiness: {
      operationsReadinessRef: 'deployment-operations-readiness-alpha',
      operationsReadinessHash: DIGEST_2,
      baselineOperationsPackReady: true,
      productionOperationsReady: false,
      railwayLoginStatus: 'login_required',
      activationBlockerIds: ['ESC-OPS-SECRETS', 'ESC-ROOT-DEPLOYMENT', 'ESC-ROOT-OWNER', 'ESC-RUNTIME'],
      metadataOnly: true,
      reviewedAtHlc: { physicalMs: 1800003200000, logical: 10 },
    },
    validationEvidence: {
      commandRefs: ['npm run quality', 'railway whoami --json', 'railway status --json'],
      commandsPassed: true,
      testCount: 326,
      coverageLineBasisPoints: 9973,
      sourceGuardPassed: true,
      noExochainSourceModified: true,
      providerStatusEvidenceHash: DIGEST_3,
      metadataOnly: true,
      recordedAtHlc: { physicalMs: 1800003300000, logical: 0 },
    },
    humanReview: {
      reviewerDid: 'did:exo:site-leader-alpha',
      reviewerRoleRefs: ['site_leader', 'quality_manager'],
      decision: 'provider_binding_ready_with_activation_blockers',
      decisionHash: DIGEST_4,
      activationBlockersAccepted: true,
      noProductionTrustClaim: true,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      reviewedAtHlc: { physicalMs: 1800003400000, logical: 0 },
      metadataOnly: true,
    },
    auditRecord: {
      auditRecordRef: 'deployment-provider-binding-audit-alpha',
      auditRecordHash: DIGEST_5,
      receiptRecordedAtHlc: { physicalMs: 1800003500000, logical: 0 },
      metadataOnly: true,
      includesProtectedContent: false,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_6,
      limitationHashes: [DIGEST_7],
      reviewedByHuman: true,
    },
    custodyDigest: DIGEST_8,
  };
  return mergeDeep(base, overrides);
}

test('deployment provider binding records Railway login-required state without production trust claims', async () => {
  const { evaluateDeploymentProviderBinding } = await loadDeploymentProviderBinding();

  const resultA = evaluateDeploymentProviderBinding(providerBindingInput());
  const resultB = evaluateDeploymentProviderBinding(
    providerBindingInput({
      providerPolicy: {
        requiredBindingDomains: [...REQUIRED_BINDING_DOMAINS].reverse(),
        allowedActivationBlockerIds: [...ALLOWED_ACTIVATION_BLOCKERS].reverse(),
      },
      bindingDomains: [...bindingDomains()].reverse(),
      operationsReadiness: {
        activationBlockerIds: ['ESC-RUNTIME', 'ESC-ROOT-OWNER', 'ESC-ROOT-DEPLOYMENT', 'ESC-OPS-SECRETS'],
      },
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.providerBinding.trustState, 'inactive');
  assert.equal(resultA.providerBinding.exochainProductionClaim, false);
  assert.equal(resultA.providerBinding.baselineProviderBindingReady, true);
  assert.equal(resultA.providerBinding.productionProviderBindingReady, false);
  assert.deepEqual(resultA.providerBinding.bindingDomainsCovered, REQUIRED_BINDING_DOMAINS);
  assert.deepEqual(resultA.providerBinding.activationBlockerIds, ALLOWED_ACTIVATION_BLOCKERS);
  assert.equal(resultA.providerBinding.provider.provider, 'railway');
  assert.equal(resultA.providerBinding.provider.bindingStatus, 'login_required');
  assert.equal(resultA.providerBinding.provider.endpointSelected, false);
  assert.equal(resultA.providerBinding.runtime.rootBundleProviderVerified, false);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'deployment_provider_binding');
  assert.deepEqual(resultA, resultB);
});

test('deployment provider binding can verify provider resources while keeping trust activation separate', async () => {
  const { evaluateDeploymentProviderBinding } = await loadDeploymentProviderBinding();

  const verified = evaluateDeploymentProviderBinding(
    providerBindingInput({
      providerBinding: {
        workspaceHash: DIGEST_9,
        projectHash: DIGEST_A,
        serviceHash: DIGEST_B,
        environmentHash: DIGEST_C,
        domainHash: DIGEST_D,
        publicEndpointHash: DIGEST_E,
        endpointSelected: true,
        projectLinked: true,
        serviceBound: true,
        environmentBound: true,
        dashboardAccessVerified: true,
        providerHealthVerified: true,
      },
      runtimeBinding: {
        rootBundleProviderHash: DIGEST_F,
        rootBundleProviderVerified: true,
      },
      bindingDomains: REQUIRED_BINDING_DOMAINS.map((domain, index) =>
        bindingDomain(domain, index, {
          status: 'ready',
          activationBlockerId: null,
          productionActivationOnly: false,
        }),
      ),
      operationsReadiness: {
        productionOperationsReady: true,
        railwayLoginStatus: 'verified',
        activationBlockerIds: [],
      },
      humanReview: {
        decision: 'provider_binding_ready',
      },
    }),
  );

  assert.equal(verified.decision, 'permitted');
  assert.equal(verified.providerBinding.provider.bindingStatus, 'verified');
  assert.deepEqual(verified.providerBinding.activationBlockerIds, []);
  assert.equal(verified.providerBinding.productionProviderBindingReady, true);
  assert.equal(verified.providerBinding.exochainProductionClaim, false);
  assert.equal(verified.trustState, 'inactive');
});

test('deployment provider binding fails closed for missing domains unsupported providers and unsafe claims', async () => {
  const { evaluateDeploymentProviderBinding } = await loadDeploymentProviderBinding();

  const result = evaluateDeploymentProviderBinding(
    providerBindingInput({
      providerPolicy: {
        allowedProviders: ['railway'],
      },
      bindingCycle: {
        productionTrustClaim: true,
      },
      providerBinding: {
        provider: 'unsupported-cloud',
        endpointSelected: true,
      },
      bindingDomains: bindingDomains().filter((entry) => entry.domain !== 'secret_scope_binding'),
      operationsReadiness: {
        activationBlockerIds: ['ESC-OPS-SECRETS', 'ESC-UNBOUNDED-PROVIDER'],
      },
      runtimeBinding: {
        browserAuthoritativePathEnabled: true,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.providerBinding, null);
  assert.ok(result.reasons.includes('binding_domain_missing:secret_scope_binding'));
  assert.ok(result.reasons.includes('provider_not_allowed:unsupported-cloud'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('endpoint_selected_without_verified_provider'));
  assert.ok(result.reasons.includes('operations_blocker_not_allowed:ESC-UNBOUNDED-PROVIDER'));
  assert.ok(result.reasons.includes('browser_authoritative_path_forbidden'));
});

test('deployment provider binding validates HLC ordering and AI advisory boundaries', async () => {
  const { evaluateDeploymentProviderBinding } = await loadDeploymentProviderBinding();

  const validSameTick = evaluateDeploymentProviderBinding(
    providerBindingInput({
      bindingCycle: {
        humanReviewedAtHlc: { physicalMs: 1800003400000, logical: 2 },
        auditRecordedAtHlc: { physicalMs: 1800003400000, logical: 3 },
      },
      humanReview: {
        reviewedAtHlc: { physicalMs: 1800003400000, logical: 2 },
      },
      auditRecord: {
        receiptRecordedAtHlc: { physicalMs: 1800003400000, logical: 3 },
      },
    }),
  );

  assert.equal(validSameTick.decision, 'permitted');

  const invalid = evaluateDeploymentProviderBinding(
    providerBindingInput({
      bindingCycle: {
        validationRecordedAtHlc: { physicalMs: 1800003190000, logical: 0 },
      },
      validationEvidence: {
        recordedAtHlc: { physicalMs: 1800003300000, logical: -1 },
      },
      aiAssistance: {
        finalAuthority: true,
        reviewedByHuman: false,
      },
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
      },
    }),
  );

  assert.equal(invalid.decision, 'denied');
  assert.ok(invalid.reasons.includes('binding_cycle_validationRecordedAtHlc_before_evidenceCollectedAtHlc'));
  assert.ok(invalid.reasons.includes('validation_time_invalid'));
  assert.ok(invalid.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(invalid.reasons.includes('ai_human_review_absent'));
  assert.ok(invalid.reasons.includes('human_review_authority_absent'));
});

test('deployment provider binding handles absent objects as fail-closed denial states', async () => {
  const { evaluateDeploymentProviderBinding } = await loadDeploymentProviderBinding();

  const result = evaluateDeploymentProviderBinding({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:deployment-owner-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['deployment_provider_binding_review'],
      authorityChainHash: DIGEST_A,
    },
  });

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('provider_policy_ref_absent'));
  assert.ok(result.reasons.includes('binding_cycle_ref_absent'));
  assert.ok(result.reasons.includes('provider_binding_absent'));
  assert.ok(result.reasons.includes('runtime_binding_absent'));
  assert.ok(result.reasons.includes('binding_domains_absent'));
  assert.ok(result.reasons.includes('operations_readiness_absent'));
  assert.ok(result.reasons.includes('validation_evidence_absent'));
  assert.ok(result.reasons.includes('human_review_absent'));
  assert.ok(result.reasons.includes('provider_binding_audit_record_ref_absent'));
});

test('deployment provider binding rejects raw deployment content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateDeploymentProviderBinding } = await loadDeploymentProviderBinding();

  const inert = providerBindingInput({
    providerBinding: {
      rawProviderStatus: false,
      apiKey: {},
    },
  });

  assert.equal(evaluateDeploymentProviderBinding(inert).decision, 'permitted');

  assert.throws(
    () =>
      evaluateDeploymentProviderBinding(
        providerBindingInput({
          providerBinding: {
            rawProviderStatus: ['unredacted provider status output stays external'],
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentProviderBinding(
        providerBindingInput({
          runtimeBinding: {
            rawDeploymentConfig: 'Participant Alice Example must not appear in deployment provider config.',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentProviderBinding(
        providerBindingInput({
          providerBinding: {
            apiKey: 'cm_live_secret_value',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentProviderBinding(
        providerBindingInput({
          humanReview: {
            token: 7,
          },
        }),
      ),
    ProtectedContentError,
  );
});
