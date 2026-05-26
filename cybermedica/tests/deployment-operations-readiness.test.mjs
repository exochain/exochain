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

const REQUIRED_OPERATION_DOMAINS = [
  'dependency_audit',
  'monitoring_destination',
  'on_call_ownership',
  'railway_access',
  'rollback_disablement',
  'secret_management',
  'secret_rotation',
  'secret_scan',
];

const ALLOWED_DEPLOYMENT_BLOCKERS = [
  'ESC-OPS-SECRETS',
  'ESC-ROOT-DEPLOYMENT',
  'ESC-ROOT-OWNER',
  'ESC-RUNTIME',
];

async function loadDeploymentOperationsReadiness() {
  try {
    return await import('../src/deployment-operations-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica deployment operations readiness module must exist and load: ${error.message}`);
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

function operationDomain(domain, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2];
  return {
    domain,
    status: domain === 'railway_access' ? 'activation_blocked' : 'ready',
    evidenceRef: `operations-evidence-${domain}`,
    evidenceHash: hashes[index],
    ownerDid: `did:exo:${domain.replaceAll('_', '-')}-owner`,
    backupOwnerDid: `did:exo:${domain.replaceAll('_', '-')}-backup`,
    activationBlockerId: domain === 'railway_access' ? 'ESC-RUNTIME' : null,
    blocksBaselineDevelopment: false,
    productionActivationOnly: domain === 'railway_access',
    reviewedByHuman: true,
    reviewedAtHlc: { physicalMs: 1800002100000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function operationDomains() {
  return REQUIRED_OPERATION_DOMAINS.map((domain, index) => operationDomain(domain, index));
}

function operationsInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:quality-manager-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'site_leader'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['deployment_operations_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    operationsPolicy: {
      policyRef: 'deployment-operations-readiness-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredOperationDomains: REQUIRED_OPERATION_DOMAINS,
      allowedDeploymentBlockerIds: ALLOWED_DEPLOYMENT_BLOCKERS,
      rootVerificationRequiredForTrustClaims: true,
      noCredentialDisclosure: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800001900000, logical: 0 },
    },
    readinessCycle: {
      cycleRef: 'deployment-operations-readiness-alpha',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      openedAtHlc: { physicalMs: 1800001950000, logical: 0 },
      evidenceCollectedAtHlc: { physicalMs: 1800002100000, logical: 8 },
      validationRecordedAtHlc: { physicalMs: 1800002200000, logical: 0 },
      humanReviewedAtHlc: { physicalMs: 1800002300000, logical: 0 },
      auditRecordedAtHlc: { physicalMs: 1800002400000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    operationDomains: operationDomains(),
    deploymentConfiguration: {
      topologyRef: 'server-side-gateway-node-baseline',
      topologyHash: DIGEST_C,
      monitoringDestinationSelected: false,
      onCallOwnerNamed: false,
      secretManagerSelected: false,
      rotationOwnerNamed: false,
      dependencyAuditPassed: true,
      secretScanPassed: true,
      rollbackAuthorityNamed: false,
      activationStateDisablementTested: true,
      missingSecretsFailClosed: true,
      productionEndpointSelected: false,
      activationBlockerIds: ['ESC-OPS-SECRETS', 'ESC-ROOT-DEPLOYMENT', 'ESC-ROOT-OWNER'],
      metadataOnly: true,
      reviewedAtHlc: { physicalMs: 1800002100000, logical: 7 },
    },
    railwayAccess: {
      provider: 'railway',
      cliInstalled: true,
      cliVersion: 'railway 4.42.1',
      cliVersionHash: DIGEST_D,
      authenticated: false,
      loginRequired: true,
      projectLinked: false,
      workspaceHash: null,
      projectHash: null,
      serviceHash: null,
      environmentHash: null,
      dashboardAccessVerified: false,
      tokenStored: false,
      credentialShared: false,
      statusEvidenceHash: DIGEST_E,
      checkedAtHlc: { physicalMs: 1800002100000, logical: 8 },
      metadataOnly: true,
    },
    validationEvidence: {
      commandRefs: ['npm run quality', 'railway whoami --json', 'railway status --json'],
      commandsPassed: true,
      testCount: 320,
      coverageLineBasisPoints: 9973,
      sourceGuardPassed: true,
      dependencyAuditEvidenceHash: DIGEST_F,
      secretScanEvidenceHash: DIGEST_1,
      noExochainSourceModified: true,
      metadataOnly: true,
      recordedAtHlc: { physicalMs: 1800002200000, logical: 0 },
    },
    humanReview: {
      reviewerDid: 'did:exo:site-leader-alpha',
      reviewerRoleRefs: ['site_leader', 'quality_manager'],
      decision: 'operations_ready_with_activation_blockers',
      decisionHash: DIGEST_2,
      noProductionTrustClaim: true,
      activationBlockersAccepted: true,
      railwayLoginRequiredAccepted: true,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      reviewedAtHlc: { physicalMs: 1800002300000, logical: 0 },
      metadataOnly: true,
    },
    auditRecord: {
      auditRecordRef: 'deployment-operations-audit-alpha',
      auditRecordHash: DIGEST_3,
      receiptRecordedAtHlc: { physicalMs: 1800002400000, logical: 0 },
      metadataOnly: true,
      includesProtectedContent: false,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_4,
      limitationHashes: [DIGEST_5],
      reviewedByHuman: true,
    },
    custodyDigest: DIGEST_6,
  };
  return mergeDeep(base, overrides);
}

test('deployment operations readiness records runbook blockers and Railway login status deterministically', async () => {
  const { evaluateDeploymentOperationsReadiness } = await loadDeploymentOperationsReadiness();

  const resultA = evaluateDeploymentOperationsReadiness(operationsInput());
  const resultB = evaluateDeploymentOperationsReadiness(
    operationsInput({
      operationsPolicy: {
        requiredOperationDomains: [...REQUIRED_OPERATION_DOMAINS].reverse(),
        allowedDeploymentBlockerIds: [...ALLOWED_DEPLOYMENT_BLOCKERS].reverse(),
      },
      operationDomains: [...operationDomains()].reverse(),
      deploymentConfiguration: {
        activationBlockerIds: ['ESC-ROOT-OWNER', 'ESC-OPS-SECRETS', 'ESC-ROOT-DEPLOYMENT'],
      },
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.operations.trustState, 'inactive');
  assert.equal(resultA.operations.exochainProductionClaim, false);
  assert.equal(resultA.operations.productionOperationsReady, false);
  assert.equal(resultA.operations.baselineOperationsPackReady, true);
  assert.deepEqual(resultA.operations.operationDomainsCovered, REQUIRED_OPERATION_DOMAINS);
  assert.deepEqual(resultA.operations.deploymentBlockerIds, [
    'ESC-OPS-SECRETS',
    'ESC-ROOT-DEPLOYMENT',
    'ESC-ROOT-OWNER',
    'ESC-RUNTIME',
  ]);
  assert.equal(resultA.operations.railway.loginStatus, 'login_required');
  assert.equal(resultA.operations.railway.credentialShared, false);
  assert.equal(resultA.operations.railway.tokenStored, false);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'deployment_operations_readiness');
  assert.deepEqual(resultA, resultB);
});

test('deployment operations readiness fails closed for missing domains broad blockers and production claims', async () => {
  const { evaluateDeploymentOperationsReadiness } = await loadDeploymentOperationsReadiness();

  const result = evaluateDeploymentOperationsReadiness(
    operationsInput({
      readinessCycle: {
        productionTrustClaim: true,
      },
      operationDomains: operationDomains().filter((entry) => entry.domain !== 'secret_scan'),
      deploymentConfiguration: {
        productionEndpointSelected: true,
        activationBlockerIds: ['ESC-OPS-SECRETS', 'ESC-UNBOUNDED-OPS'],
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.operations, null);
  assert.ok(result.reasons.includes('operation_domain_missing:secret_scan'));
  assert.ok(result.reasons.includes('deployment_blocker_not_allowed:ESC-UNBOUNDED-OPS'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('production_endpoint_selected_without_activation'));
});

test('deployment operations readiness separates verified Railway access from credential disclosure', async () => {
  const { ProtectedContentError, evaluateDeploymentOperationsReadiness } = await loadDeploymentOperationsReadiness();

  const verified = evaluateDeploymentOperationsReadiness(
    operationsInput({
      operationDomains: REQUIRED_OPERATION_DOMAINS.map((domain, index) =>
        operationDomain(domain, index, {
          status: 'ready',
          activationBlockerId: null,
          productionActivationOnly: false,
        }),
      ),
      deploymentConfiguration: {
        monitoringDestinationSelected: true,
        onCallOwnerNamed: true,
        secretManagerSelected: true,
        rotationOwnerNamed: true,
        rollbackAuthorityNamed: true,
        productionEndpointSelected: false,
        activationBlockerIds: [],
      },
      railwayAccess: {
        authenticated: true,
        loginRequired: false,
        projectLinked: true,
        workspaceHash: DIGEST_7,
        projectHash: DIGEST_8,
        serviceHash: DIGEST_A,
        environmentHash: DIGEST_B,
        dashboardAccessVerified: true,
      },
    }),
  );

  assert.equal(verified.decision, 'permitted');
  assert.equal(verified.operations.railway.loginStatus, 'verified');
  assert.deepEqual(verified.operations.deploymentBlockerIds, []);
  assert.equal(verified.operations.productionOperationsReady, true);

  const unverified = evaluateDeploymentOperationsReadiness(
    operationsInput({
      railwayAccess: {
        authenticated: true,
        loginRequired: false,
        projectLinked: false,
      },
    }),
  );

  assert.equal(unverified.decision, 'permitted');
  assert.equal(unverified.operations.railway.loginStatus, 'unverified');
  assert.equal(unverified.operations.productionOperationsReady, false);

  assert.throws(
    () =>
      evaluateDeploymentOperationsReadiness(
        operationsInput({
          railwayAccess: {
            accessToken: DIGEST_A,
          },
        }),
      ),
    ProtectedContentError,
  );
});

test('deployment operations readiness validates HLC ordering and AI advisory boundaries', async () => {
  const { evaluateDeploymentOperationsReadiness } = await loadDeploymentOperationsReadiness();

  const validSameTick = evaluateDeploymentOperationsReadiness(
    operationsInput({
      readinessCycle: {
        humanReviewedAtHlc: { physicalMs: 1800002300000, logical: 2 },
        auditRecordedAtHlc: { physicalMs: 1800002300000, logical: 3 },
      },
      humanReview: {
        reviewedAtHlc: { physicalMs: 1800002300000, logical: 2 },
      },
      auditRecord: {
        receiptRecordedAtHlc: { physicalMs: 1800002300000, logical: 3 },
      },
    }),
  );

  assert.equal(validSameTick.decision, 'permitted');

  const invalid = evaluateDeploymentOperationsReadiness(
    operationsInput({
      readinessCycle: {
        validationRecordedAtHlc: { physicalMs: 1800002090000, logical: 0 },
      },
      validationEvidence: {
        recordedAtHlc: { physicalMs: 1800002200000, logical: -1 },
      },
      aiAssistance: {
        finalAuthority: true,
        reviewedByHuman: false,
      },
      humanReview: {
        aiFinalAuthority: true,
        finalAuthority: 'ai',
      },
    }),
  );

  assert.equal(invalid.decision, 'denied');
  assert.ok(invalid.reasons.includes('readiness_cycle_validationRecordedAtHlc_before_evidenceCollectedAtHlc'));
  assert.ok(invalid.reasons.includes('validation_time_invalid'));
  assert.ok(invalid.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(invalid.reasons.includes('ai_human_review_absent'));
  assert.ok(invalid.reasons.includes('human_review_authority_absent'));
});

test('deployment operations readiness handles absent objects as fail-closed denial states', async () => {
  const { evaluateDeploymentOperationsReadiness } = await loadDeploymentOperationsReadiness();

  const result = evaluateDeploymentOperationsReadiness({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['deployment_operations_review'],
      authorityChainHash: DIGEST_A,
    },
  });

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('operations_policy_ref_absent'));
  assert.ok(result.reasons.includes('readiness_cycle_ref_absent'));
  assert.ok(result.reasons.includes('operation_domains_absent'));
  assert.ok(result.reasons.includes('deployment_configuration_absent'));
  assert.ok(result.reasons.includes('railway_access_absent'));
  assert.ok(result.reasons.includes('validation_evidence_absent'));
  assert.ok(result.reasons.includes('human_review_absent'));
  assert.ok(result.reasons.includes('operations_audit_record_ref_absent'));
});

test('deployment operations readiness rejects raw operations content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateDeploymentOperationsReadiness } = await loadDeploymentOperationsReadiness();

  const inert = operationsInput({
    operationDomains: [
      operationDomain('dependency_audit', 0, {
        rawRunbookText: false,
      }),
      ...operationDomains().slice(1),
    ],
    deploymentConfiguration: {
      apiKey: {},
    },
  });

  assert.equal(evaluateDeploymentOperationsReadiness(inert).decision, 'permitted');

  assert.throws(
    () =>
      evaluateDeploymentOperationsReadiness(
        operationsInput({
          operationDomains: [
            operationDomain('dependency_audit', 0, {
              rawRunbookText: ['unredacted deployment runbook body stays external'],
            }),
            ...operationDomains().slice(1),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentOperationsReadiness(
        operationsInput({
          deploymentConfiguration: {
            freeTextNote: 'Participant Alice Example must not appear in operations notes.',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentOperationsReadiness(
        operationsInput({
          deploymentConfiguration: {
            apiKey: 'cm_live_secret_value',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentOperationsReadiness(
        operationsInput({
          humanReview: {
            secret: 7,
          },
        }),
      ),
    ProtectedContentError,
  );
});
