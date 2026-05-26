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

const REQUIRED_HANDOFF_DOMAINS = [
  'activation_gate_review',
  'communication_plan',
  'deployment_manifest',
  'migration_backup',
  'monitoring_on_call',
  'operations_runbook',
  'provider_binding',
  'rollback_disablement',
  'runtime_configuration',
  'trust_claim_freeze',
];

const ALLOWED_CUTOVER_BLOCKERS = [
  'ESC-OPS-SECRETS',
  'ESC-ROOT-DEPLOYMENT',
  'ESC-ROOT-OWNER',
  'ESC-RUNTIME',
  'PTAG-001',
  'PTAG-016',
  'PTAG-017',
];

async function loadDeploymentHandoffCutover() {
  try {
    return await import('../src/deployment-handoff-cutover.mjs');
  } catch (error) {
    assert.fail(`CyberMedica deployment handoff cutover module must exist and load: ${error.message}`);
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

function handoffDomain(domain, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4];
  const blocked = ['provider_binding', 'runtime_configuration', 'trust_claim_freeze'].includes(domain);
  return {
    domain,
    status: blocked ? 'activation_blocked' : 'ready',
    evidenceRef: `handoff-evidence-${domain}`,
    evidenceHash: hashes[index],
    ownerDid: `did:exo:${domain.replaceAll('_', '-')}-owner`,
    backupOwnerDid: `did:exo:${domain.replaceAll('_', '-')}-backup`,
    activationBlockerId: blocked ? (domain === 'trust_claim_freeze' ? 'PTAG-001' : 'ESC-RUNTIME') : null,
    blocksBaselineDevelopment: false,
    productionActivationOnly: blocked,
    reviewedByHuman: true,
    reviewedAtHlc: { physicalMs: 1800004100000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function handoffDomains() {
  return REQUIRED_HANDOFF_DOMAINS.map((domain, index) => handoffDomain(domain, index));
}

function handoffInput(overrides = {}) {
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
      permissions: ['deployment_handoff_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    handoffPolicy: {
      policyRef: 'deployment-handoff-cutover-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredHandoffDomains: REQUIRED_HANDOFF_DOMAINS,
      allowedCutoverBlockerIds: ALLOWED_CUTOVER_BLOCKERS,
      rootVerificationRequiredForTrustClaims: true,
      noCredentialDisclosure: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800003900000, logical: 0 },
    },
    handoffCycle: {
      handoffRef: 'deployment-handoff-cutover-alpha',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      openedAtHlc: { physicalMs: 1800003950000, logical: 0 },
      evidenceCollectedAtHlc: { physicalMs: 1800004100000, logical: 10 },
      validationRecordedAtHlc: { physicalMs: 1800004200000, logical: 0 },
      humanReviewedAtHlc: { physicalMs: 1800004300000, logical: 0 },
      auditRecordedAtHlc: { physicalMs: 1800004400000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    handoffDomains: handoffDomains(),
    runtimeConfiguration: {
      configurationRef: 'runtime-config-baseline-alpha',
      configurationHash: DIGEST_C,
      configurationSource: 'railway_env_and_secret_manager',
      environmentManifestHash: DIGEST_D,
      secretScopeHash: DIGEST_E,
      trustFeatureFlagHash: DIGEST_F,
      trustClaimsDisabled: true,
      rootBundleProviderConfigured: false,
      adapterEndpointConfigured: false,
      browserAuthoritativePathEnabled: false,
      missingSecretsFailClosed: true,
      processHealthSeparatedFromTrustReadiness: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1800004100000, logical: 8 },
    },
    handoffArtifacts: {
      deploymentReadinessManifestHash: DIGEST_1,
      deploymentProviderBindingHash: DIGEST_2,
      deploymentOperationsReadinessHash: DIGEST_3,
      releaseReadinessMatrixHash: DIGEST_4,
      requirementTraceabilityHash: DIGEST_5,
      pathClassificationHash: DIGEST_6,
      activationGateRegisterHash: DIGEST_7,
      validationEvidenceHash: DIGEST_8,
      metadataOnly: true,
      linkedAtHlc: { physicalMs: 1800004100000, logical: 9 },
    },
    cutoverPlan: {
      migrationPlanHash: DIGEST_9,
      backupSnapshotHash: DIGEST_A,
      rollbackPlanHash: DIGEST_B,
      disablementPlanHash: DIGEST_C,
      smokeTestPlanHash: DIGEST_D,
      preCutoverChecklistHash: DIGEST_E,
      postCutoverObservationWindowHash: DIGEST_F,
      cutoverOwnerDid: 'did:exo:deployment-owner-alpha',
      backupOwnerDid: 'did:exo:deployment-backup-alpha',
      rollbackAuthorityDid: 'did:exo:rollback-owner-alpha',
      cutoverWindowApproved: false,
      productionEndpointSelected: false,
      activationBlockerIds: ['ESC-OPS-SECRETS', 'ESC-ROOT-DEPLOYMENT', 'ESC-ROOT-OWNER', 'ESC-RUNTIME', 'PTAG-001'],
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1800004100000, logical: 10 },
    },
    validationEvidence: {
      commandRefs: ['npm run quality', 'railway status --json', 'secret scan'],
      commandsPassed: true,
      testCount: 332,
      coverageLineBasisPoints: 9974,
      sourceGuardPassed: true,
      dependencyAuditPassed: true,
      secretScanPassed: true,
      noExochainSourceModified: true,
      metadataOnly: true,
      recordedAtHlc: { physicalMs: 1800004200000, logical: 0 },
    },
    humanReview: {
      reviewerDid: 'did:exo:site-leader-alpha',
      reviewerRoleRefs: ['site_leader', 'quality_manager'],
      decision: 'handoff_ready_inactive_trust',
      decisionHash: DIGEST_1,
      noProductionTrustClaim: true,
      activationBlockersAccepted: true,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      reviewedAtHlc: { physicalMs: 1800004300000, logical: 0 },
      metadataOnly: true,
    },
    auditRecord: {
      auditRecordRef: 'deployment-handoff-cutover-audit-alpha',
      auditRecordHash: DIGEST_2,
      receiptRecordedAtHlc: { physicalMs: 1800004400000, logical: 0 },
      metadataOnly: true,
      includesProtectedContent: false,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_3,
      limitationHashes: [DIGEST_4],
      reviewedByHuman: true,
    },
    custodyDigest: DIGEST_5,
  };
  return mergeDeep(base, overrides);
}

test('deployment handoff cutover records inactive production handoff with explicit blockers', async () => {
  const { evaluateDeploymentHandoffCutover } = await loadDeploymentHandoffCutover();

  const resultA = evaluateDeploymentHandoffCutover(handoffInput());
  const resultB = evaluateDeploymentHandoffCutover(
    handoffInput({
      handoffPolicy: {
        requiredHandoffDomains: [...REQUIRED_HANDOFF_DOMAINS].reverse(),
        allowedCutoverBlockerIds: [...ALLOWED_CUTOVER_BLOCKERS].reverse(),
      },
      handoffDomains: [...handoffDomains()].reverse(),
      cutoverPlan: {
        activationBlockerIds: ['PTAG-001', 'ESC-RUNTIME', 'ESC-ROOT-OWNER', 'ESC-ROOT-DEPLOYMENT', 'ESC-OPS-SECRETS'],
      },
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.handoff.trustState, 'inactive');
  assert.equal(resultA.handoff.exochainProductionClaim, false);
  assert.equal(resultA.handoff.baselineHandoffReady, true);
  assert.equal(resultA.handoff.productionCutoverReady, false);
  assert.deepEqual(resultA.handoff.handoffDomainsCovered, REQUIRED_HANDOFF_DOMAINS);
  assert.deepEqual(resultA.handoff.cutoverBlockerIds, [
    'ESC-OPS-SECRETS',
    'ESC-ROOT-DEPLOYMENT',
    'ESC-ROOT-OWNER',
    'ESC-RUNTIME',
    'PTAG-001',
  ]);
  assert.equal(resultA.handoff.runtimeConfiguration.trustClaimsDisabled, true);
  assert.equal(resultA.handoff.runtimeConfiguration.rootBundleProviderConfigured, false);
  assert.equal(resultA.handoff.cutoverPlan.cutoverWindowApproved, false);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'deployment_handoff_cutover');
  assert.deepEqual(resultA, resultB);
});

test('deployment handoff cutover can mark cutover ready only when runtime and blockers verify', async () => {
  const { evaluateDeploymentHandoffCutover } = await loadDeploymentHandoffCutover();

  const ready = evaluateDeploymentHandoffCutover(
    handoffInput({
      handoffDomains: REQUIRED_HANDOFF_DOMAINS.map((domain, index) =>
        handoffDomain(domain, index, {
          status: 'ready',
          activationBlockerId: null,
          productionActivationOnly: false,
        }),
      ),
      runtimeConfiguration: {
        trustClaimsDisabled: false,
        rootBundleProviderConfigured: true,
        adapterEndpointConfigured: true,
      },
      cutoverPlan: {
        cutoverWindowApproved: true,
        productionEndpointSelected: true,
        activationBlockerIds: [],
      },
      humanReview: {
        decision: 'cutover_ready_verified_runtime',
      },
    }),
  );

  assert.equal(ready.decision, 'permitted');
  assert.equal(ready.handoff.productionCutoverReady, true);
  assert.deepEqual(ready.handoff.cutoverBlockerIds, []);
  assert.equal(ready.handoff.runtimeConfiguration.rootBundleProviderConfigured, true);
  assert.equal(ready.handoff.runtimeConfiguration.adapterEndpointConfigured, true);
  assert.equal(ready.handoff.exochainProductionClaim, false);
  assert.equal(ready.trustState, 'inactive');
});

test('deployment handoff cutover fails closed for missing domains broad blockers and unsafe claims', async () => {
  const { evaluateDeploymentHandoffCutover } = await loadDeploymentHandoffCutover();

  const result = evaluateDeploymentHandoffCutover(
    handoffInput({
      handoffCycle: {
        productionTrustClaim: true,
      },
      handoffDomains: handoffDomains().filter((entry) => entry.domain !== 'rollback_disablement'),
      runtimeConfiguration: {
        browserAuthoritativePathEnabled: true,
      },
      cutoverPlan: {
        cutoverWindowApproved: true,
        productionEndpointSelected: true,
        activationBlockerIds: ['ESC-OPS-SECRETS', 'ESC-UNBOUNDED-CUTOVER'],
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.handoff, null);
  assert.ok(result.reasons.includes('handoff_domain_missing:rollback_disablement'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('browser_authoritative_path_forbidden'));
  assert.ok(result.reasons.includes('production_endpoint_without_verified_runtime'));
  assert.ok(result.reasons.includes('cutover_blocker_not_allowed:ESC-UNBOUNDED-CUTOVER'));
});

test('deployment handoff cutover validates HLC ordering and AI advisory boundaries', async () => {
  const { evaluateDeploymentHandoffCutover } = await loadDeploymentHandoffCutover();

  const sameTick = evaluateDeploymentHandoffCutover(
    handoffInput({
      handoffCycle: {
        humanReviewedAtHlc: { physicalMs: 1800004300000, logical: 2 },
        auditRecordedAtHlc: { physicalMs: 1800004300000, logical: 3 },
      },
      humanReview: {
        reviewedAtHlc: { physicalMs: 1800004300000, logical: 2 },
      },
      auditRecord: {
        receiptRecordedAtHlc: { physicalMs: 1800004300000, logical: 3 },
      },
    }),
  );

  assert.equal(sameTick.decision, 'permitted');

  const invalid = evaluateDeploymentHandoffCutover(
    handoffInput({
      handoffCycle: {
        validationRecordedAtHlc: { physicalMs: 1800004090000, logical: 0 },
      },
      validationEvidence: {
        recordedAtHlc: { physicalMs: 1800004200000, logical: -1 },
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
  assert.ok(invalid.reasons.includes('handoff_cycle_validationRecordedAtHlc_before_evidenceCollectedAtHlc'));
  assert.ok(invalid.reasons.includes('validation_time_invalid'));
  assert.ok(invalid.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(invalid.reasons.includes('ai_human_review_absent'));
  assert.ok(invalid.reasons.includes('human_review_authority_absent'));
});

test('deployment handoff cutover handles absent objects as fail-closed denial states', async () => {
  const { evaluateDeploymentHandoffCutover } = await loadDeploymentHandoffCutover();

  const result = evaluateDeploymentHandoffCutover({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:deployment-owner-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['deployment_handoff_review'],
      authorityChainHash: DIGEST_A,
    },
  });

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('handoff_policy_ref_absent'));
  assert.ok(result.reasons.includes('handoff_cycle_ref_absent'));
  assert.ok(result.reasons.includes('handoff_domains_absent'));
  assert.ok(result.reasons.includes('runtime_configuration_absent'));
  assert.ok(result.reasons.includes('handoff_artifacts_absent'));
  assert.ok(result.reasons.includes('cutover_plan_absent'));
  assert.ok(result.reasons.includes('validation_evidence_absent'));
  assert.ok(result.reasons.includes('human_review_absent'));
  assert.ok(result.reasons.includes('handoff_audit_record_ref_absent'));
});

test('deployment handoff cutover rejects raw handoff content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateDeploymentHandoffCutover } = await loadDeploymentHandoffCutover();

  const inert = handoffInput({
    runtimeConfiguration: {
      rawRuntimeConfig: false,
      apiKey: {},
    },
  });

  assert.equal(evaluateDeploymentHandoffCutover(inert).decision, 'permitted');

  assert.throws(
    () =>
      evaluateDeploymentHandoffCutover(
        handoffInput({
          runtimeConfiguration: {
            rawRuntimeConfig: ['unredacted runtime configuration stays external'],
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentHandoffCutover(
        handoffInput({
          cutoverPlan: {
            rawCutoverNotes: 'Participant Alice Example must not appear in handoff evidence.',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentHandoffCutover(
        handoffInput({
          runtimeConfiguration: {
            apiKey: 'cm_live_secret_value',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentHandoffCutover(
        handoffInput({
          humanReview: {
            token: 7,
          },
        }),
      ),
    ProtectedContentError,
  );
});
