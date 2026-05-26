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

const REQUIRED_ARTIFACT_FAMILIES = [
  'activation_gate_register',
  'council_escalation_register',
  'inactive_trust_state',
  'path_classification',
  'release_readiness_matrix',
  'requirement_traceability_matrix',
  'validation_evidence',
];

const ALLOWED_ACTIVATION_BLOCKERS = ['PTAG-001', 'PTAG-008', 'PTAG-015', 'PTAG-016', 'PTAG-017'];

const ALLOWED_BOB_ESCALATIONS = [
  'ESC-HUMAN-PROOFING',
  'ESC-OPS-SECRETS',
  'ESC-ROOT-ARTIFACT-STORE',
  'ESC-ROOT-DEPLOYMENT',
  'ESC-ROOT-OWNER',
  'ESC-ROOT-ROSTER',
  'ESC-RUNTIME',
];

async function loadDeploymentReadinessManifest() {
  try {
    return await import('../src/deployment-readiness-manifest.mjs');
  } catch (error) {
    assert.fail(`CyberMedica deployment readiness manifest module must exist and load: ${error.message}`);
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

function artifact(family, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2];
  return {
    family,
    artifactRef: `artifact-${family}`,
    artifactHash: hashes[index],
    sourceRef:
      family === 'path_classification'
        ? 'docs/implementation/PATH_CLASSIFICATION.md'
        : `docs/context/${family}.md`,
    generatedAtHlc: { physicalMs: 1800001000000, logical: index },
    schemaRef: `cybermedica.${family}.v1`,
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    trustState: 'inactive',
    ...overrides,
  };
}

function manifestArtifacts() {
  return REQUIRED_ARTIFACT_FAMILIES.map((family, index) => artifact(family, index));
}

function activationGate(gateId, status, index, overrides = {}) {
  return {
    gateId,
    status,
    requiredForProductionTrustClaim: true,
    blocksBaselineDevelopment: false,
    productionClaimActive: false,
    evidenceHash: status === 'verified' ? DIGEST_7 : null,
    reviewedAtHlc: { physicalMs: 1800001100000, logical: index },
    metadataOnly: true,
    ...overrides,
  };
}

function manifestInput(overrides = {}) {
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
      permissions: ['deployment_readiness_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    manifestPolicy: {
      policyRef: 'deployment-readiness-manifest-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredArtifactFamilies: REQUIRED_ARTIFACT_FAMILIES,
      allowedActivationBlockerIds: ALLOWED_ACTIVATION_BLOCKERS,
      allowedBobEscalationIds: ALLOWED_BOB_ESCALATIONS,
      requiredSourceRefs: [
        'README.md',
        'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
        'docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md',
        'docs/implementation/PATH_CLASSIFICATION.md',
      ],
      rootVerificationRequiredForTrustClaims: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800000900000, logical: 0 },
    },
    manifestCycle: {
      manifestRef: 'deployment-readiness-manifest-alpha',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      openedAtHlc: { physicalMs: 1800000950000, logical: 0 },
      evidenceImportedAtHlc: { physicalMs: 1800001000000, logical: 8 },
      validationRecordedAtHlc: { physicalMs: 1800001200000, logical: 0 },
      manifestCompiledAtHlc: { physicalMs: 1800001300000, logical: 0 },
      humanReviewedAtHlc: { physicalMs: 1800001400000, logical: 0 },
      auditRecordedAtHlc: { physicalMs: 1800001500000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    artifacts: manifestArtifacts(),
    releaseReadiness: {
      matrixId: 'cmrel-release-readiness-alpha',
      matrixHash: DIGEST_C,
      decision: 'baseline_ready_inactive_trust',
      acceptanceDomainsCovered: ['service_contracts', 'test_validation', 'metadata_only_boundaries'],
      unverifiedProductionGateCount: 16,
      verifiedGateCount: 2,
      noProductionTrustClaim: true,
      metadataOnly: true,
      reviewedAtHlc: { physicalMs: 1800001300000, logical: 1 },
    },
    requirementTraceability: {
      matrixId: 'cmtrace-requirement-traceability-alpha',
      matrixHash: DIGEST_D,
      requirementCount: 13,
      implementedCount: 10,
      activationOnlyBlockerIds: ['PTAG-001', 'PTAG-008', 'PTAG-015'],
      bobEscalationIds: ['ESC-ROOT-ROSTER', 'ESC-ROOT-DEPLOYMENT', 'ESC-RUNTIME'],
      validationCommandRefs: ['npm run quality'],
      noExochainSourceModified: true,
      metadataOnly: true,
      reviewedAtHlc: { physicalMs: 1800001300000, logical: 2 },
    },
    activationGates: [
      activationGate('PTAG-001', 'inactive', 0),
      activationGate('PTAG-008', 'inactive', 1),
      activationGate('PTAG-015', 'inactive', 2),
      activationGate('PTAG-016', 'inactive', 3),
      activationGate('PTAG-017', 'inactive', 4),
    ],
    deploymentConfiguration: {
      topologyRef: 'server-side-gateway-node-baseline',
      topologyHash: DIGEST_E,
      runtimeEndpointSelected: false,
      rootBundleProviderSelected: false,
      secretScopeSeparated: true,
      missingSecretsFailClosed: true,
      browserPhiTrustPathDisabled: true,
      rollbackPathRef: 'disable-production-trust-claims',
      rollbackPathHash: DIGEST_F,
      metadataOnly: true,
      reviewedAtHlc: { physicalMs: 1800001300000, logical: 3 },
    },
    validationEvidence: {
      commandRefs: ['npm test -- --test-reporter=spec', 'npm run quality'],
      commandsPassed: true,
      testCount: 314,
      coverageLineBasisPoints: 9972,
      sourceGuardPassed: true,
      pathClassificationHash: DIGEST_1,
      moduleManifestHash: DIGEST_2,
      testManifestHash: DIGEST_3,
      noExochainSourceModified: true,
      metadataOnly: true,
      recordedAtHlc: { physicalMs: 1800001200000, logical: 0 },
    },
    humanReview: {
      reviewerDid: 'did:exo:site-leader-alpha',
      reviewerRoleRefs: ['site_leader', 'quality_manager'],
      decision: 'manifest_accepted_inactive_trust',
      decisionHash: DIGEST_4,
      noProductionTrustClaim: true,
      activationOnlyBlockersAccepted: true,
      bobEscalationsNarrowed: true,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      reviewedAtHlc: { physicalMs: 1800001400000, logical: 0 },
      metadataOnly: true,
    },
    auditRecord: {
      auditRecordRef: 'deployment-readiness-audit-alpha',
      auditRecordHash: DIGEST_5,
      receiptRecordedAtHlc: { physicalMs: 1800001500000, logical: 0 },
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

test('deployment readiness manifest packages traceability release validation and inactive trust evidence deterministically', async () => {
  const { evaluateDeploymentReadinessManifest } = await loadDeploymentReadinessManifest();

  const resultA = evaluateDeploymentReadinessManifest(manifestInput());
  const resultB = evaluateDeploymentReadinessManifest(
    manifestInput({
      manifestPolicy: {
        requiredArtifactFamilies: [...REQUIRED_ARTIFACT_FAMILIES].reverse(),
        allowedActivationBlockerIds: [...ALLOWED_ACTIVATION_BLOCKERS].reverse(),
        allowedBobEscalationIds: [...ALLOWED_BOB_ESCALATIONS].reverse(),
      },
      artifacts: [...manifestArtifacts()].reverse(),
      requirementTraceability: {
        activationOnlyBlockerIds: ['PTAG-015', 'PTAG-001', 'PTAG-008'],
        bobEscalationIds: ['ESC-RUNTIME', 'ESC-ROOT-ROSTER', 'ESC-ROOT-DEPLOYMENT'],
      },
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.manifest.trustState, 'inactive');
  assert.equal(resultA.manifest.exochainProductionClaim, false);
  assert.equal(resultA.manifest.productionActivationReady, false);
  assert.equal(resultA.manifest.baselineEvidencePackReady, true);
  assert.equal(resultA.manifest.pathClassificationIncluded, true);
  assert.deepEqual(resultA.manifest.artifactFamiliesCovered, REQUIRED_ARTIFACT_FAMILIES);
  assert.deepEqual(resultA.manifest.activationOnlyBlockerIds, ['PTAG-001', 'PTAG-008', 'PTAG-015']);
  assert.deepEqual(resultA.manifest.bobEscalationIds, ['ESC-ROOT-DEPLOYMENT', 'ESC-ROOT-ROSTER', 'ESC-RUNTIME']);
  assert.equal(resultA.manifest.activationSummary.unverifiedProductionGateCount, 5);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'deployment_readiness_manifest');
  assert.deepEqual(resultA, resultB);
});

test('deployment readiness manifest fails closed for missing evidence families and broad escalations', async () => {
  const { evaluateDeploymentReadinessManifest } = await loadDeploymentReadinessManifest();

  const result = evaluateDeploymentReadinessManifest(
    manifestInput({
      artifacts: manifestArtifacts().filter((item) => item.family !== 'path_classification'),
      requirementTraceability: {
        bobEscalationIds: ['ESC-RUNTIME', 'ESC-UNBOUNDED-PRODUCT-SCOPE'],
        activationOnlyBlockerIds: ['PTAG-001', 'PTAG-999'],
      },
      releaseReadiness: {
        noProductionTrustClaim: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.manifest, null);
  assert.ok(result.reasons.includes('artifact_family_missing:path_classification'));
  assert.ok(result.reasons.includes('activation_blocker_not_allowed:PTAG-999'));
  assert.ok(result.reasons.includes('bob_escalation_not_allowed:ESC-UNBOUNDED-PRODUCT-SCOPE'));
  assert.ok(result.reasons.includes('release_readiness_production_claim_forbidden'));
});

test('deployment readiness manifest blocks production activation claims until gates and deployment endpoints verify', async () => {
  const { evaluateDeploymentReadinessManifest } = await loadDeploymentReadinessManifest();

  const result = evaluateDeploymentReadinessManifest(
    manifestInput({
      manifestCycle: {
        productionTrustClaim: true,
      },
      activationGates: [
        activationGate('PTAG-001', 'verified', 0, {
          productionClaimActive: true,
          evidenceHash: DIGEST_A,
        }),
        activationGate('PTAG-008', 'inactive', 1),
      ],
      deploymentConfiguration: {
        secretScopeSeparated: false,
        missingSecretsFailClosed: false,
        browserPhiTrustPathDisabled: false,
      },
      humanReview: {
        decision: 'production_trust_active',
        noProductionTrustClaim: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('activation_gate_active_claim_forbidden:PTAG-001'));
  assert.ok(result.reasons.includes('activation_gate_missing:PTAG-015'));
  assert.ok(result.reasons.includes('secret_scope_not_separated'));
  assert.ok(result.reasons.includes('missing_secret_fail_closed_absent'));
  assert.ok(result.reasons.includes('browser_phi_trust_path_enabled'));
  assert.ok(result.reasons.includes('human_review_production_trust_forbidden'));
});

test('deployment readiness manifest validates HLC ordering and AI advisory boundaries', async () => {
  const { evaluateDeploymentReadinessManifest } = await loadDeploymentReadinessManifest();

  const validSameTick = evaluateDeploymentReadinessManifest(
    manifestInput({
      manifestCycle: {
        humanReviewedAtHlc: { physicalMs: 1800001400000, logical: 2 },
        auditRecordedAtHlc: { physicalMs: 1800001400000, logical: 3 },
      },
      humanReview: {
        reviewedAtHlc: { physicalMs: 1800001400000, logical: 2 },
      },
      auditRecord: {
        receiptRecordedAtHlc: { physicalMs: 1800001400000, logical: 3 },
      },
    }),
  );

  assert.equal(validSameTick.decision, 'permitted');

  const invalid = evaluateDeploymentReadinessManifest(
    manifestInput({
      manifestCycle: {
        manifestCompiledAtHlc: { physicalMs: 1800001190000, logical: 0 },
      },
      validationEvidence: {
        recordedAtHlc: { physicalMs: 1800001200000, logical: -1 },
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
  assert.ok(invalid.reasons.includes('manifest_cycle_manifestCompiledAtHlc_before_validationRecordedAtHlc'));
  assert.ok(invalid.reasons.includes('validation_time_invalid'));
  assert.ok(invalid.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(invalid.reasons.includes('ai_human_review_absent'));
  assert.ok(invalid.reasons.includes('human_review_authority_absent'));
});

test('deployment readiness manifest handles absent objects as fail-closed denial states', async () => {
  const { evaluateDeploymentReadinessManifest } = await loadDeploymentReadinessManifest();

  const result = evaluateDeploymentReadinessManifest({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['deployment_readiness_review'],
      authorityChainHash: DIGEST_A,
    },
  });

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('manifest_policy_ref_absent'));
  assert.ok(result.reasons.includes('manifest_cycle_ref_absent'));
  assert.ok(result.reasons.includes('manifest_artifacts_absent'));
  assert.ok(result.reasons.includes('release_readiness_absent'));
  assert.ok(result.reasons.includes('requirement_traceability_absent'));
  assert.ok(result.reasons.includes('validation_evidence_absent'));
  assert.ok(result.reasons.includes('human_review_absent'));
  assert.ok(result.reasons.includes('manifest_audit_record_ref_absent'));
});

test('deployment readiness manifest rejects raw manifest content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateDeploymentReadinessManifest } = await loadDeploymentReadinessManifest();

  const inert = manifestInput({
    artifacts: [
      artifact('activation_gate_register', 0, { rawManifestContent: false }),
      ...manifestArtifacts().slice(1),
    ],
    deploymentConfiguration: {
      apiKey: {},
    },
  });

  assert.equal(evaluateDeploymentReadinessManifest(inert).decision, 'permitted');

  assert.throws(
    () =>
      evaluateDeploymentReadinessManifest(
        manifestInput({
          artifacts: [
            artifact('activation_gate_register', 0, {
              rawManifestContent: 'full release evidence packet body stays outside receipts',
            }),
            ...manifestArtifacts().slice(1),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentReadinessManifest(
        manifestInput({
          deploymentConfiguration: {
            freeTextNote: 'Participant Alice Example has an unredacted medical record note.',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentReadinessManifest(
        manifestInput({
          deploymentConfiguration: {
            apiKey: 'cm_live_secret_value',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentReadinessManifest(
        manifestInput({
          artifacts: [
            artifact('activation_gate_register', 0, {
              rawManifestContent: ['release evidence packet text stays external'],
            }),
            ...manifestArtifacts().slice(1),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentReadinessManifest(
        manifestInput({
          humanReview: {
            secret: 7,
          },
        }),
      ),
    ProtectedContentError,
  );
});
