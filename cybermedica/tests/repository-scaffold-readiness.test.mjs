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

const CURRENT_ARTIFACT_FAMILIES = [
  'context_docs',
  'contract_tests',
  'dependency_lockfile',
  'implementation_docs',
  'package_manifest',
  'prd_sources',
  'quality_gate',
  'readme',
  'source_contracts',
  'source_guard',
];

const TARGET_ARTIFACT_FAMILIES = [
  'ai_governance_doc',
  'api_surface',
  'app_surface',
  'audit_inspection_guide',
  'docs_architecture',
  'docs_controls',
  'docs_evidence',
  'docs_manuals',
  'docs_policies',
  'docs_procedures',
  'exochain_receipts_doc',
  'migrations',
  'ops_backup_restore',
  'ops_ci',
  'ops_incident_response',
  'ops_monitoring',
  'packages',
  'repository_root',
  'schemas',
  'tests_access_control',
  'tests_ai_governance',
  'tests_e2e',
  'tests_evidence',
  'tests_exochain_receipts',
  'tests_workflow_gates',
  'workflows',
];

const REPOSITORY_CONTROL_IDS = [
  'branch_protection',
  'codeowners',
  'dependency_alerts',
  'private_visibility',
  'required_ci',
  'secret_scanning',
  'separate_secret_scope',
];

async function loadRepositoryScaffoldReadiness() {
  try {
    return await import('../src/repository-scaffold-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica repository scaffold readiness module must exist and load: ${error.message}`);
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

function currentArtifact(family, index, overrides = {}) {
  return {
    family,
    pathRef: `cybermedica/${family.replaceAll('_', '-')}`,
    artifactHash: digestFor(index),
    evidenceHash: digestFor(index + 40),
    implemented: true,
    classified: true,
    coveredBySourceGuard: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    exochainSourceModified: false,
    reviewedAtHlc: { physicalMs: 1806000000000, logical: index },
    ...overrides,
  };
}

function targetArtifact(family, index, overrides = {}) {
  const implemented = [
    'repository_root',
    'docs_architecture',
    'exochain_receipts_doc',
    'tests_access_control',
    'tests_evidence',
    'tests_exochain_receipts',
  ].includes(family);

  return {
    family,
    sourcePrdRef: `cybermedica_2_0_sandy_seven_layer_master_prd.md#6.1:${family}`,
    accountabilityRef: `repository-artifact-${family}`,
    ownerRoleRef: implemented ? 'deployment_owner' : 'product_architect',
    evidenceHash: digestFor(index + 90),
    status: implemented ? 'implemented' : 'contracted',
    blocksProductionReleaseWhenAbsent: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function repositoryControl(controlId, index, overrides = {}) {
  return {
    controlId,
    evidenceHash: digestFor(index + 130),
    status: 'documented_pending_repository_creation',
    requiredBeforeExternalPush: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function repositoryScaffoldInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-cybermedica-alpha',
    targetTenantId: 'tenant-cybermedica-alpha',
    actor: {
      did: 'did:exo:deployment-owner-alpha',
      kind: 'human',
      roleRefs: ['deployment_owner', 'quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['repository_scaffold_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    scaffoldPolicy: {
      policyRef: 'repository-scaffold-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredCurrentArtifactFamilies: CURRENT_ARTIFACT_FAMILIES,
      requiredTargetArtifactFamilies: TARGET_ARTIFACT_FAMILIES,
      requiredRepositoryControls: REPOSITORY_CONTROL_IDS,
      requirePrivateRepositoryBeforePush: true,
      requireNoExochainImport: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1806000000000, logical: 0 },
    },
    currentInventory: {
      inventoryRef: 'cybermedica-current-package-inventory-alpha',
      inventoryHash: DIGEST_C,
      packageRoot: '/Users/bobstewart/dev/exochain/cybermedica',
      status: 'active',
      sourceGuardCommand: 'node --test tests/source-guards.test.mjs',
      qualityGateCommand: 'npm run quality',
      sourceGuardPassed: true,
      qualityGatePassed: true,
      noExochainSourceModified: true,
      noExochainSourceImported: true,
      packagePrivate: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      capturedAtHlc: { physicalMs: 1806000000100, logical: 0 },
      artifacts: CURRENT_ARTIFACT_FAMILIES.map(currentArtifact).reverse(),
    },
    targetStructure: {
      targetRef: 'prd-6-1-recommended-repository-artifact-structure',
      targetHash: DIGEST_D,
      sourcePrdRef: 'cybermedica_2_0_sandy_seven_layer_master_prd.md#6.1',
      allFamiliesAccounted: true,
      appRuntimeActivationRequired: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1806000000200, logical: 0 },
      artifacts: TARGET_ARTIFACT_FAMILIES.map(targetArtifact).reverse(),
    },
    repositoryControls: {
      controlsRef: 'cybermedica-private-repository-controls-alpha',
      controlsHash: DIGEST_E,
      githubRepository: 'github.com/bob-stewart/cybermedica',
      repositoryCreated: false,
      privateVisibilityVerified: false,
      branchProtectionVerified: false,
      requiredCiVerified: false,
      secretScanningVerified: false,
      dependencyAlertsVerified: false,
      codeownersVerified: false,
      separateSecretScopeVerified: true,
      exochainSourceImportBlocked: true,
      controls: REPOSITORY_CONTROL_IDS.map(repositoryControl).reverse(),
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1806000000300, logical: 0 },
    },
    humanReview: {
      reviewerDid: 'did:exo:deployment-owner-alpha',
      reviewerRoleRefs: ['deployment_owner', 'quality_manager'],
      decision: 'scaffold_ready_inactive_trust',
      reviewHash: DIGEST_F,
      reviewedAtHlc: { physicalMs: 1806000000400, logical: 0 },
      aiFinalAuthority: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    validationEvidence: {
      commandRefs: [
        'node --test tests/repository-scaffold-readiness.test.mjs',
        'node --test tests/source-guards.test.mjs',
        'npm run quality',
      ],
      commandsPassed: true,
      sourceGuardPassed: true,
      pathClassificationUpdated: true,
      readmeUpdated: true,
      noExochainSourceModified: true,
      validationHash: DIGEST_1,
      validatedAtHlc: { physicalMs: 1806000000500, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    trustBoundary: {
      trustState: 'inactive',
      exochainProductionClaim: false,
      rootTrustVerified: false,
      runtimeEndpointVerified: false,
      appSurfaceProductionReady: false,
      privateRepositoryPushReady: false,
      protectedContentExcluded: true,
      secretsExcluded: true,
      metadataOnly: true,
    },
    auditRecordRef: 'repository-scaffold-readiness-audit-alpha',
    custodyDigest: DIGEST_2,
  };

  return mergeDeep(base, overrides);
}

test('repository scaffold readiness packages PRD artifact structure as deterministic inactive trust evidence', async () => {
  const { evaluateRepositoryScaffoldReadiness } = await loadRepositoryScaffoldReadiness();

  const resultA = evaluateRepositoryScaffoldReadiness(repositoryScaffoldInput());
  const resultB = evaluateRepositoryScaffoldReadiness(
    repositoryScaffoldInput({
      currentInventory: {
        artifacts: CURRENT_ARTIFACT_FAMILIES.map(currentArtifact),
      },
      targetStructure: {
        artifacts: TARGET_ARTIFACT_FAMILIES.map(targetArtifact),
      },
      repositoryControls: {
        controls: REPOSITORY_CONTROL_IDS.map(repositoryControl),
      },
    }),
  );

  assert.equal(resultA.decision, 'repository_scaffold_ready_inactive_trust');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.repositoryScaffold.trustState, 'inactive');
  assert.equal(resultA.repositoryScaffold.exochainProductionClaim, false);
  assert.equal(resultA.repositoryScaffold.baselineScaffoldReady, true);
  assert.equal(resultA.repositoryScaffold.productionRepositoryReady, false);
  assert.equal(resultA.repositoryScaffold.privateRepositoryPushReady, false);
  assert.deepEqual(resultA.repositoryScaffold.currentArtifactFamiliesCovered, CURRENT_ARTIFACT_FAMILIES);
  assert.deepEqual(resultA.repositoryScaffold.targetArtifactFamiliesAccounted, TARGET_ARTIFACT_FAMILIES);
  assert.deepEqual(resultA.repositoryScaffold.repositoryControlIds, REPOSITORY_CONTROL_IDS);
  assert.deepEqual(resultA.repositoryScaffold.activationBlockerIds, [
    'repo_branch_protection_unverified',
    'repo_codeowners_unverified',
    'repo_dependency_alerts_unverified',
    'repo_private_visibility_unverified',
    'repo_required_ci_unverified',
    'repo_secret_scanning_unverified',
  ]);
  assert.equal(resultA.repositoryScaffold.scaffoldHash, resultB.repositoryScaffold.scaffoldHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'repository_scaffold_readiness');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(resultA), /Participant Alice|client_secret|root signing key/iu);
});

test('repository scaffold readiness fails closed for missing artifact families controls and Exochain source import', async () => {
  const { evaluateRepositoryScaffoldReadiness } = await loadRepositoryScaffoldReadiness();

  const result = evaluateRepositoryScaffoldReadiness(
    repositoryScaffoldInput({
      currentInventory: {
        noExochainSourceImported: false,
        artifacts: CURRENT_ARTIFACT_FAMILIES.filter((family) => family !== 'source_guard').map(currentArtifact),
      },
      targetStructure: {
        artifacts: TARGET_ARTIFACT_FAMILIES.filter((family) => family !== 'ops_monitoring').map(targetArtifact),
      },
      repositoryControls: {
        controls: REPOSITORY_CONTROL_IDS.filter((controlId) => controlId !== 'secret_scanning').map(repositoryControl),
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.repositoryScaffold, null);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('current_artifact_family_missing:source_guard'));
  assert.ok(result.reasons.includes('target_artifact_family_missing:ops_monitoring'));
  assert.ok(result.reasons.includes('repository_control_missing:secret_scanning'));
  assert.ok(result.reasons.includes('exochain_source_import_detected'));
});

test('repository scaffold readiness separates verified private repository controls from documented inactive controls', async () => {
  const { evaluateRepositoryScaffoldReadiness } = await loadRepositoryScaffoldReadiness();

  const verified = evaluateRepositoryScaffoldReadiness(
    repositoryScaffoldInput({
      repositoryControls: {
        repositoryCreated: true,
        privateVisibilityVerified: true,
        branchProtectionVerified: true,
        requiredCiVerified: true,
        secretScanningVerified: true,
        dependencyAlertsVerified: true,
        codeownersVerified: true,
        separateSecretScopeVerified: true,
        controls: REPOSITORY_CONTROL_IDS.map((controlId, index) =>
          repositoryControl(controlId, index, { status: 'verified' }),
        ),
      },
      trustBoundary: {
        privateRepositoryPushReady: true,
      },
    }),
  );

  assert.equal(verified.decision, 'repository_scaffold_ready_inactive_trust');
  assert.equal(verified.repositoryScaffold.productionRepositoryReady, true);
  assert.equal(verified.repositoryScaffold.privateRepositoryPushReady, true);
  assert.deepEqual(verified.repositoryScaffold.activationBlockerIds, []);
  assert.equal(verified.repositoryScaffold.exochainProductionClaim, false);

  const falseClaim = evaluateRepositoryScaffoldReadiness(
    repositoryScaffoldInput({
      repositoryControls: {
        repositoryCreated: false,
        privateVisibilityVerified: false,
      },
      trustBoundary: {
        privateRepositoryPushReady: true,
      },
    }),
  );

  assert.equal(falseClaim.decision, 'denied');
  assert.ok(falseClaim.reasons.includes('private_repository_push_ready_claim_unverified'));
});

test('repository scaffold readiness validates HLC ordering and AI advisory limits', async () => {
  const { evaluateRepositoryScaffoldReadiness } = await loadRepositoryScaffoldReadiness();

  const invalidTime = evaluateRepositoryScaffoldReadiness(
    repositoryScaffoldInput({
      humanReview: {
        reviewedAtHlc: { physicalMs: 1805999999999, logical: 0 },
      },
    }),
  );

  assert.equal(invalidTime.decision, 'denied');
  assert.ok(invalidTime.reasons.includes('human_review_before_repository_controls'));

  const aiFinal = evaluateRepositoryScaffoldReadiness(
    repositoryScaffoldInput({
      actor: {
        kind: 'ai_agent',
      },
      humanReview: {
        aiFinalAuthority: true,
      },
    }),
  );

  assert.equal(aiFinal.decision, 'denied');
  assert.ok(aiFinal.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(aiFinal.reasons.includes('human_repository_reviewer_required'));
});

test('repository scaffold readiness handles absent objects as fail-closed denial states', async () => {
  const { evaluateRepositoryScaffoldReadiness } = await loadRepositoryScaffoldReadiness();

  const result = evaluateRepositoryScaffoldReadiness({
    tenantId: 'tenant-cybermedica-alpha',
    targetTenantId: 'tenant-cybermedica-alpha',
    actor: { did: 'did:exo:deployment-owner-alpha', kind: 'human' },
    authority: { valid: true, permissions: ['repository_scaffold_review'], authorityChainHash: DIGEST_A },
  });

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('scaffold_policy_ref_absent'));
  assert.ok(result.reasons.includes('current_inventory_ref_absent'));
  assert.ok(result.reasons.includes('target_structure_ref_absent'));
  assert.ok(result.reasons.includes('repository_controls_ref_absent'));
  assert.ok(result.reasons.includes('human_review_absent'));
  assert.ok(result.reasons.includes('validation_evidence_absent'));
  assert.ok(result.reasons.includes('trust_boundary_absent'));
});

test('repository scaffold readiness rejects raw repository content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateRepositoryScaffoldReadiness } = await loadRepositoryScaffoldReadiness();

  assert.throws(
    () =>
      evaluateRepositoryScaffoldReadiness(
        repositoryScaffoldInput({
          currentInventory: {
            artifacts: [
              ...CURRENT_ARTIFACT_FAMILIES.slice(1).map(currentArtifact),
              currentArtifact('package_manifest', 0, {
                rawRepositoryContent: 'Participant Alice Example must not enter repository readiness receipts.',
              }),
            ],
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateRepositoryScaffoldReadiness(
        repositoryScaffoldInput({
          repositoryControls: {
            clientSecret: 'client_secret=do-not-store',
          },
        }),
      ),
    ProtectedContentError,
  );
});
