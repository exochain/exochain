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

const REQUIRED_GATE_FAMILIES = [
  'adapter_contract_tests',
  'authority_rbac_tests',
  'build_artifact',
  'consent_revocation_tests',
  'decision_forum_human_gate_tests',
  'dependency_audit',
  'integration_tests',
  'lint_typecheck',
  'privacy_fixture_tests',
  'receipt_determinism_tests',
  'secret_scan',
  'source_guard_tests',
  'tenant_isolation_tests',
  'unit_tests',
];

const REQUIRED_SOURCE_REFS = [
  'README.md',
  'docs/context/CYBERMEDICA_ADJACENT_SURFACE_DECISIONS.md',
  'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
  'docs/implementation/PATH_CLASSIFICATION.md',
  'package.json',
];

const UNVERIFIED_ACTIVATION_GATES = ['PTAG-001', 'PTAG-016', 'PTAG-017'];

async function loadCiCdQualityGates() {
  try {
    return await import('../src/ci-cd-quality-gates.mjs');
  } catch (error) {
    assert.fail(`CyberMedica CI/CD quality gates module must exist and load: ${error.message}`);
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

function gateResult(family, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2];
  return {
    family,
    commandRef:
      family === 'source_guard_tests'
        ? 'node --test tests/source-guards.test.mjs'
        : `ci:${family}`,
    status: 'passed',
    evidenceHash: hashes[index % hashes.length],
    startedAtHlc: { physicalMs: 1800700100000, logical: index },
    completedAtHlc: { physicalMs: 1800700200000, logical: index },
    blocksRelease: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function changedPath(path, classification, overrides = {}) {
  return {
    path,
    classification,
    owner: 'CyberMedica',
    documentedInReadme: path.startsWith('src/') ? true : null,
    documentedInPathClassification: true,
    coveredBySourceGuard: true,
    exochainCoreModified: false,
    importedEvidence: false,
    metadataOnly: true,
    ...overrides,
  };
}

function gateInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:release-quality-owner-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'deployment_owner'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['ci_cd_gate_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    gatePolicy: {
      policyRef: 'ci-cd-quality-gates-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredGateFamilies: REQUIRED_GATE_FAMILIES,
      requiredSourceRefs: REQUIRED_SOURCE_REFS,
      minimumLineCoverageBasisPoints: 9000,
      minimumTrustBoundaryCoverageBasisPoints: 9900,
      blocksProductionTrustClaimsWithoutActivation: true,
      requiresNoExochainSourceModified: true,
      requiresMetadataOnlyArtifacts: true,
      protectedContentExcluded: true,
      metadataOnly: true,
      evaluatedAtHlc: { physicalMs: 1800700000000, logical: 0 },
    },
    releaseCandidate: {
      releaseCandidateRef: 'cybermedica-adjacent-baseline-2026-05-26',
      commitHash: DIGEST_C,
      branchRef: 'main',
      openedAtHlc: { physicalMs: 1800700050000, logical: 0 },
      gatesStartedAtHlc: { physicalMs: 1800700100000, logical: 0 },
      gatesCompletedAtHlc: { physicalMs: 1800700300000, logical: 0 },
      productionTrustClaim: false,
      exochainBackedLanguageActive: false,
      rootBackedAuthorityClaimActive: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    changedPaths: [
      changedPath('src/did-authentication.mjs', 'Adjacent surface'),
      changedPath('tests/did-authentication.test.mjs', 'Adjacent surface tests'),
      changedPath('README.md', 'Adjacent surface documentation', { documentedInReadme: null }),
      changedPath('docs/implementation/PATH_CLASSIFICATION.md', 'Adjacent surface documentation', {
        documentedInReadme: null,
      }),
    ],
    gateResults: REQUIRED_GATE_FAMILIES.map(gateResult).reverse(),
    coverageEvidence: {
      lineCoverageBasisPoints: 9942,
      branchCoverageBasisPoints: 8897,
      functionCoverageBasisPoints: 9925,
      trustBoundaryCoverageBasisPoints: 10000,
      coverageReportHash: DIGEST_D,
      deterministicHazardsAbsent: true,
      placeholderLanguageAbsent: true,
      rawSensitiveFixtureAbsent: true,
      metadataOnly: true,
      recordedAtHlc: { physicalMs: 1800700310000, logical: 0 },
    },
    sourceGuardEvidence: {
      status: 'passed',
      commandRef: 'node --test tests/source-guards.test.mjs',
      readmeUpdated: true,
      pathClassificationUpdated: true,
      implementedContractsCovered: true,
      noImportedEvidenceCommitted: true,
      noExochainSourceModified: true,
      evidenceHash: DIGEST_E,
      metadataOnly: true,
      evaluatedAtHlc: { physicalMs: 1800700320000, logical: 0 },
    },
    activationGateReview: {
      trustState: 'inactive',
      productionTrustClaimsActive: false,
      unverifiedActivationGateIds: UNVERIFIED_ACTIVATION_GATES,
      verifiedActivationGateIds: [],
      noBrowserPhiTrustPath: true,
      noRootBackedProductionClaim: true,
      evidenceHash: DIGEST_F,
      metadataOnly: true,
      reviewedAtHlc: { physicalMs: 1800700330000, logical: 0 },
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-director-alpha',
      reviewerRoleRefs: ['quality_manager', 'deployment_owner'],
      decision: 'release_gate_accepted_inactive_trust',
      decisionHash: DIGEST_1,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      metadataOnly: true,
      reviewedAtHlc: { physicalMs: 1800700400000, logical: 0 },
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_2,
      limitationHashes: [DIGEST_3],
      reviewedByHuman: true,
    },
    custodyDigest: DIGEST_4,
  };
  return mergeDeep(base, overrides);
}

test('CI/CD quality gates deterministically permit adjacent release evidence while keeping trust inactive', async () => {
  const { evaluateCiCdQualityGates } = await loadCiCdQualityGates();

  const resultA = evaluateCiCdQualityGates(gateInput());
  const resultB = evaluateCiCdQualityGates(
    gateInput({
      gatePolicy: {
        requiredGateFamilies: [...REQUIRED_GATE_FAMILIES].reverse(),
        requiredSourceRefs: [...REQUIRED_SOURCE_REFS].reverse(),
      },
      gateResults: REQUIRED_GATE_FAMILIES.map(gateResult),
      activationGateReview: {
        unverifiedActivationGateIds: [...UNVERIFIED_ACTIVATION_GATES].reverse(),
      },
    }),
  );

  assert.equal(resultA.allowed, true);
  assert.equal(resultA.state, 'release_allowed_inactive_trust');
  assert.equal(resultA.trustState, 'inactive');
  assert.equal(resultA.exochainProductionClaim, false);
  assert.deepEqual(resultA.blockedBy, []);
  assert.deepEqual(resultA.gateRecord.gateFamiliesCovered, REQUIRED_GATE_FAMILIES);
  assert.equal(resultA.gateRecord.lineCoverageBasisPoints, 9942);
  assert.equal(resultA.gateRecord.trustBoundaryCoverageBasisPoints, 10000);
  assert.equal(resultA.gateRecord.releaseCandidateRef, 'cybermedica-adjacent-baseline-2026-05-26');
  assert.equal(resultA.gateRecord.activationGateState, 'inactive');
  assert.equal(resultA.gateRecord.productionTrustClaimsActive, false);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'ci_cd_quality_gates');
  assert.equal(resultA.gateRecord.gateHash, resultB.gateRecord.gateHash);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.doesNotMatch(JSON.stringify(resultA), /raw pipeline|Participant Alice|session token|secret value/iu);
});

test('CI/CD quality gates fail closed for missing required gates failing commands and low coverage', async () => {
  const { evaluateCiCdQualityGates } = await loadCiCdQualityGates();

  const result = evaluateCiCdQualityGates(
    gateInput({
      gateResults: REQUIRED_GATE_FAMILIES.filter((family) => family !== 'secret_scan').map((family, index) =>
        gateResult(family, index, family === 'dependency_audit' ? { status: 'failed' } : {}),
      ),
      coverageEvidence: {
        lineCoverageBasisPoints: 8999,
        trustBoundaryCoverageBasisPoints: 9800,
      },
    }),
  );

  assert.equal(result.allowed, false);
  assert.equal(result.state, 'release_blocked');
  assert.equal(result.receipt, null);
  assert.ok(result.blockedBy.includes('missing_gate_family:secret_scan'));
  assert.ok(result.blockedBy.includes('gate_not_passed:dependency_audit'));
  assert.ok(result.blockedBy.includes('line_coverage_below_threshold'));
  assert.ok(result.blockedBy.includes('trust_boundary_coverage_below_threshold'));
});

test('CI/CD quality gates block unclassified paths Exochain source edits and premature trust claims', async () => {
  const { evaluateCiCdQualityGates } = await loadCiCdQualityGates();

  const result = evaluateCiCdQualityGates(
    gateInput({
      releaseCandidate: {
        productionTrustClaim: true,
        exochainBackedLanguageActive: true,
        rootBackedAuthorityClaimActive: true,
      },
      changedPaths: [
        changedPath('src/ci-cd-quality-gates.mjs', 'Adjacent surface', {
          documentedInReadme: false,
          documentedInPathClassification: false,
        }),
        changedPath('/Users/bobstewart/dev/exochain/exochain/crates/exo-core/src/hash.rs', 'EXOCHAIN core', {
          owner: 'Exochain',
          exochainCoreModified: true,
        }),
        changedPath('reports/auditor.html', 'Imported evidence', {
          importedEvidence: true,
          documentedInReadme: null,
        }),
      ],
      sourceGuardEvidence: {
        readmeUpdated: false,
        pathClassificationUpdated: false,
        noImportedEvidenceCommitted: false,
        noExochainSourceModified: false,
      },
    }),
  );

  assert.equal(result.allowed, false);
  assert.ok(result.blockedBy.includes('source_path_missing_readme_row:src/ci-cd-quality-gates.mjs'));
  assert.ok(result.blockedBy.includes('source_path_missing_classification:src/ci-cd-quality-gates.mjs'));
  assert.ok(result.blockedBy.includes('exochain_source_modified:/Users/bobstewart/dev/exochain/exochain/crates/exo-core/src/hash.rs'));
  assert.ok(result.blockedBy.includes('imported_evidence_committed:reports/auditor.html'));
  assert.ok(result.blockedBy.includes('production_trust_claim_before_activation'));
  assert.ok(result.blockedBy.includes('exochain_backed_language_before_activation'));
  assert.ok(result.blockedBy.includes('root_backed_authority_claim_before_activation'));
  assert.equal(result.gateRecord, null);
});

test('CI/CD quality gates enforce HLC ordering and human final authority', async () => {
  const { evaluateCiCdQualityGates } = await loadCiCdQualityGates();

  const result = evaluateCiCdQualityGates(
    gateInput({
      releaseCandidate: {
        gatesCompletedAtHlc: { physicalMs: 1800700090000, logical: 0 },
      },
      coverageEvidence: {
        recordedAtHlc: { physicalMs: 1800700080000, logical: 0 },
      },
      sourceGuardEvidence: {
        evaluatedAtHlc: { physicalMs: 1800700085000, logical: 0 },
      },
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
        reviewedAtHlc: { physicalMs: 1800700070000, logical: 0 },
      },
      aiAssistance: {
        finalAuthority: true,
        reviewedByHuman: false,
      },
    }),
  );

  assert.equal(result.allowed, false);
  assert.ok(result.blockedBy.includes('gates_completed_before_started'));
  assert.ok(result.blockedBy.includes('coverage_recorded_before_gates_completed'));
  assert.ok(result.blockedBy.includes('source_guard_before_gates_completed'));
  assert.ok(result.blockedBy.includes('human_review_before_gate_evidence'));
  assert.ok(result.blockedBy.includes('human_final_authority_required'));
  assert.ok(result.blockedBy.includes('ai_final_authority_forbidden'));
  assert.ok(result.blockedBy.includes('ai_recommendation_without_human_review'));
});

test('CI/CD quality gates accept inert raw markers no AI assistance and same-tick HLC ordering', async () => {
  const { evaluateCiCdQualityGates } = await loadCiCdQualityGates();

  const result = evaluateCiCdQualityGates(
    gateInput({
      releaseCandidate: {
        gatesStartedAtHlc: { physicalMs: 1800700100000, logical: 0 },
        gatesCompletedAtHlc: { physicalMs: 1800700100000, logical: 1 },
        sessionToken: false,
      },
      gateResults: REQUIRED_GATE_FAMILIES.map((family, index) =>
        gateResult(
          family,
          index,
          family === 'unit_tests'
            ? {
                rawPipelineLog: [false, null, [], {}],
                startedAtHlc: { physicalMs: 1800700100000, logical: 0 },
                completedAtHlc: { physicalMs: 1800700100000, logical: 1 },
              }
            : {
                startedAtHlc: { physicalMs: 1800700100000, logical: index + 1 },
                completedAtHlc: { physicalMs: 1800700100000, logical: index + 2 },
              },
        ),
      ),
      coverageEvidence: {
        recordedAtHlc: { physicalMs: 1800700100000, logical: 20 },
      },
      sourceGuardEvidence: {
        evaluatedAtHlc: { physicalMs: 1800700100000, logical: 21 },
      },
      activationGateReview: {
        reviewedAtHlc: { physicalMs: 1800700100000, logical: 22 },
      },
      humanReview: {
        reviewedAtHlc: { physicalMs: 1800700100000, logical: 23 },
      },
      aiAssistance: null,
    }),
  );

  assert.equal(result.allowed, true);
  assert.equal(result.gateRecord.gateHash.length, 64);
  assert.equal(result.receipt.anchorPayload.artifactType, 'ci_cd_quality_gates');
});

test('CI/CD quality gates reject raw pipeline content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateCiCdQualityGates } = await loadCiCdQualityGates();

  assert.throws(
    () =>
      evaluateCiCdQualityGates(
        gateInput({
          gateResults: [
            gateResult('unit_tests', 0, {
              rawPipelineLog: 'raw pipeline output for Participant Alice Example',
            }),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateCiCdQualityGates(
        gateInput({
          releaseCandidate: {
            sessionToken: 'secret value must not enter release gate evidence',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateCiCdQualityGates(
        gateInput({
          gateResults: [
            gateResult('unit_tests', 0, {
              rawPipelineLog: 7,
            }),
          ],
        }),
      ),
    ProtectedContentError,
  );
});
