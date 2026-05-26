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

async function loadProductionClaimLifting() {
  try {
    return await import('../src/production-claim-lifting.mjs');
  } catch (error) {
    assert.fail(`CyberMedica production claim lifting module must exist and load: ${error.message}`);
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

function claimLiftInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:site-leader-alpha',
      kind: 'human',
      roleRefs: ['site_leader', 'quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['production_claim_lift', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    sourceTruth: {
      exochainSourcePath: '/Users/bobstewart/dev/exochain/exochain',
      branchRef: 'main',
      commitHash: '1234567890abcdef1234567890abcdef12345678',
      repoTruthCommandRef: 'tools/repo_truth.sh --json --list-tests',
      repoTruthHash: DIGEST_B,
      currentAgainstLocalCommit: true,
      workingTreeClean: true,
      noExochainSourceModified: true,
      checkedAtHlc: { physicalMs: 1800010000000, logical: 0 },
      metadataOnly: true,
    },
    runtimePath: {
      runtimePathRef: 'server-side-gateway-node-root-verifier',
      runtimePathHash: DIGEST_C,
      enabled: true,
      serverSideOnly: true,
      browserAuthoritative: false,
      gatewayAdapterVerified: true,
      nodeReceiptPathVerified: true,
      decisionForumPathVerified: true,
      rootVerifierPathVerified: true,
      identifiedAtHlc: { physicalMs: 1800010100000, logical: 0 },
      metadataOnly: true,
    },
    deploymentConfiguration: {
      deploymentConfigRef: 'cybermedica-production-runtime-topology-alpha',
      deploymentConfigHash: DIGEST_D,
      productionEnvironmentIdentified: true,
      endpointRef: 'railway-production-private-endpoint-ref',
      rootBundleProviderRef: 'root-bundle-provider-alpha',
      secretScopeSeparated: true,
      missingSecretsFailClosed: true,
      rollbackDisablementRef: 'disable-exochain-production-claim-language',
      identifiedAtHlc: { physicalMs: 1800010200000, logical: 0 },
      metadataOnly: true,
    },
    adapterBoundary: {
      boundaryRef: 'adapter-boundary-alpha',
      boundaryHash: DIGEST_E,
      cannotSimulateCoreOutcome: true,
      cannotCacheCoreOutcome: true,
      cannotOverrideCoreOutcome: true,
      failsClosedOnUnavailable: true,
      failsClosedOnReject: true,
      failsClosedOnTimeout: true,
      failsClosedOnMalformed: true,
      immutableExternalReceiptRequired: true,
      verifiedAtHlc: { physicalMs: 1800010300000, logical: 0 },
      metadataOnly: true,
    },
    testMatrix: {
      matrixRef: 'claim-lift-test-matrix-alpha',
      matrixHash: DIGEST_F,
      positiveCasePassed: true,
      negativeCasePassed: true,
      unavailableCasePassed: true,
      malformedCasePassed: true,
      timeoutCasePassed: true,
      crossTenantCasePassed: true,
      privacyNonAnchoringCasePassed: true,
      commandRefs: ['npm run quality', 'cargo test --workspace'],
      testsRecordedAtHlc: { physicalMs: 1800010400000, logical: 0 },
      metadataOnly: true,
    },
    privacyBoundary: {
      privacyBoundaryRef: 'claim-lift-privacy-boundary-alpha',
      privacyBoundaryHash: DIGEST_1,
      noRawSensitiveInReceipts: true,
      noRawSensitiveInDag: true,
      noRawSensitiveInLogs: true,
      noRawSensitiveInTelemetry: true,
      noRawSensitiveInHealth: true,
      noRawSensitiveInDebug: true,
      noRawSensitiveInExports: true,
      fixtureScanPassed: true,
      classificationHash: DIGEST_2,
      scannedAtHlc: { physicalMs: 1800010500000, logical: 0 },
      metadataOnly: true,
    },
    claimMapping: {
      gateId: 'PTAG-001',
      claimTextHash: DIGEST_3,
      mappedArtifactType: 'receipt',
      mappedArtifactHash: DIGEST_4,
      receiptId: 'receipt-root-production-claim-alpha',
      decisionId: null,
      custodyDigest: null,
      governanceOutcomeRef: null,
      noMarketingOverclaim: true,
      mappedAtHlc: { physicalMs: 1800010600000, logical: 0 },
      metadataOnly: true,
    },
    contextReview: {
      reviewRef: 'claim-lift-context-review-alpha',
      reviewHash: DIGEST_5,
      contextRefs: [
        'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
        'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
        'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
      ],
      reviewedAgainstOriginalPrd: true,
      activationGateRegisterReviewed: true,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      reviewerDid: 'did:exo:site-leader-alpha',
      reviewedAtHlc: { physicalMs: 1800010700000, logical: 0 },
      metadataOnly: true,
    },
    humanDecision: {
      decisionRef: 'claim-lift-human-decision-alpha',
      decisionHash: DIGEST_6,
      decision: 'approve_production_claim_lift',
      reviewerDid: 'did:exo:site-leader-alpha',
      finalAuthority: 'human',
      decidedAtHlc: { physicalMs: 1800010800000, logical: 0 },
      metadataOnly: true,
    },
    auditRecord: {
      auditRecordRef: 'claim-lift-audit-alpha',
      auditRecordHash: DIGEST_7,
      receiptRecordedAtHlc: { physicalMs: 1800010900000, logical: 0 },
      metadataOnly: true,
      includesProtectedContent: false,
    },
    custodyDigest: DIGEST_8,
  };
  return mergeDeep(base, overrides);
}

test('production claim lifting criteria verify source runtime deployment tests privacy mapping and human review', async () => {
  const { evaluateProductionClaimLift } = await loadProductionClaimLifting();

  const resultA = evaluateProductionClaimLift(claimLiftInput());
  const resultB = evaluateProductionClaimLift(
    claimLiftInput({
      testMatrix: { commandRefs: ['cargo test --workspace', 'npm run quality'] },
      contextReview: {
        contextRefs: [
          'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
          'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
          'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
        ],
      },
    }),
  );

  assert.equal(resultA.schema, 'cybermedica.production_claim_lift_decision.v1');
  assert.equal(resultA.allowed, true);
  assert.equal(resultA.state, 'verified');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.canLiftProductionClaim, true);
  assert.equal(resultA.exochainProductionClaim, true);
  assert.equal(resultA.claimGateId, 'PTAG-001');
  assert.deepEqual(resultA.blockedBy, []);
  assert.deepEqual(resultA.verifiedCriteria, [
    'adapter_boundary',
    'claim_mapping',
    'context_review',
    'deployment_configuration',
    'privacy_boundary',
    'runtime_path',
    'source_truth',
    'test_matrix',
  ]);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.trustState, 'verified');
  assert.equal(resultA.receipt.exochainProductionClaim, true);
  assert.equal(resultA.receipt.anchorPayload.claimGateId, 'PTAG-001');
  assert.doesNotMatch(JSON.stringify(resultA), /root-backed production authority|Participant Alice|api[_-]?key/iu);
});

test('production claim lifting fails closed for missing criteria without blocking baseline development', async () => {
  const { evaluateProductionClaimLift } = await loadProductionClaimLifting();

  const result = evaluateProductionClaimLift(
    claimLiftInput({
      sourceTruth: {
        currentAgainstLocalCommit: false,
        noExochainSourceModified: false,
      },
      runtimePath: {
        browserAuthoritative: true,
        nodeReceiptPathVerified: false,
      },
      deploymentConfiguration: {
        productionEnvironmentIdentified: false,
        rootBundleProviderRef: '',
      },
      adapterBoundary: {
        cannotCacheCoreOutcome: false,
        failsClosedOnTimeout: false,
      },
      testMatrix: {
        timeoutCasePassed: false,
        crossTenantCasePassed: false,
      },
      privacyBoundary: {
        noRawSensitiveInTelemetry: false,
        fixtureScanPassed: false,
      },
      claimMapping: {
        mappedArtifactType: 'marketing_copy',
        receiptId: '',
        noMarketingOverclaim: false,
      },
      contextReview: {
        reviewedAgainstOriginalPrd: false,
        finalAuthority: 'ai',
        aiFinalAuthority: true,
      },
      humanDecision: {
        decision: 'approve_production_claim_lift',
        finalAuthority: 'ai',
      },
    }),
  );

  assert.equal(result.allowed, false);
  assert.equal(result.state, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.canLiftProductionClaim, false);
  assert.equal(result.exochainProductionClaim, false);
  assert.equal(result.baselineDevelopmentBlocked, false);
  assert.ok(result.blockedBy.includes('source_not_current_against_local_commit'));
  assert.ok(result.blockedBy.includes('exochain_source_modified'));
  assert.ok(result.blockedBy.includes('browser_authoritative_runtime_forbidden'));
  assert.ok(result.blockedBy.includes('node_receipt_path_unverified'));
  assert.ok(result.blockedBy.includes('production_deployment_configuration_absent'));
  assert.ok(result.blockedBy.includes('root_bundle_provider_absent'));
  assert.ok(result.blockedBy.includes('adapter_cached_outcome_possible'));
  assert.ok(result.blockedBy.includes('adapter_timeout_not_fail_closed'));
  assert.ok(result.blockedBy.includes('timeout_case_missing'));
  assert.ok(result.blockedBy.includes('cross_tenant_case_missing'));
  assert.ok(result.blockedBy.includes('telemetry_sensitive_content_boundary_unverified'));
  assert.ok(result.blockedBy.includes('privacy_fixture_scan_failed'));
  assert.ok(result.blockedBy.includes('claim_mapping_artifact_type_unsupported'));
  assert.ok(result.blockedBy.includes('receipt_mapping_absent'));
  assert.ok(result.blockedBy.includes('marketing_overclaim_not_denied'));
  assert.ok(result.blockedBy.includes('context_prd_review_absent'));
  assert.ok(result.blockedBy.includes('ai_final_authority_forbidden'));
  assert.ok(result.blockedBy.includes('human_claim_lift_decision_invalid'));
  assert.equal(result.receipt.trustState, 'inactive');
  assert.equal(result.receipt.exochainProductionClaim, false);
});

test('production claim lifting rejects raw claim text protected content and secret material before receipts', async () => {
  const { ProtectedContentError, evaluateProductionClaimLift } = await loadProductionClaimLifting();

  assert.throws(
    () =>
      evaluateProductionClaimLift(
        claimLiftInput({
          claimMapping: {
            rawClaimText: 'Root-backed production authority for participant Alice Example is active.',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateProductionClaimLift(
        claimLiftInput({
          deploymentConfiguration: {
            accessToken: 'redacted-access-token-placeholder',
          },
        }),
      ),
    ProtectedContentError,
  );
});
