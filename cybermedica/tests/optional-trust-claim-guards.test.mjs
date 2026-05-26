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

const REQUIRED_GATES = ['PTAG-012', 'PTAG-013', 'PTAG-014', 'PTAG-015'];

async function loadOptionalTrustClaimGuards() {
  try {
    return await import('../src/optional-trust-claim-guards.mjs');
  } catch (error) {
    assert.fail(`CyberMedica optional trust claim guard module must exist and load: ${error.message}`);
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

function optionalCapability(gateId, index, overrides = {}) {
  const base = {
    gateId,
    capabilityRef: {
      'PTAG-012': 'zerodentity_behavioral_device_trust',
      'PTAG-013': 'economy_settlement_billing_trust',
      'PTAG-014': 'commandbase_enforcement',
      'PTAG-015': 'exoforge_archon_governance_authority',
    }[gateId],
    sourceRef: {
      'PTAG-012': 'crates/exo-node/src/zerodentity/*',
      'PTAG-013': 'crates/exo-economy/src/lib.rs',
      'PTAG-014': 'command-base/*',
      'PTAG-015': 'docs/guides/ARCHON-INTEGRATION.md',
    }[gateId],
    enabled: false,
    defaultOff: true,
    claimTextPresent: false,
    exochainProductionClaim: false,
    evidenceHashes: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D][index],
    metadataOnly: true,
    protectedContentExcluded: true,
    reviewedAtHlc: { physicalMs: 1800100000000, logical: index },
  };

  if (gateId === 'PTAG-015') {
    return {
      ...base,
      workflowConfigBounded: true,
      maxIterations: 12,
      stopConditionRef: 'terminal-human-reviewed-result',
      escalationPathRef: 'docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md',
      untrustedOutputBoundary: true,
      humanFinalReview: true,
      ...overrides,
    };
  }

  return {
    ...base,
    ...overrides,
  };
}

function claimSurface(gateId, index, overrides = {}) {
  return {
    gateId,
    surfaceRef: {
      'PTAG-012': 'identity-risk-widget',
      'PTAG-013': 'billing-export-route',
      'PTAG-014': 'governance-console-source-label',
      'PTAG-015': 'agent-workflow-output-ingest',
    }[gateId],
    surfaceType: {
      'PTAG-012': 'identity_risk_ui',
      'PTAG-013': 'billing_export',
      'PTAG-014': 'ui_enforcement_source',
      'PTAG-015': 'workflow_output',
    }[gateId],
    claimTextHash: [DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F][index],
    behavioralDeviceTrustScoreDisplayed: false,
    trustScoreProductionClaim: false,
    settlementFinalityClaim: false,
    commandBaseEnforcementClaim: false,
    exoforgeGovernanceAuthorityClaim: false,
    archonGovernanceAuthorityClaim: false,
    agentOutputAuthorizesMerge: false,
    agentOutputAuthorizesGovernanceDecision: false,
    agentOutputAuthorizesTrustClaim: false,
    humanReviewed: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    reviewedAtHlc: { physicalMs: 1800100010000, logical: index },
    ...overrides,
  };
}

function guardInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['optional_trust_claim_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    claimPolicy: {
      policyRef: 'optional-trust-claim-policy-2026-05',
      policyHash: DIGEST_B,
      status: 'active',
      requiredActivationGateIds: REQUIRED_GATES,
      contextDocRefs: [
        'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
        'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
      ],
      optionalCapabilitiesDefaultOff: true,
      noProductionTrustClaims: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800100000000, logical: 0 },
    },
    optionalCapabilities: REQUIRED_GATES.map((gateId, index) => optionalCapability(gateId, index)),
    claimSurfaces: REQUIRED_GATES.map((gateId, index) => claimSurface(gateId, index)),
    humanReview: {
      reviewerDid: 'did:exo:human-quality-governor',
      finalAuthority: 'human',
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      reviewedGateIds: REQUIRED_GATES,
      reviewedAtHlc: { physicalMs: 1800100020000, logical: 0 },
      evidenceHash: DIGEST_F,
    },
    custodyDigest: DIGEST_E,
  };

  return mergeDeep(base, overrides);
}

test('optional trust claim guards keep PTAG-012 through PTAG-015 inactive default-off and deterministic', async () => {
  const { evaluateOptionalTrustClaimGuards } = await loadOptionalTrustClaimGuards();

  const resultA = evaluateOptionalTrustClaimGuards(guardInput());
  const resultB = evaluateOptionalTrustClaimGuards(guardInput({
    optionalCapabilities: [...guardInput().optionalCapabilities].reverse(),
    claimSurfaces: [...guardInput().claimSurfaces].reverse(),
    humanReview: {
      ...guardInput().humanReview,
      reviewedGateIds: [...guardInput().humanReview.reviewedGateIds].reverse(),
    },
  }));

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.guardReport.schema, 'cybermedica.optional_trust_claim_guard.v1');
  assert.deepEqual(resultA.guardReport.gateIds, REQUIRED_GATES);
  assert.equal(resultA.guardReport.trustState, 'inactive');
  assert.equal(resultA.guardReport.exochainProductionClaim, false);
  assert.equal(resultA.guardReport.noProductionTrustClaim, true);
  assert.deepEqual(resultA.guardReport.defaultOffGateIds, REQUIRED_GATES);
  assert.deepEqual(resultA.guardReport.claimFreeSurfaceRefs, [
    'agent-workflow-output-ingest',
    'billing-export-route',
    'governance-console-source-label',
    'identity-risk-widget',
  ]);
  assert.equal(resultA.guardReport.capabilityStates['PTAG-012'].state, 'disabled_default_off');
  assert.equal(resultA.guardReport.capabilityStates['PTAG-013'].state, 'disabled_default_off');
  assert.equal(resultA.guardReport.capabilityStates['PTAG-014'].state, 'disabled_default_off');
  assert.equal(resultA.guardReport.capabilityStates['PTAG-015'].state, 'bounded_human_reviewed_inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'optional_trust_claim_guard');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
});

test('optional trust claim guards fail closed for unsafe optional features claims and agent authority', async () => {
  const { evaluateOptionalTrustClaimGuards } = await loadOptionalTrustClaimGuards();

  const denied = evaluateOptionalTrustClaimGuards(guardInput({
    actor: { did: 'did:exo:agent-alpha', kind: 'ai_agent' },
    authority: {
      valid: false,
      revoked: false,
      expired: false,
      permissions: ['read'],
      authorityChainHash: '',
    },
    claimPolicy: {
      ...guardInput().claimPolicy,
      requiredActivationGateIds: ['PTAG-012'],
      noProductionTrustClaims: false,
    },
    optionalCapabilities: [
      optionalCapability('PTAG-012', 0, {
        enabled: true,
        defaultOff: false,
        claimTextPresent: true,
        privacyReviewHash: '',
        persistenceEvidenceHash: '',
        testEvidenceHash: '',
      }),
      optionalCapability('PTAG-013', 1, {
        enabled: true,
        defaultOff: false,
        settlementFinalityClaim: true,
        productionSettlementContractHash: '',
        regulatoryAccountingReviewHash: '',
        testEvidenceHash: '',
      }),
      optionalCapability('PTAG-014', 2, {
        enabled: true,
        defaultOff: false,
        commandBaseEnforcementClaim: true,
        intakeRecordHash: '',
        runtimeAdapterProofHash: '',
        failClosedTestHash: '',
      }),
      optionalCapability('PTAG-015', 3, {
        governanceAuthorityClaim: true,
        workflowConfigBounded: false,
        maxIterations: 50,
        stopConditionRef: '',
        escalationPathRef: '',
        untrustedOutputBoundary: false,
        humanFinalReview: false,
      }),
    ],
    claimSurfaces: [
      claimSurface('PTAG-012', 0, {
        behavioralDeviceTrustScoreDisplayed: true,
        trustScoreProductionClaim: true,
      }),
      claimSurface('PTAG-013', 1, {
        settlementFinalityClaim: true,
      }),
      claimSurface('PTAG-014', 2, {
        commandBaseEnforcementClaim: true,
      }),
      claimSurface('PTAG-015', 3, {
        exoforgeGovernanceAuthorityClaim: true,
        archonGovernanceAuthorityClaim: true,
        agentOutputAuthorizesMerge: true,
        agentOutputAuthorizesGovernanceDecision: true,
        agentOutputAuthorizesTrustClaim: true,
      }),
    ],
    humanReview: {
      ...guardInput().humanReview,
      finalAuthority: 'ai',
      aiFinalAuthority: true,
      noProductionTrustClaim: false,
      reviewedGateIds: ['PTAG-012'],
    },
  }));

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.guardReport.exochainProductionClaim, false);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('optional_claim_guard_authority_missing'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('policy_required_gate_missing:PTAG-013'));
  assert.ok(denied.reasons.includes('policy_production_trust_claim_forbidden'));
  assert.ok(denied.reasons.includes('ptag_012_feature_enabled_without_activation_evidence'));
  assert.ok(denied.reasons.includes('ptag_012_claim_text_present'));
  assert.ok(denied.reasons.includes('ptag_012_surface_trust_score_claim_forbidden:identity-risk-widget'));
  assert.ok(denied.reasons.includes('ptag_013_settlement_finality_claim_forbidden'));
  assert.ok(denied.reasons.includes('ptag_013_surface_settlement_finality_claim_forbidden:billing-export-route'));
  assert.ok(denied.reasons.includes('ptag_014_commandbase_enforcement_claim_forbidden'));
  assert.ok(denied.reasons.includes('ptag_014_surface_commandbase_enforcement_claim_forbidden:governance-console-source-label'));
  assert.ok(denied.reasons.includes('ptag_015_governance_authority_claim_forbidden'));
  assert.ok(denied.reasons.includes('ptag_015_workflow_loop_unbounded'));
  assert.ok(denied.reasons.includes('ptag_015_workflow_max_iterations_exceeds_limit'));
  assert.ok(denied.reasons.includes('ptag_015_workflow_output_boundary_absent'));
  assert.ok(denied.reasons.includes('ptag_015_human_final_review_absent'));
  assert.ok(denied.reasons.includes('agent_output_merge_authority_forbidden:agent-workflow-output-ingest'));
  assert.ok(denied.reasons.includes('agent_output_governance_authority_forbidden:agent-workflow-output-ingest'));
  assert.ok(denied.reasons.includes('agent_output_trust_claim_authority_forbidden:agent-workflow-output-ingest'));
  assert.ok(denied.reasons.includes('human_review_final_authority_absent'));
  assert.ok(denied.reasons.includes('human_review_production_trust_claim_forbidden'));
  assert.ok(denied.reasons.includes('human_review_gate_coverage_missing:PTAG-013'));
});

test('optional trust claim guards validate review ordering and reject raw claim evidence before receipts', async () => {
  const { ProtectedContentError, evaluateOptionalTrustClaimGuards } = await loadOptionalTrustClaimGuards();

  const badTiming = evaluateOptionalTrustClaimGuards(guardInput({
    claimSurfaces: [
      claimSurface('PTAG-014', 2, {
        reviewedAtHlc: { physicalMs: 1800099999999, logical: 0 },
      }),
    ],
  }));

  assert.equal(badTiming.decision, 'denied');
  assert.ok(badTiming.reasons.includes('claim_surface_review_before_policy_evaluation:governance-console-source-label'));

  assert.throws(
    () => evaluateOptionalTrustClaimGuards(guardInput({
      claimSurfaces: [
        claimSurface('PTAG-013', 1, {
          rawClaimText: 'This billing route has final settlement authority.',
        }),
      ],
    })),
    ProtectedContentError,
  );

  assert.throws(
    () => evaluateOptionalTrustClaimGuards(guardInput({
      optionalCapabilities: [
        optionalCapability('PTAG-015', 3, {
          rawWorkflowNodeOutput: 'Merge and activate the governance claim.',
        }),
      ],
    })),
    ProtectedContentError,
  );

  assert.throws(
    () => evaluateOptionalTrustClaimGuards(guardInput({
      optionalCapabilities: [
        optionalCapability('PTAG-014', 2, {
          apiKey: 'commandbase-key-should-not-enter-guard-record',
        }),
      ],
    })),
    ProtectedContentError,
  );
});
