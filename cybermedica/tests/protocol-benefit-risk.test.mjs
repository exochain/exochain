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

const REQUIRED_BENEFIT_DOMAINS = [
  'data_integrity_value',
  'participant_rights',
  'participant_safety',
  'participant_wellbeing',
  'post_termination_support',
  'protocol_fit',
  'risk_mitigation',
  'scientific_social_value',
];

const REQUIRED_PROTECTION_DOMAINS = [
  'claims_exposure',
  'emergency_waiver_controls',
  'insurance_coverage',
  'malpractice_negligence',
  'non_waiver_legal_rights',
  'participant_compensation',
  'privacy_minimization',
  'recruitment_non_coercion',
];

async function loadProtocolBenefitRisk() {
  try {
    return await import('../src/protocol-benefit-risk.mjs');
  } catch (error) {
    assert.fail(`CyberMedica protocol benefit-risk module must exist and load: ${error.message}`);
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

function benefitDomain(domain, index, overrides = {}) {
  const digestCycle = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F];
  const conditional = domain === 'participant_wellbeing';
  const base = {
    domain,
    status: conditional ? 'supported_with_conditions' : 'supported',
    evidenceHash: digestCycle[index % digestCycle.length],
    benefitStatementHash: digestCycle[(index + 1) % digestCycle.length],
    participantRelevanceHash: digestCycle[(index + 2) % digestCycle.length],
    limitationHash: digestCycle[(index + 3) % digestCycle.length],
    ownerDid: `did:exo:${domain.replaceAll('_', '-')}-benefit-owner-alpha`,
    reviewedAtHlc: { physicalMs: 1803600000000 + index, logical: 0 },
    conditionRef: conditional ? 'BEN-COND-WELLBEING-001' : null,
    mitigationHash: conditional ? digestCycle[(index + 4) % digestCycle.length] : null,
    metadataOnly: true,
    protectedContentExcluded: true,
  };
  return { ...base, ...overrides };
}

function protectionDomain(domain, index, overrides = {}) {
  const digestCycle = [DIGEST_F, DIGEST_E, DIGEST_D, DIGEST_C, DIGEST_B, DIGEST_A];
  const conditional = domain === 'privacy_minimization';
  const base = {
    domain,
    status: conditional ? 'ready_with_conditions' : 'ready',
    evidenceHash: digestCycle[index % digestCycle.length],
    controlHash: digestCycle[(index + 1) % digestCycle.length],
    ownerDid: `did:exo:${domain.replaceAll('_', '-')}-protection-owner-alpha`,
    reviewedAtHlc: { physicalMs: 1803600000100 + index, logical: 0 },
    conditionRef: conditional ? 'PROTECT-COND-PRIVACY-001' : null,
    mitigationHash: conditional ? digestCycle[(index + 2) % digestCycle.length] : null,
    metadataOnly: true,
    protectedContentExcluded: true,
  };
  return { ...base, ...overrides };
}

function benefitRiskInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:principal-investigator-alpha',
      kind: 'human',
      roleRefs: ['principal_investigator', 'quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['assess_protocol_benefit_risk', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    benefitRiskPolicy: {
      policyRef: 'protocol-benefit-risk-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredBenefitDomains: REQUIRED_BENEFIT_DOMAINS,
      requiredProtectionDomains: REQUIRED_PROTECTION_DOMAINS,
      minimumBenefitCoverageBasisPoints: 10_000,
      minimumProtectionCoverageBasisPoints: 10_000,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1803000000000, logical: 0 },
      productionTrustClaim: false,
    },
    protocolContext: {
      protocolRef: 'protocol-cardiac-alpha',
      studyRef: 'study-cardiac-alpha',
      siteRef: 'site-alpha',
      sponsorRef: 'sponsor-alpha',
      croRef: 'cro-alpha',
      protocolVersionHash: DIGEST_C,
      populationFitHash: DIGEST_D,
      benefitRiskMatrixHash: DIGEST_E,
      createdAtHlc: { physicalMs: 1803100000000, logical: 0 },
      approvedAtHlc: { physicalMs: 1803500000000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    benefitDomains: REQUIRED_BENEFIT_DOMAINS.map((domain, index) => benefitDomain(domain, index)),
    protectionDomains: REQUIRED_PROTECTION_DOMAINS.map((domain, index) => protectionDomain(domain, index)),
    residualRiskReview: {
      reviewRef: 'benefit-risk-residual-review-alpha',
      residualRiskStatus: 'accepted_with_conditions',
      criticalResidualRiskCount: 0,
      highResidualRiskCount: 1,
      unmitigatedRiskCount: 0,
      highRiskConditionRefs: ['BENEFIT-RISK-HIGH-RISK-COND-001'],
      acceptedByDid: 'did:exo:principal-investigator-alpha',
      acceptanceRationaleHash: DIGEST_F,
      reviewedAtHlc: { physicalMs: 1803700000000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    dependencies: {
      protocolFeasibilityRef: 'protocol-feasibility-alpha',
      startupRiskAssessmentRef: 'startup-risk-alpha',
      insuranceClaimsReadinessRef: 'insurance-claims-alpha',
      consentMaterialsRef: 'consent-materials-alpha',
      independentEthicsApprovalRef: 'ethics-approval-alpha',
      evidenceHashes: [DIGEST_A, DIGEST_B, DIGEST_C],
      metadataOnly: true,
    },
    review: {
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-benefit-risk-alpha',
        workflowReceiptId: 'df-workflow-benefit-risk-alpha',
      },
      evidenceBundle: { complete: true, phiBoundaryAttested: true },
      finalAuthority: 'human',
      aiFinalAuthority: false,
    },
    custodyDigest: DIGEST_D,
  };
  return mergeDeep(base, overrides);
}

test('protocol benefit-risk review creates deterministic inactive acceptance receipts', async () => {
  const { evaluateProtocolBenefitRisk } = await loadProtocolBenefitRisk();

  const resultA = evaluateProtocolBenefitRisk(benefitRiskInput());
  const resultB = evaluateProtocolBenefitRisk({
    ...benefitRiskInput(),
    benefitRiskPolicy: {
      ...benefitRiskInput().benefitRiskPolicy,
      requiredBenefitDomains: [...REQUIRED_BENEFIT_DOMAINS].reverse(),
      requiredProtectionDomains: [...REQUIRED_PROTECTION_DOMAINS].reverse(),
    },
    benefitDomains: [...benefitRiskInput().benefitDomains].reverse(),
    protectionDomains: [...benefitRiskInput().protectionDomains].reverse(),
    dependencies: {
      ...benefitRiskInput().dependencies,
      evidenceHashes: [...benefitRiskInput().dependencies.evidenceHashes].reverse(),
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.protocolBenefitRisk.acceptanceStatus, 'benefit_risk_accepted_with_conditions');
  assert.equal(resultA.protocolBenefitRisk.benefitCoverageBasisPoints, 10_000);
  assert.equal(resultA.protocolBenefitRisk.protectionCoverageBasisPoints, 10_000);
  assert.deepEqual(resultA.protocolBenefitRisk.benefitDomainsCovered, REQUIRED_BENEFIT_DOMAINS);
  assert.deepEqual(resultA.protocolBenefitRisk.protectionDomainsCovered, REQUIRED_PROTECTION_DOMAINS);
  assert.deepEqual(resultA.protocolBenefitRisk.conditionRefs, [
    'BEN-COND-WELLBEING-001',
    'BENEFIT-RISK-HIGH-RISK-COND-001',
    'PROTECT-COND-PRIVACY-001',
  ]);
  assert.equal(resultA.protocolBenefitRisk.exochainProductionClaim, false);
  assert.equal(resultA.protocolBenefitRisk.aiFinalAuthority, false);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'protocol_benefit_risk');
  assert.equal(resultA.protocolBenefitRisk.acceptanceId, resultB.protocolBenefitRisk.acceptanceId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.doesNotMatch(JSON.stringify(resultA), /protocol body|Participant Alice|medical history/iu);
});

test('protocol benefit-risk review fails closed for missing domains and unresolved residual risk', async () => {
  const { evaluateProtocolBenefitRisk } = await loadProtocolBenefitRisk();

  const result = evaluateProtocolBenefitRisk({
    ...benefitRiskInput(),
    benefitDomains: benefitRiskInput().benefitDomains.filter((row) => row.domain !== 'participant_wellbeing'),
    protectionDomains: benefitRiskInput()
      .protectionDomains
      .filter((row) => row.domain !== 'malpractice_negligence')
      .map((row) =>
        row.domain === 'insurance_coverage'
          ? { ...row, status: 'not_ready', evidenceHash: '', mitigationHash: '' }
          : row,
      ),
    residualRiskReview: {
      ...benefitRiskInput().residualRiskReview,
      residualRiskStatus: 'unacceptable',
      criticalResidualRiskCount: 1,
      unmitigatedRiskCount: 1,
      highRiskConditionRefs: [],
    },
  });

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.equal(result.protocolBenefitRisk.acceptanceStatus, 'benefit_risk_not_accepted');
  assert.ok(result.reasons.includes('required_benefit_domain_missing:participant_wellbeing'));
  assert.ok(result.reasons.includes('required_protection_domain_missing:malpractice_negligence'));
  assert.ok(result.reasons.includes('protection_domain_not_ready:insurance_coverage'));
  assert.ok(result.reasons.includes('critical_residual_risk_open'));
  assert.ok(result.reasons.includes('unmitigated_risk_open'));
  assert.ok(result.reasons.includes('residual_risk_unacceptable'));
});

test('protocol benefit-risk review requires dependencies human governance and no production trust claim', async () => {
  const { evaluateProtocolBenefitRisk } = await loadProtocolBenefitRisk();

  const result = evaluateProtocolBenefitRisk({
    ...benefitRiskInput(),
    actor: { did: 'did:exo:ai-benefit-risk-agent-alpha', kind: 'ai_agent' },
    authority: { valid: true, revoked: false, expired: false, permissions: [], authorityChainHash: '' },
    benefitRiskPolicy: {
      ...benefitRiskInput().benefitRiskPolicy,
      productionTrustClaim: true,
    },
    dependencies: {
      ...benefitRiskInput().dependencies,
      protocolFeasibilityRef: '',
      insuranceClaimsReadinessRef: '',
      metadataOnly: false,
    },
    review: {
      decisionForum: {
        verified: false,
        state: 'draft',
        humanGate: { verified: false },
        quorum: { status: 'not_met' },
        openChallenge: true,
        decisionId: '',
        workflowReceiptId: '',
      },
      evidenceBundle: { complete: false, phiBoundaryAttested: false },
      finalAuthority: 'ai',
      aiFinalAuthority: true,
    },
  });

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('human_actor_required'));
  assert.ok(result.reasons.includes('protocol_benefit_risk_authority_missing'));
  assert.ok(result.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('protocol_feasibility_ref_absent'));
  assert.ok(result.reasons.includes('insurance_claims_readiness_ref_absent'));
  assert.ok(result.reasons.includes('benefit_risk_dependency_metadata_boundary_invalid'));
  assert.ok(result.reasons.includes('decision_forum_unverified'));
  assert.ok(result.reasons.includes('human_final_authority_required'));
});

test('protocol benefit-risk review validates HLC ordering for policy protocol and review evidence', async () => {
  const { evaluateProtocolBenefitRisk } = await loadProtocolBenefitRisk();

  const result = evaluateProtocolBenefitRisk({
    ...benefitRiskInput(),
    benefitRiskPolicy: {
      ...benefitRiskInput().benefitRiskPolicy,
      evaluatedAtHlc: { physicalMs: 1804000000000, logical: 0 },
    },
    protocolContext: {
      ...benefitRiskInput().protocolContext,
      approvedAtHlc: { physicalMs: 1803500000000, logical: 0 },
    },
    benefitDomains: benefitRiskInput().benefitDomains.map((row) =>
      row.domain === 'participant_safety'
        ? { ...row, reviewedAtHlc: { physicalMs: 1803400000000, logical: 0 } }
        : row,
    ),
    residualRiskReview: {
      ...benefitRiskInput().residualRiskReview,
      reviewedAtHlc: { physicalMs: 1803400000000, logical: 0 },
    },
  });

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('protocol_approved_before_policy_evaluation'));
  assert.ok(result.reasons.includes('benefit_domain_review_before_protocol_approval:participant_safety'));
  assert.ok(result.reasons.includes('benefit_risk_review_before_protocol_approval'));
});

test('protocol benefit-risk review rejects raw protocol participant content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateProtocolBenefitRisk } = await loadProtocolBenefitRisk();

  assert.throws(
    () =>
      evaluateProtocolBenefitRisk({
        ...benefitRiskInput(),
        protocolContext: {
          ...benefitRiskInput().protocolContext,
          protocolBody: 'protocol body with Participant Alice and medical history',
        },
      }),
    ProtectedContentError,
  );
  assert.throws(
    () =>
      evaluateProtocolBenefitRisk({
        ...benefitRiskInput(),
        review: {
          ...benefitRiskInput().review,
          serviceToken: 'cm-benefit-risk-secret-token',
        },
      }),
    ProtectedContentError,
  );
});
