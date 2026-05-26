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

const REQUIRED_COVERAGE_DOMAINS = [
  'clinical_trial_liability',
  'general_liability',
  'malpractice_negligence',
  'participant_injury_compensation',
  'privacy_security_claims',
  'product_handling_liability',
  'professional_liability',
  'sponsor_indemnity',
];

const REQUIRED_REVIEW_DOMAINS = [
  'claims_reporting',
  'coverage_limits',
  'deductible_exposure',
  'exclusions_review',
  'indemnification_alignment',
  'legal_review',
  'non_waiver_non_negligence',
  'participant_compensation',
];

async function loadInsuranceClaimsReadiness() {
  try {
    return await import('../src/insurance-claims-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica insurance claims readiness module must exist and load: ${error.message}`);
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

function coverageDomain(domain, index, overrides = {}) {
  const digestCycle = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F];
  const conditional = domain === 'privacy_security_claims';
  const base = {
    domain,
    status: conditional ? 'covered_with_conditions' : 'covered',
    carrierEvidenceHash: digestCycle[index % digestCycle.length],
    policyCertificateHash: digestCycle[(index + 1) % digestCycle.length],
    coverageLimitHash: digestCycle[(index + 2) % digestCycle.length],
    exclusionReviewHash: digestCycle[(index + 3) % digestCycle.length],
    ownerDid: `did:exo:${domain.replaceAll('_', '-')}-risk-owner-alpha`,
    coverageMinorUnits: 500_000,
    estimatedExposureMinorUnits: 400_000,
    deductibleMinorUnits: 10_000,
    openExclusionRefs: [],
    conditionRef: conditional ? 'INS-COND-PRIVACY-001' : null,
    mitigationHash: conditional ? digestCycle[(index + 4) % digestCycle.length] : null,
    metadataOnly: true,
    protectedContentExcluded: true,
  };
  return { ...base, ...overrides };
}

function coverageDomains() {
  return REQUIRED_COVERAGE_DOMAINS.map((domain, index) => coverageDomain(domain, index));
}

function readinessInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:claims-risk-lead-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'risk_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['assess_insurance_claims_readiness', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    insurancePolicy: {
      policyRef: 'insurance-claims-readiness-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredCoverageDomains: REQUIRED_COVERAGE_DOMAINS,
      requiredReviewDomains: REQUIRED_REVIEW_DOMAINS,
      minimumCoverageBasisPoints: 10_000,
      maximumDeductibleBasisPoints: 500,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1803000000000, logical: 0 },
      productionTrustClaim: false,
    },
    insurancePackage: {
      packageRef: 'insurance-package-cardiac-alpha',
      protocolRef: 'protocol-cardiac-alpha',
      siteRef: 'site-alpha',
      sponsorRef: 'sponsor-alpha',
      croRef: 'cro-alpha',
      status: 'approved_with_conditions',
      currencyCode: 'USD',
      aggregateCoverageMinorUnits: 4_000_000,
      aggregateExposureMinorUnits: 3_200_000,
      certificateBundleHash: DIGEST_C,
      claimsHandlingProcedureHash: DIGEST_D,
      malpracticeReviewHash: DIGEST_E,
      nonWaiverNegligenceReviewHash: DIGEST_F,
      createdAtHlc: { physicalMs: 1801000000000, logical: 0 },
      approvedAtHlc: { physicalMs: 1803000000000, logical: 1 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    coverageDomains: coverageDomains(),
    legalReview: {
      reviewRef: 'legal-insurance-review-alpha',
      reviewDomains: REQUIRED_REVIEW_DOMAINS,
      legalReviewerDid: 'did:exo:legal-reviewer-alpha',
      financeReviewerDid: 'did:exo:finance-reviewer-alpha',
      principalInvestigatorDid: 'did:exo:principal-investigator-alpha',
      participantCompensationPathHash: DIGEST_A,
      claimsEscalationPathHash: DIGEST_B,
      indemnificationMatrixHash: DIGEST_C,
      consentNonWaiverLinkHash: DIGEST_D,
      humanReviewed: true,
      reviewedAtHlc: { physicalMs: 1803000000000, logical: 2 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    dependencies: {
      protocolFeasibilityRef: 'protocol-feasibility-alpha',
      clinicalTrialAgreementRef: 'cta-cardiac-alpha',
      riskAssessmentRef: 'startup-risk-alpha',
      consentMaterialsRef: 'consent-materials-alpha',
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
        decisionId: 'df-insurance-readiness-alpha',
        workflowReceiptId: 'df-workflow-insurance-readiness-alpha',
      },
      evidenceBundle: { complete: true, phiBoundaryAttested: true },
      finalAuthority: 'human',
      aiFinalAuthority: false,
    },
    custodyDigest: DIGEST_E,
  };
  return mergeDeep(base, overrides);
}

test('insurance claims readiness creates deterministic inactive legal readiness receipts', async () => {
  const { evaluateInsuranceClaimsReadiness } = await loadInsuranceClaimsReadiness();

  const resultA = evaluateInsuranceClaimsReadiness(readinessInput());
  const resultB = evaluateInsuranceClaimsReadiness({
    ...readinessInput(),
    insurancePolicy: {
      ...readinessInput().insurancePolicy,
      requiredCoverageDomains: [...REQUIRED_COVERAGE_DOMAINS].reverse(),
      requiredReviewDomains: [...REQUIRED_REVIEW_DOMAINS].reverse(),
    },
    coverageDomains: [...readinessInput().coverageDomains].reverse(),
    legalReview: {
      ...readinessInput().legalReview,
      reviewDomains: [...REQUIRED_REVIEW_DOMAINS].reverse(),
    },
    dependencies: {
      ...readinessInput().dependencies,
      evidenceHashes: [...readinessInput().dependencies.evidenceHashes].reverse(),
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.insuranceReadiness.readinessStatus, 'insurance_claims_ready_with_conditions');
  assert.equal(resultA.insuranceReadiness.aggregateCoverageBasisPoints, 10_000);
  assert.equal(resultA.insuranceReadiness.coverageDomainBasisPoints, 10_000);
  assert.deepEqual(resultA.insuranceReadiness.coveredCoverageDomains, REQUIRED_COVERAGE_DOMAINS);
  assert.deepEqual(resultA.insuranceReadiness.reviewDomainsCovered, REQUIRED_REVIEW_DOMAINS);
  assert.deepEqual(resultA.insuranceReadiness.conditionRefs, ['INS-COND-PRIVACY-001']);
  assert.equal(resultA.insuranceReadiness.exochainProductionClaim, false);
  assert.equal(resultA.insuranceReadiness.aiFinalAuthority, false);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'insurance_claims_readiness');
  assert.equal(resultA.insuranceReadiness.readinessId, resultB.insuranceReadiness.readinessId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.doesNotMatch(JSON.stringify(resultA), /policy body|claim narrative|Participant Alice/iu);
});

test('insurance claims readiness fails closed for coverage gaps exposure deficits and exclusions', async () => {
  const { evaluateInsuranceClaimsReadiness } = await loadInsuranceClaimsReadiness();

  const result = evaluateInsuranceClaimsReadiness({
    ...readinessInput(),
    insurancePackage: {
      aggregateCoverageMinorUnits: 2_000_000,
      aggregateExposureMinorUnits: 3_200_000,
    },
    coverageDomains: coverageDomains()
      .filter((row) => row.domain !== 'participant_injury_compensation')
      .map((row) =>
        row.domain === 'malpractice_negligence'
          ? {
              ...row,
              status: 'not_covered',
              coverageMinorUnits: 250_000,
              estimatedExposureMinorUnits: 500_000,
              openExclusionRefs: ['EXCL-MAL-001'],
            }
          : row,
      ),
  });

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.insuranceReadiness.readinessStatus, 'insurance_claims_not_ready');
  assert.ok(result.reasons.includes('required_coverage_domain_missing:participant_injury_compensation'));
  assert.ok(result.reasons.includes('coverage_domain_not_ready:malpractice_negligence'));
  assert.ok(result.reasons.includes('coverage_amount_below_exposure:malpractice_negligence'));
  assert.ok(result.reasons.includes('open_exclusion_unmitigated:EXCL-MAL-001'));
  assert.ok(result.reasons.includes('aggregate_coverage_below_minimum'));
});

test('insurance claims readiness requires legal review human governance and denies AI authority', async () => {
  const { evaluateInsuranceClaimsReadiness } = await loadInsuranceClaimsReadiness();

  const result = evaluateInsuranceClaimsReadiness(
    readinessInput({
      actor: { did: 'did:exo:ai-risk-agent-alpha', kind: 'ai_agent', roleRefs: ['assistant'] },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['read'],
        authorityChainHash: 'bad',
      },
      legalReview: {
        reviewDomains: ['claims_reporting'],
        legalReviewerDid: '',
        financeReviewerDid: '',
        principalInvestigatorDid: '',
        participantCompensationPathHash: '',
        claimsEscalationPathHash: '',
        indemnificationMatrixHash: '',
        consentNonWaiverLinkHash: '',
        humanReviewed: false,
      },
      review: {
        decisionForum: {
          verified: false,
          state: 'pending',
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
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('insurance_claims_authority_missing'));
  assert.ok(result.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(result.reasons.includes('legal_review_human_review_absent'));
  assert.ok(result.reasons.includes('legal_reviewer_absent'));
  assert.ok(result.reasons.includes('participant_compensation_path_invalid'));
  assert.ok(result.reasons.includes('legal_review_domain_missing:coverage_limits'));
  assert.ok(result.reasons.includes('decision_forum_unverified'));
  assert.ok(result.reasons.includes('human_gate_unverified'));
  assert.ok(result.reasons.includes('quorum_not_met'));
  assert.ok(result.reasons.includes('challenge_open'));
  assert.ok(result.reasons.includes('human_final_authority_required'));
});

test('insurance claims readiness denies invalid metadata timing dependencies and production claims', async () => {
  const { evaluateInsuranceClaimsReadiness } = await loadInsuranceClaimsReadiness();

  const result = evaluateInsuranceClaimsReadiness(
    readinessInput({
      targetTenantId: 'tenant-site-beta',
      insurancePolicy: {
        status: 'retired',
        requiredCoverageDomains: ['clinical_trial_liability', 'unsupported_domain'],
        requiredReviewDomains: ['claims_reporting'],
        minimumCoverageBasisPoints: 20_000,
        maximumDeductibleBasisPoints: -1,
        evaluatedAtHlc: { physicalMs: 1805000000000, logical: 0 },
        metadataOnly: false,
        protectedContentExcluded: false,
        productionTrustClaim: true,
      },
      insurancePackage: {
        status: 'draft',
        currencyCode: 'usd',
        aggregateCoverageMinorUnits: 0,
        aggregateExposureMinorUnits: -1,
        createdAtHlc: { physicalMs: 1806000000000, logical: 0 },
        approvedAtHlc: { physicalMs: 1802000000000, logical: 0 },
        metadataOnly: false,
        protectedContentExcluded: false,
      },
      dependencies: {
        protocolFeasibilityRef: '',
        clinicalTrialAgreementRef: '',
        riskAssessmentRef: '',
        consentMaterialsRef: '',
        evidenceHashes: ['bad'],
        metadataOnly: false,
      },
      custodyDigest: '',
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('tenant_boundary_violation'));
  assert.ok(result.reasons.includes('insurance_policy_not_active'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('insurance_policy_coverage_domain_unsupported:unsupported_domain'));
  assert.ok(result.reasons.includes('minimum_coverage_basis_points_invalid'));
  assert.ok(result.reasons.includes('maximum_deductible_basis_points_invalid'));
  assert.ok(result.reasons.includes('insurance_package_status_not_approved'));
  assert.ok(result.reasons.includes('currency_code_invalid'));
  assert.ok(result.reasons.includes('insurance_package_approval_order_invalid'));
  assert.ok(result.reasons.includes('insurance_package_approved_before_policy_evaluation'));
  assert.ok(result.reasons.includes('dependency_evidence_hash_invalid'));
  assert.ok(result.reasons.includes('insurance_dependency_metadata_boundary_invalid'));
  assert.ok(result.reasons.includes('custody_digest_invalid'));
});

test('insurance claims readiness refuses raw policy claim content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateInsuranceClaimsReadiness } = await loadInsuranceClaimsReadiness();

  assert.throws(
    () =>
      evaluateInsuranceClaimsReadiness({
        ...readinessInput(),
        insurancePackage: {
          ...readinessInput().insurancePackage,
          insurancePolicyBody: 'policy body with claim narrative and Participant Alice details',
        },
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateInsuranceClaimsReadiness({
        ...readinessInput(),
        legalReview: {
          ...readinessInput().legalReview,
          carrierPortalToken: 'secret-token-value',
        },
      }),
    ProtectedContentError,
  );
});
