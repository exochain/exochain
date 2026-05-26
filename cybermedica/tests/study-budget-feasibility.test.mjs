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

const REQUIRED_COST_DOMAINS = [
  'data_management_systems',
  'facility_and_equipment',
  'investigational_product_handling',
  'lab_and_imaging',
  'monitoring_and_audit',
  'participant_reimbursement',
  'regulatory_ethics',
  'staff_time',
  'training_startup',
  'vendor_subcontractor',
];

async function loadStudyBudgetFeasibility() {
  try {
    return await import('../src/study-budget-feasibility.mjs');
  } catch (error) {
    assert.fail(`CyberMedica study budget feasibility module must exist and load: ${error.message}`);
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

function costDomain(domain, index, overrides = {}) {
  const digestCycle = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F];
  const base = {
    domain,
    status: domain === 'monitoring_and_audit' ? 'covered_with_conditions' : 'covered',
    budgetMinorUnits: 108_000,
    evidenceHash: digestCycle[index % digestCycle.length],
    ownerDid: `did:exo:${domain.replaceAll('_', '-')}-budget-owner-alpha`,
    rationaleHash: digestCycle[(index + 1) % digestCycle.length],
    varianceBasisPoints: domain === 'monitoring_and_audit' ? 450 : 150,
    conditionRef: domain === 'monitoring_and_audit' ? 'BUDGET-COND-MONITORING-001' : null,
    conditionMitigationHash: domain === 'monitoring_and_audit' ? digestCycle[(index + 2) % digestCycle.length] : null,
    metadataOnly: true,
    protectedContentExcluded: true,
  };
  return { ...base, ...overrides };
}

function costDomainReviews() {
  return REQUIRED_COST_DOMAINS.map((domain, index) => costDomain(domain, index));
}

function budgetInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:finance-quality-lead-alpha',
      kind: 'human',
      roleRefs: ['finance_lead', 'quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['assess_budget_feasibility', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    budgetPolicy: {
      policyRef: 'study-budget-feasibility-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredCostDomains: REQUIRED_COST_DOMAINS,
      requiredReviewDomains: [
        'cashflow',
        'contract_alignment',
        'contingency',
        'cost_domain_coverage',
        'finance_approval',
        'resource_fit',
        'sponsor_payment_terms',
      ],
      minimumContingencyBasisPoints: 1_000,
      minimumMarginBasisPoints: 750,
      maximumDomainVarianceBasisPoints: 1_500,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1802000000000, logical: 0 },
      productionTrustClaim: false,
    },
    studyBudget: {
      budgetRef: 'study-budget-cardiac-alpha',
      protocolRef: 'protocol-cardiac-alpha',
      siteRef: 'site-alpha',
      sponsorRef: 'sponsor-alpha',
      croRef: 'cro-alpha',
      status: 'approved_with_conditions',
      currencyCode: 'USD',
      sponsorBudgetMinorUnits: 1_200_000,
      totalCostMinorUnits: 1_080_000,
      contingencyBasisPoints: 1_200,
      budgetVersionHash: DIGEST_C,
      scheduleOfEventsHash: DIGEST_D,
      coverageMatrixHash: DIGEST_E,
      createdAtHlc: { physicalMs: 1800000000000, logical: 0 },
      approvedAtHlc: { physicalMs: 1802000000000, logical: 1 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    costDomainReviews: costDomainReviews(),
    resourcePlan: {
      resourceNeedHash: DIGEST_A,
      staffingPlanHash: DIGEST_B,
      equipmentPlanHash: DIGEST_C,
      vendorCostPlanHash: DIGEST_D,
      cashflowScheduleHash: DIGEST_E,
      startupFundingConfirmed: true,
      startupFundingEvidenceHash: DIGEST_F,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    dependencies: {
      protocolFeasibilityRef: 'protocol-feasibility-alpha',
      clinicalTrialAgreementRef: 'cta-cardiac-alpha',
      riskAssessmentRef: 'startup-risk-alpha',
      vendorReadinessRef: 'vendor-readiness-alpha',
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
        decisionId: 'df-budget-feasibility-alpha',
        workflowReceiptId: 'df-workflow-budget-feasibility-alpha',
      },
      evidenceBundle: { complete: true, phiBoundaryAttested: true },
      financeReviewerDid: 'did:exo:finance-reviewer-alpha',
      principalInvestigatorDid: 'did:exo:principal-investigator-alpha',
      finalAuthority: 'human',
      aiFinalAuthority: false,
    },
    custodyDigest: DIGEST_D,
  };
  return mergeDeep(base, overrides);
}

test('study budget feasibility creates deterministic inactive finance readiness receipts', async () => {
  const { evaluateStudyBudgetFeasibility } = await loadStudyBudgetFeasibility();

  const resultA = evaluateStudyBudgetFeasibility(budgetInput());
  const resultB = evaluateStudyBudgetFeasibility({
    ...budgetInput(),
    budgetPolicy: {
      ...budgetInput().budgetPolicy,
      requiredCostDomains: [...REQUIRED_COST_DOMAINS].reverse(),
      requiredReviewDomains: [...budgetInput().budgetPolicy.requiredReviewDomains].reverse(),
    },
    costDomainReviews: [...budgetInput().costDomainReviews].reverse(),
    dependencies: {
      ...budgetInput().dependencies,
      evidenceHashes: [...budgetInput().dependencies.evidenceHashes].reverse(),
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.budgetFeasibility.feasibilityStatus, 'financially_feasible_with_conditions');
  assert.equal(resultA.budgetFeasibility.marginBasisPoints, 1_000);
  assert.equal(resultA.budgetFeasibility.contingencyBasisPoints, 1_200);
  assert.equal(resultA.budgetFeasibility.costCoverageBasisPoints, 10_000);
  assert.deepEqual(resultA.budgetFeasibility.coveredCostDomains, REQUIRED_COST_DOMAINS);
  assert.deepEqual(resultA.budgetFeasibility.conditionRefs, ['BUDGET-COND-MONITORING-001']);
  assert.equal(resultA.budgetFeasibility.exochainProductionClaim, false);
  assert.equal(resultA.budgetFeasibility.aiFinalAuthority, false);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'study_budget_feasibility');
  assert.equal(resultA.budgetFeasibility.feasibilityId, resultB.budgetFeasibility.feasibilityId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.doesNotMatch(JSON.stringify(resultA), /sponsor budget text|bank account|Participant Alice/iu);
});

test('study budget feasibility fails closed for missing domains deficits and weak funding posture', async () => {
  const { evaluateStudyBudgetFeasibility } = await loadStudyBudgetFeasibility();
  const input = budgetInput({
    studyBudget: {
      sponsorBudgetMinorUnits: 900_000,
      totalCostMinorUnits: 1_080_000,
      contingencyBasisPoints: 500,
    },
    costDomainReviews: costDomainReviews()
      .filter((row) => row.domain !== 'monitoring_and_audit')
      .map((row) =>
        row.domain === 'lab_and_imaging'
          ? {
              ...row,
              status: 'not_covered',
              evidenceHash: '',
            }
          : row,
      ),
    resourcePlan: {
      startupFundingConfirmed: false,
      startupFundingEvidenceHash: '',
    },
  });

  const denied = evaluateStudyBudgetFeasibility(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.budgetFeasibility.feasibilityStatus, 'not_financially_feasible');
  assert.equal(denied.budgetFeasibility.marginBasisPoints, -2_000);
  assert.ok(denied.reasons.includes('required_cost_domain_missing:monitoring_and_audit'));
  assert.ok(denied.reasons.includes('cost_domain_not_ready:lab_and_imaging'));
  assert.ok(denied.reasons.includes('cost_domain_evidence_invalid:lab_and_imaging'));
  assert.ok(denied.reasons.includes('budget_deficit_detected'));
  assert.ok(denied.reasons.includes('budget_margin_below_minimum'));
  assert.ok(denied.reasons.includes('contingency_below_minimum'));
  assert.ok(denied.reasons.includes('startup_funding_unconfirmed'));
  assert.ok(denied.reasons.includes('startup_funding_evidence_invalid'));
});

test('conditional budget domains require mitigation and human governance evidence', async () => {
  const { evaluateStudyBudgetFeasibility } = await loadStudyBudgetFeasibility();
  const input = budgetInput({
    actor: { did: 'did:exo:ai-finance-agent-alpha', kind: 'ai_agent' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['read'],
      authorityChainHash: 'bad',
    },
    costDomainReviews: costDomainReviews().map((row) =>
      row.domain === 'monitoring_and_audit'
        ? {
            ...row,
            conditionRef: '',
            conditionMitigationHash: '',
            ownerDid: '',
            varianceBasisPoints: 2_500,
          }
        : row,
    ),
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
      financeReviewerDid: '',
      principalInvestigatorDid: '',
      finalAuthority: 'ai',
      aiFinalAuthority: true,
    },
  });

  const denied = evaluateStudyBudgetFeasibility(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('budget_feasibility_authority_missing'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('conditional_cost_domain_condition_ref_absent:monitoring_and_audit'));
  assert.ok(denied.reasons.includes('conditional_cost_domain_mitigation_invalid:monitoring_and_audit'));
  assert.ok(denied.reasons.includes('cost_domain_owner_absent:monitoring_and_audit'));
  assert.ok(denied.reasons.includes('cost_domain_variance_over_limit:monitoring_and_audit'));
  assert.ok(denied.reasons.includes('decision_forum_unverified'));
  assert.ok(denied.reasons.includes('human_gate_unverified'));
  assert.ok(denied.reasons.includes('quorum_not_met'));
  assert.ok(denied.reasons.includes('challenge_open'));
  assert.ok(denied.reasons.includes('finance_reviewer_absent'));
  assert.ok(denied.reasons.includes('principal_investigator_absent'));
  assert.ok(denied.reasons.includes('human_final_authority_required'));
});

test('study budget feasibility denies invalid metadata timing dependency evidence and production claims', async () => {
  const { evaluateStudyBudgetFeasibility } = await loadStudyBudgetFeasibility();
  const input = budgetInput({
    targetTenantId: 'tenant-site-beta',
    budgetPolicy: {
      status: 'retired',
      requiredReviewDomains: ['cashflow'],
      minimumContingencyBasisPoints: 20_000,
      minimumMarginBasisPoints: -1,
      maximumDomainVarianceBasisPoints: 50_000,
      evaluatedAtHlc: { physicalMs: 1803000000000, logical: 0 },
      productionTrustClaim: true,
    },
    studyBudget: {
      status: 'draft',
      currencyCode: 'usd',
      sponsorBudgetMinorUnits: 0,
      totalCostMinorUnits: -1,
      createdAtHlc: { physicalMs: 1804000000000, logical: 0 },
      approvedAtHlc: { physicalMs: 1801000000000, logical: 0 },
      metadataOnly: false,
      protectedContentExcluded: false,
    },
    dependencies: {
      protocolFeasibilityRef: '',
      clinicalTrialAgreementRef: '',
      riskAssessmentRef: '',
      vendorReadinessRef: '',
      evidenceHashes: ['bad'],
      metadataOnly: false,
    },
    custodyDigest: '',
  });

  const denied = evaluateStudyBudgetFeasibility(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('budget_policy_not_active'));
  assert.ok(denied.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(denied.reasons.includes('budget_status_not_approved'));
  assert.ok(denied.reasons.includes('currency_code_invalid'));
  assert.ok(denied.reasons.includes('sponsor_budget_minor_units_invalid'));
  assert.ok(denied.reasons.includes('total_cost_minor_units_invalid'));
  assert.ok(denied.reasons.includes('budget_approval_order_invalid'));
  assert.ok(denied.reasons.includes('budget_approved_before_policy_evaluation'));
  assert.ok(denied.reasons.includes('dependency_evidence_hash_invalid'));
  assert.ok(denied.reasons.includes('budget_dependency_metadata_boundary_invalid'));
  assert.ok(denied.reasons.includes('custody_digest_invalid'));
});

test('study budget feasibility refuses raw sponsor budget content and secrets before receipt creation', async () => {
  const { evaluateStudyBudgetFeasibility, ProtectedContentError } = await loadStudyBudgetFeasibility();

  assert.throws(
    () =>
      evaluateStudyBudgetFeasibility({
        ...budgetInput(),
        studyBudget: {
          ...budgetInput().studyBudget,
          sponsorBudgetText: 'Sponsor budget text with negotiated confidential terms',
        },
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateStudyBudgetFeasibility({
        ...budgetInput(),
        resourcePlan: {
          ...budgetInput().resourcePlan,
          bankAccountNumber: '123456789',
        },
      }),
    ProtectedContentError,
  );
}
);
