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

async function loadClinicalTrialAgreements() {
  try {
    return await import('../src/clinical-trial-agreements.mjs');
  } catch (error) {
    assert.fail(`CyberMedica clinical trial agreement module must exist and load: ${error.message}`);
  }
}

function policy10ReviewDimensions() {
  return [
    'duties',
    'functions',
    'financial_requirements',
    'qa_qc_requirements',
    'reporting_procedures',
    'termination_suspension_requirements',
    'document_retention',
    'data_access',
    'monitoring',
    'inspection',
    'audit_rights',
  ].map((dimension, index) => ({
    dimension,
    status: dimension === 'monitoring' ? 'accepted_with_conditions' : 'accepted',
    ownerRole: dimension === 'financial_requirements' ? 'finance_lead' : 'site_quality_lead',
    obligationHash: index % 2 === 0 ? DIGEST_A : DIGEST_B,
    evidenceHash: index % 2 === 0 ? DIGEST_C : DIGEST_D,
    riskLevel: dimension === 'monitoring' ? 'medium' : 'low',
    conditionRef: dimension === 'monitoring' ? 'CTA-COND-MONITORING-001' : null,
    conditionEvidenceHash: dimension === 'monitoring' ? DIGEST_E : null,
    conditionAcceptedByDid: dimension === 'monitoring' ? 'did:exo:principal-investigator-alpha' : null,
    unresolvedIssueRefs: [],
  }));
}

function clinicalTrialAgreementInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:contracts-lead-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['manage_trial_agreements', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    agreement: {
      agreementRef: 'CTA-PROTOCOL-CM-001',
      protocolRef: 'protocol-cm-001',
      studyRef: 'study-alpha',
      siteRef: 'site-alpha',
      sponsorRef: 'sponsor-alpha',
      croRef: 'cro-alpha',
      version: 'v1.2',
      agreementHash: DIGEST_B,
      intakeReceiptId: 'cmr_protocol_intake_0009',
      execution: {
        executed: true,
        executionState: 'fully_executed',
        siteSignatoryDid: 'did:exo:site-authorized-representative-alpha',
        sponsorSignatoryRef: 'sponsor-signatory-alpha',
        legalApprovalHash: DIGEST_C,
        financeApprovalHash: DIGEST_D,
        qualityApprovalHash: DIGEST_E,
        piAcknowledgementHash: DIGEST_A,
        siteSignatureHash: DIGEST_B,
        sponsorSignatureHash: DIGEST_C,
        executedAtHlc: { physicalMs: 1791100000000, logical: 2 },
        effectiveAtHlc: { physicalMs: 1791100000000, logical: 2 },
      },
    },
    review: {
      reviewRef: 'CTA-REVIEW-2026-0004',
      reviewedAtHlc: { physicalMs: 1791090000000, logical: 5 },
      legalReviewerDid: 'did:exo:legal-reviewer-alpha',
      financialReviewerDid: 'did:exo:finance-reviewer-alpha',
      qualityReviewerDid: 'did:exo:quality-reviewer-alpha',
      principalInvestigatorDid: 'did:exo:principal-investigator-alpha',
      aiReview: {
        completed: true,
        advisoryOnly: true,
        finalAuthority: false,
        outputHash: DIGEST_D,
        evidenceUsedHashes: [DIGEST_A, DIGEST_B],
      },
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-clinical-trial-agreement-0004',
        workflowReceiptId: 'df-workflow-clinical-trial-agreement-0004',
      },
      evidenceBundle: { complete: true, phiBoundaryAttested: true },
    },
    reviewDimensions: policy10ReviewDimensions(),
    issues: [
      {
        issueRef: 'CTA-ISSUE-MONITORING-001',
        severity: 'major',
        status: 'accepted',
        ownerDid: 'did:exo:monitoring-owner-alpha',
        mitigationHash: DIGEST_E,
        targetResolutionHlc: { physicalMs: 1791090000000, logical: 6 },
      },
    ],
    launchDependency: {
      protocolLaunchGateRef: 'LAUNCH-PROTOCOL-CM-001',
      requiresExecutedAgreement: true,
      launchGateCheckHash: DIGEST_A,
    },
    custodyDigest: DIGEST_E,
  };
}

test('clinical trial agreement review creates deterministic inactive execution readiness receipt', async () => {
  const { evaluateClinicalTrialAgreementReview } = await loadClinicalTrialAgreements();

  const resultA = evaluateClinicalTrialAgreementReview(clinicalTrialAgreementInput());
  const resultB = evaluateClinicalTrialAgreementReview({
    ...clinicalTrialAgreementInput(),
    reviewDimensions: [...clinicalTrialAgreementInput().reviewDimensions].reverse(),
    issues: [...clinicalTrialAgreementInput().issues].reverse(),
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.agreementReview.status, 'launch_ready');
  assert.equal(resultA.agreementReview.launchDependencySatisfied, true);
  assert.equal(resultA.agreementReview.exochainProductionClaim, false);
  assert.equal(resultA.agreementReview.trustState, 'inactive');
  assert.equal(resultA.agreementReview.aiFinalAuthority, false);
  assert.equal(resultA.agreementReview.policy10CoverageBasisPoints, 10000);
  assert.deepEqual(resultA.agreementReview.coveredReviewDimensions, [
    'audit_rights',
    'data_access',
    'document_retention',
    'duties',
    'financial_requirements',
    'functions',
    'inspection',
    'monitoring',
    'qa_qc_requirements',
    'reporting_procedures',
    'termination_suspension_requirements',
  ]);
  assert.equal(resultA.agreementReview.openIssueSummary.major, 1);
  assert.deepEqual(resultA.agreementReview.requiredLaunchEvidenceRefs, [
    'CTA-REVIEW-2026-0004',
    'LAUNCH-PROTOCOL-CM-001',
    'cmr_protocol_intake_0009',
  ]);
  assert.equal(resultA.agreementReview.reviewId, resultB.agreementReview.reviewId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'clinical_trial_agreement_review');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(resultA), /source document|raw agreement|participant alice|patient/iu);
});

test('clinical trial agreement review fails closed for missing Policy 10 coverage and unresolved blockers', async () => {
  const { evaluateClinicalTrialAgreementReview } = await loadClinicalTrialAgreements();
  const input = clinicalTrialAgreementInput();
  input.actor = { did: 'did:exo:ai-contract-reviewer-alpha', kind: 'ai_agent' };
  input.review.aiReview = {
    completed: false,
    advisoryOnly: false,
    finalAuthority: true,
    outputHash: '',
    evidenceUsedHashes: ['not-a-hash'],
  };
  input.reviewDimensions = input.reviewDimensions.filter((item) => item.dimension !== 'audit_rights');
  input.issues = [
    {
      issueRef: 'CTA-CRITICAL-DATA-ACCESS-001',
      severity: 'critical',
      status: 'open',
      ownerDid: '',
      mitigationHash: '',
      targetResolutionHlc: { physicalMs: 1791200000000, logical: 1 },
    },
  ];

  const denied = evaluateClinicalTrialAgreementReview(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.agreementReview.status, 'blocked');
  assert.equal(denied.agreementReview.launchDependencySatisfied, false);
  assert.equal(denied.agreementReview.openIssueSummary.critical, 1);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('ai_review_incomplete'));
  assert.ok(denied.reasons.includes('ai_review_must_be_advisory'));
  assert.ok(denied.reasons.includes('ai_review_evidence_hash_invalid'));
  assert.ok(denied.reasons.includes('required_agreement_review_dimension_missing:audit_rights'));
  assert.ok(denied.reasons.includes('critical_agreement_issue_unresolved:CTA-CRITICAL-DATA-ACCESS-001'));
  assert.ok(denied.reasons.includes('agreement_issue_owner_absent:CTA-CRITICAL-DATA-ACCESS-001'));
  assert.ok(denied.reasons.includes('agreement_issue_mitigation_invalid:CTA-CRITICAL-DATA-ACCESS-001'));
  assert.equal(denied.receipt, null);
});

test('clinical trial agreement review denies unexecuted agreements and launch evidence defects', async () => {
  const { evaluateClinicalTrialAgreementReview } = await loadClinicalTrialAgreements();
  const input = clinicalTrialAgreementInput();
  input.targetTenantId = 'tenant-site-beta';
  input.authority = {
    valid: true,
    revoked: false,
    expired: false,
    permissions: ['read'],
    authorityChainHash: 'bad',
  };
  input.agreement.execution = {
    executed: false,
    executionState: 'pending_site_signature',
    siteSignatoryDid: '',
    sponsorSignatoryRef: '',
    legalApprovalHash: '',
    financeApprovalHash: 'bad',
    qualityApprovalHash: '',
    piAcknowledgementHash: '',
    siteSignatureHash: '',
    sponsorSignatureHash: '',
    executedAtHlc: { physicalMs: 1791080000000, logical: 1 },
    effectiveAtHlc: { physicalMs: 1791070000000, logical: 1 },
  };
  input.launchDependency = {
    protocolLaunchGateRef: '',
    requiresExecutedAgreement: false,
    launchGateCheckHash: 'bad',
  };
  input.review.decisionForum = {
    verified: false,
    state: 'pending',
    humanGate: { verified: false },
    quorum: { status: 'not_met' },
    openChallenge: true,
    decisionId: '',
    workflowReceiptId: '',
  };
  input.review.evidenceBundle = { complete: false, phiBoundaryAttested: false };

  const denied = evaluateClinicalTrialAgreementReview(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('clinical_trial_agreement_authority_missing'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('agreement_not_fully_executed'));
  assert.ok(denied.reasons.includes('site_signatory_absent'));
  assert.ok(denied.reasons.includes('sponsor_signatory_absent'));
  assert.ok(denied.reasons.includes('legal_approval_hash_invalid'));
  assert.ok(denied.reasons.includes('finance_approval_hash_invalid'));
  assert.ok(denied.reasons.includes('quality_approval_hash_invalid'));
  assert.ok(denied.reasons.includes('pi_acknowledgement_hash_invalid'));
  assert.ok(denied.reasons.includes('site_signature_hash_invalid'));
  assert.ok(denied.reasons.includes('sponsor_signature_hash_invalid'));
  assert.ok(denied.reasons.includes('agreement_effective_before_execution'));
  assert.ok(denied.reasons.includes('launch_gate_ref_absent'));
  assert.ok(denied.reasons.includes('launch_requires_executed_agreement_invalid'));
  assert.ok(denied.reasons.includes('launch_gate_check_hash_invalid'));
  assert.ok(denied.reasons.includes('decision_forum_unverified'));
  assert.ok(denied.reasons.includes('human_gate_unverified'));
  assert.ok(denied.reasons.includes('quorum_not_met'));
  assert.ok(denied.reasons.includes('challenge_open'));
  assert.ok(denied.reasons.includes('evidence_bundle_incomplete'));
  assert.ok(denied.reasons.includes('phi_boundary_unattested'));
});

test('clinical trial agreement review validates conditional obligations and review timing', async () => {
  const { evaluateClinicalTrialAgreementReview } = await loadClinicalTrialAgreements();
  const input = clinicalTrialAgreementInput();
  input.review.reviewedAtHlc = { physicalMs: 1791110000000, logical: 1 };
  input.reviewDimensions = input.reviewDimensions.map((item) =>
    item.dimension === 'monitoring'
      ? {
          ...item,
          conditionRef: '',
          conditionEvidenceHash: '',
          conditionAcceptedByDid: '',
        }
      : item,
  );
  input.issues = [
    {
      issueRef: 'CTA-MINOR-RETENTION-001',
      severity: 'minor',
      status: 'accepted',
      ownerDid: 'did:exo:records-owner-alpha',
      mitigationHash: DIGEST_A,
      targetResolutionHlc: { physicalMs: 1791095000000, logical: 1 },
    },
  ];

  const denied = evaluateClinicalTrialAgreementReview(input);

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('conditional_agreement_dimension_condition_ref_absent:monitoring'));
  assert.ok(denied.reasons.includes('conditional_agreement_dimension_evidence_invalid:monitoring'));
  assert.ok(denied.reasons.includes('conditional_agreement_dimension_acceptor_absent:monitoring'));
  assert.ok(denied.reasons.includes('agreement_executed_before_review_complete'));
  assert.ok(denied.reasons.includes('agreement_issue_target_before_review:CTA-MINOR-RETENTION-001'));
});

test('clinical trial agreement review handles malformed and same-tick HLC boundaries', async () => {
  const { evaluateClinicalTrialAgreementReview } = await loadClinicalTrialAgreements();
  const input = clinicalTrialAgreementInput();
  input.agreement.execution.executedAtHlc = { physicalMs: 1791090000000, logical: 4 };
  input.agreement.execution.effectiveAtHlc = { physicalMs: 1791090000000, logical: -1 };

  const denied = evaluateClinicalTrialAgreementReview(input);

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('agreement_effective_time_invalid'));
  assert.ok(denied.reasons.includes('agreement_executed_before_review_complete'));
  assert.equal(denied.reasons.includes('agreement_issue_target_before_review:CTA-ISSUE-MONITORING-001'), false);
});

test('clinical trial agreement review rejects raw agreement text and protected content before receipt creation', async () => {
  const { evaluateClinicalTrialAgreementReview } = await loadClinicalTrialAgreements();

  assert.throws(
    () =>
      evaluateClinicalTrialAgreementReview({
        ...clinicalTrialAgreementInput(),
        agreement: {
          ...clinicalTrialAgreementInput().agreement,
          rawAgreementBody: 'Participant Alice Example source document text must not enter agreement review.',
        },
      }),
    /protected content|raw agreement/i,
  );
});
