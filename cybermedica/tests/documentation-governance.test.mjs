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

const REQUIRED_GOVERNANCE_DOMAINS = [
  'approval_authority',
  'audit_trail',
  'author_identity',
  'effective_date',
  'material_decision_forum_review',
  'reviewer_identity',
  'rollback',
  'version_lineage',
];

async function loadDocumentationGovernance() {
  try {
    return await import('../src/documentation-governance.mjs');
  } catch (error) {
    assert.fail(`CyberMedica DOC-007 documentation governance module must exist and load: ${error.message}`);
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

function documentationGovernanceInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:documentation-governor-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'documentation_owner'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['documentation_governance', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    governancePolicy: {
      policyRef: 'documentation-governance-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredGovernanceDomains: REQUIRED_GOVERNANCE_DOMAINS,
      materialChangesRequireDecisionForum: true,
      authorReviewerApproverSeparationRequired: true,
      rollbackRequired: true,
      effectiveDateRequired: true,
      auditTrailRequired: true,
      rootVerificationRequiredForTrustClaims: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800010000000, logical: 0 },
    },
    governanceCycle: {
      cycleRef: 'documentation-governance-cycle-alpha',
      openedAtHlc: { physicalMs: 1800010050000, logical: 0 },
      authoredAtHlc: { physicalMs: 1800010100000, logical: 0 },
      reviewedAtHlc: { physicalMs: 1800010200000, logical: 0 },
      approvedAtHlc: { physicalMs: 1800010300000, logical: 0 },
      rollbackTestedAtHlc: { physicalMs: 1800010400000, logical: 0 },
      effectiveAtHlc: { physicalMs: 1800010500000, logical: 0 },
      auditRecordedAtHlc: { physicalMs: 1800010600000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    documentationVersion: {
      documentRef: 'manual-site-quality-v3',
      versionRef: 'manual-site-quality-v3.2',
      priorVersionRef: 'manual-site-quality-v3.1',
      documentFamily: 'role_manual',
      sourceRequirementRefs: ['DOC-007', 'FR-031', 'NFR-014'],
      authorDid: 'did:exo:documentation-author-alpha',
      reviewerDid: 'did:exo:quality-reviewer-alpha',
      approverDid: 'did:exo:quality-approver-alpha',
      authorRoleRef: 'documentation_owner',
      reviewerRoleRef: 'quality_reviewer',
      approverRoleRef: 'quality_manager',
      versionHash: DIGEST_C,
      priorVersionHash: DIGEST_D,
      changeControlHash: DIGEST_E,
      effectiveDateEvidenceHash: DIGEST_F,
      rollbackVersionRef: 'manual-site-quality-v3.1',
      rollbackVersionHash: DIGEST_D,
      materialChange: true,
      status: 'approved_for_effective_use',
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    governanceEvidence: {
      authoringEvidenceHash: DIGEST_1,
      reviewerEvidenceHash: DIGEST_2,
      approverEvidenceHash: DIGEST_3,
      materialityAssessmentHash: DIGEST_4,
      versionHistoryHash: DIGEST_5,
      auditTrailHash: DIGEST_A,
      effectiveDateNoticeHash: DIGEST_B,
      rollbackPlanHash: DIGEST_C,
      rollbackTestHash: DIGEST_D,
      governanceDomainsCovered: REQUIRED_GOVERNANCE_DOMAINS,
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1800010250000, logical: 0 },
    },
    decisionForum: {
      matterRef: 'df-doc-governance-alpha',
      verified: true,
      decision: 'approved',
      humanGateVerified: true,
      quorumStatus: 'met',
      openChallenge: false,
      receiptHash: DIGEST_E,
      decidedAtHlc: { physicalMs: 1800010280000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    rollbackControl: {
      rollbackPlanRef: 'rollback-manual-site-quality-v3.2',
      rollbackVersionRef: 'manual-site-quality-v3.1',
      rollbackVersionHash: DIGEST_D,
      rollbackRunbookHash: DIGEST_F,
      disablementPathHash: DIGEST_1,
      accessWithdrawalHash: DIGEST_2,
      tested: true,
      testedAtHlc: { physicalMs: 1800010400000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    validationEvidence: {
      commandRefs: ['node --test tests/documentation-governance.test.mjs', 'npm run quality'],
      commandsPassed: true,
      sourceGuardPassed: true,
      docsUpdated: true,
      noExochainSourceModified: true,
      evidenceHash: DIGEST_3,
      recordedAtHlc: { physicalMs: 1800010550000, logical: 0 },
      metadataOnly: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:site-leader-alpha',
      reviewerRoleRefs: ['site_leader', 'quality_manager'],
      decision: 'documentation_governance_accepted_inactive_trust',
      decisionHash: DIGEST_4,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      reviewedAtHlc: { physicalMs: 1800010520000, logical: 0 },
      metadataOnly: true,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      reviewedByHuman: true,
      recommendationHash: DIGEST_5,
      limitationHashes: [DIGEST_A],
    },
    custodyDigest: DIGEST_5,
  };

  return mergeDeep(base, overrides);
}

test('DOC-007 documentation governance creates deterministic inactive version and rollback receipts', async () => {
  const { evaluateDocumentationGovernance } = await loadDocumentationGovernance();

  const resultA = evaluateDocumentationGovernance(documentationGovernanceInput());
  const resultB = evaluateDocumentationGovernance(
    documentationGovernanceInput({
      governancePolicy: {
        requiredGovernanceDomains: [...REQUIRED_GOVERNANCE_DOMAINS].reverse(),
      },
      governanceEvidence: {
        governanceDomainsCovered: [...REQUIRED_GOVERNANCE_DOMAINS].reverse(),
      },
      documentationVersion: {
        sourceRequirementRefs: ['NFR-014', 'FR-031', 'DOC-007'],
      },
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.deepEqual(resultA.reasons, []);
  assert.equal(resultA.documentationGovernance.doc007Satisfied, true);
  assert.equal(resultA.documentationGovernance.effectiveForUse, true);
  assert.equal(resultA.documentationGovernance.rollbackAvailable, true);
  assert.equal(resultA.documentationGovernance.materialDecisionForumLinked, true);
  assert.deepEqual(resultA.documentationGovernance.governanceDomains, REQUIRED_GOVERNANCE_DOMAINS);
  assert.deepEqual(resultA.documentationGovernance.sourceRequirementRefs, ['DOC-007', 'FR-031', 'NFR-014']);
  assert.equal(resultA.documentationGovernance.exochainProductionClaim, false);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.equal(resultA.documentationGovernance.documentationGovernanceDigest, resultB.documentationGovernance.documentationGovernanceDigest);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
});

test('DOC-007 documentation governance fails closed for missing authorship review approval effective date and rollback evidence', async () => {
  const { evaluateDocumentationGovernance } = await loadDocumentationGovernance();

  const result = evaluateDocumentationGovernance(
    documentationGovernanceInput({
      documentationVersion: {
        authorDid: null,
        reviewerDid: null,
        approverDid: null,
        effectiveDateEvidenceHash: null,
        rollbackVersionHash: null,
      },
      governanceEvidence: {
        governanceDomainsCovered: ['author_identity'],
        approverEvidenceHash: null,
        effectiveDateNoticeHash: null,
        rollbackPlanHash: null,
      },
      rollbackControl: {
        tested: false,
        rollbackRunbookHash: null,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('document_author_absent'));
  assert.ok(result.reasons.includes('document_reviewer_absent'));
  assert.ok(result.reasons.includes('document_approver_absent'));
  assert.ok(result.reasons.includes('effective_date_evidence_hash_invalid'));
  assert.ok(result.reasons.includes('governance_domain_missing:rollback'));
  assert.ok(result.reasons.includes('rollback_test_absent'));
});

test('DOC-007 material documentation changes require Decision Forum review but non-material updates stay governed', async () => {
  const { evaluateDocumentationGovernance } = await loadDocumentationGovernance();

  const denied = evaluateDocumentationGovernance(
    documentationGovernanceInput({
      decisionForum: {
        verified: false,
        quorumStatus: 'not_met',
        receiptHash: null,
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('material_decision_forum_unverified'));
  assert.ok(denied.reasons.includes('material_decision_forum_quorum_not_met'));
  assert.ok(denied.reasons.includes('material_decision_forum_receipt_hash_invalid'));

  const permitted = evaluateDocumentationGovernance(
    documentationGovernanceInput({
      documentationVersion: {
        materialChange: false,
      },
      decisionForum: null,
    }),
  );

  assert.equal(permitted.decision, 'permitted');
  assert.equal(permitted.documentationGovernance.materialDecisionForumLinked, false);
  assert.equal(permitted.documentationGovernance.effectiveForUse, true);
});

test('DOC-007 documentation governance denies AI authority unsafe HLC order and production trust claims', async () => {
  const { evaluateDocumentationGovernance } = await loadDocumentationGovernance();

  const result = evaluateDocumentationGovernance(
    documentationGovernanceInput({
      actor: {
        kind: 'ai_agent',
      },
      governanceCycle: {
        reviewedAtHlc: { physicalMs: 1800010000000, logical: 1 },
        productionTrustClaim: true,
      },
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
        noProductionTrustClaim: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('human_documentation_governor_required'));
  assert.ok(result.reasons.includes('review_time_not_after_author_time'));
  assert.ok(result.reasons.includes('documentation_governance_production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('human_review_final_authority_invalid'));
});

test('DOC-007 documentation governance rejects raw documentation content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateDocumentationGovernance } = await loadDocumentationGovernance();

  assert.throws(
    () =>
      evaluateDocumentationGovernance(
        documentationGovernanceInput({
          rawDocumentationBody: 'full manual content belongs outside metadata receipts',
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDocumentationGovernance(
        documentationGovernanceInput({
          rootSigningKey: 'root-signing-key-material',
        }),
      ),
    ProtectedContentError,
  );
});
