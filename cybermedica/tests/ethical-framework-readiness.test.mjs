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
const CUSTODY_DIGEST = 'abababababababababababababababababababababababababababababababab';
const AUTHORITY_HASH = 'f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0';

async function loadEthicalFrameworkReadiness() {
  try {
    return await import('../src/ethical-framework-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica ethical-framework-readiness module must exist and load: ${error.message}`);
  }
}

function baseInput() {
  return {
    requestId: 'ethical-framework-readiness-alpha',
    tenantId: 'tenant-site-alpha',
    siteId: 'site-alpha',
    checkedAtHlc: { physicalMs: 1791600000000, logical: 9 },
    actor: { did: 'did:exo:ethics-governance-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['ethics_framework_review', 'govern'],
      authorityChainHash: AUTHORITY_HASH,
    },
    framework: {
      frameworkRef: 'ETH-SITE-ALPHA-2026',
      version: 'v2',
      status: 'approved',
      ethicalStatementHash: DIGEST_A,
      codeOfConductHash: DIGEST_B,
      societalResponsibilityHash: DIGEST_C,
      inclusiveLeadershipPolicyHash: DIGEST_D,
      conflictDisclosurePolicyHash: DIGEST_E,
      recusalPolicyHash: DIGEST_F,
      concernReportingPolicyHash: DIGEST_1,
      anonymousReportingProcessHash: DIGEST_2,
      nonRetaliationPolicyHash: DIGEST_3,
      noBlameCulturePolicyHash: DIGEST_4,
      complaintHandlingProcedureHash: DIGEST_5,
      investigationProcedureHash: DIGEST_A,
      escalationProcedureHash: DIGEST_B,
      decisionForumLinkageHash: DIGEST_C,
      trainingRequirementHash: DIGEST_D,
      evidenceRequirementHash: DIGEST_E,
      auditTrailHash: DIGEST_F,
      evidenceRefs: [
        'ethical-statement-approved',
        'code-of-conduct-approved',
        'societal-responsibility-approved',
        'inclusive-leadership-approved',
      ],
      reviewCadence: {
        status: 'current',
        reviewedAtHlc: { physicalMs: 1790500000000, logical: 0 },
        nextReviewDueHlc: { physicalMs: 1800000000000, logical: 0 },
        evidenceHash: DIGEST_1,
      },
    },
    policyCoverage: [
      'anonymous_reporting_process',
      'audit_trail',
      'code_of_conduct',
      'complaint_handling_procedure',
      'concern_reporting_policy',
      'conflict_disclosure_policy',
      'decision_forum_linkage',
      'ethical_statement',
      'escalation_procedure',
      'evidence_requirements',
      'inclusive_leadership_policy',
      'investigation_procedure',
      'no_blame_culture_policy',
      'non_retaliation_policy',
      'recusal_policy',
      'review_cadence',
      'societal_responsibility_statement',
      'training_requirement',
    ],
    linkedControls: {
      conflictDisclosure: {
        policyRef: 'COI-POL-SITE-ALPHA-2026',
        active: true,
        evidenceHash: DIGEST_B,
      },
      recusal: {
        policyRef: 'REC-POL-SITE-ALPHA-2026',
        active: true,
        evidenceHash: DIGEST_C,
      },
      concernReporting: {
        procedureRef: 'CONCERN-PROC-SITE-ALPHA-2026',
        active: true,
        anonymousEnabled: true,
        confidentialEnabled: true,
        nonRetaliationSafeguardHash: DIGEST_D,
        noBlameCultureEvidenceHash: DIGEST_E,
      },
      decisionForum: {
        linkageRef: 'DF-LINK-ETHICS-SITE-ALPHA-2026',
        active: true,
        materialEthicsRoute: 'decision_forum',
        receiptRef: 'df-ethical-framework-alpha',
      },
      training: {
        current: true,
        requiredRoleRefs: ['principal_investigator', 'quality_manager', 'coordinator', 'site_leader'],
        trainingMatrixRef: 'TM-ETHICS-SITE-ALPHA-2026',
        completionEvidenceHash: DIGEST_F,
      },
    },
    humanGovernance: {
      verified: true,
      approvedByDid: 'did:exo:site-executive-alpha',
      decisionForumReceiptId: 'df-ethical-framework-alpha',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
    },
    aiAssistance: { used: true, finalAuthority: false, recommendationHash: DIGEST_2 },
    custodyDigest: CUSTODY_DIGEST,
  };
}

test('ethical framework readiness creates deterministic inactive Policy 4 receipts', async () => {
  const { evaluateEthicalFrameworkReadiness } = await loadEthicalFrameworkReadiness();
  const input = baseInput();

  const readyA = evaluateEthicalFrameworkReadiness(input);
  const readyB = evaluateEthicalFrameworkReadiness({
    ...input,
    framework: {
      ...input.framework,
      evidenceRefs: [...input.framework.evidenceRefs].reverse(),
    },
    policyCoverage: [...input.policyCoverage].reverse(),
    linkedControls: {
      ...input.linkedControls,
      training: {
        ...input.linkedControls.training,
        requiredRoleRefs: [...input.linkedControls.training.requiredRoleRefs].reverse(),
      },
    },
  });

  assert.equal(readyA.decision, 'permitted');
  assert.equal(readyA.failClosed, false);
  assert.deepEqual(readyA.reasons, []);
  assert.deepEqual(readyA.gaps, []);
  assert.equal(readyA.trustState, 'inactive');
  assert.equal(readyA.exochainProductionClaim, false);
  assert.equal(readyA.ethicalFramework.frameworkHash, readyB.ethicalFramework.frameworkHash);
  assert.equal(readyA.receipt.receiptId, readyB.receipt.receiptId);
  assert.equal(readyA.receipt.anchorPayload.artifactType, 'ethical_framework_readiness');
  assert.equal(readyA.receipt.trustState, 'inactive');
  assert.deepEqual(readyA.ethicalFramework.policyCoverage, [
    'anonymous_reporting_process',
    'audit_trail',
    'code_of_conduct',
    'complaint_handling_procedure',
    'concern_reporting_policy',
    'conflict_disclosure_policy',
    'decision_forum_linkage',
    'ethical_statement',
    'escalation_procedure',
    'evidence_requirements',
    'inclusive_leadership_policy',
    'investigation_procedure',
    'no_blame_culture_policy',
    'non_retaliation_policy',
    'recusal_policy',
    'review_cadence',
    'societal_responsibility_statement',
    'training_requirement',
  ]);
  assert.deepEqual(readyA.ethicalFramework.linkedControlRefs, [
    'COI-POL-SITE-ALPHA-2026',
    'CONCERN-PROC-SITE-ALPHA-2026',
    'DF-LINK-ETHICS-SITE-ALPHA-2026',
    'REC-POL-SITE-ALPHA-2026',
    'TM-ETHICS-SITE-ALPHA-2026',
  ]);
  assert.deepEqual(Object.keys(readyA.ethicalFramework), [
    'schema',
    'readinessId',
    'frameworkHash',
    'tenantId',
    'siteId',
    'checkedAtHlc',
    'frameworkRef',
    'frameworkVersion',
    'policyCoverage',
    'linkedControlRefs',
    'trainingRoleRefs',
    'evidenceHashes',
    'authorityChainHash',
    'receiptId',
  ]);
  assert.doesNotMatch(JSON.stringify(readyA), /root-backed production authority|participant alice|raw ethics narrative/iu);
});

test('ethical framework readiness fails closed for missing Policy 4 coverage and linked controls', async () => {
  const { evaluateEthicalFrameworkReadiness } = await loadEthicalFrameworkReadiness();
  const input = baseInput();

  const denied = evaluateEthicalFrameworkReadiness({
    ...input,
    actor: { did: 'did:exo:ai-ethics-agent', kind: 'ai_agent' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['read'],
      authorityChainHash: AUTHORITY_HASH,
    },
    framework: {
      ...input.framework,
      status: 'draft',
      ethicalStatementHash: '',
      nonRetaliationPolicyHash: '',
      reviewCadence: {
        ...input.framework.reviewCadence,
        status: 'overdue',
      },
    },
    policyCoverage: ['ethical_statement', 'code_of_conduct'],
    linkedControls: {
      ...input.linkedControls,
      conflictDisclosure: { policyRef: '', active: false, evidenceHash: '' },
      recusal: { policyRef: '', active: false, evidenceHash: '' },
      concernReporting: {
        procedureRef: '',
        active: true,
        anonymousEnabled: false,
        confidentialEnabled: false,
        nonRetaliationSafeguardHash: '',
        noBlameCultureEvidenceHash: '',
      },
      decisionForum: {
        linkageRef: '',
        active: false,
        materialEthicsRoute: 'local_review',
        receiptRef: '',
      },
      training: {
        current: false,
        requiredRoleRefs: ['site_leader'],
        trainingMatrixRef: '',
        completionEvidenceHash: '',
      },
    },
    humanGovernance: {
      verified: false,
      approvedByDid: '',
      decisionForumReceiptId: '',
      humanGate: { verified: false },
      quorum: { status: 'not_met' },
      openChallenge: true,
    },
    aiAssistance: { used: true, finalAuthority: true, recommendationHash: '' },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.ethicalFramework, null);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('ethical_framework_not_approved'));
  assert.ok(denied.reasons.includes('ethical_statement_hash_invalid'));
  assert.ok(denied.reasons.includes('non_retaliation_policy_hash_invalid'));
  assert.ok(denied.reasons.includes('framework_review_not_current'));
  assert.ok(denied.reasons.includes('conflict_disclosure_control_inactive'));
  assert.ok(denied.reasons.includes('recusal_control_inactive'));
  assert.ok(denied.reasons.includes('concern_reporting_anonymous_channel_absent'));
  assert.ok(denied.reasons.includes('concern_reporting_confidential_channel_absent'));
  assert.ok(denied.reasons.includes('decision_forum_linkage_inactive'));
  assert.ok(denied.reasons.includes('decision_forum_material_route_invalid'));
  assert.ok(denied.reasons.includes('ethics_training_not_current'));
  assert.ok(denied.reasons.includes('human_governance_unverified'));
  assert.ok(denied.gaps.some((gap) => gap.reason === 'policy_coverage_missing:non_retaliation_policy'));
  assert.ok(denied.gaps.some((gap) => gap.reason === 'ethics_training_role_missing:quality_manager'));
});

test('ethical framework readiness rejects stale review timing malformed evidence and protected content', async () => {
  const { evaluateEthicalFrameworkReadiness, ProtectedContentError } = await loadEthicalFrameworkReadiness();
  const input = baseInput();

  const denied = evaluateEthicalFrameworkReadiness({
    ...input,
    framework: {
      ...input.framework,
      codeOfConductHash: 'not-a-digest',
      reviewCadence: {
        ...input.framework.reviewCadence,
        reviewedAtHlc: { physicalMs: 1791700000000, logical: 0 },
        nextReviewDueHlc: { physicalMs: 1790000000000, logical: 0 },
        evidenceHash: '',
      },
    },
    linkedControls: {
      ...input.linkedControls,
      concernReporting: {
        ...input.linkedControls.concernReporting,
        nonRetaliationSafeguardHash: 'bad',
      },
    },
    custodyDigest: '0000000000000000000000000000000000000000000000000000000000000000',
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('code_of_conduct_hash_invalid'));
  assert.ok(denied.reasons.includes('framework_review_after_check'));
  assert.ok(denied.reasons.includes('framework_review_overdue'));
  assert.ok(denied.reasons.includes('framework_review_evidence_hash_invalid'));
  assert.ok(denied.reasons.includes('non_retaliation_safeguard_hash_invalid'));
  assert.ok(denied.reasons.includes('custody_digest_invalid'));

  assert.throws(
    () => evaluateEthicalFrameworkReadiness({ ...baseInput(), rawEthicsNarrative: 'Participant Alice raised a concern.' }),
    ProtectedContentError,
  );
  assert.throws(
    () => evaluateEthicalFrameworkReadiness({ ...baseInput(), codeOfConductBody: 'Full policy body text' }),
    ProtectedContentError,
  );
  assert.throws(
    () => evaluateEthicalFrameworkReadiness({ ...baseInput(), adapterSecret: 'sk-production-secret' }),
    ProtectedContentError,
  );
});

test('ethical framework readiness handles absent objects as denial states', async () => {
  const { evaluateEthicalFrameworkReadiness } = await loadEthicalFrameworkReadiness();

  const denied = evaluateEthicalFrameworkReadiness({
    requestId: 'ethical-framework-absent-objects',
    tenantId: 'tenant-site-alpha',
    siteId: 'site-alpha',
    checkedAtHlc: { physicalMs: 1791600000000, logical: 9 },
    actor: { did: 'did:exo:ethics-governance-alpha', kind: 'human' },
    authority: { valid: false, revoked: false, expired: false, permissions: [] },
    custodyDigest: CUSTODY_DIGEST,
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('ethical_framework_absent'));
  assert.ok(denied.reasons.includes('policy_coverage_missing:ethical_statement'));
  assert.ok(denied.reasons.includes('conflict_disclosure_control_absent'));
  assert.ok(denied.reasons.includes('recusal_control_absent'));
  assert.ok(denied.reasons.includes('concern_reporting_control_absent'));
  assert.ok(denied.reasons.includes('decision_forum_linkage_absent'));
  assert.ok(denied.reasons.includes('ethics_training_absent'));
  assert.ok(denied.reasons.includes('human_governance_unverified'));
});
