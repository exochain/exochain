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

const REQUIRED_SCOPE_FAMILIES = ['control', 'diligence_packet', 'protocol', 'site', 'study'];

async function loadEvidenceAgingEngine() {
  try {
    return await import('../src/evidence-aging-engine.mjs');
  } catch (error) {
    assert.fail(`CyberMedica evidence aging engine module must exist and load: ${error.message}`);
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

function evidenceRecord(evidenceRef, scopeFamily, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F];
  return {
    evidenceRef,
    scopeFamily,
    evidenceHash: hashes[index % hashes.length],
    custodyDigest: [DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6][index % 6],
    ownerRoleRef: index % 2 === 0 ? 'quality_manager' : 'site_leader',
    approvalStatus: 'approved',
    lastVerifiedAtHlc: { physicalMs: 1806999990000 + index, logical: 0 },
    freshnessWindowMs: 10_000,
    readinessSupportCandidate: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function formalWaiver(overrides = {}) {
  return {
    type: 'formal_waiver',
    reasonCode: 'approved_site_context_exception',
    approvalHash: DIGEST_7,
    approverDid: 'did:exo:quality-governance-alpha',
    approvedAtHlc: { physicalMs: 1807000200000, logical: 1 },
    validUntilHlc: { physicalMs: 1807000500000, logical: 0 },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function revalidation(overrides = {}) {
  return {
    type: 'revalidated',
    revalidationHash: DIGEST_8,
    reviewerDid: 'did:exo:quality-reviewer-alpha',
    revalidatedAtHlc: { physicalMs: 1807000200000, logical: 2 },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function replacement(overrides = {}) {
  return {
    type: 'replaced',
    replacementEvidenceRef: 'evidence-protocol-new',
    replacementEvidenceHash: DIGEST_9,
    replacementCustodyDigest: DIGEST_A,
    replacedAtHlc: { physicalMs: 1807000200000, logical: 3 },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function ownerAssignment(evidenceRef, index, overrides = {}) {
  return {
    evidenceRef,
    ownerRoleRef: index % 2 === 0 ? 'quality_manager' : 'site_leader',
    ownerDidHash: [DIGEST_A, DIGEST_B, DIGEST_C][index % 3],
    assignedAtHlc: { physicalMs: 1807000200000, logical: index },
    dueAtHlc: { physicalMs: 1807000400000, logical: index },
    metadataOnly: true,
    ...overrides,
  };
}

function agingInput(overrides = {}) {
  const staleControl = evidenceRecord('evidence-control-stale-waived', 'control', 0, {
    lastVerifiedAtHlc: { physicalMs: 1806999800000, logical: 0 },
    agingResolution: formalWaiver(),
  });
  const staleStudy = evidenceRecord('evidence-study-stale-revalidated', 'study', 3, {
    lastVerifiedAtHlc: { physicalMs: 1806999700000, logical: 0 },
    agingResolution: revalidation(),
  });
  const staleProtocol = evidenceRecord('evidence-protocol-stale-replaced', 'protocol', 4, {
    lastVerifiedAtHlc: { physicalMs: 1806999600000, logical: 0 },
    agingResolution: replacement(),
  });

  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:evidence-aging-steward-alpha',
      kind: 'human',
      roleRefs: ['quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['evidence_age_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    agingPolicy: {
      policyRef: 'evidence-aging-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredScopeFamilies: REQUIRED_SCOPE_FAMILIES,
      staleEvidenceChangesReadiness: true,
      formalWaiverAllowed: true,
      revalidationAllowed: true,
      replacementAllowed: true,
      driftSignalRequired: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1806999000000, logical: 0 },
    },
    agingRun: {
      runRef: 'evidence-aging-run-alpha',
      readinessClaimRef: 'site-qms-passport-alpha',
      sourceIndexHash: DIGEST_C,
      asOfHlc: { physicalMs: 1807000000000, logical: 10 },
      metadataOnly: true,
      protectedContentExcluded: true,
      exochainProductionClaim: false,
    },
    evidenceRecords: [
      staleControl,
      evidenceRecord('evidence-site-current', 'site', 1),
      evidenceRecord('evidence-diligence-current', 'diligence_packet', 2),
      staleStudy,
      staleProtocol,
    ],
    ownerAssignments: [
      ownerAssignment(staleControl.evidenceRef, 0),
      ownerAssignment(staleStudy.evidenceRef, 1),
      ownerAssignment(staleProtocol.evidenceRef, 2),
    ],
    humanReview: {
      reviewerDid: 'did:exo:quality-reviewer-alpha',
      decision: 'accepted',
      reviewHash: DIGEST_D,
      reviewedAtHlc: { physicalMs: 1807000300000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      modelRef: 'metadata-only-model-ref',
      outputHash: DIGEST_E,
      reviewedByHuman: true,
    },
  };
  return mergeDeep(base, overrides);
}

test('evidence aging engine creates deterministic inactive readiness receipts and drift signals', async () => {
  const { evaluateEvidenceAging } = await loadEvidenceAgingEngine();
  const first = evaluateEvidenceAging(agingInput());
  const second = evaluateEvidenceAging(
    agingInput({
      evidenceRecords: [...agingInput().evidenceRecords].reverse(),
      ownerAssignments: [...agingInput().ownerAssignments].reverse(),
    }),
  );

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.agingRegister.schema, 'cybermedica.evidence_aging_engine.v1');
  assert.equal(first.agingRegister.trustState, 'inactive');
  assert.equal(first.agingRegister.exochainProductionClaim, false);
  assert.equal(first.agingRegister.readinessClaimAllowed, true);
  assert.deepEqual(first.agingRegister.scopeFamiliesCovered, REQUIRED_SCOPE_FAMILIES);
  assert.deepEqual(first.agingRegister.staleEvidenceRefs, [
    'evidence-control-stale-waived',
    'evidence-protocol-stale-replaced',
    'evidence-study-stale-revalidated',
  ]);
  assert.deepEqual(first.agingRegister.unresolvedStaleEvidenceRefs, []);
  assert.deepEqual(first.agingRegister.resolutionTypes, ['formal_waiver', 'replaced', 'revalidated']);
  assert.equal(first.agingRegister.driftSignals.length, 3);
  assert.ok(first.agingRegister.driftSignals.every((signal) => signal.signalFamily === 'evidence_aging'));
  assert.ok(first.agingRegister.driftSignals.every((signal) => signal.reviewable === true));
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.deepEqual(first, second);
});

test('evidence aging engine fails closed when stale evidence has no approved remedy', async () => {
  const { evaluateEvidenceAging } = await loadEvidenceAgingEngine();
  const denied = evaluateEvidenceAging(
    agingInput({
      evidenceRecords: [
        evidenceRecord('evidence-control-stale-unresolved', 'control', 0, {
          lastVerifiedAtHlc: { physicalMs: 1806999600000, logical: 0 },
          agingResolution: null,
        }),
        evidenceRecord('evidence-site-current', 'site', 1),
        evidenceRecord('evidence-diligence-current', 'diligence_packet', 2),
        evidenceRecord('evidence-study-current', 'study', 3),
        evidenceRecord('evidence-protocol-current', 'protocol', 4),
      ],
      ownerAssignments: [ownerAssignment('evidence-control-stale-unresolved', 0)],
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('readiness_claim_blocked_by_stale_evidence'));
  assert.ok(denied.reasons.includes('stale_evidence_unresolved:evidence-control-stale-unresolved'));
});

test('evidence aging engine requires scope coverage human review and authorized non-AI actors', async () => {
  const { evaluateEvidenceAging } = await loadEvidenceAgingEngine();
  const denied = evaluateEvidenceAging(
    agingInput({
      actor: { did: 'did:exo:ai-agent-alpha', kind: 'ai_agent' },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['read'],
        authorityChainHash: DIGEST_A,
      },
      agingPolicy: {
        requiredScopeFamilies: ['control', 'site'],
      },
      humanReview: {
        decision: 'pending',
        reviewHash: '0000000000000000000000000000000000000000000000000000000000000000',
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('evidence_age_review_authority_missing'));
  assert.ok(denied.reasons.includes('aging_policy_scope_family_missing:diligence_packet'));
  assert.ok(denied.reasons.includes('aging_human_review_not_accepted'));
  assert.ok(denied.reasons.includes('aging_human_review_hash_invalid'));
});

test('evidence aging engine validates remedy timing and ownership for stale evidence', async () => {
  const { evaluateEvidenceAging } = await loadEvidenceAgingEngine();
  const denied = evaluateEvidenceAging(
    agingInput({
      evidenceRecords: [
        evidenceRecord('evidence-control-stale-bad-waiver', 'control', 0, {
          lastVerifiedAtHlc: { physicalMs: 1806999600000, logical: 0 },
          agingResolution: formalWaiver({
            approvedAtHlc: { physicalMs: 1806999500000, logical: 0 },
            validUntilHlc: { physicalMs: 1806999900000, logical: 0 },
          }),
        }),
        evidenceRecord('evidence-site-current', 'site', 1),
        evidenceRecord('evidence-diligence-current', 'diligence_packet', 2),
        evidenceRecord('evidence-study-stale-bad-revalidation', 'study', 3, {
          lastVerifiedAtHlc: { physicalMs: 1806999700000, logical: 0 },
          agingResolution: revalidation({
            revalidatedAtHlc: { physicalMs: 1806999600000, logical: 0 },
          }),
        }),
        evidenceRecord('evidence-protocol-stale-bad-replacement', 'protocol', 4, {
          lastVerifiedAtHlc: { physicalMs: 1806999600000, logical: 0 },
          agingResolution: replacement({
            replacementEvidenceHash: '0000000000000000000000000000000000000000000000000000000000000000',
          }),
        }),
      ],
      ownerAssignments: [ownerAssignment('evidence-control-stale-bad-waiver', 0)],
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('aging_waiver_before_last_verification:evidence-control-stale-bad-waiver'));
  assert.ok(denied.reasons.includes('aging_waiver_expired:evidence-control-stale-bad-waiver'));
  assert.ok(denied.reasons.includes('aging_revalidation_before_last_verification:evidence-study-stale-bad-revalidation'));
  assert.ok(denied.reasons.includes('aging_replacement_hash_invalid:evidence-protocol-stale-bad-replacement'));
  assert.ok(denied.reasons.includes('stale_evidence_owner_absent:evidence-study-stale-bad-revalidation'));
  assert.ok(denied.reasons.includes('stale_evidence_owner_absent:evidence-protocol-stale-bad-replacement'));
});

test('evidence aging engine rejects raw aging content protected content and secrets before receipts', async () => {
  const { evaluateEvidenceAging, ProtectedContentError } = await loadEvidenceAgingEngine();

  assert.throws(
    () =>
      evaluateEvidenceAging(
        agingInput({
          evidenceRecords: [
            ...agingInput().evidenceRecords,
            {
              evidenceRef: 'evidence-with-raw-body',
              scopeFamily: 'control',
              rawEvidenceBody: 'participant Jane Doe source note',
            },
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateEvidenceAging(
        agingInput({
          agingPolicy: {
            apiKey: 'cm_test_key_material',
          },
        }),
      ),
    ProtectedContentError,
  );
});
