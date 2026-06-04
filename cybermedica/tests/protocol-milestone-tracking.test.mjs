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

const REQUIRED_MILESTONE_FAMILIES = [
  'protocol_approval',
  'site_activation',
  'first_participant_in',
  'enrollment_close',
  'last_participant_last_visit',
  'database_lock',
  'final_report',
];

async function loadProtocolMilestoneTracking() {
  try {
    return await import('../src/protocol-milestone-tracking.mjs');
  } catch (error) {
    assert.fail(`CyberMedica protocol milestone tracking module must exist and load: ${error.message}`);
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

function milestone(family, index, overrides = {}) {
  const dueAtHlc = { physicalMs: 1817700000000 + index * 1000, logical: 0 };
  return {
    milestoneRef: `milestone-${family}`,
    family,
    ownerDid: `did:exo:${family.replaceAll('_', '-')}-owner`,
    status: index < 2 ? 'completed' : 'on_track',
    dueAtHlc,
    completedAtHlc: index < 2 ? { physicalMs: 1817400000000 + index * 1000, logical: 0 } : null,
    evidenceHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1][index],
    sourceArtifactHash: [DIGEST_2, DIGEST_3, DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E][index],
    dependencyRefs: [],
    receiptHash: [DIGEST_3, DIGEST_2, DIGEST_F, DIGEST_E, DIGEST_D, DIGEST_C, DIGEST_B][index],
    decisionForumMatterRef: family === 'site_activation' ? 'df-site-activation-alpha' : null,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function trackingInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:protocol-milestone-manager-alpha',
      kind: 'human',
      roleRefs: ['principal_investigator', 'study_coordinator'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['protocol_milestone_manage', 'write'],
      authorityChainHash: DIGEST_A,
    },
    milestonePolicy: {
      policyRef: 'protocol-milestone-policy-alpha',
      policyHash: DIGEST_B,
      requiredFamilies: REQUIRED_MILESTONE_FAMILIES,
      criticalFamilies: ['protocol_approval', 'site_activation', 'database_lock', 'final_report'],
      requireDependencyCompletion: true,
      requireHumanReviewForBlockedCritical: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      noProductionTrustClaim: true,
      approvedAtHlc: { physicalMs: 1817300000000, logical: 0 },
    },
    study: {
      studyRef: 'study-alpha',
      protocolRef: 'protocol-cm-alpha',
      activeProtocolVersionRef: 'protocol-cm-alpha:v3',
      siteRef: 'site-alpha',
      milestonePlanHash: DIGEST_C,
      informationManagementPlanRef: 'info-mgmt-plan-alpha',
      informationManagementPlanHash: DIGEST_D,
      status: 'active',
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    milestones: REQUIRED_MILESTONE_FAMILIES.map(milestone).reverse(),
    review: {
      reviewerDid: 'did:exo:principal-investigator-alpha',
      decision: 'milestones_current_inactive_trust',
      reviewHash: DIGEST_E,
      reviewedAtHlc: { physicalMs: 1817600000000, logical: 0 },
      aiAssisted: true,
      aiFinalAuthority: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    checkedAtHlc: { physicalMs: 1817550000000, logical: 0 },
    custodyDigest: DIGEST_F,
  };

  return mergeDeep(base, overrides);
}

test('protocol milestone tracking creates deterministic inactive metadata receipts', async () => {
  const { evaluateProtocolMilestoneTracking } = await loadProtocolMilestoneTracking();

  const first = evaluateProtocolMilestoneTracking(trackingInput());
  const second = evaluateProtocolMilestoneTracking({
    ...trackingInput(),
    milestonePolicy: {
      ...trackingInput().milestonePolicy,
      requiredFamilies: [...REQUIRED_MILESTONE_FAMILIES].reverse(),
      criticalFamilies: [...trackingInput().milestonePolicy.criticalFamilies].reverse(),
    },
    milestones: [...trackingInput().milestones].reverse(),
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.protocolMilestoneTracking.status, 'on_track');
  assert.equal(first.protocolMilestoneTracking.milestoneCount, REQUIRED_MILESTONE_FAMILIES.length);
  assert.equal(first.protocolMilestoneTracking.coverageBasisPoints, 10000);
  assert.deepEqual(first.protocolMilestoneTracking.requiredFamilies, REQUIRED_MILESTONE_FAMILIES);
  assert.deepEqual(first.protocolMilestoneTracking.coveredFamilies, REQUIRED_MILESTONE_FAMILIES);
  assert.deepEqual(first.protocolMilestoneTracking.blockedMilestoneRefs, []);
  assert.deepEqual(first.protocolMilestoneTracking.overdueMilestoneRefs, []);
  assert.equal(first.protocolMilestoneTracking.trustState, 'inactive');
  assert.equal(first.protocolMilestoneTracking.exochainProductionClaim, false);
  assert.equal(first.protocolMilestoneTracking.trackingHash, second.protocolMilestoneTracking.trackingHash);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.receipt.anchorPayload.artifactType, 'protocol_milestone_tracking');
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(first), /Participant Alice|raw milestone|medical record|source document/iu);
});

test('protocol milestone tracking fails closed for missing overdue and blocked critical milestones', async () => {
  const { evaluateProtocolMilestoneTracking } = await loadProtocolMilestoneTracking();
  const milestones = REQUIRED_MILESTONE_FAMILIES.map((family, index) => {
    if (family === 'database_lock') {
      return milestone(family, index, {
        status: 'blocked',
        dueAtHlc: { physicalMs: 1817000000000, logical: 0 },
        dependencyRefs: ['milestone-last_participant_last_visit', 'missing-query-closeout'],
        receiptHash: null,
        blockerRefs: ['blocker-open-query-alpha'],
      });
    }
    return milestone(family, index);
  }).filter((row) => row.family !== 'final_report');

  const result = evaluateProtocolMilestoneTracking(
    trackingInput({
      milestones,
      review: {
        decision: 'hold_for_milestone_gap',
        reviewHash: null,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.equal(result.protocolMilestoneTracking, null);
  assert.ok(result.reasons.includes('milestone_family_missing:final_report'));
  assert.ok(result.reasons.includes('critical_milestone_blocked:milestone-database_lock'));
  assert.ok(result.reasons.includes('critical_milestone_overdue:milestone-database_lock'));
  assert.ok(result.reasons.includes('milestone_receipt_hash_invalid:milestone-database_lock'));
  assert.ok(result.reasons.includes('milestone_dependency_missing:milestone-database_lock:missing-query-closeout'));
  assert.ok(result.reasons.includes('review_hash_invalid'));
});

test('protocol milestone tracking enforces authority human review HLC and dependency ordering', async () => {
  const { evaluateProtocolMilestoneTracking } = await loadProtocolMilestoneTracking();

  const result = evaluateProtocolMilestoneTracking(
    trackingInput({
      actor: { did: 'did:exo:ai-scheduler-alpha', kind: 'ai_agent' },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['read'],
        authorityChainHash: DIGEST_A,
      },
      milestones: [
        milestone('protocol_approval', 0, {
          status: 'on_track',
          completedAtHlc: null,
        }),
        milestone('site_activation', 1, {
          status: 'on_track',
          completedAtHlc: null,
          dependencyRefs: ['milestone-protocol_approval'],
        }),
        ...REQUIRED_MILESTONE_FAMILIES.slice(2).map((family, index) => milestone(family, index + 2)),
      ],
      review: {
        aiFinalAuthority: true,
        reviewedAtHlc: { physicalMs: 1817200000000, logical: 0 },
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('human_actor_required'));
  assert.ok(result.reasons.includes('protocol_milestone_authority_missing'));
  assert.ok(result.reasons.includes('milestone_dependency_incomplete:milestone-site_activation:milestone-protocol_approval'));
  assert.ok(result.reasons.includes('review_before_policy_approval'));
  assert.ok(result.reasons.includes('review_before_checked_at'));
  assert.ok(result.reasons.includes('review_ai_final_authority_forbidden'));
});

test('protocol milestone tracking rejects raw milestone content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateProtocolMilestoneTracking } = await loadProtocolMilestoneTracking();

  assert.throws(
    () =>
      evaluateProtocolMilestoneTracking(
        trackingInput({
          milestones: [
            ...trackingInput().milestones,
            {
              ...milestone('final_report', 6),
              milestoneRef: 'milestone-unsafe-raw-content',
              rawMilestoneNarrative: 'Participant Alice source document details must stay outside receipts.',
            },
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateProtocolMilestoneTracking(
        trackingInput({
          study: {
            apiKey: 'cm_live_secret',
          },
        }),
      ),
    ProtectedContentError,
  );
});
