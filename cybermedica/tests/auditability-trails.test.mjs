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

const REQUIRED_AUDIT_FAMILIES = Object.freeze([
  'access',
  'approvals',
  'authentication',
  'decisions',
  'delegations',
  'document_changes',
  'evidence',
  'exports',
  'privileged_actions',
]);

async function loadAuditabilityTrails() {
  try {
    return await import('../src/auditability-trails.mjs');
  } catch (error) {
    assert.fail(`CyberMedica auditability trails module must exist and load: ${error.message}`);
  }
}

function eventFamily(family, index) {
  return {
    family,
    eventCount: index + 2,
    firstSequence: index * 100 + 1,
    lastSequence: index * 100 + index + 2,
    sequenceGapCount: 0,
    firstEventHash: index % 2 === 0 ? DIGEST_A : DIGEST_B,
    latestEventHash: index % 2 === 0 ? DIGEST_C : DIGEST_D,
    previousFamilyHash: index % 2 === 0 ? DIGEST_E : DIGEST_F,
    appendOnly: true,
    tamperEvident: true,
    retentionPolicyRef: `retention-${family}`,
    accessPolicyRef: `access-policy-${family}`,
    storagePartitionRef: `tenant-site-alpha/audit/${family}`,
    reviewEvidenceHash: index % 2 === 0 ? DIGEST_F : DIGEST_E,
    firstEventAtHlc: { physicalMs: 1791000000000 + index * 1000, logical: 0 },
    latestEventAtHlc: { physicalMs: 1791000000500 + index * 1000, logical: 1 },
    metadataOnly: true,
    protectedContentExcluded: true,
    rawPayloadExcluded: true,
  };
}

function eventFamilies() {
  return REQUIRED_AUDIT_FAMILIES.map(eventFamily);
}

function auditabilityInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:auditability-owner-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['auditability_review', 'govern'],
      authorityChainHash: DIGEST_F,
    },
    auditabilityPolicy: {
      policyRef: 'NFR-005-AUDITABILITY-POLICY-ALPHA',
      policyHash: DIGEST_A,
      requiredEventFamilies: REQUIRED_AUDIT_FAMILIES,
      appendOnlyRequired: true,
      tamperEvidenceRequired: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      rawPayloadExcluded: true,
      silentDeletionForbidden: true,
      reviewedAtHlc: { physicalMs: 1790999999000, logical: 0 },
    },
    auditTrail: {
      trailRef: 'AUDTRAIL-CARDIAC-ALPHA-001',
      protocolRef: 'protocol-cardiac-alpha',
      siteRef: 'site-alpha',
      sourceSystemRef: 'cybermedica-operational-audit-store',
      status: 'reviewed',
      reviewWindowStartHlc: { physicalMs: 1791000000000, logical: 0 },
      reviewWindowEndHlc: { physicalMs: 1791000100000, logical: 0 },
      eventFamilies: eventFamilies(),
      deletionControls: {
        silentDeleteDisabled: true,
        deleteRequiresSupersession: true,
        deletionEventsAudited: true,
        retentionOverrideHash: DIGEST_D,
      },
      correctionControls: {
        supplementCorrectionsOnly: true,
        supersessionAuditRequired: true,
        annotationAuditRequired: true,
        correctionPolicyHash: DIGEST_E,
      },
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-auditor-alpha',
      reviewDecision: 'auditability_ready',
      reviewedAtHlc: { physicalMs: 1791000200000, logical: 0 },
      evidenceBundleHash: DIGEST_B,
      qualityApprovalHash: DIGEST_C,
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-auditability-alpha-001',
        workflowReceiptId: 'df-workflow-auditability-alpha-001',
      },
    },
    custodyDigest: DIGEST_D,
  };
  return {
    ...base,
    ...overrides,
  };
}

test('auditability trail coverage creates deterministic NFR-005 inactive metadata receipts', async () => {
  const { evaluateAuditabilityTrailCoverage } = await loadAuditabilityTrails();

  const resultA = evaluateAuditabilityTrailCoverage(auditabilityInput());
  const inputB = auditabilityInput();
  inputB.auditabilityPolicy.requiredEventFamilies = [...inputB.auditabilityPolicy.requiredEventFamilies].reverse();
  inputB.auditTrail.eventFamilies = [...inputB.auditTrail.eventFamilies].reverse();
  const resultB = evaluateAuditabilityTrailCoverage(inputB);

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.auditTrail.auditabilityStatus, 'ready');
  assert.equal(resultA.auditTrail.trustState, 'inactive');
  assert.equal(resultA.auditTrail.exochainProductionClaim, false);
  assert.equal(resultA.auditTrail.familyCoverageBasisPoints, 10000);
  assert.equal(resultA.auditTrail.appendOnlyCoverageBasisPoints, 10000);
  assert.equal(resultA.auditTrail.tamperEvidenceCoverageBasisPoints, 10000);
  assert.deepEqual(resultA.auditTrail.coveredAuditFamilies, [...REQUIRED_AUDIT_FAMILIES].sort());
  assert.equal(resultA.auditTrail.auditTrailHash, resultB.auditTrail.auditTrailHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'auditability_trail_coverage');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(resultA), /source document|raw audit log|participant alice|root-backed production authority/iu);
});

test('auditability trails fail closed for missing families gaps authority and governance defects', async () => {
  const { evaluateAuditabilityTrailCoverage } = await loadAuditabilityTrails();
  const input = auditabilityInput();

  input.targetTenantId = 'tenant-site-beta';
  input.actor = { did: 'did:exo:ai-auditability-reviewer-alpha', kind: 'ai_agent' };
  input.authority = {
    valid: true,
    revoked: true,
    expired: true,
    permissions: ['read'],
    authorityChainHash: 'bad',
  };
  input.auditabilityPolicy.requiredEventFamilies = input.auditabilityPolicy.requiredEventFamilies.filter(
    (family) => family !== 'privileged_actions',
  );
  input.auditabilityPolicy.appendOnlyRequired = false;
  input.auditTrail.eventFamilies = input.auditTrail.eventFamilies
    .filter((family) => family.family !== 'evidence')
    .map((family) => {
      if (family.family === 'authentication') {
        return { ...family, eventCount: 0 };
      }
      if (family.family === 'access') {
        return { ...family, sequenceGapCount: 1 };
      }
      if (family.family === 'decisions') {
        return { ...family, appendOnly: false };
      }
      if (family.family === 'approvals') {
        return { ...family, tamperEvident: false };
      }
      if (family.family === 'document_changes') {
        return {
          ...family,
          firstEventAtHlc: { physicalMs: 1791000005000, logical: 0 },
          latestEventAtHlc: { physicalMs: 1791000004000, logical: 0 },
        };
      }
      if (family.family === 'exports') {
        return { ...family, accessPolicyRef: '' };
      }
      if (family.family === 'delegations') {
        return { ...family, metadataOnly: false };
      }
      return family;
    });
  input.auditTrail.deletionControls = {
    silentDeleteDisabled: false,
    deleteRequiresSupersession: false,
    deletionEventsAudited: false,
    retentionOverrideHash: 'bad',
  };
  input.auditTrail.correctionControls = {
    supplementCorrectionsOnly: false,
    supersessionAuditRequired: false,
    annotationAuditRequired: false,
    correctionPolicyHash: 'bad',
  };
  input.humanReview.decisionForum = {
    verified: false,
    state: 'pending',
    humanGate: { verified: false },
    quorum: { status: 'not_met' },
    openChallenge: true,
    decisionId: '',
    workflowReceiptId: '',
  };
  input.custodyDigest = 'bad';

  const denied = evaluateAuditabilityTrailCoverage(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.auditTrail.auditabilityStatus, 'blocked');
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_chain_revoked'));
  assert.ok(denied.reasons.includes('authority_chain_expired'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('policy_required_family_missing:privileged_actions'));
  assert.ok(denied.reasons.includes('policy_append_only_not_required'));
  assert.ok(denied.reasons.includes('audit_family_missing:evidence'));
  assert.ok(denied.reasons.includes('audit_family_event_count_invalid:authentication'));
  assert.ok(denied.reasons.includes('audit_family_sequence_gap:access'));
  assert.ok(denied.reasons.includes('audit_family_not_append_only:decisions'));
  assert.ok(denied.reasons.includes('audit_family_not_tamper_evident:approvals'));
  assert.ok(denied.reasons.includes('audit_family_time_order_invalid:document_changes'));
  assert.ok(denied.reasons.includes('audit_family_access_policy_absent:exports'));
  assert.ok(denied.reasons.includes('audit_family_metadata_boundary_invalid:delegations'));
  assert.ok(denied.reasons.includes('silent_delete_control_invalid'));
  assert.ok(denied.reasons.includes('correction_control_invalid'));
  assert.ok(denied.reasons.includes('decision_forum_unverified'));
  assert.ok(denied.reasons.includes('human_gate_unverified'));
  assert.ok(denied.reasons.includes('quorum_not_met'));
  assert.ok(denied.reasons.includes('challenge_open'));
  assert.ok(denied.reasons.includes('custody_digest_invalid'));
  assert.equal(denied.receipt, null);
});

test('auditability trails fail closed when policy trail and review shape are missing', async () => {
  const { evaluateAuditabilityTrailCoverage } = await loadAuditabilityTrails();

  const denied = evaluateAuditabilityTrailCoverage({
    tenantId: '',
    targetTenantId: 'tenant-site-alpha',
    actor: null,
    authority: null,
    auditabilityPolicy: null,
    auditTrail: {
      trailRef: '',
      protocolRef: '',
      siteRef: '',
      sourceSystemRef: '',
      status: 'draft',
      reviewWindowStartHlc: null,
      reviewWindowEndHlc: null,
      eventFamilies: null,
      deletionControls: null,
      correctionControls: null,
    },
    humanReview: null,
    custodyDigest: null,
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_absent'));
  assert.ok(denied.reasons.includes('actor_did_absent'));
  assert.ok(denied.reasons.includes('authority_chain_invalid'));
  assert.ok(denied.reasons.includes('policy_ref_absent'));
  assert.ok(denied.reasons.includes('policy_hash_invalid'));
  assert.ok(denied.reasons.includes('trail_ref_absent'));
  assert.ok(denied.reasons.includes('audit_trail_not_reviewed'));
  assert.ok(denied.reasons.includes('review_window_start_invalid'));
  assert.ok(denied.reasons.includes('event_family_list_absent'));
  assert.ok(denied.reasons.includes('human_reviewer_absent'));
  assert.ok(denied.reasons.includes('decision_forum_unverified'));
  assert.ok(denied.reasons.includes('custody_digest_invalid'));
});

test('auditability hold reviews remain governed inactive without production trust claims', async () => {
  const { evaluateAuditabilityTrailCoverage } = await loadAuditabilityTrails();

  const held = evaluateAuditabilityTrailCoverage(
    auditabilityInput({
      humanReview: {
        ...auditabilityInput().humanReview,
        reviewDecision: 'hold_for_auditability_gap',
      },
    }),
  );

  assert.equal(held.decision, 'permitted');
  assert.equal(held.failClosed, false);
  assert.equal(held.auditTrail.auditabilityStatus, 'hold_for_auditability_gap');
  assert.equal(held.auditTrail.exochainProductionClaim, false);
  assert.equal(held.receipt.trustState, 'inactive');
});

test('auditability trails accept inert raw markers and same-physical-time HLC logical ordering', async () => {
  const { evaluateAuditabilityTrailCoverage } = await loadAuditabilityTrails();
  const input = auditabilityInput({
    rawAuditLog: [false],
    rawPayload: null,
    rawAuditTrail: {},
    adapterSecret: false,
  });

  input.auditTrail.reviewWindowStartHlc = { physicalMs: 1791000000000, logical: 0 };
  input.auditTrail.reviewWindowEndHlc = { physicalMs: 1791000000000, logical: 20 };
  input.auditTrail.eventFamilies = input.auditTrail.eventFamilies.map((family, index) => ({
    ...family,
    firstEventAtHlc: { physicalMs: 1791000000000, logical: index + 1 },
    latestEventAtHlc: { physicalMs: 1791000000000, logical: index + 2 },
  }));
  input.humanReview.reviewedAtHlc = { physicalMs: 1791000000000, logical: 21 };

  const result = evaluateAuditabilityTrailCoverage(input);

  assert.equal(result.decision, 'permitted');
  assert.equal(result.auditTrail.familyCoverageBasisPoints, 10000);
  assert.equal(result.receipt.trustState, 'inactive');
});

test('auditability trails reject raw audit content and secret material before anchoring', async () => {
  const { evaluateAuditabilityTrailCoverage } = await loadAuditabilityTrails();

  assert.throws(
    () =>
      evaluateAuditabilityTrailCoverage({
        ...auditabilityInput(),
        auditTrail: {
          ...auditabilityInput().auditTrail,
          rawAuditLog: 'participant Alice source document audit text',
        },
      }),
    (error) => error.name === 'ProtectedContentError' && /raw auditability content field/u.test(error.message),
  );

  assert.throws(
    () =>
      evaluateAuditabilityTrailCoverage({
        ...auditabilityInput(),
        adapterSecret: 'sk-cybermedica-should-not-anchor',
      }),
    (error) => error.name === 'ProtectedContentError' && /auditability secret field/u.test(error.message),
  );

  assert.throws(
    () =>
      evaluateAuditabilityTrailCoverage({
        ...auditabilityInput(),
        rawAuditLog: 17,
      }),
    (error) => error.name === 'ProtectedContentError' && /raw auditability content field/u.test(error.message),
  );
});
