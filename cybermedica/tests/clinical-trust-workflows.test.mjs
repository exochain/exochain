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

const DIGEST_A = '3d6f0a96f7c972d4f5b66a1c6b5177fe5a32cc0cbd27f7c67be4c11a4f7ce70a';
const DIGEST_B = '8cf4dfd546b712c3b21f0d61fd7c6b744dfc6d9c7d0c8758fb6c6db6e782a7f3';
const DIGEST_C = '54f6e9e53f0e6d9a6ce64b2d67b79d44a927f276e8916d34a2d3b942f575f1b7';
const DIGEST_D = 'd9470f1f6f89a8836e46c21ffcf84f544f8b70a54156f8380dfd5bdf8c5f9693';

async function loadClinicalTrustWorkflows() {
  try {
    return await import('../src/clinical-trust-workflows.mjs');
  } catch (error) {
    assert.fail(`CyberMedica clinical trust workflow module must exist and load: ${error.message}`);
  }
}

function validConsentGrantInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:consent-coordinator-alpha', kind: 'human' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['write'] },
    participant: { tenantScopedPseudonym: 'site-alpha-participant-0001' },
    consentVersion: {
      id: 'ICF-CARDIO-001',
      status: 'active',
      artifactHash: DIGEST_A,
      legalApproval: { status: 'approved', actorDid: 'did:exo:legal-reviewer-alpha' },
      clinicalPolicyRef: 'CONSENT-001',
      revocationPath: 'participant_portal_or_site_staff',
    },
    acknowledgement: {
      participantUnderstands: true,
      capacityAttested: true,
      signedAtHlc: { physicalMs: 1790000000100, logical: 2 },
    },
    consentRefs: ['bailment-participant-alpha-001', 'consent-policy-cardio-alpha'],
    custodyDigest: DIGEST_B,
  };
}

function validSupportAccessInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    supportActor: { did: 'did:exo:support-engineer-alpha', kind: 'human' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['read'] },
    consent: { required: true, status: 'active', revoked: false, consentRef: 'support-bailment-alpha-001' },
    supportGrant: {
      status: 'active',
      scope: 'support_access',
      reasonCode: 'validated_site_helpdesk_case',
      grantId: 'support-grant-alpha-001',
      approvedByDid: 'did:exo:site-quality-manager-alpha',
    },
    requestedAtHlc: { physicalMs: 1790000000200, logical: 1 },
    expiresAtHlc: { physicalMs: 1790003600200, logical: 1 },
    ticketDigest: DIGEST_C,
    custodyDigest: DIGEST_B,
  };
}

function validAiReviewInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    aiActor: { did: 'did:exo:ai-quality-reviewer-alpha', kind: 'ai_agent' },
    reviewClass: 'participant_safety_signal_review',
    modelRef: 'cm-ai-review-policy-2026-05',
    promptDigest: DIGEST_A,
    inputManifestDigest: DIGEST_B,
    outputDigest: DIGEST_C,
    reviewedAtHlc: { physicalMs: 1790000000300, logical: 4 },
    custodyDigest: DIGEST_D,
    humanDisposition: {
      status: 'pending',
      verifiedHumanDid: null,
      final: false,
    },
  };
}

test('participant consent grant creates deterministic inactive metadata receipt and refuses raw identifiers', async () => {
  const { recordParticipantConsentGrant } = await loadClinicalTrustWorkflows();

  const grantA = recordParticipantConsentGrant(validConsentGrantInput());
  const grantB = recordParticipantConsentGrant({
    ...validConsentGrantInput(),
    consentRefs: [...validConsentGrantInput().consentRefs].reverse(),
  });

  assert.equal(grantA.decision, 'permitted');
  assert.equal(grantA.failClosed, false);
  assert.equal(grantA.consentRecord.status, 'active');
  assert.equal(grantA.consentRecord.revocationAvailable, true);
  assert.equal(grantA.receipt.receiptId, grantB.receipt.receiptId);
  assert.equal(grantA.receipt.trustState, 'inactive');
  assert.equal(grantA.receipt.exochainProductionClaim, false);
  assert.equal(grantA.receipt.anchorPayload.artifactType, 'participant_consent_grant');
  assert.doesNotMatch(JSON.stringify(grantA.receipt), /site-alpha-participant-0001/u);

  assert.throws(
    () =>
      recordParticipantConsentGrant({
        ...validConsentGrantInput(),
        participant: { participantName: 'Participant Alice Example' },
      }),
    /protected content/i,
  );
});

test('participant consent grant fails closed when legal approval or consent references are absent', async () => {
  const { recordParticipantConsentGrant } = await loadClinicalTrustWorkflows();

  const denied = recordParticipantConsentGrant({
    ...validConsentGrantInput(),
    consentRefs: [],
    consentVersion: {
      ...validConsentGrantInput().consentVersion,
      legalApproval: { status: 'pending', actorDid: '' },
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('legal_approval_absent'));
  assert.ok(denied.reasons.includes('legal_approval_actor_absent'));
  assert.ok(denied.reasons.includes('consent_refs_absent'));
  assert.equal(denied.consentRecord, null);
  assert.equal(denied.receipt, null);
});

test('participant consent revocation is immediate append-only and terminates future access', async () => {
  const { recordParticipantConsentGrant, revokeParticipantConsent } = await loadClinicalTrustWorkflows();
  const granted = recordParticipantConsentGrant(validConsentGrantInput());

  const revoked = revokeParticipantConsent({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:consent-coordinator-alpha', kind: 'human' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['write'] },
    consentRecord: granted.consentRecord,
    revocation: {
      reasonCode: 'participant_withdrawal',
      revokedAtHlc: { physicalMs: 1790000000400, logical: 1 },
    },
    custodyDigest: DIGEST_B,
  });

  assert.equal(revoked.decision, 'permitted');
  assert.equal(revoked.revokedConsentRecord.status, 'revoked');
  assert.equal(revoked.revokedConsentRecord.futureAccessPermitted, false);
  assert.equal(revoked.revokedConsentRecord.supportAccessTerminated, true);
  assert.equal(revoked.receipt.anchorPayload.artifactType, 'participant_consent_revocation');
  assert.equal(revoked.receipt.trustState, 'inactive');

  const missingReason = revokeParticipantConsent({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:consent-coordinator-alpha', kind: 'human' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['write'] },
    consentRecord: granted.consentRecord,
    revocation: { revokedAtHlc: { physicalMs: 1790000000400, logical: 2 } },
    custodyDigest: DIGEST_B,
  });

  assert.equal(missingReason.decision, 'denied');
  assert.equal(missingReason.failClosed, true);
  assert.ok(missingReason.reasons.includes('revocation_reason_absent'));
  assert.equal(missingReason.receipt, null);
});

test('support access is time-boxed consent-gated metadata-only access and fails closed on revocation', async () => {
  const { authorizeSupportAccess } = await loadClinicalTrustWorkflows();

  const authorized = authorizeSupportAccess(validSupportAccessInput());

  assert.equal(authorized.decision, 'permitted');
  assert.equal(authorized.accessSession.status, 'active');
  assert.equal(authorized.accessSession.expiresAtHlc.physicalMs, 1790003600200);
  assert.equal(authorized.receipt.anchorPayload.artifactType, 'support_access_session');
  assert.equal(authorized.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(authorized.receipt), /helpdesk|clinical note|source document/iu);

  const revokedConsent = authorizeSupportAccess({
    ...validSupportAccessInput(),
    consent: { required: true, status: 'revoked', revoked: true, consentRef: 'support-bailment-alpha-001' },
  });
  assert.equal(revokedConsent.decision, 'denied');
  assert.ok(revokedConsent.reasons.includes('consent_revoked'));
  assert.equal(revokedConsent.accessSession, null);

  const expiredGrant = authorizeSupportAccess({
    ...validSupportAccessInput(),
    expiresAtHlc: { physicalMs: 1790000000100, logical: 1 },
  });
  assert.equal(expiredGrant.decision, 'denied');
  assert.ok(expiredGrant.reasons.includes('support_grant_not_time_boxed'));

  assert.throws(
    () =>
      authorizeSupportAccess({
        ...validSupportAccessInput(),
        sourceDocumentBody: 'Participant Alice Example called about medication symptoms.',
      }),
    /protected content/i,
  );
});

test('support access honors deterministic HLC logical ordering for short access windows', async () => {
  const { authorizeSupportAccess } = await loadClinicalTrustWorkflows();

  const logicalWindow = authorizeSupportAccess({
    ...validSupportAccessInput(),
    requestedAtHlc: { physicalMs: 1790000000200, logical: 1 },
    expiresAtHlc: { physicalMs: 1790000000200, logical: 2 },
  });

  assert.equal(logicalWindow.decision, 'permitted');
  assert.equal(logicalWindow.accessSession.timeBoxed, true);

  const reversedLogicalWindow = authorizeSupportAccess({
    ...validSupportAccessInput(),
    requestedAtHlc: { physicalMs: 1790000000200, logical: 2 },
    expiresAtHlc: { physicalMs: 1790000000200, logical: 1 },
  });

  assert.equal(reversedLogicalWindow.decision, 'denied');
  assert.ok(reversedLogicalWindow.reasons.includes('support_grant_not_time_boxed'));

  const equalWindow = authorizeSupportAccess({
    ...validSupportAccessInput(),
    requestedAtHlc: { physicalMs: 1790000000200, logical: 1 },
    expiresAtHlc: { physicalMs: 1790000000200, logical: 1 },
  });

  assert.equal(equalWindow.decision, 'denied');
  assert.ok(equalWindow.reasons.includes('support_grant_not_time_boxed'));
});

test('AI review provenance records advisory receipt but cannot finalize a governed clinical decision', async () => {
  const { recordAiReviewProvenance } = await loadClinicalTrustWorkflows();

  const advisory = recordAiReviewProvenance(validAiReviewInput());

  assert.equal(advisory.decision, 'permitted');
  assert.equal(advisory.aiReview.finalAuthority, false);
  assert.equal(advisory.aiReview.requiresHumanDisposition, true);
  assert.equal(advisory.aiReview.clinicalDecisionFinal, false);
  assert.equal(advisory.receipt.anchorPayload.artifactType, 'ai_review_provenance');
  assert.equal(advisory.receipt.trustState, 'inactive');

  const aiFinalAttempt = recordAiReviewProvenance({
    ...validAiReviewInput(),
    humanDisposition: {
      status: 'approved',
      final: true,
      verifiedHumanDid: null,
      actorKind: 'ai_agent',
    },
  });

  assert.equal(aiFinalAttempt.decision, 'denied');
  assert.ok(aiFinalAttempt.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(aiFinalAttempt.reasons.includes('human_disposition_unverified'));
  assert.equal(aiFinalAttempt.receipt, null);

  assert.throws(
    () =>
      recordAiReviewProvenance({
        ...validAiReviewInput(),
        recommendationText: 'Participant Alice Example may need urgent follow up.',
      }),
    /protected content/i,
  );
});

test('AI review provenance may record verified human disposition without making AI the final authority', async () => {
  const { recordAiReviewProvenance } = await loadClinicalTrustWorkflows();

  const humanFinal = recordAiReviewProvenance({
    ...validAiReviewInput(),
    humanDisposition: {
      status: 'approved',
      final: true,
      verifiedHumanDid: 'did:exo:principal-investigator-alpha',
      actorKind: 'human',
    },
  });

  assert.equal(humanFinal.decision, 'permitted');
  assert.equal(humanFinal.aiReview.finalAuthority, false);
  assert.equal(humanFinal.aiReview.humanFinalAuthority, true);
  assert.equal(humanFinal.aiReview.requiresHumanDisposition, false);
  assert.equal(humanFinal.aiReview.clinicalDecisionFinal, true);
  assert.equal(humanFinal.receipt.trustState, 'inactive');
});
