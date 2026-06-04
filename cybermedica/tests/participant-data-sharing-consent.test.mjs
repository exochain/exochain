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

async function loadParticipantDataSharingConsent() {
  try {
    return await import('../src/participant-data-sharing-consent.mjs');
  } catch (error) {
    assert.fail(`CyberMedica participant-data-sharing-consent module must exist and load: ${error.message}`);
  }
}

function baseInput(overrides = {}) {
  const input = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:consent-owner-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'consent_owner'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['obtain_consent', 'manage_participant_data_sharing'],
      authorityChainHash: DIGEST_A,
    },
    participant: {
      participantCodeHash: DIGEST_B,
      consentProcessRecordId: 'cmcproc-alpha',
      consentMaterialReceiptId: 'cmr-consent-material-alpha',
      consentBailmentRef: 'bailment-participant-alpha',
    },
    sharingRequest: {
      requestRef: 'policy29-sharing-alpha',
      protocolRef: 'protocol-cardiac-alpha',
      interestedPartyClass: 'sponsor',
      recipientTenantId: 'tenant-sponsor-alpha',
      purpose: 'sponsor_diligence',
      requestedScopeRefs: ['coded_data_export', 'audit_readiness_metadata'],
      requestedDataClassRefs: ['participant_linked_metadata', 'quality_evidence_metadata'],
      requestedAtHlc: { physicalMs: 1800000000000, logical: 0 },
      expiresAtHlc: { physicalMs: 1800100000000, logical: 0 },
      metadataOnly: true,
      productionTrustClaim: false,
    },
    dataSharingConsent: {
      status: 'granted',
      evidenceHash: DIGEST_C,
      consentVersionRef: 'participant-data-sharing-consent-v1',
      documentedAtHlc: { physicalMs: 1800000000000, logical: 2 },
      expiresAtHlc: { physicalMs: 1800100000000, logical: 0 },
      grantedScopeRefs: ['audit_readiness_metadata', 'coded_data_export'],
      grantedDataClassRefs: ['quality_evidence_metadata', 'participant_linked_metadata'],
      interestedPartyClassRefs: ['sponsor', 'cro'],
      privacyNoticeHash: DIGEST_D,
      retentionPolicyHash: DIGEST_E,
      withdrawalPathHash: DIGEST_F,
      copyDelivered: true,
      consentBailmentRef: 'bailment-participant-alpha',
    },
    sharingPolicy: {
      policyRef: 'policy29-data-sharing-alpha',
      status: 'active',
      policyHash: DIGEST_1,
      allowedInterestedPartyClasses: ['cro', 'sponsor'],
      allowedPurposes: ['audit_inspection', 'sponsor_diligence'],
      allowedScopeRefs: ['audit_readiness_metadata', 'coded_data_export', 'safety_reporting_metadata'],
      allowedDataClassRefs: ['participant_linked_metadata', 'quality_evidence_metadata'],
      directIdentifiersAllowed: false,
      metadataOnly: true,
      disclosureLogRequired: true,
      retentionPolicyHash: DIGEST_E,
      privacyComplianceHash: DIGEST_2,
      effectiveAtHlc: { physicalMs: 1799900000000, logical: 0 },
    },
    disclosurePlan: {
      disclosureLogHash: DIGEST_3,
      suppressionMode: 'metadata_only_pseudonymous',
      directIdentifiersExcluded: true,
      rawContentExcluded: true,
      participantListExcluded: true,
      sponsorConfidentialContentExcluded: true,
      privilegedContentExcluded: true,
      plannedAtHlc: { physicalMs: 1800000000000, logical: 3 },
    },
    humanReview: {
      approved: true,
      reviewerDid: 'did:exo:privacy-reviewer-alpha',
      privacyLegalReviewHash: DIGEST_D,
      reviewedAtHlc: { physicalMs: 1800000000000, logical: 4 },
    },
    custodyDigest: DIGEST_F,
  };

  return mergeDeep(input, overrides);
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

test('participant data sharing consent creates deterministic inactive metadata-only grants', async () => {
  const { evaluateParticipantDataSharingConsent } = await loadParticipantDataSharingConsent();

  const first = evaluateParticipantDataSharingConsent(baseInput());
  const second = evaluateParticipantDataSharingConsent(
    baseInput({
      sharingRequest: {
        requestedScopeRefs: ['audit_readiness_metadata', 'coded_data_export'],
        requestedDataClassRefs: ['quality_evidence_metadata', 'participant_linked_metadata'],
      },
      dataSharingConsent: {
        grantedScopeRefs: ['coded_data_export', 'audit_readiness_metadata'],
        grantedDataClassRefs: ['participant_linked_metadata', 'quality_evidence_metadata'],
        interestedPartyClassRefs: ['cro', 'sponsor'],
      },
      sharingPolicy: {
        allowedInterestedPartyClasses: ['sponsor', 'cro'],
        allowedPurposes: ['sponsor_diligence', 'audit_inspection'],
        allowedScopeRefs: ['safety_reporting_metadata', 'coded_data_export', 'audit_readiness_metadata'],
        allowedDataClassRefs: ['quality_evidence_metadata', 'participant_linked_metadata'],
      },
    }),
  );

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.dataSharingConsentRecord.status, 'active');
  assert.equal(first.dataSharingConsentRecord.sharingGate, 'passed');
  assert.deepEqual(first.dataSharingConsentRecord.grantedScopeRefs, [
    'audit_readiness_metadata',
    'coded_data_export',
  ]);
  assert.deepEqual(first.dataSharingConsentRecord.grantedDataClassRefs, [
    'participant_linked_metadata',
    'quality_evidence_metadata',
  ]);
  assert.equal(first.dataSharingConsentRecord.consentId, second.dataSharingConsentRecord.consentId);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.receipt.anchorPayload.artifactType, 'participant_data_sharing_consent');
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(first), /Participant Alice|raw consent|raw dataset|direct identifier|private key/iu);
});

test('participant data sharing consent fails closed for declined expired or overbroad sharing', async () => {
  const { evaluateParticipantDataSharingConsent } = await loadParticipantDataSharingConsent();

  const denied = evaluateParticipantDataSharingConsent(
    baseInput({
      sharingRequest: {
        interestedPartyClass: 'data_broker',
        purpose: 'marketing',
        requestedScopeRefs: ['coded_data_export', 'open_ended_secondary_use'],
        requestedDataClassRefs: ['participant_linked_metadata', 'direct_identifier_dataset'],
        requestedAtHlc: { physicalMs: 1800200000000, logical: 0 },
      },
      dataSharingConsent: {
        status: 'declined',
        expiresAtHlc: { physicalMs: 1800100000000, logical: 0 },
        grantedScopeRefs: ['coded_data_export'],
        grantedDataClassRefs: ['participant_linked_metadata'],
      },
      sharingPolicy: {
        directIdentifiersAllowed: true,
        metadataOnly: false,
      },
      disclosurePlan: {
        directIdentifiersExcluded: false,
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.dataSharingConsentRecord.status, 'blocked');
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('data_sharing_consent_not_granted'));
  assert.ok(denied.reasons.includes('data_sharing_consent_expired'));
  assert.ok(denied.reasons.includes('interested_party_class_not_allowed'));
  assert.ok(denied.reasons.includes('sharing_purpose_not_allowed'));
  assert.ok(denied.reasons.includes('requested_scope_not_granted:open_ended_secondary_use'));
  assert.ok(denied.reasons.includes('requested_data_class_not_allowed:direct_identifier_dataset'));
  assert.ok(denied.reasons.includes('sharing_policy_metadata_boundary_invalid'));
  assert.ok(denied.reasons.includes('direct_identifier_boundary_invalid'));
});

test('participant data sharing consent enforces human authority review and HLC ordering', async () => {
  const { evaluateParticipantDataSharingConsent } = await loadParticipantDataSharingConsent();

  const denied = evaluateParticipantDataSharingConsent(
    baseInput({
      actor: { kind: 'ai_agent' },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['read'],
        authorityChainHash: DIGEST_A,
      },
      dataSharingConsent: {
        documentedAtHlc: { physicalMs: 1799800000000, logical: 0 },
      },
      disclosurePlan: {
        plannedAtHlc: { physicalMs: 1799700000000, logical: 0 },
      },
      humanReview: {
        approved: false,
        reviewerDid: '',
        privacyLegalReviewHash: '',
        reviewedAtHlc: { physicalMs: 1799600000000, logical: 0 },
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('human_actor_required'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('data_sharing_authority_missing'));
  assert.ok(denied.reasons.includes('consent_documented_before_policy_effective'));
  assert.ok(denied.reasons.includes('disclosure_plan_before_consent_documented'));
  assert.ok(denied.reasons.includes('human_review_not_approved'));
  assert.ok(denied.reasons.includes('human_reviewer_absent'));
  assert.ok(denied.reasons.includes('privacy_legal_review_hash_invalid'));
  assert.ok(denied.reasons.includes('human_review_before_disclosure_plan'));
});

test('participant data sharing consent must remain active through human privacy review', async () => {
  const { evaluateParticipantDataSharingConsent } = await loadParticipantDataSharingConsent();

  const denied = evaluateParticipantDataSharingConsent(
    baseInput({
      dataSharingConsent: {
        expiresAtHlc: { physicalMs: 1800000000000, logical: 3 },
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('data_sharing_consent_expired_before_review'));
});

test('participant data sharing request must remain active through human privacy review', async () => {
  const { evaluateParticipantDataSharingConsent } = await loadParticipantDataSharingConsent();

  const denied = evaluateParticipantDataSharingConsent(
    baseInput({
      sharingRequest: {
        expiresAtHlc: { physicalMs: 1800000000000, logical: 3 },
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('sharing_request_expired_before_review'));
});

test('participant data sharing consent rejects protected content and secrets before receipts', async () => {
  const { evaluateParticipantDataSharingConsent } = await loadParticipantDataSharingConsent();

  assert.throws(
    () =>
      evaluateParticipantDataSharingConsent(
        baseInput({
          participant: {
            participantName: 'Participant Alice Example',
          },
        }),
      ),
    /protected content/i,
  );

  assert.throws(
    () =>
      evaluateParticipantDataSharingConsent(
        baseInput({
          disclosurePlan: {
            rawDataset: 'must never be packaged in a consent receipt',
          },
        }),
      ),
    /protected content/i,
  );

  assert.throws(
    () =>
      evaluateParticipantDataSharingConsent(
        baseInput({
          sharingPolicy: {
            privateKey: 'secret-value',
          },
        }),
      ),
    /protected content|secret/i,
  );
});
