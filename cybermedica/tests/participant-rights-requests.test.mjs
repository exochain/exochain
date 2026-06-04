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

async function loadParticipantRightsRequests() {
  try {
    return await import('../src/participant-rights-requests.mjs');
  } catch (error) {
    assert.fail(`CyberMedica participant-rights request module must exist and load: ${error.message}`);
  }
}

function participantRightsInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:privacy-officer-alpha',
      kind: 'human',
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['manage_participant_rights', 'privacy_review'],
      authorityChainHash: DIGEST_F,
    },
    participant: {
      participantCodeRecordId: 'cmpcode_active_alpha',
      participantCodeHash: DIGEST_A,
      studyRef: 'study-cardiac-alpha',
      protocolRef: 'protocol-cardiac-alpha',
      siteRef: 'site-alpha',
      consentBailmentRef: 'bailment-participant-alpha',
      currentStatus: 'enrolled',
    },
    rightsPolicy: {
      policyRef: 'participant-rights-policy-v1',
      policyHash: DIGEST_B,
      status: 'active',
      allowedScopeRefs: [
        'consent_history',
        'disclosure_accounting',
        'participant_data_sharing_preferences',
        'retention_disposition_metadata',
      ],
      allowedDataClassRefs: [
        'consent_metadata',
        'disclosure_metadata',
        'participant_linked_metadata',
        'retention_metadata',
      ],
      allowedRequestTypes: [
        'access_review',
        'accounting_of_disclosures',
        'amendment_review',
        'data_sharing_preference_review',
        'restriction_review',
        'retention_disposition_review',
      ],
      metadataOnly: true,
      directIdentifierResponseForbidden: true,
      retentionOverrideForbidden: true,
      disclosureLogRequired: true,
      effectiveAtHlc: { physicalMs: 1797000000000, logical: 0 },
    },
    request: {
      requestRef: 'rights-request-alpha',
      requestType: 'accounting_of_disclosures',
      requesterClass: 'legally_authorized_representative',
      requestedScopeRefs: ['disclosure_accounting', 'consent_history'],
      requestedDataClassRefs: ['participant_linked_metadata', 'disclosure_metadata'],
      requestedAtHlc: { physicalMs: 1797000000000, logical: 1 },
      metadataOnly: true,
      productionTrustClaim: false,
    },
    identityVerification: {
      verified: true,
      requesterClass: 'legally_authorized_representative',
      verificationEvidenceHash: DIGEST_C,
      authorizationEvidenceHash: DIGEST_D,
      verifiedAtHlc: { physicalMs: 1797000000000, logical: 2 },
    },
    privacyControls: {
      protectedDataClassificationHash: DIGEST_A,
      accessRestrictionHash: DIGEST_B,
      retentionPolicyHash: DIGEST_C,
      disclosureLogRef: 'disclosure-log-alpha',
      disclosureLogHash: DIGEST_D,
      dataMinimizationHash: DIGEST_E,
      responsePackageMetadataOnly: true,
      directIdentifiersExcluded: true,
      rawRecordAccessExcluded: true,
      retentionPreserved: true,
      consentTrackingRef: 'consent-tracking-alpha',
      consentTrackingHash: DIGEST_F,
    },
    humanReview: {
      reviewerDid: 'did:exo:privacy-officer-alpha',
      decision: 'fulfilled_metadata_only',
      responsePackageHash: DIGEST_E,
      participantNotificationHash: DIGEST_F,
      reviewedAtHlc: { physicalMs: 1797000000000, logical: 3 },
      aiFinalAuthority: false,
    },
    custodyDigest: DIGEST_F,
  };

  return {
    ...base,
    ...overrides,
    actor: { ...base.actor, ...overrides.actor },
    authority: { ...base.authority, ...overrides.authority },
    participant: { ...base.participant, ...overrides.participant },
    rightsPolicy: { ...base.rightsPolicy, ...overrides.rightsPolicy },
    request: { ...base.request, ...overrides.request },
    identityVerification: { ...base.identityVerification, ...overrides.identityVerification },
    privacyControls: { ...base.privacyControls, ...overrides.privacyControls },
    humanReview: { ...base.humanReview, ...overrides.humanReview },
  };
}

test('participant rights request creates deterministic inactive metadata receipts', async () => {
  const { evaluateParticipantRightsRequest } = await loadParticipantRightsRequests();

  const resultA = evaluateParticipantRightsRequest(participantRightsInput());
  const resultB = evaluateParticipantRightsRequest(
    participantRightsInput({
      request: {
        requestedScopeRefs: ['consent_history', 'disclosure_accounting'],
        requestedDataClassRefs: ['disclosure_metadata', 'participant_linked_metadata'],
      },
      rightsPolicy: {
        allowedRequestTypes: [
          'retention_disposition_review',
          'restriction_review',
          'data_sharing_preference_review',
          'amendment_review',
          'accounting_of_disclosures',
          'access_review',
        ],
      },
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.rightsRequestRecord.status, 'fulfilled_metadata_only');
  assert.equal(resultA.rightsRequestRecord.requestType, 'accounting_of_disclosures');
  assert.deepEqual(resultA.rightsRequestRecord.requestedScopeRefs, ['consent_history', 'disclosure_accounting']);
  assert.deepEqual(resultA.rightsRequestRecord.requestedDataClassRefs, [
    'disclosure_metadata',
    'participant_linked_metadata',
  ]);
  assert.equal(resultA.rightsRequestRecord.directIdentifiersExcluded, true);
  assert.equal(resultA.rightsRequestRecord.rawRecordAccessExcluded, true);
  assert.equal(resultA.rightsRequestRecord.retentionPreserved, true);
  assert.equal(resultA.rightsRequestRecord.exochainProductionClaim, false);
  assert.equal(resultA.rightsRequestRecord.rightsRequestRecordId, resultB.rightsRequestRecord.rightsRequestRecordId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'participant_rights_request');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(resultA), /Participant Alice|medical record|direct identifier|full record body/iu);
});

test('participant rights request fails closed for unsafe policy identity and retention posture', async () => {
  const { evaluateParticipantRightsRequest } = await loadParticipantRightsRequests();

  const denied = evaluateParticipantRightsRequest(
    participantRightsInput({
      actor: { kind: 'ai_agent' },
      authority: {
        valid: false,
        permissions: ['read'],
        authorityChainHash: 'not-a-digest',
      },
      participant: {
        participantCodeHash: 'not-a-digest',
        consentBailmentRef: '',
      },
      rightsPolicy: {
        status: 'draft',
        allowedRequestTypes: ['accounting_of_disclosures'],
        metadataOnly: false,
        directIdentifierResponseForbidden: false,
        retentionOverrideForbidden: false,
        disclosureLogRequired: false,
      },
      request: {
        requestType: 'erasure',
        metadataOnly: false,
        productionTrustClaim: true,
      },
      identityVerification: {
        verified: false,
        verificationEvidenceHash: '',
        authorizationEvidenceHash: '',
      },
      privacyControls: {
        responsePackageMetadataOnly: false,
        directIdentifiersExcluded: false,
        rawRecordAccessExcluded: false,
        retentionPreserved: false,
        disclosureLogHash: '',
      },
      humanReview: {
        decision: 'fulfilled_metadata_only',
        responsePackageHash: '',
        participantNotificationHash: '',
        aiFinalAuthority: true,
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.rightsRequestRecord.status, 'blocked');
  assert.equal(denied.receipt, null);
  assert.match(denied.reasons.join('|'), /ai_final_authority_forbidden/);
  assert.match(denied.reasons.join('|'), /participant_rights_authority_missing/);
  assert.match(denied.reasons.join('|'), /participant_code_hash_invalid/);
  assert.match(denied.reasons.join('|'), /rights_policy_not_active/);
  assert.match(denied.reasons.join('|'), /rights_request_type_unsupported/);
  assert.match(denied.reasons.join('|'), /rights_request_metadata_boundary_invalid/);
  assert.match(denied.reasons.join('|'), /rights_request_production_trust_claim_forbidden/);
  assert.match(denied.reasons.join('|'), /identity_verification_absent/);
  assert.match(denied.reasons.join('|'), /direct_identifier_response_boundary_invalid/);
  assert.match(denied.reasons.join('|'), /retention_preservation_absent/);
  assert.match(denied.reasons.join('|'), /disclosure_log_hash_invalid/);
  assert.match(denied.reasons.join('|'), /response_package_hash_invalid/);
  assert.match(denied.reasons.join('|'), /participant_notification_hash_invalid/);
});

test('participant rights request validates HLC ordering human review and metadata-only response', async () => {
  const { evaluateParticipantRightsRequest } = await loadParticipantRightsRequests();

  const denied = evaluateParticipantRightsRequest(
    participantRightsInput({
      rightsPolicy: {
        effectiveAtHlc: { physicalMs: 1797000000000, logical: 2 },
      },
      request: {
        requestedAtHlc: { physicalMs: 1797000000000, logical: 1 },
      },
      identityVerification: {
        verifiedAtHlc: { physicalMs: 1797000000000, logical: 0 },
      },
      humanReview: {
        reviewedAtHlc: { physicalMs: 1797000000000, logical: 1 },
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.rightsRequestRecord.status, 'blocked');
  assert.match(denied.reasons.join('|'), /rights_request_before_policy_effective/);
  assert.match(denied.reasons.join('|'), /identity_verification_before_request/);
  assert.match(denied.reasons.join('|'), /human_review_not_after_identity_verification/);
});

test('participant rights request denies scopes and data classes outside privacy policy', async () => {
  const { evaluateParticipantRightsRequest } = await loadParticipantRightsRequests();

  const denied = evaluateParticipantRightsRequest(
    participantRightsInput({
      request: {
        requestedScopeRefs: ['disclosure_accounting', 'source_document_body_access'],
        requestedDataClassRefs: ['participant_linked_metadata', 'direct_identifier_dataset'],
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.rightsRequestRecord.status, 'blocked');
  assert.equal(denied.receipt, null);
  assert.match(denied.reasons.join('|'), /rights_request_scope_not_allowed:source_document_body_access/);
  assert.match(denied.reasons.join('|'), /rights_request_data_class_not_allowed:direct_identifier_dataset/);
});

test('participant rights request rejects raw participant content and secrets before receipts', async () => {
  const { evaluateParticipantRightsRequest } = await loadParticipantRightsRequests();

  assert.throws(
    () =>
      evaluateParticipantRightsRequest(
        participantRightsInput({
          request: { rawParticipantRequest: 'Participant Alice asks for the full record body' },
        }),
      ),
    /participant rights protected content/i,
  );

  assert.throws(
    () =>
      evaluateParticipantRightsRequest(
        participantRightsInput({
          privacyControls: { accessToken: 'secret-token-value' },
        }),
      ),
    /participant rights secret field/i,
  );
});
