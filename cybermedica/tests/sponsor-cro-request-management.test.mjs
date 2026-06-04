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

const REQUIRED_REQUEST_DOMAINS = [
  'audit_evidence',
  'capa_status',
  'consent_readiness',
  'deviation_status',
  'evidence_index',
  'monitoring_findings',
  'quality_metrics',
  'risk_register',
  'site_readiness',
  'training_status',
];

async function loadSponsorCroRequestManagement() {
  try {
    return await import('../src/sponsor-cro-request-management.mjs');
  } catch (error) {
    assert.fail(`CyberMedica Sponsor/CRO request management module must exist and load: ${error.message}`);
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

function requestDomain(domain, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4];
  return {
    domain,
    requested: true,
    evidenceIndexHash: hashes[index],
    disclosureBoundaryHash: hashes[(index + 1) % hashes.length],
    accessDecisionHash: hashes[(index + 2) % hashes.length],
    metadataOnly: true,
    protectedContentExcluded: true,
    sponsorConfidentialMinimized: true,
    sourcePayloadExcluded: true,
    ...overrides,
  };
}

function requestInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    requesterTenantId: 'tenant-sponsor-alpha',
    actor: {
      did: 'did:exo:sponsor-ops-requester-alpha',
      kind: 'human',
      roleRefs: ['sponsor_viewer'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['read', 'request_disclosure'],
      authorityChainHash: DIGEST_A,
    },
    request: {
      requestRef: 'sponsor-cro-request-alpha',
      requesterClass: 'sponsor',
      requestType: 'readiness_packet',
      purpose: 'sponsor_cro_diligence',
      requestedDomains: REQUIRED_REQUEST_DOMAINS,
      objectRefs: ['site-qms-passport-alpha', 'diligence-packet-alpha'],
      requestedAtHlc: { physicalMs: 1797000000000, logical: 0 },
      responseDueAtHlc: { physicalMs: 1797604800000, logical: 0 },
      materialDecisionImpact: true,
      metadataOnly: true,
      sourcePayloadExcluded: true,
      exochainProductionClaim: false,
    },
    accessPolicy: {
      policyRef: 'sponsor-cro-disclosure-policy-alpha',
      policyHash: DIGEST_B,
      allowedRequesterClasses: ['cro', 'sponsor'],
      allowedPurposes: ['monitoring', 'sponsor_cro_diligence'],
      allowedDomains: REQUIRED_REQUEST_DOMAINS,
      siteApprovalRequired: true,
      disclosureLogRequired: true,
      participantDirectIdentifiersExcluded: true,
      sponsorConfidentialMinimized: true,
      metadataOnly: true,
      productionTrustClaim: false,
    },
    domainRequests: REQUIRED_REQUEST_DOMAINS.map(requestDomain),
    workItem: {
      workItemRef: 'sponsor-cro-work-item-alpha',
      ownerRoleRef: 'quality_manager',
      status: 'queued_for_site_review',
      priority: 'standard',
      triageEvidenceHash: DIGEST_C,
      createdAtHlc: { physicalMs: 1797000000000, logical: 1 },
      responseWorkflowRef: 'workflow-sponsor-cro-request-response',
      metadataOnly: true,
    },
    decisionForum: {
      requiredForMaterialRequest: true,
      matterRef: 'df-sponsor-cro-request-alpha',
      routingReceiptHash: DIGEST_D,
      state: 'routed',
      humanGate: { verified: true },
      quorum: { status: 'not_required_until_review' },
      openChallenge: false,
      metadataOnly: true,
    },
    disclosureEvent: {
      eventRef: 'disclosure-event-sponsor-cro-alpha',
      disclosureLogHash: DIGEST_E,
      recipientClass: 'sponsor',
      purpose: 'sponsor_cro_diligence',
      loggedAtHlc: { physicalMs: 1797000000000, logical: 2 },
      disclosureClasses: ['quality_evidence_metadata', 'sponsor_confidential_metadata'],
      includesRawContent: false,
      metadataOnly: true,
      sourcePayloadExcluded: true,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      evidenceRefs: ['evidence-index-alpha', 'role-dashboard-alpha'],
      reasoningSummaryHash: DIGEST_F,
      confidenceBasisPoints: 8300,
      limitationHashes: [DIGEST_1],
      recommendedHumanReviewerDids: ['did:exo:quality-manager-alpha'],
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-manager-alpha',
      status: 'approved_for_intake',
      reviewedAtHlc: { physicalMs: 1797000000000, logical: 3 },
      reviewEvidenceHash: DIGEST_2,
      aiFinalAuthorityRejected: true,
    },
    custodyDigest: DIGEST_3,
  };

  return mergeDeep(base, overrides);
}

test('Sponsor/CRO request intake creates deterministic controlled work items and disclosure receipts', async () => {
  const { evaluateSponsorCroRequest } = await loadSponsorCroRequestManagement();

  const resultA = evaluateSponsorCroRequest(requestInput());
  const resultB = evaluateSponsorCroRequest(
    requestInput({
      request: {
        requestedDomains: [...REQUIRED_REQUEST_DOMAINS].reverse(),
        objectRefs: ['diligence-packet-alpha', 'site-qms-passport-alpha'],
      },
      accessPolicy: {
        allowedDomains: [...REQUIRED_REQUEST_DOMAINS].reverse(),
      },
      domainRequests: REQUIRED_REQUEST_DOMAINS.map(requestDomain).reverse(),
      disclosureEvent: {
        disclosureClasses: ['sponsor_confidential_metadata', 'quality_evidence_metadata'],
      },
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.workItem.status, 'queued_for_site_review');
  assert.deepEqual(resultA.workItem.requestedDomains, REQUIRED_REQUEST_DOMAINS);
  assert.equal(resultA.workItem.materialDecisionImpact, true);
  assert.equal(resultA.workItem.disclosureEventRef, 'disclosure-event-sponsor-cro-alpha');
  assert.equal(resultA.workItem.decisionForumMatterRef, 'df-sponsor-cro-request-alpha');
  assert.equal(resultA.workItem.metadataOnly, true);
  assert.equal(resultA.workItem.exochainProductionClaim, false);
  assert.equal(resultA.workItem.requestHash, resultB.workItem.requestHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'sponsor_cro_request_work_item');
  assert.doesNotMatch(JSON.stringify(resultA), /Participant Alice|raw request|source document|access token/iu);
});

test('Sponsor/CRO requests fail closed for unsafe access policy disclosure and material routing defects', async () => {
  const { evaluateSponsorCroRequest } = await loadSponsorCroRequestManagement();

  const result = evaluateSponsorCroRequest(
    requestInput({
      request: {
        requesterClass: 'public_observer',
        purpose: 'unspecified',
        requestedDomains: ['audit_evidence', 'participant_listing'],
      },
      accessPolicy: {
        allowedPurposes: ['monitoring'],
        allowedDomains: ['audit_evidence'],
        siteApprovalRequired: false,
        disclosureLogRequired: false,
        participantDirectIdentifiersExcluded: false,
        metadataOnly: false,
        productionTrustClaim: true,
      },
      domainRequests: [
        requestDomain('audit_evidence', 0),
        requestDomain('participant_listing', 1, {
          evidenceIndexHash: 'not-a-digest',
          metadataOnly: false,
          protectedContentExcluded: false,
        }),
      ],
      decisionForum: {
        requiredForMaterialRequest: true,
        matterRef: '',
        routingReceiptHash: '',
        state: 'not_routed',
        humanGate: { verified: false },
        metadataOnly: false,
      },
      disclosureEvent: {
        disclosureLogHash: '',
        includesRawContent: true,
        metadataOnly: false,
        sourcePayloadExcluded: false,
      },
      humanReview: {
        status: 'pending',
        aiFinalAuthorityRejected: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('requester_class_unsupported'));
  assert.ok(result.reasons.includes('request_purpose_not_allowed'));
  assert.ok(result.reasons.includes('request_domain_unsupported:participant_listing'));
  assert.ok(result.reasons.includes('domain_evidence_index_hash_invalid:participant_listing'));
  assert.ok(result.reasons.includes('domain_metadata_boundary_invalid:participant_listing'));
  assert.ok(result.reasons.includes('site_approval_required_absent'));
  assert.ok(result.reasons.includes('disclosure_log_required_absent'));
  assert.ok(result.reasons.includes('participant_identifier_boundary_invalid'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('material_request_decision_forum_matter_absent'));
  assert.ok(result.reasons.includes('material_request_human_gate_unverified'));
  assert.ok(result.reasons.includes('disclosure_event_hash_invalid'));
  assert.ok(result.reasons.includes('disclosure_event_raw_content_included'));
  assert.ok(result.reasons.includes('human_review_not_approved'));
});

test('Sponsor/CRO request management rejects raw request content and secrets before work-item creation', async () => {
  const { evaluateSponsorCroRequest } = await loadSponsorCroRequestManagement();

  assert.throws(
    () =>
      evaluateSponsorCroRequest(
        requestInput({
          request: {
            rawRequestNarrative: 'Participant Alice source record requested for diligence.',
          },
        }),
      ),
    /raw sponsor\/cro request content|protected content/i,
  );

  assert.throws(
    () =>
      evaluateSponsorCroRequest(
        requestInput({
          disclosureEvent: {
            authorizationHeader: 'Bearer access-token-alpha',
          },
        }),
      ),
    /sponsor\/cro request secret|protected content/i,
  );
});
