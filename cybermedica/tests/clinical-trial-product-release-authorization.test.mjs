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

const REQUIRED_RELEASE_DOMAINS = Object.freeze([
  'access_control',
  'accountability_reconciliation',
  'blinding_randomization',
  'dispensing_authorization',
  'enrollment_gate',
  'expiration_control',
  'launch_authorization',
  'protocol_version',
  'storage_temperature',
  'visit_fit',
]);

async function loadProductReleaseAuthorization() {
  try {
    return await import('../src/clinical-trial-product-release-authorization.mjs');
  } catch (error) {
    assert.fail(`CyberMedica clinical-trial-product-release-authorization module must exist and load: ${error.message}`);
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

function domainEvidence(domainRef, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F];
  return {
    domainRef,
    status: 'verified',
    evidenceHash: hashes[index % hashes.length],
    reviewedAtHlc: { physicalMs: 1803000020000 + index, logical: 0 },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function productLot(overrides = {}) {
  return {
    productRef: 'ip-cardiac-alpha-001',
    lotRef: 'lot-alpha-001',
    protocolRef: 'protocol-cardiac-alpha',
    siteRef: 'site-alpha',
    sponsorRef: 'sponsor-alpha',
    accountabilityRef: 'product-accountability-alpha',
    accountabilityRecordHash: DIGEST_A,
    batchSerialHash: DIGEST_B,
    storageControlHash: DIGEST_C,
    temperatureControlHash: DIGEST_D,
    accessControlHash: DIGEST_E,
    blindingControlHash: DIGEST_F,
    randomizationPlanHash: DIGEST_A,
    currentProtocolVersionRef: 'protocol-cardiac-alpha-v3',
    receivedAtHlc: { physicalMs: 1803000000000, logical: 0 },
    expirationAtHlc: { physicalMs: 1813000000000, logical: 0 },
    quantityOnHand: 72,
    quantityQuarantined: 0,
    quantityRequestedForRelease: 6,
    openVarianceCount: 0,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function releaseRequest(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:ip-release-manager-alpha',
      kind: 'human',
      roleRefs: ['pharmacy_investigational_product_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['authorize_product_release', 'manage_product_accountability'],
      authorityChainHash: DIGEST_A,
    },
    releasePlan: {
      releaseRef: 'product-release-alpha-001',
      protocolRef: 'protocol-cardiac-alpha',
      protocolVersionRef: 'protocol-cardiac-alpha-v3',
      siteRef: 'site-alpha',
      studyRef: 'study-cardiac-alpha',
      status: 'ready_for_release',
      requiredDomains: REQUIRED_RELEASE_DOMAINS,
      releaseSopHash: DIGEST_B,
      protocolVersionHash: DIGEST_C,
      accountabilitySummaryHash: DIGEST_D,
      launchAuthorizationRef: 'launch-auth-alpha',
      enrollmentGateRef: 'enrollment-gate-alpha',
      assessedAtHlc: { physicalMs: 1803000060000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    productLots: [productLot()],
    releaseControls: {
      domainEvidence: REQUIRED_RELEASE_DOMAINS.map((domainRef, index) => domainEvidence(domainRef, index)),
      launchAuthorized: true,
      enrollmentGateOpen: true,
      accountabilityReconciled: true,
      storageTemperatureAcceptable: true,
      accessReviewCurrent: true,
      visitWindowVerified: true,
      participantIdentifiersSuppressed: true,
      emergencyUnblinding: {
        requested: false,
        authorized: false,
        reasonCode: null,
        authorizedByDid: null,
        authorizationHash: null,
      },
      releaseWindowClosesAtHlc: { physicalMs: 1803001060000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:principal-investigator-alpha',
      productManagerDid: 'did:exo:ip-release-manager-alpha',
      qualityReviewerDid: 'did:exo:quality-manager-alpha',
      decision: 'product_release_authorized',
      reviewedAtHlc: { physicalMs: 1803000070000, logical: 0 },
      finalAuthority: 'human',
      aiFinalAuthority: false,
      evidenceBundleHash: DIGEST_E,
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-product-release-alpha',
        workflowReceiptId: 'df-workflow-product-release-alpha',
      },
    },
    custodyDigest: DIGEST_F,
  };
  return mergeDeep(base, overrides);
}

test('clinical trial product release authorization creates deterministic inactive release receipts', async () => {
  const { evaluateClinicalTrialProductReleaseAuthorization } = await loadProductReleaseAuthorization();

  const resultA = evaluateClinicalTrialProductReleaseAuthorization(releaseRequest());
  const inputB = releaseRequest();
  inputB.releasePlan.requiredDomains = [...inputB.releasePlan.requiredDomains].reverse();
  inputB.releaseControls.domainEvidence = [...inputB.releaseControls.domainEvidence].reverse();
  const resultB = evaluateClinicalTrialProductReleaseAuthorization(inputB);

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.release.authorizationStatus, 'authorized');
  assert.equal(resultA.release.productLotCount, 1);
  assert.equal(resultA.release.totalRequestedQuantity, 6);
  assert.deepEqual(resultA.release.requiredDomains, REQUIRED_RELEASE_DOMAINS);
  assert.deepEqual(resultA.release.coveredDomains, REQUIRED_RELEASE_DOMAINS);
  assert.equal(resultA.release.aiFinalAuthority, false);
  assert.equal(resultA.release.exochainProductionClaim, false);
  assert.equal(resultA.release.containsProtectedContent, false);
  assert.equal(resultA.release.releaseAuthorizationId, resultB.release.releaseAuthorizationId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'clinical_trial_product_release_authorization');
  assert.doesNotMatch(JSON.stringify(resultA), /Participant Alice|unblinded assignment|raw product/iu);
});

test('clinical trial product release authorization denies missing domains and unavailable gates', async () => {
  const { evaluateClinicalTrialProductReleaseAuthorization } = await loadProductReleaseAuthorization();

  const result = evaluateClinicalTrialProductReleaseAuthorization(
    releaseRequest({
      releasePlan: {
        requiredDomains: REQUIRED_RELEASE_DOMAINS.filter((domainRef) => domainRef !== 'enrollment_gate'),
      },
      releaseControls: {
        domainEvidence: REQUIRED_RELEASE_DOMAINS.filter((domainRef) => domainRef !== 'launch_authorization').map(
          (domainRef, index) => domainEvidence(domainRef, index),
        ),
        launchAuthorized: false,
        enrollmentGateOpen: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.release.authorizationStatus, 'blocked');
  assert.match(result.denialReasons.join('|'), /required_domain_missing:enrollment_gate/);
  assert.match(result.denialReasons.join('|'), /domain_evidence_missing:launch_authorization/);
  assert.match(result.denialReasons.join('|'), /launch_authorization_absent/);
  assert.match(result.denialReasons.join('|'), /enrollment_gate_not_open/);
});

test('clinical trial product release authorization denies expired stock unsafe quantity and emergency unblinding gaps', async () => {
  const { evaluateClinicalTrialProductReleaseAuthorization } = await loadProductReleaseAuthorization();

  const result = evaluateClinicalTrialProductReleaseAuthorization(
    releaseRequest({
      productLots: [
        productLot({
          expirationAtHlc: { physicalMs: 1803000050000, logical: 0 },
          quantityOnHand: 5,
          quantityQuarantined: 2,
          quantityRequestedForRelease: 6,
          openVarianceCount: 1,
        }),
      ],
      releaseControls: {
        storageTemperatureAcceptable: false,
        accessReviewCurrent: false,
        emergencyUnblinding: {
          requested: true,
          authorized: false,
          reasonCode: '',
          authorizedByDid: '',
          authorizationHash: 'not-a-digest',
        },
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.match(result.denialReasons.join('|'), /product_expired_or_expiration_time_invalid:ip-cardiac-alpha-001/);
  assert.match(result.denialReasons.join('|'), /product_release_quantity_exceeds_available:ip-cardiac-alpha-001/);
  assert.match(result.denialReasons.join('|'), /product_open_variance_present:ip-cardiac-alpha-001/);
  assert.match(result.denialReasons.join('|'), /storage_temperature_not_acceptable/);
  assert.match(result.denialReasons.join('|'), /access_review_not_current/);
  assert.match(result.denialReasons.join('|'), /emergency_unblinding_not_authorized/);
  assert.match(result.denialReasons.join('|'), /emergency_unblinding_reason_absent/);
  assert.match(result.denialReasons.join('|'), /emergency_unblinding_authorizer_absent/);
  assert.match(result.denialReasons.join('|'), /emergency_unblinding_authorization_hash_invalid/);
});

test('clinical trial product release authorization denies AI final authority and Decision Forum gaps', async () => {
  const { evaluateClinicalTrialProductReleaseAuthorization } = await loadProductReleaseAuthorization();

  const result = evaluateClinicalTrialProductReleaseAuthorization(
    releaseRequest({
      actor: {
        kind: 'ai_agent',
      },
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
        decisionForum: {
          humanGate: { verified: false },
          quorum: { status: 'not_met' },
          openChallenge: true,
        },
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.match(result.denialReasons.join('|'), /ai_final_authority_forbidden/);
  assert.match(result.denialReasons.join('|'), /human_actor_required/);
  assert.match(result.denialReasons.join('|'), /human_final_authority_required/);
  assert.match(result.denialReasons.join('|'), /human_gate_unverified/);
  assert.match(result.denialReasons.join('|'), /quorum_not_met/);
  assert.match(result.denialReasons.join('|'), /challenge_open/);
});

test('clinical trial product release authorization rejects raw product content and secrets before receipts are created', async () => {
  const { ProtectedContentError, evaluateClinicalTrialProductReleaseAuthorization } =
    await loadProductReleaseAuthorization();

  assert.throws(
    () =>
      evaluateClinicalTrialProductReleaseAuthorization({
        ...releaseRequest(),
        rawProductReleaseNarrative: 'Participant Alice unblinded assignment raw product record',
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateClinicalTrialProductReleaseAuthorization({
        ...releaseRequest(),
        pharmacySecret: 'prod-secret',
      }),
    ProtectedContentError,
  );
});
