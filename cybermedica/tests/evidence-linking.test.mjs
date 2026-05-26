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

const REQUIRED_LINK_FAMILIES = [
  'control',
  'decision_matter',
  'document_version',
  'equipment',
  'facility',
  'participant_status',
  'protocol',
  'site',
  'staff_member',
  'study',
  'vendor',
];

async function loadEvidenceLinking() {
  try {
    return await import('../src/evidence-linking.mjs');
  } catch (error) {
    assert.fail(`CyberMedica evidence linking module must exist and load: ${error.message}`);
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

function linkTarget(family, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6];
  return {
    family,
    targetRef: `${family}-alpha`,
    targetHash: hashes[index],
    tenantId: 'tenant-site-alpha',
    accessPolicyRef: `access-policy-${family}`,
    relationshipHash: hashes[index + 1],
    requiredForReadiness: ['control', 'site', 'protocol', 'study'].includes(family),
    disclosureAllowed: family !== 'participant_status',
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function evidenceLinkingInput(overrides = {}) {
  return mergeDeep(
    {
      tenantId: 'tenant-site-alpha',
      targetTenantId: 'tenant-site-alpha',
      actor: { did: 'did:exo:evidence-linker-alpha', kind: 'human' },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['evidence_linking', 'write'],
        authorityChainHash: DIGEST_A,
      },
      evidenceRecord: {
        evidenceId: 'CM-EVD-UPLOAD-0042',
        evidenceType: 'source_document_index',
        artifactHash: DIGEST_B,
        classification: 'participant_related_metadata_only',
        documentVersionRef: 'CM-QMS-SOP-001@v2',
        intakeReceiptId: 'cmr_intake_0042',
        custodyDigest: DIGEST_C,
        reviewStatus: 'approved',
        approvalStatus: 'approved',
        retainedOutsideReceipt: true,
        metadataOnly: true,
        protectedContentExcluded: true,
        recordedAtHlc: { physicalMs: 1803010000000, logical: 0 },
      },
      linkPolicy: {
        policyRef: 'evidence-link-policy-alpha',
        policyHash: DIGEST_D,
        status: 'active',
        requiredLinkFamilies: REQUIRED_LINK_FAMILIES,
        participantCodeOnly: true,
        leastPrivilege: true,
        disclosureLogRequired: true,
        metadataOnly: true,
        protectedContentExcluded: true,
        reviewedAtHlc: { physicalMs: 1803010001000, logical: 0 },
      },
      linkTargets: REQUIRED_LINK_FAMILIES.map((family, index) => linkTarget(family, index)),
      humanReview: {
        status: 'approved',
        reviewerDid: 'did:exo:quality-reviewer-alpha',
        reviewHash: DIGEST_E,
        approvedAtHlc: { physicalMs: 1803010002000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      receiptEvidence: {
        artifactHash: DIGEST_F,
        custodyDigest: DIGEST_7,
      },
    },
    overrides,
  );
}

test('evidence linking creates deterministic FR-005 metadata registry across required object families', async () => {
  const { evaluateEvidenceLinking } = await loadEvidenceLinking();
  const first = evaluateEvidenceLinking(
    evidenceLinkingInput({
      linkTargets: [...evidenceLinkingInput().linkTargets].reverse(),
      linkPolicy: {
        requiredLinkFamilies: [...REQUIRED_LINK_FAMILIES].reverse(),
      },
    }),
  );
  const second = evaluateEvidenceLinking(evidenceLinkingInput());

  assert.equal(first.status, 'linked');
  assert.deepEqual(first.reasons, []);
  assert.equal(first.evidenceLinking.evidenceId, 'CM-EVD-UPLOAD-0042');
  assert.deepEqual(first.evidenceLinking.linkFamilies, REQUIRED_LINK_FAMILIES);
  assert.equal(first.evidenceLinking.readyForCompletenessScoring, true);
  assert.equal(first.evidenceLinking.readyForCustodyReview, true);
  assert.equal(first.evidenceLinking.metadataOnly, true);
  assert.equal(first.evidenceLinking.productionTrustClaim, false);
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.equal(first.receipt.anchorPayload.artifactType, 'evidence_link_registry');
  assert.equal(first.evidenceLinking.evidenceLinkingId, second.evidenceLinking.evidenceLinkingId);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.receipt.actionHash, second.receipt.actionHash);
  assert.doesNotMatch(JSON.stringify(first), /participant alice|medical record|source document body|raw payload/iu);
});

test('evidence linking fails closed for authority evidence policy link and review defects', async () => {
  const { evaluateEvidenceLinking } = await loadEvidenceLinking();
  const denied = evaluateEvidenceLinking(
    evidenceLinkingInput({
      targetTenantId: 'tenant-site-beta',
      actor: { did: 'did:exo:ai-linker-alpha', kind: 'ai_agent' },
      authority: {
        valid: true,
        revoked: true,
        expired: false,
        permissions: ['read'],
        authorityChainHash: 'not-a-digest',
      },
      evidenceRecord: {
        artifactHash: '',
        classification: 'direct_identifier_payload',
        reviewStatus: 'pending',
        approvalStatus: 'draft',
        retainedOutsideReceipt: false,
        metadataOnly: false,
        protectedContentExcluded: false,
      },
      linkPolicy: {
        status: 'inactive',
        requiredLinkFamilies: REQUIRED_LINK_FAMILIES.filter((family) => family !== 'equipment'),
        participantCodeOnly: false,
        leastPrivilege: false,
        disclosureLogRequired: false,
        metadataOnly: false,
        protectedContentExcluded: false,
        reviewedAtHlc: { physicalMs: 1803000000000, logical: 0 },
      },
      linkTargets: [
        ...REQUIRED_LINK_FAMILIES.filter((family) => family !== 'equipment').map((family, index) =>
          linkTarget(family, index),
        ),
        linkTarget('unsupported_family', 0, {
          targetRef: '',
          targetHash: '',
          tenantId: 'tenant-site-beta',
          accessPolicyRef: '',
          relationshipHash: '',
          metadataOnly: false,
          protectedContentExcluded: false,
        }),
      ],
      humanReview: {
        status: 'pending',
        reviewerDid: '',
        reviewHash: '',
        approvedAtHlc: { physicalMs: 1803000000000, logical: 0 },
        metadataOnly: false,
        protectedContentExcluded: false,
      },
      receiptEvidence: {
        artifactHash: '',
        custodyDigest: '',
      },
    }),
  );

  assert.equal(denied.status, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.evidenceLinking, null);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_chain_revoked'));
  assert.ok(denied.reasons.includes('evidence_linking_permission_missing'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('evidence_artifact_hash_invalid'));
  assert.ok(denied.reasons.includes('evidence_classification_invalid'));
  assert.ok(denied.reasons.includes('evidence_review_not_approved'));
  assert.ok(denied.reasons.includes('evidence_approval_not_approved'));
  assert.ok(denied.reasons.includes('evidence_payload_storage_boundary_invalid'));
  assert.ok(denied.reasons.includes('evidence_metadata_boundary_absent'));
  assert.ok(denied.reasons.includes('evidence_protected_boundary_absent'));
  assert.ok(denied.reasons.includes('link_policy_inactive'));
  assert.ok(denied.reasons.includes('link_policy_participant_code_boundary_absent'));
  assert.ok(denied.reasons.includes('link_policy_least_privilege_absent'));
  assert.ok(denied.reasons.includes('link_policy_disclosure_log_absent'));
  assert.ok(denied.reasons.includes('required_link_family_missing:equipment'));
  assert.ok(denied.reasons.includes('link_family_unsupported:unsupported_family'));
  assert.ok(denied.reasons.includes('link_target_ref_absent:unsupported_family'));
  assert.ok(denied.reasons.includes('link_target_tenant_mismatch:unsupported_family'));
  assert.ok(denied.reasons.includes('link_target_hash_invalid:unsupported_family'));
  assert.ok(denied.reasons.includes('human_link_review_not_approved'));
  assert.ok(denied.reasons.includes('human_link_reviewer_absent'));
  assert.ok(denied.reasons.includes('receipt_artifact_hash_invalid'));
  assert.ok(denied.reasons.includes('receipt_custody_digest_invalid'));
});

test('evidence linking denies absent objects without issuing receipts', async () => {
  const { evaluateEvidenceLinking } = await loadEvidenceLinking();
  const denied = evaluateEvidenceLinking({
    tenantId: '',
    targetTenantId: 'tenant-site-alpha',
    actor: null,
    authority: null,
    evidenceRecord: null,
    linkPolicy: null,
    linkTargets: null,
    humanReview: null,
    receiptEvidence: null,
  });

  assert.equal(denied.status, 'denied');
  assert.ok(denied.reasons.includes('tenant_absent'));
  assert.ok(denied.reasons.includes('actor_did_absent'));
  assert.ok(denied.reasons.includes('authority_chain_invalid'));
  assert.ok(denied.reasons.includes('evidence_id_absent'));
  assert.ok(denied.reasons.includes('link_policy_ref_absent'));
  assert.ok(denied.reasons.includes('link_targets_absent'));
  assert.ok(denied.reasons.includes('human_review_absent'));
  assert.ok(denied.reasons.includes('receipt_artifact_hash_invalid'));
  assert.ok(denied.reasons.includes('receipt_custody_digest_invalid'));
  assert.equal(denied.evidenceLinking, null);
  assert.equal(denied.receipt, null);
});

test('evidence linking rejects raw linked content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateEvidenceLinking } = await loadEvidenceLinking();

  assert.throws(
    () =>
      evaluateEvidenceLinking(
        evidenceLinkingInput({
          linkTargets: [
            ...evidenceLinkingInput().linkTargets,
            {
              family: 'control',
              rawSourceDocument: 'source document body for participant Alice',
            },
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateEvidenceLinking(
        evidenceLinkingInput({
          evidenceRecord: {
            rawEvidencePayload: 'raw clinical note',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateEvidenceLinking(
        evidenceLinkingInput({
          linkPolicy: {
            apiKey: 'secret-evidence-link-token',
          },
        }),
      ),
    ProtectedContentError,
  );
});
