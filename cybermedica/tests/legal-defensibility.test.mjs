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

const REQUIRED_DOMAINS = [
  'access_logs',
  'custody',
  'decision_rationale',
  'provenance',
  'timestamps',
  'version_history',
];

async function loadLegalDefensibility() {
  try {
    return await import('../src/legal-defensibility.mjs');
  } catch (error) {
    assert.fail(`CyberMedica legal defensibility module must exist and load: ${error.message}`);
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

function defensibilityEvidence(overrides = {}) {
  return {
    evidenceRef: 'evidence-capa-critical-alpha',
    objectFamily: 'capa',
    artifactHash: DIGEST_A,
    metadataHash: DIGEST_B,
    provenanceHash: DIGEST_C,
    custodyDigest: DIGEST_D,
    timestampHash: DIGEST_E,
    accessLogHash: DIGEST_F,
    decisionRationaleHash: DIGEST_1,
    versionHistoryHash: DIGEST_2,
    correctionHistoryHash: DIGEST_3,
    retentionRuleRef: 'retention-qms-10y',
    classification: 'restricted_metadata_only',
    sensitivityTags: ['metadata_only', 'quality_evidence'],
    custodianRoleRef: 'quality_manager',
    ownerDidHash: DIGEST_4,
    recordedAtHlc: { physicalMs: 1799000100000, logical: 0 },
    reviewedAtHlc: { physicalMs: 1799000100000, logical: 1 },
    metadataOnly: true,
    rawContentExcluded: true,
    sourcePayloadExcluded: true,
    ...overrides,
  };
}

function defensibilityInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:quality-manager-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'auditor'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['legal_defensibility_pack', 'read'],
      authorityChainHash: DIGEST_A,
    },
    packRequest: {
      requestRef: 'nfr014-defensibility-pack-alpha',
      subjectRef: 'site-alpha-qms',
      purposes: ['diligence', 'inspection', 'audit', 'dispute_resolution'],
      requestedAtHlc: { physicalMs: 1799000200000, logical: 0 },
      assembledAtHlc: { physicalMs: 1799000200000, logical: 3 },
      metadataOnly: true,
      protectedContentExcluded: true,
      exochainProductionClaim: false,
    },
    preservationProfile: {
      profileRef: 'legal-defensibility-profile-alpha',
      profileHash: DIGEST_B,
      status: 'approved',
      requiredDomains: REQUIRED_DOMAINS,
      approvedAtHlc: { physicalMs: 1799000000000, logical: 0 },
      metadataOnly: true,
      rawContentForbidden: true,
      appendOnlyEvidenceRequired: true,
      productionTrustClaim: false,
    },
    accessPolicy: {
      policyRef: 'defensibility-access-policy-alpha',
      policyHash: DIGEST_C,
      status: 'active',
      allowedPurposes: ['audit', 'diligence', 'dispute_resolution', 'inspection'],
      allowedObjectFamilies: ['audit', 'capa', 'decision', 'document', 'evidence'],
      allowedSensitivityTags: ['metadata_only', 'quality_evidence', 'sponsor_confidential_metadata'],
      sourcePayloadAccessible: false,
      disclosureLogRequired: true,
      evaluatedAtHlc: { physicalMs: 1799000200000, logical: 1 },
      metadataOnly: true,
    },
    evidenceItems: [
      defensibilityEvidence({
        evidenceRef: 'document-policy-version-alpha',
        objectFamily: 'document',
        artifactHash: DIGEST_5,
        metadataHash: DIGEST_6,
        provenanceHash: DIGEST_7,
        custodyDigest: DIGEST_8,
        versionHistoryHash: DIGEST_9,
        sensitivityTags: ['metadata_only', 'sponsor_confidential_metadata'],
      }),
      defensibilityEvidence(),
    ],
    accessLog: {
      logRef: 'defensibility-access-log-alpha',
      accessLogHash: DIGEST_D,
      includedEventCount: 14,
      privilegedActionsIncluded: true,
      includesRawContent: false,
      loggedAtHlc: { physicalMs: 1799000200000, logical: 2 },
    },
    decisionRationaleIndex: {
      indexRef: 'defensibility-decision-rationale-alpha',
      indexHash: DIGEST_E,
      decisionRefs: ['decision-launch-alpha', 'decision-capa-alpha'],
      rationaleHashes: [DIGEST_F, DIGEST_1],
      quorumEvidenceHashes: [DIGEST_2],
      aiAssistanceDisclosed: true,
      unresolvedChallengeCount: 0,
      metadataOnly: true,
    },
    legalReview: {
      reviewerDid: 'did:exo:legal-quality-reviewer-alpha',
      reviewerRoleRef: 'independent_quality_reviewer',
      status: 'approved',
      reviewedAtHlc: { physicalMs: 1799000200000, logical: 2 },
      reviewHash: DIGEST_F,
      independentReviewerForDisputes: true,
      aiFinalAuthorityRejected: true,
    },
    disclosureLog: {
      disclosureRef: 'defensibility-disclosure-alpha',
      disclosureLogHash: DIGEST_1,
      recipientClass: 'auditor',
      purposeHash: DIGEST_2,
      loggedAtHlc: { physicalMs: 1799000200000, logical: 2 },
      includesRawContent: false,
    },
    retentionHold: {
      holdRef: 'legal-hold-alpha',
      holdHash: DIGEST_3,
      status: 'active',
      appliesToDisputeResolution: true,
      expiresAtHlc: { physicalMs: 1800000000000, logical: 0 },
      retentionRuleHash: DIGEST_4,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      scopeHash: DIGEST_5,
      evidenceRefs: ['document-policy-version-alpha', 'evidence-capa-critical-alpha'],
      limitationHashes: [DIGEST_6],
      reviewedByHuman: true,
    },
  };
  return mergeDeep(base, overrides);
}

test('legal defensibility pack preserves NFR-014 evidence domains deterministically', async () => {
  const { evaluateLegalDefensibilityPack } = await loadLegalDefensibility();

  const resultA = evaluateLegalDefensibilityPack(defensibilityInput());
  const resultB = evaluateLegalDefensibilityPack(
    defensibilityInput({
      packRequest: {
        purposes: ['inspection', 'dispute_resolution', 'diligence', 'audit'],
      },
      preservationProfile: {
        requiredDomains: [...REQUIRED_DOMAINS].reverse(),
      },
      evidenceItems: [...defensibilityInput().evidenceItems].reverse(),
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.legalPack.packageId, resultB.legalPack.packageId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.legalPack.trustState, 'inactive');
  assert.equal(resultA.legalPack.exochainProductionClaim, false);
  assert.equal(resultA.legalPack.metadataOnly, true);
  assert.equal(resultA.legalPack.legalDefensibilitySubjectToHumanReview, true);
  assert.deepEqual(resultA.legalPack.purposes, ['audit', 'diligence', 'dispute_resolution', 'inspection']);
  assert.deepEqual(resultA.legalPack.preservedDomains, REQUIRED_DOMAINS);
  assert.deepEqual(resultA.legalPack.preservationMatrix, {
    access_logs: true,
    custody: true,
    decision_rationale: true,
    provenance: true,
    timestamps: true,
    version_history: true,
  });
  assert.deepEqual(
    resultA.legalPack.evidenceItems.map((item) => item.evidenceRef),
    ['document-policy-version-alpha', 'evidence-capa-critical-alpha'],
  );
  assert.deepEqual(Object.keys(resultA.legalPack.evidenceItems[0]), [
    'accessLogHash',
    'artifactHash',
    'classification',
    'correctionHistoryHash',
    'custodyDigest',
    'decisionRationaleHash',
    'evidenceRef',
    'metadataHash',
    'objectFamily',
    'provenanceHash',
    'recordedAtHlc',
    'retentionRuleRef',
    'timestampHash',
    'versionHistoryHash',
  ]);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
});

test('legal defensibility pack fails closed when required preservation domains or metadata proofs are missing', async () => {
  const { evaluateLegalDefensibilityPack } = await loadLegalDefensibility();

  const result = evaluateLegalDefensibilityPack(
    defensibilityInput({
      preservationProfile: {
        requiredDomains: ['custody', 'provenance'],
      },
      evidenceItems: [
        defensibilityEvidence({
          accessLogHash: '',
          decisionRationaleHash: DIGEST_1,
          versionHistoryHash: '',
          timestampHash: DIGEST_E,
          provenanceHash: DIGEST_C,
        }),
      ],
      accessLog: {
        accessLogHash: '',
        includedEventCount: 0,
        privilegedActionsIncluded: false,
      },
      decisionRationaleIndex: {
        rationaleHashes: [],
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(Object.hasOwn(result, 'receipt'), false);
  assert.deepEqual(result.reasons, [
    'access_log_event_count_invalid',
    'access_log_hash_invalid',
    'decision_rationale_index_empty',
    'evidence_access_log_hash_invalid:evidence-capa-critical-alpha',
    'evidence_version_history_hash_invalid:evidence-capa-critical-alpha',
    'preservation_domain_missing:access_logs',
    'preservation_domain_missing:decision_rationale',
    'preservation_domain_missing:timestamps',
    'preservation_domain_missing:version_history',
  ]);
});

test('legal defensibility pack requires human review access policy legal hold and non-final AI assistance', async () => {
  const { evaluateLegalDefensibilityPack } = await loadLegalDefensibility();

  const result = evaluateLegalDefensibilityPack(
    defensibilityInput({
      accessPolicy: {
        status: 'draft',
        allowedPurposes: ['audit'],
        sourcePayloadAccessible: true,
      },
      legalReview: {
        status: 'pending',
        independentReviewerForDisputes: false,
        aiFinalAuthorityRejected: false,
      },
      retentionHold: {
        status: 'inactive',
        expiresAtHlc: { physicalMs: 1799000200000, logical: 3 },
      },
      aiAssistance: {
        finalAuthority: true,
        reviewedByHuman: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.deepEqual(result.reasons, [
    'access_policy_not_active',
    'access_policy_source_payload_boundary_invalid',
    'ai_final_authority_forbidden',
    'ai_human_review_absent',
    'legal_hold_expired',
    'legal_hold_not_active',
    'legal_review_not_approved',
    'legal_review_rejected_ai_finality_absent',
    'requested_purpose_not_allowed:diligence',
    'requested_purpose_not_allowed:dispute_resolution',
    'requested_purpose_not_allowed:inspection',
    'retention_hold_dispute_coverage_absent',
  ]);
});

test('legal defensibility pack enforces append-only HLC ordering and same-tick logical clocks', async () => {
  const { evaluateLegalDefensibilityPack } = await loadLegalDefensibility();

  const permitted = evaluateLegalDefensibilityPack(
    defensibilityInput({
      accessPolicy: {
        evaluatedAtHlc: { physicalMs: 1799000200000, logical: 0 },
      },
      accessLog: {
        loggedAtHlc: { physicalMs: 1799000200000, logical: 1 },
      },
      legalReview: {
        reviewedAtHlc: { physicalMs: 1799000200000, logical: 2 },
      },
      packRequest: {
        assembledAtHlc: { physicalMs: 1799000200000, logical: 3 },
      },
    }),
  );
  assert.equal(permitted.decision, 'permitted');

  const denied = evaluateLegalDefensibilityPack(
    defensibilityInput({
      evidenceItems: [
        defensibilityEvidence({
          reviewedAtHlc: { physicalMs: 1799000200000, logical: 4 },
        }),
      ],
      accessPolicy: {
        evaluatedAtHlc: { physicalMs: 1799000200000, logical: 5 },
      },
      legalReview: {
        reviewedAtHlc: { physicalMs: 1799000200000, logical: 2 },
      },
      packRequest: {
        assembledAtHlc: { physicalMs: 1799000200000, logical: 3 },
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.deepEqual(denied.reasons, [
    'access_policy_evaluated_after_assembly',
    'evidence_reviewed_after_assembly:evidence-capa-critical-alpha',
  ]);
});

test('legal defensibility pack handles no-AI non-dispute and malformed evidence branches', async () => {
  const { evaluateLegalDefensibilityPack } = await loadLegalDefensibility();

  const permitted = evaluateLegalDefensibilityPack(
    defensibilityInput({
      packRequest: {
        purposes: ['audit', 'inspection'],
        rawLegalPacket: false,
      },
      retentionHold: null,
      aiAssistance: {
        used: false,
      },
    }),
  );
  assert.equal(permitted.decision, 'permitted');
  assert.deepEqual(permitted.legalPack.purposes, ['audit', 'inspection']);
  assert.equal(permitted.legalPack.retentionHoldHash, null);

  const denied = evaluateLegalDefensibilityPack(
    defensibilityInput({
      accessLog: {
        loggedAtHlc: { physicalMs: 'not-an-integer', logical: 0 },
      },
      evidenceItems: null,
      packRequest: {
        assembledAtHlc: { physicalMs: 1799000200000, logical: -1 },
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.reasons.includes('evidence_items_absent'), true);
  assert.equal(denied.reasons.includes('legal_pack_assembled_time_invalid'), true);
  assert.equal(denied.reasons.includes('access_log_time_invalid'), true);
});

test('legal defensibility pack rejects raw narratives protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateLegalDefensibilityPack } = await loadLegalDefensibility();

  assert.throws(
    () =>
      evaluateLegalDefensibilityPack(
        defensibilityInput({
          rawInspectionPacket: 'full inspection notes',
        }),
      ),
    ProtectedContentError,
  );
  assert.throws(
    () =>
      evaluateLegalDefensibilityPack(
        defensibilityInput({
          evidenceItems: [
            defensibilityEvidence({
              sourceDocumentText: 'raw source content',
            }),
          ],
        }),
      ),
    ProtectedContentError,
  );
  assert.throws(
    () =>
      evaluateLegalDefensibilityPack(
        defensibilityInput({
          rawLegalPacket: [null, false, 7],
        }),
      ),
    ProtectedContentError,
  );
  assert.throws(
    () =>
      evaluateLegalDefensibilityPack(
        defensibilityInput({
          rawAuditPacket: { recordHash: DIGEST_A },
        }),
      ),
    ProtectedContentError,
  );
  assert.throws(
    () =>
      evaluateLegalDefensibilityPack(
        defensibilityInput({
          accessPolicy: {
            clientSecret: 'secret-value',
          },
        }),
      ),
    ProtectedContentError,
  );
});
