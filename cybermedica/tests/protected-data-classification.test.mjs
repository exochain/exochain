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

const REQUIRED_DATA_CLASSES = [
  'decision_governance',
  'immutable_receipt',
  'participant_linked_phi_pii',
  'public_non_sensitive',
  'quality_evidence',
  'sponsor_cro_confidential',
  'tenant_operational',
];

const REQUIRED_DIMENSIONS = [
  'access_policy',
  'confidentiality',
  'export_eligibility',
  'participant_linkage',
  'phi_pii_status',
  'retention_rule',
  'sponsor_confidentiality',
];

async function loadProtectedDataClassification() {
  try {
    return await import('../src/protected-data-classification.mjs');
  } catch (error) {
    assert.fail(`CyberMedica protected data classification module must exist and load: ${error.message}`);
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

function classRule(dataClass, index, overrides = {}) {
  const perClass = {
    decision_governance: {
      accessPolicyRef: 'access-policy-decision-governance',
      anchoringPolicy: 'metadata_receipt_allowed',
      confidentialityLevel: 'governance_metadata',
      exportEligibility: 'controlled_decision_packet',
      participantLinkage: 'not_participant_linked',
      phiPiiStatus: 'none',
      retentionRuleRef: 'retention-governance-decisions',
      sponsorConfidentiality: 'tenant_scoped',
    },
    immutable_receipt: {
      accessPolicyRef: 'access-policy-receipt-metadata',
      anchoringPolicy: 'receipt_metadata_only',
      confidentialityLevel: 'receipt_metadata',
      exportEligibility: 'receipt_manifest_only',
      participantLinkage: 'pseudonymous_reference_only',
      phiPiiStatus: 'metadata_only',
      retentionRuleRef: 'retention-immutable-receipts',
      sponsorConfidentiality: 'reference_only',
    },
    participant_linked_phi_pii: {
      accessPolicyRef: 'access-policy-participant-linked',
      anchoringPolicy: 'no_raw_anchor_hash_reference_only',
      confidentialityLevel: 'participant_restricted',
      exportEligibility: 'consent_and_disclosure_grant_required',
      participantLinkage: 'participant_code_hash_only',
      phiPiiStatus: 'phi_pii_restricted',
      retentionRuleRef: 'retention-participant-protected',
      sponsorConfidentiality: 'study_scoped',
    },
    public_non_sensitive: {
      accessPolicyRef: 'access-policy-public-approved',
      anchoringPolicy: 'metadata_anchor_allowed_after_approval',
      confidentialityLevel: 'public_approved',
      exportEligibility: 'public_after_approval',
      participantLinkage: 'none',
      phiPiiStatus: 'none',
      retentionRuleRef: 'retention-public-approved',
      sponsorConfidentiality: 'none',
    },
    quality_evidence: {
      accessPolicyRef: 'access-policy-quality-evidence',
      anchoringPolicy: 'hash_only_receipt_allowed',
      confidentialityLevel: 'quality_metadata',
      exportEligibility: 'controlled_diligence_packet',
      participantLinkage: 'case_by_case_metadata',
      phiPiiStatus: 'metadata_only',
      retentionRuleRef: 'retention-quality-evidence',
      sponsorConfidentiality: 'may_apply',
    },
    sponsor_cro_confidential: {
      accessPolicyRef: 'access-policy-sponsor-cro',
      anchoringPolicy: 'no_sponsor_body_anchor',
      confidentialityLevel: 'sponsor_cro_confidential_metadata',
      exportEligibility: 'disclosure_grant_required',
      participantLinkage: 'not_participant_linked',
      phiPiiStatus: 'none',
      retentionRuleRef: 'retention-sponsor-cro',
      sponsorConfidentiality: 'restricted',
    },
    tenant_operational: {
      accessPolicyRef: 'access-policy-tenant-operational',
      anchoringPolicy: 'metadata_anchor_allowed',
      confidentialityLevel: 'tenant_operational_metadata',
      exportEligibility: 'tenant_scoped',
      participantLinkage: 'not_participant_linked',
      phiPiiStatus: 'none',
      retentionRuleRef: 'retention-tenant-operational',
      sponsorConfidentiality: 'none',
    },
  };

  return {
    classificationId: `class-${dataClass}`,
    dataClass,
    dimensionCoverage: REQUIRED_DIMENSIONS,
    evidenceHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1][index],
    externalPayloadsRemainControlled: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    rawContentInReceiptAllowed: false,
    reviewedAtHlc: { physicalMs: 1800900100000, logical: index },
    ...perClass[dataClass],
    ...overrides,
  };
}

function classRules() {
  return REQUIRED_DATA_CLASSES.map((dataClass, index) => classRule(dataClass, index));
}

function classificationInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:data-classification-owner-alpha',
      kind: 'human',
      roleRefs: ['privacy_officer', 'quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['classify_data', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    classificationPolicy: {
      policyRef: 'protected-data-classification-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredDataClasses: REQUIRED_DATA_CLASSES,
      requiredDimensions: REQUIRED_DIMENSIONS,
      defaultDenyUnclassified: true,
      rawProtectedContentForbidden: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800900000000, logical: 0 },
    },
    classificationModel: {
      modelRef: 'protected-data-classification-model-alpha',
      modelVersion: 'v1',
      modelHash: DIGEST_C,
      approvedByHuman: true,
      approvedAtHlc: { physicalMs: 1800900200000, logical: 0 },
      rollbackVersionRef: 'protected-data-classification-model-alpha-v0',
      noProductionTrustClaim: true,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    classRules: classRules().reverse(),
    receiptBoundary: {
      boundaryRef: 'receipt-boundary-classification-alpha',
      boundaryHash: DIGEST_D,
      directIdentifierAnchorForbidden: true,
      sponsorConfidentialBodyAnchorForbidden: true,
      privilegedContentAnchorForbidden: true,
      immutableReceiptsMetadataOnly: true,
      payloadsRemainExternal: true,
      reviewedAtHlc: { physicalMs: 1800900150000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    exportPolicy: {
      policyRef: 'classification-export-policy-alpha',
      policyHash: DIGEST_E,
      participantLinkedRequiresConsent: true,
      sponsorConfidentialRequiresDisclosureGrant: true,
      suppressedRecordsDoNotRevealIdentifiers: true,
      defaultExportEligibility: false,
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1800900150000, logical: 1 },
    },
    accessPolicy: {
      policyRef: 'classification-access-policy-alpha',
      policyHash: DIGEST_F,
      roleBased: true,
      attributeBased: true,
      authorityChainRequired: true,
      leastPrivilege: true,
      timeBound: true,
      revocationImmediate: true,
      emergencyAccessRequiresRetrospectiveReview: true,
      reviewedAtHlc: { physicalMs: 1800900150000, logical: 2 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    retentionPolicy: {
      policyRef: 'classification-retention-policy-alpha',
      policyHash: DIGEST_1,
      longestApplicableRetentionWins: true,
      legalHoldOverridesDisposition: true,
      protocolSponsorRegulatoryInstitutionalCoverage: true,
      reviewedAtHlc: { physicalMs: 1800900150000, logical: 3 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    aiAssistance: {
      used: true,
      recommendationHash: DIGEST_2,
      limitationHashes: [DIGEST_3],
      advisoryOnly: true,
      finalAuthority: false,
      reviewedByHuman: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:privacy-reviewer-alpha',
      reviewerRoleRefs: ['privacy_officer', 'quality_manager'],
      decision: 'classification_model_ready',
      decisionHash: DIGEST_4,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      reviewedAtHlc: { physicalMs: 1800900300000, logical: 0 },
      metadataOnly: true,
    },
    validationEvidence: {
      commandRefs: ['node --test tests/protected-data-classification.test.mjs', 'npm run quality'],
      commandsPassed: true,
      sourceGuardPassed: true,
      noExochainSourceModified: true,
      recordedAtHlc: { physicalMs: 1800900350000, logical: 0 },
      metadataOnly: true,
    },
    custodyDigest: DIGEST_5,
  };

  return mergeDeep(base, overrides);
}

test('protected data classification creates deterministic inactive metadata receipts', async () => {
  const { evaluateProtectedDataClassification } = await loadProtectedDataClassification();

  const first = evaluateProtectedDataClassification(classificationInput());
  const second = evaluateProtectedDataClassification(
    classificationInput({
      classificationPolicy: {
        requiredDataClasses: [...REQUIRED_DATA_CLASSES].reverse(),
        requiredDimensions: [...REQUIRED_DIMENSIONS].reverse(),
      },
      classRules: classRules(),
    }),
  );

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.deepEqual(first, second);
  assert.equal(first.classificationModel.trustState, 'inactive');
  assert.equal(first.classificationModel.exochainProductionClaim, false);
  assert.equal(first.classificationModel.metadataOnly, true);
  assert.equal(first.classificationModel.containsProtectedContent, false);
  assert.deepEqual(first.classificationModel.dataClasses, REQUIRED_DATA_CLASSES);
  assert.deepEqual(first.classificationModel.dimensions, REQUIRED_DIMENSIONS);
  assert.equal(first.classificationModel.defaultDenyUnclassified, true);
  assert.equal(first.classificationModel.participantLinkedExportGuard, true);
  assert.equal(first.classificationModel.sponsorConfidentialExportGuard, true);
  assert.equal(first.receipt.anchorPayload.artifactType, 'protected_data_classification_model');
  assert.equal(first.receipt.anchorPayload.classification, 'metadata_only_data_classification');
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(first), /participant alice|source document body|sponsor budget text|api key/iu);
});

test('protected data classification fails closed for missing classes and dimensions', async () => {
  const { evaluateProtectedDataClassification } = await loadProtectedDataClassification();

  const result = evaluateProtectedDataClassification(
    classificationInput({
      classRules: classRules()
        .filter((rule) => rule.dataClass !== 'participant_linked_phi_pii')
        .map((rule) =>
          rule.dataClass === 'tenant_operational'
            ? { ...rule, accessPolicyRef: '', dimensionCoverage: ['confidentiality'] }
            : rule,
        ),
      classificationPolicy: {
        defaultDenyUnclassified: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('data_class_missing:participant_linked_phi_pii'));
  assert.ok(result.reasons.includes('class_access_policy_absent:tenant_operational'));
  assert.ok(result.reasons.includes('class_dimension_missing:tenant_operational:access_policy'));
  assert.ok(result.reasons.includes('class_dimension_missing:tenant_operational:phi_pii_status'));
  assert.ok(result.reasons.includes('default_deny_unclassified_absent'));
});

test('protected data classification enforces participant sponsor and receipt boundaries', async () => {
  const { evaluateProtectedDataClassification } = await loadProtectedDataClassification();

  const result = evaluateProtectedDataClassification(
    classificationInput({
      classRules: classRules().map((rule) => {
        if (rule.dataClass === 'participant_linked_phi_pii') {
          return {
            ...rule,
            rawContentInReceiptAllowed: true,
            externalPayloadsRemainControlled: false,
            exportEligibility: 'public_after_approval',
          };
        }
        if (rule.dataClass === 'sponsor_cro_confidential') {
          return { ...rule, sponsorConfidentiality: 'none', anchoringPolicy: 'metadata_anchor_allowed' };
        }
        if (rule.dataClass === 'immutable_receipt') {
          return { ...rule, metadataOnly: false, anchoringPolicy: 'raw_payload_allowed' };
        }
        return rule;
      }),
      receiptBoundary: {
        directIdentifierAnchorForbidden: false,
        sponsorConfidentialBodyAnchorForbidden: false,
        immutableReceiptsMetadataOnly: false,
        payloadsRemainExternal: false,
      },
      exportPolicy: {
        participantLinkedRequiresConsent: false,
        sponsorConfidentialRequiresDisclosureGrant: false,
        suppressedRecordsDoNotRevealIdentifiers: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.match(result.reasons.join('\n'), /participant_class_receipt_raw_content_allowed/);
  assert.match(result.reasons.join('\n'), /participant_class_payload_boundary_invalid/);
  assert.match(result.reasons.join('\n'), /participant_class_export_guard_invalid/);
  assert.match(result.reasons.join('\n'), /sponsor_class_confidentiality_invalid/);
  assert.match(result.reasons.join('\n'), /sponsor_class_anchor_policy_invalid/);
  assert.match(result.reasons.join('\n'), /immutable_receipt_metadata_boundary_invalid/);
  assert.match(result.reasons.join('\n'), /receipt_direct_identifier_anchor_not_forbidden/);
  assert.match(result.reasons.join('\n'), /export_participant_consent_gate_absent/);
  assert.match(result.reasons.join('\n'), /export_sponsor_disclosure_gate_absent/);
});

test('protected data classification requires human review HLC order and advisory AI only', async () => {
  const { evaluateProtectedDataClassification } = await loadProtectedDataClassification();

  const result = evaluateProtectedDataClassification(
    classificationInput({
      actor: { did: 'did:exo:ai-classifier-alpha', kind: 'ai_agent', roleRefs: ['ai_reviewer'] },
      classificationModel: {
        approvedByHuman: false,
        approvedAtHlc: { physicalMs: 1800899900000, logical: 0 },
        noProductionTrustClaim: false,
      },
      aiAssistance: {
        finalAuthority: true,
        advisoryOnly: false,
        reviewedByHuman: false,
        limitationHashes: [],
      },
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
        noProductionTrustClaim: false,
        reviewedAtHlc: { physicalMs: 1800899800000, logical: 0 },
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('classification_model_human_approval_absent'));
  assert.ok(result.reasons.includes('model_approval_before_policy'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('ai_advisory_only_absent'));
  assert.ok(result.reasons.includes('ai_human_review_absent'));
  assert.ok(result.reasons.includes('human_final_authority_absent'));
  assert.ok(result.reasons.includes('human_review_before_model_approval'));
});

test('protected data classification rejects raw protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateProtectedDataClassification } = await loadProtectedDataClassification();

  const inertMarkers = classificationInput({
    classRules: classRules().map((rule) =>
      rule.dataClass === 'participant_linked_phi_pii' ? { ...rule, rawPhiPayload: [] } : rule,
    ),
  });
  assert.equal(evaluateProtectedDataClassification(inertMarkers).decision, 'permitted');

  assert.throws(
    () =>
      evaluateProtectedDataClassification(
        classificationInput({
          classRules: classRules().map((rule) =>
            rule.dataClass === 'participant_linked_phi_pii'
              ? { ...rule, rawParticipantNote: 'participant Alice reported chest pain' }
              : rule,
          ),
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateProtectedDataClassification(
        classificationInput({
          receiptBoundary: {
            apiKey: 'cm_live_secret',
          },
        }),
      ),
    ProtectedContentError,
  );
});
