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

const REQUIRED_STUDY_DOMAINS = [
  'authority_boundary',
  'consent_boundary',
  'ethics_review',
  'information_management',
  'protocol_binding',
  'receipt_boundary',
  'site_binding',
  'sponsor_cro_boundary',
  'study_identity',
];

const REQUIRED_RECEIPT_FAMILIES = [
  'audit',
  'authority',
  'consent',
  'decision_forum',
  'ethics_review',
  'evidence',
  'protocol',
];

async function loadStudyRegistry() {
  try {
    return await import('../src/study-registry.mjs');
  } catch (error) {
    assert.fail(`CyberMedica study registry module must exist and load: ${error.message}`);
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

function studyRegistryInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:study-registry-owner-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'principal_investigator'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['study_registry_manage', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    study: {
      studyRef: 'study-cardiac-alpha',
      studyVersion: 'v1',
      schemaVersion: 'cybermedica.study_registry.v1',
      lifecycleState: 'startup',
      tenantRef: 'tenant-site-alpha',
      organizationRef: 'org-site-alpha',
      siteRef: 'site-alpha',
      protocolRef: 'protocol-cardiac-alpha',
      protocolVersionRef: 'protocol-cardiac-alpha-v1',
      sponsorRef: 'sponsor-alpha',
      croRefs: ['cro-data-alpha', 'cro-monitoring-alpha'],
      principalInvestigatorDid: 'did:exo:pi-alpha',
      qualityManagerDid: 'did:exo:quality-manager-alpha',
      participantLinked: true,
      studyProfileHash: DIGEST_B,
      studyPlanHash: DIGEST_C,
      configurationHash: DIGEST_D,
      registeredAtHlc: { physicalMs: 1802000400000, logical: 0 },
      metadataOnly: true,
      productionTrustClaim: false,
    },
    domainCoverage: [...REQUIRED_STUDY_DOMAINS].reverse(),
    protocolBinding: {
      protocolRef: 'protocol-cardiac-alpha',
      protocolVersionRef: 'protocol-cardiac-alpha-v1',
      protocolHash: DIGEST_E,
      protocolIntakeReceiptRef: 'receipt-protocol-intake-alpha',
      protocolControlReceiptRef: 'receipt-protocol-control-alpha',
      currentApprovalState: 'approved_for_startup',
      activeAmendmentRefs: ['amendment-baseline'],
      effectiveAtHlc: { physicalMs: 1802000100000, logical: 0 },
      metadataOnly: true,
    },
    sponsorCroBoundary: {
      sponsorRef: 'sponsor-alpha',
      croRefs: ['cro-monitoring-alpha', 'cro-data-alpha'],
      clinicalTrialAgreementRef: 'cta-cardiac-alpha',
      clinicalTrialAgreementHash: DIGEST_F,
      sponsorConfidentialBodyExcluded: true,
      controlledRequestPolicyRef: 'controlled-sponsor-cro-request-policy-alpha',
      disclosureLogHash: DIGEST_1,
      metadataOnly: true,
    },
    ethicsReview: {
      iecIrbRefs: ['irb-alpha'],
      approvalRefs: ['irb-approval-cardiac-alpha'],
      consentMaterialRefs: ['consent-form-cardiac-alpha-v1'],
      status: 'current_approved',
      approvedAtHlc: { physicalMs: 1802000200000, logical: 0 },
      continuingReviewDueAtHlc: { physicalMs: 1833536200000, logical: 0 },
      metadataOnly: true,
    },
    consentBoundary: {
      required: true,
      consentMaterialVersionRef: 'consent-form-cardiac-alpha-v1',
      consentPolicyHash: DIGEST_2,
      dataSharingConsentPolicyHash: DIGEST_3,
      revocationPathRef: 'consent-revocation-path-alpha',
      noRawParticipantIdentifiers: true,
      metadataOnly: true,
    },
    informationManagement: {
      planRef: 'info-plan-cardiac-alpha',
      planHash: DIGEST_4,
      sourceDataTraceabilityRef: 'source-traceability-cardiac-alpha',
      crfMediaHash: DIGEST_A,
      retentionRuleHash: DIGEST_B,
      finalReportRequirementHash: DIGEST_C,
      distributionRuleHash: DIGEST_D,
      approvedAtHlc: { physicalMs: 1802000250000, logical: 0 },
      metadataOnly: true,
    },
    receiptBoundary: {
      requiredReceiptFamilies: [...REQUIRED_RECEIPT_FAMILIES].reverse(),
      exochainReceiptCapable: true,
      rawPayloadAnchoringForbidden: true,
      productionTrustState: 'inactive',
      rootTrustVerified: false,
      metadataOnly: true,
    },
    aiAssistance: {
      used: true,
      recommendationHash: DIGEST_E,
      limitationHashes: [DIGEST_F],
      advisoryOnly: true,
      finalAuthority: false,
      reviewedByHuman: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:study-registry-reviewer-alpha',
      reviewerRoleRefs: ['quality_manager', 'principal_investigator'],
      decision: 'study_registry_ready',
      decisionHash: DIGEST_1,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      reviewedAtHlc: { physicalMs: 1802000300000, logical: 0 },
      metadataOnly: true,
    },
    custodyDigest: DIGEST_2,
  };

  return mergeDeep(base, overrides);
}

test('study registry binds study protocol sponsor CRO ethics consent and receipt boundaries deterministically', async () => {
  const { evaluateStudyRegistry } = await loadStudyRegistry();

  const first = evaluateStudyRegistry(studyRegistryInput());
  const second = evaluateStudyRegistry(
    studyRegistryInput({
      domainCoverage: REQUIRED_STUDY_DOMAINS,
      sponsorCroBoundary: {
        croRefs: ['cro-data-alpha', 'cro-monitoring-alpha'],
      },
      receiptBoundary: {
        requiredReceiptFamilies: REQUIRED_RECEIPT_FAMILIES,
      },
    }),
  );

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.deepEqual(first, second);
  assert.equal(first.studyRegistry.schema, 'cybermedica.study_registry_record.v1');
  assert.equal(first.studyRegistry.trustState, 'inactive');
  assert.equal(first.studyRegistry.exochainProductionClaim, false);
  assert.equal(first.studyRegistry.metadataOnly, true);
  assert.equal(first.studyRegistry.containsProtectedContent, false);
  assert.deepEqual(first.studyRegistry.domainCoverage, REQUIRED_STUDY_DOMAINS);
  assert.deepEqual(first.studyRegistry.requiredReceiptFamilies, REQUIRED_RECEIPT_FAMILIES);
  assert.deepEqual(first.studyRegistry.croRefs, ['cro-data-alpha', 'cro-monitoring-alpha']);
  assert.equal(first.studyRegistry.studyRef, 'study-cardiac-alpha');
  assert.equal(first.studyRegistry.protocolRef, 'protocol-cardiac-alpha');
  assert.equal(first.studyRegistry.sponsorRef, 'sponsor-alpha');
  assert.equal(first.studyRegistry.participantLinked, true);
  assert.equal(first.receipt.anchorPayload.artifactType, 'study_registry');
  assert.equal(first.receipt.anchorPayload.classification, 'metadata_only_study_registry');
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(first), /participant alice|protocol body|sponsor contract|api key/iu);
});

test('study registry fails closed for missing study governance protocol ethics and receipt coverage', async () => {
  const { evaluateStudyRegistry } = await loadStudyRegistry();

  const result = evaluateStudyRegistry(
    studyRegistryInput({
      study: {
        sponsorRef: '',
        protocolRef: 'protocol-cardiac-beta',
        productionTrustClaim: true,
      },
      domainCoverage: ['study_identity', 'site_binding'],
      protocolBinding: {
        currentApprovalState: 'draft',
        protocolRef: 'protocol-cardiac-alpha',
        protocolControlReceiptRef: '',
      },
      ethicsReview: {
        iecIrbRefs: [],
        approvalRefs: [],
        status: 'expired',
      },
      receiptBoundary: {
        requiredReceiptFamilies: ['audit'],
        exochainReceiptCapable: false,
        rawPayloadAnchoringForbidden: false,
        productionTrustState: 'verified',
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('study_sponsor_ref_absent'));
  assert.ok(result.reasons.includes('study_protocol_binding_mismatch'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('domain_missing:consent_boundary'));
  assert.ok(result.reasons.includes('protocol_not_approved_for_startup'));
  assert.ok(result.reasons.includes('protocol_control_receipt_absent'));
  assert.ok(result.reasons.includes('ethics_committee_absent'));
  assert.ok(result.reasons.includes('ethics_review_not_current'));
  assert.ok(result.reasons.includes('receipt_family_missing:consent'));
  assert.ok(result.reasons.includes('receipt_capability_absent'));
  assert.ok(result.reasons.includes('raw_payload_anchor_guard_absent'));
  assert.ok(result.reasons.includes('production_trust_state_not_inactive'));
});

test('participant-linked studies require consent boundary PI ownership and sponsor confidentiality controls', async () => {
  const { evaluateStudyRegistry } = await loadStudyRegistry();

  const result = evaluateStudyRegistry(
    studyRegistryInput({
      study: {
        principalInvestigatorDid: '',
        qualityManagerDid: '',
      },
      sponsorCroBoundary: {
        clinicalTrialAgreementHash: '0'.repeat(64),
        sponsorConfidentialBodyExcluded: false,
        disclosureLogHash: 'not-a-digest',
      },
      ethicsReview: {
        consentMaterialRefs: [],
      },
      consentBoundary: {
        required: false,
        consentPolicyHash: '',
        dataSharingConsentPolicyHash: '',
        noRawParticipantIdentifiers: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('principal_investigator_absent'));
  assert.ok(result.reasons.includes('quality_manager_absent'));
  assert.ok(result.reasons.includes('cta_hash_invalid'));
  assert.ok(result.reasons.includes('sponsor_confidential_body_guard_absent'));
  assert.ok(result.reasons.includes('disclosure_log_hash_invalid'));
  assert.ok(result.reasons.includes('participant_consent_material_absent'));
  assert.ok(result.reasons.includes('participant_consent_required_absent'));
  assert.ok(result.reasons.includes('consent_policy_hash_invalid'));
  assert.ok(result.reasons.includes('data_sharing_consent_policy_hash_invalid'));
  assert.ok(result.reasons.includes('participant_identifier_guard_absent'));
});

test('study registry requires human authority HLC order and advisory-only AI assistance', async () => {
  const { evaluateStudyRegistry } = await loadStudyRegistry();

  const result = evaluateStudyRegistry(
    studyRegistryInput({
      actor: {
        did: 'did:exo:ai-study-registry-agent-alpha',
        kind: 'ai_agent',
        roleRefs: ['ai_reviewer'],
      },
      authority: {
        revoked: true,
        permissions: ['read'],
      },
      study: {
        registeredAtHlc: { physicalMs: 1802000100000, logical: 0 },
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
        reviewedAtHlc: { physicalMs: 1802000150000, logical: 0 },
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('authority_chain_revoked'));
  assert.ok(result.reasons.includes('study_registry_authority_missing'));
  assert.ok(result.reasons.includes('human_final_authority_absent'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('ai_advisory_only_absent'));
  assert.ok(result.reasons.includes('ai_human_review_absent'));
  assert.ok(result.reasons.includes('human_review_before_ethics_approval'));
  assert.ok(result.reasons.includes('study_registered_before_human_review'));
});

test('study registry rejects raw study protocol sponsor participant content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateStudyRegistry } = await loadStudyRegistry();

  assert.equal(
    evaluateStudyRegistry(
      studyRegistryInput({
        study: {
          rawProtocolText: [],
        },
      }),
    ).decision,
    'permitted',
  );

  assert.throws(
    () =>
      evaluateStudyRegistry(
        studyRegistryInput({
          study: {
            rawProtocolText: 'Protocol body and participant Alice belong outside receipts.',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateStudyRegistry(
        studyRegistryInput({
          sponsorCroBoundary: {
            sponsorContractBody: 'Sponsor contract body belongs in controlled storage.',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateStudyRegistry(
        studyRegistryInput({
          informationManagement: {
            apiKey: 'cm_live_secret',
          },
        }),
      ),
    ProtectedContentError,
  );
});
