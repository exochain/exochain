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

const REQUIRED_ORGANIZATION_CLASSES = [
  'clinical_site_operator',
  'cro',
  'iec_irb',
  'sponsor',
];

const REQUIRED_LIFECYCLE_DOMAINS = [
  'authority_boundary',
  'confidentiality_boundary',
  'ethics_independence',
  'identity_registry',
  'lifecycle_control',
  'ownership_accountability',
  'receipt_boundary',
  'tenant_boundary',
  'visibility_policy',
];

const REQUIRED_RECEIPT_FAMILIES = [
  'audit',
  'authority',
  'disclosure',
  'evidence',
  'organization_lifecycle',
];

async function loadOrganizationLifecycleRegistry() {
  try {
    return await import('../src/organization-lifecycle-registry.mjs');
  } catch (error) {
    assert.fail(`CyberMedica organization lifecycle registry module must exist and load: ${error.message}`);
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

function organizationRecord(organizationClass, index, overrides = {}) {
  const sponsorCro = organizationClass === 'sponsor' || organizationClass === 'cro';
  const ethicsBody = organizationClass === 'iec_irb';
  return {
    organizationRef: `org-${organizationClass.replaceAll('_', '-')}-alpha`,
    organizationVersion: 'v1',
    organizationClass,
    lifecycleState: 'active',
    tenantRef: 'tenant-site-alpha',
    ownerDid: `did:exo:${organizationClass.replaceAll('_', '-')}-owner-alpha`,
    accountableMaintainerDid: `did:exo:${organizationClass.replaceAll('_', '-')}-maintainer-alpha`,
    identityRegistryRef: `identity-registry-${organizationClass.replaceAll('_', '-')}-alpha`,
    identityRegistryHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D][index],
    legalEntityHash: [DIGEST_D, DIGEST_C, DIGEST_B, DIGEST_A][index],
    authorityBoundaryHash: [DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2][index],
    accessPolicyRef: `access-policy-${organizationClass.replaceAll('_', '-')}-alpha`,
    retentionRuleRef: `retention-${organizationClass.replaceAll('_', '-')}-alpha`,
    disclosurePolicyHash: [DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5][index],
    confidentialityClass: sponsorCro ? 'sponsor_cro_confidential' : ethicsBody ? 'decision_governance' : 'tenant_operational',
    dataClassifications: sponsorCro
      ? ['sponsor_cro_confidential', 'quality_evidence_metadata']
      : ethicsBody
        ? ['decision_governance', 'quality_evidence_metadata']
        : ['tenant_operational', 'quality_evidence_metadata'],
    directParticipantAccess: false,
    sponsorConfidentialBodyExcluded: sponsorCro,
    sponsorCroVisibilityPolicyRef: sponsorCro ? 'controlled-sponsor-cro-visibility-alpha' : 'not_applicable',
    ethicsAuthorityAttested: ethicsBody,
    independentReviewBody: ethicsBody,
    noSponsorControlAttested: ethicsBody,
    aiRepresentedAsIrb: false,
    activeAtHlc: { physicalMs: 1803000000000 + index, logical: index },
    reviewedAtHlc: { physicalMs: 1803000100000 + index, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function organizationLifecycleInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:organization-registry-owner-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'tenant_admin'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['organization_lifecycle_manage', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    registryPolicy: {
      policyRef: 'organization-lifecycle-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredOrganizationClasses: REQUIRED_ORGANIZATION_CLASSES,
      requiredLifecycleDomains: REQUIRED_LIFECYCLE_DOMAINS,
      defaultDenyUnknownOrganizationClasses: true,
      sponsorCroVisibilityDefault: 'controlled_request_only',
      directParticipantAccessDefault: 'none',
      aiFinalAuthorityForbidden: true,
      rawProtectedContentForbidden: true,
      noProductionTrustClaim: true,
      evaluatedAtHlc: { physicalMs: 1803000200000, logical: 0 },
      metadataOnly: true,
    },
    organizations: REQUIRED_ORGANIZATION_CLASSES.map((organizationClass, index) =>
      organizationRecord(organizationClass, index),
    ).reverse(),
    changeControl: {
      changeRef: 'org-lifecycle-change-alpha',
      changeType: 'register',
      requestedByDid: 'did:exo:organization-change-requester-alpha',
      reviewedByDid: 'did:exo:organization-change-reviewer-alpha',
      approvedByDid: 'did:exo:organization-change-approver-alpha',
      requestedAtHlc: { physicalMs: 1803000300000, logical: 0 },
      reviewedAtHlc: { physicalMs: 1803000400000, logical: 0 },
      approvedAtHlc: { physicalMs: 1803000500000, logical: 0 },
      effectiveAtHlc: { physicalMs: 1803000600000, logical: 0 },
      rationaleHash: DIGEST_C,
      impactAssessmentHash: DIGEST_D,
      rollbackPlanHash: DIGEST_E,
      metadataOnly: true,
    },
    receiptBoundary: {
      requiredReceiptFamilies: REQUIRED_RECEIPT_FAMILIES,
      exochainReceiptCapable: true,
      rawPayloadAnchoringForbidden: true,
      productionTrustState: 'inactive',
      rootTrustVerified: false,
      metadataOnly: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:organization-registry-reviewer-alpha',
      reviewerRoleRefs: ['quality_manager', 'tenant_admin'],
      decision: 'organization_lifecycle_ready',
      decisionHash: DIGEST_F,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      reviewedAtHlc: { physicalMs: 1803000700000, logical: 0 },
      metadataOnly: true,
    },
    custodyDigest: DIGEST_6,
  };

  return mergeDeep(base, overrides);
}

test('organization lifecycle registry binds sponsor CRO site operator and IEC IRB ownership deterministically', async () => {
  const { evaluateOrganizationLifecycleRegistry } = await loadOrganizationLifecycleRegistry();

  const first = evaluateOrganizationLifecycleRegistry(organizationLifecycleInput());
  const second = evaluateOrganizationLifecycleRegistry(
    organizationLifecycleInput({
      registryPolicy: {
        requiredOrganizationClasses: REQUIRED_ORGANIZATION_CLASSES,
        requiredLifecycleDomains: REQUIRED_LIFECYCLE_DOMAINS,
      },
      organizations: REQUIRED_ORGANIZATION_CLASSES.map((organizationClass, index) =>
        organizationRecord(organizationClass, index),
      ),
      receiptBoundary: {
        requiredReceiptFamilies: [...REQUIRED_RECEIPT_FAMILIES].reverse(),
      },
    }),
  );

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.deepEqual(first, second);
  assert.equal(first.organizationRegistry.schema, 'cybermedica.organization_lifecycle_registry_record.v1');
  assert.equal(first.organizationRegistry.trustState, 'inactive');
  assert.equal(first.organizationRegistry.exochainProductionClaim, false);
  assert.equal(first.organizationRegistry.metadataOnly, true);
  assert.equal(first.organizationRegistry.containsProtectedContent, false);
  assert.deepEqual(first.organizationRegistry.organizationClasses, REQUIRED_ORGANIZATION_CLASSES);
  assert.deepEqual(first.organizationRegistry.lifecycleDomains, REQUIRED_LIFECYCLE_DOMAINS);
  assert.deepEqual(first.organizationRegistry.requiredReceiptFamilies, REQUIRED_RECEIPT_FAMILIES);
  assert.equal(first.organizationRegistry.organizationRecords.length, 4);
  assert.equal(first.organizationRegistry.organizationRecords[0].organizationClass, 'clinical_site_operator');
  assert.equal(first.organizationRegistry.organizationRecords[1].organizationClass, 'cro');
  assert.equal(first.organizationRegistry.organizationRecords[2].organizationClass, 'iec_irb');
  assert.equal(first.organizationRegistry.organizationRecords[3].organizationClass, 'sponsor');
  assert.equal(first.organizationRegistry.organizationRecords[2].independentReviewBody, true);
  assert.equal(first.organizationRegistry.organizationRecords[3].sponsorConfidentialBodyExcluded, true);
  assert.equal(first.receipt.anchorPayload.artifactType, 'organization_lifecycle_registry');
  assert.equal(first.receipt.anchorPayload.classification, 'metadata_only_organization_lifecycle_registry');
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(first), /participant alice|sponsor contract|irb letter|api key/iu);
});

test('organization lifecycle registry fails closed for missing classes lifecycle domains and unsafe boundaries', async () => {
  const { evaluateOrganizationLifecycleRegistry } = await loadOrganizationLifecycleRegistry();

  const result = evaluateOrganizationLifecycleRegistry(
    organizationLifecycleInput({
      registryPolicy: {
        status: 'draft',
        requiredLifecycleDomains: ['identity_registry'],
        defaultDenyUnknownOrganizationClasses: false,
        sponsorCroVisibilityDefault: 'direct_portal_uncontrolled',
        directParticipantAccessDefault: 'allowed',
        rawProtectedContentForbidden: false,
        noProductionTrustClaim: false,
      },
      organizations: [
        organizationRecord('clinical_site_operator', 0, {
          ownerDid: '',
          productionTrustClaim: true,
        }),
        organizationRecord('sponsor', 1, {
          sponsorConfidentialBodyExcluded: false,
          directParticipantAccess: true,
        }),
        organizationRecord('iec_irb', 2, {
          independentReviewBody: false,
          noSponsorControlAttested: false,
          aiRepresentedAsIrb: true,
        }),
      ],
      receiptBoundary: {
        requiredReceiptFamilies: ['audit'],
        exochainReceiptCapable: false,
        rawPayloadAnchoringForbidden: false,
        productionTrustState: 'verified',
        rootTrustVerified: true,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('registry_policy_not_active'));
  assert.ok(result.reasons.includes('organization_class_missing:cro'));
  assert.ok(result.reasons.includes('lifecycle_domain_missing:authority_boundary'));
  assert.ok(result.reasons.includes('unknown_organization_class_default_deny_absent'));
  assert.ok(result.reasons.includes('sponsor_cro_visibility_default_uncontrolled'));
  assert.ok(result.reasons.includes('direct_participant_access_default_forbidden'));
  assert.ok(result.reasons.includes('raw_protected_content_guard_absent'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('organization_owner_absent:clinical_site_operator'));
  assert.ok(result.reasons.includes('sponsor_confidential_body_guard_absent:sponsor'));
  assert.ok(result.reasons.includes('direct_participant_access_forbidden:sponsor'));
  assert.ok(result.reasons.includes('ethics_independence_absent:iec_irb'));
  assert.ok(result.reasons.includes('ethics_body_sponsor_control_absent:iec_irb'));
  assert.ok(result.reasons.includes('ai_irb_confusion_forbidden:iec_irb'));
  assert.ok(result.reasons.includes('receipt_family_missing:authority'));
  assert.ok(result.reasons.includes('receipt_capability_absent'));
  assert.ok(result.reasons.includes('production_trust_state_not_inactive'));
  assert.ok(result.reasons.includes('root_trust_verified_before_activation'));
});

test('organization lifecycle registry requires human authority separation and HLC ordering', async () => {
  const { evaluateOrganizationLifecycleRegistry } = await loadOrganizationLifecycleRegistry();

  const result = evaluateOrganizationLifecycleRegistry(
    organizationLifecycleInput({
      actor: {
        did: 'did:exo:ai-organization-registry-agent-alpha',
        kind: 'ai_agent',
      },
      authority: {
        valid: true,
        revoked: true,
        expired: false,
        permissions: ['read'],
        authorityChainHash: DIGEST_A,
      },
      changeControl: {
        requestedByDid: 'did:exo:same-actor-alpha',
        reviewedByDid: 'did:exo:same-actor-alpha',
        approvedByDid: 'did:exo:same-actor-alpha',
        reviewedAtHlc: { physicalMs: 1803000200000, logical: 0 },
        approvedAtHlc: { physicalMs: 1803000100000, logical: 0 },
        effectiveAtHlc: { physicalMs: 1803000060000, logical: 0 },
      },
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
        noProductionTrustClaim: false,
        reviewedAtHlc: { physicalMs: 1803000050000, logical: 0 },
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('human_organization_lifecycle_actor_required'));
  assert.ok(result.reasons.includes('authority_chain_revoked'));
  assert.ok(result.reasons.includes('organization_lifecycle_authority_missing'));
  assert.ok(result.reasons.includes('change_review_self_approval_forbidden'));
  assert.ok(result.reasons.includes('change_approval_self_approval_forbidden'));
  assert.ok(result.reasons.includes('change_approval_before_review'));
  assert.ok(result.reasons.includes('change_effective_before_approval'));
  assert.ok(result.reasons.includes('human_final_authority_absent'));
  assert.ok(result.reasons.includes('human_review_before_change_effective'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
});

test('organization lifecycle registry rejects raw organization sponsor ethics content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateOrganizationLifecycleRegistry } = await loadOrganizationLifecycleRegistry();

  assert.equal(
    evaluateOrganizationLifecycleRegistry(
      organizationLifecycleInput({
        organizations: [
          organizationRecord('clinical_site_operator', 0, { rawOrganizationProfile: [] }),
          organizationRecord('cro', 1),
          organizationRecord('iec_irb', 2),
          organizationRecord('sponsor', 3),
        ],
      }),
    ).decision,
    'permitted',
  );

  assert.throws(
    () =>
      evaluateOrganizationLifecycleRegistry(
        organizationLifecycleInput({
          organizations: [
            organizationRecord('clinical_site_operator', 0, {
              rawOrganizationProfile: 'Named facility profile belongs in controlled operational storage.',
            }),
            organizationRecord('cro', 1),
            organizationRecord('iec_irb', 2),
            organizationRecord('sponsor', 3),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateOrganizationLifecycleRegistry(
        organizationLifecycleInput({
          organizations: [
            organizationRecord('clinical_site_operator', 0),
            organizationRecord('cro', 1),
            organizationRecord('iec_irb', 2),
            organizationRecord('sponsor', 3, {
              sponsorContractBody: 'Sponsor contract terms stay outside receipt material.',
            }),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateOrganizationLifecycleRegistry(
        organizationLifecycleInput({
          registryPolicy: {
            apiKey: 'not-for-receipt',
          },
        }),
      ),
    ProtectedContentError,
  );
});
