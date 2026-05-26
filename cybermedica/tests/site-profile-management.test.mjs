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

const REQUIRED_PROFILE_DOMAINS = [
  'configuration',
  'control_set',
  'evidence_index',
  'organization',
  'role_matrix',
  'site_identity',
  'study_portfolio',
  'tenant',
  'user_roster',
];

async function loadSiteProfileManagement() {
  try {
    return await import('../src/site-profile-management.mjs');
  } catch (error) {
    assert.fail(`CyberMedica site profile management module must exist and load: ${error.message}`);
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

function profileDomain(domain, index) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3];
  return {
    domain,
    status: index % 4 === 0 ? 'approved_with_conditions' : 'approved',
    ownerDid: `did:exo:${domain.replaceAll('_', '-')}-owner-alpha`,
    artifactHash: hashes[index],
    evidenceRefs: [`EVD-SITE-PROFILE-${String(index + 1).padStart(3, '0')}`],
    controlRefs: [`CM-SITE-PROFILE-${String(index + 1).padStart(3, '0')}`],
    reviewedAtHlc: { physicalMs: 1801000200000 + index, logical: index % 2 },
    metadataOnly: true,
  };
}

function siteProfileInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:site-profile-manager-alpha',
      kind: 'human',
      roleRefs: ['quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['site_profile_manage', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    profile: {
      profileRef: 'site-profile-alpha-2026-0001',
      profileVersion: 'v1',
      schemaVersion: 'cybermedica.site_profile.v1',
      status: 'approved_with_conditions',
      tenantRef: 'tenant-site-alpha',
      organizationRef: 'org-alpha',
      siteRef: 'site-alpha',
      legalEntityHash: DIGEST_B,
      ownershipStructureHash: DIGEST_C,
      siteIdentityHash: DIGEST_D,
      siteLocationHashes: [DIGEST_E, DIGEST_F],
      studyPortfolioHash: DIGEST_1,
      userRosterHash: DIGEST_2,
      roleMatrixHash: DIGEST_3,
      controlSetHash: DIGEST_4,
      evidenceIndexHash: DIGEST_5,
      configurationHash: DIGEST_6,
      previousProfileHash: null,
      metadataOnly: true,
      productionTrustClaim: false,
    },
    changeControl: {
      changeRef: 'site-profile-change-001',
      changeType: 'create',
      requestedByDid: 'did:exo:site-profile-manager-alpha',
      requestedAtHlc: { physicalMs: 1801000000000, logical: 0 },
      reviewedByDid: 'did:exo:quality-reviewer-alpha',
      reviewedAtHlc: { physicalMs: 1801000100000, logical: 0 },
      approvedByDid: 'did:exo:site-governance-chair-alpha',
      approvedAtHlc: { physicalMs: 1801000300000, logical: 0 },
      effectiveAtHlc: { physicalMs: 1801000400000, logical: 0 },
      rationaleHash: DIGEST_A,
      impactAssessmentHash: DIGEST_B,
      rollbackPlanHash: DIGEST_C,
      metadataOnly: true,
    },
    profileDomains: REQUIRED_PROFILE_DOMAINS.map(profileDomain).reverse(),
    siteApproval: {
      status: 'approved_with_conditions',
      reviewerDid: 'did:exo:quality-reviewer-alpha',
      reviewerRole: 'quality_manager',
      humanVerified: true,
      evidenceBundleComplete: true,
      phiBoundaryAttested: true,
      decisionForumRequired: true,
      decisionForum: {
        verified: true,
        state: 'approved',
        decisionId: 'df-site-profile-alpha-001',
        workflowReceiptId: 'df-site-profile-workflow-001',
        quorum: { status: 'met' },
        humanGate: { verified: true },
        openChallenge: false,
      },
      reviewEvidenceHash: DIGEST_D,
      approvalRationaleHash: DIGEST_E,
    },
    custodyDigest: DIGEST_F,
  };

  return mergeDeep(base, overrides);
}

test('site profile management creates deterministic FR-001 FR-002 inactive receipts', async () => {
  const { evaluateSiteProfileManagement } = await loadSiteProfileManagement();

  const resultA = evaluateSiteProfileManagement(siteProfileInput());
  const resultB = evaluateSiteProfileManagement(siteProfileInput({
    profileDomains: REQUIRED_PROFILE_DOMAINS.map(profileDomain),
    profile: {
      siteLocationHashes: [DIGEST_F, DIGEST_E],
    },
  }));

  assert.equal(resultA.permitted, true);
  assert.deepEqual(resultA.reasons, []);
  assert.equal(resultA.siteProfile.schema, 'cybermedica.site_profile_record.v1');
  assert.equal(resultA.siteProfile.profileStatus, 'approved_with_conditions');
  assert.equal(resultA.siteProfile.trustState, 'inactive');
  assert.equal(resultA.siteProfile.exochainProductionClaim, false);
  assert.deepEqual(resultA.siteProfile.domainCoverage.profileDomains, REQUIRED_PROFILE_DOMAINS);
  assert.equal(resultA.siteProfile.domainCoverage.domainCount, REQUIRED_PROFILE_DOMAINS.length);
  assert.equal(resultA.siteProfile.tenantBoundary.tenantId, 'tenant-site-alpha');
  assert.equal(resultA.siteProfile.tenantBoundary.organizationRef, 'org-alpha');
  assert.equal(resultA.siteProfile.tenantBoundary.siteRef, 'site-alpha');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.containsProtectedContent, false);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'site_profile');
  assert.equal(resultA.receipt.anchorPayload.classification, 'confidential_metadata_only');
  assert.equal(resultA.siteProfile.profileHash, resultB.siteProfile.profileHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
});

test('site profile management fails closed for tenant gaps profile gaps and governance defects', async () => {
  const { evaluateSiteProfileManagement } = await loadSiteProfileManagement();

  const absent = evaluateSiteProfileManagement({});

  assert.equal(absent.permitted, false);
  assert.ok(absent.reasons.includes('tenant_absent'));
  assert.ok(absent.reasons.includes('profile_ref_absent'));
  assert.ok(absent.reasons.includes('change_control_ref_absent'));
  assert.ok(absent.reasons.includes('profile_domains_absent'));
  assert.ok(absent.reasons.includes('site_approval_absent'));
  assert.equal(absent.siteProfile, null);
  assert.equal(absent.receipt, null);

  const denied = evaluateSiteProfileManagement(siteProfileInput({
    targetTenantId: 'tenant-site-beta',
    actor: { kind: 'ai_agent' },
    authority: { permissions: ['read'] },
    profile: {
      status: 'draft',
      productionTrustClaim: true,
      legalEntityHash: 'not-a-digest',
    },
    profileDomains: REQUIRED_PROFILE_DOMAINS
      .filter((domain) => domain !== 'role_matrix')
      .map(profileDomain),
    siteApproval: {
      humanVerified: false,
      evidenceBundleComplete: false,
      decisionForum: {
        openChallenge: true,
        quorum: { status: 'not_met' },
      },
    },
  }));

  assert.equal(denied.permitted, false);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('site_profile_authority_missing'));
  assert.ok(denied.reasons.includes('profile_not_approved'));
  assert.ok(denied.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(denied.reasons.includes('legal_entity_hash_invalid'));
  assert.ok(denied.reasons.includes('required_profile_domain_missing:role_matrix'));
  assert.ok(denied.reasons.includes('human_review_unverified'));
  assert.ok(denied.reasons.includes('evidence_bundle_incomplete'));
  assert.ok(denied.reasons.includes('quorum_not_met'));
  assert.ok(denied.reasons.includes('challenge_open'));
  assert.equal(denied.siteProfile, null);
  assert.equal(denied.receipt, null);
});

test('site profile management enforces HLC order and no self approval', async () => {
  const { evaluateSiteProfileManagement } = await loadSiteProfileManagement();

  const denied = evaluateSiteProfileManagement(siteProfileInput({
    changeControl: {
      reviewedByDid: 'did:exo:site-profile-manager-alpha',
      approvedByDid: 'did:exo:site-profile-manager-alpha',
      reviewedAtHlc: { physicalMs: 1800999999999, logical: 0 },
      approvedAtHlc: { physicalMs: 1800999999998, logical: 0 },
      effectiveAtHlc: { physicalMs: 1800999999997, logical: 0 },
    },
  }));

  assert.equal(denied.permitted, false);
  assert.ok(denied.reasons.includes('change_review_self_approval_forbidden'));
  assert.ok(denied.reasons.includes('change_approval_self_approval_forbidden'));
  assert.ok(denied.reasons.includes('change_review_before_request'));
  assert.ok(denied.reasons.includes('change_approval_before_review'));
  assert.ok(denied.reasons.includes('change_effective_before_approval'));

  const sameTickAdvancing = evaluateSiteProfileManagement(siteProfileInput({
    changeControl: {
      requestedAtHlc: { physicalMs: 1801000000000, logical: 0 },
      reviewedAtHlc: { physicalMs: 1801000000000, logical: 1 },
      approvedAtHlc: { physicalMs: 1801000000000, logical: 2 },
      effectiveAtHlc: { physicalMs: 1801000000000, logical: 3 },
    },
  }));

  assert.equal(sameTickAdvancing.permitted, true);
});

test('site profile management rejects raw site content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateSiteProfileManagement } = await loadSiteProfileManagement();

  assert.throws(
    () => evaluateSiteProfileManagement(siteProfileInput({
      profile: {
        siteProfileNarrative: 'Participant Jane Example attends this site.',
      },
    })),
    ProtectedContentError,
  );

  assert.throws(
    () => evaluateSiteProfileManagement(siteProfileInput({
      profile: {
        principalInvestigatorEmail: 'pi@example.org',
      },
    })),
    ProtectedContentError,
  );

  assert.throws(
    () => evaluateSiteProfileManagement(siteProfileInput({
      siteDirectory: {
        apiKey: { vaultRef: 'secret-ref-alpha' },
      },
    })),
    ProtectedContentError,
  );
});
