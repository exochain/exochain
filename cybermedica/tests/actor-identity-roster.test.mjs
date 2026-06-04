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

const REQUIRED_ACTOR_CLASSES = [
  'ai_agent',
  'auditor',
  'clinical_research_coordinator',
  'cro_monitor',
  'principal_investigator',
  'quality_assurance',
  'sponsor_monitor',
  'sub_investigator',
  'support_engineer',
  'system_administrator',
  'tenant_administrator',
];

const REQUIRED_SOURCE_REFS = [
  'cyber_medica_qms_prd_master.md#target-users-and-stakeholders',
  'cybermedica_2_0_sandy_seven_layer_master_prd.md#data-layer',
  'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  'docs/context/EXOCHAIN_COUNCIL_REVIEW_FOR_CYBERMEDICA_OPEN_QUESTIONS.md',
  'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
];

const DIGESTS = [
  DIGEST_A,
  DIGEST_B,
  DIGEST_C,
  DIGEST_D,
  DIGEST_E,
  DIGEST_F,
  DIGEST_1,
  DIGEST_2,
  DIGEST_3,
  DIGEST_4,
  DIGEST_5,
  DIGEST_6,
  DIGEST_7,
  DIGEST_8,
];

async function loadActorIdentityRoster() {
  try {
    return await import('../src/actor-identity-roster.mjs');
  } catch (error) {
    assert.fail(`CyberMedica actor identity roster module must exist and load: ${error.message}`);
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

function actorProfile(actorClass, index, overrides = {}) {
  const kind = actorClass === 'ai_agent' ? 'ai_agent' : 'human';
  const base = {
    actorClass,
    did: `did:exo:${actorClass.replaceAll('_', '-')}-alpha`,
    kind,
    status: 'verified',
    didRegistrySource: 'exochain_did_registry',
    didRegistryEvidenceHash: DIGESTS[index % DIGESTS.length],
    identityProofHash: DIGESTS[(index + 1) % DIGESTS.length],
    authorityPolicyHash: DIGESTS[(index + 2) % DIGESTS.length],
    roleRefs: [actorClass],
    allowedTenantIds: ['tenant-network-beta', 'tenant-site-alpha'],
    humanOwnerDid: actorClass === 'ai_agent' ? 'did:exo:quality-manager-alpha' : null,
    supportAccessPolicyRef: actorClass === 'support_engineer' ? 'support-access-policy-alpha' : null,
    privilegedAccessReviewHash: actorClass.endsWith('_administrator') ? DIGESTS[(index + 3) % DIGESTS.length] : null,
    aiFinalAuthority: false,
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    custodyDigest: DIGESTS[(index + 4) % DIGESTS.length],
    updatedAtHlc: { physicalMs: 1802000100000, logical: index },
  };
  return mergeDeep(base, overrides);
}

function rosterInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:identity-roster-reviewer-alpha',
      kind: 'human',
      roleRefs: ['security_owner', 'quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['actor_identity_roster_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    rosterPolicy: {
      policyRef: 'actor-identity-roster-policy-alpha',
      policyVersion: 'v1',
      status: 'active',
      policyHash: DIGEST_B,
      requiredActorClasses: REQUIRED_ACTOR_CLASSES,
      requiredSourceRefs: REQUIRED_SOURCE_REFS,
      didMappingRequired: true,
      didRegistrySource: 'exochain_did_registry',
      identityProofingRequired: true,
      gatewayAuthRequired: true,
      aiFinalAuthorityProhibited: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
      evaluatedAtHlc: { physicalMs: 1802000000000, logical: 0 },
    },
    actorProfiles: REQUIRED_ACTOR_CLASSES.map((actorClass, index) => actorProfile(actorClass, index)),
    rosterCheckedAtHlc: { physicalMs: 1802000200000, logical: 0 },
    humanReview: {
      reviewerDid: 'did:exo:security-owner-alpha',
      decision: 'actor_identity_roster_accepted_inactive_trust',
      reviewHash: DIGEST_C,
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      reviewedAtHlc: { physicalMs: 1802000300000, logical: 0 },
      metadataOnly: true,
    },
    validationEvidence: {
      sourceGuardPassed: true,
      noExochainSourceModified: true,
      commandRefs: ['node --test tests/actor-identity-roster.test.mjs', 'node --test tests/source-guards.test.mjs'],
      validationHash: DIGEST_8,
      recordedAtHlc: { physicalMs: 1802000400000, logical: 0 },
      metadataOnly: true,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_D,
      reviewedByHuman: true,
    },
    custodyDigest: DIGEST_E,
  };
  return mergeDeep(base, overrides);
}

test('actor identity roster creates deterministic inactive DID-mapping receipts for every governed actor class', async () => {
  const { evaluateActorIdentityRoster } = await loadActorIdentityRoster();

  const first = evaluateActorIdentityRoster(rosterInput());
  const second = evaluateActorIdentityRoster({
    ...rosterInput(),
    rosterPolicy: {
      ...rosterInput().rosterPolicy,
      requiredActorClasses: [...REQUIRED_ACTOR_CLASSES].reverse(),
      requiredSourceRefs: [...REQUIRED_SOURCE_REFS].reverse(),
    },
    actorProfiles: [...rosterInput().actorProfiles].reverse(),
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.actorIdentityRoster.status, 'ready');
  assert.equal(first.actorIdentityRoster.trustState, 'inactive');
  assert.deepEqual(first.actorIdentityRoster.actorClasses, REQUIRED_ACTOR_CLASSES);
  assert.equal(first.actorIdentityRoster.profileCount, REQUIRED_ACTOR_CLASSES.length);
  assert.deepEqual(first.actorIdentityRoster.aiAgentClasses, ['ai_agent']);
  assert.equal(first.actorIdentityRoster.metadataOnly, true);
  assert.equal(first.actorIdentityRoster.exochainProductionClaim, false);
  assert.deepEqual(first.actorIdentityRoster.sourceRefs, REQUIRED_SOURCE_REFS);
  assert.equal(first.actorIdentityRoster.rosterHash, second.actorIdentityRoster.rosterHash);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.anchorPayload.artifactType, 'actor_identity_roster');
  assert.doesNotMatch(JSON.stringify(first), /Participant Alice|private key|session secret|raw identity/iu);
});

test('actor identity roster fails closed for missing actor classes and unsafe policy posture', async () => {
  const { evaluateActorIdentityRoster } = await loadActorIdentityRoster();

  const denied = evaluateActorIdentityRoster(
    rosterInput({
      actor: {
        did: 'did:exo:identity-roster-ai-alpha',
        kind: 'ai_agent',
      },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['read'],
        authorityChainHash: DIGEST_A,
      },
      rosterPolicy: {
        requiredActorClasses: REQUIRED_ACTOR_CLASSES.filter((actorClass) => actorClass !== 'ai_agent'),
        requiredSourceRefs: REQUIRED_SOURCE_REFS.filter(
          (sourceRef) => sourceRef !== 'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
        ),
        didMappingRequired: false,
        gatewayAuthRequired: false,
        aiFinalAuthorityProhibited: false,
        productionTrustClaim: true,
      },
      actorProfiles: rosterInput().actorProfiles.filter((profile) => profile.actorClass !== 'support_engineer'),
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.actorIdentityRoster, null);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('actor_identity_roster_authority_missing'));
  assert.ok(denied.reasons.includes('policy_required_actor_class_missing:ai_agent'));
  assert.ok(denied.reasons.includes('policy_required_source_ref_missing:docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md'));
  assert.ok(denied.reasons.includes('did_mapping_requirement_absent'));
  assert.ok(denied.reasons.includes('gateway_auth_requirement_absent'));
  assert.ok(denied.reasons.includes('ai_final_authority_policy_absent'));
  assert.ok(denied.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(denied.reasons.includes('actor_profile_missing:support_engineer'));
});

test('actor identity roster denies registry proof actor-boundary and privileged-admin defects', async () => {
  const { evaluateActorIdentityRoster } = await loadActorIdentityRoster();

  const denied = evaluateActorIdentityRoster(
    rosterInput({
      actorProfiles: rosterInput().actorProfiles.map((profile) => {
        if (profile.actorClass === 'sub_investigator') {
          return {
            ...profile,
            did: 'local-sub-investigator-alpha',
            status: 'pending',
            didRegistrySource: 'local_identity_cache',
            allowedTenantIds: ['tenant-other'],
          };
        }
        if (profile.actorClass === 'ai_agent') {
          return {
            ...profile,
            humanOwnerDid: '',
            aiFinalAuthority: true,
          };
        }
        if (profile.actorClass === 'system_administrator') {
          return {
            ...profile,
            privilegedAccessReviewHash: 'not-a-digest',
          };
        }
        return profile;
      }),
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('actor_did_invalid:sub_investigator'));
  assert.ok(denied.reasons.includes('actor_identity_not_verified:sub_investigator'));
  assert.ok(denied.reasons.includes('did_registry_source_unverified:sub_investigator'));
  assert.ok(denied.reasons.includes('actor_tenant_not_allowed:sub_investigator'));
  assert.ok(denied.reasons.includes('ai_agent_human_owner_absent:ai_agent'));
  assert.ok(denied.reasons.includes('actor_ai_final_authority_forbidden:ai_agent'));
  assert.ok(denied.reasons.includes('privileged_access_review_hash_invalid:system_administrator'));
});

test('actor identity roster validates HLC ordering human review and source-control proof', async () => {
  const { evaluateActorIdentityRoster } = await loadActorIdentityRoster();

  const denied = evaluateActorIdentityRoster(
    rosterInput({
      rosterPolicy: {
        evaluatedAtHlc: { physicalMs: 1802000300000, logical: 1 },
      },
      actorProfiles: rosterInput().actorProfiles.map((profile) =>
        profile.actorClass === 'principal_investigator'
          ? { ...profile, updatedAtHlc: { physicalMs: 1802000300000, logical: 2 } }
          : profile,
      ),
      humanReview: {
        decision: 'rubber_stamp_without_review',
        aiFinalAuthority: true,
        noProductionTrustClaim: false,
        reviewedAtHlc: { physicalMs: 1802000000000, logical: 1 },
        reviewHash: 'bad',
      },
      validationEvidence: {
        sourceGuardPassed: false,
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('actor_identity_policy_after_check'));
  assert.ok(denied.reasons.includes('actor_profile_updated_after_check:principal_investigator'));
  assert.ok(denied.reasons.includes('human_review_decision_invalid'));
  assert.ok(denied.reasons.includes('human_review_hash_invalid'));
  assert.ok(denied.reasons.includes('human_review_ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('human_review_production_trust_claim_absent'));
  assert.ok(denied.reasons.includes('human_review_before_roster_check'));
  assert.ok(denied.reasons.includes('source_guard_not_passed'));
});

test('actor identity roster rejects raw identity content and secret material before receipts', async () => {
  const { evaluateActorIdentityRoster } = await loadActorIdentityRoster();

  assert.throws(
    () =>
      evaluateActorIdentityRoster(
        rosterInput({
          actorProfiles: [
            ...rosterInput().actorProfiles,
            actorProfile('auditor', 0, {
              actorClass: 'external_auditor_duplicate',
              rawIdentityWorksheet: 'Participant Alice identity packet belongs outside receipt evidence.',
            }),
          ],
        }),
      ),
    /raw actor identity content field|protected content/iu,
  );

  assert.throws(
    () =>
      evaluateActorIdentityRoster(
        rosterInput({
          rosterPolicy: {
            sessionSecret: 'secret-value',
          },
        }),
      ),
    /actor identity secret field|protected content/iu,
  );
});
