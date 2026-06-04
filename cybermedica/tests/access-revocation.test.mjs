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

async function loadAccessRevocation() {
  try {
    return await import('../src/access-revocation.mjs');
  } catch (error) {
    assert.fail(`CyberMedica access-revocation module must exist and load: ${error.message}`);
  }
}

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

const REQUIRED_TRIGGERS = [
  'delegation_expiration',
  'policy_violation',
  'role_change',
  'study_closure',
  'termination',
];

function trigger(triggerType, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E];
  return {
    triggerId: `REV-TRIGGER-${index}`,
    triggerType,
    evidenceHash: hashes[index],
    detectedAtHlc: { physicalMs: 1810000000000 + index, logical: index },
    sourceSystemRef: `source-${triggerType}`,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function accessGrant(grantId, resourceScope, index, overrides = {}) {
  const hashes = [DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4];
  return {
    grantId,
    principalDid: 'did:exo:crc-alpha',
    tenantId: 'tenant-site-alpha',
    resourceScope,
    status: 'active',
    permissions: ['read', 'write'],
    issuedAtHlc: { physicalMs: 1805000000000 + index, logical: index },
    expiresAtHlc: { physicalMs: 1815000000000 + index, logical: index },
    revocable: true,
    timeBound: true,
    leastPrivilege: true,
    accessPolicyHash: hashes[index],
    authorityChainHash: DIGEST_A,
    lastAuditHash: hashes[(index + 1) % hashes.length],
    ...overrides,
  };
}

function baseInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:access-governor-alpha',
      kind: 'human',
      roleRefs: ['security_owner', 'quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['access_revocation_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    revocationPolicy: {
      policyRef: 'POLICY-39-ACCESS-CONTROL-ALPHA',
      policyHash: DIGEST_B,
      status: 'active',
      coveredTriggerTypes: [...REQUIRED_TRIGGERS],
      leastPrivilegeRequired: true,
      timeBoundRequired: true,
      revocationRequired: true,
      auditTrailRequired: true,
      humanReviewRequired: true,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    subject: {
      did: 'did:exo:crc-alpha',
      tenantId: 'tenant-site-alpha',
      activeRoleRefs: ['clinical_research_coordinator'],
      studyRefs: ['study-cardiac-alpha'],
      currentEmploymentStatus: 'terminated',
    },
    revocationTriggers: REQUIRED_TRIGGERS.map(trigger).reverse(),
    accessGrants: [
      accessGrant('GRANT-DOC-ALPHA', 'controlled_documents', 0),
      accessGrant('GRANT-STUDY-ALPHA', 'trial_records', 1),
      accessGrant('GRANT-EVIDENCE-ALPHA', 'quality_evidence', 2),
    ].reverse(),
    revocationAction: {
      actionId: 'ACCESS-REVOCATION-ACTION-0001',
      actionType: 'revoke_access',
      reasonCode: 'termination_and_policy_trigger',
      effectiveAtHlc: { physicalMs: 1810000001000, logical: 0 },
      processedByDid: 'did:exo:access-governor-alpha',
      notificationEvidenceHash: DIGEST_C,
      previousAuditHash: DIGEST_D,
      auditEventHash: DIGEST_E,
      disclosureLogHash: DIGEST_F,
      affectedSystemRefs: ['document-service', 'evidence-service', 'study-workspace'],
      humanReviewed: true,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    custodyDigest: DIGEST_1,
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_2,
    },
  };

  return {
    ...base,
    ...overrides,
  };
}

test('access revocation creates deterministic inactive Rule 15 access-withdrawal receipts', async () => {
  const { evaluateAccessRevocation } = await loadAccessRevocation();
  const input = baseInput();

  const resultA = evaluateAccessRevocation(input);
  const resultB = evaluateAccessRevocation({
    ...input,
    revocationPolicy: {
      ...input.revocationPolicy,
      coveredTriggerTypes: [...input.revocationPolicy.coveredTriggerTypes].reverse(),
    },
    revocationTriggers: [...input.revocationTriggers].reverse(),
    accessGrants: [
      {
        ...input.accessGrants[0],
        permissions: [...input.accessGrants[0].permissions].reverse(),
      },
      input.accessGrants[2],
      input.accessGrants[1],
    ],
    revocationAction: {
      ...input.revocationAction,
      affectedSystemRefs: [...input.revocationAction.affectedSystemRefs].reverse(),
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.deepEqual(resultA.reasons, []);
  assert.equal(resultA.trustState, 'inactive');
  assert.equal(resultA.exochainProductionClaim, false);
  assert.equal(resultA.accessRevocation.revocationHash, resultB.accessRevocation.revocationHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'access_revocation_decision');
  assert.deepEqual(resultA.accessRevocation.triggerTypes, REQUIRED_TRIGGERS);
  assert.deepEqual(resultA.accessRevocation.revokedGrantIds, [
    'GRANT-DOC-ALPHA',
    'GRANT-EVIDENCE-ALPHA',
    'GRANT-STUDY-ALPHA',
  ]);
  assert.equal(resultA.accessRevocation.noActiveProtectedAccess, true);
  assert.deepEqual(Object.keys(resultA.accessRevocation), [
    'schema',
    'revocationId',
    'revocationHash',
    'tenantId',
    'subjectDid',
    'policyRef',
    'actionType',
    'effectiveAtHlc',
    'triggerTypes',
    'triggerEvidenceHashes',
    'revokedGrantIds',
    'affectedSystemRefs',
    'authorityChainHash',
    'previousAuditHash',
    'auditEventHash',
    'disclosureLogHash',
    'noActiveProtectedAccess',
    'receiptId',
  ]);
  assert.doesNotMatch(JSON.stringify(resultA), /root-backed production authority|participant alice|source document/iu);
});

test('access revocation fails closed for incomplete trigger coverage grant controls and authority defects', async () => {
  const { evaluateAccessRevocation } = await loadAccessRevocation();
  const input = baseInput({
    targetTenantId: 'tenant-site-beta',
    actor: { did: 'did:exo:access-governor-alpha', kind: 'ai_agent' },
    authority: {
      valid: false,
      revoked: true,
      expired: true,
      permissions: ['read'],
      authorityChainHash: 'not-a-digest',
    },
  });

  const denied = evaluateAccessRevocation({
    ...input,
    revocationPolicy: {
      ...input.revocationPolicy,
      status: 'draft',
      coveredTriggerTypes: ['role_change'],
      leastPrivilegeRequired: false,
      timeBoundRequired: false,
      revocationRequired: false,
      auditTrailRequired: false,
      humanReviewRequired: false,
      metadataOnly: false,
      protectedContentExcluded: false,
    },
    revocationTriggers: [
      trigger('role_change', 0, { evidenceHash: 'not-a-digest', metadataOnly: false }),
      trigger('unsupported_trigger', 1, { protectedContentExcluded: false }),
    ],
    accessGrants: [
      accessGrant('GRANT-DOC-ALPHA', 'controlled_documents', 0, {
        status: 'active',
        principalDid: 'did:exo:wrong-user',
        tenantId: 'tenant-site-beta',
        revocable: false,
        timeBound: false,
        leastPrivilege: false,
        permissions: ['read', 'write', 'govern'],
        accessPolicyHash: 'bad',
        authorityChainHash: 'bad',
        lastAuditHash: 'bad',
      }),
    ],
    revocationAction: {
      ...input.revocationAction,
      actionId: '',
      effectiveAtHlc: { physicalMs: 1809999999999, logical: 0 },
      processedByDid: 'did:exo:other-user',
      reasonCode: '',
      notificationEvidenceHash: 'bad',
      previousAuditHash: 'bad',
      auditEventHash: 'bad',
      disclosureLogHash: 'bad',
      affectedSystemRefs: [],
      humanReviewed: false,
      metadataOnly: false,
      protectedContentExcluded: false,
    },
    subject: {
      ...input.subject,
      did: '',
      tenantId: 'tenant-site-beta',
    },
    custodyDigest: 'bad',
    aiAssistance: { used: true, finalAuthority: true, recommendationHash: 'bad' },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.accessRevocation, null);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_chain_invalid'));
  assert.ok(denied.reasons.includes('authority_chain_revoked'));
  assert.ok(denied.reasons.includes('authority_chain_expired'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('policy_missing_trigger_coverage:delegation_expiration'));
  assert.ok(denied.reasons.includes('policy_missing_trigger_coverage:policy_violation'));
  assert.ok(denied.reasons.includes('trigger_type_invalid:REV-TRIGGER-1'));
  assert.ok(denied.reasons.includes('trigger_evidence_hash_invalid:REV-TRIGGER-0'));
  assert.ok(denied.reasons.includes('subject_did_absent'));
  assert.ok(denied.reasons.includes('grant_principal_mismatch:GRANT-DOC-ALPHA'));
  assert.ok(denied.reasons.includes('grant_not_revocable:GRANT-DOC-ALPHA'));
  assert.ok(denied.reasons.includes('grant_not_time_bound:GRANT-DOC-ALPHA'));
  assert.ok(denied.reasons.includes('grant_not_least_privilege:GRANT-DOC-ALPHA'));
  assert.ok(denied.reasons.includes('grant_excessive_permission:GRANT-DOC-ALPHA'));
  assert.ok(denied.reasons.includes('revocation_action_id_absent'));
  assert.ok(denied.reasons.includes('revocation_effective_before_trigger'));
  assert.ok(denied.reasons.includes('revocation_processor_actor_mismatch'));
  assert.ok(denied.reasons.includes('revocation_human_review_absent'));
  assert.ok(denied.reasons.includes('custody_digest_invalid'));
});

test('access revocation rejects raw access content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateAccessRevocation } = await loadAccessRevocation();

  assert.throws(
    () =>
      evaluateAccessRevocation({
        ...baseInput(),
        rawAccessLog: 'Participant Alice Example source document access log must stay outside receipts.',
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateAccessRevocation({
        ...baseInput(),
        accessToken: 'token-value-must-not-enter-revocation-records',
      }),
    ProtectedContentError,
  );
});
