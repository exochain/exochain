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

async function loadStudyScopeIsolation() {
  try {
    return await import('../src/study-scope-isolation.mjs');
  } catch (error) {
    assert.fail(`CyberMedica study scope isolation module must exist and load: ${error.message}`);
  }
}

const DIGEST_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const DIGEST_C = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const DIGEST_D = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const DIGEST_E = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const DIGEST_F = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

const studyRegistry = Object.freeze([
  {
    studyId: 'study-cardiac-alpha',
    tenantId: 'tenant-site-alpha',
    siteId: 'site-alpha',
    status: 'active',
    sponsorTenantId: 'tenant-sponsor-alpha',
    croTenantId: 'tenant-cro-alpha',
    protocolRefs: ['protocol-cardiac-alpha-v1', 'protocol-cardiac-alpha-v2'],
    allowedOperations: ['read', 'write', 'export'],
    registryEvidenceHash: DIGEST_A,
    confidentialityClass: 'sponsor_cro_confidential_metadata_only',
  },
  {
    studyId: 'study-oncology-beta',
    tenantId: 'tenant-site-alpha',
    siteId: 'site-alpha',
    status: 'active',
    sponsorTenantId: 'tenant-sponsor-beta',
    croTenantId: 'tenant-cro-beta',
    protocolRefs: ['protocol-oncology-beta-v1'],
    allowedOperations: ['read', 'write', 'export'],
    registryEvidenceHash: DIGEST_B,
    confidentialityClass: 'sponsor_cro_confidential_metadata_only',
  },
]);

function baseInput(overrides = {}) {
  return {
    requestId: 'cm-study-access-0001',
    operation: 'read',
    tenantId: 'tenant-site-alpha',
    siteId: 'site-alpha',
    studyId: 'study-cardiac-alpha',
    targetStudyId: 'study-cardiac-alpha',
    protocolRef: 'protocol-cardiac-alpha-v2',
    requestedAtHlc: { physicalMs: 1797000000000, logical: 11 },
    actor: {
      did: 'did:exo:coordinator-alpha',
      kind: 'human',
      tenantId: 'tenant-site-alpha',
      siteAssignments: ['site-alpha'],
      studyAssignments: ['study-cardiac-alpha'],
      protocolAssignments: ['protocol-cardiac-alpha-v2'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['read'],
      scope: {
        tenantId: 'tenant-site-alpha',
        siteId: 'site-alpha',
        studyIds: ['study-cardiac-alpha'],
        protocolRefs: ['protocol-cardiac-alpha-v2'],
      },
    },
    studyRegistry,
    resource: {
      tenantId: 'tenant-site-alpha',
      siteId: 'site-alpha',
      studyId: 'study-cardiac-alpha',
      protocolRef: 'protocol-cardiac-alpha-v2',
      resourceType: 'visit_readiness_metadata',
      resourceId: 'visit-readiness-cardiac-alpha-001',
      artifactHash: DIGEST_C,
      classification: 'study_scoped_metadata_only',
      participantLinked: false,
    },
    privacyBoundary: {
      metadataOnly: true,
      rawProtectedContentExcluded: true,
      sponsorConfidentialPayloadExcluded: true,
      directIdentifiersExcluded: true,
      receiptPayloadMinimal: true,
    },
    custodyDigest: DIGEST_D,
    ...overrides,
  };
}

test('study scope isolation permits deterministic metadata-only in-study access receipts', async () => {
  const { evaluateStudyScopeIsolation } = await loadStudyScopeIsolation();

  const first = evaluateStudyScopeIsolation(baseInput());
  const second = evaluateStudyScopeIsolation(
    baseInput({
      actor: {
        ...baseInput().actor,
        siteAssignments: [...baseInput().actor.siteAssignments].reverse(),
        studyAssignments: [...baseInput().actor.studyAssignments].reverse(),
        protocolAssignments: [...baseInput().actor.protocolAssignments].reverse(),
      },
      authority: {
        ...baseInput().authority,
        scope: {
          ...baseInput().authority.scope,
          studyIds: [...baseInput().authority.scope.studyIds].reverse(),
          protocolRefs: [...baseInput().authority.scope.protocolRefs].reverse(),
        },
      },
      studyRegistry: [...studyRegistry].reverse(),
    }),
  );

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.trustState, 'inactive');
  assert.equal(first.exochainProductionClaim, false);
  assert.equal(first.studyAccess.accessId, second.studyAccess.accessId);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.studyAccess.studyId, 'study-cardiac-alpha');
  assert.equal(first.studyAccess.protocolRef, 'protocol-cardiac-alpha-v2');
  assert.equal(first.studyAccess.metadataOnly, true);
  assert.equal(first.studyAccess.immutableAccessReceipt, true);
  assert.equal(first.studyAccess.operationalStateMutable, true);
  assert.deepEqual(first.receipt.anchorPayload.sensitivityTags, [
    'metadata_only',
    'study_scope_isolation',
    'study_scoped_access',
  ]);
  assert.doesNotMatch(JSON.stringify(first), /source document|participant alice|protocol body|secret/iu);
});

test('study scope isolation denies cross-study access protocol mismatch and resource tampering', async () => {
  const { evaluateStudyScopeIsolation } = await loadStudyScopeIsolation();

  const crossStudy = evaluateStudyScopeIsolation(
    baseInput({
      targetStudyId: 'study-oncology-beta',
      resource: {
        ...baseInput().resource,
        studyId: 'study-oncology-beta',
        protocolRef: 'protocol-oncology-beta-v1',
        resourceId: 'visit-readiness-oncology-beta-001',
      },
    }),
  );

  assert.equal(crossStudy.decision, 'denied');
  assert.equal(crossStudy.studyAccess, null);
  assert.equal(crossStudy.receipt, null);
  assert.ok(crossStudy.reasons.includes('study_boundary_violation'));
  assert.ok(crossStudy.reasons.includes('actor_target_study_assignment_missing'));
  assert.ok(crossStudy.reasons.includes('protocol_not_in_requested_study'));

  const protocolMismatch = evaluateStudyScopeIsolation(
    baseInput({
      protocolRef: 'protocol-cardiac-alpha-v1',
      resource: {
        ...baseInput().resource,
        protocolRef: 'protocol-cardiac-alpha-v2',
      },
    }),
  );

  assert.equal(protocolMismatch.decision, 'denied');
  assert.ok(protocolMismatch.reasons.includes('resource_protocol_mismatch'));
  assert.ok(protocolMismatch.reasons.includes('actor_protocol_assignment_missing'));
  assert.ok(protocolMismatch.reasons.includes('authority_protocol_scope_missing'));

  const tamperedSite = evaluateStudyScopeIsolation(
    baseInput({
      resource: {
        ...baseInput().resource,
        siteId: 'site-beta',
      },
    }),
  );

  assert.equal(tamperedSite.decision, 'denied');
  assert.ok(tamperedSite.reasons.includes('resource_site_mismatch'));
});

test('study scope isolation gates sponsor CRO exports on visibility grant consent and recipient scope', async () => {
  const { evaluateStudyScopeIsolation } = await loadStudyScopeIsolation();

  const permittedExport = evaluateStudyScopeIsolation(
    baseInput({
      operation: 'export',
      requestId: 'cm-study-export-0001',
      recipientTenantId: 'tenant-sponsor-alpha',
      authority: {
        ...baseInput().authority,
        permissions: ['read'],
      },
      resource: {
        ...baseInput().resource,
        resourceType: 'sponsor_diligence_packet_manifest',
        participantLinked: true,
      },
      consent: {
        status: 'active',
        revoked: false,
        consentRef: 'participant-sharing-consent-alpha-001',
        studyId: 'study-cardiac-alpha',
        participantCodeHash: DIGEST_E,
      },
      visibilityGrant: {
        grantId: 'study-visibility-grant-alpha-001',
        status: 'active',
        scope: 'study_sponsor_cro_export',
        sourceTenantId: 'tenant-site-alpha',
        studyId: 'study-cardiac-alpha',
        recipientTenantId: 'tenant-sponsor-alpha',
        approvedAtHlc: { physicalMs: 1796999999000, logical: 0 },
        grantHash: DIGEST_F,
      },
    }),
  );

  assert.equal(permittedExport.decision, 'permitted');
  assert.equal(permittedExport.studyAccess.operation, 'export');
  assert.equal(permittedExport.studyAccess.recipientTenantId, 'tenant-sponsor-alpha');

  const unsafeExport = evaluateStudyScopeIsolation(
    baseInput({
      operation: 'export',
      recipientTenantId: 'tenant-sponsor-beta',
      resource: {
        ...baseInput().resource,
        resourceType: 'sponsor_diligence_packet_manifest',
        participantLinked: true,
      },
      consent: {
        status: 'revoked',
        revoked: true,
        consentRef: 'participant-sharing-consent-alpha-001',
        studyId: 'study-cardiac-alpha',
        participantCodeHash: DIGEST_E,
      },
      visibilityGrant: {
        grantId: 'study-visibility-grant-alpha-001',
        status: 'active',
        scope: 'study_sponsor_cro_export',
        sourceTenantId: 'tenant-site-alpha',
        studyId: 'study-cardiac-alpha',
        recipientTenantId: 'tenant-sponsor-alpha',
        approvedAtHlc: { physicalMs: 1796999999000, logical: 0 },
        grantHash: DIGEST_F,
      },
    }),
  );

  assert.equal(unsafeExport.decision, 'denied');
  assert.ok(unsafeExport.reasons.includes('recipient_not_authorized_for_study'));
  assert.ok(unsafeExport.reasons.includes('visibility_grant_recipient_mismatch'));
  assert.ok(unsafeExport.reasons.includes('export_consent_revoked'));
});

test('study scope isolation fails closed for inactive studies authority defects and raw protected data', async () => {
  const { evaluateStudyScopeIsolation } = await loadStudyScopeIsolation();

  const denied = evaluateStudyScopeIsolation(
    baseInput({
      authority: { valid: true, revoked: true, expired: true, permissions: [] },
      studyRegistry: [
        {
          ...studyRegistry[0],
          status: 'closed',
        },
        studyRegistry[1],
      ],
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('study_not_active'));
  assert.ok(denied.reasons.includes('authority_chain_revoked'));
  assert.ok(denied.reasons.includes('authority_chain_expired'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));

  assert.throws(
    () =>
      evaluateStudyScopeIsolation(
        baseInput({
          resource: {
            ...baseInput().resource,
            sourceDocumentBody: 'Participant Alice source document',
          },
        }),
      ),
    /protected content/i,
  );

  assert.throws(
    () =>
      evaluateStudyScopeIsolation(
        baseInput({
          visibilityGrant: {
            grantId: 'study-visibility-grant-alpha-001',
            status: 'active',
            scope: 'study_sponsor_cro_export',
            clientSecret: 'redacted-client-secret-placeholder',
          },
        }),
      ),
    /secret/i,
  );
});
