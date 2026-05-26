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

async function loadTenantIsolation() {
  try {
    return await import('../src/tenant-isolation.mjs');
  } catch (error) {
    assert.fail(`CyberMedica tenant isolation module must exist and load: ${error.message}`);
  }
}

const registry = Object.freeze([
  {
    tenantId: 'tenant-site-alpha',
    kind: 'site',
    status: 'active',
    allowedOperations: ['read', 'write', 'export'],
    constitutionHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  },
  {
    tenantId: 'tenant-sponsor-alpha',
    kind: 'sponsor',
    status: 'active',
    allowedOperations: ['receive_export'],
    constitutionHash: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  },
  {
    tenantId: 'tenant-site-beta',
    kind: 'site',
    status: 'active',
    allowedOperations: ['read', 'write', 'export'],
    constitutionHash: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
  },
]);

const baseInput = Object.freeze({
  requestId: 'cm-tenant-access-0001',
  operation: 'read',
  tenantId: 'tenant-site-alpha',
  targetTenantId: 'tenant-site-alpha',
  requestedAtHlc: { physicalMs: 1790000000000, logical: 31 },
  actor: {
    did: 'did:exo:clinical-research-coordinator-alpha',
    kind: 'human',
    tenantId: 'tenant-site-alpha',
    tenantMemberships: ['tenant-site-alpha'],
  },
  authority: { valid: true, revoked: false, expired: false, permissions: ['read'] },
  tenantRegistry: registry,
  resource: {
    tenantId: 'tenant-site-alpha',
    resourceType: 'participant_record_metadata',
    resourceId: 'participant-record-metadata-0001',
    artifactHash: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    classification: 'confidential_metadata_only',
  },
  custodyDigest: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
});

test('tenant service access is deterministic metadata-only and inactive until runtime activation', async () => {
  const { evaluateTenantServiceAccess } = await loadTenantIsolation();

  const decisionA = evaluateTenantServiceAccess(baseInput);
  const decisionB = evaluateTenantServiceAccess({
    ...baseInput,
    actor: {
      ...baseInput.actor,
      tenantMemberships: [...baseInput.actor.tenantMemberships].reverse(),
    },
    tenantRegistry: [...baseInput.tenantRegistry].reverse(),
  });

  assert.equal(decisionA.decision, 'permitted');
  assert.equal(decisionA.failClosed, false);
  assert.equal(decisionA.serviceAccess.serviceAccessId, decisionB.serviceAccess.serviceAccessId);
  assert.equal(decisionA.receipt.receiptId, decisionB.receipt.receiptId);
  assert.equal(decisionA.trustState, 'inactive');
  assert.equal(decisionA.exochainProductionClaim, false);
  assert.equal(decisionA.serviceAccess.operation, 'read');
  assert.equal(decisionA.serviceAccess.immutableAccessReceipt, true);
  assert.equal(decisionA.serviceAccess.operationalStateMutable, true);
  assert.deepEqual(Object.keys(decisionA.serviceAccess), [
    'actorDid',
    'immutableAccessReceipt',
    'operation',
    'operationalStateMutable',
    'receiptId',
    'requestId',
    'requestedAtHlc',
    'resourceHash',
    'resourceId',
    'resourceTenantId',
    'resourceType',
    'schema',
    'serviceAccessId',
    'targetTenantId',
    'tenantId',
  ]);
});

test('tenant service access denies cross-tenant read write export and tenant-id tampering', async () => {
  const { evaluateTenantServiceAccess } = await loadTenantIsolation();

  const crossTenantRead = evaluateTenantServiceAccess({
    ...baseInput,
    targetTenantId: 'tenant-site-beta',
    resource: {
      ...baseInput.resource,
      tenantId: 'tenant-site-beta',
      resourceId: 'participant-record-metadata-9999',
    },
  });

  assert.equal(crossTenantRead.decision, 'denied');
  assert.equal(crossTenantRead.serviceAccess, null);
  assert.equal(crossTenantRead.receipt, null);
  assert.ok(crossTenantRead.reasons.includes('tenant_boundary_violation'));
  assert.ok(crossTenantRead.reasons.includes('actor_tenant_membership_missing'));

  const crossTenantWrite = evaluateTenantServiceAccess({
    ...baseInput,
    operation: 'write',
    authority: { valid: true, revoked: false, expired: false, permissions: ['write'] },
    actor: {
      ...baseInput.actor,
      tenantMemberships: ['tenant-site-alpha', 'tenant-site-beta'],
    },
    targetTenantId: 'tenant-site-beta',
    resource: {
      ...baseInput.resource,
      tenantId: 'tenant-site-beta',
      resourceId: 'quality-control-record-9999',
      resourceType: 'quality_control_metadata',
    },
  });

  assert.equal(crossTenantWrite.decision, 'denied');
  assert.ok(crossTenantWrite.reasons.includes('tenant_boundary_violation'));

  const tamperedResource = evaluateTenantServiceAccess({
    ...baseInput,
    resource: {
      ...baseInput.resource,
      tenantId: 'tenant-site-beta',
    },
  });

  assert.equal(tamperedResource.decision, 'denied');
  assert.ok(tamperedResource.reasons.includes('resource_tenant_mismatch'));

  const crossTenantExport = evaluateTenantServiceAccess({
    ...baseInput,
    operation: 'export',
    recipientTenantId: 'tenant-sponsor-alpha',
    targetTenantId: 'tenant-site-beta',
    authority: { valid: true, revoked: false, expired: false, permissions: ['read'] },
    actor: {
      ...baseInput.actor,
      tenantMemberships: ['tenant-site-alpha'],
    },
    consent: { required: true, status: 'active', revoked: false, consentRef: 'export-consent-alpha-0001' },
    exportGrant: {
      grantId: 'export-grant-alpha-0001',
      status: 'active',
      scope: 'tenant_export',
      sourceTenantId: 'tenant-site-alpha',
      recipientTenantId: 'tenant-sponsor-alpha',
    },
    resource: {
      ...baseInput.resource,
      tenantId: 'tenant-site-beta',
      resourceType: 'diligence_export_manifest_metadata',
    },
  });

  assert.equal(crossTenantExport.decision, 'denied');
  assert.ok(crossTenantExport.reasons.includes('tenant_boundary_violation'));
  assert.ok(crossTenantExport.reasons.includes('resource_tenant_mismatch'));
});

test('tenant service access fails closed for suspended tenants and protected content', async () => {
  const { evaluateTenantServiceAccess } = await loadTenantIsolation();

  const suspended = evaluateTenantServiceAccess({
    ...baseInput,
    tenantRegistry: [
      {
        ...registry[0],
        status: 'suspended',
      },
      registry[1],
    ],
  });

  assert.equal(suspended.decision, 'denied');
  assert.ok(suspended.reasons.includes('tenant_not_active'));
  assert.equal(suspended.serviceAccess, null);
  assert.equal(suspended.receipt, null);

  const recipientArchived = evaluateTenantServiceAccess({
    ...baseInput,
    operation: 'export',
    recipientTenantId: 'tenant-sponsor-alpha',
    authority: { valid: true, revoked: false, expired: false, permissions: ['read'] },
    consent: { required: true, status: 'active', revoked: false, consentRef: 'export-consent-alpha-0001' },
    exportGrant: {
      grantId: 'export-grant-alpha-0001',
      status: 'active',
      scope: 'tenant_export',
      sourceTenantId: 'tenant-site-alpha',
      recipientTenantId: 'tenant-sponsor-alpha',
    },
    tenantRegistry: [
      registry[0],
      {
        ...registry[1],
        status: 'archived',
      },
    ],
  });

  assert.equal(recipientArchived.decision, 'denied');
  assert.ok(recipientArchived.reasons.includes('recipient_tenant_not_active'));

  assert.throws(
    () =>
      evaluateTenantServiceAccess({
        ...baseInput,
        resource: {
          ...baseInput.resource,
          sourceDocumentBody: 'Participant Alice Example source note',
        },
      }),
    /protected content/i,
  );
});
