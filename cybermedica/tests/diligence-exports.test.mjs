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

async function loadDiligenceExports() {
  try {
    return await import('../src/diligence-exports.mjs');
  } catch (error) {
    assert.fail(`CyberMedica diligence export module must exist and load: ${error.message}`);
  }
}

const exportInput = Object.freeze({
  tenantId: 'tenant-site-alpha',
  targetTenantId: 'tenant-site-alpha',
  recipientTenantId: 'tenant-sponsor-alpha',
  actor: { did: 'did:exo:sponsor-monitor-alpha', kind: 'human' },
  authority: { valid: true, revoked: false, expired: false, permissions: ['read'] },
  consent: {
    required: true,
    status: 'active',
    revoked: false,
    consentRef: 'export-grant-sponsor-alpha-001',
  },
  exportGrant: {
    status: 'active',
    scope: 'sponsor_diligence_export',
    expiresAtHlc: { physicalMs: 1792592000000, logical: 0 },
  },
  manifestHlc: { physicalMs: 1790000000000, logical: 21 },
  custodyDigest: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  artifacts: [
    {
      evidenceId: 'evidence-training-001',
      controlId: 'CM-QMS-TRAINING-001',
      artifactType: 'training_matrix',
      artifactVersion: 'v3',
      artifactHash: '1111111111111111111111111111111111111111111111111111111111111111',
      classification: 'confidential_metadata_only',
      tenantScopedPseudonym: 'site-alpha-training-evidence-001',
    },
    {
      evidenceId: 'evidence-facility-001',
      controlId: 'CM-QMS-FACILITY-001',
      artifactType: 'facility_readiness',
      artifactVersion: 'v2',
      artifactHash: '2222222222222222222222222222222222222222222222222222222222222222',
      classification: 'confidential_metadata_only',
      tenantScopedPseudonym: 'site-alpha-facility-evidence-001',
    },
  ],
});

test('diligence export manifests are deterministic hash-only and inactive until Exochain receipt activation', async () => {
  const { buildDiligenceExportManifest } = await loadDiligenceExports();

  const manifestA = buildDiligenceExportManifest(exportInput);
  const manifestB = buildDiligenceExportManifest({
    ...exportInput,
    artifacts: [...exportInput.artifacts].reverse(),
  });

  assert.equal(manifestA.decision, 'permitted');
  assert.equal(manifestA.manifestId, manifestB.manifestId);
  assert.equal(manifestA.receipt.receiptId, manifestB.receipt.receiptId);
  assert.equal(manifestA.exochainProductionClaim, false);
  assert.equal(manifestA.trustState, 'inactive');
  assert.deepEqual(Object.keys(manifestA.manifestArtifacts[0]), [
    'artifactHash',
    'artifactType',
    'artifactVersion',
    'classification',
    'controlId',
    'evidenceId',
    'tenantScopedPseudonym',
  ]);
});

test('diligence export denies raw protected content before manifest or receipt creation', async () => {
  const { buildDiligenceExportManifest } = await loadDiligenceExports();

  assert.throws(
    () =>
      buildDiligenceExportManifest({
        ...exportInput,
        artifacts: [
          {
            ...exportInput.artifacts[0],
            sourceDocumentBody: 'Participant Alice Example signed this source document.',
          },
        ],
      }),
    /protected content/i,
  );
});

test('diligence export fails closed for tenant mismatch revoked grant or missing read authority', async () => {
  const { buildDiligenceExportManifest } = await loadDiligenceExports();

  const revoked = buildDiligenceExportManifest({
    ...exportInput,
    consent: { ...exportInput.consent, status: 'revoked', revoked: true },
    exportGrant: { ...exportInput.exportGrant, status: 'revoked' },
  });

  assert.equal(revoked.decision, 'denied');
  assert.equal(revoked.receipt, null);
  assert.ok(revoked.reasons.includes('consent_revoked'));
  assert.ok(revoked.reasons.includes('export_grant_not_active'));

  const tenantMismatch = buildDiligenceExportManifest({
    ...exportInput,
    targetTenantId: 'tenant-site-beta',
  });

  assert.equal(tenantMismatch.decision, 'denied');
  assert.ok(tenantMismatch.reasons.includes('tenant_boundary_violation'));

  const noAuthority = buildDiligenceExportManifest({
    ...exportInput,
    authority: { valid: true, revoked: false, expired: false, permissions: ['govern'] },
  });

  assert.equal(noAuthority.decision, 'denied');
  assert.ok(noAuthority.reasons.includes('authority_permission_missing'));
});
