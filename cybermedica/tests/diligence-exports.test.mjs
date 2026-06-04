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

const RESPONSE_PACKAGE_HASH = '3333333333333333333333333333333333333333333333333333333333333333';
const REQUEST_HASH = '4444444444444444444444444444444444444444444444444444444444444444';
const DISCLOSURE_LOG_HASH = '5555555555555555555555555555555555555555555555555555555555555555';
const HUMAN_REVIEW_HASH = '6666666666666666666666666666666666666666666666666666666666666666';

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
  responsePackage: {
    packageRef: 'diligence-response-package-alpha',
    packageHash: RESPONSE_PACKAGE_HASH,
    requestRef: 'sponsor-cro-request-alpha',
    workItemRef: 'sponsor-cro-work-item-alpha',
    recipientTenantId: 'tenant-sponsor-alpha',
    artifactEvidenceIds: ['evidence-training-001', 'evidence-facility-001'],
    generatedAtHlc: { physicalMs: 1790000000000, logical: 20 },
    metadataOnly: true,
    rawContentExcluded: true,
    protectedContentExcluded: true,
  },
  sponsorCroRequestEvidence: {
    requestRef: 'sponsor-cro-request-alpha',
    requestHash: REQUEST_HASH,
    requesterClass: 'sponsor',
    workItemRef: 'sponsor-cro-work-item-alpha',
    workItemStatus: 'approved_for_response',
    disclosureEventRef: 'disclosure-event-sponsor-cro-alpha',
    disclosureLogHash: DISCLOSURE_LOG_HASH,
    decisionForumMatterRef: 'df-sponsor-cro-request-alpha',
    humanReviewHash: HUMAN_REVIEW_HASH,
    responsePackageHash: RESPONSE_PACKAGE_HASH,
    linkedRecipientTenantId: 'tenant-sponsor-alpha',
    metadataOnly: true,
    sourcePayloadExcluded: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    linkedAtHlc: { physicalMs: 1790000000000, logical: 19 },
  },
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
  assert.deepEqual(manifestA.sponsorCroRequestRefs, ['sponsor-cro-request-alpha']);
  assert.deepEqual(manifestA.sponsorCroWorkItemRefs, ['sponsor-cro-work-item-alpha']);
  assert.equal(manifestA.responsePackageHash, RESPONSE_PACKAGE_HASH);
  assert.deepEqual(Object.keys(manifestA.manifestArtifacts[0]), [
    'artifactHash',
    'artifactType',
    'artifactVersion',
    'classification',
    'controlId',
    'evidenceId',
    'tenantScopedPseudonym',
  ]);
  assert.doesNotMatch(JSON.stringify(manifestA), /raw request|source document|Participant Alice|access token/iu);
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

  assert.throws(
    () =>
      buildDiligenceExportManifest({
        ...exportInput,
        sponsorCroRequestEvidence: {
          ...exportInput.sponsorCroRequestEvidence,
          rawRequestNarrative: 'Participant Alice Example source request text.',
        },
      }),
    /raw sponsor\/cro request content|protected content/i,
  );

  assert.throws(
    () =>
      buildDiligenceExportManifest({
        ...exportInput,
        responsePackage: {
          ...exportInput.responsePackage,
          accessToken: 'secret-token-value',
        },
      }),
    /secret field|protected content/i,
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

test('diligence export fails closed without controlled Sponsor/CRO request and response-package linkage', async () => {
  const { buildDiligenceExportManifest } = await loadDiligenceExports();

  const absent = buildDiligenceExportManifest({
    ...exportInput,
    sponsorCroRequestEvidence: null,
  });

  assert.equal(absent.decision, 'denied');
  assert.equal(absent.failClosed, true);
  assert.equal(absent.receipt, null);
  assert.ok(absent.reasons.includes('sponsor_cro_request_evidence_absent'));

  const malformed = buildDiligenceExportManifest({
    ...exportInput,
    sponsorCroRequestEvidence: {
      requestRef: '',
      requestHash: 'not-a-digest',
      requesterClass: 'public_observer',
      workItemRef: '',
      workItemStatus: 'draft',
      disclosureEventRef: '',
      disclosureLogHash: 'bad',
      decisionForumMatterRef: '',
      humanReviewHash: 'bad',
      responsePackageHash: 'bad',
      linkedRecipientTenantId: 'tenant-other',
      metadataOnly: false,
      sourcePayloadExcluded: false,
      protectedContentExcluded: false,
      productionTrustClaim: true,
      linkedAtHlc: { physicalMs: 1790000000000, logical: -1 },
    },
    responsePackage: {
      packageRef: '',
      packageHash: 'not-a-digest',
      requestRef: 'other-request',
      workItemRef: 'other-work-item',
      recipientTenantId: 'tenant-other',
      artifactEvidenceIds: ['evidence-training-001'],
      generatedAtHlc: { physicalMs: 1790000000, logical: 22 },
      metadataOnly: false,
      rawContentExcluded: false,
      protectedContentExcluded: false,
    },
  });

  assert.equal(malformed.decision, 'denied');
  assert.equal(malformed.receipt, null);
  assert.ok(malformed.reasons.includes('sponsor_cro_request_ref_absent'));
  assert.ok(malformed.reasons.includes('sponsor_cro_request_hash_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_requester_class_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_work_item_ref_absent'));
  assert.ok(malformed.reasons.includes('sponsor_cro_work_item_status_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_disclosure_event_ref_absent'));
  assert.ok(malformed.reasons.includes('sponsor_cro_disclosure_log_hash_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_decision_forum_matter_absent'));
  assert.ok(malformed.reasons.includes('sponsor_cro_human_review_hash_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_response_package_hash_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_response_package_ref_absent'));
  assert.ok(malformed.reasons.includes('sponsor_cro_response_package_hash_mismatch'));
  assert.ok(malformed.reasons.includes('sponsor_cro_response_package_request_mismatch'));
  assert.ok(malformed.reasons.includes('sponsor_cro_response_package_work_item_mismatch'));
  assert.ok(malformed.reasons.includes('sponsor_cro_response_package_recipient_mismatch'));
  assert.ok(malformed.reasons.includes('sponsor_cro_response_package_artifact_scope_mismatch'));
  assert.ok(malformed.reasons.includes('sponsor_cro_response_package_metadata_boundary_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_response_package_raw_content_boundary_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_response_package_protected_boundary_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_request_recipient_mismatch'));
  assert.ok(malformed.reasons.includes('sponsor_cro_request_metadata_boundary_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_request_source_payload_boundary_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_request_protected_boundary_invalid'));
  assert.ok(malformed.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(malformed.reasons.includes('sponsor_cro_request_link_time_invalid'));
});
