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
const DIGEST_9 = '9999999999999999999999999999999999999999999999999999999999999999';

const REQUIRED_FORMATS = ['markdown', 'pdf', 'print', 'word'];
const REQUIRED_PACKET_SCOPES = ['audit_training_packet', 'role_manual_packet', 'workflow_manual_packet'];
const REQUIRED_BOUNDARY_CONTROLS = [
  'metadata_only_manifest',
  'no_raw_manual_content',
  'no_unapproved_claims',
  'print_watermark',
  'role_access_filtering',
  'version_history_included',
];

async function loadManualExportPackets() {
  try {
    return await import('../src/manual-export-packets.mjs');
  } catch (error) {
    assert.fail(`CyberMedica manual export packet module must exist and load: ${error.message}`);
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

function manualArtifact(role, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F];
  return {
    manualRef: `manual-${role}`,
    roleRef: role,
    workflowRefs: ['workflow-trial-startup', 'workflow-evidence-intake'],
    sectionIndexHash: hashes[index],
    manualVersionHash: hashes[index + 1],
    crosslinkMatrixHash: DIGEST_7,
    publicationReceiptHash: DIGEST_8,
    approvedForExport: true,
    currentVersion: true,
    highRiskClaimsReviewed: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    exportEligibleFormats: REQUIRED_FORMATS,
    lastReviewedAtHlc: { physicalMs: 1800010000000, logical: index },
    ...overrides,
  };
}

function exportManifestItem(scope, index, overrides = {}) {
  const hashes = [DIGEST_1, DIGEST_2, DIGEST_3];
  return {
    scope,
    manifestRef: `manual-export-${scope}`,
    manifestHash: hashes[index],
    includesVersionHistory: true,
    includesRoleAccessSummary: true,
    includesTrainingUseStatement: true,
    includesAuditUseStatement: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function exportInput(overrides = {}) {
  return mergeDeep(
    {
      tenantId: 'tenant-site-alpha',
      targetTenantId: 'tenant-site-alpha',
      actor: {
        did: 'did:exo:documentation-exporter-alpha',
        kind: 'human',
        roleRefs: ['quality_manager', 'auditor_inspector'],
      },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['manual_export', 'read'],
        authorityChainHash: DIGEST_A,
      },
      exportPolicy: {
        policyRef: 'manual-export-policy-alpha',
        policyHash: DIGEST_B,
        status: 'active',
        allowedFormats: REQUIRED_FORMATS,
        requiredPacketScopes: REQUIRED_PACKET_SCOPES,
        requiredBoundaryControls: REQUIRED_BOUNDARY_CONTROLS,
        humanAuthorizationRequired: true,
        metadataOnly: true,
        protectedContentExcluded: true,
        evaluatedAtHlc: { physicalMs: 1800009900000, logical: 0 },
      },
      exportRequest: {
        requestRef: 'manual-export-request-alpha',
        requestedFormats: REQUIRED_FORMATS,
        requestedRoleRefs: ['quality_manager', 'auditor_inspector'],
        requestedWorkflowRefs: ['workflow-trial-startup', 'workflow-evidence-intake'],
        requestedPacketScopes: REQUIRED_PACKET_SCOPES,
        purpose: 'audit_training_use',
        requestedAtHlc: { physicalMs: 1800010100000, logical: 0 },
        generatedAtHlc: { physicalMs: 1800010200000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
        productionTrustClaim: false,
      },
      sourceManualSet: {
        runbookReceiptHash: DIGEST_C,
        publicationReceiptHash: DIGEST_D,
        manualSetHash: DIGEST_E,
        manualIndexHash: DIGEST_F,
        documentationVersionRef: 'manual-set-alpha-v3',
        rollbackVersionHash: DIGEST_1,
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      manualArtifacts: [manualArtifact('quality_manager', 0), manualArtifact('auditor_inspector', 2)],
      exportManifest: REQUIRED_PACKET_SCOPES.map((scope, index) => exportManifestItem(scope, index)),
      boundaryAttestation: {
        controls: REQUIRED_BOUNDARY_CONTROLS,
        suppressedSectionRefs: ['manual-section-sponsor-confidential-excluded'],
        suppressionLogHash: DIGEST_4,
        watermarkedForPrint: true,
        formatRenderHashes: {
          markdown: DIGEST_5,
          pdf: DIGEST_6,
          print: DIGEST_7,
          word: DIGEST_8,
        },
        noRawManualContent: true,
        noUnapprovedClaims: true,
        protectedContentExcluded: true,
        metadataOnly: true,
      },
      humanAuthorization: {
        status: 'approved',
        reviewerDid: 'did:exo:documentation-reviewer-alpha',
        reviewHash: DIGEST_9,
        approvedAtHlc: { physicalMs: 1800010150000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      receiptEvidence: {
        custodyDigest: DIGEST_2,
        artifactHash: DIGEST_3,
        evidenceHash: DIGEST_4,
      },
    },
    overrides,
  );
}

test('manual export packets create deterministic DOC-008 inactive receipts', async () => {
  const { evaluateManualExportPacket } = await loadManualExportPackets();
  const inputA = exportInput({
    exportRequest: {
      requestedFormats: ['word', 'markdown', 'print', 'pdf'],
      requestedRoleRefs: ['auditor_inspector', 'quality_manager'],
    },
  });
  const inputB = exportInput({
    exportRequest: {
      requestedFormats: ['markdown', 'pdf', 'print', 'word'],
      requestedRoleRefs: ['quality_manager', 'auditor_inspector'],
    },
  });

  const first = evaluateManualExportPacket(inputA);
  const second = evaluateManualExportPacket(inputB);

  assert.equal(first.status, 'ready');
  assert.deepEqual(first.reasons, []);
  assert.deepEqual(first.manualExportPacket.formats, REQUIRED_FORMATS);
  assert.deepEqual(first.manualExportPacket.packetScopes, REQUIRED_PACKET_SCOPES);
  assert.deepEqual(first.manualExportPacket.roleRefs, ['auditor_inspector', 'quality_manager']);
  assert.equal(first.manualExportPacket.printReady, true);
  assert.equal(first.manualExportPacket.productionTrustClaim, false);
  assert.equal(first.manualExportPacket.metadataOnly, true);
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.equal(first.receipt.anchorPayload.artifactType, 'manual_export_packet');
  assert.deepEqual(first, second);
});

test('manual export packets fail closed for missing formats unsafe access and unreviewed claims', async () => {
  const { evaluateManualExportPacket } = await loadManualExportPackets();
  const result = evaluateManualExportPacket(
    exportInput({
      actor: {
        roleRefs: ['sponsor_viewer'],
      },
      authority: {
        permissions: ['read'],
      },
      exportPolicy: {
        allowedFormats: ['markdown'],
        requiredBoundaryControls: ['metadata_only_manifest'],
      },
      exportRequest: {
        requestedFormats: ['markdown', 'pdf', 'html'],
        requestedRoleRefs: ['quality_manager', 'auditor_inspector'],
        generatedAtHlc: { physicalMs: 1800010100000, logical: 0 },
      },
      manualArtifacts: [
        manualArtifact('quality_manager', 0, { highRiskClaimsReviewed: false }),
        manualArtifact('auditor_inspector', 2, { currentVersion: false }),
      ],
      boundaryAttestation: {
        controls: ['metadata_only_manifest'],
        noUnapprovedClaims: false,
        watermarkedForPrint: false,
      },
      humanAuthorization: {
        status: 'pending',
      },
    }),
  );

  assert.equal(result.status, 'denied');
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('manual_export_authority_missing'));
  assert.ok(result.reasons.includes('format_unsupported:html'));
  assert.ok(result.reasons.includes('format_not_allowed:pdf'));
  assert.ok(result.reasons.includes('requested_role_not_authorized:auditor_inspector'));
  assert.ok(result.reasons.includes('requested_role_not_authorized:quality_manager'));
  assert.ok(result.reasons.includes('boundary_control_missing:no_unapproved_claims'));
  assert.ok(result.reasons.includes('boundary_control_missing:print_watermark'));
  assert.ok(result.reasons.includes('manual_high_risk_claim_review_missing:manual-quality_manager'));
  assert.ok(result.reasons.includes('manual_not_current_version:manual-auditor_inspector'));
  assert.ok(result.reasons.includes('human_authorization_not_approved'));
  assert.ok(result.reasons.includes('generated_hlc_not_after_requested_hlc'));
});

test('manual export packets report absent objects and inert raw markers as denial states', async () => {
  const { evaluateManualExportPacket } = await loadManualExportPackets();
  const result = evaluateManualExportPacket(
    exportInput({
      actor: {
        kind: 'service_account',
      },
      exportRequest: {
        requestedFormats: ['html'],
        requestedPacketScopes: ['role_manual_packet'],
        requestedRoleRefs: ['quality_manager'],
        rawManualContent: null,
      },
      sourceManualSet: null,
      manualArtifacts: [],
      exportManifest: [],
      boundaryAttestation: {
        controls: [],
        formatRenderHashes: null,
        noRawManualContent: false,
        rawManualContent: null,
      },
      humanAuthorization: null,
      receiptEvidence: {
        artifactHash: null,
        custodyDigest: null,
        evidenceHash: null,
      },
    }),
  );

  assert.equal(result.status, 'denied');
  assert.ok(result.reasons.includes('service_account_human_owner_absent'));
  assert.ok(result.reasons.includes('format_unsupported:html'));
  assert.ok(result.reasons.includes('required_format_missing:markdown'));
  assert.ok(result.reasons.includes('manual_artifact_missing:quality_manager'));
  assert.ok(result.reasons.includes('manifest_packet_scope_missing:audit_training_packet'));
  assert.ok(result.reasons.includes('source_manual_set_metadata_only_absent'));
  assert.ok(result.reasons.includes('boundary_control_missing:no_raw_manual_content'));
  assert.ok(result.reasons.includes('format_render_hash_invalid:pdf'));
  assert.ok(result.reasons.includes('human_authorization_not_approved'));
  assert.ok(result.reasons.includes('custody_digest_invalid'));
});

test('manual export packets reject raw manual content and secrets before receipt creation', async () => {
  const { ProtectedContentError, evaluateManualExportPacket } = await loadManualExportPackets();

  assert.throws(
    () =>
      evaluateManualExportPacket(
        exportInput({
          manualArtifacts: [manualArtifact('quality_manager', 0, { rawManualContent: 'source section text' })],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateManualExportPacket(
        exportInput({
          manualArtifacts: [manualArtifact('quality_manager', 0, { rawManualContent: ['source section text'] })],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateManualExportPacket(
        exportInput({
          exportRequest: {
            signerPrivateKey: 'private-key-material',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateManualExportPacket(
        exportInput({
          exportRequest: {
            signerPrivateKey: { keyRef: 'root-signing-material' },
          },
        }),
      ),
    ProtectedContentError,
  );
});
