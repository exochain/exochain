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

const DIGEST_A = '3d6f0a96f7c972d4f5b66a1c6b5177fe5a32cc0cbd27f7c67be4c11a4f7ce70a';
const DIGEST_B = '8cf4dfd546b712c3b21f0d61fd7c6b744dfc6d9c7d0c8758fb6c6db6e782a7f3';
const DIGEST_C = '54f6e9e53f0e6d9a6ce64b2d67b79d44a927f276e8916d34a2d3b942f575f1b7';
const DIGEST_D = 'd9470f1f6f89a8836e46c21ffcf84f544f8b70a54156f8380dfd5bdf8c5f9693';

async function loadDocumentVersions() {
  try {
    return await import('../src/document-versions.mjs');
  } catch (error) {
    assert.fail(`CyberMedica document version workflow module must exist and load: ${error.message}`);
  }
}

function approvedDocumentInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['govern', 'write'] },
    document: {
      documentId: 'CM-QMS-SOP-001',
      documentType: 'standard_operating_procedure',
      controlId: 'CTRL-DOC-001',
      versionId: 'v2',
      lifecycleState: 'approved',
      artifactHash: DIGEST_A,
      previousVersionHash: DIGEST_B,
      previousReceiptId: 'cmr_previous_document_version',
      effectiveAtHlc: { physicalMs: 1790000000500, logical: 3 },
    },
    review: {
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
      },
      evidenceBundle: { complete: true, phiBoundaryAttested: true },
      approverDid: 'did:exo:principal-investigator-alpha',
    },
    evidenceRefs: ['training-impact-assessment', 'sop-redline-review', 'quality-risk-assessment'],
    custodyDigest: DIGEST_C,
    recordedAtHlc: { physicalMs: 1790000000600, logical: 1 },
  };
}

test('approved document versions require human governance and create deterministic inactive metadata receipts', async () => {
  const { registerDocumentVersion } = await loadDocumentVersions();

  const approvedA = registerDocumentVersion(approvedDocumentInput());
  const approvedB = registerDocumentVersion({
    ...approvedDocumentInput(),
    evidenceRefs: [...approvedDocumentInput().evidenceRefs].reverse(),
    review: {
      evidenceBundle: { phiBoundaryAttested: true, complete: true },
      decisionForum: {
        openChallenge: false,
        quorum: { status: 'met' },
        humanGate: { verified: true },
        state: 'approved',
        verified: true,
      },
      approverDid: 'did:exo:principal-investigator-alpha',
    },
  });

  assert.equal(approvedA.decision, 'permitted');
  assert.equal(approvedA.failClosed, false);
  assert.equal(approvedA.documentVersion.lifecycleState, 'approved');
  assert.equal(approvedA.documentVersion.effectiveForUse, true);
  assert.equal(approvedA.documentVersion.operationalStateMutable, true);
  assert.equal(approvedA.documentVersion.immutableVersionReceipt, true);
  assert.equal(approvedA.documentVersion.humanGovernanceRequired, true);
  assert.equal(approvedA.receipt.receiptId, approvedB.receipt.receiptId);
  assert.equal(approvedA.receipt.actionHash, approvedB.receipt.actionHash);
  assert.equal(approvedA.receipt.trustState, 'inactive');
  assert.equal(approvedA.receipt.exochainProductionClaim, false);
  assert.equal(approvedA.receipt.anchorPayload.artifactType, 'document_version');
  assert.doesNotMatch(JSON.stringify(approvedA), /sop-redline-review.*training-impact-assessment.*quality-risk-assessment/u);
  assert.doesNotMatch(JSON.stringify(approvedA.receipt), /protocol body|participant alice|source document/iu);
});

test('document version registration fails closed for tenant boundary authority lineage and protected content', async () => {
  const { registerDocumentVersion } = await loadDocumentVersions();

  const denied = registerDocumentVersion({
    ...approvedDocumentInput(),
    targetTenantId: 'tenant-site-beta',
    authority: { valid: true, revoked: false, expired: false, permissions: ['write'] },
    document: {
      ...approvedDocumentInput().document,
      previousVersionHash: null,
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('previous_version_hash_invalid'));
  assert.equal(denied.documentVersion, null);
  assert.equal(denied.receipt, null);

  assert.throws(
    () =>
      registerDocumentVersion({
        ...approvedDocumentInput(),
        rawContent: 'Participant Alice Example source document body should never be anchored.',
      }),
    /protected content/i,
  );
});

test('draft document versions can be registered with write authority without claiming governed approval', async () => {
  const { registerDocumentVersion } = await loadDocumentVersions();

  const draft = registerDocumentVersion({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:document-control-alpha', kind: 'human' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['write'] },
    document: {
      documentId: 'CM-QMS-WI-014',
      documentType: 'work_instruction',
      controlId: 'CTRL-DOC-014',
      versionId: 'v1',
      lifecycleState: 'draft',
      artifactHash: DIGEST_D,
      previousVersionHash: null,
      previousReceiptId: null,
      effectiveAtHlc: null,
    },
    review: null,
    evidenceRefs: ['authoring-record'],
    custodyDigest: DIGEST_C,
    recordedAtHlc: { physicalMs: 1790000000700, logical: 1 },
  });

  assert.equal(draft.decision, 'permitted');
  assert.equal(draft.documentVersion.lifecycleState, 'draft');
  assert.equal(draft.documentVersion.effectiveForUse, false);
  assert.equal(draft.documentVersion.humanGovernanceRequired, false);
  assert.equal(draft.documentVersion.requiresApprovalBeforeUse, true);
  assert.equal(draft.receipt.anchorPayload.artifactType, 'document_version');
  assert.equal(draft.receipt.trustState, 'inactive');
});
