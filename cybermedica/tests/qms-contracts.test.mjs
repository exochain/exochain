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

async function loadQmsContracts() {
  try {
    return await import('../src/qms-contracts.mjs');
  } catch (error) {
    assert.fail(`CyberMedica QMS contract module must exist and load: ${error.message}`);
  }
}

const evidenceReceiptInput = Object.freeze({
  tenantId: 'tenant-site-alpha',
  actorDid: 'did:exo:site-quality-manager-alpha',
  artifactType: 'qms_control_evidence',
  artifactVersion: 'CM-QMS-CTRL-0001@v1',
  artifactHash: '3d6f0a96f7c972d4f5b66a1c6b5177fe5a32cc0cbd27f7c67be4c11a4f7ce70a',
  classification: 'confidential_metadata_only',
  hlcTimestamp: { physicalMs: 1790000000000, logical: 7 },
  custodyDigest: '8cf4dfd546b712c3b21f0d61fd7c6b744dfc6d9c7d0c8758fb6c6db6e782a7f3',
  sensitivityTags: ['participant_safety_relevant', 'sponsor_confidential_metadata'],
  sourceSystem: 'cybermedica-qms',
});

test('evidence receipts are deterministic and refuse protected source content', async () => {
  const { createEvidenceReceipt } = await loadQmsContracts();

  const receiptA = createEvidenceReceipt(evidenceReceiptInput);
  const receiptB = createEvidenceReceipt({
    sourceSystem: evidenceReceiptInput.sourceSystem,
    sensitivityTags: [...evidenceReceiptInput.sensitivityTags].reverse(),
    custodyDigest: evidenceReceiptInput.custodyDigest,
    hlcTimestamp: { logical: 7, physicalMs: 1790000000000 },
    classification: evidenceReceiptInput.classification,
    artifactHash: evidenceReceiptInput.artifactHash,
    artifactVersion: evidenceReceiptInput.artifactVersion,
    artifactType: evidenceReceiptInput.artifactType,
    actorDid: evidenceReceiptInput.actorDid,
    tenantId: evidenceReceiptInput.tenantId,
  });

  assert.equal(receiptA.receiptId, receiptB.receiptId);
  assert.equal(receiptA.actionHash, receiptB.actionHash);
  assert.equal(receiptA.exochainProductionClaim, false);
  assert.equal(receiptA.trustState, 'inactive');
  assert.equal(receiptA.containsProtectedContent, false);
  assert.deepEqual(Object.keys(receiptA.anchorPayload), [
    'actorDid',
    'artifactHash',
    'artifactType',
    'artifactVersion',
    'classification',
    'custodyDigest',
    'hlcTimestamp',
    'schema',
    'sensitivityTags',
    'sourceSystem',
    'tenantId',
  ]);

  assert.throws(
    () =>
      createEvidenceReceipt({
        ...evidenceReceiptInput,
        sourceDocumentBody: 'Participant Alice Example had a clinically significant adverse event.',
      }),
    /protected content/i,
  );
});

test('strategic clinical gates deny AI final authority and require verified human governance', async () => {
  const { evaluateGovernedAction } = await loadQmsContracts();

  const aiLaunchDecision = evaluateGovernedAction({
    action: 'protocol_launch',
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:ai-quality-reviewer-alpha', kind: 'ai_agent' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['govern'] },
    decisionForum: {
      verified: true,
      state: 'approved',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
    },
    evidenceBundle: { complete: true, phiBoundaryAttested: true },
  });

  assert.equal(aiLaunchDecision.decision, 'denied');
  assert.equal(aiLaunchDecision.failClosed, true);
  assert.ok(aiLaunchDecision.reasons.includes('ai_final_authority_forbidden'));

  const unverifiedHumanDecision = evaluateGovernedAction({
    action: 'protocol_launch',
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:principal-investigator-alpha', kind: 'human' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['govern'] },
    decisionForum: {
      verified: true,
      state: 'approved',
      humanGate: { verified: false },
      quorum: { status: 'met' },
      openChallenge: false,
    },
    evidenceBundle: { complete: true, phiBoundaryAttested: true },
  });

  assert.equal(unverifiedHumanDecision.decision, 'denied');
  assert.ok(unverifiedHumanDecision.reasons.includes('human_gate_unverified'));

  const verifiedHumanDecision = evaluateGovernedAction({
    action: 'protocol_launch',
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:principal-investigator-alpha', kind: 'human' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['govern'] },
    decisionForum: {
      verified: true,
      state: 'approved',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
    },
    evidenceBundle: { complete: true, phiBoundaryAttested: true },
  });

  assert.equal(verifiedHumanDecision.decision, 'permitted');
  assert.equal(verifiedHumanDecision.exochainProductionClaim, false);
  assert.equal(verifiedHumanDecision.trustState, 'inactive');
});

test('participant consent revocation and tenant mismatch deny regulated access', async () => {
  const { evaluateGovernedAction } = await loadQmsContracts();

  const revokedConsentDecision = evaluateGovernedAction({
    action: 'enrollment_gate',
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:principal-investigator-alpha', kind: 'human' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['govern'] },
    consent: {
      required: true,
      status: 'revoked',
      revoked: true,
      consentRef: 'consent-participant-alpha-001',
    },
    decisionForum: {
      verified: true,
      state: 'approved',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
    },
    evidenceBundle: { complete: true, phiBoundaryAttested: true },
  });

  assert.equal(revokedConsentDecision.decision, 'denied');
  assert.ok(revokedConsentDecision.reasons.includes('consent_revoked'));

  const tenantMismatchDecision = evaluateGovernedAction({
    action: 'sponsor_export',
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-beta',
    actor: { did: 'did:exo:sponsor-monitor-alpha', kind: 'human' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['read'] },
    consent: { required: false },
    evidenceBundle: { complete: true, phiBoundaryAttested: true },
  });

  assert.equal(tenantMismatchDecision.decision, 'denied');
  assert.ok(tenantMismatchDecision.reasons.includes('tenant_boundary_violation'));
});
