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
const DIGEST_E = 'f50b82f55e509c9fb872d064d8e513ba60b74a5925c16f70b96c41d727fcb2cc';

async function loadEvidenceIntake() {
  try {
    return await import('../src/evidence-intake.mjs');
  } catch (error) {
    assert.fail(`CyberMedica evidence intake module must exist and load: ${error.message}`);
  }
}

function evidenceIntakeInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:evidence-uploader-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['write', 'evidence_intake'],
      authorityChainHash: DIGEST_D,
    },
    evidence: {
      evidenceId: 'CM-EVD-UPLOAD-0042',
      evidenceType: 'source_document_index',
      artifactHash: DIGEST_A,
      artifactVersion: 'v1',
      documentVersionRef: 'CM-QMS-SOP-001@v2',
      originatingSystemHash: DIGEST_B,
      storageObjectHash: DIGEST_C,
      byteSize: 4096,
      classification: 'participant_related_metadata_only',
      subjectCodeHash: DIGEST_E,
      retentionPolicyRef: 'RET-TRIAL-25Y',
      consentOrBailmentRef: 'consent:CM-ICF-001@v3',
      evidenceRefIds: ['custody-checklist', 'upload-manifest', 'document-control-link'],
      sensitivityTags: ['participant_related', 'source_document', 'metadata_only'],
    },
    intake: {
      uploadedAtHlc: { physicalMs: 1790000000900, logical: 1 },
      uploadChannel: 'validated_site_portal',
      uploaderDid: 'did:exo:evidence-uploader-alpha',
      initialCustodianDid: 'did:exo:evidence-custodian-alpha',
      manifestHash: DIGEST_B,
      payloadStoredOutsideReceipt: true,
    },
    review: {
      reviewerDid: 'did:exo:quality-reviewer-alpha',
      reviewerKind: 'human',
      reviewedAtHlc: { physicalMs: 1790000000910, logical: 0 },
      classificationDecision: 'accepted',
      phiBoundaryAttested: true,
      piiBoundaryAttested: true,
      sponsorConfidentialBoundaryAttested: true,
      privilegedBoundaryAttested: true,
      metadataMinimized: true,
      payloadOpenForInspection: false,
      versionAnchorApproved: true,
      custodyStartApproved: true,
      rationaleHash: DIGEST_C,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_D,
      modelRefHash: DIGEST_E,
      disposition: 'human_reviewed_advisory',
    },
    recordedAtHlc: { physicalMs: 1790000000910, logical: 1 },
  };
}

test('evidence intake classifies uploaded evidence and creates deterministic inactive metadata receipts', async () => {
  const { evaluateEvidenceIntake } = await loadEvidenceIntake();

  const intakeA = evaluateEvidenceIntake(evidenceIntakeInput());
  const intakeB = evaluateEvidenceIntake({
    ...evidenceIntakeInput(),
    evidence: {
      ...evidenceIntakeInput().evidence,
      evidenceRefIds: [...evidenceIntakeInput().evidence.evidenceRefIds].reverse(),
      sensitivityTags: [...evidenceIntakeInput().evidence.sensitivityTags].reverse(),
    },
    review: {
      custodyStartApproved: true,
      versionAnchorApproved: true,
      payloadOpenForInspection: false,
      metadataMinimized: true,
      privilegedBoundaryAttested: true,
      sponsorConfidentialBoundaryAttested: true,
      piiBoundaryAttested: true,
      phiBoundaryAttested: true,
      classificationDecision: 'accepted',
      reviewedAtHlc: { logical: 0, physicalMs: 1790000000910 },
      reviewerKind: 'human',
      reviewerDid: 'did:exo:quality-reviewer-alpha',
      rationaleHash: DIGEST_C,
    },
  });

  assert.equal(intakeA.decision, 'permitted');
  assert.equal(intakeA.failClosed, false);
  assert.equal(intakeA.evidenceIntake.evidenceId, 'CM-EVD-UPLOAD-0042');
  assert.equal(intakeA.evidenceIntake.classification, 'participant_related_metadata_only');
  assert.equal(intakeA.evidenceIntake.readyForDocumentVersioning, true);
  assert.equal(intakeA.evidenceIntake.readyForCustodyChain, true);
  assert.equal(intakeA.evidenceIntake.payloadStoredOutsideReceipt, true);
  assert.equal(intakeA.evidenceIntake.operationalStateMutable, true);
  assert.equal(intakeA.evidenceIntake.immutableClassificationReceipt, true);
  assert.match(intakeA.evidenceIntake.initialCustodyDigest, /^[0-9a-f]{64}$/u);
  assert.equal(intakeA.evidenceIntake.initialCustodyDigest, intakeB.evidenceIntake.initialCustodyDigest);
  assert.equal(intakeA.receipt.receiptId, intakeB.receipt.receiptId);
  assert.equal(intakeA.receipt.actionHash, intakeB.receipt.actionHash);
  assert.equal(intakeA.receipt.anchorPayload.artifactType, 'evidence_intake_classification');
  assert.equal(intakeA.receipt.anchorPayload.custodyDigest, intakeA.evidenceIntake.initialCustodyDigest);
  assert.equal(intakeA.receipt.trustState, 'inactive');
  assert.equal(intakeA.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(intakeA), /source document body|participant alice|raw payload|clinical note/iu);
});

test('evidence intake fails closed for boundary classification review and version defects', async () => {
  const { evaluateEvidenceIntake } = await loadEvidenceIntake();

  const denied = evaluateEvidenceIntake({
    ...evidenceIntakeInput(),
    targetTenantId: 'tenant-site-beta',
    authority: { valid: true, revoked: true, expired: false, permissions: ['read'], authorityChainHash: DIGEST_D },
    evidence: {
      ...evidenceIntakeInput().evidence,
      artifactHash: null,
      artifactVersion: '',
      classification: 'direct_identifier_payload',
      consentOrBailmentRef: '',
    },
    intake: {
      ...evidenceIntakeInput().intake,
      payloadStoredOutsideReceipt: false,
    },
    review: {
      ...evidenceIntakeInput().review,
      reviewerKind: 'ai_agent',
      phiBoundaryAttested: false,
      metadataMinimized: false,
      versionAnchorApproved: false,
      custodyStartApproved: false,
      reviewedAtHlc: { physicalMs: 1790000000900, logical: 1 },
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('authority_chain_revoked'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('evidence_artifact_hash_invalid'));
  assert.ok(denied.reasons.includes('artifact_version_absent'));
  assert.ok(denied.reasons.includes('evidence_classification_invalid'));
  assert.ok(denied.reasons.includes('participant_consent_or_bailment_absent'));
  assert.ok(denied.reasons.includes('payload_storage_boundary_invalid'));
  assert.ok(denied.reasons.includes('human_classification_review_absent'));
  assert.ok(denied.reasons.includes('phi_boundary_unattested'));
  assert.ok(denied.reasons.includes('metadata_minimization_absent'));
  assert.ok(denied.reasons.includes('version_anchor_not_approved'));
  assert.ok(denied.reasons.includes('custody_start_not_approved'));
  assert.ok(denied.reasons.includes('review_time_not_after_upload'));
  assert.equal(denied.evidenceIntake, null);
  assert.equal(denied.receipt, null);
});

test('evidence intake records advisory AI review but denies AI final authority', async () => {
  const { evaluateEvidenceIntake } = await loadEvidenceIntake();

  const advisory = evaluateEvidenceIntake(evidenceIntakeInput());
  assert.equal(advisory.decision, 'permitted');
  assert.equal(advisory.evidenceIntake.aiAssistanceRecorded, true);
  assert.equal(advisory.evidenceIntake.aiFinalAuthority, false);

  const denied = evaluateEvidenceIntake({
    ...evidenceIntakeInput(),
    actor: { did: 'did:exo:ai-classifier', kind: 'ai_agent' },
    aiAssistance: {
      ...evidenceIntakeInput().aiAssistance,
      finalAuthority: true,
      disposition: 'finalized',
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('ai_advisory_disposition_invalid'));
});

test('evidence intake validates HLC ordering and rejects protected upload content', async () => {
  const { evaluateEvidenceIntake } = await loadEvidenceIntake();

  const sameTick = evaluateEvidenceIntake({
    ...evidenceIntakeInput(),
    intake: {
      ...evidenceIntakeInput().intake,
      uploadedAtHlc: { physicalMs: 1790000000900, logical: 1 },
    },
    review: {
      ...evidenceIntakeInput().review,
      reviewedAtHlc: { physicalMs: 1790000000900, logical: 2 },
    },
    recordedAtHlc: { physicalMs: 1790000000900, logical: 3 },
  });
  assert.equal(sameTick.decision, 'permitted');

  const malformed = evaluateEvidenceIntake({
    ...evidenceIntakeInput(),
    intake: { ...evidenceIntakeInput().intake, uploadedAtHlc: { physicalMs: 1790000000900, logical: -1 } },
    review: { ...evidenceIntakeInput().review, reviewedAtHlc: null },
    recordedAtHlc: null,
  });
  assert.equal(malformed.decision, 'denied');
  assert.ok(malformed.reasons.includes('upload_time_invalid'));
  assert.ok(malformed.reasons.includes('review_time_invalid'));
  assert.ok(malformed.reasons.includes('recorded_time_invalid'));

  assert.throws(
    () =>
      evaluateEvidenceIntake({
        ...evidenceIntakeInput(),
        sourceDocumentBody: 'Participant Alice Example source document body must not enter evidence intake.',
      }),
    /protected content/i,
  );
});

test('evidence intake handles absent AI assistance and malformed metadata lists as denial states', async () => {
  const { evaluateEvidenceIntake } = await loadEvidenceIntake();

  const denied = evaluateEvidenceIntake({
    ...evidenceIntakeInput(),
    evidence: {
      ...evidenceIntakeInput().evidence,
      evidenceRefIds: null,
      sensitivityTags: null,
    },
    aiAssistance: null,
    recordedAtHlc: { physicalMs: 1790000000900, logical: 1 },
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('evidence_refs_absent'));
  assert.ok(denied.reasons.includes('sensitivity_tags_absent'));
  assert.ok(denied.reasons.includes('metadata_only_tag_absent'));
  assert.ok(denied.reasons.includes('recorded_time_before_review'));
  assert.ok(!denied.reasons.includes('ai_recommendation_hash_invalid'));
});
