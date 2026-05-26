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

async function loadControlledDocumentDistribution() {
  try {
    return await import('../src/controlled-document-distribution.mjs');
  } catch (error) {
    assert.fail(`CyberMedica controlled document distribution module must exist and load: ${error.message}`);
  }
}

function distributionInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:document-control-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['write', 'document_distribute'],
      authorityChainHash: DIGEST_F,
    },
    documentVersion: {
      documentId: 'CM-QMS-SOP-001',
      documentVersionId: 'cmdv_site_alpha_sop_001_v3',
      documentType: 'standard_operating_procedure',
      versionId: 'v3',
      lifecycleState: 'approved',
      artifactHash: DIGEST_A,
      documentVersionReceiptId: 'cmr_document_version_v3',
      effectiveAtHlc: { physicalMs: 1797000000000, logical: 0 },
      reviewDueAtHlc: { physicalMs: 1804776000000, logical: 0 },
      retentionPolicyRef: 'retention-qms-controlled-documents',
      accessControlProfileRef: 'doc-access-site-alpha-sop',
      controlRefs: ['CTRL-DOC-001', 'CTRL-TRAIN-001'],
    },
    distribution: {
      distributionRef: 'dist-site-alpha-sop-001-v3',
      publishedByDid: 'did:exo:document-control-alpha',
      publishedAtHlc: { physicalMs: 1797000000000, logical: 1 },
      distributionEvidenceHash: DIGEST_B,
      releaseNotesHash: DIGEST_C,
      trainingImpactAssessmentHash: DIGEST_D,
      accessGrantPolicyHash: DIGEST_E,
      audienceRoleRefs: ['principal_investigator', 'quality_manager', 'study_coordinator'],
      requiredAcknowledgementRoleRefs: ['quality_manager', 'study_coordinator'],
      notificationEvidenceHash: DIGEST_1,
      staffCommunicationEvidenceHash: DIGEST_2,
      payloadStoredOutsideReceipt: true,
    },
    accessControl: {
      leastPrivilege: true,
      revocable: true,
      audited: true,
      timeBound: true,
      permittedActionRefs: ['read_current_version', 'acknowledge_effective_use'],
      deniedObsoleteVersionUse: true,
    },
    acknowledgements: [
      {
        staffDid: 'did:exo:study-coordinator-alpha',
        roleRef: 'study_coordinator',
        acknowledgedVersionId: 'v3',
        acknowledgedAtHlc: { physicalMs: 1797000000200, logical: 0 },
        acknowledgementEvidenceHash: DIGEST_3,
        trainingImpactReviewed: true,
        effectiveUseAttested: true,
      },
      {
        staffDid: 'did:exo:quality-manager-alpha',
        roleRef: 'quality_manager',
        acknowledgedVersionId: 'v3',
        acknowledgedAtHlc: { physicalMs: 1797000000100, logical: 0 },
        acknowledgementEvidenceHash: DIGEST_4,
        trainingImpactReviewed: true,
        effectiveUseAttested: true,
      },
    ],
    custodyDigest: DIGEST_2,
  };
}

function withdrawalInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:document-control-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['write', 'document_withdraw'],
      authorityChainHash: DIGEST_F,
    },
    obsoleteVersion: {
      documentId: 'CM-QMS-SOP-001',
      documentVersionId: 'cmdv_site_alpha_sop_001_v2',
      documentType: 'standard_operating_procedure',
      versionId: 'v2',
      lifecycleState: 'approved',
      artifactHash: DIGEST_A,
      documentVersionReceiptId: 'cmr_document_version_v2',
      effectiveAtHlc: { physicalMs: 1796000000000, logical: 0 },
      supersededByDocumentVersionId: 'cmdv_site_alpha_sop_001_v3',
      supersededByReceiptId: 'cmr_document_version_v3',
      retainedUnderPolicyRef: 'retention-qms-controlled-documents',
    },
    withdrawal: {
      withdrawalRef: 'withdraw-site-alpha-sop-001-v2',
      reasonCode: 'superseded_by_new_effective_version',
      withdrawnByDid: 'did:exo:document-control-alpha',
      withdrawnAtHlc: { physicalMs: 1797000000300, logical: 0 },
      withdrawalEvidenceHash: DIGEST_B,
      communicationEvidenceHash: DIGEST_C,
      activeCopyInventoryHash: DIGEST_D,
      accessRevocationEvidenceHash: DIGEST_E,
      affectedAudienceRoleRefs: ['quality_manager', 'study_coordinator'],
      removedAccessProfileRefs: ['doc-access-site-alpha-sop-v2'],
      noActiveUseAttested: true,
      retainedForInspection: true,
      exceptionCount: 0,
      exceptionRationaleHash: null,
    },
    custodyDigest: DIGEST_3,
  };
}

test('controlled document distribution records access controlled effective use acknowledgements', async () => {
  const { recordControlledDocumentDistribution } = await loadControlledDocumentDistribution();

  const resultA = recordControlledDocumentDistribution(distributionInput());
  const resultB = recordControlledDocumentDistribution({
    ...distributionInput(),
    documentVersion: {
      ...distributionInput().documentVersion,
      controlRefs: [...distributionInput().documentVersion.controlRefs].reverse(),
    },
    distribution: {
      ...distributionInput().distribution,
      audienceRoleRefs: [...distributionInput().distribution.audienceRoleRefs].reverse(),
      requiredAcknowledgementRoleRefs: [...distributionInput().distribution.requiredAcknowledgementRoleRefs].reverse(),
    },
    accessControl: {
      ...distributionInput().accessControl,
      permittedActionRefs: [...distributionInput().accessControl.permittedActionRefs].reverse(),
    },
    acknowledgements: [...distributionInput().acknowledgements].reverse(),
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.distributionRecord.status, 'distributed_for_effective_use');
  assert.equal(resultA.distributionRecord.effectiveForUse, true);
  assert.equal(resultA.distributionRecord.accessControlled, true);
  assert.equal(resultA.distributionRecord.obsoleteVersionUseBlocked, true);
  assert.deepEqual(resultA.distributionRecord.acknowledgedRoleRefs, ['quality_manager', 'study_coordinator']);
  assert.equal(resultA.distributionRecord.distributionRecordId, resultB.distributionRecord.distributionRecordId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'controlled_document_distribution');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(resultA), /Participant Alice|source document body|raw document|email|phone/iu);
});

test('controlled document distribution fails closed for unapproved access and acknowledgement defects', async () => {
  const { recordControlledDocumentDistribution } = await loadControlledDocumentDistribution();

  const denied = recordControlledDocumentDistribution({
    ...distributionInput(),
    targetTenantId: 'tenant-site-beta',
    actor: { did: 'did:exo:ai-document-bot', kind: 'ai_agent' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['write'],
      authorityChainHash: 'not-a-digest',
    },
    documentVersion: {
      ...distributionInput().documentVersion,
      lifecycleState: 'draft',
      documentVersionReceiptId: '',
      reviewDueAtHlc: null,
    },
    distribution: {
      ...distributionInput().distribution,
      publishedByDid: 'did:exo:other-human',
      publishedAtHlc: { physicalMs: 1796999999000, logical: 1 },
      distributionEvidenceHash: 'not-a-digest',
      requiredAcknowledgementRoleRefs: ['principal_investigator', 'quality_manager'],
      payloadStoredOutsideReceipt: false,
    },
    accessControl: {
      leastPrivilege: false,
      revocable: false,
      audited: false,
      timeBound: false,
      permittedActionRefs: ['read_current_version'],
      deniedObsoleteVersionUse: false,
    },
    acknowledgements: [
      {
        ...distributionInput().acknowledgements[0],
        acknowledgedVersionId: 'v2',
        acknowledgedAtHlc: { physicalMs: 1796999999000, logical: 0 },
        trainingImpactReviewed: false,
        effectiveUseAttested: false,
      },
    ],
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('document_version_not_approved'));
  assert.ok(denied.reasons.includes('document_version_receipt_absent'));
  assert.ok(denied.reasons.includes('distribution_time_before_effective_time'));
  assert.ok(denied.reasons.includes('publisher_actor_mismatch'));
  assert.ok(denied.reasons.includes('payload_storage_boundary_invalid'));
  assert.ok(denied.reasons.includes('least_privilege_not_attested'));
  assert.ok(denied.reasons.includes('obsolete_version_use_not_blocked'));
  assert.ok(denied.reasons.includes('required_acknowledgement_role_missing'));
  assert.ok(denied.reasons.includes('acknowledgement_version_mismatch'));
  assert.ok(denied.reasons.includes('acknowledgement_time_before_distribution'));
  assert.ok(denied.reasons.includes('training_impact_not_reviewed'));
  assert.ok(denied.reasons.includes('effective_use_not_attested'));
  assert.equal(denied.distributionRecord, null);
  assert.equal(denied.receipt, null);
});

test('obsolete controlled document withdrawal blocks effective use while preserving retention metadata', async () => {
  const { withdrawObsoleteDocumentVersion } = await loadControlledDocumentDistribution();

  const resultA = withdrawObsoleteDocumentVersion(withdrawalInput());
  const resultB = withdrawObsoleteDocumentVersion({
    ...withdrawalInput(),
    withdrawal: {
      ...withdrawalInput().withdrawal,
      affectedAudienceRoleRefs: [...withdrawalInput().withdrawal.affectedAudienceRoleRefs].reverse(),
      removedAccessProfileRefs: [...withdrawalInput().withdrawal.removedAccessProfileRefs].reverse(),
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.withdrawalRecord.status, 'obsolete_withdrawn');
  assert.equal(resultA.withdrawalRecord.effectiveForUse, false);
  assert.equal(resultA.withdrawalRecord.accessWithdrawn, true);
  assert.equal(resultA.withdrawalRecord.retentionPreserved, true);
  assert.equal(resultA.withdrawalRecord.noActiveUseAttested, true);
  assert.equal(resultA.withdrawalRecord.withdrawalRecordId, resultB.withdrawalRecord.withdrawalRecordId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'controlled_document_withdrawal');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.exochainProductionClaim, false);
});

test('obsolete controlled document withdrawal fails closed for broken supersession and active copies', async () => {
  const { withdrawObsoleteDocumentVersion } = await loadControlledDocumentDistribution();

  const denied = withdrawObsoleteDocumentVersion({
    ...withdrawalInput(),
    targetTenantId: 'tenant-site-beta',
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['write'],
      authorityChainHash: DIGEST_F,
    },
    obsoleteVersion: {
      ...withdrawalInput().obsoleteVersion,
      supersededByDocumentVersionId: '',
      supersededByReceiptId: '',
      retainedUnderPolicyRef: '',
    },
    withdrawal: {
      ...withdrawalInput().withdrawal,
      withdrawnByDid: 'did:exo:other-human',
      withdrawnAtHlc: { physicalMs: 1795000000000, logical: 0 },
      withdrawalEvidenceHash: 'not-a-digest',
      communicationEvidenceHash: null,
      activeCopyInventoryHash: null,
      accessRevocationEvidenceHash: null,
      affectedAudienceRoleRefs: [],
      removedAccessProfileRefs: [],
      noActiveUseAttested: false,
      retainedForInspection: false,
      exceptionCount: 2,
      exceptionRationaleHash: null,
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('superseding_document_version_absent'));
  assert.ok(denied.reasons.includes('superseding_receipt_absent'));
  assert.ok(denied.reasons.includes('retention_policy_absent'));
  assert.ok(denied.reasons.includes('withdrawn_by_actor_mismatch'));
  assert.ok(denied.reasons.includes('withdrawal_time_before_obsolete_effective_time'));
  assert.ok(denied.reasons.includes('withdrawal_evidence_hash_invalid'));
  assert.ok(denied.reasons.includes('communication_evidence_hash_invalid'));
  assert.ok(denied.reasons.includes('active_copy_inventory_hash_invalid'));
  assert.ok(denied.reasons.includes('access_revocation_evidence_hash_invalid'));
  assert.ok(denied.reasons.includes('affected_audience_absent'));
  assert.ok(denied.reasons.includes('removed_access_profile_absent'));
  assert.ok(denied.reasons.includes('active_use_attestation_absent'));
  assert.ok(denied.reasons.includes('retention_preservation_absent'));
  assert.ok(denied.reasons.includes('withdrawal_exception_rationale_absent'));
  assert.equal(denied.withdrawalRecord, null);
  assert.equal(denied.receipt, null);
});

test('controlled document distribution handles same tick HLC ordering and rejects raw document content', async () => {
  const { recordControlledDocumentDistribution, withdrawObsoleteDocumentVersion } =
    await loadControlledDocumentDistribution();

  const sameTickDistribution = recordControlledDocumentDistribution({
    ...distributionInput(),
    distribution: {
      ...distributionInput().distribution,
      publishedAtHlc: { physicalMs: 1797000000000, logical: 0 },
    },
    acknowledgements: distributionInput().acknowledgements.map((acknowledgement, index) => ({
      ...acknowledgement,
      acknowledgedAtHlc: { physicalMs: 1797000000000, logical: index + 1 },
    })),
  });

  assert.equal(sameTickDistribution.decision, 'permitted');
  assert.equal(sameTickDistribution.distributionRecord.effectiveForUse, true);

  assert.throws(
    () =>
      recordControlledDocumentDistribution({
        ...distributionInput(),
        rawDocumentBody: 'Source document body for a controlled SOP should never be anchored.',
      }),
    /protected content/i,
  );

  assert.throws(
    () =>
      withdrawObsoleteDocumentVersion({
        ...withdrawalInput(),
        controlledDocumentText: 'Participant Alice raw controlled document content.',
      }),
    /protected content/i,
  );
});
