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

async function loadQmsControlApprovals() {
  try {
    return await import('../src/qms-control-approvals.mjs');
  } catch (error) {
    assert.fail(`CyberMedica QMS control approval module must exist and load: ${error.message}`);
  }
}

function governedControlApprovalInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['govern'] },
    control: {
      controlId: 'CM-QMS-CONSENT-001',
      versionId: 'v1',
      title: 'Informed consent artifact version control',
      objective: 'Ensure consent artifacts are approved, current, revocable, and metadata-only.',
      ownerRole: 'quality_manager',
      riskCriticality: 'critical',
      lifecycleAction: 'approve',
      affectedWorkflowRefs: ['participant_consent_grant', 'enrollment_gate'],
      policyRefs: ['CONSENT-001', 'PRIV-001'],
    },
    evidenceRefs: [
      {
        evidenceId: 'evidence-consent-policy-approval',
        artifactType: 'policy_approval',
        artifactVersion: 'v1',
        artifactHash: DIGEST_A,
        custodyDigest: DIGEST_B,
        classification: 'confidential_metadata_only',
      },
      {
        evidenceId: 'evidence-privacy-boundary-attestation',
        artifactType: 'privacy_boundary_attestation',
        artifactVersion: 'v1',
        artifactHash: DIGEST_C,
        custodyDigest: DIGEST_D,
        classification: 'confidential_metadata_only',
      },
    ],
    decisionForum: {
      verified: true,
      state: 'approved',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
      decisionId: 'df-qms-control-approval-001',
      workflowReceiptId: 'df-workflow-receipt-001',
    },
    evidenceBundle: { complete: true, phiBoundaryAttested: true },
    approvedAtHlc: { physicalMs: 1790000000800, logical: 5 },
    custodyDigest: DIGEST_B,
  };
}

test('QMS control approvals require human governance and create deterministic inactive metadata receipts', async () => {
  const { evaluateQmsControlApproval } = await loadQmsControlApprovals();

  const approvalA = evaluateQmsControlApproval(governedControlApprovalInput());
  const approvalB = evaluateQmsControlApproval({
    ...governedControlApprovalInput(),
    evidenceRefs: [...governedControlApprovalInput().evidenceRefs].reverse(),
    control: {
      ...governedControlApprovalInput().control,
      affectedWorkflowRefs: [...governedControlApprovalInput().control.affectedWorkflowRefs].reverse(),
      policyRefs: [...governedControlApprovalInput().control.policyRefs].reverse(),
    },
  });

  assert.equal(approvalA.decision, 'permitted');
  assert.equal(approvalA.failClosed, false);
  assert.equal(approvalA.controlApproval.status, 'approved');
  assert.equal(approvalA.controlApproval.humanGovernanceRequired, true);
  assert.equal(approvalA.controlApproval.operationalStateMutable, true);
  assert.equal(approvalA.controlApproval.immutableApprovalReceipt, true);
  assert.equal(approvalA.controlApproval.effectiveForUse, true);
  assert.deepEqual(approvalA.controlApproval.evidenceRefs, [
    'evidence-consent-policy-approval',
    'evidence-privacy-boundary-attestation',
  ]);
  assert.equal(approvalA.controlApproval.controlApprovalId, approvalB.controlApproval.controlApprovalId);
  assert.equal(approvalA.receipt.receiptId, approvalB.receipt.receiptId);
  assert.equal(approvalA.receipt.actionHash, approvalB.receipt.actionHash);
  assert.equal(approvalA.receipt.trustState, 'inactive');
  assert.equal(approvalA.receipt.exochainProductionClaim, false);
  assert.equal(approvalA.receipt.anchorPayload.artifactType, 'qms_control_approval');
  assert.doesNotMatch(JSON.stringify(approvalA.receipt), /source document|participant alice|patient/iu);
});

test('QMS control approval fails closed for tenant authority governance and evidence defects', async () => {
  const { evaluateQmsControlApproval } = await loadQmsControlApprovals();

  const denied = evaluateQmsControlApproval({
    ...governedControlApprovalInput(),
    targetTenantId: 'tenant-site-beta',
    actor: { did: 'did:exo:ai-quality-reviewer-alpha', kind: 'ai_agent' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['write'] },
    evidenceRefs: [
      {
        evidenceId: '',
        artifactType: '',
        artifactVersion: '',
        artifactHash: 'not-a-digest',
        custodyDigest: '0000000000000000000000000000000000000000000000000000000000000000',
        classification: '',
      },
    ],
    decisionForum: {
      verified: true,
      state: 'approved',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: true,
    },
    evidenceBundle: { complete: false, phiBoundaryAttested: false },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('challenge_open'));
  assert.ok(denied.reasons.includes('evidence_bundle_incomplete'));
  assert.ok(denied.reasons.includes('phi_boundary_unattested'));
  assert.ok(denied.reasons.includes('control_evidence_id_absent'));
  assert.ok(denied.reasons.includes('control_evidence_artifact_hash_invalid'));
  assert.ok(denied.reasons.includes('control_evidence_custody_digest_invalid'));
  assert.equal(denied.controlApproval, null);
  assert.equal(denied.receipt, null);
  assert.equal(denied.exochainProductionClaim, false);
});

test('QMS control approval fails closed when control metadata and evidence refs are absent', async () => {
  const { evaluateQmsControlApproval } = await loadQmsControlApprovals();

  const denied = evaluateQmsControlApproval({
    ...governedControlApprovalInput(),
    control: {
      controlId: '',
      versionId: '',
      title: '',
      objective: '',
      ownerRole: '',
      riskCriticality: 'unknown',
      lifecycleAction: 'publish',
      affectedWorkflowRefs: [],
      policyRefs: [],
    },
    evidenceRefs: [],
    decisionForum: {
      verified: true,
      state: 'approved',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
      decisionId: '',
      workflowReceiptId: '',
    },
    approvedAtHlc: { physicalMs: null, logical: 0 },
    custodyDigest: 'not-a-digest',
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('control_evidence_refs_absent'));
  assert.ok(denied.reasons.includes('control_id_absent'));
  assert.ok(denied.reasons.includes('control_version_id_absent'));
  assert.ok(denied.reasons.includes('control_title_absent'));
  assert.ok(denied.reasons.includes('control_objective_absent'));
  assert.ok(denied.reasons.includes('control_owner_role_absent'));
  assert.ok(denied.reasons.includes('control_risk_criticality_invalid'));
  assert.ok(denied.reasons.includes('control_lifecycle_action_invalid'));
  assert.ok(denied.reasons.includes('control_affected_workflow_refs_absent'));
  assert.ok(denied.reasons.includes('control_policy_refs_absent'));
  assert.ok(denied.reasons.includes('control_approval_time_invalid'));
  assert.ok(denied.reasons.includes('custody_digest_invalid'));
  assert.ok(denied.reasons.includes('decision_forum_decision_id_absent'));
  assert.ok(denied.reasons.includes('decision_forum_workflow_receipt_absent'));
  assert.equal(denied.receipt, null);
});

test('QMS control approval handles missing object branches as denial states', async () => {
  const { evaluateQmsControlApproval } = await loadQmsControlApprovals();

  const denied = evaluateQmsControlApproval({
    tenantId: '',
    targetTenantId: 'tenant-site-alpha',
    actor: null,
    authority: null,
    control: null,
    evidenceRefs: [null],
    decisionForum: null,
    evidenceBundle: null,
    approvedAtHlc: null,
    custodyDigest: null,
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_absent'));
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('actor_did_absent'));
  assert.ok(denied.reasons.includes('authority_chain_invalid'));
  assert.ok(denied.reasons.includes('decision_forum_unverified'));
  assert.ok(denied.reasons.includes('control_id_absent'));
  assert.ok(denied.reasons.includes('control_evidence_id_absent'));
  assert.ok(denied.reasons.includes('control_evidence_type_absent'));
  assert.equal(denied.controlApproval, null);
  assert.equal(denied.receipt, null);
});

test('QMS control retirement is governed and disables effective use without production trust claims', async () => {
  const { evaluateQmsControlApproval } = await loadQmsControlApprovals();

  const retirement = evaluateQmsControlApproval({
    ...governedControlApprovalInput(),
    control: {
      ...governedControlApprovalInput().control,
      controlId: 'CM-QMS-LEGACY-001',
      versionId: 'v4',
      title: 'Legacy checklist retirement control',
      objective: 'Retire obsolete checklist evidence while preserving receipt lineage.',
      lifecycleAction: 'retire',
      affectedWorkflowRefs: ['document_version_registration'],
      policyRefs: ['DOC-001'],
    },
    decisionForum: {
      ...governedControlApprovalInput().decisionForum,
      decisionId: 'df-qms-control-retirement-001',
      workflowReceiptId: 'df-workflow-retirement-receipt-001',
    },
  });

  assert.equal(retirement.decision, 'permitted');
  assert.equal(retirement.controlApproval.status, 'retired');
  assert.equal(retirement.controlApproval.effectiveForUse, false);
  assert.equal(retirement.controlApproval.lifecycleAction, 'retire');
  assert.equal(retirement.receipt.anchorPayload.artifactVersion, 'CM-QMS-LEGACY-001@v4:retire');
  assert.equal(retirement.receipt.trustState, 'inactive');
  assert.equal(retirement.exochainProductionClaim, false);
});

test('QMS control approval rejects protected source content before creating receipts', async () => {
  const { evaluateQmsControlApproval } = await loadQmsControlApprovals();

  assert.throws(
    () =>
      evaluateQmsControlApproval({
        ...governedControlApprovalInput(),
        evidenceRefs: [
          {
            ...governedControlApprovalInput().evidenceRefs[0],
            sourceDocumentBody: 'Participant Alice Example consent form body must never be anchored.',
          },
        ],
      }),
    /protected content/i,
  );
});
