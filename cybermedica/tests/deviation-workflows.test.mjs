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

async function loadDeviationWorkflows() {
  try {
    return await import('../src/deviation-workflows.mjs');
  } catch (error) {
    assert.fail(`CyberMedica deviation workflow module must exist and load: ${error.message}`);
  }
}

function criticalDeviationInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:crc-alpha', kind: 'human' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['write'] },
    deviation: {
      deviationRef: 'DEV-2026-0009',
      studyRef: 'study-cm-001',
      protocolRef: 'protocol-cm-001',
      siteRef: 'site-alpha',
      discoveredAtHlc: { physicalMs: 1790000000100, logical: 4 },
      discovererDid: 'did:exo:crc-alpha',
      discoveryMethod: 'source_review',
      descriptionHash: DIGEST_A,
      classification: 'unplanned',
      protocolSectionRef: 'protocol-section-eligibility-2',
      participantRisk: 'critical',
      consentImpact: 'elevated',
      dataIntegrityImpact: 'high',
      randomizationImpact: 'none',
      blindingImpact: 'none',
      aeSaeLinkage: { status: 'linked', eventRef: 'SAFETY-EVENT-2026-0004', eventHash: DIGEST_B },
      ownerDid: 'did:exo:quality-manager-alpha',
      dueHlc: { physicalMs: 1790086400100, logical: 0 },
      status: 'investigation_open',
      policyRefs: ['deviation-management-policy-v1', 'participant-safety-reporting-v1'],
    },
    immediateAction: {
      required: true,
      status: 'completed',
      actionEvidenceHash: DIGEST_B,
      completedAtHlc: { physicalMs: 1790000000200, logical: 1 },
      ownerDid: 'did:exo:principal-investigator-alpha',
    },
    reporting: {
      sponsor: { required: true, status: 'submitted', evidenceHash: DIGEST_C },
      irb: { required: true, status: 'submitted', evidenceHash: DIGEST_D },
      regulatory: { required: false, status: 'not_required', rationaleHash: DIGEST_E },
    },
    rootCause: { status: 'pending', category: 'process_control', evidenceHash: null },
    correctiveAction: { status: 'planned', planHash: DIGEST_C },
    preventiveAction: { status: 'planned', planHash: DIGEST_D },
    capaLinkage: { required: true, capaRef: 'CAPA-2026-0017', receiptId: 'cmr-capa-intake-0017' },
    verification: { evidenceHashes: [], custodyDigest: null },
    effectivenessCheck: { status: 'not_ready' },
    decisionForum: {
      linkageRequired: true,
      decisionId: 'df-deviation-escalation-0009',
      workflowReceiptId: 'df-workflow-receipt-deviation-0009',
      verified: true,
      state: 'approved',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
    },
    custodyDigest: DIGEST_E,
  };
}

test('deviation workflow creates deterministic inactive escalation records for critical unplanned deviations', async () => {
  const { evaluateDeviationWorkflow } = await loadDeviationWorkflows();

  const recordA = evaluateDeviationWorkflow(criticalDeviationInput());
  const recordB = evaluateDeviationWorkflow({
    ...criticalDeviationInput(),
    deviation: {
      ...criticalDeviationInput().deviation,
      policyRefs: [...criticalDeviationInput().deviation.policyRefs].reverse(),
    },
    reporting: {
      regulatory: criticalDeviationInput().reporting.regulatory,
      irb: criticalDeviationInput().reporting.irb,
      sponsor: criticalDeviationInput().reporting.sponsor,
    },
  });

  assert.equal(recordA.decision, 'permitted');
  assert.equal(recordA.failClosed, false);
  assert.equal(recordA.deviation.immediateEscalationRequired, true);
  assert.equal(recordA.deviation.escalationStatus, 'required_ready');
  assert.equal(recordA.deviation.capaRequired, true);
  assert.equal(recordA.deviation.closureStatus, 'open');
  assert.equal(recordA.deviation.aiFinalAuthority, false);
  assert.equal(recordA.deviation.exochainProductionClaim, false);
  assert.deepEqual(recordA.deviation.requiredEscalationRoles, [
    'data_integrity_officer',
    'decision_forum',
    'principal_investigator',
    'site_quality_lead',
  ]);
  assert.equal(recordA.deviation.deviationId, recordB.deviation.deviationId);
  assert.equal(recordA.receipt.receiptId, recordB.receipt.receiptId);
  assert.equal(recordA.receipt.actionHash, recordB.receipt.actionHash);
  assert.equal(recordA.receipt.trustState, 'inactive');
  assert.equal(recordA.receipt.anchorPayload.artifactType, 'deviation_record');
  assert.doesNotMatch(JSON.stringify(recordA), /Participant Alice|source document|medical record|raw narrative/iu);
});

test('planned low-risk deviation can remain open without Decision Forum or CAPA linkage', async () => {
  const { evaluateDeviationWorkflow } = await loadDeviationWorkflows();

  const result = evaluateDeviationWorkflow({
    ...criticalDeviationInput(),
    deviation: {
      ...criticalDeviationInput().deviation,
      deviationRef: 'DEV-2026-0010',
      classification: 'planned',
      participantRisk: 'minor',
      consentImpact: 'none',
      dataIntegrityImpact: 'none',
      protocolSectionRef: 'protocol-section-visit-window',
      randomizationImpact: 'none',
      blindingImpact: 'none',
      aeSaeLinkage: { status: 'not_applicable' },
      status: 'investigation_open',
    },
    immediateAction: { required: false, status: 'not_required', rationaleHash: DIGEST_B },
    reporting: {
      sponsor: { required: false, status: 'not_required', rationaleHash: DIGEST_C },
      irb: { required: false, status: 'not_required', rationaleHash: DIGEST_D },
      regulatory: { required: false, status: 'not_required', rationaleHash: DIGEST_E },
    },
    capaLinkage: { required: false },
    decisionForum: null,
  });

  assert.equal(result.decision, 'permitted');
  assert.equal(result.deviation.immediateEscalationRequired, false);
  assert.equal(result.deviation.escalationStatus, 'not_required');
  assert.equal(result.deviation.capaRequired, false);
  assert.equal(result.deviation.closureStatus, 'open');
  assert.deepEqual(result.deviation.requiredEscalationRoles, ['site_quality_lead']);
});

test('deviation closure requires human governance CAPA linkage verification evidence and effectiveness state', async () => {
  const { evaluateDeviationWorkflow } = await loadDeviationWorkflows();

  const result = evaluateDeviationWorkflow({
    ...criticalDeviationInput(),
    deviation: {
      ...criticalDeviationInput().deviation,
      status: 'closure_ready',
    },
    rootCause: { status: 'complete', category: 'process_control', evidenceHash: DIGEST_A },
    correctiveAction: { status: 'implemented', planHash: DIGEST_C, implementationEvidenceHash: DIGEST_D },
    preventiveAction: { status: 'implemented', planHash: DIGEST_D, implementationEvidenceHash: DIGEST_E },
    verification: { evidenceHashes: [DIGEST_A, DIGEST_B], custodyDigest: DIGEST_E },
    effectivenessCheck: {
      status: 'met',
      criteriaHash: DIGEST_C,
      checkedAtHlc: { physicalMs: 1790172800100, logical: 2 },
    },
    closureDecisionForum: {
      verified: true,
      state: 'approved',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
      decisionId: 'df-deviation-closure-0009',
      workflowReceiptId: 'df-workflow-receipt-deviation-closure-0009',
    },
  });

  assert.equal(result.decision, 'permitted');
  assert.equal(result.deviation.closureStatus, 'closed');
  assert.equal(result.deviation.effectivenessFinal, true);
  assert.equal(result.closureReceipt.anchorPayload.artifactType, 'deviation_closure');
  assert.equal(result.closureReceipt.trustState, 'inactive');
  assert.equal(result.closureReceipt.exochainProductionClaim, false);
});

test('deviation closure can record scheduled effectiveness follow-up without final effectiveness', async () => {
  const { evaluateDeviationWorkflow } = await loadDeviationWorkflows();

  const result = evaluateDeviationWorkflow({
    ...criticalDeviationInput(),
    deviation: {
      ...criticalDeviationInput().deviation,
      status: 'closure_ready',
    },
    rootCause: { status: 'complete', category: 'process_control', evidenceHash: DIGEST_A },
    correctiveAction: { status: 'implemented', planHash: DIGEST_C, implementationEvidenceHash: DIGEST_D },
    preventiveAction: { status: 'implemented', planHash: DIGEST_D, implementationEvidenceHash: DIGEST_E },
    verification: { evidenceHashes: [DIGEST_A, DIGEST_B], custodyDigest: DIGEST_E },
    effectivenessCheck: {
      status: 'follow_up_scheduled',
      criteriaHash: DIGEST_C,
      rationaleHash: DIGEST_D,
      followUpHlc: { physicalMs: 1790259200100, logical: 0 },
    },
    closureDecisionForum: {
      verified: true,
      state: 'approved',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
      decisionId: 'df-deviation-closure-0009',
      workflowReceiptId: 'df-workflow-receipt-deviation-closure-0009',
    },
  });

  assert.equal(result.decision, 'permitted');
  assert.equal(result.deviation.closureStatus, 'closed_with_effectiveness_followup');
  assert.equal(result.deviation.effectivenessFinal, false);
  assert.equal(result.deviation.followUpRequired, true);
  assert.equal(result.closureReceipt.anchorPayload.artifactType, 'deviation_closure');
});

test('open investigation reports completed root-cause and action evidence defects before closure', async () => {
  const { evaluateDeviationWorkflow } = await loadDeviationWorkflows();

  const denied = evaluateDeviationWorkflow({
    ...criticalDeviationInput(),
    rootCause: { status: 'complete', category: '', evidenceHash: 'bad' },
    correctiveAction: { status: 'implemented', planHash: 'bad', implementationEvidenceHash: '' },
    preventiveAction: { status: 'implemented', planHash: '', implementationEvidenceHash: 'bad' },
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('root_cause_category_absent'));
  assert.ok(denied.reasons.includes('root_cause_evidence_invalid'));
  assert.ok(denied.reasons.includes('corrective_action_plan_invalid'));
  assert.ok(denied.reasons.includes('corrective_action_evidence_invalid'));
  assert.ok(denied.reasons.includes('preventive_action_plan_invalid'));
  assert.ok(denied.reasons.includes('preventive_action_evidence_invalid'));
});

test('deviation escalation routes consent and sponsor reviewers for consent randomization and blinding impact', async () => {
  const { evaluateDeviationWorkflow } = await loadDeviationWorkflows();

  const result = evaluateDeviationWorkflow({
    ...criticalDeviationInput(),
    deviation: {
      ...criticalDeviationInput().deviation,
      participantRisk: 'none',
      consentImpact: 'critical',
      dataIntegrityImpact: 'none',
      randomizationImpact: 'high',
      blindingImpact: 'critical',
      aeSaeLinkage: { status: 'not_applicable' },
    },
    immediateAction: { required: false, status: 'not_required', rationaleHash: DIGEST_B },
    reporting: {
      sponsor: { required: false, status: 'not_required', rationaleHash: DIGEST_C },
      irb: { required: false, status: 'not_required', rationaleHash: DIGEST_D },
      regulatory: { required: false, status: 'not_required', rationaleHash: DIGEST_E },
    },
    capaLinkage: { required: true, capaRef: 'CAPA-2026-0018', receiptId: 'cmr-capa-intake-0018' },
  });

  assert.equal(result.decision, 'permitted');
  assert.deepEqual(result.deviation.requiredEscalationRoles, [
    'consent_authority_reviewer',
    'decision_forum',
    'site_quality_lead',
    'sponsor_quality_reviewer',
  ]);
});

test('deviation workflow fails closed for missing reporting decisions and due dates before discovery', async () => {
  const { evaluateDeviationWorkflow } = await loadDeviationWorkflows();

  const denied = evaluateDeviationWorkflow({
    ...criticalDeviationInput(),
    deviation: {
      ...criticalDeviationInput().deviation,
      dueHlc: { physicalMs: 1789999990000, logical: 0 },
    },
    reporting: {
      sponsor: { status: 'submitted', evidenceHash: DIGEST_C },
      irb: { required: false, status: 'not_required', rationaleHash: DIGEST_D },
      regulatory: { required: false, status: 'not_required', rationaleHash: DIGEST_E },
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('required_reporting_incomplete'));
  assert.ok(denied.reasons.includes('due_time_precedes_discovery'));
});

test('deviation workflow fails closed for authority reporting escalation and closure defects', async () => {
  const { evaluateDeviationWorkflow } = await loadDeviationWorkflows();

  const denied = evaluateDeviationWorkflow({
    ...criticalDeviationInput(),
    targetTenantId: 'tenant-site-beta',
    actor: { did: 'did:exo:ai-reviewer-alpha', kind: 'ai_agent' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['read'] },
    deviation: {
      ...criticalDeviationInput().deviation,
      deviationRef: '',
      descriptionHash: 'not-a-digest',
      participantRisk: 'severe',
      consentImpact: 'critical',
      dataIntegrityImpact: 'high',
      status: 'closure_ready',
    },
    immediateAction: { required: true, status: 'pending' },
    reporting: {
      sponsor: { required: true, status: 'pending' },
      irb: { required: true, status: 'submitted', evidenceHash: 'bad' },
      regulatory: { required: true, status: 'not_required', rationaleHash: '' },
    },
    rootCause: { status: 'pending', category: '', evidenceHash: null },
    correctiveAction: { status: 'planned', planHash: DIGEST_C },
    preventiveAction: { status: 'planned', planHash: DIGEST_D },
    capaLinkage: { required: true, capaRef: '', receiptId: '' },
    verification: { evidenceHashes: [], custodyDigest: 'bad' },
    effectivenessCheck: { status: 'not_ready' },
    decisionForum: null,
    closureDecisionForum: { verified: false, state: 'draft', humanGate: { verified: false }, quorum: { status: 'missing' } },
    custodyDigest: '0000000000000000000000000000000000000000000000000000000000000000',
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.deviation, null);
  assert.equal(denied.receipt, null);
  assert.equal(denied.closureReceipt, null);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('deviation_ref_absent'));
  assert.ok(denied.reasons.includes('deviation_description_hash_invalid'));
  assert.ok(denied.reasons.includes('deviation_impact_invalid'));
  assert.ok(denied.reasons.includes('immediate_action_evidence_absent'));
  assert.ok(denied.reasons.includes('required_reporting_incomplete'));
  assert.ok(denied.reasons.includes('critical_escalation_route_absent'));
  assert.ok(denied.reasons.includes('root_cause_incomplete'));
  assert.ok(denied.reasons.includes('capa_linkage_absent'));
  assert.ok(denied.reasons.includes('closure_decision_forum_unverified'));
  assert.ok(denied.reasons.includes('verification_evidence_absent'));
  assert.ok(denied.reasons.includes('effectiveness_not_established'));
  assert.ok(denied.reasons.includes('custody_digest_invalid'));
});

test('deviation workflow rejects raw narratives and protected source content before receipt creation', async () => {
  const { evaluateDeviationWorkflow } = await loadDeviationWorkflows();

  assert.throws(
    () =>
      evaluateDeviationWorkflow({
        ...criticalDeviationInput(),
        deviation: {
          ...criticalDeviationInput().deviation,
          description: 'Participant Alice Example source document body must remain outside receipts.',
        },
      }),
    /protected content|raw narrative/iu,
  );
});
