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

async function loadConcernReporting() {
  try {
    return await import('../src/concern-reporting.mjs');
  } catch (error) {
    assert.fail(`CyberMedica concern reporting module must exist and load: ${error.message}`);
  }
}

function criticalConcernInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-coordinator-alpha', kind: 'human' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['write'] },
    reporter: {
      anonymous: false,
      reporterDid: 'did:exo:crc-alpha',
      notificationPermitted: true,
      intakeChannel: 'staff_quality_portal',
    },
    concern: {
      concernRef: 'CONCERN-2026-0007',
      concernType: 'participant_safety',
      siteRef: 'site-alpha',
      protocolRef: 'protocol-cm-001',
      descriptionHash: DIGEST_A,
      classification: 'confidential_metadata_only',
      participantSafetyImpact: 'critical',
      ethicalImpact: 'moderate',
      dataIntegrityImpact: 'none',
      consentImpact: 'none',
      productHandlingImpact: 'none',
      unauthorizedAccessImpact: 'none',
      retaliationRisk: 'elevated',
      policyRefs: ['ethics-framework-v1', 'concern-reporting-policy-v1'],
    },
    evidenceRefs: [
      {
        artifactType: 'site_quality_note',
        artifactHash: DIGEST_A,
        custodyDigest: DIGEST_B,
        receiptId: 'cmr-site-quality-note-0007',
        classification: 'confidential_metadata_only',
      },
      {
        artifactType: 'training_matrix_exception',
        artifactHash: DIGEST_C,
        custodyDigest: DIGEST_B,
        receiptId: 'cmr-training-exception-0007',
        classification: 'confidential_metadata_only',
      },
    ],
    assignedInvestigator: {
      did: 'did:exo:quality-investigator-alpha',
      kind: 'human',
      role: 'independent_quality_investigator',
    },
    decisionForum: {
      linkageRequired: true,
      decisionId: 'df-concern-escalation-0007',
      workflowReceiptId: 'df-workflow-receipt-concern-0007',
    },
    reportedAtHlc: { physicalMs: 1790000000200, logical: 9 },
    custodyDigest: DIGEST_B,
  };
}

test('concern reporting creates deterministic inactive receipts and immediate escalation metadata', async () => {
  const { evaluateConcernReport } = await loadConcernReporting();

  const reportA = evaluateConcernReport(criticalConcernInput());
  const reportB = evaluateConcernReport({
    ...criticalConcernInput(),
    evidenceRefs: [...criticalConcernInput().evidenceRefs].reverse(),
    concern: {
      ...criticalConcernInput().concern,
      policyRefs: [...criticalConcernInput().concern.policyRefs].reverse(),
    },
  });

  assert.equal(reportA.decision, 'permitted');
  assert.equal(reportA.failClosed, false);
  assert.equal(reportA.concern.immediateEscalationRequired, true);
  assert.equal(reportA.concern.investigationStatus, 'assigned');
  assert.equal(reportA.concern.closureDecision, 'open');
  assert.equal(reportA.concern.aiFinalAuthority, false);
  assert.equal(reportA.concern.exochainProductionClaim, false);
  assert.deepEqual(reportA.concern.requiredEscalationRoles, [
    'decision_forum',
    'ethics_governance_reviewer',
    'principal_investigator',
    'site_quality_lead',
  ]);
  assert.equal(reportA.concern.concernId, reportB.concern.concernId);
  assert.equal(reportA.receipt.receiptId, reportB.receipt.receiptId);
  assert.equal(reportA.receipt.actionHash, reportB.receipt.actionHash);
  assert.equal(reportA.receipt.trustState, 'inactive');
  assert.equal(reportA.receipt.exochainProductionClaim, false);
  assert.equal(reportA.receipt.anchorPayload.artifactType, 'concern_report');
  assert.doesNotMatch(JSON.stringify(reportA), /Participant Alice|source document|medical record|raw narrative/iu);
});

test('non-critical anonymous concern intake stays open without Decision Forum escalation claim', async () => {
  const { evaluateConcernReport } = await loadConcernReporting();

  const result = evaluateConcernReport({
    ...criticalConcernInput(),
    reporter: {
      anonymous: true,
      notificationPermitted: false,
      intakeChannel: 'anonymous_hotline',
    },
    concern: {
      ...criticalConcernInput().concern,
      concernType: 'quality_system',
      participantSafetyImpact: 'none',
      ethicalImpact: 'minor',
      retaliationRisk: 'none',
    },
    decisionForum: null,
  });

  assert.equal(result.decision, 'permitted');
  assert.equal(result.concern.reporter.anonymous, true);
  assert.equal(result.concern.reporter.reporterDid, null);
  assert.equal(result.concern.immediateEscalationRequired, false);
  assert.equal(result.concern.escalationStatus, 'not_required');
  assert.deepEqual(result.concern.requiredEscalationRoles, ['ethics_governance_reviewer', 'site_quality_lead']);
  assert.equal(result.receipt.anchorPayload.artifactType, 'concern_report');
});

test('critical multi-domain concerns route data consent product security and ethics owners', async () => {
  const { evaluateConcernReport } = await loadConcernReporting();

  const result = evaluateConcernReport({
    ...criticalConcernInput(),
    concern: {
      ...criticalConcernInput().concern,
      concernType: 'unauthorized_access',
      participantSafetyImpact: 'none',
      ethicalImpact: 'none',
      dataIntegrityImpact: 'high',
      consentImpact: 'critical',
      productHandlingImpact: 'high',
      unauthorizedAccessImpact: 'critical',
      retaliationRisk: 'critical',
    },
  });

  assert.equal(result.decision, 'permitted');
  assert.equal(result.concern.immediateEscalationRequired, true);
  assert.deepEqual(result.concern.requiredEscalationRoles, [
    'consent_authority_reviewer',
    'data_integrity_officer',
    'decision_forum',
    'ethics_governance_reviewer',
    'product_accountable_person',
    'security_privacy_officer',
    'site_quality_lead',
  ]);
});

test('concern reporting fails closed for authority reporter investigator evidence and escalation defects', async () => {
  const { evaluateConcernReport } = await loadConcernReporting();

  const denied = evaluateConcernReport({
    ...criticalConcernInput(),
    targetTenantId: 'tenant-site-beta',
    authority: { valid: true, revoked: false, expired: false, permissions: ['read'] },
    reporter: {
      anonymous: false,
      reporterDid: '',
      notificationPermitted: true,
      intakeChannel: '',
    },
    concern: {
      ...criticalConcernInput().concern,
      concernRef: '',
      concernType: 'rumor',
      descriptionHash: 'not-a-digest',
      participantSafetyImpact: 'critical',
      ethicalImpact: 'severe',
    },
    evidenceRefs: [
      {
        artifactType: '',
        artifactHash: 'bad',
        custodyDigest: DIGEST_B,
        receiptId: '',
        classification: '',
      },
    ],
    assignedInvestigator: { did: 'did:exo:ai-investigator-alpha', kind: 'ai_agent', role: '' },
    decisionForum: null,
    reportedAtHlc: null,
    custodyDigest: '0000000000000000000000000000000000000000000000000000000000000000',
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('reporter_did_absent'));
  assert.ok(denied.reasons.includes('reporter_intake_channel_absent'));
  assert.ok(denied.reasons.includes('concern_ref_absent'));
  assert.ok(denied.reasons.includes('concern_type_invalid'));
  assert.ok(denied.reasons.includes('concern_description_hash_invalid'));
  assert.ok(denied.reasons.includes('concern_impact_invalid'));
  assert.ok(denied.reasons.includes('investigator_human_required'));
  assert.ok(denied.reasons.includes('evidence_ref_invalid'));
  assert.ok(denied.reasons.includes('critical_escalation_route_absent'));
  assert.ok(denied.reasons.includes('reported_time_invalid'));
  assert.ok(denied.reasons.includes('custody_digest_invalid'));
  assert.equal(denied.concern, null);
  assert.equal(denied.receipt, null);
});

test('concern reporting denies empty evidence references without creating receipts', async () => {
  const { evaluateConcernReport } = await loadConcernReporting();

  const denied = evaluateConcernReport({
    ...criticalConcernInput(),
    evidenceRefs: [],
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('evidence_refs_absent'));
  assert.equal(denied.concern, null);
  assert.equal(denied.receipt, null);
});

test('concern reporting rejects protected narrative content before receipt creation', async () => {
  const { evaluateConcernReport } = await loadConcernReporting();

  assert.throws(
    () =>
      evaluateConcernReport({
        ...criticalConcernInput(),
        concern: {
          ...criticalConcernInput().concern,
          description: 'Participant Alice Example source document body must remain outside receipts.',
        },
      }),
    /protected content|raw narrative/iu,
  );
});
