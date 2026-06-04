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

async function loadComplaintManagement() {
  try {
    return await import('../src/complaint-management.mjs');
  } catch (error) {
    assert.fail(`CyberMedica complaint management module must exist and load: ${error.message}`);
  }
}

function evidenceRef(overrides = {}) {
  return {
    evidenceRef: 'evidence-complaint-intake-001',
    artifactType: 'complaint_intake_form',
    artifactHash: DIGEST_A,
    custodyDigest: DIGEST_B,
    receiptId: 'cmr-complaint-intake-001',
    classification: 'confidential_metadata_only',
    ...overrides,
  };
}

function complaintInput(overrides = {}) {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    siteId: 'site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['complaint_manage'],
      authorityChainHash: DIGEST_A,
    },
    complaintPolicy: {
      policyRef: 'policy-complaint-management-v1',
      policyHash: DIGEST_B,
      status: 'active',
      categories: [
        'data_integrity',
        'participant_rights',
        'privacy',
        'quality_system',
        'safety',
        'sponsor_cro',
        'staff_wellbeing',
        'vendor',
      ],
      requiredTriageDomains: [
        'classification',
        'confidentiality',
        'cqi_linkage',
        'decision_forum_materiality',
        'investigator_assignment',
        'non_retaliation',
        'response_plan',
      ],
      anonymousReportingAllowed: true,
      nonRetaliationRequired: true,
      cqiLinkageRequiredForClosure: true,
      humanInvestigatorRequired: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1790700000000, logical: 1 },
    },
    reporter: {
      anonymous: false,
      reporterDid: 'did:exo:crc-alpha',
      reporterClass: 'staff',
      notificationPermitted: true,
      intakeChannel: 'quality_portal',
    },
    complaint: {
      complaintRef: 'CMP-2026-0004',
      category: 'participant_rights',
      severity: 'critical',
      sourceClass: 'internal_staff',
      summaryHash: DIGEST_C,
      affectedSubjectClass: 'participant',
      siteRef: 'site-alpha',
      protocolRef: 'protocol-cm-001',
      relatedConcernRef: 'CONCERN-2026-0007',
      affectedAreaRefs: ['consent-process', 'participant-communications'],
      participantSafetyImpact: true,
      dataIntegrityImpact: false,
      privacyImpact: false,
      retaliationRiskLevel: 'elevated',
      receivedAtHlc: { physicalMs: 1790700000100, logical: 3 },
      status: 'closed_cqi_linked',
    },
    evidenceRefs: [
      evidenceRef({ evidenceRef: 'evidence-complaint-follow-up-002', artifactType: 'follow_up_record', artifactHash: DIGEST_D }),
      evidenceRef(),
    ],
    triage: {
      triagedAtHlc: { physicalMs: 1790700000200, logical: 2 },
      categoryConfirmed: true,
      severityConfirmed: true,
      confidentialityClass: 'confidential_metadata_only',
      nonRetaliationNoticeHash: DIGEST_D,
      escalationRequired: true,
      responseDueAtHlc: { physicalMs: 1790700000300, logical: 1 },
    },
    assignedInvestigator: {
      did: 'did:exo:quality-investigator-alpha',
      kind: 'human',
      role: 'independent_quality_investigator',
      independenceAttestationHash: DIGEST_E,
      conflictCleared: true,
    },
    investigation: {
      planHash: DIGEST_A,
      findingHash: DIGEST_B,
      rootCauseHash: DIGEST_C,
      completedAtHlc: { physicalMs: 1790700000400, logical: 1 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    responsePlan: {
      acknowledgementHash: DIGEST_D,
      responsePlanHash: DIGEST_E,
      correctiveActionRefs: ['capa-2026-0004'],
      communicationRecordHash: DIGEST_A,
      reporterResponsePermitted: true,
      completedAtHlc: { physicalMs: 1790700000500, logical: 1 },
    },
    decisionForum: {
      invoked: true,
      matterRef: 'df-complaint-cmp-2026-0004',
      receiptId: 'cmr-df-complaint-0004',
      quorumStatus: 'met',
      humanGateVerified: true,
      openChallenge: false,
      decidedAtHlc: { physicalMs: 1790700000600, logical: 1 },
    },
    cqiLinkage: {
      required: true,
      cqiCycleRef: 'cqi-complaint-2026-0004',
      cqiReceiptId: 'cmr-cqi-complaint-0004',
      improvementSource: 'complaint',
      effectivenessCheckScheduled: true,
    },
    humanReview: {
      verified: true,
      reviewedByDid: 'did:exo:quality-lead-alpha',
      reviewEvidenceHash: DIGEST_B,
      decision: 'complaint_closed_cqi_linked',
      reviewedAtHlc: { physicalMs: 1790700000700, logical: 1 },
    },
    auditRecord: {
      auditRecordRef: 'audit-complaint-2026-0004',
      auditRecordHash: DIGEST_C,
      recordedAtHlc: { physicalMs: 1790700000800, logical: 1 },
      metadataOnly: true,
    },
    aiAssistance: {
      used: true,
      advisoryOnly: true,
      finalAuthority: false,
      promptHash: DIGEST_D,
      outputHash: DIGEST_E,
      humanReviewed: true,
    },
    checkedAtHlc: { physicalMs: 1790700000900, logical: 1 },
    custodyDigest: DIGEST_B,
    ...overrides,
  };
}

test('complaint management closes a critical complaint with deterministic inactive receipts', async () => {
  const { evaluateComplaintManagement } = await loadComplaintManagement();

  const resultA = evaluateComplaintManagement(complaintInput());
  const resultB = evaluateComplaintManagement(
    complaintInput({
      complaintPolicy: {
        ...complaintInput().complaintPolicy,
        categories: [...complaintInput().complaintPolicy.categories].reverse(),
        requiredTriageDomains: [...complaintInput().complaintPolicy.requiredTriageDomains].reverse(),
      },
      evidenceRefs: [...complaintInput().evidenceRefs].reverse(),
      complaint: {
        ...complaintInput().complaint,
        affectedAreaRefs: [...complaintInput().complaint.affectedAreaRefs].reverse(),
      },
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.complaint.status, 'closed_cqi_linked');
  assert.equal(resultA.complaint.materialDecisionForumRequired, true);
  assert.equal(resultA.complaint.reporter.anonymous, false);
  assert.equal(resultA.complaint.aiFinalAuthority, false);
  assert.equal(resultA.complaint.exochainProductionClaim, false);
  assert.deepEqual(resultA.complaint.requiredResponseRoles, [
    'decision_forum',
    'participant_rights_reviewer',
    'principal_investigator',
    'site_quality_lead',
  ]);
  assert.equal(resultA.complaint.complaintId, resultB.complaint.complaintId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'complaint_management_record');
  assert.doesNotMatch(JSON.stringify(resultA), /Participant Alice|source document|complaint narrative/iu);
});

test('anonymous non-material complaints remain metadata-only without reporter identity disclosure', async () => {
  const { evaluateComplaintManagement } = await loadComplaintManagement();

  const result = evaluateComplaintManagement(
    complaintInput({
      reporter: {
        anonymous: true,
        reporterClass: 'staff',
        notificationPermitted: false,
        intakeChannel: 'anonymous_hotline',
      },
      complaint: {
        ...complaintInput().complaint,
        category: 'quality_system',
        severity: 'minor',
        participantSafetyImpact: false,
        relatedConcernRef: null,
        retaliationRiskLevel: 'none',
        status: 'investigation_assigned',
      },
      triage: {
        ...complaintInput().triage,
        escalationRequired: false,
      },
      decisionForum: null,
      cqiLinkage: {
        required: false,
        cqiCycleRef: null,
        cqiReceiptId: null,
        improvementSource: null,
        effectivenessCheckScheduled: false,
      },
      responsePlan: {
        ...complaintInput().responsePlan,
        acknowledgementHash: null,
        communicationRecordHash: null,
        reporterResponsePermitted: false,
      },
      humanReview: {
        ...complaintInput().humanReview,
        decision: 'complaint_investigation_assigned',
      },
    }),
  );

  assert.equal(result.decision, 'permitted');
  assert.equal(result.complaint.status, 'investigation_assigned');
  assert.equal(result.complaint.reporter.anonymous, true);
  assert.equal(result.complaint.reporter.reporterDid, null);
  assert.equal(result.complaint.materialDecisionForumRequired, false);
  assert.deepEqual(result.complaint.requiredResponseRoles, ['site_quality_lead']);
  assert.equal(result.complaint.cqiLinkage, null);
});

test('complaint management fails closed for authority policy triage investigation closure and governance defects', async () => {
  const { evaluateComplaintManagement } = await loadComplaintManagement();

  const denied = evaluateComplaintManagement(
    complaintInput({
      targetTenantId: 'tenant-site-beta',
      actor: { did: 'did:exo:ai-agent-alpha', kind: 'ai_agent' },
      authority: { valid: true, revoked: false, expired: false, permissions: ['read'], authorityChainHash: 'bad' },
      complaintPolicy: {
        ...complaintInput().complaintPolicy,
        status: 'draft',
        categories: ['quality_system'],
        requiredTriageDomains: ['classification'],
        nonRetaliationRequired: false,
        cqiLinkageRequiredForClosure: false,
      },
      reporter: { anonymous: false, reporterDid: '', notificationPermitted: true, intakeChannel: '' },
      complaint: {
        ...complaintInput().complaint,
        complaintRef: '',
        category: 'unsupported',
        severity: 'critical',
        summaryHash: 'bad',
        affectedAreaRefs: [],
        status: 'closed_cqi_linked',
      },
      evidenceRefs: [evidenceRef({ artifactHash: 'bad', receiptId: '' })],
      triage: {
        triagedAtHlc: { physicalMs: 1790700000000, logical: 1 },
        categoryConfirmed: false,
        severityConfirmed: false,
        confidentialityClass: 'public',
        nonRetaliationNoticeHash: 'bad',
        escalationRequired: false,
        responseDueAtHlc: { physicalMs: 1790700000000, logical: 0 },
      },
      assignedInvestigator: {
        did: 'did:exo:complaint-review-agent',
        kind: 'ai_agent',
        role: '',
        independenceAttestationHash: 'bad',
        conflictCleared: false,
      },
      investigation: {
        planHash: 'bad',
        findingHash: 'bad',
        rootCauseHash: 'bad',
        completedAtHlc: { physicalMs: 1790700000100, logical: 1 },
        metadataOnly: false,
        protectedContentExcluded: false,
      },
      responsePlan: {
        acknowledgementHash: null,
        responsePlanHash: 'bad',
        correctiveActionRefs: [],
        communicationRecordHash: null,
        reporterResponsePermitted: false,
        completedAtHlc: { physicalMs: 1790700000100, logical: 0 },
      },
      decisionForum: null,
      cqiLinkage: { required: true, cqiCycleRef: '', cqiReceiptId: '', improvementSource: 'complaint', effectivenessCheckScheduled: false },
      humanReview: {
        verified: false,
        reviewedByDid: '',
        reviewEvidenceHash: 'bad',
        decision: 'approve_anyway',
        reviewedAtHlc: { physicalMs: 1790700000200, logical: 1 },
      },
      auditRecord: { auditRecordRef: '', auditRecordHash: 'bad', recordedAtHlc: { physicalMs: 1790700000100, logical: 1 }, metadataOnly: false },
      aiAssistance: { used: true, advisoryOnly: false, finalAuthority: true, promptHash: 'bad', outputHash: 'bad', humanReviewed: false },
      checkedAtHlc: null,
      custodyDigest: '0000000000000000000000000000000000000000000000000000000000000000',
    }),
  );

  assert.equal(denied.decision, 'hold_for_complaint_gap');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('complaint_authority_missing'));
  assert.ok(denied.reasons.includes('complaint_policy_not_active'));
  assert.ok(denied.reasons.includes('complaint_policy_category_missing:participant_rights'));
  assert.ok(denied.reasons.includes('triage_category_unconfirmed'));
  assert.ok(denied.reasons.includes('investigator_human_required'));
  assert.ok(denied.reasons.includes('material_complaint_decision_forum_required'));
  assert.ok(denied.reasons.includes('closed_complaint_cqi_linkage_absent'));
  assert.ok(denied.reasons.includes('human_review_unverified'));
  assert.ok(denied.reasons.includes('custody_digest_invalid'));
  assert.equal(denied.receipt, null);
});

test('complaint management rejects raw complaint content and secret material before receipts', async () => {
  const { evaluateComplaintManagement } = await loadComplaintManagement();

  assert.throws(
    () =>
      evaluateComplaintManagement(
        complaintInput({
          complaint: {
            ...complaintInput().complaint,
            complaintNarrative: 'Participant Alice Example source document body must remain outside CyberMedica receipts.',
          },
        }),
      ),
    /raw complaint content|protected content/iu,
  );

  assert.throws(
    () =>
      evaluateComplaintManagement(
        complaintInput({
          responsePlan: {
            ...complaintInput().responsePlan,
            apiKey: 'redacted-complaint-provider-key',
          },
        }),
      ),
    /secret/iu,
  );
});
