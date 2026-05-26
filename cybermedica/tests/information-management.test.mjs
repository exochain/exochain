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
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

const PLAN_COMPONENTS = Object.freeze([
  'access_permissions',
  'ae_reporting',
  'alcoac_requirements',
  'approval_dates',
  'correction_rules',
  'crf_media',
  'deadlines',
  'discrepancy_reporting',
  'distribution_rules',
  'document_inventory',
  'document_security_rules',
  'document_storage_rules',
  'dsmb_reporting',
  'final_report_requirements',
  'milestones',
  'participant_code_rules',
  'required_records',
  'retention_period',
  'review_frequency',
  'sae_reporting',
  'source_data_definition',
  'source_data_traceability',
  'sponsor_reporting_frequency',
  'staff_communication_evidence',
  'susar_reporting',
  'urgent_change_reporting',
  'version_history',
]);

const SYSTEM_CONTROLS = Object.freeze([
  'authorized_access_list',
  'availability_procedure',
  'backup_procedure',
  'business_continuity_procedure',
  'confidentiality_procedure',
  'data_loss_protection',
  'data_protection_regulation_checks',
  'disaster_recovery_procedure',
  'integrity_procedure',
  'maintenance_procedure',
  'monitor_auditor_regulator_access_controls',
  'recovery_procedure',
  'regulatory_compliance_mapping',
  'setup_installation_use_procedure',
  'tampering_protection',
  'unauthorized_use_protection',
]);

async function loadInformationManagement() {
  try {
    return await import('../src/information-management.mjs');
  } catch (error) {
    assert.fail(`CyberMedica information-management module must exist and load: ${error.message}`);
  }
}

function planComponentEvidence() {
  return PLAN_COMPONENTS.map((component, index) => ({
    component,
    status: index === 5 ? 'approved_with_conditions' : 'approved',
    evidenceHash: index % 2 === 0 ? DIGEST_A : DIGEST_B,
    ownerDid: `did:exo:${component.replaceAll('_', '-')}-owner`,
    reviewDueHlc: { physicalMs: 1797000000000 + index, logical: 0 },
  }));
}

function alcoacControls() {
  return ['accurate', 'attributable', 'complete', 'contemporaneous', 'legible', 'original'].map(
    (principle, index) => ({
      principle,
      status: 'implemented',
      evidenceHash: index % 2 === 0 ? DIGEST_C : DIGEST_D,
      controlRef: `ALCOAC-${principle.toUpperCase()}`,
    }),
  );
}

function electronicSystems() {
  return [
    {
      systemRef: 'edc-alpha',
      status: 'validated',
      validationEvidenceHash: DIGEST_A,
      verificationEvidenceHash: DIGEST_B,
      authorizedAccessListHash: DIGEST_C,
      accessStartHlc: { physicalMs: 1790000000000, logical: 0 },
      accessRemovalHlc: { physicalMs: 1796000000000, logical: 0 },
      controlEvidence: SYSTEM_CONTROLS.map((control, index) => ({
        control,
        status: 'implemented',
        evidenceHash: index % 2 === 0 ? DIGEST_D : DIGEST_E,
      })),
    },
  ];
}

function informationPlanInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:data-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['govern', 'write'],
      authorityChainHash: DIGEST_F,
    },
    informationPlan: {
      planRef: 'IMP-CARDIAC-ALPHA-001',
      protocolRef: 'protocol-cardiac-alpha',
      sponsorRef: 'sponsor-alpha',
      siteRef: 'site-alpha',
      status: 'approved',
      version: 3,
      effectiveAtHlc: { physicalMs: 1791000000000, logical: 0 },
      reviewDueHlc: { physicalMs: 1796000000000, logical: 0 },
      planHash: DIGEST_A,
      componentEvidence: planComponentEvidence(),
      alcoacControls: alcoacControls(),
      retention: {
        retentionClass: 'trial_master_quality_record',
        periodMonths: 300,
        conflictPolicy: 'longest_applicable_retention',
        governingRuleHash: DIGEST_B,
        legalHoldActive: false,
      },
      accessPolicy: {
        policyRef: 'ACCESS-IMP-CARDIAC-ALPHA',
        leastPrivilege: true,
        revocable: true,
        timeBound: true,
        auditTrailRequired: true,
        authorizedRoleRefs: ['principal_investigator', 'data_manager', 'monitor_cra'],
      },
      staffCommunication: {
        communicated: true,
        communicationEvidenceHash: DIGEST_C,
        communicatedByDid: 'did:exo:data-manager-alpha',
        communicatedAtHlc: { physicalMs: 1791000100000, logical: 0 },
      },
      electronicSystems: electronicSystems(),
    },
    review: {
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-information-plan-001',
        workflowReceiptId: 'df-workflow-information-plan-001',
      },
      evidenceBundle: { complete: true, phiBoundaryAttested: true },
      qualityReviewerDid: 'did:exo:quality-reviewer-alpha',
    },
    custodyDigest: DIGEST_E,
  };
}

function correctionInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:data-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['record_correction', 'write'],
      authorityChainHash: DIGEST_F,
    },
    correction: {
      correctionRef: 'CORR-SOURCE-ALPHA-0007',
      recordRef: 'source-traceability-record-alpha-0007',
      recordType: 'source_data_traceability',
      correctedByDid: 'did:exo:data-manager-alpha',
      originalArtifactHash: DIGEST_A,
      correctedArtifactHash: DIGEST_B,
      previousAuditHash: DIGEST_C,
      sequence: 8,
      correctionMethod: 'append_attributable_correction',
      reasonCode: 'transcription_error_resolved',
      originalContentPreserved: true,
      correctionAtHlc: { physicalMs: 1792000000010, logical: 0 },
      originalRecordedAtHlc: { physicalMs: 1792000000000, logical: 0 },
      sourceTraceability: {
        traceabilityRef: 'TRACE-SOURCE-ALPHA-0007',
        sourceRecordHash: DIGEST_D,
        crfFieldHash: DIGEST_E,
        discrepancyRef: 'DISC-ALPHA-0007',
        preservesParticipantCodeBoundary: true,
      },
      approvalRequired: true,
    },
    approval: {
      status: 'approved',
      approverDid: 'did:exo:principal-investigator-alpha',
      humanGate: { verified: true },
      approvedAtHlc: { physicalMs: 1792000000020, logical: 0 },
      rationaleHash: DIGEST_D,
    },
    custodyDigest: DIGEST_E,
  };
}

test('information management plan readiness creates deterministic inactive metadata receipts', async () => {
  const { evaluateInformationManagementPlan } = await loadInformationManagement();

  const resultA = evaluateInformationManagementPlan(informationPlanInput());
  const resultB = evaluateInformationManagementPlan({
    ...informationPlanInput(),
    informationPlan: {
      ...informationPlanInput().informationPlan,
      componentEvidence: [...informationPlanInput().informationPlan.componentEvidence].reverse(),
      alcoacControls: [...informationPlanInput().informationPlan.alcoacControls].reverse(),
      accessPolicy: {
        ...informationPlanInput().informationPlan.accessPolicy,
        authorizedRoleRefs: [...informationPlanInput().informationPlan.accessPolicy.authorizedRoleRefs].reverse(),
      },
      electronicSystems: [
        {
          ...informationPlanInput().informationPlan.electronicSystems[0],
          controlEvidence: [...informationPlanInput().informationPlan.electronicSystems[0].controlEvidence].reverse(),
        },
      ],
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.informationPlan.readinessStatus, 'ready');
  assert.equal(resultA.informationPlan.trustState, 'inactive');
  assert.equal(resultA.informationPlan.exochainProductionClaim, false);
  assert.equal(resultA.informationPlan.componentCoverageBasisPoints, 10000);
  assert.equal(resultA.informationPlan.alcoacCoverageBasisPoints, 10000);
  assert.deepEqual(resultA.informationPlan.coveredAlcoacPrinciples, [
    'accurate',
    'attributable',
    'complete',
    'contemporaneous',
    'legible',
    'original',
  ]);
  assert.equal(resultA.informationPlan.systemValidationSummary.validated, 1);
  assert.equal(resultA.informationPlan.systemValidationSummary.blocked, 0);
  assert.equal(resultA.informationPlan.planFingerprint, resultB.informationPlan.planFingerprint);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'information_management_plan');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(resultA), /source document|clinical note|participant alice|root-backed production authority/iu);
});

test('information management plan fails closed for ALCOAC system retention access and governance defects', async () => {
  const { evaluateInformationManagementPlan } = await loadInformationManagement();
  const input = informationPlanInput();
  input.actor = { did: 'did:exo:ai-reviewer-alpha', kind: 'ai_agent' };
  input.targetTenantId = 'tenant-site-beta';
  input.authority = { valid: true, revoked: true, expired: true, permissions: ['read'], authorityChainHash: 'bad' };
  input.informationPlan.status = 'draft';
  input.informationPlan.version = 0;
  input.informationPlan.reviewDueHlc = { physicalMs: 1790000000000, logical: 0 };
  input.informationPlan.componentEvidence = input.informationPlan.componentEvidence.filter(
    (component) => component.component !== 'sae_reporting',
  );
  input.informationPlan.alcoacControls = input.informationPlan.alcoacControls.filter(
    (control) => control.principle !== 'legible',
  );
  input.informationPlan.retention = {
    retentionClass: '',
    periodMonths: 0,
    conflictPolicy: 'shortest_available',
    governingRuleHash: 'bad',
  };
  input.informationPlan.accessPolicy = {
    policyRef: '',
    leastPrivilege: false,
    revocable: false,
    timeBound: false,
    auditTrailRequired: false,
    authorizedRoleRefs: [],
  };
  input.informationPlan.staffCommunication = { communicated: false, communicationEvidenceHash: '', communicatedByDid: '' };
  input.informationPlan.electronicSystems = [
    {
      systemRef: '',
      status: 'draft',
      validationEvidenceHash: '',
      verificationEvidenceHash: '',
      authorizedAccessListHash: '',
      accessStartHlc: { physicalMs: 1796000000000, logical: 0 },
      accessRemovalHlc: { physicalMs: 1796000000000, logical: 0 },
      controlEvidence: [],
    },
  ];
  input.review.decisionForum = {
    verified: false,
    state: 'pending',
    humanGate: { verified: false },
    quorum: { status: 'not_met' },
    openChallenge: true,
    decisionId: '',
    workflowReceiptId: '',
  };
  input.review.evidenceBundle = { complete: false, phiBoundaryAttested: false };

  const denied = evaluateInformationManagementPlan(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.informationPlan.readinessStatus, 'blocked');
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_chain_revoked'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('information_plan_not_approved'));
  assert.ok(denied.reasons.includes('information_plan_version_invalid'));
  assert.ok(denied.reasons.includes('information_plan_review_due_not_after_effective'));
  assert.ok(denied.reasons.includes('plan_component_missing:sae_reporting'));
  assert.ok(denied.reasons.includes('alcoac_principle_missing:legible'));
  assert.ok(denied.reasons.includes('system_ref_absent:unknown'));
  assert.ok(denied.reasons.includes('system_not_validated:unknown'));
  assert.ok(denied.reasons.includes('system_control_missing:unknown:backup_procedure'));
  assert.ok(denied.reasons.includes('system_access_window_invalid:unknown'));
  assert.ok(denied.reasons.includes('retention_conflict_policy_invalid'));
  assert.ok(denied.reasons.includes('access_policy_not_least_privilege'));
  assert.ok(denied.reasons.includes('staff_communication_absent'));
  assert.ok(denied.reasons.includes('decision_forum_unverified'));
  assert.ok(denied.reasons.includes('human_gate_unverified'));
  assert.equal(denied.receipt, null);
});

test('information management plan uses HLC logical ordering and refuses raw information fields', async () => {
  const { evaluateInformationManagementPlan } = await loadInformationManagement();
  const input = informationPlanInput();
  input.informationPlan.effectiveAtHlc = { physicalMs: 1791000000000, logical: 1 };
  input.informationPlan.reviewDueHlc = { physicalMs: 1791000000000, logical: 2 };
  input.informationPlan.staffCommunication.communicatedAtHlc = { physicalMs: 1791000000000, logical: 3 };
  input.informationPlan.electronicSystems[0].accessStartHlc = { physicalMs: 1791000000000, logical: 4 };
  input.informationPlan.electronicSystems[0].accessRemovalHlc = { physicalMs: 1791000000000, logical: 5 };

  const permitted = evaluateInformationManagementPlan(input);

  assert.equal(permitted.decision, 'permitted');
  assert.equal(permitted.failClosed, false);
  assert.equal(permitted.informationPlan.effectiveAtHlc.logical, 1);
  assert.equal(permitted.informationPlan.reviewDueHlc.logical, 2);

  assert.throws(
    () =>
      evaluateInformationManagementPlan({
        ...informationPlanInput(),
        informationPlan: {
          ...informationPlanInput().informationPlan,
          rawSourceData: 'hashes only may leave the controlled repository',
        },
      }),
    /raw information content|protected content/i,
  );
});

test('attributable correction records preserve original content by hash and receipt metadata only', async () => {
  const { recordAttributableCorrection } = await loadInformationManagement();

  const resultA = recordAttributableCorrection(correctionInput());
  const resultB = recordAttributableCorrection({
    ...correctionInput(),
    correction: {
      ...correctionInput().correction,
      sourceTraceability: {
        preservesParticipantCodeBoundary: true,
        discrepancyRef: 'DISC-ALPHA-0007',
        crfFieldHash: DIGEST_E,
        sourceRecordHash: DIGEST_D,
        traceabilityRef: 'TRACE-SOURCE-ALPHA-0007',
      },
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.correctionRecord.trustState, 'inactive');
  assert.equal(resultA.correctionRecord.exochainProductionClaim, false);
  assert.equal(resultA.correctionRecord.originalContentPreserved, true);
  assert.equal(resultA.correctionRecord.originalArtifactHash, DIGEST_A);
  assert.equal(resultA.correctionRecord.correctedArtifactHash, DIGEST_B);
  assert.equal(resultA.correctionRecord.previousAuditHash, DIGEST_C);
  assert.equal(resultA.correctionRecord.correctionRecordHash, resultB.correctionRecord.correctionRecordHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'attributable_record_correction');
  assert.doesNotMatch(JSON.stringify(resultA), /raw value|participant alice|source document text|clinical note/iu);
});

test('attributable corrections fail closed for approval timing audit and protected-content defects', async () => {
  const { recordAttributableCorrection } = await loadInformationManagement();
  const input = correctionInput();
  input.actor = { did: 'did:exo:ai-reviewer-alpha', kind: 'ai_agent' };
  input.correction.correctedByDid = 'did:exo:different-user';
  input.correction.correctedArtifactHash = DIGEST_A;
  input.correction.previousAuditHash = ZERO_HASH;
  input.correction.sequence = 3;
  input.correction.originalContentPreserved = false;
  input.correction.reasonCode = '';
  input.correction.correctionAtHlc = { physicalMs: 1792000000000, logical: 0 };
  input.correction.originalRecordedAtHlc = { physicalMs: 1792000000000, logical: 1 };
  input.correction.sourceTraceability.preservesParticipantCodeBoundary = false;
  input.approval = {
    status: 'pending',
    approverDid: '',
    humanGate: { verified: false },
    approvedAtHlc: { physicalMs: 1791000000000, logical: 0 },
    rationaleHash: '',
  };

  const denied = recordAttributableCorrection(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.correctionRecord, null);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('correction_actor_mismatch'));
  assert.ok(denied.reasons.includes('correction_no_change'));
  assert.ok(denied.reasons.includes('previous_audit_hash_missing_for_sequence'));
  assert.ok(denied.reasons.includes('original_content_not_preserved'));
  assert.ok(denied.reasons.includes('correction_reason_absent'));
  assert.ok(denied.reasons.includes('correction_time_not_after_original'));
  assert.ok(denied.reasons.includes('traceability_participant_code_boundary_unattested'));
  assert.ok(denied.reasons.includes('correction_approval_not_approved'));
  assert.ok(denied.reasons.includes('correction_approval_human_gate_unverified'));

  assert.throws(
    () =>
      recordAttributableCorrection({
        ...correctionInput(),
        correction: {
          ...correctionInput().correction,
          rawContent: 'Participant Alice Example source document text must not enter correction receipts.',
        },
      }),
    /protected content/i,
  );
});

test('attributable correction can record non-approval corrections when policy allows', async () => {
  const { recordAttributableCorrection } = await loadInformationManagement();
  const input = correctionInput();
  input.correction.approvalRequired = false;
  input.correction.originalRecordedAtHlc = { physicalMs: 1792000000010, logical: 4 };
  input.correction.correctionAtHlc = { physicalMs: 1792000000010, logical: 5 };
  delete input.approval;

  const permitted = recordAttributableCorrection(input);

  assert.equal(permitted.decision, 'permitted');
  assert.equal(permitted.failClosed, false);
  assert.equal(permitted.correctionRecord.approvalRef, null);
  assert.equal(permitted.receipt.anchorPayload.artifactType, 'attributable_record_correction');
});
