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

const REQUIRED_SECTIONS = Object.freeze([
  'calibration_records',
  'clinical_trial_product_handling_readiness',
  'communication_plan',
  'competency_records',
  'decision_forum_determinations',
  'delegation_logs',
  'deviation_capa_readiness',
  'document_control_status',
  'equipment_inventory',
  'ethical_framework',
  'evidence_completeness_score',
  'evidence_freshness_score',
  'exochain_evidence_receipt_refs',
  'facility_readiness_evidence',
  'facility_types',
  'informed_consent_process_readiness',
  'internal_audit_status',
  'investigator_roster',
  'kpi_trends',
  'last_review_date',
  'legal_entity',
  'mission_vision_values',
  'next_review_due_date',
  'open_critical_gaps',
  'open_major_gaps',
  'open_minor_gaps',
  'organization_chart',
  'ownership_structure',
  'performance_objectives',
  'principal_investigator_qualifications',
  'quality_manager_designation',
  'quality_plan',
  'quality_risk_level',
  'readiness_status',
  'regulatory_inspection_history',
  'risk_management_framework',
  'role_definitions',
  'sae_ae_reporting_readiness',
  'site_identity',
  'site_locations',
  'sop_inventory',
  'sponsor_cro_evidence_summary',
  'sponsor_cro_oversight_summary',
  'staff_roster',
  'therapeutic_areas',
  'training_records',
  'vulnerable_population_safeguards',
]);

async function loadSiteQmsPassport() {
  try {
    return await import('../src/site-qms-passport.mjs');
  } catch (error) {
    assert.fail(`CyberMedica site QMS passport module must exist and load: ${error.message}`);
  }
}

function sectionEvidenceRef(section, index) {
  return `EVD-${String(index + 1).padStart(3, '0')}-${section.toUpperCase().replaceAll('_', '-')}`;
}

function completePassportSections() {
  return REQUIRED_SECTIONS.map((section, index) => ({
    section,
    status: index % 7 === 0 ? 'complete_with_conditions' : 'complete',
    ownerDid: `did:exo:${section.replaceAll('_', '-')}-owner-alpha`,
    artifactHash: index % 2 === 0 ? DIGEST_A : DIGEST_B,
    evidenceRefs: [sectionEvidenceRef(section, index)],
    controlRefs: [`CTRL-${section.toUpperCase()}-001`],
    updatedAtHlc: { physicalMs: 1792000000000 + index, logical: index % 3 },
  }));
}

function evidenceInventoryFromSections(sections = completePassportSections()) {
  return sections.map((section, index) => ({
    evidenceRef: section.evidenceRefs[0],
    section: section.section,
    artifactHash: index % 2 === 0 ? DIGEST_C : DIGEST_D,
    status: 'approved',
    fresh: true,
    classification: 'confidential_metadata_only',
    custodyDigest: index % 2 === 0 ? DIGEST_E : DIGEST_A,
  }));
}

function siteQmsPassportInput() {
  const sections = completePassportSections();
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:site-quality-lead-alpha', kind: 'human' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['govern'] },
    siteProfile: {
      passportRef: 'QMS-PASSPORT-SITE-ALPHA-2026-0001',
      siteRef: 'site-alpha',
      legalEntityRef: 'legal-entity-alpha',
      ownerOrgRef: 'org-alpha',
      version: 'v1',
      readinessStatus: 'ready_with_conditions',
      qualityRiskLevel: 'controlled',
      status: 'approved_with_conditions',
      qualityManagerDid: 'did:exo:quality-manager-alpha',
      principalInvestigatorDid: 'did:exo:principal-investigator-alpha',
      createdAtHlc: { physicalMs: 1792000000000, logical: 5 },
      lastReviewedAtHlc: { physicalMs: 1792000005000, logical: 1 },
      nextReviewDueHlc: { physicalMs: 1794592005000, logical: 0 },
      policyRefs: ['site-qms-passport-procedure-v1', 'qms-profile-review-policy-v1'],
    },
    sections,
    evidenceInventory: evidenceInventoryFromSections(sections),
    findings: [
      {
        findingRef: 'FIND-QMS-001',
        severity: 'major',
        status: 'accepted',
        ownerDid: 'did:exo:quality-manager-alpha',
        mitigationHash: DIGEST_B,
      },
      {
        findingRef: 'FIND-QMS-002',
        severity: 'minor',
        status: 'closed',
        ownerDid: 'did:exo:site-leader-alpha',
        mitigationHash: DIGEST_C,
      },
    ],
    capaSummary: {
      openCritical: 0,
      openMajor: 1,
      overdue: 0,
      linkedCapaRefs: ['CAPA-QMS-001'],
    },
    riskRegisterSummary: {
      qualityRiskLevel: 'controlled',
      activeHighRiskCount: 0,
      activeCriticalRiskCount: 0,
      startupRiskAssessmentRefs: ['RISK-STARTUP-2026-0007'],
    },
    qualityObjectives: [
      {
        objectiveRef: 'QOBJ-QMS-001',
        status: 'active',
        scoreBasisPoints: 9300,
        evidenceHash: DIGEST_D,
      },
    ],
    aiEvidenceReview: {
      completed: true,
      advisoryOnly: true,
      finalAuthority: false,
      reviewerRole: 'quality_manager',
      outputHash: DIGEST_E,
      evidenceUsedHashes: [DIGEST_A, DIGEST_C],
      unresolvedGaps: ['FIND-QMS-001'],
    },
    qualityReview: {
      decision: 'approve_with_conditions',
      reviewerDid: 'did:exo:quality-reviewer-alpha',
      humanVerified: true,
      rationaleHash: DIGEST_A,
      approvedAtHlc: { physicalMs: 1792000010000, logical: 1 },
      decisionReceiptRef: 'decision-receipt-site-qms-passport-0001',
      decisionReceiptHash: DIGEST_B,
      evidenceBundle: { complete: true, phiBoundaryAttested: true },
      decisionForumDeterminations: [
        {
          decisionId: 'df-qms-control-approval-0004',
          workflowReceiptId: 'df-workflow-qms-control-approval-0004',
          status: 'approved',
          receiptHash: DIGEST_C,
        },
      ],
    },
    custodyDigest: DIGEST_D,
  };
}

test('site QMS passport creates deterministic inactive metadata receipt', async () => {
  const { evaluateSiteQmsPassport } = await loadSiteQmsPassport();

  const input = siteQmsPassportInput();
  const resultA = evaluateSiteQmsPassport(input);
  const resultB = evaluateSiteQmsPassport({
    ...siteQmsPassportInput(),
    sections: [...siteQmsPassportInput().sections].reverse(),
    evidenceInventory: [...siteQmsPassportInput().evidenceInventory].reverse(),
    findings: [...siteQmsPassportInput().findings].reverse(),
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.passport.passportStatus, 'approved_with_conditions');
  assert.equal(resultA.passport.readinessStatus, 'ready_with_conditions');
  assert.equal(resultA.passport.exochainProductionClaim, false);
  assert.equal(resultA.passport.trustState, 'inactive');
  assert.deepEqual(resultA.passport.sourceRequirements, ['FR-009']);
  assert.equal(resultA.passport.aiFinalAuthority, false);
  assert.equal(resultA.passport.evidenceCompletenessBasisPoints, 10000);
  assert.equal(resultA.passport.evidenceFreshnessBasisPoints, 10000);
  assert.deepEqual(resultA.passport.openGapSummary, { critical: 0, major: 1, minor: 0 });
  assert.ok(resultA.passport.coveredSections.includes('site_identity'));
  assert.ok(resultA.passport.coveredSections.includes('exochain_evidence_receipt_refs'));
  assert.equal(resultA.passport.coveredSections.length, REQUIRED_SECTIONS.length);
  assert.deepEqual(resultA.passport.requiredEscalationRoles, ['site_quality_lead']);
  assert.equal(resultA.passport.passportId, resultB.passport.passportId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'site_qms_passport');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(resultA), /source document body|direct identifier|participant name|raw profile/iu);
});

test('site QMS passport fails closed for missing sections stale evidence and critical gaps', async () => {
  const { evaluateSiteQmsPassport } = await loadSiteQmsPassport();
  const input = siteQmsPassportInput();
  input.actor = { did: 'did:exo:ai-reviewer-alpha', kind: 'ai_agent' };
  input.sections = input.sections.filter((section) => section.section !== 'ethical_framework');
  input.evidenceInventory = evidenceInventoryFromSections(input.sections);
  input.evidenceInventory[0] = {
    ...input.evidenceInventory[0],
    status: 'pending',
    fresh: false,
    artifactHash: 'not-a-hash',
  };
  input.findings = [
    {
      findingRef: 'FIND-CRITICAL-001',
      severity: 'critical',
      status: 'open',
      ownerDid: '',
      mitigationHash: '',
    },
  ];

  const denied = evaluateSiteQmsPassport(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.passport.passportStatus, 'blocked');
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('required_passport_section_missing:ethical_framework'));
  assert.ok(denied.reasons.includes('evidence_not_approved:EVD-001-CALIBRATION-RECORDS'));
  assert.ok(denied.reasons.includes('evidence_stale:EVD-001-CALIBRATION-RECORDS'));
  assert.ok(denied.reasons.includes('evidence_hash_invalid:EVD-001-CALIBRATION-RECORDS'));
  assert.ok(denied.reasons.includes('critical_gap_unresolved:FIND-CRITICAL-001'));
  assert.ok(denied.reasons.includes('finding_owner_absent:FIND-CRITICAL-001'));
  assert.ok(denied.reasons.includes('finding_mitigation_invalid:FIND-CRITICAL-001'));
  assert.equal(denied.passport.openGapSummary.critical, 1);
});

test('site QMS passport denies tenant authority and quality review defects', async () => {
  const { evaluateSiteQmsPassport } = await loadSiteQmsPassport();
  const input = siteQmsPassportInput();
  input.targetTenantId = 'tenant-site-beta';
  input.authority = { valid: true, revoked: false, expired: false, permissions: ['read'] };
  input.siteProfile = {
    ...input.siteProfile,
    readinessStatus: 'ready',
    qualityRiskLevel: 'unknown',
    nextReviewDueHlc: { physicalMs: 1791000000000, logical: 0 },
    policyRefs: [],
  };
  input.aiEvidenceReview = {
    completed: false,
    advisoryOnly: false,
    finalAuthority: true,
    reviewerRole: '',
    outputHash: '',
    evidenceUsedHashes: ['bad'],
    unresolvedGaps: [],
  };
  input.qualityReview = {
    decision: 'reject',
    reviewerDid: '',
    humanVerified: false,
    rationaleHash: '',
    approvedAtHlc: { physicalMs: 1792000010000, logical: 1 },
    decisionReceiptRef: '',
    decisionReceiptHash: 'bad',
    evidenceBundle: { complete: false, phiBoundaryAttested: false },
    decisionForumDeterminations: [
      {
        decisionId: '',
        workflowReceiptId: '',
        status: 'pending',
        receiptHash: '',
      },
    ],
  };

  const denied = evaluateSiteQmsPassport(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('quality_risk_level_invalid'));
  assert.ok(denied.reasons.includes('next_review_not_after_last_review'));
  assert.ok(denied.reasons.includes('policy_refs_absent'));
  assert.ok(denied.reasons.includes('ai_evidence_review_incomplete'));
  assert.ok(denied.reasons.includes('ai_evidence_review_must_be_advisory'));
  assert.ok(denied.reasons.includes('ai_evidence_review_evidence_hash_invalid'));
  assert.ok(denied.reasons.includes('quality_review_rejected'));
  assert.ok(denied.reasons.includes('quality_reviewer_absent'));
  assert.ok(denied.reasons.includes('quality_review_human_unverified'));
  assert.ok(denied.reasons.includes('decision_receipt_ref_absent'));
  assert.ok(denied.reasons.includes('decision_receipt_hash_invalid'));
  assert.ok(denied.reasons.includes('evidence_bundle_incomplete'));
  assert.ok(denied.reasons.includes('phi_boundary_unattested'));
  assert.ok(denied.reasons.includes('decision_forum_determination_invalid:unknown'));
});

test('site QMS passport rejects raw profile text and protected source content before receipt creation', async () => {
  const { evaluateSiteQmsPassport } = await loadSiteQmsPassport();

  assert.throws(
    () =>
      evaluateSiteQmsPassport({
        ...siteQmsPassportInput(),
        siteProfile: {
          ...siteQmsPassportInput().siteProfile,
          rawProfileNarrative: 'Direct raw source document body text must remain outside the passport receipt.',
        },
      }),
    /protected content|raw profile/i,
  );
});

test('site QMS passport permits fully approved profile without open escalation roles', async () => {
  const { evaluateSiteQmsPassport } = await loadSiteQmsPassport();
  const input = siteQmsPassportInput();
  input.siteProfile = {
    ...input.siteProfile,
    readinessStatus: 'ready',
    status: 'approved',
  };
  input.findings = [];
  input.capaSummary = {
    openCritical: 0,
    openMajor: 0,
    overdue: 0,
    linkedCapaRefs: [],
  };
  input.qualityObjectives = [
    {
      objectiveRef: 'QOBJ-QMS-001',
      status: 'active',
      scoreBasisPoints: 9000,
      evidenceHash: DIGEST_D,
    },
    {
      objectiveRef: 'QOBJ-QMS-002',
      status: 'active',
      scoreBasisPoints: 9600,
      evidenceHash: DIGEST_E,
    },
  ];
  input.qualityReview = {
    ...input.qualityReview,
    decision: 'approve',
    decisionForumDeterminations: [
      {
        decisionId: 'df-qms-control-approval-0006',
        workflowReceiptId: 'df-workflow-qms-control-approval-0006',
        status: 'approved',
        receiptHash: DIGEST_C,
      },
      {
        decisionId: 'df-qms-control-approval-0005',
        workflowReceiptId: 'df-workflow-qms-control-approval-0005',
        status: 'closed',
        receiptHash: DIGEST_B,
      },
    ],
  };

  const result = evaluateSiteQmsPassport(input);

  assert.equal(result.decision, 'permitted');
  assert.equal(result.passport.passportStatus, 'approved');
  assert.equal(result.passport.readinessStatus, 'ready');
  assert.deepEqual(result.passport.openGapSummary, { critical: 0, major: 0, minor: 0 });
  assert.deepEqual(result.passport.requiredEscalationRoles, []);
  assert.equal(result.passport.qualityObjectiveScoreBasisPoints, 9300);
  assert.deepEqual(
    result.passport.qualityReview.decisionForumDeterminations.map((determination) => determination.decisionId),
    ['df-qms-control-approval-0005', 'df-qms-control-approval-0006'],
  );
});

test('site QMS passport denies empty objective evidence and same-tick review ordering', async () => {
  const { evaluateSiteQmsPassport } = await loadSiteQmsPassport();
  const input = siteQmsPassportInput();
  input.siteProfile = {
    ...input.siteProfile,
    lastReviewedAtHlc: { physicalMs: 1792000005000, logical: 3 },
    nextReviewDueHlc: { physicalMs: 1792000005000, logical: 2 },
  };
  input.qualityObjectives = [];
  input.qualityReview = {
    ...input.qualityReview,
  };
  delete input.qualityReview.decisionForumDeterminations;

  const denied = evaluateSiteQmsPassport(input);

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('next_review_not_after_last_review'));
  assert.ok(denied.reasons.includes('quality_objectives_absent'));
  assert.equal(denied.passport.qualityObjectiveScoreBasisPoints, 0);
  assert.deepEqual(denied.passport.qualityReview.decisionForumDeterminations, []);
});

test('site QMS passport fails closed instead of throwing when required objects are absent', async () => {
  const { evaluateSiteQmsPassport } = await loadSiteQmsPassport();

  const denied = evaluateSiteQmsPassport({});

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.passport.passportStatus, 'blocked');
  assert.equal(denied.passport.evidenceCompletenessBasisPoints, 0);
  assert.equal(denied.passport.evidenceFreshnessBasisPoints, 0);
  assert.equal(denied.passport.missingSections.length, REQUIRED_SECTIONS.length);
  assert.ok(denied.reasons.includes('tenant_absent'));
  assert.ok(denied.reasons.includes('actor_did_absent'));
  assert.ok(denied.reasons.includes('passport_ref_absent'));
  assert.ok(denied.reasons.includes('passport_section_inventory_empty'));
  assert.ok(denied.reasons.includes('passport_evidence_inventory_empty'));
  assert.ok(denied.reasons.includes('quality_objectives_absent'));
  assert.ok(denied.reasons.includes('quality_review_decision_invalid'));
  assert.equal(denied.receipt, undefined);
});
