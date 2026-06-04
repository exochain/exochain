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

async function loadStandardsControlLibrary() {
  try {
    return await import('../src/standards-control-library.mjs');
  } catch (error) {
    assert.fail(`CyberMedica standards control library module must exist and load: ${error.message}`);
  }
}

function sourceRef(sourceRefId, clauseRef) {
  return {
    sourceRefId,
    sourceType: 'clinical_research_site_qms_standard',
    sourceVersion: 'metadata-edition-2026-01',
    clauseRef,
    sourceHash: DIGEST_A,
    rightsAttested: true,
  };
}

function applicabilityCriterion(criterionId, subject, outcome) {
  return {
    criterionId,
    subject,
    operator: 'metadata_equals',
    valueHash: subject === 'site_has_product_storage' ? DIGEST_B : DIGEST_C,
    outcome,
  };
}

function evidenceRequirement(artifactType, index, required = true) {
  return {
    artifactType,
    freshnessDays: 365 + index,
    classification: index % 2 === 0 ? 'confidential_metadata_only' : 'sponsor_confidential_metadata_only',
    required,
    evidenceHash: index % 2 === 0 ? DIGEST_D : DIGEST_E,
  };
}

function standardsControlInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['govern'] },
    control: {
      controlId: 'CM-QMS-PRODUCT-001',
      versionId: 'v1',
      title: 'Clinical trial product accountability readiness control',
      sourceRefs: [
        sourceRef('SRC-QMS-CLAUSE-07-02', '7.2'),
        sourceRef('SRC-ICH-E6-R3-INV-001', 'ICH-E6-R3-INV'),
      ],
      normativeStatementHash: DIGEST_A,
      plainLanguageExplanationHash: DIGEST_B,
      applicabilityCriteria: [
        applicabilityCriterion('CRIT-PRODUCT-STORAGE', 'site_has_product_storage', 'applicable'),
        applicabilityCriterion('CRIT-NO-PRODUCT', 'site_no_product_storage', 'not_applicable'),
      ],
      ownerRole: 'quality_manager',
      approverRole: 'principal_investigator',
      reviewerRole: 'control_reviewer',
      requiredEvidence: [
        evidenceRequirement('product_accountability_sop', 0),
        evidenceRequirement('temperature_monitoring_process', 1),
      ],
      optionalEvidence: [evidenceRequirement('sponsor_product_handling_attestation', 2, false)],
      reviewFrequencyDays: 365,
      triggerEvents: ['new_protocol', 'product_storage_change', 'temperature_excursion'],
      riskCriticality: 'critical',
      relevance: {
        participantSafety: true,
        dataIntegrity: true,
        sponsorDiligence: true,
        irbIec: false,
        croOversight: true,
        siteOperational: true,
      },
      aiReviewPromptHash: DIGEST_C,
      humanReviewGates: ['quality_manager_review', 'principal_investigator_approval', 'decision_forum_material_change'],
      waiverRules: [
        {
          waiverType: 'site_specific_waiver',
          rationaleRequired: true,
          approverRole: 'quality_manager',
          maxDays: 90,
        },
      ],
      escalationRules: [
        { condition: 'critical_gap', role: 'quality_manager' },
        { condition: 'participant_safety_impact', role: 'principal_investigator' },
      ],
      capaLinkage: {
        requiredForCriticalFindings: true,
        requiredSeverity: 'major',
        capaControlRef: 'CM-QMS-CAPA-001',
      },
      auditExportMappings: [
        { audience: 'sponsor', fieldSetHash: DIGEST_D },
        { audience: 'internal_audit', fieldSetHash: DIGEST_E },
      ],
      dependencies: ['CM-QMS-DOC-001', 'CM-QMS-TRAINING-001'],
      crosswalkMappings: [
        { framework: 'ICH_E6_R3', reference: 'investigator-responsibilities', mappingHash: DIGEST_E },
        { framework: 'ISO_9001', reference: 'operational-control', mappingHash: DIGEST_F },
      ],
      status: 'active',
      materialChange: true,
      effectiveAtHlc: { physicalMs: 1794000000000, logical: 1 },
      retiredAtHlc: null,
      changeHistory: [
        {
          changeId: 'CHG-CM-QMS-PRODUCT-001-DRAFT',
          changeType: 'revision',
          rationaleHash: DIGEST_E,
          changedAtHlc: { physicalMs: 1793999998000, logical: 1 },
          approvedByDecisionId: 'df-control-library-product-draft',
        },
        {
          changeId: 'CHG-CM-QMS-PRODUCT-001-V1',
          changeType: 'initial_publication',
          rationaleHash: DIGEST_F,
          changedAtHlc: { physicalMs: 1793999999000, logical: 1 },
          approvedByDecisionId: 'df-control-library-product-001',
        },
      ],
    },
    governanceReview: {
      reviewed: true,
      decision: 'approve',
      reviewerDid: 'did:exo:control-reviewer-alpha',
      humanVerified: true,
      reviewHash: DIGEST_C,
      reviewedAtHlc: { physicalMs: 1794000000500, logical: 2 },
    },
    decisionForum: {
      verified: true,
      state: 'approved',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
      decisionId: 'df-control-library-product-001',
      workflowReceiptId: 'df-workflow-control-library-product-001',
    },
    evidenceBundle: { complete: true, phiBoundaryAttested: true },
    publishedAtHlc: { physicalMs: 1794000001000, logical: 3 },
    custodyDigest: DIGEST_B,
  };
}

function applicabilityInput(state = 'applicable') {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['govern'] },
    controlRef: {
      controlId: 'CM-QMS-PRODUCT-001',
      versionId: 'v1',
      status: 'active',
      controlFingerprint: DIGEST_A,
      controlVersionReceiptRef: 'cmr-control-version-product-001',
    },
    subject: {
      siteRef: 'site-alpha',
      studyRef: 'study-product-alpha',
      protocolRef: 'protocol-product-alpha-v1',
    },
    determination: {
      state,
      rationaleHash: DIGEST_C,
      criteriaEvidenceRefs: ['EVD-PRODUCT-STORAGE-001', 'EVD-PRODUCT-SOP-001'],
      approvedByDid: 'did:exo:quality-manager-alpha',
      approvedAtHlc: { physicalMs: 1794000010000, logical: 1 },
      conditionHash: state === 'conditionally_applicable' ? DIGEST_D : null,
      waiverRuleRef: state === 'waived' ? 'site_specific_waiver' : null,
      waiverExpiresAtHlc: state === 'waived' ? { physicalMs: 1794604810000, logical: 0 } : null,
      deferredUntilHlc: state === 'deferred' ? { physicalMs: 1794000010000, logical: 3 } : null,
      supersedingControlId: state === 'superseded' ? 'CM-QMS-PRODUCT-002' : null,
      supersedingVersionId: state === 'superseded' ? 'v1' : null,
    },
    approvalEvidence: {
      reviewed: true,
      humanVerified: true,
      approverRole: 'quality_manager',
      decisionHash: DIGEST_E,
    },
    custodyDigest: DIGEST_F,
  };
}

test('standards control versions require PRD fields and create deterministic inactive metadata receipts', async () => {
  const { publishStandardsControlVersion } = await loadStandardsControlLibrary();

  const resultA = publishStandardsControlVersion(standardsControlInput());
  const resultB = publishStandardsControlVersion({
    ...standardsControlInput(),
    control: {
      ...standardsControlInput().control,
      sourceRefs: [...standardsControlInput().control.sourceRefs].reverse(),
      applicabilityCriteria: [...standardsControlInput().control.applicabilityCriteria].reverse(),
      requiredEvidence: [...standardsControlInput().control.requiredEvidence].reverse(),
      triggerEvents: [...standardsControlInput().control.triggerEvents].reverse(),
      dependencies: [...standardsControlInput().control.dependencies].reverse(),
      crosswalkMappings: [...standardsControlInput().control.crosswalkMappings].reverse(),
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.controlVersion.status, 'active');
  assert.equal(resultA.controlVersion.materialChange, true);
  assert.equal(resultA.controlVersion.decisionForumDecisionId, 'df-control-library-product-001');
  assert.deepEqual(resultA.controlVersion.sourceRequirements, ['FR-003']);
  assert.equal(resultA.controlVersion.allPrdFieldsRepresented, true);
  assert.equal(resultA.controlVersion.metadataOnly, true);
  assert.equal(resultA.controlVersion.exochainProductionClaim, false);
  assert.deepEqual(resultA.controlVersion.sourceRefs, ['SRC-ICH-E6-R3-INV-001', 'SRC-QMS-CLAUSE-07-02']);
  assert.deepEqual(resultA.controlVersion.requiredEvidenceTypes, [
    'product_accountability_sop',
    'temperature_monitoring_process',
  ]);
  assert.equal(resultA.controlVersion.controlVersionId, resultB.controlVersion.controlVersionId);
  assert.equal(resultA.controlVersion.controlFingerprint, resultB.controlVersion.controlFingerprint);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'standards_control_version');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(resultA), /source document body|patient|participant alice|raw standard text/iu);
});

test('standards control versions fail closed for absent metadata governance and material review defects', async () => {
  const { publishStandardsControlVersion } = await loadStandardsControlLibrary();

  const denied = publishStandardsControlVersion({
    ...standardsControlInput(),
    actor: { did: 'did:exo:ai-control-agent', kind: 'ai_agent' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['write'] },
    control: {
      controlId: '',
      versionId: '',
      title: '',
      sourceRefs: [
        {
          sourceRefId: '',
          sourceType: '',
          sourceVersion: '',
          clauseRef: '',
          sourceHash: 'not-a-digest',
          rightsAttested: false,
        },
      ],
      normativeStatementHash: 'not-a-digest',
      plainLanguageExplanationHash: '',
      applicabilityCriteria: [],
      ownerRole: '',
      approverRole: '',
      reviewerRole: '',
      requiredEvidence: [],
      optionalEvidence: [{ artifactType: '', freshnessDays: -1, classification: 'raw', required: false, evidenceHash: '' }],
      reviewFrequencyDays: 0,
      triggerEvents: [],
      riskCriticality: 'unknown',
      relevance: {
        participantSafety: false,
        dataIntegrity: false,
        sponsorDiligence: false,
        irbIec: false,
        croOversight: false,
        siteOperational: false,
      },
      aiReviewPromptHash: '',
      humanReviewGates: [],
      waiverRules: [],
      escalationRules: [],
      capaLinkage: { requiredForCriticalFindings: true, requiredSeverity: 'unknown', capaControlRef: '' },
      auditExportMappings: [],
      dependencies: [],
      crosswalkMappings: [],
      status: 'retired',
      materialChange: true,
      effectiveAtHlc: null,
      retiredAtHlc: { physicalMs: 1793999990000, logical: 0 },
      changeHistory: [],
    },
    governanceReview: { reviewed: false, decision: 'reject', reviewerDid: '', humanVerified: false },
    decisionForum: {
      verified: true,
      state: 'approved',
      humanGate: { verified: false },
      quorum: { status: 'not_met' },
      openChallenge: true,
      decisionId: '',
      workflowReceiptId: '',
    },
    evidenceBundle: { complete: false, phiBoundaryAttested: false },
    publishedAtHlc: { physicalMs: null, logical: 0 },
    custodyDigest: 'not-a-digest',
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('control_id_absent'));
  assert.ok(denied.reasons.includes('control_source_rights_unattested:SRC-UNKNOWN'));
  assert.ok(denied.reasons.includes('normative_statement_hash_invalid'));
  assert.ok(denied.reasons.includes('plain_language_explanation_hash_invalid'));
  assert.ok(denied.reasons.includes('applicability_criteria_absent'));
  assert.ok(denied.reasons.includes('required_evidence_absent'));
  assert.ok(denied.reasons.includes('review_frequency_invalid'));
  assert.ok(denied.reasons.includes('control_relevance_absent'));
  assert.ok(denied.reasons.includes('human_review_gates_absent'));
  assert.ok(denied.reasons.includes('material_decision_forum_human_gate_unverified'));
  assert.ok(denied.reasons.includes('material_decision_forum_challenge_open'));
  assert.ok(denied.reasons.includes('governance_review_not_approved'));
  assert.ok(denied.reasons.includes('custody_digest_invalid'));
  assert.equal(denied.controlVersion, null);
  assert.equal(denied.receipt, null);
});

test('control applicability determinations cover all FR-004 states with rationale approval and inactive receipts', async () => {
  const { determineControlApplicability } = await loadStandardsControlLibrary();
  const states = ['applicable', 'not_applicable', 'conditionally_applicable', 'deferred', 'waived', 'superseded'];

  const results = states.map((state) => determineControlApplicability(applicabilityInput(state)));

  for (const [index, result] of results.entries()) {
    assert.equal(result.decision, 'permitted', states[index]);
    assert.equal(result.failClosed, false, states[index]);
    assert.equal(result.applicability.state, states[index]);
    assert.deepEqual(result.applicability.sourceRequirements, ['FR-004']);
    assert.equal(result.applicability.approvalRequired, true);
    assert.equal(result.applicability.rationaleRequired, true);
    assert.equal(result.applicability.metadataOnly, true);
    assert.equal(result.applicability.exochainProductionClaim, false);
    assert.equal(result.receipt.anchorPayload.artifactType, 'control_applicability_determination');
    assert.equal(result.receipt.trustState, 'inactive');
  }

  assert.equal(results[2].applicability.conditionHash, DIGEST_D);
  assert.equal(results[3].applicability.deferredUntilHlc.logical, 3);
  assert.equal(results[4].applicability.waiverRuleRef, 'site_specific_waiver');
  assert.equal(results[5].applicability.supersedingControlId, 'CM-QMS-PRODUCT-002');
  assert.equal(results[0].applicability.applicabilityId, determineControlApplicability(applicabilityInput('applicable')).applicability.applicabilityId);
  assert.doesNotMatch(JSON.stringify(results), /source document body|patient|participant alice|raw rationale/iu);
});

test('control applicability determinations fail closed for missing rationale approval and state-specific evidence', async () => {
  const { determineControlApplicability } = await loadStandardsControlLibrary();

  const denied = determineControlApplicability({
    ...applicabilityInput('waived'),
    actor: { did: 'did:exo:ai-control-agent', kind: 'ai_agent' },
    authority: { valid: false, revoked: true, expired: true, permissions: ['read'] },
    controlRef: {
      controlId: '',
      versionId: '',
      status: 'draft',
      controlFingerprint: 'not-a-digest',
      controlVersionReceiptRef: '',
    },
    subject: { siteRef: '', studyRef: '', protocolRef: '' },
    determination: {
      state: 'waived',
      rationaleHash: '',
      criteriaEvidenceRefs: [],
      approvedByDid: '',
      approvedAtHlc: null,
      conditionHash: null,
      waiverRuleRef: '',
      waiverExpiresAtHlc: null,
      deferredUntilHlc: null,
      supersedingControlId: null,
      supersedingVersionId: null,
    },
    approvalEvidence: { reviewed: false, humanVerified: false, approverRole: '', decisionHash: '' },
    custodyDigest: 'not-a-digest',
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_chain_invalid'));
  assert.ok(denied.reasons.includes('authority_chain_revoked'));
  assert.ok(denied.reasons.includes('authority_chain_expired'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('control_ref_id_absent'));
  assert.ok(denied.reasons.includes('control_ref_inactive'));
  assert.ok(denied.reasons.includes('control_fingerprint_invalid'));
  assert.ok(denied.reasons.includes('subject_site_ref_absent'));
  assert.ok(denied.reasons.includes('applicability_rationale_hash_invalid'));
  assert.ok(denied.reasons.includes('applicability_criteria_evidence_absent'));
  assert.ok(denied.reasons.includes('applicability_approval_unreviewed'));
  assert.ok(denied.reasons.includes('applicability_human_approval_unverified'));
  assert.ok(denied.reasons.includes('waiver_rule_ref_absent'));
  assert.ok(denied.reasons.includes('waiver_expiry_invalid'));
  assert.equal(denied.applicability, null);
  assert.equal(denied.receipt, null);
});

test('standards control library handles missing object branches as denial states', async () => {
  const { determineControlApplicability, publishStandardsControlVersion } = await loadStandardsControlLibrary();

  const controlDenied = publishStandardsControlVersion({
    tenantId: '',
    targetTenantId: 'tenant-site-alpha',
    actor: null,
    authority: null,
    control: null,
    governanceReview: null,
    decisionForum: null,
    evidenceBundle: null,
    publishedAtHlc: null,
    custodyDigest: null,
  });
  const applicabilityDenied = determineControlApplicability({
    tenantId: '',
    targetTenantId: 'tenant-site-alpha',
    actor: null,
    authority: null,
    controlRef: null,
    subject: null,
    determination: null,
    approvalEvidence: null,
    custodyDigest: null,
  });

  assert.equal(controlDenied.decision, 'denied');
  assert.equal(controlDenied.failClosed, true);
  assert.ok(controlDenied.reasons.includes('tenant_absent'));
  assert.ok(controlDenied.reasons.includes('tenant_boundary_violation'));
  assert.ok(controlDenied.reasons.includes('actor_did_absent'));
  assert.ok(controlDenied.reasons.includes('control_id_absent'));
  assert.ok(controlDenied.reasons.includes('source_refs_absent'));
  assert.ok(controlDenied.reasons.includes('governance_review_absent'));

  assert.equal(applicabilityDenied.decision, 'denied');
  assert.equal(applicabilityDenied.failClosed, true);
  assert.ok(applicabilityDenied.reasons.includes('tenant_absent'));
  assert.ok(applicabilityDenied.reasons.includes('control_ref_id_absent'));
  assert.ok(applicabilityDenied.reasons.includes('applicability_state_invalid'));
  assert.ok(applicabilityDenied.reasons.includes('applicability_approval_absent'));
});

test('standards control library rejects raw controlled text before creating receipts', async () => {
  const { determineControlApplicability, publishStandardsControlVersion } = await loadStandardsControlLibrary();

  assert.throws(
    () =>
      publishStandardsControlVersion({
        ...standardsControlInput(),
        control: {
          ...standardsControlInput().control,
          rawStandardText: 'Raw standard/license-controlled text must not be anchored in CyberMedica receipts.',
        },
      }),
    /raw control library content/i,
  );

  assert.throws(
    () =>
      determineControlApplicability({
        ...applicabilityInput('not_applicable'),
        determination: {
          ...applicabilityInput('not_applicable').determination,
          rawRationale: 'Participant Alice has no direct fit and this free text must not be anchored.',
        },
      }),
    /raw control library content|protected content/i,
  );
});
