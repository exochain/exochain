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
const DIGEST_5 = '5555555555555555555555555555555555555555555555555555555555555555';
const DIGEST_6 = '6666666666666666666666666666666666666666666666666666666666666666';
const DIGEST_7 = '7777777777777777777777777777777777777777777777777777777777777777';
const DIGEST_8 = '8888888888888888888888888888888888888888888888888888888888888888';
const DIGEST_9 = '9999999999999999999999999999999999999999999999999999999999999999';

const REQUIRED_DOCUMENTATION_DOMAINS = [
  'administrator_runbook',
  'ai_orientation_assistant',
  'audit_inspector_mode',
  'contextual_manual_drawer',
  'evidence_checklists',
  'inquiry_cqi_reporting',
  'policy_procedure_crosslinks',
  'role_manuals',
  'version_governance',
  'workflow_guides',
];

const REQUIRED_ROLE_MANUALS = [
  'administrator',
  'auditor_inspector',
  'clinical_research_coordinator',
  'cro_portfolio_manager',
  'decision_forum_member',
  'principal_investigator',
  'quality_manager',
  'site_leader',
  'sponsor_viewer',
];

const REQUIRED_INSPECTION_EVIDENCE = [
  'access_logs',
  'chain_of_custody',
  'corrective_actions',
  'decision_rationale',
  'document_version_history',
  'evidence_traceability',
  'exportable_audit_packet',
  'issue_history',
  'role_delegation_records',
  'staff_training_records',
];

const REQUIRED_DOCUMENTATION_ARTIFACTS = [
  'cybermedica_user_manual',
  'site_leader_manual',
  'principal_investigator_manual',
  'coordinator_site_staff_manual',
  'quality_manager_manual',
  'cro_portfolio_manual',
  'sponsor_viewer_manual',
  'auditor_monitor_inspector_manual',
  'decision_forum_manual',
  'ai_quality_review_manual',
  'tenant_administrator_manual',
  'system_administrator_manual',
  'evidence_chain_of_custody_manual',
  'protocol_readiness_launch_gate_manual',
  'consent_participant_protection_manual',
  'deviation_capa_manual',
  'training_delegation_manual',
  'clinical_trial_product_accountability_manual',
  'exochain_receipts_privacy_anchoring_guide',
  'support_access_break_glass_emergency_runbook',
  'sponsor_cro_diligence_packet_guide',
  'audit_inspection_packet_guide',
  'ai_governance_model_use_policy',
  'deployment_backup_recovery_incident_response_runbook',
];

async function loadDocumentationRunbooks() {
  try {
    return await import('../src/documentation-runbooks.mjs');
  } catch (error) {
    assert.fail(`CyberMedica documentation runbooks module must exist and load: ${error.message}`);
  }
}

function mergeDeep(base, overrides) {
  if (Array.isArray(base) || Array.isArray(overrides)) {
    return overrides === undefined ? base : overrides;
  }
  if (base === null || overrides === null || typeof base !== 'object' || typeof overrides !== 'object') {
    return overrides === undefined ? base : overrides;
  }
  return Object.fromEntries(
    [...new Set([...Object.keys(base), ...Object.keys(overrides)])].map((key) => [
      key,
      mergeDeep(base[key], overrides[key]),
    ]),
  );
}

function documentationDomain(domain, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4];
  return {
    domain,
    status: 'ready',
    artifactRef: `manual-domain-${domain}`,
    artifactHash: hashes[index],
    ownerDid: `did:exo:${domain.replaceAll('_', '-')}-owner`,
    reviewerDid: `did:exo:${domain.replaceAll('_', '-')}-reviewer`,
    reviewedByHuman: true,
    reviewedAtHlc: { physicalMs: 1800005100000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function documentationDomains() {
  return REQUIRED_DOCUMENTATION_DOMAINS.map((domain, index) => documentationDomain(domain, index));
}

function roleManual(role, index, overrides = {}) {
  const hashes = [DIGEST_5, DIGEST_6, DIGEST_7, DIGEST_8, DIGEST_9, DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D];
  return {
    role,
    manualRef: `role-manual-${role}`,
    versionRef: `role-manual-${role}-v1`,
    versionHash: hashes[index],
    workflowGuideRefs: ['workflow-trial-startup', 'workflow-evidence-intake', 'workflow-decision-forum'],
    evidenceChecklistRefs: ['checklist-quality-evidence', 'checklist-controlled-documents'],
    accessPolicyHash: DIGEST_E,
    plainLanguageSummaryHash: DIGEST_F,
    approvedForUse: true,
    reviewedAtHlc: { physicalMs: 1800005100000, logical: 20 + index },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function roleManuals() {
  return REQUIRED_ROLE_MANUALS.map((role, index) => roleManual(role, index));
}

function inspectionEvidence(kind, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4];
  return {
    kind,
    packetRef: `inspection-evidence-${kind}`,
    packetHash: hashes[index],
    accessPolicyRef: 'audit-inspector-access-policy',
    exportEligible: true,
    retainedForInspection: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    reviewedAtHlc: { physicalMs: 1800005150000, logical: index },
    ...overrides,
  };
}

function inspectionEvidenceItems() {
  return REQUIRED_INSPECTION_EVIDENCE.map((kind, index) => inspectionEvidence(kind, index));
}

function documentationArtifact(artifact, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4];
  return {
    artifact,
    artifactRef: `documentation-artifact-${artifact}`,
    versionRef: `documentation-artifact-${artifact}-v1`,
    artifactHash: hashes[index % hashes.length],
    ownerRoleRef: index % 2 === 0 ? 'quality_manager' : 'documentation_owner',
    targetAudienceRoleRefs: ['quality_manager', 'site_leader'],
    crosslinkRefs: ['manual-crosslink-matrix-alpha', 'policy-procedure-rule-register-alpha'],
    approvedForSandyReview: true,
    reviewedByHuman: true,
    reviewedAtHlc: { physicalMs: 1800005180000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function documentationArtifacts() {
  return REQUIRED_DOCUMENTATION_ARTIFACTS.map((artifact, index) => documentationArtifact(artifact, index));
}

function runbookInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:documentation-owner-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'administrator'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['documentation_runbook_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    documentationPolicy: {
      policyRef: 'documentation-runbook-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredDocumentationDomains: REQUIRED_DOCUMENTATION_DOMAINS,
      requiredRoleManuals: REQUIRED_ROLE_MANUALS,
      requiredInspectionEvidenceKinds: REQUIRED_INSPECTION_EVIDENCE,
      requiredDocumentationArtifacts: REQUIRED_DOCUMENTATION_ARTIFACTS,
      manualVersionGovernanceRequired: true,
      aiOrientationAdvisoryOnly: true,
      inquiryCqiRoutingRequired: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800005000000, logical: 0 },
    },
    documentationCycle: {
      cycleRef: 'documentation-runbook-cycle-alpha',
      openedAtHlc: { physicalMs: 1800005050000, logical: 0 },
      manualReviewAtHlc: { physicalMs: 1800005200000, logical: 0 },
      humanApprovedAtHlc: { physicalMs: 1800005300000, logical: 0 },
      publishedAtHlc: { physicalMs: 1800005400000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    documentationDomains: documentationDomains(),
    roleManuals: roleManuals(),
    documentationArtifacts: documentationArtifacts(),
    crosslinkMatrix: {
      matrixRef: 'manual-crosslink-matrix-alpha',
      matrixHash: DIGEST_C,
      linksControls: true,
      linksEvidence: true,
      linksProcedures: true,
      linksWorkflows: true,
      linksPolicies: true,
      brokenLinkCount: 0,
      reviewedAtHlc: { physicalMs: 1800005200000, logical: 10 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    inspectionGuide: {
      guideRef: 'audit-inspector-guide-alpha',
      guideHash: DIGEST_D,
      modeEnabledForAuthorizedAuditorsOnly: true,
      accessPolicyHash: DIGEST_E,
      exportPolicyHash: DIGEST_F,
      suppressedProtectedContent: true,
      disclosureLogRequired: true,
      evidenceKinds: inspectionEvidenceItems(),
      reviewedAtHlc: { physicalMs: 1800005200000, logical: 11 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    aiOrientation: {
      assistantRef: 'ai-orientation-assistant-alpha',
      promptPolicyHash: DIGEST_1,
      scopeHash: DIGEST_2,
      finalAuthority: false,
      advisoryOnly: true,
      routesUnresolvedQuestionsToHuman: true,
      confidenceFloorBasisPoints: 8000,
      reviewedByHuman: true,
      reviewedAtHlc: { physicalMs: 1800005200000, logical: 12 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    inquiryCqiReporting: {
      intakeRef: 'inquiry-cqi-intake-alpha',
      intakeHash: DIGEST_3,
      frictionTagSetHash: DIGEST_4,
      cqiActionPolicyHash: DIGEST_5,
      routesToQualityOwner: true,
      permitsAnonymousInquiry: true,
      noRetaliationReminderHash: DIGEST_6,
      reviewedAtHlc: { physicalMs: 1800005200000, logical: 13 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    versionGovernance: {
      currentManualSetHash: DIGEST_7,
      priorManualSetHash: DIGEST_8,
      changeControlRef: 'manual-change-control-alpha',
      supersededVersionRetained: true,
      effectiveUseAcknowledgementRequired: true,
      distributionEvidenceHash: DIGEST_9,
      approvedByHuman: true,
      approvedAtHlc: { physicalMs: 1800005300000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    validationEvidence: {
      commandRefs: ['npm run quality'],
      commandsPassed: true,
      sourceGuardPassed: true,
      noExochainSourceModified: true,
      recordedAtHlc: { physicalMs: 1800005350000, logical: 0 },
      metadataOnly: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-director-alpha',
      reviewerRoleRefs: ['quality_manager', 'administrator'],
      decision: 'documentation_pack_ready',
      decisionHash: DIGEST_A,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      reviewedAtHlc: { physicalMs: 1800005300000, logical: 0 },
      metadataOnly: true,
    },
    custodyDigest: DIGEST_B,
  };
  return mergeDeep(base, overrides);
}

test('documentation runbook readiness creates deterministic manual and inspection guide receipts', async () => {
  const { evaluateDocumentationRunbookReadiness } = await loadDocumentationRunbooks();

  const resultA = evaluateDocumentationRunbookReadiness(runbookInput());
  const resultB = evaluateDocumentationRunbookReadiness(
    runbookInput({
      documentationPolicy: {
        requiredDocumentationDomains: [...REQUIRED_DOCUMENTATION_DOMAINS].reverse(),
        requiredRoleManuals: [...REQUIRED_ROLE_MANUALS].reverse(),
        requiredInspectionEvidenceKinds: [...REQUIRED_INSPECTION_EVIDENCE].reverse(),
        requiredDocumentationArtifacts: [...REQUIRED_DOCUMENTATION_ARTIFACTS].reverse(),
      },
      documentationDomains: [...documentationDomains()].reverse(),
      roleManuals: [...roleManuals()].reverse(),
      documentationArtifacts: [...documentationArtifacts()].reverse(),
      inspectionGuide: {
        evidenceKinds: [...inspectionEvidenceItems()].reverse(),
      },
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.documentationReadiness.ready, true);
  assert.equal(resultA.documentationReadiness.trustState, 'inactive');
  assert.equal(resultA.documentationReadiness.exochainProductionClaim, false);
  assert.equal(resultA.documentationReadiness.roleManualCount, REQUIRED_ROLE_MANUALS.length);
  assert.equal(resultA.documentationReadiness.documentationArtifactCount, REQUIRED_DOCUMENTATION_ARTIFACTS.length);
  assert.equal(resultA.documentationReadiness.inspectionEvidenceCount, REQUIRED_INSPECTION_EVIDENCE.length);
  assert.deepEqual(resultA.documentationReadiness.missingDocumentationDomains, []);
  assert.deepEqual(resultA.documentationReadiness.missingRoleManuals, []);
  assert.deepEqual(resultA.documentationReadiness.missingDocumentationArtifacts, []);
  assert.equal(resultA.receipt.containsProtectedContent, false);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.documentationReadiness.documentationDigest, resultB.documentationReadiness.documentationDigest);
});

test('documentation runbook readiness fails closed for missing documentation domains and role manuals', async () => {
  const { evaluateDocumentationRunbookReadiness } = await loadDocumentationRunbooks();

  const result = evaluateDocumentationRunbookReadiness(
    runbookInput({
      documentationDomains: documentationDomains().filter((row) => row.domain !== 'contextual_manual_drawer'),
      roleManuals: roleManuals().filter((row) => row.role !== 'principal_investigator'),
      crosslinkMatrix: {
        linksEvidence: false,
        brokenLinkCount: 2,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('documentation_domain_missing:contextual_manual_drawer'));
  assert.ok(result.reasons.includes('role_manual_missing:principal_investigator'));
  assert.ok(result.reasons.includes('crosslink_evidence_missing'));
  assert.ok(result.reasons.includes('manual_crosslink_matrix_has_broken_links'));
});

test('documentation runbook readiness requires the full Sandy review artifact catalog', async () => {
  const { evaluateDocumentationRunbookReadiness } = await loadDocumentationRunbooks();

  const result = evaluateDocumentationRunbookReadiness(
    runbookInput({
      documentationArtifacts: [
        ...documentationArtifacts().filter((row) => row.artifact !== 'ai_quality_review_manual'),
        documentationArtifact('tenant_administrator_manual', 10, {
          approvedForSandyReview: false,
          crosslinkRefs: [],
        }),
      ],
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('documentation_artifact_missing:ai_quality_review_manual'));
  assert.ok(
    result.reasons.includes('documentation_artifact_invalid:tenant_administrator_manual:not_approved_for_sandy_review'),
  );
  assert.ok(result.reasons.includes('documentation_artifact_invalid:tenant_administrator_manual:crosslink_refs_absent'));
  assert.deepEqual(result.documentationReadiness.missingDocumentationArtifacts, ['ai_quality_review_manual']);
});

test('documentation runbook readiness requires complete audit and inspection evidence', async () => {
  const { evaluateDocumentationRunbookReadiness } = await loadDocumentationRunbooks();

  const result = evaluateDocumentationRunbookReadiness(
    runbookInput({
      inspectionGuide: {
        modeEnabledForAuthorizedAuditorsOnly: false,
        suppressedProtectedContent: false,
        disclosureLogRequired: false,
        evidenceKinds: inspectionEvidenceItems().filter((row) => row.kind !== 'chain_of_custody'),
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('inspection_evidence_missing:chain_of_custody'));
  assert.ok(result.reasons.includes('inspection_mode_not_authorized_auditor_only'));
  assert.ok(result.reasons.includes('inspection_protected_content_suppression_missing'));
  assert.ok(result.reasons.includes('inspection_disclosure_log_missing'));
});

test('documentation runbook readiness enforces AI advisory limits and CQI routing', async () => {
  const { evaluateDocumentationRunbookReadiness } = await loadDocumentationRunbooks();

  const result = evaluateDocumentationRunbookReadiness(
    runbookInput({
      aiOrientation: {
        finalAuthority: true,
        advisoryOnly: false,
        routesUnresolvedQuestionsToHuman: false,
        confidenceFloorBasisPoints: 10001,
      },
      inquiryCqiReporting: {
        routesToQualityOwner: false,
        cqiActionPolicyHash: null,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('ai_orientation_final_authority_forbidden'));
  assert.ok(result.reasons.includes('ai_orientation_not_advisory_only'));
  assert.ok(result.reasons.includes('ai_orientation_human_routing_missing'));
  assert.ok(result.reasons.includes('ai_orientation_confidence_floor_invalid'));
  assert.ok(result.reasons.includes('inquiry_cqi_quality_owner_route_missing'));
  assert.ok(result.reasons.includes('inquiry_cqi_action_policy_hash_invalid'));
});

test('documentation runbook readiness validates HLC ordering and human publication authority', async () => {
  const { evaluateDocumentationRunbookReadiness } = await loadDocumentationRunbooks();

  const result = evaluateDocumentationRunbookReadiness(
    runbookInput({
      documentationCycle: {
        manualReviewAtHlc: { physicalMs: 1800005050000, logical: 0 },
        publishedAtHlc: { physicalMs: 1800005299999, logical: 0 },
      },
      actor: {
        kind: 'ai_agent',
      },
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
        noProductionTrustClaim: false,
      },
      versionGovernance: {
        approvedAtHlc: { physicalMs: 1800005200000, logical: 0 },
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('human_documentation_reviewer_required'));
  assert.ok(result.reasons.includes('manual_review_time_not_after_open'));
  assert.ok(result.reasons.includes('publication_time_not_after_human_approval'));
  assert.ok(result.reasons.includes('manual_version_approval_time_not_after_review'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
});

test('documentation runbook readiness handles absent objects malformed HLC and inert sensitivity markers', async () => {
  const { ProtectedContentError, evaluateDocumentationRunbookReadiness } = await loadDocumentationRunbooks();

  const absent = evaluateDocumentationRunbookReadiness({});

  assert.equal(absent.decision, 'denied');
  assert.equal(absent.failClosed, true);
  assert.ok(absent.reasons.includes('tenant_absent'));
  assert.ok(absent.reasons.includes('documentation_policy_ref_absent'));
  assert.ok(absent.reasons.includes('manual_version_approval_time_invalid'));

  const malformed = evaluateDocumentationRunbookReadiness(
    runbookInput({
      documentationPolicy: {
        evaluatedAtHlc: { physicalMs: '1800005000000', logical: 0 },
      },
      roleManuals: [
        roleManual('administrator', 0, {
          rawManualText: false,
          rawGuideContent: [null, false],
          apiKey: {},
        }),
        ...roleManuals().slice(1),
      ],
    }),
  );

  assert.equal(malformed.decision, 'denied');
  assert.equal(malformed.failClosed, true);
  assert.ok(malformed.reasons.includes('documentation_policy_time_invalid'));

  assert.throws(
    () =>
      evaluateDocumentationRunbookReadiness(
        runbookInput({
          documentationPolicy: {
            apiKey: 123,
          },
        }),
      ),
    ProtectedContentError,
  );
});

test('documentation runbook readiness rejects raw manual content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateDocumentationRunbookReadiness } = await loadDocumentationRunbooks();

  assert.throws(
    () =>
      evaluateDocumentationRunbookReadiness(
        runbookInput({
          roleManuals: [
            roleManual('site_leader', 0, {
              rawManualText: 'This is raw manual body text that belongs in controlled storage, not a receipt.',
            }),
            ...roleManuals().slice(1),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDocumentationRunbookReadiness(
        runbookInput({
          documentationDomains: [
            documentationDomain('contextual_manual_drawer', 0, {
              participantName: 'Participant Jane',
            }),
            ...documentationDomains().slice(1),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDocumentationRunbookReadiness(
        runbookInput({
          documentationPolicy: {
            apiKey: 'secret-api-key',
          },
        }),
      ),
    ProtectedContentError,
  );
});
