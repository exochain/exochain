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

async function loadAiQualityReviewWorkbench() {
  try {
    return await import('../src/ai-quality-review-workbench.mjs');
  } catch (error) {
    assert.fail(`CyberMedica AI quality review workbench module must exist and load: ${error.message}`);
  }
}

const REQUIRED_AI_REVIEW_FUNCTIONS = Object.freeze([
  'clause_to_evidence_mapping',
  'evidence_completeness_analysis',
  'evidence_freshness_analysis',
  'evidence_contradiction_detection',
  'policy_procedure_gap_detection',
  'protocol_to_site_fit_analysis',
  'consent_readability_analysis',
  'consent_required_element_analysis',
  'vulnerable_population_safeguard_review',
  'recruitment_ethics_review',
  'risk_assessment_adequacy_review',
  'sae_ae_procedure_completeness_review',
  'deviation_procedure_completeness_review',
  'information_management_plan_review',
  'alcoac_support_review',
  'training_gap_detection',
  'delegation_mismatch_detection',
  'qualification_mismatch_detection',
  'facility_equipment_readiness_review',
  'clinical_trial_product_control_review',
  'communication_plan_adequacy_review',
  'open_finding_prioritization',
  'capa_root_cause_quality_review',
  'capa_effectiveness_check_suggestions',
  'kpi_trend_anomaly_detection',
  'sponsor_diligence_summary_generation',
  'audit_packet_assembly_recommendations',
  'decision_forum_brief_generation',
  'escalation_recommendations',
  'human_review_prompt_generation',
]);

const DIGESTS = [
  DIGEST_A,
  DIGEST_B,
  DIGEST_C,
  DIGEST_D,
  DIGEST_E,
  DIGEST_F,
  DIGEST_1,
  DIGEST_2,
  DIGEST_3,
  DIGEST_4,
  DIGEST_5,
  DIGEST_6,
  DIGEST_7,
  DIGEST_8,
  DIGEST_9,
];

function workbenchItem(functionFamily, index, overrides = {}) {
  return {
    itemRef: `AI-WB-${String(index + 1).padStart(2, '0')}`,
    functionFamily,
    sourceModuleRefs: ['src/ai-control-review.mjs', 'src/assistant-explainability.mjs'],
    evidenceRefs: [`EVD-AI-WB-${String(index + 1).padStart(2, '0')}`],
    inputManifestHash: DIGESTS[index % DIGESTS.length],
    outputHash: DIGESTS[(index + 1) % DIGESTS.length],
    reasoningSummaryHash: DIGESTS[(index + 2) % DIGESTS.length],
    limitationHashes: [DIGESTS[(index + 3) % DIGESTS.length]],
    unresolvedAssumptionHashes: index % 7 === 0 ? [DIGESTS[(index + 4) % DIGESTS.length]] : [],
    conflictRefs: index % 11 === 0 ? [`conflict-ai-review-${index + 1}`] : [],
    confidenceBasisPoints: 8_000 + index * 50,
    priority: index % 9 === 0 ? 'critical' : index % 4 === 0 ? 'high' : 'standard',
    status: index % 6 === 0 ? 'needs_human_review' : 'queued_for_review',
    recommendedHumanReviewerRole:
      index % 5 === 0 ? 'principal_investigator' : index % 3 === 0 ? 'data_integrity_owner' : 'quality_manager',
    escalationRecommended: index % 9 === 0,
    decisionForumCandidate: functionFamily === 'decision_forum_brief_generation' || index % 10 === 0,
    humanPromptHash: DIGESTS[(index + 5) % DIGESTS.length],
    createdAtHlc: { physicalMs: 1796200000000, logical: index + 4 },
    metadataOnly: true,
    finalAuthority: false,
    ...overrides,
  };
}

function aiQualityReviewWorkbenchInput(overrides = {}) {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:ai-quality-reviewer-human-alpha',
      kind: 'human',
      roleRefs: ['ai_quality_reviewer'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['ai_quality_workbench_review', 'read'],
      authorityChainHash: DIGEST_A,
    },
    workbench: {
      workbenchRef: 'AI-QA-WORKBENCH-SITE-ALPHA',
      schemaVersion: 'cybermedica.ai_quality_review_workbench.v1',
      role: 'ai_quality_reviewer',
      generatedAtHlc: { physicalMs: 1796200000000, logical: 1 },
      sourceIndexHash: DIGEST_B,
      modelRegistryHash: DIGEST_C,
      promptLibraryHash: DIGEST_D,
      metadataOnly: true,
      rawPayloadExcluded: true,
      productionTrustClaim: false,
    },
    aiReviewPolicy: {
      policyRef: 'AI-QUALITY-WORKBENCH-POLICY-2026-05',
      policyHash: DIGEST_E,
      status: 'active',
      requiredFunctionFamilies: REQUIRED_AI_REVIEW_FUNCTIONS,
      allowedReviewerRoles: ['quality_manager', 'principal_investigator', 'data_integrity_owner', 'site_quality_lead'],
      assistanceOnly: true,
      allowAiFinalAuthority: false,
      requiresEvidenceRefs: true,
      requiresHumanPrompt: true,
      requiresConfidenceLimits: true,
      contestable: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1796200000000, logical: 2 },
    },
    reviewItems: REQUIRED_AI_REVIEW_FUNCTIONS.map((functionFamily, index) => workbenchItem(functionFamily, index)),
    humanReview: {
      reviewerDid: 'did:exo:site-quality-lead-alpha',
      reviewerRole: 'site_quality_lead',
      reviewedAtHlc: { physicalMs: 1796200000000, logical: 60 },
      decision: 'workbench_ready_inactive_trust',
      evidenceBundleHash: DIGEST_F,
      decisionForumEscalationPolicyRef: 'DF-ESC-AI-WORKBENCH-2026-05',
      contextRefs: [
        'cybermedica_2_0_sandy_seven_layer_master_prd.md:AI Quality Review Layer',
        'cybermedica_2_0_sandy_seven_layer_master_prd.md:Doors Backlog:AI Quality Review Workbench',
      ],
      activationOnlyBlockersAccepted: true,
    },
    custodyDigest: DIGEST_1,
    ...overrides,
  };
}

test('AI quality review workbench covers all PRD AI review functions as advisory inactive work queues', async () => {
  const { evaluateAiQualityReviewWorkbench } = await loadAiQualityReviewWorkbench();

  const input = aiQualityReviewWorkbenchInput();
  const reversedInput = {
    ...input,
    aiReviewPolicy: {
      ...input.aiReviewPolicy,
      allowedReviewerRoles: [...input.aiReviewPolicy.allowedReviewerRoles].reverse(),
      requiredFunctionFamilies: [...input.aiReviewPolicy.requiredFunctionFamilies].reverse(),
    },
    reviewItems: [...input.reviewItems].reverse(),
  };

  const resultA = evaluateAiQualityReviewWorkbench(input);
  const resultB = evaluateAiQualityReviewWorkbench(reversedInput);

  assert.equal(resultA.status, 'ready');
  assert.deepEqual(resultA.denialReasons, []);
  assert.equal(resultA.trustState, 'inactive');
  assert.equal(resultA.exochainProductionClaim, false);
  assert.equal(resultA.canShowProductionTrustClaim, false);
  assert.equal(resultA.workbench.assistanceOnly, true);
  assert.equal(resultA.workbench.aiFinalAuthority, false);
  assert.deepEqual(resultA.workbench.requiredFunctionFamilies, REQUIRED_AI_REVIEW_FUNCTIONS);
  assert.deepEqual(resultA.workbench.functionFamiliesCovered, REQUIRED_AI_REVIEW_FUNCTIONS);
  assert.equal(resultA.workbench.summary.reviewItemCount, REQUIRED_AI_REVIEW_FUNCTIONS.length);
  assert.equal(resultA.workbench.summary.decisionForumCandidateCount, 4);
  assert.equal(resultA.workbench.summary.escalationRecommendedCount, 4);
  assert.deepEqual(resultA.workbench.humanReviewQueue.slice(0, 3), [
    'data_integrity_owner:AI-WB-04',
    'data_integrity_owner:AI-WB-07',
    'data_integrity_owner:AI-WB-10',
  ]);
  assert.deepEqual(resultA.workbench.escalationQueue, [
    'AI-WB-01:clause_to_evidence_mapping',
    'AI-WB-10:recruitment_ethics_review',
    'AI-WB-19:facility_equipment_readiness_review',
    'AI-WB-28:decision_forum_brief_generation',
  ]);
  assert.equal(resultA.workbench.workbenchHash, resultB.workbench.workbenchHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'ai_quality_review_workbench');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(resultA), /raw ai output|source document body|participant alice|secret token/iu);
});

test('AI quality review workbench fails closed for missing coverage final authority and invalid review evidence', async () => {
  const { evaluateAiQualityReviewWorkbench } = await loadAiQualityReviewWorkbench();
  const input = aiQualityReviewWorkbenchInput({
    actor: { did: 'did:exo:ai-agent-reviewer-alpha', kind: 'ai_agent', roleRefs: ['ai_quality_reviewer'] },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['read'],
      authorityChainHash: DIGEST_A,
    },
  });
  input.workbench = {
    ...input.workbench,
    productionTrustClaim: true,
    rawPayloadExcluded: false,
  };
  input.aiReviewPolicy = {
    ...input.aiReviewPolicy,
    requiredFunctionFamilies: input.aiReviewPolicy.requiredFunctionFamilies.slice(1),
    allowedReviewerRoles: [],
    assistanceOnly: false,
    allowAiFinalAuthority: true,
    requiresEvidenceRefs: false,
    requiresHumanPrompt: false,
    requiresConfidenceLimits: false,
    contestable: false,
    metadataOnly: false,
    protectedContentExcluded: false,
    evaluatedAtHlc: { physicalMs: 1796200000000, logical: -1 },
  };
  input.reviewItems = input.reviewItems.slice(1);
  input.reviewItems[0] = {
    ...input.reviewItems[0],
    sourceModuleRefs: [],
    evidenceRefs: [],
    outputHash: 'not-a-digest',
    limitationHashes: [],
    confidenceBasisPoints: 10_001,
    status: 'approved_by_ai',
    recommendedHumanReviewerRole: '',
    humanPromptHash: '',
    finalAuthority: true,
    metadataOnly: false,
  };
  input.humanReview = {
    ...input.humanReview,
    decision: 'ai_final_approval',
    reviewedAtHlc: { physicalMs: 1796199999999, logical: 0 },
    evidenceBundleHash: '',
    activationOnlyBlockersAccepted: false,
  };

  const result = evaluateAiQualityReviewWorkbench(input);

  assert.equal(result.status, 'denied');
  assert.equal(result.receipt, null);
  assert.equal(result.workbench, null);
  assert.ok(result.denialReasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.denialReasons.includes('human_actor_required'));
  assert.ok(result.denialReasons.includes('ai_quality_workbench_authority_missing'));
  assert.ok(result.denialReasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.denialReasons.includes('workbench_raw_payload_boundary_invalid'));
  assert.ok(result.denialReasons.includes('policy_required_function_missing:clause_to_evidence_mapping'));
  assert.ok(result.denialReasons.includes('required_function_missing:clause_to_evidence_mapping'));
  assert.ok(result.denialReasons.includes('allowed_reviewer_roles_absent'));
  assert.ok(result.denialReasons.includes('ai_assistance_only_policy_absent'));
  assert.ok(result.denialReasons.includes('policy_allows_ai_final_authority'));
  assert.ok(result.denialReasons.includes('policy_evidence_refs_requirement_absent'));
  assert.ok(result.denialReasons.includes('policy_human_prompt_requirement_absent'));
  assert.ok(result.denialReasons.includes('policy_confidence_limits_requirement_absent'));
  assert.ok(result.denialReasons.includes('policy_contestation_absent'));
  assert.ok(result.denialReasons.includes('policy_metadata_boundary_invalid'));
  assert.ok(result.denialReasons.includes('policy_protected_boundary_invalid'));
  assert.ok(result.denialReasons.includes('policy_time_invalid'));
  assert.ok(result.denialReasons.includes('item_source_module_refs_absent:AI-WB-02'));
  assert.ok(result.denialReasons.includes('item_evidence_refs_absent:AI-WB-02'));
  assert.ok(result.denialReasons.includes('item_output_hash_invalid:AI-WB-02'));
  assert.ok(result.denialReasons.includes('item_limitation_hashes_absent:AI-WB-02'));
  assert.ok(result.denialReasons.includes('item_confidence_invalid:AI-WB-02'));
  assert.ok(result.denialReasons.includes('item_status_invalid:AI-WB-02'));
  assert.ok(result.denialReasons.includes('item_reviewer_role_absent:AI-WB-02'));
  assert.ok(result.denialReasons.includes('item_human_prompt_hash_invalid:AI-WB-02'));
  assert.ok(result.denialReasons.includes('item_final_authority_forbidden:AI-WB-02'));
  assert.ok(result.denialReasons.includes('item_metadata_boundary_invalid:AI-WB-02'));
  assert.ok(result.denialReasons.includes('human_review_time_before_workbench'));
  assert.ok(result.denialReasons.includes('human_review_decision_invalid'));
  assert.ok(result.denialReasons.includes('human_review_evidence_bundle_hash_invalid'));
  assert.ok(result.denialReasons.includes('activation_only_blockers_not_accepted'));
});

test('AI quality review workbench rejects raw AI output protected source content and secrets', async () => {
  const { evaluateAiQualityReviewWorkbench, ProtectedContentError } = await loadAiQualityReviewWorkbench();

  assert.throws(
    () =>
      evaluateAiQualityReviewWorkbench({
        ...aiQualityReviewWorkbenchInput(),
        reviewItems: [
          {
            ...aiQualityReviewWorkbenchInput().reviewItems[0],
            rawAiOutput: 'AI free text is not accepted here',
          },
          ...aiQualityReviewWorkbenchInput().reviewItems.slice(1),
        ],
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateAiQualityReviewWorkbench({
        ...aiQualityReviewWorkbenchInput(),
        workbench: {
          ...aiQualityReviewWorkbenchInput().workbench,
          sourceDocumentBody: 'participant Alice source note',
        },
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateAiQualityReviewWorkbench({
        ...aiQualityReviewWorkbenchInput(),
        aiReviewPolicy: {
          ...aiQualityReviewWorkbenchInput().aiReviewPolicy,
          apiToken: 'secret token must not be accepted',
        },
      }),
    ProtectedContentError,
  );
});
