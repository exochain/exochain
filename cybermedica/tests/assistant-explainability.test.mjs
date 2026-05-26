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

const REQUIRED_OUTPUT_CLASSES = [
  'ai_control_review',
  'audit_assessment_review',
  'decision_support_summary',
  'kpi_trend_analysis',
  'orientation_guidance',
  'reporting_export_explanation',
  'workflow_guidance',
];

async function loadAssistantExplainability() {
  try {
    return await import('../src/assistant-explainability.mjs');
  } catch (error) {
    assert.fail(`CyberMedica assistant explainability module must exist and load: ${error.message}`);
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

function outputFor(outputClass, index) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1];
  const aiBacked = outputClass !== 'orientation_guidance';
  const reviewerRoles = index % 2 === 0 ? ['quality_manager', 'site_quality_lead'] : ['principal_investigator'];
  return {
    outputRef: `asst-output-${outputClass}`,
    outputClass,
    assistantKind: aiBacked ? 'ai_assistant' : 'rules_assistant',
    modelRefHash: aiBacked ? hashes[index % hashes.length] : null,
    generatorPolicyHash: aiBacked ? null : DIGEST_4,
    promptHash: hashes[(index + 1) % hashes.length],
    inputManifestHash: hashes[(index + 2) % hashes.length],
    outputHash: hashes[(index + 3) % hashes.length],
    generatedAtHlc: { physicalMs: 1797000000000 + index * 1000, logical: 0 },
    evidenceRefs: [`evidence-${outputClass}-001`, `evidence-${outputClass}-002`],
    evidenceManifestHash: hashes[(index + 4) % hashes.length],
    reasoningSummaryHash: hashes[(index + 5) % hashes.length],
    confidenceBasisPoints: 7600 + index * 300,
    limitationHashes: [hashes[(index + 6) % hashes.length]],
    unresolvedAssumptionHashes: index % 3 === 0 ? [hashes[index % hashes.length]] : [],
    unresolvedAssumptionsReviewed: true,
    recommendedHumanReviewerRoles: reviewerRoles,
    requiresHumanReview: true,
    advisoryOnly: true,
    finalAuthority: false,
    canOpenCqiItem: outputClass === 'orientation_guidance',
    metadataOnly: true,
  };
}

function assignment(roleRef, outputRefs, index) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F];
  return {
    roleRef,
    queueRef: `review-queue-${roleRef}`,
    outputRefs,
    required: true,
    acceptanceCriteriaHash: hashes[index % hashes.length],
    escalationRoleRef: roleRef === 'principal_investigator' ? 'decision_forum_chair' : 'site_quality_lead',
    metadataOnly: true,
  };
}

function explainabilityInput(overrides = {}) {
  const outputs = REQUIRED_OUTPUT_CLASSES.map(outputFor).reverse();
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:explainability-governor-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'site_leader'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['explainability_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    explainabilityPolicy: {
      policyRef: 'nfr-011-explainability-policy-alpha',
      schemaVersion: 'cybermedica.assistant_explainability_policy.v1',
      status: 'approved',
      requiredOutputClasses: REQUIRED_OUTPUT_CLASSES.toReversed(),
      requiredExplanationFields: [
        'confidence',
        'evidence_references',
        'limitations',
        'reasoning_summary',
        'recommended_human_reviewers',
        'unresolved_assumptions',
      ],
      allowedReviewerRoles: [
        'decision_forum_chair',
        'principal_investigator',
        'quality_manager',
        'site_quality_lead',
      ],
      minimumConfidenceForDisplayBasisPoints: 7000,
      humanReviewRequired: true,
      contestable: true,
      aiFinalAuthorityAllowed: false,
      sourceBoundaryHash: DIGEST_B,
      humanReviewPolicyHash: DIGEST_C,
      retentionPolicyHash: DIGEST_D,
      metadataOnly: true,
    },
    outputs,
    reviewRouting: {
      routeRef: 'assistant-explainability-route-alpha',
      generatedAtHlc: { physicalMs: 1797000010000, logical: 0 },
      queuedAtHlc: { physicalMs: 1797000010000, logical: 1 },
      dueAtHlc: { physicalMs: 1797086410000, logical: 0 },
      reviewerAssignments: [
        assignment('principal_investigator', ['asst-output-audit_assessment_review', 'asst-output-decision_support_summary'], 0),
        assignment(
          'quality_manager',
          [
            'asst-output-ai_control_review',
            'asst-output-kpi_trend_analysis',
            'asst-output-orientation_guidance',
            'asst-output-reporting_export_explanation',
            'asst-output-workflow_guidance',
          ],
          1,
        ),
        assignment('site_quality_lead', ['asst-output-ai_control_review', 'asst-output-kpi_trend_analysis'], 2),
      ],
      escalationPathRef: 'decision-forum-escalation-alpha',
      disclosureLogHash: DIGEST_E,
      metadataOnly: true,
    },
    custodyDigest: DIGEST_F,
  };

  return mergeDeep(base, overrides);
}

test('assistant explainability creates deterministic NFR-011 inactive receipts and review routing', async () => {
  const { evaluateAssistantExplainability } = await loadAssistantExplainability();

  const resultA = evaluateAssistantExplainability(explainabilityInput());
  const resultB = evaluateAssistantExplainability(explainabilityInput({
    outputs: REQUIRED_OUTPUT_CLASSES.map(outputFor),
    reviewRouting: {
      reviewerAssignments: [
        assignment(
          'quality_manager',
          [
            'asst-output-ai_control_review',
            'asst-output-kpi_trend_analysis',
            'asst-output-orientation_guidance',
            'asst-output-reporting_export_explanation',
            'asst-output-workflow_guidance',
          ],
          1,
        ),
        assignment('site_quality_lead', ['asst-output-ai_control_review', 'asst-output-kpi_trend_analysis'], 2),
        assignment('principal_investigator', ['asst-output-audit_assessment_review', 'asst-output-decision_support_summary'], 0),
      ],
    },
  }));

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.deepEqual(resultA.reasons, []);
  assert.equal(resultA.explainabilityRecord.schema, 'cybermedica.assistant_explainability_record.v1');
  assert.equal(resultA.explainabilityRecord.trustState, 'inactive');
  assert.equal(resultA.explainabilityRecord.exochainProductionClaim, false);
  assert.deepEqual(resultA.explainabilityRecord.outputClassCoverage, REQUIRED_OUTPUT_CLASSES);
  assert.deepEqual(resultA.explainabilityRecord.explanationFieldCoverage, [
    'confidence',
    'evidence_references',
    'limitations',
    'reasoning_summary',
    'recommended_human_reviewers',
    'unresolved_assumptions',
  ]);
  assert.deepEqual(resultA.explainabilityRecord.assistantKinds, ['ai_assistant', 'rules_assistant']);
  assert.equal(resultA.explainabilityRecord.averageConfidenceBasisPoints, 8500);
  assert.deepEqual(resultA.explainabilityRecord.requiredReviewerRoles, [
    'principal_investigator',
    'quality_manager',
    'site_quality_lead',
  ]);
  assert.deepEqual(resultA.explainabilityRecord.humanReviewQueue, [
    'principal_investigator:asst-output-audit_assessment_review',
    'principal_investigator:asst-output-decision_support_summary',
    'quality_manager:asst-output-ai_control_review',
    'quality_manager:asst-output-kpi_trend_analysis',
    'quality_manager:asst-output-orientation_guidance',
    'quality_manager:asst-output-reporting_export_explanation',
    'quality_manager:asst-output-workflow_guidance',
    'site_quality_lead:asst-output-ai_control_review',
    'site_quality_lead:asst-output-kpi_trend_analysis',
  ]);
  assert.equal(resultA.explainabilityRecord.outputRefs[0], 'asst-output-ai_control_review');
  assert.equal(resultA.explainabilityRecord.recordHash, resultB.explainabilityRecord.recordHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'assistant_explainability');
  assert.equal(resultA.receipt.anchorPayload.classification, 'restricted_metadata_only');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.containsProtectedContent, false);
  assert.doesNotMatch(JSON.stringify(resultA), /raw output|reasoning text|participant alice|source document body/iu);
});

test('assistant explainability fails closed for missing required explanation fields and unsafe human routing', async () => {
  const { evaluateAssistantExplainability } = await loadAssistantExplainability();

  const absent = evaluateAssistantExplainability({});

  assert.equal(absent.decision, 'denied');
  assert.ok(absent.reasons.includes('tenant_absent'));
  assert.ok(absent.reasons.includes('explainability_policy_ref_absent'));
  assert.ok(absent.reasons.includes('assistant_outputs_absent'));
  assert.ok(absent.reasons.includes('review_route_ref_absent'));
  assert.equal(absent.explainabilityRecord, null);
  assert.equal(absent.receipt, null);

  const denied = evaluateAssistantExplainability(explainabilityInput({
    explainabilityPolicy: {
      status: 'draft',
      requiredOutputClasses: REQUIRED_OUTPUT_CLASSES.filter((value) => value !== 'kpi_trend_analysis'),
      requiredExplanationFields: ['confidence', 'evidence_references'],
      allowedReviewerRoles: ['quality_manager'],
      humanReviewRequired: false,
      contestable: false,
      aiFinalAuthorityAllowed: true,
      minimumConfidenceForDisplayBasisPoints: 10001,
    },
    outputs: REQUIRED_OUTPUT_CLASSES.map((outputClass, index) =>
      outputClass === 'ai_control_review'
        ? {
            ...outputFor(outputClass, index),
            evidenceRefs: [],
            reasoningSummaryHash: '',
            confidenceBasisPoints: 10001,
            limitationHashes: [],
            unresolvedAssumptionHashes: null,
            unresolvedAssumptionsReviewed: false,
            recommendedHumanReviewerRoles: [],
            requiresHumanReview: false,
            advisoryOnly: false,
            finalAuthority: true,
          }
        : outputFor(outputClass, index),
    ),
    reviewRouting: {
      reviewerAssignments: [
        assignment('unapproved_reviewer', ['asst-output-ai_control_review'], 0),
      ],
    },
  }));

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('explainability_policy_not_approved'));
  assert.ok(denied.reasons.includes('policy_required_output_class_missing:kpi_trend_analysis'));
  assert.ok(denied.reasons.includes('policy_required_field_missing:limitations'));
  assert.ok(denied.reasons.includes('policy_required_field_missing:reasoning_summary'));
  assert.ok(denied.reasons.includes('policy_required_field_missing:recommended_human_reviewers'));
  assert.ok(denied.reasons.includes('policy_required_field_missing:unresolved_assumptions'));
  assert.ok(denied.reasons.includes('policy_human_review_required_absent'));
  assert.ok(denied.reasons.includes('policy_contestation_absent'));
  assert.ok(denied.reasons.includes('policy_allows_ai_final_authority'));
  assert.ok(denied.reasons.includes('policy_confidence_threshold_invalid'));
  assert.ok(denied.reasons.includes('output_evidence_refs_absent:asst-output-ai_control_review'));
  assert.ok(denied.reasons.includes('output_reasoning_summary_hash_invalid:asst-output-ai_control_review'));
  assert.ok(denied.reasons.includes('output_confidence_basis_points_invalid:asst-output-ai_control_review'));
  assert.ok(denied.reasons.includes('output_limitations_absent:asst-output-ai_control_review'));
  assert.ok(denied.reasons.includes('output_unresolved_assumptions_not_reviewed:asst-output-ai_control_review'));
  assert.ok(denied.reasons.includes('output_reviewer_roles_absent:asst-output-ai_control_review'));
  assert.ok(denied.reasons.includes('output_human_review_required_absent:asst-output-ai_control_review'));
  assert.ok(denied.reasons.includes('output_ai_final_authority_forbidden:asst-output-ai_control_review'));
  assert.ok(denied.reasons.includes('review_assignment_role_not_allowed:unapproved_reviewer'));
  assert.equal(denied.explainabilityRecord, null);
  assert.equal(denied.receipt, null);
});

test('assistant explainability validates same-tick HLC routing and low-confidence escalation', async () => {
  const { evaluateAssistantExplainability } = await loadAssistantExplainability();

  const lowConfidence = evaluateAssistantExplainability(explainabilityInput({
    outputs: REQUIRED_OUTPUT_CLASSES.map((outputClass, index) =>
      outputClass === 'workflow_guidance'
        ? {
            ...outputFor(outputClass, index),
            generatedAtHlc: { physicalMs: 1797000010000, logical: 0 },
            confidenceBasisPoints: 6400,
            lowConfidenceEscalationRef: 'low-confidence-human-route-workflow',
          }
        : outputFor(outputClass, index),
    ),
    reviewRouting: {
      generatedAtHlc: { physicalMs: 1797000010000, logical: 0 },
      queuedAtHlc: { physicalMs: 1797000010000, logical: 1 },
      dueAtHlc: { physicalMs: 1797000010000, logical: 2 },
    },
  }));

  assert.equal(lowConfidence.decision, 'permitted');
  assert.deepEqual(lowConfidence.explainabilityRecord.lowConfidenceOutputRefs, ['asst-output-workflow_guidance']);
  assert.equal(lowConfidence.explainabilityRecord.averageConfidenceBasisPoints, 8071);

  const unsafeOrdering = evaluateAssistantExplainability(explainabilityInput({
    outputs: REQUIRED_OUTPUT_CLASSES.map((outputClass, index) =>
      outputClass === 'workflow_guidance'
        ? {
            ...outputFor(outputClass, index),
            generatedAtHlc: { physicalMs: 1797000011000, logical: 0 },
            confidenceBasisPoints: 6500,
            lowConfidenceEscalationRef: '',
          }
        : outputFor(outputClass, index),
    ),
    reviewRouting: {
      generatedAtHlc: { physicalMs: 1797000010000, logical: 0 },
      queuedAtHlc: { physicalMs: 1797000010000, logical: 0 },
      dueAtHlc: { physicalMs: 1797000009999, logical: 0 },
    },
  }));

  assert.equal(unsafeOrdering.decision, 'denied');
  assert.ok(unsafeOrdering.reasons.includes('review_route_queue_not_after_generation'));
  assert.ok(unsafeOrdering.reasons.includes('review_route_due_not_after_queue'));
  assert.ok(unsafeOrdering.reasons.includes('output_generated_after_route:asst-output-workflow_guidance'));
  assert.ok(unsafeOrdering.reasons.includes('output_low_confidence_escalation_absent:asst-output-workflow_guidance'));
});

test('assistant explainability rejects raw assistant output protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateAssistantExplainability } = await loadAssistantExplainability();

  assert.throws(
    () => evaluateAssistantExplainability(explainabilityInput({
      outputs: [
        {
          ...outputFor('ai_control_review', 0),
          rawAssistantOutput: 'This raw output is not receipt material.',
        },
      ],
    })),
    ProtectedContentError,
  );

  assert.throws(
    () => evaluateAssistantExplainability(explainabilityInput({
      outputs: [
        {
          ...outputFor('decision_support_summary', 2),
          reasoningText: 'Participant Alice Example should be routed to consent review.',
        },
      ],
    })),
    ProtectedContentError,
  );

  assert.throws(
    () => evaluateAssistantExplainability(explainabilityInput({
      reviewRouting: {
        apiKey: { vaultRef: 'secret-ref-alpha' },
      },
    })),
    ProtectedContentError,
  );

  assert.throws(
    () => evaluateAssistantExplainability(explainabilityInput({
      outputs: [
        {
          ...outputFor('workflow_guidance', 6),
          rawAssistantOutput: [false, 1],
        },
      ],
    })),
    ProtectedContentError,
  );

  assert.throws(
    () => evaluateAssistantExplainability(explainabilityInput({
      reviewRouting: {
        token: 1,
      },
    })),
    ProtectedContentError,
  );

  const inertRawMarker = evaluateAssistantExplainability(explainabilityInput({
    outputs: [
      {
        ...outputFor('orientation_guidance', 4),
        rawAssistantOutput: false,
      },
      ...REQUIRED_OUTPUT_CLASSES.filter((value) => value !== 'orientation_guidance').map(outputFor),
    ],
  }));

  assert.equal(inertRawMarker.decision, 'permitted');
});
