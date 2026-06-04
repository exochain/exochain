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

const REQUIRED_CONTEXT_FIELDS = [
  'active_object',
  'available_manuals',
  'tenant_context',
  'user_role',
  'workflow_state',
];

const REQUIRED_CITATION_FAMILIES = [
  'control',
  'manual_section',
  'procedure',
];

const REQUIRED_SIGNAL_FAMILIES = [
  'ai_orientation_question',
  'manual_confusion',
  'missing_documentation',
  'product_gap',
];

async function loadAiOrientationAssistant() {
  try {
    return await import('../src/ai-orientation-assistant.mjs');
  } catch (error) {
    assert.fail(`CyberMedica AI orientation assistant module must exist and load: ${error.message}`);
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

function citation(family, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F];
  return {
    citationRef: `orientation-citation-${family}`,
    family,
    targetRef: `${family}-orientation-source-alpha`,
    targetHash: hashes[index],
    manualSectionRef: `manual-section-${family}`,
    relationToActiveObject: index === 0 ? 'governs_active_object' : 'supports_orientation',
    displayOrder: index + 1,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function orientationInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:documentation-orientation-owner-alpha',
      kind: 'human',
      roleRefs: ['quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['ai_orientation_review', 'cqi_triage'],
      authorityChainHash: DIGEST_A,
    },
    orientationPolicy: {
      policyRef: 'doc-005-orientation-assistant-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredContextFields: REQUIRED_CONTEXT_FIELDS,
      requiredCitationFamilies: REQUIRED_CITATION_FAMILIES,
      requiredConfusionSignalFamilies: REQUIRED_SIGNAL_FAMILIES,
      guidanceLabel: 'guidance_not_policy_authority',
      cqiReportingRequired: true,
      unresolvedQuestionHumanRouteRequired: true,
      advisoryOnly: true,
      allowAiFinalAuthority: false,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1805020000000, logical: 0 },
    },
    requestContext: {
      requestRef: 'orientation-request-launch-gate-alpha',
      userRoleRef: 'quality_manager',
      tenantContextRef: 'tenant-site-alpha-qms',
      activeObjectType: 'workflow_step',
      activeObjectRef: 'protocol-launch-readiness.step.evidence-review',
      workflowRef: 'protocol-launch-readiness',
      workflowStateRef: 'evidence_review_pending',
      availableManualRefs: [
        'role-manual-quality-manager',
        'workflow-guide-protocol-launch',
        'procedure-evidence-review',
      ],
      manualIndexHash: DIGEST_C,
      contextualDrawerReceiptHash: DIGEST_D,
      requestedAtHlc: { physicalMs: 1805020000000, logical: 1 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    guidanceAnswer: {
      answerRef: 'orientation-answer-launch-gate-alpha',
      guidanceLabel: 'guidance_not_policy_authority',
      guidanceHash: DIGEST_E,
      confidenceBasisPoints: 8600,
      unresolvedQuestion: false,
      humanEscalationRoleRef: 'quality_manager',
      generatedAtHlc: { physicalMs: 1805020000000, logical: 2 },
      advisoryOnly: true,
      finalAuthority: false,
      citesLinkedSources: true,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    citations: REQUIRED_CITATION_FAMILIES.map((family, index) => citation(family, index)),
    confusionReporter: {
      reporterRef: 'doc-006-orientation-confusion-reporter-alpha',
      enabled: true,
      capturesRoleContext: true,
      capturesTenantContext: true,
      capturesActiveObjectContext: true,
      capturesWorkflowState: true,
      capturesManualSectionContext: true,
      capturesSuggestedImprovementCategory: true,
      requiredSignalFamilies: REQUIRED_SIGNAL_FAMILIES,
      cqiRouteRef: 'inquiry-cqi-cycle-alpha',
      inquiryCqiPolicyHash: DIGEST_F,
      noRawInquiryContent: true,
      reviewedAtHlc: { physicalMs: 1805020000000, logical: 3 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-owner-alpha',
      reviewerRoleRefs: ['quality_manager', 'documentation_owner'],
      decision: 'orientation_assistant_ready_inactive_trust',
      decisionHash: DIGEST_1,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      reviewedAtHlc: { physicalMs: 1805020000000, logical: 4 },
      metadataOnly: true,
    },
    custodyDigest: DIGEST_2,
  };

  return mergeDeep(base, overrides);
}

test('AI orientation assistant creates deterministic DOC-005 and DOC-006 inactive citation records', async () => {
  const { evaluateAiOrientationAssistant } = await loadAiOrientationAssistant();

  const first = evaluateAiOrientationAssistant(orientationInput());
  const second = evaluateAiOrientationAssistant(
    orientationInput({
      orientationPolicy: {
        requiredContextFields: [...REQUIRED_CONTEXT_FIELDS].reverse(),
        requiredCitationFamilies: [...REQUIRED_CITATION_FAMILIES].reverse(),
        requiredConfusionSignalFamilies: [...REQUIRED_SIGNAL_FAMILIES].reverse(),
      },
      citations: REQUIRED_CITATION_FAMILIES.map((family, index) => citation(family, index)).reverse(),
    }),
  );

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.deepEqual(first.reasons, []);
  assert.equal(first.orientationRecord.schema, 'cybermedica.ai_orientation_assistant.v1');
  assert.equal(first.orientationRecord.trustState, 'inactive');
  assert.equal(first.orientationRecord.exochainProductionClaim, false);
  assert.equal(first.orientationRecord.guidanceLabel, 'guidance_not_policy_authority');
  assert.deepEqual(first.orientationRecord.contextCoverage, REQUIRED_CONTEXT_FIELDS);
  assert.deepEqual(first.orientationRecord.citationFamilies, REQUIRED_CITATION_FAMILIES);
  assert.deepEqual(first.orientationRecord.confusionSignalFamilies, REQUIRED_SIGNAL_FAMILIES);
  assert.equal(first.orientationRecord.cqiReporterReady, true);
  assert.equal(first.orientationRecord.advisoryOnly, true);
  assert.equal(first.orientationRecord.aiFinalAuthority, false);
  assert.equal(first.orientationRecord.recordHash, second.orientationRecord.recordHash);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.receipt.anchorPayload.artifactType, 'ai_orientation_assistant');
  assert.equal(first.receipt.anchorPayload.classification, 'metadata_only_orientation_guidance');
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.containsProtectedContent, false);
  assert.doesNotMatch(JSON.stringify(first), /answer body|question text|participant alice|source document|secret/iu);
});

test('AI orientation assistant fails closed for missing context citation and reporter controls', async () => {
  const { evaluateAiOrientationAssistant } = await loadAiOrientationAssistant();

  const result = evaluateAiOrientationAssistant(
    orientationInput({
      requestContext: {
        userRoleRef: '',
        activeObjectRef: '',
        availableManualRefs: [],
      },
      guidanceAnswer: {
        guidanceLabel: 'policy_authority',
        finalAuthority: true,
        citesLinkedSources: false,
      },
      citations: [
        citation('manual_section', 0),
        citation('control', 1, {
          targetHash: 'bad',
          metadataOnly: false,
        }),
      ],
      confusionReporter: {
        enabled: false,
        capturesRoleContext: false,
        capturesManualSectionContext: false,
        capturesSuggestedImprovementCategory: false,
        cqiRouteRef: '',
        inquiryCqiPolicyHash: '',
        noRawInquiryContent: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.orientationRecord, null);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('request_context_user_role_absent'));
  assert.ok(result.reasons.includes('request_context_active_object_absent'));
  assert.ok(result.reasons.includes('request_context_available_manuals_absent'));
  assert.ok(result.reasons.includes('guidance_label_invalid'));
  assert.ok(result.reasons.includes('guidance_final_authority_forbidden'));
  assert.ok(result.reasons.includes('guidance_linked_source_citation_missing'));
  assert.ok(result.reasons.includes('citation_family_missing:procedure'));
  assert.ok(result.reasons.includes('citation_target_hash_invalid:orientation-citation-control'));
  assert.ok(result.reasons.includes('citation_metadata_boundary_invalid:orientation-citation-control'));
  assert.ok(result.reasons.includes('confusion_reporter_disabled'));
  assert.ok(result.reasons.includes('confusion_reporter_role_context_missing'));
  assert.ok(result.reasons.includes('confusion_reporter_manual_section_context_missing'));
  assert.ok(result.reasons.includes('confusion_reporter_improvement_category_missing'));
  assert.ok(result.reasons.includes('confusion_reporter_cqi_route_absent'));
  assert.ok(result.reasons.includes('confusion_reporter_policy_hash_invalid'));
  assert.ok(result.reasons.includes('confusion_reporter_raw_inquiry_boundary_absent'));
});

test('AI orientation assistant validates HLC ordering human authority and no-AI operation', async () => {
  const { evaluateAiOrientationAssistant } = await loadAiOrientationAssistant();

  const noAi = evaluateAiOrientationAssistant(
    orientationInput({
      guidanceAnswer: {
        guidanceLabel: 'guidance_not_policy_authority',
        confidenceBasisPoints: 0,
        unresolvedQuestion: true,
        citesLinkedSources: true,
        generatedAtHlc: { physicalMs: 1805020000000, logical: 2 },
      },
      confusionReporter: { reviewedAtHlc: { physicalMs: 1805020000000, logical: 3 } },
    }),
  );
  assert.equal(noAi.decision, 'permitted');
  assert.equal(noAi.orientationRecord.unresolvedQuestionRoutedToHuman, true);

  const denied = evaluateAiOrientationAssistant(
    orientationInput({
      actor: {
        kind: 'ai_agent',
        roleRefs: ['ai_orientation_assistant'],
      },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['read'],
        authorityChainHash: 'bad',
      },
      requestContext: {
        requestedAtHlc: { physicalMs: 1805019999999, logical: 1 },
      },
      guidanceAnswer: {
        generatedAtHlc: { physicalMs: 1805019999999, logical: 0 },
        confidenceBasisPoints: 10001,
      },
      confusionReporter: {
        reviewedAtHlc: { physicalMs: 1805019999999, logical: 0 },
      },
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
        noProductionTrustClaim: false,
        reviewedAtHlc: { physicalMs: 1805020000000, logical: 2 },
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('human_orientation_reviewer_required'));
  assert.ok(denied.reasons.includes('orientation_authority_missing'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('request_context_before_policy'));
  assert.ok(denied.reasons.includes('guidance_generated_before_request'));
  assert.ok(denied.reasons.includes('guidance_confidence_invalid'));
  assert.ok(denied.reasons.includes('confusion_reporter_review_before_guidance'));
  assert.ok(denied.reasons.includes('human_final_authority_absent'));
  assert.ok(denied.reasons.includes('human_review_ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('human_review_production_trust_claim_forbidden'));
});

test('AI orientation assistant rejects raw questions answers protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateAiOrientationAssistant } = await loadAiOrientationAssistant();

  assert.throws(
    () =>
      evaluateAiOrientationAssistant(
        orientationInput({
          requestContext: {
            questionText: 'How do I route participant Alice consent evidence?',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateAiOrientationAssistant(
        orientationInput({
          guidanceAnswer: {
            answerBody: 'Answer body must remain outside the metadata contract.',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateAiOrientationAssistant(
        orientationInput({
          citations: [
            citation('manual_section', 0, {
              sourceDocumentBody: 'source document text is not accepted',
            }),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateAiOrientationAssistant(
        orientationInput({
          adapter: {
            apiKey: 'secret-runtime-token',
          },
        }),
      ),
    /secret/i,
  );
});
