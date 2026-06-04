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

const REQUIRED_RESPONSE_DOMAINS = [
  'capa_linkage',
  'classification',
  'closure_review',
  'disclosure_log',
  'due_date_control',
  'evidence_package',
  'finding_intake',
  'management_response',
  'regulatory_communication',
];

const REQUIRED_FINDING_CATEGORIES = [
  'consent',
  'data_integrity',
  'documentation',
  'participant_safety',
  'privacy_security',
  'product_handling',
  'regulatory_reporting',
  'training_delegation',
];

async function loadInspectionResponseManagement() {
  try {
    return await import('../src/inspection-response-management.mjs');
  } catch (error) {
    assert.fail(`CyberMedica inspection-response-management module must exist and load: ${error.message}`);
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

function responseDomain(domain, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3];
  return {
    domain,
    status: 'complete',
    evidenceHash: hashes[index],
    reviewedAtHlc: { physicalMs: 1803010300000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function finding(findingRef, category, severity, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2];
  return {
    findingRef,
    category,
    severity,
    status: 'responded',
    findingHash: hashes[index],
    responseHash: hashes[index + 1],
    ownerDid: `did:exo:${category.replaceAll('_', '-')}-owner`,
    dueAtHlc: { physicalMs: 1803610000000, logical: index },
    responseSubmittedAtHlc: { physicalMs: 1803200000000, logical: index },
    correctionEvidenceHash: hashes[index + 2],
    capaRef: severity === 'minor' ? null : `CAPA-${findingRef}`,
    participantSafetyReviewHash: category === 'participant_safety' ? DIGEST_5 : null,
    dataIntegrityReviewHash: category === 'data_integrity' ? DIGEST_6 : null,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function communication(recipientRole, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1];
  return {
    recipientRole,
    communicationHash: hashes[index],
    sentAtHlc: { physicalMs: 1803210000000, logical: index },
    acknowledged: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function inspectionResponseInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    siteRef: 'site-alpha',
    protocolRef: 'protocol-cardiac-alpha',
    actor: {
      did: 'did:exo:inspection-response-owner-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'inspection_response_owner'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['inspection_response_manage', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    responsePolicy: {
      policyRef: 'inspection-response-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredResponseDomains: REQUIRED_RESPONSE_DOMAINS,
      requiredFindingCategories: REQUIRED_FINDING_CATEGORIES,
      criticalFindingsRequireDecisionForum: true,
      majorFindingsRequireCapa: true,
      responseDueDatesRequired: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1803010000000, logical: 0 },
    },
    inspectionEvent: {
      inspectionRef: 'inspection-regulatory-alpha-001',
      sourceType: 'regulatory_inspection',
      sessionRef: 'inspection-session-alpha',
      inspectionModeReceiptId: 'cmr-inspection-session-alpha',
      inspectorOrganizationRef: 'regulator-alpha',
      issuedAtHlc: { physicalMs: 1803000000000, logical: 0 },
      responseDueAtHlc: { physicalMs: 1803700000000, logical: 0 },
      status: 'findings_issued',
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    responseDomains: REQUIRED_RESPONSE_DOMAINS.map((domain, index) => responseDomain(domain, index)),
    findings: [
      finding('finding-participant-safety-alpha', 'participant_safety', 'critical', 0),
      finding('finding-data-integrity-alpha', 'data_integrity', 'major', 2),
      finding('finding-documentation-alpha', 'documentation', 'minor', 4),
    ],
    responsePackage: {
      packageRef: 'inspection-response-package-alpha',
      packageHash: DIGEST_C,
      evidenceIndexHash: DIGEST_D,
      managementResponseHash: DIGEST_E,
      responseManifestHash: DIGEST_F,
      submittedAtHlc: { physicalMs: 1803215000000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    communications: [
      communication('decision_forum', 0),
      communication('principal_investigator', 1),
      communication('regulatory_contact', 2),
      communication('site_quality_lead', 3),
    ],
    decisionForum: {
      invoked: true,
      matterRef: 'df-inspection-response-alpha',
      receiptId: 'cmr-df-inspection-response-alpha',
      quorumStatus: 'met',
      humanGateVerified: true,
      openChallenge: false,
      decision: 'inspection_response_accepted',
      decidedAtHlc: { physicalMs: 1803220000000, logical: 0 },
    },
    correctiveLinkage: {
      capaRefs: ['CAPA-finding-data-integrity-alpha', 'CAPA-finding-participant-safety-alpha'],
      cqiCycleRef: 'CQI-inspection-response-alpha',
      driftSignalRef: 'drift-inspection-response-alpha',
      effectivenessCheckHash: DIGEST_1,
      ownerDid: 'did:exo:quality-manager-alpha',
      dueAtHlc: { physicalMs: 1804300000000, logical: 0 },
      metadataOnly: true,
    },
    closureReview: {
      reviewerDid: 'did:exo:quality-director-alpha',
      decision: 'closed_with_capa_linkage',
      reviewEvidenceHash: DIGEST_2,
      reviewedAtHlc: { physicalMs: 1803230000000, logical: 0 },
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      metadataOnly: true,
    },
    auditTrail: {
      auditRecordHash: DIGEST_3,
      disclosureLogHash: DIGEST_4,
      responseHistoryHash: DIGEST_5,
      recordedAtHlc: { physicalMs: 1803240000000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    aiAssistance: {
      used: true,
      advisoryOnly: true,
      finalAuthority: false,
      recommendationHash: DIGEST_6,
      humanReviewed: true,
    },
    custodyDigest: DIGEST_F,
    checkedAtHlc: { physicalMs: 1803250000000, logical: 0 },
  };

  return mergeDeep(base, overrides);
}

test('inspection response closes critical regulatory findings with deterministic inactive receipts', async () => {
  const { evaluateInspectionResponseManagement } = await loadInspectionResponseManagement();
  const input = inspectionResponseInput();

  const first = evaluateInspectionResponseManagement(input);
  const second = evaluateInspectionResponseManagement({
    ...input,
    responsePolicy: {
      ...input.responsePolicy,
      requiredResponseDomains: [...input.responsePolicy.requiredResponseDomains].reverse(),
      requiredFindingCategories: [...input.responsePolicy.requiredFindingCategories].reverse(),
    },
    responseDomains: [...input.responseDomains].reverse(),
    findings: [...input.findings].reverse(),
    communications: [...input.communications].reverse(),
    correctiveLinkage: {
      ...input.correctiveLinkage,
      capaRefs: [...input.correctiveLinkage.capaRefs].reverse(),
    },
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.inspectionResponse.status, 'closed_with_capa_linkage');
  assert.equal(first.inspectionResponse.materialDecisionForumRequired, true);
  assert.equal(first.inspectionResponse.findingCount, 3);
  assert.equal(first.inspectionResponse.criticalFindingCount, 1);
  assert.equal(first.inspectionResponse.majorFindingCount, 1);
  assert.deepEqual(first.inspectionResponse.requiredResponseRoles, [
    'decision_forum',
    'principal_investigator',
    'regulatory_contact',
    'site_quality_lead',
  ]);
  assert.deepEqual(first.inspectionResponse.coveredResponseDomains, REQUIRED_RESPONSE_DOMAINS);
  assert.equal(first.inspectionResponse.exochainProductionClaim, false);
  assert.equal(first.inspectionResponse.metadataOnly, true);
  assert.equal(first.inspectionResponse.inspectionResponseId, second.inspectionResponse.inspectionResponseId);
  assert.equal(first.inspectionResponse.responseHash, second.inspectionResponse.responseHash);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.equal(first.receipt.anchorPayload.artifactType, 'inspection_response_package');
  assert.doesNotMatch(JSON.stringify(first), /participant alice|medical record|raw finding|source document|api key/iu);
});

test('sponsor audit responses can be response-ready without Decision Forum when findings are non-material', async () => {
  const { evaluateInspectionResponseManagement } = await loadInspectionResponseManagement();
  const result = evaluateInspectionResponseManagement(
    inspectionResponseInput({
      inspectionEvent: {
        sourceType: 'sponsor_audit',
        inspectorOrganizationRef: 'sponsor-alpha',
      },
      findings: [finding('finding-documentation-sponsor-alpha', 'documentation', 'minor', 4)],
      communications: [communication('site_quality_lead', 3), communication('sponsor_cro_contact', 4)],
      decisionForum: {
        invoked: false,
        matterRef: null,
        receiptId: null,
        quorumStatus: null,
        humanGateVerified: false,
        openChallenge: false,
        decision: null,
        decidedAtHlc: null,
      },
      correctiveLinkage: {
        capaRefs: [],
      },
      closureReview: {
        decision: 'response_ready',
      },
    }),
  );

  assert.equal(result.decision, 'permitted');
  assert.equal(result.failClosed, false);
  assert.equal(result.inspectionResponse.status, 'response_ready');
  assert.equal(result.inspectionResponse.materialDecisionForumRequired, false);
  assert.deepEqual(result.inspectionResponse.requiredResponseRoles, ['site_quality_lead', 'sponsor_cro_contact']);
  assert.equal(result.inspectionResponse.criticalFindingCount, 0);
  assert.equal(result.inspectionResponse.majorFindingCount, 0);
  assert.equal(result.receipt.anchorPayload.artifactType, 'inspection_response_package');
});

test('inspection response fails closed for missing domains overdue responses and governance defects', async () => {
  const { evaluateInspectionResponseManagement } = await loadInspectionResponseManagement();
  const result = evaluateInspectionResponseManagement(
    inspectionResponseInput({
      actor: {
        did: 'did:exo:ai-inspection-agent-alpha',
        kind: 'ai_agent',
      },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['read'],
        authorityChainHash: DIGEST_A,
      },
      responsePolicy: {
        requiredResponseDomains: REQUIRED_RESPONSE_DOMAINS.filter((domain) => domain !== 'capa_linkage'),
      },
      responseDomains: REQUIRED_RESPONSE_DOMAINS.filter((domain) => domain !== 'closure_review').map((domain, index) =>
        responseDomain(domain, index),
      ),
      findings: [
        finding('finding-safety-overdue-alpha', 'participant_safety', 'critical', 0, {
          status: 'open',
          responseHash: '',
          responseSubmittedAtHlc: { physicalMs: 1803710000000, logical: 0 },
          capaRef: null,
          participantSafetyReviewHash: '',
        }),
      ],
      communications: [communication('site_quality_lead', 3)],
      decisionForum: {
        invoked: false,
        matterRef: null,
        receiptId: null,
        quorumStatus: 'not_met',
        humanGateVerified: false,
        openChallenge: true,
        decision: 'held',
        decidedAtHlc: null,
      },
      closureReview: {
        reviewerDid: '',
        decision: 'closed_with_capa_linkage',
        reviewEvidenceHash: '',
        aiFinalAuthority: true,
      },
      responsePackage: {
        submittedAtHlc: { physicalMs: 1803710000000, logical: 0 },
        packageHash: '',
      },
      correctiveLinkage: {
        capaRefs: [],
        effectivenessCheckHash: '',
        ownerDid: '',
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.inspectionResponse, null);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('inspection_response_authority_missing'));
  assert.ok(result.reasons.includes('policy_response_domain_missing:capa_linkage'));
  assert.ok(result.reasons.includes('response_domain_missing:closure_review'));
  assert.ok(result.reasons.includes('finding_not_responded:finding-safety-overdue-alpha'));
  assert.ok(result.reasons.includes('finding_response_hash_invalid:finding-safety-overdue-alpha'));
  assert.ok(result.reasons.includes('finding_response_submitted_after_due:finding-safety-overdue-alpha'));
  assert.ok(result.reasons.includes('critical_finding_capa_absent:finding-safety-overdue-alpha'));
  assert.ok(result.reasons.includes('participant_safety_review_absent:finding-safety-overdue-alpha'));
  assert.ok(result.reasons.includes('decision_forum_required_for_material_findings'));
  assert.ok(result.reasons.includes('required_communication_missing:decision_forum'));
  assert.ok(result.reasons.includes('required_communication_missing:principal_investigator'));
  assert.ok(result.reasons.includes('closure_human_reviewer_absent'));
  assert.ok(result.reasons.includes('closure_ai_final_authority_forbidden'));
});

test('inspection response refuses raw finding content and secrets before creating receipts', async () => {
  const { ProtectedContentError, evaluateInspectionResponseManagement } = await loadInspectionResponseManagement();

  assert.throws(
    () =>
      evaluateInspectionResponseManagement({
        ...inspectionResponseInput(),
        findings: [
          {
            ...inspectionResponseInput().findings[0],
            rawFindingText: 'Participant Alice medical record and source document excerpts',
          },
        ],
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateInspectionResponseManagement({
        ...inspectionResponseInput(),
        responsePackage: {
          ...inspectionResponseInput().responsePackage,
          apiKey: 'redacted-api-key-placeholder',
        },
      }),
    ProtectedContentError,
  );
});
