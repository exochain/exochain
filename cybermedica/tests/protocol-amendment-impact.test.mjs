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

const REQUIRED_IMPACT_DOMAINS = [
  'budget_contract',
  'consent_reconsent',
  'ethics_review',
  'participant_communication',
  'product_blinding_randomization',
  'regulatory_submission',
  'risk_capa_deviation',
  'safety_reporting',
  'source_data_crf',
  'training_delegation',
  'vendor_lab_pharmacy',
  'visit_schedule',
];

async function loadProtocolAmendmentImpact() {
  try {
    return await import('../src/protocol-amendment-impact.mjs');
  } catch (error) {
    assert.fail(`CyberMedica protocol amendment impact module must exist and load: ${error.message}`);
  }
}

function domainImpact(domain, index, overrides = {}) {
  const materialDomains = new Set([
    'consent_reconsent',
    'ethics_review',
    'participant_communication',
    'training_delegation',
    'visit_schedule',
  ]);
  return {
    domain,
    impactLevel: materialDomains.has(domain) ? 'participant_affecting' : 'material',
    status: 'complete',
    evidenceHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F][index % 6],
    requiredActionRefs: [`amendment-action-${domain}`],
    ownerRoleRef: `${domain}_owner`,
    reviewedAtHlc: { physicalMs: 1820000001000 + index, logical: 0 },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function completeDomainImpacts() {
  return REQUIRED_IMPACT_DOMAINS.map((domain, index) => domainImpact(domain, index));
}

function amendmentImpactInput(overrides = {}) {
  const base = {
    requestId: 'protocol-amendment-impact-alpha',
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:protocol-amendment-owner-alpha',
      kind: 'human',
      roleRefs: ['principal_investigator', 'quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['protocol_amendment_impact', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    amendment: {
      amendmentRef: 'amendment-cardio-alpha-003',
      protocolRef: 'protocol-cardio-alpha',
      studyRef: 'study-alpha',
      siteRef: 'site-alpha',
      supersedesVersionRef: 'protocol-cardio-alpha:v3',
      proposedVersionRef: 'protocol-cardio-alpha:v4',
      amendmentPackageHash: DIGEST_B,
      amendmentSummaryHash: DIGEST_C,
      implementationPlanHash: DIGEST_D,
      assessedAtHlc: { physicalMs: 1820000000000, logical: 0 },
      targetEffectiveAtHlc: { physicalMs: 1820000100000, logical: 0 },
      status: 'ready_for_implementation',
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    domainImpacts: completeDomainImpacts(),
    downstreamReadiness: {
      ethicsApproval: {
        required: true,
        status: 'approved',
        independentEthicsReviewRef: 'irb-amendment-cardio-alpha-003',
        approvalEvidenceHash: DIGEST_E,
      },
      consentMaterials: {
        reconsentRequired: true,
        consentVersionRef: 'icf-cardio-alpha:v5',
        approvalStatus: 'approved',
        reconsentPlanHash: DIGEST_F,
        participantCommunicationRef: 'participant-communication-amendment-alpha',
      },
      participantCommunication: {
        required: true,
        communicationPlanRef: 'communication-plan-amendment-alpha',
        approvedMaterialHash: DIGEST_A,
        disseminationReady: true,
      },
      trainingDelegation: {
        required: true,
        trainingMatrixRef: 'training-matrix-amendment-alpha',
        updateEvidenceHash: DIGEST_B,
        allAffectedRolesTrained: true,
        delegationEligibilityUpdated: true,
      },
      protocolControl: {
        activeVersionReady: true,
        obsoleteVersionsWithdrawn: true,
        documentSecurityHash: DIGEST_C,
      },
      safetyData: {
        safetyPlanUpdated: true,
        sourceDataMapHash: DIGEST_D,
        crfUpdateHash: DIGEST_E,
        reportingTimelineHash: DIGEST_F,
      },
      productOperations: {
        randomizationBlindingAssessed: true,
        productAccountabilityImpactHash: DIGEST_1,
        pharmacyReadinessRef: 'pharmacy-readiness-amendment-alpha',
        labVendorReadinessRef: 'lab-vendor-readiness-amendment-alpha',
      },
      riskGovernance: {
        riskAssessmentRef: 'risk-assessment-amendment-alpha',
        deviationCapaImpactHash: DIGEST_A,
        budgetContractImpactHash: DIGEST_B,
        vendorImpactHash: DIGEST_C,
      },
    },
    reviewGovernance: {
      humanReviewerDid: 'did:exo:principal-investigator-alpha',
      aiAssisted: true,
      aiFinalAuthority: false,
      decisionForum: {
        required: true,
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-amendment-impact-alpha',
        workflowReceiptId: 'df-amendment-impact-receipt-alpha',
      },
    },
    custodyDigest: DIGEST_D,
  };
  return {
    ...base,
    ...overrides,
  };
}

test('protocol amendment impact module loads', async () => {
  const mod = await loadProtocolAmendmentImpact();
  assert.equal(typeof mod.evaluateProtocolAmendmentImpact, 'function');
});

test('protocol amendment impact creates deterministic inactive downstream readiness receipts', async () => {
  const { evaluateProtocolAmendmentImpact } = await loadProtocolAmendmentImpact();
  const input = amendmentImpactInput();

  const first = evaluateProtocolAmendmentImpact(input);
  const second = evaluateProtocolAmendmentImpact({
    ...input,
    domainImpacts: [...input.domainImpacts].reverse().map((impact) => ({
      ...impact,
      requiredActionRefs: [...impact.requiredActionRefs].reverse(),
    })),
    downstreamReadiness: {
      ...input.downstreamReadiness,
      productOperations: {
        labVendorReadinessRef: input.downstreamReadiness.productOperations.labVendorReadinessRef,
        pharmacyReadinessRef: input.downstreamReadiness.productOperations.pharmacyReadinessRef,
        productAccountabilityImpactHash: input.downstreamReadiness.productOperations.productAccountabilityImpactHash,
        randomizationBlindingAssessed: true,
      },
    },
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.deepEqual(first.reasons, []);
  assert.equal(first.amendmentImpact.implementationReady, true);
  assert.equal(first.amendmentImpact.protocolRef, 'protocol-cardio-alpha');
  assert.equal(first.amendmentImpact.proposedVersionRef, 'protocol-cardio-alpha:v4');
  assert.deepEqual(first.amendmentImpact.impactDomains, REQUIRED_IMPACT_DOMAINS);
  assert.deepEqual(first.amendmentImpact.participantAffectingDomains, [
    'consent_reconsent',
    'ethics_review',
    'participant_communication',
    'training_delegation',
    'visit_schedule',
  ]);
  assert.equal(first.amendmentImpact.trustState, 'inactive');
  assert.equal(first.amendmentImpact.exochainProductionClaim, false);
  assert.equal(first.amendmentImpact.impactHash, second.amendmentImpact.impactHash);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.receipt.anchorPayload.artifactType, 'protocol_amendment_impact');
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(first), /root-backed production authority|raw protocol|participant alice|medical record/iu);
});

test('protocol amendment impact fails closed for incomplete downstream readiness', async () => {
  const { evaluateProtocolAmendmentImpact } = await loadProtocolAmendmentImpact();
  const input = amendmentImpactInput();

  const denied = evaluateProtocolAmendmentImpact({
    ...input,
    actor: { did: 'did:exo:ai-amendment-reviewer-alpha', kind: 'ai_agent' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['read'],
      authorityChainHash: DIGEST_A,
    },
    amendment: {
      ...input.amendment,
      status: 'draft',
      productionTrustClaim: true,
    },
    domainImpacts: input.domainImpacts.filter((impact) => impact.domain !== 'visit_schedule'),
    downstreamReadiness: {
      ...input.downstreamReadiness,
      ethicsApproval: {
        ...input.downstreamReadiness.ethicsApproval,
        status: 'pending',
        approvalEvidenceHash: '',
      },
      consentMaterials: {
        ...input.downstreamReadiness.consentMaterials,
        approvalStatus: 'pending',
        reconsentPlanHash: '',
        participantCommunicationRef: '',
      },
      participantCommunication: {
        ...input.downstreamReadiness.participantCommunication,
        disseminationReady: false,
      },
      trainingDelegation: {
        ...input.downstreamReadiness.trainingDelegation,
        allAffectedRolesTrained: false,
        delegationEligibilityUpdated: false,
      },
      protocolControl: {
        ...input.downstreamReadiness.protocolControl,
        activeVersionReady: false,
        obsoleteVersionsWithdrawn: false,
      },
      safetyData: {
        ...input.downstreamReadiness.safetyData,
        sourceDataMapHash: '',
      },
      productOperations: {
        ...input.downstreamReadiness.productOperations,
        randomizationBlindingAssessed: false,
      },
      riskGovernance: {
        ...input.downstreamReadiness.riskGovernance,
        budgetContractImpactHash: '',
      },
    },
    reviewGovernance: {
      ...input.reviewGovernance,
      humanReviewerDid: '',
      aiFinalAuthority: true,
      decisionForum: {
        required: true,
        verified: false,
        state: 'pending',
        humanGate: { verified: false },
        quorum: { status: 'not_met' },
        openChallenge: true,
        decisionId: '',
        workflowReceiptId: '',
      },
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.receipt, null);
  assert.equal(denied.amendmentImpact.implementationReady, false);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('human_actor_required'));
  assert.ok(denied.reasons.includes('protocol_amendment_impact_authority_missing'));
  assert.ok(denied.reasons.includes('amendment_not_ready_for_implementation'));
  assert.ok(denied.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(denied.reasons.includes('impact_domain_missing:visit_schedule'));
  assert.ok(denied.reasons.includes('ethics_approval_not_approved'));
  assert.ok(denied.reasons.includes('consent_material_approval_not_approved'));
  assert.ok(denied.reasons.includes('participant_communication_ref_absent'));
  assert.ok(denied.reasons.includes('amendment_communication_not_ready'));
  assert.ok(denied.reasons.includes('training_update_incomplete'));
  assert.ok(denied.reasons.includes('delegation_eligibility_not_updated'));
  assert.ok(denied.reasons.includes('protocol_active_version_not_ready'));
  assert.ok(denied.reasons.includes('source_data_map_hash_invalid'));
  assert.ok(denied.reasons.includes('randomization_blinding_assessment_absent'));
  assert.ok(denied.reasons.includes('budget_contract_impact_hash_invalid'));
  assert.ok(denied.reasons.includes('decision_forum_not_verified'));
});

test('protocol amendment impact validates HLC ordering and no-AI operation', async () => {
  const { evaluateProtocolAmendmentImpact } = await loadProtocolAmendmentImpact();
  const input = amendmentImpactInput();

  const sameTickReady = evaluateProtocolAmendmentImpact({
    ...input,
    amendment: {
      ...input.amendment,
      assessedAtHlc: { physicalMs: 1820000000000, logical: 0 },
      targetEffectiveAtHlc: { physicalMs: 1820000000000, logical: 2 },
    },
    domainImpacts: input.domainImpacts.map((impact, index) => ({
      ...impact,
      reviewedAtHlc: { physicalMs: 1820000000000, logical: index + 1 },
    })),
    reviewGovernance: {
      ...input.reviewGovernance,
      aiAssisted: false,
      aiFinalAuthority: false,
    },
  });

  assert.equal(sameTickReady.decision, 'permitted');
  assert.equal(sameTickReady.amendmentImpact.aiAssisted, false);

  const denied = evaluateProtocolAmendmentImpact({
    ...input,
    amendment: {
      ...input.amendment,
      targetEffectiveAtHlc: { physicalMs: 1819999999999, logical: 0 },
    },
    domainImpacts: input.domainImpacts.map((impact, index) => ({
      ...impact,
      reviewedAtHlc: index === 0 ? { physicalMs: 1819999999999, logical: 0 } : impact.reviewedAtHlc,
    })),
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('target_effective_before_assessment'));
  assert.ok(denied.reasons.includes('impact_review_before_assessment:budget_contract'));
});

test('protocol amendment impact rejects raw amendment content protected content and secrets', async () => {
  const { ProtectedContentError, evaluateProtocolAmendmentImpact } = await loadProtocolAmendmentImpact();

  assert.throws(
    () =>
      evaluateProtocolAmendmentImpact({
        ...amendmentImpactInput(),
        amendment: {
          ...amendmentImpactInput().amendment,
          rawAmendmentBody: 'Participant Alice source document',
        },
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateProtocolAmendmentImpact({
        ...amendmentImpactInput(),
        downstreamReadiness: {
          ...amendmentImpactInput().downstreamReadiness,
          integrationSecret: 'secret-value',
        },
      }),
    ProtectedContentError,
  );
});
