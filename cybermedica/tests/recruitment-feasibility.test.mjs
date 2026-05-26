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

const REQUIRED_RECRUITMENT_CHANNELS = [
  'clinic_referral',
  'community_outreach',
  'database_prescreen',
  'participant_registry',
];

const REQUIRED_SCREENING_DOMAINS = [
  'eligibility_precheck',
  'inclusion_exclusion_review',
  'privacy_prescreen_boundary',
  'source_traceability',
];

async function loadRecruitmentFeasibility() {
  try {
    return await import('../src/recruitment-feasibility.mjs');
  } catch (error) {
    assert.fail(`CyberMedica recruitment-feasibility module must exist and load: ${error.message}`);
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

function channel(channelRef, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F];
  return {
    channelRef,
    status: 'active',
    forecastCount: [16, 11, 9, 8][index],
    evidenceHash: hashes[index],
    iecIrbApprovalHash: hashes[index + 1],
    privacyBoundaryHash: hashes[index + 2],
    ownerDid: `did:exo:recruitment-channel-owner-${index}`,
    lastReviewedAtHlc: { physicalMs: 1797000000000 + index, logical: 0 },
    vulnerablePopulationTargeted: channelRef === 'community_outreach',
    safeguardRefs: channelRef === 'community_outreach' ? ['safeguard-adult-lar-alpha'] : [],
    nonCoercionReviewHash: hashes[(index + 3) % hashes.length],
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function recruitmentChannels() {
  return REQUIRED_RECRUITMENT_CHANNELS.map((channelRef, index) => channel(channelRef, index));
}

function screeningDomain(domainRef, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F];
  return {
    domainRef,
    status: 'ready',
    evidenceHash: hashes[index],
    policyHash: hashes[index + 1],
    ownerDid: `did:exo:screening-domain-owner-${index}`,
    participantIdentifierSuppressed: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function screeningDomains() {
  return REQUIRED_SCREENING_DOMAINS.map((domainRef, index) => screeningDomain(domainRef, index));
}

function feasibilityInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:recruitment-lead-alpha',
      kind: 'human',
      roleRefs: ['clinical_research_coordinator', 'recruitment_lead'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['manage_recruitment_feasibility', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    recruitmentPlan: {
      planRef: 'recruitment-plan-cardiac-alpha',
      protocolRef: 'protocol-cardiac-alpha',
      siteRef: 'site-alpha',
      status: 'active',
      targetEnrollmentCount: 36,
      recruitmentWindowDays: 120,
      minimumScreeningCapacityCount: 58,
      expectedScreenFailureBasisPoints: 2800,
      populationEvidenceHash: DIGEST_B,
      feasibilityProcedureHash: DIGEST_C,
      consentReadinessRef: 'consent-materials-cardiac-alpha',
      protocolFeasibilityRef: 'protocol-feasibility-alpha',
      startupRiskAssessmentRef: 'startup-risk-cardiac-alpha',
      reviewedAtHlc: { physicalMs: 1798000000000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    recruitmentChannels: recruitmentChannels(),
    screeningDomains: screeningDomains(),
    participantProtections: {
      vulnerablePopulationSafeguardsApproved: true,
      safeguardEvidenceHashes: [DIGEST_D, DIGEST_E],
      consentMaterialRef: 'consent-materials-cardiac-alpha',
      nonCoercionPolicyHash: DIGEST_F,
      noRecruitmentBeforeLaunch: true,
      noSupersededMaterials: true,
      participantFacingMaterialIecIrbApproved: true,
      privacyPrescreeningAttested: true,
      updatedInformationReconsentGate: true,
      dataSharingConsentBoundaryHash: DIGEST_A,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    capacityEvidence: {
      activeStaffCount: 5,
      trainedStaffCount: 5,
      delegatedStaffCount: 5,
      screeningSlotCount: 64,
      retentionSupportCapacityCount: 40,
      staffTrainingMatrixHash: DIGEST_B,
      delegationLogHash: DIGEST_C,
      facilityCapacityHash: DIGEST_D,
      referralVolumeHash: DIGEST_E,
      monitoringMetricHash: DIGEST_F,
      metadataOnly: true,
    },
    review: {
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-recruitment-feasibility-alpha',
        workflowReceiptId: 'df-workflow-recruitment-feasibility-alpha',
      },
      evidenceBundle: { complete: true, phiBoundaryAttested: true },
      humanReviewerDid: 'did:exo:principal-investigator-alpha',
      finalAuthority: 'human',
      aiFinalAuthority: false,
    },
    custodyDigest: DIGEST_F,
  };
  return mergeDeep(base, overrides);
}

test('recruitment feasibility creates deterministic inactive metadata receipts', async () => {
  const { evaluateRecruitmentFeasibility } = await loadRecruitmentFeasibility();

  const resultA = evaluateRecruitmentFeasibility(feasibilityInput());
  const resultB = evaluateRecruitmentFeasibility({
    ...feasibilityInput(),
    recruitmentChannels: [...feasibilityInput().recruitmentChannels].reverse(),
    screeningDomains: [...feasibilityInput().screeningDomains].reverse(),
    participantProtections: {
      ...feasibilityInput().participantProtections,
      safeguardEvidenceHashes: [...feasibilityInput().participantProtections.safeguardEvidenceHashes].reverse(),
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.recruitmentFeasibility.readinessStatus, 'ready_for_recruitment');
  assert.equal(resultA.recruitmentFeasibility.trustState, 'inactive');
  assert.equal(resultA.recruitmentFeasibility.exochainProductionClaim, false);
  assert.deepEqual(resultA.recruitmentFeasibility.channelsCovered, REQUIRED_RECRUITMENT_CHANNELS);
  assert.deepEqual(resultA.recruitmentFeasibility.screeningDomainsCovered, REQUIRED_SCREENING_DOMAINS);
  assert.equal(resultA.recruitmentFeasibility.forecastRecruitmentCount, 44);
  assert.equal(resultA.recruitmentFeasibility.screeningCapacityCount, 64);
  assert.equal(resultA.recruitmentFeasibility.screeningCoverageBasisPoints, 10000);
  assert.equal(resultA.recruitmentFeasibility.safeguardStatus, 'approved');
  assert.equal(resultA.recruitmentFeasibility.feasibilityId, resultB.recruitmentFeasibility.feasibilityId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'recruitment_feasibility');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(resultA), /participant alice|phone number|raw ad copy|medical record|source document/iu);
});

test('recruitment feasibility fails closed for missing channels vulnerable safeguards and capacity gaps', async () => {
  const { evaluateRecruitmentFeasibility } = await loadRecruitmentFeasibility();

  const result = evaluateRecruitmentFeasibility(
    feasibilityInput({
      recruitmentPlan: {
        targetEnrollmentCount: 36,
        minimumScreeningCapacityCount: 58,
      },
      recruitmentChannels: recruitmentChannels()
        .filter((row) => row.channelRef !== 'participant_registry')
        .map((row) =>
          row.channelRef === 'community_outreach'
            ? {
                ...row,
                safeguardRefs: [],
                iecIrbApprovalHash: '',
                forecastCount: 4,
              }
            : { ...row, forecastCount: 4 },
        ),
      capacityEvidence: {
        activeStaffCount: 5,
        trainedStaffCount: 3,
        delegatedStaffCount: 2,
        screeningSlotCount: 25,
        retentionSupportCapacityCount: 10,
        staffTrainingMatrixHash: '',
        delegationLogHash: '',
      },
      participantProtections: {
        vulnerablePopulationSafeguardsApproved: false,
        safeguardEvidenceHashes: [],
        noRecruitmentBeforeLaunch: false,
        noSupersededMaterials: false,
        participantFacingMaterialIecIrbApproved: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.recruitmentFeasibility.readinessStatus, 'not_ready');
  assert.equal(result.recruitmentFeasibility.safeguardStatus, 'blocked');
  assert.equal(result.recruitmentFeasibility.screeningCoverageBasisPoints, 4310);
  assert.ok(result.reasons.includes('required_recruitment_channel_missing:participant_registry'));
  assert.ok(result.reasons.includes('channel_vulnerable_safeguard_absent:community_outreach'));
  assert.ok(result.reasons.includes('channel_iec_irb_approval_invalid:community_outreach'));
  assert.ok(result.reasons.includes('vulnerable_population_safeguards_not_approved'));
  assert.ok(result.reasons.includes('participant_facing_material_approval_absent'));
  assert.ok(result.reasons.includes('recruitment_before_launch_guard_absent'));
  assert.ok(result.reasons.includes('superseded_material_guard_absent'));
  assert.ok(result.reasons.includes('forecast_below_target_enrollment'));
  assert.ok(result.reasons.includes('screening_capacity_below_required'));
  assert.ok(result.reasons.includes('trained_staff_below_active_staff'));
  assert.ok(result.reasons.includes('delegated_staff_below_trained_staff'));
  assert.ok(result.reasons.includes('retention_support_below_target_enrollment'));
  assert.ok(result.reasons.includes('staff_training_matrix_hash_invalid'));
  assert.ok(result.reasons.includes('delegation_log_hash_invalid'));
});

test('recruitment feasibility requires human governance and metadata-only dependencies', async () => {
  const { evaluateRecruitmentFeasibility } = await loadRecruitmentFeasibility();

  const result = evaluateRecruitmentFeasibility(
    feasibilityInput({
      actor: { did: 'did:exo:ai-recruitment-agent-alpha', kind: 'ai_agent' },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['read'],
        authorityChainHash: 'not-a-hash',
      },
      recruitmentPlan: {
        consentReadinessRef: '',
        protocolFeasibilityRef: '',
        startupRiskAssessmentRef: '',
        metadataOnly: false,
        protectedContentExcluded: false,
        productionTrustClaim: true,
      },
      review: {
        decisionForum: {
          verified: false,
          state: 'pending',
          humanGate: { verified: false },
          quorum: { status: 'not_met' },
          openChallenge: true,
          decisionId: '',
          workflowReceiptId: '',
        },
        evidenceBundle: { complete: false, phiBoundaryAttested: false },
        humanReviewerDid: '',
        finalAuthority: 'ai',
        aiFinalAuthority: true,
      },
      custodyDigest: '',
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('human_actor_required'));
  assert.ok(result.reasons.includes('recruitment_feasibility_authority_missing'));
  assert.ok(result.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(result.reasons.includes('consent_readiness_ref_absent'));
  assert.ok(result.reasons.includes('protocol_feasibility_ref_absent'));
  assert.ok(result.reasons.includes('startup_risk_assessment_ref_absent'));
  assert.ok(result.reasons.includes('recruitment_plan_metadata_boundary_invalid'));
  assert.ok(result.reasons.includes('recruitment_plan_protected_boundary_invalid'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('decision_forum_unverified'));
  assert.ok(result.reasons.includes('human_gate_unverified'));
  assert.ok(result.reasons.includes('quorum_not_met'));
  assert.ok(result.reasons.includes('challenge_open'));
  assert.ok(result.reasons.includes('evidence_bundle_incomplete'));
  assert.ok(result.reasons.includes('phi_boundary_unattested'));
  assert.ok(result.reasons.includes('human_reviewer_absent'));
  assert.ok(result.reasons.includes('human_final_authority_required'));
  assert.ok(result.reasons.includes('custody_digest_invalid'));
});

test('recruitment feasibility rejects raw recruitment content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateRecruitmentFeasibility } = await loadRecruitmentFeasibility();

  assert.throws(
    () =>
      evaluateRecruitmentFeasibility(
        feasibilityInput({
          recruitmentChannels: [
            {
              ...recruitmentChannels()[0],
              rawRecruitmentCopy: 'raw ad copy with participant Alice phone number',
            },
            ...recruitmentChannels().slice(1),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateRecruitmentFeasibility(
        feasibilityInput({
          recruitmentPlan: {
            apiKey: 'sk_live_recruitment_secret',
          },
        }),
      ),
    ProtectedContentError,
  );
});
