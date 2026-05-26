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

const REQUIRED_VISIT_DOMAINS = [
  'active_consent_version',
  'delegated_staff_assignment',
  'eligibility_status',
  'participant_communication',
  'procedure_checklist',
  'product_accountability',
  'safety_assessment_plan',
  'source_data_capture',
  'specimen_collection_plan',
  'visit_window_control',
];

async function loadParticipantVisitReadiness() {
  try {
    return await import('../src/participant-visit-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica participant-visit-readiness module must exist and load: ${error.message}`);
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

function readinessCheck(domainRef, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F];
  return {
    domainRef,
    status: 'ready',
    evidenceHash: hashes[index % hashes.length],
    ownerDid: `did:exo:visit-domain-owner-${index}`,
    completedAtHlc: { physicalMs: 1800000000000 + index, logical: 0 },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function readinessChecks() {
  return REQUIRED_VISIT_DOMAINS.map((domainRef, index) => readinessCheck(domainRef, index));
}

function visitReadinessInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:clinical-research-coordinator-alpha',
      kind: 'human',
      roleRefs: ['clinical_research_coordinator', 'visit_owner'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['manage_participant_visits', 'read'],
      authorityChainHash: DIGEST_A,
    },
    visitPlan: {
      visitRef: 'visit-cardiac-alpha-screening-001',
      visitType: 'screening',
      status: 'scheduled',
      protocolRef: 'protocol-cardiac-alpha',
      siteRef: 'site-alpha',
      participantCodeHash: DIGEST_B,
      activeProtocolVersionRef: 'protocol-version-cardiac-alpha-2',
      activeConsentMaterialRef: 'consent-materials-cardiac-alpha-2',
      requiredVisitDomains: REQUIRED_VISIT_DOMAINS,
      visitWindowOpenHlc: { physicalMs: 1800200000000, logical: 0 },
      scheduledStartHlc: { physicalMs: 1800210000000, logical: 0 },
      scheduledEndHlc: { physicalMs: 1800217200000, logical: 0 },
      visitWindowCloseHlc: { physicalMs: 1800300000000, logical: 0 },
      procedureScheduleHash: DIGEST_C,
      visitChecklistHash: DIGEST_D,
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    readinessChecks: readinessChecks(),
    participantReadiness: {
      participantStatus: 'active',
      consentStatus: 'active',
      codeAssignmentRef: 'participant-code-alpha-001',
      consentProcessRef: 'consent-process-alpha-001',
      currentConsentMaterialRef: 'consent-materials-cardiac-alpha-2',
      reconsentRequired: false,
      withdrawalStatus: 'not_withdrawn',
      lostToFollowUp: false,
      dataUseBoundaryHash: DIGEST_E,
      participantIdentifierSuppressed: true,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    staffReadiness: {
      assignedStaffDid: 'did:exo:clinical-research-coordinator-alpha',
      investigatorDid: 'did:exo:principal-investigator-alpha',
      delegatedTaskRefs: ['delegation-consent-alpha', 'delegation-screening-alpha'],
      trainingMatrixHash: DIGEST_F,
      delegationLogHash: DIGEST_A,
      allRequiredStaffTrained: true,
      allRequiredTasksDelegated: true,
      investigatorAvailable: true,
      backupCoverageHash: DIGEST_B,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    materialsReadiness: {
      specimenLifecycleReadinessRef: 'specimen-lifecycle-ready-alpha',
      facilityProductReadinessRef: 'facility-product-ready-alpha',
      activeDocumentVersionRefs: ['doc-procedure-alpha', 'doc-source-worksheet-alpha'],
      equipmentCalibrationHash: DIGEST_C,
      productAccountabilityHash: DIGEST_D,
      kitReadinessHash: DIGEST_E,
      sourceDataWorksheetHash: DIGEST_F,
      privacyBoundaryHash: DIGEST_A,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    operationalControls: {
      launchGateRef: 'launch-gate-alpha',
      enrollmentGateRef: 'enrollment-gate-alpha',
      launchAuthorized: true,
      enrollmentAuthorized: true,
      dueDateNotificationHash: DIGEST_B,
      deviationEscalationPathHash: DIGEST_C,
      safetyEventEscalationPathHash: DIGEST_D,
      visitReminderPolicyHash: DIGEST_E,
      missedVisitProcedureHash: DIGEST_F,
      unscheduledVisitProcedureHash: DIGEST_A,
      noVisitBeforeLaunchAuthorization: true,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    review: {
      humanReviewerDid: 'did:exo:principal-investigator-alpha',
      reviewedAtHlc: { physicalMs: 1800218000000, logical: 0 },
      evidenceBundle: { complete: true, phiBoundaryAttested: true },
      finalAuthority: 'human',
      aiFinalAuthority: false,
    },
    custodyDigest: DIGEST_D,
  };
  return mergeDeep(base, overrides);
}

test('participant visit readiness creates deterministic inactive metadata receipts', async () => {
  const { evaluateParticipantVisitReadiness } = await loadParticipantVisitReadiness();

  const resultA = evaluateParticipantVisitReadiness(visitReadinessInput());
  const resultB = evaluateParticipantVisitReadiness({
    ...visitReadinessInput(),
    visitPlan: {
      ...visitReadinessInput().visitPlan,
      requiredVisitDomains: [...REQUIRED_VISIT_DOMAINS].reverse(),
    },
    readinessChecks: [...visitReadinessInput().readinessChecks].reverse(),
    staffReadiness: {
      ...visitReadinessInput().staffReadiness,
      delegatedTaskRefs: [...visitReadinessInput().staffReadiness.delegatedTaskRefs].reverse(),
    },
    materialsReadiness: {
      ...visitReadinessInput().materialsReadiness,
      activeDocumentVersionRefs: [...visitReadinessInput().materialsReadiness.activeDocumentVersionRefs].reverse(),
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.participantVisitReadiness.readinessStatus, 'ready_for_visit_execution');
  assert.equal(resultA.participantVisitReadiness.trustState, 'inactive');
  assert.equal(resultA.participantVisitReadiness.exochainProductionClaim, false);
  assert.equal(resultA.participantVisitReadiness.visitType, 'screening');
  assert.equal(resultA.participantVisitReadiness.visitWindowStatus, 'within_window');
  assert.equal(resultA.participantVisitReadiness.participantContinuationStatus, 'eligible_for_visit');
  assert.deepEqual(resultA.participantVisitReadiness.visitDomainsCovered, REQUIRED_VISIT_DOMAINS);
  assert.deepEqual(resultA.participantVisitReadiness.requiredEscalationRoles, []);
  assert.equal(resultA.participantVisitReadiness.readinessId, resultB.participantVisitReadiness.readinessId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'participant_visit_readiness');
  assert.doesNotMatch(JSON.stringify(resultA), /participant alice|visit note|source document|medical record|raw visit/iu);
});

test('participant visit readiness fails closed for missing domains and visit blockers', async () => {
  const { evaluateParticipantVisitReadiness } = await loadParticipantVisitReadiness();

  const result = evaluateParticipantVisitReadiness(
    visitReadinessInput({
      visitPlan: {
        requiredVisitDomains: REQUIRED_VISIT_DOMAINS.filter((domain) => domain !== 'specimen_collection_plan'),
        scheduledStartHlc: { physicalMs: 1800310000000, logical: 0 },
      },
      readinessChecks: readinessChecks()
        .filter((check) => check.domainRef !== 'specimen_collection_plan')
        .map((check) =>
          check.domainRef === 'active_consent_version'
            ? {
                ...check,
                status: 'blocked',
                evidenceHash: '',
              }
            : check,
        ),
      participantReadiness: {
        consentStatus: 'superseded',
        reconsentRequired: true,
      },
      staffReadiness: {
        allRequiredStaffTrained: false,
        allRequiredTasksDelegated: false,
        investigatorAvailable: false,
      },
      materialsReadiness: {
        specimenLifecycleReadinessRef: '',
        productAccountabilityHash: '',
      },
      operationalControls: {
        launchAuthorized: false,
        enrollmentAuthorized: false,
        noVisitBeforeLaunchAuthorization: false,
      },
      review: {
        evidenceBundle: { complete: false, phiBoundaryAttested: false },
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.participantVisitReadiness, null);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('visit_domain_missing:specimen_collection_plan'));
  assert.ok(result.reasons.includes('readiness_check_not_ready:active_consent_version'));
  assert.ok(result.reasons.includes('readiness_check_evidence_hash_invalid:active_consent_version'));
  assert.ok(result.reasons.includes('visit_start_outside_window'));
  assert.ok(result.reasons.includes('participant_consent_not_active'));
  assert.ok(result.reasons.includes('reconsent_required_before_visit'));
  assert.ok(result.reasons.includes('required_staff_training_incomplete'));
  assert.ok(result.reasons.includes('required_task_delegation_incomplete'));
  assert.ok(result.reasons.includes('investigator_unavailable'));
  assert.ok(result.reasons.includes('specimen_lifecycle_readiness_ref_absent'));
  assert.ok(result.reasons.includes('product_accountability_hash_invalid'));
  assert.ok(result.reasons.includes('visit_before_launch_authorization_forbidden'));
  assert.ok(result.reasons.includes('enrollment_gate_not_authorized'));
  assert.ok(result.reasons.includes('review_evidence_bundle_incomplete'));
  assert.ok(result.reasons.includes('phi_boundary_attestation_absent'));
});

test('participant visit readiness fails closed for tenant authority and human review defects', async () => {
  const { evaluateParticipantVisitReadiness } = await loadParticipantVisitReadiness();

  const result = evaluateParticipantVisitReadiness(
    visitReadinessInput({
      targetTenantId: 'tenant-site-beta',
      actor: {
        kind: 'ai_agent',
      },
      authority: {
        valid: true,
        permissions: ['read'],
      },
      review: {
        humanReviewerDid: '',
        finalAuthority: 'ai',
        aiFinalAuthority: true,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.participantVisitReadiness, null);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('tenant_boundary_violation'));
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('human_actor_required'));
  assert.ok(result.reasons.includes('participant_visit_authority_missing'));
  assert.ok(result.reasons.includes('human_reviewer_absent'));
});

test('participant visit readiness denies absent objects without issuing receipts', async () => {
  const { evaluateParticipantVisitReadiness } = await loadParticipantVisitReadiness();

  const result = evaluateParticipantVisitReadiness({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: null,
    authority: null,
    visitPlan: null,
    readinessChecks: null,
    participantReadiness: null,
    staffReadiness: null,
    materialsReadiness: null,
    operationalControls: null,
    review: null,
    custodyDigest: '',
  });

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.equal(result.participantVisitReadiness, null);
  assert.ok(result.reasons.includes('actor_did_absent'));
  assert.ok(result.reasons.includes('authority_chain_invalid'));
  assert.ok(result.reasons.includes('visit_ref_absent'));
  assert.ok(result.reasons.includes('participant_readiness_absent'));
  assert.ok(result.reasons.includes('staff_readiness_absent'));
  assert.ok(result.reasons.includes('materials_readiness_absent'));
  assert.ok(result.reasons.includes('operational_controls_absent'));
  assert.ok(result.reasons.includes('custody_digest_invalid'));
});

test('participant visit readiness rejects raw participant visit content protected content and secrets', async () => {
  const { ProtectedContentError, evaluateParticipantVisitReadiness } = await loadParticipantVisitReadiness();

  assert.throws(
    () =>
      evaluateParticipantVisitReadiness(
        visitReadinessInput({
          visitPlan: {
            rawVisitNotes: 'Participant Alice Example asked about the procedure.',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateParticipantVisitReadiness(
        visitReadinessInput({
          participantReadiness: {
            participantName: 'Alice Example',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateParticipantVisitReadiness(
        visitReadinessInput({
          operationalControls: {
            apiKey: 'visit-system-secret',
          },
        }),
      ),
    ProtectedContentError,
  );
});

test('participant visit readiness exports required domains as immutable contract metadata', async () => {
  const { participantVisitReadinessRequirements } = await loadParticipantVisitReadiness();

  assert.equal(participantVisitReadinessRequirements.schema, 'cybermedica.participant_visit_readiness.v1');
  assert.deepEqual(participantVisitReadinessRequirements.requiredVisitDomains, REQUIRED_VISIT_DOMAINS);
  assert.equal(participantVisitReadinessRequirements.requiredPermission, 'manage_participant_visits');
  assert.equal(participantVisitReadinessRequirements.productionTrustState, 'inactive');
  assert.equal(Object.isFrozen(participantVisitReadinessRequirements.requiredVisitDomains), true);
});
