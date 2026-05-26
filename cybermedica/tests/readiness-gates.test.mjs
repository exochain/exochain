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

async function loadReadinessGates() {
  try {
    return await import('../src/readiness-gates.mjs');
  } catch (error) {
    assert.fail(`CyberMedica readiness gate module must exist and load: ${error.message}`);
  }
}

const assessmentHlc = Object.freeze({ physicalMs: 1790000000000, logical: 11 });
const dayMs = 86_400_000;

const currentEvidence = Object.freeze({
  id: 'evidence-training-matrix-current',
  artifactHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  observedAtHlc: { physicalMs: assessmentHlc.physicalMs - 5 * dayMs, logical: 2 },
  freshnessWindowMs: 30 * dayMs,
  status: 'approved',
});

const staleEvidence = Object.freeze({
  id: 'evidence-delegation-log-stale',
  artifactHash: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  observedAtHlc: { physicalMs: assessmentHlc.physicalMs - 45 * dayMs, logical: 3 },
  freshnessWindowMs: 30 * dayMs,
  status: 'approved',
});

test('control readiness is deterministic and stale evidence blocks active readiness unless formally waived', async () => {
  const { buildControlReadinessSnapshot } = await loadReadinessGates();

  const staleSnapshot = buildControlReadinessSnapshot({
    tenantId: 'tenant-site-alpha',
    assessmentHlc,
    controls: [
      {
        id: 'CM-QMS-TRAINING-001',
        title: 'Protocol training evidence is current',
        applicability: 'applicable',
        riskCriticality: 'critical',
        requiredEvidence: ['training_matrix'],
        evidence: [currentEvidence],
      },
      {
        id: 'CM-QMS-DELEGATION-001',
        title: 'Delegation log is current and approved',
        applicability: 'applicable',
        riskCriticality: 'critical',
        requiredEvidence: ['delegation_log'],
        evidence: [staleEvidence],
      },
    ],
  });

  assert.equal(staleSnapshot.status, 'blocked');
  assert.equal(staleSnapshot.activeReadinessClaim, false);
  assert.equal(staleSnapshot.completenessBasisPoints, 5000);
  assert.deepEqual(staleSnapshot.blockers, [
    {
      controlId: 'CM-QMS-DELEGATION-001',
      evidenceId: 'evidence-delegation-log-stale',
      reason: 'evidence_stale',
      severity: 'critical',
    },
  ]);

  const waivedControls = [
    {
      id: 'CM-QMS-DELEGATION-001',
      title: 'Delegation log is current and approved',
      applicability: 'applicable',
      riskCriticality: 'critical',
      requiredEvidence: ['delegation_log'],
      evidence: [{ ...staleEvidence, waiver: { status: 'approved', authorityDid: 'did:exo:quality-manager-alpha' } }],
    },
    {
      id: 'CM-QMS-TRAINING-001',
      title: 'Protocol training evidence is current',
      applicability: 'applicable',
      riskCriticality: 'critical',
      requiredEvidence: ['training_matrix'],
      evidence: [currentEvidence],
    },
  ];

  const waivedSnapshotA = buildControlReadinessSnapshot({
    tenantId: 'tenant-site-alpha',
    assessmentHlc,
    controls: waivedControls,
  });

  const waivedSnapshotB = buildControlReadinessSnapshot({
    controls: [...waivedControls].reverse(),
    assessmentHlc: { logical: 11, physicalMs: 1790000000000 },
    tenantId: 'tenant-site-alpha',
  });

  assert.equal(waivedSnapshotA.status, 'ready');
  assert.equal(waivedSnapshotA.activeReadinessClaim, true);
  assert.equal(waivedSnapshotA.completenessBasisPoints, 10000);
  assert.equal(waivedSnapshotA.snapshotId, waivedSnapshotB.snapshotId);
});

test('deferred or waived controls require rationale and approval before exclusion from readiness', async () => {
  const { buildControlReadinessSnapshot } = await loadReadinessGates();

  const unapprovedDeferral = buildControlReadinessSnapshot({
    tenantId: 'tenant-site-alpha',
    assessmentHlc,
    controls: [
      {
        id: 'CM-QMS-FACILITY-001',
        title: 'Facility readiness evidence is available',
        applicability: 'deferred',
        riskCriticality: 'critical',
        requiredEvidence: ['facility_readiness'],
        evidence: [],
      },
    ],
  });

  assert.equal(unapprovedDeferral.status, 'blocked');
  assert.deepEqual(unapprovedDeferral.blockers, [
    {
      controlId: 'CM-QMS-FACILITY-001',
      evidenceId: null,
      reason: 'control_exclusion_unapproved',
      severity: 'critical',
    },
  ]);

  const approvedWaiver = buildControlReadinessSnapshot({
    tenantId: 'tenant-site-alpha',
    assessmentHlc,
    controls: [
      {
        id: 'CM-QMS-FACILITY-001',
        title: 'Facility readiness evidence is available',
        applicability: 'waived',
        rationale: 'Protocol does not use site-controlled facility procedures.',
        approval: { status: 'approved', actorDid: 'did:exo:quality-manager-alpha' },
        riskCriticality: 'critical',
        requiredEvidence: ['facility_readiness'],
        evidence: [],
      },
    ],
  });

  assert.equal(approvedWaiver.status, 'ready');
  assert.equal(approvedWaiver.completenessBasisPoints, 10000);
  assert.equal(approvedWaiver.controls[0].status, 'excluded');
  assert.equal(approvedWaiver.controls[0].applicability, 'waived');
});

test('readiness snapshots fail closed for empty control inventory and invalid evidence clocks', async () => {
  const { buildControlReadinessSnapshot } = await loadReadinessGates();

  const emptyInventory = buildControlReadinessSnapshot({
    tenantId: 'tenant-site-alpha',
    assessmentHlc,
    controls: [],
  });

  assert.equal(emptyInventory.status, 'blocked');
  assert.equal(emptyInventory.activeReadinessClaim, false);
  assert.deepEqual(emptyInventory.blockers, [
    {
      controlId: null,
      evidenceId: null,
      reason: 'control_inventory_empty',
      severity: 'critical',
    },
  ]);

  assert.throws(
    () =>
      buildControlReadinessSnapshot({
        tenantId: 'tenant-site-alpha',
        assessmentHlc,
        controls: [
          {
            id: 'CM-QMS-CONSENT-001',
            title: 'Consent version readiness',
            applicability: 'applicable',
            riskCriticality: 'critical',
            requiredEvidence: ['consent_approval'],
            evidence: [
              {
                ...currentEvidence,
                freshnessWindowMs: -1,
              },
            ],
          },
        ],
      }),
    /freshnessWindowMs/i,
  );
});

test('control readiness validates evidence hashes and records missing unapproved or invalid control branches', async () => {
  const { buildControlReadinessSnapshot } = await loadReadinessGates();

  assert.throws(
    () =>
      buildControlReadinessSnapshot({
        tenantId: 'tenant-site-alpha',
        assessmentHlc,
        controls: [
          {
            id: 'CM-QMS-DOC-001',
            title: 'Document inventory evidence is hashed',
            applicability: 'applicable',
            riskCriticality: 'major',
            requiredEvidence: ['document_inventory'],
            evidence: [{ ...currentEvidence, artifactHash: 'not-a-canonical-hash' }],
          },
        ],
      }),
    /artifactHash/i,
  );

  const snapshot = buildControlReadinessSnapshot({
    tenantId: 'tenant-site-alpha',
    assessmentHlc,
    controls: [
      {
        id: 'CM-QMS-CONSENT-001',
        title: 'Consent approval evidence exists',
        applicability: 'applicable',
        riskCriticality: 'critical',
        requiredEvidence: ['consent_approval', 'consent_publication'],
        evidence: [{ ...currentEvidence, id: 'evidence-consent-draft', status: 'draft' }],
      },
      {
        id: 'CM-QMS-UNKNOWN-001',
        title: 'Unknown applicability is not silently accepted',
        applicability: 'paused',
        riskCriticality: 'major',
        requiredEvidence: [],
        evidence: [],
      },
    ],
  });

  assert.equal(snapshot.status, 'blocked');
  assert.deepEqual(snapshot.blockers, [
    {
      controlId: 'CM-QMS-CONSENT-001',
      evidenceId: null,
      reason: 'required_evidence_missing',
      severity: 'critical',
    },
    {
      controlId: 'CM-QMS-CONSENT-001',
      evidenceId: 'evidence-consent-draft',
      reason: 'evidence_not_approved',
      severity: 'critical',
    },
    {
      controlId: 'CM-QMS-UNKNOWN-001',
      evidenceId: null,
      reason: 'control_applicability_invalid',
      severity: 'major',
    },
  ]);
});

test('protocol launch gate denies unresolved blockers and requires human governed readiness approval', async () => {
  const { evaluateProtocolLaunchGate } = await loadReadinessGates();

  const denied = evaluateProtocolLaunchGate({
    tenantId: 'tenant-site-alpha',
    protocolId: 'protocol-cm-001',
    actor: { did: 'did:exo:principal-investigator-alpha', kind: 'human' },
    launchChecks: {
      protocolApproved: true,
      irbApproved: true,
      clinicalTrialAgreementExecuted: true,
      informationManagementPlanApproved: true,
      feasibilityApproved: true,
      startupRiskAssessmentApproved: true,
      staffTrainingComplete: false,
      delegationLogComplete: true,
      consentVersionReady: true,
      facilityReady: true,
      equipmentReady: true,
      productHandlingReady: true,
      saeAeReportingReady: true,
      monitoringArrangementsReady: true,
      documentInventoryComplete: true,
      sponsorCroApprovalsComplete: true,
      aiReviewComplete: true,
      qualityManagerSigned: true,
      piSigned: true,
      authorizedRepresentativeApproved: true,
    },
    unresolvedBlockers: [{ area: 'training', severity: 'critical', id: 'blocker-training-001' }],
    decisionForum: {
      verified: true,
      state: 'approved',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
    },
    evidenceBundle: { complete: true, phiBoundaryAttested: true },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('staff_training_incomplete'));
  assert.ok(denied.reasons.includes('unresolved_critical_blocker'));
  assert.equal(denied.enrollmentAuthorizationActive, false);

  const permitted = evaluateProtocolLaunchGate({
    ...denied.inputEcho,
    launchChecks: Object.fromEntries(Object.keys(denied.inputEcho.launchChecks).map((key) => [key, true])),
    unresolvedBlockers: [],
  });

  assert.equal(permitted.decision, 'permitted');
  assert.equal(permitted.enrollmentAuthorizationActive, true);
  assert.equal(permitted.exochainProductionClaim, false);
});

test('enrollment gate denies inactive protocol launch and superseded consent versions', async () => {
  const { evaluateEnrollmentGate } = await loadReadinessGates();

  const denied = evaluateEnrollmentGate({
    tenantId: 'tenant-site-alpha',
    protocolId: 'protocol-cm-001',
    actor: { did: 'did:exo:clinical-research-coordinator-alpha', kind: 'human' },
    protocol: { status: 'active' },
    launchGate: { status: 'pending', enrollmentAuthorizationActive: false },
    consentForm: { status: 'superseded', version: 'ICF-v1' },
    staffTraining: { complete: true, current: true },
    delegation: { authorized: true, expired: false, revoked: false },
    blockingRisks: [],
    participantConsent: { required: true, status: 'active', revoked: false },
    authority: { valid: true, revoked: false, expired: false, permissions: ['govern'] },
    decisionForum: {
      verified: true,
      state: 'approved',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
    },
    evidenceBundle: { complete: true, phiBoundaryAttested: true },
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('launch_gate_not_approved'));
  assert.ok(denied.reasons.includes('consent_form_superseded'));

  const permitted = evaluateEnrollmentGate({
    ...denied.inputEcho,
    launchGate: { status: 'approved', enrollmentAuthorizationActive: true },
    consentForm: { status: 'active', version: 'ICF-v2' },
  });

  assert.equal(permitted.decision, 'permitted');
  assert.equal(permitted.participantMayEnroll, true);
  assert.equal(permitted.trustState, 'inactive');
});
