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

async function loadQualityObjectives() {
  try {
    return await import('../src/quality-objectives.mjs');
  } catch (error) {
    assert.fail(`CyberMedica quality objective module must exist and load: ${error.message}`);
  }
}

function activeObjectiveInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['govern', 'write'] },
    objective: {
      objectiveId: 'CM-QO-ENROLLMENT-001',
      name: 'Enrollment source-data review timeliness',
      sourceStrategyRef: 'site-quality-plan-2026',
      sourceControlIds: ['CM-QMS-MONITORING-001', 'CM-QMS-SOURCE-DATA-002'],
      definition: 'Completed source-data reviews within the protocol-defined review window.',
      numeratorDefinition: 'Reviews completed on time',
      denominatorDefinition: 'Reviews due during the reporting period',
      collectionMethod: 'metadata_receipt_count',
      frequency: 'monthly',
      ownerDid: 'did:exo:clinical-operations-alpha',
      thresholdBasisPoints: 7500,
      targetBasisPoints: 9000,
      alertRule: {
        warningBelowBasisPoints: 7000,
        criticalBelowBasisPoints: 6000,
      },
      riskRefs: ['risk-source-data-late-review'],
      qualityObjectiveLinkage: 'QMS annual review objective 2026-01',
      reportingAudience: ['site_quality_council', 'sponsor_monitor'],
      decisionUse: 'protocol_monitoring_resourcing',
      lifecycleState: 'active',
    },
    measurement: {
      numerator: 80,
      denominator: 100,
      measuredAtHlc: { physicalMs: 1790000000000, logical: 21 },
      evidenceHashes: [DIGEST_A, DIGEST_B],
      custodyDigest: DIGEST_C,
    },
    previousMeasurement: {
      actualBasisPoints: 7600,
      measuredAtHlc: { physicalMs: 1787408000000, logical: 8 },
    },
    review: {
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
      },
      evidenceBundle: { complete: true, phiBoundaryAttested: true },
      approverDid: 'did:exo:principal-investigator-alpha',
    },
  };
}

test('active quality objectives require human governance and create deterministic inactive measurement receipts', async () => {
  const { evaluateQualityObjective } = await loadQualityObjectives();

  const objectiveA = evaluateQualityObjective(activeObjectiveInput());
  const objectiveB = evaluateQualityObjective({
    ...activeObjectiveInput(),
    objective: {
      ...activeObjectiveInput().objective,
      sourceControlIds: [...activeObjectiveInput().objective.sourceControlIds].reverse(),
      riskRefs: [...activeObjectiveInput().objective.riskRefs].reverse(),
      reportingAudience: [...activeObjectiveInput().objective.reportingAudience].reverse(),
    },
    measurement: {
      ...activeObjectiveInput().measurement,
      evidenceHashes: [...activeObjectiveInput().measurement.evidenceHashes].reverse(),
      measuredAtHlc: { logical: 21, physicalMs: 1790000000000 },
    },
  });

  assert.equal(objectiveA.decision, 'permitted');
  assert.equal(objectiveA.failClosed, false);
  assert.equal(objectiveA.qualityObjective.actualBasisPoints, 8000);
  assert.equal(objectiveA.qualityObjective.status, 'within_threshold');
  assert.equal(objectiveA.qualityObjective.alertLevel, 'none');
  assert.equal(objectiveA.qualityObjective.trend, 'improving');
  assert.equal(objectiveA.qualityObjective.humanGovernanceRequired, true);
  assert.equal(objectiveA.receipt.receiptId, objectiveB.receipt.receiptId);
  assert.equal(objectiveA.receipt.actionHash, objectiveB.receipt.actionHash);
  assert.equal(objectiveA.receipt.trustState, 'inactive');
  assert.equal(objectiveA.receipt.exochainProductionClaim, false);
  assert.deepEqual(objectiveA.qualityObjective.sourceControlIds, ['CM-QMS-MONITORING-001', 'CM-QMS-SOURCE-DATA-002']);
  assert.deepEqual(Object.keys(objectiveA.receipt.anchorPayload), [
    'actorDid',
    'artifactHash',
    'artifactType',
    'artifactVersion',
    'classification',
    'custodyDigest',
    'hlcTimestamp',
    'schema',
    'sensitivityTags',
    'sourceSystem',
    'tenantId',
  ]);
});

test('quality objective evaluation fails closed for missing governance invalid ratios and missing linkage evidence', async () => {
  const { evaluateQualityObjective } = await loadQualityObjectives();

  const denied = evaluateQualityObjective({
    ...activeObjectiveInput(),
    actor: { did: 'did:exo:ai-quality-analyst-alpha', kind: 'ai_agent' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['write'] },
    objective: {
      ...activeObjectiveInput().objective,
      sourceControlIds: [],
      qualityObjectiveLinkage: '',
      targetBasisPoints: 10001,
      alertRule: {
        warningBelowBasisPoints: 6500,
        criticalBelowBasisPoints: 7000,
      },
    },
    measurement: {
      ...activeObjectiveInput().measurement,
      numerator: 12,
      denominator: 0,
      evidenceHashes: [],
    },
    review: {
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: false },
        quorum: { status: 'met' },
        openChallenge: false,
      },
      evidenceBundle: { complete: false, phiBoundaryAttested: false },
      approverDid: '',
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.qualityObjective, null);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('source_control_linkage_absent'));
  assert.ok(denied.reasons.includes('quality_objective_linkage_absent'));
  assert.ok(denied.reasons.includes('target_basis_points_invalid'));
  assert.ok(denied.reasons.includes('alert_threshold_order_invalid'));
  assert.ok(denied.reasons.includes('measurement_denominator_invalid'));
  assert.ok(denied.reasons.includes('measurement_evidence_absent'));
  assert.ok(denied.reasons.includes('human_gate_unverified'));
  assert.ok(denied.reasons.includes('evidence_bundle_incomplete'));
});

test('quality objectives produce warning and critical alert states without production trust claims', async () => {
  const { evaluateQualityObjective } = await loadQualityObjectives();

  const warning = evaluateQualityObjective({
    ...activeObjectiveInput(),
    measurement: {
      ...activeObjectiveInput().measurement,
      numerator: 65,
      denominator: 100,
    },
    previousMeasurement: {
      actualBasisPoints: 8000,
      measuredAtHlc: { physicalMs: 1787408000000, logical: 8 },
    },
  });

  assert.equal(warning.decision, 'permitted');
  assert.equal(warning.qualityObjective.actualBasisPoints, 6500);
  assert.equal(warning.qualityObjective.status, 'below_threshold');
  assert.equal(warning.qualityObjective.alertLevel, 'warning');
  assert.equal(warning.qualityObjective.trend, 'declining');
  assert.equal(warning.exochainProductionClaim, false);

  const critical = evaluateQualityObjective({
    ...activeObjectiveInput(),
    measurement: {
      ...activeObjectiveInput().measurement,
      numerator: 55,
      denominator: 100,
    },
    previousMeasurement: null,
  });

  assert.equal(critical.decision, 'permitted');
  assert.equal(critical.qualityObjective.actualBasisPoints, 5500);
  assert.equal(critical.qualityObjective.status, 'below_threshold');
  assert.equal(critical.qualityObjective.alertLevel, 'critical');
  assert.equal(critical.qualityObjective.trend, 'not_established');
  assert.equal(critical.receipt.exochainProductionClaim, false);
});

test('quality objective inputs reject protected content before receipt creation', async () => {
  const { evaluateQualityObjective } = await loadQualityObjectives();

  assert.throws(
    () =>
      evaluateQualityObjective({
        ...activeObjectiveInput(),
        participantName: 'Participant Alice Example',
      }),
    /protected content/i,
  );
});

test('quality objective definitions without measurement data fail closed without throwing', async () => {
  const { evaluateQualityObjective } = await loadQualityObjectives();

  const result = evaluateQualityObjective({
    ...activeObjectiveInput(),
    authority: { valid: true, revoked: false, expired: false, permissions: ['write'] },
    objective: {
      ...activeObjectiveInput().objective,
      lifecycleState: 'draft',
    },
    measurement: null,
    previousMeasurement: null,
    review: null,
  });

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('measurement_absent'));
  assert.equal(result.qualityObjective, null);
  assert.equal(result.receipt, null);
});
