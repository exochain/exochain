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

async function loadCapaWorkflows() {
  try {
    return await import('../src/capa-workflows.mjs');
  } catch (error) {
    assert.fail(`CyberMedica CAPA workflow module must exist and load: ${error.message}`);
  }
}

const closureHash = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const custodyDigest = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const criteriaHash = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';

const governedCapaClosure = Object.freeze({
  tenantId: 'tenant-site-alpha',
  targetTenantId: 'tenant-site-alpha',
  capaId: 'CAPA-2026-0001',
  sourceEventId: 'deviation-2026-0007',
  actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
  capa: {
    status: 'verification_ready',
    type: 'corrective_preventive',
    rootCauseComplete: true,
    correctiveActionImplemented: true,
    preventiveActionImplemented: true,
    impactedPoliciesReviewed: true,
    impactedTrainingReviewed: true,
    verificationMethodDefined: true,
  },
  evidencePackage: {
    complete: true,
    objectiveEvidenceHashes: [closureHash],
    custodyDigest,
  },
  effectiveness: {
    status: 'met',
    criteriaHash,
    checkedAtHlc: { physicalMs: 1790000000000, logical: 14 },
  },
  decisionForum: {
    verified: true,
    state: 'approved',
    humanGate: { verified: true },
    quorum: { status: 'met' },
    openChallenge: false,
  },
  evidenceBundle: { complete: true, phiBoundaryAttested: true },
});

test('CAPA closure denies missing evidence missing effectiveness and AI final authority', async () => {
  const { evaluateCapaClosure } = await loadCapaWorkflows();

  const result = evaluateCapaClosure({
    ...governedCapaClosure,
    actor: { did: 'did:exo:ai-quality-reviewer-alpha', kind: 'ai_agent' },
    evidencePackage: { complete: false, objectiveEvidenceHashes: [], custodyDigest },
    effectiveness: { status: 'not_checked' },
  });

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.closureState, 'open');
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('objective_evidence_absent'));
  assert.ok(result.reasons.includes('evidence_package_incomplete'));
  assert.ok(result.reasons.includes('effectiveness_not_established'));
  assert.equal(result.exochainProductionClaim, false);
});

test('CAPA closure permits verified human closure and produces deterministic inactive receipt metadata', async () => {
  const { evaluateCapaClosure } = await loadCapaWorkflows();

  const closureA = evaluateCapaClosure(governedCapaClosure);
  const closureB = evaluateCapaClosure({
    evidenceBundle: governedCapaClosure.evidenceBundle,
    decisionForum: governedCapaClosure.decisionForum,
    effectiveness: governedCapaClosure.effectiveness,
    evidencePackage: { ...governedCapaClosure.evidencePackage, objectiveEvidenceHashes: [closureHash] },
    capa: governedCapaClosure.capa,
    actor: governedCapaClosure.actor,
    sourceEventId: governedCapaClosure.sourceEventId,
    capaId: governedCapaClosure.capaId,
    targetTenantId: governedCapaClosure.targetTenantId,
    tenantId: governedCapaClosure.tenantId,
  });

  assert.equal(closureA.decision, 'permitted');
  assert.equal(closureA.closureState, 'closed');
  assert.equal(closureA.terminalImmutable, true);
  assert.equal(closureA.receipt.trustState, 'inactive');
  assert.equal(closureA.receipt.exochainProductionClaim, false);
  assert.equal(closureA.receipt.receiptId, closureB.receipt.receiptId);
  assert.deepEqual(Object.keys(closureA.receipt.anchorPayload), [
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

test('CAPA closure can record a documented effectiveness follow-up without claiming final effectiveness', async () => {
  const { evaluateCapaClosure } = await loadCapaWorkflows();

  const result = evaluateCapaClosure({
    ...governedCapaClosure,
    effectiveness: {
      status: 'not_determinable_yet',
      criteriaHash,
      rationale: 'Longitudinal recurrence window has not elapsed.',
      followUpHlc: { physicalMs: 1792592000000, logical: 0 },
    },
  });

  assert.equal(result.decision, 'permitted');
  assert.equal(result.closureState, 'closed_with_effectiveness_followup');
  assert.equal(result.effectivenessFinal, false);
  assert.equal(result.followUpRequired, true);
});
