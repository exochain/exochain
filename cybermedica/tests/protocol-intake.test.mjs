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

const REQUIRED_ARTIFACT_TYPES = [
  'investigator_brochure',
  'protocol_amendment',
  'protocol_document',
  'sponsor_material',
  'trial_agreement',
];

async function loadProtocolIntake() {
  try {
    return await import('../src/protocol-intake.mjs');
  } catch (error) {
    assert.fail(`CyberMedica protocol intake module must exist and load: ${error.message}`);
  }
}

function artifact(artifactType, index, overrides = {}) {
  return {
    artifactRef: `${artifactType}-alpha-${index}`,
    artifactType,
    versionRef: `${artifactType}:v${index + 1}`,
    artifactHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E][index % 5],
    custodyDigest: [DIGEST_E, DIGEST_D, DIGEST_C, DIGEST_B, DIGEST_A][index % 5],
    classification: artifactType === 'trial_agreement' ? 'contract_metadata_only' : 'sponsor_confidential_metadata_only',
    sourcePartyRef: artifactType === 'sponsor_material' ? 'sponsor-alpha' : 'cro-alpha',
    receivedAtHlc: { physicalMs: 1801000000000 + index, logical: index },
    humanReviewed: true,
    phiBoundaryAttested: true,
    protectedContentExcluded: true,
    metadataOnly: true,
    ...overrides,
  };
}

function protocolIntakeInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:protocol-intake-owner-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'study_startup_lead'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['protocol_intake', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    intakePacket: {
      packetRef: 'protocol-intake-packet-alpha',
      protocolRef: 'protocol-cm-alpha',
      siteRef: 'site-alpha',
      sponsorRef: 'sponsor-alpha',
      croRef: 'cro-alpha',
      studyRef: 'study-alpha',
      intakePurpose: 'initial_protocol_startup',
      sourceSystemRef: 'sponsor-portal-alpha',
      receivedAtHlc: { physicalMs: 1801000000000, logical: 0 },
      classifiedAtHlc: { physicalMs: 1801000005000, logical: 0 },
      reviewedAtHlc: { physicalMs: 1801000010000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    artifactCoverage: REQUIRED_ARTIFACT_TYPES.map((artifactType) => ({
      artifactType,
      status: artifactType === 'protocol_amendment' ? 'not_applicable' : 'received',
      rationaleHash: artifactType === 'protocol_amendment' ? DIGEST_F : null,
    })),
    artifacts: [
      artifact('protocol_document', 0),
      artifact('sponsor_material', 1),
      artifact('investigator_brochure', 2),
      artifact('trial_agreement', 3),
    ],
    confidentialityProfile: {
      profileRef: 'protocol-intake-confidentiality-alpha',
      accessPolicyRef: 'protocol-startup-access-policy-alpha',
      retentionScheduleRef: 'trial-startup-retention-alpha',
      classificationRefs: [
        'sponsor-confidential-metadata-only',
        'qms-metadata-only',
      ],
      encryptedAtRest: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      directIdentifiersExcluded: true,
      sponsorConfidentialBoundaryAttested: true,
      externalAnchorEligible: false,
    },
    review: {
      qualityReviewerDid: 'did:exo:quality-reviewer-alpha',
      humanReviewed: true,
      aiAssisted: true,
      aiFinalAuthority: false,
      reviewDecision: 'ready_for_feasibility',
      reviewDecisionHash: DIGEST_B,
      requiredEscalationRoles: ['decision_forum', 'quality_manager', 'study_startup_lead'],
    },
    decisionForum: {
      required: true,
      verified: true,
      state: 'approved',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
      decisionId: 'df-protocol-intake-alpha',
      workflowReceiptId: 'df-workflow-protocol-intake-alpha',
    },
    custodyDigest: DIGEST_1,
  };
  return {
    ...base,
    ...overrides,
  };
}

test('protocol intake module loads', async () => {
  const mod = await loadProtocolIntake();
  assert.equal(typeof mod.evaluateProtocolIntake, 'function');
});

test('protocol intake creates deterministic inactive metadata receipt for FR-010 coverage', async () => {
  const { evaluateProtocolIntake } = await loadProtocolIntake();

  const first = evaluateProtocolIntake(protocolIntakeInput());
  const second = evaluateProtocolIntake({
    ...protocolIntakeInput(),
    artifactCoverage: [...protocolIntakeInput().artifactCoverage].reverse(),
    artifacts: [...protocolIntakeInput().artifacts].reverse(),
    confidentialityProfile: {
      ...protocolIntakeInput().confidentialityProfile,
      classificationRefs: [...protocolIntakeInput().confidentialityProfile.classificationRefs].reverse(),
    },
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.protocolIntake.intakeReady, true);
  assert.equal(first.protocolIntake.readinessStatus, 'ready_for_feasibility');
  assert.equal(first.protocolIntake.exochainProductionClaim, false);
  assert.equal(first.protocolIntake.trustState, 'inactive');
  assert.equal(first.protocolIntake.aiFinalAuthority, false);
  assert.equal(first.protocolIntake.coverageBasisPoints, 10000);
  assert.deepEqual(first.protocolIntake.supportedArtifactTypes, REQUIRED_ARTIFACT_TYPES);
  assert.deepEqual(first.protocolIntake.receivedArtifactTypes, [
    'investigator_brochure',
    'protocol_document',
    'sponsor_material',
    'trial_agreement',
  ]);
  assert.deepEqual(first.protocolIntake.notApplicableArtifactTypes, ['protocol_amendment']);
  assert.deepEqual(first.protocolIntake.requiredEscalationRoles, [
    'decision_forum',
    'quality_manager',
    'study_startup_lead',
  ]);
  assert.equal(first.protocolIntake.packetId, second.protocolIntake.packetId);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.receipt.actionHash, second.receipt.actionHash);
  assert.equal(first.receipt.anchorPayload.artifactType, 'protocol_intake_packet');
  assert.equal(first.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(first), /source document|raw protocol|participant alice|patient/iu);
});

test('protocol intake fails closed when required materials or governance evidence are absent', async () => {
  const { evaluateProtocolIntake } = await loadProtocolIntake();
  const input = protocolIntakeInput({
    artifactCoverage: protocolIntakeInput().artifactCoverage.filter(
      (coverage) => coverage.artifactType !== 'sponsor_material',
    ),
    artifacts: protocolIntakeInput().artifacts.filter((item) => item.artifactType !== 'sponsor_material'),
    actor: { did: 'did:exo:ai-intake-agent-alpha', kind: 'ai_agent' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['read'],
      authorityChainHash: DIGEST_A,
    },
    review: {
      ...protocolIntakeInput().review,
      aiFinalAuthority: true,
      humanReviewed: false,
      reviewDecision: 'ready_for_feasibility',
      qualityReviewerDid: '',
    },
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
  });

  const denied = evaluateProtocolIntake(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.protocolIntake.intakeReady, false);
  assert.equal(denied.protocolIntake.readinessStatus, 'blocked');
  assert.equal(denied.protocolIntake.coverageBasisPoints, 8000);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('human_actor_required'));
  assert.ok(denied.reasons.includes('protocol_intake_authority_missing'));
  assert.ok(denied.reasons.includes('artifact_coverage_missing:sponsor_material'));
  assert.ok(denied.reasons.includes('artifact_required_but_absent:sponsor_material'));
  assert.ok(denied.reasons.includes('human_review_required'));
  assert.ok(denied.reasons.includes('decision_forum_unverified'));
  assert.ok(denied.reasons.includes('human_gate_unverified'));
  assert.ok(denied.reasons.includes('quorum_not_met'));
});

test('protocol intake denies unsafe HLC ordering and malformed artifact metadata', async () => {
  const { evaluateProtocolIntake } = await loadProtocolIntake();
  const input = protocolIntakeInput({
    intakePacket: {
      ...protocolIntakeInput().intakePacket,
      receivedAtHlc: { physicalMs: 1801000015000, logical: 0 },
      classifiedAtHlc: { physicalMs: 1801000005000, logical: 0 },
      reviewedAtHlc: { physicalMs: 1801000000000, logical: 0 },
      productionTrustClaim: true,
    },
    artifacts: [
      ...protocolIntakeInput().artifacts,
      artifact('protocol_amendment', 4, {
        artifactHash: 'bad-hash',
        custodyDigest: DIGEST_F,
        humanReviewed: false,
        phiBoundaryAttested: false,
        metadataOnly: false,
        protectedContentExcluded: false,
        supersedesArtifactRef: '',
        amendmentImpactHash: '',
      }),
    ],
    confidentialityProfile: {
      ...protocolIntakeInput().confidentialityProfile,
      encryptedAtRest: false,
      directIdentifiersExcluded: false,
      externalAnchorEligible: true,
    },
  });

  const denied = evaluateProtocolIntake(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('classified_before_received'));
  assert.ok(denied.reasons.includes('reviewed_before_classified'));
  assert.ok(denied.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(denied.reasons.includes('artifact_hash_invalid:protocol_amendment-alpha-4'));
  assert.ok(denied.reasons.includes('artifact_human_review_absent:protocol_amendment-alpha-4'));
  assert.ok(denied.reasons.includes('artifact_phi_boundary_unattested:protocol_amendment-alpha-4'));
  assert.ok(denied.reasons.includes('protocol_amendment_supersession_absent:protocol_amendment-alpha-4'));
  assert.ok(denied.reasons.includes('protocol_amendment_impact_hash_invalid:protocol_amendment-alpha-4'));
  assert.ok(denied.reasons.includes('confidentiality_encryption_absent'));
  assert.ok(denied.reasons.includes('direct_identifier_boundary_unattested'));
  assert.ok(denied.reasons.includes('external_anchor_must_be_disabled_for_intake'));
});

test('protocol intake rejects raw protocol text protected content and secret material', async () => {
  const { ProtectedContentError, evaluateProtocolIntake } = await loadProtocolIntake();

  assert.throws(
    () =>
      evaluateProtocolIntake({
        ...protocolIntakeInput(),
        artifacts: [
          {
            ...protocolIntakeInput().artifacts[0],
            rawProtocolBody: 'full protocol narrative with participant Alice details',
          },
        ],
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateProtocolIntake({
        ...protocolIntakeInput(),
        sourceConnector: {
          apiToken: 'secret-token-value',
        },
      }),
    ProtectedContentError,
  );
});
