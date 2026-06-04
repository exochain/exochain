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

const REQUIRED_AUDIENCES = ['cro_operations', 'sponsor_facing'];
const SPONSOR_SECTIONS = [
  'access_limitations',
  'authorized_exports',
  'capa_status',
  'launch_gate',
  'open_findings',
  'provider_readiness',
  'readiness_status',
  'risk_summary',
];
const CRO_SECTIONS = [
  'findings_capa_tracking',
  'monitoring_plan',
  'portfolio_readiness',
  'provider_coordination',
  'sponsor_reporting',
  'startup_status',
  'systemic_risk',
  'training_quality_trends',
];

async function loadReadinessPackets() {
  try {
    return await import('../src/readiness-packets.mjs');
  } catch (error) {
    assert.fail(`CyberMedica readiness packet module must exist and load: ${error.message}`);
  }
}

function packet(audience, index, overrides = {}) {
  const sections = audience === 'sponsor_facing' ? SPONSOR_SECTIONS : CRO_SECTIONS;
  const recipientClass = audience === 'sponsor_facing' ? 'sponsor' : 'cro';
  return {
    audience,
    packetRef: `packet-${audience}-alpha`,
    status: 'ready',
    recipientClass,
    authorizedRoleRefs: audience === 'sponsor_facing' ? ['sponsor_viewer'] : ['cro_portfolio_manager'],
    sections,
    packetHash: [DIGEST_A, DIGEST_B][index],
    accessPolicyHash: [DIGEST_C, DIGEST_D][index],
    disclosurePolicyHash: [DIGEST_E, DIGEST_F][index],
    exportControlReceiptId: `cmr_export_control_${audience}`,
    generatedAtHlc: { physicalMs: 1812800030000 + index * 1000, logical: 0 },
    metadataOnly: true,
    suppressedProtectedContent: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function readinessPacketInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    protocolRef: 'protocol-cm-alpha',
    studyRef: 'study-alpha',
    siteRef: 'site-alpha',
    actor: {
      did: 'did:exo:readiness-packet-owner-alpha',
      kind: 'human',
      roleRefs: ['quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['readiness_packet_publish', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    launchGate: {
      decision: 'permitted',
      enrollmentAuthorizationActive: true,
      receiptId: 'cmr_launch_gate_alpha',
      gateHash: DIGEST_B,
      reviewedAtHlc: { physicalMs: 1812800010000, logical: 0 },
      productionTrustClaim: false,
    },
    providerReadiness: {
      status: 'ready',
      readinessHash: DIGEST_C,
      receiptId: 'cmr_provider_readiness_alpha',
      providerReadinessBasisPoints: 10000,
      reviewedAtHlc: { physicalMs: 1812800015000, logical: 0 },
      productionTrustClaim: false,
    },
    readinessDecision: {
      decisionRecordRef: 'readiness-decision-alpha',
      decisionHash: DIGEST_D,
      decisionForumMatterRef: 'df-readiness-alpha',
      status: 'approved',
      humanGateVerified: true,
      quorumMet: true,
      openChallenge: false,
      reviewedAtHlc: { physicalMs: 1812800020000, logical: 0 },
      aiAssisted: true,
      aiFinalAuthority: false,
    },
    packetSet: {
      packetSetRef: 'readiness-packet-set-alpha',
      generatedAtHlc: { physicalMs: 1812800040000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    audiencePackets: [packet('sponsor_facing', 0), packet('cro_operations', 1)],
    packetEvidence: {
      riskSummaryHash: DIGEST_E,
      openFindingsHash: DIGEST_F,
      capaStatusHash: DIGEST_1,
      authorizedExportManifestHash: DIGEST_2,
      accessLimitationPolicyHash: DIGEST_A,
      monitoringPlanHash: DIGEST_B,
      portfolioComparisonHash: DIGEST_C,
      trainingQualityTrendHash: DIGEST_D,
      systemicRiskHash: DIGEST_E,
      sponsorReportControlHash: DIGEST_F,
      custodyDigest: DIGEST_1,
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-manager-alpha',
      reviewedAtHlc: { physicalMs: 1812800050000, logical: 0 },
      status: 'approved',
      reviewHash: DIGEST_2,
      aiFinalAuthority: false,
    },
    custodyDigest: DIGEST_1,
  };

  return {
    ...base,
    ...overrides,
  };
}

test('readiness packet module loads', async () => {
  const mod = await loadReadinessPackets();
  assert.equal(typeof mod.evaluateReadinessPackets, 'function');
});

test('readiness packets create deterministic inactive sponsor and CRO packet receipts', async () => {
  const { evaluateReadinessPackets } = await loadReadinessPackets();

  const first = evaluateReadinessPackets(readinessPacketInput());
  const second = evaluateReadinessPackets({
    ...readinessPacketInput(),
    audiencePackets: [...readinessPacketInput().audiencePackets].reverse(),
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.packetSet.status, 'ready');
  assert.equal(first.packetSet.trustState, 'inactive');
  assert.equal(first.packetSet.exochainProductionClaim, false);
  assert.deepEqual(first.packetSet.requiredAudiences, REQUIRED_AUDIENCES);
  assert.deepEqual(first.packetSet.coveredAudiences, REQUIRED_AUDIENCES);
  assert.equal(first.packetSet.packetReadinessBasisPoints, 10000);
  assert.equal(first.packetSet.packetSetHash, second.packetSet.packetSetHash);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.receipt.anchorPayload.artifactType, 'readiness_packet_set');
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.deepEqual(first.packetSet.packets[0].sections, CRO_SECTIONS);
  assert.deepEqual(first.packetSet.packets[1].sections, SPONSOR_SECTIONS);
  assert.doesNotMatch(JSON.stringify(first), /Participant Alice|source document|raw packet|access token/iu);
});

test('readiness packets fail closed for missing audience packets and sections', async () => {
  const { evaluateReadinessPackets } = await loadReadinessPackets();

  const missingAudience = evaluateReadinessPackets({
    ...readinessPacketInput(),
    audiencePackets: [packet('cro_operations', 1)],
  });

  assert.equal(missingAudience.decision, 'denied');
  assert.equal(missingAudience.failClosed, true);
  assert.equal(missingAudience.receipt, null);
  assert.ok(missingAudience.reasons.includes('packet_audience_missing:sponsor_facing'));

  const missingSection = evaluateReadinessPackets({
    ...readinessPacketInput(),
    audiencePackets: [
      packet('sponsor_facing', 0, { sections: SPONSOR_SECTIONS.filter((section) => section !== 'open_findings') }),
      packet('cro_operations', 1, { sections: CRO_SECTIONS.filter((section) => section !== 'systemic_risk') }),
    ],
  });

  assert.equal(missingSection.decision, 'denied');
  assert.ok(missingSection.reasons.includes('packet_section_missing:sponsor_facing:open_findings'));
  assert.ok(missingSection.reasons.includes('packet_section_missing:cro_operations:systemic_risk'));
});

test('readiness packets require launch provider readiness and human-governed approval evidence', async () => {
  const { evaluateReadinessPackets } = await loadReadinessPackets();

  const result = evaluateReadinessPackets({
    ...readinessPacketInput(),
    launchGate: {
      ...readinessPacketInput().launchGate,
      decision: 'denied',
      enrollmentAuthorizationActive: false,
      productionTrustClaim: true,
    },
    providerReadiness: {
      ...readinessPacketInput().providerReadiness,
      status: 'blocked',
      providerReadinessBasisPoints: 7500,
    },
    readinessDecision: {
      ...readinessPacketInput().readinessDecision,
      status: 'deferred',
      humanGateVerified: false,
      quorumMet: false,
      openChallenge: true,
      aiFinalAuthority: true,
    },
    packetSet: {
      ...readinessPacketInput().packetSet,
      productionTrustClaim: true,
    },
  });

  assert.equal(result.decision, 'denied');
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('launch_gate_not_permitted'));
  assert.ok(result.reasons.includes('provider_readiness_not_ready'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('readiness_decision_not_approved'));
  assert.ok(result.reasons.includes('human_gate_unverified'));
  assert.ok(result.reasons.includes('quorum_not_met'));
  assert.ok(result.reasons.includes('challenge_open'));
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
});

test('readiness packets enforce audience access policy and HLC ordering', async () => {
  const { evaluateReadinessPackets } = await loadReadinessPackets();

  const result = evaluateReadinessPackets({
    ...readinessPacketInput(),
    audiencePackets: [
      packet('sponsor_facing', 0, {
        recipientClass: 'public_observer',
        authorizedRoleRefs: [],
        exportControlReceiptId: '',
        generatedAtHlc: { physicalMs: 1812800010000, logical: 0 },
        suppressedProtectedContent: false,
      }),
      packet('cro_operations', 1, {
        recipientClass: 'sponsor',
        status: 'draft',
        generatedAtHlc: { physicalMs: 1812800010000, logical: -1 },
      }),
    ],
    humanReview: {
      ...readinessPacketInput().humanReview,
      reviewedAtHlc: { physicalMs: 1812800035000, logical: 0 },
      aiFinalAuthority: true,
    },
  });

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('packet_recipient_class_invalid:sponsor_facing'));
  assert.ok(result.reasons.includes('packet_authorized_roles_absent:sponsor_facing'));
  assert.ok(result.reasons.includes('packet_export_control_receipt_absent:sponsor_facing'));
  assert.ok(result.reasons.includes('packet_protected_content_suppression_absent:sponsor_facing'));
  assert.ok(result.reasons.includes('packet_generated_before_readiness_decision:sponsor_facing'));
  assert.ok(result.reasons.includes('packet_recipient_class_invalid:cro_operations'));
  assert.ok(result.reasons.includes('packet_not_ready:cro_operations'));
  assert.ok(result.reasons.includes('packet_generated_time_invalid:cro_operations'));
  assert.ok(result.reasons.includes('human_review_before_packet_set_generation'));
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
});

test('readiness packets reject raw packet content and secrets', async () => {
  const { ProtectedContentError, evaluateReadinessPackets } = await loadReadinessPackets();

  assert.throws(
    () =>
      evaluateReadinessPackets({
        ...readinessPacketInput(),
        audiencePackets: [
          {
            ...packet('sponsor_facing', 0),
            rawSponsorPacket: 'Participant Alice Example source document text.',
          },
          packet('cro_operations', 1),
        ],
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateReadinessPackets({
        ...readinessPacketInput(),
        audiencePackets: [
          packet('sponsor_facing', 0),
          {
            ...packet('cro_operations', 1),
            accessToken: 'secret-token-value',
          },
        ],
      }),
    ProtectedContentError,
  );
});
