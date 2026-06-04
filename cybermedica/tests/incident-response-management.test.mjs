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

const REQUIRED_INCIDENT_FAMILIES = [
  'adapter_degraded',
  'availability_outage',
  'data_integrity_event',
  'privacy_boundary_failure',
  'receipt_queue_backlog',
  'root_bundle_unavailable',
  'security_event',
  'sponsor_export_disclosure',
];

const REQUIRED_RESPONSE_DOMAINS = [
  'audit_record',
  'communications',
  'containment',
  'decision_forum',
  'drift_or_cqi',
  'evidence_preservation',
  'restoration',
  'root_cause',
  'triage',
];

async function loadIncidentResponseManagement() {
  try {
    return await import('../src/incident-response-management.mjs');
  } catch (error) {
    assert.fail(`CyberMedica incident-response-management module must exist and load: ${error.message}`);
  }
}

function evidenceRef(ref, hash = DIGEST_A, overrides = {}) {
  return {
    evidenceRef: ref,
    artifactType: 'incident_response_evidence',
    artifactHash: hash,
    custodyDigest: DIGEST_B,
    receiptId: `cmr-${ref}`,
    classification: 'restricted_metadata_only',
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function communication(audienceClass, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F];
  return {
    audienceClass,
    channelRef: `incident-${audienceClass}-route`,
    messageHash: hashes[index],
    deliveredAtHlc: { physicalMs: 1800800400000, logical: index },
    acknowledged: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function incidentInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    siteId: 'site-alpha',
    actor: {
      did: 'did:exo:incident-commander-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'security_owner', 'incident_commander'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['incident_response_manage', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    incidentPolicy: {
      policyRef: 'incident-response-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredIncidentFamilies: [...REQUIRED_INCIDENT_FAMILIES],
      requiredResponseDomains: [...REQUIRED_RESPONSE_DOMAINS],
      materialDecisionForumRequired: true,
      humanIncidentCommanderRequired: true,
      noProductionTrustClaimWithoutActivation: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800800000000, logical: 0 },
    },
    incident: {
      incidentRef: 'INC-PRIVACY-2026-0001',
      incidentFamily: 'privacy_boundary_failure',
      severity: 'critical',
      status: 'closed_corrective_action_linked',
      sourceSignalRef: 'signal-privacy-boundary-failure-alpha',
      sourceSystemRef: 'health-observability',
      detectedAtHlc: { physicalMs: 1800800100000, logical: 0 },
      participantSafetyImpact: true,
      dataIntegrityImpact: true,
      sponsorCroImpact: true,
      productionTrustClaim: false,
      affectedServiceRefs: ['qms-core', 'receipt-adapter', 'trust-readiness'],
      affectedControlRefs: ['CM-QMS-PRIVACY-001', 'CM-QMS-EXOCHAIN-001'],
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    triage: {
      classifiedAtHlc: { physicalMs: 1800800110000, logical: 0 },
      classifiedByDid: 'did:exo:incident-commander-alpha',
      classificationHash: DIGEST_C,
      incidentCommanderDid: 'did:exo:incident-commander-alpha',
      severityConfirmed: true,
      materialityConfirmed: true,
      participantSafetyReviewed: true,
      dataIntegrityReviewed: true,
      sponsorCroReviewed: true,
      metadataOnly: true,
    },
    containment: {
      status: 'contained',
      containedAtHlc: { physicalMs: 1800800200000, logical: 0 },
      containmentEvidenceHash: DIGEST_D,
      affectedAccessDisabled: true,
      trustClaimsFrozen: true,
      protectedExportsPaused: true,
      failClosedObserved: true,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    evidencePreservation: {
      preservedAtHlc: { physicalMs: 1800800210000, logical: 0 },
      custodyDigest: DIGEST_E,
      legalHoldHash: DIGEST_F,
      evidenceIndexHash: DIGEST_1,
      rawPayloadsExcluded: true,
      immutableAuditRefs: ['audit-incident-alpha'],
      metadataOnly: true,
    },
    evidenceRefs: [
      evidenceRef('evidence-incident-root-cause', DIGEST_A),
      evidenceRef('evidence-incident-containment', DIGEST_C),
      evidenceRef('evidence-incident-restoration', DIGEST_D),
    ],
    rootCause: {
      completedAtHlc: { physicalMs: 1800800300000, logical: 0 },
      analysisHash: DIGEST_2,
      categoryRefs: ['configuration_gap', 'privacy_boundary_gap'],
      correctiveActionRefs: ['CAPA-INC-PRIVACY-001'],
      preventiveActionRefs: ['CQI-INC-PRIVACY-001'],
      humanReviewed: true,
      metadataOnly: true,
    },
    communications: [
      communication('incident_commander', 0),
      communication('operations_owner', 0),
      communication('privacy_officer', 1),
      communication('security_owner', 2),
      communication('site_quality_lead', 3),
      communication('sponsor_cro_contact', 4),
      communication('decision_forum', 5),
    ],
    decisionForum: {
      invoked: true,
      matterRef: 'df-incident-privacy-alpha',
      receiptId: 'cmr-df-incident-privacy-alpha',
      quorumStatus: 'met',
      humanGateVerified: true,
      openChallenge: false,
      decidedAtHlc: { physicalMs: 1800800500000, logical: 0 },
      decision: 'incident_response_accepted',
    },
    restoration: {
      status: 'verified_restored',
      restoredAtHlc: { physicalMs: 1800800600000, logical: 0 },
      restorationEvidenceHash: DIGEST_3,
      validationEvidenceHash: DIGEST_4,
      privacyBoundaryReverified: true,
      receiptQueueReconciled: true,
      trustReadinessRemainsInactive: true,
      metadataOnly: true,
    },
    correctiveLinkage: {
      capaRef: 'CAPA-INC-PRIVACY-001',
      cqiCycleRef: 'CQI-INC-PRIVACY-001',
      driftSignalRef: 'signal-incident-privacy-alpha',
      effectivenessCheckHash: DIGEST_5,
      ownerDid: 'did:exo:quality-manager-alpha',
      dueAtHlc: { physicalMs: 1801400000000, logical: 0 },
      metadataOnly: true,
    },
    humanReview: {
      verified: true,
      reviewedByDid: 'did:exo:quality-director-alpha',
      reviewEvidenceHash: DIGEST_6,
      decision: 'incident_closed_corrective_action_linked',
      reviewedAtHlc: { physicalMs: 1800800700000, logical: 0 },
    },
    auditRecord: {
      auditRecordRef: 'audit-incident-privacy-alpha',
      auditRecordHash: DIGEST_A,
      recordedAtHlc: { physicalMs: 1800800800000, logical: 0 },
      metadataOnly: true,
      includesProtectedContent: false,
    },
    aiAssistance: {
      used: true,
      advisoryOnly: true,
      finalAuthority: false,
      recommendationHash: DIGEST_B,
      humanReviewed: true,
    },
    checkedAtHlc: { physicalMs: 1800800900000, logical: 0 },
    custodyDigest: DIGEST_E,
  };

  return { ...base, ...overrides };
}

test('incident response closes a critical privacy incident with deterministic inactive receipts', async () => {
  const { evaluateIncidentResponseManagement } = await loadIncidentResponseManagement();
  const input = incidentInput();

  const resultA = evaluateIncidentResponseManagement(input);
  const resultB = evaluateIncidentResponseManagement({
    ...input,
    incidentPolicy: {
      ...input.incidentPolicy,
      requiredIncidentFamilies: [...input.incidentPolicy.requiredIncidentFamilies].reverse(),
      requiredResponseDomains: [...input.incidentPolicy.requiredResponseDomains].reverse(),
    },
    incident: {
      ...input.incident,
      affectedServiceRefs: [...input.incident.affectedServiceRefs].reverse(),
      affectedControlRefs: [...input.incident.affectedControlRefs].reverse(),
    },
    evidenceRefs: [...input.evidenceRefs].reverse(),
    communications: [...input.communications].reverse(),
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.incidentRecord.status, 'closed_corrective_action_linked');
  assert.equal(resultA.incidentRecord.materialDecisionForumRequired, true);
  assert.equal(resultA.incidentRecord.containmentStatus, 'contained');
  assert.equal(resultA.incidentRecord.restorationStatus, 'verified_restored');
  assert.equal(resultA.incidentRecord.aiFinalAuthority, false);
  assert.equal(resultA.incidentRecord.exochainProductionClaim, false);
  assert.deepEqual(resultA.incidentRecord.requiredResponseRoles, [
    'decision_forum',
    'incident_commander',
    'operations_owner',
    'privacy_officer',
    'security_owner',
    'site_quality_lead',
    'sponsor_cro_contact',
  ]);
  assert.equal(resultA.incidentRecord.incidentResponseId, resultB.incidentRecord.incidentResponseId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'incident_response_record');
  assert.doesNotMatch(JSON.stringify(resultA), /raw incident|participant name|source document|medical record|api key/iu);
});

test('minor adapter incidents can remain open without Decision Forum when monitoring and drift linkage are documented', async () => {
  const { evaluateIncidentResponseManagement } = await loadIncidentResponseManagement();

  const result = evaluateIncidentResponseManagement(
    incidentInput({
      incident: {
        ...incidentInput().incident,
        incidentRef: 'INC-ADAPTER-2026-0002',
        incidentFamily: 'adapter_degraded',
        severity: 'minor',
        status: 'monitoring',
        participantSafetyImpact: false,
        dataIntegrityImpact: false,
        sponsorCroImpact: false,
        affectedServiceRefs: ['receipt-adapter'],
        affectedControlRefs: ['CM-QMS-EXOCHAIN-001'],
      },
      triage: {
        ...incidentInput().triage,
        materialityConfirmed: false,
        participantSafetyReviewed: false,
        dataIntegrityReviewed: false,
        sponsorCroReviewed: false,
      },
      containment: {
        ...incidentInput().containment,
        status: 'monitoring',
        trustClaimsFrozen: true,
        protectedExportsPaused: false,
      },
      communications: [
        communication('incident_commander', 0),
        communication('operations_owner', 1),
        communication('site_quality_lead', 2),
      ],
      decisionForum: {
        invoked: false,
        matterRef: null,
        receiptId: null,
        quorumStatus: null,
        humanGateVerified: false,
        openChallenge: false,
        decidedAtHlc: null,
        decision: null,
      },
      restoration: {
        ...incidentInput().restoration,
        status: 'monitoring_verified',
        trustReadinessRemainsInactive: true,
      },
      humanReview: {
        ...incidentInput().humanReview,
        decision: 'incident_monitoring_accepted',
      },
    }),
  );

  assert.equal(result.decision, 'permitted');
  assert.equal(result.failClosed, false);
  assert.equal(result.incidentRecord.materialDecisionForumRequired, false);
  assert.equal(result.incidentRecord.status, 'monitoring');
  assert.equal(result.incidentRecord.decisionForumMatterRef, null);
  assert.deepEqual(result.incidentRecord.requiredResponseRoles, [
    'incident_commander',
    'operations_owner',
    'site_quality_lead',
  ]);
});

test('incident response fails closed for unsafe authority missing critical response evidence and AI final authority', async () => {
  const { evaluateIncidentResponseManagement } = await loadIncidentResponseManagement();

  const denied = evaluateIncidentResponseManagement({
    ...incidentInput(),
    actor: { did: 'did:exo:ai-incident-agent-alpha', kind: 'ai_agent' },
    authority: {
      ...incidentInput().authority,
      valid: false,
      permissions: ['read'],
      authorityChainHash: '',
    },
    triage: {
      ...incidentInput().triage,
      severityConfirmed: false,
      incidentCommanderDid: '',
    },
    containment: {
      ...incidentInput().containment,
      status: 'pending',
      failClosedObserved: false,
    },
    decisionForum: {
      ...incidentInput().decisionForum,
      invoked: false,
      receiptId: null,
      humanGateVerified: false,
    },
    restoration: {
      ...incidentInput().restoration,
      privacyBoundaryReverified: false,
      receiptQueueReconciled: false,
    },
    correctiveLinkage: {
      ...incidentInput().correctiveLinkage,
      cqiCycleRef: '',
      driftSignalRef: '',
    },
    humanReview: {
      ...incidentInput().humanReview,
      verified: false,
      decision: 'invalid',
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.receipt, null);
  assert.equal(denied.incidentRecord, null);
  assert.match(denied.reasons.join('|'), /ai_final_authority_forbidden/);
  assert.match(denied.reasons.join('|'), /authority_chain_invalid/);
  assert.match(denied.reasons.join('|'), /incident_response_authority_missing/);
  assert.match(denied.reasons.join('|'), /incident_commander_absent/);
  assert.match(denied.reasons.join('|'), /critical_incident_decision_forum_missing/);
  assert.match(denied.reasons.join('|'), /fail_closed_containment_absent/);
  assert.match(denied.reasons.join('|'), /restoration_privacy_boundary_unverified/);
  assert.match(denied.reasons.join('|'), /corrective_cqi_linkage_absent/);
  assert.match(denied.reasons.join('|'), /human_review_unverified/);

  assert.throws(
    () =>
      evaluateIncidentResponseManagement({
        ...incidentInput(),
        incident: { ...incidentInput().incident, rawIncident: 'raw incident narrative with source details' },
      }),
    /raw incident response content/i,
  );

  assert.throws(
    () =>
      evaluateIncidentResponseManagement({
        ...incidentInput(),
        restoration: { ...incidentInput().restoration, apiKey: 'redacted-api-key-placeholder' },
      }),
    /incident response secret field/i,
  );
});
