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

const REQUIRED_POLICY_DOMAINS = [
  'approved_protocol_version',
  'deviation_management',
  'document_security',
  'iec_irb_approval_tracking',
  'staff_communication',
  'training_update',
];

const REQUIRED_COMMUNICATION_AUDIENCES = [
  'investigator',
  'pharmacy',
  'site_quality',
  'sponsor_cro',
  'study_staff',
];

async function loadProtocolControl() {
  try {
    return await import('../src/protocol-control.mjs');
  } catch (error) {
    assert.fail(`CyberMedica protocol control module must exist and load: ${error.message}`);
  }
}

function protocolControlInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:protocol-control-owner-alpha',
      kind: 'human',
      roleRefs: ['principal_investigator', 'regulatory_coordinator'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['protocol_control', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    protocolControl: {
      controlRef: 'protocol-control-cardio-alpha-v3',
      protocolRef: 'protocol-cm-alpha',
      studyRef: 'study-alpha',
      siteRef: 'site-alpha',
      activeProtocolVersionRef: 'protocol-cm-alpha:v3',
      amendmentRef: 'amendment-cm-alpha-002',
      status: 'active',
      approvedAtHlc: { physicalMs: 1812000000000, logical: 0 },
      effectiveAtHlc: { physicalMs: 1812000005000, logical: 0 },
      evaluatedAtHlc: { physicalMs: 1812000030000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    policyCoverage: REQUIRED_POLICY_DOMAINS.map((domain, index) => ({
      domain,
      evidenceHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F][index],
      status: 'verified',
      metadataOnly: true,
    })),
    versionControl: {
      protocolDocumentHash: DIGEST_B,
      approvedVersionReceiptId: 'cmr_protocol_version_approved_alpha',
      documentVersionReceiptId: 'cmr_document_version_protocol_alpha',
      supersededVersionRefs: ['protocol-cm-alpha:v1', 'protocol-cm-alpha:v2'],
      currentVersionConfirmed: true,
      amendmentPackageHash: DIGEST_C,
      implementationPlanHash: DIGEST_D,
    },
    ethicsApproval: {
      independentEthicsReviewRef: 'irb-review-cardio-alpha',
      ethicsReceiptId: 'cmr_ethics_review_cardio_alpha',
      approvalStatus: 'approved',
      approvalEvidenceHash: DIGEST_C,
      approvalAppliesToActiveVersion: true,
      amendmentApprovalRequired: true,
      amendmentApprovalStatus: 'approved',
      approvalExpiresAtHlc: { physicalMs: 1816000000000, logical: 0 },
    },
    staffCommunication: {
      communicationPlanRef: 'protocol-communication-plan-alpha',
      audienceRefs: REQUIRED_COMMUNICATION_AUDIENCES,
      channelPolicyRefs: ['secure_portal', 'team_huddle', 'sponsor_notice'],
      communicationEvidenceHash: DIGEST_D,
      deliveredAtHlc: { physicalMs: 1812000010000, logical: 0 },
      acknowledgementCoverageBasisPoints: 10000,
      disclosureLogHash: DIGEST_E,
      metadataOnly: true,
    },
    deviationManagement: {
      deviationProcessRef: 'protocol-deviation-process-alpha',
      deviationLogRef: 'deviation-log-alpha',
      deviationLogLinked: true,
      openCriticalDeviations: 0,
      escalationPathHash: DIGEST_E,
      capaLinkageRequired: true,
      capaLinkageReady: true,
    },
    documentSecurity: {
      accessPolicyRef: 'protocol-document-access-policy-alpha',
      leastPrivilege: true,
      currentVersionOnly: true,
      obsoleteVersionsWithdrawn: true,
      accessLogHash: DIGEST_F,
      securityEvidenceHash: DIGEST_1,
      controlledDocumentRefs: ['protocol-cm-alpha:v3', 'icf-cardio-alpha:v4'],
    },
    trainingUpdate: {
      trainingMatrixRef: 'training-matrix-protocol-alpha-v3',
      updateEvidenceHash: DIGEST_A,
      affectedRoleRefs: ['coordinator', 'investigator', 'pharmacy'],
      allAffectedStaffTrained: true,
      delegationEligibilityUpdated: true,
      effectiveBeforeProtocolUse: true,
      trainingCompletedAtHlc: { physicalMs: 1812000020000, logical: 0 },
    },
    reviewGovernance: {
      humanReviewerDid: 'did:exo:principal-investigator-alpha',
      decisionForum: {
        required: true,
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-protocol-control-alpha',
        workflowReceiptId: 'df-protocol-control-workflow-alpha',
      },
      aiAssisted: true,
      aiFinalAuthority: false,
    },
    custodyDigest: DIGEST_1,
  };
  return {
    ...base,
    ...overrides,
  };
}

test('protocol control module loads', async () => {
  const mod = await loadProtocolControl();
  assert.equal(typeof mod.evaluateProtocolControl, 'function');
});

test('protocol control creates deterministic inactive Policy 8 receipts', async () => {
  const { evaluateProtocolControl } = await loadProtocolControl();

  const first = evaluateProtocolControl(protocolControlInput());
  const second = evaluateProtocolControl({
    ...protocolControlInput(),
    policyCoverage: [...protocolControlInput().policyCoverage].reverse(),
    versionControl: {
      ...protocolControlInput().versionControl,
      supersededVersionRefs: [...protocolControlInput().versionControl.supersededVersionRefs].reverse(),
    },
    staffCommunication: {
      ...protocolControlInput().staffCommunication,
      audienceRefs: [...protocolControlInput().staffCommunication.audienceRefs].reverse(),
      channelPolicyRefs: [...protocolControlInput().staffCommunication.channelPolicyRefs].reverse(),
    },
    documentSecurity: {
      ...protocolControlInput().documentSecurity,
      controlledDocumentRefs: [...protocolControlInput().documentSecurity.controlledDocumentRefs].reverse(),
    },
    trainingUpdate: {
      ...protocolControlInput().trainingUpdate,
      affectedRoleRefs: [...protocolControlInput().trainingUpdate.affectedRoleRefs].reverse(),
    },
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.protocolControl.controlReady, true);
  assert.equal(first.protocolControl.controlState, 'active');
  assert.equal(first.protocolControl.protocolRef, 'protocol-cm-alpha');
  assert.equal(first.protocolControl.activeProtocolVersionRef, 'protocol-cm-alpha:v3');
  assert.equal(first.protocolControl.policyCoverageBasisPoints, 10000);
  assert.deepEqual(first.protocolControl.policyCoverage, REQUIRED_POLICY_DOMAINS);
  assert.deepEqual(first.protocolControl.communicationAudiences, REQUIRED_COMMUNICATION_AUDIENCES);
  assert.equal(first.protocolControl.ethicsApprovalStatus, 'approved');
  assert.equal(first.protocolControl.staffCommunicationReady, true);
  assert.equal(first.protocolControl.documentSecurityReady, true);
  assert.equal(first.protocolControl.trainingUpdateReady, true);
  assert.equal(first.protocolControl.trustState, 'inactive');
  assert.equal(first.protocolControl.exochainProductionClaim, false);
  assert.equal(first.protocolControl.controlHash, second.protocolControl.controlHash);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.receipt.anchorPayload.artifactType, 'protocol_control');
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(first), /source document|raw protocol|participant alice|patient|medical record/iu);
});

test('protocol control fails closed for approval communication security and training defects', async () => {
  const { evaluateProtocolControl } = await loadProtocolControl();
  const input = protocolControlInput({
    actor: { did: 'did:exo:ai-protocol-agent-alpha', kind: 'ai_agent' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['read'],
      authorityChainHash: DIGEST_A,
    },
    protocolControl: {
      ...protocolControlInput().protocolControl,
      status: 'pending',
      productionTrustClaim: true,
    },
    policyCoverage: protocolControlInput().policyCoverage.filter((item) => item.domain !== 'training_update'),
    ethicsApproval: {
      ...protocolControlInput().ethicsApproval,
      approvalStatus: 'pending',
      amendmentApprovalStatus: 'pending',
      approvalAppliesToActiveVersion: false,
      approvalEvidenceHash: '',
    },
    staffCommunication: {
      ...protocolControlInput().staffCommunication,
      audienceRefs: ['investigator'],
      communicationEvidenceHash: '',
      acknowledgementCoverageBasisPoints: 8500,
    },
    deviationManagement: {
      ...protocolControlInput().deviationManagement,
      deviationLogLinked: false,
      openCriticalDeviations: 1,
      capaLinkageReady: false,
    },
    documentSecurity: {
      ...protocolControlInput().documentSecurity,
      leastPrivilege: false,
      currentVersionOnly: false,
      obsoleteVersionsWithdrawn: false,
      accessLogHash: '',
    },
    trainingUpdate: {
      ...protocolControlInput().trainingUpdate,
      allAffectedStaffTrained: false,
      delegationEligibilityUpdated: false,
      effectiveBeforeProtocolUse: false,
      updateEvidenceHash: '',
    },
    reviewGovernance: {
      ...protocolControlInput().reviewGovernance,
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

  const denied = evaluateProtocolControl(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.protocolControl.controlReady, false);
  assert.equal(denied.protocolControl.controlState, 'blocked');
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('human_actor_required'));
  assert.ok(denied.reasons.includes('protocol_control_authority_missing'));
  assert.ok(denied.reasons.includes('protocol_control_not_active'));
  assert.ok(denied.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(denied.reasons.includes('policy_domain_missing:training_update'));
  assert.ok(denied.reasons.includes('ethics_approval_not_approved'));
  assert.ok(denied.reasons.includes('ethics_approval_not_version_bound'));
  assert.ok(denied.reasons.includes('amendment_approval_not_approved'));
  assert.ok(denied.reasons.includes('communication_audience_missing:sponsor_cro'));
  assert.ok(denied.reasons.includes('communication_acknowledgement_incomplete'));
  assert.ok(denied.reasons.includes('open_critical_deviations_present'));
  assert.ok(denied.reasons.includes('document_least_privilege_absent'));
  assert.ok(denied.reasons.includes('obsolete_versions_not_withdrawn'));
  assert.ok(denied.reasons.includes('training_update_incomplete'));
  assert.ok(denied.reasons.includes('decision_forum_not_verified'));
  assert.equal(denied.receipt, null);
});

test('protocol control validates HLC ordering and no-AI operation', async () => {
  const { evaluateProtocolControl } = await loadProtocolControl();

  const sameTickReady = evaluateProtocolControl({
    ...protocolControlInput(),
    protocolControl: {
      ...protocolControlInput().protocolControl,
      approvedAtHlc: { physicalMs: 1812000000000, logical: 0 },
      effectiveAtHlc: { physicalMs: 1812000000000, logical: 1 },
    },
    staffCommunication: {
      ...protocolControlInput().staffCommunication,
      deliveredAtHlc: { physicalMs: 1812000000000, logical: 2 },
    },
    trainingUpdate: {
      ...protocolControlInput().trainingUpdate,
      trainingCompletedAtHlc: { physicalMs: 1812000000000, logical: 3 },
    },
    reviewGovernance: {
      ...protocolControlInput().reviewGovernance,
      aiAssisted: false,
      aiFinalAuthority: false,
    },
  });

  assert.equal(sameTickReady.decision, 'permitted');
  assert.equal(sameTickReady.protocolControl.aiAssisted, false);

  const malformed = evaluateProtocolControl({
    ...protocolControlInput(),
    protocolControl: {
      ...protocolControlInput().protocolControl,
      effectiveAtHlc: { physicalMs: 1811999999999, logical: 0 },
    },
    ethicsApproval: {
      ...protocolControlInput().ethicsApproval,
      approvalExpiresAtHlc: { physicalMs: 1811999999999, logical: 0 },
    },
    staffCommunication: {
      ...protocolControlInput().staffCommunication,
      deliveredAtHlc: { physicalMs: 1811999999998, logical: 0 },
      metadataOnly: false,
    },
    trainingUpdate: {
      ...protocolControlInput().trainingUpdate,
      trainingCompletedAtHlc: { physicalMs: 1811999999997, logical: 0 },
    },
  });

  assert.equal(malformed.decision, 'denied');
  assert.ok(malformed.reasons.includes('effective_before_approval'));
  assert.ok(malformed.reasons.includes('approval_expires_before_evaluation'));
  assert.ok(malformed.reasons.includes('communication_before_protocol_effective'));
  assert.ok(malformed.reasons.includes('communication_metadata_boundary_invalid'));
  assert.ok(malformed.reasons.includes('training_before_staff_communication'));
});

test('protocol control handles absent objects as fail-closed denial states', async () => {
  const { evaluateProtocolControl } = await loadProtocolControl();

  const denied = evaluateProtocolControl({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:protocol-control-owner-alpha', kind: 'human' },
    authority: {
      valid: false,
      revoked: false,
      expired: true,
      permissions: [],
      authorityChainHash: '0000000000000000000000000000000000000000000000000000000000000000',
    },
    protocolControl: null,
    policyCoverage: [
      {
        domain: 'unsupported_protocol_domain',
        status: 'draft',
        evidenceHash: 'not-a-digest',
        metadataOnly: false,
      },
    ],
    versionControl: null,
    ethicsApproval: null,
    staffCommunication: null,
    deviationManagement: null,
    documentSecurity: null,
    trainingUpdate: null,
    reviewGovernance: null,
    custodyDigest: '',
    rawProtocolBody: '',
    rawCommunication: [null, false, ''],
    rawDeviationNarrative: {},
    integrationSecret: null,
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('authority_chain_invalid'));
  assert.ok(denied.reasons.includes('authority_chain_expired'));
  assert.ok(denied.reasons.includes('protocol_control_ref_absent'));
  assert.ok(denied.reasons.includes('policy_domain_unsupported:unsupported_protocol_domain'));
  assert.ok(denied.reasons.includes('policy_domain_not_verified:unsupported_protocol_domain'));
  assert.ok(denied.reasons.includes('policy_domain_evidence_hash_invalid:unsupported_protocol_domain'));
  assert.ok(denied.reasons.includes('policy_domain_metadata_boundary_invalid:unsupported_protocol_domain'));
  assert.ok(denied.reasons.includes('policy_domain_missing:approved_protocol_version'));
  assert.ok(denied.reasons.includes('approved_protocol_version_receipt_absent'));
  assert.ok(denied.reasons.includes('ethics_receipt_absent'));
  assert.ok(denied.reasons.includes('communication_plan_ref_absent'));
  assert.ok(denied.reasons.includes('deviation_process_ref_absent'));
  assert.ok(denied.reasons.includes('document_access_policy_ref_absent'));
  assert.ok(denied.reasons.includes('training_matrix_ref_absent'));
  assert.ok(denied.reasons.includes('decision_forum_not_verified'));
  assert.ok(denied.reasons.includes('custody_digest_invalid'));
  assert.equal(denied.receipt, null);
});

test('protocol control rejects raw protocol content protected data and secrets before receipts', async () => {
  const { evaluateProtocolControl, ProtectedContentError } = await loadProtocolControl();

  assert.throws(
    () =>
      evaluateProtocolControl({
        ...protocolControlInput(),
        rawProtocolBody: 'source document body must not be stored in the receipt',
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateProtocolControl({
        ...protocolControlInput(),
        participantName: 'Participant Alice',
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateProtocolControl({
        ...protocolControlInput(),
        integrationSecret: 'protocol-portal-token',
      }),
    ProtectedContentError,
  );
});
