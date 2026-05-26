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

async function loadTrainingDelegation() {
  try {
    return await import('../src/training-delegation.mjs');
  } catch (error) {
    assert.fail(`CyberMedica training-delegation module must exist and load: ${error.message}`);
  }
}

const evidenceHashA = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const evidenceHashB = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const evidenceHashC = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const evidenceHashD = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const evidenceHashE = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const custodyDigest = 'abababababababababababababababababababababababababababababababab';
const authorityChainHash = 'f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0';

const baseInput = Object.freeze({
  requestId: 'training-delegation-check-0001',
  tenantId: 'tenant-site-alpha',
  siteId: 'site-alpha',
  protocolId: 'protocol-cardiac-alpha',
  controlledAction: 'informed_consent_documentation',
  checkedAtHlc: { physicalMs: 1790000000000, logical: 41 },
  actor: {
    did: 'did:exo:crc-alpha',
    kind: 'human',
  },
  roleAssignment: {
    actorDid: 'did:exo:crc-alpha',
    role: 'clinical_research_coordinator',
    status: 'active',
    tenantId: 'tenant-site-alpha',
    siteId: 'site-alpha',
    protocolIds: ['protocol-cardiac-alpha'],
  },
  trainingMatrix: {
    matrixId: 'training-matrix-protocol-cardiac-alpha',
    status: 'approved',
    verified: true,
    receiptId: 'training-matrix-receipt-alpha',
    humanGate: { verified: true },
    quorum: { status: 'met' },
    openChallenge: false,
  },
  requirements: [
    {
      requirementId: 'req-gcp-current',
      appliesToRoles: ['clinical_research_coordinator'],
      protocolId: 'protocol-cardiac-alpha',
      actionScopes: ['informed_consent_documentation', 'enrollment_screening'],
      requiredVersion: 4,
      requiredEvidenceType: 'training_certificate',
      requiredCompetencyId: 'competency-consent-process-alpha',
    },
    {
      requirementId: 'req-consent-sop',
      appliesToRoles: ['clinical_research_coordinator'],
      protocolId: 'protocol-cardiac-alpha',
      controlId: 'control-consent-process',
      actionScopes: ['informed_consent_documentation'],
      requiredVersion: 2,
      requiredEvidenceType: 'sop_training_attestation',
      requiredCompetencyId: 'competency-consent-process-alpha',
    },
  ],
  trainingRecords: [
    {
      requirementId: 'req-gcp-current',
      actorDid: 'did:exo:crc-alpha',
      status: 'completed',
      version: 4,
      evidenceType: 'training_certificate',
      evidenceHash: evidenceHashA,
      completedAtHlc: { physicalMs: 1789900000000, logical: 0 },
      expiresAtHlc: { physicalMs: 1795000000000, logical: 0 },
    },
    {
      requirementId: 'req-consent-sop',
      actorDid: 'did:exo:crc-alpha',
      status: 'completed',
      version: 2,
      evidenceType: 'sop_training_attestation',
      evidenceHash: evidenceHashB,
      completedAtHlc: { physicalMs: 1789900100000, logical: 0 },
      expiresAtHlc: { physicalMs: 1795000100000, logical: 0 },
    },
  ],
  competencyEvidence: [
    {
      competencyId: 'competency-consent-process-alpha',
      actorDid: 'did:exo:crc-alpha',
      status: 'verified',
      verifiedByHuman: true,
      evidenceHash: evidenceHashC,
      scopes: ['enrollment_screening', 'informed_consent_documentation'],
      verifiedAtHlc: { physicalMs: 1789900200000, logical: 0 },
      expiresAtHlc: { physicalMs: 1795000200000, logical: 0 },
    },
  ],
  qualifications: [
    {
      qualificationId: 'qualification-crc-license-alpha',
      actorDid: 'did:exo:crc-alpha',
      status: 'active',
      evidenceHash: evidenceHashD,
      expiresAtHlc: { physicalMs: 1795000300000, logical: 0 },
    },
  ],
  delegation: {
    delegationId: 'delegation-protocol-cardiac-alpha-crc',
    actorDid: 'did:exo:crc-alpha',
    tenantId: 'tenant-site-alpha',
    siteId: 'site-alpha',
    protocolId: 'protocol-cardiac-alpha',
    status: 'active',
    revoked: false,
    allowedActions: ['informed_consent_documentation', 'enrollment_screening'],
    notBeforeHlc: { physicalMs: 1789900300000, logical: 0 },
    expiresAtHlc: { physicalMs: 1795000400000, logical: 0 },
    authorityChainHash,
  },
  authority: {
    valid: true,
    revoked: false,
    expired: false,
    permissions: ['perform_protocol_task'],
    authorityChainHash,
  },
  conflictDisclosure: { status: 'clear' },
  recusal: { active: false },
  custodyDigest,
});

test('training and delegation readiness permits trained competent staff with deterministic inactive receipts', async () => {
  const { evaluateTrainingDelegationReadiness } = await loadTrainingDelegation();

  const permittedA = evaluateTrainingDelegationReadiness(baseInput);
  const permittedB = evaluateTrainingDelegationReadiness({
    ...baseInput,
    requirements: [...baseInput.requirements].reverse(),
    trainingRecords: [...baseInput.trainingRecords].reverse(),
    competencyEvidence: [
      {
        ...baseInput.competencyEvidence[0],
        scopes: [...baseInput.competencyEvidence[0].scopes].reverse(),
      },
    ],
    roleAssignment: {
      ...baseInput.roleAssignment,
      protocolIds: [...baseInput.roleAssignment.protocolIds].reverse(),
    },
    delegation: {
      ...baseInput.delegation,
      allowedActions: [...baseInput.delegation.allowedActions].reverse(),
    },
  });

  assert.equal(permittedA.decision, 'permitted');
  assert.equal(permittedA.failClosed, false);
  assert.deepEqual(permittedA.reasons, []);
  assert.equal(permittedA.trustState, 'inactive');
  assert.equal(permittedA.exochainProductionClaim, false);
  assert.equal(permittedA.eligibility.eligibilityHash, permittedB.eligibility.eligibilityHash);
  assert.equal(permittedA.receipt.receiptId, permittedB.receipt.receiptId);
  assert.equal(permittedA.receipt.trustState, 'inactive');
  assert.equal(permittedA.receipt.anchorPayload.artifactType, 'training_delegation_eligibility');
  assert.equal(permittedA.eligibility.actorDid, 'did:exo:crc-alpha');
  assert.equal(permittedA.eligibility.controlledAction, 'informed_consent_documentation');
  assert.deepEqual(permittedA.eligibility.requirementIds, ['req-consent-sop', 'req-gcp-current']);
  assert.deepEqual(Object.keys(permittedA.eligibility), [
    'schema',
    'eligibilityId',
    'eligibilityHash',
    'tenantId',
    'siteId',
    'protocolId',
    'actorDid',
    'role',
    'controlledAction',
    'checkedAtHlc',
    'requirementIds',
    'trainingRecordHashes',
    'competencyIds',
    'qualificationIds',
    'delegationId',
    'authorityChainHash',
    'receiptId',
  ]);
  assert.doesNotMatch(JSON.stringify(permittedA), /root-backed production authority/i);
});

test('training and delegation readiness fails closed for gaps stale records conflicts and invalid delegation', async () => {
  const { evaluateTrainingDelegationReadiness } = await loadTrainingDelegation();

  const denied = evaluateTrainingDelegationReadiness({
    ...baseInput,
    actor: { did: 'did:exo:crc-alpha', kind: 'ai_agent' },
    trainingMatrix: {
      ...baseInput.trainingMatrix,
      status: 'draft',
      verified: false,
      humanGate: { verified: false },
      quorum: { status: 'not_met' },
      openChallenge: true,
    },
    trainingRecords: [
      {
        ...baseInput.trainingRecords[0],
        status: 'expired',
        version: 3,
        expiresAtHlc: { physicalMs: 1789999999999, logical: 99 },
      },
    ],
    competencyEvidence: [
      {
        ...baseInput.competencyEvidence[0],
        verifiedByHuman: false,
        expiresAtHlc: { physicalMs: 1789999999999, logical: 99 },
      },
    ],
    qualifications: [
      {
        ...baseInput.qualifications[0],
        status: 'expired',
        expiresAtHlc: { physicalMs: 1789999999999, logical: 99 },
      },
    ],
    delegation: {
      ...baseInput.delegation,
      status: 'revoked',
      revoked: true,
      allowedActions: ['source_document_review'],
      expiresAtHlc: { physicalMs: 1789999999999, logical: 99 },
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['read'],
      authorityChainHash,
    },
    conflictDisclosure: { status: 'active' },
    recusal: { active: true },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.eligibility, null);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('ai_controlled_action_forbidden'));
  assert.ok(denied.reasons.includes('training_matrix_unverified'));
  assert.ok(denied.reasons.includes('training_matrix_not_approved'));
  assert.ok(denied.reasons.includes('training_matrix_human_gate_unverified'));
  assert.ok(denied.reasons.includes('training_matrix_quorum_not_met'));
  assert.ok(denied.reasons.includes('training_matrix_challenge_open'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('training_requirement_version_stale'));
  assert.ok(denied.reasons.includes('training_requirement_expired'));
  assert.ok(denied.reasons.includes('training_requirement_missing_record'));
  assert.ok(denied.reasons.includes('competency_human_verification_absent'));
  assert.ok(denied.reasons.includes('competency_expired'));
  assert.ok(denied.reasons.includes('qualification_not_active'));
  assert.ok(denied.reasons.includes('qualification_expired'));
  assert.ok(denied.reasons.includes('delegation_revoked'));
  assert.ok(denied.reasons.includes('delegation_action_not_allowed'));
  assert.ok(denied.reasons.includes('delegation_expired'));
  assert.ok(denied.reasons.includes('conflict_active'));
  assert.ok(denied.reasons.includes('recusal_active'));
  assert.deepEqual(denied.trainingGaps, [
    { requirementId: 'req-consent-sop', reason: 'training_requirement_missing_record' },
    { requirementId: 'req-gcp-current', reason: 'training_requirement_expired' },
    { requirementId: 'req-gcp-current', reason: 'training_requirement_version_stale' },
  ]);
});

test('training and delegation readiness rejects protected content before creating eligibility receipts', async () => {
  const { evaluateTrainingDelegationReadiness } = await loadTrainingDelegation();

  assert.throws(
    () =>
      evaluateTrainingDelegationReadiness({
        ...baseInput,
        trainingRecords: [
          {
            ...baseInput.trainingRecords[0],
            sourceDocumentBody: 'Participant Alice Example consent process note',
          },
        ],
      }),
    /protected content/i,
  );

  const denied = evaluateTrainingDelegationReadiness({
    ...baseInput,
    delegation: {
      ...baseInput.delegation,
      authorityChainHash: evidenceHashE,
    },
    custodyDigest: '0000000000000000000000000000000000000000000000000000000000000000',
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('custody_digest_invalid'));
  assert.ok(denied.reasons.includes('delegation_authority_chain_invalid'));
  assert.equal(denied.receipt, null);
});

test('training and delegation readiness reports malformed matrix role authority and evidence branches', async () => {
  const { evaluateTrainingDelegationReadiness } = await loadTrainingDelegation();

  const denied = evaluateTrainingDelegationReadiness({
    ...baseInput,
    requestId: '',
    roleAssignment: {
      ...baseInput.roleAssignment,
      status: 'inactive',
      actorDid: 'did:exo:sub-investigator-alpha',
      tenantId: 'tenant-site-beta',
      siteId: 'site-beta',
      protocolIds: [],
    },
    trainingMatrix: null,
    requirements: [
      null,
      {
        requirementId: 'req-other-protocol',
        appliesToRoles: ['clinical_research_coordinator'],
        protocolId: 'protocol-neurology-beta',
        actionScopes: ['informed_consent_documentation'],
      },
      {
        requirementId: 'req-other-role',
        appliesToRoles: ['principal_investigator'],
        protocolId: 'protocol-cardiac-alpha',
        actionScopes: ['informed_consent_documentation'],
      },
      {
        requirementId: 'req-open-scope',
        appliesToRoles: [],
        protocolId: 'protocol-cardiac-alpha',
        actionScopes: [],
        requiredVersion: 2,
        requiredEvidenceType: 'protocol_training',
        requiredCompetencyId: 'competency-missing-alpha',
      },
      {
        requirementId: 'req-status-branch',
        appliesToRoles: [],
        protocolId: 'protocol-cardiac-alpha',
        actionScopes: ['informed_consent_documentation'],
        requiredVersion: 2,
        requiredEvidenceType: 'protocol_training',
        requiredCompetencyId: 'competency-status-alpha',
      },
    ],
    trainingRecords: [
      {
        requirementId: 'req-open-scope',
        actorDid: 'did:exo:crc-alpha',
        status: 'assigned',
        version: 2,
        evidenceType: 'wrong_evidence_type',
        evidenceHash: 'not-a-digest',
        completedAtHlc: null,
        expiresAtHlc: null,
      },
      {
        requirementId: 'req-status-branch',
        actorDid: 'did:exo:crc-alpha',
        status: 'completed',
        version: 2,
        evidenceType: 'protocol_training',
        evidenceHash: evidenceHashA,
        completedAtHlc: { physicalMs: 1790000000000, logical: 42 },
        expiresAtHlc: { physicalMs: 1795000000000, logical: 0 },
      },
    ],
    competencyEvidence: [
      {
        competencyId: 'competency-status-alpha',
        actorDid: 'did:exo:crc-alpha',
        status: 'pending',
        verifiedByHuman: true,
        evidenceHash: 'not-a-digest',
        scopes: ['informed_consent_documentation'],
        expiresAtHlc: null,
      },
    ],
    qualifications: [],
    delegation: {
      ...baseInput.delegation,
      notBeforeHlc: { physicalMs: 1790000000000, logical: 42 },
      expiresAtHlc: { physicalMs: 1795000000000, logical: 0 },
    },
    authority: {
      valid: false,
      revoked: true,
      expired: true,
      permissions: [],
      authorityChainHash,
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('request_id_absent'));
  assert.ok(denied.reasons.includes('role_assignment_not_active'));
  assert.ok(denied.reasons.includes('role_assignment_actor_mismatch'));
  assert.ok(denied.reasons.includes('role_assignment_tenant_mismatch'));
  assert.ok(denied.reasons.includes('role_assignment_site_mismatch'));
  assert.ok(denied.reasons.includes('role_assignment_protocol_missing'));
  assert.ok(denied.reasons.includes('training_matrix_unverified'));
  assert.ok(denied.reasons.includes('training_matrix_not_approved'));
  assert.ok(denied.reasons.includes('training_matrix_receipt_absent'));
  assert.ok(denied.reasons.includes('authority_chain_invalid'));
  assert.ok(denied.reasons.includes('authority_chain_revoked'));
  assert.ok(denied.reasons.includes('authority_chain_expired'));
  assert.ok(denied.reasons.includes('training_requirement_not_completed'));
  assert.ok(denied.reasons.includes('training_requirement_evidence_type_invalid'));
  assert.ok(denied.reasons.includes('training_requirement_evidence_hash_invalid'));
  assert.ok(denied.reasons.includes('training_requirement_completion_time_invalid'));
  assert.ok(denied.reasons.includes('training_requirement_expiry_time_invalid'));
  assert.ok(denied.reasons.includes('training_requirement_completed_after_check'));
  assert.ok(denied.reasons.includes('competency_missing'));
  assert.ok(denied.reasons.includes('competency_unverified'));
  assert.ok(denied.reasons.includes('competency_evidence_hash_invalid'));
  assert.ok(denied.reasons.includes('competency_expiry_time_invalid'));
  assert.ok(denied.reasons.includes('qualification_absent'));
  assert.ok(denied.reasons.includes('delegation_not_yet_active'));
  assert.equal(denied.eligibility, null);
  assert.equal(denied.receipt, null);

  const absentCollections = evaluateTrainingDelegationReadiness({
    ...baseInput,
    requirements: null,
    trainingRecords: null,
    competencyEvidence: null,
    qualifications: null,
  });

  assert.equal(absentCollections.decision, 'denied');
  assert.ok(absentCollections.reasons.includes('training_requirements_absent'));
  assert.ok(absentCollections.reasons.includes('qualification_absent'));
});
