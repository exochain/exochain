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

async function loadParticipantProtection() {
  try {
    return await import('../src/participant-protection.mjs');
  } catch (error) {
    assert.fail(`CyberMedica participant-protection module must exist and load: ${error.message}`);
  }
}

function participantCodeInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:participant-coordinator-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['write', 'manage_participants'],
      authorityChainHash: DIGEST_F,
    },
    codeAssignment: {
      studyRef: 'study-cardiac-alpha',
      protocolRef: 'protocol-cardiac-alpha',
      siteRef: 'site-alpha',
      codeNamespace: 'site-subject-code',
      participantCodeHash: DIGEST_A,
      codeListHash: DIGEST_B,
      sequenceNumber: 42,
      assignedAtHlc: { physicalMs: 1793000000000, logical: 0 },
      sourceConsentProcessReceiptId: 'cmr_consent_process_alpha',
      consentBailmentRef: 'bailment-participant-alpha',
      privacyBoundaryHash: DIGEST_C,
      existingParticipantCodeHashes: [DIGEST_D, DIGEST_E],
      status: 'active',
    },
    identitySeparation: {
      directIdentifiersStored: false,
      linkingKeyEscrowed: true,
      linkingKeyCustodianDid: 'did:exo:data-custodian-alpha',
      linkingKeyDigest: DIGEST_D,
      reidentificationPolicyHash: DIGEST_E,
      accessRoleRefs: ['principal_investigator', 'data_custodian'],
    },
    custodyDigest: DIGEST_F,
  };
}

function dispositionInput(kind = 'withdrawal') {
  const notificationBaseMs = kind === 'lost_to_follow_up' ? 1795604900000 : 1794000300000;
  const withdrawal = {
    kind: 'withdrawal',
    status: 'withdrawn',
    requestedAtHlc: { physicalMs: 1794000000000, logical: 0 },
    effectiveAtHlc: { physicalMs: 1794000000000, logical: 1 },
    reasonStatus: 'refused',
    reasonHash: null,
    refusalDocumented: true,
    sourceEvidenceHash: DIGEST_B,
    participantRightsNotificationHash: DIGEST_C,
    postDispositionDataUse: {
      consentLimited: true,
      scopeRefs: ['safety_follow_up', 'regulatory_retention'],
      policyHash: DIGEST_D,
    },
    safetyFollowUp: {
      required: true,
      planHash: DIGEST_E,
      ownerDid: 'did:exo:principal-investigator-alpha',
      dueAtHlc: { physicalMs: 1794086400000, logical: 0 },
    },
  };
  const lostToFollowUp = {
    kind: 'lost_to_follow_up',
    status: 'lost_to_follow_up',
    requestedAtHlc: { physicalMs: 1795000000000, logical: 0 },
    effectiveAtHlc: { physicalMs: 1795604800000, logical: 0 },
    reasonStatus: 'not_applicable',
    reasonHash: null,
    refusalDocumented: false,
    sourceEvidenceHash: DIGEST_B,
    participantRightsNotificationHash: DIGEST_C,
    contactPolicyRef: 'lost-to-follow-up-contact-policy-v1',
    contactAttempts: [
      { methodRef: 'phone_attempt', attemptedAtHlc: { physicalMs: 1795000000000, logical: 1 }, evidenceHash: DIGEST_D },
      { methodRef: 'certified_letter', attemptedAtHlc: { physicalMs: 1795200000000, logical: 0 }, evidenceHash: DIGEST_E },
      { methodRef: 'portal_message', attemptedAtHlc: { physicalMs: 1795400000000, logical: 0 }, evidenceHash: DIGEST_F },
    ],
    postDispositionDataUse: {
      consentLimited: true,
      scopeRefs: ['safety_follow_up', 'regulatory_retention'],
      policyHash: DIGEST_D,
    },
    safetyFollowUp: {
      required: false,
      rationaleHash: DIGEST_E,
      ownerDid: 'did:exo:principal-investigator-alpha',
      dueAtHlc: null,
    },
  };

  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:participant-coordinator-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['write', 'manage_participants'],
      authorityChainHash: DIGEST_F,
    },
    participant: {
      participantCodeRecordId: 'cmpcode_active_alpha',
      participantCodeHash: DIGEST_A,
      studyRef: 'study-cardiac-alpha',
      protocolRef: 'protocol-cardiac-alpha',
      siteRef: 'site-alpha',
      statusBefore: 'enrolled',
      consentBailmentRef: 'bailment-participant-alpha',
    },
    disposition: kind === 'lost_to_follow_up' ? lostToFollowUp : withdrawal,
    notifications: [
      {
        party: 'principal_investigator',
        status: 'notified',
        notifiedAtHlc: { physicalMs: notificationBaseMs, logical: 0 },
        evidenceHash: DIGEST_B,
      },
      {
        party: 'site_quality_lead',
        status: 'notified',
        notifiedAtHlc: { physicalMs: notificationBaseMs + 100000, logical: 0 },
        evidenceHash: DIGEST_C,
      },
      {
        party: 'sponsor_contact',
        status: 'notified',
        notifiedAtHlc: { physicalMs: notificationBaseMs + 200000, logical: 0 },
        evidenceHash: DIGEST_D,
      },
    ],
    review: {
      humanReviewerDid: 'did:exo:participant-rights-lead-alpha',
      phiBoundaryAttested: true,
      aiFinalAuthority: false,
    },
    custodyDigest: DIGEST_F,
  };
}

test('participant code assignment creates deterministic inactive code records without direct identifiers', async () => {
  const { assignParticipantCode } = await loadParticipantProtection();

  const resultA = assignParticipantCode(participantCodeInput());
  const resultB = assignParticipantCode({
    ...participantCodeInput(),
    codeAssignment: {
      ...participantCodeInput().codeAssignment,
      existingParticipantCodeHashes: [...participantCodeInput().codeAssignment.existingParticipantCodeHashes].reverse(),
    },
    identitySeparation: {
      ...participantCodeInput().identitySeparation,
      accessRoleRefs: [...participantCodeInput().identitySeparation.accessRoleRefs].reverse(),
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.participantCodeRecord.status, 'active');
  assert.equal(resultA.participantCodeRecord.participantCodeHash, DIGEST_A);
  assert.equal(resultA.participantCodeRecord.sequenceNumber, 42);
  assert.equal(resultA.participantCodeRecord.directIdentifiersStored, false);
  assert.equal(resultA.participantCodeRecord.exochainProductionClaim, false);
  assert.equal(resultA.participantCodeRecord.participantCodeRecordId, resultB.participantCodeRecord.participantCodeRecordId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'participant_code_assignment');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(resultA), /Participant Alice|medical record|raw participant code|phone|email/iu);
});

test('participant code assignment fails closed for duplicate codes identity linkage defects and raw participant content', async () => {
  const { assignParticipantCode } = await loadParticipantProtection();

  const denied = assignParticipantCode({
    ...participantCodeInput(),
    actor: { did: 'did:exo:ai-reviewer-alpha', kind: 'ai_agent' },
    codeAssignment: {
      ...participantCodeInput().codeAssignment,
      existingParticipantCodeHashes: [DIGEST_A],
      sourceConsentProcessReceiptId: '',
    },
    identitySeparation: {
      ...participantCodeInput().identitySeparation,
      directIdentifiersStored: true,
      linkingKeyDigest: '',
      accessRoleRefs: [],
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.participantCodeRecord.status, 'blocked');
  assert.equal(denied.receipt, null);
  assert.match(denied.reasons.join('|'), /ai_final_authority_forbidden/);
  assert.match(denied.reasons.join('|'), /participant_code_duplicate/);
  assert.match(denied.reasons.join('|'), /consent_process_receipt_absent/);
  assert.match(denied.reasons.join('|'), /direct_identifier_storage_forbidden/);
  assert.match(denied.reasons.join('|'), /linking_key_digest_invalid/);
  assert.match(denied.reasons.join('|'), /identity_access_roles_absent/);

  assert.throws(
    () =>
      assignParticipantCode({
        ...participantCodeInput(),
        codeAssignment: { ...participantCodeInput().codeAssignment, rawParticipantCode: 'SUBJ-ALPHA-0042' },
      }),
    /participant protected content/i,
  );
});

test('participant withdrawal records refusal to provide reason and blocks continuation without raw reason text', async () => {
  const { recordParticipantDisposition } = await loadParticipantProtection();

  const resultA = recordParticipantDisposition(dispositionInput('withdrawal'));
  const resultB = recordParticipantDisposition({
    ...dispositionInput('withdrawal'),
    notifications: [...dispositionInput('withdrawal').notifications].reverse(),
    disposition: {
      ...dispositionInput('withdrawal').disposition,
      postDispositionDataUse: {
        ...dispositionInput('withdrawal').disposition.postDispositionDataUse,
        scopeRefs: [...dispositionInput('withdrawal').disposition.postDispositionDataUse.scopeRefs].reverse(),
      },
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.dispositionRecord.kind, 'withdrawal');
  assert.equal(resultA.dispositionRecord.status, 'withdrawn');
  assert.equal(resultA.dispositionRecord.reasonStatus, 'refused');
  assert.equal(resultA.dispositionRecord.reasonStored, false);
  assert.equal(resultA.dispositionRecord.continuationAllowed, false);
  assert.equal(resultA.dispositionRecord.enrollmentConsentGate, 'blocked');
  assert.equal(resultA.dispositionRecord.safetyFollowUpStatus, 'required_ready');
  assert.equal(resultA.dispositionRecord.dispositionRecordId, resultB.dispositionRecord.dispositionRecordId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'participant_disposition');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(resultA), /withdrawal reason text|Participant Alice|medical record|raw contact/iu);
});

test('lost to follow up process tracks contact attempts and remains metadata only', async () => {
  const { recordParticipantDisposition } = await loadParticipantProtection();

  const result = recordParticipantDisposition(dispositionInput('lost_to_follow_up'));

  assert.equal(result.decision, 'permitted');
  assert.equal(result.failClosed, false);
  assert.equal(result.dispositionRecord.kind, 'lost_to_follow_up');
  assert.equal(result.dispositionRecord.status, 'lost_to_follow_up');
  assert.equal(result.dispositionRecord.lostToFollowUpProcessStatus, 'tracked');
  assert.equal(result.dispositionRecord.contactAttemptCount, 3);
  assert.equal(result.dispositionRecord.continuationAllowed, false);
  assert.equal(result.dispositionRecord.safetyFollowUpStatus, 'not_required_documented');
  assert.equal(result.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(result), /Participant Alice|phone number|email|home address|raw contact/iu);
});

test('participant disposition fails closed for malformed withdrawal LTFU and HLC evidence', async () => {
  const { recordParticipantDisposition } = await loadParticipantProtection();

  const deniedWithdrawal = recordParticipantDisposition({
    ...dispositionInput('withdrawal'),
    participant: { ...dispositionInput('withdrawal').participant, participantCodeHash: 'not-a-digest' },
    disposition: {
      ...dispositionInput('withdrawal').disposition,
      requestedAtHlc: { physicalMs: 1794000000000, logical: 3 },
      effectiveAtHlc: { physicalMs: 1794000000000, logical: 2 },
      reasonStatus: 'provided',
      reasonHash: '',
      refusalDocumented: false,
      postDispositionDataUse: {
        consentLimited: false,
        scopeRefs: [],
        policyHash: '',
      },
      safetyFollowUp: {
        required: true,
        planHash: '',
        ownerDid: '',
        dueAtHlc: { physicalMs: 1793999999999, logical: 0 },
      },
    },
    notifications: [{ party: 'principal_investigator', status: 'pending', notifiedAtHlc: null, evidenceHash: '' }],
    review: { humanReviewerDid: '', phiBoundaryAttested: false, aiFinalAuthority: true },
  });

  assert.equal(deniedWithdrawal.decision, 'denied');
  assert.equal(deniedWithdrawal.failClosed, true);
  assert.equal(deniedWithdrawal.dispositionRecord.status, 'blocked');
  assert.equal(deniedWithdrawal.receipt, null);
  assert.match(deniedWithdrawal.reasons.join('|'), /participant_code_hash_invalid/);
  assert.match(deniedWithdrawal.reasons.join('|'), /disposition_effective_before_request/);
  assert.match(deniedWithdrawal.reasons.join('|'), /withdrawal_reason_hash_absent/);
  assert.match(deniedWithdrawal.reasons.join('|'), /post_disposition_consent_limit_absent/);
  assert.match(deniedWithdrawal.reasons.join('|'), /safety_follow_up_plan_absent/);
  assert.match(deniedWithdrawal.reasons.join('|'), /required_notification_absent/);
  assert.match(deniedWithdrawal.reasons.join('|'), /human_review_absent/);
  assert.match(deniedWithdrawal.reasons.join('|'), /ai_final_authority_forbidden/);

  const deniedLtfu = recordParticipantDisposition({
    ...dispositionInput('lost_to_follow_up'),
    disposition: {
      ...dispositionInput('lost_to_follow_up').disposition,
      contactAttempts: [dispositionInput('lost_to_follow_up').disposition.contactAttempts[0]],
    },
  });
  assert.equal(deniedLtfu.decision, 'denied');
  assert.match(deniedLtfu.reasons.join('|'), /lost_to_follow_up_attempts_insufficient/);

  assert.throws(
    () =>
      recordParticipantDisposition({
        ...dispositionInput('withdrawal'),
        disposition: { ...dispositionInput('withdrawal').disposition, rawWithdrawalReason: 'withdrawal reason text' },
      }),
    /participant protected content/i,
  );
});

test('lost to follow up status does not mark malformed contact tracking complete', async () => {
  const { recordParticipantDisposition } = await loadParticipantProtection();

  const denied = recordParticipantDisposition({
    ...dispositionInput('lost_to_follow_up'),
    disposition: {
      ...dispositionInput('lost_to_follow_up').disposition,
      contactAttempts: [
        dispositionInput('lost_to_follow_up').disposition.contactAttempts[0],
        {
          methodRef: 'certified_letter',
          attemptedAtHlc: { physicalMs: 1795604800001, logical: 0 },
          evidenceHash: DIGEST_E,
        },
        {
          methodRef: 'portal_message',
          attemptedAtHlc: { physicalMs: 1795400000000, logical: 0 },
          evidenceHash: 'not-a-digest',
        },
      ],
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.dispositionRecord.status, 'blocked');
  assert.equal(denied.dispositionRecord.contactAttemptCount, 3);
  assert.equal(denied.dispositionRecord.lostToFollowUpProcessStatus, 'incomplete');
  assert.match(denied.reasons.join('|'), /contact_attempt_after_lost_to_follow_up_closure/);
  assert.match(denied.reasons.join('|'), /contact_attempt_evidence_invalid/);
});

test('participant protection reports invalid assignment clocks and alternate disposition branches', async () => {
  const { assignParticipantCode, recordParticipantDisposition } = await loadParticipantProtection();

  const badClock = assignParticipantCode({
    ...participantCodeInput(),
    codeAssignment: {
      ...participantCodeInput().codeAssignment,
      assignedAtHlc: { physicalMs: 1793000000000, logical: -1 },
    },
  });
  assert.equal(badClock.decision, 'denied');
  assert.match(badClock.reasons.join('|'), /code_assignment_time_invalid/);

  const earlyTermination = recordParticipantDisposition({
    ...dispositionInput('withdrawal'),
    disposition: {
      ...dispositionInput('withdrawal').disposition,
      kind: 'early_termination',
      status: 'early_terminated',
      requestedAtHlc: { physicalMs: 1794000000000, logical: 0 },
      effectiveAtHlc: { physicalMs: 1794000000000, logical: 0 },
      safetyFollowUp: {},
    },
  });
  assert.equal(earlyTermination.decision, 'denied');
  assert.equal(earlyTermination.dispositionRecord.safetyFollowUpStatus, 'unknown');
  assert.match(earlyTermination.reasons.join('|'), /safety_follow_up_requirement_invalid/);

  const suspension = recordParticipantDisposition({
    ...dispositionInput('withdrawal'),
    disposition: {
      ...dispositionInput('withdrawal').disposition,
      kind: 'suspension',
      status: 'suspended',
      reasonStatus: 'not_requested_due_to_safety',
    },
  });
  assert.equal(suspension.decision, 'permitted');
  assert.equal(suspension.dispositionRecord.kind, 'suspension');
  assert.equal(suspension.dispositionRecord.status, 'suspended');

  const invalidKind = recordParticipantDisposition({
    ...dispositionInput('withdrawal'),
    disposition: {
      ...dispositionInput('withdrawal').disposition,
      kind: 'continued',
      status: 'active',
    },
  });
  assert.equal(invalidKind.decision, 'denied');
  assert.match(invalidKind.reasons.join('|'), /participant_disposition_kind_invalid/);
  assert.match(invalidKind.reasons.join('|'), /participant_disposition_status_invalid/);
});
