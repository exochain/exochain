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

async function loadSupportAccess() {
  try {
    return await import('../src/support-access.mjs');
  } catch (error) {
    assert.fail(`CyberMedica support-access module must exist and load: ${error.message}`);
  }
}

const previousEntryHash = '9999999999999999999999999999999999999999999999999999999999999999';
const custodyDigest = 'abababababababababababababababababababababababababababababababab';

const supportAccessInput = Object.freeze({
  tenantId: 'tenant-site-alpha',
  targetTenantId: 'tenant-site-alpha',
  actor: { did: 'did:exo:support-engineer-alpha', kind: 'human' },
  authority: { valid: true, revoked: false, expired: false, permissions: ['read'] },
  consent: {
    required: true,
    status: 'active',
    revoked: false,
    consentRef: 'support-access-consent-alpha-001',
  },
  supportGrant: {
    grantId: 'support-grant-alpha-001',
    status: 'active',
    scope: 'support_access',
    revoked: false,
    consentRef: 'support-access-consent-alpha-001',
    notBeforeHlc: { physicalMs: 1789999000000, logical: 0 },
    expiresAtHlc: { physicalMs: 1790003600000, logical: 0 },
  },
  supportPolicy: {
    verified: true,
    state: 'approved',
    policyReceiptId: 'support-policy-receipt-alpha',
    humanGate: { verified: true },
    quorum: { status: 'met' },
    openChallenge: false,
  },
  reason: {
    code: 'incident_response',
    description: 'Investigate failed document metadata receipt creation.',
    ticketRef: 'SUP-2026-0001',
  },
  requestedAtHlc: { physicalMs: 1790000000000, logical: 33 },
  requestedFields: ['audit_trail_metadata', 'document_version_metadata', 'workflow_state_metadata'],
  accessLog: {
    previousEntryHash,
    sequence: 17,
    custodyDigest,
  },
});

test('support access permits active time-boxed grants and creates deterministic inactive log receipts', async () => {
  const { evaluateSupportAccessRequest } = await loadSupportAccess();

  const permittedA = evaluateSupportAccessRequest(supportAccessInput);
  const permittedB = evaluateSupportAccessRequest({
    accessLog: supportAccessInput.accessLog,
    requestedFields: [...supportAccessInput.requestedFields].reverse(),
    requestedAtHlc: { logical: 33, physicalMs: 1790000000000 },
    reason: supportAccessInput.reason,
    supportPolicy: supportAccessInput.supportPolicy,
    supportGrant: supportAccessInput.supportGrant,
    consent: supportAccessInput.consent,
    authority: supportAccessInput.authority,
    actor: supportAccessInput.actor,
    targetTenantId: supportAccessInput.targetTenantId,
    tenantId: supportAccessInput.tenantId,
  });

  assert.equal(permittedA.decision, 'permitted');
  assert.equal(permittedA.failClosed, false);
  assert.deepEqual(permittedA.reasons, []);
  assert.equal(permittedA.accessWindowActive, true);
  assert.equal(permittedA.trustState, 'inactive');
  assert.equal(permittedA.exochainProductionClaim, false);
  assert.equal(permittedA.logEntry.entryHash, permittedB.logEntry.entryHash);
  assert.equal(permittedA.receipt.receiptId, permittedB.receipt.receiptId);
  assert.deepEqual(Object.keys(permittedA.logEntry), [
    'schema',
    'accessLogId',
    'entryHash',
    'tenantId',
    'actorDid',
    'grantId',
    'consentRef',
    'reasonCode',
    'ticketRef',
    'requestedAtHlc',
    'requestedFields',
    'previousEntryHash',
    'sequence',
  ]);
  assert.deepEqual(permittedA.logEntry.requestedFields, [
    'audit_trail_metadata',
    'document_version_metadata',
    'workflow_state_metadata',
  ]);
  assert.equal(permittedA.receipt.trustState, 'inactive');
  assert.equal(permittedA.receipt.exochainProductionClaim, false);
  assert.equal(permittedA.receipt.anchorPayload.artifactType, 'support_access_log');

  const exactBoundary = evaluateSupportAccessRequest({
    ...supportAccessInput,
    supportGrant: {
      ...supportAccessInput.supportGrant,
      notBeforeHlc: supportAccessInput.requestedAtHlc,
      expiresAtHlc: supportAccessInput.requestedAtHlc,
    },
    requestedFields: ['case_metadata', 'system_error_code', 'tenant_config_metadata'],
  });

  assert.equal(exactBoundary.decision, 'permitted');
  assert.deepEqual(exactBoundary.logEntry.requestedFields, [
    'case_metadata',
    'system_error_code',
    'tenant_config_metadata',
  ]);
});

test('support access fails closed for revoked grants expired windows missing reasons and AI access', async () => {
  const { evaluateSupportAccessRequest } = await loadSupportAccess();

  const revoked = evaluateSupportAccessRequest({
    ...supportAccessInput,
    actor: { did: 'did:exo:ai-support-reviewer-alpha', kind: 'ai_agent' },
    supportGrant: { ...supportAccessInput.supportGrant, status: 'revoked', revoked: true },
    reason: { code: '', description: '', ticketRef: '' },
    requestedAtHlc: { physicalMs: 1790007200000, logical: 0 },
    emergencyOverride: true,
  });

  assert.equal(revoked.decision, 'denied');
  assert.equal(revoked.failClosed, true);
  assert.equal(revoked.accessWindowActive, false);
  assert.ok(revoked.reasons.includes('ai_support_access_forbidden'));
  assert.ok(revoked.reasons.includes('support_grant_not_active'));
  assert.ok(revoked.reasons.includes('support_grant_revoked'));
  assert.ok(revoked.reasons.includes('support_grant_expired'));
  assert.ok(revoked.reasons.includes('reason_code_absent'));
  assert.ok(revoked.reasons.includes('reason_description_absent'));
  assert.ok(revoked.reasons.includes('ticket_ref_absent'));
  assert.equal(revoked.logEntry, null);
  assert.equal(revoked.receipt, null);

  const policyDenied = evaluateSupportAccessRequest({
    ...supportAccessInput,
    supportPolicy: {
      ...supportAccessInput.supportPolicy,
      humanGate: { verified: false },
      quorum: { status: 'not_met' },
      openChallenge: true,
    },
  });

  assert.equal(policyDenied.decision, 'denied');
  assert.ok(policyDenied.reasons.includes('support_policy_human_gate_unverified'));
  assert.ok(policyDenied.reasons.includes('support_policy_quorum_not_met'));
  assert.ok(policyDenied.reasons.includes('support_policy_challenge_open'));

  const malformedGrant = evaluateSupportAccessRequest({
    ...supportAccessInput,
    supportPolicy: null,
    supportGrant: {
      ...supportAccessInput.supportGrant,
      grantId: '',
      scope: 'tenant_admin',
      consentRef: 'different-consent-ref',
      notBeforeHlc: { physicalMs: 1790001000000, logical: 0 },
      expiresAtHlc: { physicalMs: 1790003600000, logical: 0 },
    },
    requestedFields: [],
    accessLog: {
      previousEntryHash: '0000000000000000000000000000000000000000000000000000000000000000',
      sequence: -1,
      custodyDigest: 'not-a-digest',
    },
  });

  assert.equal(malformedGrant.decision, 'denied');
  assert.ok(malformedGrant.reasons.includes('support_policy_unverified'));
  assert.ok(malformedGrant.reasons.includes('support_policy_not_approved'));
  assert.ok(malformedGrant.reasons.includes('support_policy_receipt_absent'));
  assert.ok(malformedGrant.reasons.includes('support_grant_id_absent'));
  assert.ok(malformedGrant.reasons.includes('support_grant_scope_invalid'));
  assert.ok(malformedGrant.reasons.includes('support_grant_consent_mismatch'));
  assert.ok(malformedGrant.reasons.includes('support_grant_not_yet_active'));
  assert.ok(malformedGrant.reasons.includes('requested_fields_absent'));
  assert.ok(malformedGrant.reasons.includes('access_log_previous_hash_invalid'));
  assert.ok(malformedGrant.reasons.includes('access_log_sequence_invalid'));
  assert.ok(malformedGrant.reasons.includes('access_log_custody_digest_invalid'));

  const invalidRequestedValues = evaluateSupportAccessRequest({
    ...supportAccessInput,
    requestedAtHlc: { physicalMs: Number.MAX_SAFE_INTEGER + 1, logical: 0 },
    supportGrant: {
      ...supportAccessInput.supportGrant,
      notBeforeHlc: { physicalMs: 1790000000000, logical: Number.MAX_SAFE_INTEGER + 1 },
      expiresAtHlc: { physicalMs: 1790003600000, logical: Number.MAX_SAFE_INTEGER + 1 },
    },
    requestedFields: ['', 'free_form_payload'],
  });

  assert.equal(invalidRequestedValues.decision, 'denied');
  assert.ok(invalidRequestedValues.reasons.includes('requested_time_invalid'));
  assert.ok(invalidRequestedValues.reasons.includes('support_grant_start_time_invalid'));
  assert.ok(invalidRequestedValues.reasons.includes('support_grant_expiry_time_invalid'));
  assert.ok(invalidRequestedValues.reasons.includes('requested_field_invalid'));
  assert.ok(invalidRequestedValues.reasons.includes('requested_field_not_allowed'));

  const logicalCounterBounds = evaluateSupportAccessRequest({
    ...supportAccessInput,
    requestedAtHlc: { physicalMs: 1790000000000, logical: 33 },
    supportGrant: {
      ...supportAccessInput.supportGrant,
      notBeforeHlc: { physicalMs: 1790000000000, logical: 34 },
      expiresAtHlc: { physicalMs: 1790000000000, logical: 32 },
    },
  });

  assert.equal(logicalCounterBounds.decision, 'denied');
  assert.ok(logicalCounterBounds.reasons.includes('support_grant_not_yet_active'));
  assert.ok(logicalCounterBounds.reasons.includes('support_grant_expired'));
});

test('support access denies protected content and prohibited raw data requests before creating logs', async () => {
  const { evaluateSupportAccessRequest } = await loadSupportAccess();

  const denied = evaluateSupportAccessRequest({
    ...supportAccessInput,
    reason: {
      ...supportAccessInput.reason,
      description: 'Participant Alice Example reported a source document mismatch.',
    },
    requestedFields: ['audit_trail_metadata', 'source_document_body'],
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('protected_content_present'));
  assert.ok(denied.reasons.includes('requested_field_prohibited'));
  assert.equal(denied.logEntry, null);
  assert.equal(denied.receipt, null);
  assert.equal(denied.exochainProductionClaim, false);
});
