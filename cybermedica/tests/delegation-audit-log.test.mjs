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

const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const DIGEST_A = '1111111111111111111111111111111111111111111111111111111111111111';
const DIGEST_B = '2222222222222222222222222222222222222222222222222222222222222222';
const DIGEST_C = '3333333333333333333333333333333333333333333333333333333333333333';
const DIGEST_D = '4444444444444444444444444444444444444444444444444444444444444444';
const DIGEST_E = '5555555555555555555555555555555555555555555555555555555555555555';
const DIGEST_F = '6666666666666666666666666666666666666666666666666666666666666666';

async function loadDelegationAuditLog() {
  try {
    return await import('../src/delegation-audit-log.mjs');
  } catch (error) {
    assert.fail(`CyberMedica delegation-audit-log module must exist and load: ${error.message}`);
  }
}

function delegationInput(overrides = {}) {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:principal-investigator-alpha',
      kind: 'human',
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['delegate_protocol_task', 'perform_protocol_task'],
      authorityChainHash: DIGEST_C,
    },
    delegationEvent: {
      eventId: 'CM-DEL-EVT-0001',
      eventType: 'delegation_authorized',
      sequence: 1,
      previousDelegationHash: ZERO_HASH,
      occurredAtHlc: { physicalMs: 1790000002000, logical: 7 },
      delegationId: 'delegation-protocol-cardiac-alpha-crc',
      parentDelegationId: 'delegation-site-root-pi',
      parentDelegationHash: DIGEST_A,
      grantorDid: 'did:exo:principal-investigator-alpha',
      delegateDid: 'did:exo:crc-alpha',
      status: 'active',
      reasonCode: 'protocol_activation',
      evidenceHash: DIGEST_B,
      signatureHash: DIGEST_D,
      parentScope: {
        siteIds: ['site-alpha'],
        protocolIds: ['protocol-cardiac-alpha'],
        permissions: ['perform_protocol_task', 'review_protocol_task'],
        allowedActions: ['enrollment_screening', 'informed_consent_documentation', 'source_document_review'],
      },
      scope: {
        siteId: 'site-alpha',
        protocolId: 'protocol-cardiac-alpha',
        role: 'clinical_research_coordinator',
        permissions: ['perform_protocol_task'],
        allowedActions: ['informed_consent_documentation', 'enrollment_screening'],
        notBeforeHlc: { physicalMs: 1789900000000, logical: 0 },
        expiresAtHlc: { physicalMs: 1795000000000, logical: 0 },
      },
      lineage: [
        {
          delegationId: 'delegation-site-root-pi',
          grantorDid: 'did:exo:qms-governor-alpha',
          delegateDid: 'did:exo:principal-investigator-alpha',
          authorityChainHash: DIGEST_E,
        },
      ],
    },
    custodyDigest: DIGEST_F,
    ...overrides,
  };
}

test('delegation audit log records authorized scoped delegation with deterministic inactive receipts', async () => {
  const { recordDelegationAuditEvent } = await loadDelegationAuditLog();

  const recordedA = recordDelegationAuditEvent(delegationInput());
  const recordedB = recordDelegationAuditEvent(
    delegationInput({
      authority: {
        authorityChainHash: DIGEST_C,
        permissions: ['perform_protocol_task', 'delegate_protocol_task'],
        expired: false,
        revoked: false,
        valid: true,
      },
      delegationEvent: {
        ...delegationInput().delegationEvent,
        parentScope: {
          protocolIds: ['protocol-cardiac-alpha'],
          siteIds: ['site-alpha'],
          allowedActions: ['source_document_review', 'informed_consent_documentation', 'enrollment_screening'],
          permissions: ['review_protocol_task', 'perform_protocol_task'],
        },
        scope: {
          ...delegationInput().delegationEvent.scope,
          allowedActions: ['enrollment_screening', 'informed_consent_documentation'],
          permissions: ['perform_protocol_task'],
        },
      },
    }),
  );

  assert.equal(recordedA.decision, 'permitted');
  assert.equal(recordedA.failClosed, false);
  assert.deepEqual(recordedA.reasons, []);
  assert.equal(recordedA.delegationAuditRecord.delegationId, 'delegation-protocol-cardiac-alpha-crc');
  assert.equal(recordedA.delegationAuditRecord.eventType, 'delegation_authorized');
  assert.equal(recordedA.delegationAuditRecord.activeForUse, true);
  assert.equal(recordedA.delegationAuditRecord.scopeHash, recordedB.delegationAuditRecord.scopeHash);
  assert.equal(recordedA.delegationAuditRecord.delegationEventHash, recordedB.delegationAuditRecord.delegationEventHash);
  assert.equal(recordedA.receipt.receiptId, recordedB.receipt.receiptId);
  assert.equal(recordedA.receipt.trustState, 'inactive');
  assert.equal(recordedA.receipt.exochainProductionClaim, false);
  assert.equal(recordedA.receipt.anchorPayload.artifactType, 'delegation_audit_event');
  assert.deepEqual(recordedA.delegationAuditRecord.scope.allowedActions, [
    'enrollment_screening',
    'informed_consent_documentation',
  ]);
  assert.deepEqual(recordedA.delegationAuditRecord.scope.permissions, ['perform_protocol_task']);
  assert.doesNotMatch(JSON.stringify(recordedA), /source document|participant alice|raw signature|production authority/iu);
});

test('delegation audit log fails closed for self grant scope escalation cycles tenant and authority defects', async () => {
  const { recordDelegationAuditEvent } = await loadDelegationAuditLog();

  const denied = recordDelegationAuditEvent(
    delegationInput({
      targetTenantId: 'tenant-site-beta',
      actor: { did: 'did:exo:principal-investigator-alpha', kind: 'ai_agent' },
      authority: {
        valid: true,
        revoked: true,
        expired: true,
        permissions: ['read'],
        authorityChainHash: 'not-a-digest',
      },
      delegationEvent: {
        ...delegationInput().delegationEvent,
        eventId: '',
        eventType: 'delegation_authorized',
        sequence: 2,
        previousDelegationHash: ZERO_HASH,
        occurredAtHlc: { physicalMs: 1790000002000, logical: -1 },
        grantorDid: 'did:exo:crc-alpha',
        delegateDid: 'did:exo:crc-alpha',
        evidenceHash: ZERO_HASH,
        signatureHash: 'not-a-digest',
        parentScope: {
          siteIds: ['site-alpha'],
          protocolIds: ['protocol-cardiac-alpha'],
          permissions: ['perform_protocol_task'],
          allowedActions: ['informed_consent_documentation'],
        },
        scope: {
          ...delegationInput().delegationEvent.scope,
          protocolId: 'protocol-neurology-beta',
          permissions: ['perform_protocol_task', 'approve_protocol_launch'],
          allowedActions: ['informed_consent_documentation', 'source_document_review'],
        },
        lineage: [
          ...delegationInput().delegationEvent.lineage,
          {
            delegationId: 'delegation-cycle-alpha',
            grantorDid: 'did:exo:crc-alpha',
            delegateDid: 'did:exo:principal-investigator-alpha',
            authorityChainHash: DIGEST_E,
          },
        ],
      },
      custodyDigest: 'not-a-digest',
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.delegationAuditRecord, null);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_delegation_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_chain_revoked'));
  assert.ok(denied.reasons.includes('authority_chain_expired'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('delegation_event_id_absent'));
  assert.ok(denied.reasons.includes('previous_delegation_hash_missing_for_sequence'));
  assert.ok(denied.reasons.includes('delegation_event_time_invalid'));
  assert.ok(denied.reasons.includes('delegation_grantor_actor_mismatch'));
  assert.ok(denied.reasons.includes('delegation_self_grant_forbidden'));
  assert.ok(denied.reasons.includes('delegation_scope_permission_escalation'));
  assert.ok(denied.reasons.includes('delegation_scope_action_escalation'));
  assert.ok(denied.reasons.includes('delegation_scope_protocol_escalation'));
  assert.ok(denied.reasons.includes('delegation_cycle_detected'));
  assert.ok(denied.reasons.includes('delegation_evidence_hash_invalid'));
  assert.ok(denied.reasons.includes('delegation_signature_hash_invalid'));
  assert.ok(denied.reasons.includes('custody_digest_invalid'));
});

test('delegation revocation requires signed revocation evidence and disables active use', async () => {
  const { recordDelegationAuditEvent } = await loadDelegationAuditLog();

  const revoked = recordDelegationAuditEvent(
    delegationInput({
      delegationEvent: {
        ...delegationInput().delegationEvent,
        eventId: 'CM-DEL-EVT-0002',
        eventType: 'delegation_revoked',
        sequence: 2,
        previousDelegationHash: DIGEST_A,
        occurredAtHlc: { physicalMs: 1790000003000, logical: 0 },
        status: 'revoked',
        revocationEvidence: {
          revokedByDid: 'did:exo:principal-investigator-alpha',
          revokedAtHlc: { physicalMs: 1790000003000, logical: 0 },
          reasonCode: 'scope_no_longer_required',
          revocationSignatureHash: DIGEST_E,
        },
      },
    }),
  );

  assert.equal(revoked.decision, 'permitted');
  assert.equal(revoked.delegationAuditRecord.eventType, 'delegation_revoked');
  assert.equal(revoked.delegationAuditRecord.activeForUse, false);
  assert.equal(revoked.delegationAuditRecord.revocationEvidence.signatureVerified, true);
  assert.equal(revoked.receipt.trustState, 'inactive');

  const denied = recordDelegationAuditEvent(
    delegationInput({
      delegationEvent: {
        ...delegationInput().delegationEvent,
        eventType: 'delegation_revoked',
        sequence: 2,
        previousDelegationHash: DIGEST_A,
        status: 'revoked',
        revocationEvidence: {
          revokedByDid: 'did:exo:principal-investigator-alpha',
          revokedAtHlc: { physicalMs: 1790000003000, logical: 0 },
          reasonCode: '',
          revocationSignatureHash: ZERO_HASH,
        },
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('revocation_reason_absent'));
  assert.ok(denied.reasons.includes('revocation_signature_hash_invalid'));
});

test('delegation audit chains verify continuity and reject broken or empty chains', async () => {
  const { recordDelegationAuditEvent, verifyDelegationAuditChain } = await loadDelegationAuditLog();

  const first = recordDelegationAuditEvent(delegationInput());
  const second = recordDelegationAuditEvent(
    delegationInput({
      delegationEvent: {
        ...delegationInput().delegationEvent,
        eventId: 'CM-DEL-EVT-0002',
        eventType: 'delegation_scope_reduced',
        sequence: 2,
        previousDelegationHash: first.delegationAuditRecord.delegationEventHash,
        occurredAtHlc: { physicalMs: 1790000003000, logical: 0 },
        scope: {
          ...delegationInput().delegationEvent.scope,
          allowedActions: ['informed_consent_documentation'],
        },
      },
    }),
  );

  const verified = verifyDelegationAuditChain([first.delegationAuditRecord, second.delegationAuditRecord]);

  assert.equal(verified.valid, true);
  assert.equal(verified.failClosed, false);
  assert.equal(verified.entriesVerified, 2);
  assert.equal(verified.headHash, second.delegationAuditRecord.delegationEventHash);
  assert.deepEqual(verified.reasons, []);

  const broken = verifyDelegationAuditChain([
    first.delegationAuditRecord,
    {
      ...second.delegationAuditRecord,
      previousDelegationHash: DIGEST_B,
    },
  ]);

  assert.equal(broken.valid, false);
  assert.equal(broken.failClosed, true);
  assert.ok(broken.reasons.includes('delegation_chain_broken_at_2'));

  const empty = verifyDelegationAuditChain([]);
  assert.equal(empty.valid, false);
  assert.equal(empty.failClosed, true);
  assert.deepEqual(empty.reasons, ['delegation_chain_empty']);
  assert.equal(empty.headHash, null);
});

test('delegation audit log rejects protected content and raw signature material before receipt creation', async () => {
  const { recordDelegationAuditEvent } = await loadDelegationAuditLog();

  assert.throws(
    () =>
      recordDelegationAuditEvent({
        ...delegationInput(),
        sourceDocumentBody: 'Participant Alice Example source document content must not enter delegation logs.',
      }),
    /protected content/i,
  );

  assert.throws(
    () =>
      recordDelegationAuditEvent({
        ...delegationInput(),
        delegationEvent: {
          ...delegationInput().delegationEvent,
          rawSignature: 'raw signature bytes must remain outside CyberMedica delegation logs',
        },
      }),
    /raw signature/i,
  );
});

test('delegation audit log reports malformed lineage and HLC ordering denial branches', async () => {
  const { recordDelegationAuditEvent } = await loadDelegationAuditLog();

  const notBeforeAfterExpiry = recordDelegationAuditEvent(
    delegationInput({
      delegationEvent: {
        ...delegationInput().delegationEvent,
        scope: {
          ...delegationInput().delegationEvent.scope,
          notBeforeHlc: { physicalMs: 1795000000001, logical: 0 },
          expiresAtHlc: { physicalMs: 1795000000000, logical: 0 },
        },
        lineage: [
          {
            delegationId: 'delegation-malformed-edge',
            authorityChainHash: DIGEST_E,
          },
        ],
      },
    }),
  );

  assert.equal(notBeforeAfterExpiry.decision, 'denied');
  assert.ok(notBeforeAfterExpiry.reasons.includes('delegation_scope_time_window_invalid'));

  const logicalWindow = recordDelegationAuditEvent(
    delegationInput({
      delegationEvent: {
        ...delegationInput().delegationEvent,
        occurredAtHlc: { physicalMs: 1795000000000, logical: 1 },
        scope: {
          ...delegationInput().delegationEvent.scope,
          notBeforeHlc: { physicalMs: 1795000000000, logical: 0 },
          expiresAtHlc: { physicalMs: 1795000000000, logical: 1 },
        },
      },
    }),
  );

  assert.equal(logicalWindow.decision, 'permitted');
  assert.equal(logicalWindow.delegationAuditRecord.activeForUse, true);

  const logicalInversion = recordDelegationAuditEvent(
    delegationInput({
      delegationEvent: {
        ...delegationInput().delegationEvent,
        scope: {
          ...delegationInput().delegationEvent.scope,
          notBeforeHlc: { physicalMs: 1795000000000, logical: 2 },
          expiresAtHlc: { physicalMs: 1795000000000, logical: 1 },
        },
      },
    }),
  );

  assert.equal(logicalInversion.decision, 'denied');
  assert.ok(logicalInversion.reasons.includes('delegation_scope_time_window_invalid'));

  const prematureExpiration = recordDelegationAuditEvent(
    delegationInput({
      delegationEvent: {
        ...delegationInput().delegationEvent,
        eventType: 'delegation_expired',
        status: 'expired',
        occurredAtHlc: { physicalMs: 1790000003000, logical: 0 },
      },
    }),
  );

  assert.equal(prematureExpiration.decision, 'denied');
  assert.ok(prematureExpiration.reasons.includes('delegation_expiration_before_scope_expiry'));
});
