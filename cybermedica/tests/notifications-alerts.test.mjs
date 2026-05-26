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
const DIGEST_7 = '7777777777777777777777777777777777777777777777777777777777777777';
const DIGEST_8 = '8888888888888888888888888888888888888888888888888888888888888888';
const DIGEST_9 = '9999999999999999999999999999999999999999999999999999999999999999';

async function loadNotificationsAlerts() {
  try {
    return await import('../src/notifications-alerts.mjs');
  } catch (error) {
    assert.fail(`CyberMedica notifications alerts module must exist and load: ${error.message}`);
  }
}

const REQUIRED_CATEGORIES = [
  'approval',
  'assignment',
  'critical_risk',
  'decision',
  'due_date',
  'escalation',
  'expiration',
  'finding',
];

function notificationInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['notify', 'read'],
      authorityChainHash: DIGEST_A,
    },
    consent: {
      required: true,
      status: 'active',
      revoked: false,
      consentRef: 'participant-notification-consent-metadata',
    },
    policy: {
      policyRef: 'cm-notification-policy-fr-045',
      policyHash: DIGEST_B,
      evaluatedAtHlc: { physicalMs: 1794000000000, logical: 0 },
      categories: REQUIRED_CATEGORIES,
      allowedChannels: ['email_gateway', 'in_app', 'task_queue', 'webhook'],
      requireHumanReviewForCritical: true,
      metadataOnly: true,
      rawPayloadExcluded: true,
      participantIdentifiersExcluded: true,
      disclosureLogRequired: true,
    },
    disclosureLog: {
      logId: 'notification-disclosure-log-2026-05',
      loggedAtHlc: { physicalMs: 1794000000000, logical: 7 },
      disclosureLogHash: DIGEST_C,
      includesRawContent: false,
      purpose: 'qms_notification_routing',
    },
    channelRegistry: [
      channel('in-app-quality', 'in_app', DIGEST_D),
      channel('email-quality', 'email_gateway', DIGEST_E),
      channel('task-quality', 'task_queue', DIGEST_F),
      channel('webhook-sponsor', 'webhook', DIGEST_1),
    ],
    recipients: [
      recipient('did:exo:quality-manager-alpha', ['quality_manager'], ['site-alpha'], ['in-app-quality', 'email-quality']),
      recipient('did:exo:principal-investigator-alpha', ['principal_investigator'], ['site-alpha'], ['in-app-quality']),
      recipient('did:exo:sponsor-monitor-alpha', ['sponsor_monitor'], ['site-alpha'], ['webhook-sponsor']),
      recipient('did:exo:decision-chair-alpha', ['decision_forum'], ['site-alpha'], ['task-quality']),
    ],
    signals: [
      signal('assignment-delegation-review', 'assignment', ['quality_manager'], {
        sourceObjectFamily: 'delegation',
        sourceObjectRef: 'delegation-review-2026-05',
        detectedAtHlc: { physicalMs: 1794000000000, logical: 1 },
        scheduledAtHlc: { physicalMs: 1794000000000, logical: 2 },
        dueAtHlc: { physicalMs: 1794604800000, logical: 0 },
      }),
      signal('due-capa-action', 'due_date', ['quality_manager'], {
        sourceObjectFamily: 'capas',
        sourceObjectRef: 'CAPA-CONSENT-READINESS-001',
        detectedAtHlc: { physicalMs: 1794000000000, logical: 1 },
        scheduledAtHlc: { physicalMs: 1794000000000, logical: 3 },
        dueAtHlc: { physicalMs: 1794260000000, logical: 0 },
      }),
      signal('expiration-training', 'expiration', ['quality_manager', 'principal_investigator'], {
        sourceObjectFamily: 'training',
        sourceObjectRef: 'training-consent-process',
        detectedAtHlc: { physicalMs: 1794000000000, logical: 1 },
        scheduledAtHlc: { physicalMs: 1794000000000, logical: 4 },
        expiresAtHlc: { physicalMs: 1794520000000, logical: 0 },
      }),
      signal('critical-risk-product-storage', 'critical_risk', ['decision_forum', 'principal_investigator', 'quality_manager'], {
        severity: 'critical',
        sourceObjectFamily: 'risks',
        sourceObjectRef: 'risk-product-storage-001',
        detectedAtHlc: { physicalMs: 1794000000000, logical: 2 },
        scheduledAtHlc: { physicalMs: 1794000000000, logical: 5 },
        escalationRequired: true,
        decisionForumRef: 'dfm-product-storage-risk',
        humanReviewEvidenceHash: DIGEST_2,
      }),
      signal('finding-audit-major', 'finding', ['quality_manager'], {
        severity: 'major',
        sourceObjectFamily: 'findings',
        sourceObjectRef: 'finding-audit-major-001',
        detectedAtHlc: { physicalMs: 1794000000000, logical: 2 },
        scheduledAtHlc: { physicalMs: 1794000000000, logical: 6 },
      }),
      signal('decision-launch-readiness', 'decision', ['principal_investigator', 'quality_manager'], {
        sourceObjectFamily: 'decisions',
        sourceObjectRef: 'dfm-launch-readiness-2026-05',
        detectedAtHlc: { physicalMs: 1794000000000, logical: 3 },
        scheduledAtHlc: { physicalMs: 1794000000000, logical: 7 },
        decisionForumRef: 'dfm-launch-readiness-2026-05',
      }),
      signal('approval-consent-material', 'approval', ['quality_manager', 'sponsor_monitor'], {
        sourceObjectFamily: 'approvals',
        sourceObjectRef: 'approval-consent-material-v3',
        detectedAtHlc: { physicalMs: 1794000000000, logical: 3 },
        scheduledAtHlc: { physicalMs: 1794000000000, logical: 8 },
      }),
      signal('escalation-data-integrity', 'escalation', ['decision_forum', 'quality_manager'], {
        severity: 'critical',
        sourceObjectFamily: 'escalations',
        sourceObjectRef: 'escalation-data-integrity-001',
        detectedAtHlc: { physicalMs: 1794000000000, logical: 4 },
        scheduledAtHlc: { physicalMs: 1794000000000, logical: 9 },
        escalationRequired: true,
        decisionForumRef: 'dfm-data-integrity-escalation',
        humanReviewEvidenceHash: DIGEST_3,
      }),
    ],
    deliveryAttempts: [
      delivery('assignment-delegation-review', 'did:exo:quality-manager-alpha', 'in-app-quality', DIGEST_4),
      delivery('due-capa-action', 'did:exo:quality-manager-alpha', 'email-quality', DIGEST_5),
      delivery('expiration-training', 'did:exo:quality-manager-alpha', 'email-quality', DIGEST_6),
      delivery('expiration-training', 'did:exo:principal-investigator-alpha', 'in-app-quality', DIGEST_7),
      delivery('critical-risk-product-storage', 'did:exo:quality-manager-alpha', 'email-quality', DIGEST_8, {
        acknowledgementRequired: true,
        acknowledgedAtHlc: { physicalMs: 1794000000000, logical: 11 },
        acknowledgementEvidenceHash: DIGEST_9,
      }),
      delivery('critical-risk-product-storage', 'did:exo:principal-investigator-alpha', 'in-app-quality', DIGEST_A, {
        acknowledgementRequired: true,
        acknowledgedAtHlc: { physicalMs: 1794000000000, logical: 12 },
        acknowledgementEvidenceHash: DIGEST_B,
      }),
      delivery('critical-risk-product-storage', 'did:exo:decision-chair-alpha', 'task-quality', DIGEST_C, {
        acknowledgementRequired: true,
        acknowledgedAtHlc: { physicalMs: 1794000000000, logical: 13 },
        acknowledgementEvidenceHash: DIGEST_D,
      }),
      delivery('finding-audit-major', 'did:exo:quality-manager-alpha', 'in-app-quality', DIGEST_E),
      delivery('decision-launch-readiness', 'did:exo:quality-manager-alpha', 'email-quality', DIGEST_F),
      delivery('decision-launch-readiness', 'did:exo:principal-investigator-alpha', 'in-app-quality', DIGEST_1),
      delivery('approval-consent-material', 'did:exo:quality-manager-alpha', 'email-quality', DIGEST_2),
      delivery('approval-consent-material', 'did:exo:sponsor-monitor-alpha', 'webhook-sponsor', DIGEST_3),
      delivery('escalation-data-integrity', 'did:exo:quality-manager-alpha', 'email-quality', DIGEST_4, {
        acknowledgementRequired: true,
        acknowledgedAtHlc: { physicalMs: 1794000000000, logical: 14 },
        acknowledgementEvidenceHash: DIGEST_5,
      }),
      delivery('escalation-data-integrity', 'did:exo:decision-chair-alpha', 'task-quality', DIGEST_6, {
        acknowledgementRequired: true,
        acknowledgedAtHlc: { physicalMs: 1794000000000, logical: 15 },
        acknowledgementEvidenceHash: DIGEST_7,
      }),
    ],
  };
}

function channel(channelRef, channelType, providerEvidenceHash) {
  return {
    channelRef,
    channelType,
    providerEvidenceHash,
    enabled: true,
    metadataOnly: true,
    rawAddressStored: false,
  };
}

function recipient(did, roleRefs, siteRefs, channelRefs) {
  return {
    did,
    roleRefs,
    siteRefs,
    channelRefs,
    verifiedHuman: true,
    active: true,
    notificationOptOut: false,
  };
}

function signal(signalRef, category, requiredRecipientRoles, overrides = {}) {
  return {
    signalRef,
    category,
    severity: 'standard',
    sourceObjectFamily: 'quality_event',
    sourceObjectRef: `${category}-source-ref`,
    sourceArtifactHash: DIGEST_8,
    sourceCustodyDigest: DIGEST_9,
    titleHash: DIGEST_A,
    siteRefs: ['site-alpha'],
    protocolRefs: ['protocol-alpha'],
    sensitivityTags: ['metadata_only', 'qms'],
    participantLinked: false,
    requiredRecipientRoles,
    templateHash: DIGEST_B,
    payloadHash: DIGEST_C,
    escalationRequired: false,
    ...overrides,
  };
}

function delivery(signalRef, recipientDid, channelRef, deliveryEvidenceHash, overrides = {}) {
  return {
    signalRef,
    recipientDid,
    channelRef,
    status: 'delivered',
    dispatchedAtHlc: { physicalMs: 1794000000000, logical: 10 },
    deliveryEvidenceHash,
    acknowledgementRequired: false,
    ...overrides,
  };
}

test('notifications and alerts route all FR-045 categories as deterministic metadata-only receipts', async () => {
  const { evaluateNotificationsAlerts } = await loadNotificationsAlerts();

  const resultA = evaluateNotificationsAlerts(notificationInput());
  const resultB = evaluateNotificationsAlerts({
    ...notificationInput(),
    policy: {
      ...notificationInput().policy,
      categories: [...notificationInput().policy.categories].reverse(),
      allowedChannels: [...notificationInput().policy.allowedChannels].reverse(),
    },
    channelRegistry: [...notificationInput().channelRegistry].reverse(),
    recipients: [...notificationInput().recipients].reverse(),
    signals: [...notificationInput().signals].reverse(),
    deliveryAttempts: [...notificationInput().deliveryAttempts].reverse(),
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.deepEqual(resultA.notificationRun.categoriesCovered, REQUIRED_CATEGORIES);
  assert.equal(resultA.notificationRun.signalCount, 8);
  assert.equal(resultA.notificationRun.deliveryCount, 14);
  assert.equal(resultA.notificationRun.acknowledgementRequiredCount, 5);
  assert.equal(resultA.notificationRun.criticalSignalCount, 2);
  assert.deepEqual(resultA.notificationRun.escalationRoles, ['decision_forum', 'principal_investigator', 'quality_manager']);
  assert.deepEqual(
    resultA.alerts.map((alert) => alert.signalRef),
    [
      'approval-consent-material',
      'assignment-delegation-review',
      'critical-risk-product-storage',
      'decision-launch-readiness',
      'due-capa-action',
      'escalation-data-integrity',
      'expiration-training',
      'finding-audit-major',
    ],
  );
  assert.deepEqual(Object.keys(resultA.alerts[0]), [
    'category',
    'deliveryRefs',
    'dueAtHlc',
    'expiresAtHlc',
    'recipientRoles',
    'severity',
    'signalRef',
    'siteRefs',
    'sourceArtifactHash',
    'sourceObjectFamily',
    'sourceObjectRef',
  ]);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.equal(resultA.notificationRun.exochainProductionClaim, false);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
});

test('notifications and alerts fail closed for unsafe authority policy delivery and consent defects', async () => {
  const { evaluateNotificationsAlerts } = await loadNotificationsAlerts();

  const denied = evaluateNotificationsAlerts({
    ...notificationInput(),
    actor: { did: 'did:exo:ai-notification-agent', kind: 'ai_agent' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['read'], authorityChainHash: '' },
    consent: { required: true, status: 'revoked', revoked: true, consentRef: '' },
    policy: {
      ...notificationInput().policy,
      categories: ['assignment'],
      allowedChannels: ['email_gateway'],
      metadataOnly: false,
      rawPayloadExcluded: false,
      participantIdentifiersExcluded: false,
    },
    channelRegistry: [
      {
        ...channel('email-quality', 'email_gateway', ''),
        metadataOnly: false,
        rawAddressStored: true,
      },
    ],
    recipients: [
      {
        ...recipient('did:exo:quality-manager-alpha', ['quality_manager'], ['site-alpha'], ['email-quality']),
        verifiedHuman: false,
      },
    ],
    signals: [
      {
        ...notificationInput().signals[0],
        participantLinked: true,
        sourceArtifactHash: '',
        payloadHash: '',
      },
    ],
    deliveryAttempts: [
      {
        ...delivery('assignment-delegation-review', 'did:exo:quality-manager-alpha', 'email-quality', ''),
        status: 'pending',
      },
    ],
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('notification_authority_missing'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('participant_notification_consent_inactive'));
  assert.ok(denied.reasons.includes('policy_category_missing:approval'));
  assert.ok(denied.reasons.includes('notification_policy_metadata_boundary_invalid'));
  assert.ok(denied.reasons.includes('channel_provider_evidence_invalid:email-quality'));
  assert.ok(denied.reasons.includes('channel_raw_address_forbidden:email-quality'));
  assert.ok(denied.reasons.includes('recipient_human_verification_absent:did:exo:quality-manager-alpha'));
  assert.ok(denied.reasons.includes('signal_artifact_hash_invalid:assignment-delegation-review'));
  assert.ok(denied.reasons.includes('signal_payload_hash_invalid:assignment-delegation-review'));
  assert.ok(denied.reasons.includes('delivery_status_invalid:assignment-delegation-review:did:exo:quality-manager-alpha'));
  assert.ok(denied.reasons.includes('delivery_evidence_hash_invalid:assignment-delegation-review:did:exo:quality-manager-alpha'));
});

test('critical risks findings and escalations require routed human escalation evidence', async () => {
  const { evaluateNotificationsAlerts } = await loadNotificationsAlerts();

  const denied = evaluateNotificationsAlerts({
    ...notificationInput(),
    signals: notificationInput().signals.map((entry) =>
      entry.signalRef === 'critical-risk-product-storage'
        ? {
            ...entry,
            decisionForumRef: '',
            humanReviewEvidenceHash: '',
            requiredRecipientRoles: ['quality_manager'],
          }
        : entry,
    ),
    deliveryAttempts: notificationInput().deliveryAttempts.filter(
      (entry) =>
        entry.signalRef !== 'critical-risk-product-storage' ||
        entry.recipientDid === 'did:exo:quality-manager-alpha',
    ),
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('critical_signal_decision_forum_absent:critical-risk-product-storage'));
  assert.ok(denied.reasons.includes('critical_signal_human_review_absent:critical-risk-product-storage'));
  assert.ok(denied.reasons.includes('critical_signal_role_missing:critical-risk-product-storage:decision_forum'));
  assert.ok(denied.reasons.includes('critical_signal_role_missing:critical-risk-product-storage:principal_investigator'));
  assert.ok(denied.reasons.includes('signal_delivery_missing:critical-risk-product-storage:decision_forum'));
  assert.ok(denied.reasons.includes('signal_delivery_missing:critical-risk-product-storage:principal_investigator'));
});

test('notifications and alerts accept same-tick logical clocks and reject unsafe ordering', async () => {
  const { evaluateNotificationsAlerts } = await loadNotificationsAlerts();

  const sameTick = evaluateNotificationsAlerts({
    ...notificationInput(),
    policy: {
      ...notificationInput().policy,
      evaluatedAtHlc: { physicalMs: 1794000000000, logical: 0 },
    },
    signals: notificationInput().signals.map((entry) => ({
      ...entry,
      detectedAtHlc: { physicalMs: 1794000000000, logical: 1 },
      scheduledAtHlc: { physicalMs: 1794000000000, logical: 2 },
    })),
    deliveryAttempts: notificationInput().deliveryAttempts.map((entry) => ({
      ...entry,
      dispatchedAtHlc: { physicalMs: 1794000000000, logical: 3 },
    })),
    disclosureLog: {
      ...notificationInput().disclosureLog,
      loggedAtHlc: { physicalMs: 1794000000000, logical: 4 },
    },
  });

  assert.equal(sameTick.decision, 'permitted');

  const unsafe = evaluateNotificationsAlerts({
    ...notificationInput(),
    signals: notificationInput().signals.map((entry) =>
      entry.signalRef === 'due-capa-action'
        ? {
            ...entry,
            detectedAtHlc: { physicalMs: 1794000000000, logical: 6 },
            scheduledAtHlc: { physicalMs: 1794000000000, logical: 5 },
            dueAtHlc: { physicalMs: 1793999999999, logical: 0 },
          }
        : entry,
    ),
    deliveryAttempts: notificationInput().deliveryAttempts.map((entry) =>
      entry.signalRef === 'due-capa-action'
        ? {
            ...entry,
            dispatchedAtHlc: { physicalMs: 1794000000000, logical: 4 },
          }
        : entry,
    ),
  });

  assert.equal(unsafe.decision, 'denied');
  assert.ok(unsafe.reasons.includes('signal_scheduled_before_detected:due-capa-action'));
  assert.ok(unsafe.reasons.includes('signal_due_before_detected:due-capa-action'));
  assert.ok(unsafe.reasons.includes('delivery_before_signal_scheduled:due-capa-action:did:exo:quality-manager-alpha'));
});

test('notifications and alerts cover not-required consent and malformed HLC denial branches', async () => {
  const { evaluateNotificationsAlerts } = await loadNotificationsAlerts();

  const participantMetadataOnly = evaluateNotificationsAlerts({
    ...notificationInput(),
    consent: {
      required: false,
      status: 'not_required',
      revoked: false,
    },
    signals: notificationInput().signals.map((entry) =>
      entry.signalRef === 'assignment-delegation-review'
        ? {
            ...entry,
            participantLinked: true,
          }
        : entry,
    ),
    deliveryAttempts: notificationInput().deliveryAttempts.map((entry) =>
      entry.signalRef === 'critical-risk-product-storage' &&
      entry.recipientDid === 'did:exo:decision-chair-alpha'
        ? {
            ...entry,
            acknowledgedAtHlc: entry.dispatchedAtHlc,
          }
        : entry,
    ),
  });

  assert.equal(participantMetadataOnly.decision, 'permitted');

  const malformed = evaluateNotificationsAlerts({
    ...notificationInput(),
    policy: {
      ...notificationInput().policy,
      evaluatedAtHlc: { physicalMs: 1794000000000, logical: -1 },
    },
    disclosureLog: {
      ...notificationInput().disclosureLog,
      loggedAtHlc: { physicalMs: 1794000000000, logical: -1 },
    },
  });

  assert.equal(malformed.decision, 'denied');
  assert.ok(malformed.reasons.includes('notification_policy_time_invalid'));
  assert.ok(malformed.reasons.includes('disclosure_log_time_invalid'));
});

test('notifications and alerts reject raw messages contact data and protected content before receipts', async () => {
  const { evaluateNotificationsAlerts } = await loadNotificationsAlerts();

  assert.throws(
    () =>
      evaluateNotificationsAlerts({
        ...notificationInput(),
        signals: [
          {
            ...notificationInput().signals[0],
            rawMessageBody: 'Tell Participant Alice Example about the assignment.',
          },
        ],
      }),
    /raw notification content|protected content/i,
  );

  assert.throws(
    () =>
      evaluateNotificationsAlerts({
        ...notificationInput(),
        recipients: [
          {
            ...notificationInput().recipients[0],
            email: 'alice@example.com',
          },
        ],
      }),
    /protected content|raw notification content/i,
  );
});
