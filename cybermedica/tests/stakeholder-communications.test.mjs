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

const REQUIRED_AUDIENCE_CLASSES = ['auditors', 'cro', 'iec_irb', 'monitors', 'regulators', 'sponsors', 'staff', 'stakeholders'];
const REQUIRED_TOPIC_FAMILIES = [
  'ae_sae_lessons_learned',
  'deviations',
  'feedback',
  'protocol_requirements',
  'quality_improvement_results',
  'regulatory_changes',
  'safety_governance_updates',
  'strategy_updates',
];

async function loadStakeholderCommunications() {
  try {
    return await import('../src/stakeholder-communications.mjs');
  } catch (error) {
    assert.fail(`CyberMedica stakeholder communications module must exist and load: ${error.message}`);
  }
}

function mergeDeep(base, overrides) {
  if (Array.isArray(base) || Array.isArray(overrides)) {
    return overrides === undefined ? base : overrides;
  }
  if (base === null || overrides === null || typeof base !== 'object' || typeof overrides !== 'object') {
    return overrides === undefined ? base : overrides;
  }
  return Object.fromEntries(
    [...new Set([...Object.keys(base), ...Object.keys(overrides)])].map((key) => [
      key,
      mergeDeep(base[key], overrides[key]),
    ]),
  );
}

function audience(audienceClass, digest, overrides = {}) {
  return {
    audienceRef: `audience-${audienceClass}`,
    audienceClass,
    roleRefs: [`${audienceClass}_reader`],
    authorizedChannelRefs: [`channel-${audienceClass}`],
    accessPolicyHash: digest,
    verifiedRecipientGroup: true,
    active: true,
    metadataOnly: true,
    rawAddressStored: false,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function channel(audienceClass, channelType, digest, overrides = {}) {
  return {
    channelRef: `channel-${audienceClass}`,
    channelType,
    providerEvidenceHash: digest,
    active: true,
    metadataOnly: true,
    rawAddressStored: false,
    ...overrides,
  };
}

function communicationItem(topicFamily, audienceClasses, digest, overrides = {}) {
  return {
    itemRef: `comm-${topicFamily}`,
    topicFamily,
    audienceClasses,
    channelRefs: audienceClasses.map((audienceClass) => `channel-${audienceClass}`),
    artifactHash: digest,
    custodyDigest: DIGEST_9,
    templateHash: DIGEST_A,
    payloadHash: DIGEST_B,
    sensitivityTags: ['metadata_only', 'qms_communication'],
    scheduledAtHlc: { physicalMs: 1801000000000, logical: 3 },
    humanReviewEvidenceHash: DIGEST_C,
    escalationRequired: false,
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function delivery(itemRef, audienceClass, digest, overrides = {}) {
  return {
    itemRef,
    audienceRef: `audience-${audienceClass}`,
    channelRef: `channel-${audienceClass}`,
    status: 'delivered',
    deliveredAtHlc: { physicalMs: 1801000000000, logical: 4 },
    deliveryEvidenceHash: digest,
    disclosureEventRef: `disclosure-${itemRef}-${audienceClass}`,
    disclosureEventHash: DIGEST_1,
    acknowledgementRequired: false,
    ...overrides,
  };
}

function baseInput(overrides = {}) {
  const items = [
    communicationItem('strategy_updates', ['staff', 'stakeholders'], DIGEST_A),
    communicationItem('regulatory_changes', ['staff', 'regulators', 'iec_irb'], DIGEST_B),
    communicationItem('protocol_requirements', ['staff', 'cro', 'sponsors', 'monitors'], DIGEST_C),
    communicationItem('ae_sae_lessons_learned', ['staff', 'cro', 'sponsors', 'monitors', 'iec_irb'], DIGEST_D, {
      escalationRequired: true,
      decisionForumMatterRef: 'dfm-ae-sae-communication-alpha',
      humanReviewEvidenceHash: DIGEST_D,
    }),
    communicationItem('deviations', ['staff', 'cro', 'sponsors', 'monitors', 'auditors'], DIGEST_E),
    communicationItem('feedback', ['staff', 'stakeholders'], DIGEST_F),
    communicationItem('safety_governance_updates', ['staff', 'cro', 'sponsors', 'monitors', 'regulators', 'iec_irb'], DIGEST_2, {
      escalationRequired: true,
      decisionForumMatterRef: 'dfm-safety-governance-communication-alpha',
      humanReviewEvidenceHash: DIGEST_E,
    }),
    communicationItem('quality_improvement_results', ['staff', 'cro', 'sponsors', 'auditors'], DIGEST_3),
  ];

  const deliveryEvidence = items.flatMap((item, itemIndex) =>
    item.audienceClasses.map((audienceClass, audienceIndex) =>
      delivery(item.itemRef, audienceClass, [DIGEST_4, DIGEST_5, DIGEST_6, DIGEST_7, DIGEST_8][(itemIndex + audienceIndex) % 5], {
        acknowledgementRequired: item.escalationRequired === true,
        acknowledgedAtHlc: item.escalationRequired === true ? { physicalMs: 1801000000000, logical: 5 + itemIndex } : null,
        acknowledgementEvidenceHash: item.escalationRequired === true ? DIGEST_F : null,
      }),
    ),
  );

  const input = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:communications-owner-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['stakeholder_communication', 'read'],
      authorityChainHash: DIGEST_A,
    },
    communicationPolicy: {
      policyRef: 'policy-6-communication-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredAudienceClasses: REQUIRED_AUDIENCE_CLASSES,
      requiredTopicFamilies: REQUIRED_TOPIC_FAMILIES,
      allowedChannelTypes: ['email_gateway', 'in_app', 'task_queue', 'webhook'],
      disclosureLogRequired: true,
      sponsorCroBoundaryRequired: true,
      participantIdentifiersExcluded: true,
      sponsorConfidentialExcluded: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1801000000000, logical: 0 },
    },
    communicationPlan: {
      planRef: 'site-communication-plan-alpha',
      version: '2026.05',
      planHash: DIGEST_C,
      status: 'approved',
      approvedByDid: 'did:exo:site-leader-alpha',
      reviewedByHuman: true,
      approvedAtHlc: { physicalMs: 1801000000000, logical: 1 },
      effectiveAtHlc: { physicalMs: 1801000000000, logical: 2 },
      nextReviewDueHlc: { physicalMs: 1803600000000, logical: 0 },
      channelPolicyHash: DIGEST_D,
      escalationPathHash: DIGEST_E,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    disclosureLog: {
      logRef: 'stakeholder-communication-disclosure-alpha',
      logHash: DIGEST_F,
      recordedAtHlc: { physicalMs: 1801000000000, logical: 6 },
      purpose: 'policy_6_stakeholder_communications',
      includesRawContent: false,
      metadataOnly: true,
    },
    channels: [
      channel('staff', 'in_app', DIGEST_A),
      channel('stakeholders', 'email_gateway', DIGEST_B),
      channel('sponsors', 'webhook', DIGEST_C),
      channel('cro', 'webhook', DIGEST_D),
      channel('monitors', 'task_queue', DIGEST_E),
      channel('auditors', 'task_queue', DIGEST_F),
      channel('iec_irb', 'email_gateway', DIGEST_1),
      channel('regulators', 'email_gateway', DIGEST_2),
    ],
    audienceRegistry: [
      audience('staff', DIGEST_A),
      audience('stakeholders', DIGEST_B),
      audience('sponsors', DIGEST_C, { sponsorCroScopeHash: DIGEST_3 }),
      audience('cro', DIGEST_D, { sponsorCroScopeHash: DIGEST_4 }),
      audience('monitors', DIGEST_E),
      audience('auditors', DIGEST_F),
      audience('iec_irb', DIGEST_1),
      audience('regulators', DIGEST_2),
    ],
    communicationItems: items,
    deliveryEvidence,
    humanReview: {
      reviewerDid: 'did:exo:quality-manager-alpha',
      decision: 'stakeholder_communications_accepted_inactive_trust',
      reviewedAtHlc: { physicalMs: 1801000000000, logical: 7 },
      reviewEvidenceHash: DIGEST_5,
      aiFinalAuthority: false,
      metadataOnly: true,
    },
    custodyDigest: DIGEST_6,
  };

  return mergeDeep(input, overrides);
}

test('stakeholder communications create deterministic inactive Policy 6 packets', async () => {
  const { evaluateStakeholderCommunications } = await loadStakeholderCommunications();
  const input = baseInput();

  const first = evaluateStakeholderCommunications(input);
  const second = evaluateStakeholderCommunications({
    ...input,
    audienceRegistry: [...input.audienceRegistry].reverse(),
    communicationItems: [...input.communicationItems].reverse(),
    deliveryEvidence: [...input.deliveryEvidence].reverse(),
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.trustState, 'inactive');
  assert.equal(first.exochainProductionClaim, false);
  assert.equal(first.communicationPacket.packetId, second.communicationPacket.packetId);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.deepEqual(first.communicationPacket.audienceClasses, REQUIRED_AUDIENCE_CLASSES);
  assert.deepEqual(first.communicationPacket.topicFamilies, REQUIRED_TOPIC_FAMILIES);
  assert.equal(first.communicationPacket.itemCount, 8);
  assert.equal(first.communicationPacket.deliveryCount, input.deliveryEvidence.length);
  assert.equal(first.communicationPacket.disclosureLogRef, 'stakeholder-communication-disclosure-alpha');
  assert.equal(first.receipt.anchorPayload.artifactType, 'stakeholder_communications_packet');
  assert.equal(first.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(first), /Participant Alice|raw sponsor|root-backed production authority/iu);
});

test('stakeholder communications fail closed for missing audience and topic coverage', async () => {
  const { evaluateStakeholderCommunications } = await loadStakeholderCommunications();
  const input = baseInput({
    actor: { did: 'did:exo:ai-reviewer-alpha', kind: 'ai_agent' },
    authority: { ...baseInput().authority, permissions: ['read'] },
    communicationPolicy: {
      ...baseInput().communicationPolicy,
      requiredAudienceClasses: REQUIRED_AUDIENCE_CLASSES.filter((audienceClass) => audienceClass !== 'regulators'),
      requiredTopicFamilies: REQUIRED_TOPIC_FAMILIES.filter((topicFamily) => topicFamily !== 'regulatory_changes'),
    },
    communicationPlan: {
      ...baseInput().communicationPlan,
      status: 'draft',
      reviewedByHuman: false,
      nextReviewDueHlc: { physicalMs: 1800999999999, logical: 0 },
    },
    communicationItems: baseInput().communicationItems.filter((item) => item.topicFamily !== 'regulatory_changes'),
    audienceRegistry: baseInput().audienceRegistry.filter((entry) => entry.audienceClass !== 'regulators'),
  });

  const result = evaluateStakeholderCommunications(input);

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.communicationPacket, null);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('stakeholder_communication_authority_missing'));
  assert.ok(result.reasons.includes('policy_audience_class_missing:regulators'));
  assert.ok(result.reasons.includes('policy_topic_family_missing:regulatory_changes'));
  assert.ok(result.reasons.includes('packet_audience_class_missing:regulators'));
  assert.ok(result.reasons.includes('packet_topic_family_missing:regulatory_changes'));
  assert.ok(result.reasons.includes('communication_plan_not_approved'));
  assert.ok(result.reasons.includes('communication_plan_human_review_absent'));
  assert.ok(result.reasons.includes('communication_plan_review_overdue'));
});

test('stakeholder communications enforce delivery disclosure HLC and sponsor boundaries', async () => {
  const { evaluateStakeholderCommunications } = await loadStakeholderCommunications();
  const source = baseInput();
  const brokenDelivery = {
    ...source.deliveryEvidence.find((entry) => entry.itemRef === 'comm-protocol_requirements' && entry.audienceRef === 'audience-sponsors'),
    deliveredAtHlc: { physicalMs: 1800999999999, logical: 0 },
    disclosureEventHash: '',
  };
  const result = evaluateStakeholderCommunications({
    ...source,
    disclosureLog: { ...source.disclosureLog, includesRawContent: true },
    audienceRegistry: source.audienceRegistry.map((entry) =>
      entry.audienceClass === 'sponsors'
        ? { ...entry, sponsorCroScopeHash: '', protectedContentExcluded: false }
        : entry,
    ),
    communicationItems: source.communicationItems.map((item) =>
      item.topicFamily === 'safety_governance_updates'
        ? {
            ...item,
            escalationRequired: false,
            decisionForumMatterRef: '',
            humanReviewEvidenceHash: '',
            sensitivityTags: ['metadata_only', 'sponsor_confidential_metadata'],
          }
        : item,
    ),
    deliveryEvidence: source.deliveryEvidence.map((entry) =>
      entry.itemRef === brokenDelivery.itemRef && entry.audienceRef === brokenDelivery.audienceRef ? brokenDelivery : entry,
    ),
  });

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('disclosure_log_raw_content_forbidden'));
  assert.ok(result.reasons.includes('sponsor_cro_scope_hash_invalid:audience-sponsors'));
  assert.ok(result.reasons.includes('audience_protected_boundary_invalid:audience-sponsors'));
  assert.ok(result.reasons.includes('delivery_before_item_scheduled:comm-protocol_requirements:audience-sponsors'));
  assert.ok(result.reasons.includes('delivery_disclosure_hash_invalid:comm-protocol_requirements:audience-sponsors'));
  assert.ok(result.reasons.includes('material_communication_escalation_absent:comm-safety_governance_updates'));
  assert.ok(result.reasons.includes('material_communication_decision_forum_absent:comm-safety_governance_updates'));
  assert.ok(result.reasons.includes('material_communication_human_review_absent:comm-safety_governance_updates'));
});

test('stakeholder communications reject raw content protected data and secrets', async () => {
  const { ProtectedContentError, evaluateStakeholderCommunications } = await loadStakeholderCommunications();

  assert.throws(
    () =>
      evaluateStakeholderCommunications({
        ...baseInput(),
        rawCommunicationBody: 'Direct update for Participant Alice Example.',
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateStakeholderCommunications({
        ...baseInput(),
        communicationPlan: { ...baseInput().communicationPlan, clientSecret: 'secret-value' },
      }),
    ProtectedContentError,
  );
});
