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

import { ProtectedContentError, canonicalize, createEvidenceReceipt, sha256Hex } from './qms-contracts.mjs';

export { ProtectedContentError };

const HEX_64 = /^[0-9a-f]{64}$/u;
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const REQUIRED_PERMISSION = 'stakeholder_communication';

const REQUIRED_AUDIENCE_CLASSES = Object.freeze([
  'auditors',
  'cro',
  'iec_irb',
  'monitors',
  'regulators',
  'sponsors',
  'staff',
  'stakeholders',
]);

const REQUIRED_TOPIC_FAMILIES = Object.freeze([
  'ae_sae_lessons_learned',
  'deviations',
  'feedback',
  'protocol_requirements',
  'quality_improvement_results',
  'regulatory_changes',
  'safety_governance_updates',
  'strategy_updates',
]);

const CHANNEL_TYPES = new Set(['email_gateway', 'in_app', 'task_queue', 'webhook']);
const DELIVERY_STATUSES = new Set(['acknowledged', 'delivered', 'dispatched']);
const SPONSOR_CRO_AUDIENCES = new Set(['cro', 'sponsors']);
const MATERIAL_TOPIC_FAMILIES = new Set(['ae_sae_lessons_learned', 'safety_governance_updates']);
const HUMAN_REVIEW_DECISIONS = new Set([
  'hold_for_stakeholder_communication_gap',
  'stakeholder_communications_accepted_inactive_trust',
]);

const RAW_COMMUNICATION_FIELDS = new Set([
  'body',
  'communicationbody',
  'communicationcontent',
  'communicationtext',
  'content',
  'directcommunication',
  'emailbody',
  'freetext',
  'freetextnote',
  'messagebody',
  'messagetext',
  'rawcommunication',
  'rawcommunicationbody',
  'rawcommunicationcontent',
  'rawmessage',
  'rawrequest',
  'rawsponsorrequest',
  'rawstakeholderfeedback',
  'sponsorconfidentialupdate',
  'subjecttext',
]);

const SECRET_COMMUNICATION_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credentialsecret',
  'password',
  'privatekey',
  'railwaytoken',
  'refreshtoken',
  'rootkey',
  'rootsigningkey',
  'secret',
  'sessionsecret',
  'signaturesecret',
  'signingkey',
  'token',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && value !== ZERO_HASH;
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function sensitiveValuePresent(value) {
  if (value === null || value === undefined || value === false) {
    return false;
  }
  if (typeof value === 'string') {
    return value.trim().length > 0;
  }
  if (Array.isArray(value)) {
    return value.some((item) => sensitiveValuePresent(item));
  }
  if (typeof value === 'object') {
    return Object.keys(value).length > 0;
  }
  return true;
}

function assertNoRawCommunicationContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawCommunicationContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_COMMUNICATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw stakeholder communication content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_COMMUNICATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`stakeholder communication secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawCommunicationContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawCommunicationContent(input ?? {});
  canonicalize(input ?? {});
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function evaluateRequiredSet(actual, required, missingPrefix, unsupportedPrefix, reasons) {
  for (const value of required) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !required.includes(value), `${unsupportedPrefix}:${value}`);
  }
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [hlc.physicalMs, hlc.logical];
}

function compareHlc(left, right) {
  if (left[0] !== right[0]) {
    return left[0] < right[0] ? -1 : 1;
  }
  if (left[1] !== right[1]) {
    return left[1] < right[1] ? -1 : 1;
  }
  return 0;
}

function hlcBefore(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) < 0;
}

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function hlcAfterOrEqual(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) >= 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'stakeholder_communication_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(policy, reasons) {
  const audienceClasses = sortedTextList(policy?.requiredAudienceClasses);
  const topicFamilies = sortedTextList(policy?.requiredTopicFamilies);
  const allowedChannelTypes = sortedTextList(policy?.allowedChannelTypes);

  addReason(reasons, !hasText(policy?.policyRef), 'communication_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'communication_policy_hash_invalid');
  addReason(reasons, policy?.status !== 'active', 'communication_policy_not_active');
  addReason(reasons, policy?.disclosureLogRequired !== true, 'communication_policy_disclosure_log_required');
  addReason(reasons, policy?.sponsorCroBoundaryRequired !== true, 'communication_policy_sponsor_cro_boundary_absent');
  addReason(reasons, policy?.participantIdentifiersExcluded !== true, 'communication_policy_participant_boundary_invalid');
  addReason(reasons, policy?.sponsorConfidentialExcluded !== true, 'communication_policy_sponsor_boundary_invalid');
  addReason(reasons, policy?.metadataOnly !== true, 'communication_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'communication_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'communication_policy_time_invalid');
  addReason(reasons, allowedChannelTypes.length === 0, 'communication_policy_channels_absent');

  evaluateRequiredSet(
    audienceClasses,
    REQUIRED_AUDIENCE_CLASSES,
    'policy_audience_class_missing',
    'policy_audience_class_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    topicFamilies,
    REQUIRED_TOPIC_FAMILIES,
    'policy_topic_family_missing',
    'policy_topic_family_unsupported',
    reasons,
  );
  for (const channelType of allowedChannelTypes) {
    addReason(reasons, !CHANNEL_TYPES.has(channelType), `policy_channel_type_unsupported:${channelType}`);
  }

  return { allowedChannelTypes, audienceClasses, topicFamilies };
}

function evaluatePlan(plan, policy, checkedAtHlc, reasons) {
  addReason(reasons, !hasText(plan?.planRef), 'communication_plan_ref_absent');
  addReason(reasons, !hasText(plan?.version), 'communication_plan_version_absent');
  addReason(reasons, plan?.status !== 'approved', 'communication_plan_not_approved');
  addReason(reasons, !isDigest(plan?.planHash), 'communication_plan_hash_invalid');
  addReason(reasons, !hasText(plan?.approvedByDid), 'communication_plan_approver_absent');
  addReason(reasons, plan?.reviewedByHuman !== true, 'communication_plan_human_review_absent');
  addReason(reasons, !isDigest(plan?.channelPolicyHash), 'communication_channel_policy_hash_invalid');
  addReason(reasons, !isDigest(plan?.escalationPathHash), 'communication_escalation_path_hash_invalid');
  addReason(reasons, plan?.metadataOnly !== true, 'communication_plan_metadata_boundary_invalid');
  addReason(reasons, plan?.protectedContentExcluded !== true, 'communication_plan_protected_boundary_invalid');
  addReason(reasons, hlcTuple(plan?.approvedAtHlc) === null, 'communication_plan_approval_time_invalid');
  addReason(reasons, hlcTuple(plan?.effectiveAtHlc) === null, 'communication_plan_effective_time_invalid');
  addReason(reasons, hlcTuple(plan?.nextReviewDueHlc) === null, 'communication_plan_next_review_time_invalid');
  addReason(reasons, hlcBefore(plan?.approvedAtHlc, policy?.evaluatedAtHlc), 'communication_plan_approved_before_policy');
  addReason(reasons, hlcBefore(plan?.effectiveAtHlc, plan?.approvedAtHlc), 'communication_plan_effective_before_approval');
  addReason(reasons, hlcAfter(plan?.approvedAtHlc, checkedAtHlc), 'communication_plan_approved_after_check');
  addReason(reasons, hlcBefore(plan?.nextReviewDueHlc, checkedAtHlc), 'communication_plan_review_overdue');
}

function evaluateDisclosureLog(log, policy, reasons) {
  addReason(reasons, !hasText(log?.logRef), 'disclosure_log_ref_absent');
  addReason(reasons, !isDigest(log?.logHash), 'disclosure_log_hash_invalid');
  addReason(reasons, hlcTuple(log?.recordedAtHlc) === null, 'disclosure_log_time_invalid');
  addReason(reasons, !hasText(log?.purpose), 'disclosure_log_purpose_absent');
  addReason(reasons, log?.includesRawContent !== false, 'disclosure_log_raw_content_forbidden');
  addReason(reasons, log?.metadataOnly !== true, 'disclosure_log_metadata_boundary_invalid');
  addReason(reasons, hlcBefore(log?.recordedAtHlc, policy?.evaluatedAtHlc), 'disclosure_log_before_policy');
}

function evaluateChannels(input, policyAllowedChannelTypes, reasons) {
  const channels = Array.isArray(input?.channels) ? [...input.channels] : [];
  addReason(reasons, channels.length === 0, 'communication_channels_absent');
  const byRef = new Map();

  for (const channel of channels) {
    const channelRef = hasText(channel?.channelRef) ? channel.channelRef : 'unknown';
    addReason(reasons, !hasText(channel?.channelRef), 'channel_ref_absent');
    addReason(reasons, byRef.has(channelRef), `channel_duplicate:${channelRef}`);
    addReason(reasons, !CHANNEL_TYPES.has(channel?.channelType), `channel_type_invalid:${channelRef}`);
    addReason(
      reasons,
      CHANNEL_TYPES.has(channel?.channelType) &&
        policyAllowedChannelTypes.length > 0 &&
        !policyAllowedChannelTypes.includes(channel.channelType),
      `channel_type_not_allowed:${channelRef}`,
    );
    addReason(reasons, channel?.active !== true, `channel_inactive:${channelRef}`);
    addReason(reasons, !isDigest(channel?.providerEvidenceHash), `channel_provider_evidence_invalid:${channelRef}`);
    addReason(reasons, channel?.metadataOnly !== true, `channel_metadata_boundary_invalid:${channelRef}`);
    addReason(reasons, channel?.rawAddressStored !== false, `channel_raw_address_forbidden:${channelRef}`);
    if (hasText(channel?.channelRef)) {
      byRef.set(channel.channelRef, channel);
    }
  }

  return byRef;
}

function evaluateAudienceRegistry(input, channelsByRef, reasons) {
  const audiences = Array.isArray(input?.audienceRegistry) ? [...input.audienceRegistry] : [];
  addReason(reasons, audiences.length === 0, 'audience_registry_absent');
  const byRef = new Map();

  for (const audience of audiences) {
    const audienceRef = hasText(audience?.audienceRef) ? audience.audienceRef : 'unknown';
    const channelRefs = sortedTextList(audience?.authorizedChannelRefs);
    addReason(reasons, !hasText(audience?.audienceRef), 'audience_ref_absent');
    addReason(reasons, byRef.has(audienceRef), `audience_duplicate:${audienceRef}`);
    addReason(reasons, !REQUIRED_AUDIENCE_CLASSES.includes(audience?.audienceClass), `audience_class_invalid:${audienceRef}`);
    addReason(reasons, sortedTextList(audience?.roleRefs).length === 0, `audience_roles_absent:${audienceRef}`);
    addReason(reasons, channelRefs.length === 0, `audience_channels_absent:${audienceRef}`);
    addReason(reasons, audience?.verifiedRecipientGroup !== true, `audience_recipient_group_unverified:${audienceRef}`);
    addReason(reasons, audience?.active !== true, `audience_inactive:${audienceRef}`);
    addReason(reasons, !isDigest(audience?.accessPolicyHash), `audience_access_policy_hash_invalid:${audienceRef}`);
    addReason(reasons, audience?.metadataOnly !== true, `audience_metadata_boundary_invalid:${audienceRef}`);
    addReason(reasons, audience?.rawAddressStored !== false, `audience_raw_address_forbidden:${audienceRef}`);
    addReason(reasons, audience?.protectedContentExcluded !== true, `audience_protected_boundary_invalid:${audienceRef}`);
    if (SPONSOR_CRO_AUDIENCES.has(audience?.audienceClass)) {
      addReason(reasons, !isDigest(audience?.sponsorCroScopeHash), `sponsor_cro_scope_hash_invalid:${audienceRef}`);
    }
    for (const channelRef of channelRefs) {
      addReason(reasons, !channelsByRef.has(channelRef), `audience_channel_unknown:${audienceRef}:${channelRef}`);
    }
    if (hasText(audience?.audienceRef)) {
      byRef.set(audience.audienceRef, audience);
    }
  }

  return byRef;
}

function audienceClassesFromRegistry(audiencesByRef) {
  return uniqueSorted([...audiencesByRef.values()].map((audience) => audience.audienceClass));
}

function itemIsMaterial(item) {
  return (
    item?.escalationRequired === true ||
    MATERIAL_TOPIC_FAMILIES.has(item?.topicFamily) ||
    sortedTextList(item?.sensitivityTags).includes('sponsor_confidential_metadata')
  );
}

function evaluateCommunicationItem(item, policyTopicFamilies, policyAudienceClasses, channelsByRef, reasons) {
  const itemRef = hasText(item?.itemRef) ? item.itemRef : 'unknown';
  const audienceClasses = sortedTextList(item?.audienceClasses);
  const channelRefs = sortedTextList(item?.channelRefs);
  const sensitivityTags = sortedTextList(item?.sensitivityTags);

  addReason(reasons, !hasText(item?.itemRef), 'communication_item_ref_absent');
  addReason(reasons, !REQUIRED_TOPIC_FAMILIES.includes(item?.topicFamily), `communication_topic_invalid:${itemRef}`);
  addReason(
    reasons,
    REQUIRED_TOPIC_FAMILIES.includes(item?.topicFamily) &&
      policyTopicFamilies.length > 0 &&
      !policyTopicFamilies.includes(item.topicFamily),
    `communication_topic_not_allowed:${itemRef}`,
  );
  addReason(reasons, audienceClasses.length === 0, `communication_item_audiences_absent:${itemRef}`);
  for (const audienceClass of audienceClasses) {
    addReason(reasons, !REQUIRED_AUDIENCE_CLASSES.includes(audienceClass), `communication_audience_class_invalid:${itemRef}:${audienceClass}`);
    addReason(
      reasons,
      REQUIRED_AUDIENCE_CLASSES.includes(audienceClass) &&
        policyAudienceClasses.length > 0 &&
        !policyAudienceClasses.includes(audienceClass),
      `communication_audience_class_not_allowed:${itemRef}:${audienceClass}`,
    );
  }
  addReason(reasons, channelRefs.length === 0, `communication_item_channels_absent:${itemRef}`);
  for (const channelRef of channelRefs) {
    addReason(reasons, !channelsByRef.has(channelRef), `communication_item_channel_unknown:${itemRef}:${channelRef}`);
  }
  addReason(reasons, !isDigest(item?.artifactHash), `communication_item_artifact_hash_invalid:${itemRef}`);
  addReason(reasons, !isDigest(item?.custodyDigest), `communication_item_custody_digest_invalid:${itemRef}`);
  addReason(reasons, !isDigest(item?.templateHash), `communication_item_template_hash_invalid:${itemRef}`);
  addReason(reasons, !isDigest(item?.payloadHash), `communication_item_payload_hash_invalid:${itemRef}`);
  addReason(reasons, sensitivityTags.length === 0, `communication_item_sensitivity_tags_absent:${itemRef}`);
  addReason(reasons, sensitivityTags.length > 0 && !sensitivityTags.includes('metadata_only'), `communication_item_metadata_tag_absent:${itemRef}`);
  addReason(reasons, hlcTuple(item?.scheduledAtHlc) === null, `communication_item_schedule_time_invalid:${itemRef}`);
  addReason(reasons, item?.metadataOnly !== true, `communication_item_metadata_boundary_invalid:${itemRef}`);
  addReason(reasons, item?.protectedContentExcluded !== true, `communication_item_protected_boundary_invalid:${itemRef}`);
  addReason(reasons, item?.productionTrustClaim === true, `communication_item_production_trust_claim_forbidden:${itemRef}`);

  if (itemIsMaterial(item)) {
    addReason(reasons, item?.escalationRequired !== true, `material_communication_escalation_absent:${itemRef}`);
    addReason(reasons, !hasText(item?.decisionForumMatterRef), `material_communication_decision_forum_absent:${itemRef}`);
    addReason(reasons, !isDigest(item?.humanReviewEvidenceHash), `material_communication_human_review_absent:${itemRef}`);
  }
}

function normalizeCommunicationItems(input, policyTopicFamilies, policyAudienceClasses, channelsByRef, reasons) {
  const items = Array.isArray(input?.communicationItems) ? [...input.communicationItems] : [];
  addReason(reasons, items.length === 0, 'communication_items_absent');
  for (const item of items) {
    evaluateCommunicationItem(item, policyTopicFamilies, policyAudienceClasses, channelsByRef, reasons);
  }
  return items.sort((left, right) => String(left?.itemRef).localeCompare(String(right?.itemRef)));
}

function deliveryKey(delivery) {
  return `${delivery?.itemRef ?? ''}:${delivery?.audienceRef ?? ''}:${delivery?.channelRef ?? ''}`;
}

function normalizeDelivery(delivery) {
  return {
    acknowledgementEvidenceHash: delivery?.acknowledgementEvidenceHash ?? null,
    acknowledgementRequired: delivery?.acknowledgementRequired === true,
    acknowledgedAtHlc: delivery?.acknowledgedAtHlc ?? null,
    audienceRef: delivery?.audienceRef ?? null,
    channelRef: delivery?.channelRef ?? null,
    deliveredAtHlc: delivery?.deliveredAtHlc ?? null,
    deliveryEvidenceHash: delivery?.deliveryEvidenceHash ?? null,
    disclosureEventHash: delivery?.disclosureEventHash ?? null,
    disclosureEventRef: delivery?.disclosureEventRef ?? null,
    itemRef: delivery?.itemRef ?? null,
    status: delivery?.status ?? null,
  };
}

function validateDelivery(delivery, itemByRef, audienceByRef, channelsByRef, reasons) {
  const itemRef = hasText(delivery?.itemRef) ? delivery.itemRef : 'unknown';
  const audienceRef = hasText(delivery?.audienceRef) ? delivery.audienceRef : 'unknown';
  const reasonSuffix = `${itemRef}:${audienceRef}`;
  const item = itemByRef.get(itemRef);
  const audience = audienceByRef.get(audienceRef);

  addReason(reasons, !hasText(delivery?.itemRef), 'delivery_item_ref_absent');
  addReason(reasons, !hasText(delivery?.audienceRef), `delivery_audience_ref_absent:${itemRef}`);
  addReason(reasons, !hasText(delivery?.channelRef), `delivery_channel_ref_absent:${reasonSuffix}`);
  addReason(reasons, !itemByRef.has(itemRef), `delivery_item_unknown:${itemRef}`);
  addReason(reasons, !audienceByRef.has(audienceRef), `delivery_audience_unknown:${reasonSuffix}`);
  addReason(reasons, !channelsByRef.has(delivery?.channelRef), `delivery_channel_unknown:${reasonSuffix}`);
  addReason(reasons, !DELIVERY_STATUSES.has(delivery?.status), `delivery_status_invalid:${reasonSuffix}`);
  addReason(reasons, hlcTuple(delivery?.deliveredAtHlc) === null, `delivery_time_invalid:${reasonSuffix}`);
  addReason(reasons, !isDigest(delivery?.deliveryEvidenceHash), `delivery_evidence_hash_invalid:${reasonSuffix}`);
  addReason(reasons, !hasText(delivery?.disclosureEventRef), `delivery_disclosure_ref_absent:${reasonSuffix}`);
  addReason(reasons, !isDigest(delivery?.disclosureEventHash), `delivery_disclosure_hash_invalid:${reasonSuffix}`);

  if (item !== undefined) {
    addReason(reasons, hlcBefore(delivery?.deliveredAtHlc, item.scheduledAtHlc), `delivery_before_item_scheduled:${reasonSuffix}`);
    addReason(
      reasons,
      audience !== undefined && !sortedTextList(item.audienceClasses).includes(audience.audienceClass),
      `delivery_audience_not_required:${reasonSuffix}`,
    );
    addReason(reasons, !sortedTextList(item.channelRefs).includes(delivery?.channelRef), `delivery_channel_not_planned:${reasonSuffix}`);
  }
  if (audience !== undefined) {
    addReason(
      reasons,
      !sortedTextList(audience.authorizedChannelRefs).includes(delivery?.channelRef),
      `delivery_channel_not_authorized:${reasonSuffix}`,
    );
  }
  if (item !== undefined && itemIsMaterial(item)) {
    addReason(reasons, delivery?.acknowledgementRequired !== true, `material_delivery_acknowledgement_required:${reasonSuffix}`);
  }
  if (delivery?.acknowledgementRequired === true) {
    addReason(reasons, !isDigest(delivery?.acknowledgementEvidenceHash), `acknowledgement_evidence_hash_invalid:${reasonSuffix}`);
    addReason(reasons, hlcTuple(delivery?.acknowledgedAtHlc) === null, `acknowledgement_time_invalid:${reasonSuffix}`);
    addReason(
      reasons,
      !hlcAfterOrEqual(delivery?.acknowledgedAtHlc, delivery?.deliveredAtHlc),
      `acknowledgement_before_delivery:${reasonSuffix}`,
    );
  }
}

function itemDeliveredToAudience(item, audienceClass, deliveries, audienceByRef) {
  return deliveries.some((delivery) => {
    const audience = audienceByRef.get(delivery.audienceRef);
    return (
      delivery.itemRef === item.itemRef &&
      DELIVERY_STATUSES.has(delivery.status) &&
      audience?.audienceClass === audienceClass
    );
  });
}

function normalizeDeliveries(input, items, audienceByRef, channelsByRef, reasons) {
  const deliveries = Array.isArray(input?.deliveryEvidence) ? [...input.deliveryEvidence].sort((left, right) => deliveryKey(left).localeCompare(deliveryKey(right))) : [];
  addReason(reasons, deliveries.length === 0, 'delivery_evidence_absent');
  const itemByRef = new Map(items.filter((item) => hasText(item?.itemRef)).map((item) => [item.itemRef, item]));
  for (const delivery of deliveries) {
    validateDelivery(delivery, itemByRef, audienceByRef, channelsByRef, reasons);
  }
  for (const item of items) {
    for (const audienceClass of sortedTextList(item?.audienceClasses)) {
      addReason(reasons, !itemDeliveredToAudience(item, audienceClass, deliveries, audienceByRef), `communication_delivery_missing:${item.itemRef}:${audienceClass}`);
    }
  }
  return deliveries.map(normalizeDelivery);
}

function evaluatePacketCoverage(audienceByRef, items, reasons) {
  const audienceClasses = audienceClassesFromRegistry(audienceByRef);
  const topicFamilies = uniqueSorted(items.map((item) => item.topicFamily));
  evaluateRequiredSet(audienceClasses, REQUIRED_AUDIENCE_CLASSES, 'packet_audience_class_missing', 'packet_audience_class_unsupported', reasons);
  evaluateRequiredSet(topicFamilies, REQUIRED_TOPIC_FAMILIES, 'packet_topic_family_missing', 'packet_topic_family_unsupported', reasons);
  return { audienceClasses, topicFamilies };
}

function evaluateHumanReview(input, checkedAtHlc, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, input?.disclosureLog?.recordedAtHlc), 'human_review_before_disclosure_log');
  addReason(reasons, hlcAfter(review?.reviewedAtHlc, checkedAtHlc), 'human_review_after_check');
  addReason(reasons, !isDigest(review?.reviewEvidenceHash), 'human_review_evidence_hash_invalid');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
}

function deliveryRefsForItem(itemRef, deliveries) {
  return deliveries
    .filter((delivery) => delivery.itemRef === itemRef)
    .map((delivery) =>
      sha256Hex({
        audienceRef: delivery.audienceRef,
        channelRef: delivery.channelRef,
        deliveryEvidenceHash: delivery.deliveryEvidenceHash,
        itemRef: delivery.itemRef,
      }),
    )
    .sort();
}

function buildMessages(items, deliveries) {
  return items.map((item) => ({
    audienceClasses: sortedTextList(item.audienceClasses),
    deliveryRefs: deliveryRefsForItem(item.itemRef, deliveries),
    itemRef: item.itemRef,
    scheduledAtHlc: item.scheduledAtHlc,
    sensitivityTags: sortedTextList(item.sensitivityTags),
    topicFamily: item.topicFamily,
  }));
}

function buildPacket(input, audienceClasses, topicFamilies, items, deliveries, messages) {
  const evidenceHashes = uniqueSorted([
    input.communicationPolicy.policyHash,
    input.communicationPlan.planHash,
    input.communicationPlan.channelPolicyHash,
    input.communicationPlan.escalationPathHash,
    input.disclosureLog.logHash,
    input.humanReview.reviewEvidenceHash,
    ...[...input.audienceRegistry].map((audience) => audience.accessPolicyHash),
    ...items.map((item) => item.artifactHash),
    ...items.map((item) => item.custodyDigest),
    ...items.map((item) => item.payloadHash),
    ...deliveries.map((delivery) => delivery.deliveryEvidenceHash),
    ...deliveries.map((delivery) => delivery.disclosureEventHash),
    ...deliveries.map((delivery) => delivery.acknowledgementEvidenceHash).filter(isDigest),
  ]);
  const messageDigest = sha256Hex(messages);
  const deliveryDigest = sha256Hex(deliveries);
  const evidenceHashDigest = sha256Hex(evidenceHashes);

  return {
    schema: 'cybermedica.stakeholder_communications_packet.v1',
    tenantId: input.tenantId,
    policyRef: input.communicationPolicy.policyRef,
    communicationPlanRef: input.communicationPlan.planRef,
    disclosureLogRef: input.disclosureLog.logRef,
    audienceClasses,
    topicFamilies,
    itemCount: items.length,
    deliveryCount: deliveries.length,
    materialItemCount: items.filter(itemIsMaterial).length,
    packetId: `cmcomm_${sha256Hex({
      audienceClasses,
      deliveryDigest,
      evidenceHashDigest,
      messageDigest,
      policyRef: input.communicationPolicy.policyRef,
      topicFamilies,
    }).slice(0, 32)}`,
    messageDigest,
    deliveryDigest,
    evidenceHashDigest,
    metadataOnly: true,
    immutableCommunicationReceipt: true,
    operationalStateMutable: true,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function buildReceipt(input, packet) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'stakeholder_communications_packet',
    artifactVersion: `${packet.packetId}@${input.disclosureLog.recordedAtHlc.physicalMs}.${input.disclosureLog.recordedAtHlc.logical}`,
    artifactHash: sha256Hex({
      deliveryDigest: packet.deliveryDigest,
      evidenceHashDigest: packet.evidenceHashDigest,
      messageDigest: packet.messageDigest,
      packetId: packet.packetId,
    }),
    classification: 'stakeholder_communication_metadata_only',
    hlcTimestamp: input.disclosureLog.recordedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['metadata_only', 'policy_6_communications', 'qms'],
    sourceSystem: 'cybermedica.stakeholder_communications',
  });
}

export function evaluateStakeholderCommunications(input) {
  assertMetadataOnly(input);

  const reasons = [];
  const checkedAtHlc = hlcTuple(input?.humanReview?.reviewedAtHlc) === null ? input?.disclosureLog?.recordedAtHlc : input.humanReview.reviewedAtHlc;

  evaluateTenantActorAuthority(input, reasons);
  const { allowedChannelTypes, audienceClasses: policyAudienceClasses, topicFamilies: policyTopicFamilies } = evaluatePolicy(input?.communicationPolicy, reasons);
  evaluatePlan(input?.communicationPlan, input?.communicationPolicy, checkedAtHlc, reasons);
  evaluateDisclosureLog(input?.disclosureLog, input?.communicationPolicy, reasons);
  const channelsByRef = evaluateChannels(input, allowedChannelTypes, reasons);
  const audienceByRef = evaluateAudienceRegistry(input, channelsByRef, reasons);
  const items = normalizeCommunicationItems(input, policyTopicFamilies, policyAudienceClasses, channelsByRef, reasons);
  const deliveries = normalizeDeliveries(input, items, audienceByRef, channelsByRef, reasons);
  const { audienceClasses, topicFamilies } = evaluatePacketCoverage(audienceByRef, items, reasons);
  evaluateHumanReview(input, checkedAtHlc, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const normalizedReasons = uniqueReasons(reasons);
  if (normalizedReasons.length > 0) {
    return {
      schema: 'cybermedica.stakeholder_communications_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: normalizedReasons,
      communicationPacket: null,
      messages: [],
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const messages = buildMessages(items, deliveries);
  const communicationPacket = buildPacket(input, audienceClasses, topicFamilies, items, deliveries, messages);
  const receipt = buildReceipt(input, communicationPacket);
  communicationPacket.receiptId = receipt.receiptId;

  return {
    schema: 'cybermedica.stakeholder_communications_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    communicationPacket,
    messages,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
