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
const CATEGORY_SET = new Set(REQUIRED_CATEGORIES);
const CHANNEL_TYPES = new Set(['email_gateway', 'in_app', 'sms_gateway', 'task_queue', 'webhook']);
const DELIVERY_STATUSES = new Set(['acknowledged', 'delivered', 'dispatched']);
const SEVERITIES = new Set(['critical', 'major', 'standard', 'urgent', 'warning']);
const SOURCE_FAMILIES = new Set([
  'approvals',
  'capas',
  'decisions',
  'delegation',
  'escalations',
  'evidence',
  'findings',
  'quality_event',
  'risks',
  'training',
]);
const RAW_NOTIFICATION_FIELDS = new Set([
  'contactaddress',
  'emailbody',
  'emailtext',
  'messagebody',
  'messagetext',
  'notificationbody',
  'notificationmessage',
  'rawalert',
  'rawcontact',
  'rawmessage',
  'rawmessagebody',
  'rawnotification',
  'rawpayload',
  'recipientaddress',
  'subjecttext',
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

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function assertNoRawNotificationContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawNotificationContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    if (RAW_NOTIFICATION_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`raw notification content field is not allowed at ${path}.${key}`);
    }
    assertNoRawNotificationContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawNotificationContent(input ?? {});
  canonicalize(input ?? {});
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

function hlcAfterOrEqual(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) >= 0;
}

function intersects(left, right) {
  const rightSet = new Set(right);
  return left.some((value) => rightSet.has(value));
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
    !hasAuthorityPermission(input?.authority, 'notify') && !hasAuthorityPermission(input?.authority, 'govern'),
    'notification_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(input, reasons) {
  const policy = input?.policy;
  const categories = sortedTextList(policy?.categories);
  const allowedChannels = sortedTextList(policy?.allowedChannels);
  addReason(reasons, !hasText(policy?.policyRef), 'notification_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'notification_policy_hash_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'notification_policy_time_invalid');
  addReason(reasons, categories.length === 0, 'notification_policy_categories_absent');
  addReason(reasons, allowedChannels.length === 0, 'notification_policy_channels_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'notification_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.rawPayloadExcluded !== true, 'notification_policy_payload_boundary_invalid');
  addReason(reasons, policy?.participantIdentifiersExcluded !== true, 'notification_policy_identifier_boundary_invalid');
  addReason(reasons, policy?.disclosureLogRequired !== true, 'notification_policy_disclosure_log_required');

  for (const category of REQUIRED_CATEGORIES) {
    addReason(reasons, !categories.includes(category), `policy_category_missing:${category}`);
  }
  for (const category of categories) {
    addReason(reasons, !CATEGORY_SET.has(category), `policy_category_unsupported:${category}`);
  }
  for (const channelType of allowedChannels) {
    addReason(reasons, !CHANNEL_TYPES.has(channelType), `policy_channel_unsupported:${channelType}`);
  }

  return { allowedChannels, categories };
}

function evaluateDisclosureLog(input, reasons) {
  const log = input?.disclosureLog;
  addReason(reasons, !hasText(log?.logId), 'disclosure_log_id_absent');
  addReason(reasons, hlcTuple(log?.loggedAtHlc) === null, 'disclosure_log_time_invalid');
  addReason(reasons, !isDigest(log?.disclosureLogHash), 'disclosure_log_hash_invalid');
  addReason(reasons, log?.includesRawContent !== false, 'disclosure_log_raw_content_forbidden');
  addReason(reasons, !hasText(log?.purpose), 'disclosure_log_purpose_absent');
  addReason(reasons, hlcBefore(log?.loggedAtHlc, input?.policy?.evaluatedAtHlc), 'disclosure_log_before_policy');
}

function consentActive(consent) {
  if (consent?.required === false && consent?.status === 'not_required') {
    return true;
  }
  return consent?.status === 'active' && consent?.revoked !== true && hasText(consent?.consentRef);
}

function evaluateConsent(input, signals, reasons) {
  if (signals.some((signal) => signal?.participantLinked === true)) {
    addReason(reasons, !consentActive(input?.consent), 'participant_notification_consent_inactive');
  }
}

function evaluateChannels(input, allowedChannels, reasons) {
  const channels = Array.isArray(input?.channelRegistry) ? input.channelRegistry : [];
  addReason(reasons, channels.length === 0, 'channel_registry_absent');
  const byRef = new Map();
  for (const channel of channels) {
    const channelRef = hasText(channel?.channelRef) ? channel.channelRef : 'unknown';
    addReason(reasons, !hasText(channel?.channelRef), 'channel_ref_absent');
    addReason(reasons, byRef.has(channelRef), `channel_duplicate:${channelRef}`);
    addReason(reasons, !CHANNEL_TYPES.has(channel?.channelType), `channel_type_invalid:${channelRef}`);
    addReason(
      reasons,
      CHANNEL_TYPES.has(channel?.channelType) && allowedChannels.length > 0 && !allowedChannels.includes(channel.channelType),
      `channel_type_not_allowed:${channelRef}`,
    );
    addReason(reasons, channel?.enabled !== true, `channel_disabled:${channelRef}`);
    addReason(reasons, !isDigest(channel?.providerEvidenceHash), `channel_provider_evidence_invalid:${channelRef}`);
    addReason(reasons, channel?.metadataOnly !== true, `channel_metadata_boundary_invalid:${channelRef}`);
    addReason(reasons, channel?.rawAddressStored !== false, `channel_raw_address_forbidden:${channelRef}`);
    if (hasText(channel?.channelRef)) {
      byRef.set(channel.channelRef, channel);
    }
  }
  return byRef;
}

function evaluateRecipients(input, channelsByRef, reasons) {
  const recipients = Array.isArray(input?.recipients) ? input.recipients : [];
  addReason(reasons, recipients.length === 0, 'notification_recipients_absent');
  const byDid = new Map();
  for (const recipient of recipients) {
    const did = hasText(recipient?.did) ? recipient.did : 'unknown';
    const channelRefs = sortedTextList(recipient?.channelRefs);
    addReason(reasons, !hasText(recipient?.did), 'recipient_did_absent');
    addReason(reasons, byDid.has(did), `recipient_duplicate:${did}`);
    addReason(reasons, sortedTextList(recipient?.roleRefs).length === 0, `recipient_roles_absent:${did}`);
    addReason(reasons, sortedTextList(recipient?.siteRefs).length === 0, `recipient_sites_absent:${did}`);
    addReason(reasons, channelRefs.length === 0, `recipient_channels_absent:${did}`);
    addReason(reasons, recipient?.verifiedHuman !== true, `recipient_human_verification_absent:${did}`);
    addReason(reasons, recipient?.active !== true, `recipient_inactive:${did}`);
    addReason(reasons, recipient?.notificationOptOut === true, `recipient_opted_out:${did}`);
    for (const channelRef of channelRefs) {
      addReason(reasons, !channelsByRef.has(channelRef), `recipient_channel_unknown:${did}:${channelRef}`);
    }
    if (hasText(recipient?.did)) {
      byDid.set(recipient.did, recipient);
    }
  }
  return byDid;
}

function criticalRequiredRoles(signal) {
  const roles = ['decision_forum', 'quality_manager'];
  if (signal?.category === 'critical_risk') {
    roles.push('principal_investigator');
  }
  return roles.sort();
}

function isCriticalSignal(signal) {
  return signal?.category === 'critical_risk' || signal?.category === 'escalation' || signal?.severity === 'critical';
}

function evaluateSignal(signal, policyCategories, reasons) {
  const signalRef = hasText(signal?.signalRef) ? signal.signalRef : 'unknown';
  const recipientRoles = sortedTextList(signal?.requiredRecipientRoles);
  addReason(reasons, !hasText(signal?.signalRef), 'signal_ref_absent');
  addReason(reasons, !CATEGORY_SET.has(signal?.category), `signal_category_invalid:${signalRef}`);
  addReason(
    reasons,
    CATEGORY_SET.has(signal?.category) && policyCategories.length > 0 && !policyCategories.includes(signal.category),
    `signal_category_not_allowed:${signalRef}`,
  );
  addReason(reasons, !SEVERITIES.has(signal?.severity), `signal_severity_invalid:${signalRef}`);
  addReason(reasons, !SOURCE_FAMILIES.has(signal?.sourceObjectFamily), `signal_source_family_invalid:${signalRef}`);
  addReason(reasons, !hasText(signal?.sourceObjectRef), `signal_source_ref_absent:${signalRef}`);
  addReason(reasons, !isDigest(signal?.sourceArtifactHash), `signal_artifact_hash_invalid:${signalRef}`);
  addReason(reasons, !isDigest(signal?.sourceCustodyDigest), `signal_custody_digest_invalid:${signalRef}`);
  addReason(reasons, !isDigest(signal?.titleHash), `signal_title_hash_invalid:${signalRef}`);
  addReason(reasons, sortedTextList(signal?.siteRefs).length === 0, `signal_site_refs_absent:${signalRef}`);
  addReason(reasons, sortedTextList(signal?.sensitivityTags).length === 0, `signal_sensitivity_tags_absent:${signalRef}`);
  addReason(
    reasons,
    sortedTextList(signal?.sensitivityTags).length > 0 && !sortedTextList(signal.sensitivityTags).includes('metadata_only'),
    `signal_metadata_tag_absent:${signalRef}`,
  );
  addReason(reasons, recipientRoles.length === 0, `signal_recipient_roles_absent:${signalRef}`);
  addReason(reasons, !isDigest(signal?.templateHash), `signal_template_hash_invalid:${signalRef}`);
  addReason(reasons, !isDigest(signal?.payloadHash), `signal_payload_hash_invalid:${signalRef}`);
  addReason(reasons, hlcTuple(signal?.detectedAtHlc) === null, `signal_detected_time_invalid:${signalRef}`);
  addReason(reasons, hlcTuple(signal?.scheduledAtHlc) === null, `signal_scheduled_time_invalid:${signalRef}`);
  addReason(reasons, hlcBefore(signal?.scheduledAtHlc, signal?.detectedAtHlc), `signal_scheduled_before_detected:${signalRef}`);
  addReason(reasons, hlcBefore(signal?.scheduledAtHlc, signal?.policyEvaluatedAtHlc), `signal_scheduled_before_policy:${signalRef}`);

  if (signal?.category === 'due_date') {
    addReason(reasons, hlcTuple(signal?.dueAtHlc) === null, `signal_due_time_invalid:${signalRef}`);
    addReason(reasons, hlcBefore(signal?.dueAtHlc, signal?.detectedAtHlc), `signal_due_before_detected:${signalRef}`);
  }
  if (signal?.category === 'expiration') {
    addReason(reasons, hlcTuple(signal?.expiresAtHlc) === null, `signal_expiration_time_invalid:${signalRef}`);
    addReason(reasons, hlcBefore(signal?.expiresAtHlc, signal?.detectedAtHlc), `signal_expiration_before_detected:${signalRef}`);
  }

  if (isCriticalSignal(signal)) {
    addReason(reasons, signal?.escalationRequired !== true, `critical_signal_escalation_required:${signalRef}`);
    addReason(reasons, !hasText(signal?.decisionForumRef), `critical_signal_decision_forum_absent:${signalRef}`);
    addReason(reasons, !isDigest(signal?.humanReviewEvidenceHash), `critical_signal_human_review_absent:${signalRef}`);
    for (const role of criticalRequiredRoles(signal)) {
      addReason(reasons, !recipientRoles.includes(role), `critical_signal_role_missing:${signalRef}:${role}`);
    }
  }
}

function normalizeSignals(input, policyCategories, reasons) {
  const signals = Array.isArray(input?.signals) ? [...input.signals] : [];
  addReason(reasons, signals.length === 0, 'notification_signals_absent');
  for (const signal of signals) {
    evaluateSignal({ ...signal, policyEvaluatedAtHlc: input?.policy?.evaluatedAtHlc }, policyCategories, reasons);
  }
  return signals.sort((left, right) => String(left?.signalRef).localeCompare(String(right?.signalRef)));
}

function deliverySort(left, right) {
  const leftKey = `${left.signalRef}:${left.recipientDid}:${left.channelRef}`;
  const rightKey = `${right.signalRef}:${right.recipientDid}:${right.channelRef}`;
  return leftKey.localeCompare(rightKey);
}

function normalizeDeliveryAttempt(delivery) {
  return {
    acknowledgementEvidenceHash: delivery?.acknowledgementEvidenceHash ?? null,
    acknowledgementRequired: delivery?.acknowledgementRequired === true,
    acknowledgedAtHlc: delivery?.acknowledgedAtHlc ?? null,
    channelRef: delivery?.channelRef ?? null,
    deliveryEvidenceHash: delivery?.deliveryEvidenceHash ?? null,
    dispatchedAtHlc: delivery?.dispatchedAtHlc ?? null,
    recipientDid: delivery?.recipientDid ?? null,
    signalRef: delivery?.signalRef ?? null,
    status: delivery?.status ?? null,
  };
}

function validateDelivery(delivery, signalsByRef, recipientsByDid, channelsByRef, reasons) {
  const signalRef = hasText(delivery?.signalRef) ? delivery.signalRef : 'unknown';
  const recipientDid = hasText(delivery?.recipientDid) ? delivery.recipientDid : 'unknown';
  const reasonSuffix = `${signalRef}:${recipientDid}`;
  const signal = signalsByRef.get(signalRef);
  const recipient = recipientsByDid.get(recipientDid);

  addReason(reasons, !hasText(delivery?.signalRef), 'delivery_signal_ref_absent');
  addReason(reasons, !hasText(delivery?.recipientDid), `delivery_recipient_absent:${signalRef}`);
  addReason(reasons, !hasText(delivery?.channelRef), `delivery_channel_absent:${reasonSuffix}`);
  addReason(reasons, !signalsByRef.has(signalRef), `delivery_signal_unknown:${signalRef}`);
  addReason(reasons, !recipientsByDid.has(recipientDid), `delivery_recipient_unknown:${reasonSuffix}`);
  addReason(reasons, !channelsByRef.has(delivery?.channelRef), `delivery_channel_unknown:${reasonSuffix}`);
  addReason(reasons, !DELIVERY_STATUSES.has(delivery?.status), `delivery_status_invalid:${reasonSuffix}`);
  addReason(reasons, !isDigest(delivery?.deliveryEvidenceHash), `delivery_evidence_hash_invalid:${reasonSuffix}`);
  addReason(reasons, hlcTuple(delivery?.dispatchedAtHlc) === null, `delivery_time_invalid:${reasonSuffix}`);
  addReason(
    reasons,
    signal !== undefined && hlcBefore(delivery?.dispatchedAtHlc, signal.scheduledAtHlc),
    `delivery_before_signal_scheduled:${reasonSuffix}`,
  );
  if (recipient !== undefined && hasText(delivery?.channelRef)) {
    addReason(
      reasons,
      !sortedTextList(recipient.channelRefs).includes(delivery.channelRef),
      `delivery_channel_not_authorized:${reasonSuffix}`,
    );
  }
  if (signal !== undefined && recipient !== undefined) {
    addReason(
      reasons,
      !intersects(sortedTextList(recipient.roleRefs), sortedTextList(signal.requiredRecipientRoles)),
      `delivery_recipient_role_not_required:${reasonSuffix}`,
    );
    addReason(
      reasons,
      !intersects(sortedTextList(recipient.siteRefs), sortedTextList(signal.siteRefs)),
      `delivery_recipient_site_not_allowed:${reasonSuffix}`,
    );
  }

  if (signal !== undefined && isCriticalSignal(signal)) {
    addReason(reasons, delivery?.acknowledgementRequired !== true, `critical_delivery_acknowledgement_required:${reasonSuffix}`);
  }
  if (delivery?.acknowledgementRequired === true) {
    addReason(reasons, !isDigest(delivery?.acknowledgementEvidenceHash), `acknowledgement_evidence_hash_invalid:${reasonSuffix}`);
    addReason(reasons, hlcTuple(delivery?.acknowledgedAtHlc) === null, `acknowledgement_time_invalid:${reasonSuffix}`);
    addReason(
      reasons,
      !hlcAfterOrEqual(delivery?.acknowledgedAtHlc, delivery?.dispatchedAtHlc),
      `acknowledgement_before_delivery:${reasonSuffix}`,
    );
  }
}

function signalHasDeliveredRole(signal, role, deliveries, recipientsByDid) {
  return deliveries.some((delivery) => {
    const recipient = recipientsByDid.get(delivery.recipientDid);
    return (
      delivery.signalRef === signal.signalRef &&
      DELIVERY_STATUSES.has(delivery.status) &&
      recipient !== undefined &&
      sortedTextList(recipient.roleRefs).includes(role) &&
      intersects(sortedTextList(recipient.siteRefs), sortedTextList(signal.siteRefs))
    );
  });
}

function evaluateDeliveries(input, signals, recipientsByDid, channelsByRef, reasons) {
  const deliveries = Array.isArray(input?.deliveryAttempts) ? [...input.deliveryAttempts].sort(deliverySort) : [];
  addReason(reasons, deliveries.length === 0, 'delivery_attempts_absent');
  const signalsByRef = new Map(signals.filter((signal) => hasText(signal?.signalRef)).map((signal) => [signal.signalRef, signal]));
  for (const delivery of deliveries) {
    validateDelivery(delivery, signalsByRef, recipientsByDid, channelsByRef, reasons);
  }
  for (const signal of signals) {
    const requiredRoles = isCriticalSignal(signal)
      ? uniqueSorted([...sortedTextList(signal?.requiredRecipientRoles), ...criticalRequiredRoles(signal)])
      : sortedTextList(signal?.requiredRecipientRoles);
    for (const role of requiredRoles) {
      addReason(reasons, !signalHasDeliveredRole(signal, role, deliveries, recipientsByDid), `signal_delivery_missing:${signal.signalRef}:${role}`);
    }
  }
  return deliveries.map(normalizeDeliveryAttempt);
}

function deliveryRefsForSignal(signalRef, deliveries) {
  return deliveries
    .filter((delivery) => delivery.signalRef === signalRef)
    .map((delivery) =>
      sha256Hex({
        channelRef: delivery.channelRef,
        deliveryEvidenceHash: delivery.deliveryEvidenceHash,
        recipientDid: delivery.recipientDid,
        signalRef: delivery.signalRef,
      }),
    )
    .sort();
}

function buildAlerts(signals, deliveries) {
  return signals.map((signal) => ({
    category: signal.category,
    deliveryRefs: deliveryRefsForSignal(signal.signalRef, deliveries),
    dueAtHlc: signal.dueAtHlc ?? null,
    expiresAtHlc: signal.expiresAtHlc ?? null,
    recipientRoles: sortedTextList(signal.requiredRecipientRoles),
    severity: signal.severity,
    signalRef: signal.signalRef,
    siteRefs: sortedTextList(signal.siteRefs),
    sourceArtifactHash: signal.sourceArtifactHash,
    sourceObjectFamily: signal.sourceObjectFamily,
    sourceObjectRef: signal.sourceObjectRef,
  }));
}

function buildNotificationRun(input, signals, deliveries, alerts) {
  const criticalSignals = signals.filter(isCriticalSignal);
  const categoriesCovered = uniqueSorted(signals.map((signal) => signal.category));
  const escalationRoles = uniqueSorted(criticalSignals.flatMap((signal) => sortedTextList(signal.requiredRecipientRoles)));
  const evidenceHashes = uniqueSorted([
    input.policy.policyHash,
    input.disclosureLog.disclosureLogHash,
    ...signals.map((signal) => signal.sourceArtifactHash),
    ...signals.map((signal) => signal.sourceCustodyDigest),
    ...deliveries.map((delivery) => delivery.deliveryEvidenceHash),
    ...deliveries.map((delivery) => delivery.acknowledgementEvidenceHash).filter(isDigest),
  ]);

  return {
    schema: 'cybermedica.notifications_alerts_run.v1',
    tenantId: input.tenantId,
    policyRef: input.policy.policyRef,
    categoriesCovered,
    signalCount: signals.length,
    deliveryCount: deliveries.length,
    acknowledgementRequiredCount: deliveries.filter((delivery) => delivery.acknowledgementRequired === true).length,
    criticalSignalCount: criticalSignals.length,
    escalationRoles,
    siteRefs: uniqueSorted(signals.flatMap((signal) => sortedTextList(signal.siteRefs))),
    alertDigest: sha256Hex(alerts),
    deliveryDigest: sha256Hex(deliveries),
    evidenceHashDigest: sha256Hex(evidenceHashes),
    disclosureLogRef: input.disclosureLog.logId,
    loggedAtHlc: input.disclosureLog.loggedAtHlc,
    metadataOnly: true,
    immutableNotificationReceipt: true,
    operationalStateMutable: true,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function buildReceipt(input, notificationRun) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'notifications_alerts_run',
    artifactVersion: `${input.policy.policyRef}@${input.disclosureLog.loggedAtHlc.physicalMs}.${input.disclosureLog.loggedAtHlc.logical}`,
    artifactHash: sha256Hex({
      alertDigest: notificationRun.alertDigest,
      deliveryDigest: notificationRun.deliveryDigest,
      disclosureLogHash: input.disclosureLog.disclosureLogHash,
      policyHash: input.policy.policyHash,
    }),
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.disclosureLog.loggedAtHlc,
    custodyDigest: input.disclosureLog.disclosureLogHash,
    sensitivityTags: ['metadata_only', 'notifications', 'qms_alerts'],
    sourceSystem: 'cybermedica-qms',
  });
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

export function evaluateNotificationsAlerts(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const { allowedChannels, categories } = evaluatePolicy(input, reasons);
  evaluateDisclosureLog(input, reasons);
  const channelsByRef = evaluateChannels(input, allowedChannels, reasons);
  const recipientsByDid = evaluateRecipients(input, channelsByRef, reasons);
  const signals = normalizeSignals(input, categories, reasons);
  evaluateConsent(input, signals, reasons);
  const deliveries = evaluateDeliveries(input, signals, recipientsByDid, channelsByRef, reasons);
  const alerts = buildAlerts(signals, deliveries);
  const normalizedReasons = uniqueReasons(reasons);

  if (normalizedReasons.length > 0) {
    return {
      schema: 'cybermedica.notifications_alerts_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: normalizedReasons,
      notificationRun: null,
      alerts: [],
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const notificationRun = buildNotificationRun(input, signals, deliveries, alerts);
  const receipt = buildReceipt(input, notificationRun);
  notificationRun.receiptId = receipt.receiptId;

  return {
    schema: 'cybermedica.notifications_alerts_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    notificationRun,
    alerts,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
