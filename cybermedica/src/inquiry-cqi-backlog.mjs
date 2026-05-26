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
const INQUIRY_CQI_SCHEMA = 'cybermedica.inquiry_cqi_backlog.v1';
const REQUIRED_PERMISSION = 'cqi_triage';
const ACTIVE_POLICY_STATUSES = new Set(['active']);
const HUMAN_DECISIONS = new Set(['cqi_backlog_ready', 'hold_for_cqi_gap']);
const SIGNAL_SEVERITIES = new Set(['critical', 'major', 'minor', 'observation']);
const BACKLOG_PRIORITIES = new Set(['critical', 'high', 'standard', 'low']);
const TRIAGE_DISPOSITIONS = new Set([
  'draft_documentation_update',
  'hold_for_high_risk_review',
  'open_for_cqi',
  'route_to_drift',
]);

const REQUIRED_SOURCE_FAMILIES = Object.freeze([
  'accessibility_barrier',
  'ai_orientation_question',
  'manual_confusion',
  'missing_documentation',
  'product_gap',
  'repeated_inquiry',
  'search_zero_result',
  'workflow_exit',
]);

const REQUIRED_IMPROVEMENT_CATEGORIES = Object.freeze([
  'cqi_review',
  'documentation_update',
  'manual_crosslink_refresh',
  'system_change',
  'training_update',
  'workflow_change',
]);

const SUPPORTED_IMPROVEMENT_CATEGORIES = new Set([
  ...REQUIRED_IMPROVEMENT_CATEGORIES,
  'accessibility_update',
  'risk_review',
]);

const RAW_INQUIRY_FIELDS = new Set([
  'answerbody',
  'assistantanswer',
  'assistantbody',
  'body',
  'comment',
  'content',
  'freetext',
  'freetextnote',
  'helpbody',
  'helpcontent',
  'helpquery',
  'helptext',
  'inquirynarrative',
  'inquirytext',
  'manualbody',
  'manualcontent',
  'manualtext',
  'questionbody',
  'questiontext',
  'rawassistancecontent',
  'rawcontent',
  'rawfrictionsignal',
  'rawhelpcontent',
  'rawinquirycontent',
  'rawinquirytext',
  'rawmanualcontent',
  'rawquery',
  'reviewnotes',
  'sourcebody',
  'sourcedocumentbody',
]);

const SECRET_INQUIRY_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credential',
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

function isPositiveSafeInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
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

function assertNoRawInquiryContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawInquiryContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_INQUIRY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw inquiry content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_INQUIRY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`inquiry secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawInquiryContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawInquiryContent(input ?? {});
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

function evaluateRequiredSet(actual, expected, missingPrefix, unsupportedPrefix, supportedSet, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !supportedSet.has(value), `${unsupportedPrefix}:${value}`);
  }
}

function missingValues(expected, actual) {
  return expected.filter((value) => !actual.includes(value));
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

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_cqi_triage_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'cqi_triage_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(policy, reasons) {
  const requiredSourceFamilies = sortedTextList(policy?.requiredSourceFamilies);
  const allowedImprovementCategories = sortedTextList(policy?.allowedImprovementCategories);
  const sourceFamilySet = new Set(REQUIRED_SOURCE_FAMILIES);

  addReason(reasons, !hasText(policy?.policyRef), 'backlog_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'backlog_policy_hash_invalid');
  addReason(reasons, !ACTIVE_POLICY_STATUSES.has(policy?.status), 'backlog_policy_not_active');
  addReason(reasons, policy?.highRiskReviewRequired !== true, 'high_risk_review_policy_absent');
  addReason(
    reasons,
    policy?.documentationVersionGovernanceRequired !== true,
    'documentation_version_governance_policy_absent',
  );
  addReason(reasons, policy?.driftRoutingRequired !== true, 'drift_routing_policy_absent');
  addReason(reasons, policy?.aiAssistanceAdvisoryOnly !== true, 'ai_assistance_policy_not_advisory_only');
  addReason(reasons, policy?.metadataOnly !== true, 'backlog_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'backlog_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'backlog_policy_time_invalid');

  evaluateRequiredSet(
    requiredSourceFamilies,
    REQUIRED_SOURCE_FAMILIES,
    'policy_source_family_missing',
    'policy_source_family_unsupported',
    sourceFamilySet,
    reasons,
  );
  evaluateRequiredSet(
    allowedImprovementCategories,
    REQUIRED_IMPROVEMENT_CATEGORIES,
    'policy_improvement_category_missing',
    'policy_improvement_category_unsupported',
    SUPPORTED_IMPROVEMENT_CATEGORIES,
    reasons,
  );

  return {
    allowedImprovementCategories,
    requiredSourceFamilies,
  };
}

function evaluateCycle(cycle, policy, reasons) {
  addReason(reasons, !hasText(cycle?.cycleRef), 'backlog_cycle_ref_absent');
  addReason(reasons, cycle?.metadataOnly !== true, 'backlog_cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'backlog_cycle_protected_boundary_invalid');
  addReason(reasons, cycle?.productionTrustClaim === true, 'production_trust_claim_forbidden');

  const ordered = [
    ['openedAtHlc', cycle?.openedAtHlc],
    ['signalsCapturedAtHlc', cycle?.signalsCapturedAtHlc],
    ['triagedAtHlc', cycle?.triagedAtHlc],
    ['ownerAssignedAtHlc', cycle?.ownerAssignedAtHlc],
    ['actionPackagedAtHlc', cycle?.actionPackagedAtHlc],
    ['humanReviewedAtHlc', cycle?.humanReviewedAtHlc],
    ['auditRecordedAtHlc', cycle?.auditRecordedAtHlc],
  ];

  for (const [label, value] of ordered) {
    addReason(reasons, hlcTuple(value) === null, `backlog_cycle_${label}_invalid`);
  }
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, cycle?.openedAtHlc), 'backlog_policy_after_cycle_open');
  for (let index = 1; index < ordered.length; index += 1) {
    const [previousLabel, previousValue] = ordered[index - 1];
    const [currentLabel, currentValue] = ordered[index];
    addReason(
      reasons,
      hlcBefore(currentValue, previousValue),
      `backlog_cycle_${currentLabel}_before_${previousLabel}`,
    );
  }
}

function evaluateSourceAnalytics(sourceAnalytics, cycle, reasons) {
  addReason(reasons, !isDigest(sourceAnalytics?.userAssistanceReceiptHash), 'source_assistance_receipt_hash_invalid');
  addReason(reasons, !isDigest(sourceAnalytics?.documentationRunbookReceiptHash), 'source_runbook_receipt_hash_invalid');
  addReason(reasons, !isDigest(sourceAnalytics?.driftPolicyHash), 'source_drift_policy_hash_invalid');
  addReason(reasons, !isDigest(sourceAnalytics?.currentManualSetHash), 'source_manual_set_hash_invalid');
  addReason(reasons, !isDigest(sourceAnalytics?.currentManualIndexHash), 'source_manual_index_hash_invalid');
  addReason(reasons, sourceAnalytics?.noRawInquiryContent !== true, 'source_raw_inquiry_boundary_absent');
  addReason(reasons, sourceAnalytics?.metadataOnly !== true, 'source_analytics_metadata_boundary_invalid');
  addReason(reasons, sourceAnalytics?.protectedContentExcluded !== true, 'source_analytics_protected_boundary_invalid');
  addReason(reasons, hlcTuple(sourceAnalytics?.reviewedAtHlc) === null, 'source_analytics_review_time_invalid');
  addReason(reasons, hlcBefore(sourceAnalytics?.reviewedAtHlc, cycle?.openedAtHlc), 'source_analytics_review_before_cycle_open');
  addReason(
    reasons,
    hlcAfter(sourceAnalytics?.reviewedAtHlc, cycle?.signalsCapturedAtHlc),
    'source_analytics_review_after_signal_capture',
  );
}

function signalLabel(signal, index) {
  return hasText(signal?.signalRef) ? signal.signalRef : `inquiry_signal_${index}`;
}

function evaluateInquirySignals(signals, requiredSourceFamilies, allowedImprovementCategories, cycle, reasons) {
  addReason(reasons, !Array.isArray(signals) || signals.length === 0, 'inquiry_signals_absent');
  if (!Array.isArray(signals)) {
    return { cqiRequiredSignalRefs: [], highRiskSignalRefs: [], signalRefs: [], sourceFamilies: [], totalEvents: 0 };
  }

  const seenRefs = new Set();
  const sourceFamilies = sortedTextList(signals.map((signal) => signal?.sourceFamily));
  const signalRefs = sortedTextList(signals.map((signal) => signal?.signalRef));
  const cqiRequiredSignalRefs = [];
  const highRiskSignalRefs = [];

  for (const family of requiredSourceFamilies) {
    addReason(reasons, !sourceFamilies.includes(family), `source_family_missing:${family}`);
  }

  signals.forEach((signal, index) => {
    const label = signalLabel(signal, index);
    const affectedRoleRefs = sortedTextList(signal?.affectedRoleRefs);
    addReason(reasons, !hasText(signal?.signalRef), `inquiry_signal_ref_absent:${label}`);
    addReason(reasons, seenRefs.has(signal?.signalRef), `inquiry_signal_ref_duplicate:${label}`);
    if (hasText(signal?.signalRef)) {
      seenRefs.add(signal.signalRef);
    }
    addReason(reasons, !REQUIRED_SOURCE_FAMILIES.includes(signal?.sourceFamily), `source_family_unsupported:${label}`);
    addReason(reasons, !isDigest(signal?.sourceSignalHash), `source_signal_hash_invalid:${label}`);
    addReason(reasons, !hasText(signal?.roleRef), `inquiry_signal_role_ref_absent:${label}`);
    addReason(reasons, !hasText(signal?.manualSectionRef), `manual_section_ref_absent:${label}`);
    addReason(reasons, !hasText(signal?.workflowRef), `workflow_ref_absent:${label}`);
    addReason(
      reasons,
      !allowedImprovementCategories.includes(signal?.suggestedImprovementCategory) ||
        !SUPPORTED_IMPROVEMENT_CATEGORIES.has(signal?.suggestedImprovementCategory),
      `suggested_improvement_category_invalid:${label}`,
    );
    addReason(reasons, !isPositiveSafeInteger(signal?.eventCount), `inquiry_event_count_invalid:${label}`);
    addReason(reasons, affectedRoleRefs.length === 0, `inquiry_affected_roles_absent:${label}`);
    addReason(reasons, !SIGNAL_SEVERITIES.has(signal?.severity), `inquiry_severity_invalid:${label}`);
    addReason(reasons, typeof signal?.highRiskContent !== 'boolean', `high_risk_content_flag_invalid:${label}`);
    addReason(reasons, signal?.requiresCqi !== true, `inquiry_cqi_required_absent:${label}`);
    addReason(reasons, signal?.metadataOnly !== true, `inquiry_signal_metadata_boundary_invalid:${label}`);
    addReason(reasons, signal?.protectedContentExcluded !== true, `inquiry_signal_protected_boundary_invalid:${label}`);
    addReason(reasons, hlcTuple(signal?.capturedAtHlc) === null, `inquiry_signal_capture_time_invalid:${label}`);
    addReason(reasons, hlcBefore(signal?.capturedAtHlc, cycle?.signalsCapturedAtHlc), `inquiry_signal_before_cycle_capture:${label}`);

    if (signal?.requiresCqi === true && hasText(signal?.signalRef)) {
      cqiRequiredSignalRefs.push(signal.signalRef);
    }
    if (signal?.highRiskContent === true && hasText(signal?.signalRef)) {
      highRiskSignalRefs.push(signal.signalRef);
    }
  });

  return {
    cqiRequiredSignalRefs: uniqueSorted(cqiRequiredSignalRefs),
    highRiskSignalRefs: uniqueSorted(highRiskSignalRefs),
    signalRefs,
    sourceFamilies,
    totalEvents: signals.reduce((total, signal) => total + (Number.isSafeInteger(signal?.eventCount) ? signal.eventCount : 0), 0),
  };
}

function itemLabel(item, index) {
  return hasText(item?.backlogItemRef) ? item.backlogItemRef : `backlog_item_${index}`;
}

function evaluateBacklogItems(items, signals, signalSummary, allowedImprovementCategories, cycle, reasons) {
  addReason(reasons, !Array.isArray(items) || items.length === 0, 'backlog_items_absent');
  if (!Array.isArray(items)) {
    return { backlogItemRefs: [], highRiskBacklogItemRefs: [], improvementCategories: [] };
  }

  const signalsByRef = new Map(signals.map((signal) => [signal.signalRef, signal]));
  const itemsBySignal = new Map();
  const seenItems = new Set();
  const backlogItemRefs = [];
  const highRiskBacklogItemRefs = [];
  const improvementCategories = [];

  items.forEach((item, index) => {
    if (hasText(item?.sourceSignalRef)) {
      itemsBySignal.set(item.sourceSignalRef, item);
    }
    const label = itemLabel(item, index);
    const sourceSignal = signalsByRef.get(item?.sourceSignalRef);
    const requiredReviewRoleRefs = sortedTextList(item?.requiredReviewRoleRefs);
    addReason(reasons, !hasText(item?.backlogItemRef), `backlog_item_ref_absent:${label}`);
    addReason(reasons, seenItems.has(item?.backlogItemRef), `backlog_item_ref_duplicate:${label}`);
    if (hasText(item?.backlogItemRef)) {
      seenItems.add(item.backlogItemRef);
      backlogItemRefs.push(item.backlogItemRef);
    }
    addReason(reasons, !hasText(item?.sourceSignalRef), `backlog_item_source_signal_absent:${label}`);
    addReason(
      reasons,
      hasText(item?.sourceSignalRef) && !signalsByRef.has(item.sourceSignalRef),
      `backlog_item_source_signal_unknown:${label}`,
    );
    addReason(reasons, !BACKLOG_PRIORITIES.has(item?.priority), `backlog_item_priority_invalid:${label}`);
    addReason(reasons, !hasText(item?.ownerRoleRef), `backlog_item_owner_role_absent:${label}`);
    addReason(reasons, !TRIAGE_DISPOSITIONS.has(item?.triageDisposition), `backlog_item_disposition_invalid:${label}`);
    addReason(
      reasons,
      !allowedImprovementCategories.includes(item?.improvementCategory) ||
        !SUPPORTED_IMPROVEMENT_CATEGORIES.has(item?.improvementCategory),
      `backlog_item_category_invalid:${label}`,
    );
    addReason(reasons, requiredReviewRoleRefs.length === 0, `backlog_item_review_roles_absent:${label}`);
    addReason(reasons, !isDigest(item?.linkedDocumentationSectionHash), `backlog_item_documentation_hash_invalid:${label}`);
    addReason(reasons, !isDigest(item?.noRetaliationReminderHash), `backlog_item_no_retaliation_hash_invalid:${label}`);
    addReason(reasons, item?.metadataOnly !== true, `backlog_item_metadata_boundary_invalid:${label}`);
    addReason(reasons, item?.protectedContentExcluded !== true, `backlog_item_protected_boundary_invalid:${label}`);
    addReason(reasons, hlcTuple(item?.triagedAtHlc) === null, `backlog_item_triage_time_invalid:${label}`);
    addReason(reasons, hlcTuple(item?.dueAtHlc) === null, `backlog_item_due_time_invalid:${label}`);
    addReason(reasons, hlcBefore(item?.triagedAtHlc, cycle?.triagedAtHlc), `backlog_item_triaged_before_cycle_triage:${label}`);
    addReason(reasons, hlcBefore(item?.dueAtHlc, item?.triagedAtHlc), `backlog_item_due_before_triage:${label}`);
    addReason(
      reasons,
      sourceSignal?.highRiskContent === true && item?.triageDisposition !== 'hold_for_high_risk_review',
      `high_risk_item_not_held_for_review:${label}`,
    );
    addReason(
      reasons,
      sourceSignal?.highRiskContent === true && !requiredReviewRoleRefs.includes('regulatory_reviewer'),
      `high_risk_review_role_absent:${label}`,
    );

    if (sourceSignal?.highRiskContent === true && hasText(item?.backlogItemRef)) {
      highRiskBacklogItemRefs.push(item.backlogItemRef);
    }
    if (hasText(item?.improvementCategory)) {
      improvementCategories.push(item.improvementCategory);
    }
  });

  for (const signalRef of signalSummary.cqiRequiredSignalRefs) {
    addReason(reasons, !itemsBySignal.has(signalRef), `backlog_item_absent:${signalRef}`);
  }

  return {
    backlogItemRefs: uniqueSorted(backlogItemRefs),
    highRiskBacklogItemRefs: uniqueSorted(highRiskBacklogItemRefs),
    improvementCategories: uniqueSorted(improvementCategories),
  };
}

function evaluateActionPackage(actionPackage, itemSummary, highRiskBacklogItemRefs, cycle, reasons) {
  const linkedBacklogItemRefs = sortedTextList(actionPackage?.linkedBacklogItemRefs);
  const improvementCategories = sortedTextList(actionPackage?.improvementCategories);
  const driftSignalRefs = sortedTextList(actionPackage?.driftSignalRefs);
  const documentationUpdateDraftHashes = Array.isArray(actionPackage?.documentationUpdateDraftHashes)
    ? actionPackage.documentationUpdateDraftHashes
    : [];
  const highRiskReviewHashes = Array.isArray(actionPackage?.highRiskReviewHashes) ? actionPackage.highRiskReviewHashes : [];

  addReason(reasons, !hasText(actionPackage?.packageRef), 'action_package_ref_absent');
  addReason(reasons, linkedBacklogItemRefs.length === 0, 'action_package_backlog_items_absent');
  addReason(reasons, improvementCategories.length === 0, 'action_package_categories_absent');
  addReason(reasons, driftSignalRefs.length === 0, 'action_package_drift_signals_absent');
  addReason(reasons, documentationUpdateDraftHashes.filter(isDigest).length === 0, 'documentation_update_draft_hash_absent');
  addReason(reasons, !isDigest(actionPackage?.cqiQueueHash), 'cqi_queue_hash_invalid');
  addReason(reasons, !isDigest(actionPackage?.crosslinkRefreshHash), 'crosslink_refresh_hash_invalid');
  addReason(reasons, !isDigest(actionPackage?.versionGovernanceHash), 'version_governance_hash_invalid');
  addReason(
    reasons,
    highRiskBacklogItemRefs.length > 0 && highRiskReviewHashes.filter(isDigest).length === 0,
    'high_risk_review_hash_absent',
  );
  addReason(reasons, !hasText(actionPackage?.qualityOwnerRoleRef), 'action_package_quality_owner_absent');
  addReason(reasons, actionPackage?.metadataOnly !== true, 'action_package_metadata_boundary_invalid');
  addReason(reasons, actionPackage?.protectedContentExcluded !== true, 'action_package_protected_boundary_invalid');
  addReason(reasons, hlcTuple(actionPackage?.packagedAtHlc) === null, 'action_package_time_invalid');
  addReason(reasons, hlcBefore(actionPackage?.packagedAtHlc, cycle?.actionPackagedAtHlc), 'action_package_before_cycle_step');

  for (const itemRef of itemSummary.backlogItemRefs) {
    addReason(reasons, !linkedBacklogItemRefs.includes(itemRef), `action_package_item_missing:${itemRef}`);
  }
  for (const itemRef of linkedBacklogItemRefs) {
    addReason(reasons, !itemSummary.backlogItemRefs.includes(itemRef), `action_package_item_unknown:${itemRef}`);
  }
  for (const category of REQUIRED_IMPROVEMENT_CATEGORIES) {
    addReason(reasons, !improvementCategories.includes(category), `action_package_category_missing:${category}`);
  }
  for (const category of improvementCategories) {
    addReason(
      reasons,
      !SUPPORTED_IMPROVEMENT_CATEGORIES.has(category),
      `action_package_category_unsupported:${category}`,
    );
  }
  for (const hash of documentationUpdateDraftHashes) {
    addReason(reasons, !isDigest(hash), `documentation_update_draft_hash_invalid:${String(hash)}`);
  }
  for (const hash of highRiskReviewHashes) {
    addReason(reasons, !isDigest(hash), `high_risk_review_hash_invalid:${String(hash)}`);
  }

  return {
    driftReady: driftSignalRefs.length >= itemSummary.backlogItemRefs.length && itemSummary.backlogItemRefs.length > 0,
    driftSignalRefs,
    improvementCategories,
    linkedBacklogItemRefs,
  };
}

function evaluateAiAssistant(aiAssistant, cycle, reasons) {
  if (aiAssistant === null || aiAssistant === undefined || aiAssistant?.used !== true) {
    return false;
  }

  addReason(reasons, !hasText(aiAssistant?.assistantRef), 'ai_assistant_ref_absent');
  addReason(reasons, !isDigest(aiAssistant?.recommendationHash), 'ai_recommendation_hash_invalid');
  addReason(reasons, sortedTextList(aiAssistant?.limitationHashes).filter(isDigest).length === 0, 'ai_limitation_hashes_absent');
  addReason(reasons, aiAssistant?.advisoryOnly !== true, 'ai_not_advisory');
  addReason(reasons, aiAssistant?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, aiAssistant?.humanReviewed !== true, 'ai_human_review_absent');
  addReason(reasons, aiAssistant?.metadataOnly !== true, 'ai_metadata_boundary_invalid');
  addReason(reasons, aiAssistant?.protectedContentExcluded !== true, 'ai_protected_boundary_invalid');
  addReason(reasons, hlcTuple(aiAssistant?.reviewedAtHlc) === null, 'ai_review_time_invalid');
  addReason(reasons, hlcBefore(aiAssistant?.reviewedAtHlc, cycle?.actionPackagedAtHlc), 'ai_review_before_action_package');
  return true;
}

function evaluateHumanReview(humanReview, cycle, reasons) {
  const reviewerRoleRefs = sortedTextList(humanReview?.reviewerRoleRefs);
  addReason(reasons, !hasText(humanReview?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, reviewerRoleRefs.length === 0, 'human_reviewer_roles_absent');
  addReason(reasons, !HUMAN_DECISIONS.has(humanReview?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(humanReview?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, humanReview?.finalAuthority !== 'human', 'human_final_authority_absent');
  addReason(reasons, humanReview?.aiFinalAuthority === true, 'human_review_ai_final_authority_forbidden');
  addReason(reasons, humanReview?.noProductionTrustClaim !== true, 'human_review_production_trust_claim_forbidden');
  addReason(reasons, humanReview?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, humanReview?.protectedContentExcluded !== true, 'human_review_protected_boundary_invalid');
  addReason(reasons, hlcTuple(humanReview?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(humanReview?.reviewedAtHlc, cycle?.humanReviewedAtHlc), 'human_review_before_cycle_step');
}

function createBacklogDigest(input, signalSummary, itemSummary, actionSummary) {
  return sha256Hex({
    actionPackageRef: input?.actionPackage?.packageRef ?? null,
    backlogItemRefs: itemSummary.backlogItemRefs,
    cycleRef: input?.backlogCycle?.cycleRef ?? null,
    driftSignalRefs: actionSummary.driftSignalRefs,
    sourceFamilies: signalSummary.sourceFamilies,
    sourceReceiptHash: input?.sourceAnalytics?.userAssistanceReceiptHash ?? null,
    tenantId: input?.tenantId ?? null,
  });
}

function createCqiBacklog(input, finalReasons, signalSummary, itemSummary, actionSummary, aiAssistanceUsed) {
  const backlogDigest = createBacklogDigest(input, signalSummary, itemSummary, actionSummary);
  return {
    schema: INQUIRY_CQI_SCHEMA,
    ready: finalReasons.length === 0,
    trustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    backlogDigest,
    tenantId: input?.tenantId ?? null,
    cycleRef: input?.backlogCycle?.cycleRef ?? null,
    sourceFamilies: signalSummary.sourceFamilies,
    missingSourceFamilies: missingValues(REQUIRED_SOURCE_FAMILIES, signalSummary.sourceFamilies),
    improvementCategories: actionSummary.improvementCategories,
    missingImprovementCategories: missingValues(REQUIRED_IMPROVEMENT_CATEGORIES, actionSummary.improvementCategories),
    signalCount: signalSummary.signalRefs.length,
    backlogItemCount: itemSummary.backlogItemRefs.length,
    totalInquiryEvents: signalSummary.totalEvents,
    cqiRequiredSignalRefs: signalSummary.cqiRequiredSignalRefs,
    highRiskBacklogItemRefs: itemSummary.highRiskBacklogItemRefs,
    linkedBacklogItemRefs: actionSummary.linkedBacklogItemRefs,
    driftSignalRefs: actionSummary.driftSignalRefs,
    driftReady: actionSummary.driftReady,
    aiAssistanceUsed,
    reviewerDid: input?.humanReview?.reviewerDid ?? null,
    auditRecordedAtHlc: input?.backlogCycle?.auditRecordedAtHlc ?? null,
    sourceEvidence: [
      'cybermedica_2_0_sandy_seven_layer_master_prd.md',
      'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
      'docs/context/CYBERMEDICA_ADJACENT_SURFACE_DECISIONS.md',
    ],
  };
}

function buildReceipt(input, cqiBacklog) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: cqiBacklog.backlogDigest,
    artifactType: 'inquiry_cqi_backlog',
    artifactVersion: input.backlogCycle.cycleRef,
    classification: 'metadata_only_documentation_cqi',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.backlogCycle.auditRecordedAtHlc,
    sensitivityTags: ['documentation_friction', 'cqi_backlog', 'metadata_only'],
    sourceSystem: 'cybermedica',
    tenantId: input.tenantId,
  });
}

export function evaluateInquiryCqiBacklog(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policySummary = evaluatePolicy(input?.backlogPolicy, reasons);
  evaluateCycle(input?.backlogCycle, input?.backlogPolicy, reasons);
  evaluateSourceAnalytics(input?.sourceAnalytics, input?.backlogCycle, reasons);
  const signals = Array.isArray(input?.inquirySignals) ? input.inquirySignals : [];
  const signalSummary = evaluateInquirySignals(
    input?.inquirySignals,
    policySummary.requiredSourceFamilies,
    policySummary.allowedImprovementCategories,
    input?.backlogCycle,
    reasons,
  );
  const itemSummary = evaluateBacklogItems(
    input?.backlogItems,
    signals,
    signalSummary,
    policySummary.allowedImprovementCategories,
    input?.backlogCycle,
    reasons,
  );
  const actionSummary = evaluateActionPackage(input?.actionPackage, itemSummary, itemSummary.highRiskBacklogItemRefs, input?.backlogCycle, reasons);
  const aiAssistanceUsed = evaluateAiAssistant(input?.aiAssistant, input?.backlogCycle, reasons);
  evaluateHumanReview(input?.humanReview, input?.backlogCycle, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const finalReasons = uniqueReasons(reasons);
  const cqiBacklog = createCqiBacklog(input, finalReasons, signalSummary, itemSummary, actionSummary, aiAssistanceUsed);

  if (finalReasons.length > 0) {
    return {
      schema: INQUIRY_CQI_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: finalReasons,
      cqiBacklog,
      receipt: null,
    };
  }

  return {
    schema: INQUIRY_CQI_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    cqiBacklog,
    receipt: buildReceipt(input, cqiBacklog),
  };
}
