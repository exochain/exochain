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
const USER_ASSISTANCE_SCHEMA = 'cybermedica.user_assistance_analytics.v1';
const REQUIRED_PERMISSION = 'user_assistance_review';
const ACTIVE_POLICY_STATUSES = new Set(['active']);
const HUMAN_DECISIONS = new Set(['assistance_analytics_ready', 'hold_for_assistance_gap']);
const CQI_DESTINATIONS = new Set(['drift_improvement']);
const SIGNAL_SEVERITIES = new Set(['critical', 'major', 'minor', 'observation']);

const REQUIRED_NAVIGATION_STATES = Object.freeze([
  'administrator_runbook_linkage',
  'ai_orientation_prompt',
  'audit_inspector_help',
  'contextual_manual_drawer',
  'cqi_inquiry_capture',
  'evidence_checklist_guidance',
  'role_manual_entrypoint',
  'workflow_step_help',
]);

const REQUIRED_FRICTION_FAMILIES = Object.freeze([
  'accessibility_barrier',
  'ai_confidence_low',
  'checklist_blocker',
  'manual_dead_end',
  'policy_crosslink_gap',
  'repeated_inquiry',
  'search_zero_result',
  'workflow_exit',
]);

const RAW_ASSISTANCE_FIELDS = new Set([
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
  'manualbody',
  'manualcontent',
  'manualtext',
  'navigationbody',
  'query',
  'querytext',
  'rawassistancecontent',
  'rawcontent',
  'rawhelpcontent',
  'rawhelptext',
  'rawmanualcontent',
  'rawnavigationevent',
  'rawquery',
  'reviewnotes',
  'sourcebody',
  'sourcedocumentbody',
]);

const SECRET_ASSISTANCE_FIELDS = new Set([
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

function isBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 10_000;
}

function isPositiveSafeInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function isNonNegativeSafeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
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

function assertNoRawAssistanceContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawAssistanceContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_ASSISTANCE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw user assistance content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_ASSISTANCE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`user assistance secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawAssistanceContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawAssistanceContent(input ?? {});
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

function evaluateRequiredSet(actual, expected, missingPrefix, unsupportedPrefix, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !expected.includes(value), `${unsupportedPrefix}:${value}`);
  }
}

function missingValues(expected, actual) {
  return expected.filter((value) => !actual.includes(value));
}

function includesAll(actual, expected) {
  return expected.every((value) => actual.includes(value));
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

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function hlcBefore(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) < 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function basisPoints(numerator, denominator) {
  if (!Number.isSafeInteger(numerator) || !Number.isSafeInteger(denominator) || denominator <= 0) {
    return 0;
  }
  return Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_assistance_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'user_assistance_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateAssistancePolicy(policy, reasons) {
  const requiredNavigationStates = sortedTextList(policy?.requiredNavigationStates);
  const requiredFrictionFamilies = sortedTextList(policy?.requiredFrictionFamilies);

  addReason(reasons, !hasText(policy?.policyRef), 'assistance_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'assistance_policy_hash_invalid');
  addReason(reasons, !ACTIVE_POLICY_STATUSES.has(policy?.status), 'assistance_policy_not_active');
  addReason(reasons, !isBasisPoints(policy?.cqiThresholdBasisPoints), 'assistance_policy_cqi_threshold_invalid');
  addReason(reasons, policy?.manualVersionGovernanceRequired !== true, 'manual_version_governance_required_absent');
  addReason(reasons, policy?.aiAssistanceAdvisoryOnly !== true, 'ai_assistance_policy_not_advisory_only');
  addReason(reasons, policy?.metadataOnly !== true, 'assistance_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'assistance_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'assistance_policy_time_invalid');

  evaluateRequiredSet(
    requiredNavigationStates,
    REQUIRED_NAVIGATION_STATES,
    'policy_navigation_state_missing',
    'policy_navigation_state_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    requiredFrictionFamilies,
    REQUIRED_FRICTION_FAMILIES,
    'policy_friction_family_missing',
    'policy_friction_family_unsupported',
    reasons,
  );

  return { requiredFrictionFamilies, requiredNavigationStates };
}

function evaluateAssistanceCycle(cycle, policy, humanReview, reasons) {
  addReason(reasons, !hasText(cycle?.cycleRef), 'assistance_cycle_ref_absent');
  addReason(reasons, cycle?.metadataOnly !== true, 'assistance_cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'assistance_cycle_protected_boundary_invalid');
  addReason(reasons, cycle?.productionTrustClaim !== false, 'assistance_cycle_production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(cycle?.openedAtHlc) === null, 'assistance_cycle_open_time_invalid');
  addReason(reasons, hlcTuple(cycle?.navigationCapturedAtHlc) === null, 'navigation_capture_time_invalid');
  addReason(reasons, hlcTuple(cycle?.frictionAnalyzedAtHlc) === null, 'friction_analysis_time_invalid');
  addReason(reasons, hlcTuple(cycle?.cqiRoutedAtHlc) === null, 'cqi_route_time_invalid');
  addReason(reasons, hlcTuple(cycle?.humanReviewedAtHlc) === null, 'assistance_human_review_time_invalid');
  addReason(reasons, hlcTuple(cycle?.receiptRecordedAtHlc) === null, 'assistance_receipt_time_invalid');
  addReason(reasons, !hlcAfter(cycle?.openedAtHlc, policy?.evaluatedAtHlc), 'assistance_cycle_open_not_after_policy');
  addReason(reasons, !hlcAfter(cycle?.navigationCapturedAtHlc, cycle?.openedAtHlc), 'navigation_capture_before_open');
  addReason(
    reasons,
    !hlcAfter(cycle?.frictionAnalyzedAtHlc, cycle?.navigationCapturedAtHlc),
    'friction_analysis_before_navigation_capture',
  );
  addReason(reasons, !hlcAfter(cycle?.cqiRoutedAtHlc, cycle?.frictionAnalyzedAtHlc), 'cqi_route_before_friction_analysis');
  addReason(reasons, !hlcAfter(cycle?.humanReviewedAtHlc, cycle?.cqiRoutedAtHlc), 'human_review_before_cqi_route');
  addReason(reasons, !hlcAfter(cycle?.receiptRecordedAtHlc, cycle?.humanReviewedAtHlc), 'receipt_recorded_before_human_review');
  addReason(reasons, hlcBefore(cycle?.receiptRecordedAtHlc, humanReview?.reviewedAtHlc), 'receipt_recorded_before_human_review');
}

function evaluateManualIndex(index, cycle, reasons) {
  addReason(reasons, !hasText(index?.documentationReadinessRef), 'manual_index_ref_absent');
  addReason(reasons, !isDigest(index?.documentationRunbookReceiptHash), 'manual_index_receipt_hash_invalid');
  addReason(reasons, !isDigest(index?.currentManualSetHash), 'manual_index_current_set_hash_invalid');
  addReason(reasons, !isDigest(index?.crosslinkMatrixHash), 'manual_index_crosslink_hash_invalid');
  addReason(reasons, !isDigest(index?.versionGovernanceHash), 'manual_index_version_governance_hash_invalid');
  addReason(reasons, index?.metadataOnly !== true, 'manual_index_metadata_boundary_invalid');
  addReason(reasons, index?.protectedContentExcluded !== true, 'manual_index_protected_boundary_invalid');
  addReason(reasons, hlcTuple(index?.reviewedAtHlc) === null, 'manual_index_review_time_invalid');
  addReason(reasons, hlcBefore(index?.reviewedAtHlc, cycle?.openedAtHlc), 'manual_index_review_before_cycle_open');
}

function navigationLabel(state, index) {
  return hasText(state?.stateRef) ? state.stateRef : `navigation_${index}`;
}

function evaluateNavigationStates(states, cycle, reasons) {
  const rows = Array.isArray(states) ? [...states] : [];
  const navigationRefs = new Set();
  const summaries = rows
    .sort((left, right) => String(left?.stateRef ?? '').localeCompare(String(right?.stateRef ?? '')))
    .map((state, index) => {
      const label = navigationLabel(state, index);
      addReason(reasons, !hasText(state?.stateRef), `navigation_state_ref_absent:${label}`);
      addReason(reasons, !REQUIRED_NAVIGATION_STATES.includes(state?.stateFamily), `navigation_state_family_unsupported:${label}`);
      addReason(reasons, !hasText(state?.roleRef), `navigation_role_ref_absent:${label}`);
      addReason(reasons, !hasText(state?.manualRef), `navigation_manual_ref_absent:${label}`);
      addReason(reasons, !hasText(state?.manualVersionRef), `navigation_manual_version_absent:${label}`);
      addReason(reasons, !isDigest(state?.entrypointHash), `navigation_entrypoint_hash_invalid:${label}`);
      addReason(reasons, !isDigest(state?.targetArtifactHash), `navigation_target_hash_invalid:${label}`);
      addReason(reasons, !isPositiveSafeInteger(state?.totalNavigationCount), `navigation_total_count_invalid:${label}`);
      addReason(reasons, !isNonNegativeSafeInteger(state?.successfulNavigationCount), `navigation_success_count_invalid:${label}`);
      addReason(reasons, !isNonNegativeSafeInteger(state?.blockedNavigationCount), `navigation_blocked_count_invalid:${label}`);
      addReason(
        reasons,
        isNonNegativeSafeInteger(state?.successfulNavigationCount) &&
          isPositiveSafeInteger(state?.totalNavigationCount) &&
          state.successfulNavigationCount > state.totalNavigationCount,
        `navigation_success_exceeds_total:${label}`,
      );
      addReason(
        reasons,
        isNonNegativeSafeInteger(state?.blockedNavigationCount) &&
          isPositiveSafeInteger(state?.totalNavigationCount) &&
          state.blockedNavigationCount > state.totalNavigationCount,
        `navigation_blocked_exceeds_total:${label}`,
      );
      addReason(reasons, !isBasisPoints(state?.completionBasisPoints), `navigation_completion_basis_points_invalid:${label}`);
      addReason(reasons, state?.metadataOnly !== true, `navigation_metadata_boundary_invalid:${label}`);
      addReason(reasons, state?.protectedContentExcluded !== true, `navigation_protected_boundary_invalid:${label}`);
      addReason(reasons, hlcTuple(state?.lastUpdatedAtHlc) === null, `navigation_update_time_invalid:${label}`);
      addReason(reasons, hlcBefore(state?.lastUpdatedAtHlc, cycle?.navigationCapturedAtHlc), `navigation_update_before_capture:${label}`);

      if (hasText(state?.stateRef)) {
        navigationRefs.add(state.stateRef);
      }
      return {
        blockedNavigationCount: state?.blockedNavigationCount ?? 0,
        completionBasisPoints: state?.completionBasisPoints ?? 0,
        entrypointHash: state?.entrypointHash ?? null,
        manualRef: state?.manualRef ?? null,
        manualVersionRef: state?.manualVersionRef ?? null,
        roleRef: state?.roleRef ?? null,
        stateFamily: state?.stateFamily ?? null,
        stateRef: label,
        successfulNavigationCount: state?.successfulNavigationCount ?? 0,
        targetArtifactHash: state?.targetArtifactHash ?? null,
        totalNavigationCount: state?.totalNavigationCount ?? 0,
      };
    });

  const actualFamilies = uniqueSorted(summaries.map((state) => state.stateFamily).filter(hasText));
  evaluateRequiredSet(
    actualFamilies,
    REQUIRED_NAVIGATION_STATES,
    'navigation_state_missing',
    'navigation_state_unsupported',
    reasons,
  );

  return {
    actualFamilies,
    navigationRefs,
    summaries,
    totalBlockedNavigationEvents: summaries.reduce((total, state) => total + state.blockedNavigationCount, 0),
    totalNavigationEvents: summaries.reduce((total, state) => total + state.totalNavigationCount, 0),
  };
}

function evaluateManualNavigationReadiness(readiness, states, cycle, reasons) {
  const rows = Array.isArray(states) ? states : [];
  const contextualDrawerStates = rows.filter((state) => state?.stateFamily === 'contextual_manual_drawer');
  const navigationRoleRefs = uniqueSorted(rows.map((state) => state?.roleRef));
  const requiredAcknowledgementRoleRefs = sortedTextList(readiness?.requiredAcknowledgementRoleRefs);
  const acknowledgedRoleRefs = sortedTextList(readiness?.acknowledgedRoleRefs);

  addReason(reasons, !isDigest(readiness?.contextualManualDrawerReceiptHash), 'manual_navigation_drawer_receipt_hash_invalid');
  addReason(reasons, !isDigest(readiness?.contextualManualDrawerHash), 'manual_navigation_drawer_hash_invalid');
  addReason(reasons, !hasText(readiness?.controlledDocumentDistributionRecordId), 'manual_navigation_distribution_record_absent');
  addReason(
    reasons,
    !isDigest(readiness?.controlledDocumentDistributionReceiptHash),
    'manual_navigation_distribution_receipt_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(readiness?.documentationPublicationReceiptHash),
    'manual_navigation_publication_receipt_hash_invalid',
  );
  addReason(reasons, !isDigest(readiness?.manualExportReceiptHash), 'manual_navigation_manual_export_receipt_hash_invalid');
  addReason(
    reasons,
    !isDigest(readiness?.roleManualCoverageReceiptHash),
    'manual_navigation_role_manual_coverage_receipt_hash_invalid',
  );
  addReason(reasons, !isDigest(readiness?.acknowledgementRosterHash), 'manual_navigation_acknowledgement_roster_hash_invalid');
  addReason(
    reasons,
    requiredAcknowledgementRoleRefs.length === 0 || acknowledgedRoleRefs.length === 0,
    'manual_navigation_acknowledgement_roles_missing',
  );
  addReason(
    reasons,
    requiredAcknowledgementRoleRefs.length > 0 &&
      acknowledgedRoleRefs.length > 0 &&
      !includesAll(acknowledgedRoleRefs, requiredAcknowledgementRoleRefs),
    'manual_navigation_acknowledgement_roles_incomplete',
  );

  for (const roleRef of navigationRoleRefs) {
    addReason(
      reasons,
      !acknowledgedRoleRefs.includes(roleRef),
      `manual_navigation_role_effective_use_acknowledgement_missing:${roleRef}`,
    );
  }

  addReason(reasons, readiness?.effectiveUseAcknowledged !== true, 'manual_navigation_effective_use_acknowledgement_absent');
  addReason(reasons, readiness?.currentVersionOnly !== true, 'manual_navigation_current_version_boundary_invalid');
  addReason(reasons, readiness?.obsoleteVersionUseBlocked !== true, 'manual_navigation_obsolete_version_boundary_invalid');
  addReason(reasons, readiness?.metadataOnly !== true, 'manual_navigation_metadata_boundary_invalid');
  addReason(reasons, readiness?.protectedContentExcluded !== true, 'manual_navigation_protected_boundary_invalid');
  addReason(reasons, readiness?.productionTrustClaim === true, 'manual_navigation_production_claim_forbidden');
  addReason(reasons, hlcTuple(readiness?.distributionPublishedAtHlc) === null, 'manual_navigation_distribution_time_invalid');
  addReason(
    reasons,
    hlcAfter(readiness?.distributionPublishedAtHlc, cycle?.navigationCapturedAtHlc),
    'manual_navigation_distribution_after_capture',
  );
  addReason(reasons, contextualDrawerStates.length === 0, 'manual_navigation_contextual_drawer_state_absent');

  for (const state of contextualDrawerStates) {
    const label = navigationLabel(state, 0);
    addReason(
      reasons,
      hasText(readiness?.contextualManualDrawerHash) &&
        hasText(state?.targetArtifactHash) &&
        readiness.contextualManualDrawerHash !== state.targetArtifactHash,
      `manual_navigation_contextual_drawer_target_mismatch:${label}`,
    );
  }

  return {
    acknowledgedRoleRefs,
    acknowledgementRosterHash: readiness?.acknowledgementRosterHash ?? null,
    contextualManualDrawerHash: readiness?.contextualManualDrawerHash ?? null,
    contextualManualDrawerReceiptHash: readiness?.contextualManualDrawerReceiptHash ?? null,
    controlledDocumentDistributionReceiptHash:
      readiness?.controlledDocumentDistributionReceiptHash ?? null,
    controlledDocumentDistributionRecordId: readiness?.controlledDocumentDistributionRecordId ?? null,
    currentVersionOnly: readiness?.currentVersionOnly === true,
    distributionPublishedAtHlc: readiness?.distributionPublishedAtHlc ?? null,
    documentationPublicationReceiptHash: readiness?.documentationPublicationReceiptHash ?? null,
    effectiveUseAcknowledged: readiness?.effectiveUseAcknowledged === true,
    manualExportReceiptHash: readiness?.manualExportReceiptHash ?? null,
    navigationRoleRefs,
    obsoleteVersionUseBlocked: readiness?.obsoleteVersionUseBlocked === true,
    requiredAcknowledgementRoleRefs,
    roleManualCoverageReceiptHash: readiness?.roleManualCoverageReceiptHash ?? null,
  };
}

function signalLabel(signal, index) {
  return hasText(signal?.signalRef) ? signal.signalRef : `friction_${index}`;
}

function evaluateFrictionSignals(signals, navigationRefs, cycle, reasons) {
  const rows = Array.isArray(signals) ? [...signals] : [];
  const summaries = rows
    .sort((left, right) => String(left?.signalRef ?? '').localeCompare(String(right?.signalRef ?? '')))
    .map((signal, index) => {
      const label = signalLabel(signal, index);
      const affectedRoleRefs = sortedTextList(signal?.affectedRoleRefs);
      addReason(reasons, !hasText(signal?.signalRef), `friction_signal_ref_absent:${label}`);
      addReason(reasons, !REQUIRED_FRICTION_FAMILIES.includes(signal?.signalFamily), `friction_family_unsupported:${label}`);
      addReason(reasons, !hasText(signal?.sourceNavigationRef), `friction_source_navigation_absent:${label}`);
      addReason(
        reasons,
        hasText(signal?.sourceNavigationRef) && !navigationRefs.has(signal.sourceNavigationRef),
        `friction_source_navigation_unknown:${label}`,
      );
      addReason(reasons, !isDigest(signal?.signalHash), `friction_signal_hash_invalid:${label}`);
      addReason(reasons, !isPositiveSafeInteger(signal?.eventCount), `friction_event_count_invalid:${label}`);
      addReason(reasons, affectedRoleRefs.length === 0, `friction_affected_roles_absent:${label}`);
      addReason(reasons, !SIGNAL_SEVERITIES.has(signal?.severity), `friction_severity_invalid:${label}`);
      addReason(reasons, typeof signal?.requiresCqi !== 'boolean', `friction_cqi_flag_invalid:${label}`);
      addReason(
        reasons,
        (signal?.severity === 'critical' || signal?.severity === 'major') && signal?.requiresCqi !== true,
        `friction_severity_cqi_required:${label}`,
      );
      addReason(reasons, signal?.participantLinked !== false, `friction_participant_link_forbidden:${label}`);
      addReason(reasons, signal?.metadataOnly !== true, `friction_metadata_boundary_invalid:${label}`);
      addReason(reasons, signal?.protectedContentExcluded !== true, `friction_protected_boundary_invalid:${label}`);
      addReason(reasons, hlcTuple(signal?.detectedAtHlc) === null, `friction_detected_time_invalid:${label}`);
      addReason(reasons, hlcBefore(signal?.detectedAtHlc, cycle?.frictionAnalyzedAtHlc), `friction_detected_before_analysis:${label}`);

      return {
        affectedRoleRefs,
        eventCount: signal?.eventCount ?? 0,
        requiresCqi: signal?.requiresCqi === true,
        severity: signal?.severity ?? null,
        signalFamily: signal?.signalFamily ?? null,
        signalHash: signal?.signalHash ?? null,
        signalRef: label,
        sourceNavigationRef: signal?.sourceNavigationRef ?? null,
      };
    });

  const actualFamilies = uniqueSorted(summaries.map((signal) => signal.signalFamily).filter(hasText));
  evaluateRequiredSet(
    actualFamilies,
    REQUIRED_FRICTION_FAMILIES,
    'friction_family_missing',
    'friction_family_unsupported',
    reasons,
  );

  return {
    actualFamilies,
    summaries,
    totalFrictionEvents: summaries.reduce((total, signal) => total + signal.eventCount, 0),
  };
}

function cqiRequiredSignals(signals) {
  return signals
    .filter((signal) => signal.requiresCqi || signal.severity === 'critical' || signal.severity === 'major')
    .map((signal) => signal.signalRef)
    .sort();
}

function evaluateCqiRouting(routing, requiredSignalRefs, cycle, reasons) {
  const routedSignalRefs = sortedTextList(routing?.routedSignalRefs);
  addReason(reasons, !hasText(routing?.routeRef), 'cqi_route_ref_absent');
  addReason(reasons, !CQI_DESTINATIONS.has(routing?.destination), 'cqi_destination_invalid');
  addReason(reasons, !hasText(routing?.qualityOwnerRoleRef), 'cqi_quality_owner_role_absent');
  addReason(reasons, !isDigest(routing?.frictionTagSetHash), 'cqi_friction_tag_set_hash_invalid');
  addReason(reasons, !isDigest(routing?.cqiActionPolicyHash), 'cqi_action_policy_hash_invalid');
  addReason(reasons, !isDigest(routing?.noRetaliationReminderHash), 'cqi_no_retaliation_hash_invalid');
  addReason(reasons, routing?.permitsAnonymousInquiry !== true, 'cqi_anonymous_route_missing');
  addReason(reasons, routing?.metadataOnly !== true, 'cqi_route_metadata_boundary_invalid');
  addReason(reasons, routing?.protectedContentExcluded !== true, 'cqi_route_protected_boundary_invalid');
  addReason(reasons, hlcTuple(routing?.routedAtHlc) === null, 'cqi_route_recorded_time_invalid');
  addReason(reasons, hlcBefore(routing?.routedAtHlc, cycle?.cqiRoutedAtHlc), 'cqi_route_recorded_before_cycle_step');

  for (const signalRef of requiredSignalRefs) {
    addReason(reasons, !routedSignalRefs.includes(signalRef), `cqi_route_missing_required_signal:${signalRef}`);
  }

  return routedSignalRefs;
}

function evaluateAccessibilityReview(review, cycle, reasons) {
  addReason(reasons, !hasText(review?.reviewRef), 'accessibility_review_ref_absent');
  addReason(reasons, !isDigest(review?.reviewHash), 'accessibility_review_hash_invalid');
  addReason(reasons, review?.keyboardNavigationVerified !== true, 'accessibility_keyboard_navigation_missing');
  addReason(reasons, review?.screenReaderNavigationVerified !== true, 'accessibility_screen_reader_navigation_missing');
  addReason(reasons, review?.statusIndicatorsVerified !== true, 'accessibility_status_indicators_missing');
  addReason(reasons, review?.roleSpecificNavigationVerified !== true, 'accessibility_role_navigation_missing');
  addReason(reasons, review?.metadataOnly !== true, 'accessibility_review_metadata_boundary_invalid');
  addReason(reasons, review?.protectedContentExcluded !== true, 'accessibility_review_protected_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'accessibility_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, cycle?.frictionAnalyzedAtHlc), 'accessibility_review_before_friction_analysis');
}

function evaluateAiAssistant(aiAssistant, cycle, reasons) {
  if (aiAssistant === null || aiAssistant === undefined || aiAssistant?.used !== true) {
    return false;
  }
  addReason(reasons, !hasText(aiAssistant?.assistantRef), 'ai_assistance_ref_absent');
  addReason(reasons, !isDigest(aiAssistant?.promptPolicyHash), 'ai_assistance_prompt_policy_hash_invalid');
  addReason(reasons, !isDigest(aiAssistant?.outputHash), 'ai_assistance_output_hash_invalid');
  addReason(
    reasons,
    sortedTextList(aiAssistant?.limitationHashes).filter(isDigest).length === 0,
    'ai_assistance_limitation_hashes_absent',
  );
  addReason(
    reasons,
    !isDigest(aiAssistant?.unresolvedQuestionRoutingHash),
    'ai_assistance_unresolved_question_route_hash_invalid',
  );
  addReason(reasons, !isBasisPoints(aiAssistant?.confidenceFloorBasisPoints), 'ai_assistance_confidence_floor_invalid');
  addReason(reasons, aiAssistant?.advisoryOnly !== true, 'ai_assistance_not_advisory');
  addReason(reasons, aiAssistant?.finalAuthority === true, 'ai_assistance_final_authority_forbidden');
  addReason(reasons, aiAssistant?.humanReviewed !== true, 'ai_assistance_human_review_absent');
  addReason(reasons, aiAssistant?.metadataOnly !== true, 'ai_assistance_metadata_boundary_invalid');
  addReason(reasons, aiAssistant?.protectedContentExcluded !== true, 'ai_assistance_protected_boundary_invalid');
  addReason(reasons, hlcTuple(aiAssistant?.reviewedAtHlc) === null, 'ai_assistance_review_time_invalid');
  addReason(reasons, hlcBefore(aiAssistant?.reviewedAtHlc, cycle?.frictionAnalyzedAtHlc), 'ai_assistance_review_before_friction_analysis');
  return true;
}

function evaluateHumanReview(review, cycle, reasons) {
  const reviewerRoles = sortedTextList(review?.reviewerRoleRefs);
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, reviewerRoles.length === 0, 'human_reviewer_roles_absent');
  addReason(reasons, !HUMAN_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_final_authority_absent');
  addReason(reasons, review?.aiFinalAuthority === true, 'human_review_ai_final_authority_forbidden');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'human_review_production_trust_claim_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, cycle?.humanReviewedAtHlc), 'human_review_before_cycle_human_step');
}

function createAnalyticsDigest(
  input,
  navigationSummary,
  frictionSummary,
  routedSignalRefs,
  frictionRateBasisPoints,
  manualNavigationReadiness,
) {
  return sha256Hex({
    accessibilityReviewHash: input?.accessibilityReview?.reviewHash ?? null,
    acknowledgementRosterHash: manualNavigationReadiness.acknowledgementRosterHash,
    contextualManualDrawerHash: manualNavigationReadiness.contextualManualDrawerHash,
    contextualManualDrawerReceiptHash: manualNavigationReadiness.contextualManualDrawerReceiptHash,
    controlledDocumentDistributionReceiptHash: manualNavigationReadiness.controlledDocumentDistributionReceiptHash,
    cqiActionPolicyHash: input?.cqiRouting?.cqiActionPolicyHash ?? null,
    cycleRef: input?.assistanceCycle?.cycleRef ?? null,
    frictionFamilies: frictionSummary.actualFamilies,
    frictionRateBasisPoints,
    manualExportReceiptHash: manualNavigationReadiness.manualExportReceiptHash,
    manualIndexHash: input?.manualIndex?.currentManualSetHash ?? null,
    navigationFamilies: navigationSummary.actualFamilies,
    routedSignalRefs,
    roleManualCoverageReceiptHash: manualNavigationReadiness.roleManualCoverageReceiptHash,
    tenantId: input?.tenantId ?? null,
  });
}

function createAssistanceAnalytics(
  input,
  finalReasons,
  navigationSummary,
  frictionSummary,
  routedSignalRefs,
  aiAssistanceUsed,
  manualNavigationReadiness,
) {
  const frictionRateBasisPoints = basisPoints(
    frictionSummary.totalFrictionEvents,
    navigationSummary.totalNavigationEvents,
  );
  const analyticsDigest = createAnalyticsDigest(
    input,
    navigationSummary,
    frictionSummary,
    routedSignalRefs,
    frictionRateBasisPoints,
    manualNavigationReadiness,
  );

  return {
    schema: USER_ASSISTANCE_SCHEMA,
    ready: finalReasons.length === 0,
    trustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    analyticsDigest,
    tenantId: input?.tenantId ?? null,
    cycleRef: input?.assistanceCycle?.cycleRef ?? null,
    navigationFamilies: navigationSummary.actualFamilies,
    frictionFamilies: frictionSummary.actualFamilies,
    missingNavigationStates: missingValues(REQUIRED_NAVIGATION_STATES, navigationSummary.actualFamilies),
    missingFrictionFamilies: missingValues(REQUIRED_FRICTION_FAMILIES, frictionSummary.actualFamilies),
    navigationStateCount: navigationSummary.summaries.length,
    frictionSignalCount: frictionSummary.summaries.length,
    totalNavigationEvents: navigationSummary.totalNavigationEvents,
    totalBlockedNavigationEvents: navigationSummary.totalBlockedNavigationEvents,
    totalFrictionEvents: frictionSummary.totalFrictionEvents,
    frictionRateBasisPoints,
    cqiRoutedSignalRefs: routedSignalRefs,
    cqiRequired: cqiRequiredSignals(frictionSummary.summaries).length > 0,
    aiAssistanceUsed,
    manualNavigationReady: finalReasons.length === 0,
    contextualManualDrawerHash: manualNavigationReadiness.contextualManualDrawerHash,
    contextualManualDrawerReceiptHash: manualNavigationReadiness.contextualManualDrawerReceiptHash,
    controlledDocumentDistributionReceiptHash: manualNavigationReadiness.controlledDocumentDistributionReceiptHash,
    controlledDocumentDistributionRecordId: manualNavigationReadiness.controlledDocumentDistributionRecordId,
    documentationPublicationReceiptHash: manualNavigationReadiness.documentationPublicationReceiptHash,
    manualExportReceiptHash: manualNavigationReadiness.manualExportReceiptHash,
    roleManualCoverageReceiptHash: manualNavigationReadiness.roleManualCoverageReceiptHash,
    manualNavigationAcknowledgedRoleRefs: manualNavigationReadiness.acknowledgedRoleRefs,
    manualNavigationRequiredAcknowledgementRoleRefs: manualNavigationReadiness.requiredAcknowledgementRoleRefs,
    manualNavigationRoleRefs: manualNavigationReadiness.navigationRoleRefs,
    manualNavigationCurrentVersionOnly: manualNavigationReadiness.currentVersionOnly,
    manualNavigationObsoleteVersionUseBlocked: manualNavigationReadiness.obsoleteVersionUseBlocked,
    manualNavigationEffectiveUseAcknowledged: manualNavigationReadiness.effectiveUseAcknowledged,
    reviewerDid: input?.humanReview?.reviewerDid ?? null,
    receiptRecordedAtHlc: input?.assistanceCycle?.receiptRecordedAtHlc ?? null,
    sourceEvidence: [
      'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
      'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
      'docs/context/CYBERMEDICA_ADJACENT_SURFACE_DECISIONS.md',
    ],
  };
}

function buildReceipt(input, assistanceAnalytics) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: assistanceAnalytics.analyticsDigest,
    artifactType: 'user_assistance_friction_analytics',
    artifactVersion: input.assistanceCycle.cycleRef,
    classification: 'metadata_only_user_assistance',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.assistanceCycle.receiptRecordedAtHlc,
    sensitivityTags: [
      'documentation_assistance_metadata',
      'friction_analytics',
      'manual_navigation_readiness',
      'no_raw_content',
    ],
    sourceSystem: 'cybermedica',
    tenantId: input.tenantId,
  });
}

export function evaluateUserAssistanceAnalytics(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateAssistancePolicy(input?.assistancePolicy, reasons);
  evaluateAssistanceCycle(input?.assistanceCycle, input?.assistancePolicy, input?.humanReview, reasons);
  evaluateManualIndex(input?.manualIndex, input?.assistanceCycle, reasons);
  const navigationSummary = evaluateNavigationStates(input?.navigationStates, input?.assistanceCycle, reasons);
  const manualNavigationReadiness = evaluateManualNavigationReadiness(
    input?.manualNavigationReadiness,
    input?.navigationStates,
    input?.assistanceCycle,
    reasons,
  );
  const frictionSummary = evaluateFrictionSignals(
    input?.frictionSignals,
    navigationSummary.navigationRefs,
    input?.assistanceCycle,
    reasons,
  );
  const routedSignalRefs = evaluateCqiRouting(
    input?.cqiRouting,
    cqiRequiredSignals(frictionSummary.summaries),
    input?.assistanceCycle,
    reasons,
  );
  evaluateAccessibilityReview(input?.accessibilityReview, input?.assistanceCycle, reasons);
  const aiAssistanceUsed = evaluateAiAssistant(input?.aiAssistant, input?.assistanceCycle, reasons);
  evaluateHumanReview(input?.humanReview, input?.assistanceCycle, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const finalReasons = uniqueReasons(reasons);
  const assistanceAnalytics = createAssistanceAnalytics(
    input,
    finalReasons,
    navigationSummary,
    frictionSummary,
    routedSignalRefs,
    aiAssistanceUsed,
    manualNavigationReadiness,
  );

  if (finalReasons.length > 0) {
    return {
      schema: USER_ASSISTANCE_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: finalReasons,
      assistanceAnalytics,
      receipt: null,
    };
  }

  return {
    schema: USER_ASSISTANCE_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    assistanceAnalytics,
    receipt: buildReceipt(input, assistanceAnalytics),
  };
}
