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
const DRIFT_SCHEMA = 'cybermedica.drift_improvement_loop.v1';
const REQUIRED_PERMISSION = 'drift_manage';
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const POLICY_STATUSES = new Set(['active']);
const ACTOR_KINDS = new Set(['human', 'service_account']);
const RISK_LEVELS = new Set(['critical', 'major', 'minor', 'standard']);
const URGENCY_LEVELS = new Set(['deferred', 'standard', 'urgent']);
const EFFECTIVENESS_STATUSES = new Set(['effective', 'follow_up_scheduled', 'ineffective']);
const STATE_UPDATE_TARGETS = ['passport', 'quality_state', 'readiness'];
const REQUIRED_SIGNAL_FAMILIES = [
  'ai_finding',
  'audit',
  'capa_trend',
  'concern',
  'consent_supersession',
  'deviation',
  'equipment_expiration',
  'evidence_aging',
  'protocol_amendment',
  'sponsor_expectation',
  'staff_change',
  'stakeholder_feedback',
  'training_gap',
];
const SUPPORTED_SIGNAL_FAMILIES = new Set([
  ...REQUIRED_SIGNAL_FAMILIES,
  'incident',
  'kpi_trend',
  'open_question',
  'risk_trigger',
  'user_friction',
]);
const SUPPORTED_ACTION_TYPES = new Set([
  'capa',
  'cqi',
  'documentation_update',
  'passport_update',
  'quality_state_update',
  'readiness_update',
  'risk_reassessment',
  'system_change',
  'training_update',
  'workflow_change',
]);

const RAW_DRIFT_FIELDS = new Set([
  'ainewsuggestiontext',
  'auditfindingbody',
  'capanarrative',
  'concernnarrative',
  'content',
  'deviationdescription',
  'driftnarrative',
  'evidencebody',
  'feedbacktext',
  'freetext',
  'freetextnote',
  'incidentnarrative',
  'participantlisting',
  'protocoltext',
  'rawcontent',
  'rawdriftnarrative',
  'rawfinding',
  'rawrecommendation',
  'rawsignal',
  'rawsource',
  'rawsourcedata',
  'reviewnotes',
  'sponsorrequesttext',
  'stakeholdercomment',
  'trainingrecordbody',
]);
const SECRET_DRIFT_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credentialsecret',
  'password',
  'privatekey',
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

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
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

function assertNoRawDriftContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawDriftContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_DRIFT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw drift content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_DRIFT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`drift secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawDriftContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawDriftContent(input ?? {});
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

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function signalLabel(signal, index = null) {
  if (hasText(signal?.signalRef)) {
    return signal.signalRef;
  }
  return index === null ? 'unknown' : `index_${index}`;
}

function actionLabel(action, index = null) {
  if (hasText(action?.actionRef)) {
    return action.actionRef;
  }
  return index === null ? 'unknown' : `index_${index}`;
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, !ACTOR_KINDS.has(input?.actor?.kind), 'drift_actor_kind_invalid');
  addReason(
    reasons,
    input?.actor?.kind === 'service_account' && !hasText(input?.actor?.humanOwnerDid),
    'service_account_human_owner_absent',
  );
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'drift_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(policy, reasons) {
  const requiredFamilies = sortedTextList(policy?.requiredSignalFamilies);
  const allowedActions = sortedTextList(policy?.allowedActionTypes);

  addReason(reasons, !hasText(policy?.policyRef), 'drift_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'drift_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'drift_policy_not_active');
  addReason(reasons, policy?.materialDecisionForumRequired !== true, 'drift_policy_material_forum_rule_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'drift_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'drift_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'drift_policy_time_invalid');

  for (const family of REQUIRED_SIGNAL_FAMILIES) {
    addReason(reasons, !requiredFamilies.includes(family), `drift_policy_required_family_missing:${family}`);
  }
  for (const family of requiredFamilies) {
    addReason(reasons, !SUPPORTED_SIGNAL_FAMILIES.has(family), `drift_policy_signal_family_unsupported:${family}`);
  }
  for (const actionType of allowedActions) {
    addReason(reasons, !SUPPORTED_ACTION_TYPES.has(actionType), `drift_policy_action_type_unsupported:${actionType}`);
  }

  return { allowedActions, requiredFamilies };
}

function evaluateCycle(cycle, policy, reasons) {
  addReason(reasons, !hasText(cycle?.cycleRef), 'drift_cycle_ref_absent');
  addReason(reasons, !hasText(cycle?.siteRef), 'drift_cycle_site_ref_absent');
  addReason(reasons, cycle?.metadataOnly !== true, 'drift_cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'drift_cycle_protected_boundary_invalid');
  addReason(reasons, cycle?.exochainProductionClaim === true, 'production_trust_claim_forbidden');

  const ordered = [
    ['openedAtHlc', cycle?.openedAtHlc],
    ['classifiedAtHlc', cycle?.classifiedAtHlc],
    ['ownerAssignedAtHlc', cycle?.ownerAssignedAtHlc],
    ['reviewPathIdentifiedAtHlc', cycle?.reviewPathIdentifiedAtHlc],
    ['improvementCreatedAtHlc', cycle?.improvementCreatedAtHlc],
    ['effectivenessCheckedAtHlc', cycle?.effectivenessCheckedAtHlc],
    ['stateUpdatedAtHlc', cycle?.stateUpdatedAtHlc],
    ['auditRecordedAtHlc', cycle?.auditRecordedAtHlc],
  ];

  for (const [label, value] of ordered) {
    addReason(reasons, hlcTuple(value) === null, `drift_cycle_${label}_invalid`);
  }
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, cycle?.openedAtHlc), 'drift_policy_after_cycle_open');
  for (let index = 1; index < ordered.length; index += 1) {
    const [previousLabel, previousValue] = ordered[index - 1];
    const [currentLabel, currentValue] = ordered[index];
    addReason(
      reasons,
      hlcBefore(currentValue, previousValue),
      `drift_cycle_${currentLabel}_before_${previousLabel}`,
    );
  }
}

function isMaterialSignal(signal) {
  return signal?.riskLevel === 'critical' || signal?.urgency === 'urgent' || signal?.participantSafetyImpact === true;
}

function evaluateSignals(signals, requiredFamilies, cycle, reasons) {
  addReason(reasons, !Array.isArray(signals) || signals.length === 0, 'drift_signals_absent');
  if (!Array.isArray(signals)) {
    return { signalRefs: [], materialSignalRefs: [], signalFamilies: [] };
  }

  const seenRefs = new Set();
  const signalFamilies = sortedTextList(signals.map((signal) => signal?.signalFamily));
  const signalRefs = sortedTextList(signals.map((signal) => signal?.signalRef));
  const materialSignalRefs = [];

  for (const family of requiredFamilies) {
    addReason(reasons, !signalFamilies.includes(family), `drift_signal_family_missing:${family}`);
  }

  signals.forEach((signal, index) => {
    const label = signalLabel(signal, index);
    addReason(reasons, !hasText(signal?.signalRef), `drift_signal_ref_absent:${label}`);
    addReason(reasons, seenRefs.has(signal?.signalRef), `drift_signal_ref_duplicate:${label}`);
    if (hasText(signal?.signalRef)) {
      seenRefs.add(signal.signalRef);
    }
    addReason(reasons, !SUPPORTED_SIGNAL_FAMILIES.has(signal?.signalFamily), `drift_signal_family_unsupported:${label}`);
    addReason(reasons, !hasText(signal?.sourceRef), `drift_signal_source_ref_absent:${label}`);
    addReason(reasons, !hasText(signal?.sourceFamily), `drift_signal_source_family_absent:${label}`);
    addReason(reasons, !isDigest(signal?.sourceHash), `drift_signal_source_hash_invalid:${label}`);
    addReason(reasons, hlcTuple(signal?.detectedAtHlc) === null, `drift_signal_time_invalid:${label}`);
    addReason(reasons, sortedTextList(signal?.affectedControlRefs).length === 0, `drift_signal_controls_absent:${label}`);
    addReason(reasons, !RISK_LEVELS.has(signal?.riskLevel), `drift_signal_risk_level_invalid:${label}`);
    addReason(reasons, !URGENCY_LEVELS.has(signal?.urgency), `drift_signal_urgency_invalid:${label}`);
    addReason(
      reasons,
      !Number.isSafeInteger(signal?.riskScoreBasisPoints) ||
        signal.riskScoreBasisPoints < 0 ||
        signal.riskScoreBasisPoints > 10000,
      `drift_signal_risk_score_invalid:${label}`,
    );
    addReason(reasons, signal?.humanVisible !== true, `drift_signal_visibility_absent:${label}`);
    addReason(reasons, signal?.reviewable !== true, `drift_signal_reviewability_absent:${label}`);
    addReason(reasons, signal?.metadataOnly !== true, `drift_signal_metadata_boundary_invalid:${label}`);
    addReason(reasons, signal?.protectedContentExcluded !== true, `drift_signal_protected_boundary_invalid:${label}`);
    if (isMaterialSignal(signal)) {
      materialSignalRefs.push(signal.signalRef);
    }
  });

  return {
    materialSignalRefs: uniqueSorted(materialSignalRefs),
    signalFamilies,
    signalRefs,
  };
}

function evaluateOwnerAssignments(assignments, signalRefs, cycle, reasons) {
  addReason(reasons, !Array.isArray(assignments) || assignments.length === 0, 'drift_owner_assignments_absent');
  if (!Array.isArray(assignments)) {
    return { allSignalsOwned: false, ownedSignalRefs: [] };
  }

  const assignmentsBySignal = new Map();
  assignments.forEach((assignment) => {
    if (hasText(assignment?.signalRef)) {
      assignmentsBySignal.set(assignment.signalRef, assignment);
    }
  });

  for (const signalRef of signalRefs) {
    addReason(reasons, !assignmentsBySignal.has(signalRef), `drift_signal_owner_absent:${signalRef}`);
  }

  assignments.forEach((assignment, index) => {
    const label = hasText(assignment?.signalRef) ? assignment.signalRef : `index_${index}`;
    addReason(reasons, !hasText(assignment?.signalRef), `drift_assignment_signal_ref_absent:${label}`);
    addReason(reasons, !hasText(assignment?.ownerRoleRef), `drift_assignment_owner_role_absent:${label}`);
    addReason(reasons, !isDigest(assignment?.ownerDidHash), `drift_assignment_owner_hash_invalid:${label}`);
    addReason(reasons, assignment?.metadataOnly !== true, `drift_assignment_metadata_boundary_invalid:${label}`);
    addReason(reasons, hlcTuple(assignment?.assignedAtHlc) === null, `drift_assignment_time_invalid:${label}`);
    addReason(reasons, hlcTuple(assignment?.acceptedAtHlc) === null, `drift_assignment_acceptance_time_invalid:${label}`);
    addReason(reasons, hlcTuple(assignment?.dueAtHlc) === null, `drift_assignment_due_time_invalid:${label}`);
    addReason(reasons, hlcBefore(assignment?.assignedAtHlc, cycle?.ownerAssignedAtHlc), `drift_assignment_before_cycle_owner_step:${label}`);
    addReason(reasons, hlcBefore(assignment?.acceptedAtHlc, assignment?.assignedAtHlc), `drift_assignment_accepted_before_assigned:${label}`);
    addReason(reasons, hlcBefore(assignment?.dueAtHlc, assignment?.acceptedAtHlc), `drift_assignment_due_before_acceptance:${label}`);
  });

  return {
    allSignalsOwned: signalRefs.every((signalRef) => assignmentsBySignal.has(signalRef)),
    ownedSignalRefs: sortedTextList([...assignmentsBySignal.keys()]),
  };
}

function evaluateReviewPath(reviewPath, materialSignalRefs, signals, cycle, policy, reasons) {
  const reviewedMaterialRefs = sortedTextList(reviewPath?.materialSignalRefs);
  const decisionForumMatterRefs = sortedTextList(reviewPath?.decisionForumMatterRefs);
  const participantSafetyRequired = signals.some((signal) => signal?.participantSafetyImpact === true);
  const dataIntegrityRequired = signals.some((signal) => signal?.dataIntegrityImpact === true);
  const sponsorCroRequired = signals.some((signal) => signal?.sponsorCroImpact === true);
  const decisionForumRequired = policy?.materialDecisionForumRequired === true && materialSignalRefs.length > 0;

  addReason(reasons, !hasText(reviewPath?.pathRef), 'drift_review_path_ref_absent');
  addReason(reasons, !isDigest(reviewPath?.pathHash), 'drift_review_path_hash_invalid');
  addReason(reasons, sortedTextList(reviewPath?.requiredEvidenceRefs).length === 0, 'drift_review_required_evidence_absent');
  addReason(reasons, sortedTextList(reviewPath?.reviewerRoleRefs).length === 0, 'drift_reviewer_roles_absent');
  addReason(reasons, reviewPath?.metadataOnly !== true, 'drift_review_path_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(reviewPath?.reviewedAtHlc) === null, 'drift_review_path_time_invalid');
  addReason(reasons, hlcBefore(reviewPath?.reviewedAtHlc, cycle?.reviewPathIdentifiedAtHlc), 'drift_review_before_cycle_review_step');
  addReason(reasons, participantSafetyRequired && reviewPath?.participantSafetyReviewed !== true, 'participant_safety_review_absent');
  addReason(reasons, dataIntegrityRequired && reviewPath?.dataIntegrityReviewed !== true, 'data_integrity_review_absent');
  addReason(reasons, sponsorCroRequired && reviewPath?.sponsorCroReviewed !== true, 'sponsor_cro_review_absent');
  addReason(
    reasons,
    decisionForumRequired && (reviewPath?.decisionForumInvoked !== true || decisionForumMatterRefs.length === 0),
    'material_decision_forum_absent',
  );

  for (const signalRef of materialSignalRefs) {
    addReason(reasons, !reviewedMaterialRefs.includes(signalRef), `material_signal_review_absent:${signalRef}`);
  }

  return {
    decisionForumInvoked: reviewPath?.decisionForumInvoked === true,
    decisionForumRequired,
    reviewedMaterialRefs,
  };
}

function evaluateImprovementActions(actions, signals, requiredFamilies, allowedActions, cycle, reasons) {
  addReason(reasons, !Array.isArray(actions) || actions.length === 0, 'drift_actions_absent');
  if (!Array.isArray(actions)) {
    return { actionTypes: [], allSignalsActioned: false, actionSummaries: [] };
  }

  const signalFamilies = new Map(signals.map((signal) => [signal.signalFamily, signal.signalRef]));
  const actionedSignalRefs = new Set();
  const actionTypes = [];
  const actionSummaries = [];
  const seenActions = new Set();

  for (const family of requiredFamilies) {
    const signalRef = signalFamilies.get(family) ?? `signal-${family}`;
    if (!signalFamilies.has(family)) {
      addReason(reasons, true, `drift_signal_action_absent:${signalRef}`);
    }
  }

  actions.forEach((action, index) => {
    const label = actionLabel(action, index);
    const linkedSignalRefs = sortedTextList(action?.linkedSignalRefs);
    addReason(reasons, !hasText(action?.actionRef), `drift_action_ref_absent:${label}`);
    addReason(reasons, seenActions.has(action?.actionRef), `drift_action_ref_duplicate:${label}`);
    if (hasText(action?.actionRef)) {
      seenActions.add(action.actionRef);
    }
    addReason(reasons, !SUPPORTED_ACTION_TYPES.has(action?.actionType), `drift_action_type_unsupported:${label}`);
    addReason(reasons, !allowedActions.includes(action?.actionType), `drift_action_type_not_allowed:${label}`);
    addReason(reasons, linkedSignalRefs.length === 0, `drift_action_signals_absent:${label}`);
    addReason(reasons, !hasText(action?.ownerRoleRef), `drift_action_owner_role_absent:${label}`);
    addReason(reasons, !isDigest(action?.implementationTrackingHash), `drift_action_tracking_hash_invalid:${label}`);
    addReason(reasons, !isDigest(action?.effectivenessCheckHash), `drift_action_effectiveness_hash_invalid:${label}`);
    addReason(reasons, !EFFECTIVENESS_STATUSES.has(action?.effectivenessStatus), `drift_action_effectiveness_status_invalid:${label}`);
    addReason(reasons, !isDigest(action?.stateUpdateHash), `drift_action_state_update_hash_invalid:${label}`);
    addReason(reasons, action?.metadataOnly !== true, `drift_action_metadata_boundary_invalid:${label}`);
    addReason(reasons, hlcTuple(action?.openedAtHlc) === null, `drift_action_opened_time_invalid:${label}`);
    addReason(reasons, hlcTuple(action?.implementedAtHlc) === null, `drift_action_implemented_time_invalid:${label}`);
    addReason(reasons, hlcTuple(action?.effectivenessCheckedAtHlc) === null, `drift_action_effectiveness_time_invalid:${label}`);
    addReason(reasons, hlcTuple(action?.stateUpdatedAtHlc) === null, `drift_action_state_update_time_invalid:${label}`);
    addReason(reasons, hlcBefore(action?.openedAtHlc, cycle?.improvementCreatedAtHlc), `drift_action_opened_before_cycle_action_step:${label}`);
    addReason(reasons, hlcBefore(action?.implementedAtHlc, action?.openedAtHlc), `drift_action_implemented_before_opened:${label}`);
    addReason(
      reasons,
      hlcBefore(action?.effectivenessCheckedAtHlc, action?.implementedAtHlc),
      `drift_action_effectiveness_before_implementation:${label}`,
    );
    addReason(
      reasons,
      hlcBefore(action?.stateUpdatedAtHlc, action?.effectivenessCheckedAtHlc),
      `drift_action_state_update_before_effectiveness:${label}`,
    );

    for (const target of sortedTextList(action?.stateUpdateTargets)) {
      addReason(reasons, !STATE_UPDATE_TARGETS.includes(target), `drift_action_state_target_unsupported:${label}:${target}`);
    }
    addReason(reasons, sortedTextList(action?.stateUpdateTargets).length === 0, `drift_action_state_targets_absent:${label}`);

    for (const signalRef of linkedSignalRefs) {
      actionedSignalRefs.add(signalRef);
    }
    if (hasText(action?.actionType)) {
      actionTypes.push(action.actionType);
    }
    actionSummaries.push({
      actionRef: action.actionRef,
      actionType: action.actionType,
      effectivenessStatus: action.effectivenessStatus,
      linkedSignalRefs,
      stateUpdateTargets: sortedTextList(action?.stateUpdateTargets),
    });
  });

  for (const signal of signals) {
    addReason(reasons, !actionedSignalRefs.has(signal.signalRef), `drift_signal_action_absent:${signal.signalRef}`);
  }

  return {
    actionSummaries: actionSummaries.sort((left, right) => left.actionRef.localeCompare(right.actionRef)),
    actionTypes: uniqueSorted(actionTypes),
    allSignalsActioned: signals.every((signal) => actionedSignalRefs.has(signal.signalRef)),
  };
}

function evaluateStateUpdate(stateUpdate, cycle, reasons) {
  addReason(reasons, !hasText(stateUpdate?.updateRef), 'state_update_ref_absent');
  addReason(reasons, !isDigest(stateUpdate?.updateReceiptHash), 'state_update_receipt_hash_invalid');
  addReason(reasons, stateUpdate?.passportUpdated !== true, 'state_update_passport_absent');
  addReason(reasons, stateUpdate?.readinessUpdated !== true, 'state_update_readiness_absent');
  addReason(reasons, stateUpdate?.qualityStateUpdated !== true, 'state_update_quality_state_absent');
  addReason(reasons, stateUpdate?.metadataOnly !== true, 'state_update_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(stateUpdate?.updatedAtHlc) === null, 'state_update_time_invalid');
  addReason(reasons, hlcBefore(stateUpdate?.updatedAtHlc, cycle?.stateUpdatedAtHlc), 'state_update_before_cycle_state_step');
}

function evaluateAuditRecord(auditRecord, cycle, stateUpdate, reasons) {
  addReason(reasons, !hasText(auditRecord?.auditRecordRef), 'drift_audit_record_ref_absent');
  addReason(reasons, !isDigest(auditRecord?.auditRecordHash), 'drift_audit_record_hash_invalid');
  addReason(reasons, auditRecord?.metadataOnly !== true, 'drift_audit_record_metadata_boundary_invalid');
  addReason(reasons, auditRecord?.includesProtectedContent === true, 'drift_audit_record_protected_content_forbidden');
  addReason(reasons, hlcTuple(auditRecord?.receiptRecordedAtHlc) === null, 'drift_audit_record_time_invalid');
  addReason(reasons, hlcBefore(auditRecord?.receiptRecordedAtHlc, cycle?.auditRecordedAtHlc), 'drift_audit_record_before_cycle_audit_step');
  addReason(reasons, hlcBefore(auditRecord?.receiptRecordedAtHlc, stateUpdate?.updatedAtHlc), 'drift_audit_record_before_state_update');
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance === null || aiAssistance === undefined || aiAssistance?.used !== true) {
    return;
  }

  addReason(reasons, aiAssistance.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, aiAssistance.reviewedByHuman !== true, 'ai_human_review_absent');
  addReason(reasons, !isDigest(aiAssistance.recommendationHash), 'ai_recommendation_hash_invalid');
  addReason(reasons, sortedTextList(aiAssistance.limitationHashes).filter(isDigest).length === 0, 'ai_limitation_hashes_absent');
}

function buildStateTargets(stateUpdate) {
  const targets = [];
  if (stateUpdate?.passportUpdated === true) {
    targets.push('passport');
  }
  if (stateUpdate?.qualityStateUpdated === true) {
    targets.push('quality_state');
  }
  if (stateUpdate?.readinessUpdated === true) {
    targets.push('readiness');
  }
  return targets.sort();
}

function buildDriftLoop(input, signalFamilies, materialSignalRefs, ownerCoverage, reviewSummary, actionSummary) {
  const stateUpdateTargets = buildStateTargets(input.stateUpdate);
  const loopBasis = {
    actionSummaries: actionSummary.actionSummaries,
    auditRecordHash: input.auditRecord.auditRecordHash,
    cycleRef: input.driftCycle.cycleRef,
    materialSignalRefs,
    reviewPathHash: input.reviewPath.pathHash,
    signalFamilies,
    stateUpdateHash: input.stateUpdate.updateReceiptHash,
    tenantId: input.tenantId,
  };

  return {
    schema: DRIFT_SCHEMA,
    loopId: `cmdrift_${sha256Hex(loopBasis).slice(0, 32)}`,
    trustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    tenantId: input.tenantId,
    cycleRef: input.driftCycle.cycleRef,
    siteRef: input.driftCycle.siteRef,
    studyRef: input.driftCycle.studyRef ?? null,
    signalFamilies,
    materialSignalRefs,
    improvementActionTypes: actionSummary.actionTypes,
    stateUpdateTargets,
    ownerCoverage: {
      allSignalsOwned: ownerCoverage.allSignalsOwned,
      signalCount: signalFamilies.length,
    },
    decisionForumRequired: reviewSummary.decisionForumRequired,
    decisionForumInvoked: reviewSummary.decisionForumInvoked,
    effectivenessChecked: actionSummary.actionSummaries.every((action) => EFFECTIVENESS_STATUSES.has(action.effectivenessStatus)),
    actionSummaries: actionSummary.actionSummaries,
    reviewPathHash: input.reviewPath.pathHash,
    stateUpdateHash: input.stateUpdate.updateReceiptHash,
    auditRecordHash: input.auditRecord.auditRecordHash,
    auditRecordedAtHlc: input.auditRecord.receiptRecordedAtHlc,
  };
}

function buildReceipt(input, driftLoop) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: sha256Hex(driftLoop),
    artifactType: 'drift_improvement_loop',
    artifactVersion: 'v1',
    classification: 'restricted_metadata_only',
    custodyDigest: sha256Hex({
      actionStateUpdateHashes: driftLoop.actionSummaries.map((action) => action.actionRef),
      auditRecordHash: input.auditRecord.auditRecordHash,
      ownerSignalRefs: input.ownerAssignments.map((assignment) => assignment.signalRef).sort(),
      stateUpdateHash: input.stateUpdate.updateReceiptHash,
    }),
    hlcTimestamp: input.auditRecord.receiptRecordedAtHlc,
    sensitivityTags: ['drift_management', 'metadata_only'],
    sourceSystem: 'cybermedica',
    tenantId: input.tenantId,
  });
}

export function evaluateDriftImprovementLoop(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policySummary = evaluatePolicy(input?.driftPolicy, reasons);
  evaluateCycle(input?.driftCycle, input?.driftPolicy, reasons);
  const signals = Array.isArray(input?.signals) ? input.signals : [];
  const signalSummary = evaluateSignals(input?.signals, policySummary.requiredFamilies, input?.driftCycle, reasons);
  const ownerCoverage = evaluateOwnerAssignments(input?.ownerAssignments, signalSummary.signalRefs, input?.driftCycle, reasons);
  const reviewSummary = evaluateReviewPath(
    input?.reviewPath,
    signalSummary.materialSignalRefs,
    signals,
    input?.driftCycle,
    input?.driftPolicy,
    reasons,
  );
  const actionSummary = evaluateImprovementActions(
    input?.improvementActions,
    signals,
    policySummary.requiredFamilies,
    policySummary.allowedActions,
    input?.driftCycle,
    reasons,
  );
  evaluateStateUpdate(input?.stateUpdate, input?.driftCycle, reasons);
  evaluateAuditRecord(input?.auditRecord, input?.driftCycle, input?.stateUpdate, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      decision: 'denied',
      failClosed: true,
      reasons: unique,
    };
  }

  const driftLoop = buildDriftLoop(
    input,
    signalSummary.signalFamilies,
    signalSummary.materialSignalRefs,
    ownerCoverage,
    reviewSummary,
    actionSummary,
  );

  return {
    decision: 'permitted',
    failClosed: false,
    driftLoop,
    receipt: buildReceipt(input, driftLoop),
  };
}
