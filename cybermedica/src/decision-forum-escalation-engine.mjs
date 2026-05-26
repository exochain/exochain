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
const ENGINE_SCHEMA = 'cybermedica.decision_forum_escalation_engine.v1';
const DECISION_SCHEMA = 'cybermedica.decision_forum_escalation_engine_decision.v1';
const REQUIRED_PERMISSION = 'decision_forum_escalate';

const REQUIRED_ESCALATION_FAMILIES = Object.freeze([
  'capa_closure',
  'consent_policy_change',
  'enrollment_gate',
  'production_trust_activation',
  'protocol_launch',
  'qms_control_approval',
  'support_access_policy',
]);

const ESCALATION_FAMILIES = new Set(REQUIRED_ESCALATION_FAMILIES);
const POLICY_STATUSES = new Set(['active']);
const DECISION_CLASSES = new Set(['constitutional', 'operational', 'routine', 'strategic']);
const ROUTE_TYPES = new Set(['decision_forum']);
const RISK_LEVELS = new Set(['constitutional', 'critical', 'high', 'moderate']);
const URGENCY_LEVELS = new Set(['immediate', 'standard', 'urgent']);
const HUMAN_REVIEW_DECISIONS = new Set(['decision_forum_escalation_ready', 'hold_for_escalation_review']);

const RAW_ESCALATION_FIELDS = new Set([
  'body',
  'content',
  'decisiontext',
  'escalationnarrative',
  'freetext',
  'freetextnote',
  'matterbody',
  'mattercontent',
  'mattertext',
  'rawdecision',
  'rawdeliberation',
  'rawescalation',
  'rawescalationnarrative',
  'rawmatter',
  'rawmatterbody',
  'rawprompt',
  'rawrecommendation',
  'rawroute',
  'rawsignal',
  'reviewnotes',
  'sourcedocumentbody',
  'signalbody',
  'signalcontent',
  'signaltext',
]);

const SECRET_ESCALATION_FIELDS = new Set([
  'accesstoken',
  'adaptertoken',
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
  'servicetoken',
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

function assertNoRawEscalationContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawEscalationContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_ESCALATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw Decision Forum escalation field is not allowed at ${path}.${key}`);
    }
    if (SECRET_ESCALATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`Decision Forum escalation secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawEscalationContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawEscalationContent(input ?? {});
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

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function signalLabel(signal, index = null) {
  if (hasText(signal?.signalRef)) {
    return signal.signalRef;
  }
  return index === null ? 'unknown' : `index_${index}`;
}

function routeLabel(route, index = null) {
  if (hasText(route?.routeRef)) {
    return route.routeRef;
  }
  return index === null ? 'unknown' : `index_${index}`;
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_actor_cannot_escalate_final');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_escalation_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'decision_forum_escalation_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(policy, reasons) {
  const requiredFamilies = sortedTextList(policy?.requiredEscalationFamilies);

  addReason(reasons, !hasText(policy?.policyRef), 'escalation_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'escalation_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'escalation_policy_not_active');
  addReason(
    reasons,
    policy?.requireDecisionForumForMaterialSignals !== true,
    'material_decision_forum_escalation_policy_absent',
  );
  addReason(reasons, policy?.requireHumanFinalAuthority !== true, 'human_final_authority_policy_absent');
  addReason(reasons, policy?.requireMetadataOnlyRoutes !== true, 'metadata_only_route_policy_absent');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'escalation_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'escalation_policy_time_invalid');

  for (const family of REQUIRED_ESCALATION_FAMILIES) {
    addReason(reasons, !requiredFamilies.includes(family), `escalation_policy_family_missing:${family}`);
  }
  for (const family of requiredFamilies) {
    addReason(reasons, !ESCALATION_FAMILIES.has(family), `escalation_policy_family_unsupported:${family}`);
  }

  return {
    requiredFamilies: requiredFamilies.length > 0 ? requiredFamilies : [...REQUIRED_ESCALATION_FAMILIES],
  };
}

function evaluateCycle(cycle, reasons) {
  addReason(reasons, !hasText(cycle?.cycleRef), 'escalation_cycle_ref_absent');
  addReason(reasons, cycle?.exochainProductionClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, cycle?.metadataOnly !== true, 'escalation_cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'escalation_cycle_protected_boundary_invalid');
  addReason(reasons, hlcTuple(cycle?.openedAtHlc) === null, 'escalation_cycle_opened_time_invalid');
  addReason(reasons, hlcTuple(cycle?.signalsClassifiedAtHlc) === null, 'signals_classified_time_invalid');
  addReason(reasons, hlcTuple(cycle?.routesDeterminedAtHlc) === null, 'routes_determined_time_invalid');
  addReason(reasons, hlcTuple(cycle?.humanReviewedAtHlc) === null, 'human_reviewed_time_invalid');
  addReason(reasons, hlcTuple(cycle?.auditRecordedAtHlc) === null, 'audit_recorded_time_invalid');
  addReason(reasons, hlcBefore(cycle?.signalsClassifiedAtHlc, cycle?.openedAtHlc), 'signals_classified_before_opened');
  addReason(
    reasons,
    hlcBefore(cycle?.routesDeterminedAtHlc, cycle?.signalsClassifiedAtHlc),
    'routes_determined_before_signals_classified',
  );
  addReason(
    reasons,
    hlcBefore(cycle?.humanReviewedAtHlc, cycle?.routesDeterminedAtHlc),
    'human_review_before_routes_determined',
  );
  addReason(
    reasons,
    hlcBefore(cycle?.auditRecordedAtHlc, cycle?.humanReviewedAtHlc),
    'audit_recorded_before_human_review',
  );
}

function signalIsMaterial(signal) {
  return (
    signal?.materialDecision === true ||
    signal?.riskLevel === 'constitutional' ||
    signal?.riskLevel === 'critical' ||
    signal?.urgency === 'immediate' ||
    signal?.urgency === 'urgent' ||
    signal?.participantSafetyImpact === true ||
    signal?.consentOrAuthorityImpact === true ||
    signal?.trustActivationImpact === true
  );
}

function evaluateSignals(signals, requiredFamilies, cycle, reasons) {
  addReason(reasons, !Array.isArray(signals) || signals.length === 0, 'escalation_signals_absent');
  if (!Array.isArray(signals)) {
    return {
      materialSignals: [],
      signalByRef: new Map(),
      signalFamilies: [],
      signalRefs: [],
      signalSummaries: [],
    };
  }

  const seenSignalRefs = new Set();
  const signalByRef = new Map();
  const signalFamilies = [];
  const signalRefs = [];
  const signalSummaries = [];
  const materialSignals = [];

  for (const family of requiredFamilies) {
    addReason(
      reasons,
      !signals.some((signal) => signal?.signalFamily === family),
      `escalation_signal_family_missing:${family}`,
    );
  }

  signals.forEach((signal, index) => {
    const label = signalLabel(signal, index);
    const controlRefs = sortedTextList(signal?.controlRefs);
    addReason(reasons, !hasText(signal?.signalRef), `escalation_signal_ref_absent:${label}`);
    addReason(reasons, seenSignalRefs.has(signal?.signalRef), `escalation_signal_ref_duplicate:${label}`);
    if (hasText(signal?.signalRef)) {
      seenSignalRefs.add(signal.signalRef);
      signalByRef.set(signal.signalRef, signal);
      signalRefs.push(signal.signalRef);
    }
    addReason(reasons, !ESCALATION_FAMILIES.has(signal?.signalFamily), `escalation_signal_family_unsupported:${label}`);
    addReason(
      reasons,
      hasText(signal?.signalFamily) && !requiredFamilies.includes(signal.signalFamily),
      `escalation_signal_family_not_allowed:${label}`,
    );
    addReason(reasons, !hasText(signal?.sourceWorkflowRef), `escalation_signal_source_workflow_absent:${label}`);
    addReason(reasons, !isDigest(signal?.sourceArtifactHash), `escalation_signal_source_hash_invalid:${label}`);
    addReason(reasons, controlRefs.length === 0, `escalation_signal_control_refs_absent:${label}`);
    addReason(reasons, !RISK_LEVELS.has(signal?.riskLevel), `escalation_signal_risk_level_invalid:${label}`);
    addReason(reasons, !URGENCY_LEVELS.has(signal?.urgency), `escalation_signal_urgency_invalid:${label}`);
    addReason(reasons, signal?.materialDecision !== true, `material_signal_flag_absent:${label}`);
    addReason(
      reasons,
      !DECISION_CLASSES.has(signal?.recommendedDecisionClass),
      `recommended_decision_class_invalid:${label}`,
    );
    addReason(reasons, signal?.metadataOnly !== true, `escalation_signal_metadata_boundary_invalid:${label}`);
    addReason(reasons, signal?.protectedContentExcluded !== true, `escalation_signal_protected_boundary_invalid:${label}`);
    addReason(reasons, hlcTuple(signal?.detectedAtHlc) === null, `escalation_signal_detected_time_invalid:${label}`);
    addReason(
      reasons,
      hlcBefore(signal?.detectedAtHlc, cycle?.openedAtHlc),
      `escalation_signal_detected_before_cycle:${label}`,
    );

    if (hasText(signal?.signalFamily)) {
      signalFamilies.push(signal.signalFamily);
    }
    if (signalIsMaterial(signal)) {
      materialSignals.push(signal);
    }
    signalSummaries.push({
      controlRefs,
      recommendedDecisionClass: signal?.recommendedDecisionClass ?? null,
      riskLevel: signal?.riskLevel ?? null,
      signalFamily: signal?.signalFamily ?? null,
      signalRef: signal?.signalRef ?? null,
      sourceWorkflowRef: signal?.sourceWorkflowRef ?? null,
      urgency: signal?.urgency ?? null,
    });
  });

  return {
    materialSignals,
    signalByRef,
    signalFamilies: uniqueSorted(signalFamilies),
    signalRefs: uniqueSorted(signalRefs),
    signalSummaries: signalSummaries.sort((left, right) => String(left.signalRef).localeCompare(String(right.signalRef))),
  };
}

function evaluateRoutes(routes, signalSummary, cycle, policy, reasons) {
  addReason(reasons, !Array.isArray(routes) || routes.length === 0, 'escalation_routes_absent');
  if (!Array.isArray(routes)) {
    return {
      decisionClassCounts: { constitutional: 0, operational: 0, routine: 0, strategic: 0 },
      decisionForumMatterCount: 0,
      matterDrafts: [],
      matterRefs: [],
      routeBySignalRef: new Map(),
      routeRefs: [],
      routeSummaries: [],
    };
  }

  const decisionClassCounts = { constitutional: 0, operational: 0, routine: 0, strategic: 0 };
  const matterDrafts = [];
  const matterRefs = [];
  const routeBySignalRef = new Map();
  const routeRefs = [];
  const routeSummaries = [];
  const seenRouteRefs = new Set();

  routes.forEach((route, index) => {
    const label = routeLabel(route, index);
    const governanceRoles = sortedTextList(route?.requiredGovernanceRoleRefs);
    const sourceSignal = signalSummary.signalByRef.get(route?.signalRef);

    addReason(reasons, !hasText(route?.routeRef), `route_ref_absent:${label}`);
    addReason(reasons, seenRouteRefs.has(route?.routeRef), `route_ref_duplicate:${label}`);
    if (hasText(route?.routeRef)) {
      seenRouteRefs.add(route.routeRef);
      routeRefs.push(route.routeRef);
    }
    addReason(reasons, !hasText(route?.signalRef), `route_signal_ref_absent:${label}`);
    addReason(reasons, hasText(route?.signalRef) && sourceSignal === undefined, `route_signal_unknown:${label}`);
    addReason(reasons, !ROUTE_TYPES.has(route?.routeType), `route_type_invalid:${label}`);
    addReason(reasons, !hasText(route?.matterRef), `route_matter_ref_absent:${label}`);
    addReason(reasons, !hasText(route?.decisionType), `route_decision_type_absent:${label}`);
    addReason(
      reasons,
      sourceSignal !== undefined && route?.decisionType !== sourceSignal.signalFamily,
      `route_decision_type_mismatch:${label}`,
    );
    addReason(reasons, !DECISION_CLASSES.has(route?.decisionClass), `route_decision_class_invalid:${label}`);
    addReason(
      reasons,
      sourceSignal !== undefined && route?.decisionClass !== sourceSignal.recommendedDecisionClass,
      `route_decision_class_mismatch:${label}`,
    );
    addReason(reasons, governanceRoles.length === 0, `route_governance_roles_absent:${label}`);
    addReason(reasons, !isDigest(route?.evidenceBundleHash), `route_evidence_bundle_hash_invalid:${label}`);
    addReason(reasons, !isDigest(route?.rationaleHash), `route_rationale_hash_invalid:${label}`);
    addReason(reasons, !hasText(route?.openedByDid), `route_opened_by_did_absent:${label}`);
    addReason(reasons, route?.metadataOnly !== true, `route_metadata_boundary_invalid:${label}`);
    addReason(reasons, route?.protectedContentExcluded !== true, `route_protected_boundary_invalid:${label}`);
    addReason(reasons, hlcTuple(route?.routedAtHlc) === null, `route_time_invalid:${label}`);
    addReason(
      reasons,
      sourceSignal !== undefined && hlcBefore(route?.routedAtHlc, sourceSignal.detectedAtHlc),
      `route_before_signal_detection:${label}`,
    );

    if (hasText(route?.signalRef)) {
      const routesForSignal = routeBySignalRef.get(route.signalRef) ?? [];
      routesForSignal.push(route);
      routeBySignalRef.set(route.signalRef, routesForSignal);
    }
    if (route?.routeType === 'decision_forum' && hasText(route?.matterRef)) {
      matterRefs.push(route.matterRef);
      if (DECISION_CLASSES.has(route?.decisionClass)) {
        decisionClassCounts[route.decisionClass] += 1;
      }
      matterDrafts.push({
        decisionClass: route?.decisionClass ?? null,
        decisionType: route?.decisionType ?? null,
        evidenceBundleHash: route?.evidenceBundleHash ?? null,
        exochainProductionClaim: false,
        matterRef: route.matterRef,
        metadataOnly: true,
        protectedContentExcluded: true,
        requiredGovernanceRoleRefs: governanceRoles,
        routeRef: route?.routeRef ?? null,
        signalRef: route?.signalRef ?? null,
        trustState: 'inactive',
      });
    }
    routeSummaries.push({
      decisionClass: route?.decisionClass ?? null,
      decisionType: route?.decisionType ?? null,
      matterRef: route?.matterRef ?? null,
      routeRef: route?.routeRef ?? null,
      routeType: route?.routeType ?? null,
      signalRef: route?.signalRef ?? null,
    });
  });

  if (policy?.requireDecisionForumForMaterialSignals === true) {
    for (const signal of signalSummary.materialSignals) {
      const routesForSignal = routeBySignalRef.get(signal.signalRef) ?? [];
      if (routesForSignal.length === 0) {
        reasons.push(`material_signal_route_missing:${signal.signalFamily}`);
      } else if (!routesForSignal.some((route) => route?.routeType === 'decision_forum')) {
        reasons.push(`material_signal_requires_decision_forum_route:${signal.signalFamily}`);
      }
    }
  }

  return {
    decisionClassCounts,
    decisionForumMatterCount: matterRefs.length,
    matterDrafts: matterDrafts.sort((left, right) => String(left.matterRef).localeCompare(String(right.matterRef))),
    matterRefs: uniqueSorted(matterRefs),
    routeBySignalRef,
    routeRefs: uniqueSorted(routeRefs),
    routeSummaries: routeSummaries.sort((left, right) => String(left.routeRef).localeCompare(String(right.routeRef))),
  };
}

function evaluateAiAssistance(ai, cycle, reasons) {
  if (ai?.used !== true) {
    return;
  }
  addReason(reasons, ai?.advisoryOnly !== true, 'ai_assistance_must_be_advisory');
  addReason(reasons, ai?.finalAuthority === true, 'ai_assistance_final_authority_forbidden');
  addReason(reasons, !isDigest(ai?.recommendationHash), 'ai_assistance_recommendation_hash_invalid');
  for (const hash of Array.isArray(ai?.limitationHashes) ? ai.limitationHashes : []) {
    addReason(reasons, !isDigest(hash), 'ai_assistance_limitation_hash_invalid');
  }
  addReason(reasons, !Array.isArray(ai?.limitationHashes) || ai.limitationHashes.length === 0, 'ai_assistance_limits_absent');
  addReason(reasons, ai?.reviewedByHuman !== true, 'ai_assistance_human_review_absent');
  addReason(reasons, ai?.metadataOnly !== true, 'ai_assistance_metadata_boundary_invalid');
  addReason(reasons, ai?.protectedContentExcluded !== true, 'ai_assistance_protected_boundary_invalid');
  addReason(
    reasons,
    hlcBefore(cycle?.humanReviewedAtHlc, cycle?.routesDeterminedAtHlc),
    'ai_review_before_route_determination',
  );
}

function evaluateHumanReview(review, cycle, reasons) {
  const reviewerRoles = sortedTextList(review?.reviewerRoleRefs);
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_did_absent');
  addReason(reasons, reviewerRoles.length === 0, 'human_reviewer_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.finalAuthority !== 'human' || review?.aiFinalAuthority === true, 'human_final_authority_missing');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'human_review_production_claim_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(
    reasons,
    hlcBefore(review?.reviewedAtHlc, cycle?.routesDeterminedAtHlc),
    'human_review_before_route_determination',
  );
}

function evaluateAuditRecord(audit, cycle, review, reasons) {
  addReason(reasons, !hasText(audit?.auditRecordRef), 'audit_record_ref_absent');
  addReason(reasons, !isDigest(audit?.auditRecordHash), 'audit_record_hash_invalid');
  addReason(reasons, audit?.metadataOnly !== true, 'audit_record_metadata_boundary_invalid');
  addReason(reasons, audit?.includesProtectedContent === true, 'audit_record_protected_content_forbidden');
  addReason(reasons, hlcTuple(audit?.receiptRecordedAtHlc) === null, 'audit_receipt_time_invalid');
  addReason(
    reasons,
    hlcBefore(audit?.receiptRecordedAtHlc, review?.reviewedAtHlc ?? cycle?.humanReviewedAtHlc),
    'audit_receipt_before_human_review',
  );
}

function buildEscalationEngine(input, signalSummary, routeSummary) {
  const engineHash = sha256Hex({
    auditRecordHash: input?.auditRecord?.auditRecordHash ?? null,
    cycleRef: input?.escalationCycle?.cycleRef ?? null,
    decisionClassCounts: routeSummary.decisionClassCounts,
    escalationFamiliesCovered: signalSummary.signalFamilies,
    matterRefs: routeSummary.matterRefs,
    signalRefs: signalSummary.signalRefs,
    tenantId: input?.tenantId ?? null,
  });

  return {
    schema: ENGINE_SCHEMA,
    engineId: `cmdfes_${sha256Hex({
      cycleRef: input?.escalationCycle?.cycleRef ?? null,
      engineHash,
      tenantId: input?.tenantId ?? null,
    }).slice(0, 32)}`,
    tenantId: input?.tenantId ?? null,
    cycleRef: input?.escalationCycle?.cycleRef ?? null,
    trustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    aiFinalAuthority: false,
    humanFinalAuthorityRequired: true,
    escalationFamiliesCovered: signalSummary.signalFamilies,
    signalRefs: signalSummary.signalRefs,
    routeRefs: routeSummary.routeRefs,
    matterRefs: routeSummary.matterRefs,
    decisionForumMatterCount: routeSummary.decisionForumMatterCount,
    decisionClassCounts: routeSummary.decisionClassCounts,
    engineHash,
    auditRecordHash: input?.auditRecord?.auditRecordHash ?? null,
    auditRecordedAtHlc: input?.auditRecord?.receiptRecordedAtHlc ?? null,
  };
}

function buildReceipt(input, escalationEngine) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: escalationEngine.engineHash,
    artifactType: 'decision_forum_escalation_engine',
    artifactVersion: input.escalationCycle.cycleRef,
    classification: 'restricted_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.auditRecord.receiptRecordedAtHlc,
    sensitivityTags: ['decision_forum', 'escalation_engine', 'human_review_required', 'metadata_only'],
    sourceSystem: 'cybermedica-qms',
    tenantId: input.tenantId,
  });
}

export function evaluateDecisionForumEscalationEngine(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policySummary = evaluatePolicy(input?.escalationPolicy, reasons);
  evaluateCycle(input?.escalationCycle, reasons);
  const signalSummary = evaluateSignals(
    input?.escalationSignals,
    policySummary.requiredFamilies,
    input?.escalationCycle,
    reasons,
  );
  const routeSummary = evaluateRoutes(
    input?.escalationRoutes,
    signalSummary,
    input?.escalationCycle,
    input?.escalationPolicy,
    reasons,
  );
  evaluateAiAssistance(input?.aiAssistance, input?.escalationCycle, reasons);
  evaluateHumanReview(input?.humanReview, input?.escalationCycle, reasons);
  evaluateAuditRecord(input?.auditRecord, input?.escalationCycle, input?.humanReview, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const escalationEngine = buildEscalationEngine(input, signalSummary, routeSummary);
  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: unique,
      escalationEngine,
      matterDrafts: routeSummary.matterDrafts,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    escalationEngine,
    matterDrafts: routeSummary.matterDrafts,
    receipt: buildReceipt(input, escalationEngine),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
