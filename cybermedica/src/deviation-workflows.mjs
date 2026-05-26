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

import { canonicalize, createEvidenceReceipt, ProtectedContentError, sha256Hex } from './qms-contracts.mjs';

const HEX_64 = /^[0-9a-f]{64}$/u;
const DEVIATION_CLASSES = new Set(['planned', 'unplanned']);
const DEVIATION_STATUSES = new Set(['reported', 'investigation_open', 'closure_ready', 'closed']);
const IMPACT_LEVELS = new Set(['none', 'minor', 'moderate', 'elevated', 'high', 'critical']);
const CAPA_TRIGGER_LEVELS = new Set(['moderate', 'elevated', 'high', 'critical']);
const ESCALATION_TRIGGER_LEVELS = new Set(['high', 'critical']);
const AE_SAE_STATUSES = new Set(['linked', 'not_applicable', 'pending_assessment']);
const RAW_NARRATIVE_FIELDS = new Set([
  'correctiveactionnarrative',
  'description',
  'narrative',
  'preventiveactionnarrative',
  'rawnarrative',
  'rootcausenarrative',
  'sourcebody',
  'sourcedocument',
  'sourcetext',
  'verificationnotes',
]);
const IMPACT_FIELDS = Object.freeze([
  'participantRisk',
  'consentImpact',
  'dataIntegrityImpact',
  'randomizationImpact',
  'blindingImpact',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function assertNoRawNarrative(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawNarrative(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    if (RAW_NARRATIVE_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`raw narrative field is not allowed at ${path}.${key}`);
    }
    assertNoRawNarrative(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawNarrative(input ?? {});
  canonicalize(input ?? {});
}

function hlcPresent(hlc) {
  return Number.isSafeInteger(hlc?.physicalMs) && Number.isSafeInteger(hlc?.logical);
}

function hlcAfterOrEqual(left, right) {
  return left.physicalMs > right.physicalMs || (left.physicalMs === right.physicalMs && left.logical >= right.logical);
}

function sortedTextList(value) {
  return Array.isArray(value) ? value.filter(hasText).sort() : [];
}

function hasPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !hasPermission(input?.authority, 'write'), 'authority_permission_missing');
}

function evaluateDeviation(deviation, reasons) {
  addReason(reasons, !hasText(deviation?.deviationRef), 'deviation_ref_absent');
  addReason(reasons, !hasText(deviation?.studyRef), 'study_ref_absent');
  addReason(reasons, !hasText(deviation?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(deviation?.siteRef), 'site_ref_absent');
  addReason(reasons, !hlcPresent(deviation?.discoveredAtHlc), 'discovered_time_invalid');
  addReason(reasons, !hasText(deviation?.discovererDid), 'discoverer_did_absent');
  addReason(reasons, !hasText(deviation?.discoveryMethod), 'discovery_method_absent');
  addReason(reasons, !isDigest(deviation?.descriptionHash), 'deviation_description_hash_invalid');
  addReason(reasons, !DEVIATION_CLASSES.has(deviation?.classification), 'deviation_classification_invalid');
  addReason(reasons, !hasText(deviation?.protocolSectionRef), 'protocol_section_ref_absent');
  addReason(reasons, !hasText(deviation?.ownerDid), 'deviation_owner_absent');
  addReason(reasons, !hlcPresent(deviation?.dueHlc), 'due_time_invalid');
  addReason(
    reasons,
    hlcPresent(deviation?.discoveredAtHlc) &&
      hlcPresent(deviation?.dueHlc) &&
      !hlcAfterOrEqual(deviation.dueHlc, deviation.discoveredAtHlc),
    'due_time_precedes_discovery',
  );
  addReason(reasons, !DEVIATION_STATUSES.has(deviation?.status), 'deviation_status_invalid');
  addReason(reasons, sortedTextList(deviation?.policyRefs).length === 0, 'policy_refs_absent');

  for (const field of IMPACT_FIELDS) {
    addReason(reasons, !IMPACT_LEVELS.has(deviation?.[field]), 'deviation_impact_invalid');
  }

  addReason(reasons, !AE_SAE_STATUSES.has(deviation?.aeSaeLinkage?.status), 'ae_sae_linkage_invalid');
  if (deviation?.aeSaeLinkage?.status === 'linked') {
    addReason(reasons, !hasText(deviation.aeSaeLinkage.eventRef), 'ae_sae_linkage_invalid');
    addReason(reasons, !isDigest(deviation.aeSaeLinkage.eventHash), 'ae_sae_linkage_invalid');
  }
}

function actionRequired(input) {
  return input?.immediateAction?.required === true || ESCALATION_TRIGGER_LEVELS.has(input?.deviation?.participantRisk);
}

function evaluateImmediateAction(input, reasons) {
  const required = actionRequired(input);
  const immediateAction = input?.immediateAction;

  addReason(reasons, typeof immediateAction?.required !== 'boolean', 'immediate_action_requirement_invalid');
  if (required) {
    const incomplete =
      immediateAction?.status !== 'completed' ||
      !isDigest(immediateAction?.actionEvidenceHash) ||
      !hlcPresent(immediateAction?.completedAtHlc) ||
      !hasText(immediateAction?.ownerDid);
    addReason(reasons, incomplete, 'immediate_action_evidence_absent');
    return;
  }

  addReason(
    reasons,
    immediateAction?.status !== 'not_required' || !isDigest(immediateAction?.rationaleHash),
    'immediate_action_rationale_absent',
  );
}

function reportingComplete(reportingDecision) {
  if (reportingDecision?.required === true) {
    return reportingDecision.status === 'submitted' && isDigest(reportingDecision.evidenceHash);
  }
  if (reportingDecision?.required === false) {
    return reportingDecision.status === 'not_required' && isDigest(reportingDecision.rationaleHash);
  }
  return false;
}

function evaluateReporting(reporting, reasons) {
  const incomplete =
    !reportingComplete(reporting?.sponsor) ||
    !reportingComplete(reporting?.irb) ||
    !reportingComplete(reporting?.regulatory);
  addReason(reasons, incomplete, 'required_reporting_incomplete');
}

function impactAtOrAbove(deviation, levels) {
  return IMPACT_FIELDS.some((field) => levels.has(deviation?.[field]));
}

function immediateEscalationRequired(input) {
  return (
    impactAtOrAbove(input?.deviation, ESCALATION_TRIGGER_LEVELS) ||
    input?.deviation?.aeSaeLinkage?.status === 'linked' ||
    (input?.deviation?.classification === 'unplanned' && CAPA_TRIGGER_LEVELS.has(input?.deviation?.participantRisk))
  );
}

function capaRequired(input) {
  return (
    input?.capaLinkage?.required === true ||
    impactAtOrAbove(input?.deviation, CAPA_TRIGGER_LEVELS) ||
    input?.deviation?.aeSaeLinkage?.status === 'linked' ||
    input?.immediateAction?.required === true
  );
}

function evaluateEscalationRoute(decisionForum, required, reasons) {
  if (!required) {
    return;
  }

  const routeAbsent =
    decisionForum?.linkageRequired !== true ||
    !hasText(decisionForum?.decisionId) ||
    !hasText(decisionForum?.workflowReceiptId);
  addReason(reasons, routeAbsent, 'critical_escalation_route_absent');
}

function evaluateCapaLinkage(linkage, required, reasons) {
  if (!required) {
    return;
  }

  addReason(reasons, !hasText(linkage?.capaRef) || !hasText(linkage?.receiptId), 'capa_linkage_absent');
}

function evaluateOpenInvestigationEvidence(input, reasons) {
  if (input?.deviation?.status === 'closure_ready' || input?.deviation?.status === 'closed') {
    return;
  }

  if (input?.rootCause?.status === 'complete') {
    addReason(reasons, !hasText(input.rootCause.category), 'root_cause_category_absent');
    addReason(reasons, !isDigest(input.rootCause.evidenceHash), 'root_cause_evidence_invalid');
  }
  if (input?.correctiveAction?.status === 'implemented') {
    addReason(reasons, !isDigest(input.correctiveAction.planHash), 'corrective_action_plan_invalid');
    addReason(reasons, !isDigest(input.correctiveAction.implementationEvidenceHash), 'corrective_action_evidence_invalid');
  }
  if (input?.preventiveAction?.status === 'implemented') {
    addReason(reasons, !isDigest(input.preventiveAction.planHash), 'preventive_action_plan_invalid');
    addReason(reasons, !isDigest(input.preventiveAction.implementationEvidenceHash), 'preventive_action_evidence_invalid');
  }
}

function closureRequested(input) {
  return input?.deviation?.status === 'closure_ready' || input?.deviation?.status === 'closed';
}

function evaluateClosureGovernance(closureDecisionForum, reasons) {
  const invalid =
    closureDecisionForum?.verified !== true ||
    closureDecisionForum?.state !== 'approved' ||
    closureDecisionForum?.humanGate?.verified !== true ||
    closureDecisionForum?.quorum?.status !== 'met' ||
    closureDecisionForum?.openChallenge === true ||
    !hasText(closureDecisionForum?.decisionId) ||
    !hasText(closureDecisionForum?.workflowReceiptId);
  addReason(reasons, invalid, 'closure_decision_forum_unverified');
}

function evaluateClosureEvidence(input, reasons) {
  if (!closureRequested(input)) {
    return { closureStatus: 'open', effectivenessFinal: false, followUpRequired: false };
  }

  addReason(
    reasons,
    input?.rootCause?.status !== 'complete' || !hasText(input?.rootCause?.category) || !isDigest(input?.rootCause?.evidenceHash),
    'root_cause_incomplete',
  );
  addReason(
    reasons,
    input?.correctiveAction?.status !== 'implemented' ||
      !isDigest(input?.correctiveAction?.planHash) ||
      !isDigest(input?.correctiveAction?.implementationEvidenceHash),
    'corrective_action_incomplete',
  );
  addReason(
    reasons,
    input?.preventiveAction?.status !== 'implemented' ||
      !isDigest(input?.preventiveAction?.planHash) ||
      !isDigest(input?.preventiveAction?.implementationEvidenceHash),
    'preventive_action_incomplete',
  );

  const evidenceHashes = input?.verification?.evidenceHashes;
  addReason(
    reasons,
    !Array.isArray(evidenceHashes) || evidenceHashes.length === 0 || evidenceHashes.some((hash) => !isDigest(hash)),
    'verification_evidence_absent',
  );
  addReason(reasons, !isDigest(input?.verification?.custodyDigest), 'verification_custody_digest_invalid');
  evaluateClosureGovernance(input?.closureDecisionForum, reasons);

  if (input?.effectivenessCheck?.status === 'met') {
    addReason(reasons, !isDigest(input.effectivenessCheck.criteriaHash), 'effectiveness_criteria_hash_invalid');
    addReason(reasons, !hlcPresent(input.effectivenessCheck.checkedAtHlc), 'effectiveness_check_time_invalid');
    return { closureStatus: 'closed', effectivenessFinal: true, followUpRequired: false };
  }

  if (input?.effectivenessCheck?.status === 'follow_up_scheduled') {
    addReason(reasons, !isDigest(input.effectivenessCheck.criteriaHash), 'effectiveness_criteria_hash_invalid');
    addReason(reasons, !isDigest(input.effectivenessCheck.rationaleHash), 'effectiveness_followup_rationale_absent');
    addReason(reasons, !hlcPresent(input.effectivenessCheck.followUpHlc), 'effectiveness_followup_time_invalid');
    return {
      closureStatus: 'closed_with_effectiveness_followup',
      effectivenessFinal: false,
      followUpRequired: true,
    };
  }

  reasons.push('effectiveness_not_established');
  return { closureStatus: 'open', effectivenessFinal: false, followUpRequired: false };
}

function requiredEscalationRoles(input, escalationRequired) {
  const roles = new Set(['site_quality_lead']);
  if (
    CAPA_TRIGGER_LEVELS.has(input?.deviation?.participantRisk) ||
    input?.deviation?.aeSaeLinkage?.status === 'linked'
  ) {
    roles.add('principal_investigator');
  }
  if (ESCALATION_TRIGGER_LEVELS.has(input?.deviation?.dataIntegrityImpact)) {
    roles.add('data_integrity_officer');
  }
  if (ESCALATION_TRIGGER_LEVELS.has(input?.deviation?.consentImpact)) {
    roles.add('consent_authority_reviewer');
  }
  if (
    ESCALATION_TRIGGER_LEVELS.has(input?.deviation?.randomizationImpact) ||
    ESCALATION_TRIGGER_LEVELS.has(input?.deviation?.blindingImpact)
  ) {
    roles.add('sponsor_quality_reviewer');
  }
  if (input?.deviation?.aeSaeLinkage?.status === 'linked') {
    roles.add('principal_investigator');
  }
  if (escalationRequired) {
    roles.add('decision_forum');
  }
  return [...roles].sort();
}

function reportingSummary(reporting) {
  return {
    irb: reporting?.irb?.required === true ? 'submitted' : 'not_required',
    regulatory: reporting?.regulatory?.required === true ? 'submitted' : 'not_required',
    sponsor: reporting?.sponsor?.required === true ? 'submitted' : 'not_required',
  };
}

function normalizeCapaLinkage(linkage, required) {
  if (!required) {
    return { required: false, capaRef: null, receiptId: null };
  }
  return {
    required: true,
    capaRef: linkage.capaRef,
    receiptId: linkage.receiptId,
  };
}

function deviationArtifactHash(input, roles, escalationRequired, requiredCapa) {
  return sha256Hex({
    aeSaeLinkage: input.deviation.aeSaeLinkage,
    capaLinkage: normalizeCapaLinkage(input.capaLinkage, requiredCapa),
    classification: input.deviation.classification,
    descriptionHash: input.deviation.descriptionHash,
    deviationRef: input.deviation.deviationRef,
    discoveredAtHlc: input.deviation.discoveredAtHlc,
    impactSummary: Object.fromEntries(IMPACT_FIELDS.map((field) => [field, input.deviation[field]])),
    immediateAction: input.immediateAction,
    immediateEscalationRequired: escalationRequired,
    policyRefs: sortedTextList(input.deviation.policyRefs),
    protocolRef: input.deviation.protocolRef,
    reporting: input.reporting,
    requiredEscalationRoles: roles,
    siteRef: input.deviation.siteRef,
    status: input.deviation.status,
    studyRef: input.deviation.studyRef,
    tenantId: input.tenantId,
  });
}

function buildDeviationReceipt(input, artifactHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'deviation_record',
    artifactVersion: `${input.deviation.deviationRef}@${input.deviation.discoveredAtHlc.physicalMs}.${input.deviation.discoveredAtHlc.logical}`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.deviation.discoveredAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['deviation', 'metadata_only', 'participant_safety_relevant'],
    sourceSystem: 'cybermedica-qms',
  });
}

function closureArtifactHash(input, closureResult) {
  return sha256Hex({
    capaLinkage: input.capaLinkage,
    closureDecisionForum: {
      decisionId: input.closureDecisionForum.decisionId,
      workflowReceiptId: input.closureDecisionForum.workflowReceiptId,
    },
    closureStatus: closureResult.closureStatus,
    correctiveAction: input.correctiveAction,
    deviationRef: input.deviation.deviationRef,
    effectivenessCheck: input.effectivenessCheck,
    preventiveAction: input.preventiveAction,
    rootCause: input.rootCause,
    verification: {
      custodyDigest: input.verification.custodyDigest,
      evidenceHashes: [...input.verification.evidenceHashes].sort(),
    },
  });
}

function buildClosureReceipt(input, closureResult) {
  const hlcTimestamp = input.effectivenessCheck.checkedAtHlc ?? input.effectivenessCheck.followUpHlc;
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'deviation_closure',
    artifactVersion: `${input.deviation.deviationRef}@closure`,
    artifactHash: closureArtifactHash(input, closureResult),
    classification: 'confidential_metadata_only',
    hlcTimestamp,
    custodyDigest: input.verification.custodyDigest,
    sensitivityTags: ['deviation', 'closure', 'metadata_only', 'participant_safety_relevant'],
    sourceSystem: 'cybermedica-qms',
  });
}

function buildDeviation(input, roles, escalationRequired, requiredCapa, closureResult, receipt) {
  return {
    schema: 'cybermedica.deviation_record.v1',
    deviationId: `cmdev_${sha256Hex({
      deviationRef: input.deviation.deviationRef,
      discoveredAtHlc: input.deviation.discoveredAtHlc,
      tenantId: input.tenantId,
    }).slice(0, 32)}`,
    deviationRef: input.deviation.deviationRef,
    tenantId: input.tenantId,
    studyRef: input.deviation.studyRef,
    protocolRef: input.deviation.protocolRef,
    siteRef: input.deviation.siteRef,
    classification: input.deviation.classification,
    status: input.deviation.status,
    descriptionHash: input.deviation.descriptionHash,
    protocolSectionRef: input.deviation.protocolSectionRef,
    discovererDid: input.deviation.discovererDid,
    ownerDid: input.deviation.ownerDid,
    impactSummary: Object.fromEntries(IMPACT_FIELDS.map((field) => [field, input.deviation[field]])),
    aeSaeLinkage: input.deviation.aeSaeLinkage,
    immediateActionRequired: actionRequired(input),
    immediateEscalationRequired: escalationRequired,
    escalationStatus: escalationRequired ? 'required_ready' : 'not_required',
    requiredEscalationRoles: roles,
    decisionForumLinkage: escalationRequired
      ? {
          decisionId: input.decisionForum.decisionId,
          workflowReceiptId: input.decisionForum.workflowReceiptId,
        }
      : null,
    reportingSummary: reportingSummary(input.reporting),
    capaRequired: requiredCapa,
    capaLinkage: normalizeCapaLinkage(input.capaLinkage, requiredCapa),
    rootCauseStatus: input.rootCause?.status ?? 'not_started',
    correctiveActionStatus: input.correctiveAction?.status ?? 'not_started',
    preventiveActionStatus: input.preventiveAction?.status ?? 'not_started',
    verificationEvidenceHashes: Array.isArray(input.verification?.evidenceHashes)
      ? [...input.verification.evidenceHashes].sort()
      : [],
    closureStatus: closureResult.closureStatus,
    effectivenessFinal: closureResult.effectivenessFinal,
    followUpRequired: closureResult.followUpRequired,
    policyRefs: sortedTextList(input.deviation.policyRefs),
    receiptId: receipt.receiptId,
    operationalStateMutable: closureResult.closureStatus !== 'closed',
    immutableDeviationReceipt: true,
    aiFinalAuthority: false,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

export function evaluateDeviationWorkflow(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateDeviation(input?.deviation, reasons);
  evaluateImmediateAction(input, reasons);
  evaluateReporting(input?.reporting, reasons);

  const escalationRequired = immediateEscalationRequired(input);
  const requiredCapa = capaRequired(input);
  evaluateEscalationRoute(input?.decisionForum, escalationRequired, reasons);
  evaluateCapaLinkage(input?.capaLinkage, requiredCapa, reasons);
  evaluateOpenInvestigationEvidence(input, reasons);
  const closureResult = evaluateClosureEvidence(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const uniqueReasons = [...new Set(reasons)].sort();
  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.deviation_workflow_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      deviation: null,
      receipt: null,
      closureReceipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const roles = requiredEscalationRoles(input, escalationRequired);
  const artifactHash = deviationArtifactHash(input, roles, escalationRequired, requiredCapa);
  const receipt = buildDeviationReceipt(input, artifactHash);
  const closureReceipt = closureRequested(input) ? buildClosureReceipt(input, closureResult) : null;

  return {
    schema: 'cybermedica.deviation_workflow_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    deviation: buildDeviation(input, roles, escalationRequired, requiredCapa, closureResult, receipt),
    receipt,
    closureReceipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
