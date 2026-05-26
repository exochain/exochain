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
const IMPACT_LEVELS = new Set(['none', 'minor', 'moderate', 'elevated', 'high', 'critical']);
const RISK_CATEGORIES = new Set([
  'consent',
  'data_integrity',
  'facility',
  'operational',
  'product_handling',
  'regulatory',
  'staffing',
  'vendor',
]);
const ASSESSMENT_TYPES = new Set(['trial_startup']);
const ASSESSMENT_STATUSES = new Set(['approved', 'approved_with_conditions', 'deferred', 'rejected']);
const RESIDUAL_STATUSES = new Set(['accepted', 'accepted_with_conditions', 'monitoring_required', 'unacceptable']);
const RAW_RISK_FIELDS = new Set([
  'description',
  'freeformrisktext',
  'impactnarrative',
  'participantdetails',
  'rawassessment',
  'rawdescription',
  'rawnarrative',
  'rawrisk',
  'riskdescription',
  'sourcedocument',
  'sourcedocumentbody',
]);
const IMPACT_FIELDS = Object.freeze([
  'participantSafetyImpact',
  'dataIntegrityImpact',
  'ethicalImpact',
  'regulatoryImpact',
  'operationalImpact',
  'financialImpact',
  'sponsorImpact',
  'croImpact',
]);
const ESCALATION_RATINGS = new Set(['high', 'critical']);
const SAFETY_PLAN_IMPACTS = new Set(['moderate', 'elevated', 'high', 'critical']);

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

function assertNoRawRiskText(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawRiskText(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    if (RAW_RISK_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`raw risk narrative field is not allowed at ${path}.${key}`);
    }
    assertNoRawRiskText(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawRiskText(input ?? {});
  canonicalize(input ?? {});
}

function hlcPresent(hlc) {
  return Number.isSafeInteger(hlc?.physicalMs) && Number.isSafeInteger(hlc?.logical);
}

function sortedTextList(value) {
  return Array.isArray(value) ? value.filter(hasText).sort() : [];
}

function uniqueSorted(value) {
  return [...new Set(value)].sort();
}

function hasPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function riskSort(left, right) {
  return String(left.riskRef).localeCompare(String(right.riskRef));
}

function scoreValue(value) {
  return Number.isSafeInteger(value) && value >= 1 && value <= 5;
}

function riskScore(risk) {
  if (!scoreValue(risk?.probability) || !scoreValue(risk?.severity) || !scoreValue(risk?.detectability)) {
    return null;
  }
  return risk.probability * risk.severity * risk.detectability;
}

function riskRating(score) {
  if (!Number.isSafeInteger(score) || score < 1) {
    return 'invalid';
  }
  if (score <= 8) {
    return 'low';
  }
  if (score <= 20) {
    return 'moderate';
  }
  if (score <= 40) {
    return 'high';
  }
  return 'critical';
}

function residualRiskScore(residualRisk) {
  if (
    !scoreValue(residualRisk?.probability) ||
    !scoreValue(residualRisk?.severity) ||
    !scoreValue(residualRisk?.detectability)
  ) {
    return null;
  }
  return residualRisk.probability * residualRisk.severity * residualRisk.detectability;
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
  addReason(reasons, !hasPermission(input?.authority, 'govern'), 'authority_permission_missing');
}

function evaluateAssessment(assessment, reasons) {
  addReason(reasons, !hasText(assessment?.assessmentRef), 'assessment_ref_absent');
  addReason(reasons, !hasText(assessment?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(assessment?.siteRef), 'site_ref_absent');
  addReason(reasons, !ASSESSMENT_TYPES.has(assessment?.assessmentType), 'assessment_type_invalid');
  addReason(reasons, !ASSESSMENT_STATUSES.has(assessment?.status), 'assessment_status_invalid');
  addReason(reasons, !hlcPresent(assessment?.createdAtHlc), 'assessment_time_invalid');
  addReason(reasons, !hasText(assessment?.reviewFrequency), 'review_frequency_absent');
  addReason(reasons, !hasText(assessment?.qualityReviewRef), 'quality_review_ref_absent');
  addReason(reasons, sortedTextList(assessment?.policyRefs).length === 0, 'policy_refs_absent');
  addReason(
    reasons,
    assessment?.status === 'deferred' || assessment?.status === 'rejected',
    `startup_risk_assessment_${assessment?.status ?? 'not_approved'}`,
  );
}

function evaluateHumanGovernance(input, reasons) {
  const forum = input?.review?.decisionForum;
  addReason(reasons, forum?.verified !== true, 'decision_forum_unverified');
  addReason(reasons, forum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, forum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, forum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, forum?.openChallenge === true, 'challenge_open');
  addReason(reasons, !hasText(forum?.decisionId), 'decision_forum_id_absent');
  addReason(reasons, !hasText(forum?.workflowReceiptId), 'decision_forum_receipt_absent');
  addReason(reasons, input?.review?.evidenceBundle?.complete !== true, 'evidence_bundle_incomplete');
  addReason(reasons, input?.review?.evidenceBundle?.phiBoundaryAttested !== true, 'phi_boundary_unattested');
  addReason(reasons, !hasText(input?.review?.qualityReviewerDid), 'quality_reviewer_absent');
}

function evaluateRequiredCategories(risks, reasons) {
  const present = new Set(risks.map((risk) => risk.category).filter((category) => RISK_CATEGORIES.has(category)));
  for (const category of [...RISK_CATEGORIES].sort()) {
    addReason(reasons, !present.has(category), `required_risk_category_missing:${category}`);
  }
  return [...present].sort();
}

function validateImpactFields(risk, reasons) {
  for (const field of IMPACT_FIELDS) {
    addReason(reasons, !IMPACT_LEVELS.has(risk?.[field]), `risk_impact_invalid:${risk?.riskRef ?? 'unknown'}`);
  }
}

function safetyPlanRequired(risk, initialRating) {
  return SAFETY_PLAN_IMPACTS.has(risk?.participantSafetyImpact) || initialRating === 'high' || initialRating === 'critical';
}

function evaluateRisk(risk, reasons) {
  const riskRef = hasText(risk?.riskRef) ? risk.riskRef : 'unknown';
  const initialScore = riskScore(risk);
  const initialRating = riskRating(initialScore);
  const residualScore = residualRiskScore(risk?.residualRisk);
  const residualRating = riskRating(residualScore);

  addReason(reasons, !hasText(risk?.riskRef), 'risk_ref_absent');
  addReason(reasons, !hasText(risk?.title), `risk_title_absent:${riskRef}`);
  addReason(reasons, !hasText(risk?.source), `risk_source_absent:${riskRef}`);
  addReason(reasons, !RISK_CATEGORIES.has(risk?.category), `risk_category_invalid:${riskRef}`);
  validateImpactFields(risk, reasons);
  addReason(reasons, initialScore === null, `initial_risk_score_invalid:${riskRef}`);
  addReason(reasons, !hasText(risk?.ownerDid), `risk_owner_absent:${riskRef}`);
  addReason(reasons, sortedTextList(risk?.linkedControlIds).length === 0, `linked_control_absent:${riskRef}`);
  addReason(
    reasons,
    !Array.isArray(risk?.linkedEvidenceHashes) ||
      risk.linkedEvidenceHashes.length === 0 ||
      risk.linkedEvidenceHashes.some((hash) => !isDigest(hash)),
    `risk_evidence_hash_invalid:${riskRef}`,
  );
  addReason(reasons, !isDigest(risk?.mitigationPlanHash), `mitigation_plan_invalid:${riskRef}`);
  addReason(reasons, risk?.mitigationStatus !== 'implemented', `mitigation_not_implemented:${riskRef}`);
  addReason(reasons, safetyPlanRequired(risk, initialRating) && !isDigest(risk?.safetyPlanHash), `safety_plan_absent:${riskRef}`);
  addReason(reasons, !isDigest(risk?.preventiveActionHash), `preventive_action_invalid:${riskRef}`);
  addReason(reasons, !isDigest(risk?.correctiveActionHash), `corrective_action_invalid:${riskRef}`);
  addReason(reasons, !hasText(risk?.monitoringMetricRef), `monitoring_metric_absent:${riskRef}`);
  addReason(reasons, sortedTextList(risk?.triggerConditions).length === 0, `trigger_conditions_absent:${riskRef}`);
  addReason(reasons, !ESCALATION_RATINGS.has(risk?.escalationThreshold), `escalation_threshold_invalid:${riskRef}`);
  addReason(reasons, residualScore === null, `residual_risk_score_invalid:${riskRef}`);
  addReason(reasons, !RESIDUAL_STATUSES.has(risk?.residualRisk?.status), `residual_risk_status_invalid:${riskRef}`);
  addReason(reasons, !isDigest(risk?.residualRisk?.acceptanceRationaleHash), `acceptance_rationale_absent:${riskRef}`);
  addReason(reasons, !hasText(risk?.residualRisk?.approverDid), `risk_approver_absent:${riskRef}`);
  addReason(reasons, risk?.residualRisk?.status === 'unacceptable', 'residual_risk_unacceptable');

  return {
    schema: 'cybermedica.risk_assessment_item.v1',
    riskRef,
    title: risk?.title,
    source: risk?.source,
    category: risk?.category,
    impactProfile: Object.fromEntries(IMPACT_FIELDS.map((field) => [field, risk?.[field]])),
    initialRiskScore: initialScore,
    initialRiskRating: initialRating,
    residualRiskScore: residualScore,
    residualRiskRating: residualRating,
    residualRiskStatus: risk?.residualRisk?.status,
    ownerDid: risk?.ownerDid,
    linkedControlIds: sortedTextList(risk?.linkedControlIds),
    linkedEvidenceHashes: sortedTextList(risk?.linkedEvidenceHashes),
    mitigationPlanHash: risk?.mitigationPlanHash,
    mitigationStatus: risk?.mitigationStatus,
    safetyPlanRequired: safetyPlanRequired(risk, initialRating),
    safetyPlanHash: risk?.safetyPlanHash,
    preventiveActionHash: risk?.preventiveActionHash,
    correctiveActionHash: risk?.correctiveActionHash,
    monitoringMetricRef: risk?.monitoringMetricRef,
    triggerConditions: sortedTextList(risk?.triggerConditions),
    escalationThreshold: risk?.escalationThreshold,
    escalationRequired: ESCALATION_RATINGS.has(initialRating) || risk?.residualRisk?.status === 'unacceptable',
    acceptanceRationaleHash: risk?.residualRisk?.acceptanceRationaleHash,
    approverDid: risk?.residualRisk?.approverDid,
  };
}

function normalizeRisks(input, reasons) {
  const risks = Array.isArray(input?.risks) ? [...input.risks].sort(riskSort) : [];
  addReason(reasons, risks.length === 0, 'risk_inventory_empty');
  const coveredRiskCategories = evaluateRequiredCategories(risks, reasons);
  const normalizedRisks = risks.map((risk) => evaluateRisk(risk, reasons));
  return { coveredRiskCategories, normalizedRisks };
}

function buildRiskAssessment(input, normalizedRisks, coveredRiskCategories, reasons) {
  const uniqueReasonsList = uniqueSorted(reasons);
  const blockingRiskPresent =
    uniqueReasonsList.length > 0 || normalizedRisks.some((risk) => risk.residualRiskStatus === 'unacceptable');
  const startupReadinessStatus =
    uniqueReasonsList.length === 0 && input?.assessment?.status === 'approved'
      ? 'approved'
      : uniqueReasonsList.length === 0 && input?.assessment?.status === 'approved_with_conditions'
        ? 'approved_with_conditions'
        : 'blocked';
  const requiredEscalationRoles = uniqueSorted(
    normalizedRisks.flatMap((risk) => {
      if (!risk.escalationRequired) {
        return [];
      }
      const roles = ['decision_forum', 'site_quality_lead'];
      if (risk.impactProfile.participantSafetyImpact === 'high' || risk.impactProfile.participantSafetyImpact === 'critical') {
        roles.push('principal_investigator');
      }
      if (risk.category === 'data_integrity') {
        roles.push('data_integrity_officer');
      }
      if (risk.category === 'consent') {
        roles.push('consent_governance_lead');
      }
      if (risk.category === 'product_handling') {
        roles.push('clinical_product_lead');
      }
      return roles;
    }),
  );

  const material = {
    assessmentRef: input?.assessment?.assessmentRef,
    coveredRiskCategories,
    protocolRef: input?.assessment?.protocolRef,
    risks: normalizedRisks,
    siteRef: input?.assessment?.siteRef,
    startupReadinessStatus,
    tenantId: input?.tenantId,
  };

  return {
    schema: 'cybermedica.startup_risk_assessment.v1',
    tenantId: input?.tenantId,
    assessmentRef: input?.assessment?.assessmentRef,
    protocolRef: input?.assessment?.protocolRef,
    siteRef: input?.assessment?.siteRef,
    assessmentType: input?.assessment?.assessmentType,
    startupReadinessStatus,
    blockingRiskPresent,
    aiFinalAuthority: false,
    exochainProductionClaim: false,
    trustState: 'inactive',
    coveredRiskCategories,
    requiredEscalationRoles,
    risks: normalizedRisks,
    decisionForum: {
      decisionId: input?.review?.decisionForum?.decisionId,
      workflowReceiptId: input?.review?.decisionForum?.workflowReceiptId,
      verified: input?.review?.decisionForum?.verified === true,
      humanGateVerified: input?.review?.decisionForum?.humanGate?.verified === true,
      quorumStatus: input?.review?.decisionForum?.quorum?.status,
    },
    assessmentId: `cmrisk_${sha256Hex(material).slice(0, 32)}`,
  };
}

function buildReceipt(input, riskAssessment) {
  const artifactHash = sha256Hex({
    assessmentId: riskAssessment.assessmentId,
    coveredRiskCategories: riskAssessment.coveredRiskCategories,
    protocolRef: riskAssessment.protocolRef,
    requiredEscalationRoles: riskAssessment.requiredEscalationRoles,
    risks: riskAssessment.risks,
    siteRef: riskAssessment.siteRef,
    startupReadinessStatus: riskAssessment.startupReadinessStatus,
  });

  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'startup_risk_assessment',
    artifactVersion: `${input.assessment.assessmentRef}@${input.assessment.createdAtHlc.physicalMs}.${input.assessment.createdAtHlc.logical}`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.assessment.createdAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['risk_assessment', 'startup_readiness', 'metadata_only'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function evaluateStartupRiskAssessment(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateAssessment(input?.assessment, reasons);
  evaluateHumanGovernance(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
  const { coveredRiskCategories, normalizedRisks } = normalizeRisks(input, reasons);
  const riskAssessment = buildRiskAssessment(input, normalizedRisks, coveredRiskCategories, reasons);
  const sortedReasons = uniqueSorted(reasons);

  if (sortedReasons.length > 0) {
    return {
      decision: 'denied',
      failClosed: true,
      reasons: sortedReasons,
      riskAssessment,
    };
  }

  return {
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    riskAssessment,
    receipt: buildReceipt(input, riskAssessment),
  };
}
