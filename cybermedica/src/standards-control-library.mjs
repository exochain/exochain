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
const CONTROL_STATUSES = new Set(['active']);
const CONTROL_RISK_CRITICALITIES = new Set(['critical', 'major', 'minor']);
const CONTROL_RELEVANCE_KEYS = Object.freeze([
  'participantSafety',
  'dataIntegrity',
  'sponsorDiligence',
  'irbIec',
  'croOversight',
  'siteOperational',
]);
const APPLICABILITY_STATES = new Set([
  'applicable',
  'not_applicable',
  'conditionally_applicable',
  'deferred',
  'waived',
  'superseded',
]);
const APPLICABILITY_OPERATORS = new Set([
  'metadata_equals',
  'metadata_present',
  'metadata_absent',
  'metadata_in',
  'metadata_not_in',
]);
const EVIDENCE_CLASSIFICATIONS = new Set([
  'confidential_metadata_only',
  'restricted_metadata_only',
  'sponsor_confidential_metadata_only',
]);
const GOVERNANCE_REVIEW_DECISIONS = new Set(['approve']);
const CHANGE_TYPES = new Set(['initial_publication', 'revision', 'retirement_reversal']);
const ESCALATION_ROLES = new Set([
  'control_reviewer',
  'principal_investigator',
  'quality_manager',
  'site_quality_lead',
  'sponsor_contact',
]);
const APPROVER_ROLES = new Set([
  'control_reviewer',
  'principal_investigator',
  'quality_manager',
  'site_quality_lead',
]);
const RAW_CONTROL_LIBRARY_FIELDS = new Set([
  'freeformrationale',
  'fullstandardtext',
  'normativestatement',
  'normativestatementtext',
  'plainlanguageexplanation',
  'plainlanguageexplanationtext',
  'rawapplicabilityrationale',
  'rawcontroltext',
  'rawrationale',
  'rawrequirement',
  'rawstandard',
  'rawstandardtext',
  'requirementtext',
  'sourcedocument',
  'sourcedocumentbody',
  'sourcetext',
  'standardclausetext',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
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

function assertNoRawControlLibraryText(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawControlLibraryText(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    if (RAW_CONTROL_LIBRARY_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`raw control library content field is not allowed at ${path}.${key}`);
    }
    assertNoRawControlLibraryText(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawControlLibraryText(input ?? {});
  canonicalize(input ?? {});
}

function hlcPresent(hlc) {
  return Number.isSafeInteger(hlc?.physicalMs) && Number.isSafeInteger(hlc?.logical);
}

function compareHlc(left, right) {
  if (left.physicalMs !== right.physicalMs) {
    return left.physicalMs - right.physicalMs;
  }
  return left.logical - right.logical;
}

function sortedTextList(value) {
  return Array.isArray(value) ? value.filter(hasText).sort() : [];
}

function uniqueSorted(value) {
  return [...new Set(value)].sort();
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
  addReason(reasons, !hasAuthorityPermission(input?.authority, 'govern'), 'authority_permission_missing');
}

function sourceRefSort(left, right) {
  return String(left.sourceRefId).localeCompare(String(right.sourceRefId));
}

function applicabilityCriterionSort(left, right) {
  return String(left.criterionId).localeCompare(String(right.criterionId));
}

function evidenceRequirementSort(left, right) {
  return String(left.artifactType).localeCompare(String(right.artifactType));
}

function crosswalkSort(left, right) {
  return String(left.framework).localeCompare(String(right.framework)) || String(left.reference).localeCompare(String(right.reference));
}

function auditExportSort(left, right) {
  return String(left.audience).localeCompare(String(right.audience));
}

function changeHistorySort(left, right) {
  return String(left.changeId).localeCompare(String(right.changeId));
}

function normalizeSourceRefs(input, reasons) {
  const sourceRefs = Array.isArray(input?.control?.sourceRefs) ? [...input.control.sourceRefs].sort(sourceRefSort) : [];
  addReason(reasons, sourceRefs.length === 0, 'source_refs_absent');

  return sourceRefs.map((sourceRef) => {
    const sourceRefId = hasText(sourceRef?.sourceRefId) ? sourceRef.sourceRefId : 'SRC-UNKNOWN';
    addReason(reasons, !hasText(sourceRef?.sourceRefId), 'control_source_ref_id_absent');
    addReason(reasons, !hasText(sourceRef?.sourceType), `control_source_type_absent:${sourceRefId}`);
    addReason(reasons, !hasText(sourceRef?.sourceVersion), `control_source_version_absent:${sourceRefId}`);
    addReason(reasons, !hasText(sourceRef?.clauseRef), `control_source_clause_absent:${sourceRefId}`);
    addReason(reasons, !isDigest(sourceRef?.sourceHash), `control_source_hash_invalid:${sourceRefId}`);
    addReason(reasons, sourceRef?.rightsAttested !== true, `control_source_rights_unattested:${sourceRefId}`);

    return {
      clauseRef: sourceRef?.clauseRef ?? null,
      rightsAttested: sourceRef?.rightsAttested === true,
      sourceHash: sourceRef?.sourceHash ?? null,
      sourceRefId,
      sourceType: sourceRef?.sourceType ?? null,
      sourceVersion: sourceRef?.sourceVersion ?? null,
    };
  });
}

function normalizeApplicabilityCriteria(input, reasons) {
  const criteria = Array.isArray(input?.control?.applicabilityCriteria)
    ? [...input.control.applicabilityCriteria].sort(applicabilityCriterionSort)
    : [];
  addReason(reasons, criteria.length === 0, 'applicability_criteria_absent');

  return criteria.map((criterion) => {
    const criterionId = hasText(criterion?.criterionId) ? criterion.criterionId : 'CRITERION-UNKNOWN';
    addReason(reasons, !hasText(criterion?.criterionId), 'applicability_criterion_id_absent');
    addReason(reasons, !hasText(criterion?.subject), `applicability_criterion_subject_absent:${criterionId}`);
    addReason(
      reasons,
      !APPLICABILITY_OPERATORS.has(criterion?.operator),
      `applicability_criterion_operator_invalid:${criterionId}`,
    );
    addReason(reasons, !isDigest(criterion?.valueHash), `applicability_criterion_value_hash_invalid:${criterionId}`);
    addReason(
      reasons,
      !APPLICABILITY_STATES.has(criterion?.outcome),
      `applicability_criterion_outcome_invalid:${criterionId}`,
    );

    return {
      criterionId,
      operator: criterion?.operator ?? null,
      outcome: criterion?.outcome ?? null,
      subject: criterion?.subject ?? null,
      valueHash: criterion?.valueHash ?? null,
    };
  });
}

function normalizeEvidenceRequirements(evidenceRequirements, reasons, collectionName) {
  const requirements = Array.isArray(evidenceRequirements) ? [...evidenceRequirements].sort(evidenceRequirementSort) : [];
  if (collectionName === 'requiredEvidence') {
    addReason(reasons, requirements.length === 0, 'required_evidence_absent');
  }

  return requirements.map((requirement) => {
    const artifactType = hasText(requirement?.artifactType) ? requirement.artifactType : 'EVIDENCE-UNKNOWN';
    addReason(reasons, !hasText(requirement?.artifactType), `${collectionName}_artifact_type_absent`);
    addReason(reasons, !isPositiveSafeInteger(requirement?.freshnessDays), `${collectionName}_freshness_invalid:${artifactType}`);
    addReason(
      reasons,
      !EVIDENCE_CLASSIFICATIONS.has(requirement?.classification),
      `${collectionName}_classification_invalid:${artifactType}`,
    );
    addReason(reasons, !isDigest(requirement?.evidenceHash), `${collectionName}_hash_invalid:${artifactType}`);

    return {
      artifactType,
      classification: requirement?.classification ?? null,
      evidenceHash: requirement?.evidenceHash ?? null,
      freshnessDays: requirement?.freshnessDays ?? null,
      required: requirement?.required === true,
    };
  });
}

function normalizeWaiverRules(input, reasons) {
  const rules = Array.isArray(input?.control?.waiverRules) ? [...input.control.waiverRules].sort((left, right) => String(left.waiverType).localeCompare(String(right.waiverType))) : [];
  addReason(reasons, rules.length === 0, 'waiver_rules_absent');

  return rules.map((rule) => {
    const waiverType = hasText(rule?.waiverType) ? rule.waiverType : 'WAIVER-UNKNOWN';
    addReason(reasons, !hasText(rule?.waiverType), 'waiver_type_absent');
    addReason(reasons, rule?.rationaleRequired !== true, `waiver_rationale_not_required:${waiverType}`);
    addReason(reasons, !APPROVER_ROLES.has(rule?.approverRole), `waiver_approver_role_invalid:${waiverType}`);
    addReason(reasons, !isPositiveSafeInteger(rule?.maxDays), `waiver_max_days_invalid:${waiverType}`);

    return {
      approverRole: rule?.approverRole ?? null,
      maxDays: rule?.maxDays ?? null,
      rationaleRequired: rule?.rationaleRequired === true,
      waiverType,
    };
  });
}

function normalizeEscalationRules(input, reasons) {
  const rules = Array.isArray(input?.control?.escalationRules)
    ? [...input.control.escalationRules].sort((left, right) => String(left.condition).localeCompare(String(right.condition)))
    : [];
  addReason(reasons, rules.length === 0, 'escalation_rules_absent');

  return rules.map((rule) => {
    const condition = hasText(rule?.condition) ? rule.condition : 'ESCALATION-UNKNOWN';
    addReason(reasons, !hasText(rule?.condition), 'escalation_condition_absent');
    addReason(reasons, !ESCALATION_ROLES.has(rule?.role), `escalation_role_invalid:${condition}`);

    return {
      condition,
      role: rule?.role ?? null,
    };
  });
}

function normalizeAuditExportMappings(input, reasons) {
  const mappings = Array.isArray(input?.control?.auditExportMappings)
    ? [...input.control.auditExportMappings].sort(auditExportSort)
    : [];
  addReason(reasons, mappings.length === 0, 'audit_export_mappings_absent');

  return mappings.map((mapping) => {
    const audience = hasText(mapping?.audience) ? mapping.audience : 'AUDIENCE-UNKNOWN';
    addReason(reasons, !hasText(mapping?.audience), 'audit_export_audience_absent');
    addReason(reasons, !isDigest(mapping?.fieldSetHash), `audit_export_field_set_hash_invalid:${audience}`);

    return {
      audience,
      fieldSetHash: mapping?.fieldSetHash ?? null,
    };
  });
}

function normalizeCrosswalkMappings(input, reasons) {
  const mappings = Array.isArray(input?.control?.crosswalkMappings)
    ? [...input.control.crosswalkMappings].sort(crosswalkSort)
    : [];
  addReason(reasons, mappings.length === 0, 'crosswalk_mappings_absent');

  return mappings.map((mapping) => {
    const framework = hasText(mapping?.framework) ? mapping.framework : 'FRAMEWORK-UNKNOWN';
    addReason(reasons, !hasText(mapping?.framework), 'crosswalk_framework_absent');
    addReason(reasons, !hasText(mapping?.reference), `crosswalk_reference_absent:${framework}`);
    addReason(reasons, !isDigest(mapping?.mappingHash), `crosswalk_mapping_hash_invalid:${framework}`);

    return {
      framework,
      mappingHash: mapping?.mappingHash ?? null,
      reference: mapping?.reference ?? null,
    };
  });
}

function normalizeChangeHistory(input, reasons) {
  const changes = Array.isArray(input?.control?.changeHistory) ? [...input.control.changeHistory].sort(changeHistorySort) : [];
  addReason(reasons, changes.length === 0, 'change_history_absent');

  return changes.map((change) => {
    const changeId = hasText(change?.changeId) ? change.changeId : 'CHANGE-UNKNOWN';
    addReason(reasons, !hasText(change?.changeId), 'change_id_absent');
    addReason(reasons, !CHANGE_TYPES.has(change?.changeType), `change_type_invalid:${changeId}`);
    addReason(reasons, !isDigest(change?.rationaleHash), `change_rationale_hash_invalid:${changeId}`);
    addReason(reasons, !hlcPresent(change?.changedAtHlc), `change_time_invalid:${changeId}`);
    addReason(reasons, !hasText(change?.approvedByDecisionId), `change_approval_absent:${changeId}`);

    return {
      approvedByDecisionId: change?.approvedByDecisionId ?? null,
      changedAtHlc: change?.changedAtHlc ?? null,
      changeId,
      changeType: change?.changeType ?? null,
      rationaleHash: change?.rationaleHash ?? null,
    };
  });
}

function evaluateControlShape(input, normalized, reasons) {
  const control = input?.control;
  addReason(reasons, !hasText(control?.controlId), 'control_id_absent');
  addReason(reasons, !hasText(control?.versionId), 'control_version_id_absent');
  addReason(reasons, !hasText(control?.title), 'control_title_absent');
  addReason(reasons, !isDigest(control?.normativeStatementHash), 'normative_statement_hash_invalid');
  addReason(reasons, !isDigest(control?.plainLanguageExplanationHash), 'plain_language_explanation_hash_invalid');
  addReason(reasons, !hasText(control?.ownerRole), 'control_owner_role_absent');
  addReason(reasons, !APPROVER_ROLES.has(control?.approverRole), 'control_approver_role_invalid');
  addReason(reasons, !hasText(control?.reviewerRole), 'control_reviewer_role_absent');
  addReason(reasons, !isPositiveSafeInteger(control?.reviewFrequencyDays), 'review_frequency_invalid');
  addReason(reasons, normalized.triggerEvents.length === 0, 'trigger_events_absent');
  addReason(reasons, !CONTROL_RISK_CRITICALITIES.has(control?.riskCriticality), 'control_risk_criticality_invalid');
  addReason(reasons, !isDigest(control?.aiReviewPromptHash), 'ai_review_prompt_hash_invalid');
  addReason(reasons, normalized.humanReviewGates.length === 0, 'human_review_gates_absent');
  addReason(reasons, !CONTROL_STATUSES.has(control?.status), 'control_status_not_active');
  addReason(reasons, control?.materialChange !== true && control?.materialChange !== false, 'material_change_flag_invalid');
  addReason(reasons, !hlcPresent(control?.effectiveAtHlc), 'control_effective_time_invalid');
  addReason(reasons, control?.status === 'active' && control?.retiredAtHlc !== null, 'active_control_has_retirement_time');
  addReason(reasons, !hlcPresent(input?.publishedAtHlc), 'control_published_time_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function evaluateRelevance(input, reasons) {
  const relevance = input?.control?.relevance;
  const relevanceValues = CONTROL_RELEVANCE_KEYS.map((key) => relevance?.[key]);
  addReason(reasons, relevanceValues.every((value) => value !== true), 'control_relevance_absent');
  for (const key of CONTROL_RELEVANCE_KEYS) {
    addReason(reasons, typeof relevance?.[key] !== 'boolean', `control_relevance_flag_invalid:${key}`);
  }
}

function evaluateCapaLinkage(input, reasons) {
  const capaLinkage = input?.control?.capaLinkage;
  addReason(reasons, capaLinkage?.requiredForCriticalFindings !== true, 'capa_linkage_critical_findings_not_required');
  addReason(reasons, !CONTROL_RISK_CRITICALITIES.has(capaLinkage?.requiredSeverity), 'capa_linkage_required_severity_invalid');
  addReason(reasons, !hasText(capaLinkage?.capaControlRef), 'capa_control_ref_absent');
}

function evaluateGovernanceReview(input, reasons) {
  const review = input?.governanceReview;
  addReason(reasons, review === null || review === undefined, 'governance_review_absent');
  addReason(reasons, review?.reviewed !== true, 'governance_review_unreviewed');
  addReason(reasons, !GOVERNANCE_REVIEW_DECISIONS.has(review?.decision), 'governance_review_not_approved');
  addReason(reasons, !hasText(review?.reviewerDid), 'governance_reviewer_absent');
  addReason(reasons, review?.humanVerified !== true, 'governance_reviewer_human_unverified');
  addReason(reasons, !isDigest(review?.reviewHash), 'governance_review_hash_invalid');
  addReason(reasons, !hlcPresent(review?.reviewedAtHlc), 'governance_review_time_invalid');
}

function evaluateMaterialDecisionForum(input, reasons) {
  if (input?.control?.materialChange !== true) {
    return;
  }

  const decisionForum = input?.decisionForum;
  addReason(reasons, decisionForum?.verified !== true, 'material_decision_forum_unverified');
  addReason(reasons, decisionForum?.state !== 'approved', 'material_decision_forum_not_approved');
  addReason(reasons, decisionForum?.humanGate?.verified !== true, 'material_decision_forum_human_gate_unverified');
  addReason(reasons, decisionForum?.quorum?.status !== 'met', 'material_decision_forum_quorum_not_met');
  addReason(reasons, decisionForum?.openChallenge === true, 'material_decision_forum_challenge_open');
  addReason(reasons, !hasText(decisionForum?.decisionId), 'material_decision_forum_decision_id_absent');
  addReason(reasons, !hasText(decisionForum?.workflowReceiptId), 'material_decision_forum_workflow_receipt_absent');
  addReason(reasons, input?.evidenceBundle?.complete !== true, 'evidence_bundle_incomplete');
  addReason(reasons, input?.evidenceBundle?.phiBoundaryAttested !== true, 'phi_boundary_unattested');
}

function normalizeControlDefinition(input, reasons) {
  const normalized = {
    auditExportMappings: normalizeAuditExportMappings(input, reasons),
    applicabilityCriteria: normalizeApplicabilityCriteria(input, reasons),
    changeHistory: normalizeChangeHistory(input, reasons),
    crosswalkMappings: normalizeCrosswalkMappings(input, reasons),
    dependencies: sortedTextList(input?.control?.dependencies),
    escalationRules: normalizeEscalationRules(input, reasons),
    humanReviewGates: sortedTextList(input?.control?.humanReviewGates),
    optionalEvidence: normalizeEvidenceRequirements(input?.control?.optionalEvidence, reasons, 'optionalEvidence'),
    requiredEvidence: normalizeEvidenceRequirements(input?.control?.requiredEvidence, reasons, 'requiredEvidence'),
    sourceRefs: normalizeSourceRefs(input, reasons),
    triggerEvents: sortedTextList(input?.control?.triggerEvents),
    waiverRules: normalizeWaiverRules(input, reasons),
  };

  evaluateControlShape(input, normalized, reasons);
  evaluateRelevance(input, reasons);
  evaluateCapaLinkage(input, reasons);
  evaluateGovernanceReview(input, reasons);
  evaluateMaterialDecisionForum(input, reasons);

  return normalized;
}

function controlFingerprintPayload(input, normalized) {
  return {
    aiReviewPromptHash: input.control.aiReviewPromptHash,
    applicabilityCriteria: normalized.applicabilityCriteria,
    approverRole: input.control.approverRole,
    auditExportMappings: normalized.auditExportMappings,
    capaLinkage: input.control.capaLinkage,
    changeHistory: normalized.changeHistory,
    controlId: input.control.controlId,
    crosswalkMappings: normalized.crosswalkMappings,
    dependencies: normalized.dependencies,
    effectiveAtHlc: input.control.effectiveAtHlc,
    escalationRules: normalized.escalationRules,
    humanReviewGates: normalized.humanReviewGates,
    normativeStatementHash: input.control.normativeStatementHash,
    optionalEvidence: normalized.optionalEvidence,
    ownerRole: input.control.ownerRole,
    plainLanguageExplanationHash: input.control.plainLanguageExplanationHash,
    relevance: input.control.relevance,
    requiredEvidence: normalized.requiredEvidence,
    reviewFrequencyDays: input.control.reviewFrequencyDays,
    reviewerRole: input.control.reviewerRole,
    riskCriticality: input.control.riskCriticality,
    sourceRefs: normalized.sourceRefs,
    status: input.control.status,
    title: input.control.title,
    triggerEvents: normalized.triggerEvents,
    versionId: input.control.versionId,
    waiverRules: normalized.waiverRules,
  };
}

function buildControlVersionReceipt(input, artifactHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'standards_control_version',
    artifactVersion: `${input.control.controlId}@${input.control.versionId}:${input.control.status}`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.publishedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['control_library', 'metadata_only', 'standards_derived', 'human_governed'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function publishStandardsControlVersion(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const normalized = normalizeControlDefinition(input, reasons);
  const uniqueReasons = uniqueSorted(reasons);
  const denied = uniqueReasons.length > 0;

  if (denied) {
    return {
      schema: 'cybermedica.standards_control_version_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      controlVersion: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const controlFingerprint = sha256Hex(controlFingerprintPayload(input, normalized));
  const receipt = buildControlVersionReceipt(input, controlFingerprint);

  return {
    schema: 'cybermedica.standards_control_version_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    controlVersion: {
      schema: 'cybermedica.standards_control_version.v1',
      controlVersionId: `cmcl_${sha256Hex({
        controlFingerprint,
        controlId: input.control.controlId,
        tenantId: input.tenantId,
        versionId: input.control.versionId,
      }).slice(0, 32)}`,
      tenantId: input.tenantId,
      controlId: input.control.controlId,
      versionId: input.control.versionId,
      title: input.control.title,
      status: input.control.status,
      materialChange: input.control.materialChange,
      sourceRefs: normalized.sourceRefs.map((sourceRef) => sourceRef.sourceRefId),
      sourceRightsAttested: normalized.sourceRefs.every((sourceRef) => sourceRef.rightsAttested === true),
      normativeStatementHash: input.control.normativeStatementHash,
      plainLanguageExplanationHash: input.control.plainLanguageExplanationHash,
      applicabilityCriteriaCount: normalized.applicabilityCriteria.length,
      ownerRole: input.control.ownerRole,
      approverRole: input.control.approverRole,
      reviewerRole: input.control.reviewerRole,
      requiredEvidenceTypes: normalized.requiredEvidence.map((requirement) => requirement.artifactType),
      optionalEvidenceTypes: normalized.optionalEvidence.map((requirement) => requirement.artifactType),
      reviewFrequencyDays: input.control.reviewFrequencyDays,
      triggerEvents: normalized.triggerEvents,
      riskCriticality: input.control.riskCriticality,
      relevance: input.control.relevance,
      humanReviewGates: normalized.humanReviewGates,
      waiverRules: normalized.waiverRules.map((rule) => rule.waiverType),
      escalationRoles: uniqueSorted(normalized.escalationRules.map((rule) => rule.role)),
      capaControlRef: input.control.capaLinkage.capaControlRef,
      auditExportAudiences: normalized.auditExportMappings.map((mapping) => mapping.audience),
      dependencies: normalized.dependencies,
      crosswalkFrameworks: uniqueSorted(normalized.crosswalkMappings.map((mapping) => mapping.framework)),
      changeHistoryRefs: normalized.changeHistory.map((change) => change.changeId),
      effectiveAtHlc: input.control.effectiveAtHlc,
      retiredAtHlc: input.control.retiredAtHlc,
      governanceReviewerDid: input.governanceReview.reviewerDid,
      decisionForumDecisionId: input.control.materialChange ? input.decisionForum.decisionId : null,
      workflowReceiptId: input.control.materialChange ? input.decisionForum.workflowReceiptId : null,
      controlFingerprint,
      receiptId: receipt.receiptId,
      allPrdFieldsRepresented: true,
      metadataOnly: true,
      containsProtectedContent: false,
      aiFinalAuthority: false,
      humanGovernanceRequired: true,
      operationalStateMutable: true,
      immutableVersionReceipt: true,
      trustState: 'inactive',
      exochainProductionClaim: false,
    },
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function evaluateControlRef(input, reasons) {
  const controlRef = input?.controlRef;
  addReason(reasons, !hasText(controlRef?.controlId), 'control_ref_id_absent');
  addReason(reasons, !hasText(controlRef?.versionId), 'control_ref_version_absent');
  addReason(reasons, controlRef?.status !== 'active', 'control_ref_inactive');
  addReason(reasons, !isDigest(controlRef?.controlFingerprint), 'control_fingerprint_invalid');
  addReason(reasons, !hasText(controlRef?.controlVersionReceiptRef), 'control_version_receipt_ref_absent');
}

function evaluateApplicabilitySubject(input, reasons) {
  const subject = input?.subject;
  addReason(reasons, !hasText(subject?.siteRef), 'subject_site_ref_absent');
}

function evaluateApplicabilityApproval(input, reasons) {
  const approvalEvidence = input?.approvalEvidence;
  addReason(reasons, approvalEvidence === null || approvalEvidence === undefined, 'applicability_approval_absent');
  addReason(reasons, approvalEvidence?.reviewed !== true, 'applicability_approval_unreviewed');
  addReason(reasons, approvalEvidence?.humanVerified !== true, 'applicability_human_approval_unverified');
  addReason(reasons, !APPROVER_ROLES.has(approvalEvidence?.approverRole), 'applicability_approver_role_invalid');
  addReason(reasons, !isDigest(approvalEvidence?.decisionHash), 'applicability_decision_hash_invalid');
}

function evaluateApplicabilityDetermination(input, reasons) {
  const determination = input?.determination;
  addReason(reasons, !APPLICABILITY_STATES.has(determination?.state), 'applicability_state_invalid');
  addReason(reasons, !isDigest(determination?.rationaleHash), 'applicability_rationale_hash_invalid');
  addReason(reasons, sortedTextList(determination?.criteriaEvidenceRefs).length === 0, 'applicability_criteria_evidence_absent');
  addReason(reasons, !hasText(determination?.approvedByDid), 'applicability_approver_absent');
  addReason(reasons, !hlcPresent(determination?.approvedAtHlc), 'applicability_approval_time_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  if (determination?.state === 'conditionally_applicable') {
    addReason(reasons, !isDigest(determination?.conditionHash), 'condition_hash_invalid');
  }
  if (determination?.state === 'waived') {
    addReason(reasons, !hasText(determination?.waiverRuleRef), 'waiver_rule_ref_absent');
    addReason(reasons, !hlcPresent(determination?.waiverExpiresAtHlc), 'waiver_expiry_invalid');
    addReason(
      reasons,
      hlcPresent(determination?.approvedAtHlc) &&
        hlcPresent(determination?.waiverExpiresAtHlc) &&
        compareHlc(determination.waiverExpiresAtHlc, determination.approvedAtHlc) <= 0,
      'waiver_expiry_not_after_approval',
    );
  }
  if (determination?.state === 'deferred') {
    addReason(reasons, !hlcPresent(determination?.deferredUntilHlc), 'deferred_until_invalid');
    addReason(
      reasons,
      hlcPresent(determination?.approvedAtHlc) &&
        hlcPresent(determination?.deferredUntilHlc) &&
        compareHlc(determination.deferredUntilHlc, determination.approvedAtHlc) <= 0,
      'deferred_until_not_after_approval',
    );
  }
  if (determination?.state === 'superseded') {
    addReason(reasons, !hasText(determination?.supersedingControlId), 'superseding_control_id_absent');
    addReason(reasons, !hasText(determination?.supersedingVersionId), 'superseding_version_id_absent');
  }
}

function applicabilityArtifactHash(input, criteriaEvidenceRefs) {
  return sha256Hex({
    approvalEvidence: input.approvalEvidence,
    controlFingerprint: input.controlRef.controlFingerprint,
    controlId: input.controlRef.controlId,
    criteriaEvidenceRefs,
    determination: input.determination,
    subject: input.subject,
    tenantId: input.tenantId,
    versionId: input.controlRef.versionId,
  });
}

function buildApplicabilityReceipt(input, artifactHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'control_applicability_determination',
    artifactVersion: `${input.controlRef.controlId}@${input.controlRef.versionId}:${input.determination.state}`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.determination.approvedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['control_applicability', 'metadata_only', 'human_approved'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function determineControlApplicability(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateControlRef(input, reasons);
  evaluateApplicabilitySubject(input, reasons);
  evaluateApplicabilityDetermination(input, reasons);
  evaluateApplicabilityApproval(input, reasons);

  const uniqueReasons = uniqueSorted(reasons);
  const denied = uniqueReasons.length > 0;

  if (denied) {
    return {
      schema: 'cybermedica.control_applicability_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      applicability: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const criteriaEvidenceRefs = sortedTextList(input.determination.criteriaEvidenceRefs);
  const artifactHash = applicabilityArtifactHash(input, criteriaEvidenceRefs);
  const receipt = buildApplicabilityReceipt(input, artifactHash);

  return {
    schema: 'cybermedica.control_applicability_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    applicability: {
      schema: 'cybermedica.control_applicability.v1',
      applicabilityId: `cmca_${sha256Hex({
        artifactHash,
        controlId: input.controlRef.controlId,
        state: input.determination.state,
        subject: input.subject,
        tenantId: input.tenantId,
        versionId: input.controlRef.versionId,
      }).slice(0, 32)}`,
      tenantId: input.tenantId,
      controlId: input.controlRef.controlId,
      versionId: input.controlRef.versionId,
      controlVersionReceiptRef: input.controlRef.controlVersionReceiptRef,
      controlFingerprint: input.controlRef.controlFingerprint,
      state: input.determination.state,
      subject: input.subject,
      rationaleHash: input.determination.rationaleHash,
      criteriaEvidenceRefs,
      approvedByDid: input.determination.approvedByDid,
      approvedAtHlc: input.determination.approvedAtHlc,
      approvalDecisionHash: input.approvalEvidence.decisionHash,
      approverRole: input.approvalEvidence.approverRole,
      conditionHash: input.determination.conditionHash,
      waiverRuleRef: input.determination.waiverRuleRef,
      waiverExpiresAtHlc: input.determination.waiverExpiresAtHlc,
      deferredUntilHlc: input.determination.deferredUntilHlc,
      supersedingControlId: input.determination.supersedingControlId,
      supersedingVersionId: input.determination.supersedingVersionId,
      receiptId: receipt.receiptId,
      approvalRequired: true,
      rationaleRequired: true,
      metadataOnly: true,
      containsProtectedContent: false,
      aiFinalAuthority: false,
      humanGovernanceRequired: true,
      operationalStateMutable: true,
      immutableApplicabilityReceipt: true,
      trustState: 'inactive',
      exochainProductionClaim: false,
    },
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
