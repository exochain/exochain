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
const MAX_BASIS_POINTS = 10000;
const EXPLAINABILITY_POLICY_SCHEMA = 'cybermedica.assistant_explainability_policy.v1';
const EXPLAINABILITY_RECORD_SCHEMA = 'cybermedica.assistant_explainability_record.v1';

const REQUIRED_OUTPUT_CLASSES = Object.freeze([
  'ai_control_review',
  'audit_assessment_review',
  'decision_support_summary',
  'kpi_trend_analysis',
  'orientation_guidance',
  'reporting_export_explanation',
  'workflow_guidance',
]);

const REQUIRED_EXPLANATION_FIELDS = Object.freeze([
  'confidence',
  'evidence_references',
  'limitations',
  'reasoning_summary',
  'recommended_human_reviewers',
  'unresolved_assumptions',
]);

const ASSISTANT_KINDS = new Set(['ai_agent', 'ai_assistant', 'ai_model', 'retrieval_assistant', 'rules_assistant']);

const RAW_ASSISTANT_FIELDS = new Set([
  'assistantoutput',
  'assumptiontext',
  'freeformanswer',
  'freeformexplanation',
  'freeformguidance',
  'freeformrationale',
  'limitationtext',
  'outputbody',
  'outputcopy',
  'outputtext',
  'promptbody',
  'prompttext',
  'rawanswer',
  'rawassistantoutput',
  'rawexplanation',
  'rawguidance',
  'rawinput',
  'rawoutput',
  'rawprompt',
  'rawreasoning',
  'reasoningbody',
  'reasoningcopy',
  'reasoningtext',
  'recommendationtext',
  'reviewernotes',
  'sourcecontent',
  'sourcedocument',
  'sourcedocumentbody',
  'unresolvedassumptiontext',
]);

const SECRET_ASSISTANT_FIELDS = new Set([
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
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
}

function isBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_BASIS_POINTS;
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

function assertNoRawAssistantContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawAssistantContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_ASSISTANT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw assistant explainability content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_ASSISTANT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`assistant explainability secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawAssistantContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawAssistantContent(input ?? {});
  canonicalize(input ?? {});
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [hlc.physicalMs, hlc.logical];
}

function compareHlcTuples(left, right) {
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
  return leftTuple !== null && rightTuple !== null && compareHlcTuples(leftTuple, rightTuple) > 0;
}

function hlcNotAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlcTuples(leftTuple, rightTuple) <= 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_explainability_governor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, 'explainability_review') && !hasAuthorityPermission(input?.authority, 'govern'),
    'explainability_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function normalizePolicy(input, reasons) {
  const policy = input?.explainabilityPolicy;
  const requiredOutputClasses = sortedTextList(policy?.requiredOutputClasses);
  const requiredFields = sortedTextList(policy?.requiredExplanationFields);
  const allowedReviewerRoles = sortedTextList(policy?.allowedReviewerRoles);

  addReason(reasons, !hasText(policy?.policyRef), 'explainability_policy_ref_absent');
  addReason(reasons, policy?.schemaVersion !== EXPLAINABILITY_POLICY_SCHEMA, 'explainability_policy_schema_invalid');
  addReason(reasons, policy?.status !== 'approved', 'explainability_policy_not_approved');
  for (const outputClass of REQUIRED_OUTPUT_CLASSES) {
    addReason(reasons, !requiredOutputClasses.includes(outputClass), `policy_required_output_class_missing:${outputClass}`);
  }
  for (const field of REQUIRED_EXPLANATION_FIELDS) {
    addReason(reasons, !requiredFields.includes(field), `policy_required_field_missing:${field}`);
  }
  addReason(reasons, allowedReviewerRoles.length === 0, 'policy_allowed_reviewer_roles_absent');
  addReason(reasons, !isBasisPoints(policy?.minimumConfidenceForDisplayBasisPoints), 'policy_confidence_threshold_invalid');
  addReason(reasons, policy?.humanReviewRequired !== true, 'policy_human_review_required_absent');
  addReason(reasons, policy?.contestable !== true, 'policy_contestation_absent');
  addReason(reasons, policy?.aiFinalAuthorityAllowed === true, 'policy_allows_ai_final_authority');
  addReason(reasons, !isDigest(policy?.sourceBoundaryHash), 'policy_source_boundary_hash_invalid');
  addReason(reasons, !isDigest(policy?.humanReviewPolicyHash), 'policy_human_review_hash_invalid');
  addReason(reasons, !isDigest(policy?.retentionPolicyHash), 'policy_retention_hash_invalid');
  addReason(reasons, policy?.metadataOnly !== true, 'policy_metadata_boundary_invalid');

  return {
    allowedReviewerRoles,
    contestable: policy?.contestable === true,
    humanReviewRequired: policy?.humanReviewRequired === true,
    minimumConfidenceForDisplayBasisPoints: isBasisPoints(policy?.minimumConfidenceForDisplayBasisPoints)
      ? policy.minimumConfidenceForDisplayBasisPoints
      : MAX_BASIS_POINTS,
    policyRef: hasText(policy?.policyRef) ? policy.policyRef : 'EXPLAINABILITY-POLICY-UNKNOWN',
    requiredFields,
    requiredOutputClasses,
  };
}

function normalizeOutputs(input, policy, reasons) {
  const outputs = Array.isArray(input?.outputs) ? [...input.outputs].sort((left, right) => String(left?.outputRef).localeCompare(String(right?.outputRef))) : [];
  addReason(reasons, outputs.length === 0, 'assistant_outputs_absent');

  const outputClassCoverage = uniqueSorted(outputs.map((output) => output?.outputClass));
  for (const outputClass of REQUIRED_OUTPUT_CLASSES) {
    addReason(reasons, !outputClassCoverage.includes(outputClass), `required_output_class_missing:${outputClass}`);
  }

  return outputs.map((output) => {
    const outputRef = hasText(output?.outputRef) ? output.outputRef : 'assistant-output-unknown';
    const aiBacked = ['ai_agent', 'ai_assistant', 'ai_model'].includes(output?.assistantKind);
    const evidenceRefs = sortedTextList(output?.evidenceRefs);
    const limitationHashes = sortedTextList(output?.limitationHashes);
    const unresolvedAssumptionHashes = Array.isArray(output?.unresolvedAssumptionHashes)
      ? sortedTextList(output.unresolvedAssumptionHashes)
      : [];
    const recommendedHumanReviewerRoles = sortedTextList(output?.recommendedHumanReviewerRoles);

    addReason(reasons, !hasText(output?.outputRef), 'output_ref_absent');
    addReason(reasons, !REQUIRED_OUTPUT_CLASSES.includes(output?.outputClass), `output_class_invalid:${outputRef}`);
    addReason(reasons, !ASSISTANT_KINDS.has(output?.assistantKind), `output_assistant_kind_invalid:${outputRef}`);
    addReason(
      reasons,
      aiBacked && !isDigest(output?.modelRefHash),
      `output_model_ref_hash_invalid:${outputRef}`,
    );
    addReason(
      reasons,
      ['retrieval_assistant', 'rules_assistant'].includes(output?.assistantKind) && !isDigest(output?.generatorPolicyHash),
      `output_generator_policy_hash_invalid:${outputRef}`,
    );
    addReason(reasons, aiBacked && output?.aiGeneratedSummaryMarked !== true, `output_ai_generated_marker_absent:${outputRef}`);
    addReason(
      reasons,
      output?.humanEnteredEvidencePolicy !== 'preserve_original_require_human_review',
      `output_human_evidence_policy_invalid:${outputRef}`,
    );
    addReason(
      reasons,
      output?.humanEvidenceOverwriteAllowed === true,
      `output_human_evidence_overwrite_forbidden:${outputRef}`,
    );
    addReason(reasons, !isDigest(output?.promptHash), `output_prompt_hash_invalid:${outputRef}`);
    addReason(reasons, !isDigest(output?.inputManifestHash), `output_input_manifest_hash_invalid:${outputRef}`);
    addReason(reasons, !isDigest(output?.outputHash), `output_hash_invalid:${outputRef}`);
    addReason(reasons, hlcTuple(output?.generatedAtHlc) === null, `output_generated_hlc_invalid:${outputRef}`);
    addReason(reasons, evidenceRefs.length === 0, `output_evidence_refs_absent:${outputRef}`);
    addReason(reasons, !isDigest(output?.evidenceManifestHash), `output_evidence_manifest_hash_invalid:${outputRef}`);
    addReason(reasons, !isDigest(output?.reasoningSummaryHash), `output_reasoning_summary_hash_invalid:${outputRef}`);
    addReason(reasons, !isBasisPoints(output?.confidenceBasisPoints), `output_confidence_basis_points_invalid:${outputRef}`);
    addReason(reasons, limitationHashes.length === 0, `output_limitations_absent:${outputRef}`);
    for (const limitationHash of limitationHashes) {
      addReason(reasons, !isDigest(limitationHash), `output_limitation_hash_invalid:${outputRef}`);
    }
    addReason(reasons, !Array.isArray(output?.unresolvedAssumptionHashes), `output_unresolved_assumptions_absent:${outputRef}`);
    for (const assumptionHash of unresolvedAssumptionHashes) {
      addReason(reasons, !isDigest(assumptionHash), `output_unresolved_assumption_hash_invalid:${outputRef}`);
    }
    addReason(reasons, output?.unresolvedAssumptionsReviewed !== true, `output_unresolved_assumptions_not_reviewed:${outputRef}`);
    addReason(reasons, recommendedHumanReviewerRoles.length === 0, `output_reviewer_roles_absent:${outputRef}`);
    for (const role of recommendedHumanReviewerRoles) {
      addReason(reasons, !policy.allowedReviewerRoles.includes(role), `output_reviewer_role_not_allowed:${outputRef}:${role}`);
    }
    addReason(reasons, output?.requiresHumanReview !== true, `output_human_review_required_absent:${outputRef}`);
    addReason(reasons, output?.advisoryOnly !== true || output?.finalAuthority === true, `output_ai_final_authority_forbidden:${outputRef}`);
    addReason(reasons, output?.metadataOnly !== true, `output_metadata_boundary_invalid:${outputRef}`);
    addReason(
      reasons,
      isBasisPoints(output?.confidenceBasisPoints) &&
        output.confidenceBasisPoints < policy.minimumConfidenceForDisplayBasisPoints &&
        !hasText(output?.lowConfidenceEscalationRef),
      `output_low_confidence_escalation_absent:${outputRef}`,
    );

    return {
      advisoryOnly: output?.advisoryOnly === true && output?.finalAuthority !== true,
      aiGeneratedSummaryMarked: aiBacked ? output?.aiGeneratedSummaryMarked === true : false,
      assistantKind: output?.assistantKind ?? null,
      canOpenCqiItem: output?.canOpenCqiItem === true,
      confidenceBasisPoints: isBasisPoints(output?.confidenceBasisPoints) ? output.confidenceBasisPoints : null,
      evidenceManifestHash: output?.evidenceManifestHash ?? null,
      evidenceRefs,
      generatedAtHlc: output?.generatedAtHlc ?? null,
      humanEnteredEvidencePolicy: output?.humanEnteredEvidencePolicy ?? null,
      humanEvidenceOverwriteAllowed: output?.humanEvidenceOverwriteAllowed === true,
      inputManifestHash: output?.inputManifestHash ?? null,
      limitationHashes,
      lowConfidence: isBasisPoints(output?.confidenceBasisPoints) && output.confidenceBasisPoints < policy.minimumConfidenceForDisplayBasisPoints,
      lowConfidenceEscalationRef: output?.lowConfidenceEscalationRef ?? null,
      outputClass: output?.outputClass ?? null,
      outputHash: output?.outputHash ?? null,
      outputRef,
      promptHash: output?.promptHash ?? null,
      reasoningSummaryHash: output?.reasoningSummaryHash ?? null,
      recommendedHumanReviewerRoles,
      requiresHumanReview: output?.requiresHumanReview === true,
      unresolvedAssumptionHashes,
      unresolvedAssumptionsReviewed: output?.unresolvedAssumptionsReviewed === true,
    };
  });
}

function normalizeReviewRouting(input, policy, outputRefs, routeGeneratedAtHlc, reasons) {
  const route = input?.reviewRouting;
  const assignments = Array.isArray(route?.reviewerAssignments)
    ? [...route.reviewerAssignments].sort((left, right) => String(left?.roleRef).localeCompare(String(right?.roleRef)))
    : [];
  const outputRefSet = new Set(outputRefs);

  addReason(reasons, !hasText(route?.routeRef), 'review_route_ref_absent');
  addReason(reasons, hlcTuple(route?.generatedAtHlc) === null, 'review_route_generated_time_invalid');
  addReason(reasons, hlcTuple(route?.queuedAtHlc) === null, 'review_route_queue_time_invalid');
  addReason(reasons, hlcTuple(route?.dueAtHlc) === null, 'review_route_due_time_invalid');
  addReason(reasons, hlcNotAfter(route?.queuedAtHlc, route?.generatedAtHlc), 'review_route_queue_not_after_generation');
  addReason(reasons, hlcNotAfter(route?.dueAtHlc, route?.queuedAtHlc), 'review_route_due_not_after_queue');
  addReason(reasons, assignments.length === 0, 'review_assignments_absent');
  addReason(reasons, !hasText(route?.escalationPathRef), 'review_route_escalation_path_absent');
  addReason(reasons, !isDigest(route?.disclosureLogHash), 'review_route_disclosure_log_hash_invalid');
  addReason(reasons, route?.metadataOnly !== true, 'review_route_metadata_boundary_invalid');

  const assignmentOutputRefs = [];
  const normalizedAssignments = assignments.map((assignment) => {
    const roleRef = hasText(assignment?.roleRef) ? assignment.roleRef : 'reviewer-role-unknown';
    const refs = sortedTextList(assignment?.outputRefs);
    assignmentOutputRefs.push(...refs);

    addReason(reasons, !hasText(assignment?.roleRef), 'review_assignment_role_absent');
    addReason(reasons, !policy.allowedReviewerRoles.includes(roleRef), `review_assignment_role_not_allowed:${roleRef}`);
    addReason(reasons, !hasText(assignment?.queueRef), `review_assignment_queue_ref_absent:${roleRef}`);
    addReason(reasons, refs.length === 0, `review_assignment_outputs_absent:${roleRef}`);
    for (const outputRef of refs) {
      addReason(reasons, !outputRefSet.has(outputRef), `review_assignment_output_unknown:${roleRef}:${outputRef}`);
    }
    addReason(reasons, assignment?.required !== true, `review_assignment_not_required:${roleRef}`);
    addReason(reasons, !isDigest(assignment?.acceptanceCriteriaHash), `review_assignment_acceptance_hash_invalid:${roleRef}`);
    addReason(reasons, !hasText(assignment?.escalationRoleRef), `review_assignment_escalation_role_absent:${roleRef}`);
    addReason(reasons, assignment?.metadataOnly !== true, `review_assignment_metadata_boundary_invalid:${roleRef}`);

    return {
      acceptanceCriteriaHash: assignment?.acceptanceCriteriaHash ?? null,
      escalationRoleRef: assignment?.escalationRoleRef ?? null,
      outputRefs: refs,
      queueRef: assignment?.queueRef ?? null,
      required: assignment?.required === true,
      roleRef,
    };
  });

  const assignedOutputRefSet = new Set(assignmentOutputRefs);
  for (const outputRef of outputRefs) {
    addReason(reasons, !assignedOutputRefSet.has(outputRef), `output_not_routed:${outputRef}`);
  }

  return {
    disclosureLogHash: route?.disclosureLogHash ?? null,
    dueAtHlc: route?.dueAtHlc ?? null,
    escalationPathRef: route?.escalationPathRef ?? null,
    generatedAtHlc: routeGeneratedAtHlc,
    queuedAtHlc: route?.queuedAtHlc ?? null,
    routeRef: hasText(route?.routeRef) ? route.routeRef : 'REVIEW-ROUTE-UNKNOWN',
    reviewerAssignments: normalizedAssignments,
  };
}

function averageBasisPoints(outputs) {
  const values = outputs.map((output) => output.confidenceBasisPoints).filter(Number.isSafeInteger);
  return Number(values.reduce((sum, value) => sum + BigInt(value), 0n) / BigInt(values.length));
}

function buildHumanReviewQueue(assignments) {
  return assignments
    .flatMap((assignment) => assignment.outputRefs.map((outputRef) => `${assignment.roleRef}:${outputRef}`))
    .sort();
}

function buildRecordHash(input, policy, outputs, route, humanReviewQueue, requiredReviewerRoles) {
  return sha256Hex({
    actorDid: input.actor.did,
    humanReviewQueue,
    outputs,
    policy: {
      contestable: policy.contestable,
      humanReviewRequired: policy.humanReviewRequired,
      policyRef: policy.policyRef,
      requiredFields: REQUIRED_EXPLANATION_FIELDS,
      requiredOutputClasses: REQUIRED_OUTPUT_CLASSES,
    },
    requiredReviewerRoles,
    route,
    tenantId: input.tenantId,
  });
}

function buildReceipt(input, route, recordHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'assistant_explainability',
    artifactVersion: `${route.routeRef}@nfr-011`,
    artifactHash: recordHash,
    classification: 'restricted_metadata_only',
    hlcTimestamp: route.queuedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['assistant_output', 'explainability', 'human_review_required', 'metadata_only'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function evaluateAssistantExplainability(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policy = normalizePolicy(input, reasons);
  const outputs = normalizeOutputs(input, policy, reasons);
  const outputRefs = outputs.map((output) => output.outputRef);
  const route = normalizeReviewRouting(input, policy, outputRefs, input?.reviewRouting?.generatedAtHlc ?? null, reasons);

  for (const output of outputs) {
    addReason(reasons, hlcAfter(output.generatedAtHlc, route.generatedAtHlc), `output_generated_after_route:${output.outputRef}`);
  }

  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const uniqueReasons = [...new Set(reasons)].sort();
  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.assistant_explainability_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      explainabilityRecord: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const outputClassCoverage = uniqueSorted(outputs.map((output) => output.outputClass));
  const assistantKinds = uniqueSorted(outputs.map((output) => output.assistantKind));
  const requiredReviewerRoles = uniqueSorted(outputs.flatMap((output) => output.recommendedHumanReviewerRoles));
  const humanReviewQueue = buildHumanReviewQueue(route.reviewerAssignments);
  const lowConfidenceOutputRefs = outputs.filter((output) => output.lowConfidence).map((output) => output.outputRef).sort();
  const recordHash = buildRecordHash(input, policy, outputs, route, humanReviewQueue, requiredReviewerRoles);
  const receipt = buildReceipt(input, route, recordHash);

  return {
    schema: 'cybermedica.assistant_explainability_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    explainabilityRecord: {
      schema: EXPLAINABILITY_RECORD_SCHEMA,
      recordId: `cmaex_${sha256Hex({
        recordHash,
        routeRef: route.routeRef,
        tenantId: input.tenantId,
      }).slice(0, 32)}`,
      tenantId: input.tenantId,
      policyRef: policy.policyRef,
      routeRef: route.routeRef,
      outputRefs,
      outputClassCoverage,
      explanationFieldCoverage: [...REQUIRED_EXPLANATION_FIELDS],
      assistantKinds,
      averageConfidenceBasisPoints: averageBasisPoints(outputs),
      lowConfidenceOutputRefs,
      requiredReviewerRoles,
      humanReviewQueue,
      humanReviewRequired: true,
      humanFinalAuthorityRequired: true,
      contestable: true,
      assistanceOnly: true,
      aiFinalAuthority: false,
      recordHash,
      receiptId: receipt.receiptId,
      trustState: 'inactive',
      exochainProductionClaim: false,
      operationalStateMutable: true,
      immutableExplainabilityReceipt: true,
    },
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
