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
const ENGINE_SCHEMA = 'cybermedica.workflow_engine_readiness.v1';
const DECISION_SCHEMA = 'cybermedica.workflow_engine_decision.v1';
const REQUIRED_PERMISSION = 'workflow_engine_review';
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

const REQUIRED_WORKFLOW_DOMAINS = Object.freeze([
  'approval',
  'audit',
  'capa',
  'consent',
  'deviation',
  'enrollment',
  'export',
  'gate',
  'launch',
  'policy',
  'procedure',
  'risk',
]);

const PARTICIPANT_AFFECTING_DOMAINS = new Set(['consent', 'enrollment']);
const DECISION_FORUM_DOMAINS = new Set(['approval', 'capa', 'enrollment', 'gate', 'launch', 'policy']);
const POLICY_STATUSES = new Set(['active']);
const HUMAN_REVIEW_DECISIONS = new Set(['workflow_engine_ready_inactive_trust', 'hold_for_workflow_engine_gap']);

const RAW_WORKFLOW_FIELDS = new Set([
  'body',
  'content',
  'definitionbody',
  'freetext',
  'nodeoutput',
  'rawapprovalnotes',
  'rawdecision',
  'rawnodeoutput',
  'rawpolicytext',
  'rawproceduretext',
  'rawtransitionpayload',
  'rawworkflow',
  'rawworkflowbody',
  'rawworkflowcontent',
  'rawworkflowtext',
  'reviewnotes',
  'sourcedocumentbody',
  'transitionpayload',
  'workflowbody',
  'workflowcontent',
  'workflowtext',
]);

const SECRET_WORKFLOW_FIELDS = new Set([
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

function isBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 10_000;
}

function isPositiveBoundedInteger(value, max) {
  return Number.isSafeInteger(value) && value > 0 && value <= max;
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

function assertNoRawWorkflowContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawWorkflowContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_WORKFLOW_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw workflow engine content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_WORKFLOW_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`workflow engine secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawWorkflowContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawWorkflowContent(input ?? {});
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

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
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

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_workflow_engine_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'workflow_engine_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateEnginePolicy(policy, reasons) {
  const requiredDomains = sortedTextList(policy?.requiredWorkflowDomains);

  addReason(reasons, !hasText(policy?.policyRef), 'workflow_engine_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'workflow_engine_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'workflow_engine_policy_not_active');
  addReason(reasons, !Number.isSafeInteger(policy?.maxLoopIterations), 'workflow_engine_loop_limit_invalid');
  addReason(
    reasons,
    Number.isSafeInteger(policy?.maxLoopIterations) &&
      (policy.maxLoopIterations <= 0 || policy.maxLoopIterations > 25),
    'workflow_engine_loop_limit_invalid',
  );
  addReason(
    reasons,
    !Number.isSafeInteger(policy?.sameFailureEscalatesAfterCount) ||
      policy.sameFailureEscalatesAfterCount <= 0 ||
      policy.sameFailureEscalatesAfterCount > 2,
    'workflow_engine_repeated_failure_limit_invalid',
  );
  addReason(reasons, policy?.requireBoundedUntrustedNodeOutputs !== true, 'untrusted_node_output_boundary_policy_absent');
  addReason(reasons, policy?.requireHumanFinalAuthority !== true, 'human_final_authority_policy_absent');
  addReason(reasons, policy?.requireMetadataOnlyDefinitions !== true, 'workflow_metadata_boundary_policy_absent');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'workflow_protected_boundary_policy_absent');
  addReason(reasons, policy?.rootVerificationRequiredForTrustClaims !== true, 'root_verification_gate_absent');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'workflow_engine_policy_time_invalid');

  evaluateRequiredSet(
    requiredDomains,
    REQUIRED_WORKFLOW_DOMAINS,
    'policy_workflow_domain_missing',
    'policy_workflow_domain_unsupported',
    reasons,
  );

  return {
    maxLoopIterations:
      Number.isSafeInteger(policy?.maxLoopIterations) && policy.maxLoopIterations > 0
        ? policy.maxLoopIterations
        : 25,
    requiredWorkflowDomains: requiredDomains.length > 0 ? requiredDomains : [...REQUIRED_WORKFLOW_DOMAINS],
    sameFailureEscalatesAfterCount:
      Number.isSafeInteger(policy?.sameFailureEscalatesAfterCount) && policy.sameFailureEscalatesAfterCount > 0
        ? policy.sameFailureEscalatesAfterCount
        : 2,
  };
}

function evaluateEngineCycle(cycle, policy, reasons) {
  addReason(reasons, !hasText(cycle?.cycleRef), 'engine_cycle_ref_absent');
  addReason(reasons, !hasText(cycle?.releaseCandidateRef), 'release_candidate_ref_absent');
  addReason(reasons, cycle?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, cycle?.metadataOnly !== true, 'engine_cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'engine_cycle_protected_boundary_invalid');

  const ordered = [
    ['openedAtHlc', cycle?.openedAtHlc],
    ['definitionsReviewedAtHlc', cycle?.definitionsReviewedAtHlc],
    ['validationRecordedAtHlc', cycle?.validationRecordedAtHlc],
    ['auditRecordedAtHlc', cycle?.auditRecordedAtHlc],
  ];

  for (const [label, value] of ordered) {
    addReason(reasons, hlcTuple(value) === null, `engine_cycle_${label}_invalid`);
  }
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, cycle?.openedAtHlc), 'workflow_engine_policy_after_cycle_open');
  for (let index = 1; index < ordered.length; index += 1) {
    const [previousLabel, previousValue] = ordered[index - 1];
    const [currentLabel, currentValue] = ordered[index];
    addReason(reasons, hlcBefore(currentValue, previousValue), `engine_cycle_${currentLabel}_before_${previousLabel}`);
  }
}

function evaluateBoundedLoop(workflow, policySummary, label, reasons) {
  const loop = workflow?.boundedLoop;
  const enabled = loop?.enabled === true;
  if (!enabled) {
    return false;
  }

  addReason(
    reasons,
    !isPositiveBoundedInteger(loop?.maxIterations, policySummary.maxLoopIterations),
    `workflow_loop_max_iterations_invalid:${label}`,
  );
  addReason(reasons, !hasText(loop?.stopConditionRef), `workflow_loop_stop_condition_absent:${label}`);
  addReason(reasons, !hasText(loop?.escalationPathRef), `workflow_loop_escalation_absent:${label}`);
  addReason(
    reasons,
    !isPositiveBoundedInteger(loop?.sameFailureEscalatesAfterCount, policySummary.sameFailureEscalatesAfterCount),
    `workflow_loop_repeated_failure_limit_invalid:${label}`,
  );
  return true;
}

function evaluateTransitionPolicy(workflow, label, reasons) {
  const transition = workflow?.transitionPolicy;
  const domain = workflow?.domain;

  addReason(reasons, transition?.authorityRequired !== true, `workflow_transition_authority_absent:${label}`);
  addReason(
    reasons,
    PARTICIPANT_AFFECTING_DOMAINS.has(domain) && transition?.consentRequiredWhenParticipantAffecting !== true,
    `workflow_transition_consent_absent:${label}`,
  );
  addReason(
    reasons,
    DECISION_FORUM_DOMAINS.has(domain) && transition?.decisionForumRequired !== true,
    `workflow_transition_decision_forum_absent:${label}`,
  );
  addReason(reasons, transition?.receiptRequired !== true, `workflow_transition_receipt_absent:${label}`);
  addReason(reasons, transition?.protectedPayloadProhibited !== true, `workflow_transition_protected_boundary_absent:${label}`);
  addReason(reasons, transition?.metadataOnly !== true, `workflow_transition_metadata_boundary_invalid:${label}`);
}

function evaluateNodeOutputBoundary(workflow, label, reasons) {
  const boundary = workflow?.nodeOutputBoundary;
  addReason(
    reasons,
    boundary?.boundedUntrustedWorkflowNodeOutputs !== true ||
      boundary?.nodeOutputCannotAuthorizeTrustClaims !== true ||
      boundary?.nodeOutputCannotAuthorizeGitOperations !== true ||
      boundary?.humanReviewRequiredForTransitions !== true,
    `workflow_node_output_boundary_absent:${label}`,
  );
}

function evaluateWorkflowDefinitions(workflows, policySummary, cycle, reasons) {
  addReason(reasons, !Array.isArray(workflows) || workflows.length === 0, 'workflow_definitions_absent');
  if (!Array.isArray(workflows)) {
    return {
      boundedLoopCount: 0,
      domains: [],
      rowSummaries: [],
      totalWorkflowCount: 0,
      workflowRefs: [],
    };
  }

  const domains = sortedTextList(workflows.map((workflow) => workflow?.domain));
  const workflowRefs = [];
  const rowSummaries = [];
  const seenDomains = new Set();
  const seenWorkflowRefs = new Set();
  let boundedLoopCount = 0;

  evaluateRequiredSet(
    domains,
    policySummary.requiredWorkflowDomains,
    'workflow_domain_missing',
    'workflow_domain_unsupported',
    reasons,
  );

  workflows.forEach((workflow, index) => {
    const label = hasText(workflow?.workflowRef) ? workflow.workflowRef : `index_${index}`;
    const domain = workflow?.domain;
    const sourceRequirementRefs = sortedTextList(workflow?.sourceRequirementRefs);
    const ownerRoleRefs = sortedTextList(workflow?.ownerRoleRefs);
    const stepRefs = sortedTextList(workflow?.stepRefs);
    const entryGateRefs = sortedTextList(workflow?.entryGateRefs);
    const exitGateRefs = sortedTextList(workflow?.exitGateRefs);

    addReason(reasons, !hasText(workflow?.workflowRef), `workflow_ref_absent:${label}`);
    addReason(reasons, seenWorkflowRefs.has(workflow?.workflowRef), `workflow_ref_duplicate:${label}`);
    if (hasText(workflow?.workflowRef)) {
      seenWorkflowRefs.add(workflow.workflowRef);
      workflowRefs.push(workflow.workflowRef);
    }

    addReason(reasons, !hasText(domain), `workflow_domain_absent:${label}`);
    addReason(reasons, seenDomains.has(domain), `workflow_id_duplicate:workflow-${domain}`);
    if (hasText(domain)) {
      seenDomains.add(domain);
    }
    addReason(reasons, !policySummary.requiredWorkflowDomains.includes(domain), `workflow_domain_invalid:${label}`);
    addReason(reasons, !hasText(workflow?.versionRef), `workflow_version_ref_absent:${label}`);
    addReason(reasons, !isDigest(workflow?.definitionHash), `workflow_definition_hash_invalid:${label}`);
    addReason(reasons, sourceRequirementRefs.length === 0, `workflow_source_requirement_refs_absent:${label}`);
    addReason(reasons, ownerRoleRefs.length === 0, `workflow_owner_roles_absent:${label}`);
    addReason(reasons, stepRefs.length < 2, `workflow_steps_insufficient:${label}`);
    addReason(reasons, entryGateRefs.length === 0, `workflow_entry_gates_absent:${label}`);
    addReason(reasons, exitGateRefs.length === 0, `workflow_exit_gates_absent:${label}`);
    addReason(reasons, workflow?.humanReviewRequired !== true, `workflow_human_review_absent:${label}`);
    addReason(reasons, workflow?.aiFinalAuthorityForbidden !== true, `workflow_ai_final_authority_policy_absent:${label}`);
    addReason(reasons, workflow?.metadataOnly !== true, `workflow_metadata_boundary_invalid:${label}`);
    addReason(reasons, workflow?.protectedContentExcluded !== true, `workflow_protected_boundary_invalid:${label}`);
    addReason(reasons, workflow?.reviewedByHuman !== true, `workflow_review_absent:${label}`);
    addReason(reasons, hlcTuple(workflow?.reviewedAtHlc) === null, `workflow_review_time_invalid:${label}`);
    addReason(reasons, hlcBefore(workflow?.reviewedAtHlc, cycle?.openedAtHlc), `workflow_review_before_cycle:${label}`);

    if (evaluateBoundedLoop(workflow, policySummary, label, reasons)) {
      boundedLoopCount += 1;
    }
    evaluateTransitionPolicy(workflow, label, reasons);
    evaluateNodeOutputBoundary(workflow, label, reasons);

    rowSummaries.push({
      boundedLoopEnabled: workflow?.boundedLoop?.enabled === true,
      definitionHash: isDigest(workflow?.definitionHash) ? workflow.definitionHash : null,
      domain: domain ?? null,
      humanReviewRequired: workflow?.humanReviewRequired === true,
      sourceRequirementRefs,
      stepRefs,
      workflowRef: label,
    });
  });

  return {
    boundedLoopCount,
    domains,
    rowSummaries: rowSummaries.sort((left, right) => left.workflowRef.localeCompare(right.workflowRef)),
    totalWorkflowCount: workflows.length,
    workflowRefs: uniqueSorted(workflowRefs),
  };
}

function evaluateRuntimeContract(runtime, reasons) {
  addReason(reasons, runtime === null || runtime === undefined, 'runtime_contract_absent');
  addReason(reasons, !hasText(runtime?.contractRef), 'runtime_contract_ref_absent');
  addReason(reasons, !isDigest(runtime?.deterministicReducerHash), 'runtime_deterministic_reducer_hash_invalid');
  addReason(reasons, runtime?.noSystemTime !== true, 'runtime_system_time_forbidden');
  addReason(reasons, runtime?.noRandomness !== true, 'runtime_randomness_forbidden');
  addReason(reasons, runtime?.noFloatingPoint !== true, 'runtime_floating_point_forbidden');
  addReason(reasons, runtime?.noRuntimeSecretMaterial !== true, 'runtime_secret_material_forbidden');
  addReason(reasons, runtime?.externalNodeOutputsTreatedAsUntrusted !== true, 'runtime_untrusted_node_output_boundary_absent');
  addReason(reasons, runtime?.idempotencyKeyRequired !== true, 'runtime_idempotency_key_absent');
  addReason(reasons, runtime?.replayProtectionRequired !== true, 'runtime_replay_protection_absent');
  addReason(reasons, !isDigest(runtime?.receiptBoundaryHash), 'runtime_receipt_boundary_hash_invalid');
  addReason(reasons, runtime?.operationalStateSeparateFromReceipts !== true, 'runtime_receipt_state_separation_absent');
  addReason(reasons, runtime?.metadataOnly !== true, 'runtime_metadata_boundary_invalid');
}

function evaluateValidationEvidence(validation, cycle, reasons) {
  addReason(reasons, validation === null || validation === undefined, 'validation_evidence_absent');
  addReason(reasons, sortedTextList(validation?.commandRefs).length === 0, 'validation_command_refs_absent');
  addReason(reasons, validation?.commandsPassed !== true, 'validation_commands_not_passed');
  addReason(reasons, !Number.isSafeInteger(validation?.testCount) || validation.testCount <= 0, 'validation_test_count_invalid');
  addReason(reasons, !isBasisPoints(validation?.coverageLineBasisPoints), 'validation_coverage_invalid');
  addReason(reasons, validation?.sourceGuardPassed !== true, 'validation_source_guard_absent');
  addReason(reasons, validation?.noExochainSourceModified !== true, 'validation_exochain_read_only_absent');
  addReason(reasons, !isDigest(validation?.workflowManifestHash), 'validation_workflow_manifest_hash_invalid');
  addReason(reasons, !isDigest(validation?.evidenceHash), 'validation_evidence_hash_invalid');
  addReason(reasons, validation?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(validation?.recordedAtHlc) === null, 'validation_time_invalid');
  addReason(reasons, hlcBefore(validation?.recordedAtHlc, cycle?.validationRecordedAtHlc), 'validation_before_cycle_validation_step');
}

function evaluateHumanReview(review, cycle, reasons) {
  addReason(reasons, review === null || review === undefined, 'human_review_absent');
  addReason(reasons, !hasText(review?.reviewerDid), 'human_review_reviewer_absent');
  addReason(reasons, sortedTextList(review?.reviewerRoleRefs).length === 0, 'human_review_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'human_review_production_trust_forbidden');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_review_authority_absent');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, cycle?.definitionsReviewedAtHlc), 'human_review_before_cycle_review_step');
}

function evaluateAuditRecord(auditRecord, cycle, review, reasons) {
  addReason(reasons, !hasText(auditRecord?.auditRecordRef), 'workflow_engine_audit_record_ref_absent');
  addReason(reasons, !isDigest(auditRecord?.auditRecordHash), 'workflow_engine_audit_record_hash_invalid');
  addReason(reasons, auditRecord?.metadataOnly !== true, 'workflow_engine_audit_record_metadata_boundary_invalid');
  addReason(reasons, auditRecord?.includesProtectedContent === true, 'workflow_engine_audit_record_protected_content_forbidden');
  addReason(reasons, hlcTuple(auditRecord?.receiptRecordedAtHlc) === null, 'workflow_engine_audit_record_time_invalid');
  addReason(reasons, hlcBefore(auditRecord?.receiptRecordedAtHlc, cycle?.auditRecordedAtHlc), 'workflow_engine_audit_before_cycle_audit_step');
  addReason(reasons, hlcBefore(auditRecord?.receiptRecordedAtHlc, review?.reviewedAtHlc), 'workflow_engine_audit_before_review');
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

function buildWorkflowEngine(input, policySummary, workflowSummary) {
  const workflowEngineHash = sha256Hex({
    auditRecordHash: input.auditRecord.auditRecordHash,
    cycleRef: input.engineCycle.cycleRef,
    humanDecisionHash: input.humanReview.decisionHash,
    policyHash: input.enginePolicy.policyHash,
    runtimeContractHash: input.runtimeContract.deterministicReducerHash,
    tenantId: input.tenantId,
    validationEvidenceHash: input.validationEvidence.evidenceHash,
    workflowDefinitions: workflowSummary.rowSummaries,
  });

  return {
    schema: ENGINE_SCHEMA,
    engineId: `cmwfe_${sha256Hex({
      cycleRef: input.engineCycle.cycleRef,
      tenantId: input.tenantId,
      workflowEngineHash,
    }).slice(0, 32)}`,
    tenantId: input.tenantId,
    releaseCandidateRef: input.engineCycle.releaseCandidateRef,
    engineReady: true,
    readinessState: 'baseline_ready_inactive_trust',
    productionActivationReady: false,
    trustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    workflowDomainsCovered: workflowSummary.domains,
    workflowRefs: workflowSummary.workflowRefs,
    workflowDefinitions: workflowSummary.rowSummaries,
    requiredWorkflowDomains: policySummary.requiredWorkflowDomains,
    coverageSummary: {
      boundedLoopCount: workflowSummary.boundedLoopCount,
      totalWorkflowCount: workflowSummary.totalWorkflowCount,
    },
    runtimeSummary: {
      contractRef: input.runtimeContract.contractRef,
      externalNodeOutputsTreatedAsUntrusted: input.runtimeContract.externalNodeOutputsTreatedAsUntrusted,
      idempotencyKeyRequired: input.runtimeContract.idempotencyKeyRequired,
      operationalStateSeparateFromReceipts: input.runtimeContract.operationalStateSeparateFromReceipts,
      replayProtectionRequired: input.runtimeContract.replayProtectionRequired,
    },
    validationSummary: {
      commandRefs: sortedTextList(input.validationEvidence.commandRefs),
      coverageLineBasisPoints: input.validationEvidence.coverageLineBasisPoints,
      sourceGuardPassed: input.validationEvidence.sourceGuardPassed,
      testCount: input.validationEvidence.testCount,
    },
    workflowEngineHash,
    auditRecordHash: input.auditRecord.auditRecordHash,
    auditRecordedAtHlc: input.auditRecord.receiptRecordedAtHlc,
  };
}

function buildReceipt(input, workflowEngine) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: workflowEngine.workflowEngineHash,
    artifactType: 'workflow_engine_readiness',
    artifactVersion: input.engineCycle.releaseCandidateRef,
    classification: 'deployment_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.auditRecord.receiptRecordedAtHlc,
    sensitivityTags: ['workflow_engine', 'metadata_only', 'inactive_trust_state'],
    sourceSystem: 'cybermedica-qms',
    tenantId: input.tenantId,
  });
}

export function evaluateWorkflowEngineReadiness(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policySummary = evaluateEnginePolicy(input?.enginePolicy, reasons);
  evaluateEngineCycle(input?.engineCycle, input?.enginePolicy, reasons);
  const workflowSummary = evaluateWorkflowDefinitions(input?.workflowDefinitions, policySummary, input?.engineCycle, reasons);
  evaluateRuntimeContract(input?.runtimeContract, reasons);
  evaluateValidationEvidence(input?.validationEvidence, input?.engineCycle, reasons);
  evaluateHumanReview(input?.humanReview, input?.engineCycle, reasons);
  evaluateAuditRecord(input?.auditRecord, input?.engineCycle, input?.humanReview, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: unique,
      workflowEngine: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const workflowEngine = buildWorkflowEngine(input, policySummary, workflowSummary);

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    workflowEngine,
    receipt: buildReceipt(input, workflowEngine),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
