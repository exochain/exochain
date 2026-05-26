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
const VALIDATION_SCHEMA = 'cybermedica.syntaxis_workflow_validation.v1';
const DECISION_SCHEMA = 'cybermedica.syntaxis_workflow_validation_decision.v1';
const REQUIRED_PERMISSION = 'syntaxis_registry_review';

const REQUIRED_NODE_TYPES = Object.freeze([
  'authority-check',
  'consent-verify',
  'dag-append',
  'governance-propose',
  'governance-resolve',
  'governance-vote',
  'identity-verify',
  'kernel-adjudicate',
]);

const REQUIRED_CRATES = Object.freeze([
  'exo-authority',
  'exo-consent',
  'exo-dag',
  'exo-gatekeeper',
  'exo-governance',
  'exo-identity',
]);

const ACTIVE_POLICY_STATUSES = new Set(['active']);
const HUMAN_REVIEW_DECISIONS = new Set([
  'hold_for_syntaxis_registry_gap',
  'syntaxis_design_time_validated_inactive_trust',
]);

const RAW_SYNTAXIS_FIELDS = new Set([
  'commandoutput',
  'content',
  'freeform',
  'freetext',
  'generatedrust',
  'nodeoutput',
  'rawcommandoutput',
  'rawgeneratedmodule',
  'rawgeneratedrust',
  'rawgeneratedtest',
  'rawnodeoutput',
  'rawregistry',
  'rawregistryjson',
  'rawsource',
  'rawworkflow',
  'rawworkflowdefinition',
  'rawworkflowjson',
  'registryjson',
  'reviewnotes',
  'sourcedocumentbody',
  'workflowbody',
  'workflowcontent',
  'workflowjson',
]);

const SECRET_SYNTAXIS_FIELDS = new Set([
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

function assertNoRawSyntaxisContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawSyntaxisContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_SYNTAXIS_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw Syntaxis generated content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_SYNTAXIS_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`Syntaxis validation secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawSyntaxisContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawSyntaxisContent(input ?? {});
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
  addReason(reasons, input?.actor?.kind !== 'human', 'human_syntaxis_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'syntaxis_registry_review_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateValidationPolicy(policy, reasons) {
  const requiredNodeTypes = sortedTextList(policy?.requiredNodeTypes);

  addReason(reasons, !hasText(policy?.policyRef), 'syntaxis_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'syntaxis_policy_hash_invalid');
  addReason(reasons, !ACTIVE_POLICY_STATUSES.has(policy?.status), 'syntaxis_policy_not_active');
  addReason(reasons, policy?.designTimeOnly !== true, 'syntaxis_design_time_policy_absent');
  addReason(reasons, policy?.productionTrustClaimForbidden !== true, 'production_trust_claim_policy_absent');
  addReason(reasons, policy?.registryToCodeValidationRequired !== true, 'registry_to_code_validation_policy_absent');
  addReason(reasons, policy?.generatedWorkflowCompileRequired !== true, 'generated_compile_policy_absent');
  addReason(reasons, policy?.generatedTestsRequired !== true, 'generated_tests_policy_absent');
  addReason(reasons, policy?.invalidNodeEdgeDenialRequired !== true, 'invalid_node_edge_policy_absent');
  addReason(reasons, policy?.untrustedGeneratedOutputBoundaryRequired !== true, 'untrusted_generated_output_policy_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'syntaxis_policy_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'syntaxis_policy_time_invalid');

  evaluateRequiredSet(
    requiredNodeTypes,
    REQUIRED_NODE_TYPES,
    'policy_required_node_missing',
    'policy_required_node_unsupported',
    reasons,
  );

  return {
    requiredNodeTypes: requiredNodeTypes.length > 0 ? requiredNodeTypes : [...REQUIRED_NODE_TYPES],
  };
}

function evaluateRegistrySnapshot(registry, policySummary, reasons) {
  addReason(reasons, registry === null || registry === undefined, 'registry_snapshot_absent');
  addReason(reasons, !hasText(registry?.registryRef), 'registry_ref_absent');
  addReason(reasons, !isDigest(registry?.registryHash), 'registry_hash_invalid');
  addReason(reasons, !hasText(registry?.schemaRef), 'registry_schema_ref_absent');
  addReason(reasons, !hasText(registry?.version), 'registry_version_absent');
  addReason(reasons, !isDigest(registry?.sourceCommitHash), 'registry_source_commit_hash_invalid');
  addReason(reasons, registry?.verifiedReadOnly !== true, 'registry_read_only_evidence_absent');
  addReason(reasons, registry?.metadataOnly !== true, 'registry_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(registry?.generatedAtHlc) === null, 'registry_generated_time_invalid');

  if (!Array.isArray(registry?.nodeMappings) || registry.nodeMappings.length === 0) {
    addReason(reasons, true, 'registry_node_mappings_absent');
    return {
      crateRefs: [],
      mapByNodeType: new Map(),
      nodeTypes: [],
      rowSummaries: [],
    };
  }

  const mapByNodeType = new Map();
  const nodeTypes = [];
  const crateRefs = [];
  const rowSummaries = [];
  const seenNodeTypes = new Set();

  registry.nodeMappings.forEach((mapping, index) => {
    const label = hasText(mapping?.nodeType) ? mapping.nodeType : `index_${index}`;
    const sourcePathRefs = sortedTextList(mapping?.sourcePathRefs);
    const invariantRefs = sortedTextList(mapping?.invariantRefs);
    const inputRefs = sortedTextList(mapping?.inputRefs);
    const outputRefs = sortedTextList(mapping?.outputRefs);

    addReason(reasons, !hasText(mapping?.nodeType), `registry_node_type_absent:${label}`);
    addReason(reasons, seenNodeTypes.has(mapping?.nodeType), `registry_node_duplicate:${label}`);
    if (hasText(mapping?.nodeType)) {
      seenNodeTypes.add(mapping.nodeType);
      nodeTypes.push(mapping.nodeType);
      mapByNodeType.set(mapping.nodeType, mapping);
    }

    addReason(reasons, !REQUIRED_NODE_TYPES.includes(mapping?.nodeType), `registry_node_unsupported:${label}`);
    addReason(reasons, !hasText(mapping?.crate), `registry_node_crate_absent:${label}`);
    addReason(reasons, !REQUIRED_CRATES.includes(mapping?.crate), `registry_node_crate_unsupported:${label}`);
    if (hasText(mapping?.crate)) {
      crateRefs.push(mapping.crate);
    }
    addReason(reasons, !hasText(mapping?.rustModule), `registry_node_rust_module_absent:${label}`);
    addReason(reasons, !hasText(mapping?.rustTraitRef), `registry_node_rust_trait_absent:${label}`);
    addReason(reasons, !hasText(mapping?.combinatorRef), `registry_node_combinator_absent:${label}`);
    addReason(reasons, invariantRefs.length === 0, `registry_node_invariants_absent:${label}`);
    addReason(reasons, inputRefs.length === 0, `registry_node_inputs_absent:${label}`);
    addReason(reasons, outputRefs.length === 0, `registry_node_outputs_absent:${label}`);
    addReason(reasons, !sourcePathRefs.includes('tools/syntaxis/node_registry.json'), `registry_source_path_absent:${label}`);
    addReason(reasons, mapping?.verifiedAgainstCurrentSource !== true, `registry_node_current_source_unverified:${label}`);
    addReason(reasons, mapping?.metadataOnly !== true, `registry_node_metadata_boundary_invalid:${label}`);

    rowSummaries.push({
      crate: mapping?.crate ?? null,
      invariantRefs,
      nodeType: label,
      rustModule: mapping?.rustModule ?? null,
      sourcePathRefs,
    });
  });

  evaluateRequiredSet(
    uniqueSorted(nodeTypes),
    policySummary.requiredNodeTypes,
    'registry_node_missing',
    'registry_node_unexpected',
    reasons,
  );

  return {
    crateRefs: uniqueSorted(crateRefs),
    mapByNodeType,
    nodeTypes: uniqueSorted(nodeTypes),
    rowSummaries: rowSummaries.sort((left, right) => left.nodeType.localeCompare(right.nodeType)),
  };
}

function evaluateGeneratedSteps(workflow, registrySummary, policySummary, reasons) {
  if (!Array.isArray(workflow?.steps) || workflow.steps.length === 0) {
    addReason(reasons, true, 'generated_workflow_steps_absent');
    return {
      stepRefs: [],
      stepSummaries: [],
      stepNodeTypes: [],
    };
  }

  const stepRefs = [];
  const stepNodeTypes = [];
  const stepSummaries = [];
  const seenStepRefs = new Set();

  workflow.steps.forEach((step, index) => {
    const label = hasText(step?.stepRef) ? step.stepRef : `index_${index}`;
    const nodeType = step?.nodeType;
    const registryNodeType = step?.registryNodeType;
    const edgeRefs = sortedTextList(step?.edgeRefs);

    addReason(reasons, !hasText(step?.stepRef), `generated_step_ref_absent:${label}`);
    addReason(reasons, seenStepRefs.has(step?.stepRef), `generated_step_ref_duplicate:${label}`);
    if (hasText(step?.stepRef)) {
      seenStepRefs.add(step.stepRef);
      stepRefs.push(step.stepRef);
    }

    addReason(reasons, !hasText(nodeType), `generated_step_node_type_absent:${label}`);
    addReason(reasons, !policySummary.requiredNodeTypes.includes(nodeType), `generated_step_unsupported_node:${label}`);
    addReason(reasons, registryNodeType !== nodeType, `generated_step_registry_node_mismatch:${label}`);
    addReason(
      reasons,
      hasText(nodeType) && !registrySummary.mapByNodeType.has(nodeType),
      `generated_step_registry_node_missing:${label}`,
    );
    addReason(reasons, !isDigest(step?.inputSchemaHash), `generated_step_input_schema_hash_invalid:${label}`);
    addReason(reasons, !isDigest(step?.outputSchemaHash), `generated_step_output_schema_hash_invalid:${label}`);
    addReason(reasons, step?.metadataOnly !== true, `generated_step_metadata_boundary_invalid:${label}`);
    addReason(reasons, step?.protectedContentExcluded !== true, `generated_step_protected_boundary_invalid:${label}`);
    if (hasText(nodeType)) {
      stepNodeTypes.push(nodeType);
    }

    stepSummaries.push({
      edgeRefs,
      inputSchemaHash: isDigest(step?.inputSchemaHash) ? step.inputSchemaHash : null,
      nodeType: nodeType ?? null,
      outputSchemaHash: isDigest(step?.outputSchemaHash) ? step.outputSchemaHash : null,
      stepRef: label,
    });
  });

  evaluateRequiredSet(
    uniqueSorted(stepNodeTypes),
    policySummary.requiredNodeTypes,
    'generated_workflow_node_missing',
    'generated_workflow_node_unexpected',
    reasons,
  );

  return {
    stepRefs: uniqueSorted(stepRefs),
    stepNodeTypes: uniqueSorted(stepNodeTypes),
    stepSummaries: stepSummaries.sort((left, right) => left.stepRef.localeCompare(right.stepRef)),
  };
}

function evaluateGeneratedWorkflow(workflow, registrySummary, policySummary, reasons) {
  addReason(reasons, workflow === null || workflow === undefined, 'generated_workflow_absent');
  addReason(reasons, !hasText(workflow?.workflowRef), 'generated_workflow_ref_absent');
  addReason(reasons, !isDigest(workflow?.workflowHash), 'generated_workflow_hash_invalid');
  addReason(reasons, !isDigest(workflow?.generatedModuleHash), 'generated_module_hash_invalid');
  addReason(reasons, !isDigest(workflow?.generatedTestHash), 'generated_test_hash_invalid');
  addReason(reasons, !isDigest(workflow?.sourceWorkflowHash), 'source_workflow_hash_invalid');
  addReason(reasons, workflow?.composition !== 'guarded_sequence', 'generated_workflow_composition_invalid');
  addReason(reasons, workflow?.workflowClass !== 'clinical_governance', 'generated_workflow_class_invalid');
  addReason(reasons, workflow?.compile?.passed !== true, 'generated_workflow_compile_failed');
  addReason(reasons, !hasText(workflow?.compile?.commandRef), 'generated_workflow_compile_command_absent');
  addReason(reasons, !isDigest(workflow?.compile?.artifactHash), 'generated_workflow_compile_artifact_hash_invalid');
  addReason(reasons, workflow?.edgeValidation?.passed !== true, 'edge_validation_not_passed');
  addReason(reasons, workflow?.edgeValidation?.invalidNodeRejected !== true, 'invalid_node_rejection_absent');
  addReason(reasons, workflow?.edgeValidation?.invalidEdgeRejected !== true, 'invalid_edge_rejection_absent');
  addReason(reasons, workflow?.edgeValidation?.missingNodeRejected !== true, 'missing_node_rejection_absent');
  addReason(reasons, workflow?.edgeValidation?.cycleRejected !== true, 'cycle_rejection_absent');
  addReason(reasons, workflow?.trustBoundary?.designTimeOnly !== true, 'generated_workflow_design_time_boundary_absent');
  addReason(reasons, workflow?.trustBoundary?.runtimeEnforcementClaim === true, 'runtime_enforcement_claim_forbidden');
  addReason(
    reasons,
    workflow?.trustBoundary?.generatedOutputCannotAuthorizeGovernance !== true,
    'generated_output_governance_authority_forbidden',
  );
  addReason(
    reasons,
    workflow?.trustBoundary?.generatedOutputCannotAuthorizeTrustClaims !== true,
    'generated_output_trust_claim_authority_forbidden',
  );
  addReason(
    reasons,
    workflow?.trustBoundary?.generatedOutputCannotModifyExochainSource !== true,
    'generated_output_exochain_source_edit_forbidden',
  );
  addReason(
    reasons,
    workflow?.trustBoundary?.boundedUntrustedWorkflowOutputs !== true,
    'untrusted_generated_output_boundary_absent',
  );
  addReason(reasons, workflow?.trustBoundary?.metadataOnly !== true, 'generated_trust_boundary_metadata_invalid');
  addReason(reasons, workflow?.metadataOnly !== true, 'generated_workflow_metadata_boundary_invalid');
  addReason(reasons, workflow?.protectedContentExcluded !== true, 'generated_workflow_protected_boundary_invalid');

  return evaluateGeneratedSteps(workflow, registrySummary, policySummary, reasons);
}

function evaluateValidationEvidence(validation, reasons) {
  addReason(reasons, validation === null || validation === undefined, 'validation_evidence_absent');
  addReason(reasons, sortedTextList(validation?.commandRefs).length === 0, 'validation_command_refs_absent');
  addReason(reasons, validation?.registryToCodeValidationPassed !== true, 'validation_registry_to_code_absent');
  addReason(reasons, validation?.generatedWorkflowCompilePassed !== true, 'validation_generated_compile_absent');
  addReason(reasons, validation?.generatedTestsPassed !== true, 'validation_generated_tests_absent');
  addReason(reasons, validation?.invalidNodeEdgeTestsPassed !== true, 'validation_invalid_node_edge_tests_absent');
  addReason(reasons, validation?.noExochainSourceModified !== true, 'validation_exochain_read_only_absent');
  addReason(reasons, validation?.sourceGuardPassed !== true, 'validation_source_guard_absent');
  addReason(reasons, !Number.isSafeInteger(validation?.testCount) || validation.testCount <= 0, 'validation_test_count_invalid');
  addReason(reasons, !isBasisPoints(validation?.coverageLineBasisPoints), 'validation_coverage_invalid');
  addReason(reasons, !isDigest(validation?.evidenceHash), 'validation_evidence_hash_invalid');
  addReason(reasons, validation?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(validation?.recordedAtHlc) === null, 'validation_time_invalid');
}

function evaluateHumanReview(review, reasons) {
  addReason(reasons, review === null || review === undefined, 'human_review_absent');
  addReason(reasons, !hasText(review?.reviewerDid), 'human_review_reviewer_absent');
  addReason(reasons, sortedTextList(review?.reviewerRoleRefs).length === 0, 'human_review_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_review_authority_absent');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'human_review_production_trust_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
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

function evaluateHlcOrdering(input, reasons) {
  addReason(
    reasons,
    hlcAfter(input?.validationPolicy?.evaluatedAtHlc, input?.registrySnapshot?.generatedAtHlc),
    'syntaxis_policy_after_registry_snapshot',
  );
  addReason(
    reasons,
    hlcBefore(input?.validationEvidence?.recordedAtHlc, input?.registrySnapshot?.generatedAtHlc),
    'validation_before_registry_snapshot',
  );
  addReason(
    reasons,
    hlcBefore(input?.humanReview?.reviewedAtHlc, input?.validationEvidence?.recordedAtHlc),
    'human_review_before_validation',
  );
}

function buildSyntaxisValidation(input, policySummary, registrySummary, generatedSummary) {
  const validationHash = sha256Hex({
    generatedModuleHash: input.generatedWorkflow.generatedModuleHash,
    generatedTestHash: input.generatedWorkflow.generatedTestHash,
    nodeMappings: registrySummary.rowSummaries,
    policyHash: input.validationPolicy.policyHash,
    stepSummaries: generatedSummary.stepSummaries,
    tenantId: input.tenantId,
    validationEvidenceHash: input.validationEvidence.evidenceHash,
    workflowHash: input.generatedWorkflow.workflowHash,
  });

  return {
    schema: VALIDATION_SCHEMA,
    syntaxisValidationId: `cmsyn_${sha256Hex({
      tenantId: input.tenantId,
      validationHash,
      workflowRef: input.generatedWorkflow.workflowRef,
    }).slice(0, 32)}`,
    tenantId: input.tenantId,
    workflowRef: input.generatedWorkflow.workflowRef,
    designTimeReady: true,
    runtimeEnforcementReady: false,
    readinessState: 'design_time_validated_inactive_trust',
    trustState: 'inactive',
    exochainProductionClaim: false,
    syntaxisBackedRuntimeClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    requiredNodeTypes: policySummary.requiredNodeTypes,
    nodeTypesCovered: registrySummary.nodeTypes,
    generatedWorkflowNodeTypes: generatedSummary.stepNodeTypes,
    crateRefsCovered: registrySummary.crateRefs,
    registrySummary: {
      registryHash: input.registrySnapshot.registryHash,
      registryRef: input.registrySnapshot.registryRef,
      sourceCommitHash: input.registrySnapshot.sourceCommitHash,
      version: input.registrySnapshot.version,
    },
    generatedWorkflowSummary: {
      composition: input.generatedWorkflow.composition,
      generatedModuleHash: input.generatedWorkflow.generatedModuleHash,
      generatedTestHash: input.generatedWorkflow.generatedTestHash,
      stepRefs: generatedSummary.stepRefs,
      workflowClass: input.generatedWorkflow.workflowClass,
      workflowHash: input.generatedWorkflow.workflowHash,
    },
    validationSummary: {
      commandRefs: sortedTextList(input.validationEvidence.commandRefs),
      coverageLineBasisPoints: input.validationEvidence.coverageLineBasisPoints,
      invalidNodeEdgeTestsPassed: input.validationEvidence.invalidNodeEdgeTestsPassed,
      noExochainSourceModified: input.validationEvidence.noExochainSourceModified,
      registryToCodeValidationPassed: input.validationEvidence.registryToCodeValidationPassed,
      testCount: input.validationEvidence.testCount,
    },
    validationHash,
    reviewedAtHlc: input.humanReview.reviewedAtHlc,
  };
}

function buildReceipt(input, syntaxisValidation) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: syntaxisValidation.validationHash,
    artifactType: 'syntaxis_workflow_validation',
    artifactVersion: input.generatedWorkflow.workflowRef,
    classification: 'adjacent_design_time_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    sensitivityTags: ['syntaxis', 'workflow_validation', 'metadata_only', 'inactive_trust_state'],
    sourceSystem: 'cybermedica-qms',
    tenantId: input.tenantId,
  });
}

export function evaluateSyntaxisWorkflowValidation(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policySummary = evaluateValidationPolicy(input?.validationPolicy, reasons);
  const registrySummary = evaluateRegistrySnapshot(input?.registrySnapshot, policySummary, reasons);
  const generatedSummary = evaluateGeneratedWorkflow(input?.generatedWorkflow, registrySummary, policySummary, reasons);
  evaluateValidationEvidence(input?.validationEvidence, reasons);
  evaluateHumanReview(input?.humanReview, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  evaluateHlcOrdering(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: unique,
      syntaxisValidation: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const syntaxisValidation = buildSyntaxisValidation(input, policySummary, registrySummary, generatedSummary);

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    syntaxisValidation,
    receipt: buildReceipt(input, syntaxisValidation),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
