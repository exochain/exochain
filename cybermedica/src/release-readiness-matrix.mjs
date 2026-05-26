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
const MATRIX_SCHEMA = 'cybermedica.release_readiness_matrix.v1';
const DECISION_SCHEMA = 'cybermedica.release_readiness_matrix_decision.v1';
const REQUIRED_PERMISSION = 'release_readiness_review';
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

const REQUIRED_DOCTRINE_LAYERS = Object.freeze([
  'data',
  'deployment',
  'doctrine',
  'documentation',
  'domain',
  'doors',
  'drift',
  'ground_truth',
]);

const REQUIRED_ACCEPTANCE_DOMAINS = Object.freeze([
  'consent_authority',
  'deterministic_fixtures',
  'documentation',
  'fail_closed_adapters',
  'human_governance',
  'inactive_trust_state_ui',
  'metadata_only_boundaries',
  'release_decision',
  'service_contracts',
  'test_validation',
]);

const REQUIRED_CONTEXT_DOC_REFS = Object.freeze([
  'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
  'docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md',
  'docs/context/EXOCHAIN_COUNCIL_REVIEW_FOR_CYBERMEDICA_OPEN_QUESTIONS.md',
  'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
]);

const ALLOWED_BOB_ESCALATION_IDS = Object.freeze([
  'ESC-CONSENT-LEGAL',
  'ESC-HUMAN-PROOFING',
  'ESC-OPS-SECRETS',
  'ESC-OPTIONAL-ADJACENT',
  'ESC-ROLE-MATRIX',
  'ESC-ROOT-ARTIFACT-STORE',
  'ESC-ROOT-DEPLOYMENT',
  'ESC-ROOT-OWNER',
  'ESC-ROOT-ROSTER',
  'ESC-RUNTIME',
]);

const ACTIVATION_GATE_IDS = Object.freeze(Array.from({ length: 18 }, (_, index) => `PTAG-${String(index + 1).padStart(3, '0')}`));
const POLICY_STATUSES = new Set(['active']);
const RELEASE_CLASSES = new Set(['baseline_contract_build', 'internal_release_candidate', 'customer_zero_release_candidate']);
const ACCEPTANCE_STATUSES = new Set(['passed']);
const OPEN_QUESTION_DISPOSITIONS = new Set(['bob_escalation_required', 'council_consensus_default']);
const GATE_STATUSES = new Set(['denied', 'failed', 'inactive', 'pending', 'verified']);
const RELEASE_DECISIONS = new Set(['baseline_ready_inactive_trust', 'hold_for_production_trust', 'not_ready']);

const RAW_RELEASE_FIELDS = new Set([
  'acceptancenarrative',
  'activationnarrative',
  'auditlogbody',
  'consoleoutput',
  'content',
  'freetext',
  'freetextnote',
  'gatefindingtext',
  'legalopiniontext',
  'openquestiontext',
  'rawacceptancetext',
  'rawactivationevidence',
  'rawbobanswer',
  'rawconsoleoutput',
  'rawcontext',
  'rawdecision',
  'rawescalation',
  'rawgateevidence',
  'rawnotes',
  'rawopenquestiontext',
  'rawregister',
  'rawreleasecopy',
  'rawvalidationoutput',
  'releasecommentary',
  'reviewnotes',
  'sourcedocumentbody',
  'validationlog',
]);

const SECRET_RELEASE_FIELDS = new Set([
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

function isBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 10000;
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

function assertNoRawReleaseContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawReleaseContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_RELEASE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw release readiness content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_RELEASE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`release readiness secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawReleaseContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawReleaseContent(input ?? {});
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

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_release_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'release_readiness_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateRequiredSet(actual, expected, missingPrefix, unexpectedPrefix, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !expected.includes(value), `${unexpectedPrefix}:${value}`);
  }
}

function evaluateReleasePolicy(policy, reasons) {
  const requiredDoctrineLayers = sortedTextList(policy?.requiredDoctrineLayers);
  const requiredAcceptanceDomains = sortedTextList(policy?.requiredAcceptanceDomains);
  const allowedBobEscalationIds = sortedTextList(policy?.allowedBobEscalationIds);
  const activationGateIds = sortedTextList(policy?.activationGateIds);
  const contextDocRefs = sortedTextList(policy?.contextDocRefs);

  addReason(reasons, !hasText(policy?.policyRef), 'release_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'release_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'release_policy_not_active');
  addReason(reasons, policy?.councilDefaultsApplied !== true, 'council_defaults_not_applied');
  addReason(reasons, policy?.rootVerificationRequiredForTrustClaims !== true, 'root_verification_gate_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'release_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'release_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'release_policy_time_invalid');

  evaluateRequiredSet(
    requiredDoctrineLayers,
    REQUIRED_DOCTRINE_LAYERS,
    'doctrine_layer_missing',
    'doctrine_layer_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    requiredAcceptanceDomains,
    REQUIRED_ACCEPTANCE_DOMAINS,
    'policy_acceptance_domain_missing',
    'policy_acceptance_domain_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    allowedBobEscalationIds,
    ALLOWED_BOB_ESCALATION_IDS,
    'policy_bob_escalation_missing',
    'policy_bob_escalation_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    activationGateIds,
    ACTIVATION_GATE_IDS,
    'policy_activation_gate_missing',
    'policy_activation_gate_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    contextDocRefs,
    REQUIRED_CONTEXT_DOC_REFS,
    'context_doc_ref_missing',
    'context_doc_ref_unsupported',
    reasons,
  );

  return {
    activationGateIds: activationGateIds.length > 0 ? activationGateIds : [...ACTIVATION_GATE_IDS],
    allowedBobEscalationIds: allowedBobEscalationIds.length > 0 ? allowedBobEscalationIds : [...ALLOWED_BOB_ESCALATION_IDS],
    contextDocRefs: contextDocRefs.length > 0 ? contextDocRefs : [...REQUIRED_CONTEXT_DOC_REFS],
    requiredAcceptanceDomains: requiredAcceptanceDomains.length > 0 ? requiredAcceptanceDomains : [...REQUIRED_ACCEPTANCE_DOMAINS],
    requiredDoctrineLayers: requiredDoctrineLayers.length > 0 ? requiredDoctrineLayers : [...REQUIRED_DOCTRINE_LAYERS],
  };
}

function evaluateReleaseCycle(cycle, policy, reasons) {
  addReason(reasons, !hasText(cycle?.cycleRef), 'release_cycle_ref_absent');
  addReason(reasons, !hasText(cycle?.releaseCandidateRef), 'release_candidate_ref_absent');
  addReason(reasons, !RELEASE_CLASSES.has(cycle?.releaseClass), 'release_class_invalid');
  addReason(reasons, cycle?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, cycle?.metadataOnly !== true, 'release_cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'release_cycle_protected_boundary_invalid');

  const ordered = [
    ['openedAtHlc', cycle?.openedAtHlc],
    ['matrixCompiledAtHlc', cycle?.matrixCompiledAtHlc],
    ['councilReviewedAtHlc', cycle?.councilReviewedAtHlc],
    ['bobEscalationReviewedAtHlc', cycle?.bobEscalationReviewedAtHlc],
    ['validationRecordedAtHlc', cycle?.validationRecordedAtHlc],
    ['releaseDecisionAtHlc', cycle?.releaseDecisionAtHlc],
    ['auditRecordedAtHlc', cycle?.auditRecordedAtHlc],
  ];

  for (const [label, value] of ordered) {
    addReason(reasons, hlcTuple(value) === null, `release_cycle_${label}_invalid`);
  }
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, cycle?.openedAtHlc), 'release_policy_after_cycle_open');
  for (let index = 1; index < ordered.length; index += 1) {
    const [previousLabel, previousValue] = ordered[index - 1];
    const [currentLabel, currentValue] = ordered[index];
    addReason(
      reasons,
      hlcBefore(currentValue, previousValue),
      `release_cycle_${currentLabel}_before_${previousLabel}`,
    );
  }
}

function evaluateAcceptanceRows(rows, requiredDomains, requiredLayers, cycle, reasons) {
  addReason(reasons, !Array.isArray(rows) || rows.length === 0, 'acceptance_rows_absent');
  if (!Array.isArray(rows)) {
    return { domains: [], layers: [], rowSummaries: [] };
  }

  const domains = sortedTextList(rows.map((row) => row?.domain));
  const layers = sortedTextList(rows.map((row) => row?.doctrineLayer));
  const rowSummaries = [];
  const seenDomains = new Set();

  for (const domain of requiredDomains) {
    addReason(reasons, !domains.includes(domain), `acceptance_domain_missing:${domain}`);
  }
  for (const layer of requiredLayers) {
    addReason(reasons, !layers.includes(layer), `acceptance_doctrine_layer_missing:${layer}`);
  }

  rows.forEach((row, index) => {
    const label = hasText(row?.domain) ? row.domain : `index_${index}`;
    addReason(reasons, !hasText(row?.domain), `acceptance_domain_absent:${label}`);
    addReason(reasons, seenDomains.has(row?.domain), `acceptance_domain_duplicate:${label}`);
    if (hasText(row?.domain)) {
      seenDomains.add(row.domain);
    }
    addReason(reasons, !requiredDomains.includes(row?.domain), `acceptance_domain_unsupported:${label}`);
    addReason(reasons, !requiredLayers.includes(row?.doctrineLayer), `acceptance_doctrine_layer_unsupported:${label}`);
    addReason(reasons, !ACCEPTANCE_STATUSES.has(row?.status), `acceptance_row_not_passed:${label}`);
    addReason(reasons, !hasText(row?.ownerRoleRef), `acceptance_owner_role_absent:${label}`);
    addReason(reasons, sortedTextList(row?.evidenceRefs).length === 0, `acceptance_evidence_refs_absent:${label}`);
    addReason(reasons, !isDigest(row?.evidenceHash), `acceptance_evidence_hash_invalid:${label}`);
    addReason(reasons, row?.reviewedByHuman !== true, `acceptance_human_review_absent:${label}`);
    addReason(reasons, hlcTuple(row?.reviewedAtHlc) === null, `acceptance_review_time_invalid:${label}`);
    addReason(reasons, hlcBefore(row?.reviewedAtHlc, cycle?.matrixCompiledAtHlc), `acceptance_review_before_matrix:${label}`);
    addReason(reasons, row?.metadataOnly !== true, `acceptance_metadata_boundary_invalid:${label}`);
    addReason(reasons, row?.protectedContentExcluded !== true, `acceptance_protected_boundary_invalid:${label}`);
    addReason(reasons, row?.productionTrustClaim === true, `acceptance_production_claim_forbidden:${label}`);

    rowSummaries.push({
      doctrineLayer: row?.doctrineLayer ?? null,
      domain: row?.domain ?? label,
      evidenceHash: row?.evidenceHash ?? null,
      evidenceRefs: sortedTextList(row?.evidenceRefs),
      status: row?.status ?? 'invalid',
    });
  });

  return {
    domains,
    layers,
    rowSummaries: rowSummaries.sort((left, right) => left.domain.localeCompare(right.domain)),
  };
}

function evaluateOpenQuestions(openQuestions, allowedBobEscalationIds, cycle, reasons) {
  addReason(reasons, !Array.isArray(openQuestions) || openQuestions.length === 0, 'open_questions_absent');
  if (!Array.isArray(openQuestions)) {
    return {
      bobEscalationIds: [],
      consensusDefaultCount: 0,
      escalatedToBobCount: 0,
      questionIds: [],
    };
  }

  const bobEscalationIds = [];
  let consensusDefaultCount = 0;
  let escalatedToBobCount = 0;
  const questionIds = [];
  const seenQuestionIds = new Set();

  openQuestions.forEach((question, index) => {
    const label = hasText(question?.questionId) ? question.questionId : `index_${index}`;
    const escalationId = question?.escalationId;
    const escalated = question?.escalatedToBob === true || question?.disposition === 'bob_escalation_required' || hasText(escalationId);
    const allowedEscalation = hasText(escalationId) && allowedBobEscalationIds.includes(escalationId);

    addReason(reasons, !hasText(question?.questionId), `open_question_id_absent:${label}`);
    addReason(reasons, seenQuestionIds.has(question?.questionId), `open_question_id_duplicate:${label}`);
    if (hasText(question?.questionId)) {
      seenQuestionIds.add(question.questionId);
      questionIds.push(question.questionId);
    }
    addReason(reasons, !OPEN_QUESTION_DISPOSITIONS.has(question?.disposition), `open_question_disposition_invalid:${label}`);
    addReason(reasons, !isDigest(question?.baselineDefaultHash), `open_question_default_hash_invalid:${label}`);
    addReason(reasons, question?.blocksBaselineDevelopment === true, `open_question_blocks_baseline:${label}`);
    addReason(reasons, question?.metadataOnly !== true, `open_question_metadata_boundary_invalid:${label}`);
    addReason(reasons, question?.protectedContentExcluded !== true, `open_question_protected_boundary_invalid:${label}`);
    addReason(reasons, hlcTuple(question?.reviewedAtHlc) === null, `open_question_review_time_invalid:${label}`);
    addReason(reasons, hlcBefore(question?.reviewedAtHlc, cycle?.openedAtHlc), `open_question_review_before_cycle_open:${label}`);

    if (escalated) {
      escalatedToBobCount += 1;
      addReason(reasons, !allowedEscalation, `bob_escalation_not_allowed:${escalationId ?? 'absent'}`);
      addReason(reasons, question?.productionActivationOnly !== true, `bob_escalation_scope_invalid:${label}`);
      if (!allowedEscalation) {
        addReason(reasons, true, `open_question_baseline_default_absent:${label}`);
      } else {
        bobEscalationIds.push(escalationId);
      }
    } else {
      consensusDefaultCount += 1;
      addReason(reasons, question?.disposition !== 'council_consensus_default', `open_question_baseline_default_absent:${label}`);
      addReason(reasons, hasText(escalationId), `open_question_unexpected_escalation:${label}`);
    }
  });

  for (const escalationId of allowedBobEscalationIds) {
    addReason(reasons, !bobEscalationIds.includes(escalationId), `bob_escalation_register_missing:${escalationId}`);
  }

  return {
    bobEscalationIds: uniqueSorted(bobEscalationIds),
    consensusDefaultCount,
    escalatedToBobCount,
    questionIds: uniqueSorted(questionIds),
  };
}

function evaluateActivationGates(gates, requiredGateIds, releaseDecision, reasons) {
  addReason(reasons, !Array.isArray(gates) || gates.length === 0, 'activation_gates_absent');
  if (!Array.isArray(gates)) {
    return {
      activeClaimGateIds: [],
      gateIds: [],
      totalGateCount: 0,
      unverifiedProductionGateCount: requiredGateIds.length,
      verifiedGateCount: 0,
    };
  }

  const gateIds = sortedTextList(gates.map((gate) => gate?.gateId));
  const activeClaimGateIds = [];
  let verifiedGateCount = 0;
  let unverifiedProductionGateCount = 0;
  const seenGateIds = new Set();

  for (const gateId of requiredGateIds) {
    addReason(reasons, !gateIds.includes(gateId), `activation_gate_missing:${gateId}`);
  }

  gates.forEach((gate, index) => {
    const label = hasText(gate?.gateId) ? gate.gateId : `index_${index}`;
    addReason(reasons, !hasText(gate?.gateId), `activation_gate_id_absent:${label}`);
    addReason(reasons, seenGateIds.has(gate?.gateId), `activation_gate_duplicate:${label}`);
    if (hasText(gate?.gateId)) {
      seenGateIds.add(gate.gateId);
    }
    addReason(reasons, !requiredGateIds.includes(gate?.gateId), `activation_gate_unsupported:${label}`);
    addReason(reasons, !hasText(gate?.sourceRef), `activation_gate_source_ref_absent:${label}`);
    addReason(reasons, !GATE_STATUSES.has(gate?.status), `activation_gate_status_invalid:${label}`);
    addReason(reasons, gate?.requiredForProductionTrustClaim !== true, `activation_gate_production_rule_absent:${label}`);
    addReason(reasons, gate?.blocksBaselineDevelopment === true, `activation_gate_blocks_baseline:${label}`);
    addReason(reasons, sortedTextList(gate?.minimumTestRefs).length === 0, `activation_gate_minimum_tests_absent:${label}`);
    addReason(reasons, !isDigest(gate?.minimumTestHash), `activation_gate_minimum_test_hash_invalid:${label}`);
    addReason(reasons, gate?.metadataOnly !== true, `activation_gate_metadata_boundary_invalid:${label}`);
    addReason(reasons, hlcTuple(gate?.reviewedAtHlc) === null, `activation_gate_review_time_invalid:${label}`);

    if (gate?.status === 'verified') {
      verifiedGateCount += 1;
      addReason(reasons, !isDigest(gate?.verificationEvidenceHash), `activation_gate_verification_evidence_missing:${label}`);
    } else if (gate?.requiredForProductionTrustClaim === true) {
      unverifiedProductionGateCount += 1;
    }

    if (gate?.productionClaimActive === true) {
      activeClaimGateIds.push(label);
      addReason(reasons, true, `activation_gate_active_claim_forbidden:${label}`);
    }

    addReason(
      reasons,
      releaseDecision?.decision === 'production_trust_active' && gate?.status !== 'verified',
      `production_claim_gate_unverified:${label}`,
    );
  });

  return {
    activeClaimGateIds: uniqueSorted(activeClaimGateIds),
    gateIds,
    totalGateCount: gates.length,
    unverifiedProductionGateCount,
    verifiedGateCount,
  };
}

function evaluateValidationEvidence(validation, cycle, reasons) {
  addReason(reasons, validation === null || validation === undefined, 'validation_evidence_absent');
  addReason(reasons, !hasText(validation?.commandRef), 'validation_command_ref_absent');
  addReason(reasons, validation?.passed !== true, 'validation_not_passed');
  addReason(reasons, !Number.isSafeInteger(validation?.testCount) || validation.testCount <= 0, 'validation_test_count_invalid');
  addReason(reasons, !isBasisPoints(validation?.coverageLineBasisPoints), 'validation_coverage_invalid');
  addReason(reasons, validation?.sourceGuardPassed !== true, 'validation_source_guard_absent');
  addReason(reasons, validation?.noExochainSourceModified !== true, 'validation_exochain_read_only_absent');
  addReason(reasons, validation?.docsUpdated !== true, 'validation_docs_update_absent');
  addReason(reasons, !isDigest(validation?.evidenceHash), 'validation_evidence_hash_invalid');
  addReason(reasons, validation?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(validation?.recordedAtHlc) === null, 'validation_time_invalid');
  addReason(reasons, hlcBefore(validation?.recordedAtHlc, cycle?.validationRecordedAtHlc), 'validation_before_cycle_validation_step');
}

function evaluateReleaseDecision(decision, cycle, reasons) {
  addReason(reasons, decision === null || decision === undefined, 'release_decision_absent');
  addReason(reasons, !RELEASE_DECISIONS.has(decision?.decision), 'release_decision_invalid');
  addReason(reasons, decision?.decision === 'production_trust_active', 'release_decision_production_trust_forbidden');
  addReason(reasons, !hasText(decision?.reviewerDid), 'release_decision_reviewer_absent');
  addReason(reasons, sortedTextList(decision?.reviewerRoleRefs).length === 0, 'release_decision_reviewer_roles_absent');
  addReason(reasons, !isDigest(decision?.decisionHash), 'release_decision_hash_invalid');
  addReason(reasons, decision?.noProductionTrustClaim !== true, 'release_decision_production_trust_forbidden');
  addReason(reasons, decision?.bobEscalationsNarrowed !== true, 'release_decision_bob_escalations_not_narrowed');
  addReason(reasons, decision?.exochainSourceReadOnly !== true, 'release_decision_exochain_read_only_absent');
  addReason(reasons, decision?.finalAuthority !== 'human', 'release_decision_human_authority_absent');
  addReason(reasons, decision?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, decision?.metadataOnly !== true, 'release_decision_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(decision?.decidedAtHlc) === null, 'release_decision_time_invalid');
  addReason(reasons, hlcBefore(decision?.decidedAtHlc, cycle?.releaseDecisionAtHlc), 'release_decision_before_cycle_decision_step');
}

function evaluateAuditRecord(auditRecord, cycle, decision, reasons) {
  addReason(reasons, !hasText(auditRecord?.auditRecordRef), 'release_audit_record_ref_absent');
  addReason(reasons, !isDigest(auditRecord?.auditRecordHash), 'release_audit_record_hash_invalid');
  addReason(reasons, auditRecord?.metadataOnly !== true, 'release_audit_record_metadata_boundary_invalid');
  addReason(reasons, auditRecord?.includesProtectedContent === true, 'release_audit_record_protected_content_forbidden');
  addReason(reasons, hlcTuple(auditRecord?.receiptRecordedAtHlc) === null, 'release_audit_record_time_invalid');
  addReason(reasons, hlcBefore(auditRecord?.receiptRecordedAtHlc, cycle?.auditRecordedAtHlc), 'release_audit_before_cycle_audit_step');
  addReason(reasons, hlcBefore(auditRecord?.receiptRecordedAtHlc, decision?.decidedAtHlc), 'release_audit_before_decision');
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

function buildReleaseReadiness(input, policySummary, acceptanceSummary, openQuestionSummary, activationSummary) {
  const validationSummary = {
    commandRef: input.validationEvidence.commandRef,
    coverageLineBasisPoints: input.validationEvidence.coverageLineBasisPoints,
    passed: true,
    sourceGuardPassed: true,
    testCount: input.validationEvidence.testCount,
  };
  const matrixHash = sha256Hex({
    acceptanceRows: acceptanceSummary.rowSummaries,
    activationGateIds: activationSummary.gateIds,
    auditRecordHash: input.auditRecord.auditRecordHash,
    bobEscalationIds: openQuestionSummary.bobEscalationIds,
    cycleRef: input.releaseCycle.cycleRef,
    releaseDecisionHash: input.releaseDecision.decisionHash,
    tenantId: input.tenantId,
    validationEvidenceHash: input.validationEvidence.evidenceHash,
  });

  return {
    schema: MATRIX_SCHEMA,
    matrixId: `cmrel_${sha256Hex({
      cycleRef: input.releaseCycle.cycleRef,
      matrixHash,
      tenantId: input.tenantId,
    }).slice(0, 32)}`,
    tenantId: input.tenantId,
    releaseCandidateRef: input.releaseCycle.releaseCandidateRef,
    releaseState: input.releaseDecision.decision,
    trustState: 'inactive',
    productionTrustState: 'inactive',
    exochainProductionClaim: false,
    baselineReleasePermitted: input.releaseDecision.decision === 'baseline_ready_inactive_trust',
    productionActivationPermitted: false,
    metadataOnly: true,
    containsProtectedContent: false,
    doctrineLayersCovered: [...REQUIRED_DOCTRINE_LAYERS],
    acceptanceDomainsCovered: acceptanceSummary.domains,
    acceptanceRows: acceptanceSummary.rowSummaries,
    contextDocRefs: policySummary.contextDocRefs,
    bobEscalationIds: openQuestionSummary.bobEscalationIds,
    openQuestionSummary: {
      consensusDefaultCount: openQuestionSummary.consensusDefaultCount,
      escalatedToBobCount: openQuestionSummary.escalatedToBobCount,
      questionIds: openQuestionSummary.questionIds,
    },
    activationGateSummary: {
      activeClaimGateIds: activationSummary.activeClaimGateIds,
      totalGateCount: activationSummary.totalGateCount,
      unverifiedProductionGateCount: activationSummary.unverifiedProductionGateCount,
      verifiedGateCount: activationSummary.verifiedGateCount,
    },
    validationSummary,
    matrixHash,
    auditRecordHash: input.auditRecord.auditRecordHash,
    auditRecordedAtHlc: input.auditRecord.receiptRecordedAtHlc,
  };
}

function buildReceipt(input, releaseReadiness) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: releaseReadiness.matrixHash,
    artifactType: 'release_readiness_matrix',
    artifactVersion: input.releaseCycle.releaseCandidateRef,
    classification: 'restricted_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.auditRecord.receiptRecordedAtHlc,
    sensitivityTags: ['release_readiness', 'metadata_only', 'inactive_trust_state'],
    sourceSystem: 'cybermedica-qms',
    tenantId: input.tenantId,
  });
}

export function evaluateReleaseReadinessMatrix(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policySummary = evaluateReleasePolicy(input?.releasePolicy, reasons);
  evaluateReleaseCycle(input?.releaseCycle, input?.releasePolicy, reasons);
  const acceptanceSummary = evaluateAcceptanceRows(
    input?.acceptanceRows,
    policySummary.requiredAcceptanceDomains,
    policySummary.requiredDoctrineLayers,
    input?.releaseCycle,
    reasons,
  );
  const openQuestionSummary = evaluateOpenQuestions(
    input?.openQuestions,
    policySummary.allowedBobEscalationIds,
    input?.releaseCycle,
    reasons,
  );
  const activationSummary = evaluateActivationGates(
    input?.activationGates,
    policySummary.activationGateIds,
    input?.releaseDecision,
    reasons,
  );
  evaluateValidationEvidence(input?.validationEvidence, input?.releaseCycle, reasons);
  evaluateReleaseDecision(input?.releaseDecision, input?.releaseCycle, reasons);
  evaluateAuditRecord(input?.auditRecord, input?.releaseCycle, input?.releaseDecision, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: unique,
      releaseReadiness: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const releaseReadiness = buildReleaseReadiness(
    input,
    policySummary,
    acceptanceSummary,
    openQuestionSummary,
    activationSummary,
  );

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    releaseReadiness,
    receipt: buildReceipt(input, releaseReadiness),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
