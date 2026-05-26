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
const REGISTER_SCHEMA = 'cybermedica.open_question_register.v1';
const DECISION_SCHEMA = 'cybermedica.open_question_register_decision.v1';
const REQUIRED_PERMISSION = 'open_question_register_review';

const REQUIRED_QUESTION_FAMILIES = Object.freeze([
  'adjacent_scope',
  'clinical_consent_legal',
  'data_privacy',
  'governance_decision_forum',
  'identity_human_gate',
  'operations_secret_management',
  'role_authority_matrix',
  'root_trust_activation',
  'runtime_topology',
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

const REQUIRED_CONTEXT_DOC_REFS = Object.freeze([
  'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  'docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md',
  'docs/context/EXOCHAIN_COUNCIL_REVIEW_FOR_CYBERMEDICA_OPEN_QUESTIONS.md',
  'docs/context/EXOCHAIN_OPEN_QUESTIONS_FOR_BOB.md',
]);

const POLICY_STATUSES = new Set(['active']);
const QUESTION_DISPOSITIONS = new Set([
  'bob_activation_escalation',
  'closed_by_governance',
  'council_consensus_default',
]);
const HUMAN_REVIEW_DECISIONS = new Set([
  'hold_for_open_question_gap',
  'open_question_register_accepted_inactive_trust',
]);

const RAW_OPEN_QUESTION_FIELDS = new Set([
  'answerbody',
  'body',
  'consoleoutput',
  'content',
  'decisiontext',
  'freetext',
  'freetextnote',
  'openquestiontext',
  'questionbody',
  'rawanswer',
  'rawbobanswer',
  'rawcontext',
  'rawdecision',
  'rawescalation',
  'rawopenquestion',
  'rawquestion',
  'rawquestiontext',
  'rawreview',
  'rawsourcecontent',
  'reviewnotes',
  'sourcedocumentbody',
  'validationlog',
]);

const SECRET_OPEN_QUESTION_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
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

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
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

function assertNoRawOpenQuestionContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawOpenQuestionContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_OPEN_QUESTION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw open question content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_OPEN_QUESTION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`open question secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawOpenQuestionContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawOpenQuestionContent(input ?? {});
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
  addReason(reasons, input?.actor?.kind !== 'human', 'human_open_question_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'open_question_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateOpenQuestionPolicy(policy, reasons) {
  const requiredQuestionFamilies = sortedTextList(policy?.requiredQuestionFamilies);
  const allowedBobEscalationIds = sortedTextList(policy?.allowedBobEscalationIds);
  const contextDocRefs = sortedTextList(policy?.contextDocRefs);

  addReason(reasons, !hasText(policy?.policyRef), 'open_question_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'open_question_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'open_question_policy_inactive');
  addReason(reasons, policy?.councilDefaultsRequired !== true, 'open_question_council_default_rule_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'open_question_policy_metadata_boundary_missing');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'open_question_policy_protected_boundary_missing');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'open_question_policy_evaluated_hlc_invalid');

  evaluateRequiredSet(
    requiredQuestionFamilies,
    REQUIRED_QUESTION_FAMILIES,
    'policy_question_family_missing',
    'policy_question_family_unsupported',
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
    contextDocRefs,
    REQUIRED_CONTEXT_DOC_REFS,
    'policy_context_doc_missing',
    'policy_context_doc_unsupported',
    reasons,
  );

  return {
    allowedBobEscalationIds: allowedBobEscalationIds.length > 0 ? allowedBobEscalationIds : [...ALLOWED_BOB_ESCALATION_IDS],
    requiredQuestionFamilies:
      requiredQuestionFamilies.length > 0 ? requiredQuestionFamilies : [...REQUIRED_QUESTION_FAMILIES],
  };
}

function evaluateRegisterCycle(cycle, policy, reasons) {
  addReason(reasons, !hasText(cycle?.registerRef), 'open_question_register_ref_absent');
  addReason(reasons, cycle?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, cycle?.metadataOnly !== true, 'open_question_cycle_metadata_boundary_missing');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'open_question_cycle_protected_boundary_missing');

  const ordered = [
    ['openedAtHlc', cycle?.openedAtHlc],
    ['compiledAtHlc', cycle?.compiledAtHlc],
    ['councilReviewedAtHlc', cycle?.councilReviewedAtHlc],
    ['humanReviewedAtHlc', cycle?.humanReviewedAtHlc],
    ['validationRecordedAtHlc', cycle?.validationRecordedAtHlc],
  ];

  for (const [label, value] of ordered) {
    addReason(reasons, hlcTuple(value) === null, `open_question_cycle_${label}_invalid`);
  }
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, cycle?.openedAtHlc), 'open_question_policy_after_cycle_open');
  addReason(reasons, !hlcAfter(cycle?.compiledAtHlc, cycle?.openedAtHlc), 'open_question_compile_order_invalid');
  addReason(
    reasons,
    !hlcAfter(cycle?.councilReviewedAtHlc, cycle?.compiledAtHlc),
    'open_question_council_review_order_invalid',
  );
  addReason(
    reasons,
    !hlcAfter(cycle?.humanReviewedAtHlc, cycle?.councilReviewedAtHlc),
    'open_question_human_review_order_invalid',
  );
  addReason(
    reasons,
    !hlcAfter(cycle?.validationRecordedAtHlc, cycle?.humanReviewedAtHlc),
    'open_question_validation_order_invalid',
  );
}

function evaluateQuestionRecords(questionRecords, policySummary, cycle, humanReview, reasons) {
  addReason(reasons, !Array.isArray(questionRecords) || questionRecords.length === 0, 'open_question_records_absent');
  if (!Array.isArray(questionRecords)) {
    return {
      baselineBlockedQuestionIds: [],
      bobEscalationIds: [],
      consensusDefaultQuestionIds: [],
      questionFamiliesCovered: [],
      questionIds: [],
      visibleQuestionIds: [],
    };
  }

  const questionFamiliesCovered = uniqueSorted(questionRecords.map((question) => question?.questionFamily));
  const questionIds = [];
  const visibleQuestionIds = [];
  const consensusDefaultQuestionIds = [];
  const bobEscalationIds = [];
  const baselineBlockedQuestionIds = [];
  const seenQuestionIds = new Set();

  evaluateRequiredSet(
    questionFamiliesCovered,
    policySummary.requiredQuestionFamilies,
    'question_family_missing',
    'question_family_unsupported',
    reasons,
  );

  questionRecords.forEach((question, index) => {
    const label = hasText(question?.questionId) ? question.questionId : `index_${index}`;
    const escalationId = question?.escalationId;
    const escalated =
      question?.disposition === 'bob_activation_escalation' || question?.productionActivationOnly === true || hasText(escalationId);
    const allowedEscalation = hasText(escalationId) && policySummary.allowedBobEscalationIds.includes(escalationId);

    addReason(reasons, !hasText(question?.questionId), `open_question_id_absent:${label}`);
    addReason(reasons, seenQuestionIds.has(question?.questionId), `open_question_id_duplicate:${label}`);
    if (hasText(question?.questionId)) {
      seenQuestionIds.add(question.questionId);
      questionIds.push(question.questionId);
    }
    addReason(reasons, !hasText(question?.sourceRef), `open_question_source_ref_absent:${label}`);
    addReason(reasons, !QUESTION_DISPOSITIONS.has(question?.disposition), `open_question_disposition_invalid:${label}`);
    addReason(reasons, !isDigest(question?.baselineDefaultHash), `open_question_baseline_default_hash_invalid:${label}`);
    addReason(reasons, !isDigest(question?.decisionNeededHash), `open_question_decision_needed_hash_invalid:${label}`);
    addReason(reasons, !hasText(question?.ownerRoleRef), `open_question_owner_absent:${label}`);
    addReason(reasons, question?.blocksBaselineDevelopment === true, `open_question_blocks_baseline:${label}`);
    addReason(reasons, question?.metadataOnly !== true, `open_question_metadata_boundary_missing:${label}`);
    addReason(reasons, question?.protectedContentExcluded !== true, `open_question_protected_boundary_missing:${label}`);
    addReason(reasons, question?.productionTrustClaim === true, `open_question_production_trust_claim_forbidden:${label}`);
    addReason(reasons, hlcTuple(question?.reviewedAtHlc) === null, `open_question_review_hlc_invalid:${label}`);
    addReason(reasons, hlcBefore(question?.reviewedAtHlc, cycle?.openedAtHlc), `open_question_review_before_cycle_open:${label}`);
    addReason(
      reasons,
      humanReview?.reviewedAtHlc !== undefined && hlcAfter(question?.reviewedAtHlc, humanReview?.reviewedAtHlc),
      `open_question_review_after_human_review:${label}`,
    );

    if (question?.visibleUntilClosed === true && question?.closedByGovernance !== true) {
      visibleQuestionIds.push(label);
    }
    if (question?.blocksBaselineDevelopment === true) {
      baselineBlockedQuestionIds.push(label);
    }

    if (escalated) {
      addReason(reasons, !allowedEscalation, `bob_escalation_not_allowed:${escalationId ?? 'absent'}`);
      addReason(
        reasons,
        question?.productionActivationOnly !== true,
        `open_question_escalation_not_activation_only:${label}`,
      );
      if (allowedEscalation) {
        bobEscalationIds.push(escalationId);
      }
    } else {
      addReason(
        reasons,
        question?.disposition !== 'council_consensus_default',
        `open_question_baseline_default_missing:${label}`,
      );
      addReason(reasons, hasText(escalationId), `open_question_unexpected_escalation:${label}`);
      consensusDefaultQuestionIds.push(label);
    }
  });

  for (const escalationId of policySummary.allowedBobEscalationIds) {
    addReason(reasons, !bobEscalationIds.includes(escalationId), `bob_escalation_register_missing:${escalationId}`);
  }

  return {
    baselineBlockedQuestionIds: uniqueSorted(baselineBlockedQuestionIds),
    bobEscalationIds: uniqueSorted(bobEscalationIds),
    consensusDefaultQuestionIds: uniqueSorted(consensusDefaultQuestionIds),
    questionFamiliesCovered,
    questionIds: uniqueSorted(questionIds),
    visibleQuestionIds: uniqueSorted(visibleQuestionIds),
  };
}

function evaluateValidationEvidence(validation, cycle, reasons) {
  addReason(reasons, validation === null || validation === undefined, 'open_question_validation_absent');
  addReason(reasons, !hasText(validation?.commandRef), 'open_question_validation_command_absent');
  addReason(reasons, validation?.passed !== true, 'open_question_validation_failed');
  addReason(reasons, validation?.sourceGuardPassed !== true, 'source_guard_not_passed');
  addReason(reasons, validation?.docsUpdated !== true, 'open_question_docs_not_updated');
  addReason(reasons, validation?.noExochainSourceModified !== true, 'exochain_source_modified');
  addReason(reasons, !isDigest(validation?.evidenceHash), 'open_question_validation_hash_invalid');
  addReason(reasons, validation?.metadataOnly !== true, 'open_question_validation_metadata_boundary_missing');
  addReason(reasons, hlcTuple(validation?.recordedAtHlc) === null, 'open_question_validation_hlc_invalid');
  addReason(reasons, hlcBefore(validation?.recordedAtHlc, cycle?.validationRecordedAtHlc), 'open_question_validation_before_cycle');
}

function evaluateHumanReview(review, cycle, reasons) {
  addReason(reasons, !hasText(review?.reviewerDid), 'open_question_reviewer_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'open_question_human_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'open_question_human_decision_hash_invalid');
  addReason(reasons, review?.finalAuthority !== 'human' || review?.aiFinalAuthority === true, 'open_question_human_final_authority_required');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'production_trust_claim_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'open_question_human_review_metadata_boundary_missing');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'open_question_human_review_hlc_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, cycle?.humanReviewedAtHlc), 'open_question_human_review_before_cycle');
}

function buildOpenQuestionRegister(input, questionSummary) {
  const summary = {
    bobEscalationCount: questionSummary.bobEscalationIds.length,
    consensusDefaultCount: questionSummary.consensusDefaultQuestionIds.length,
    totalQuestionCount: questionSummary.questionIds.length,
    visibleOpenQuestionCount: questionSummary.visibleQuestionIds.length,
  };

  const registerMaterial = {
    schema: REGISTER_SCHEMA,
    registerRef: input?.registerCycle?.registerRef ?? null,
    tenantId: input?.tenantId ?? null,
    questionFamiliesCovered: questionSummary.questionFamiliesCovered,
    questionIds: questionSummary.questionIds,
    visibleQuestionIds: questionSummary.visibleQuestionIds,
    consensusDefaultQuestionIds: questionSummary.consensusDefaultQuestionIds,
    bobEscalationIds: questionSummary.bobEscalationIds,
    baselineBlockedQuestionIds: questionSummary.baselineBlockedQuestionIds,
    summary,
    productionTrustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    protectedContentExcluded: true,
  };

  return {
    ...registerMaterial,
    openQuestionRegisterHash: sha256Hex(registerMaterial),
  };
}

function buildReceipt(input, openQuestionRegister) {
  return createEvidenceReceipt({
    actorDid: input?.actor?.did ?? 'did:exo:open-question-unknown',
    artifactHash: openQuestionRegister.openQuestionRegisterHash,
    artifactType: 'open_question_register',
    artifactVersion: 'v1',
    classification: 'metadata_only_open_question_register',
    custodyDigest: input?.custodyDigest ?? openQuestionRegister.openQuestionRegisterHash,
    hlcTimestamp: input?.registerCycle?.validationRecordedAtHlc ?? { physicalMs: 0, logical: 0 },
    schema: DECISION_SCHEMA,
    sensitivityTags: ['open_questions', 'metadata_only', 'inactive_trust_state'],
    sourceSystem: 'cybermedica',
    tenantId: input?.tenantId ?? 'tenant-unknown',
  });
}

export function evaluateOpenQuestionRegister(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policySummary = evaluateOpenQuestionPolicy(input?.openQuestionPolicy, reasons);
  evaluateRegisterCycle(input?.registerCycle, input?.openQuestionPolicy, reasons);
  evaluateValidationEvidence(input?.validationEvidence, input?.registerCycle, reasons);
  evaluateHumanReview(input?.humanReview, input?.registerCycle, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'open_question_custody_digest_invalid');

  const questionSummary = evaluateQuestionRecords(
    input?.questionRecords,
    policySummary,
    input?.registerCycle,
    input?.humanReview,
    reasons,
  );
  const finalReasons = uniqueReasons(reasons);
  const openQuestionRegister = buildOpenQuestionRegister(input, questionSummary);
  const receipt = buildReceipt(input, openQuestionRegister);

  return {
    schema: DECISION_SCHEMA,
    decision: finalReasons.length === 0 ? 'permitted' : 'denied',
    failClosed: finalReasons.length > 0,
    reasons: finalReasons,
    openQuestionRegister,
    receipt,
  };
}
