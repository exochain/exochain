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
const REGISTER_SCHEMA = 'cybermedica.scope_legal_review_register.v1';
const DECISION_SCHEMA = 'cybermedica.scope_legal_review_register_decision.v1';
const REQUIRED_PERMISSION = 'scope_legal_review_register';

const REQUIRED_SCOPE_QUESTION_FAMILIES = Object.freeze([
  'accreditation_language',
  'ai_irb_public_language',
  'anchoring_metadata_prohibitions',
  'control_library_amendment_authority',
  'control_library_scope',
  'cro_white_labeling',
  'ctms_scope_boundary',
  'decision_forum_panel_model',
  'econsent_execution_model',
  'evidence_retention_policy_model',
  'exochain_deployment_model',
  'first_commercial_form',
  'inspection_mode_support',
  'participant_facing_scope',
  'portable_site_passports',
  'product_accountability_model',
  'safest_commercial_claim',
  'sasi_qms_rights',
  'sponsor_visibility_standard',
  'system_of_record_posture',
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

const REQUIRED_SOURCE_DOC_REFS = Object.freeze([
  'cyber_medica_qms_prd_master.md#open-questions-for-scoping-and-legal-review',
  'cybermedica_2_0_sandy_seven_layer_master_prd.md#open-questions-for-scoping-and-legal-review',
  'docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md',
]);

const ACTIVE_POLICY_STATUSES = new Set(['active']);
const QUESTION_DISPOSITIONS = new Set([
  'bob_activation_escalation',
  'closed_by_governance',
  'commercial_decision_required',
  'council_default_for_baseline',
  'legal_review_required',
]);
const HUMAN_REVIEW_DECISIONS = new Set([
  'hold_for_scope_legal_gap',
  'scope_legal_register_accepted_inactive_trust',
]);

const RAW_SCOPE_REVIEW_FIELDS = new Set([
  'answerbody',
  'body',
  'claimcopy',
  'claimlanguage',
  'commercialcopy',
  'content',
  'decisiontext',
  'freetext',
  'freetextnote',
  'legalanalysisbody',
  'openquestiontext',
  'prdtext',
  'questionbody',
  'rawanswer',
  'rawclaimcopy',
  'rawcommercialcopy',
  'rawlegalanalysis',
  'rawopenquestion',
  'rawprdcontent',
  'rawprdtext',
  'rawquestion',
  'rawquestiontext',
  'rawreview',
  'rawscopecontent',
  'rawsourcecontent',
  'reviewnotes',
  'scopebody',
  'sourcedocumentbody',
]);

const SECRET_SCOPE_REVIEW_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'bootstrapsecret',
  'bootstraptoken',
  'clientsecret',
  'credential',
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

function assertNoRawScopeReviewContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawScopeReviewContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_SCOPE_REVIEW_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw scope legal review content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_SCOPE_REVIEW_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`scope legal review secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawScopeReviewContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawScopeReviewContent(input ?? {});
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
  addReason(reasons, input?.actor?.kind !== 'human', 'human_scope_legal_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'scope_legal_review_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateScopeLegalPolicy(policy, reasons) {
  const requiredQuestionFamilies = sortedTextList(policy?.requiredQuestionFamilies);
  const allowedBobEscalationIds = sortedTextList(policy?.allowedBobEscalationIds);
  const sourceDocRefs = sortedTextList(policy?.sourceDocRefs);

  addReason(reasons, !hasText(policy?.policyRef), 'scope_legal_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'scope_legal_policy_hash_invalid');
  addReason(reasons, !ACTIVE_POLICY_STATUSES.has(policy?.status), 'scope_legal_policy_inactive');
  addReason(reasons, policy?.councilDefaultsRequired !== true, 'scope_legal_council_default_rule_absent');
  addReason(reasons, policy?.noBroadBobEscalations !== true, 'scope_legal_broad_bob_escalation_rule_absent');
  addReason(reasons, policy?.publicClaimReviewRequired !== true, 'scope_legal_public_claim_review_rule_absent');
  addReason(reasons, policy?.legalRegulatoryReviewRequired !== true, 'scope_legal_review_rule_absent');
  addReason(reasons, policy?.productionTrustClaimsInactive !== true, 'scope_legal_production_claim_rule_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'scope_legal_policy_metadata_boundary_missing');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'scope_legal_policy_protected_boundary_missing');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'scope_legal_policy_evaluated_hlc_invalid');

  evaluateRequiredSet(
    requiredQuestionFamilies,
    REQUIRED_SCOPE_QUESTION_FAMILIES,
    'policy_scope_question_family_missing',
    'policy_scope_question_family_unsupported',
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
    sourceDocRefs,
    REQUIRED_SOURCE_DOC_REFS,
    'policy_scope_source_doc_missing',
    'policy_scope_source_doc_unsupported',
    reasons,
  );

  return {
    allowedBobEscalationIds:
      allowedBobEscalationIds.length > 0 ? allowedBobEscalationIds : [...ALLOWED_BOB_ESCALATION_IDS],
    requiredQuestionFamilies:
      requiredQuestionFamilies.length > 0 ? requiredQuestionFamilies : [...REQUIRED_SCOPE_QUESTION_FAMILIES],
  };
}

function evaluateRegisterCycle(cycle, policy, reasons) {
  addReason(reasons, !hasText(cycle?.registerRef), 'scope_legal_register_ref_absent');
  addReason(reasons, cycle?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, cycle?.metadataOnly !== true, 'scope_legal_cycle_metadata_boundary_missing');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'scope_legal_cycle_protected_boundary_missing');

  const ordered = [
    ['compiledAtHlc', cycle?.compiledAtHlc],
    ['humanReviewedAtHlc', cycle?.humanReviewedAtHlc],
    ['validationRecordedAtHlc', cycle?.validationRecordedAtHlc],
  ];

  for (const [label, value] of ordered) {
    addReason(reasons, hlcTuple(value) === null, `scope_legal_cycle_${label}_invalid`);
  }
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, cycle?.compiledAtHlc), 'scope_legal_policy_after_compile');
  addReason(reasons, !hlcAfter(cycle?.humanReviewedAtHlc, cycle?.compiledAtHlc), 'scope_legal_human_review_order_invalid');
  addReason(
    reasons,
    !hlcAfter(cycle?.validationRecordedAtHlc, cycle?.humanReviewedAtHlc),
    'scope_legal_validation_order_invalid',
  );
}

function evaluateQuestionRecords(questionRecords, policySummary, cycle, humanReview, reasons) {
  addReason(reasons, !Array.isArray(questionRecords) || questionRecords.length === 0, 'scope_question_records_absent');
  if (!Array.isArray(questionRecords)) {
    return {
      baselineBlockedQuestionIds: [],
      bobEscalationIds: [],
      commercialDecisionQuestionIds: [],
      councilDefaultQuestionIds: [],
      legalReviewQuestionIds: [],
      questionFamiliesCovered: [],
      questionIds: [],
      records: [],
      visibleQuestionIds: [],
    };
  }

  const questionFamiliesCovered = uniqueSorted(questionRecords.map((question) => question?.questionFamily));
  const questionIds = [];
  const visibleQuestionIds = [];
  const councilDefaultQuestionIds = [];
  const legalReviewQuestionIds = [];
  const commercialDecisionQuestionIds = [];
  const bobEscalationIds = [];
  const baselineBlockedQuestionIds = [];
  const seenQuestionIds = new Set();
  const seenQuestionFamilies = new Set();

  evaluateRequiredSet(
    questionFamiliesCovered,
    policySummary.requiredQuestionFamilies,
    'scope_question_family_missing',
    'scope_question_family_unsupported',
    reasons,
  );

  const records = questionRecords
    .map((question, index) => {
      const label = hasText(question?.questionId) ? question.questionId : `index_${index}`;
      const questionFamily = question?.questionFamily;
      const escalationId = question?.bobEscalationId;
      const escalated = question?.disposition === 'bob_activation_escalation' || hasText(escalationId);
      const allowedEscalation = hasText(escalationId) && policySummary.allowedBobEscalationIds.includes(escalationId);

      addReason(reasons, !hasText(question?.questionId), `scope_question_id_absent:${label}`);
      addReason(reasons, seenQuestionIds.has(question?.questionId), `scope_question_id_duplicate:${label}`);
      if (hasText(question?.questionId)) {
        seenQuestionIds.add(question.questionId);
        questionIds.push(question.questionId);
      }
      addReason(reasons, !hasText(questionFamily), `scope_question_family_absent:${label}`);
      addReason(reasons, seenQuestionFamilies.has(questionFamily), `scope_question_family_duplicate:${questionFamily}`);
      if (hasText(questionFamily)) {
        seenQuestionFamilies.add(questionFamily);
      }
      addReason(reasons, !hasText(question?.sourceRef), `scope_question_source_ref_absent:${label}`);
      addReason(reasons, !Number.isSafeInteger(question?.sourceLineRef), `scope_question_source_line_invalid:${label}`);
      addReason(reasons, !QUESTION_DISPOSITIONS.has(question?.disposition), `scope_question_disposition_invalid:${label}`);
      addReason(reasons, !isDigest(question?.baselineDefaultHash), `scope_question_baseline_default_hash_invalid:${label}`);
      addReason(reasons, !isDigest(question?.decisionNeededHash), `scope_question_decision_needed_hash_invalid:${label}`);
      addReason(reasons, !hasText(question?.ownerRoleRef), `scope_question_owner_absent:${label}`);
      addReason(reasons, typeof question?.legalReviewRequired !== 'boolean', `scope_question_legal_flag_invalid:${label}`);
      addReason(
        reasons,
        typeof question?.commercialDecisionRequired !== 'boolean',
        `scope_question_commercial_flag_invalid:${label}`,
      );
      addReason(reasons, question?.councilDefaultUsed !== true, `scope_question_council_default_absent:${label}`);
      addReason(reasons, question?.blocksBaselineDevelopment === true, `scope_question_blocks_baseline:${label}`);
      addReason(reasons, question?.publicClaimAllowed === true, `scope_question_public_claim_allowed:${label}`);
      addReason(reasons, question?.metadataOnly !== true, `scope_question_metadata_boundary_missing:${label}`);
      addReason(reasons, question?.protectedContentExcluded !== true, `scope_question_protected_boundary_missing:${label}`);
      addReason(reasons, question?.productionTrustClaim === true, `scope_question_production_trust_claim_forbidden:${label}`);
      addReason(reasons, hlcTuple(question?.reviewedAtHlc) === null, `scope_question_review_hlc_invalid:${label}`);
      addReason(reasons, hlcBefore(question?.reviewedAtHlc, cycle?.compiledAtHlc), `scope_question_review_before_compile:${label}`);
      addReason(
        reasons,
        humanReview?.reviewedAtHlc !== undefined && hlcAfter(question?.reviewedAtHlc, humanReview?.reviewedAtHlc),
        `scope_question_review_after_human_review:${label}`,
      );

      if (question?.visibleUntilClosed === true && question?.disposition !== 'closed_by_governance') {
        visibleQuestionIds.push(label);
      }
      if (question?.blocksBaselineDevelopment === true) {
        baselineBlockedQuestionIds.push(label);
      }
      if (question?.legalReviewRequired === true) {
        legalReviewQuestionIds.push(label);
      }
      if (question?.commercialDecisionRequired === true) {
        commercialDecisionQuestionIds.push(label);
      }

      if (escalated) {
        addReason(reasons, !allowedEscalation, `bob_escalation_not_allowed:${escalationId ?? 'absent'}`);
        addReason(reasons, question?.productionActivationOnly !== true, `scope_question_escalation_not_activation_only:${label}`);
        if (allowedEscalation) {
          bobEscalationIds.push(escalationId);
        }
      } else {
        addReason(
          reasons,
          question?.disposition !== 'council_default_for_baseline',
          `scope_question_baseline_default_missing:${label}`,
        );
        councilDefaultQuestionIds.push(label);
      }

      return {
        questionFamily: questionFamily ?? '',
        questionId: hasText(question?.questionId) ? question.questionId : label,
        disposition: question?.disposition ?? '',
        ownerRoleRef: question?.ownerRoleRef ?? '',
        legalReviewRequired: question?.legalReviewRequired === true,
        commercialDecisionRequired: question?.commercialDecisionRequired === true,
        productionActivationOnly: question?.productionActivationOnly === true,
        baselineDefaultHash: question?.baselineDefaultHash ?? null,
        decisionNeededHash: question?.decisionNeededHash ?? null,
        reviewedAtHlc: question?.reviewedAtHlc ?? null,
        metadataOnly: question?.metadataOnly === true,
        protectedContentExcluded: question?.protectedContentExcluded === true,
      };
    })
    .sort((left, right) => left.questionFamily.localeCompare(right.questionFamily));

  return {
    baselineBlockedQuestionIds: uniqueSorted(baselineBlockedQuestionIds),
    bobEscalationIds: uniqueSorted(bobEscalationIds),
    commercialDecisionQuestionIds: uniqueSorted(commercialDecisionQuestionIds),
    councilDefaultQuestionIds: uniqueSorted(councilDefaultQuestionIds),
    legalReviewQuestionIds: uniqueSorted(legalReviewQuestionIds),
    questionFamiliesCovered,
    questionIds: uniqueSorted(questionIds),
    records,
    visibleQuestionIds: uniqueSorted(visibleQuestionIds),
  };
}

function evaluateScopeBoundary(boundary, cycle, reasons) {
  addReason(reasons, !hasText(boundary?.boundaryRef), 'scope_boundary_ref_absent');
  addReason(reasons, boundary?.sasiRightsVerified === true, 'scope_sasi_rights_unreviewed');
  addReason(reasons, boundary?.accreditationLanguageAllowed === true, 'scope_accreditation_language_unreviewed');
  addReason(reasons, boundary?.aiIrbPublicLanguageAllowed === true, 'scope_ai_irb_public_language_unreviewed');
  addReason(reasons, boundary?.econsentExecutionEnabled === true, 'scope_econsent_execution_unreviewed');
  addReason(reasons, boundary?.ctmsPrimaryFunctionEnabled === true, 'scope_ctms_execution_unreviewed');
  addReason(reasons, boundary?.croWhiteLabelingEnabled === true, 'scope_cro_white_labeling_unreviewed');
  addReason(reasons, boundary?.portablePassportTransferEnabled === true, 'scope_portable_passport_transfer_unreviewed');
  addReason(reasons, boundary?.participantFacingFeaturesEnabled === true, 'scope_participant_facing_unreviewed');
  addReason(
    reasons,
    boundary?.productAccountabilityNativeDefaultApproved === true,
    'scope_product_accountability_native_default_unreviewed',
  );
  addReason(reasons, boundary?.inspectionModeControlledAccessOnly !== true, 'scope_inspection_mode_control_absent');
  addReason(reasons, boundary?.exochainProductionClaimsInactive !== true, 'scope_production_trust_claim_active');
  addReason(reasons, !isDigest(boundary?.manualClaimReviewReceiptHash), 'scope_manual_claim_review_hash_invalid');
  addReason(reasons, !isDigest(boundary?.publicClaimReviewReceiptHash), 'scope_public_claim_review_hash_invalid');
  addReason(reasons, !isDigest(boundary?.openQuestionRegisterHash), 'scope_open_question_register_hash_invalid');
  addReason(reasons, boundary?.metadataOnly !== true, 'scope_boundary_metadata_boundary_missing');
  addReason(reasons, boundary?.protectedContentExcluded !== true, 'scope_boundary_protected_boundary_missing');
  addReason(reasons, hlcTuple(boundary?.evaluatedAtHlc) === null, 'scope_boundary_evaluated_hlc_invalid');
  addReason(reasons, hlcBefore(boundary?.evaluatedAtHlc, cycle?.compiledAtHlc), 'scope_boundary_before_compile');

  return {
    accreditationLanguageAllowed: boundary?.accreditationLanguageAllowed === true,
    aiIrbPublicLanguageAllowed: boundary?.aiIrbPublicLanguageAllowed === true,
    croWhiteLabelingEnabled: boundary?.croWhiteLabelingEnabled === true,
    ctmsPrimaryFunctionEnabled: boundary?.ctmsPrimaryFunctionEnabled === true,
    econsentExecutionEnabled: boundary?.econsentExecutionEnabled === true,
    exochainProductionClaimsInactive: boundary?.exochainProductionClaimsInactive === true,
    inspectionModeControlledAccessOnly: boundary?.inspectionModeControlledAccessOnly === true,
    participantFacingFeaturesEnabled: boundary?.participantFacingFeaturesEnabled === true,
    portablePassportTransferEnabled: boundary?.portablePassportTransferEnabled === true,
    productAccountabilityNativeDefaultApproved: boundary?.productAccountabilityNativeDefaultApproved === true,
    sasiRightsVerified: boundary?.sasiRightsVerified === true,
  };
}

function evaluateSourceControl(sourceControl, reasons) {
  addReason(reasons, !isDigest(sourceControl?.masterPrdHash), 'scope_master_prd_hash_invalid');
  addReason(reasons, !isDigest(sourceControl?.sandyPrdHash), 'scope_sandy_prd_hash_invalid');
  addReason(reasons, sourceControl?.noRawPrdText !== true, 'scope_raw_prd_text_boundary_missing');
  addReason(reasons, sourceControl?.noExochainSourceModified !== true, 'exochain_source_modified');
  addReason(reasons, !isDigest(sourceControl?.sourceGuardEvidenceHash), 'scope_source_guard_hash_invalid');
  addReason(reasons, sourceControl?.metadataOnly !== true, 'scope_source_control_metadata_boundary_missing');
  addReason(reasons, sourceControl?.protectedContentExcluded !== true, 'scope_source_control_protected_boundary_missing');
}

function evaluateValidationEvidence(validation, cycle, reasons) {
  const commandRefs = sortedTextList(validation?.commandRefs);
  addReason(reasons, commandRefs.length === 0, 'scope_validation_command_refs_absent');
  addReason(
    reasons,
    !commandRefs.includes('node --test tests/scope-legal-review-register.test.mjs'),
    'scope_validation_focused_test_absent',
  );
  addReason(reasons, !commandRefs.includes('npm run quality'), 'scope_validation_quality_gate_absent');
  addReason(reasons, validation?.commandsPassed !== true, 'scope_validation_failed');
  addReason(reasons, validation?.sourceGuardPassed !== true, 'source_guard_not_passed');
  addReason(reasons, validation?.docsUpdated !== true, 'scope_docs_not_updated');
  addReason(reasons, validation?.noExochainSourceModified !== true, 'exochain_source_modified');
  addReason(reasons, !isDigest(validation?.evidenceHash), 'scope_validation_hash_invalid');
  addReason(reasons, validation?.metadataOnly !== true, 'scope_validation_metadata_boundary_missing');
  addReason(reasons, hlcTuple(validation?.recordedAtHlc) === null, 'scope_validation_hlc_invalid');
  addReason(reasons, hlcBefore(validation?.recordedAtHlc, cycle?.validationRecordedAtHlc), 'scope_validation_before_cycle');
}

function evaluateHumanReview(review, cycle, reasons) {
  addReason(reasons, !hasText(review?.reviewerDid), 'scope_legal_reviewer_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'scope_legal_human_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'scope_legal_human_decision_hash_invalid');
  addReason(reasons, review?.finalAuthority !== 'human' || review?.aiFinalAuthority === true, 'human_review_final_authority_invalid');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'production_trust_claim_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'scope_legal_human_review_metadata_boundary_missing');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'scope_legal_human_review_hlc_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, cycle?.humanReviewedAtHlc), 'scope_legal_human_review_before_cycle');
}

function buildScopeLegalReviewRegister(input, questionSummary, scopeBoundary) {
  const summary = {
    baselineBlockedCount: questionSummary.baselineBlockedQuestionIds.length,
    bobEscalationCount: questionSummary.bobEscalationIds.length,
    commercialDecisionCount: questionSummary.commercialDecisionQuestionIds.length,
    councilDefaultCount: questionSummary.councilDefaultQuestionIds.length,
    legalReviewCount: questionSummary.legalReviewQuestionIds.length,
    totalQuestionCount: questionSummary.questionIds.length,
    visibleQuestionCount: questionSummary.visibleQuestionIds.length,
  };

  const registerMaterial = {
    schema: REGISTER_SCHEMA,
    registerRef: input?.registerCycle?.registerRef ?? null,
    tenantId: input?.tenantId ?? null,
    baselineBlockedQuestionIds: questionSummary.baselineBlockedQuestionIds,
    bobEscalationIds: questionSummary.bobEscalationIds,
    commercialDecisionQuestionIds: questionSummary.commercialDecisionQuestionIds,
    councilDefaultQuestionIds: questionSummary.councilDefaultQuestionIds,
    legalReviewQuestionIds: questionSummary.legalReviewQuestionIds,
    questionFamiliesCovered: questionSummary.questionFamiliesCovered,
    questionIds: questionSummary.questionIds,
    records: questionSummary.records,
    scopeBoundary,
    summary,
    visibleQuestionIds: questionSummary.visibleQuestionIds,
    productionTrustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    protectedContentExcluded: true,
  };

  return {
    ...registerMaterial,
    scopeLegalReviewRegisterHash: sha256Hex(registerMaterial),
  };
}

function buildReceipt(input, scopeLegalReviewRegister) {
  return createEvidenceReceipt({
    actorDid: input?.actor?.did ?? 'did:exo:scope-legal-review-unknown',
    artifactHash: scopeLegalReviewRegister.scopeLegalReviewRegisterHash,
    artifactType: 'scope_legal_review_register',
    artifactVersion: 'v1',
    classification: 'metadata_only_scope_legal_review_register',
    custodyDigest: input?.custodyDigest ?? scopeLegalReviewRegister.scopeLegalReviewRegisterHash,
    hlcTimestamp: input?.registerCycle?.validationRecordedAtHlc ?? { physicalMs: 0, logical: 0 },
    schema: DECISION_SCHEMA,
    sensitivityTags: ['scope_legal_review', 'metadata_only', 'inactive_trust_state'],
    sourceSystem: 'cybermedica',
    tenantId: input?.tenantId ?? 'tenant-unknown',
  });
}

export function evaluateScopeLegalReviewRegister(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policySummary = evaluateScopeLegalPolicy(input?.scopeLegalPolicy, reasons);
  evaluateRegisterCycle(input?.registerCycle, input?.scopeLegalPolicy, reasons);
  evaluateSourceControl(input?.sourceControl, reasons);
  evaluateValidationEvidence(input?.validationEvidence, input?.registerCycle, reasons);
  evaluateHumanReview(input?.humanReview, input?.registerCycle, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'scope_legal_custody_digest_invalid');

  const questionSummary = evaluateQuestionRecords(
    input?.questionRecords,
    policySummary,
    input?.registerCycle,
    input?.humanReview,
    reasons,
  );
  const scopeBoundary = evaluateScopeBoundary(input?.scopeBoundary, input?.registerCycle, reasons);
  const finalReasons = uniqueReasons(reasons);
  const scopeLegalReviewRegister = buildScopeLegalReviewRegister(input, questionSummary, scopeBoundary);
  const receipt = buildReceipt(input, scopeLegalReviewRegister);

  return {
    schema: DECISION_SCHEMA,
    decision: finalReasons.length === 0 ? 'permitted' : 'denied',
    failClosed: finalReasons.length > 0,
    reasons: finalReasons,
    scopeLegalReviewRegister,
    receipt,
  };
}
