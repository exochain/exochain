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
const REGISTER_SCHEMA = 'cybermedica.sandy_review_register.v1';
const REQUIRED_PERMISSION = 'sandy_review_register';
const ACCEPTED_HUMAN_DECISIONS = new Set([
  'hold_for_sandy_review_gap',
  'sandy_review_register_accepted_inactive_trust',
]);
const ACTIVE_STATUSES = new Set(['active']);
const QUESTION_DISPOSITIONS = new Set([
  'closed_by_governance',
  'council_default_for_baseline',
]);

const REQUIRED_SANDY_QUESTION_FAMILIES = Object.freeze([
  'ai_irb_language',
  'control_source_legal_permission',
  'exochain_deployment_model',
  'first_commercial_deployment',
  'minimum_viable_control_library',
  'participant_facing_scope',
  'product_positioning',
  'public_claim',
  'sales_content_review',
  'sponsor_visibility_model',
]);

const REQUIRED_SOURCE_DOC_REFS = Object.freeze([
  'cyber_medica_qms_prd_master.md',
  'cybermedica_2_0_sandy_seven_layer_master_prd.md',
  'docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md',
]);

const COUNCIL_ALLOWED_BOB_ESCALATION_IDS = Object.freeze([
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

const RAW_SANDY_REVIEW_FIELDS = new Set([
  'answerbody',
  'body',
  'claimcopy',
  'claimtext',
  'commercialcopy',
  'content',
  'decisiontext',
  'freetext',
  'freetextnote',
  'prdtext',
  'questionbody',
  'rawanswer',
  'rawclaimcopy',
  'rawcommercialcopy',
  'rawprdcontent',
  'rawprdtext',
  'rawpublicclaim',
  'rawreview',
  'rawsandyanswer',
  'rawsandyreview',
  'rawsourcecontent',
  'reviewnotes',
  'salescopy',
  'sourcedocumentbody',
]);

const SECRET_SANDY_REVIEW_FIELDS = new Set([
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

function assertNoRawSandyReviewContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawSandyReviewContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_SANDY_REVIEW_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw Sandy review content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_SANDY_REVIEW_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`Sandy review secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawSandyReviewContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawSandyReviewContent(input ?? {});
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
  addReason(reasons, input?.actor?.kind !== 'human', 'human_sandy_review_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'sandy_review_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateSandyPolicy(policy, reasons) {
  const requiredQuestionFamilies = sortedTextList(policy?.requiredQuestionFamilies);
  const sourceDocRefs = sortedTextList(policy?.sourceDocRefs);
  const allowedBobEscalationIds = sortedTextList(policy?.allowedBobEscalationIds);

  addReason(reasons, !hasText(policy?.policyRef), 'sandy_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'sandy_policy_hash_invalid');
  addReason(reasons, !ACTIVE_STATUSES.has(policy?.status), 'sandy_policy_inactive');
  addReason(reasons, policy?.councilDefaultsRequired !== true, 'sandy_council_default_rule_absent');
  addReason(reasons, policy?.publicClaimReviewRequired !== true, 'sandy_public_claim_review_rule_absent');
  addReason(reasons, policy?.legalRegulatoryReviewRequired !== true, 'sandy_legal_regulatory_review_rule_absent');
  addReason(reasons, policy?.aiIrbPublicLanguageBlocked !== true, 'sandy_ai_irb_public_language_rule_absent');
  addReason(
    reasons,
    policy?.participantFacingDisabledUntilReview !== true,
    'sandy_participant_facing_scope_rule_absent',
  );
  addReason(reasons, policy?.productionTrustClaimsInactive !== true, 'sandy_production_trust_inactive_rule_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'sandy_policy_metadata_boundary_absent');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'sandy_policy_protected_boundary_absent');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'sandy_policy_hlc_invalid');

  evaluateRequiredSet(
    requiredQuestionFamilies,
    REQUIRED_SANDY_QUESTION_FAMILIES,
    'sandy_policy_question_family_missing',
    'sandy_policy_question_family_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    sourceDocRefs,
    REQUIRED_SOURCE_DOC_REFS,
    'sandy_policy_source_doc_missing',
    'sandy_policy_source_doc_unsupported',
    reasons,
  );

  for (const escalationId of allowedBobEscalationIds) {
    addReason(
      reasons,
      !COUNCIL_ALLOWED_BOB_ESCALATION_IDS.includes(escalationId),
      `sandy_policy_bob_escalation_not_allowed:${escalationId}`,
    );
  }

  return {
    allowedBobEscalationIds,
    requiredQuestionFamilies,
    sourceDocRefs,
  };
}

function evaluateRegisterCycle(cycle, reasons) {
  addReason(reasons, !hasText(cycle?.registerRef), 'sandy_register_ref_absent');
  addReason(reasons, hlcTuple(cycle?.compiledAtHlc) === null, 'sandy_register_compiled_hlc_invalid');
  addReason(reasons, hlcTuple(cycle?.humanReviewedAtHlc) === null, 'sandy_register_human_review_hlc_invalid');
  addReason(reasons, hlcTuple(cycle?.validationRecordedAtHlc) === null, 'sandy_register_validation_hlc_invalid');
  addReason(reasons, cycle?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, cycle?.metadataOnly !== true, 'sandy_register_metadata_boundary_absent');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'sandy_register_protected_boundary_absent');
  addReason(reasons, !hlcBefore(cycle?.compiledAtHlc, cycle?.humanReviewedAtHlc), 'sandy_human_review_order_invalid');
  addReason(
    reasons,
    !hlcBefore(cycle?.humanReviewedAtHlc, cycle?.validationRecordedAtHlc),
    'sandy_validation_order_invalid',
  );
}

function evaluateQuestionRecords(records, policyContext, cycle, reasons) {
  const questionRecords = Array.isArray(records) ? records : [];
  addReason(reasons, questionRecords.length === 0, 'sandy_question_records_absent');

  const questionFamilies = uniqueSorted(questionRecords.map((record) => record?.questionFamily));
  evaluateRequiredSet(
    questionFamilies,
    REQUIRED_SANDY_QUESTION_FAMILIES,
    'sandy_question_family_missing',
    'sandy_question_family_unsupported',
    reasons,
  );

  const summary = {
    baselineBlockedQuestionIds: [],
    bobEscalationCount: 0,
    commercialDecisionQuestionIds: [],
    conservativeDefaultCount: 0,
    legalReviewQuestionIds: [],
    publicClaimRiskQuestionIds: [],
  };

  for (const record of questionRecords) {
    const questionId = hasText(record?.questionId) ? record.questionId : 'unknown';
    addReason(reasons, !hasText(record?.questionId), 'sandy_question_id_absent');
    addReason(reasons, !REQUIRED_SANDY_QUESTION_FAMILIES.includes(record?.questionFamily), `sandy_question_family_invalid:${questionId}`);
    addReason(
      reasons,
      record?.sourceRef !== 'cybermedica_2_0_sandy_seven_layer_master_prd.md#appendix-b-sandy-review-questions',
      `sandy_question_source_invalid:${questionId}`,
    );
    addReason(
      reasons,
      !Number.isSafeInteger(record?.sourceLineRef) || record.sourceLineRef < 1,
      `sandy_question_line_ref_invalid:${questionId}`,
    );
    addReason(
      reasons,
      !QUESTION_DISPOSITIONS.has(record?.disposition),
      `sandy_question_disposition_invalid:${questionId}`,
    );
    addReason(reasons, !hasText(record?.conservativeDefaultRef), `sandy_question_default_ref_absent:${questionId}`);
    addReason(reasons, !isDigest(record?.conservativeDefaultHash), `sandy_question_default_hash_invalid:${questionId}`);
    addReason(reasons, !isDigest(record?.decisionNeededHash), `sandy_question_decision_hash_invalid:${questionId}`);
    addReason(reasons, !hasText(record?.ownerRoleRef), `sandy_question_owner_absent:${questionId}`);
    addReason(reasons, record?.metadataOnly !== true, `sandy_question_metadata_boundary_absent:${questionId}`);
    addReason(reasons, record?.protectedContentExcluded !== true, `sandy_question_protected_boundary_absent:${questionId}`);
    addReason(reasons, record?.productionTrustClaim === true, `sandy_question_production_trust_forbidden:${questionId}`);
    addReason(reasons, record?.visibleUntilClosed !== true, `sandy_question_visibility_absent:${questionId}`);
    addReason(reasons, record?.councilDefaultUsed !== true, `sandy_question_council_default_absent:${questionId}`);
    addReason(reasons, record?.blocksBaselineDevelopment === true, `sandy_question_blocks_baseline:${questionId}`);
    addReason(reasons, record?.publicClaimAllowed === true, `sandy_question_public_claim_forbidden:${questionId}`);
    addReason(reasons, hlcTuple(record?.reviewedAtHlc) === null, `sandy_question_review_hlc_invalid:${questionId}`);
    addReason(
      reasons,
      hlcAfter(record?.reviewedAtHlc, cycle?.humanReviewedAtHlc),
      `sandy_question_review_after_human_review:${questionId}`,
    );

    if (hasText(record?.bobEscalationId)) {
      summary.bobEscalationCount += 1;
      addReason(
        reasons,
        !policyContext.allowedBobEscalationIds.includes(record.bobEscalationId) ||
          !COUNCIL_ALLOWED_BOB_ESCALATION_IDS.includes(record.bobEscalationId),
        `bob_escalation_not_allowed:${record.bobEscalationId}`,
      );
      addReason(
        reasons,
        record?.productionActivationOnly !== true,
        `sandy_bob_escalation_not_activation_only:${questionId}`,
      );
    }

    if (record?.legalReviewRequired === true) {
      summary.legalReviewQuestionIds.push(questionId);
    }
    if (record?.commercialDecisionRequired === true) {
      summary.commercialDecisionQuestionIds.push(questionId);
    }
    if (record?.blocksBaselineDevelopment === true) {
      summary.baselineBlockedQuestionIds.push(questionId);
    }
    if (record?.publicClaimAllowed === true) {
      summary.publicClaimRiskQuestionIds.push(questionId);
    }
    if (isDigest(record?.conservativeDefaultHash) && record?.councilDefaultUsed === true) {
      summary.conservativeDefaultCount += 1;
    }
  }

  return {
    baselineBlockedQuestionIds: uniqueSorted(summary.baselineBlockedQuestionIds),
    bobEscalationCount: summary.bobEscalationCount,
    commercialDecisionQuestionIds: uniqueSorted(summary.commercialDecisionQuestionIds),
    conservativeDefaultCount: summary.conservativeDefaultCount,
    legalReviewQuestionIds: uniqueSorted(summary.legalReviewQuestionIds),
    publicClaimRiskQuestionIds: uniqueSorted(summary.publicClaimRiskQuestionIds),
    questionCount: questionRecords.length,
    questionFamilies,
  };
}

function evaluateClaimBoundary(boundary, reasons) {
  addReason(reasons, !hasText(boundary?.boundaryRef), 'claim_boundary_ref_absent');
  addReason(reasons, !isDigest(boundary?.manualClaimReviewReceiptHash), 'claim_boundary_manual_review_hash_invalid');
  addReason(reasons, !isDigest(boundary?.legalRegulatoryReviewHash), 'claim_boundary_legal_review_hash_invalid');
  addReason(
    reasons,
    !isDigest(boundary?.controlledSponsorCroRequestPolicyHash),
    'claim_boundary_sponsor_cro_policy_hash_invalid',
  );
  addReason(reasons, boundary?.noRawStandardTextEmbedded !== true, 'claim_boundary_raw_standard_boundary_absent');
  addReason(reasons, boundary?.aiIrbPublicLanguageAllowed !== false, 'ai_irb_public_language_not_blocked');
  addReason(
    reasons,
    boundary?.productionTrustClaimsInactive !== true,
    'claim_boundary_production_trust_not_inactive',
  );
  addReason(
    reasons,
    boundary?.participantFacingFeaturesEnabled !== false,
    'claim_boundary_participant_facing_not_disabled',
  );
  addReason(
    reasons,
    boundary?.sponsorVisibilityRequiresTenantConfig !== true,
    'claim_boundary_sponsor_visibility_policy_absent',
  );
  addReason(
    reasons,
    boundary?.exochainDeploymentChoiceActivationOnly !== true,
    'claim_boundary_exochain_deployment_not_activation_only',
  );
  addReason(reasons, boundary?.metadataOnly !== true, 'claim_boundary_metadata_boundary_absent');
  addReason(reasons, boundary?.protectedContentExcluded !== true, 'claim_boundary_protected_boundary_absent');
  addReason(reasons, hlcTuple(boundary?.evaluatedAtHlc) === null, 'claim_boundary_hlc_invalid');

  return {
    aiIrbPublicLanguageAllowed: boundary?.aiIrbPublicLanguageAllowed === true,
    exochainDeploymentChoiceActivationOnly: boundary?.exochainDeploymentChoiceActivationOnly === true,
    participantFacingFeaturesEnabled: boundary?.participantFacingFeaturesEnabled === true,
    sponsorVisibilityRequiresTenantConfig: boundary?.sponsorVisibilityRequiresTenantConfig === true,
  };
}

function evaluateSourceControl(sourceControl, reasons) {
  addReason(reasons, !isDigest(sourceControl?.sandyPrdHash), 'source_control_sandy_prd_hash_invalid');
  addReason(reasons, !isDigest(sourceControl?.masterPrdHash), 'source_control_master_prd_hash_invalid');
  addReason(reasons, sourceControl?.noRawPrdText !== true, 'source_control_raw_prd_boundary_absent');
  addReason(reasons, sourceControl?.noExochainSourceModified !== true, 'source_control_exochain_modified');
  addReason(reasons, !isDigest(sourceControl?.sourceGuardEvidenceHash), 'source_control_guard_hash_invalid');
  addReason(reasons, sourceControl?.metadataOnly !== true, 'source_control_metadata_boundary_absent');
  addReason(reasons, sourceControl?.protectedContentExcluded !== true, 'source_control_protected_boundary_absent');

  return {
    masterPrdHash: sourceControl?.masterPrdHash ?? null,
    noExochainSourceModified: sourceControl?.noExochainSourceModified === true,
    noRawPrdText: sourceControl?.noRawPrdText === true,
    sandyPrdHash: sourceControl?.sandyPrdHash ?? null,
    sourceGuardEvidenceHash: sourceControl?.sourceGuardEvidenceHash ?? null,
  };
}

function evaluateHumanReview(humanReview, cycle, reasons) {
  addReason(reasons, !hasText(humanReview?.reviewerDid), 'sandy_review_human_reviewer_absent');
  addReason(reasons, !ACCEPTED_HUMAN_DECISIONS.has(humanReview?.decision), 'sandy_review_human_decision_invalid');
  addReason(reasons, !isDigest(humanReview?.decisionHash), 'sandy_review_human_decision_hash_invalid');
  addReason(reasons, humanReview?.finalAuthority !== 'human', 'sandy_review_human_final_authority_required');
  addReason(reasons, humanReview?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, humanReview?.noProductionTrustClaim !== true, 'sandy_review_human_claim_boundary_absent');
  addReason(reasons, hlcTuple(humanReview?.reviewedAtHlc) === null, 'sandy_review_human_hlc_invalid');
  addReason(reasons, !hlcBefore(cycle?.compiledAtHlc, humanReview?.reviewedAtHlc), 'sandy_review_human_order_invalid');
  addReason(reasons, humanReview?.metadataOnly !== true, 'sandy_review_human_metadata_boundary_absent');
}

function evaluateValidationEvidence(validationEvidence, reasons) {
  const commandRefs = sortedTextList(validationEvidence?.commandRefs);
  addReason(reasons, commandRefs.length === 0, 'validation_command_refs_absent');
  addReason(reasons, validationEvidence?.commandsPassed !== true, 'validation_commands_not_passed');
  addReason(reasons, validationEvidence?.sourceGuardPassed !== true, 'validation_source_guard_failed');
  addReason(reasons, validationEvidence?.noExochainSourceModified !== true, 'validation_exochain_source_modified');
  addReason(reasons, hlcTuple(validationEvidence?.recordedAtHlc) === null, 'validation_recorded_hlc_invalid');
  addReason(reasons, validationEvidence?.metadataOnly !== true, 'validation_metadata_boundary_absent');

  return commandRefs;
}

function buildSandyReviewRegister(input, questionSummary, policyContext, claimBoundary, sourceControl, commandRefs) {
  const artifact = {
    schema: REGISTER_SCHEMA,
    registerRef: input.registerCycle.registerRef,
    productionTrustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    compiledAtHlc: input.registerCycle.compiledAtHlc,
    humanReviewedAtHlc: input.registerCycle.humanReviewedAtHlc,
    validationRecordedAtHlc: input.registerCycle.validationRecordedAtHlc,
    tenantId: input.tenantId,
    questionFamiliesCovered: questionSummary.questionFamilies,
    questionCount: questionSummary.questionCount,
    sourceDocRefs: policyContext.sourceDocRefs,
    baselineBlockedQuestionIds: questionSummary.baselineBlockedQuestionIds,
    claimBoundary,
    sourceControl,
    validationCommandRefs: commandRefs,
    summary: {
      baselineBlockedCount: questionSummary.baselineBlockedQuestionIds.length,
      bobEscalationCount: questionSummary.bobEscalationCount,
      commercialDecisionCount: questionSummary.commercialDecisionQuestionIds.length,
      conservativeDefaultCount: questionSummary.conservativeDefaultCount,
      legalReviewCount: questionSummary.legalReviewQuestionIds.length,
      publicClaimRiskCount: questionSummary.publicClaimRiskQuestionIds.length,
    },
  };

  const artifactHash = sha256Hex(artifact);
  const receipt = createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash,
    artifactType: 'sandy_review_register',
    artifactVersion: 'v1',
    classification: 'metadata_only_sandy_review_register',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.registerCycle.validationRecordedAtHlc,
    sensitivityTags: ['governance_metadata', 'product_scope_metadata', 'sandy_review_metadata'],
    sourceSystem: 'cybermedica',
    tenantId: input.tenantId,
  });

  return {
    ...artifact,
    artifactHash,
    receiptId: receipt.receiptId,
  };
}

export function evaluateSandyReviewRegister(input) {
  assertMetadataOnly(input ?? {});
  const reasons = [];

  evaluateTenantActorAuthority(input, reasons);
  const policyContext = evaluateSandyPolicy(input?.sandyReviewPolicy, reasons);
  evaluateRegisterCycle(input?.registerCycle, reasons);
  const questionSummary = evaluateQuestionRecords(input?.questionRecords, policyContext, input?.registerCycle, reasons);
  const claimBoundary = evaluateClaimBoundary(input?.claimBoundary, reasons);
  const sourceControl = evaluateSourceControl(input?.sourceControl, reasons);
  evaluateHumanReview(input?.humanReview, input?.registerCycle, reasons);
  const commandRefs = evaluateValidationEvidence(input?.validationEvidence, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const normalizedReasons = uniqueReasons(reasons);
  if (normalizedReasons.length > 0) {
    return {
      schema: 'cybermedica.sandy_review_register_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: normalizedReasons,
      sandyReviewRegister: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const sandyReviewRegister = buildSandyReviewRegister(
    input,
    questionSummary,
    policyContext,
    claimBoundary,
    sourceControl,
    commandRefs,
  );
  const receipt = createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: sandyReviewRegister.artifactHash,
    artifactType: 'sandy_review_register',
    artifactVersion: 'v1',
    classification: 'metadata_only_sandy_review_register',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.registerCycle.validationRecordedAtHlc,
    sensitivityTags: ['governance_metadata', 'product_scope_metadata', 'sandy_review_metadata'],
    sourceSystem: 'cybermedica',
    tenantId: input.tenantId,
  });

  return {
    schema: 'cybermedica.sandy_review_register_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    sandyReviewRegister,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
