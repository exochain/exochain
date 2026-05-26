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
const MANUAL_CLAIM_REVIEW_SCHEMA = 'cybermedica.manual_claim_review.v1';
const REQUIRED_PERMISSION = 'manual_claim_review';
const ACTIVE_POLICY_STATUSES = new Set(['active']);
const HUMAN_DECISIONS = new Set(['manual_claims_approved_for_publication', 'hold_for_claim_review']);
const REVIEW_DECISIONS = new Set(['approved', 'requires_revision', 'rejected']);
const APPROVED_DISPOSITIONS = new Set(['approved_for_publication']);

const REQUIRED_CLAIM_FAMILIES = Object.freeze(['accreditation', 'clinical', 'compliance', 'regulatory']);
const REQUIRED_REVIEWER_ROLES = Object.freeze(['legal', 'quality', 'regulatory']);

const RAW_MANUAL_CLAIM_FIELDS = new Set([
  'body',
  'claimbody',
  'claimcopy',
  'claimtext',
  'content',
  'freetext',
  'freetextnote',
  'manualbody',
  'manualclaimcontent',
  'manualcontent',
  'manualtext',
  'rawaccreditationclaim',
  'rawclaimcontent',
  'rawclaimtext',
  'rawclinicalclaim',
  'rawcomplianceclaim',
  'rawcontent',
  'rawmanualclaimcontent',
  'rawmanualcontent',
  'rawregulatoryclaimtext',
  'reviewnotes',
  'sourcebody',
  'sourcedocumentbody',
]);

const SECRET_MANUAL_CLAIM_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
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

function assertNoRawManualClaimContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawManualClaimContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_MANUAL_CLAIM_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw manual claim content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_MANUAL_CLAIM_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`manual claim review secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawManualClaimContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawManualClaimContent(input ?? {});
  canonicalize(input ?? {});
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

function missingValues(required, actual) {
  return required.filter((value) => !actual.includes(value));
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
  addReason(reasons, input?.actor?.kind !== 'human', 'manual_claim_review_human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'manual_claim_review_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(policy, earliestClaimHlc, reasons) {
  const claimFamilies = sortedTextList(policy?.requiredClaimFamilies);
  const reviewerRoles = sortedTextList(policy?.requiredReviewerRoles);

  addReason(reasons, !hasText(policy?.policyRef), 'claim_review_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'claim_review_policy_hash_invalid');
  addReason(reasons, !ACTIVE_POLICY_STATUSES.has(policy?.status), 'claim_review_policy_inactive');
  addReason(reasons, policy?.highRiskReviewRequired !== true, 'high_risk_review_policy_absent');
  addReason(reasons, policy?.qualityReviewRequired !== true, 'quality_review_policy_absent');
  addReason(reasons, policy?.legalReviewRequired !== true, 'legal_review_policy_absent');
  addReason(reasons, policy?.regulatoryReviewRequired !== true, 'regulatory_review_policy_absent');
  addReason(reasons, policy?.aiAssistanceAdvisoryOnly !== true, 'ai_assistance_policy_not_advisory_only');
  addReason(reasons, policy?.metadataOnly !== true, 'claim_review_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'claim_review_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'claim_review_policy_time_invalid');
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, earliestClaimHlc), 'policy_review_after_claim_classification');

  evaluateRequiredSet(
    claimFamilies,
    REQUIRED_CLAIM_FAMILIES,
    'policy_claim_family_missing',
    'policy_claim_family_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    reviewerRoles,
    REQUIRED_REVIEWER_ROLES,
    'policy_reviewer_role_missing',
    'policy_reviewer_role_unsupported',
    reasons,
  );

  return { claimFamilies, reviewerRoles };
}

function evaluateClaimRegister(register, reasons) {
  addReason(reasons, !hasText(register?.registerRef), 'claim_register_ref_absent');
  addReason(reasons, !isDigest(register?.manualSetHash), 'claim_register_manual_set_hash_invalid');
  addReason(reasons, !isDigest(register?.manualIndexHash), 'claim_register_manual_index_hash_invalid');
  addReason(
    reasons,
    !isDigest(register?.documentationPublicationReceiptHash),
    'claim_register_publication_receipt_hash_invalid',
  );
  addReason(reasons, !isDigest(register?.documentationRunbookReceiptHash), 'claim_register_runbook_receipt_hash_invalid');
  addReason(reasons, register?.noRawClaimText !== true, 'claim_register_raw_claim_boundary_absent');
  addReason(reasons, hlcTuple(register?.classifiedAtHlc) === null, 'claim_register_time_invalid');
  addReason(reasons, register?.metadataOnly !== true, 'claim_register_metadata_boundary_invalid');
  addReason(reasons, register?.protectedContentExcluded !== true, 'claim_register_protected_boundary_invalid');

  const claims = Array.isArray(register?.claims) ? register.claims : [];
  const families = uniqueSorted(claims.map((claim) => claim?.family));
  evaluateRequiredSet(families, REQUIRED_CLAIM_FAMILIES, 'claim_family_missing', 'claim_family_unsupported', reasons);

  for (const claim of claims) {
    const claimRef = claim?.claimRef ?? 'unknown';
    const prefix = `claim_invalid:${claimRef}`;
    addReason(reasons, !hasText(claim?.claimRef), `${prefix}:claim_ref_absent`);
    addReason(reasons, !REQUIRED_CLAIM_FAMILIES.includes(claim?.family), `${prefix}:family_unsupported`);
    addReason(reasons, !hasText(claim?.sectionRef), `${prefix}:section_ref_absent`);
    addReason(reasons, !isDigest(claim?.claimHash), `${prefix}:claim_hash_invalid`);
    addReason(reasons, !isDigest(claim?.evidenceHash), `${prefix}:evidence_hash_invalid`);
    addReason(reasons, claim?.riskLevel !== 'high', `${prefix}:risk_level_not_high`);
    addReason(
      reasons,
      !APPROVED_DISPOSITIONS.has(claim?.publicationDisposition),
      `claim_not_approved_for_publication:${claimRef}`,
    );
    addReason(reasons, claim?.requiresClaimReview !== true, `${prefix}:claim_review_requirement_absent`);
    addReason(reasons, hlcTuple(claim?.classifiedAtHlc) === null, `${prefix}:classification_time_invalid`);
    addReason(reasons, claim?.metadataOnly !== true, `${prefix}:metadata_boundary_invalid`);
    addReason(reasons, claim?.protectedContentExcluded !== true, `${prefix}:protected_boundary_invalid`);
  }

  return {
    claims,
    claimFamilies: families,
    earliestClaimHlc: claims
      .map((claim) => hlcTuple(claim?.classifiedAtHlc))
      .filter((value) => value !== null)
      .sort(compareHlc)
      .map(([physicalMs, logical]) => ({ physicalMs, logical }))[0],
  };
}

function reviewsByClaimAndRole(reviews) {
  const index = new Map();
  for (const review of Array.isArray(reviews) ? reviews : []) {
    const claimRef = review?.claimRef;
    const role = review?.reviewerRole;
    if (!hasText(claimRef) || !hasText(role)) {
      continue;
    }
    index.set(`${claimRef}:${role}`, review);
  }
  return index;
}

function evaluateReviews(claims, reviews, reasons) {
  const rows = Array.isArray(reviews) ? reviews : [];
  const index = reviewsByClaimAndRole(rows);
  const claimRefs = uniqueSorted(claims.map((claim) => claim?.claimRef));
  const reviewRoles = uniqueSorted(rows.map((review) => review?.reviewerRole));

  for (const role of reviewRoles) {
    addReason(reasons, !REQUIRED_REVIEWER_ROLES.includes(role), `claim_review_role_unsupported:${role}`);
  }

  for (const claim of claims) {
    const claimRef = claim?.claimRef ?? 'unknown';
    for (const role of REQUIRED_REVIEWER_ROLES) {
      const review = index.get(`${claimRef}:${role}`);
      addReason(reasons, review === undefined, `claim_required_review_missing:${claimRef}:${role}`);
      if (review === undefined) {
        continue;
      }
      const prefix = `claim_review_invalid:${claimRef}:${role}`;
      addReason(reasons, !hasText(review?.reviewRef), `${prefix}:review_ref_absent`);
      addReason(reasons, !hasText(review?.reviewerDid), `${prefix}:reviewer_absent`);
      addReason(reasons, !REVIEW_DECISIONS.has(review?.decision), `${prefix}:decision_invalid`);
      addReason(
        reasons,
        review?.decision !== 'approved',
        `claim_review_not_approved:${claimRef}:${role}`,
      );
      addReason(reasons, !isDigest(review?.reviewHash), `${prefix}:review_hash_invalid`);
      addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, `${prefix}:review_time_invalid`);
      addReason(
        reasons,
        hlcBefore(review?.reviewedAtHlc, claim?.classifiedAtHlc),
        `claim_review_before_classification:${claimRef}:${role}`,
      );
      addReason(reasons, review?.metadataOnly !== true, `${prefix}:metadata_boundary_invalid`);
      addReason(reasons, review?.protectedContentExcluded !== true, `${prefix}:protected_boundary_invalid`);
    }
  }

  for (const review of rows) {
    addReason(
      reasons,
      hasText(review?.claimRef) && !claimRefs.includes(review.claimRef),
      `claim_review_unknown_claim:${review.claimRef}`,
    );
  }

  return reviewRoles;
}

function evaluatePublicationGate(gate, claimRegister, reasons) {
  addReason(reasons, !hasText(gate?.gateRef), 'publication_gate_ref_absent');
  addReason(
    reasons,
    !isDigest(gate?.documentationPublicationReceiptHash),
    'publication_gate_documentation_receipt_hash_invalid',
  );
  addReason(
    reasons,
    isDigest(gate?.documentationPublicationReceiptHash) &&
      isDigest(claimRegister?.documentationPublicationReceiptHash) &&
      gate.documentationPublicationReceiptHash !== claimRegister.documentationPublicationReceiptHash,
    'publication_gate_documentation_receipt_mismatch',
  );
  addReason(reasons, !isDigest(gate?.manualExportBoundaryHash), 'publication_gate_manual_export_boundary_hash_invalid');
  addReason(reasons, !isDigest(gate?.approvedClaimRegisterHash), 'publication_gate_claim_register_hash_invalid');
  addReason(reasons, !hasText(gate?.publicationPackageRef), 'publication_gate_package_ref_absent');
  addReason(reasons, gate?.highRiskSectionsHeld === true, 'high_risk_sections_held');
  addReason(reasons, gate?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(gate?.gatedAtHlc) === null, 'publication_gate_time_invalid');
  addReason(reasons, gate?.metadataOnly !== true, 'publication_gate_metadata_boundary_invalid');
  addReason(reasons, gate?.protectedContentExcluded !== true, 'publication_gate_protected_boundary_invalid');
}

function evaluateAiAssistant(aiAssistant, humanReview, reasons) {
  if (aiAssistant?.used === false) {
    return false;
  }

  addReason(reasons, !hasText(aiAssistant?.assistantRef), 'ai_assistant_ref_absent');
  addReason(reasons, !isDigest(aiAssistant?.recommendationHash), 'ai_recommendation_hash_invalid');
  addReason(
    reasons,
    !Array.isArray(aiAssistant?.limitationHashes) || !aiAssistant.limitationHashes.every(isDigest),
    'ai_limitation_hashes_invalid',
  );
  addReason(reasons, aiAssistant?.advisoryOnly !== true, 'ai_assistant_not_advisory_only');
  addReason(reasons, aiAssistant?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, aiAssistant?.humanReviewed !== true, 'ai_human_review_missing');
  addReason(reasons, hlcTuple(aiAssistant?.reviewedAtHlc) === null, 'ai_review_time_invalid');
  addReason(reasons, !hlcBefore(aiAssistant?.reviewedAtHlc, humanReview?.reviewedAtHlc), 'ai_review_not_before_human_review');
  addReason(reasons, hlcBefore(humanReview?.reviewedAtHlc, aiAssistant?.reviewedAtHlc), 'human_review_before_ai_review');
  addReason(reasons, aiAssistant?.metadataOnly !== true, 'ai_assistant_metadata_boundary_invalid');
  addReason(reasons, aiAssistant?.protectedContentExcluded !== true, 'ai_assistant_protected_boundary_invalid');

  return true;
}

function evaluateHumanReview(review, gate, reasons) {
  addReason(reasons, !hasText(review?.reviewerDid), 'human_review_reviewer_absent');
  addReason(
    reasons,
    !Array.isArray(review?.reviewerRoleRefs) || review.reviewerRoleRefs.filter(hasText).length === 0,
    'human_review_roles_absent',
  );
  for (const role of REQUIRED_REVIEWER_ROLES) {
    addReason(
      reasons,
      !Array.isArray(review?.reviewerRoleRefs) || !review.reviewerRoleRefs.includes(role),
      `human_review_role_missing:${role}`,
    );
  }
  addReason(reasons, !HUMAN_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_final_authority_missing');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, !hlcBefore(review?.reviewedAtHlc, gate?.gatedAtHlc), 'human_review_not_before_publication_gate');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, review?.protectedContentExcluded !== true, 'human_review_protected_boundary_invalid');
}

function evaluateValidationEvidence(validationEvidence, humanReview, reasons) {
  addReason(
    reasons,
    !Array.isArray(validationEvidence?.commandRefs) || validationEvidence.commandRefs.filter(hasText).length === 0,
    'validation_command_refs_absent',
  );
  addReason(reasons, validationEvidence?.commandsPassed !== true, 'validation_commands_not_passed');
  addReason(reasons, validationEvidence?.sourceGuardPassed !== true, 'validation_source_guard_not_passed');
  addReason(reasons, validationEvidence?.noExochainSourceModified !== true, 'exochain_source_modification_forbidden');
  addReason(reasons, hlcTuple(validationEvidence?.recordedAtHlc) === null, 'validation_record_time_invalid');
  addReason(
    reasons,
    !hlcAfter(validationEvidence?.recordedAtHlc, humanReview?.reviewedAtHlc),
    'validation_record_not_after_human_review',
  );
  addReason(reasons, validationEvidence?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
}

function createClaimReviewDigest(input, claimFamilies, reviewRoles) {
  return sha256Hex({
    schema: MANUAL_CLAIM_REVIEW_SCHEMA,
    tenantId: input?.tenantId ?? null,
    registerRef: input?.claimRegister?.registerRef ?? null,
    manualSetHash: input?.claimRegister?.manualSetHash ?? null,
    manualIndexHash: input?.claimRegister?.manualIndexHash ?? null,
    claimFamilies,
    reviewRoles,
    gateRef: input?.publicationGate?.gateRef ?? null,
    approvedClaimRegisterHash: input?.publicationGate?.approvedClaimRegisterHash ?? null,
  });
}

function createClaimSummary(input, reasons, claimFamilies, reviewRoles, aiAssistanceUsed, digest) {
  const claims = Array.isArray(input?.claimRegister?.claims) ? input.claimRegister.claims : [];
  const approvedClaimRefs = uniqueSorted(
    claims
      .filter((claim) => APPROVED_DISPOSITIONS.has(claim?.publicationDisposition))
      .map((claim) => claim?.claimRef),
  );
  const heldClaimRefs = uniqueSorted(
    claims
      .filter((claim) => !APPROVED_DISPOSITIONS.has(claim?.publicationDisposition))
      .map((claim) => claim?.claimRef),
  );

  return {
    schema: MANUAL_CLAIM_REVIEW_SCHEMA,
    ready: reasons.length === 0,
    trustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    manualClaimReviewDigest: digest,
    doc009Satisfied: reasons.length === 0,
    publicationEligible: reasons.length === 0,
    claimFamilies,
    missingClaimFamilies: missingValues(REQUIRED_CLAIM_FAMILIES, claimFamilies),
    requiredReviewerRoles: REQUIRED_REVIEWER_ROLES,
    reviewRoles,
    missingReviewerRoles: missingValues(REQUIRED_REVIEWER_ROLES, reviewRoles),
    claimCount: claims.length,
    approvedClaimRefs,
    heldClaimRefs,
    aiAssistanceUsed,
    publicationPackageRef: input?.publicationGate?.publicationPackageRef ?? null,
    sourceEvidence: [
      'cybermedica_2_0_sandy_seven_layer_master_prd.md#DOC-009',
      'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
    ],
  };
}

export function evaluateManualClaimReview(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const { claims, claimFamilies, earliestClaimHlc } = evaluateClaimRegister(input?.claimRegister, reasons);
  evaluatePolicy(input?.claimReviewPolicy, earliestClaimHlc, reasons);
  const reviewRoles = evaluateReviews(claims, input?.reviews, reasons);
  evaluatePublicationGate(input?.publicationGate, input?.claimRegister, reasons);
  evaluateHumanReview(input?.humanReview, input?.publicationGate, reasons);
  const aiAssistanceUsed = evaluateAiAssistant(input?.aiAssistant, input?.humanReview, reasons);
  evaluateValidationEvidence(input?.validationEvidence, input?.humanReview, reasons);

  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  const digest = createClaimReviewDigest(input, claimFamilies, reviewRoles);
  const manualClaimReview = createClaimSummary(input, unique, claimFamilies, reviewRoles, aiAssistanceUsed, digest);

  if (unique.length > 0) {
    return {
      decision: 'denied',
      failClosed: true,
      reasons: unique,
      manualClaimReview,
      receipt: null,
    };
  }

  return {
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    manualClaimReview,
    receipt: createEvidenceReceipt({
      tenantId: input.tenantId,
      actorDid: input.actor.did,
      artifactType: 'manual_claim_review',
      artifactVersion: MANUAL_CLAIM_REVIEW_SCHEMA,
      artifactHash: digest,
      custodyDigest: input.custodyDigest,
      classification: 'metadata_only_manual_claim_review',
      sourceSystem: 'cybermedica',
      sensitivityTags: ['doc009_claim_review', 'manual_metadata'],
      hlcTimestamp: input.publicationGate.gatedAtHlc,
    }),
  };
}
