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
const PUBLIC_CLAIM_REVIEW_SCHEMA = 'cybermedica.public_claim_review.v1';
const PRODUCTION_CLAIM_LIFT_RECEIPT_SCHEMA = 'cybermedica.production_claim_lift_receipt.v1';
const REQUIRED_PERMISSION = 'public_claim_review';

const REQUIRED_PUBLIC_CONTENT_TYPES = Object.freeze([
  'case_study',
  'demo_script',
  'one_page_product_thesis',
  'press_release',
  'sales_deck',
  'sponsor_diligence_pitch',
  'website_copy',
]);

const REQUIRED_CLAIM_FAMILIES = Object.freeze([
  'ai_irb_language',
  'audit_ready_evidence',
  'clinical_research_safety',
  'exochain_trust',
  'qms_readiness',
  'site_readiness',
]);

const REQUIRED_REVIEWER_ROLES = Object.freeze(['legal', 'product_governance', 'quality', 'regulatory']);

const BASELINE_SAFE_CLAIM_CATEGORIES = Object.freeze([
  'audit_ready_evidence',
  'qms_passport',
  'site_readiness_fabric',
  'standard_aligned_governance_layer',
]);

const CLAIM_GATE_IDS = new Set(Array.from({ length: 18 }, (_, index) => `PTAG-${String(index + 1).padStart(3, '0')}`));
const REQUIRED_ROLE_DASHBOARD_ROLES = Object.freeze([
  'auditor',
  'coordinator',
  'cro_portfolio_manager',
  'decision_forum',
  'principal_investigator',
  'quality_manager',
  'site_leader',
  'sponsor_viewer',
]);

const ACTIVE_POLICY_STATUSES = new Set(['active']);
const REVIEW_DECISIONS = new Set(['approved', 'rejected', 'requires_revision']);
const APPROVED_REVIEW_DECISIONS = new Set(['approved']);
const HUMAN_REVIEW_DECISIONS = new Set(['hold_for_public_claim_review', 'public_claims_approved_for_use']);

const RAW_PUBLIC_CLAIM_FIELDS = new Set([
  'adcopy',
  'body',
  'campaigncopy',
  'casestudybody',
  'claimbody',
  'claimcopy',
  'claimlanguage',
  'claimtext',
  'commercialcopy',
  'content',
  'deckbody',
  'demobody',
  'demoscriptbody',
  'freetext',
  'freetextnote',
  'marketingcopy',
  'pagebody',
  'pressreleasebody',
  'publiccopy',
  'rawadcopy',
  'rawbody',
  'rawclaim',
  'rawclaimcopy',
  'rawclaimtext',
  'rawcommercialcopy',
  'rawcontent',
  'rawmarketingcopy',
  'rawpublicclaim',
  'rawpubliccopy',
  'rawsalescopy',
  'rawsalesmaterial',
  'reviewnotes',
  'salescopy',
  'sourcedocumentbody',
  'websitecopy',
]);

const SECRET_PUBLIC_CLAIM_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
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

function assertNoRawPublicClaimContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawPublicClaimContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_PUBLIC_CLAIM_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw public claim content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_PUBLIC_CLAIM_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`public claim review secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawPublicClaimContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawPublicClaimContent(input ?? {});
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
  addReason(reasons, input?.actor?.kind !== 'human', 'public_claim_review_human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'public_claim_review_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function earliestClaimHlc(register) {
  const times = Array.isArray(register?.claimRecords)
    ? register.claimRecords.map((claim) => hlcTuple(claim?.classifiedAtHlc)).filter((item) => item !== null)
    : [];
  return times.sort(compareHlc)[0] ?? null;
}

function evaluatePolicy(policy, register, reasons) {
  const contentTypes = sortedTextList(policy?.requiredContentTypes);
  const claimFamilies = sortedTextList(policy?.requiredClaimFamilies);
  const reviewerRoles = sortedTextList(policy?.requiredReviewerRoles);
  const safeClaimCategories = sortedTextList(policy?.baselineSafeClaimCategories);
  const firstClaimHlc = earliestClaimHlc(register);
  const policyHlc = hlcTuple(policy?.evaluatedAtHlc);

  addReason(reasons, !hasText(policy?.policyRef), 'public_claim_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'public_claim_policy_hash_invalid');
  addReason(reasons, !ACTIVE_POLICY_STATUSES.has(policy?.status), 'public_claim_policy_inactive');
  addReason(reasons, policy?.aiIrbPublicLanguageBlocked !== true, 'ai_irb_public_language_policy_absent');
  addReason(reasons, policy?.irbIecSubstitutionBlocked !== true, 'irb_iec_substitution_policy_absent');
  addReason(reasons, policy?.productionTrustClaimsInactive !== true, 'production_claim_inactive_policy_absent');
  addReason(reasons, policy?.legalRegulatoryReviewRequired !== true, 'legal_regulatory_review_policy_absent');
  addReason(reasons, policy?.salesContentReviewRequired !== true, 'sales_content_review_policy_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'public_claim_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'public_claim_policy_protected_boundary_invalid');
  addReason(reasons, policyHlc === null, 'public_claim_policy_time_invalid');
  addReason(
    reasons,
    firstClaimHlc !== null && policyHlc !== null && compareHlc(policyHlc, firstClaimHlc) > 0,
    'policy_review_after_claim_classification',
  );

  evaluateRequiredSet(
    contentTypes,
    REQUIRED_PUBLIC_CONTENT_TYPES,
    'policy_content_type_missing',
    'policy_content_type_unsupported',
    reasons,
  );
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
  evaluateRequiredSet(
    safeClaimCategories,
    BASELINE_SAFE_CLAIM_CATEGORIES,
    'baseline_safe_claim_category_missing',
    'baseline_safe_claim_category_unsupported',
    reasons,
  );

  return { contentTypes, claimFamilies, reviewerRoles, safeClaimCategories };
}

function normalizeContentAssets(register, requiredContentTypes, reasons) {
  addReason(reasons, !hasText(register?.registerRef), 'content_register_ref_absent');
  addReason(reasons, !isDigest(register?.sourcePrdHash), 'content_register_source_prd_hash_invalid');
  addReason(reasons, !isDigest(register?.sandyReviewRegisterHash), 'sandy_review_register_hash_invalid');
  addReason(reasons, !isDigest(register?.manualClaimReviewReceiptHash), 'manual_claim_review_receipt_hash_invalid');
  addReason(
    reasons,
    register?.productionClaimLiftReceiptHash !== null &&
      register?.productionClaimLiftReceiptHash !== undefined &&
      !isDigest(register.productionClaimLiftReceiptHash),
    'production_claim_lift_receipt_hash_invalid',
  );
  addReason(reasons, register?.noRawCopyStored !== true, 'public_content_raw_copy_boundary_absent');
  addReason(reasons, register?.metadataOnly !== true, 'content_register_metadata_boundary_invalid');
  addReason(reasons, register?.protectedContentExcluded !== true, 'content_register_protected_boundary_invalid');
  addReason(reasons, hlcTuple(register?.compiledAtHlc) === null, 'content_register_compile_time_invalid');

  const assets = Array.isArray(register?.contentAssets) ? [...register.contentAssets] : [];
  addReason(reasons, assets.length === 0, 'public_content_assets_absent');
  const normalized = assets
    .map((asset) => {
      const ref = hasText(asset?.assetRef) ? asset.assetRef : `unknown_asset_${asset?.contentType ?? 'unknown'}`;
      addReason(reasons, !hasText(asset?.assetRef), `asset_ref_absent:${ref}`);
      addReason(reasons, !requiredContentTypes.includes(asset?.contentType), `content_type_unsupported:${asset?.contentType ?? 'unknown'}`);
      addReason(reasons, !isDigest(asset?.artifactHash), `asset_hash_invalid:${ref}`);
      addReason(reasons, !hasText(asset?.audience), `asset_audience_absent:${ref}`);
      addReason(reasons, asset?.publicNonSensitiveClassification !== true, `asset_public_classification_absent:${ref}`);
      addReason(reasons, asset?.legalRegulatoryReviewRequired !== true, `asset_legal_regulatory_review_absent:${ref}`);
      addReason(reasons, asset?.approvedForPublicUse !== true, `asset_not_approved_for_public_use:${ref}`);
      addReason(reasons, asset?.rawCopyExcluded !== true, `asset_raw_copy_boundary_absent:${ref}`);
      addReason(reasons, asset?.metadataOnly !== true, `asset_metadata_boundary_invalid:${ref}`);
      addReason(reasons, asset?.protectedContentExcluded !== true, `asset_protected_boundary_invalid:${ref}`);
      addReason(reasons, asset?.productionTrustClaim === true, `asset_production_trust_claim_forbidden:${ref}`);
      addReason(reasons, hlcTuple(asset?.reviewedAtHlc) === null, `asset_review_time_invalid:${ref}`);
      return {
        artifactHash: isDigest(asset?.artifactHash) ? asset.artifactHash : null,
        assetRef: ref,
        audience: hasText(asset?.audience) ? asset.audience : 'unknown',
        contentType: hasText(asset?.contentType) ? asset.contentType : 'unknown',
      };
    })
    .sort((left, right) => left.assetRef.localeCompare(right.assetRef));

  const contentTypes = uniqueSorted(normalized.map((asset) => asset.contentType));
  evaluateRequiredSet(contentTypes, requiredContentTypes, 'content_type_missing', 'content_type_unsupported', reasons);

  return { contentTypes, normalizedAssets: normalized };
}

function normalizeClaimRecords(register, requiredClaimFamilies, safeClaimCategories, reasons) {
  const claims = Array.isArray(register?.claimRecords) ? [...register.claimRecords] : [];
  addReason(reasons, claims.length === 0, 'public_claim_records_absent');

  const normalized = claims
    .map((claim) => {
      const ref = hasText(claim?.claimRef) ? claim.claimRef : `unknown_claim_${claim?.family ?? 'unknown'}`;
      addReason(reasons, !hasText(claim?.claimRef), `claim_ref_absent:${ref}`);
      addReason(reasons, !requiredClaimFamilies.includes(claim?.family), `claim_family_unsupported:${claim?.family ?? 'unknown'}`);
      addReason(reasons, !safeClaimCategories.includes(claim?.safestClaimCategory), `unsafe_public_claim_category:${ref}`);
      addReason(reasons, !isDigest(claim?.claimHash), `claim_hash_invalid:${ref}`);
      addReason(reasons, !isDigest(claim?.evidenceHash), `claim_evidence_hash_invalid:${ref}`);
      addReason(reasons, claim?.approvedForPublicUse !== true, `claim_not_approved_for_public_use:${ref}`);
      addReason(reasons, claim?.aiIrbEquivalentLanguageAbsent !== true, `ai_irb_public_language_forbidden:${ref}`);
      addReason(reasons, claim?.irbIecSubstitutionClaimAbsent !== true, `irb_iec_substitution_claim_forbidden:${ref}`);
      addReason(reasons, claim?.exochainProductionClaimAbsent !== true, `claim_production_trust_claim_forbidden:${ref}`);
      addReason(reasons, claim?.legalRegulatoryReviewRequired !== true, `claim_legal_regulatory_review_absent:${ref}`);
      addReason(reasons, claim?.metadataOnly !== true, `claim_metadata_boundary_invalid:${ref}`);
      addReason(reasons, claim?.protectedContentExcluded !== true, `claim_protected_boundary_invalid:${ref}`);
      addReason(reasons, claim?.productionTrustClaim === true, `claim_production_trust_claim_forbidden:${ref}`);
      addReason(reasons, hlcTuple(claim?.classifiedAtHlc) === null, `claim_classification_time_invalid:${ref}`);
      return {
        claimHash: isDigest(claim?.claimHash) ? claim.claimHash : null,
        claimRef: ref,
        classifiedAtHlc: claim?.classifiedAtHlc ?? null,
        evidenceHash: isDigest(claim?.evidenceHash) ? claim.evidenceHash : null,
        family: hasText(claim?.family) ? claim.family : 'unknown',
        safestClaimCategory: hasText(claim?.safestClaimCategory) ? claim.safestClaimCategory : 'unknown',
      };
    })
    .sort((left, right) => left.claimRef.localeCompare(right.claimRef));

  const claimFamilies = uniqueSorted(normalized.map((claim) => claim.family));
  evaluateRequiredSet(claimFamilies, requiredClaimFamilies, 'claim_family_missing', 'claim_family_unsupported', reasons);

  return { claimFamilies, normalizedClaims: normalized };
}

function normalizeProductionClaimLiftLineage(register, lineage, humanReview, reasons) {
  const registerReceiptHash = register?.productionClaimLiftReceiptHash;
  const lineageProvided = lineage !== null && lineage !== undefined;
  const receiptHashRequired = registerReceiptHash !== null && registerReceiptHash !== undefined;
  const roleDashboardRoles = sortedTextList(lineage?.adapterActivationDeploymentHandoffCutoverRoleDashboardRoles);

  if (!receiptHashRequired && !lineageProvided) {
    return {
      actionHash: null,
      blockedBy: [],
      canLiftProductionClaim: false,
      claimGateId: null,
      receiptHash: null,
      roleDashboardProviderReceiptHash: null,
      roleDashboardProviderSummaryHash: null,
      roleDashboardProviderTrustStateViewHash: null,
      roleDashboardReadinessReceiptHash: null,
      roleDashboardReadinessSummaryHash: null,
      roleDashboardReadinessTrustStateViewHash: null,
      roleDashboardRoles: [],
      runtimeSourceProviderRoleDashboardReceiptHash: null,
      runtimeSourceProviderRoleDashboardSummaryHash: null,
      runtimeSourceProviderRoleDashboardTrustStateViewHash: null,
      runtimeSourceReadinessRoleDashboardReceiptHash: null,
      runtimeSourceReadinessRoleDashboardSummaryHash: null,
      runtimeSourceReadinessRoleDashboardTrustStateViewHash: null,
      adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: null,
      adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: null,
      adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: null,
      adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: null,
      adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: null,
      adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: null,
      trustState: null,
      verifiedCriteria: [],
    };
  }

  addReason(reasons, receiptHashRequired && !lineageProvided, 'production_claim_lift_lineage_absent');
  addReason(reasons, !receiptHashRequired && lineageProvided, 'production_claim_lift_receipt_hash_absent');
  addReason(
    reasons,
    receiptHashRequired && lineage?.receiptHash !== registerReceiptHash,
    'production_claim_lift_receipt_hash_mismatch',
  );
  addReason(reasons, !isDigest(lineage?.receiptHash), 'production_claim_lift_receipt_hash_invalid');
  addReason(reasons, !hasText(lineage?.receiptId), 'production_claim_lift_receipt_id_absent');
  addReason(
    reasons,
    lineage?.receiptSchema !== PRODUCTION_CLAIM_LIFT_RECEIPT_SCHEMA,
    'production_claim_lift_receipt_schema_invalid',
  );
  addReason(reasons, !isDigest(lineage?.actionHash), 'production_claim_lift_action_hash_invalid');
  addReason(reasons, !CLAIM_GATE_IDS.has(lineage?.claimGateId), 'production_claim_lift_gate_id_unsupported');
  addReason(reasons, lineage?.state !== 'denied', 'production_claim_lift_state_invalid');
  addReason(reasons, lineage?.trustState !== 'inactive', 'production_claim_lift_trust_state_invalid');
  addReason(
    reasons,
    lineage?.canLiftProductionClaim === true || lineage?.exochainProductionClaim === true,
    'production_claim_lift_public_claim_forbidden',
  );
  addReason(reasons, sortedTextList(lineage?.blockedBy).length === 0, 'production_claim_lift_blocker_absent');
  addReason(
    reasons,
    !isDigest(lineage?.adapterActivationHandoffProviderRoleDashboardReceiptHash),
    'production_claim_lift_role_dashboard_provider_receipt_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(lineage?.adapterActivationHandoffProviderRoleDashboardSummaryHash),
    'production_claim_lift_role_dashboard_provider_summary_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(lineage?.adapterActivationHandoffProviderRoleDashboardTrustStateViewHash),
    'production_claim_lift_role_dashboard_provider_trust_state_view_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(lineage?.adapterActivationHandoffReadinessRoleDashboardReceiptHash),
    'production_claim_lift_role_dashboard_readiness_receipt_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(lineage?.adapterActivationHandoffReadinessRoleDashboardSummaryHash),
    'production_claim_lift_role_dashboard_readiness_summary_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(lineage?.adapterActivationHandoffReadinessRoleDashboardTrustStateViewHash),
    'production_claim_lift_role_dashboard_readiness_trust_state_view_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(lineage?.adapterActivationRuntimeSourceProviderRoleDashboardReceiptHash),
    'production_claim_lift_runtime_source_provider_role_dashboard_receipt_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(lineage?.adapterActivationRuntimeSourceProviderRoleDashboardSummaryHash),
    'production_claim_lift_runtime_source_provider_role_dashboard_summary_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(lineage?.adapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash),
    'production_claim_lift_runtime_source_provider_role_dashboard_trust_state_view_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(lineage?.adapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash),
    'production_claim_lift_runtime_source_readiness_role_dashboard_receipt_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(lineage?.adapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash),
    'production_claim_lift_runtime_source_readiness_role_dashboard_summary_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(lineage?.adapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash),
    'production_claim_lift_runtime_source_readiness_role_dashboard_trust_state_view_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(lineage?.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash),
    'production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_receipt_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(lineage?.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash),
    'production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_summary_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(lineage?.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash),
    'production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_trust_state_view_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(lineage?.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash),
    'production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_receipt_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(lineage?.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash),
    'production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_summary_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(lineage?.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash),
    'production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_trust_state_view_hash_invalid',
  );
  addReason(
    reasons,
    isDigest(lineage?.adapterActivationHandoffProviderRoleDashboardReceiptHash) &&
      isDigest(lineage?.adapterActivationRuntimeSourceProviderRoleDashboardReceiptHash) &&
      lineage.adapterActivationHandoffProviderRoleDashboardReceiptHash !==
        lineage.adapterActivationRuntimeSourceProviderRoleDashboardReceiptHash,
    'production_claim_lift_runtime_source_provider_role_dashboard_receipt_mismatch',
  );
  addReason(
    reasons,
    isDigest(lineage?.adapterActivationHandoffProviderRoleDashboardSummaryHash) &&
      isDigest(lineage?.adapterActivationRuntimeSourceProviderRoleDashboardSummaryHash) &&
      lineage.adapterActivationHandoffProviderRoleDashboardSummaryHash !==
        lineage.adapterActivationRuntimeSourceProviderRoleDashboardSummaryHash,
    'production_claim_lift_runtime_source_provider_role_dashboard_summary_mismatch',
  );
  addReason(
    reasons,
    isDigest(lineage?.adapterActivationHandoffProviderRoleDashboardTrustStateViewHash) &&
      isDigest(lineage?.adapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash) &&
      lineage.adapterActivationHandoffProviderRoleDashboardTrustStateViewHash !==
        lineage.adapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    'production_claim_lift_runtime_source_provider_role_dashboard_trust_state_view_mismatch',
  );
  addReason(
    reasons,
    isDigest(lineage?.adapterActivationHandoffReadinessRoleDashboardReceiptHash) &&
      isDigest(lineage?.adapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash) &&
      lineage.adapterActivationHandoffReadinessRoleDashboardReceiptHash !==
        lineage.adapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash,
    'production_claim_lift_runtime_source_readiness_role_dashboard_receipt_mismatch',
  );
  addReason(
    reasons,
    isDigest(lineage?.adapterActivationHandoffReadinessRoleDashboardSummaryHash) &&
      isDigest(lineage?.adapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash) &&
      lineage.adapterActivationHandoffReadinessRoleDashboardSummaryHash !==
        lineage.adapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash,
    'production_claim_lift_runtime_source_readiness_role_dashboard_summary_mismatch',
  );
  addReason(
    reasons,
    isDigest(lineage?.adapterActivationHandoffReadinessRoleDashboardTrustStateViewHash) &&
      isDigest(lineage?.adapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash) &&
      lineage.adapterActivationHandoffReadinessRoleDashboardTrustStateViewHash !==
        lineage.adapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    'production_claim_lift_runtime_source_readiness_role_dashboard_trust_state_view_mismatch',
  );
  addReason(
    reasons,
    isDigest(lineage?.adapterActivationRuntimeSourceProviderRoleDashboardReceiptHash) &&
      isDigest(lineage?.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash) &&
      lineage.adapterActivationRuntimeSourceProviderRoleDashboardReceiptHash !==
        lineage.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash,
    'production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_receipt_mismatch',
  );
  addReason(
    reasons,
    isDigest(lineage?.adapterActivationRuntimeSourceProviderRoleDashboardSummaryHash) &&
      isDigest(lineage?.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash) &&
      lineage.adapterActivationRuntimeSourceProviderRoleDashboardSummaryHash !==
        lineage.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash,
    'production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_summary_mismatch',
  );
  addReason(
    reasons,
    isDigest(lineage?.adapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash) &&
      isDigest(lineage?.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash) &&
      lineage.adapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash !==
        lineage.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    'production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_trust_state_view_mismatch',
  );
  addReason(
    reasons,
    isDigest(lineage?.adapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash) &&
      isDigest(lineage?.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash) &&
      lineage.adapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash !==
        lineage.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash,
    'production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_receipt_mismatch',
  );
  addReason(
    reasons,
    isDigest(lineage?.adapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash) &&
      isDigest(lineage?.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash) &&
      lineage.adapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash !==
        lineage.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash,
    'production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_summary_mismatch',
  );
  addReason(
    reasons,
    isDigest(lineage?.adapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash) &&
      isDigest(lineage?.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash) &&
      lineage.adapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash !==
        lineage.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    'production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_trust_state_view_mismatch',
  );
  for (const role of REQUIRED_ROLE_DASHBOARD_ROLES) {
    addReason(reasons, !roleDashboardRoles.includes(role), `production_claim_lift_role_dashboard_role_missing:${role}`);
  }
  for (const role of roleDashboardRoles) {
    addReason(
      reasons,
      !REQUIRED_ROLE_DASHBOARD_ROLES.includes(role),
      `production_claim_lift_role_dashboard_role_unsupported:${role}`,
    );
  }
  addReason(reasons, lineage?.metadataOnly !== true, 'production_claim_lift_metadata_boundary_invalid');
  addReason(reasons, lineage?.protectedContentExcluded !== true, 'production_claim_lift_protected_boundary_invalid');
  addReason(reasons, hlcTuple(lineage?.reviewedAtHlc) === null, 'production_claim_lift_review_time_invalid');
  addReason(
    reasons,
    hlcBefore(lineage?.reviewedAtHlc, register?.compiledAtHlc),
    'production_claim_lift_review_before_content_register',
  );
  addReason(
    reasons,
    humanReview !== null &&
      humanReview !== undefined &&
      hlcAfter(lineage?.reviewedAtHlc, humanReview?.reviewedAtHlc),
    'production_claim_lift_review_after_human_review',
  );

  return {
    actionHash: isDigest(lineage?.actionHash) ? lineage.actionHash : null,
    blockedBy: sortedTextList(lineage?.blockedBy),
    canLiftProductionClaim: lineage?.canLiftProductionClaim === true,
    claimGateId: CLAIM_GATE_IDS.has(lineage?.claimGateId) ? lineage.claimGateId : null,
    receiptHash: isDigest(lineage?.receiptHash) ? lineage.receiptHash : null,
    roleDashboardProviderReceiptHash: isDigest(lineage?.adapterActivationHandoffProviderRoleDashboardReceiptHash)
      ? lineage.adapterActivationHandoffProviderRoleDashboardReceiptHash
      : null,
    roleDashboardProviderSummaryHash: isDigest(lineage?.adapterActivationHandoffProviderRoleDashboardSummaryHash)
      ? lineage.adapterActivationHandoffProviderRoleDashboardSummaryHash
      : null,
    roleDashboardProviderTrustStateViewHash: isDigest(
      lineage?.adapterActivationHandoffProviderRoleDashboardTrustStateViewHash,
    )
      ? lineage.adapterActivationHandoffProviderRoleDashboardTrustStateViewHash
      : null,
    roleDashboardReadinessReceiptHash: isDigest(lineage?.adapterActivationHandoffReadinessRoleDashboardReceiptHash)
      ? lineage.adapterActivationHandoffReadinessRoleDashboardReceiptHash
      : null,
    roleDashboardReadinessSummaryHash: isDigest(lineage?.adapterActivationHandoffReadinessRoleDashboardSummaryHash)
      ? lineage.adapterActivationHandoffReadinessRoleDashboardSummaryHash
      : null,
    roleDashboardReadinessTrustStateViewHash: isDigest(
      lineage?.adapterActivationHandoffReadinessRoleDashboardTrustStateViewHash,
    )
      ? lineage.adapterActivationHandoffReadinessRoleDashboardTrustStateViewHash
      : null,
    roleDashboardRoles,
    runtimeSourceProviderRoleDashboardReceiptHash: isDigest(
      lineage?.adapterActivationRuntimeSourceProviderRoleDashboardReceiptHash,
    )
      ? lineage.adapterActivationRuntimeSourceProviderRoleDashboardReceiptHash
      : null,
    runtimeSourceProviderRoleDashboardSummaryHash: isDigest(
      lineage?.adapterActivationRuntimeSourceProviderRoleDashboardSummaryHash,
    )
      ? lineage.adapterActivationRuntimeSourceProviderRoleDashboardSummaryHash
      : null,
    runtimeSourceProviderRoleDashboardTrustStateViewHash: isDigest(
      lineage?.adapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    )
      ? lineage.adapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash
      : null,
    runtimeSourceReadinessRoleDashboardReceiptHash: isDigest(
      lineage?.adapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash,
    )
      ? lineage.adapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash
      : null,
    runtimeSourceReadinessRoleDashboardSummaryHash: isDigest(
      lineage?.adapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash,
    )
      ? lineage.adapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash
      : null,
    runtimeSourceReadinessRoleDashboardTrustStateViewHash: isDigest(
      lineage?.adapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    )
      ? lineage.adapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash
      : null,
    adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: isDigest(
      lineage?.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash,
    )
      ? lineage.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash
      : null,
    adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: isDigest(
      lineage?.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash,
    )
      ? lineage.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash
      : null,
    adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: isDigest(
      lineage?.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    )
      ? lineage.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash
      : null,
    adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: isDigest(
      lineage?.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash,
    )
      ? lineage.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash
      : null,
    adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: isDigest(
      lineage?.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash,
    )
      ? lineage.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash
      : null,
    adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: isDigest(
      lineage?.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    )
      ? lineage.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash
      : null,
    trustState: hasText(lineage?.trustState) ? lineage.trustState : null,
    verifiedCriteria: sortedTextList(lineage?.verifiedCriteria),
  };
}

function normalizeReviews(claims, reviews, requiredReviewerRoles, reasons) {
  const rows = Array.isArray(reviews) ? [...reviews] : [];
  addReason(reasons, rows.length === 0, 'public_claim_reviews_absent');
  const claimByRef = new Map(claims.map((claim) => [claim.claimRef, claim]));
  const approvedReviewRefs = [];
  const reviewRoles = [];

  for (const review of rows) {
    const claimRef = hasText(review?.claimRef) ? review.claimRef : 'unknown_claim';
    const reviewRef = hasText(review?.reviewRef) ? review.reviewRef : `review_${claimRef}_${review?.reviewerRole ?? 'unknown'}`;
    const claim = claimByRef.get(claimRef);
    addReason(reasons, !hasText(review?.reviewRef), `review_ref_absent:${claimRef}`);
    addReason(reasons, !claimByRef.has(claimRef), `review_claim_ref_unknown:${claimRef}`);
    addReason(reasons, !requiredReviewerRoles.includes(review?.reviewerRole), `reviewer_role_unsupported:${claimRef}:${review?.reviewerRole ?? 'unknown'}`);
    addReason(reasons, !hasText(review?.reviewerDid), `reviewer_did_absent:${claimRef}:${review?.reviewerRole ?? 'unknown'}`);
    addReason(reasons, !REVIEW_DECISIONS.has(review?.decision), `claim_review_decision_invalid:${claimRef}:${review?.reviewerRole ?? 'unknown'}`);
    addReason(
      reasons,
      REVIEW_DECISIONS.has(review?.decision) && !APPROVED_REVIEW_DECISIONS.has(review.decision),
      `claim_review_not_approved:${claimRef}:${review?.reviewerRole ?? 'unknown'}`,
    );
    addReason(reasons, !isDigest(review?.reviewHash), `claim_review_hash_invalid:${claimRef}:${review?.reviewerRole ?? 'unknown'}`);
    addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, `claim_review_time_invalid:${claimRef}:${review?.reviewerRole ?? 'unknown'}`);
    addReason(
      reasons,
      claim !== undefined && hlcBefore(review?.reviewedAtHlc, claim.classifiedAtHlc),
      `claim_review_before_classification:${claimRef}:${review?.reviewerRole ?? 'unknown'}`,
    );
    addReason(reasons, review?.metadataOnly !== true, `claim_review_metadata_boundary_invalid:${claimRef}:${review?.reviewerRole ?? 'unknown'}`);
    addReason(
      reasons,
      review?.protectedContentExcluded !== true,
      `claim_review_protected_boundary_invalid:${claimRef}:${review?.reviewerRole ?? 'unknown'}`,
    );
    if (APPROVED_REVIEW_DECISIONS.has(review?.decision)) {
      approvedReviewRefs.push(reviewRef);
      reviewRoles.push(review.reviewerRole);
    }
  }

  for (const claim of claims) {
    for (const role of requiredReviewerRoles) {
      const matchingReview = rows.find((review) => review?.claimRef === claim.claimRef && review?.reviewerRole === role);
      addReason(reasons, matchingReview === undefined, `claim_required_review_missing:${claim.claimRef}:${role}`);
    }
  }

  return {
    approvedReviewRefs: uniqueSorted(approvedReviewRefs),
    reviewRoles: uniqueSorted(reviewRoles),
  };
}

function evaluatePublicationGate(gate, safeClaimCategories, reasons) {
  addReason(reasons, !hasText(gate?.gateRef), 'publication_gate_ref_absent');
  addReason(reasons, !safeClaimCategories.includes(gate?.safePublicClaimCategory), 'publication_gate_safe_claim_category_invalid');
  addReason(reasons, gate?.websiteCopyApproved !== true, 'website_copy_not_approved');
  addReason(reasons, gate?.salesMaterialsApproved !== true, 'sales_materials_not_approved');
  addReason(reasons, gate?.aiIrbPublicLanguageAllowed === true, 'publication_gate_ai_irb_language_forbidden');
  addReason(reasons, gate?.irbIecSubstitutionClaimAllowed === true, 'publication_gate_irb_iec_claim_forbidden');
  addReason(reasons, gate?.exochainProductionClaimAllowed === true, 'publication_gate_exochain_claim_forbidden');
  addReason(reasons, gate?.highRiskClaimsHeld === true, 'high_risk_claims_held');
  addReason(reasons, gate?.publicUseAuthorized !== true, 'public_use_not_authorized');
  addReason(reasons, gate?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, gate?.metadataOnly !== true, 'publication_gate_metadata_boundary_invalid');
  addReason(reasons, gate?.protectedContentExcluded !== true, 'publication_gate_protected_boundary_invalid');
  addReason(reasons, hlcTuple(gate?.gatedAtHlc) === null, 'publication_gate_time_invalid');
}

function evaluateAiAssistant(aiAssistant, humanReview, reasons) {
  if (aiAssistant?.used === false) {
    return { used: false };
  }
  addReason(reasons, !isDigest(aiAssistant?.recommendationHash), 'ai_recommendation_hash_invalid');
  addReason(reasons, sortedTextList(aiAssistant?.limitationHashes).some((hash) => !isDigest(hash)), 'ai_limitation_hash_invalid');
  addReason(reasons, aiAssistant?.advisoryOnly !== true, 'ai_assistant_not_advisory_only');
  addReason(reasons, aiAssistant?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, aiAssistant?.humanReviewed !== true, 'ai_human_review_absent');
  addReason(reasons, aiAssistant?.metadataOnly !== true, 'ai_assistant_metadata_boundary_invalid');
  addReason(reasons, aiAssistant?.protectedContentExcluded !== true, 'ai_assistant_protected_boundary_invalid');
  addReason(reasons, hlcTuple(aiAssistant?.reviewedAtHlc) === null, 'ai_review_time_invalid');
  addReason(reasons, hlcAfter(aiAssistant?.reviewedAtHlc, humanReview?.reviewedAtHlc), 'ai_review_not_before_human_review');
  return { used: true };
}

function evaluateHumanReview(humanReview, aiAssistant, reasons) {
  const reviewerRoles = sortedTextList(humanReview?.reviewerRoleRefs);
  addReason(reasons, !hasText(humanReview?.reviewerDid), 'human_reviewer_did_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(humanReview?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(humanReview?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, humanReview?.finalAuthority !== 'human', 'human_final_authority_missing');
  addReason(reasons, humanReview?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, humanReview?.noProductionTrustClaim !== true, 'human_review_production_claim_boundary_absent');
  addReason(reasons, humanReview?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, humanReview?.protectedContentExcluded !== true, 'human_review_protected_boundary_invalid');
  addReason(reasons, hlcTuple(humanReview?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(
    reasons,
    aiAssistant?.used !== false && hlcBefore(humanReview?.reviewedAtHlc, aiAssistant?.reviewedAtHlc),
    'human_review_before_ai_review',
  );
  evaluateRequiredSet(
    reviewerRoles,
    REQUIRED_REVIEWER_ROLES,
    'human_reviewer_role_missing',
    'human_reviewer_role_unsupported',
    reasons,
  );
}

function evaluateValidationEvidence(validation, humanReview, reasons) {
  const commandRefs = sortedTextList(validation?.commandRefs);
  addReason(reasons, !commandRefs.includes('node --test tests/public-claim-review.test.mjs'), 'focused_test_command_ref_absent');
  addReason(reasons, !commandRefs.includes('npm run quality'), 'quality_command_ref_absent');
  addReason(reasons, validation?.commandsPassed !== true, 'validation_commands_not_passed');
  addReason(reasons, validation?.sourceGuardPassed !== true, 'source_guard_not_passed');
  addReason(reasons, validation?.noExochainSourceModified !== true, 'exochain_source_modified');
  addReason(reasons, validation?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(validation?.recordedAtHlc) === null, 'validation_record_time_invalid');
  addReason(reasons, !hlcAfter(validation?.recordedAtHlc, humanReview?.reviewedAtHlc), 'validation_before_human_review');
}

function buildPublicClaimReview(input, contentSummary, claimSummary, reviewSummary, productionClaimLiftSummary) {
  const material = {
    claimRefs: claimSummary.normalizedClaims.map((claim) => claim.claimRef),
    contentRefs: contentSummary.normalizedAssets.map((asset) => asset.assetRef),
    gateRef: input.publicationGate.gateRef,
    humanDecisionHash: input.humanReview.decisionHash,
    productionClaimLiftActionHash: productionClaimLiftSummary.actionHash,
    productionClaimLiftBlockedBy: productionClaimLiftSummary.blockedBy,
    productionClaimLiftClaimGateId: productionClaimLiftSummary.claimGateId,
    productionClaimLiftReceiptHash: productionClaimLiftSummary.receiptHash,
    productionClaimLiftRoleDashboardProviderReceiptHash: productionClaimLiftSummary.roleDashboardProviderReceiptHash,
    productionClaimLiftRoleDashboardProviderSummaryHash: productionClaimLiftSummary.roleDashboardProviderSummaryHash,
    productionClaimLiftRoleDashboardProviderTrustStateViewHash:
      productionClaimLiftSummary.roleDashboardProviderTrustStateViewHash,
    productionClaimLiftRoleDashboardReadinessReceiptHash: productionClaimLiftSummary.roleDashboardReadinessReceiptHash,
    productionClaimLiftRoleDashboardReadinessSummaryHash: productionClaimLiftSummary.roleDashboardReadinessSummaryHash,
    productionClaimLiftRoleDashboardReadinessTrustStateViewHash:
      productionClaimLiftSummary.roleDashboardReadinessTrustStateViewHash,
    productionClaimLiftRoleDashboardRoles: productionClaimLiftSummary.roleDashboardRoles,
    productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash:
      productionClaimLiftSummary.runtimeSourceProviderRoleDashboardReceiptHash,
    productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash:
      productionClaimLiftSummary.runtimeSourceProviderRoleDashboardSummaryHash,
    productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash:
      productionClaimLiftSummary.runtimeSourceProviderRoleDashboardTrustStateViewHash,
    productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash:
      productionClaimLiftSummary.runtimeSourceReadinessRoleDashboardReceiptHash,
    productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash:
      productionClaimLiftSummary.runtimeSourceReadinessRoleDashboardSummaryHash,
    productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash:
      productionClaimLiftSummary.runtimeSourceReadinessRoleDashboardTrustStateViewHash,
    productionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardReceiptHash:
      productionClaimLiftSummary.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash,
    productionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardSummaryHash:
      productionClaimLiftSummary.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash,
    productionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash:
      productionClaimLiftSummary.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    productionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash:
      productionClaimLiftSummary.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash,
    productionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash:
      productionClaimLiftSummary.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash,
    productionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash:
      productionClaimLiftSummary.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    productionClaimLiftTrustState: productionClaimLiftSummary.trustState,
    productionClaimLiftVerifiedCriteria: productionClaimLiftSummary.verifiedCriteria,
    registerRef: input.contentRegister.registerRef,
  };
  const reviewPackageHash = sha256Hex(material);

  return {
    schema: PUBLIC_CLAIM_REVIEW_SCHEMA,
    reviewRef: `public_claim_review_${reviewPackageHash.slice(0, 32)}`,
    registerRef: input.contentRegister.registerRef,
    status: 'approved_for_public_use',
    trustState: 'inactive',
    exochainProductionClaim: false,
    containsProtectedContent: false,
    metadataOnly: true,
    contentTypes: contentSummary.contentTypes,
    claimFamilies: claimSummary.claimFamilies,
    baselineSafeClaimCategories: [...BASELINE_SAFE_CLAIM_CATEGORIES],
    requiredReviewerRoles: [...REQUIRED_REVIEWER_ROLES],
    reviewRoles: reviewSummary.reviewRoles,
    reviewedClaimCount: claimSummary.normalizedClaims.length,
    approvedReviewRefs: reviewSummary.approvedReviewRefs,
    safePublicClaimCategory: input.publicationGate.safePublicClaimCategory,
    aiAssistanceUsed: input.aiAssistant?.used !== false,
    aiIrbPublicLanguageAllowed: false,
    irbIecSubstitutionClaimAllowed: false,
    productionClaimLiftActionHash: productionClaimLiftSummary.actionHash,
    productionClaimLiftBlockedBy: productionClaimLiftSummary.blockedBy,
    productionClaimLiftCanLiftProductionClaim: productionClaimLiftSummary.canLiftProductionClaim,
    productionClaimLiftClaimGateId: productionClaimLiftSummary.claimGateId,
    productionClaimLiftReceiptHash: productionClaimLiftSummary.receiptHash,
    productionClaimLiftRoleDashboardProviderReceiptHash: productionClaimLiftSummary.roleDashboardProviderReceiptHash,
    productionClaimLiftRoleDashboardProviderSummaryHash: productionClaimLiftSummary.roleDashboardProviderSummaryHash,
    productionClaimLiftRoleDashboardProviderTrustStateViewHash:
      productionClaimLiftSummary.roleDashboardProviderTrustStateViewHash,
    productionClaimLiftRoleDashboardReadinessReceiptHash: productionClaimLiftSummary.roleDashboardReadinessReceiptHash,
    productionClaimLiftRoleDashboardReadinessSummaryHash: productionClaimLiftSummary.roleDashboardReadinessSummaryHash,
    productionClaimLiftRoleDashboardReadinessTrustStateViewHash:
      productionClaimLiftSummary.roleDashboardReadinessTrustStateViewHash,
    productionClaimLiftRoleDashboardRoles: productionClaimLiftSummary.roleDashboardRoles,
    productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash:
      productionClaimLiftSummary.runtimeSourceProviderRoleDashboardReceiptHash,
    productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash:
      productionClaimLiftSummary.runtimeSourceProviderRoleDashboardSummaryHash,
    productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash:
      productionClaimLiftSummary.runtimeSourceProviderRoleDashboardTrustStateViewHash,
    productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash:
      productionClaimLiftSummary.runtimeSourceReadinessRoleDashboardReceiptHash,
    productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash:
      productionClaimLiftSummary.runtimeSourceReadinessRoleDashboardSummaryHash,
    productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash:
      productionClaimLiftSummary.runtimeSourceReadinessRoleDashboardTrustStateViewHash,
    productionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardReceiptHash:
      productionClaimLiftSummary.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash,
    productionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardSummaryHash:
      productionClaimLiftSummary.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash,
    productionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash:
      productionClaimLiftSummary.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    productionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash:
      productionClaimLiftSummary.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash,
    productionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash:
      productionClaimLiftSummary.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash,
    productionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash:
      productionClaimLiftSummary.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    productionClaimLiftTrustState: productionClaimLiftSummary.trustState,
    productionClaimLiftVerifiedCriteria: productionClaimLiftSummary.verifiedCriteria,
    publicUseAuthorized: true,
    reviewPackageHash,
    publicationGateRef: input.publicationGate.gateRef,
    evaluatedAtHlc: input.publicClaimPolicy.evaluatedAtHlc,
    approvedAtHlc: input.humanReview.reviewedAtHlc,
  };
}

function createPublicClaimReceipt(input, publicClaimReview) {
  const sensitivityTags = ['metadata_only', 'public_claim_review', 'sales_claim_review'];
  if (publicClaimReview.productionClaimLiftReceiptHash !== null) {
    sensitivityTags.push('production_claim_lift_lineage');
  }
  if (publicClaimReview.productionClaimLiftRoleDashboardRoles.length > 0) {
    sensitivityTags.push('production_claim_lift_role_dashboard_lineage');
  }
  if (
    publicClaimReview.productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash !== null ||
    publicClaimReview.productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash !== null
  ) {
    sensitivityTags.push('production_claim_lift_runtime_source_trust_state_view_lineage');
  }
  if (
    publicClaimReview.productionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardReceiptHash !== null ||
    publicClaimReview.productionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardSummaryHash !== null ||
    publicClaimReview.productionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash !==
      null ||
    publicClaimReview.productionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash !== null ||
    publicClaimReview.productionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash !== null ||
    publicClaimReview.productionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash !== null
  ) {
    sensitivityTags.push('production_claim_lift_adapter_activation_runtime_source_lineage');
  }

  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: publicClaimReview.reviewPackageHash,
    artifactType: 'public_claim_review',
    artifactVersion: `${input.contentRegister.registerRef}@${input.contentRegister.compiledAtHlc.physicalMs}.${input.contentRegister.compiledAtHlc.logical}`,
    classification: 'metadata_only_public_claim_review',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    sensitivityTags,
    sourceSystem: 'cybermedica-public-claim-review',
    tenantId: input.tenantId,
  });
}

export function evaluatePublicClaimReview(input = {}) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policySummary = evaluatePolicy(input?.publicClaimPolicy, input?.contentRegister, reasons);
  const contentSummary = normalizeContentAssets(input?.contentRegister, policySummary.contentTypes, reasons);
  const claimSummary = normalizeClaimRecords(
    input?.contentRegister,
    policySummary.claimFamilies,
    policySummary.safeClaimCategories,
    reasons,
  );
  const productionClaimLiftSummary = normalizeProductionClaimLiftLineage(
    input?.contentRegister,
    input?.productionClaimLiftLineage,
    input?.humanReview,
    reasons,
  );
  const reviewSummary = normalizeReviews(claimSummary.normalizedClaims, input?.reviews, policySummary.reviewerRoles, reasons);
  evaluatePublicationGate(input?.publicationGate, policySummary.safeClaimCategories, reasons);
  evaluateAiAssistant(input?.aiAssistant, input?.humanReview, reasons);
  evaluateHumanReview(input?.humanReview, input?.aiAssistant, reasons);
  evaluateValidationEvidence(input?.validationEvidence, input?.humanReview, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: PUBLIC_CLAIM_REVIEW_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: unique,
      publicClaimReview: {
        schema: PUBLIC_CLAIM_REVIEW_SCHEMA,
        status: 'blocked',
        trustState: 'inactive',
        exochainProductionClaim: false,
        metadataOnly: input?.contentRegister?.metadataOnly === true,
        containsProtectedContent: false,
      },
      receipt: null,
      sourceEvidence: [
        'cybermedica_2_0_sandy_seven_layer_master_prd.md#appendix-b-sandy-review-questions',
        'cybermedica_2_0_sandy_seven_layer_master_prd.md#data-layer',
        'cybermedica_2_0_sandy_seven_layer_master_prd.md#DOC-009',
      ],
    };
  }

  const publicClaimReview = buildPublicClaimReview(
    input,
    contentSummary,
    claimSummary,
    reviewSummary,
    productionClaimLiftSummary,
  );
  const receipt = createPublicClaimReceipt(input, publicClaimReview);

  return {
    schema: PUBLIC_CLAIM_REVIEW_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    publicClaimReview,
    receipt,
    sourceEvidence: [
      'cybermedica_2_0_sandy_seven_layer_master_prd.md#appendix-b-sandy-review-questions',
      'cybermedica_2_0_sandy_seven_layer_master_prd.md#data-layer',
      'cybermedica_2_0_sandy_seven_layer_master_prd.md#DOC-009',
    ],
  };
}

export const publicClaimReviewRequirements = Object.freeze({
  baselineSafeClaimCategories: [...BASELINE_SAFE_CLAIM_CATEGORIES],
  claimFamilies: [...REQUIRED_CLAIM_FAMILIES],
  contentTypes: [...REQUIRED_PUBLIC_CONTENT_TYPES],
  reviewerRoles: [...REQUIRED_REVIEWER_ROLES],
  schema: PUBLIC_CLAIM_REVIEW_SCHEMA,
});
