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

const TRUST_STATE_COPY = Object.freeze({
  inactive: {
    severity: 'neutral',
    primaryText: 'Exochain production trust is inactive for this CyberMedica action.',
    secondaryText: 'Baseline QMS workflow may proceed only as operational state without an active Exochain production claim.',
  },
  pending: {
    severity: 'attention',
    primaryText: 'Exochain trust evidence is pending verification.',
    secondaryText: 'The action remains disabled for production trust language until all required receipts verify.',
  },
  denied: {
    severity: 'critical',
    primaryText: 'Exochain trust evidence was denied.',
    secondaryText: 'The action cannot proceed as a trusted CyberMedica workflow until the failing evidence is corrected.',
  },
  degraded: {
    severity: 'warning',
    primaryText: 'Exochain trust dependency is degraded or unavailable.',
    secondaryText: 'The adapter fails closed and disables trust-dependent actions until service readiness returns.',
  },
  verified: {
    severity: 'success',
    primaryText: 'Verified Exochain receipt path is available for this CyberMedica action.',
    secondaryText: 'The UI may show the verified production trust claim that maps to this receipt path.',
  },
});

const BLOCKER_CODE_PATTERN = /^[a-z0-9]+(?:[_:-][a-z0-9]+)*$/u;
const CLAIM_ID_PATTERN = /^PTAG-\d{3}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const PRODUCTION_TRUST_ACTIVATION_SCHEMA = 'cybermedica.production_trust_activation.v1';
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

const UNSAFE_BLOCKER_TERMS = Object.freeze([
  'apikey',
  'credential',
  'email',
  'medicalrecord',
  'mrn',
  'participant',
  'password',
  'patient',
  'phone',
  'phi',
  'pii',
  'privatekey',
  'secret',
  'ssn',
  'subject',
  'token',
]);

const BOB_ESCALATION_RULES = Object.freeze([
  ['human_adapter_activation', 'ESC-HUMAN-PROOFING'],
  ['human_gate', 'ESC-HUMAN-PROOFING'],
  ['root_certifier', 'ESC-ROOT-ROSTER'],
  ['root_roster', 'ESC-ROOT-ROSTER'],
  ['root_dkg', 'ESC-ROOT-ARTIFACT-STORE'],
  ['root_trust_bundle_hash', 'ESC-ROOT-ARTIFACT-STORE'],
  ['root_artifact_registry', 'ESC-ROOT-ARTIFACT-STORE'],
  ['root_operations_runbook', 'ESC-ROOT-OWNER'],
  ['root_bundle_provider', 'ESC-ROOT-DEPLOYMENT'],
  ['root_verifier', 'ESC-ROOT-DEPLOYMENT'],
  ['root_bundle_absent', 'ESC-ROOT-DEPLOYMENT'],
  ['gateway', 'ESC-RUNTIME'],
  ['receipt_path', 'ESC-RUNTIME'],
  ['node_receipt', 'ESC-RUNTIME'],
  ['decision_forum', 'ESC-RUNTIME'],
  ['runtime', 'ESC-RUNTIME'],
  ['monitoring', 'ESC-OPS-SECRETS'],
  ['on_call', 'ESC-OPS-SECRETS'],
  ['secret_manager', 'ESC-OPS-SECRETS'],
  ['commandbase', 'ESC-OPTIONAL-ADJACENT'],
  ['exochain_web', 'ESC-OPTIONAL-ADJACENT'],
  ['avc', 'ESC-OPTIONAL-ADJACENT'],
]);

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value);
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value.filter(hasText)) : [];
}

function unsafeBlockerCode(blocker) {
  const compact = blocker.replaceAll(/[^a-z0-9]/gu, '');
  return UNSAFE_BLOCKER_TERMS.some((term) => compact.includes(term));
}

function sanitizeBlockerCode(item) {
  if (typeof item !== 'string') {
    return null;
  }
  const blocker = item.trim().toLowerCase();
  if (!BLOCKER_CODE_PATTERN.test(blocker) || unsafeBlockerCode(blocker)) {
    return null;
  }
  return blocker;
}

function normalizeBlockedBy(blockedBy) {
  if (!Array.isArray(blockedBy)) {
    return { blockedBy: [], unsafeBlockedByCount: 0 };
  }
  const sanitized = [];
  let unsafeBlockedByCount = 0;

  for (const item of blockedBy) {
    const blocker = sanitizeBlockerCode(item);
    if (blocker === null) {
      unsafeBlockedByCount += 1;
    } else {
      sanitized.push(blocker);
    }
  }

  return {
    blockedBy: uniqueSorted(sanitized),
    unsafeBlockedByCount,
  };
}

function escalationForBlocker(blocker) {
  const match = BOB_ESCALATION_RULES.find(([prefix]) => blocker.startsWith(prefix));
  return match?.[1] ?? null;
}

function bobEscalationsFor(blockedBy) {
  return uniqueSorted(blockedBy.map(escalationForBlocker).filter((item) => item !== null));
}

function effectiveStatus(requestedStatus, blockedBy, unsafeBlockedByCount, forceDenied) {
  if (forceDenied || (requestedStatus === 'verified' && (blockedBy.length > 0 || unsafeBlockedByCount > 0))) {
    return 'denied';
  }
  return requestedStatus;
}

function hasProductionTrustActivation(input) {
  return input?.productionTrustActivation !== null && input?.productionTrustActivation !== undefined;
}

function requiresProductionTrustActivationLineage(input) {
  return input?.requireProductionTrustActivationLineage === true || hasProductionTrustActivation(input);
}

function hasPublicClaimReviewLineage(activation) {
  return (
    activation !== null &&
    activation !== undefined &&
    typeof activation === 'object' &&
    [
      activation.publicClaimReviewReceiptHash,
      activation.publicClaimReviewPackageHash,
      activation.publicClaimReviewStatus,
      activation.publicClaimReviewTrustState,
      activation.publicClaimReviewProductionClaimLiftReceiptHash,
      activation.publicClaimReviewProductionClaimLiftTrustState,
      activation.publicClaimReviewProductionClaimLiftCanLiftProductionClaim,
      activation.publicClaimReviewProductionClaimLiftRoleDashboardProviderReceiptHash,
      activation.publicClaimReviewProductionClaimLiftRoleDashboardProviderSummaryHash,
      activation.publicClaimReviewProductionClaimLiftRoleDashboardProviderTrustStateViewHash,
      activation.publicClaimReviewProductionClaimLiftRoleDashboardReadinessReceiptHash,
      activation.publicClaimReviewProductionClaimLiftRoleDashboardReadinessSummaryHash,
      activation.publicClaimReviewProductionClaimLiftRoleDashboardReadinessTrustStateViewHash,
      activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash,
      activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash,
      activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
      activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash,
      activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash,
      activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
      activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardReceiptHash,
      activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardSummaryHash,
      activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash,
      activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash,
      activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash,
      activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
      activation.publicClaimReviewProductionClaimLiftRoleDashboardRoles,
    ].some((value) => value !== null && value !== undefined)
  );
}

function requiresPublicClaimReviewLineage(input, activation) {
  return input?.requirePublicClaimReviewLineage === true || hasPublicClaimReviewLineage(activation);
}

function summarizeProductionTrustActivation(activation) {
  if (activation === null || activation === undefined || typeof activation !== 'object') {
    return null;
  }

  return {
    claimId: CLAIM_ID_PATTERN.test(activation.claimId) ? activation.claimId : null,
    activationState: Object.hasOwn(TRUST_STATE_COPY, activation.state) ? activation.state : null,
    allowed: activation.allowed === true,
    failClosed: activation.failClosed === true,
    exochainProductionClaim: activation.exochainProductionClaim === true,
    publicClaimReviewReceiptHash: isDigest(activation.publicClaimReviewReceiptHash)
      ? activation.publicClaimReviewReceiptHash
      : null,
    publicClaimReviewPackageHash: isDigest(activation.publicClaimReviewPackageHash)
      ? activation.publicClaimReviewPackageHash
      : null,
    publicClaimReviewStatus: hasText(activation.publicClaimReviewStatus)
      ? activation.publicClaimReviewStatus
      : null,
    publicClaimReviewTrustState: hasText(activation.publicClaimReviewTrustState)
      ? activation.publicClaimReviewTrustState
      : null,
    publicClaimReviewPublicUseAuthorized: activation.publicClaimReviewPublicUseAuthorized === true,
    publicClaimReviewProductionClaimLiftReceiptHash: isDigest(
      activation.publicClaimReviewProductionClaimLiftReceiptHash,
    )
      ? activation.publicClaimReviewProductionClaimLiftReceiptHash
      : null,
    publicClaimReviewProductionClaimLiftTrustState: hasText(
      activation.publicClaimReviewProductionClaimLiftTrustState,
    )
      ? activation.publicClaimReviewProductionClaimLiftTrustState
      : null,
    publicClaimReviewProductionClaimLiftCanLiftProductionClaim:
      typeof activation.publicClaimReviewProductionClaimLiftCanLiftProductionClaim === 'boolean'
        ? activation.publicClaimReviewProductionClaimLiftCanLiftProductionClaim
        : null,
    publicClaimReviewProductionClaimLiftRoleDashboardProviderReceiptHash: isDigest(
      activation.publicClaimReviewProductionClaimLiftRoleDashboardProviderReceiptHash,
    )
      ? activation.publicClaimReviewProductionClaimLiftRoleDashboardProviderReceiptHash
      : null,
    publicClaimReviewProductionClaimLiftRoleDashboardProviderSummaryHash: isDigest(
      activation.publicClaimReviewProductionClaimLiftRoleDashboardProviderSummaryHash,
    )
      ? activation.publicClaimReviewProductionClaimLiftRoleDashboardProviderSummaryHash
      : null,
    publicClaimReviewProductionClaimLiftRoleDashboardProviderTrustStateViewHash: isDigest(
      activation.publicClaimReviewProductionClaimLiftRoleDashboardProviderTrustStateViewHash,
    )
      ? activation.publicClaimReviewProductionClaimLiftRoleDashboardProviderTrustStateViewHash
      : null,
    publicClaimReviewProductionClaimLiftRoleDashboardReadinessReceiptHash: isDigest(
      activation.publicClaimReviewProductionClaimLiftRoleDashboardReadinessReceiptHash,
    )
      ? activation.publicClaimReviewProductionClaimLiftRoleDashboardReadinessReceiptHash
      : null,
    publicClaimReviewProductionClaimLiftRoleDashboardReadinessSummaryHash: isDigest(
      activation.publicClaimReviewProductionClaimLiftRoleDashboardReadinessSummaryHash,
    )
      ? activation.publicClaimReviewProductionClaimLiftRoleDashboardReadinessSummaryHash
      : null,
    publicClaimReviewProductionClaimLiftRoleDashboardReadinessTrustStateViewHash: isDigest(
      activation.publicClaimReviewProductionClaimLiftRoleDashboardReadinessTrustStateViewHash,
    )
      ? activation.publicClaimReviewProductionClaimLiftRoleDashboardReadinessTrustStateViewHash
      : null,
    publicClaimReviewProductionClaimLiftRoleDashboardRoles: sortedTextList(
      activation.publicClaimReviewProductionClaimLiftRoleDashboardRoles,
    ),
    publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: isDigest(
      activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash,
    )
      ? activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash
      : null,
    publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: isDigest(
      activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash,
    )
      ? activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash
      : null,
    publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: isDigest(
      activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    )
      ? activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash
      : null,
    publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: isDigest(
      activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash,
    )
      ? activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash
      : null,
    publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: isDigest(
      activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash,
    )
      ? activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash
      : null,
    publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: isDigest(
      activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    )
      ? activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash
      : null,
    publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardReceiptHash: isDigest(
      activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardReceiptHash,
    )
      ? activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardReceiptHash
      : null,
    publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardSummaryHash: isDigest(
      activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardSummaryHash,
    )
      ? activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardSummaryHash
      : null,
    publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash: isDigest(
      activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    )
      ? activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash
      : null,
    publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash: isDigest(
      activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash,
    )
      ? activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash
      : null,
    publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash: isDigest(
      activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash,
    )
      ? activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash
      : null,
    publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash: isDigest(
      activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    )
      ? activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash
      : null,
  };
}

function productionTrustActivationBlocks(input) {
  const required = requiresProductionTrustActivationLineage(input);
  const activation = input?.productionTrustActivation;
  const blocks = [];
  const rawBlockedBy = [];

  if (activation === null || activation === undefined || typeof activation !== 'object') {
    if (required) {
      blocks.push('production_trust_activation_lineage_absent');
    }
    if (requiresPublicClaimReviewLineage(input, activation)) {
      blocks.push('public_claim_review_lineage_absent');
    }
    return {
      accepted: false,
      blocks,
      rawBlockedBy,
      lineage: null,
    };
  }

  if (activation.schema !== PRODUCTION_TRUST_ACTIVATION_SCHEMA) {
    blocks.push('production_trust_activation_schema_invalid');
  }
  if (!CLAIM_ID_PATTERN.test(activation.claimId)) {
    blocks.push('production_trust_activation_claim_id_invalid');
  }
  if (!Object.hasOwn(TRUST_STATE_COPY, activation.state)) {
    blocks.push('production_trust_activation_state_invalid');
  }
  if (typeof activation.allowed !== 'boolean') {
    blocks.push('production_trust_activation_allowed_flag_invalid');
  }
  if (typeof activation.failClosed !== 'boolean') {
    blocks.push('production_trust_activation_fail_closed_flag_invalid');
  }
  if (typeof activation.exochainProductionClaim !== 'boolean') {
    blocks.push('production_trust_activation_claim_flag_invalid');
  }
  if (activation.allowed === true && activation.state !== 'verified') {
    blocks.push('production_trust_activation_allowed_state_mismatch');
  }
  if (activation.allowed === false && activation.failClosed !== true) {
    blocks.push('production_trust_activation_fail_closed_invalid');
  }
  if (activation.allowed === true && activation.failClosed !== false) {
    blocks.push('production_trust_activation_fail_closed_invalid');
  }
  if (typeof activation.exochainProductionClaim === 'boolean' && activation.exochainProductionClaim !== activation.allowed) {
    blocks.push('production_trust_activation_claim_state_mismatch');
  }
  if (!Array.isArray(activation.blockedBy)) {
    blocks.push('production_trust_activation_blockers_invalid');
  } else {
    rawBlockedBy.push(...activation.blockedBy);
    if (normalizeBlockedBy(activation.blockedBy).unsafeBlockedByCount > 0) {
      blocks.push('production_trust_activation_blocker_payload_disclosure');
    }
  }

  if (requiresPublicClaimReviewLineage(input, activation)) {
    const roleDashboardRoles = sortedTextList(activation.publicClaimReviewProductionClaimLiftRoleDashboardRoles);
    if (!hasPublicClaimReviewLineage(activation)) {
      blocks.push('public_claim_review_lineage_absent');
    }
    if (!isDigest(activation.publicClaimReviewReceiptHash)) {
      blocks.push('public_claim_review_receipt_hash_invalid');
    }
    if (!isDigest(activation.publicClaimReviewPackageHash)) {
      blocks.push('public_claim_review_package_hash_invalid');
    }
    if (activation.publicClaimReviewStatus !== 'approved_for_public_use') {
      blocks.push('public_claim_review_status_invalid');
    }
    if (activation.publicClaimReviewTrustState !== 'inactive') {
      blocks.push('public_claim_review_trust_state_invalid');
    }
    if (activation.publicClaimReviewPublicUseAuthorized !== true) {
      blocks.push('public_claim_review_public_use_not_authorized');
    }
    if (!isDigest(activation.publicClaimReviewProductionClaimLiftReceiptHash)) {
      blocks.push('public_claim_review_production_claim_lift_receipt_hash_invalid');
    }
    if (activation.publicClaimReviewProductionClaimLiftTrustState !== 'inactive') {
      blocks.push('public_claim_review_production_claim_lift_state_invalid');
    }
    if (activation.publicClaimReviewProductionClaimLiftCanLiftProductionClaim !== false) {
      blocks.push('public_claim_review_production_claim_lift_public_claim_forbidden');
    }
    if (!isDigest(activation.publicClaimReviewProductionClaimLiftRoleDashboardProviderReceiptHash)) {
      blocks.push('public_claim_review_production_claim_lift_role_dashboard_provider_receipt_hash_invalid');
    }
    if (!isDigest(activation.publicClaimReviewProductionClaimLiftRoleDashboardProviderSummaryHash)) {
      blocks.push('public_claim_review_production_claim_lift_role_dashboard_provider_summary_hash_invalid');
    }
    if (!isDigest(activation.publicClaimReviewProductionClaimLiftRoleDashboardProviderTrustStateViewHash)) {
      blocks.push('public_claim_review_production_claim_lift_role_dashboard_provider_trust_state_view_hash_invalid');
    }
    if (!isDigest(activation.publicClaimReviewProductionClaimLiftRoleDashboardReadinessReceiptHash)) {
      blocks.push('public_claim_review_production_claim_lift_role_dashboard_readiness_receipt_hash_invalid');
    }
    if (!isDigest(activation.publicClaimReviewProductionClaimLiftRoleDashboardReadinessSummaryHash)) {
      blocks.push('public_claim_review_production_claim_lift_role_dashboard_readiness_summary_hash_invalid');
    }
    if (!isDigest(activation.publicClaimReviewProductionClaimLiftRoleDashboardReadinessTrustStateViewHash)) {
      blocks.push('public_claim_review_production_claim_lift_role_dashboard_readiness_trust_state_view_hash_invalid');
    }
    if (!isDigest(activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash)) {
      blocks.push('public_claim_review_production_claim_lift_runtime_source_provider_role_dashboard_receipt_hash_invalid');
    }
    if (!isDigest(activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash)) {
      blocks.push('public_claim_review_production_claim_lift_runtime_source_provider_role_dashboard_summary_hash_invalid');
    }
    if (!isDigest(activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash)) {
      blocks.push(
        'public_claim_review_production_claim_lift_runtime_source_provider_role_dashboard_trust_state_view_hash_invalid',
      );
    }
    if (!isDigest(activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash)) {
      blocks.push('public_claim_review_production_claim_lift_runtime_source_readiness_role_dashboard_receipt_hash_invalid');
    }
    if (!isDigest(activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash)) {
      blocks.push('public_claim_review_production_claim_lift_runtime_source_readiness_role_dashboard_summary_hash_invalid');
    }
    if (!isDigest(activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash)) {
      blocks.push(
        'public_claim_review_production_claim_lift_runtime_source_readiness_role_dashboard_trust_state_view_hash_invalid',
      );
    }
    if (!isDigest(activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardReceiptHash)) {
      blocks.push(
        'public_claim_review_production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_receipt_hash_invalid',
      );
    }
    if (!isDigest(activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardSummaryHash)) {
      blocks.push(
        'public_claim_review_production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_summary_hash_invalid',
      );
    }
    if (
      !isDigest(
        activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash,
      )
    ) {
      blocks.push(
        'public_claim_review_production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_trust_state_view_hash_invalid',
      );
    }
    if (
      !isDigest(
        activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash,
      )
    ) {
      blocks.push(
        'public_claim_review_production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_receipt_hash_invalid',
      );
    }
    if (
      !isDigest(
        activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash,
      )
    ) {
      blocks.push(
        'public_claim_review_production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_summary_hash_invalid',
      );
    }
    if (
      !isDigest(
        activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
      )
    ) {
      blocks.push(
        'public_claim_review_production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_trust_state_view_hash_invalid',
      );
    }
    if (
      isDigest(activation.publicClaimReviewProductionClaimLiftRoleDashboardProviderReceiptHash) &&
      isDigest(activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash) &&
      activation.publicClaimReviewProductionClaimLiftRoleDashboardProviderReceiptHash !==
        activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash
    ) {
      blocks.push('public_claim_review_production_claim_lift_runtime_source_provider_role_dashboard_receipt_mismatch');
    }
    if (
      isDigest(activation.publicClaimReviewProductionClaimLiftRoleDashboardProviderSummaryHash) &&
      isDigest(activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash) &&
      activation.publicClaimReviewProductionClaimLiftRoleDashboardProviderSummaryHash !==
        activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash
    ) {
      blocks.push('public_claim_review_production_claim_lift_runtime_source_provider_role_dashboard_summary_mismatch');
    }
    if (
      isDigest(activation.publicClaimReviewProductionClaimLiftRoleDashboardProviderTrustStateViewHash) &&
      isDigest(activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash) &&
      activation.publicClaimReviewProductionClaimLiftRoleDashboardProviderTrustStateViewHash !==
        activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash
    ) {
      blocks.push(
        'public_claim_review_production_claim_lift_runtime_source_provider_role_dashboard_trust_state_view_mismatch',
      );
    }
    if (
      isDigest(activation.publicClaimReviewProductionClaimLiftRoleDashboardReadinessReceiptHash) &&
      isDigest(activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash) &&
      activation.publicClaimReviewProductionClaimLiftRoleDashboardReadinessReceiptHash !==
        activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash
    ) {
      blocks.push('public_claim_review_production_claim_lift_runtime_source_readiness_role_dashboard_receipt_mismatch');
    }
    if (
      isDigest(activation.publicClaimReviewProductionClaimLiftRoleDashboardReadinessSummaryHash) &&
      isDigest(activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash) &&
      activation.publicClaimReviewProductionClaimLiftRoleDashboardReadinessSummaryHash !==
        activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash
    ) {
      blocks.push('public_claim_review_production_claim_lift_runtime_source_readiness_role_dashboard_summary_mismatch');
    }
    if (
      isDigest(activation.publicClaimReviewProductionClaimLiftRoleDashboardReadinessTrustStateViewHash) &&
      isDigest(activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash) &&
      activation.publicClaimReviewProductionClaimLiftRoleDashboardReadinessTrustStateViewHash !==
        activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash
    ) {
      blocks.push(
        'public_claim_review_production_claim_lift_runtime_source_readiness_role_dashboard_trust_state_view_mismatch',
      );
    }
    if (
      isDigest(activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash) &&
      isDigest(
        activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardReceiptHash,
      ) &&
      activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash !==
        activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardReceiptHash
    ) {
      blocks.push(
        'public_claim_review_production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_receipt_mismatch',
      );
    }
    if (
      isDigest(activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash) &&
      isDigest(
        activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardSummaryHash,
      ) &&
      activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash !==
        activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardSummaryHash
    ) {
      blocks.push(
        'public_claim_review_production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_summary_mismatch',
      );
    }
    if (
      isDigest(activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash) &&
      isDigest(
        activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash,
      ) &&
      activation.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash !==
        activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash
    ) {
      blocks.push(
        'public_claim_review_production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_trust_state_view_mismatch',
      );
    }
    if (
      isDigest(activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash) &&
      isDigest(
        activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash,
      ) &&
      activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash !==
        activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash
    ) {
      blocks.push(
        'public_claim_review_production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_receipt_mismatch',
      );
    }
    if (
      isDigest(activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash) &&
      isDigest(
        activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash,
      ) &&
      activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash !==
        activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash
    ) {
      blocks.push(
        'public_claim_review_production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_summary_mismatch',
      );
    }
    if (
      isDigest(activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash) &&
      isDigest(
        activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
      ) &&
      activation.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash !==
        activation.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash
    ) {
      blocks.push(
        'public_claim_review_production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_trust_state_view_mismatch',
      );
    }
    for (const role of REQUIRED_ROLE_DASHBOARD_ROLES) {
      if (!roleDashboardRoles.includes(role)) {
        blocks.push(`public_claim_review_production_claim_lift_role_dashboard_role_missing:${role}`);
      }
    }
    for (const role of roleDashboardRoles) {
      if (!REQUIRED_ROLE_DASHBOARD_ROLES.includes(role)) {
        blocks.push(`public_claim_review_production_claim_lift_role_dashboard_role_unsupported:${role}`);
      }
    }
  }

  return {
    accepted: blocks.length === 0,
    blocks,
    rawBlockedBy,
    lineage: summarizeProductionTrustActivation(activation),
  };
}

export function buildTrustStateView(input) {
  const activationLineage = productionTrustActivationBlocks(input);
  const activationState = activationLineage.lineage?.activationState;
  const requestedState = typeof input?.state === 'string' ? input.state : activationState ?? 'inactive';
  const requestedStatus = Object.hasOwn(TRUST_STATE_COPY, requestedState) ? requestedState : 'inactive';
  const { blockedBy, unsafeBlockedByCount } = normalizeBlockedBy([
    ...(Array.isArray(input?.blockedBy) ? input.blockedBy : []),
    ...activationLineage.rawBlockedBy,
    ...activationLineage.blocks,
  ]);
  const status = effectiveStatus(
    requestedStatus,
    blockedBy,
    unsafeBlockedByCount,
    requiresProductionTrustActivationLineage(input) && !activationLineage.accepted,
  );
  const copy = TRUST_STATE_COPY[status];
  const canShowProductionTrustClaim =
    status === 'verified' &&
    blockedBy.length === 0 &&
    unsafeBlockedByCount === 0 &&
    (!requiresProductionTrustActivationLineage(input) || activationLineage.accepted);

  return {
    schema: 'cybermedica.trust_state_view.v1',
    requestedStatus,
    status,
    severity: copy.severity,
    primaryText: copy.primaryText,
    secondaryText: copy.secondaryText,
    blockedBy,
    unsafeBlockedByCount,
    bobEscalations: bobEscalationsFor(blockedBy),
    actionsDisabled: !canShowProductionTrustClaim,
    canShowProductionTrustClaim,
    activationLineageAccepted: activationLineage.accepted,
    productionTrustActivationLineage: activationLineage.lineage,
  };
}
