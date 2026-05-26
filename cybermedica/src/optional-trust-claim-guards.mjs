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
const GUARD_SCHEMA = 'cybermedica.optional_trust_claim_guard.v1';
const REQUIRED_PERMISSION = 'optional_trust_claim_review';
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

const REQUIRED_GATES = Object.freeze(['PTAG-012', 'PTAG-013', 'PTAG-014', 'PTAG-015']);
const REQUIRED_CONTEXT_REFS = Object.freeze([
  'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
]);
const POLICY_STATUSES = new Set(['active']);
const SURFACE_GATE_TYPES = new Set([
  'billing_export',
  'identity_risk_ui',
  'ui_enforcement_source',
  'workflow_output',
]);

const RAW_CLAIM_FIELDS = new Set([
  'claimbody',
  'claimtext',
  'claimtextbody',
  'freeformclaim',
  'rawclaim',
  'rawclaimtext',
  'rawcommandbaseclaim',
  'raweconomyclaim',
  'rawexoforgeclaim',
  'rawnotes',
  'rawoptionalclaim',
  'rawsurfacecopy',
  'rawworkflownodeoutput',
  'reviewnotes',
  'sourcedocumentbody',
  'workflowoutputbody',
]);

const SECRET_CLAIM_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'bootstraptoken',
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

function assertNoRawClaimContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawClaimContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_CLAIM_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw optional trust claim field is not allowed at ${path}.${key}`);
    }
    if (SECRET_CLAIM_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`optional trust claim secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawClaimContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawClaimContent(input ?? {});
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

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_optional_claim_reviewer_required');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'optional_claim_guard_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'policy_not_active');
  addReason(reasons, policy?.optionalCapabilitiesDefaultOff !== true, 'policy_default_off_rule_absent');
  addReason(reasons, policy?.noProductionTrustClaims !== true, 'policy_production_trust_claim_forbidden');
  addReason(reasons, policy?.metadataOnly !== true, 'policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'policy_evaluation_time_invalid');

  const requiredGateIds = sortedTextList(policy?.requiredActivationGateIds);
  const contextDocRefs = sortedTextList(policy?.contextDocRefs);

  for (const gateId of REQUIRED_GATES) {
    addReason(reasons, !requiredGateIds.includes(gateId), `policy_required_gate_missing:${gateId}`);
  }
  for (const contextRef of REQUIRED_CONTEXT_REFS) {
    addReason(reasons, !contextDocRefs.includes(contextRef), `policy_context_ref_missing:${contextRef}`);
  }

  return {
    contextDocRefs,
    evaluatedAtHlc: policy?.evaluatedAtHlc ?? null,
    requiredGateIds,
  };
}

function capabilityActivationEvidencePresent(capability, gateId) {
  if (gateId === 'PTAG-012') {
    return isDigest(capability?.privacyReviewHash) &&
      isDigest(capability?.persistenceEvidenceHash) &&
      isDigest(capability?.testEvidenceHash);
  }
  if (gateId === 'PTAG-013') {
    return isDigest(capability?.productionSettlementContractHash) &&
      isDigest(capability?.regulatoryAccountingReviewHash) &&
      isDigest(capability?.testEvidenceHash);
  }
  if (gateId === 'PTAG-014') {
    return isDigest(capability?.intakeRecordHash) &&
      isDigest(capability?.runtimeAdapterProofHash) &&
      isDigest(capability?.failClosedTestHash);
  }
  return true;
}

function capabilityState(capability, gateId) {
  if (gateId === 'PTAG-015') {
    return capability?.workflowConfigBounded === true &&
      Number.isSafeInteger(capability?.maxIterations) &&
      capability.maxIterations > 0 &&
      capability.maxIterations <= 25 &&
      hasText(capability?.stopConditionRef) &&
      hasText(capability?.escalationPathRef) &&
      capability?.untrustedOutputBoundary === true &&
      capability?.humanFinalReview === true
      ? 'bounded_human_reviewed_inactive'
      : 'blocked';
  }
  return capability?.enabled === false && capability?.defaultOff === true
    ? 'disabled_default_off'
    : 'blocked';
}

function evaluateCapability(capability, policySummary, reasons) {
  const gateId = capability?.gateId ?? 'unknown';
  addReason(reasons, !REQUIRED_GATES.includes(gateId), `optional_capability_gate_unsupported:${gateId}`);
  addReason(reasons, !hasText(capability?.capabilityRef), `optional_capability_ref_absent:${gateId}`);
  addReason(reasons, !hasText(capability?.sourceRef), `optional_capability_source_absent:${gateId}`);
  addReason(reasons, capability?.metadataOnly !== true, `optional_capability_metadata_boundary_invalid:${gateId}`);
  addReason(reasons, capability?.protectedContentExcluded !== true, `optional_capability_protected_boundary_invalid:${gateId}`);
  addReason(reasons, capability?.exochainProductionClaim === true, `optional_capability_production_claim_forbidden:${gateId}`);
  addReason(reasons, hlcTuple(capability?.reviewedAtHlc) === null, `optional_capability_review_time_invalid:${gateId}`);
  addReason(
    reasons,
    hlcBefore(capability?.reviewedAtHlc, policySummary.evaluatedAtHlc),
    `optional_capability_review_before_policy_evaluation:${gateId}`,
  );

  if (gateId === 'PTAG-012') {
    addReason(reasons, capability?.claimTextPresent === true, 'ptag_012_claim_text_present');
    addReason(
      reasons,
      capability?.enabled === true && !capabilityActivationEvidencePresent(capability, gateId),
      'ptag_012_feature_enabled_without_activation_evidence',
    );
    addReason(reasons, capability?.enabled === true && capability?.defaultOff !== true, 'ptag_012_feature_default_on_forbidden');
  }

  if (gateId === 'PTAG-013') {
    addReason(reasons, capability?.settlementFinalityClaim === true, 'ptag_013_settlement_finality_claim_forbidden');
    addReason(
      reasons,
      capability?.enabled === true && !capabilityActivationEvidencePresent(capability, gateId),
      'ptag_013_feature_enabled_without_activation_evidence',
    );
    addReason(reasons, capability?.enabled === true && capability?.defaultOff !== true, 'ptag_013_feature_default_on_forbidden');
  }

  if (gateId === 'PTAG-014') {
    addReason(reasons, capability?.commandBaseEnforcementClaim === true, 'ptag_014_commandbase_enforcement_claim_forbidden');
    addReason(
      reasons,
      capability?.enabled === true && !capabilityActivationEvidencePresent(capability, gateId),
      'ptag_014_feature_enabled_without_activation_evidence',
    );
    addReason(reasons, capability?.enabled === true && capability?.defaultOff !== true, 'ptag_014_feature_default_on_forbidden');
  }

  if (gateId === 'PTAG-015') {
    addReason(reasons, capability?.governanceAuthorityClaim === true, 'ptag_015_governance_authority_claim_forbidden');
    addReason(reasons, capability?.workflowConfigBounded !== true, 'ptag_015_workflow_loop_unbounded');
    addReason(
      reasons,
      !Number.isSafeInteger(capability?.maxIterations) || capability.maxIterations <= 0,
      'ptag_015_workflow_max_iterations_invalid',
    );
    addReason(
      reasons,
      Number.isSafeInteger(capability?.maxIterations) && capability.maxIterations > 25,
      'ptag_015_workflow_max_iterations_exceeds_limit',
    );
    addReason(reasons, !hasText(capability?.stopConditionRef), 'ptag_015_workflow_stop_condition_absent');
    addReason(reasons, !hasText(capability?.escalationPathRef), 'ptag_015_workflow_escalation_path_absent');
    addReason(reasons, capability?.untrustedOutputBoundary !== true, 'ptag_015_workflow_output_boundary_absent');
    addReason(reasons, capability?.humanFinalReview !== true, 'ptag_015_human_final_review_absent');
  }

  return {
    capabilityRef: capability?.capabilityRef ?? null,
    defaultOff: capability?.defaultOff === true,
    enabled: capability?.enabled === true,
    gateId,
    sourceRef: capability?.sourceRef ?? null,
    state: capabilityState(capability, gateId),
  };
}

function evaluateCapabilities(capabilities, policySummary, reasons) {
  const records = Array.isArray(capabilities) ? capabilities : [];
  addReason(reasons, records.length === 0, 'optional_capabilities_absent');

  const seen = new Set();
  const states = {};
  for (const capability of [...records].sort((left, right) => String(left?.gateId).localeCompare(String(right?.gateId)))) {
    const gateId = capability?.gateId ?? 'unknown';
    addReason(reasons, seen.has(gateId), `optional_capability_duplicate:${gateId}`);
    seen.add(gateId);
    if (REQUIRED_GATES.includes(gateId)) {
      states[gateId] = evaluateCapability(capability, policySummary, reasons);
    } else {
      evaluateCapability(capability, policySummary, reasons);
    }
  }

  for (const gateId of REQUIRED_GATES) {
    if (!seen.has(gateId)) {
      reasons.push(`optional_capability_missing:${gateId}`);
      states[gateId] = {
        capabilityRef: null,
        defaultOff: false,
        enabled: false,
        gateId,
        sourceRef: null,
        state: 'blocked',
      };
    }
  }

  return states;
}

function evaluateClaimSurface(surface, policySummary, reasons) {
  const gateId = surface?.gateId ?? 'unknown';
  const surfaceRef = surface?.surfaceRef ?? 'unknown';
  addReason(reasons, !REQUIRED_GATES.includes(gateId), `claim_surface_gate_unsupported:${surfaceRef}`);
  addReason(reasons, !hasText(surface?.surfaceRef), `claim_surface_ref_absent:${surfaceRef}`);
  addReason(reasons, !SURFACE_GATE_TYPES.has(surface?.surfaceType), `claim_surface_type_invalid:${surfaceRef}`);
  addReason(reasons, !isDigest(surface?.claimTextHash), `claim_surface_hash_invalid:${surfaceRef}`);
  addReason(reasons, surface?.humanReviewed !== true, `claim_surface_human_review_absent:${surfaceRef}`);
  addReason(reasons, surface?.metadataOnly !== true, `claim_surface_metadata_boundary_invalid:${surfaceRef}`);
  addReason(reasons, surface?.protectedContentExcluded !== true, `claim_surface_protected_boundary_invalid:${surfaceRef}`);
  addReason(reasons, hlcTuple(surface?.reviewedAtHlc) === null, `claim_surface_review_time_invalid:${surfaceRef}`);
  addReason(
    reasons,
    hlcBefore(surface?.reviewedAtHlc, policySummary.evaluatedAtHlc),
    `claim_surface_review_before_policy_evaluation:${surfaceRef}`,
  );

  if (gateId === 'PTAG-012') {
    addReason(
      reasons,
      surface?.behavioralDeviceTrustScoreDisplayed === true || surface?.trustScoreProductionClaim === true,
      `ptag_012_surface_trust_score_claim_forbidden:${surfaceRef}`,
    );
  }
  if (gateId === 'PTAG-013') {
    addReason(
      reasons,
      surface?.settlementFinalityClaim === true,
      `ptag_013_surface_settlement_finality_claim_forbidden:${surfaceRef}`,
    );
  }
  if (gateId === 'PTAG-014') {
    addReason(
      reasons,
      surface?.commandBaseEnforcementClaim === true,
      `ptag_014_surface_commandbase_enforcement_claim_forbidden:${surfaceRef}`,
    );
  }
  if (gateId === 'PTAG-015') {
    addReason(
      reasons,
      surface?.exoforgeGovernanceAuthorityClaim === true || surface?.archonGovernanceAuthorityClaim === true,
      `ptag_015_surface_agent_governance_claim_forbidden:${surfaceRef}`,
    );
    addReason(
      reasons,
      surface?.agentOutputAuthorizesMerge === true,
      `agent_output_merge_authority_forbidden:${surfaceRef}`,
    );
    addReason(
      reasons,
      surface?.agentOutputAuthorizesGovernanceDecision === true,
      `agent_output_governance_authority_forbidden:${surfaceRef}`,
    );
    addReason(
      reasons,
      surface?.agentOutputAuthorizesTrustClaim === true,
      `agent_output_trust_claim_authority_forbidden:${surfaceRef}`,
    );
  }

  return {
    gateId,
    surfaceRef,
    surfaceType: surface?.surfaceType ?? null,
  };
}

function evaluateClaimSurfaces(surfaces, policySummary, reasons) {
  const records = Array.isArray(surfaces) ? surfaces : [];
  addReason(reasons, records.length === 0, 'claim_surfaces_absent');

  const seenRefs = new Set();
  const coveredGateIds = [];
  const cleanSurfaceRefs = [];
  const summaries = [];
  for (const surface of [...records].sort((left, right) => String(left?.surfaceRef).localeCompare(String(right?.surfaceRef)))) {
    const surfaceRef = surface?.surfaceRef ?? 'unknown';
    const beforeCount = reasons.length;
    addReason(reasons, seenRefs.has(surfaceRef), `claim_surface_duplicate:${surfaceRef}`);
    seenRefs.add(surfaceRef);
    const summary = evaluateClaimSurface(surface, policySummary, reasons);
    summaries.push(summary);
    if (REQUIRED_GATES.includes(summary.gateId)) {
      coveredGateIds.push(summary.gateId);
    }
    if (reasons.length === beforeCount) {
      cleanSurfaceRefs.push(surfaceRef);
    }
  }

  for (const gateId of REQUIRED_GATES) {
    addReason(reasons, !coveredGateIds.includes(gateId), `claim_surface_gate_missing:${gateId}`);
  }

  return {
    cleanSurfaceRefs: uniqueSorted(cleanSurfaceRefs),
    summaries,
  };
}

function evaluateHumanReview(review, reasons) {
  const reviewedGateIds = sortedTextList(review?.reviewedGateIds);
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_review_final_authority_absent');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'human_review_production_trust_claim_forbidden');
  addReason(reasons, !isDigest(review?.evidenceHash), 'human_review_evidence_hash_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');

  for (const gateId of REQUIRED_GATES) {
    addReason(reasons, !reviewedGateIds.includes(gateId), `human_review_gate_coverage_missing:${gateId}`);
  }

  return {
    reviewedGateIds,
    reviewedAtHlc: review?.reviewedAtHlc ?? null,
    reviewerDid: review?.reviewerDid ?? null,
  };
}

function buildGuardReport(input, policySummary, capabilityStates, claimSurfaceSummary, humanReviewSummary) {
  const defaultOffGateIds = REQUIRED_GATES.filter((gateId) => capabilityStates[gateId]?.defaultOff === true);

  return {
    schema: GUARD_SCHEMA,
    tenantId: input?.tenantId ?? null,
    policyRef: input?.claimPolicy?.policyRef ?? null,
    gateIds: [...REQUIRED_GATES],
    trustState: 'inactive',
    exochainProductionClaim: false,
    noProductionTrustClaim: input?.claimPolicy?.noProductionTrustClaims === true && input?.humanReview?.noProductionTrustClaim === true,
    defaultOffGateIds,
    capabilityStates,
    claimFreeSurfaceRefs: claimSurfaceSummary.cleanSurfaceRefs,
    contextDocRefs: policySummary.contextDocRefs,
    humanReview: {
      reviewedGateIds: humanReviewSummary.reviewedGateIds,
      reviewedAtHlc: humanReviewSummary.reviewedAtHlc,
      reviewerDid: humanReviewSummary.reviewerDid,
    },
    sourceEvidence: [
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md#PTAG-012',
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md#PTAG-013',
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md#PTAG-014',
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md#PTAG-015',
    ],
  };
}

function createGuardReceipt(input, guardReport) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactHash: sha256Hex(guardReport),
    artifactType: 'optional_trust_claim_guard',
    artifactVersion: 'v1',
    classification: 'optional_trust_claim_guard_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    sensitivityTags: ['optional_trust_claims', 'metadata_only', 'inactive_trust_state'],
    sourceSystem: 'cybermedica.optional_trust_claim_guards',
  });
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

export function evaluateOptionalTrustClaimGuards(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
  const policySummary = evaluatePolicy(input?.claimPolicy, reasons);
  const capabilityStates = evaluateCapabilities(input?.optionalCapabilities, policySummary, reasons);
  const claimSurfaceSummary = evaluateClaimSurfaces(input?.claimSurfaces, policySummary, reasons);
  const humanReviewSummary = evaluateHumanReview(input?.humanReview, reasons);
  const finalReasons = uniqueReasons(reasons);
  const guardReport = buildGuardReport(input, policySummary, capabilityStates, claimSurfaceSummary, humanReviewSummary);

  if (finalReasons.length > 0) {
    return {
      schema: 'cybermedica.optional_trust_claim_guard_decision.v1',
      decision: 'denied',
      failClosed: true,
      trustState: 'inactive',
      exochainProductionClaim: false,
      reasons: finalReasons,
      guardReport,
    };
  }

  return {
    schema: 'cybermedica.optional_trust_claim_guard_decision.v1',
    decision: 'permitted',
    failClosed: false,
    trustState: 'inactive',
    exochainProductionClaim: false,
    reasons: [],
    guardReport,
    receipt: createGuardReceipt(input, guardReport),
  };
}
