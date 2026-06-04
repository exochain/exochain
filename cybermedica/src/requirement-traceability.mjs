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
const TRACEABILITY_SCHEMA = 'cybermedica.requirement_traceability_matrix.v1';
const DECISION_SCHEMA = 'cybermedica.requirement_traceability_decision.v1';
const REQUIRED_PERMISSION = 'traceability_review';
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

const REQUIRED_REQUIREMENT_FAMILIES = Object.freeze([
  'activation_gate',
  'context_obligation',
  'functional',
  'nonfunctional',
]);

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

const REQUIRED_MASTER_PRD_REQUIREMENT_IDS = Object.freeze([
  'FR-001',
  'FR-002',
  'FR-003',
  'FR-004',
  'FR-005',
  'FR-006',
  'FR-007',
  'FR-008',
  'FR-009',
  'FR-010',
  'FR-011',
  'FR-012',
  'FR-013',
  'FR-014',
  'FR-015',
  'FR-016',
  'FR-017',
  'FR-018',
  'FR-019',
  'FR-020',
  'FR-021',
  'FR-022',
  'FR-023',
  'FR-024',
  'FR-025',
  'FR-026',
  'FR-027',
  'FR-028',
  'FR-029',
  'FR-030',
  'FR-031',
  'FR-032',
  'FR-033',
  'FR-034',
  'FR-035',
  'FR-036',
  'FR-037',
  'FR-038',
  'FR-039',
  'FR-040',
  'FR-041',
  'FR-042',
  'FR-043',
  'FR-044',
  'FR-045',
  'FR-046',
  'FR-047',
  'FR-048',
  'FR-049',
  'FR-050',
  'NFR-001',
  'NFR-002',
  'NFR-003',
  'NFR-004',
  'NFR-005',
  'NFR-006',
  'NFR-007',
  'NFR-008',
  'NFR-009',
  'NFR-010',
  'NFR-011',
  'NFR-012',
  'NFR-013',
  'NFR-014',
]);

const REQUIRED_MASTER_PRD_REQUIREMENT_ID_SET = new Set(REQUIRED_MASTER_PRD_REQUIREMENT_IDS);

const REQUIRED_CONTEXT_DOC_REFS = Object.freeze([
  'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
  'docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md',
  'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
]);

const DEFAULT_ACTIVATION_BLOCKER_IDS = Object.freeze([
  'PTAG-001',
  'PTAG-002',
  'PTAG-008',
  'PTAG-015',
  'PTAG-016',
  'PTAG-017',
]);

const DEFAULT_BOB_ESCALATION_IDS = Object.freeze([
  'ESC-CONSENT-LEGAL',
  'ESC-HUMAN-PROOFING',
  'ESC-OPS-SECRETS',
  'ESC-ROLE-MATRIX',
  'ESC-ROOT-ARTIFACT-STORE',
  'ESC-ROOT-DEPLOYMENT',
  'ESC-ROOT-OWNER',
  'ESC-ROOT-ROSTER',
  'ESC-RUNTIME',
]);

const REQUIRED_MODULE_REFS_BY_REQUIREMENT = Object.freeze({
  'FR-016': Object.freeze(['src/consent-materials.mjs', 'src/participant-data-sharing-consent.mjs']),
  'FR-017': Object.freeze(['src/participant-protection.mjs']),
  'FR-018': Object.freeze(['src/participant-protection.mjs']),
});
const REQUIRED_TEST_REFS_BY_REQUIREMENT = Object.freeze({
  'FR-016': Object.freeze(['tests/consent-materials.test.mjs', 'tests/participant-data-sharing-consent.test.mjs']),
  'FR-017': Object.freeze(['tests/participant-protection.test.mjs']),
  'FR-018': Object.freeze(['tests/participant-protection.test.mjs']),
});
const REQUIRED_EXOCHAIN_PRIMITIVE_REFS_BY_REQUIREMENT = Object.freeze({
  'FR-016': Object.freeze(['crates/exo-consent/src/bailment.rs', 'crates/exo-consent/src/policy.rs']),
  'FR-017': Object.freeze(['crates/exo-consent/src/bailment.rs', 'crates/exo-core/src/types.rs']),
  'FR-018': Object.freeze(['crates/exo-consent/src/gatekeeper.rs', 'crates/exo-core/src/types.rs']),
});
const REQUIRED_ADAPTER_BOUNDARY_REFS_BY_REQUIREMENT = Object.freeze({
  'FR-016': Object.freeze(['src/consent-materials.mjs', 'src/participant-data-sharing-consent.mjs']),
  'FR-017': Object.freeze(['src/participant-protection.mjs']),
  'FR-018': Object.freeze(['src/participant-protection.mjs']),
});

const POLICY_STATUSES = new Set(['active']);
const REQUIREMENT_FAMILIES = new Set(REQUIRED_REQUIREMENT_FAMILIES);
const IMPLEMENTED_STATUSES = new Set(['implemented', 'activation_only_blocked']);
const HUMAN_REVIEW_DECISIONS = new Set(['traceability_accepted_inactive_trust', 'hold_for_traceability_gap']);
const MASTER_PRD_REQUIREMENT_ID_PREFIX = /^(?:FR|NFR)-/u;

const RAW_TRACEABILITY_FIELDS = new Set([
  'acceptancecopy',
  'body',
  'commentary',
  'content',
  'freetext',
  'freetextnote',
  'prdtext',
  'rawactivationevidence',
  'rawcontext',
  'rawdecision',
  'rawevidence',
  'rawrequirement',
  'rawrequirementtext',
  'rawsource',
  'rawsourcedata',
  'rawtraceabilitytext',
  'rawvalidationoutput',
  'requirementnarrative',
  'requirementtext',
  'reviewnotes',
  'sourcedocumentbody',
  'validationlog',
]);

const SECRET_TRACEABILITY_FIELDS = new Set([
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

function requiredRefsFor(requirementId, refTable) {
  return Array.isArray(refTable[requirementId]) ? refTable[requirementId] : [];
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

function assertNoRawTraceabilityContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawTraceabilityContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_TRACEABILITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw requirement traceability content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_TRACEABILITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`requirement traceability secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawTraceabilityContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawTraceabilityContent(input ?? {});
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
  addReason(reasons, input?.actor?.kind !== 'human', 'human_traceability_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'traceability_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateTraceabilityPolicy(policy, reasons) {
  const requiredFamilies = sortedTextList(policy?.requiredRequirementFamilies);
  const requiredLayers = sortedTextList(policy?.requiredDoctrineLayers);
  const requiredContextDocRefs = sortedTextList(policy?.requiredContextDocRefs);
  const allowedActivationBlockerIds = sortedTextList(policy?.allowedActivationBlockerIds);
  const allowedBobEscalationIds = sortedTextList(policy?.allowedBobEscalationIds);

  addReason(reasons, !hasText(policy?.policyRef), 'traceability_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'traceability_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'traceability_policy_not_active');
  addReason(reasons, policy?.rootVerificationRequiredForTrustClaims !== true, 'root_verification_gate_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'traceability_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'traceability_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'traceability_policy_time_invalid');

  evaluateRequiredSet(
    requiredFamilies,
    REQUIRED_REQUIREMENT_FAMILIES,
    'policy_requirement_family_missing',
    'policy_requirement_family_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    requiredLayers,
    REQUIRED_DOCTRINE_LAYERS,
    'policy_doctrine_layer_missing',
    'policy_doctrine_layer_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    requiredContextDocRefs,
    REQUIRED_CONTEXT_DOC_REFS,
    'context_doc_ref_missing',
    'context_doc_ref_unsupported',
    reasons,
  );

  return {
    allowedActivationBlockerIds:
      allowedActivationBlockerIds.length > 0 ? allowedActivationBlockerIds : [...DEFAULT_ACTIVATION_BLOCKER_IDS],
    allowedBobEscalationIds:
      allowedBobEscalationIds.length > 0 ? allowedBobEscalationIds : [...DEFAULT_BOB_ESCALATION_IDS],
    requiredContextDocRefs: requiredContextDocRefs.length > 0 ? requiredContextDocRefs : [...REQUIRED_CONTEXT_DOC_REFS],
    requiredDoctrineLayers: requiredLayers.length > 0 ? requiredLayers : [...REQUIRED_DOCTRINE_LAYERS],
    requiredRequirementFamilies: requiredFamilies.length > 0 ? requiredFamilies : [...REQUIRED_REQUIREMENT_FAMILIES],
  };
}

function evaluateMatrixCycle(cycle, policy, reasons) {
  addReason(reasons, !hasText(cycle?.matrixRef), 'matrix_cycle_ref_absent');
  addReason(reasons, !hasText(cycle?.releaseCandidateRef), 'release_candidate_ref_absent');
  addReason(reasons, cycle?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, cycle?.metadataOnly !== true, 'matrix_cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'matrix_cycle_protected_boundary_invalid');

  const ordered = [
    ['openedAtHlc', cycle?.openedAtHlc],
    ['compiledAtHlc', cycle?.compiledAtHlc],
    ['humanReviewedAtHlc', cycle?.humanReviewedAtHlc],
    ['validationRecordedAtHlc', cycle?.validationRecordedAtHlc],
    ['auditRecordedAtHlc', cycle?.auditRecordedAtHlc],
  ];

  for (const [label, value] of ordered) {
    addReason(reasons, hlcTuple(value) === null, `matrix_cycle_${label}_invalid`);
  }
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, cycle?.openedAtHlc), 'traceability_policy_after_cycle_open');
  for (let index = 1; index < ordered.length; index += 1) {
    const [previousLabel, previousValue] = ordered[index - 1];
    const [currentLabel, currentValue] = ordered[index];
    addReason(reasons, hlcBefore(currentValue, previousValue), `matrix_cycle_${currentLabel}_before_${previousLabel}`);
  }
}

function evaluateRequirementRows(rows, policySummary, cycle, reasons) {
  addReason(reasons, !Array.isArray(rows) || rows.length === 0, 'requirement_rows_absent');
  if (!Array.isArray(rows)) {
    return {
      activationOnlyBlockerIds: [],
      bobEscalationIds: [],
      doctrineLayers: [],
      families: [],
      implementedCount: 0,
      requirementIds: [],
      rowSummaries: [],
      totalRequirementCount: 0,
    };
  }

  const families = sortedTextList(rows.map((row) => row?.requirementFamily));
  const doctrineLayers = sortedTextList(rows.map((row) => row?.doctrineLayer));
  const requirementIds = [];
  const rowSummaries = [];
  const activationOnlyBlockerIds = [];
  const bobEscalationIds = [];
  const seenRequirementIds = new Set();
  let implementedCount = 0;

  evaluateRequiredSet(
    families,
    policySummary.requiredRequirementFamilies,
    'requirement_family_missing',
    'requirement_family_unsupported',
    reasons,
  );
  for (const layer of policySummary.requiredDoctrineLayers) {
    addReason(reasons, !doctrineLayers.includes(layer), `doctrine_layer_missing:${layer}`);
  }

  rows.forEach((row, index) => {
    const label = hasText(row?.requirementId) ? row.requirementId : `index_${index}`;
    const moduleRefs = sortedTextList(row?.moduleRefs);
    const testRefs = sortedTextList(row?.testRefs);
    const evidenceHashes = Array.isArray(row?.evidenceHashes)
      ? uniqueSorted(row.evidenceHashes.filter((hash) => isDigest(hash)))
      : isDigest(row?.evidenceHashes)
        ? [row.evidenceHashes]
        : [];
    const exochainPrimitiveRefs = sortedTextList(row?.exochainPrimitiveRefs);
    const adapterBoundaryRefs = sortedTextList(row?.adapterBoundaryRefs);
    const validationCommandRefs = sortedTextList(row?.validationCommandRefs);
    const rowActivationGateIds = sortedTextList(row?.activationGateIds);
    const rowBobEscalationIds = sortedTextList(row?.bobEscalationIds);
    const activationOnlyBlocker = row?.activationOnlyBlocker === true || row?.implementationStatus === 'activation_only_blocked';

    addReason(reasons, !hasText(row?.requirementId), `requirement_id_absent:${label}`);
    addReason(reasons, seenRequirementIds.has(row?.requirementId), `requirement_id_duplicate:${label}`);
    if (hasText(row?.requirementId)) {
      seenRequirementIds.add(row.requirementId);
      requirementIds.push(row.requirementId);
    }
    addReason(
      reasons,
      hasText(row?.requirementId) &&
        MASTER_PRD_REQUIREMENT_ID_PREFIX.test(row.requirementId) &&
        !REQUIRED_MASTER_PRD_REQUIREMENT_ID_SET.has(row.requirementId),
      `requirement_id_unsupported:${label}`,
    );
    addReason(reasons, !REQUIREMENT_FAMILIES.has(row?.requirementFamily), `requirement_family_invalid:${label}`);
    addReason(
      reasons,
      !policySummary.requiredDoctrineLayers.includes(row?.doctrineLayer),
      `requirement_doctrine_layer_invalid:${label}`,
    );
    addReason(reasons, !hasText(row?.sourceRef), `requirement_source_ref_absent:${label}`);
    addReason(reasons, !IMPLEMENTED_STATUSES.has(row?.implementationStatus), `requirement_row_not_implemented:${label}`);
    addReason(reasons, moduleRefs.length === 0, `requirement_module_refs_absent:${label}`);
    for (const requiredRef of requiredRefsFor(label, REQUIRED_MODULE_REFS_BY_REQUIREMENT)) {
      addReason(reasons, !moduleRefs.includes(requiredRef), `requirement_required_module_ref_missing:${label}:${requiredRef}`);
    }
    addReason(reasons, testRefs.length === 0, `requirement_test_refs_absent:${label}`);
    for (const requiredRef of requiredRefsFor(label, REQUIRED_TEST_REFS_BY_REQUIREMENT)) {
      addReason(reasons, !testRefs.includes(requiredRef), `requirement_required_test_ref_missing:${label}:${requiredRef}`);
    }
    addReason(reasons, evidenceHashes.length === 0, `requirement_evidence_hashes_absent:${label}`);
    addReason(reasons, exochainPrimitiveRefs.length === 0, `requirement_exochain_primitives_absent:${label}`);
    for (const requiredRef of requiredRefsFor(label, REQUIRED_EXOCHAIN_PRIMITIVE_REFS_BY_REQUIREMENT)) {
      addReason(
        reasons,
        !exochainPrimitiveRefs.includes(requiredRef),
        `requirement_required_exochain_primitive_ref_missing:${label}:${requiredRef}`,
      );
    }
    addReason(reasons, adapterBoundaryRefs.length === 0, `requirement_adapter_boundary_absent:${label}`);
    for (const requiredRef of requiredRefsFor(label, REQUIRED_ADAPTER_BOUNDARY_REFS_BY_REQUIREMENT)) {
      addReason(
        reasons,
        !adapterBoundaryRefs.includes(requiredRef),
        `requirement_required_adapter_boundary_ref_missing:${label}:${requiredRef}`,
      );
    }
    addReason(reasons, validationCommandRefs.length === 0, `requirement_validation_commands_absent:${label}`);
    addReason(reasons, row?.reviewedByHuman !== true, `requirement_human_review_absent:${label}`);
    addReason(reasons, row?.metadataOnly !== true, `requirement_metadata_boundary_invalid:${label}`);
    addReason(reasons, row?.protectedContentExcluded !== true, `requirement_protected_boundary_invalid:${label}`);
    addReason(reasons, row?.productionTrustClaim === true, `requirement_production_claim_forbidden:${label}`);
    addReason(reasons, row?.blocksBaselineDevelopment === true, `requirement_blocks_baseline:${label}`);
    addReason(reasons, hlcTuple(row?.reviewedAtHlc) === null, `requirement_review_time_invalid:${label}`);
    addReason(reasons, hlcBefore(row?.reviewedAtHlc, cycle?.compiledAtHlc), `requirement_review_before_matrix:${label}`);

    if (activationOnlyBlocker) {
      addReason(reasons, row?.implementationStatus !== 'activation_only_blocked', `activation_blocker_status_invalid:${label}`);
      addReason(reasons, rowActivationGateIds.length === 0, `activation_blocker_gate_absent:${label}`);
      for (const gateId of rowActivationGateIds) {
        addReason(
          reasons,
          !policySummary.allowedActivationBlockerIds.includes(gateId),
          `activation_blocker_not_allowed:${gateId}`,
        );
        if (policySummary.allowedActivationBlockerIds.includes(gateId)) {
          activationOnlyBlockerIds.push(gateId);
        }
      }
      for (const escalationId of rowBobEscalationIds) {
        addReason(
          reasons,
          !policySummary.allowedBobEscalationIds.includes(escalationId),
          `bob_escalation_not_allowed:${escalationId}`,
        );
        if (policySummary.allowedBobEscalationIds.includes(escalationId)) {
          bobEscalationIds.push(escalationId);
        }
      }
    } else {
      implementedCount += 1;
      addReason(reasons, row?.implementationStatus !== 'implemented', `requirement_row_not_implemented:${label}`);
      addReason(reasons, rowActivationGateIds.length > 0, `implemented_requirement_activation_gate_forbidden:${label}`);
    }

    rowSummaries.push({
      activationGateIds: rowActivationGateIds,
      activationOnlyBlocker,
      adapterBoundaryRefs,
      doctrineLayer: row?.doctrineLayer ?? null,
      evidenceHashes,
      exochainPrimitiveRefs,
      implementationStatus: row?.implementationStatus ?? 'invalid',
      moduleRefs,
      requirementFamily: row?.requirementFamily ?? null,
      requirementId: label,
      testRefs,
    });
  });

  for (const requiredRequirementId of REQUIRED_MASTER_PRD_REQUIREMENT_IDS) {
    addReason(reasons, !seenRequirementIds.has(requiredRequirementId), `requirement_id_missing:${requiredRequirementId}`);
  }

  return {
    activationOnlyBlockerIds: uniqueSorted(activationOnlyBlockerIds),
    bobEscalationIds: uniqueSorted(bobEscalationIds),
    doctrineLayers,
    families,
    implementedCount,
    requirementIds: uniqueSorted(requirementIds),
    rowSummaries: rowSummaries.sort((left, right) => left.requirementId.localeCompare(right.requirementId)),
    totalRequirementCount: rows.length,
  };
}

function evaluateValidationEvidence(validation, cycle, reasons) {
  addReason(reasons, validation === null || validation === undefined, 'validation_evidence_absent');
  addReason(reasons, sortedTextList(validation?.commandRefs).length === 0, 'validation_command_refs_absent');
  addReason(reasons, validation?.commandsPassed !== true, 'validation_commands_not_passed');
  addReason(reasons, !Number.isSafeInteger(validation?.testCount) || validation.testCount <= 0, 'validation_test_count_invalid');
  addReason(reasons, !isBasisPoints(validation?.coverageLineBasisPoints), 'validation_coverage_invalid');
  addReason(reasons, validation?.sourceGuardPassed !== true, 'validation_source_guard_absent');
  addReason(reasons, !isDigest(validation?.moduleManifestHash), 'validation_module_manifest_hash_invalid');
  addReason(reasons, !isDigest(validation?.testManifestHash), 'validation_test_manifest_hash_invalid');
  addReason(reasons, validation?.noExochainSourceModified !== true, 'validation_exochain_read_only_absent');
  addReason(reasons, validation?.docsUpdated !== true, 'validation_docs_update_absent');
  addReason(reasons, !isDigest(validation?.evidenceHash), 'validation_evidence_hash_invalid');
  addReason(reasons, validation?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(validation?.recordedAtHlc) === null, 'validation_time_invalid');
  addReason(reasons, hlcBefore(validation?.recordedAtHlc, cycle?.validationRecordedAtHlc), 'validation_before_cycle_validation_step');
}

function evaluateHumanReview(review, cycle, traceabilitySummary, reasons) {
  addReason(reasons, review === null || review === undefined, 'human_review_absent');
  addReason(reasons, !hasText(review?.reviewerDid), 'human_review_reviewer_absent');
  addReason(reasons, sortedTextList(review?.reviewerRoleRefs).length === 0, 'human_review_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.activationOnlyBlockersAccepted !== true, 'activation_only_blockers_not_accepted');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'human_review_production_trust_forbidden');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_review_authority_absent');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, cycle?.humanReviewedAtHlc), 'human_review_before_cycle_review_step');
  addReason(
    reasons,
    traceabilitySummary.activationOnlyBlockerIds.length > 0 && review?.decision !== 'traceability_accepted_inactive_trust',
    'activation_only_blockers_require_inactive_acceptance',
  );
}

function evaluateAuditRecord(auditRecord, cycle, review, reasons) {
  addReason(reasons, !hasText(auditRecord?.auditRecordRef), 'traceability_audit_record_ref_absent');
  addReason(reasons, !isDigest(auditRecord?.auditRecordHash), 'traceability_audit_record_hash_invalid');
  addReason(reasons, auditRecord?.metadataOnly !== true, 'traceability_audit_record_metadata_boundary_invalid');
  addReason(reasons, auditRecord?.includesProtectedContent === true, 'traceability_audit_record_protected_content_forbidden');
  addReason(reasons, hlcTuple(auditRecord?.receiptRecordedAtHlc) === null, 'traceability_audit_record_time_invalid');
  addReason(reasons, hlcBefore(auditRecord?.receiptRecordedAtHlc, cycle?.auditRecordedAtHlc), 'traceability_audit_before_cycle_audit_step');
  addReason(reasons, hlcBefore(auditRecord?.receiptRecordedAtHlc, review?.reviewedAtHlc), 'traceability_audit_before_review');
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

function buildTraceabilityMatrix(input, policySummary, rowSummary) {
  const implementedCount = rowSummary.implementedCount;
  const activationOnlyBlockerCount = rowSummary.activationOnlyBlockerIds.length;
  const matrixHash = sha256Hex({
    activationOnlyBlockerIds: rowSummary.activationOnlyBlockerIds,
    auditRecordHash: input.auditRecord.auditRecordHash,
    humanDecisionHash: input.humanReview.decisionHash,
    matrixRef: input.matrixCycle.matrixRef,
    requirementRows: rowSummary.rowSummaries,
    tenantId: input.tenantId,
    validationEvidenceHash: input.validationEvidence.evidenceHash,
  });

  return {
    schema: TRACEABILITY_SCHEMA,
    matrixId: `cmtrace_${sha256Hex({
      matrixHash,
      matrixRef: input.matrixCycle.matrixRef,
      tenantId: input.tenantId,
    }).slice(0, 32)}`,
    tenantId: input.tenantId,
    releaseCandidateRef: input.matrixCycle.releaseCandidateRef,
    trustState: 'inactive',
    productionTrustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    requirementFamiliesCovered: rowSummary.families,
    doctrineLayersCovered: rowSummary.doctrineLayers,
    contextDocRefs: policySummary.requiredContextDocRefs,
    requirementIds: rowSummary.requirementIds,
    requirementRows: rowSummary.rowSummaries,
    activationOnlyBlockerIds: rowSummary.activationOnlyBlockerIds,
    bobEscalationIds: rowSummary.bobEscalationIds,
    coverageSummary: {
      activationOnlyBlockerCount,
      implementedCount,
      totalRequirementCount: rowSummary.totalRequirementCount,
    },
    validationSummary: {
      commandRefs: sortedTextList(input.validationEvidence.commandRefs),
      coverageLineBasisPoints: input.validationEvidence.coverageLineBasisPoints,
      sourceGuardPassed: input.validationEvidence.sourceGuardPassed,
      testCount: input.validationEvidence.testCount,
    },
    matrixHash,
    auditRecordHash: input.auditRecord.auditRecordHash,
    auditRecordedAtHlc: input.auditRecord.receiptRecordedAtHlc,
  };
}

function buildReceipt(input, traceability) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: traceability.matrixHash,
    artifactType: 'requirement_traceability_matrix',
    artifactVersion: input.matrixCycle.releaseCandidateRef,
    classification: 'restricted_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.auditRecord.receiptRecordedAtHlc,
    sensitivityTags: ['requirement_traceability', 'metadata_only', 'inactive_trust_state'],
    sourceSystem: 'cybermedica-qms',
    tenantId: input.tenantId,
  });
}

export function evaluateRequirementTraceability(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policySummary = evaluateTraceabilityPolicy(input?.traceabilityPolicy, reasons);
  evaluateMatrixCycle(input?.matrixCycle, input?.traceabilityPolicy, reasons);
  const rowSummary = evaluateRequirementRows(input?.requirementRows, policySummary, input?.matrixCycle, reasons);
  evaluateValidationEvidence(input?.validationEvidence, input?.matrixCycle, reasons);
  evaluateHumanReview(input?.humanReview, input?.matrixCycle, rowSummary, reasons);
  evaluateAuditRecord(input?.auditRecord, input?.matrixCycle, input?.humanReview, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: unique,
      traceability: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const traceability = buildTraceabilityMatrix(input, policySummary, rowSummary);

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    traceability,
    receipt: buildReceipt(input, traceability),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
