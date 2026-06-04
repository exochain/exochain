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
const DOMAIN_MODEL_SCHEMA = 'cybermedica.domain_operating_model.v1';
const REQUIRED_PERMISSION = 'domain_operating_model_govern';
const DECISION_READY = 'domain_model_ready_inactive_trust';
const DECISION_HOLD = 'hold_for_domain_model_gap';

export const REQUIRED_DOMAIN_MODULES = Object.freeze([
  'ai_review',
  'control_library',
  'cqi',
  'decision_forum',
  'deviations_capa',
  'ethics',
  'evaluation_audit_reporting',
  'evidence_custody',
  'facilities_equipment_product',
  'information_management',
  'participant_protection',
  'protocol_readiness',
  'qms_passport',
  'risk',
  'workforce_delegation',
]);

export const REQUIRED_OPERATING_OBJECTS = Object.freeze([
  'clinical_trial_product',
  'controls',
  'decisions',
  'evidence',
  'facilities',
  'obligations',
  'participants',
  'people',
  'policies',
  'protocols',
  'risks',
  'source_data',
  'standards',
  'training_delegation',
]);

const REQUIRED_DECISION_CLASSES = Object.freeze([
  'operational',
  'routine',
  'strategic',
]);

const REQUIRED_EVIDENCE_FAMILIES = Object.freeze([
  'authority_chain',
  'consent_bailment_boundary',
  'decision_forum_receipt',
  'evidence_custody_digest',
  'metadata_only_receipt',
  'tenant_scope',
]);

const REQUIRED_VALIDATION_COMMANDS = Object.freeze([
  'node --test tests/domain-operating-model.test.mjs',
  'node --test tests/source-guards.test.mjs',
]);

const POLICY_STATUSES = new Set(['active']);
const HUMAN_REVIEW_DECISIONS = new Set([DECISION_READY, DECISION_HOLD]);
const DOMAIN_MODULE_SET = new Set(REQUIRED_DOMAIN_MODULES);
const OPERATING_OBJECT_SET = new Set(REQUIRED_OPERATING_OBJECTS);
const DECISION_CLASS_SET = new Set(REQUIRED_DECISION_CLASSES);
const EVIDENCE_FAMILY_SET = new Set(REQUIRED_EVIDENCE_FAMILIES);

const RAW_DOMAIN_FIELDS = new Set([
  'body',
  'clinicalnote',
  'content',
  'domainbody',
  'domaincontent',
  'domainnarrative',
  'freetext',
  'freetextnote',
  'narrative',
  'rawclinicalcontent',
  'rawdomain',
  'rawdomaincontent',
  'rawdomainnarrative',
  'rawoperatingmodel',
  'rawsource',
  'rawsourcecontent',
  'reviewnotes',
  'sourcebody',
  'sourcedocumentbody',
  'sourcedocumenttext',
]);

const SECRET_DOMAIN_FIELDS = new Set([
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
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
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

function assertNoRawDomainContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawDomainContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_DOMAIN_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw domain operating model field is not allowed at ${path}.${key}`);
    }
    if (SECRET_DOMAIN_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`domain operating model secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawDomainContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawDomainContent(input ?? {});
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

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateRequiredSet(actual, expected, missingPrefix, unsupportedPrefix, allowedSet, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !allowedSet.has(value), `${unsupportedPrefix}:${value}`);
  }
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_domain_owner_required');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, hlcTuple(input?.requestedAtHlc) === null, 'requested_time_invalid');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'domain_operating_model_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateDomainPolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'domain_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'domain_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'domain_policy_not_active');
  addReason(reasons, !hasText(policy?.sourcePrdRef), 'domain_policy_source_prd_absent');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'domain_policy_evaluation_time_invalid');
  addReason(reasons, policy?.metadataOnly !== true, 'domain_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'domain_policy_protected_boundary_invalid');
  addReason(reasons, policy?.noProductionTrustClaim !== true, 'domain_policy_no_production_claim_invalid');

  evaluateRequiredSet(
    sortedTextList(policy?.requiredDomainModules),
    REQUIRED_DOMAIN_MODULES,
    'domain_policy_module_missing',
    'domain_policy_module_unsupported',
    DOMAIN_MODULE_SET,
    reasons,
  );
  evaluateRequiredSet(
    sortedTextList(policy?.requiredOperatingObjects),
    REQUIRED_OPERATING_OBJECTS,
    'domain_policy_object_missing',
    'domain_policy_object_unsupported',
    OPERATING_OBJECT_SET,
    reasons,
  );
  evaluateRequiredSet(
    sortedTextList(policy?.requiredDecisionClasses),
    REQUIRED_DECISION_CLASSES,
    'domain_policy_decision_class_missing',
    'domain_policy_decision_class_unsupported',
    DECISION_CLASS_SET,
    reasons,
  );
  evaluateRequiredSet(
    sortedTextList(policy?.requiredEvidenceFamilies),
    REQUIRED_EVIDENCE_FAMILIES,
    'domain_policy_evidence_family_missing',
    'domain_policy_evidence_family_unsupported',
    EVIDENCE_FAMILY_SET,
    reasons,
  );
}

function evaluateModuleRecords(moduleRecords, reasons) {
  const records = Array.isArray(moduleRecords)
    ? [...moduleRecords].sort((left, right) => String(left?.moduleRef ?? '').localeCompare(String(right?.moduleRef ?? '')))
    : [];
  const seen = new Set();
  const presentModules = [];
  const presentDecisionClasses = [];
  const presentEvidenceFamilies = [];

  addReason(reasons, records.length === 0, 'domain_modules_absent');

  const normalized = records.map((record) => {
    const moduleRef = hasText(record?.moduleRef) ? record.moduleRef : 'unknown';
    const actorRoleRefs = sortedTextList(record?.actorRoleRefs);
    const controlledObjectRefs = sortedTextList(record?.controlledObjectRefs);
    const evidenceFamilyRefs = sortedTextList(record?.evidenceFamilyRefs);

    addReason(reasons, seen.has(moduleRef), `domain_module_duplicate:${moduleRef}`);
    seen.add(moduleRef);
    addReason(reasons, !DOMAIN_MODULE_SET.has(moduleRef), `domain_module_unsupported:${moduleRef}`);
    addReason(reasons, !hasText(record?.ownerRole), `domain_module_owner_absent:${moduleRef}`);
    addReason(reasons, actorRoleRefs.length === 0, `domain_module_actor_roles_absent:${moduleRef}`);
    addReason(reasons, controlledObjectRefs.length === 0, `domain_module_objects_absent:${moduleRef}`);
    addReason(reasons, !DECISION_CLASS_SET.has(record?.decisionClass), `domain_module_decision_class_invalid:${moduleRef}`);
    addReason(reasons, !hasText(record?.sourcePrdRef), `domain_module_source_prd_absent:${moduleRef}`);
    addReason(reasons, !hasText(record?.implementationModuleRef), `domain_module_implementation_absent:${moduleRef}`);
    addReason(reasons, !hasText(record?.testRef), `domain_module_test_absent:${moduleRef}`);
    addReason(reasons, !isDigest(record?.evidenceHash), `domain_module_evidence_hash_invalid:${moduleRef}`);
    addReason(reasons, !isDigest(record?.custodyDigest), `domain_module_custody_digest_invalid:${moduleRef}`);
    addReason(reasons, hlcTuple(record?.reviewedAtHlc) === null, `domain_module_review_time_invalid:${moduleRef}`);
    addReason(reasons, record?.metadataOnly !== true, `domain_module_metadata_boundary_invalid:${moduleRef}`);
    addReason(reasons, record?.protectedContentExcluded !== true, `domain_module_protected_boundary_invalid:${moduleRef}`);
    addReason(reasons, record?.productionTrustClaim === true, `domain_module_production_claim_forbidden:${moduleRef}`);

    for (const objectRef of controlledObjectRefs) {
      addReason(reasons, !OPERATING_OBJECT_SET.has(objectRef), `domain_module_object_unsupported:${moduleRef}:${objectRef}`);
    }
    for (const evidenceFamily of REQUIRED_EVIDENCE_FAMILIES) {
      addReason(reasons, !evidenceFamilyRefs.includes(evidenceFamily), `domain_module_evidence_family_missing:${moduleRef}:${evidenceFamily}`);
    }
    for (const evidenceFamily of evidenceFamilyRefs) {
      addReason(reasons, !EVIDENCE_FAMILY_SET.has(evidenceFamily), `domain_module_evidence_family_unsupported:${moduleRef}:${evidenceFamily}`);
    }

    if (DOMAIN_MODULE_SET.has(moduleRef)) {
      presentModules.push(moduleRef);
    }
    if (DECISION_CLASS_SET.has(record?.decisionClass)) {
      presentDecisionClasses.push(record.decisionClass);
    }
    presentEvidenceFamilies.push(...evidenceFamilyRefs.filter((family) => EVIDENCE_FAMILY_SET.has(family)));

    return {
      actorRoleRefs,
      controlledObjectRefs,
      custodyDigest: record?.custodyDigest ?? null,
      decisionClass: record?.decisionClass ?? null,
      evidenceFamilyRefs,
      evidenceHash: record?.evidenceHash ?? null,
      implementationModuleRef: record?.implementationModuleRef ?? null,
      moduleRef,
      ownerRole: record?.ownerRole ?? null,
      policyRefs: sortedTextList(record?.policyRefs),
      procedureRefs: sortedTextList(record?.procedureRefs),
      reviewedAtHlc: record?.reviewedAtHlc ?? null,
      sourcePrdRef: record?.sourcePrdRef ?? null,
      testRef: record?.testRef ?? null,
    };
  });

  evaluateRequiredSet(
    uniqueSorted(presentModules),
    REQUIRED_DOMAIN_MODULES,
    'domain_module_missing',
    'domain_module_unsupported',
    DOMAIN_MODULE_SET,
    reasons,
  );
  evaluateRequiredSet(
    uniqueSorted(presentDecisionClasses),
    REQUIRED_DECISION_CLASSES,
    'domain_decision_class_missing',
    'domain_decision_class_unsupported',
    DECISION_CLASS_SET,
    reasons,
  );
  evaluateRequiredSet(
    uniqueSorted(presentEvidenceFamilies),
    REQUIRED_EVIDENCE_FAMILIES,
    'domain_evidence_family_missing',
    'domain_evidence_family_unsupported',
    EVIDENCE_FAMILY_SET,
    reasons,
  );

  return normalized;
}

function evaluateOperatingObjectInventory(inventory, reasons) {
  const rows = Array.isArray(inventory)
    ? [...inventory].sort((left, right) => String(left?.objectRef ?? '').localeCompare(String(right?.objectRef ?? '')))
    : [];
  const seen = new Set();
  const presentObjects = [];

  addReason(reasons, rows.length === 0, 'operating_object_inventory_absent');

  const normalized = rows.map((row) => {
    const objectRef = hasText(row?.objectRef) ? row.objectRef : 'unknown';
    addReason(reasons, seen.has(objectRef), `operating_object_duplicate:${objectRef}`);
    seen.add(objectRef);
    addReason(reasons, !OPERATING_OBJECT_SET.has(objectRef), `operating_object_unsupported:${objectRef}`);
    addReason(reasons, !hasText(row?.ownerRole), `operating_object_owner_absent:${objectRef}`);
    addReason(reasons, !hasText(row?.accessPolicyRef), `operating_object_access_policy_absent:${objectRef}`);
    addReason(reasons, !hasText(row?.retentionPolicyRef), `operating_object_retention_policy_absent:${objectRef}`);
    addReason(reasons, !isDigest(row?.evidenceHash), `operating_object_evidence_hash_invalid:${objectRef}`);
    addReason(reasons, hlcTuple(row?.reviewedAtHlc) === null, `operating_object_review_time_invalid:${objectRef}`);
    addReason(reasons, row?.metadataOnly !== true, `operating_object_metadata_boundary_invalid:${objectRef}`);
    addReason(reasons, row?.protectedContentExcluded !== true, `operating_object_protected_boundary_invalid:${objectRef}`);

    if (OPERATING_OBJECT_SET.has(objectRef)) {
      presentObjects.push(objectRef);
    }

    return {
      accessPolicyRef: row?.accessPolicyRef ?? null,
      evidenceHash: row?.evidenceHash ?? null,
      objectRef,
      ownerRole: row?.ownerRole ?? null,
      retentionPolicyRef: row?.retentionPolicyRef ?? null,
      reviewedAtHlc: row?.reviewedAtHlc ?? null,
    };
  });

  evaluateRequiredSet(
    uniqueSorted(presentObjects),
    REQUIRED_OPERATING_OBJECTS,
    'operating_object_missing',
    'operating_object_unsupported',
    OPERATING_OBJECT_SET,
    reasons,
  );

  return normalized;
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'human_review_reviewer_absent');
  addReason(reasons, !Array.isArray(review?.reviewerRoleRefs) || review.reviewerRoleRefs.length === 0, 'human_review_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.reviewHash), 'human_review_hash_invalid');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, review?.protectedContentExcluded !== true, 'human_review_protected_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, !hlcAfter(review?.reviewedAtHlc, input?.requestedAtHlc), 'human_review_not_after_request');
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance === undefined || aiAssistance === null || aiAssistance.used !== true) {
    return;
  }
  addReason(reasons, aiAssistance.finalAuthority === true, 'ai_assistance_final_authority_forbidden');
  addReason(reasons, !isDigest(aiAssistance.recommendationHash), 'ai_recommendation_hash_invalid');
  addReason(reasons, aiAssistance.metadataOnly !== true, 'ai_assistance_metadata_boundary_invalid');
  addReason(reasons, aiAssistance.protectedContentExcluded !== true, 'ai_assistance_protected_boundary_invalid');
}

function evaluateValidationEvidence(validationEvidence, reasons) {
  const commandRefs = sortedTextList(validationEvidence?.commandRefs);
  addReason(reasons, validationEvidence?.sourceGuardPassed !== true, 'source_guard_not_passed');
  addReason(reasons, validationEvidence?.contractTestsPassed !== true, 'validation_contract_tests_not_passed');
  addReason(reasons, validationEvidence?.pathClassificationCurrent !== true, 'path_classification_not_current');
  addReason(reasons, !isDigest(validationEvidence?.validationHash), 'validation_hash_invalid');
  addReason(reasons, validationEvidence?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
  addReason(reasons, validationEvidence?.protectedContentExcluded !== true, 'validation_protected_boundary_invalid');
  addReason(reasons, hlcTuple(validationEvidence?.validatedAtHlc) === null, 'validation_time_invalid');
  for (const command of REQUIRED_VALIDATION_COMMANDS) {
    addReason(reasons, !commandRefs.includes(command), `validation_command_missing:${command}`);
  }
}

function buildDomainOperatingModel(input, moduleRecords, operatingObjects, reasons) {
  const domainModules = uniqueSorted(moduleRecords.map((record) => record.moduleRef).filter((moduleRef) => DOMAIN_MODULE_SET.has(moduleRef)));
  const objectRefs = uniqueSorted(operatingObjects.map((record) => record.objectRef).filter((objectRef) => OPERATING_OBJECT_SET.has(objectRef)));
  const decisionClasses = uniqueSorted(moduleRecords.map((record) => record.decisionClass).filter((value) => DECISION_CLASS_SET.has(value)));
  const evidenceFamilies = uniqueSorted(
    moduleRecords.flatMap((record) => record.evidenceFamilyRefs).filter((value) => EVIDENCE_FAMILY_SET.has(value)),
  );

  const modelMaterial = {
    actorDid: input?.actor?.did ?? null,
    authorityChainHash: input?.authority?.authorityChainHash ?? null,
    decisionClasses,
    domainModules,
    evidenceFamilies,
    moduleRecords,
    operatingObjects,
    policyHash: input?.domainPolicy?.policyHash ?? null,
    requestedAtHlc: input?.requestedAtHlc ?? null,
    schema: DOMAIN_MODEL_SCHEMA,
    tenantId: input?.tenantId ?? null,
  };
  const modelHash = sha256Hex(modelMaterial);

  return {
    schema: DOMAIN_MODEL_SCHEMA,
    status: reasons.length === 0 ? 'ready_inactive_trust' : 'blocked',
    tenantId: input?.tenantId ?? null,
    domainLayer: 'domain',
    sourcePrdRef: input?.domainPolicy?.sourcePrdRef ?? null,
    domainModules,
    operatingObjects: objectRefs,
    decisionClasses,
    evidenceFamilies,
    moduleCount: domainModules.length,
    operatingObjectCount: objectRefs.length,
    modelHash,
    moduleRecords,
    objectInventory: operatingObjects,
    metadataOnly: true,
    exochainProductionClaim: false,
    trustState: 'inactive',
  };
}

export function evaluateDomainOperatingModel(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateDomainPolicy(input?.domainPolicy, reasons);
  const moduleRecords = evaluateModuleRecords(input?.moduleRecords, reasons);
  const operatingObjects = evaluateOperatingObjectInventory(input?.operatingObjectInventory, reasons);
  evaluateHumanReview(input, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  evaluateValidationEvidence(input?.validationEvidence, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const denialReasons = uniqueReasons(reasons);
  const denied = denialReasons.length > 0;
  const domainOperatingModel = buildDomainOperatingModel(input, moduleRecords, operatingObjects, denialReasons);
  const receipt = denied
    ? null
    : createEvidenceReceipt({
        actorDid: input.actor.did,
        artifactHash: domainOperatingModel.modelHash,
        artifactType: 'domain_operating_model',
        artifactVersion: 'v1',
        classification: 'metadata_only_domain_model',
        custodyDigest: input.custodyDigest,
        hlcTimestamp: input.requestedAtHlc,
        sensitivityTags: [
          'authority_metadata',
          'clinical_qms_metadata',
          'no_phi_pii',
          'no_sponsor_confidential_payload',
        ],
        sourceSystem: 'cybermedica-adjacent-surface',
        tenantId: input.tenantId,
      });

  return {
    schema: 'cybermedica.domain_operating_model_decision.v1',
    decision: denied ? 'denied' : 'permitted',
    failClosed: denied,
    reasons: denialReasons,
    domainOperatingModel,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
