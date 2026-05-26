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
const ENTITY_SCHEMA_CATALOG = 'cybermedica.entity_schema_catalog.v1';
const ENTITY_SCHEMA_DECISION = 'cybermedica.entity_schema_catalog_decision.v1';
const REQUIRED_PERMISSION = 'manage_entity_schemas';

const REQUIRED_ENTITY_TYPES = Object.freeze([
  'ae_sae_susar',
  'audit',
  'audit_log_entry',
  'authority_chain',
  'calibration_record',
  'capa',
  'chain_of_custody_record',
  'clinical_trial_agreement',
  'clinical_trial_product',
  'competency_attestation',
  'complaint',
  'concern',
  'consent_form',
  'consent_process',
  'control',
  'control_assessment',
  'controlled_document',
  'cro',
  'data_sharing_consent',
  'decision_matter',
  'decision_rationale',
  'decision_vote',
  'delegation',
  'deviation',
  'disclosure_log',
  'equipment',
  'evidence_object',
  'evidence_receipt',
  'exochain_anchor',
  'export_packet',
  'facility',
  'finding',
  'iec_irb',
  'information_management_plan',
  'kpi',
  'mitigation',
  'nonconformance',
  'organization',
  'participant_code',
  'policy',
  'procedure',
  'product_accountability_record',
  'protocol',
  'protocol_amendment',
  'recusal',
  'responsibility',
  'risk',
  'risk_assessment',
  'role',
  'safety_plan',
  'site',
  'sop',
  'sponsor',
  'staff_profile',
  'study',
  'tenant',
  'training_completion',
  'training_requirement',
  'user',
]);

const REQUIRED_SCHEMA_DIMENSIONS = Object.freeze([
  'access_policy',
  'authority_chain',
  'consent_boundary',
  'data_classification',
  'exochain_receipt_boundary',
  'object_storage_boundary',
  'retention_rule',
  'tenant_isolation',
  'versioning',
]);

const PARTICIPANT_LINKED_ENTITIES = new Set([
  'ae_sae_susar',
  'consent_form',
  'consent_process',
  'data_sharing_consent',
  'participant_code',
]);

const SPONSOR_CONFIDENTIAL_ENTITIES = new Set([
  'clinical_trial_agreement',
  'cro',
  'export_packet',
  'sponsor',
]);

const RAW_ARTIFACT_ENTITIES = new Set([
  'controlled_document',
  'evidence_object',
  'export_packet',
]);

const IMMUTABLE_RECEIPT_ENTITIES = new Set([
  'audit_log_entry',
  'evidence_receipt',
  'exochain_anchor',
]);

const DATA_CLASSES = new Set([
  'decision_governance',
  'immutable_receipt',
  'participant_linked_phi_pii',
  'public_non_sensitive',
  'quality_evidence',
  'sponsor_cro_confidential',
  'tenant_operational',
]);

const STORAGE_CLASSES = new Set([
  'external_receipt_store',
  'object_storage',
  'operational_database',
  'reference_only',
]);

const ACTOR_KINDS = new Set(['human', 'service_account']);
const POLICY_STATUSES = new Set(['active']);
const HUMAN_REVIEW_DECISIONS = new Set(['entity_schema_catalog_ready', 'entity_schema_catalog_hold']);

const RAW_ENTITY_SCHEMA_FIELDS = new Set([
  'body',
  'clinicalnote',
  'directidentifier',
  'directidentifiers',
  'freetext',
  'participantidentifier',
  'participantlisting',
  'participantname',
  'participantnote',
  'protectedcontent',
  'rawartifact',
  'rawartifactbody',
  'rawclinicalrecord',
  'rawcontent',
  'rawparticipant',
  'rawparticipantcontent',
  'rawparticipantnote',
  'rawpayload',
  'rawphipayload',
  'rawpiipayload',
  'rawsponsorbody',
  'rawsourcecontent',
  'reviewnotes',
  'sourcebody',
  'sourcedocumentbody',
  'sponsorbudgettext',
  'sponsorconfidentialbody',
]);

const SECRET_ENTITY_SCHEMA_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'bootstrapsecret',
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

function assertNoRawEntitySchemaContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawEntitySchemaContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_ENTITY_SCHEMA_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw protected entity schema content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_ENTITY_SCHEMA_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`entity schema secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawEntitySchemaContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawEntitySchemaContent(input ?? {});
  canonicalize(input ?? {});
}

function sortedTextList(values) {
  return Array.isArray(values) ? [...new Set(values.filter(hasText))].sort() : [];
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [hlc.physicalMs, hlc.logical];
}

function compareHlcTuple(left, right) {
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
  return leftTuple !== null && rightTuple !== null && compareHlcTuple(leftTuple, rightTuple) < 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function firstSchemasByType(schemas, reasons) {
  const output = {};
  if (!Array.isArray(schemas)) {
    return output;
  }
  for (const schema of schemas) {
    if (!hasText(schema?.entityType)) {
      reasons.push('entity_type_absent');
      continue;
    }
    if (output[schema.entityType] !== undefined) {
      reasons.push(`entity_schema_duplicate:${schema.entityType}`);
      continue;
    }
    output[schema.entityType] = schema;
  }
  return output;
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, !ACTOR_KINDS.has(input?.actor?.kind), 'actor_kind_invalid');
  addReason(
    reasons,
    input?.actor?.kind === 'service_account' && !hasText(input?.actor?.humanOwnerDid),
    'service_account_human_owner_absent',
  );
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'entity_schema_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateSchemaPolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'schema_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'schema_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'schema_policy_not_active');
  addReason(reasons, policy?.defaultDenyUnknownEntities !== true, 'default_deny_unknown_entities_absent');
  addReason(reasons, policy?.schemaVersioningRequired !== true, 'schema_versioning_policy_absent');
  addReason(reasons, policy?.tenantPartitionRequired !== true, 'tenant_partition_policy_absent');
  addReason(reasons, policy?.receiptSeparationRequired !== true, 'receipt_separation_policy_absent');
  addReason(reasons, policy?.rawProtectedContentForbidden !== true, 'raw_protected_content_policy_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'schema_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'schema_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'schema_policy_evaluation_time_invalid');

  for (const entityType of REQUIRED_ENTITY_TYPES) {
    addReason(
      reasons,
      !sortedTextList(policy?.requiredEntityTypes).includes(entityType),
      `policy_required_entity_missing:${entityType}`,
    );
  }
  for (const dimension of REQUIRED_SCHEMA_DIMENSIONS) {
    addReason(
      reasons,
      !sortedTextList(policy?.requiredDimensions).includes(dimension),
      `policy_required_dimension_missing:${dimension}`,
    );
  }
}

function evaluateSchemaCatalog(input, reasons) {
  const catalog = input?.schemaCatalog;
  addReason(reasons, !hasText(catalog?.catalogRef), 'schema_catalog_ref_absent');
  addReason(reasons, !hasText(catalog?.catalogVersion), 'schema_catalog_version_absent');
  addReason(reasons, !isDigest(catalog?.catalogHash), 'schema_catalog_hash_invalid');
  addReason(reasons, catalog?.approvedByHuman !== true, 'schema_catalog_human_approval_absent');
  addReason(reasons, hlcTuple(catalog?.approvedAtHlc) === null, 'schema_catalog_approval_time_invalid');
  addReason(reasons, hlcBefore(catalog?.approvedAtHlc, input?.schemaPolicy?.evaluatedAtHlc), 'catalog_approval_before_policy');
  addReason(reasons, !hasText(catalog?.rollbackCatalogRef), 'schema_catalog_rollback_ref_absent');
  addReason(reasons, catalog?.mutableOperationalStateSeparate !== true, 'operational_state_separation_absent');
  addReason(reasons, catalog?.exochainReceiptStoreExternal !== true, 'receipt_store_external_absent');
  addReason(reasons, catalog?.noProductionTrustClaim !== true, 'production_trust_claim_forbidden');
  addReason(reasons, catalog?.metadataOnly !== true, 'schema_catalog_metadata_boundary_invalid');
  addReason(reasons, catalog?.protectedContentExcluded !== true, 'schema_catalog_protected_boundary_invalid');
}

function evaluateGenericEntitySchema(schema, reasons) {
  const entityType = schema?.entityType;
  addReason(reasons, !hasText(schema?.schemaRef), `entity_schema_ref_absent:${entityType}`);
  addReason(
    reasons,
    schema?.schemaVersion !== `cybermedica.${entityType}.v1`,
    `entity_schema_version_invalid:${entityType}`,
  );
  addReason(reasons, !isDigest(schema?.schemaHash), `entity_schema_hash_invalid:${entityType}`);
  addReason(reasons, !DATA_CLASSES.has(schema?.dataClass), `entity_data_class_invalid:${entityType}`);
  addReason(reasons, !STORAGE_CLASSES.has(schema?.storageClass), `entity_storage_class_invalid:${entityType}`);
  addReason(reasons, schema?.tenantScoped !== true, `entity_tenant_scope_absent:${entityType}`);
  addReason(reasons, schema?.tenantPartitionKey !== 'tenant_id', `entity_tenant_partition_invalid:${entityType}`);
  addReason(reasons, schema?.authorityRequired !== true, `entity_authority_boundary_absent:${entityType}`);
  addReason(reasons, !hasText(schema?.retentionRuleRef), `entity_retention_rule_absent:${entityType}`);
  addReason(reasons, !hasText(schema?.accessPolicyRef), `entity_access_policy_absent:${entityType}`);
  addReason(reasons, schema?.directIdentifiersAllowed === true, `entity_direct_identifier_allowed:${entityType}`);
  addReason(reasons, schema?.receiptPayloadMetadataOnly !== true, `entity_receipt_metadata_boundary_invalid:${entityType}`);
  addReason(reasons, schema?.externalPayloadsRemainControlled !== true, `entity_payload_boundary_invalid:${entityType}`);
  addReason(reasons, !isDigest(schema?.evidenceHash), `entity_schema_evidence_hash_invalid:${entityType}`);
  addReason(reasons, schema?.metadataOnly !== true, `entity_metadata_boundary_invalid:${entityType}`);
  addReason(reasons, schema?.protectedContentExcluded !== true, `entity_protected_boundary_invalid:${entityType}`);
  addReason(reasons, hlcTuple(schema?.reviewedAtHlc) === null, `entity_review_time_invalid:${entityType}`);
  for (const dimension of REQUIRED_SCHEMA_DIMENSIONS) {
    addReason(
      reasons,
      !sortedTextList(schema?.dimensionCoverage).includes(dimension),
      `entity_dimension_missing:${entityType}:${dimension}`,
    );
  }
}

function evaluateParticipantEntity(schema, reasons) {
  if (schema === undefined) {
    return;
  }
  const entityType = schema.entityType;
  addReason(
    reasons,
    schema.dataClass !== 'participant_linked_phi_pii',
    `participant_entity_data_class_invalid:${entityType}`,
  );
  addReason(
    reasons,
    schema.directIdentifiersAllowed === true,
    `participant_entity_direct_identifier_allowed:${entityType}`,
  );
  addReason(
    reasons,
    schema.consentRequiredForParticipantLinked !== true,
    `participant_entity_consent_boundary_absent:${entityType}`,
  );
  addReason(
    reasons,
    schema.receiptPayloadMetadataOnly !== true,
    `participant_entity_receipt_metadata_boundary_invalid:${entityType}`,
  );
}

function evaluateSponsorEntity(schema, reasons) {
  if (schema === undefined) {
    return;
  }
  const entityType = schema.entityType;
  addReason(
    reasons,
    schema.dataClass !== 'sponsor_cro_confidential',
    `sponsor_entity_data_class_invalid:${entityType}`,
  );
  addReason(
    reasons,
    schema.sponsorConfidentialBodyExcluded !== true,
    `sponsor_entity_body_boundary_invalid:${entityType}`,
  );
}

function evaluateRawArtifactEntity(schema, reasons) {
  if (schema === undefined) {
    return;
  }
  const entityType = schema.entityType;
  addReason(
    reasons,
    schema.rawPayloadStoredExternally !== true ||
      schema.storageClass !== 'object_storage' ||
      !hasText(schema.objectStorageBoundaryRef) ||
      schema.objectStorageBoundaryRef === 'not_applicable',
    `raw_artifact_storage_boundary_invalid:${entityType}`,
  );
}

function evaluateImmutableReceiptEntity(schema, reasons) {
  if (schema === undefined) {
    return;
  }
  const entityType = schema.entityType;
  addReason(
    reasons,
    schema.immutableReceipt !== true ||
      schema.mutableOperationalState !== false ||
      schema.storageClass !== 'external_receipt_store' ||
      schema.receiptPayloadMetadataOnly !== true,
    `immutable_receipt_boundary_invalid:${entityType}`,
  );
}

function evaluateEntitySchemaList(input, reasons) {
  const byType = firstSchemasByType(input?.entitySchemas, reasons);
  for (const entityType of REQUIRED_ENTITY_TYPES) {
    const schema = byType[entityType];
    addReason(reasons, schema === undefined, `entity_schema_missing:${entityType}`);
    if (schema !== undefined) {
      evaluateGenericEntitySchema(schema, reasons);
    }
  }
  for (const entityType of PARTICIPANT_LINKED_ENTITIES) {
    evaluateParticipantEntity(byType[entityType], reasons);
  }
  for (const entityType of SPONSOR_CONFIDENTIAL_ENTITIES) {
    evaluateSponsorEntity(byType[entityType], reasons);
  }
  for (const entityType of RAW_ARTIFACT_ENTITIES) {
    evaluateRawArtifactEntity(byType[entityType], reasons);
  }
  for (const entityType of IMMUTABLE_RECEIPT_ENTITIES) {
    evaluateImmutableReceiptEntity(byType[entityType], reasons);
  }
  return byType;
}

function evaluateBoundaryModel(boundary, reasons) {
  addReason(reasons, !hasText(boundary?.boundaryRef), 'boundary_ref_absent');
  addReason(reasons, !isDigest(boundary?.boundaryHash), 'boundary_hash_invalid');
  addReason(reasons, boundary?.participantDirectIdentifiersForbidden !== true, 'boundary_participant_identifier_guard_absent');
  addReason(reasons, boundary?.sponsorConfidentialBodiesExcluded !== true, 'boundary_sponsor_confidential_body_guard_absent');
  addReason(reasons, boundary?.immutableReceiptsMetadataOnly !== true, 'boundary_immutable_receipt_metadata_absent');
  addReason(reasons, boundary?.rawArtifactsStoredInObjectStorage !== true, 'boundary_raw_artifact_object_storage_absent');
  addReason(reasons, boundary?.operationalStateMutable !== true, 'boundary_operational_state_mutability_absent');
  addReason(reasons, boundary?.externalPayloadsRemainControlled !== true, 'boundary_external_payload_control_absent');
  addReason(reasons, boundary?.metadataOnly !== true, 'boundary_metadata_invalid');
  addReason(reasons, boundary?.protectedContentExcluded !== true, 'boundary_protected_invalid');
  addReason(reasons, hlcTuple(boundary?.reviewedAtHlc) === null, 'boundary_review_time_invalid');
}

function evaluateValidationEvidence(evidence, reasons) {
  addReason(reasons, !Array.isArray(evidence?.commandRefs) || evidence.commandRefs.length === 0, 'validation_commands_absent');
  addReason(reasons, evidence?.commandsPassed !== true, 'validation_commands_not_passed');
  addReason(reasons, evidence?.sourceGuardPassed !== true, 'source_guard_not_passed');
  addReason(reasons, evidence?.noExochainSourceModified !== true, 'exochain_source_modification_forbidden');
  addReason(reasons, evidence?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(evidence?.recordedAtHlc) === null, 'validation_time_invalid');
}

function evaluateAiAssistance(ai, reasons) {
  if (ai === undefined || ai === null || ai.used !== true) {
    return;
  }
  addReason(reasons, !isDigest(ai.recommendationHash), 'ai_recommendation_hash_invalid');
  addReason(reasons, sortedTextList(ai.limitationHashes).length === 0, 'ai_limitation_hashes_absent');
  addReason(reasons, ai.advisoryOnly !== true, 'ai_advisory_only_absent');
  addReason(reasons, ai.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, ai.reviewedByHuman !== true, 'ai_human_review_absent');
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, sortedTextList(review?.reviewerRoleRefs).length === 0, 'human_reviewer_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_final_authority_absent');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'production_trust_claim_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(
    reasons,
    hlcBefore(review?.reviewedAtHlc, input?.schemaCatalog?.approvedAtHlc),
    'human_review_before_catalog_approval',
  );
}

function summarizeEntitySchema(schema) {
  return {
    entityType: schema.entityType,
    schemaRef: schema.schemaRef,
    schemaVersion: schema.schemaVersion,
    schemaHash: schema.schemaHash,
    dataClass: schema.dataClass,
    storageClass: schema.storageClass,
    tenantScoped: schema.tenantScoped === true,
    mutableOperationalState: schema.mutableOperationalState === true,
    immutableReceipt: schema.immutableReceipt === true,
    exochainReceiptCapable: schema.exochainReceiptCapable === true,
    directIdentifiersAllowed: schema.directIdentifiersAllowed === true,
    retentionRuleRef: schema.retentionRuleRef,
    accessPolicyRef: schema.accessPolicyRef,
    metadataOnly: schema.metadataOnly === true,
  };
}

function buildCatalog(input, byType) {
  const entitySchemas = REQUIRED_ENTITY_TYPES.map((entityType) => summarizeEntitySchema(byType[entityType]));
  const dataClasses = uniqueSorted(entitySchemas.map((schema) => schema.dataClass));
  const storageClasses = uniqueSorted(entitySchemas.map((schema) => schema.storageClass));
  const receiptCapableEntities = entitySchemas
    .filter((schema) => schema.exochainReceiptCapable)
    .map((schema) => schema.entityType)
    .sort();
  const rawArtifactEntities = REQUIRED_ENTITY_TYPES.filter((entityType) => RAW_ARTIFACT_ENTITIES.has(entityType));
  const participantEntities = REQUIRED_ENTITY_TYPES.filter((entityType) => PARTICIPANT_LINKED_ENTITIES.has(entityType));
  const sponsorEntities = REQUIRED_ENTITY_TYPES.filter((entityType) => SPONSOR_CONFIDENTIAL_ENTITIES.has(entityType));

  const material = {
    catalogHash: input.schemaCatalog.catalogHash,
    catalogRef: input.schemaCatalog.catalogRef,
    catalogVersion: input.schemaCatalog.catalogVersion,
    dimensions: REQUIRED_SCHEMA_DIMENSIONS,
    entitySchemas,
    policyHash: input.schemaPolicy.policyHash,
  };

  return {
    schema: ENTITY_SCHEMA_CATALOG,
    catalogId: `cm_entity_schema_catalog_${sha256Hex(material).slice(0, 32)}`,
    catalogRef: input.schemaCatalog.catalogRef,
    catalogVersion: input.schemaCatalog.catalogVersion,
    catalogHash: input.schemaCatalog.catalogHash,
    policyRef: input.schemaPolicy.policyRef,
    trustState: 'inactive',
    exochainProductionClaim: false,
    containsProtectedContent: false,
    metadataOnly: true,
    entityTypes: [...REQUIRED_ENTITY_TYPES],
    entityCount: REQUIRED_ENTITY_TYPES.length,
    dimensions: [...REQUIRED_SCHEMA_DIMENSIONS],
    dataClasses,
    storageClasses,
    receiptCapableEntities,
    participantLinkedEntities: participantEntities,
    sponsorConfidentialEntities: sponsorEntities,
    rawArtifactEntities,
    participantDirectIdentifierGuard: input.boundaryModel.participantDirectIdentifiersForbidden === true,
    rawArtifactObjectStorageBoundary: input.boundaryModel.rawArtifactsStoredInObjectStorage === true,
    receiptStoreExternal: input.schemaCatalog.exochainReceiptStoreExternal === true,
    mutableOperationalStateSeparate: input.schemaCatalog.mutableOperationalStateSeparate === true,
    entitySchemas,
    catalogMaterialHash: sha256Hex(material),
    validationCommands: sortedTextList(input.validationEvidence?.commandRefs),
  };
}

function buildReceipt(input) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: input.schemaCatalog.catalogHash,
    artifactType: 'entity_schema_catalog',
    artifactVersion: input.schemaCatalog.catalogVersion,
    classification: 'metadata_only_entity_schema_catalog',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    schema: ENTITY_SCHEMA_CATALOG,
    sensitivityTags: ['metadata_only', 'schema_catalog', 'adjacent_surface'],
    sourceSystem: 'cybermedica-qms-contracts',
    tenantId: input.tenantId,
  });
}

export function evaluateEntitySchemas(input = {}) {
  assertMetadataOnly(input);
  const reasons = [];

  evaluateTenantActorAuthority(input, reasons);
  evaluateSchemaPolicy(input?.schemaPolicy, reasons);
  evaluateSchemaCatalog(input, reasons);
  const byType = evaluateEntitySchemaList(input, reasons);
  evaluateBoundaryModel(input?.boundaryModel, reasons);
  evaluateValidationEvidence(input?.validationEvidence, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  evaluateHumanReview(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const uniqueReasons = uniqueSorted(reasons);
  if (uniqueReasons.length > 0) {
    return {
      schema: ENTITY_SCHEMA_DECISION,
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      entitySchemaCatalog: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  return {
    schema: ENTITY_SCHEMA_DECISION,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    entitySchemaCatalog: buildCatalog(input, byType),
    receipt: buildReceipt(input),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
