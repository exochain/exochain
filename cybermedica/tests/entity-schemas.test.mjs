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

import assert from 'node:assert/strict';
import { test } from 'node:test';

const REQUIRED_ENTITY_TYPES = [
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
];

const REQUIRED_SCHEMA_DIMENSIONS = [
  'access_policy',
  'authority_chain',
  'consent_boundary',
  'data_classification',
  'exochain_receipt_boundary',
  'object_storage_boundary',
  'retention_rule',
  'tenant_isolation',
  'versioning',
];

const PARTICIPANT_LINKED_ENTITIES = [
  'ae_sae_susar',
  'consent_form',
  'consent_process',
  'data_sharing_consent',
  'participant_code',
];

const SPONSOR_CONFIDENTIAL_ENTITIES = [
  'clinical_trial_agreement',
  'cro',
  'export_packet',
  'sponsor',
];

const RAW_ARTIFACT_ENTITIES = [
  'controlled_document',
  'evidence_object',
  'export_packet',
];

const IMMUTABLE_RECEIPT_ENTITIES = [
  'audit_log_entry',
  'evidence_receipt',
  'exochain_anchor',
];

async function loadEntitySchemas() {
  try {
    return await import('../src/entity-schemas.mjs');
  } catch (error) {
    assert.fail(`CyberMedica entity schemas module must exist and load: ${error.message}`);
  }
}

function digestFor(index) {
  return (index + 1).toString(16).padStart(2, '0').repeat(32);
}

function mergeDeep(base, overrides) {
  if (Array.isArray(base) || Array.isArray(overrides)) {
    return overrides === undefined ? base : overrides;
  }
  if (base === null || overrides === null || typeof base !== 'object' || typeof overrides !== 'object') {
    return overrides === undefined ? base : overrides;
  }
  return Object.fromEntries(
    [...new Set([...Object.keys(base), ...Object.keys(overrides)])].map((key) => [
      key,
      mergeDeep(base[key], overrides[key]),
    ]),
  );
}

function schemaFor(entityType, index, overrides = {}) {
  const participantLinked = PARTICIPANT_LINKED_ENTITIES.includes(entityType);
  const sponsorConfidential = SPONSOR_CONFIDENTIAL_ENTITIES.includes(entityType);
  const rawArtifact = RAW_ARTIFACT_ENTITIES.includes(entityType);
  const immutableReceipt = IMMUTABLE_RECEIPT_ENTITIES.includes(entityType);
  const dataClass = participantLinked
    ? 'participant_linked_phi_pii'
    : sponsorConfidential
      ? 'sponsor_cro_confidential'
      : immutableReceipt
        ? 'immutable_receipt'
        : rawArtifact
          ? 'quality_evidence'
          : 'tenant_operational';

  return {
    entityType,
    schemaRef: `schemas/${entityType}.schema.json`,
    schemaVersion: `cybermedica.${entityType}.v1`,
    schemaHash: digestFor(index),
    dataClass,
    storageClass: immutableReceipt ? 'external_receipt_store' : rawArtifact ? 'object_storage' : 'operational_database',
    tenantScoped: true,
    tenantPartitionKey: 'tenant_id',
    mutableOperationalState: !immutableReceipt,
    immutableReceipt,
    exochainReceiptCapable: ['evidence_object', 'evidence_receipt', 'exochain_anchor', 'decision_matter'].includes(entityType),
    directIdentifiersAllowed: false,
    consentRequiredForParticipantLinked: participantLinked,
    sponsorConfidentialBodyExcluded: sponsorConfidential,
    rawPayloadStoredExternally: rawArtifact,
    objectStorageBoundaryRef: rawArtifact ? 'encrypted-object-storage-boundary' : 'not_applicable',
    retentionRuleRef: `retention-${entityType.replaceAll('_', '-')}`,
    accessPolicyRef: `access-policy-${entityType.replaceAll('_', '-')}`,
    authorityRequired: true,
    receiptPayloadMetadataOnly: true,
    externalPayloadsRemainControlled: true,
    dimensionCoverage: REQUIRED_SCHEMA_DIMENSIONS,
    evidenceHash: digestFor(index + REQUIRED_ENTITY_TYPES.length),
    metadataOnly: true,
    protectedContentExcluded: true,
    reviewedAtHlc: { physicalMs: 1801000100000, logical: index },
    ...overrides,
  };
}

function allSchemas() {
  return REQUIRED_ENTITY_TYPES.map((entityType, index) => schemaFor(entityType, index));
}

function entitySchemaInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:entity-schema-owner-alpha',
      kind: 'human',
      roleRefs: ['data_architect', 'quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['manage_entity_schemas', 'govern'],
      authorityChainHash: digestFor(121),
    },
    schemaPolicy: {
      policyRef: 'entity-schema-policy-alpha',
      policyHash: digestFor(122),
      status: 'active',
      requiredEntityTypes: REQUIRED_ENTITY_TYPES,
      requiredDimensions: REQUIRED_SCHEMA_DIMENSIONS,
      defaultDenyUnknownEntities: true,
      schemaVersioningRequired: true,
      tenantPartitionRequired: true,
      receiptSeparationRequired: true,
      rawProtectedContentForbidden: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1801000000000, logical: 0 },
    },
    schemaCatalog: {
      catalogRef: 'cybermedica-core-entity-schema-catalog-alpha',
      catalogVersion: 'v1',
      catalogHash: digestFor(123),
      approvedByHuman: true,
      approvedAtHlc: { physicalMs: 1801000200000, logical: 0 },
      rollbackCatalogRef: 'cybermedica-core-entity-schema-catalog-v0',
      mutableOperationalStateSeparate: true,
      exochainReceiptStoreExternal: true,
      noProductionTrustClaim: true,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    entitySchemas: allSchemas().reverse(),
    boundaryModel: {
      boundaryRef: 'entity-schema-boundary-alpha',
      boundaryHash: digestFor(124),
      participantDirectIdentifiersForbidden: true,
      sponsorConfidentialBodiesExcluded: true,
      immutableReceiptsMetadataOnly: true,
      rawArtifactsStoredInObjectStorage: true,
      operationalStateMutable: true,
      externalPayloadsRemainControlled: true,
      reviewedAtHlc: { physicalMs: 1801000150000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    validationEvidence: {
      commandRefs: ['node --test tests/entity-schemas.test.mjs', 'npm run quality'],
      commandsPassed: true,
      sourceGuardPassed: true,
      noExochainSourceModified: true,
      recordedAtHlc: { physicalMs: 1801000300000, logical: 0 },
      metadataOnly: true,
    },
    aiAssistance: {
      used: true,
      recommendationHash: digestFor(125),
      limitationHashes: [digestFor(126)],
      advisoryOnly: true,
      finalAuthority: false,
      reviewedByHuman: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:schema-reviewer-alpha',
      reviewerRoleRefs: ['quality_manager', 'data_architect'],
      decision: 'entity_schema_catalog_ready',
      decisionHash: digestFor(127),
      finalAuthority: 'human',
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      reviewedAtHlc: { physicalMs: 1801000400000, logical: 0 },
      metadataOnly: true,
    },
    custodyDigest: digestFor(128),
  };
  return mergeDeep(base, overrides);
}

test('entity schema catalog creates deterministic inactive metadata receipts', async () => {
  const { evaluateEntitySchemas } = await loadEntitySchemas();

  const first = evaluateEntitySchemas(entitySchemaInput());
  const second = evaluateEntitySchemas(
    entitySchemaInput({
      schemaPolicy: {
        requiredEntityTypes: [...REQUIRED_ENTITY_TYPES].reverse(),
        requiredDimensions: [...REQUIRED_SCHEMA_DIMENSIONS].reverse(),
      },
      entitySchemas: allSchemas(),
    }),
  );

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.deepEqual(first, second);
  assert.equal(first.entitySchemaCatalog.schema, 'cybermedica.entity_schema_catalog.v1');
  assert.equal(first.entitySchemaCatalog.trustState, 'inactive');
  assert.equal(first.entitySchemaCatalog.exochainProductionClaim, false);
  assert.equal(first.entitySchemaCatalog.metadataOnly, true);
  assert.equal(first.entitySchemaCatalog.containsProtectedContent, false);
  assert.deepEqual(first.entitySchemaCatalog.entityTypes, REQUIRED_ENTITY_TYPES);
  assert.equal(first.entitySchemaCatalog.entityCount, REQUIRED_ENTITY_TYPES.length);
  assert.deepEqual(first.entitySchemaCatalog.dimensions, REQUIRED_SCHEMA_DIMENSIONS);
  assert.equal(first.entitySchemaCatalog.participantDirectIdentifierGuard, true);
  assert.equal(first.entitySchemaCatalog.rawArtifactObjectStorageBoundary, true);
  assert.equal(first.entitySchemaCatalog.receiptStoreExternal, true);
  assert.equal(first.receipt.anchorPayload.artifactType, 'entity_schema_catalog');
  assert.equal(first.receipt.anchorPayload.classification, 'metadata_only_entity_schema_catalog');
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(first), /participant alice|source document body|sponsor budget text|api key/iu);
});

test('entity schema catalog fails closed for missing entities dimensions and schema metadata', async () => {
  const { evaluateEntitySchemas } = await loadEntitySchemas();

  const result = evaluateEntitySchemas(
    entitySchemaInput({
      schemaPolicy: {
        defaultDenyUnknownEntities: false,
      },
      entitySchemas: allSchemas()
        .filter((schema) => schema.entityType !== 'participant_code')
        .map((schema) =>
          schema.entityType === 'tenant'
            ? { ...schema, schemaRef: '', dimensionCoverage: ['tenant_isolation'] }
            : schema,
        ),
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('entity_schema_missing:participant_code'));
  assert.ok(result.reasons.includes('entity_schema_ref_absent:tenant'));
  assert.ok(result.reasons.includes('entity_dimension_missing:tenant:access_policy'));
  assert.ok(result.reasons.includes('default_deny_unknown_entities_absent'));
});

test('entity schemas enforce participant sponsor receipt and object-storage boundaries', async () => {
  const { evaluateEntitySchemas } = await loadEntitySchemas();

  const result = evaluateEntitySchemas(
    entitySchemaInput({
      entitySchemas: allSchemas().map((schema) => {
        if (schema.entityType === 'participant_code') {
          return {
            ...schema,
            directIdentifiersAllowed: true,
            consentRequiredForParticipantLinked: false,
            receiptPayloadMetadataOnly: false,
          };
        }
        if (schema.entityType === 'sponsor') {
          return {
            ...schema,
            sponsorConfidentialBodyExcluded: false,
            dataClass: 'public_non_sensitive',
          };
        }
        if (schema.entityType === 'evidence_object') {
          return {
            ...schema,
            rawPayloadStoredExternally: false,
            objectStorageBoundaryRef: '',
          };
        }
        if (schema.entityType === 'evidence_receipt') {
          return {
            ...schema,
            immutableReceipt: false,
            mutableOperationalState: true,
            storageClass: 'operational_database',
          };
        }
        return schema;
      }),
      boundaryModel: {
        participantDirectIdentifiersForbidden: false,
        sponsorConfidentialBodiesExcluded: false,
        immutableReceiptsMetadataOnly: false,
        rawArtifactsStoredInObjectStorage: false,
        externalPayloadsRemainControlled: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.match(result.reasons.join('\n'), /participant_entity_direct_identifier_allowed:participant_code/);
  assert.match(result.reasons.join('\n'), /participant_entity_consent_boundary_absent:participant_code/);
  assert.match(result.reasons.join('\n'), /sponsor_entity_data_class_invalid:sponsor/);
  assert.match(result.reasons.join('\n'), /sponsor_entity_body_boundary_invalid:sponsor/);
  assert.match(result.reasons.join('\n'), /raw_artifact_storage_boundary_invalid:evidence_object/);
  assert.match(result.reasons.join('\n'), /immutable_receipt_boundary_invalid:evidence_receipt/);
  assert.match(result.reasons.join('\n'), /boundary_participant_identifier_guard_absent/);
  assert.match(result.reasons.join('\n'), /boundary_raw_artifact_object_storage_absent/);
});

test('entity schemas require human review HLC order and advisory AI only', async () => {
  const { evaluateEntitySchemas } = await loadEntitySchemas();

  const result = evaluateEntitySchemas(
    entitySchemaInput({
      actor: {
        did: 'did:exo:ai-schema-writer-alpha',
        kind: 'ai_agent',
        roleRefs: ['ai_reviewer'],
      },
      schemaCatalog: {
        approvedByHuman: false,
        approvedAtHlc: { physicalMs: 1800999900000, logical: 0 },
        noProductionTrustClaim: false,
      },
      aiAssistance: {
        finalAuthority: true,
        advisoryOnly: false,
        reviewedByHuman: false,
        limitationHashes: [],
      },
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
        noProductionTrustClaim: false,
        reviewedAtHlc: { physicalMs: 1800999800000, logical: 0 },
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('schema_catalog_human_approval_absent'));
  assert.ok(result.reasons.includes('catalog_approval_before_policy'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('ai_advisory_only_absent'));
  assert.ok(result.reasons.includes('ai_human_review_absent'));
  assert.ok(result.reasons.includes('human_final_authority_absent'));
  assert.ok(result.reasons.includes('human_review_before_catalog_approval'));
});

test('entity schemas reject raw protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateEntitySchemas } = await loadEntitySchemas();

  const inertMarkers = entitySchemaInput({
    entitySchemas: allSchemas().map((schema) =>
      schema.entityType === 'participant_code' ? { ...schema, rawParticipantContent: [] } : schema,
    ),
  });
  assert.equal(evaluateEntitySchemas(inertMarkers).decision, 'permitted');

  assert.throws(
    () =>
      evaluateEntitySchemas(
        entitySchemaInput({
          entitySchemas: allSchemas().map((schema) =>
            schema.entityType === 'participant_code'
              ? { ...schema, rawParticipantContent: 'participant Alice source document body' }
              : schema,
          ),
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateEntitySchemas(
        entitySchemaInput({
          boundaryModel: {
            apiKey: 'cm_live_secret',
          },
        }),
      ),
    ProtectedContentError,
  );
});
