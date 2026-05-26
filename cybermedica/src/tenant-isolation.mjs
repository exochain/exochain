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

import { canonicalize, createEvidenceReceipt, sha256Hex } from './qms-contracts.mjs';

const HEX_64 = /^[0-9a-f]{64}$/u;
const OPERATIONS = new Set(['read', 'write', 'export']);
const REQUIRED_PERMISSION = Object.freeze({
  export: 'read',
  read: 'read',
  write: 'write',
});
const EXPORT_SCOPE = 'tenant_export';

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

function hlcPresent(hlc) {
  return Number.isSafeInteger(hlc?.physicalMs) && Number.isSafeInteger(hlc?.logical);
}

function sortedTextList(value) {
  return Array.isArray(value) ? value.filter(hasText).sort() : [];
}

function normalizeTenantRecord(record) {
  if (record === null || typeof record !== 'object') {
    return null;
  }
  return {
    allowedOperations: sortedTextList(record.allowedOperations),
    constitutionHash: record.constitutionHash,
    kind: record.kind,
    status: record.status,
    tenantId: record.tenantId,
  };
}

function tenantRegistryRecords(registry) {
  if (!Array.isArray(registry)) {
    return [];
  }
  return registry.map(normalizeTenantRecord).filter((record) => record !== null).sort((left, right) => {
    return String(left.tenantId).localeCompare(String(right.tenantId));
  });
}

function findTenant(registry, tenantId) {
  return tenantRegistryRecords(registry).find((record) => record.tenantId === tenantId) ?? null;
}

function tenantActive(record) {
  return record !== null && record.status === 'active';
}

function tenantAllows(record, operation) {
  return Array.isArray(record?.allowedOperations) && record.allowedOperations.includes(operation);
}

function evaluateAuthority(input, reasons) {
  const required = REQUIRED_PERMISSION[input?.operation];
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasText(required) || !Array.isArray(input?.authority?.permissions) || !input.authority.permissions.includes(required),
    'authority_permission_missing',
  );
}

function evaluateTenantRegistry(input, reasons) {
  const tenant = findTenant(input?.tenantRegistry, input?.tenantId);
  const targetTenant = findTenant(input?.tenantRegistry, input?.targetTenantId);

  addReason(reasons, !Array.isArray(input?.tenantRegistry) || input.tenantRegistry.length === 0, 'tenant_registry_absent');
  addReason(reasons, tenant === null, 'tenant_registry_record_absent');
  addReason(reasons, tenant !== null && !tenantActive(tenant), 'tenant_not_active');
  addReason(
    reasons,
    tenant !== null && !tenantAllows(tenant, input?.operation),
    'tenant_operation_not_allowed',
  );

  if (input?.targetTenantId !== input?.tenantId) {
    addReason(reasons, targetTenant === null, 'target_tenant_registry_record_absent');
    addReason(reasons, targetTenant !== null && !tenantActive(targetTenant), 'target_tenant_not_active');
  }

  return { targetTenant, tenant };
}

function evaluateActorTenantBoundary(input, reasons) {
  const memberships = sortedTextList(input?.actor?.tenantMemberships);
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.tenantId !== input?.tenantId, 'actor_tenant_mismatch');
  addReason(reasons, !memberships.includes(input?.tenantId), 'actor_request_tenant_membership_missing');
  addReason(reasons, !memberships.includes(input?.targetTenantId), 'actor_tenant_membership_missing');
}

function evaluateResource(input, reasons) {
  addReason(reasons, !hasText(input?.resource?.resourceId), 'resource_id_absent');
  addReason(reasons, !hasText(input?.resource?.resourceType), 'resource_type_absent');
  addReason(reasons, input?.resource?.tenantId !== input?.tenantId, 'resource_tenant_mismatch');
  addReason(reasons, !isDigest(input?.resource?.artifactHash), 'resource_artifact_hash_invalid');
  addReason(reasons, input?.resource?.classification !== 'confidential_metadata_only', 'resource_classification_invalid');
}

function evaluateConsent(input, reasons) {
  if (input?.operation !== 'export') {
    return;
  }
  addReason(reasons, input?.consent === null || input?.consent === undefined, 'export_consent_absent');
  addReason(reasons, input?.consent?.status !== 'active', 'export_consent_not_active');
  addReason(reasons, input?.consent?.revoked === true || input?.consent?.status === 'revoked', 'export_consent_revoked');
}

function evaluateExport(input, tenantRegistryState, reasons) {
  if (input?.operation !== 'export') {
    return;
  }

  const recipientTenant = findTenant(input?.tenantRegistry, input?.recipientTenantId);
  addReason(reasons, !hasText(input?.recipientTenantId), 'recipient_tenant_absent');
  addReason(reasons, recipientTenant === null, 'recipient_tenant_registry_record_absent');
  addReason(reasons, recipientTenant !== null && !tenantActive(recipientTenant), 'recipient_tenant_not_active');
  addReason(
    reasons,
    recipientTenant !== null && !tenantAllows(recipientTenant, 'receive_export'),
    'recipient_tenant_receive_export_not_allowed',
  );
  addReason(reasons, tenantRegistryState.tenant !== null && !tenantAllows(tenantRegistryState.tenant, 'export'), 'tenant_export_not_allowed');

  const grant = input?.exportGrant;
  addReason(reasons, !hasText(grant?.grantId), 'export_grant_id_absent');
  addReason(reasons, grant?.status !== 'active', 'export_grant_not_active');
  addReason(reasons, grant?.scope !== EXPORT_SCOPE, 'export_grant_scope_invalid');
  addReason(reasons, grant?.sourceTenantId !== input?.tenantId, 'export_grant_source_tenant_mismatch');
  addReason(reasons, grant?.recipientTenantId !== input?.recipientTenantId, 'export_grant_recipient_tenant_mismatch');
}

function validateInput(input, reasons) {
  canonicalize(input ?? {});
  addReason(reasons, !hasText(input?.requestId), 'request_id_absent');
  addReason(reasons, !OPERATIONS.has(input?.operation), 'operation_invalid');
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, !hasText(input?.targetTenantId), 'target_tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hlcPresent(input?.requestedAtHlc), 'requested_time_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
  const tenantRegistryState = evaluateTenantRegistry(input, reasons);
  evaluateActorTenantBoundary(input, reasons);
  evaluateAuthority(input, reasons);
  evaluateResource(input, reasons);
  evaluateConsent(input, reasons);
  evaluateExport(input, tenantRegistryState, reasons);
}

function registryDigest(input) {
  const relevantTenantIds = [input.tenantId, input.targetTenantId, input.recipientTenantId].filter(hasText).sort();
  const relevantRecords = tenantRegistryRecords(input.tenantRegistry).filter((record) => {
    return relevantTenantIds.includes(record.tenantId);
  });
  return sha256Hex({
    records: relevantRecords,
    schema: 'cybermedica.tenant_registry_evidence.v1',
  });
}

function serviceAccessMaterial(input) {
  return {
    actorDid: input.actor.did,
    operation: input.operation,
    recipientTenantId: input.recipientTenantId ?? null,
    registryDigest: registryDigest(input),
    requestId: input.requestId,
    requestedAtHlc: input.requestedAtHlc,
    resourceArtifactHash: input.resource.artifactHash,
    resourceId: input.resource.resourceId,
    resourceTenantId: input.resource.tenantId,
    resourceType: input.resource.resourceType,
    targetTenantId: input.targetTenantId,
    tenantId: input.tenantId,
  };
}

function buildReceipt(input, materialHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'tenant_service_access',
    artifactVersion: `${input.requestId}@${input.operation}`,
    artifactHash: materialHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.requestedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['metadata_only', 'service_access', 'tenant_isolation'],
    sourceSystem: 'cybermedica-qms',
  });
}

function buildServiceAccess(input, serviceAccessId, materialHash, receipt) {
  return {
    actorDid: input.actor.did,
    immutableAccessReceipt: true,
    operation: input.operation,
    operationalStateMutable: true,
    receiptId: receipt.receiptId,
    requestId: input.requestId,
    requestedAtHlc: input.requestedAtHlc,
    resourceHash: materialHash,
    resourceId: input.resource.resourceId,
    resourceTenantId: input.resource.tenantId,
    resourceType: input.resource.resourceType,
    schema: 'cybermedica.tenant_service_access.v1',
    serviceAccessId,
    targetTenantId: input.targetTenantId,
    tenantId: input.tenantId,
  };
}

export function evaluateTenantServiceAccess(input) {
  const reasons = [];
  validateInput(input, reasons);
  const uniqueReasons = [...new Set(reasons)].sort();
  const denied = uniqueReasons.length > 0;

  if (denied) {
    return {
      schema: 'cybermedica.tenant_service_access_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      serviceAccess: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const materialHash = sha256Hex(serviceAccessMaterial(input));
  const serviceAccessId = `cmta_${sha256Hex({
    materialHash,
    requestId: input.requestId,
    tenantId: input.tenantId,
  }).slice(0, 32)}`;
  const receipt = buildReceipt(input, materialHash);

  return {
    schema: 'cybermedica.tenant_service_access_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    serviceAccess: buildServiceAccess(input, serviceAccessId, materialHash, receipt),
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
