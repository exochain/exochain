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

const HEX_64 = /^[0-9a-f]{64}$/u;
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const REQUIRED_PERMISSION = 'delegate_protocol_task';

const EVENT_TYPES = new Set([
  'delegation_authorized',
  'delegation_expired',
  'delegation_revoked',
  'delegation_scope_reduced',
]);

const ACTIVE_EVENT_TYPES = new Set([
  'delegation_authorized',
  'delegation_scope_reduced',
]);

const RAW_SIGNATURE_FIELD_NAMES = new Set([
  'rawsignature',
  'signaturebytes',
  'signaturematerial',
  'signingsecret',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function sortedUniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && value !== ZERO_HASH;
}

function isDigestOrZero(value) {
  return value === ZERO_HASH || isDigest(value);
}

function normalizedFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function assertNoRawSignatureMaterial(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawSignatureMaterial(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    if (RAW_SIGNATURE_FIELD_NAMES.has(normalizedFieldName(key))) {
      throw new ProtectedContentError(`raw signature material is not allowed at ${path}.${key}`);
    }
    assertNoRawSignatureMaterial(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawSignatureMaterial(input);
  canonicalize(input ?? {});
}

function sortedTextList(values) {
  return Array.isArray(values) ? [...new Set(values.filter(hasText))].sort() : [];
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [BigInt(hlc.physicalMs), BigInt(hlc.logical)];
}

function compareHlc(left, right) {
  if (left[0] < right[0]) {
    return -1;
  }
  if (left[0] > right[0]) {
    return 1;
  }
  if (left[1] < right[1]) {
    return -1;
  }
  if (left[1] > right[1]) {
    return 1;
  }
  return 0;
}

function hasAuthorityPermission(authority) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(REQUIRED_PERMISSION);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_delegation_authority_forbidden');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !hasAuthorityPermission(input?.authority), 'authority_permission_missing');
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateDelegationEventShape(event, reasons) {
  addReason(reasons, !hasText(event?.eventId), 'delegation_event_id_absent');
  addReason(reasons, !EVENT_TYPES.has(event?.eventType), 'delegation_event_type_invalid');
  addReason(reasons, !Number.isSafeInteger(event?.sequence) || event.sequence < 1, 'delegation_sequence_invalid');
  addReason(reasons, !isDigestOrZero(event?.previousDelegationHash), 'previous_delegation_hash_invalid');
  addReason(
    reasons,
    Number.isSafeInteger(event?.sequence) && event.sequence > 1 && event.previousDelegationHash === ZERO_HASH,
    'previous_delegation_hash_missing_for_sequence',
  );
  addReason(reasons, hlcTuple(event?.occurredAtHlc) === null, 'delegation_event_time_invalid');
  addReason(reasons, !hasText(event?.delegationId), 'delegation_id_absent');
  addReason(reasons, !hasText(event?.parentDelegationId), 'parent_delegation_id_absent');
  addReason(reasons, !isDigest(event?.parentDelegationHash), 'parent_delegation_hash_invalid');
  addReason(reasons, !hasText(event?.grantorDid), 'delegation_grantor_absent');
  addReason(reasons, !hasText(event?.delegateDid), 'delegation_delegate_absent');
  addReason(reasons, !hasText(event?.status), 'delegation_status_absent');
  addReason(reasons, !hasText(event?.reasonCode), 'delegation_reason_absent');
  addReason(reasons, !isDigest(event?.evidenceHash), 'delegation_evidence_hash_invalid');
  addReason(reasons, !isDigest(event?.signatureHash), 'delegation_signature_hash_invalid');
}

function evaluateNoSelfGrant(input, reasons) {
  const event = input?.delegationEvent;
  addReason(reasons, hasText(event?.grantorDid) && event.grantorDid !== input?.actor?.did, 'delegation_grantor_actor_mismatch');
  addReason(
    reasons,
    hasText(event?.grantorDid) && hasText(event?.delegateDid) && event.grantorDid === event.delegateDid,
    'delegation_self_grant_forbidden',
  );
}

function isSubset(childValues, parentValues) {
  const parent = new Set(parentValues);
  return childValues.every((value) => parent.has(value));
}

function normalizedScope(scope) {
  return {
    allowedActions: sortedTextList(scope?.allowedActions),
    expiresAtHlc: scope?.expiresAtHlc ?? null,
    notBeforeHlc: scope?.notBeforeHlc ?? null,
    permissions: sortedTextList(scope?.permissions),
    protocolId: hasText(scope?.protocolId) ? scope.protocolId : null,
    role: hasText(scope?.role) ? scope.role : null,
    siteId: hasText(scope?.siteId) ? scope.siteId : null,
  };
}

function evaluateScope(event, reasons) {
  const scope = normalizedScope(event?.scope);
  const parentScope = event?.parentScope;
  const parentSiteIds = sortedTextList(parentScope?.siteIds);
  const parentProtocolIds = sortedTextList(parentScope?.protocolIds);
  const parentPermissions = sortedTextList(parentScope?.permissions);
  const parentActions = sortedTextList(parentScope?.allowedActions);
  const notBefore = hlcTuple(scope.notBeforeHlc);
  const expiresAt = hlcTuple(scope.expiresAtHlc);

  addReason(reasons, !hasText(scope.siteId), 'delegation_scope_site_absent');
  addReason(reasons, !hasText(scope.protocolId), 'delegation_scope_protocol_absent');
  addReason(reasons, !hasText(scope.role), 'delegation_scope_role_absent');
  addReason(reasons, scope.permissions.length === 0, 'delegation_scope_permission_absent');
  addReason(reasons, scope.allowedActions.length === 0, 'delegation_scope_action_absent');
  addReason(reasons, parentSiteIds.length === 0, 'parent_scope_site_absent');
  addReason(reasons, parentProtocolIds.length === 0, 'parent_scope_protocol_absent');
  addReason(reasons, parentPermissions.length === 0, 'parent_scope_permission_absent');
  addReason(reasons, parentActions.length === 0, 'parent_scope_action_absent');
  addReason(reasons, notBefore === null, 'delegation_scope_start_time_invalid');
  addReason(reasons, expiresAt === null, 'delegation_scope_expiry_time_invalid');
  addReason(
    reasons,
    notBefore !== null && expiresAt !== null && compareHlc(notBefore, expiresAt) >= 0,
    'delegation_scope_time_window_invalid',
  );
  addReason(
    reasons,
    hasText(scope.siteId) && parentSiteIds.length > 0 && !parentSiteIds.includes(scope.siteId),
    'delegation_scope_site_escalation',
  );
  addReason(
    reasons,
    hasText(scope.protocolId) && parentProtocolIds.length > 0 && !parentProtocolIds.includes(scope.protocolId),
    'delegation_scope_protocol_escalation',
  );
  addReason(
    reasons,
    scope.permissions.length > 0 && parentPermissions.length > 0 && !isSubset(scope.permissions, parentPermissions),
    'delegation_scope_permission_escalation',
  );
  addReason(
    reasons,
    scope.allowedActions.length > 0 && parentActions.length > 0 && !isSubset(scope.allowedActions, parentActions),
    'delegation_scope_action_escalation',
  );

  return scope;
}

function normalizedLineage(lineage) {
  return Array.isArray(lineage)
    ? lineage
        .map((entry) => ({
          authorityChainHash: hasText(entry?.authorityChainHash) ? entry.authorityChainHash : null,
          delegateDid: hasText(entry?.delegateDid) ? entry.delegateDid : null,
          delegationId: hasText(entry?.delegationId) ? entry.delegationId : null,
          grantorDid: hasText(entry?.grantorDid) ? entry.grantorDid : null,
        }))
        .sort((left, right) => String(left.delegationId).localeCompare(String(right.delegationId)))
    : [];
}

function graphHasCycle(edges) {
  const graph = new Map();
  for (const edge of edges) {
    if (!hasText(edge.grantorDid) || !hasText(edge.delegateDid)) {
      continue;
    }
    const delegates = graph.get(edge.grantorDid) ?? [];
    delegates.push(edge.delegateDid);
    graph.set(edge.grantorDid, delegates);
  }

  const visiting = new Set();
  const visited = new Set();

  function visit(node) {
    if (visiting.has(node)) {
      return true;
    }
    if (visited.has(node)) {
      return false;
    }
    visiting.add(node);
    for (const next of graph.get(node) ?? []) {
      if (visit(next)) {
        return true;
      }
    }
    visiting.delete(node);
    visited.add(node);
    return false;
  }

  return [...graph.keys()].some((node) => visit(node));
}

function evaluateLineage(event, reasons) {
  const lineage = normalizedLineage(event?.lineage);
  const delegationIds = lineage.map((entry) => entry.delegationId).filter(hasText);
  const authorityHashes = lineage.map((entry) => entry.authorityChainHash).filter(hasText);

  addReason(reasons, !Array.isArray(event?.lineage), 'delegation_lineage_invalid');
  addReason(reasons, delegationIds.length !== new Set(delegationIds).size, 'delegation_lineage_duplicate_id');
  addReason(reasons, authorityHashes.some((hash) => !isDigest(hash)), 'delegation_lineage_authority_hash_invalid');

  const edges = [
    ...lineage.map((entry) => ({ grantorDid: entry.grantorDid, delegateDid: entry.delegateDid })),
    { grantorDid: event?.grantorDid, delegateDid: event?.delegateDid },
  ];
  addReason(reasons, graphHasCycle(edges), 'delegation_cycle_detected');

  return lineage;
}

function evaluateRevocation(event, reasons) {
  if (event?.eventType !== 'delegation_revoked') {
    return null;
  }

  const revocation = event?.revocationEvidence;
  addReason(reasons, revocation === null || revocation === undefined, 'revocation_evidence_absent');
  addReason(reasons, revocation?.revokedByDid !== event?.grantorDid, 'revocation_actor_mismatch');
  addReason(reasons, hlcTuple(revocation?.revokedAtHlc) === null, 'revocation_time_invalid');
  addReason(reasons, !hasText(revocation?.reasonCode), 'revocation_reason_absent');
  addReason(reasons, !isDigest(revocation?.revocationSignatureHash), 'revocation_signature_hash_invalid');

  return {
    reasonCode: hasText(revocation?.reasonCode) ? revocation.reasonCode : null,
    revokedAtHlc: revocation?.revokedAtHlc ?? null,
    revokedByDid: hasText(revocation?.revokedByDid) ? revocation.revokedByDid : null,
    signatureHash: isDigest(revocation?.revocationSignatureHash) ? revocation.revocationSignatureHash : null,
    signatureVerified: isDigest(revocation?.revocationSignatureHash),
  };
}

function evaluateExpiration(event, scope, reasons) {
  if (event?.eventType !== 'delegation_expired') {
    return;
  }

  const occurredAt = hlcTuple(event?.occurredAtHlc);
  const expiresAt = hlcTuple(scope?.expiresAtHlc);
  addReason(
    reasons,
    occurredAt !== null && expiresAt !== null && compareHlc(occurredAt, expiresAt) < 0,
    'delegation_expiration_before_scope_expiry',
  );
}

function isActiveForUse(event, scope) {
  if (!ACTIVE_EVENT_TYPES.has(event?.eventType) || event?.status !== 'active') {
    return false;
  }
  const occurredAt = hlcTuple(event?.occurredAtHlc);
  const expiresAt = hlcTuple(scope?.expiresAtHlc);
  return occurredAt !== null && expiresAt !== null && compareHlc(occurredAt, expiresAt) <= 0;
}

function buildDelegationAuditRecord(input, scope, lineage, revocationEvidence) {
  const event = input.delegationEvent;
  const scopeHash = sha256Hex({
    schema: 'cybermedica.delegation_scope.v1',
    scope,
  });
  const lineageHash = sha256Hex({
    lineage,
    schema: 'cybermedica.delegation_lineage.v1',
  });
  const hashMaterial = {
    actorDid: input.actor.did,
    authorityChainHash: input.authority.authorityChainHash,
    delegateDid: event.delegateDid,
    delegationId: event.delegationId,
    eventId: event.eventId,
    eventType: event.eventType,
    evidenceHash: event.evidenceHash,
    grantorDid: event.grantorDid,
    lineageHash,
    occurredAtHlc: event.occurredAtHlc,
    parentDelegationHash: event.parentDelegationHash,
    parentDelegationId: event.parentDelegationId,
    previousDelegationHash: event.previousDelegationHash,
    reasonCode: event.reasonCode,
    revocationEvidence,
    schema: 'cybermedica.delegation_audit_event_hash_material.v1',
    scopeHash,
    sequence: event.sequence,
    signatureHash: event.signatureHash,
    status: event.status,
    tenantId: input.tenantId,
  };
  const delegationEventHash = sha256Hex(hashMaterial);

  return {
    schema: 'cybermedica.delegation_audit_record.v1',
    tenantId: input.tenantId,
    eventId: event.eventId,
    eventType: event.eventType,
    sequence: event.sequence,
    previousDelegationHash: event.previousDelegationHash,
    delegationEventHash,
    delegationId: event.delegationId,
    parentDelegationId: event.parentDelegationId,
    parentDelegationHash: event.parentDelegationHash,
    grantorDid: event.grantorDid,
    delegateDid: event.delegateDid,
    authorityChainHash: input.authority.authorityChainHash,
    status: event.status,
    activeForUse: isActiveForUse(event, scope),
    occurredAtHlc: event.occurredAtHlc,
    reasonCode: event.reasonCode,
    evidenceHash: event.evidenceHash,
    signatureHash: event.signatureHash,
    scope,
    scopeHash,
    lineage,
    lineageHash,
    revocationEvidence,
    operationalDelegationStateMutable: true,
    immutableDelegationAuditEvent: true,
    trustState: 'inactive',
    exochainProductionClaim: false,
    sourceEvidence: [
      'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
      'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
    ],
  };
}

function computeDelegationRecordHash(record) {
  return sha256Hex({
    actorDid: record?.grantorDid,
    authorityChainHash: record?.authorityChainHash,
    delegateDid: record?.delegateDid,
    delegationId: record?.delegationId,
    eventId: record?.eventId,
    eventType: record?.eventType,
    evidenceHash: record?.evidenceHash,
    grantorDid: record?.grantorDid,
    lineageHash: record?.lineageHash,
    occurredAtHlc: record?.occurredAtHlc,
    parentDelegationHash: record?.parentDelegationHash,
    parentDelegationId: record?.parentDelegationId,
    previousDelegationHash: record?.previousDelegationHash,
    reasonCode: record?.reasonCode,
    revocationEvidence: record?.revocationEvidence,
    schema: 'cybermedica.delegation_audit_event_hash_material.v1',
    scopeHash: record?.scopeHash,
    sequence: record?.sequence,
    signatureHash: record?.signatureHash,
    status: record?.status,
    tenantId: record?.tenantId,
  });
}

function buildReceipt(input, delegationEventHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'delegation_audit_event',
    artifactVersion: `${input.delegationEvent.delegationId}@${input.delegationEvent.sequence}`,
    artifactHash: delegationEventHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.delegationEvent.occurredAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['authority', 'delegation', 'hash_chained', 'metadata_only'],
    sourceSystem: 'cybermedica-qms',
  });
}

function unwrapDelegationAuditRecord(entry) {
  return entry?.delegationAuditRecord ?? entry;
}

export function recordDelegationAuditEvent(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateDelegationEventShape(input?.delegationEvent, reasons);
  evaluateNoSelfGrant(input, reasons);
  const scope = evaluateScope(input?.delegationEvent, reasons);
  const lineage = evaluateLineage(input?.delegationEvent, reasons);
  const revocationEvidence = evaluateRevocation(input?.delegationEvent, reasons);
  evaluateExpiration(input?.delegationEvent, scope, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const uniqueReasons = sortedUniqueReasons(reasons);
  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.delegation_audit_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      delegationAuditRecord: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const delegationAuditRecord = buildDelegationAuditRecord(input, scope, lineage, revocationEvidence);
  const receipt = buildReceipt(input, delegationAuditRecord.delegationEventHash);

  return {
    schema: 'cybermedica.delegation_audit_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    delegationAuditRecord,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

export function verifyDelegationAuditChain(entries) {
  assertMetadataOnly(entries);

  const reasons = [];
  if (!Array.isArray(entries) || entries.length === 0) {
    reasons.push('delegation_chain_empty');
  }

  let expectedPreviousHash = ZERO_HASH;
  let headHash = ZERO_HASH;
  const safeEntries = Array.isArray(entries) ? entries : [];

  safeEntries.forEach((entry, index) => {
    const position = index + 1;
    const record = unwrapDelegationAuditRecord(entry);

    addReason(reasons, record === null || record === undefined, `delegation_record_absent_at_${position}`);
    addReason(reasons, record?.sequence !== position, `delegation_sequence_broken_at_${position}`);
    addReason(
      reasons,
      record?.previousDelegationHash !== expectedPreviousHash,
      `delegation_chain_broken_at_${position}`,
    );

    if (record !== null && record !== undefined) {
      const computedHash = computeDelegationRecordHash(record);
      addReason(reasons, record.delegationEventHash !== computedHash, `delegation_event_hash_mismatch_at_${position}`);
      expectedPreviousHash = record.delegationEventHash;
      headHash = record.delegationEventHash;
    }
  });

  const uniqueReasons = sortedUniqueReasons(reasons);
  const valid = uniqueReasons.length === 0;

  return {
    schema: 'cybermedica.delegation_audit_chain_verification.v1',
    valid,
    failClosed: !valid,
    reasons: uniqueReasons,
    entriesVerified: valid ? safeEntries.length : 0,
    headHash: valid ? headHash : null,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
