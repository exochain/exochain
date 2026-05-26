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
const REQUIRED_PERMISSION = 'audit_append';

const EVENT_TYPES = new Set([
  'ai_review',
  'audit_readiness',
  'capa_closure',
  'document_version',
  'enrollment_gate',
  'evidence_custody_transfer',
  'participant_consent',
  'protocol_launch',
  'qms_control_approval',
  'quality_objective',
  'sponsor_export',
  'support_access',
  'support_access_policy',
  'tenant_access',
  'training_delegation',
]);

const AUDIT_RESULTS = new Set([
  'approved',
  'closed',
  'denied',
  'held',
  'logged',
  'permitted',
  'rejected',
  'released',
  'revoked',
]);

const SIGNATURE_ALGORITHMS = new Set(['ed25519', 'frost_ristretto255', 'hybrid_ed25519_pq']);

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

function sortedDigestList(values, reasons) {
  if (!Array.isArray(values)) {
    reasons.push('dag_parent_hashes_invalid');
    return [];
  }

  const normalized = [];
  for (const value of values) {
    addReason(reasons, !isDigest(value), 'dag_parent_hash_invalid');
    if (isDigest(value)) {
      normalized.push(value);
    }
  }
  return [...new Set(normalized)].sort();
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

function hlcPresent(hlc) {
  return Number.isSafeInteger(hlc?.physicalMs) && Number.isSafeInteger(hlc?.logical) && hlc.logical >= 0;
}

function hasAuthorityPermission(authority) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(REQUIRED_PERMISSION);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !hasAuthorityPermission(input?.authority), 'authority_permission_missing');
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateAuditEvent(input, reasons) {
  const event = input?.auditEvent;
  addReason(reasons, !hasText(event?.eventId), 'audit_event_id_absent');
  addReason(reasons, !EVENT_TYPES.has(event?.eventType), 'audit_event_type_invalid');
  addReason(reasons, !hasText(event?.action), 'audit_action_absent');
  addReason(reasons, !AUDIT_RESULTS.has(event?.result), 'audit_result_invalid');
  addReason(reasons, !hasText(event?.objectRef), 'audit_object_ref_absent');
  addReason(reasons, !Number.isSafeInteger(event?.sequence) || event.sequence < 1, 'audit_sequence_invalid');
  addReason(reasons, !hlcPresent(event?.occurredAtHlc), 'audit_event_time_invalid');
  addReason(reasons, !isDigest(event?.evidenceHash), 'audit_evidence_hash_invalid');
  addReason(reasons, !isDigestOrZero(event?.previousAuditHash), 'previous_audit_hash_invalid');
  addReason(
    reasons,
    Number.isSafeInteger(event?.sequence) && event.sequence > 1 && event.previousAuditHash === ZERO_HASH,
    'previous_audit_hash_missing_for_sequence',
  );
}

function evaluateOperationalLog(input, reasons) {
  const log = input?.operationalLog;
  addReason(reasons, !hasText(log?.logId), 'operational_log_id_absent');
  addReason(reasons, !hasText(log?.source), 'operational_log_source_absent');
  addReason(reasons, log?.mutable !== true, 'operational_log_must_be_mutable');
  addReason(reasons, !hasText(log?.retentionClass), 'operational_retention_class_absent');
  addReason(reasons, !isDigest(log?.eventPayloadHash), 'operational_payload_hash_invalid');
}

function evaluateReceiptEvidence(input, reasons) {
  const receipt = input?.receiptEvidence;
  addReason(reasons, !hasText(receipt?.receiptId), 'receipt_id_absent');
  addReason(reasons, !isDigest(receipt?.actionHash), 'receipt_action_hash_invalid');
  addReason(reasons, !hasText(receipt?.signerDid), 'receipt_signer_absent');
  addReason(reasons, !SIGNATURE_ALGORITHMS.has(receipt?.signatureAlgorithm), 'receipt_signature_algorithm_invalid');
  addReason(reasons, !isDigest(receipt?.signatureHash), 'receipt_signature_missing');
}

function evaluateDagEvidence(input, reasons) {
  const dag = input?.dagEvidence;
  addReason(reasons, !isDigest(dag?.nodeHash), 'dag_node_hash_invalid');
  addReason(reasons, !isDigest(dag?.payloadHash), 'dag_payload_hash_invalid');
  addReason(
    reasons,
    isDigest(dag?.payloadHash) && isDigest(input?.receiptEvidence?.actionHash) && dag.payloadHash !== input.receiptEvidence.actionHash,
    'dag_payload_hash_mismatch',
  );
  addReason(reasons, !hasText(dag?.nodeSignerDid), 'dag_node_signer_absent');
  addReason(reasons, !isDigest(dag?.nodeSignatureHash), 'dag_signature_missing');
  return sortedDigestList(dag?.parentNodeHashes, reasons);
}

function buildAuditEntry(input) {
  const event = input.auditEvent;
  return {
    schema: 'cybermedica.audit_entry.v1',
    exochainAuditDomain: 'exo.governance.audit_entry.v1',
    id: event.eventId,
    timestamp: event.occurredAtHlc,
    actor: input.actor.did,
    action: event.action,
    result: event.result,
    evidenceHash: event.evidenceHash,
    chainHash: event.previousAuditHash,
    cybermedicaContext: {
      decisionForumReceiptId: event.decisionForumReceiptId ?? null,
      eventType: event.eventType,
      objectRef: event.objectRef,
      sequence: event.sequence,
      tenantId: input.tenantId,
    },
  };
}

function computeAuditEntryHash(auditEntry) {
  return sha256Hex({
    action: auditEntry?.action,
    actor: auditEntry?.actor,
    chainHash: auditEntry?.chainHash,
    cybermedicaContext: auditEntry?.cybermedicaContext,
    evidenceHash: auditEntry?.evidenceHash,
    exochainAuditDomain: auditEntry?.exochainAuditDomain,
    id: auditEntry?.id,
    result: auditEntry?.result,
    schema: auditEntry?.schema,
    timestamp: auditEntry?.timestamp,
  });
}

function buildOperationalAuditRecord(input) {
  const operationalLogHash = sha256Hex({
    auditEventId: input.auditEvent.eventId,
    eventPayloadHash: input.operationalLog.eventPayloadHash,
    logId: input.operationalLog.logId,
    retentionClass: input.operationalLog.retentionClass,
    schema: 'cybermedica.operational_audit_log.v1',
    source: input.operationalLog.source,
    tenantId: input.tenantId,
  });

  return {
    schema: 'cybermedica.operational_audit_record.v1',
    operationalLogId: input.operationalLog.logId,
    tenantId: input.tenantId,
    auditEventId: input.auditEvent.eventId,
    source: input.operationalLog.source,
    retentionClass: input.operationalLog.retentionClass,
    eventPayloadHash: input.operationalLog.eventPayloadHash,
    operationalLogHash,
    operationalStateMutable: true,
    immutableReceipt: false,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function buildLocalReceipt(input, auditEntryHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'audit_event_receipt',
    artifactVersion: `${input.auditEvent.eventId}@${input.auditEvent.sequence}`,
    artifactHash: auditEntryHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.auditEvent.occurredAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['audit_event', 'hash_chained', 'metadata_only', 'signed_receipt_evidence'],
    sourceSystem: 'cybermedica-qms',
  });
}

function buildImmutableAuditEvidence(input, auditEntry, auditEntryHash, parentNodeHashes, operationalLogHash) {
  return {
    schema: 'cybermedica.immutable_audit_evidence.v1',
    tenantId: input.tenantId,
    auditEventId: input.auditEvent.eventId,
    sequence: input.auditEvent.sequence,
    previousAuditHash: input.auditEvent.previousAuditHash,
    auditEntry,
    auditEntryHash,
    externalTrustReceipt: {
      receiptId: input.receiptEvidence.receiptId,
      actionHash: input.receiptEvidence.actionHash,
      signerDid: input.receiptEvidence.signerDid,
      signatureAlgorithm: input.receiptEvidence.signatureAlgorithm,
      signatureHash: input.receiptEvidence.signatureHash,
      signed: true,
      adapterVerified: false,
    },
    dagNode: {
      nodeHash: input.dagEvidence.nodeHash,
      payloadHash: input.dagEvidence.payloadHash,
      parentNodeHashes,
      nodeSignerDid: input.dagEvidence.nodeSignerDid,
      nodeSignatureHash: input.dagEvidence.nodeSignatureHash,
      signed: true,
    },
    operationalLogHash,
    immutableAuditReceipt: true,
    operationalStateMutable: false,
    trustState: 'inactive',
    exochainProductionClaim: false,
    sourceEvidence: [
      'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
      'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
    ],
  };
}

export function recordAuditEventReceipt(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateAuditEvent(input, reasons);
  evaluateOperationalLog(input, reasons);
  evaluateReceiptEvidence(input, reasons);
  const parentNodeHashes = evaluateDagEvidence(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const uniqueReasons = sortedUniqueReasons(reasons);
  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.audit_event_receipt_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      operationalAuditRecord: null,
      immutableAuditEvidence: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const auditEntry = buildAuditEntry(input);
  const auditEntryHash = computeAuditEntryHash(auditEntry);
  const operationalAuditRecord = buildOperationalAuditRecord(input);
  const immutableAuditEvidence = buildImmutableAuditEvidence(
    input,
    auditEntry,
    auditEntryHash,
    parentNodeHashes,
    operationalAuditRecord.operationalLogHash,
  );
  const receipt = buildLocalReceipt(input, auditEntryHash);

  return {
    schema: 'cybermedica.audit_event_receipt_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    operationalAuditRecord,
    immutableAuditEvidence,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function unwrapImmutableAuditEvidence(entry) {
  return entry?.immutableAuditEvidence ?? entry;
}

export function verifyAuditEventReceiptChain(entries) {
  assertMetadataOnly(entries);

  const reasons = [];
  if (!Array.isArray(entries) || entries.length === 0) {
    reasons.push('audit_chain_empty');
  }

  let expectedPreviousHash = ZERO_HASH;
  let headHash = ZERO_HASH;
  const safeEntries = Array.isArray(entries) ? entries : [];

  safeEntries.forEach((entry, index) => {
    const position = index + 1;
    const evidence = unwrapImmutableAuditEvidence(entry);
    const auditEntry = evidence?.auditEntry;
    const sequence = evidence?.sequence ?? auditEntry?.cybermedicaContext?.sequence;

    addReason(reasons, auditEntry === null || auditEntry === undefined, `audit_entry_absent_at_${position}`);
    addReason(reasons, sequence !== position, `audit_sequence_broken_at_${position}`);
    addReason(reasons, auditEntry?.chainHash !== expectedPreviousHash, `audit_chain_broken_at_${position}`);

    if (auditEntry !== null && auditEntry !== undefined) {
      const computedHash = computeAuditEntryHash(auditEntry);
      addReason(reasons, evidence?.auditEntryHash !== computedHash, `audit_entry_hash_mismatch_at_${position}`);
      expectedPreviousHash = computedHash;
      headHash = computedHash;
    }
  });

  const uniqueReasons = sortedUniqueReasons(reasons);
  const valid = uniqueReasons.length === 0;

  return {
    schema: 'cybermedica.audit_event_chain_verification.v1',
    valid,
    failClosed: !valid,
    reasons: uniqueReasons,
    entriesVerified: valid ? safeEntries.length : 0,
    headHash: valid ? headHash : null,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
