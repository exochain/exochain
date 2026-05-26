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
const REQUIRED_PERMISSION = 'custody_transfer';

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

function sortedTextList(values) {
  if (!Array.isArray(values)) {
    return [];
  }
  return values.filter(hasText).sort();
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [hlc.physicalMs, hlc.logical];
}

function compareHlc(left, right) {
  if (left[0] !== right[0]) {
    return left[0] - right[0];
  }
  return left[1] - right[1];
}

function nextSequence(sequence) {
  return sequence + 1;
}

function evaluateAuthority(input, reasons) {
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !Array.isArray(input?.authority?.permissions) || !input.authority.permissions.includes(REQUIRED_PERMISSION),
    'authority_permission_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateEvidence(input, reasons) {
  addReason(reasons, !hasText(input?.evidence?.evidenceId), 'evidence_id_absent');
  addReason(reasons, !hasText(input?.evidence?.evidenceType), 'evidence_type_absent');
  addReason(reasons, !isDigest(input?.evidence?.artifactHash), 'evidence_artifact_hash_invalid');
  addReason(reasons, !hasText(input?.evidence?.currentCustodianDid), 'current_custodian_absent');
  addReason(reasons, !isDigest(input?.evidence?.currentCustodyDigest), 'current_custody_digest_invalid');
  addReason(
    reasons,
    !Number.isSafeInteger(input?.evidence?.custodySequence) || input.evidence.custodySequence < 1,
    'custody_sequence_invalid',
  );
  addReason(reasons, !hasText(input?.evidence?.classification), 'evidence_classification_absent');
}

function evaluateTransfer(input, reasons) {
  const previousTransferAt = hlcTuple(input?.transfer?.previousTransferAtHlc);
  const transferAt = hlcTuple(input?.transfer?.transferAtHlc);

  addReason(reasons, !hasText(input?.transfer?.fromCustodianDid), 'from_custodian_absent');
  addReason(reasons, !hasText(input?.transfer?.toCustodianDid), 'to_custodian_absent');
  addReason(reasons, input?.transfer?.fromCustodianDid !== input?.evidence?.currentCustodianDid, 'current_custodian_mismatch');
  addReason(reasons, input?.actor?.did !== input?.transfer?.fromCustodianDid, 'actor_custodian_mismatch');
  addReason(
    reasons,
    hasText(input?.transfer?.fromCustodianDid) && input.transfer.fromCustodianDid === input?.transfer?.toCustodianDid,
    'recipient_custodian_unchanged',
  );
  addReason(reasons, !hasText(input?.transfer?.transferType), 'transfer_type_absent');
  addReason(reasons, !hasText(input?.transfer?.reasonCode), 'transfer_reason_absent');
  addReason(reasons, sortedTextList(input?.transfer?.evidenceRefIds).length === 0, 'evidence_refs_absent');
  addReason(reasons, previousTransferAt === null, 'previous_transfer_time_invalid');
  addReason(reasons, transferAt === null, 'transfer_time_invalid');
  addReason(
    reasons,
    previousTransferAt !== null && transferAt !== null && compareHlc(transferAt, previousTransferAt) <= 0,
    'transfer_time_not_monotonic',
  );
}

function evaluateCustodyTransfer(input, reasons) {
  canonicalize(input ?? {});
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  evaluateAuthority(input, reasons);
  evaluateEvidence(input, reasons);
  evaluateTransfer(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
  addReason(
    reasons,
    isDigest(input?.custodyDigest) &&
      isDigest(input?.evidence?.currentCustodyDigest) &&
      input.custodyDigest !== input.evidence.currentCustodyDigest,
    'custody_digest_mismatch',
  );
}

function buildCustodyMaterial(input) {
  return {
    schema: 'cybermedica.evidence_custody_material.v1',
    actorDid: input.actor.did,
    artifactHash: input.evidence.artifactHash,
    authorityChainHash: input.authority.authorityChainHash,
    evidenceId: input.evidence.evidenceId,
    evidenceRefIds: sortedTextList(input.transfer.evidenceRefIds),
    evidenceType: input.evidence.evidenceType,
    fromCustodianDid: input.transfer.fromCustodianDid,
    previousCustodyDigest: input.evidence.currentCustodyDigest,
    previousSequence: input.evidence.custodySequence,
    previousTransferAtHlc: input.transfer.previousTransferAtHlc,
    reasonCode: input.transfer.reasonCode,
    tenantId: input.tenantId,
    toCustodianDid: input.transfer.toCustodianDid,
    transferAtHlc: input.transfer.transferAtHlc,
    transferType: input.transfer.transferType,
  };
}

function buildReceipt(input, custodyMaterialHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'evidence_custody_transfer',
    artifactVersion: `${input.evidence.evidenceId}@${nextSequence(input.evidence.custodySequence)}`,
    artifactHash: custodyMaterialHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.transfer.transferAtHlc,
    custodyDigest: custodyMaterialHash,
    sensitivityTags: ['chain_of_custody', 'evidence', 'metadata_only'],
    sourceSystem: 'cybermedica-qms',
  });
}

function buildCustodyTransfer(input, custodyMaterialHash, receipt) {
  const sequence = nextSequence(input.evidence.custodySequence);

  return {
    schema: 'cybermedica.evidence_custody_transfer.v1',
    custodyTransferId: `cmct_${sha256Hex({
      tenantId: input.tenantId,
      evidenceId: input.evidence.evidenceId,
      sequence,
      newCustodyDigest: custodyMaterialHash,
    }).slice(0, 32)}`,
    tenantId: input.tenantId,
    evidenceId: input.evidence.evidenceId,
    evidenceType: input.evidence.evidenceType,
    artifactHash: input.evidence.artifactHash,
    classification: input.evidence.classification,
    sequence,
    fromCustodianDid: input.transfer.fromCustodianDid,
    toCustodianDid: input.transfer.toCustodianDid,
    previousCustodyDigest: input.evidence.currentCustodyDigest,
    newCustodyDigest: custodyMaterialHash,
    transferType: input.transfer.transferType,
    reasonCode: input.transfer.reasonCode,
    transferAtHlc: input.transfer.transferAtHlc,
    previousTransferAtHlc: input.transfer.previousTransferAtHlc,
    evidenceRefDigest: sha256Hex({
      tenantId: input.tenantId,
      evidenceId: input.evidence.evidenceId,
      evidenceRefIds: sortedTextList(input.transfer.evidenceRefIds),
    }),
    authorityChainHash: input.authority.authorityChainHash,
    receiptId: receipt.receiptId,
    immutableCustodyReceipt: true,
    operationalStateMutable: true,
  };
}

export function evaluateEvidenceCustodyTransfer(input) {
  const reasons = [];
  evaluateCustodyTransfer(input, reasons);
  const uniqueReasons = [...new Set(reasons)].sort();

  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.evidence_custody_transfer_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      custodyTransfer: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const custodyMaterialHash = sha256Hex(buildCustodyMaterial(input));
  const receipt = buildReceipt(input, custodyMaterialHash);

  return {
    schema: 'cybermedica.evidence_custody_transfer_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    custodyTransfer: buildCustodyTransfer(input, custodyMaterialHash, receipt),
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
