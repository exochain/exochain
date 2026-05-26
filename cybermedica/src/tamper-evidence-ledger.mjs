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
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const REQUIRED_PERMISSION = 'tamper_evidence_review';

const REQUIRED_TAMPER_ACTIONS = Object.freeze([
  'audit_package_release',
  'capa_closure',
  'consent_policy_change',
  'enrollment_gate',
  'evidence_custody_transfer',
  'evidence_intake',
  'protocol_launch',
  'qms_control_approval',
  'sponsor_export',
  'support_access_policy',
]);

const LEDGER_STATUSES = new Set(['reviewed']);
const HUMAN_REVIEW_DECISIONS = new Set(['tamper_evidence_ready', 'hold_for_tamper_evidence_gap']);
const SIGNATURE_ALGORITHMS = new Set(['ed25519', 'frost_ristretto255', 'hybrid_ed25519_pq']);

const RAW_TAMPER_EVIDENCE_FIELDS = new Set([
  'clinicalnote',
  'evidencebody',
  'freetext',
  'rawclinicalnote',
  'rawevidence',
  'rawpayload',
  'rawrecord',
  'rawsourcedata',
  'rawtamperevidencecontent',
  'sourcebody',
  'sourcedocumentbody',
]);

const SECRET_TAMPER_EVIDENCE_FIELDS = new Set([
  'accesstoken',
  'adaptersecret',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'bootstrapsecret',
  'bootstraptoken',
  'clientsecret',
  'credential',
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

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function uniqueSorted(reasons) {
  return [...new Set(reasons)].sort();
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && value !== ZERO_HASH;
}

function isPositiveSafeInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
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

function assertNoRawTamperEvidenceContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawTamperEvidenceContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_TAMPER_EVIDENCE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw tamper evidence content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_TAMPER_EVIDENCE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`tamper evidence secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawTamperEvidenceContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawTamperEvidenceContent(input ?? {});
  canonicalize(input ?? {});
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function integerBasisPoints(present, total) {
  if (!Number.isSafeInteger(present) || !Number.isSafeInteger(total) || present <= 0 || total <= 0) {
    return 0;
  }
  return Number((BigInt(present) * 10_000n) / BigInt(total));
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

function hasAuthorityPermission(authority) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(REQUIRED_PERMISSION);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !hasAuthorityPermission(input?.authority), 'authority_permission_missing');
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'policy_hash_invalid');
  addReason(reasons, hlcTuple(policy?.reviewedAtHlc) === null, 'policy_review_time_invalid');
  addReason(reasons, policy?.hashChainRequired !== true, 'policy_hash_chain_not_required');
  addReason(reasons, policy?.receiptVerificationRequired !== true, 'policy_receipt_verification_not_required');
  addReason(reasons, policy?.metadataOnly !== true, 'policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'policy_protected_boundary_invalid');
  addReason(reasons, policy?.rawPayloadExcluded !== true, 'policy_raw_payload_boundary_invalid');
  addReason(reasons, policy?.humanReviewRequired !== true, 'policy_human_review_not_required');

  const configuredActions = new Set(sortedTextList(policy?.requiredActionTypes));
  for (const action of REQUIRED_TAMPER_ACTIONS) {
    addReason(reasons, !configuredActions.has(action), `policy_required_action_missing:${action}`);
  }
}

function evaluateLedgerShape(ledger, reasons) {
  addReason(reasons, !hasText(ledger?.ledgerRef), 'ledger_ref_absent');
  addReason(reasons, !hasText(ledger?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(ledger?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(ledger?.sourceSystemRef), 'source_system_ref_absent');
  addReason(reasons, !LEDGER_STATUSES.has(ledger?.status), 'ledger_not_reviewed');
  addReason(reasons, ledger?.chainStartHash !== ZERO_HASH, 'ledger_chain_start_invalid');
  addReason(reasons, !Array.isArray(ledger?.entries) || ledger.entries.length === 0, 'ledger_entries_absent');
}

function entryLabel(entry) {
  return hasText(entry?.actionType) ? entry.actionType : 'unknown';
}

function evaluateReceiptEvidence(entry, reasons) {
  const action = entryLabel(entry);
  const receipt = entry?.receiptEvidence;
  addReason(reasons, !hasText(receipt?.receiptId), `receipt_id_absent:${action}`);
  addReason(reasons, receipt?.verified !== true, `receipt_evidence_not_verified:${action}`);
  addReason(reasons, !isDigest(receipt?.actionHash), `receipt_action_hash_invalid:${action}`);
  addReason(
    reasons,
    isDigest(receipt?.actionHash) && isDigest(entry?.actionHash) && receipt.actionHash !== entry.actionHash,
    `receipt_action_hash_mismatch:${action}`,
  );
  addReason(reasons, !hasText(receipt?.signerDid), `receipt_signer_absent:${action}`);
  addReason(reasons, !SIGNATURE_ALGORITHMS.has(receipt?.signatureAlgorithm), `receipt_signature_algorithm_invalid:${action}`);
  addReason(reasons, !isDigest(receipt?.signatureHash), `receipt_signature_hash_invalid:${action}`);
  addReason(reasons, !isDigest(receipt?.dagNodeHash), `dag_node_hash_invalid:${action}`);
  addReason(reasons, !isDigest(receipt?.dagPayloadHash), `dag_payload_hash_invalid:${action}`);
  addReason(
    reasons,
    isDigest(receipt?.dagPayloadHash) && isDigest(entry?.actionHash) && receipt.dagPayloadHash !== entry.actionHash,
    `dag_payload_hash_mismatch:${action}`,
  );
}

function evaluateEntry(entry, policy, reasons) {
  const action = entryLabel(entry);
  addReason(reasons, !REQUIRED_TAMPER_ACTIONS.includes(action), `ledger_action_unsupported:${action}`);
  addReason(reasons, !hasText(entry?.actionRef), `ledger_action_ref_absent:${action}`);
  addReason(reasons, !isPositiveSafeInteger(entry?.sequence), `ledger_sequence_invalid:${action}`);
  addReason(reasons, !isDigest(entry?.actionHash), `ledger_action_hash_invalid:${action}`);
  addReason(reasons, !isDigest(entry?.evidenceHash), `ledger_evidence_hash_invalid:${action}`);
  addReason(reasons, !isDigest(entry?.custodyDigest), `ledger_custody_digest_invalid:${action}`);
  addReason(reasons, hlcTuple(entry?.occurredAtHlc) === null, `ledger_entry_time_invalid:${action}`);
  addReason(
    reasons,
    hlcTuple(entry?.occurredAtHlc) !== null &&
      hlcTuple(policy?.reviewedAtHlc) !== null &&
      !hlcAfter(entry.occurredAtHlc, policy.reviewedAtHlc),
    `ledger_entry_before_policy_review:${action}`,
  );
  addReason(reasons, entry?.metadataOnly !== true, `ledger_entry_metadata_boundary_invalid:${action}`);
  addReason(reasons, entry?.protectedContentExcluded !== true, `ledger_entry_protected_boundary_invalid:${action}`);
  addReason(reasons, entry?.rawPayloadExcluded !== true, `ledger_entry_raw_payload_boundary_invalid:${action}`);
  evaluateReceiptEvidence(entry, reasons);
}

function evaluateHumanReview(review, reasons) {
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.reviewDecision), 'human_review_decision_invalid');
  addReason(reasons, review?.reviewDecision !== 'tamper_evidence_ready', 'human_review_not_ready');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, !isDigest(review?.evidenceBundleHash), 'human_review_evidence_hash_invalid');
  addReason(reasons, !isDigest(review?.qualityApprovalHash), 'quality_approval_hash_invalid');
  addReason(reasons, review?.decisionForum?.verified !== true, 'decision_forum_unverified');
  addReason(reasons, review?.decisionForum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, review?.decisionForum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, review?.decisionForum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, review?.decisionForum?.openChallenge === true, 'challenge_open');
  addReason(reasons, !hasText(review?.decisionForum?.decisionId), 'decision_forum_id_absent');
  addReason(reasons, !hasText(review?.decisionForum?.workflowReceiptId), 'decision_forum_workflow_receipt_absent');
}

function sortedLedgerEntries(entries) {
  if (!Array.isArray(entries)) {
    return [];
  }
  return [...entries].sort((left, right) => {
    const leftSequence = Number.isSafeInteger(left?.sequence) ? left.sequence : Number.MAX_SAFE_INTEGER;
    const rightSequence = Number.isSafeInteger(right?.sequence) ? right.sequence : Number.MAX_SAFE_INTEGER;
    if (leftSequence !== rightSequence) {
      return leftSequence - rightSequence;
    }
    return entryLabel(left).localeCompare(entryLabel(right));
  });
}

function computeTamperRecordHash(record) {
  return sha256Hex({
    actionHash: record?.actionHash,
    actionRef: record?.actionRef,
    actionType: record?.actionType,
    custodyDigest: record?.custodyDigest,
    evidenceHash: record?.evidenceHash,
    externalReceipt: record?.externalReceipt,
    occurredAtHlc: record?.occurredAtHlc,
    previousTamperRecordHash: record?.previousTamperRecordHash,
    schema: record?.schema,
    sequence: record?.sequence,
    tenantId: record?.tenantId,
  });
}

function buildTamperRecord(input, entry, previousTamperRecordHash) {
  const record = {
    schema: 'cybermedica.tamper_evidence_record.v1',
    tenantId: input.tenantId,
    actionType: entry.actionType,
    actionRef: entry.actionRef,
    sequence: entry.sequence,
    previousTamperRecordHash,
    actionHash: entry.actionHash,
    evidenceHash: entry.evidenceHash,
    custodyDigest: entry.custodyDigest,
    occurredAtHlc: entry.occurredAtHlc,
    externalReceipt: {
      receiptId: entry.receiptEvidence.receiptId,
      actionHash: entry.receiptEvidence.actionHash,
      signerDid: entry.receiptEvidence.signerDid,
      signatureAlgorithm: entry.receiptEvidence.signatureAlgorithm,
      signatureHash: entry.receiptEvidence.signatureHash,
      dagNodeHash: entry.receiptEvidence.dagNodeHash,
      dagPayloadHash: entry.receiptEvidence.dagPayloadHash,
      verified: entry.receiptEvidence.verified === true,
      adapterVerified: entry.receiptEvidence.adapterVerified === true,
    },
    immutableTamperEvidence: true,
    operationalStateMutable: false,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
  return {
    ...record,
    tamperRecordHash: computeTamperRecordHash(record),
  };
}

function buildDeniedLedger(input, reasons) {
  return {
    schema: 'cybermedica.tamper_evidence_ledger.v1',
    ledgerRef: input?.ledger?.ledgerRef ?? null,
    tenantId: input?.tenantId ?? null,
    tamperEvidenceStatus: 'blocked',
    actionCoverageBasisPoints: 0,
    receiptVerificationBasisPoints: 0,
    chainVerified: false,
    records: [],
    coveredActionTypes: [],
    chainHeadHash: null,
    ledgerHash: null,
    reasons,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function buildLocalReceipt(input, ledgerHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'tamper_evidence_ledger',
    artifactVersion: input.ledger.ledgerRef,
    artifactHash: ledgerHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['hash_chained', 'metadata_only', 'nfr_006', 'tamper_evidence'],
    sourceSystem: 'cybermedica-qms',
  });
}

function buildPermittedLedger(input, records, coveredActionTypes, verifiedReceiptCount) {
  const chainHeadHash = records.at(-1)?.tamperRecordHash ?? ZERO_HASH;
  const ledgerHash = sha256Hex({
    coveredActionTypes,
    ledgerRef: input.ledger.ledgerRef,
    policyHash: input.tamperEvidencePolicy.policyHash,
    records,
    schema: 'cybermedica.tamper_evidence_ledger_hash.v1',
    tenantId: input.tenantId,
  });

  return {
    schema: 'cybermedica.tamper_evidence_ledger.v1',
    ledgerRef: input.ledger.ledgerRef,
    tenantId: input.tenantId,
    protocolRef: input.ledger.protocolRef,
    siteRef: input.ledger.siteRef,
    sourceSystemRef: input.ledger.sourceSystemRef,
    tamperEvidenceStatus: 'ready',
    coveredActionTypes,
    actionCoverageBasisPoints: integerBasisPoints(coveredActionTypes.length, REQUIRED_TAMPER_ACTIONS.length),
    receiptVerificationBasisPoints: integerBasisPoints(verifiedReceiptCount, REQUIRED_TAMPER_ACTIONS.length),
    chainVerified: true,
    records,
    chainStartHash: ZERO_HASH,
    chainHeadHash,
    ledgerHash,
    trustState: 'inactive',
    exochainProductionClaim: false,
    sourceEvidence: [
      'cybermedica_2_0_sandy_seven_layer_master_prd.md',
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
      'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
    ],
  };
}

export function verifyTamperEvidenceChain(records) {
  assertMetadataOnly(records);

  const reasons = [];
  if (!Array.isArray(records) || records.length === 0) {
    reasons.push('tamper_chain_empty');
  }

  let expectedPreviousHash = ZERO_HASH;
  let headHash = ZERO_HASH;
  const safeRecords = Array.isArray(records) ? records : [];

  safeRecords.forEach((record, index) => {
    const position = index + 1;
    addReason(reasons, record?.sequence !== position, `tamper_sequence_broken_at_${position}`);
    addReason(reasons, record?.previousTamperRecordHash !== expectedPreviousHash, `tamper_chain_broken_at_${position}`);

    const computedHash = computeTamperRecordHash(record);
    addReason(reasons, record?.tamperRecordHash !== computedHash, `tamper_record_hash_mismatch_at_${position}`);
    expectedPreviousHash = computedHash;
    headHash = computedHash;
  });

  const uniqueReasons = uniqueSorted(reasons);
  const valid = uniqueReasons.length === 0;

  return {
    schema: 'cybermedica.tamper_evidence_chain_verification.v1',
    valid,
    failClosed: !valid,
    reasons: uniqueReasons,
    entriesVerified: valid ? safeRecords.length : 0,
    headHash: valid ? headHash : null,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

export function evaluateTamperEvidenceLedger(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluatePolicy(input?.tamperEvidencePolicy, reasons);
  evaluateLedgerShape(input?.ledger, reasons);
  evaluateHumanReview(input?.humanReview, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const entries = sortedLedgerEntries(input?.ledger?.entries);
  const entryActions = new Set(entries.map((entry) => entry?.actionType).filter(hasText));
  for (const action of REQUIRED_TAMPER_ACTIONS) {
    addReason(reasons, !entryActions.has(action), `ledger_action_missing:${action}`);
  }

  let expectedPreviousHash = ZERO_HASH;
  let previousEntryHlc = null;
  const records = [];
  let verifiedReceiptCount = 0;

  entries.forEach((entry, index) => {
    const action = entryLabel(entry);
    evaluateEntry(entry, input?.tamperEvidencePolicy, reasons);

    if (entry?.sequence === 1 && entry?.previousTamperRecordHash !== ZERO_HASH) {
      addReason(reasons, true, `tamper_chain_start_mismatch:${action}`);
    } else if (index === 0) {
      addReason(reasons, entry?.previousTamperRecordHash !== ZERO_HASH, `tamper_chain_start_mismatch:${action}`);
    } else if (isDigest(entry?.previousTamperRecordHash) && entry.previousTamperRecordHash !== expectedPreviousHash) {
      addReason(reasons, true, `tamper_chain_input_mismatch:${action}`);
    }

    const currentHlc = hlcTuple(entry?.occurredAtHlc);
    addReason(
      reasons,
      previousEntryHlc !== null && currentHlc !== null && compareHlc(currentHlc, previousEntryHlc) <= 0,
      `ledger_entry_time_order_invalid:${action}`,
    );
    if (currentHlc !== null) {
      previousEntryHlc = currentHlc;
    }

    if (entry?.receiptEvidence?.verified === true) {
      verifiedReceiptCount += 1;
    }

    if (REQUIRED_TAMPER_ACTIONS.includes(action) && isPositiveSafeInteger(entry?.sequence)) {
      const record = buildTamperRecord(input, entry, expectedPreviousHash);
      expectedPreviousHash = record.tamperRecordHash;
      records.push(record);
    }
  });

  const chainVerification = verifyTamperEvidenceChain(records);
  addReason(reasons, chainVerification.valid !== true, 'tamper_chain_verification_failed');

  const uniqueReasons = uniqueSorted(reasons);
  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.tamper_evidence_ledger_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      ledger: buildDeniedLedger(input, uniqueReasons),
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const coveredActionTypes = [...entryActions].filter((action) => REQUIRED_TAMPER_ACTIONS.includes(action)).sort();
  const ledger = buildPermittedLedger(input, records, coveredActionTypes, verifiedReceiptCount);
  const receipt = buildLocalReceipt(input, ledger.ledgerHash);

  return {
    schema: 'cybermedica.tamper_evidence_ledger_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    ledger,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
