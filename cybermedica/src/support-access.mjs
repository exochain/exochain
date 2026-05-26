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

import { canonicalize, createEvidenceReceipt, evaluateGovernedAction, sha256Hex } from './qms-contracts.mjs';

const HEX_64 = /^[0-9a-f]{64}$/u;
const SUPPORT_ACCESS_SCOPE = 'support_access';

const REQUESTED_FIELD_CANONICAL = new Map([
  ['audittrailmetadata', 'audit_trail_metadata'],
  ['casemetadata', 'case_metadata'],
  ['documentversionmetadata', 'document_version_metadata'],
  ['systemerrorcode', 'system_error_code'],
  ['tenantconfigmetadata', 'tenant_config_metadata'],
  ['workflowstatemetadata', 'workflow_state_metadata'],
]);

const PROHIBITED_REQUESTED_FIELDS = new Set([
  'address',
  'credential',
  'dateofbirth',
  'dob',
  'email',
  'medicalrecordnumber',
  'mrn',
  'participantname',
  'patientname',
  'phone',
  'rawcontent',
  'rawphi',
  'rawpii',
  'socialsecuritynumber',
  'sourcedocumentbody',
  'ssn',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical)) {
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

function validateProtectedContentBoundary(input, reasons) {
  try {
    canonicalize({
      reason: input?.reason ?? null,
      requestedFields: input?.requestedFields ?? [],
    });
  } catch {
    reasons.push('protected_content_present');
  }
}

function normalizeRequestedFields(requestedFields, reasons) {
  if (!Array.isArray(requestedFields) || requestedFields.length === 0) {
    reasons.push('requested_fields_absent');
    return [];
  }

  const canonicalFields = new Set();
  for (const field of requestedFields) {
    if (!hasText(field)) {
      reasons.push('requested_field_invalid');
      continue;
    }
    const normalized = normalizeFieldName(field);
    if (PROHIBITED_REQUESTED_FIELDS.has(normalized)) {
      reasons.push('requested_field_prohibited');
      continue;
    }
    const canonical = REQUESTED_FIELD_CANONICAL.get(normalized);
    if (!hasText(canonical)) {
      reasons.push('requested_field_not_allowed');
      continue;
    }
    canonicalFields.add(canonical);
  }

  return [...canonicalFields].sort();
}

function evaluateSupportPolicy(policy, reasons) {
  addReason(reasons, policy?.verified !== true, 'support_policy_unverified');
  addReason(reasons, policy?.state !== 'approved', 'support_policy_not_approved');
  addReason(reasons, !hasText(policy?.policyReceiptId), 'support_policy_receipt_absent');
  addReason(reasons, policy?.humanGate?.verified !== true, 'support_policy_human_gate_unverified');
  addReason(reasons, policy?.quorum?.status !== 'met', 'support_policy_quorum_not_met');
  addReason(reasons, policy?.openChallenge === true, 'support_policy_challenge_open');
}

function evaluateSupportGrant(input, reasons) {
  const grant = input?.supportGrant;
  addReason(reasons, !hasText(grant?.grantId), 'support_grant_id_absent');
  addReason(reasons, grant?.status !== 'active', 'support_grant_not_active');
  addReason(reasons, grant?.scope !== SUPPORT_ACCESS_SCOPE, 'support_grant_scope_invalid');
  addReason(reasons, grant?.revoked === true, 'support_grant_revoked');
  addReason(
    reasons,
    hasText(grant?.consentRef) && hasText(input?.consent?.consentRef) && grant.consentRef !== input.consent.consentRef,
    'support_grant_consent_mismatch',
  );

  const requestedAt = hlcTuple(input?.requestedAtHlc);
  const notBefore = hlcTuple(grant?.notBeforeHlc);
  const expiresAt = hlcTuple(grant?.expiresAtHlc);

  addReason(reasons, requestedAt === null, 'requested_time_invalid');
  addReason(reasons, notBefore === null, 'support_grant_start_time_invalid');
  addReason(reasons, expiresAt === null, 'support_grant_expiry_time_invalid');

  if (requestedAt !== null && notBefore !== null && compareHlc(requestedAt, notBefore) < 0) {
    reasons.push('support_grant_not_yet_active');
  }
  if (requestedAt !== null && expiresAt !== null && compareHlc(requestedAt, expiresAt) > 0) {
    reasons.push('support_grant_expired');
  }
}

function evaluateReason(reason, reasons) {
  addReason(reasons, !hasText(reason?.code), 'reason_code_absent');
  addReason(reasons, !hasText(reason?.description), 'reason_description_absent');
  addReason(reasons, !hasText(reason?.ticketRef), 'ticket_ref_absent');
}

function evaluateAccessLog(accessLog, reasons) {
  addReason(reasons, !isDigest(accessLog?.previousEntryHash), 'access_log_previous_hash_invalid');
  addReason(
    reasons,
    !Number.isSafeInteger(accessLog?.sequence) || accessLog.sequence < 0,
    'access_log_sequence_invalid',
  );
  addReason(reasons, !isDigest(accessLog?.custodyDigest), 'access_log_custody_digest_invalid');
}

function buildLogEntry(input, requestedFields) {
  const material = {
    actorDid: input.actor.did,
    consentRef: input.consent.consentRef,
    grantId: input.supportGrant.grantId,
    previousEntryHash: input.accessLog.previousEntryHash,
    reasonCode: input.reason.code,
    requestedAtHlc: input.requestedAtHlc,
    requestedFields,
    sequence: input.accessLog.sequence,
    supportPolicyReceiptId: input.supportPolicy.policyReceiptId,
    tenantId: input.tenantId,
    ticketRef: input.reason.ticketRef,
  };
  const entryHash = sha256Hex(material);

  return {
    schema: 'cybermedica.support_access_log_entry.v1',
    accessLogId: `cmsa_${entryHash.slice(0, 32)}`,
    entryHash,
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    grantId: input.supportGrant.grantId,
    consentRef: input.consent.consentRef,
    reasonCode: input.reason.code,
    ticketRef: input.reason.ticketRef,
    requestedAtHlc: input.requestedAtHlc,
    requestedFields,
    previousEntryHash: input.accessLog.previousEntryHash,
    sequence: input.accessLog.sequence,
  };
}

function buildReceipt(input, logEntry) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'support_access_log',
    artifactVersion: `${input.supportGrant.grantId}@${input.accessLog.sequence}`,
    artifactHash: logEntry.entryHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.requestedAtHlc,
    custodyDigest: input.accessLog.custodyDigest,
    sensitivityTags: ['metadata_only', 'quality_audit', 'support_access'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function evaluateSupportAccessRequest(input) {
  const governedDecision = evaluateGovernedAction({
    action: SUPPORT_ACCESS_SCOPE,
    tenantId: input?.tenantId,
    targetTenantId: input?.targetTenantId,
    actor: input?.actor,
    authority: input?.authority,
    consent: input?.consent,
    evidenceBundle: { complete: true, phiBoundaryAttested: true },
  });
  const reasons = [...governedDecision.reasons];

  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_support_access_forbidden');
  validateProtectedContentBoundary(input, reasons);
  evaluateSupportPolicy(input?.supportPolicy, reasons);
  evaluateSupportGrant(input, reasons);
  evaluateReason(input?.reason, reasons);
  evaluateAccessLog(input?.accessLog, reasons);
  const requestedFields = normalizeRequestedFields(input?.requestedFields, reasons);

  const uniqueReasons = [...new Set(reasons)].sort();
  const denied = uniqueReasons.length > 0;
  const logEntry = denied ? null : buildLogEntry(input, requestedFields);

  return {
    schema: 'cybermedica.support_access_decision.v1',
    decision: denied ? 'denied' : 'permitted',
    failClosed: denied,
    reasons: uniqueReasons,
    accessWindowActive: !denied,
    trustState: 'inactive',
    exochainProductionClaim: false,
    logEntry,
    receipt: denied ? null : buildReceipt(input, logEntry),
  };
}
