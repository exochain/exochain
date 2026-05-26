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

import { createHash } from 'node:crypto';

const HEX_64 = /^[0-9a-f]{64}$/u;

const PROHIBITED_FIELD_NAMES = new Set([
  'address',
  'credential',
  'dateofbirth',
  'dob',
  'email',
  'freetextnote',
  'medicalrecordnumber',
  'mrn',
  'participantname',
  'patientname',
  'phone',
  'privatekey',
  'rawcontent',
  'rawphi',
  'rawpii',
  'signaturesecret',
  'socialsecuritynumber',
  'sourcedocumentbody',
  'ssn',
]);

const PROHIBITED_TEXT_PATTERNS = [
  /\b\d{3}-\d{2}-\d{4}\b/u,
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/iu,
  /\b(?:patient|participant)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/iu,
  /\b(?:mrn|medical record)\s*[:#]\s*[A-Z0-9-]+\b/iu,
];

const GOVERNED_ACTION_PERMISSION = Object.freeze({
  capa_closure: 'govern',
  consent_policy_change: 'govern',
  enrollment_gate: 'govern',
  evidence_receipt_create: 'write',
  participant_record_access: 'read',
  protocol_launch: 'govern',
  qms_control_approval: 'govern',
  sponsor_export: 'read',
  support_access: 'read',
  support_access_policy: 'govern',
});

const HUMAN_GATED_ACTIONS = new Set([
  'capa_closure',
  'consent_policy_change',
  'enrollment_gate',
  'protocol_launch',
  'qms_control_approval',
  'support_access_policy',
]);

const CONSENT_GATED_ACTIONS = new Set([
  'ai_review',
  'enrollment_gate',
  'participant_record_access',
  'sponsor_export',
  'support_access',
]);

export class ProtectedContentError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ProtectedContentError';
  }
}

export class DeterminismError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DeterminismError';
  }
}

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function assertNoProtectedText(value, path) {
  if (typeof value !== 'string') {
    return;
  }
  for (const pattern of PROHIBITED_TEXT_PATTERNS) {
    if (pattern.test(value)) {
      throw new ProtectedContentError(`protected content is not allowed at ${path}`);
    }
  }
}

function assertAllowedFieldName(fieldName, path) {
  const normalized = normalizeFieldName(fieldName);
  if (PROHIBITED_FIELD_NAMES.has(normalized)) {
    throw new ProtectedContentError(`protected content field is not allowed at ${path}`);
  }
}

function normalizeDeterministically(value, path = '$') {
  if (value === null) {
    return null;
  }
  if (Array.isArray(value)) {
    const normalized = value.map((item, index) => normalizeDeterministically(item, `${path}[${index}]`));
    if (normalized.every((item) => typeof item === 'string')) {
      return [...normalized].sort();
    }
    return normalized;
  }
  if (typeof value === 'string') {
    assertNoProtectedText(value, path);
    return value;
  }
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) {
      throw new DeterminismError(`only safe integers are allowed at ${path}`);
    }
    return value;
  }
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (typeof value !== 'object') {
    throw new DeterminismError(`unsupported nondeterministic value at ${path}`);
  }

  const output = {};
  for (const key of Object.keys(value).sort()) {
    assertAllowedFieldName(key, `${path}.${key}`);
    const nested = value[key];
    if (nested === undefined) {
      throw new DeterminismError(`undefined is not allowed at ${path}.${key}`);
    }
    output[key] = normalizeDeterministically(nested, `${path}.${key}`);
  }
  return output;
}

export function canonicalize(value) {
  return JSON.stringify(normalizeDeterministically(value));
}

export function sha256Hex(value) {
  return createHash('sha256').update(canonicalize(value), 'utf8').digest('hex');
}

function assertHash64(value, fieldName) {
  if (!hasText(value) || !HEX_64.test(value) || /^0+$/u.test(value)) {
    throw new DeterminismError(`${fieldName} must be a non-zero lowercase 64 hex character digest`);
  }
}

function sortedAnchorPayload(input) {
  return normalizeDeterministically({
    actorDid: input.actorDid,
    artifactHash: input.artifactHash,
    artifactType: input.artifactType,
    artifactVersion: input.artifactVersion,
    classification: input.classification,
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.hlcTimestamp,
    schema: 'cybermedica.evidence_receipt_anchor.v1',
    sensitivityTags: input.sensitivityTags,
    sourceSystem: input.sourceSystem,
    tenantId: input.tenantId,
  });
}

export function createEvidenceReceipt(input) {
  const normalizedInput = normalizeDeterministically(input);
  assertHash64(normalizedInput.artifactHash, 'artifactHash');
  assertHash64(normalizedInput.custodyDigest, 'custodyDigest');

  const anchorPayload = sortedAnchorPayload(normalizedInput);
  const actionHash = sha256Hex({
    artifactHash: anchorPayload.artifactHash,
    artifactType: anchorPayload.artifactType,
    artifactVersion: anchorPayload.artifactVersion,
    custodyDigest: anchorPayload.custodyDigest,
    tenantId: anchorPayload.tenantId,
  });

  return {
    schema: 'cybermedica.evidence_receipt.v1',
    receiptId: `cmr_${sha256Hex(anchorPayload).slice(0, 32)}`,
    actionHash,
    trustState: 'inactive',
    exochainProductionClaim: false,
    containsProtectedContent: false,
    anchorPayload,
    immutableReceipt: true,
    operationalStateMutable: true,
    sourceEvidence: [
      'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
    ],
  };
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function hasPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateAuthority(action, authority, reasons) {
  const requiredPermission = GOVERNED_ACTION_PERMISSION[action];
  addReason(reasons, !authority || authority.valid !== true, 'authority_chain_invalid');
  addReason(reasons, authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    hasText(requiredPermission) && !hasPermission(authority, requiredPermission),
    'authority_permission_missing',
  );
}

function evaluateConsent(action, consent, reasons) {
  if (!CONSENT_GATED_ACTIONS.has(action)) {
    return;
  }
  addReason(reasons, consent === null || consent === undefined, 'consent_absent');
  addReason(reasons, consent?.required === true && consent?.status !== 'active', 'consent_not_active');
  addReason(reasons, consent?.revoked === true || consent?.status === 'revoked', 'consent_revoked');
  addReason(reasons, consent?.expired === true || consent?.status === 'expired', 'consent_expired');
}

function evaluateDecisionForum(action, actor, decisionForum, evidenceBundle, reasons) {
  if (!HUMAN_GATED_ACTIONS.has(action)) {
    return;
  }

  addReason(reasons, actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, !decisionForum || decisionForum.verified !== true, 'decision_forum_unverified');
  addReason(reasons, decisionForum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, decisionForum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, decisionForum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, decisionForum?.openChallenge === true, 'challenge_open');
  addReason(reasons, evidenceBundle?.complete !== true, 'evidence_bundle_incomplete');
  addReason(reasons, evidenceBundle?.phiBoundaryAttested !== true, 'phi_boundary_unattested');
}

export function evaluateGovernedAction(input) {
  const action = input?.action;
  const reasons = [];

  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');

  evaluateAuthority(action, input?.authority, reasons);
  evaluateConsent(action, input?.consent, reasons);
  evaluateDecisionForum(action, input?.actor, input?.decisionForum, input?.evidenceBundle, reasons);

  const denied = reasons.length > 0;
  return {
    schema: 'cybermedica.governed_action_decision.v1',
    action: hasText(action) ? action : 'unclassified',
    decision: denied ? 'denied' : 'permitted',
    failClosed: denied,
    reasons,
    requiresHumanGate: HUMAN_GATED_ACTIONS.has(action),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
