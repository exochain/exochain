// Copyright (c) 2026 Exochain Foundation. All rights reserved.
// Proprietary and confidential. See cybermedica/LICENSE.
// SPDX-License-Identifier: LicenseRef-Exochain-Proprietary

import { ProtectedContentError, createEvidenceReceipt } from './qms-contracts.mjs';

const HEX_64 = /^[0-9a-f]{64}$/u;
const SCHEMA = 'cybermedica.authorized_action_evidence_design_partner.v1';
const ALLOWED_PURPOSES = new Set(['regulated_proof', 'readiness_review']);
const RAW_FIELDS = new Set([
  'phi',
  'rawphi',
  'rawcontent',
  'participantdata',
  'sourcepayload',
]);
const SECRET_FIELDS = new Set([
  'apikey',
  'privatekey',
  'secret',
  'token',
  'password',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function walkForbiddenFields(value, reasons) {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item) => walkForbiddenFields(item, reasons));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    addReason(reasons, RAW_FIELDS.has(normalized), `protected_content_field_forbidden:${key}`);
    addReason(reasons, SECRET_FIELDS.has(normalized), `secret_field_forbidden:${key}`);
    walkForbiddenFields(nested, reasons);
  }
}

function evaluateRequest(input, reasons) {
  addReason(reasons, !isDigest(input?.evidencePackHash), 'evidence_pack_hash_invalid');
  addReason(reasons, !isDigest(input?.actionCommitmentHash), 'action_commitment_hash_invalid');
  addReason(reasons, !hasText(input?.partnerRef), 'partner_ref_absent');
  addReason(reasons, !hasText(input?.tenantId), 'tenant_id_absent');
  addReason(reasons, !hasText(input?.actorDid), 'actor_did_absent');
  addReason(reasons, input?.metadataOnly !== true, 'metadata_only_required');
  addReason(reasons, input?.protectedContentExcluded !== true, 'protected_content_must_be_excluded');
  addReason(reasons, input?.exochainProductionClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, input?.insuranceRiskTransfer === true, 'insurance_is_readiness_not_risk_transfer');
  addReason(reasons, input?.gmvTakeRateClaim === true, 'gmv_take_rate_forbidden');
  addReason(reasons, !ALLOWED_PURPOSES.has(input?.purpose), 'purpose_unsupported');
  addReason(
    reasons,
    input?.hlcTimestamp?.physicalMs === undefined
      || !Number.isSafeInteger(input.hlcTimestamp.physicalMs)
      || input.hlcTimestamp.physicalMs <= 0
      || !Number.isSafeInteger(input.hlcTimestamp.logical)
      || input.hlcTimestamp.logical < 0,
    'hlc_timestamp_invalid',
  );
  walkForbiddenFields(input, reasons);
}

export function consumeAuthorizedActionEvidencePack(input) {
  const reasons = [];
  evaluateRequest(input, reasons);
  if (reasons.length > 0) {
    throw new ProtectedContentError(reasons.join('; '));
  }

  const receipt = createEvidenceReceipt({
    actorDid: input.actorDid,
    artifactHash: input.evidencePackHash,
    artifactType: 'authorized_action_evidence_pack',
    artifactVersion: 'v1',
    classification: 'restricted_metadata_only',
    custodyDigest: input.actionCommitmentHash,
    hlcTimestamp: input.hlcTimestamp,
    sensitivityTags: ['metadata_only', 'design_partner_proof'],
    sourceSystem: 'cybermedica.authorized_action_evidence_design_partner',
    tenantId: input.tenantId,
  });

  return {
    schema: SCHEMA,
    accepted: true,
    insuranceRiskTransfer: false,
    insuranceReadinessOnly: true,
    gmvTakeRateClaim: false,
    exochainProductionClaim: false,
    trustState: receipt.trustState,
    evidencePackHash: input.evidencePackHash,
    receipt,
  };
}

export { ProtectedContentError };
