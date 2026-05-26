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

import { createPublicKey, verify } from 'node:crypto';
import { canonicalize, createEvidenceReceipt, sha256Hex } from './qms-contracts.mjs';

const HEX_64 = /^[0-9a-f]{64}$/u;
const DID_EXO = /^did:exo:[a-z0-9][a-z0-9-]{2,127}$/u;
const VERIFIED_REGISTRY_STATUSES = new Set(['active', 'verified']);
const DEFAULT_MAX_CHALLENGE_AGE_MS = 300000;
const DID_REGISTRY_SOURCE = 'exochain_did_registry';
const DID_AUTH_AUDIENCE = 'cybermedica.did-auth.v1';

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
}

function isDid(value) {
  return hasText(value) && DID_EXO.test(value);
}

function isPositiveSafeInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function isNonNegativeSafeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function hlcTuple(value) {
  if (!isPositiveSafeInteger(value?.physicalMs) || !isNonNegativeSafeInteger(value?.logical)) {
    return null;
  }
  return [value.physicalMs, value.logical];
}

function compareHlc(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  if (leftTuple === null || rightTuple === null) {
    return null;
  }
  if (leftTuple[0] !== rightTuple[0]) {
    return leftTuple[0] < rightTuple[0] ? -1 : 1;
  }
  if (leftTuple[1] !== rightTuple[1]) {
    return leftTuple[1] < rightTuple[1] ? -1 : 1;
  }
  return 0;
}

function publicKeyIsUsable(publicKeyPem) {
  if (!hasText(publicKeyPem)) {
    return false;
  }
  try {
    createPublicKey(publicKeyPem);
    return true;
  } catch {
    return false;
  }
}

function verifyEd25519(challenge, publicKeyPem, signature) {
  if (!hasText(signature) || !publicKeyIsUsable(publicKeyPem)) {
    return false;
  }
  try {
    return verify(null, Buffer.from(challenge, 'utf8'), createPublicKey(publicKeyPem), Buffer.from(signature, 'base64'));
  } catch {
    return false;
  }
}

function sortedTextList(values) {
  if (!Array.isArray(values)) {
    return [];
  }
  return [...new Set(values.filter(hasText))].sort();
}

function challengePayload(input) {
  return {
    actorDid: input?.actor?.did ?? null,
    audience: DID_AUTH_AUDIENCE,
    expiresAtHlc: input?.challenge?.expiresAtHlc ?? null,
    issuedAtHlc: input?.challenge?.issuedAtHlc ?? null,
    keyRef: input?.registryRecord?.keyRef ?? null,
    nonceHash: input?.challenge?.nonceHash ?? null,
    purpose: input?.challenge?.purpose ?? null,
    requestHash: input?.challenge?.requestHash ?? null,
    tenantId: input?.tenantId ?? null,
  };
}

export function buildDidAuthenticationChallenge(input) {
  return canonicalize(challengePayload(input));
}

function stateForBlocks(blockedBy) {
  if (blockedBy.length === 0) {
    return 'verified';
  }
  if (blockedBy.length === 1 && blockedBy[0] === 'did_registry_record_absent') {
    return 'inactive';
  }
  if (blockedBy.length === 1 && blockedBy[0] === 'did_registry_pending') {
    return 'pending';
  }
  return 'denied';
}

function failure(blockedBy) {
  const state = stateForBlocks(blockedBy);
  return {
    verified: false,
    state,
    failClosed: true,
    blockedBy,
    exochainProductionClaim: false,
    authentication: {
      verified: false,
      signatureVerified: false,
    },
    allowedTenantIds: [],
    receipt: null,
    sourceEvidence: [
      'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
    ],
  };
}

function validateRegistry(input, reasons) {
  const registry = input?.registryRecord;
  if (registry === null || registry === undefined) {
    reasons.push('did_registry_record_absent');
    return false;
  }
  if (registry.status === 'pending') {
    reasons.push('did_registry_pending');
    return false;
  }

  addReason(reasons, registry.source !== DID_REGISTRY_SOURCE, 'did_registry_source_unverified');
  addReason(reasons, !VERIFIED_REGISTRY_STATUSES.has(registry.status), 'did_registry_unverified');
  addReason(reasons, registry.algorithm !== 'Ed25519', 'did_algorithm_unsupported');
  addReason(reasons, !hasText(registry.keyRef), 'did_key_ref_absent');
  addReason(reasons, registry.did !== input?.actor?.did, 'did_registry_did_mismatch');
  addReason(reasons, !publicKeyIsUsable(registry.publicKeyPem), 'did_public_key_invalid');
  addReason(reasons, !isDigest(registry.registryEvidenceHash), 'did_registry_evidence_hash_invalid');
  addReason(reasons, !isDigest(registry.custodyDigest), 'did_registry_custody_digest_invalid');
  addReason(
    reasons,
    !sortedTextList(registry.allowedTenantIds).includes(input?.tenantId),
    'did_tenant_not_allowed_by_registry',
  );
  return true;
}

function validateChallenge(input, reasons) {
  const issued = input?.challenge?.issuedAtHlc;
  const expires = input?.challenge?.expiresAtHlc;
  const checked = input?.verification?.checkedAtHlc;
  const issuedTuple = hlcTuple(issued);
  const expiresTuple = hlcTuple(expires);
  const checkedTuple = hlcTuple(checked);
  const maxAgeMs = isPositiveSafeInteger(input?.verification?.maxChallengeAgeMs)
    ? input.verification.maxChallengeAgeMs
    : DEFAULT_MAX_CHALLENGE_AGE_MS;

  addReason(reasons, !hasText(input?.challenge?.purpose), 'did_auth_purpose_absent');
  addReason(reasons, !isDigest(input?.challenge?.requestHash), 'did_auth_request_hash_invalid');
  addReason(reasons, !isDigest(input?.challenge?.nonceHash), 'did_auth_nonce_hash_invalid');
  addReason(reasons, issuedTuple === null, 'did_auth_issued_hlc_invalid');
  addReason(reasons, expiresTuple === null, 'did_auth_expires_hlc_invalid');
  addReason(reasons, checkedTuple === null, 'did_auth_checked_hlc_invalid');

  if (issuedTuple !== null && expiresTuple !== null) {
    addReason(reasons, compareHlc(issued, expires) >= 0, 'did_auth_challenge_window_invalid');
  }
  if (issuedTuple !== null && checkedTuple !== null) {
    addReason(reasons, compareHlc(issued, checked) > 0, 'did_auth_issued_after_verification');
    addReason(reasons, checked.physicalMs - issued.physicalMs > maxAgeMs, 'did_auth_challenge_stale');
  }
  if (expiresTuple !== null && checkedTuple !== null) {
    addReason(reasons, compareHlc(expires, checked) < 0, 'did_auth_challenge_expired');
  }
}

export function evaluateDidAuthentication(input) {
  canonicalize(input);

  const reasons = [];
  addReason(reasons, !hasText(input?.tenantId), 'tenant_id_absent');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, !isDid(input?.actor?.did), 'did_format_invalid');

  const canEvaluateRegistry = validateRegistry(input, reasons);
  if (!canEvaluateRegistry && reasons.length === 1) {
    return failure(reasons);
  }

  validateChallenge(input, reasons);
  addReason(reasons, input?.verification?.gatewayAuthRequired !== true, 'gateway_auth_requirement_absent');
  addReason(reasons, !hasText(input?.signature), 'did_signature_absent');

  const challenge = buildDidAuthenticationChallenge(input);
  const signatureVerified = verifyEd25519(challenge, input?.registryRecord?.publicKeyPem, input?.signature);
  addReason(reasons, !signatureVerified, 'did_signature_invalid');

  if (reasons.length > 0) {
    return failure([...new Set(reasons)]);
  }

  const allowedTenantIds = sortedTextList(input.registryRecord.allowedTenantIds);
  const challengeHash = sha256Hex(challenge);
  const signatureHash = sha256Hex({
    challengeHash,
    signature: input.signature,
  });
  const registryEvidenceHash = sha256Hex({
    allowedTenantIds,
    custodyDigest: input.registryRecord.custodyDigest,
    did: input.actor.did,
    keyRef: input.registryRecord.keyRef,
    registryEvidenceHash: input.registryRecord.registryEvidenceHash,
    registrySource: input.registryRecord.source,
    signatureHash,
  });

  const receipt = createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: registryEvidenceHash,
    artifactType: 'did_authentication_evidence',
    artifactVersion: input.registryRecord.keyRef,
    classification: 'metadata_only_identity_authentication',
    custodyDigest: input.registryRecord.custodyDigest,
    hlcTimestamp: input.verification.checkedAtHlc,
    sensitivityTags: ['identity_metadata', 'signature_hash_only'],
    sourceSystem: 'cybermedica.did_authentication',
    tenantId: input.tenantId,
  });

  return {
    verified: true,
    state: 'verified',
    failClosed: false,
    blockedBy: [],
    exochainProductionClaim: false,
    authentication: {
      verified: true,
      signatureVerified,
      actorDid: input.actor.did,
      keyRef: input.registryRecord.keyRef,
      registrySource: input.registryRecord.source,
      challengeHash,
      signatureHash,
      checkedAtHlc: input.verification.checkedAtHlc,
    },
    allowedTenantIds,
    receipt,
    sourceEvidence: [
      'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
    ],
  };
}
