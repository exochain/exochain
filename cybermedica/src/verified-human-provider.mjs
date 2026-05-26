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
import { TrustState } from './trust-adapter.mjs';

const HEX_64 = /^[0-9a-f]{64}$/u;

const PROHIBITED_PROVIDER_CONFIG_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'credentialsecret',
  'password',
  'secret',
  'token',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function normalizeInput(input) {
  return JSON.parse(canonicalize(input ?? {}));
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function addBlock(blocks, condition, block) {
  if (condition && !blocks.includes(block)) {
    blocks.push(block);
  }
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
}

function hlcPresent(hlc) {
  return Number.isSafeInteger(hlc?.physicalMs) && Number.isSafeInteger(hlc?.logical);
}

function sortedTextList(value) {
  return Array.isArray(value) ? value.filter(hasText).sort() : [];
}

function containsProviderSecretMaterial(value) {
  if (value === null || value === undefined) {
    return false;
  }
  if (Array.isArray(value)) {
    return value.some((item) => containsProviderSecretMaterial(item));
  }
  if (!isObject(value)) {
    return false;
  }

  return Object.entries(value).some(([key, nested]) => {
    return PROHIBITED_PROVIDER_CONFIG_FIELDS.has(normalizeFieldName(key)) || containsProviderSecretMaterial(nested);
  });
}

function providerBlocks(provider, actorDid) {
  if (!isObject(provider)) {
    return ['verified_human_provider_absent'];
  }

  const blocks = [];
  if (provider.status === TrustState.PENDING) {
    addBlock(blocks, true, 'verified_human_provider_pending');
  } else {
    addBlock(blocks, provider.status !== TrustState.VERIFIED, 'verified_human_provider_unverified');
  }

  const allowedHumanDids = sortedTextList(provider.allowedHumanDids);
  addBlock(blocks, !hasText(provider.providerId), 'verified_human_provider_id_absent');
  addBlock(blocks, !hasText(provider.checkedBy), 'verified_human_checked_by_absent');
  addBlock(blocks, !hlcPresent(provider.checkedAtHlc), 'verified_human_checked_at_invalid');
  addBlock(blocks, !hasText(provider.evidenceRef), 'verified_human_evidence_ref_absent');
  addBlock(blocks, !isDigest(provider.attestationHash), 'verified_human_attestation_hash_invalid');
  addBlock(blocks, !isDigest(provider.custodyDigest), 'verified_human_custody_digest_invalid');
  addBlock(blocks, allowedHumanDids.length === 0, 'verified_human_allowlist_absent');
  addBlock(
    blocks,
    hasText(actorDid) && allowedHumanDids.length > 0 && !allowedHumanDids.includes(actorDid),
    'human_did_not_allowed_by_provider',
  );
  addBlock(blocks, provider.revoked === true, 'verified_human_attestation_revoked');
  addBlock(blocks, provider.expired === true, 'verified_human_attestation_expired');
  addBlock(blocks, containsProviderSecretMaterial(provider), 'verified_human_provider_secret_material_prohibited');
  return blocks;
}

function classifyState(input, provider, blocks) {
  if (!input || Object.keys(input).length === 0 || !isObject(provider)) {
    return TrustState.INACTIVE;
  }
  if (blocks.length === 1 && blocks[0] === 'verified_human_provider_pending') {
    return TrustState.PENDING;
  }
  return blocks.length === 0 ? TrustState.VERIFIED : TrustState.DENIED;
}

function buildProviderEvidence(input, allowedHumanDids) {
  return {
    schema: 'cybermedica.verified_human_provider_evidence.v1',
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    actorKind: input.actor.kind,
    providerId: input.provider.providerId,
    providerStatus: input.provider.status,
    checkedBy: input.provider.checkedBy,
    checkedAtHlc: input.provider.checkedAtHlc,
    evidenceRef: input.provider.evidenceRef,
    attestationHash: input.provider.attestationHash,
    allowedHumanDids,
  };
}

function buildReceipt(input, providerEvidenceHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'verified_human_provider_evidence',
    artifactVersion: `${input.provider.providerId}:${input.provider.evidenceRef}`,
    artifactHash: providerEvidenceHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.provider.checkedAtHlc,
    custodyDigest: input.provider.custodyDigest,
    sensitivityTags: ['human_gate', 'identity_proofing', 'metadata_only'],
    sourceSystem: 'cybermedica-verified-human-provider',
  });
}

export function evaluateVerifiedHumanProvider(input) {
  const normalized = normalizeInput(input);
  const actorDid = normalized.actor?.did;
  const allowedHumanDids = sortedTextList(normalized.provider?.allowedHumanDids);
  const blocks = [
    ...providerBlocks(normalized.provider, actorDid),
  ];

  addBlock(blocks, !hasText(normalized.tenantId), 'tenant_absent');
  addBlock(blocks, !hasText(actorDid), 'actor_did_absent');
  addBlock(blocks, normalized.actor?.kind !== 'human', 'human_actor_kind_invalid');
  addBlock(blocks, normalized.actor?.kind === 'ai_agent', 'ai_actor_cannot_satisfy_human_gate');
  addBlock(blocks, normalized.actor?.selfDeclaredHuman === true, 'self_declared_human_insufficient');

  const state = classifyState(input, normalized.provider, blocks);
  const verified = state === TrustState.VERIFIED;
  const providerEvidence = verified ? buildProviderEvidence(normalized, allowedHumanDids) : null;
  const providerEvidenceHash = verified ? sha256Hex(providerEvidence) : null;
  const receipt = verified ? buildReceipt(normalized, providerEvidenceHash) : null;

  return {
    schema: 'cybermedica.verified_human_provider_contract.v1',
    verified,
    state,
    failClosed: !verified,
    blockedBy: blocks,
    providerEvidenceHash,
    providerAllowedHumanDids: allowedHumanDids,
    humanGate: {
      verified,
      actorDid: hasText(actorDid) ? actorDid : null,
      providerId: hasText(normalized.provider?.providerId) ? normalized.provider.providerId : null,
      evidenceRef: hasText(normalized.provider?.evidenceRef) ? normalized.provider.evidenceRef : null,
      evidenceReceiptId: receipt?.receiptId ?? null,
    },
    receipt,
    exochainProductionClaim: false,
  };
}
