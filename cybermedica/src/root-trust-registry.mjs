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

import { canonicalize, sha256Hex } from './qms-contracts.mjs';
import { TrustState } from './trust-adapter.mjs';

const REQUIRED_ROOT_CERTIFIERS = 13;
const REQUIRED_DKG_PARTICIPANTS = 13;
const REQUIRED_THRESHOLD_SIGNATURE = '7-of-13';
const HEX_64 = /^[0-9a-f]{64}$/u;

const REQUIRED_ARTIFACT_KINDS = Object.freeze([
  'root_certifier_roster',
  'dkg_transcript',
  'root_signed_envelopes',
  'root_trust_bundle',
  'root_verifier_evidence',
  'immutable_audit_hash',
]);

const REQUIRED_ARTIFACT_BLOCKS = Object.freeze({
  dkg_transcript: 'dkg_transcript_absent',
  immutable_audit_hash: 'immutable_audit_hash_absent',
  root_certifier_roster: 'root_certifier_roster_absent',
  root_signed_envelopes: 'root_signed_envelopes_absent',
  root_trust_bundle: 'root_trust_bundle_absent',
  root_verifier_evidence: 'root_verifier_evidence_absent',
});

const PROHIBITED_PROVIDER_CONFIG_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'credentialsecret',
  'password',
  'privatekey',
  'rootkey',
  'secret',
  'signingkey',
  'token',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function addBlock(blocks, condition, block) {
  if (condition && !blocks.includes(block)) {
    blocks.push(block);
  }
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function normalizeInput(input) {
  return JSON.parse(canonicalize(input ?? {}));
}

function validHash(value) {
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
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

function sortedCertifiers(certifiers) {
  return [...certifiers].sort((left, right) => {
    const leftDid = hasText(left?.certifierDid) ? left.certifierDid : '';
    const rightDid = hasText(right?.certifierDid) ? right.certifierDid : '';
    return leftDid.localeCompare(rightDid, 'en-US');
  });
}

function sortedArtifacts(artifacts) {
  return [...artifacts].sort((left, right) => {
    const leftKind = hasText(left?.artifactKind) ? left.artifactKind : '';
    const rightKind = hasText(right?.artifactKind) ? right.artifactKind : '';
    return leftKind.localeCompare(rightKind, 'en-US');
  });
}

function countUnique(values) {
  return new Set(values.filter((value) => hasText(value))).size;
}

export function evaluateRootCertifierRoster(input) {
  const normalized = normalizeInput(input);
  const certifiers = Array.isArray(normalized.certifiers) ? normalized.certifiers : [];
  const blocks = [];

  addBlock(blocks, certifiers.length !== REQUIRED_ROOT_CERTIFIERS, 'root_certifier_roster_count_invalid');

  const certifierDids = certifiers.map((certifier) => certifier?.certifierDid);
  const rosterPositions = certifiers.map((certifier) => certifier?.rosterPosition);
  addBlock(blocks, countUnique(certifierDids) !== certifiers.length, 'root_certifier_roster_duplicate');
  addBlock(blocks, new Set(rosterPositions).size !== rosterPositions.length, 'root_certifier_position_duplicate');

  for (const certifier of certifiers) {
    addBlock(blocks, !hasText(certifier?.certifierDid), 'root_certifier_did_absent');
    addBlock(blocks, !hasText(certifier?.organizationRef), 'root_certifier_organization_absent');
    addBlock(blocks, !hasText(certifier?.independenceBasis), 'root_certifier_independence_basis_absent');
    addBlock(blocks, certifier?.active !== true, 'root_certifier_inactive');
    addBlock(blocks, !validHash(certifier?.signingKeyHash), 'root_certifier_signing_key_hash_invalid');
    addBlock(blocks, !Number.isSafeInteger(certifier?.rosterPosition), 'root_certifier_position_invalid');
  }

  const valid = blocks.length === 0;
  const canonicalRoster = {
    schema: 'cybermedica.root_certifier_roster_evidence.v1',
    rosterId: hasText(normalized.rosterId) ? normalized.rosterId : 'unclassified',
    rosterVersion: hasText(normalized.rosterVersion) ? normalized.rosterVersion : 'unversioned',
    hlcTimestamp: normalized.hlcTimestamp ?? null,
    certifiers: sortedCertifiers(certifiers).map((certifier) => ({
      active: certifier.active === true,
      certifierDid: certifier.certifierDid,
      independenceBasis: certifier.independenceBasis,
      organizationRef: certifier.organizationRef,
      rosterPosition: certifier.rosterPosition,
      signingKeyHash: certifier.signingKeyHash,
    })),
  };

  return {
    schema: 'cybermedica.root_certifier_roster_contract.v1',
    valid,
    state: valid ? TrustState.VERIFIED : TrustState.DENIED,
    failClosed: !valid,
    blockedBy: blocks,
    rosterHash: sha256Hex(canonicalRoster),
    rosterId: canonicalRoster.rosterId,
    rosterVersion: canonicalRoster.rosterVersion,
    certifierCount: certifiers.length,
    dkgParticipantCount: valid ? REQUIRED_DKG_PARTICIPANTS : certifiers.filter((certifier) => certifier?.active === true).length,
    thresholdSignature: REQUIRED_THRESHOLD_SIGNATURE,
    certifierDids: sortedCertifiers(certifiers).map((certifier) => certifier.certifierDid).filter(hasText),
    exochainProductionClaim: false,
    immutableEvidence: true,
  };
}

export function evaluateRootArtifactRegistry(input) {
  const normalized = normalizeInput(input);
  const artifacts = Array.isArray(normalized.artifacts) ? normalized.artifacts : [];
  const blocks = [];
  const artifactKinds = artifacts.map((artifact) => artifact?.artifactKind);
  const artifactKindSet = new Set(artifactKinds.filter(hasText));

  for (const requiredKind of REQUIRED_ARTIFACT_KINDS) {
    addBlock(blocks, !artifactKindSet.has(requiredKind), REQUIRED_ARTIFACT_BLOCKS[requiredKind]);
  }
  addBlock(blocks, artifactKindSet.size !== artifactKinds.filter(hasText).length, 'root_artifact_duplicate');

  for (const artifact of artifacts) {
    const kind = artifact?.artifactKind;
    addBlock(blocks, !REQUIRED_ARTIFACT_KINDS.includes(kind), 'root_artifact_kind_unrecognized');
    addBlock(blocks, !hasText(artifact?.artifactVersion), 'root_artifact_version_absent');
    addBlock(blocks, !validHash(artifact?.artifactHash), 'root_artifact_hash_invalid');
    addBlock(blocks, !validHash(artifact?.custodyDigest), 'root_artifact_custody_digest_invalid');
    addBlock(blocks, !hasText(artifact?.storageRef), 'root_artifact_storage_ref_absent');
  }

  const valid = blocks.length === 0;
  const canonicalRegistry = {
    schema: 'cybermedica.root_artifact_registry_evidence.v1',
    registryId: hasText(normalized.registryId) ? normalized.registryId : 'unclassified',
    registryVersion: hasText(normalized.registryVersion) ? normalized.registryVersion : 'unversioned',
    hlcTimestamp: normalized.hlcTimestamp ?? null,
    artifacts: sortedArtifacts(artifacts).map((artifact) => ({
      artifactHash: artifact.artifactHash,
      artifactKind: artifact.artifactKind,
      artifactVersion: artifact.artifactVersion,
      custodyDigest: artifact.custodyDigest,
      storageRef: artifact.storageRef,
    })),
  };

  return {
    schema: 'cybermedica.root_artifact_registry_contract.v1',
    valid,
    state: valid ? TrustState.VERIFIED : TrustState.DENIED,
    failClosed: !valid,
    blockedBy: blocks,
    registryHash: sha256Hex(canonicalRegistry),
    registryId: canonicalRegistry.registryId,
    registryVersion: canonicalRegistry.registryVersion,
    artifactCount: artifacts.length,
    artifactKinds: sortedArtifacts(artifacts).map((artifact) => artifact.artifactKind).filter(hasText),
    requiredArtifactKinds: [...REQUIRED_ARTIFACT_KINDS],
    exochainProductionClaim: false,
    immutableEvidence: true,
  };
}

function providerConfigBlocks(providerConfig) {
  const blocks = [];
  addBlock(blocks, !hasText(providerConfig?.endpointRef), 'root_bundle_provider_endpoint_absent');
  addBlock(blocks, !hasText(providerConfig?.credentialScope), 'root_bundle_provider_credential_scope_absent');
  addBlock(blocks, providerConfig?.health !== 'ready', 'root_bundle_provider_unready');
  addBlock(
    blocks,
    containsProviderSecretMaterial(providerConfig),
    'root_bundle_provider_secret_material_prohibited',
  );
  return blocks;
}

function verifierBlocks(verifierResult) {
  const blocks = [];
  if (!isObject(verifierResult)) {
    return ['root_verifier_absent'];
  }

  if (verifierResult.status === TrustState.PENDING && verifierResult.verified !== true) {
    addBlock(blocks, true, 'root_verifier_pending');
  } else {
    addBlock(blocks, verifierResult.verified !== true, 'root_verifier_unverified');
  }

  addBlock(blocks, !hasText(verifierResult.verifierReceiptId), 'root_verifier_absent');
  addBlock(blocks, !validHash(verifierResult.rootTrustBundleHash), 'root_trust_bundle_hash_invalid');
  addBlock(blocks, verifierResult.thresholdSignature !== REQUIRED_THRESHOLD_SIGNATURE, 'root_threshold_signature_absent');
  addBlock(blocks, verifierResult.dkgParticipantCount !== REQUIRED_DKG_PARTICIPANTS, 'root_dkg_transcript_absent');
  return blocks;
}

function classifyProviderState(input, blocks) {
  if (blocks.length === 0) {
    return TrustState.VERIFIED;
  }
  if (!input || Object.keys(input).length === 0) {
    return TrustState.INACTIVE;
  }
  if (blocks.length === 1 && blocks[0] === 'root_verifier_pending') {
    return TrustState.PENDING;
  }
  return TrustState.DENIED;
}

function canBuildRootBundle(state, blocks) {
  return state === TrustState.VERIFIED || (state === TrustState.PENDING && blocks.length === 1);
}

export function evaluateRootTrustBundleProvider(input) {
  const normalized = normalizeInput(input);
  const roster = normalized.roster;
  const artifactRegistry = normalized.artifactRegistry;
  const verifierResult = normalized.verifierResult;
  const blocks = [
    ...providerConfigBlocks(normalized.providerConfig),
  ];

  addBlock(blocks, roster?.valid !== true, 'root_certifier_roster_unverified');
  addBlock(blocks, artifactRegistry?.valid !== true, 'root_artifact_registry_unverified');
  for (const block of verifierBlocks(verifierResult)) {
    addBlock(blocks, true, block);
  }

  const state = classifyProviderState(input, blocks);
  const allowed = state === TrustState.VERIFIED;
  const rootBundle = canBuildRootBundle(state, blocks)
    ? {
        status: state,
        verified: allowed,
        certifierCount: roster.certifierCount,
        dkgParticipantCount: verifierResult.dkgParticipantCount,
        thresholdSignature: verifierResult.thresholdSignature,
        verifierReceiptId: verifierResult.verifierReceiptId,
        rosterHash: roster.rosterHash,
        artifactRegistryHash: artifactRegistry.registryHash,
        rootTrustBundleHash: verifierResult.rootTrustBundleHash,
      }
    : null;

  return {
    schema: 'cybermedica.root_trust_bundle_provider_contract.v1',
    allowed,
    state,
    failClosed: !allowed,
    blockedBy: blocks,
    rootBundle,
    providerEndpointRef: hasText(normalized.providerConfig?.endpointRef) ? normalized.providerConfig.endpointRef : null,
    credentialScope: hasText(normalized.providerConfig?.credentialScope) ? normalized.providerConfig.credentialScope : null,
    exochainProductionClaim: false,
  };
}
