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

import { sha256Hex } from './qms-contracts.mjs';
import { evaluateProductionTrustActivation, TrustState } from './trust-adapter.mjs';

const READY = 'ready';
const DENIED = TrustState.DENIED;
const DEGRADED = TrustState.DEGRADED;
const VERIFIED = TrustState.VERIFIED;
const PENDING = TrustState.PENDING;
const INACTIVE = TrustState.INACTIVE;

const REQUIRED_DEPENDENCIES = Object.freeze([
  ['gateway', 'gateway_dependency_unready'],
  ['nodeReceiptStore', 'node_receipt_store_unready'],
  ['decisionForum', 'decision_forum_dependency_unready'],
  ['rootBundleProvider', 'root_bundle_provider_unready'],
]);

const REQUIRED_PRIVACY_BOUNDARIES = Object.freeze([
  ['anchors', 'privacy_anchor_boundary_unverified'],
  ['logs', 'privacy_log_boundary_unverified'],
  ['telemetry', 'privacy_telemetry_boundary_unverified'],
  ['health', 'privacy_health_boundary_unverified'],
  ['exports', 'privacy_export_boundary_unverified'],
]);

const PROHIBITED_HEALTH_FIELDS = new Set([
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

const PROHIBITED_RUNTIME_CONFIG_FIELDS = new Set([
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

const DISCLOSURE_TEXT_PATTERNS = [
  /\b\d{3}-\d{2}-\d{4}\b/u,
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/iu,
  /\b(?:patient|participant)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/iu,
  /\b(?:mrn|medical record)\s*[:#]\s*[A-Z0-9-]+\b/iu,
];

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function addBlock(blocks, condition, block) {
  if (condition) {
    blocks.push(block);
  }
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function deterministicPlainValue(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    return Number.isSafeInteger(value) ? value : String(value);
  }
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (Array.isArray(value)) {
    const normalized = value.map((item) => deterministicPlainValue(item));
    if (normalized.every((item) => typeof item === 'string')) {
      return [...normalized].sort();
    }
    return normalized;
  }
  if (!isObject(value)) {
    return String(value);
  }

  const output = {};
  for (const key of Object.keys(value).sort()) {
    const nested = value[key];
    if (nested !== undefined) {
      output[key] = deterministicPlainValue(nested);
    }
  }
  return output;
}

function containsFieldName(value, prohibitedFields) {
  if (value === null || value === undefined) {
    return false;
  }
  if (Array.isArray(value)) {
    return value.some((item) => containsFieldName(item, prohibitedFields));
  }
  if (!isObject(value)) {
    return false;
  }

  return Object.entries(value).some(([key, nested]) => {
    return prohibitedFields.has(normalizeFieldName(key)) || containsFieldName(nested, prohibitedFields);
  });
}

function containsDisclosureText(value) {
  if (value === null || value === undefined) {
    return false;
  }
  if (typeof value === 'string') {
    return DISCLOSURE_TEXT_PATTERNS.some((pattern) => pattern.test(value));
  }
  if (Array.isArray(value)) {
    return value.some((item) => containsDisclosureText(item));
  }
  if (isObject(value)) {
    return Object.values(value).some((nested) => containsDisclosureText(nested));
  }
  return false;
}

function safeHealthPayload(healthPayload, blocks) {
  const disclosesProtectedContent =
    containsFieldName(healthPayload, PROHIBITED_HEALTH_FIELDS) || containsDisclosureText(healthPayload);
  addBlock(blocks, disclosesProtectedContent, 'health_payload_disclosure');

  if (disclosesProtectedContent) {
    return {
      redacted: true,
      reason: 'health_payload_disclosure',
    };
  }

  return deterministicPlainValue(healthPayload ?? {});
}

function componentState(component) {
  if (component?.status === READY) {
    return READY;
  }
  if (component?.status === PENDING) {
    return PENDING;
  }
  if (component?.status === DEGRADED || component?.status === 'unavailable') {
    return DEGRADED;
  }
  return DENIED;
}

function processState(service, blocks) {
  const process = service?.process;
  addBlock(blocks, !hasText(service?.serviceId), 'service_id_absent');
  addBlock(blocks, !hasText(service?.releaseId), 'release_id_absent');
  addBlock(blocks, process?.status !== READY, 'process_unready');
  return process?.status === READY ? READY : DEGRADED;
}

function dependencyState(dependencies, blocks) {
  const states = [];
  for (const [name, block] of REQUIRED_DEPENDENCIES) {
    const state = componentState(dependencies?.[name]);
    states.push(state);
    addBlock(blocks, state !== READY, block);
    addBlock(blocks, !hasText(dependencies?.[name]?.checkedBy), `${name}_dependency_checker_absent`);
  }

  if (states.every((state) => state === READY)) {
    return READY;
  }
  if (states.some((state) => state === DEGRADED || state === PENDING)) {
    return DEGRADED;
  }
  return DENIED;
}

function privacyBoundaryState(privacyBoundary, blocks) {
  for (const [name, block] of REQUIRED_PRIVACY_BOUNDARIES) {
    addBlock(blocks, privacyBoundary?.[name]?.verified !== true, block);
  }
  return REQUIRED_PRIVACY_BOUNDARIES.every(([name]) => privacyBoundary?.[name]?.verified === true)
    ? VERIFIED
    : DENIED;
}

function runtimeConfigBlocks(runtimeConfig) {
  return containsFieldName(runtimeConfig, PROHIBITED_RUNTIME_CONFIG_FIELDS)
    ? ['runtime_secret_material_prohibited']
    : [];
}

function receiptReadinessState(dependencies, trustActivation) {
  if (dependencies?.nodeReceiptStore?.status !== READY) {
    return DEGRADED;
  }
  if (trustActivation.blockedBy.includes('receipt_path_unverified')) {
    return DENIED;
  }
  return READY;
}

function decisionForumReadinessState(dependencies, trustActivation) {
  if (dependencies?.decisionForum?.status !== READY) {
    return DEGRADED;
  }
  if (trustActivation.blockedBy.includes('decision_forum_unverified')) {
    return DENIED;
  }
  return READY;
}

function classifyOverallState({
  process,
  dependencies,
  trustActivation,
  privacy,
  blockedBy,
}) {
  if (blockedBy.includes('health_payload_disclosure') || blockedBy.includes('runtime_secret_material_prohibited')) {
    return DENIED;
  }
  if (process !== READY || dependencies === DEGRADED) {
    return DEGRADED;
  }
  if (dependencies === DENIED || privacy === DENIED) {
    return DENIED;
  }
  if (trustActivation.state === VERIFIED) {
    return READY;
  }
  return trustActivation.state;
}

export function buildRuntimeReadinessSnapshot(input) {
  const blocks = [];
  const service = input?.service ?? {};
  const dependencies = input?.dependencies ?? {};
  const trustActivation = evaluateProductionTrustActivation(input?.trust ?? {});
  const process = processState(service, blocks);
  const dependency = dependencyState(dependencies, blocks);
  const privacy = privacyBoundaryState(input?.privacyBoundary, blocks);
  const sanitizedHealthPayload = safeHealthPayload(input?.healthPayload, blocks);
  blocks.push(...trustActivation.blockedBy, ...runtimeConfigBlocks(input?.runtimeConfig));

  const blockedBy = uniqueSorted(blocks);
  const receiptState = receiptReadinessState(dependencies, trustActivation);
  const decisionForumState = decisionForumReadinessState(dependencies, trustActivation);
  const overallState = classifyOverallState({
    process,
    dependencies: dependency,
    trustActivation,
    privacy,
    blockedBy,
  });
  const canServeRegulatedTraffic = overallState === READY && trustActivation.allowed === true;
  const canShowProductionTrustClaim = canServeRegulatedTraffic;
  const rootReadinessState = trustActivation.state;

  const snapshotMaterial = {
    blockedBy,
    canServeRegulatedTraffic,
    canShowProductionTrustClaim,
    decisionForumReadinessState: decisionForumState,
    dependencyState: dependency,
    overallState,
    privacyBoundaryState: privacy,
    processState: process,
    receiptReadinessState: receiptState,
    releaseId: hasText(service?.releaseId) ? service.releaseId : 'unreleased',
    rootReadinessState,
    safeHealthPayload: sanitizedHealthPayload,
    schema: 'cybermedica.runtime_readiness_snapshot.v1',
    serviceId: hasText(service?.serviceId) ? service.serviceId : 'unclassified',
    trustState: trustActivation.state,
  };
  const snapshotHash = sha256Hex(snapshotMaterial);

  return {
    schema: 'cybermedica.runtime_readiness_snapshot.v1',
    snapshotId: `cmrr_${snapshotHash.slice(0, 32)}`,
    snapshotHash,
    serviceId: snapshotMaterial.serviceId,
    releaseId: snapshotMaterial.releaseId,
    processState: process,
    dependencyState: dependency,
    receiptReadinessState: receiptState,
    decisionForumReadinessState: decisionForumState,
    rootReadinessState,
    privacyBoundaryState: privacy,
    trustState: trustActivation.state,
    overallState,
    failClosed: !canServeRegulatedTraffic,
    canServeRegulatedTraffic,
    canShowProductionTrustClaim,
    exochainProductionClaim: canShowProductionTrustClaim,
    blockedBy,
    safeHealthPayload: sanitizedHealthPayload,
    sourceEvidence: [
      'docs/context/EXOCHAIN_COUNCIL_REVIEW_FOR_CYBERMEDICA_OPEN_QUESTIONS.md#rt-003',
      'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
    ],
  };
}
