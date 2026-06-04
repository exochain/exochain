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

const VERIFIED = 'verified';
const DENIED = 'denied';
const HEX_64 = /^[0-9a-f]{64}$/u;
const BROWSER_TRUST_PATH_ACTIVATION_GATE_ID = 'PTAG-018';

const SERVER_PATHS = Object.freeze([
  ['gateway', 'gateway_server_path_unverified'],
  ['receiptPath', 'receipt_server_path_unverified'],
  ['decisionForum', 'decision_forum_server_path_unverified'],
  ['privacyBoundary', 'privacy_server_path_unverified'],
  ['rootBundleProvider', 'root_bundle_provider_server_path_unverified'],
]);

const PROTECTED_FIELD_NAMES = new Set([
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
  'rawcontent',
  'rawphi',
  'rawpii',
  'socialsecuritynumber',
  'sourcedocumentbody',
  'ssn',
]);

const SECRET_FIELD_TOKENS = Object.freeze([
  'accesstoken',
  'apikey',
  'credentialsecret',
  'password',
  'privatekey',
  'rootkey',
  'rootsigningkey',
  'secret',
  'signaturesecret',
  'signingkey',
  'token',
]);

const DISCLOSURE_TEXT_PATTERNS = Object.freeze([
  /\b\d{3}-\d{2}-\d{4}\b/u,
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/iu,
  /\b(?:patient|participant)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/iu,
  /\b(?:mrn|medical record)\s*[:#]\s*[A-Z0-9-]+\b/iu,
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function addBlock(blocks, condition, block) {
  if (condition) {
    blocks.push(block);
  }
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
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
  if (isObject(value)) {
    return Object.keys(value).length > 0;
  }
  return true;
}

function fieldHasSecretMaterial(fieldName, value) {
  const normalized = normalizeFieldName(fieldName);
  return SECRET_FIELD_TOKENS.some((token) => normalized.includes(token)) && sensitiveValuePresent(value);
}

function containsSecretMaterial(value) {
  if (value === null || value === undefined) {
    return false;
  }
  if (Array.isArray(value)) {
    return value.some((item) => containsSecretMaterial(item));
  }
  if (!isObject(value)) {
    return false;
  }

  return Object.entries(value).some(([key, nested]) => {
    return fieldHasSecretMaterial(key, nested) || containsSecretMaterial(nested);
  });
}

function containsDisclosure(value) {
  if (value === null || value === undefined) {
    return false;
  }
  if (typeof value === 'string') {
    return DISCLOSURE_TEXT_PATTERNS.some((pattern) => pattern.test(value));
  }
  if (Array.isArray(value)) {
    return value.some((item) => containsDisclosure(item));
  }
  if (!isObject(value)) {
    return false;
  }

  return Object.entries(value).some(([key, nested]) => {
    const protectedField = PROTECTED_FIELD_NAMES.has(normalizeFieldName(key)) && sensitiveValuePresent(nested);
    return protectedField || containsDisclosure(nested);
  });
}

function isVerifiedPath(path) {
  return path !== null && typeof path === 'object' && path.verified === true && path.status === VERIFIED && hasText(path.receiptId);
}

function serverTrustBlocks(serverTrustPath) {
  return SERVER_PATHS.flatMap(([name, block]) => (isVerifiedPath(serverTrustPath?.[name]) ? [] : [block]));
}

function digestBlock(value, block) {
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value) ? [] : [block];
}

function payloadBoundaryBlocks(payloadBoundary) {
  const blocks = [];
  addBlock(blocks, payloadBoundary?.metadataOnly !== true, 'browser_metadata_only_boundary_absent');
  addBlock(blocks, payloadBoundary?.rawPayloadSentToBrowser !== false, 'browser_raw_payload_forbidden');
  addBlock(blocks, payloadBoundary?.sourceDocumentsInBrowser !== false, 'browser_source_documents_forbidden');
  addBlock(blocks, payloadBoundary?.clientAnchoringDisabled !== true, 'browser_client_anchoring_forbidden');
  addBlock(blocks, payloadBoundary?.telemetryMetadataOnly !== true, 'browser_telemetry_boundary_unverified');
  addBlock(blocks, payloadBoundary?.healthDebugMetadataOnly !== true, 'browser_health_debug_boundary_unverified');
  return blocks;
}

function clientRuntimeBlocks(input) {
  const blocks = [];
  const clientKind = input?.client?.kind;
  addBlock(blocks, clientKind !== 'browser' && clientKind !== 'wasm_browser', 'browser_client_kind_invalid');
  addBlock(blocks, !hasText(input?.client?.appId), 'browser_app_id_absent');
  addBlock(blocks, !hasText(input?.client?.releaseId), 'browser_release_id_absent');
  addBlock(blocks, !hasText(input?.client?.tenantId), 'browser_tenant_absent');
  addBlock(blocks, input?.clientTrustClaimRequested === true, 'client_trust_claim_forbidden');

  const adapterMode = input?.wasm?.adapterMode;
  addBlock(
    blocks,
    adapterMode !== 'client_request_only' && adapterMode !== 'view_only',
    'client_enforcement_authority_forbidden',
  );
  addBlock(blocks, containsSecretMaterial(input?.publicConfig), 'browser_secret_material_prohibited');
  addBlock(blocks, containsSecretMaterial(input?.wasm), 'wasm_secret_material_prohibited');
  return blocks;
}

function workflowBlocks(workflow) {
  const blocks = [];
  addBlock(blocks, !hasText(workflow?.action), 'browser_workflow_action_absent');
  addBlock(blocks, workflow?.regulated !== true, 'browser_regulated_workflow_absent');
  addBlock(blocks, workflow?.involvesPhi !== true, 'browser_phi_workflow_flag_absent');
  blocks.push(...digestBlock(workflow?.expectedServerActionHash, 'browser_expected_server_action_hash_invalid'));
  return blocks;
}

function disclosureBlocks(input) {
  const blocks = [];
  addBlock(blocks, containsDisclosure(input?.browserPayload), 'browser_payload_disclosure');
  addBlock(blocks, containsDisclosure(input?.healthDebugPayload), 'browser_health_debug_disclosure');
  addBlock(blocks, containsDisclosure(input?.telemetryPayload), 'browser_telemetry_disclosure');
  return blocks;
}

function redactionReason(blockedBy) {
  const disclosure = blockedBy.find((block) => {
    return block === 'browser_payload_disclosure' || block === 'browser_telemetry_disclosure';
  });
  if (disclosure) {
    return disclosure;
  }
  if (blockedBy.includes('browser_health_debug_disclosure')) {
    return 'browser_health_debug_disclosure';
  }
  if (blockedBy.includes('browser_secret_material_prohibited')) {
    return 'browser_secret_material_prohibited';
  }
  if (blockedBy.includes('wasm_secret_material_prohibited')) {
    return 'wasm_secret_material_prohibited';
  }
  return null;
}

function safeClientManifest(input, blockedBy) {
  const reason = redactionReason(blockedBy);
  if (reason) {
    return {
      redacted: true,
      reason,
    };
  }

  return {
    appId: hasText(input?.client?.appId) ? input.client.appId : 'unclassified',
    clientKind: hasText(input?.client?.kind) ? input.client.kind : 'unclassified',
    releaseId: hasText(input?.client?.releaseId) ? input.client.releaseId : 'unreleased',
    tenantId: hasText(input?.client?.tenantId) ? input.client.tenantId : 'unclassified',
    workflowAction: hasText(input?.workflow?.action) ? input.workflow.action : 'unclassified',
    publicConfig: {
      apiBasePath: hasText(input?.publicConfig?.apiBasePath) ? input.publicConfig.apiBasePath : null,
      configHash: hasText(input?.publicConfig?.configHash) ? input.publicConfig.configHash : null,
      runtimeConfigSource: hasText(input?.publicConfig?.runtimeConfigSource)
        ? input.publicConfig.runtimeConfigSource
        : null,
    },
    wasm: {
      adapterMode: hasText(input?.wasm?.adapterMode) ? input.wasm.adapterMode : 'unclassified',
      exportManifestHash: hasText(input?.wasm?.exportManifestHash) ? input.wasm.exportManifestHash : null,
    },
  };
}

function serverReceiptIds(serverTrustPath) {
  const ids = {};
  for (const [name] of SERVER_PATHS) {
    ids[name] = hasText(serverTrustPath?.[name]?.receiptId) ? serverTrustPath[name].receiptId : null;
  }
  return ids;
}

export function evaluateBrowserTrustPath(input) {
  const blocks = [
    ...serverTrustBlocks(input?.serverTrustPath),
    ...payloadBoundaryBlocks(input?.payloadBoundary),
    ...clientRuntimeBlocks(input),
    ...workflowBlocks(input?.workflow),
    ...disclosureBlocks(input),
  ];
  const blockedBy = uniqueSorted(blocks);
  const pathState = blockedBy.length === 0 ? VERIFIED : DENIED;
  const allowed = pathState === VERIFIED;
  const manifest = safeClientManifest(input, blockedBy);
  const pathMaterial = {
    blockedBy,
    clientMayEnforceTrust: false,
    clientMayRequestRegulatedWorkflow: allowed,
    pathState,
    safeClientManifest: manifest,
    schema: 'cybermedica.browser_trust_path.v1',
    serverReceiptIds: serverReceiptIds(input?.serverTrustPath),
    serverSideAdjudicationRequired: true,
    workflowAction: hasText(input?.workflow?.action) ? input.workflow.action : 'unclassified',
  };
  const pathHash = sha256Hex(pathMaterial);

  return {
    schema: 'cybermedica.browser_trust_path.v1',
    pathId: `cmbtp_${pathHash.slice(0, 32)}`,
    pathHash,
    allowed,
    pathState,
    failClosed: !allowed,
    clientMayRequestRegulatedWorkflow: allowed,
    clientMayEnforceTrust: false,
    serverSideAdjudicationRequired: true,
    clientTrustAuthority: 'none',
    productionTrustClaimAllowed: false,
    exochainProductionClaim: false,
    activationGateIds: [BROWSER_TRUST_PATH_ACTIVATION_GATE_ID],
    blockedBy,
    safeClientManifest: manifest,
    claimLanguage: allowed
      ? 'Server-side CyberMedica trust adapter evidence is verified; the browser remains a non-authoritative request surface.'
      : 'Browser trust path denied until verified server-side evidence and metadata-only boundaries are present.',
    sourceEvidence: [
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md#PTAG-018',
      'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
    ],
  };
}
