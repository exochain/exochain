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

import assert from 'node:assert/strict';
import { test } from 'node:test';

const DIGEST_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const DIGEST_C = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const DIGEST_D = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const DIGEST_E = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const DIGEST_F = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
const DIGEST_1 = '1111111111111111111111111111111111111111111111111111111111111111';
const DIGEST_2 = '2222222222222222222222222222222222222222222222222222222222222222';
const DIGEST_3 = '3333333333333333333333333333333333333333333333333333333333333333';
const DIGEST_4 = '4444444444444444444444444444444444444444444444444444444444444444';
const DIGEST_5 = '5555555555555555555555555555555555555555555555555555555555555555';
const DIGEST_6 = '6666666666666666666666666666666666666666666666666666666666666666';

const REQUIRED_CAPABILITY_FAMILIES = ['api', 'connector', 'import_export_format', 'webhook'];
const REQUIRED_CONNECTOR_TYPES = [
  'ctms',
  'data_warehouse',
  'document_system',
  'econsent',
  'edc',
  'eisf',
  'etmf',
  'hris',
  'identity_provider',
  'irb_system',
  'lms',
  'qms',
  'sponsor_portal',
];
const REQUIRED_EXPORT_FORMATS = ['csv', 'json', 'markdown'];
const REQUIRED_WEBHOOK_EVENTS = [
  'audit_event_recorded',
  'capa_status_changed',
  'consent_status_changed',
  'decision_forum_outcome',
  'evidence_classified',
  'site_readiness_changed',
];

async function loadInteroperabilityReadiness() {
  try {
    return await import('../src/interoperability-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica interoperability readiness module must exist and load: ${error.message}`);
  }
}

function mergeDeep(base, overrides) {
  if (Array.isArray(base) || Array.isArray(overrides)) {
    return overrides === undefined ? base : overrides;
  }
  if (base === null || overrides === null || typeof base !== 'object' || typeof overrides !== 'object') {
    return overrides === undefined ? base : overrides;
  }
  return Object.fromEntries(
    [...new Set([...Object.keys(base), ...Object.keys(overrides)])].map((key) => [
      key,
      mergeDeep(base[key], overrides[key]),
    ]),
  );
}

function capability(family, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2];
  return {
    family,
    capabilityRef: `capability-${family}-alpha`,
    status: 'verified',
    policyHash: hashes[index],
    schemaHash: hashes[index + 1],
    boundaryHash: hashes[index + 2],
    testedAtHlc: { physicalMs: 1801000000000, logical: index + 10 },
    metadataOnly: true,
    payloadsExcluded: true,
    failClosedOnUnavailable: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function connector(type, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3];
  return {
    connectorRef: `connector-${type}-alpha`,
    type,
    status: 'verified',
    systemRef: `system-${type}-alpha`,
    mappingHash: hashes[index % hashes.length],
    accessPolicyHash: hashes[(index + 1) % hashes.length],
    endpointProfileHash: hashes[(index + 2) % hashes.length],
    lastVerifiedAtHlc: { physicalMs: 1801000000000, logical: index + 20 },
    metadataOnly: true,
    payloadsExcluded: true,
    failClosedOnError: true,
    secretsManagedExternally: true,
    ...overrides,
  };
}

function format(format, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3];
  return {
    format,
    profileRef: `format-${format}-alpha`,
    profileHash: hashes[index],
    schemaVersion: 'cybermedica.interoperability.format.v1',
    supportedDirections: ['import', 'export'],
    validationHash: hashes[index + 1],
    metadataOnly: true,
    rawPayloadExcluded: true,
    ...overrides,
  };
}

function webhook(eventType, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3];
  return {
    eventType,
    webhookRef: `webhook-${eventType}-alpha`,
    status: 'verified',
    schemaHash: hashes[index],
    signaturePolicyHash: hashes[index + 1],
    retryPolicyHash: hashes[index + 2],
    signatureRequired: true,
    replayProtectionEnabled: true,
    idempotencyRequired: true,
    rawPayloadLoggingDisabled: true,
    lastVerifiedAtHlc: { physicalMs: 1801000000000, logical: index + 40 },
    metadataOnly: true,
    payloadsExcluded: true,
    ...overrides,
  };
}

function interoperabilityInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:integration-governor-alpha',
      kind: 'human',
      roleRefs: ['system_admin', 'quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['interoperability_review', 'manage_integrations'],
      authorityChainHash: DIGEST_A,
    },
    interoperabilityPolicy: {
      policyRef: 'nfr007-interoperability-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredCapabilityFamilies: REQUIRED_CAPABILITY_FAMILIES,
      requiredConnectorTypes: REQUIRED_CONNECTOR_TYPES,
      requiredExportFormats: REQUIRED_EXPORT_FORMATS,
      requiredWebhookEvents: REQUIRED_WEBHOOK_EVENTS,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800999900000, logical: 0 },
    },
    capabilityEvidence: REQUIRED_CAPABILITY_FAMILIES.map((family, index) => capability(family, index)),
    governedIntegrationReadiness: {
      readinessRef: 'fr048-governed-integrations-alpha',
      readinessStatus: 'ready',
      readinessHash: DIGEST_C,
      connectorRefs: REQUIRED_CONNECTOR_TYPES.map((type) => `connector-${type}-alpha`),
      governedApiOnly: true,
      metadataOnly: true,
      reviewedAtHlc: { physicalMs: 1801000000000, logical: 70 },
    },
    governedApiAccess: {
      accessRef: 'fr049-governed-api-alpha',
      accessStatus: 'ready',
      accessHash: DIGEST_D,
      endpointFamilies: ['integration', 'reporting'],
      openApiSpecHash: DIGEST_E,
      rateLimitPolicyHash: DIGEST_F,
      replayProtectionEnabled: true,
      metadataOnly: true,
      reviewedAtHlc: { physicalMs: 1801000000000, logical: 71 },
    },
    structuredDataPortability: {
      exportRef: 'nfr013-structured-data-alpha',
      portabilityStatus: 'ready',
      portabilityHash: DIGEST_1,
      exportFamilies: ['audit_record', 'diligence_packet', 'evidence_index', 'site_data'],
      metadataOnly: true,
      reviewedAtHlc: { physicalMs: 1801000000000, logical: 72 },
    },
    connectors: REQUIRED_CONNECTOR_TYPES.map((type, index) => connector(type, index)),
    importExportFormats: REQUIRED_EXPORT_FORMATS.map((item, index) => format(item, index)),
    webhookEvents: REQUIRED_WEBHOOK_EVENTS.map((item, index) => webhook(item, index)),
    privacyBoundary: {
      boundaryRef: 'nfr007-interoperability-privacy-boundary-alpha',
      phiPiiExcludedFromReceipts: true,
      sourcePayloadsRemainExternal: true,
      sponsorConfidentialMinimized: true,
      disclosureLoggingRequired: true,
      participantConsentCheckedWhenLinked: true,
      boundaryHash: DIGEST_2,
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-manager-alpha',
      decision: 'interoperability_ready_inactive_trust',
      reviewedAtHlc: { physicalMs: 1801000000000, logical: 80 },
      reviewHash: DIGEST_3,
      aiFinalAuthorityRejected: true,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      scopeHash: DIGEST_4,
      evidenceRefs: ['fr048-governed-integrations-alpha', 'fr049-governed-api-alpha'],
      reviewedByHuman: true,
    },
    custodyDigest: DIGEST_5,
  };
  return mergeDeep(base, overrides);
}

test('interoperability readiness creates deterministic NFR-007 inactive metadata receipts', async () => {
  const { evaluateInteroperabilityReadiness } = await loadInteroperabilityReadiness();

  const first = evaluateInteroperabilityReadiness(interoperabilityInput());
  const second = evaluateInteroperabilityReadiness({
    ...interoperabilityInput(),
    connectors: [...interoperabilityInput().connectors].reverse(),
    webhookEvents: [...interoperabilityInput().webhookEvents].reverse(),
    importExportFormats: [...interoperabilityInput().importExportFormats].reverse(),
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.interoperabilityReadiness.status, 'ready');
  assert.deepEqual(first.interoperabilityReadiness.capabilityFamilies, REQUIRED_CAPABILITY_FAMILIES);
  assert.deepEqual(first.interoperabilityReadiness.connectorTypes, REQUIRED_CONNECTOR_TYPES);
  assert.deepEqual(first.interoperabilityReadiness.exportFormats, REQUIRED_EXPORT_FORMATS);
  assert.deepEqual(first.interoperabilityReadiness.webhookEvents, REQUIRED_WEBHOOK_EVENTS);
  assert.equal(first.interoperabilityReadiness.metadataOnly, true);
  assert.equal(first.interoperabilityReadiness.exochainProductionClaim, false);
  assert.equal(first.interoperabilityReadiness.readinessHash, second.interoperabilityReadiness.readinessHash);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.anchorPayload.artifactType, 'interoperability_readiness');
  assert.doesNotMatch(JSON.stringify(first), /Participant Alice|raw payload|client_secret|source document/iu);
});

test('interoperability readiness fails closed for missing capabilities and unready dependent contracts', async () => {
  const { evaluateInteroperabilityReadiness } = await loadInteroperabilityReadiness();

  const denied = evaluateInteroperabilityReadiness(
    interoperabilityInput({
      capabilityEvidence: REQUIRED_CAPABILITY_FAMILIES.filter((family) => family !== 'webhook').map((family, index) =>
        capability(family, index),
      ),
      governedIntegrationReadiness: {
        ...interoperabilityInput().governedIntegrationReadiness,
        readinessStatus: 'blocked',
        governedApiOnly: false,
      },
      governedApiAccess: {
        ...interoperabilityInput().governedApiAccess,
        accessStatus: 'blocked',
        replayProtectionEnabled: false,
      },
      structuredDataPortability: {
        ...interoperabilityInput().structuredDataPortability,
        portabilityStatus: 'blocked',
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.interoperabilityReadiness.status, 'blocked');
  assert.ok(denied.reasons.includes('capability_family_missing:webhook'));
  assert.ok(denied.reasons.includes('governed_integration_not_ready'));
  assert.ok(denied.reasons.includes('integration_governed_api_only_absent'));
  assert.ok(denied.reasons.includes('governed_api_access_not_ready'));
  assert.ok(denied.reasons.includes('api_replay_protection_absent'));
  assert.ok(denied.reasons.includes('structured_portability_not_ready'));
});

test('interoperability readiness denies incomplete connectors formats and webhook event controls', async () => {
  const { evaluateInteroperabilityReadiness } = await loadInteroperabilityReadiness();

  const denied = evaluateInteroperabilityReadiness(
    interoperabilityInput({
      connectors: interoperabilityInput().connectors
        .filter((item) => item.type !== 'edc')
        .map((item) =>
          item.type === 'ctms'
            ? {
                ...item,
                status: 'failing',
                payloadsExcluded: false,
                failClosedOnError: false,
                secretsManagedExternally: false,
              }
            : item,
        ),
      importExportFormats: interoperabilityInput().importExportFormats
        .filter((item) => item.format !== 'markdown')
        .map((item) =>
          item.format === 'json'
            ? {
                ...item,
                rawPayloadExcluded: false,
                supportedDirections: ['export'],
              }
            : item,
        ),
      webhookEvents: interoperabilityInput().webhookEvents
        .filter((item) => item.eventType !== 'evidence_classified')
        .map((item) =>
          item.eventType === 'site_readiness_changed'
            ? {
                ...item,
                signatureRequired: false,
                replayProtectionEnabled: false,
                rawPayloadLoggingDisabled: false,
              }
            : item,
        ),
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('connector_type_missing:edc'));
  assert.ok(denied.reasons.includes('connector_not_verified:connector-ctms-alpha'));
  assert.ok(denied.reasons.includes('connector_payload_boundary_invalid:connector-ctms-alpha'));
  assert.ok(denied.reasons.includes('connector_fail_closed_absent:connector-ctms-alpha'));
  assert.ok(denied.reasons.includes('connector_secret_scope_invalid:connector-ctms-alpha'));
  assert.ok(denied.reasons.includes('export_format_missing:markdown'));
  assert.ok(denied.reasons.includes('format_raw_payload_boundary_invalid:format-json-alpha'));
  assert.ok(denied.reasons.includes('format_import_direction_missing:format-json-alpha'));
  assert.ok(denied.reasons.includes('webhook_event_missing:evidence_classified'));
  assert.ok(denied.reasons.includes('webhook_signature_absent:webhook-site_readiness_changed-alpha'));
  assert.ok(denied.reasons.includes('webhook_replay_protection_absent:webhook-site_readiness_changed-alpha'));
  assert.ok(denied.reasons.includes('webhook_raw_payload_logging_forbidden:webhook-site_readiness_changed-alpha'));
});

test('interoperability readiness validates tenant authority HLC human review and advisory AI boundaries', async () => {
  const { evaluateInteroperabilityReadiness } = await loadInteroperabilityReadiness();

  const denied = evaluateInteroperabilityReadiness(
    interoperabilityInput({
      targetTenantId: 'tenant-other',
      actor: { did: 'did:exo:ai-integration-agent', kind: 'ai_agent' },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['read'],
        authorityChainHash: DIGEST_A,
      },
      interoperabilityPolicy: {
        ...interoperabilityInput().interoperabilityPolicy,
        status: 'draft',
        metadataOnly: false,
      },
      humanReview: {
        ...interoperabilityInput().humanReview,
        decision: 'ready',
        reviewedAtHlc: { physicalMs: 1800999800000, logical: 0 },
        aiFinalAuthorityRejected: false,
      },
      aiAssistance: {
        used: true,
        finalAuthority: true,
        scopeHash: DIGEST_4,
        evidenceRefs: [],
        reviewedByHuman: false,
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('interoperability_authority_missing'));
  assert.ok(denied.reasons.includes('interoperability_policy_not_active'));
  assert.ok(denied.reasons.includes('interoperability_policy_metadata_boundary_invalid'));
  assert.ok(denied.reasons.includes('human_review_decision_invalid'));
  assert.ok(denied.reasons.includes('human_review_before_policy'));
  assert.ok(denied.reasons.includes('human_review_ai_final_authority_not_rejected'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('ai_evidence_refs_absent'));
  assert.ok(denied.reasons.includes('ai_human_review_absent'));
});

test('interoperability readiness accepts service account actors only with human ownership', async () => {
  const { evaluateInteroperabilityReadiness } = await loadInteroperabilityReadiness();

  const permitted = evaluateInteroperabilityReadiness(
    interoperabilityInput({
      actor: {
        did: 'did:exo:interoperability-service-alpha',
        kind: 'service_account',
        humanOwnerDid: 'did:exo:system-administrator-alpha',
        roleRefs: ['system_admin'],
      },
    }),
  );
  assert.equal(permitted.decision, 'permitted');

  const denied = evaluateInteroperabilityReadiness(
    interoperabilityInput({
      actor: {
        did: 'did:exo:interoperability-service-alpha',
        kind: 'service_account',
        roleRefs: ['system_admin'],
      },
    }),
  );
  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('service_account_human_owner_absent'));
});

test('interoperability readiness handles no AI operation inert raw markers and malformed HLC branches', async () => {
  const { ProtectedContentError, evaluateInteroperabilityReadiness } = await loadInteroperabilityReadiness();

  const permitted = evaluateInteroperabilityReadiness(
    interoperabilityInput({
      aiAssistance: {
        used: false,
      },
      rawPayload: [null, false],
      connectorSecret: {},
    }),
  );
  assert.equal(permitted.decision, 'permitted');

  const denied = evaluateInteroperabilityReadiness(
    interoperabilityInput({
      capabilityEvidence: [],
      connectors: [],
      importExportFormats: [],
      webhookEvents: [],
      interoperabilityPolicy: {
        ...interoperabilityInput().interoperabilityPolicy,
        requiredCapabilityFamilies: ['api', 'unsupported_family'],
        evaluatedAtHlc: { physicalMs: 1800999900000, logical: -1 },
      },
      humanReview: {
        ...interoperabilityInput().humanReview,
        reviewedAtHlc: { physicalMs: 1801000000000, logical: -1 },
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('capability_evidence_absent'));
  assert.ok(denied.reasons.includes('connectors_absent'));
  assert.ok(denied.reasons.includes('import_export_formats_absent'));
  assert.ok(denied.reasons.includes('webhook_events_absent'));
  assert.ok(denied.reasons.includes('interoperability_policy_time_invalid'));
  assert.ok(denied.reasons.includes('policy_required_capability_family_unsupported:unsupported_family'));
  assert.ok(denied.reasons.includes('human_review_time_invalid'));

  assert.throws(
    () =>
      evaluateInteroperabilityReadiness({
        ...interoperabilityInput(),
        rawPayload: 1,
      }),
    ProtectedContentError,
  );
});

test('interoperability readiness rejects raw integration payloads protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateInteroperabilityReadiness } = await loadInteroperabilityReadiness();

  assert.throws(
    () =>
      evaluateInteroperabilityReadiness({
        ...interoperabilityInput(),
        rawPayload: 'Participant Alice source document payload',
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateInteroperabilityReadiness({
        ...interoperabilityInput(),
        connectors: [
          {
            ...connector('edc', 3),
            clientSecret: 'must-not-be-stored',
          },
        ],
      }),
    ProtectedContentError,
  );
});
