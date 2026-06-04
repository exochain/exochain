#!/usr/bin/env node
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
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const INTEGRATION_MAP_REF = 'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md';

function label(parts) {
  return parts.join(' ');
}

const EXPECTED_INTEGRATION_NEEDS = Object.freeze([
  {
    name: 'Tenant isolation',
    sourceContracts: Object.freeze([
      contract('src/tenant-isolation.mjs', ['tenant_boundary_violation', 'tenantActive']),
    ]),
    testContracts: Object.freeze([
      contract('tests/tenant-isolation.test.mjs', ['tenant isolation', 'tenant-site-alpha']),
    ]),
  },
  {
    name: 'Clinical research site identity',
    sourceContracts: Object.freeze([
      contract('src/did-authentication.mjs', ['DID_AUTH_AUDIENCE', 'did:exo']),
    ]),
    testContracts: Object.freeze([
      contract('tests/did-authentication.test.mjs', ['DID authentication', 'Ed25519']),
    ]),
  },
  {
    name: 'User identity',
    sourceContracts: Object.freeze([
      contract('src/verified-human-provider.mjs', [
        'verified_human_provider_unverified',
        'human_did_not_allowed_by_provider',
      ]),
    ]),
    testContracts: Object.freeze([
      contract('tests/verified-human-provider.test.mjs', ['verified human provider', 'external-human-proofing-provider']),
    ]),
  },
  {
    name: 'Role authority',
    sourceContracts: Object.freeze([
      contract('src/clinical-authority-policy.mjs', ['clinical_authority_policy', 'PTAG-010']),
    ]),
    testContracts: Object.freeze([
      contract('tests/clinical-authority-policy.test.mjs', ['sponsor_export_release', 'PTAG-010']),
    ]),
  },
  {
    name: 'Delegation logs',
    sourceContracts: Object.freeze([
      contract('src/delegation-audit-log.mjs', ['delegation_authorized', 'delegation_scope_reduced']),
    ]),
    testContracts: Object.freeze([
      contract('tests/delegation-audit-log.test.mjs', ['delegation_authorized', 'authorityChainHash']),
    ]),
  },
  {
    name: 'Participant consent',
    sourceContracts: Object.freeze([
      contract('src/consent-materials.mjs', ['PTAG-007', 'consent_process']),
    ]),
    testContracts: Object.freeze([
      contract('tests/consent-materials.test.mjs', ['consent material', 'PTAG-007']),
    ]),
  },
  {
    name: 'Support access grants',
    sourceContracts: Object.freeze([
      contract('src/support-access.mjs', ['support_policy_receipt_absent', 'support_grant_consent_mismatch']),
    ]),
    testContracts: Object.freeze([
      contract('tests/support-access.test.mjs', ['support-access-consent', 'support_grant_consent_mismatch']),
    ]),
  },
  {
    name: 'Evidence object hashing',
    sourceContracts: Object.freeze([
      contract('src/qms-contracts.mjs', ['createEvidenceReceipt', 'sha256Hex', 'canonicalize']),
    ]),
    testContracts: Object.freeze([
      contract('tests/qms-contracts.test.mjs', ['createEvidenceReceipt', 'evidence receipts are deterministic']),
    ]),
  },
  {
    name: 'Chain of custody',
    sourceContracts: Object.freeze([
      contract('src/evidence-custody.mjs', ['custody_transfer', 'current_custody_digest_invalid']),
    ]),
    testContracts: Object.freeze([
      contract('tests/evidence-custody.test.mjs', ['custody transfer', 'custodyDigest']),
    ]),
  },
  {
    name: 'Document version receipts',
    sourceContracts: Object.freeze([
      contract('src/document-versions.mjs', ['document_version_id_absent', 'previous_receipt_id_absent']),
    ]),
    testContracts: Object.freeze([
      contract('tests/document-versions.test.mjs', ['document version', 'previousReceiptId']),
    ]),
  },
  {
    name: 'QMS control approval',
    sourceContracts: Object.freeze([
      contract('src/qms-control-approvals.mjs', [
        'decision_forum_workflow_receipt_absent',
        'control_evidence_custody_digest_invalid',
      ]),
    ]),
    testContracts: Object.freeze([
      contract('tests/qms-control-approvals.test.mjs', ['control approval', 'PTAG-004']),
    ]),
  },
  {
    name: 'Protocol launch gate',
    sourceContracts: Object.freeze([
      contract('src/readiness-gates.mjs', ['evaluateProtocolLaunchGate', 'protocol_not_approved']),
      contract('src/decision-forum-matters.mjs', ['cybermedica.decision_forum_matter.v1', 'quorum_unverified']),
    ]),
    testContracts: Object.freeze([
      contract('tests/readiness-gates.test.mjs', ['protocol launch gate denies', 'enrollmentAuthorizationActive']),
      contract('tests/decision-forum-matters.test.mjs', ['Decision Forum matter lifecycle', 'decision_forum_matter']),
    ]),
  },
  {
    name: 'Enrollment gate',
    sourceContracts: Object.freeze([
      contract('src/readiness-gates.mjs', ['evaluateEnrollmentGate', 'launch_gate_not_approved']),
    ]),
    testContracts: Object.freeze([
      contract('tests/readiness-gates.test.mjs', ['enrollment gate denies', 'participantMayEnroll']),
    ]),
  },
  {
    name: 'CAPA closure',
    sourceContracts: Object.freeze([
      contract('src/capa-workflows.mjs', ['capa_closure', 'ai_final_authority_forbidden']),
    ]),
    testContracts: Object.freeze([
      contract('tests/capa-workflows.test.mjs', ['CAPA closure', 'artifactType']),
    ]),
  },
  {
    name: 'Sponsor/CRO export',
    sourceContracts: Object.freeze([
      contract('src/diligence-exports.mjs', ['sponsor_cro_diligence_export', 'sponsor_export']),
    ]),
    testContracts: Object.freeze([
      contract('tests/diligence-exports.test.mjs', ['sponsor_diligence_export', 'protected content']),
    ]),
  },
  {
    name: 'Audit event receipts',
    sourceContracts: Object.freeze([
      contract('src/audit-event-receipts.mjs', ['cybermedica.audit_entry.v1', 'receipt_signature_missing']),
    ]),
    testContracts: Object.freeze([
      contract('tests/audit-event-receipts.test.mjs', ['audit event receipts', 'receipt_signature_missing']),
    ]),
  },
  {
    name: 'AI review provenance',
    sourceContracts: Object.freeze([
      contract('src/ai-control-review.mjs', ['AI_CONTROL_REVIEW_SOURCE_REQUIREMENTS', 'ai_control_review_decision']),
    ]),
    testContracts: Object.freeze([
      contract('tests/ai-control-review.test.mjs', ['AI control review maps', 'aiControlReview']),
    ]),
  },
  {
    name: 'Deterministic scoring',
    sourceContracts: Object.freeze([
      contract('src/evidence-scoring.mjs', ['basisPoints', 'scoreSetHash']),
    ]),
    testContracts: Object.freeze([
      contract('tests/evidence-scoring.test.mjs', ['evidence scoring computes deterministic', 'scoreSetHash']),
    ]),
  },
  {
    name: 'Privacy-preserving anchors',
    sourceContracts: Object.freeze([
      contract('src/privacy-fixture-boundary.mjs', ['receipt_anchor', 'health_response', 'export_manifest']),
      contract('src/exochain-anchoring.mjs', ['PTAG-003', 'anchoring_policy_metadata_boundary_invalid']),
    ]),
    testContracts: Object.freeze([
      contract('tests/privacy-fixture-boundary.test.mjs', ['receipt_anchor', 'health_response', 'export_manifest']),
      contract('tests/exochain-anchoring.test.mjs', ['PTAG-003', 'raw payload']),
    ]),
  },
  {
    name: label(['Root-backed', 'production authority']),
    sourceContracts: Object.freeze([
      contract('src/root-trust-registry.mjs', ['root_trust_bundle_absent', 'root_verifier_evidence_absent']),
    ]),
    testContracts: Object.freeze([
      contract('tests/root-trust-registry.test.mjs', ['root trust registry', 'root_trust_bundle']),
    ]),
  },
  {
    name: 'Gateway call path',
    sourceContracts: Object.freeze([
      contract('src/gateway-call-path.mjs', ['GATEWAY_CALL_SCHEMA', 'gateway_service_unavailable']),
    ]),
    testContracts: Object.freeze([
      contract('tests/gateway-call-path.test.mjs', ['gateway call path creates deterministic', 'gateway_service_unavailable']),
    ]),
  },
  {
    name: 'Node receipt path',
    sourceContracts: Object.freeze([
      contract('src/node-receipt-sync.mjs', ['node_receipt_sync_ready_inactive_trust', 'receipt_signature_missing']),
    ]),
    testContracts: Object.freeze([
      contract('tests/node-receipt-sync.test.mjs', ['node receipt sync creates deterministic', 'receipt_signature_missing']),
    ]),
  },
  {
    name: 'Runtime readiness and health',
    sourceContracts: Object.freeze([
      contract('src/runtime-readiness.mjs', ['root_bundle_provider_unready', 'safeHealthPayload']),
    ]),
    testContracts: Object.freeze([
      contract('tests/runtime-readiness.test.mjs', ['runtime readiness separates process health', 'safeHealthPayload']),
    ]),
  },
  {
    name: 'WASM/browser path',
    sourceContracts: Object.freeze([
      contract('src/browser-trust-path.mjs', ['PTAG-018', 'browser_client_anchoring_forbidden']),
    ]),
    testContracts: Object.freeze([
      contract('tests/browser-trust-path.test.mjs', ['browser trust path', 'PTAG-018']),
    ]),
  },
]);

const EXPECTED_AVOID_TRUST_CLAIM_PRIMITIVES = Object.freeze([
  {
    name: 'ZK proofs',
    sourceContracts: Object.freeze([
      contract('src/requirement-traceability.mjs', ['PTAG-002', 'DEFAULT_ACTIVATION_BLOCKER_IDS']),
    ]),
    testContracts: Object.freeze([
      contract('tests/requirement-traceability.test.mjs', ['PTAG-002', 'activationOnlyBlockerIds']),
    ]),
  },
  {
    name: 'CrossChecked anchoring',
    sourceContracts: Object.freeze([
      contract('src/exochain-anchoring.mjs', ['PTAG-003', 'anchoring_policy_not_active']),
    ]),
    testContracts: Object.freeze([
      contract('tests/exochain-anchoring.test.mjs', ['PTAG-003', 'anchoring_policy_not_active']),
    ]),
  },
  {
    name: 'Raw admin governance',
    sourceContracts: Object.freeze([
      contract('src/qms-control-approvals.mjs', ['PTAG-004', 'decision_forum_workflow_receipt_absent']),
    ]),
    testContracts: Object.freeze([
      contract('tests/qms-control-approvals.test.mjs', ['PTAG-004', 'decisionForum']),
    ]),
  },
  {
    name: '0dentity device/behavior axes',
    sourceContracts: Object.freeze([
      contract('src/optional-trust-claim-guards.mjs', ['PTAG-012', 'ptag_012_surface_trust_score_claim_forbidden']),
    ]),
    testContracts: Object.freeze([
      contract('tests/optional-trust-claim-guards.test.mjs', ['PTAG-012', 'zerodentity_behavioral_device_trust']),
    ]),
  },
  {
    name: 'Economy settlement',
    sourceContracts: Object.freeze([
      contract('src/optional-trust-claim-guards.mjs', ['PTAG-013', 'ptag_013_settlement_finality_claim_forbidden']),
    ]),
    testContracts: Object.freeze([
      contract('tests/optional-trust-claim-guards.test.mjs', ['PTAG-013', 'economy_settlement_billing_trust']),
    ]),
  },
  {
    name: 'CommandBase enforcement',
    sourceContracts: Object.freeze([
      contract('src/optional-trust-claim-guards.mjs', ['PTAG-014', 'commandbase_enforcement']),
    ]),
    testContracts: Object.freeze([
      contract('tests/optional-trust-claim-guards.test.mjs', ['PTAG-014', 'commandbase_enforcement']),
    ]),
  },
  {
    name: 'ExoForge/Archon as authority',
    sourceContracts: Object.freeze([
      contract('src/optional-trust-claim-guards.mjs', ['PTAG-015', 'ptag_015_surface_agent_governance_claim_forbidden']),
    ]),
    testContracts: Object.freeze([
      contract('tests/optional-trust-claim-guards.test.mjs', ['PTAG-015', 'exoforge_archon_governance_authority']),
    ]),
  },
]);

function contract(pathRef, requiredTextRefs) {
  return Object.freeze({
    pathRef,
    requiredTextRefs: Object.freeze(requiredTextRefs),
  });
}

function sha256Hex(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function readProjectFile(rootDir, pathRef) {
  const absolutePath = resolve(rootDir, pathRef);
  return existsSync(absolutePath) ? readFileSync(absolutePath, 'utf8') : null;
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function evaluateTextRefs(rootDir, rowName, contractDef, kind) {
  const source = readProjectFile(rootDir, contractDef.pathRef);
  if (source === null) {
    return [
      {
        ruleId: `integration_map_${kind}_file_absent`,
        rowName,
        pathRef: contractDef.pathRef,
        requiredTextRef: null,
        metadataOnly: true,
      },
    ];
  }

  return contractDef.requiredTextRefs
    .filter((requiredTextRef) => !source.includes(requiredTextRef))
    .map((requiredTextRef) => ({
      ruleId: `integration_map_${kind}_text_absent`,
      rowName,
      pathRef: contractDef.pathRef,
      requiredTextRef,
      metadataOnly: true,
    }));
}

function contextFindings(integrationMapText) {
  if (integrationMapText === null) {
    return [
      {
        ruleId: 'integration_map_register_file_absent',
        rowName: null,
        pathRef: INTEGRATION_MAP_REF,
        requiredTextRef: null,
        metadataOnly: true,
      },
    ];
  }

  const needFindings = EXPECTED_INTEGRATION_NEEDS.filter((entry) => !integrationMapText.includes(entry.name)).map(
    (entry) => ({
      ruleId: 'integration_map_need_row_absent',
      rowName: entry.name,
      pathRef: INTEGRATION_MAP_REF,
      requiredTextRef: entry.name,
      metadataOnly: true,
    }),
  );
  const avoidFindings = EXPECTED_AVOID_TRUST_CLAIM_PRIMITIVES.filter((entry) => !integrationMapText.includes(entry.name))
    .map((entry) => ({
      ruleId: 'integration_map_avoid_row_absent',
      rowName: entry.name,
      pathRef: INTEGRATION_MAP_REF,
      requiredTextRef: entry.name,
      metadataOnly: true,
    }));

  return [...needFindings, ...avoidFindings];
}

function compareFindings(left, right) {
  const rowCompare = String(left.rowName).localeCompare(String(right.rowName));
  if (rowCompare !== 0) {
    return rowCompare;
  }
  const pathCompare = String(left.pathRef).localeCompare(String(right.pathRef));
  if (pathCompare !== 0) {
    return pathCompare;
  }
  const textCompare = String(left.requiredTextRef).localeCompare(String(right.requiredTextRef));
  if (textCompare !== 0) {
    return textCompare;
  }
  return left.ruleId.localeCompare(right.ruleId);
}

export function scanIntegrationMapCoverage(rootDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')) {
  const integrationMapText = readProjectFile(rootDir, INTEGRATION_MAP_REF);
  const allRows = [...EXPECTED_INTEGRATION_NEEDS, ...EXPECTED_AVOID_TRUST_CLAIM_PRIMITIVES];
  const checkedSourceRefs = uniqueSorted(
    allRows.flatMap((entry) => entry.sourceContracts.map((contractDef) => contractDef.pathRef)),
  );
  const checkedTestRefs = uniqueSorted(
    allRows.flatMap((entry) => entry.testContracts.map((contractDef) => contractDef.pathRef)),
  );
  const findings = [
    ...contextFindings(integrationMapText),
    ...allRows.flatMap((entry) => [
      ...entry.sourceContracts.flatMap((contractDef) => evaluateTextRefs(rootDir, entry.name, contractDef, 'source')),
      ...entry.testContracts.flatMap((contractDef) => evaluateTextRefs(rootDir, entry.name, contractDef, 'test')),
    ]),
  ].sort(compareFindings);

  return {
    schema: 'cybermedica.source_integration_map_guard.v1',
    status: findings.length === 0 ? 'passed' : 'failed',
    exitCode: findings.length === 0 ? 0 : 1,
    scannerRef: 'cybermedica-source-integration-map-guard',
    scannerVersionHash: sha256Hex(allRows.map((entry) => entry.name).join('|')),
    integrationMapRef: INTEGRATION_MAP_REF,
    integrationNeedNames: EXPECTED_INTEGRATION_NEEDS.map((entry) => entry.name),
    integrationNeedCount: EXPECTED_INTEGRATION_NEEDS.length,
    avoidTrustClaimPrimitiveNames: EXPECTED_AVOID_TRUST_CLAIM_PRIMITIVES.map((entry) => entry.name),
    avoidTrustClaimPrimitiveCount: EXPECTED_AVOID_TRUST_CLAIM_PRIMITIVES.length,
    checkedSourceRefs,
    checkedTestRefs,
    exochainSourceExcluded: [...checkedSourceRefs, ...checkedTestRefs].every(
      (pathRef) => !pathRef.startsWith('../exochain') && !pathRef.startsWith('/Users/bobstewart/dev/exochain/exochain'),
    ),
    findings,
    findingsCount: findings.length,
    metadataOnly: true,
  };
}

const invokedPath = process.argv[1] === undefined ? '' : resolve(process.argv[1]);
const modulePath = fileURLToPath(import.meta.url);

if (invokedPath === modulePath) {
  const rootDir = resolve(dirname(modulePath), '..');
  const report = scanIntegrationMapCoverage(rootDir);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.exitCode;
}
