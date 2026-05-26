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

async function loadAuditReadiness() {
  try {
    return await import('../src/audit-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica audit readiness module must exist and load: ${error.message}`);
  }
}

function auditReadinessInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['govern'] },
    audit: {
      auditId: 'AUDIT-2026-SPONSOR-001',
      auditType: 'sponsor',
      scope: 'site_quality_system',
      siteRef: 'site-alpha',
      protocolRef: 'protocol-cm-001',
      readinessDecision: 'release_package',
    },
    controlEvidence: [
      {
        controlId: 'CM-QMS-CONSENT-001',
        readinessStatus: 'ready',
        artifactHash: DIGEST_A,
        custodyDigest: DIGEST_B,
        receiptId: 'cmr-consent-control-approval',
        classification: 'confidential_metadata_only',
      },
      {
        controlId: 'CM-QMS-DELEGATION-001',
        readinessStatus: 'ready',
        artifactHash: DIGEST_C,
        custodyDigest: DIGEST_D,
        receiptId: 'cmr-delegation-control-approval',
        classification: 'confidential_metadata_only',
      },
    ],
    manifestRefs: {
      documentVersionReceiptIds: ['cmr-doc-sop-v2', 'cmr-doc-delegation-log-v4'],
      capaClosureReceiptIds: ['cmr-capa-closure-0001'],
      consentPolicyReceiptIds: ['cmr-consent-policy-v1'],
      supportAccessLogReceiptIds: ['cmr-support-access-log-17'],
      exportManifestReceiptIds: ['cmr-diligence-export-001'],
      qualityObjectiveReceiptIds: ['cmr-quality-objective-001'],
    },
    findingSummary: {
      openCritical: 0,
      openMajor: 0,
      openMinor: 1,
      observations: 2,
      closedCritical: 1,
      closedMajor: 3,
    },
    decisionForum: {
      verified: true,
      state: 'approved',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
      decisionId: 'df-audit-readiness-001',
      workflowReceiptId: 'df-audit-workflow-receipt-001',
    },
    evidenceBundle: { complete: true, phiBoundaryAttested: true },
    preparedAtHlc: { physicalMs: 1790000000900, logical: 6 },
    custodyDigest: DIGEST_B,
  };
}

test('audit readiness packages require human governance and create deterministic inactive metadata receipts', async () => {
  const { compileAuditReadinessPackage } = await loadAuditReadiness();

  const packageA = compileAuditReadinessPackage(auditReadinessInput());
  const packageB = compileAuditReadinessPackage({
    ...auditReadinessInput(),
    controlEvidence: [...auditReadinessInput().controlEvidence].reverse(),
    manifestRefs: {
      ...auditReadinessInput().manifestRefs,
      documentVersionReceiptIds: [...auditReadinessInput().manifestRefs.documentVersionReceiptIds].reverse(),
    },
  });

  assert.equal(packageA.decision, 'permitted');
  assert.equal(packageA.failClosed, false);
  assert.equal(packageA.auditPackage.auditReady, true);
  assert.equal(packageA.auditPackage.humanGovernanceRequired, true);
  assert.equal(packageA.auditPackage.operationalStateMutable, true);
  assert.equal(packageA.auditPackage.immutablePackageReceipt, true);
  assert.equal(packageA.auditPackage.exochainProductionClaim, false);
  assert.deepEqual(packageA.auditPackage.controlEvidenceIds, ['CM-QMS-CONSENT-001', 'CM-QMS-DELEGATION-001']);
  assert.equal(packageA.auditPackage.auditPackageId, packageB.auditPackage.auditPackageId);
  assert.equal(packageA.receipt.receiptId, packageB.receipt.receiptId);
  assert.equal(packageA.receipt.actionHash, packageB.receipt.actionHash);
  assert.equal(packageA.receipt.trustState, 'inactive');
  assert.equal(packageA.receipt.exochainProductionClaim, false);
  assert.equal(packageA.receipt.anchorPayload.artifactType, 'audit_readiness_package');
  assert.doesNotMatch(JSON.stringify(packageA.receipt), /source document|participant alice|patient|medical record/iu);
});

test('audit readiness fails closed for tenant authority governance findings and evidence defects', async () => {
  const { compileAuditReadinessPackage } = await loadAuditReadiness();

  const denied = compileAuditReadinessPackage({
    ...auditReadinessInput(),
    targetTenantId: 'tenant-site-beta',
    actor: { did: 'did:exo:ai-audit-reviewer-alpha', kind: 'ai_agent' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['write'] },
    controlEvidence: [
      {
        controlId: '',
        readinessStatus: 'blocked',
        artifactHash: 'not-a-digest',
        custodyDigest: '0000000000000000000000000000000000000000000000000000000000000000',
        receiptId: '',
        classification: '',
      },
    ],
    findingSummary: {
      openCritical: 1,
      openMajor: 1,
      openMinor: -1,
      observations: null,
      closedCritical: 0,
      closedMajor: 0,
    },
    decisionForum: {
      verified: true,
      state: 'approved',
      humanGate: { verified: false },
      quorum: { status: 'not_met' },
      openChallenge: true,
      decisionId: '',
      workflowReceiptId: '',
    },
    evidenceBundle: { complete: false, phiBoundaryAttested: false },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('human_gate_unverified'));
  assert.ok(denied.reasons.includes('quorum_not_met'));
  assert.ok(denied.reasons.includes('challenge_open'));
  assert.ok(denied.reasons.includes('evidence_bundle_incomplete'));
  assert.ok(denied.reasons.includes('phi_boundary_unattested'));
  assert.ok(denied.reasons.includes('audit_open_critical_findings'));
  assert.ok(denied.reasons.includes('audit_open_major_findings'));
  assert.ok(denied.reasons.includes('audit_control_blocked'));
  assert.ok(denied.reasons.includes('audit_control_id_absent'));
  assert.ok(denied.reasons.includes('audit_control_artifact_hash_invalid'));
  assert.ok(denied.reasons.includes('audit_control_custody_digest_invalid'));
  assert.ok(denied.reasons.includes('audit_control_receipt_absent'));
  assert.ok(denied.reasons.includes('audit_finding_count_invalid'));
  assert.equal(denied.auditPackage, null);
  assert.equal(denied.receipt, null);
});

test('audit readiness fails closed when package shape and manifests are missing', async () => {
  const { compileAuditReadinessPackage } = await loadAuditReadiness();

  const denied = compileAuditReadinessPackage({
    tenantId: '',
    targetTenantId: 'tenant-site-alpha',
    actor: null,
    authority: null,
    audit: {
      auditId: '',
      auditType: 'unknown',
      scope: '',
      siteRef: '',
      protocolRef: '',
      readinessDecision: 'announce_ready',
    },
    controlEvidence: [],
    manifestRefs: null,
    findingSummary: null,
    decisionForum: null,
    evidenceBundle: null,
    preparedAtHlc: null,
    custodyDigest: null,
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('tenant_absent'));
  assert.ok(denied.reasons.includes('actor_did_absent'));
  assert.ok(denied.reasons.includes('authority_chain_invalid'));
  assert.ok(denied.reasons.includes('audit_id_absent'));
  assert.ok(denied.reasons.includes('audit_type_invalid'));
  assert.ok(denied.reasons.includes('audit_scope_absent'));
  assert.ok(denied.reasons.includes('audit_site_ref_absent'));
  assert.ok(denied.reasons.includes('audit_protocol_ref_absent'));
  assert.ok(denied.reasons.includes('audit_readiness_decision_invalid'));
  assert.ok(denied.reasons.includes('audit_control_evidence_absent'));
  assert.ok(denied.reasons.includes('audit_manifest_refs_absent'));
  assert.ok(denied.reasons.includes('audit_finding_summary_absent'));
  assert.ok(denied.reasons.includes('audit_prepared_time_invalid'));
  assert.ok(denied.reasons.includes('custody_digest_invalid'));
  assert.ok(denied.reasons.includes('decision_forum_unverified'));
  assert.equal(denied.auditPackage, null);
  assert.equal(denied.receipt, null);
});

test('audit readiness hold packages remain governed inactive and not audit-ready', async () => {
  const { compileAuditReadinessPackage } = await loadAuditReadiness();

  const held = compileAuditReadinessPackage({
    ...auditReadinessInput(),
    audit: {
      ...auditReadinessInput().audit,
      auditId: 'AUDIT-2026-INTERNAL-HOLD-001',
      auditType: 'internal',
      readinessDecision: 'hold_package',
    },
    controlEvidence: [
      {
        ...auditReadinessInput().controlEvidence[0],
        controlId: 'CM-QMS-FACILITY-001',
        readinessStatus: 'excluded',
      },
    ],
    manifestRefs: {
      documentVersionReceiptIds: ['cmr-doc-facility-waiver-v1'],
    },
    findingSummary: {
      openCritical: 0,
      openMajor: 0,
      openMinor: 0,
      observations: 0,
      closedCritical: 0,
      closedMajor: 0,
    },
  });

  assert.equal(held.decision, 'permitted');
  assert.equal(held.auditPackage.auditReady, false);
  assert.deepEqual(held.auditPackage.controlEvidenceIds, ['CM-QMS-FACILITY-001']);
  assert.equal(held.auditPackage.manifestRefCounts.documentVersionReceiptIds, 1);
  assert.equal(held.auditPackage.manifestRefCounts.capaClosureReceiptIds, 0);
  assert.equal(held.receipt.trustState, 'inactive');
  assert.equal(held.exochainProductionClaim, false);
});

test('audit readiness reports revoked authority unapproved governance and empty manifest objects', async () => {
  const { compileAuditReadinessPackage } = await loadAuditReadiness();

  const denied = compileAuditReadinessPackage({
    ...auditReadinessInput(),
    authority: { valid: true, revoked: true, expired: true, permissions: ['govern'] },
    manifestRefs: {},
    decisionForum: {
      verified: true,
      state: 'rejected',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
      decisionId: 'df-audit-readiness-rejected',
      workflowReceiptId: 'df-audit-workflow-rejected',
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('authority_chain_revoked'));
  assert.ok(denied.reasons.includes('authority_chain_expired'));
  assert.ok(denied.reasons.includes('decision_forum_not_approved'));
  assert.ok(denied.reasons.includes('audit_manifest_refs_absent'));
  assert.equal(denied.auditPackage, null);
  assert.equal(denied.receipt, null);
});

test('audit readiness reports null control evidence rows and incomplete finding summaries', async () => {
  const { compileAuditReadinessPackage } = await loadAuditReadiness();

  const denied = compileAuditReadinessPackage({
    ...auditReadinessInput(),
    controlEvidence: [null],
    findingSummary: {
      openCritical: 0,
      openMajor: 0,
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('audit_control_id_absent'));
  assert.ok(denied.reasons.includes('audit_control_blocked'));
  assert.ok(denied.reasons.includes('audit_control_artifact_hash_invalid'));
  assert.ok(denied.reasons.includes('audit_control_custody_digest_invalid'));
  assert.ok(denied.reasons.includes('audit_control_receipt_absent'));
  assert.ok(denied.reasons.includes('audit_control_classification_absent'));
  assert.ok(denied.reasons.includes('audit_finding_count_invalid'));
  assert.equal(denied.auditPackage, null);
  assert.equal(denied.receipt, null);
});

test('audit readiness rejects protected source content before creating receipts', async () => {
  const { compileAuditReadinessPackage } = await loadAuditReadiness();

  assert.throws(
    () =>
      compileAuditReadinessPackage({
        ...auditReadinessInput(),
        sourceDocumentBody: 'Participant Alice Example medical record content must never be packaged.',
      }),
    /protected content/i,
  );
});
