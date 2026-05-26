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

const HEX_64 = /^[0-9a-f]{64}$/u;
const AUDIT_TYPES = new Set(['internal', 'sponsor', 'cro', 'regulatory_inspection', 'vendor']);
const READINESS_DECISIONS = new Set(['release_package', 'hold_package']);
const CONTROL_READY_STATES = new Set(['ready', 'excluded']);
const MANIFEST_REF_FIELDS = Object.freeze([
  'capaClosureReceiptIds',
  'consentPolicyReceiptIds',
  'documentVersionReceiptIds',
  'exportManifestReceiptIds',
  'qualityObjectiveReceiptIds',
  'supportAccessLogReceiptIds',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
}

function isNonNegativeSafeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function hlcPresent(hlc) {
  return Number.isSafeInteger(hlc?.physicalMs) && Number.isSafeInteger(hlc?.logical);
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function sortedTextList(value) {
  return Array.isArray(value) ? value.filter(hasText).sort() : [];
}

function assertMetadataOnly(input) {
  canonicalize(input ?? {});
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !hasAuthorityPermission(input?.authority, 'govern'), 'authority_permission_missing');
}

function evaluateHumanGovernance(input, reasons) {
  const forum = input?.decisionForum;
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, forum?.verified !== true, 'decision_forum_unverified');
  addReason(reasons, forum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, forum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, forum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, forum?.openChallenge === true, 'challenge_open');
  addReason(reasons, input?.evidenceBundle?.complete !== true, 'evidence_bundle_incomplete');
  addReason(reasons, input?.evidenceBundle?.phiBoundaryAttested !== true, 'phi_boundary_unattested');
  addReason(reasons, !hasText(forum?.decisionId), 'decision_forum_decision_id_absent');
  addReason(reasons, !hasText(forum?.workflowReceiptId), 'decision_forum_workflow_receipt_absent');
}

function evaluateAuditShape(input, reasons) {
  const audit = input?.audit;
  addReason(reasons, !hasText(audit?.auditId), 'audit_id_absent');
  addReason(reasons, !AUDIT_TYPES.has(audit?.auditType), 'audit_type_invalid');
  addReason(reasons, !hasText(audit?.scope), 'audit_scope_absent');
  addReason(reasons, !hasText(audit?.siteRef), 'audit_site_ref_absent');
  addReason(reasons, !hasText(audit?.protocolRef), 'audit_protocol_ref_absent');
  addReason(reasons, !READINESS_DECISIONS.has(audit?.readinessDecision), 'audit_readiness_decision_invalid');
  addReason(reasons, !hlcPresent(input?.preparedAtHlc), 'audit_prepared_time_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function normalizeControlEvidence(controlEvidence, reasons) {
  if (!Array.isArray(controlEvidence) || controlEvidence.length === 0) {
    reasons.push('audit_control_evidence_absent');
    return [];
  }

  return controlEvidence
    .map((control) => {
      addReason(reasons, !hasText(control?.controlId), 'audit_control_id_absent');
      addReason(reasons, !CONTROL_READY_STATES.has(control?.readinessStatus), 'audit_control_blocked');
      addReason(reasons, !isDigest(control?.artifactHash), 'audit_control_artifact_hash_invalid');
      addReason(reasons, !isDigest(control?.custodyDigest), 'audit_control_custody_digest_invalid');
      addReason(reasons, !hasText(control?.receiptId), 'audit_control_receipt_absent');
      addReason(reasons, !hasText(control?.classification), 'audit_control_classification_absent');

      return {
        artifactHash: control?.artifactHash ?? null,
        classification: control?.classification ?? null,
        controlId: control?.controlId ?? null,
        custodyDigest: control?.custodyDigest ?? null,
        readinessStatus: control?.readinessStatus ?? null,
        receiptId: control?.receiptId ?? null,
      };
    })
    .sort((left, right) => String(left.controlId).localeCompare(String(right.controlId)));
}

function normalizeManifestRefs(manifestRefs, reasons) {
  if (manifestRefs === null || manifestRefs === undefined || typeof manifestRefs !== 'object') {
    reasons.push('audit_manifest_refs_absent');
    return Object.fromEntries(MANIFEST_REF_FIELDS.map((field) => [field, []]));
  }

  const normalized = {};
  for (const field of MANIFEST_REF_FIELDS) {
    normalized[field] = sortedTextList(manifestRefs[field]);
  }

  const hasAnyRefs = Object.values(normalized).some((refs) => refs.length > 0);
  addReason(reasons, !hasAnyRefs, 'audit_manifest_refs_absent');
  return normalized;
}

function evaluateFindingSummary(findingSummary, reasons) {
  if (findingSummary === null || findingSummary === undefined || typeof findingSummary !== 'object') {
    reasons.push('audit_finding_summary_absent');
    return {
      closedCritical: 0,
      closedMajor: 0,
      observations: 0,
      openCritical: 0,
      openMajor: 0,
      openMinor: 0,
    };
  }

  const fields = ['closedCritical', 'closedMajor', 'observations', 'openCritical', 'openMajor', 'openMinor'];
  for (const field of fields) {
    addReason(reasons, !isNonNegativeSafeInteger(findingSummary[field]), 'audit_finding_count_invalid');
  }
  addReason(reasons, findingSummary.openCritical > 0, 'audit_open_critical_findings');
  addReason(reasons, findingSummary.openMajor > 0, 'audit_open_major_findings');

  return {
    closedCritical: findingSummary.closedCritical ?? 0,
    closedMajor: findingSummary.closedMajor ?? 0,
    observations: findingSummary.observations ?? 0,
    openCritical: findingSummary.openCritical ?? 0,
    openMajor: findingSummary.openMajor ?? 0,
    openMinor: findingSummary.openMinor ?? 0,
  };
}

function packageArtifactHash(input, normalizedControlEvidence, normalizedManifestRefs, normalizedFindingSummary) {
  return sha256Hex({
    audit: input.audit,
    controlEvidence: normalizedControlEvidence,
    decisionForumDecisionId: input.decisionForum.decisionId,
    findingSummary: normalizedFindingSummary,
    manifestRefs: normalizedManifestRefs,
    preparedAtHlc: input.preparedAtHlc,
    workflowReceiptId: input.decisionForum.workflowReceiptId,
  });
}

function buildReceipt(input, artifactHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'audit_readiness_package',
    artifactVersion: `${input.audit.auditId}@${input.preparedAtHlc.physicalMs}.${input.preparedAtHlc.logical}`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.preparedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['audit_readiness', 'metadata_only', 'human_governed'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function compileAuditReadinessPackage(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateHumanGovernance(input, reasons);
  evaluateAuditShape(input, reasons);
  const normalizedControlEvidence = normalizeControlEvidence(input?.controlEvidence, reasons);
  const normalizedManifestRefs = normalizeManifestRefs(input?.manifestRefs, reasons);
  const normalizedFindingSummary = evaluateFindingSummary(input?.findingSummary, reasons);

  const uniqueReasons = [...new Set(reasons)].sort();
  const denied = uniqueReasons.length > 0;

  if (denied) {
    return {
      schema: 'cybermedica.audit_readiness_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      auditPackage: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const artifactHash = packageArtifactHash(
    input,
    normalizedControlEvidence,
    normalizedManifestRefs,
    normalizedFindingSummary,
  );
  const receipt = buildReceipt(input, artifactHash);
  const manifestRefCounts = Object.fromEntries(
    MANIFEST_REF_FIELDS.map((field) => [field, normalizedManifestRefs[field].length]),
  );
  const auditReady = input.audit.readinessDecision === 'release_package';

  return {
    schema: 'cybermedica.audit_readiness_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    auditPackage: {
      schema: 'cybermedica.audit_readiness_package.v1',
      auditPackageId: `cmarp_${sha256Hex({
        artifactHash,
        auditId: input.audit.auditId,
        tenantId: input.tenantId,
      }).slice(0, 32)}`,
      tenantId: input.tenantId,
      auditId: input.audit.auditId,
      auditType: input.audit.auditType,
      scope: input.audit.scope,
      siteRef: input.audit.siteRef,
      protocolRef: input.audit.protocolRef,
      auditReady,
      readinessDecision: input.audit.readinessDecision,
      controlEvidenceIds: normalizedControlEvidence.map((control) => control.controlId),
      controlEvidenceManifestHash: sha256Hex(normalizedControlEvidence),
      manifestRefs: normalizedManifestRefs,
      manifestRefCounts,
      findingSummary: normalizedFindingSummary,
      decisionForumDecisionId: input.decisionForum.decisionId,
      workflowReceiptId: input.decisionForum.workflowReceiptId,
      preparedAtHlc: input.preparedAtHlc,
      receiptId: receipt.receiptId,
      humanGovernanceRequired: true,
      operationalStateMutable: true,
      immutablePackageReceipt: true,
      trustState: 'inactive',
      exochainProductionClaim: false,
    },
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
