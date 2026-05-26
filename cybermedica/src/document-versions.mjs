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
const GOVERNED_DOCUMENT_STATES = new Set(['approved']);
const DRAFT_DOCUMENT_STATES = new Set(['draft']);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function hlcPresent(hlc) {
  return Number.isSafeInteger(hlc?.physicalMs) && Number.isSafeInteger(hlc?.logical);
}

function sortedEvidenceRefs(input) {
  return Array.isArray(input?.evidenceRefs) ? input.evidenceRefs.filter(hasText).sort() : [];
}

function requiredPermission(lifecycleState) {
  return GOVERNED_DOCUMENT_STATES.has(lifecycleState) ? 'govern' : 'write';
}

function evaluateAuthority(input, reasons) {
  const permission = requiredPermission(input?.document?.lifecycleState);
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !Array.isArray(input?.authority?.permissions) || !input.authority.permissions.includes(permission),
    'authority_permission_missing',
  );
}

function evaluateHumanGovernance(input, reasons) {
  if (!GOVERNED_DOCUMENT_STATES.has(input?.document?.lifecycleState)) {
    return;
  }

  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, !input?.review?.decisionForum || input.review.decisionForum.verified !== true, 'decision_forum_unverified');
  addReason(reasons, input?.review?.decisionForum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, input?.review?.decisionForum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, input?.review?.decisionForum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, input?.review?.decisionForum?.openChallenge === true, 'challenge_open');
  addReason(reasons, input?.review?.evidenceBundle?.complete !== true, 'evidence_bundle_incomplete');
  addReason(reasons, input?.review?.evidenceBundle?.phiBoundaryAttested !== true, 'phi_boundary_unattested');
  addReason(reasons, !hasText(input?.review?.approverDid), 'approver_did_absent');
}

function evaluateDocumentLineage(input, reasons) {
  const state = input?.document?.lifecycleState;
  addReason(reasons, !hasText(input?.document?.documentId), 'document_id_absent');
  addReason(reasons, !hasText(input?.document?.documentType), 'document_type_absent');
  addReason(reasons, !hasText(input?.document?.controlId), 'document_control_id_absent');
  addReason(reasons, !hasText(input?.document?.versionId), 'document_version_id_absent');
  addReason(reasons, !GOVERNED_DOCUMENT_STATES.has(state) && !DRAFT_DOCUMENT_STATES.has(state), 'document_lifecycle_state_invalid');
  addReason(reasons, !isDigest(input?.document?.artifactHash), 'document_artifact_hash_invalid');
  addReason(
    reasons,
    GOVERNED_DOCUMENT_STATES.has(state) && !isDigest(input?.document?.previousVersionHash),
    'previous_version_hash_invalid',
  );
  addReason(
    reasons,
    GOVERNED_DOCUMENT_STATES.has(state) && !hasText(input?.document?.previousReceiptId),
    'previous_receipt_id_absent',
  );
  addReason(reasons, GOVERNED_DOCUMENT_STATES.has(state) && !hlcPresent(input?.document?.effectiveAtHlc), 'effective_time_invalid');
}

function evaluateDocumentVersion(input, reasons) {
  canonicalize(input ?? {});
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  evaluateAuthority(input, reasons);
  evaluateDocumentLineage(input, reasons);
  evaluateHumanGovernance(input, reasons);
  addReason(reasons, sortedEvidenceRefs(input).length === 0, 'evidence_refs_absent');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
  addReason(reasons, !hlcPresent(input?.recordedAtHlc), 'recorded_time_invalid');
}

function documentVersionId(input) {
  return `cmdv_${sha256Hex({
    tenantId: input.tenantId,
    documentId: input.document.documentId,
    versionId: input.document.versionId,
    artifactHash: input.document.artifactHash,
  }).slice(0, 32)}`;
}

function buildReceipt(input, versionId, evidenceRefDigest) {
  const artifactHash = sha256Hex({
    versionId,
    documentId: input.document.documentId,
    documentType: input.document.documentType,
    controlId: input.document.controlId,
    documentVersionId: input.document.versionId,
    lifecycleState: input.document.lifecycleState,
    sourceArtifactHash: input.document.artifactHash,
    previousVersionHash: input.document.previousVersionHash,
    previousReceiptId: input.document.previousReceiptId,
    effectiveAtHlc: input.document.effectiveAtHlc,
    evidenceRefDigest,
  });

  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'document_version',
    artifactVersion: `${input.document.documentId}@${input.document.versionId}`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.recordedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['document_version', 'metadata_only', 'quality_evidence'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function registerDocumentVersion(input) {
  const reasons = [];
  evaluateDocumentVersion(input, reasons);
  const uniqueReasons = [...new Set(reasons)].sort();
  const denied = uniqueReasons.length > 0;

  if (denied) {
    return {
      schema: 'cybermedica.document_version_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      documentVersion: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const id = documentVersionId(input);
  const evidenceRefDigest = sha256Hex({
    tenantId: input.tenantId,
    documentId: input.document.documentId,
    versionId: input.document.versionId,
    evidenceRefs: sortedEvidenceRefs(input),
  });
  const receipt = buildReceipt(input, id, evidenceRefDigest);
  const approved = GOVERNED_DOCUMENT_STATES.has(input.document.lifecycleState);

  return {
    schema: 'cybermedica.document_version_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    documentVersion: {
      schema: 'cybermedica.document_version.v1',
      documentVersionId: id,
      tenantId: input.tenantId,
      documentId: input.document.documentId,
      documentType: input.document.documentType,
      controlId: input.document.controlId,
      versionId: input.document.versionId,
      lifecycleState: input.document.lifecycleState,
      artifactHash: input.document.artifactHash,
      previousVersionHash: input.document.previousVersionHash,
      previousReceiptId: input.document.previousReceiptId,
      effectiveAtHlc: input.document.effectiveAtHlc,
      recordedAtHlc: input.recordedAtHlc,
      evidenceRefDigest,
      effectiveForUse: approved,
      humanGovernanceRequired: approved,
      requiresApprovalBeforeUse: !approved,
      operationalStateMutable: true,
      immutableVersionReceipt: true,
      receiptId: receipt.receiptId,
    },
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
