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

import { canonicalize, createEvidenceReceipt, evaluateGovernedAction, sha256Hex } from './qms-contracts.mjs';

const HEX_64 = /^[0-9a-f]{64}$/u;
const RAW_ADMIN_GOVERNANCE_GATE_ID = 'PTAG-004';
const CONTROL_LIFECYCLE_ACTIONS = new Set(['approve', 'revise', 'retire']);
const CONTROL_RISK_CRITICALITIES = new Set(['critical', 'major', 'minor']);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
}

function hlcPresent(hlc) {
  return Number.isSafeInteger(hlc?.physicalMs) && Number.isSafeInteger(hlc?.logical);
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function assertMetadataOnly(input) {
  canonicalize(input ?? {});
}

function sortedTextList(value) {
  return Array.isArray(value) ? value.filter(hasText).sort() : [];
}

function normalizeEvidenceRefs(evidenceRefs, reasons) {
  if (!Array.isArray(evidenceRefs) || evidenceRefs.length === 0) {
    reasons.push('control_evidence_refs_absent');
    return [];
  }

  return evidenceRefs
    .map((evidence) => {
      addReason(reasons, !hasText(evidence?.evidenceId), 'control_evidence_id_absent');
      addReason(reasons, !hasText(evidence?.artifactType), 'control_evidence_type_absent');
      addReason(reasons, !hasText(evidence?.artifactVersion), 'control_evidence_version_absent');
      addReason(reasons, !isDigest(evidence?.artifactHash), 'control_evidence_artifact_hash_invalid');
      addReason(reasons, !isDigest(evidence?.custodyDigest), 'control_evidence_custody_digest_invalid');
      addReason(reasons, !hasText(evidence?.classification), 'control_evidence_classification_absent');

      return {
        artifactHash: evidence?.artifactHash ?? null,
        artifactType: evidence?.artifactType ?? null,
        artifactVersion: evidence?.artifactVersion ?? null,
        classification: evidence?.classification ?? null,
        custodyDigest: evidence?.custodyDigest ?? null,
        evidenceId: evidence?.evidenceId ?? null,
      };
    })
    .sort((left, right) => String(left.evidenceId).localeCompare(String(right.evidenceId)));
}

function evaluateControlShape(input, affectedWorkflowRefs, policyRefs, reasons) {
  const control = input?.control;
  addReason(reasons, !hasText(control?.controlId), 'control_id_absent');
  addReason(reasons, !hasText(control?.versionId), 'control_version_id_absent');
  addReason(reasons, !hasText(control?.title), 'control_title_absent');
  addReason(reasons, !hasText(control?.objective), 'control_objective_absent');
  addReason(reasons, !hasText(control?.ownerRole), 'control_owner_role_absent');
  addReason(
    reasons,
    !CONTROL_RISK_CRITICALITIES.has(control?.riskCriticality),
    'control_risk_criticality_invalid',
  );
  addReason(
    reasons,
    !CONTROL_LIFECYCLE_ACTIONS.has(control?.lifecycleAction),
    'control_lifecycle_action_invalid',
  );
  addReason(reasons, affectedWorkflowRefs.length === 0, 'control_affected_workflow_refs_absent');
  addReason(reasons, policyRefs.length === 0, 'control_policy_refs_absent');
  addReason(reasons, !hlcPresent(input?.approvedAtHlc), 'control_approval_time_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function evaluateDecisionForumEvidence(decisionForum, reasons) {
  addReason(reasons, !hasText(decisionForum?.decisionId), 'decision_forum_decision_id_absent');
  addReason(reasons, !hasText(decisionForum?.workflowReceiptId), 'decision_forum_workflow_receipt_absent');
  addReason(
    reasons,
    decisionForum?.rawAdminGovernanceEndpointUsed === true,
    'ptag_004_raw_admin_governance_endpoint_forbidden',
  );
}

function lifecycleStatus(lifecycleAction) {
  if (lifecycleAction === 'retire') {
    return 'retired';
  }
  return 'approved';
}

function controlApprovalArtifactHash(input, normalizedEvidenceRefs, affectedWorkflowRefs, policyRefs) {
  return sha256Hex({
    affectedWorkflowRefs,
    approvedAtHlc: input.approvedAtHlc,
    controlId: input.control.controlId,
    decisionForumDecisionId: input.decisionForum.decisionId,
    evidenceRefs: normalizedEvidenceRefs,
    lifecycleAction: input.control.lifecycleAction,
    objective: input.control.objective,
    ownerRole: input.control.ownerRole,
    policyRefs,
    riskCriticality: input.control.riskCriticality,
    title: input.control.title,
    versionId: input.control.versionId,
    workflowReceiptId: input.decisionForum.workflowReceiptId,
  });
}

function buildReceipt(input, artifactHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'qms_control_approval',
    artifactVersion: `${input.control.controlId}@${input.control.versionId}:${input.control.lifecycleAction}`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.approvedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['metadata_only', 'qms_control', 'human_governed'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function evaluateQmsControlApproval(input) {
  assertMetadataOnly(input);

  const reasons = [];
  const affectedWorkflowRefs = sortedTextList(input?.control?.affectedWorkflowRefs);
  const policyRefs = sortedTextList(input?.control?.policyRefs);
  const normalizedEvidenceRefs = normalizeEvidenceRefs(input?.evidenceRefs, reasons);
  const governedDecision = evaluateGovernedAction({
    action: 'qms_control_approval',
    tenantId: input?.tenantId,
    targetTenantId: input?.targetTenantId,
    actor: input?.actor,
    authority: input?.authority,
    decisionForum: input?.decisionForum,
    evidenceBundle: input?.evidenceBundle,
  });

  reasons.push(...governedDecision.reasons);
  evaluateControlShape(input, affectedWorkflowRefs, policyRefs, reasons);
  evaluateDecisionForumEvidence(input?.decisionForum, reasons);

  const uniqueReasons = [...new Set(reasons)].sort();
  const denied = uniqueReasons.length > 0;

  if (denied) {
    return {
      schema: 'cybermedica.qms_control_approval_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      controlApproval: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const artifactHash = controlApprovalArtifactHash(input, normalizedEvidenceRefs, affectedWorkflowRefs, policyRefs);
  const receipt = buildReceipt(input, artifactHash);
  const status = lifecycleStatus(input.control.lifecycleAction);

  return {
    schema: 'cybermedica.qms_control_approval_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    controlApproval: {
      schema: 'cybermedica.qms_control_approval.v1',
      controlApprovalId: `cmqa_${sha256Hex({
        artifactHash,
        controlId: input.control.controlId,
        tenantId: input.tenantId,
        versionId: input.control.versionId,
      }).slice(0, 32)}`,
      tenantId: input.tenantId,
      controlId: input.control.controlId,
      versionId: input.control.versionId,
      status,
      lifecycleAction: input.control.lifecycleAction,
      riskCriticality: input.control.riskCriticality,
      ownerRole: input.control.ownerRole,
      affectedWorkflowRefs,
      policyRefs,
      evidenceRefs: normalizedEvidenceRefs.map((evidence) => evidence.evidenceId),
      evidenceManifestHash: sha256Hex(normalizedEvidenceRefs),
      decisionForumDecisionId: input.decisionForum.decisionId,
      workflowReceiptId: input.decisionForum.workflowReceiptId,
      approvedAtHlc: input.approvedAtHlc,
      effectiveForUse: status === 'approved',
      humanGovernanceRequired: true,
      rawAdminGovernanceEndpointUsed: false,
      activationGateIds: [RAW_ADMIN_GOVERNANCE_GATE_ID],
      operationalStateMutable: true,
      immutableApprovalReceipt: true,
      receiptId: receipt.receiptId,
    },
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
