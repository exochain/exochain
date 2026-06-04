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

import { ProtectedContentError, canonicalize, createEvidenceReceipt, sha256Hex } from './qms-contracts.mjs';

export { ProtectedContentError };

const HEX_64 = /^[0-9a-f]{64}$/u;
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const AGING_SCHEMA = 'cybermedica.evidence_aging_engine.v1';
const REQUIRED_PERMISSION = 'evidence_age_review';
const REQUIRED_SCOPE_FAMILIES = Object.freeze(['control', 'diligence_packet', 'protocol', 'site', 'study']);
const ACTIVE_POLICY_STATUSES = new Set(['active']);
const ACTOR_KINDS = new Set(['human', 'service_account']);
const APPROVAL_STATUSES = new Set(['approved']);
const HUMAN_REVIEW_DECISIONS = new Set(['accepted']);
const RESOLUTION_TYPES = new Set(['formal_waiver', 'replaced', 'revalidated']);

const RAW_AGING_FIELDS = new Set([
  'agingnarrative',
  'content',
  'evidencebody',
  'freetext',
  'freetextnote',
  'rawagingcontent',
  'rawcontent',
  'rawevidence',
  'rawevidencebody',
  'rawevidencetext',
  'rawfinding',
  'rawreviewnotes',
  'rawsource',
  'rawsourcedata',
  'reviewnotes',
  'sourcebody',
  'sourcedocumentbody',
  'sourcedocumenttext',
]);

const SECRET_AGING_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'bootstraptoken',
  'clientsecret',
  'credentialsecret',
  'password',
  'privatekey',
  'refreshtoken',
  'rootkey',
  'rootsigningkey',
  'secret',
  'sessionsecret',
  'signaturesecret',
  'signingkey',
  'token',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && value !== ZERO_HASH;
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
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
  if (typeof value === 'object') {
    return Object.keys(value).length > 0;
  }
  return true;
}

function assertNoRawAgingContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawAgingContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_AGING_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw evidence aging content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_AGING_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`evidence aging secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawAgingContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawAgingContent(input ?? {});
  canonicalize(input ?? {});
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [hlc.physicalMs, hlc.logical];
}

function compareHlc(left, right) {
  if (left[0] !== right[0]) {
    return left[0] < right[0] ? -1 : 1;
  }
  if (left[1] !== right[1]) {
    return left[1] < right[1] ? -1 : 1;
  }
  return 0;
}

function hlcBefore(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) < 0;
}

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function evidenceLabel(record, index = null) {
  if (hasText(record?.evidenceRef)) {
    return record.evidenceRef;
  }
  return index === null ? 'unknown' : `index_${index}`;
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, !ACTOR_KINDS.has(input?.actor?.kind), 'aging_actor_kind_invalid');
  addReason(
    reasons,
    input?.actor?.kind === 'service_account' && !hasText(input?.actor?.humanOwnerDid),
    'service_account_human_owner_absent',
  );
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'evidence_age_review_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(policy, reasons) {
  const requiredScopeFamilies = sortedTextList(policy?.requiredScopeFamilies);
  addReason(reasons, !hasText(policy?.policyRef), 'aging_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'aging_policy_hash_invalid');
  addReason(reasons, !ACTIVE_POLICY_STATUSES.has(policy?.status), 'aging_policy_not_active');
  addReason(reasons, policy?.staleEvidenceChangesReadiness !== true, 'aging_policy_readiness_rule_absent');
  addReason(reasons, policy?.formalWaiverAllowed !== true, 'aging_policy_formal_waiver_rule_absent');
  addReason(reasons, policy?.revalidationAllowed !== true, 'aging_policy_revalidation_rule_absent');
  addReason(reasons, policy?.replacementAllowed !== true, 'aging_policy_replacement_rule_absent');
  addReason(reasons, policy?.driftSignalRequired !== true, 'aging_policy_drift_signal_rule_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'aging_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'aging_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'aging_policy_time_invalid');

  for (const family of REQUIRED_SCOPE_FAMILIES) {
    addReason(reasons, !requiredScopeFamilies.includes(family), `aging_policy_scope_family_missing:${family}`);
  }
  for (const family of requiredScopeFamilies) {
    addReason(reasons, !REQUIRED_SCOPE_FAMILIES.includes(family), `aging_policy_scope_family_unsupported:${family}`);
  }

  return { requiredScopeFamilies };
}

function evaluateRun(run, policy, reasons) {
  addReason(reasons, !hasText(run?.runRef), 'aging_run_ref_absent');
  addReason(reasons, !hasText(run?.readinessClaimRef), 'aging_readiness_claim_ref_absent');
  addReason(reasons, !isDigest(run?.sourceIndexHash), 'aging_source_index_hash_invalid');
  addReason(reasons, hlcTuple(run?.asOfHlc) === null, 'aging_as_of_time_invalid');
  addReason(reasons, run?.metadataOnly !== true, 'aging_run_metadata_boundary_invalid');
  addReason(reasons, run?.protectedContentExcluded !== true, 'aging_run_protected_boundary_invalid');
  addReason(reasons, run?.exochainProductionClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, run?.asOfHlc), 'aging_policy_after_run_as_of');
}

function ageMs(record, asOfHlc) {
  const verified = hlcTuple(record?.lastVerifiedAtHlc);
  const asOf = hlcTuple(asOfHlc);
  if (verified === null || asOf === null || asOf[0] < verified[0]) {
    return null;
  }
  return asOf[0] - verified[0];
}

function freshnessBasisPoints(record, asOfHlc) {
  const elapsed = ageMs(record, asOfHlc);
  if (elapsed === null || !Number.isSafeInteger(record?.freshnessWindowMs) || record.freshnessWindowMs <= 0) {
    return 0;
  }
  if (elapsed >= record.freshnessWindowMs) {
    return 0;
  }
  const remaining = record.freshnessWindowMs - elapsed;
  return Number((BigInt(remaining) * 10000n) / BigInt(record.freshnessWindowMs));
}

function isRecordStale(record, asOfHlc) {
  const elapsed = ageMs(record, asOfHlc);
  return elapsed !== null && Number.isSafeInteger(record?.freshnessWindowMs) && elapsed > record.freshnessWindowMs;
}

function resolutionTime(resolution) {
  if (resolution?.type === 'formal_waiver') {
    return resolution.approvedAtHlc;
  }
  if (resolution?.type === 'revalidated') {
    return resolution.revalidatedAtHlc;
  }
  if (resolution?.type === 'replaced') {
    return resolution.replacedAtHlc;
  }
  return null;
}

function evaluateFormalWaiver(record, policy, run, reasons) {
  const resolution = record?.agingResolution;
  const label = evidenceLabel(record);
  addReason(reasons, policy?.formalWaiverAllowed !== true, `aging_waiver_not_allowed:${label}`);
  addReason(reasons, !hasText(resolution?.reasonCode), `aging_waiver_reason_absent:${label}`);
  addReason(reasons, !isDigest(resolution?.approvalHash), `aging_waiver_approval_hash_invalid:${label}`);
  addReason(reasons, !hasText(resolution?.approverDid), `aging_waiver_approver_absent:${label}`);
  addReason(reasons, hlcTuple(resolution?.approvedAtHlc) === null, `aging_waiver_approval_time_invalid:${label}`);
  addReason(reasons, hlcTuple(resolution?.validUntilHlc) === null, `aging_waiver_valid_until_invalid:${label}`);
  addReason(reasons, resolution?.metadataOnly !== true, `aging_waiver_metadata_boundary_invalid:${label}`);
  addReason(reasons, resolution?.protectedContentExcluded !== true, `aging_waiver_protected_boundary_invalid:${label}`);
  addReason(reasons, !hlcAfter(resolution?.approvedAtHlc, record?.lastVerifiedAtHlc), `aging_waiver_before_last_verification:${label}`);
  addReason(reasons, !hlcAfter(resolution?.validUntilHlc, run?.asOfHlc), `aging_waiver_expired:${label}`);
}

function evaluateRevalidation(record, policy, reasons) {
  const resolution = record?.agingResolution;
  const label = evidenceLabel(record);
  addReason(reasons, policy?.revalidationAllowed !== true, `aging_revalidation_not_allowed:${label}`);
  addReason(reasons, !isDigest(resolution?.revalidationHash), `aging_revalidation_hash_invalid:${label}`);
  addReason(reasons, !hasText(resolution?.reviewerDid), `aging_revalidation_reviewer_absent:${label}`);
  addReason(reasons, hlcTuple(resolution?.revalidatedAtHlc) === null, `aging_revalidation_time_invalid:${label}`);
  addReason(reasons, resolution?.metadataOnly !== true, `aging_revalidation_metadata_boundary_invalid:${label}`);
  addReason(reasons, resolution?.protectedContentExcluded !== true, `aging_revalidation_protected_boundary_invalid:${label}`);
  addReason(
    reasons,
    !hlcAfter(resolution?.revalidatedAtHlc, record?.lastVerifiedAtHlc),
    `aging_revalidation_before_last_verification:${label}`,
  );
}

function evaluateReplacement(record, policy, reasons) {
  const resolution = record?.agingResolution;
  const label = evidenceLabel(record);
  addReason(reasons, policy?.replacementAllowed !== true, `aging_replacement_not_allowed:${label}`);
  addReason(reasons, !hasText(resolution?.replacementEvidenceRef), `aging_replacement_ref_absent:${label}`);
  addReason(reasons, !isDigest(resolution?.replacementEvidenceHash), `aging_replacement_hash_invalid:${label}`);
  addReason(reasons, !isDigest(resolution?.replacementCustodyDigest), `aging_replacement_custody_invalid:${label}`);
  addReason(reasons, hlcTuple(resolution?.replacedAtHlc) === null, `aging_replacement_time_invalid:${label}`);
  addReason(reasons, resolution?.metadataOnly !== true, `aging_replacement_metadata_boundary_invalid:${label}`);
  addReason(reasons, resolution?.protectedContentExcluded !== true, `aging_replacement_protected_boundary_invalid:${label}`);
  addReason(
    reasons,
    !hlcAfter(resolution?.replacedAtHlc, record?.lastVerifiedAtHlc),
    `aging_replacement_before_last_verification:${label}`,
  );
}

function evaluateResolution(record, policy, run, reasons) {
  const label = evidenceLabel(record);
  const resolution = record?.agingResolution;
  addReason(reasons, resolution === null || resolution === undefined, `stale_evidence_unresolved:${label}`);
  if (resolution === null || resolution === undefined) {
    return { type: null, resolved: false };
  }

  addReason(reasons, !RESOLUTION_TYPES.has(resolution.type), `aging_resolution_type_unsupported:${label}`);
  if (!RESOLUTION_TYPES.has(resolution.type)) {
    addReason(reasons, true, `stale_evidence_unresolved:${label}`);
    return { type: resolution.type, resolved: false };
  }

  const before = reasons.length;
  if (resolution.type === 'formal_waiver') {
    evaluateFormalWaiver(record, policy, run, reasons);
  }
  if (resolution.type === 'revalidated') {
    evaluateRevalidation(record, policy, reasons);
  }
  if (resolution.type === 'replaced') {
    evaluateReplacement(record, policy, reasons);
  }

  const resolved = reasons.length === before;
  addReason(reasons, !resolved, `stale_evidence_unresolved:${label}`);
  return { type: resolution.type, resolved };
}

function evaluateEvidenceRecords(records, policy, run, reasons) {
  addReason(reasons, !Array.isArray(records) || records.length === 0, 'evidence_records_absent');
  if (!Array.isArray(records)) {
    return { currentRefs: [], records: [], resolutionTypes: [], scopeFamilies: [], staleRefs: [], unresolvedStaleRefs: [] };
  }

  const seenRefs = new Set();
  const currentRefs = [];
  const staleRefs = [];
  const unresolvedStaleRefs = [];
  const resolutionTypes = [];
  const recordSummaries = [];
  const scopeFamilies = sortedTextList(records.map((record) => record?.scopeFamily));

  for (const family of REQUIRED_SCOPE_FAMILIES) {
    addReason(reasons, !scopeFamilies.includes(family), `aging_scope_family_missing:${family}`);
  }

  records.forEach((record, index) => {
    const label = evidenceLabel(record, index);
    addReason(reasons, !hasText(record?.evidenceRef), `evidence_ref_absent:${label}`);
    addReason(reasons, seenRefs.has(record?.evidenceRef), `evidence_ref_duplicate:${label}`);
    if (hasText(record?.evidenceRef)) {
      seenRefs.add(record.evidenceRef);
    }
    addReason(reasons, !REQUIRED_SCOPE_FAMILIES.includes(record?.scopeFamily), `evidence_scope_family_unsupported:${label}`);
    addReason(reasons, !isDigest(record?.evidenceHash), `evidence_hash_invalid:${label}`);
    addReason(reasons, !isDigest(record?.custodyDigest), `evidence_custody_digest_invalid:${label}`);
    addReason(reasons, !hasText(record?.ownerRoleRef), `evidence_owner_role_absent:${label}`);
    addReason(reasons, !APPROVAL_STATUSES.has(record?.approvalStatus), `evidence_not_approved:${label}`);
    addReason(reasons, hlcTuple(record?.lastVerifiedAtHlc) === null, `evidence_last_verified_time_invalid:${label}`);
    addReason(
      reasons,
      !Number.isSafeInteger(record?.freshnessWindowMs) || record.freshnessWindowMs <= 0,
      `evidence_freshness_window_invalid:${label}`,
    );
    addReason(reasons, record?.readinessSupportCandidate !== true, `evidence_readiness_support_absent:${label}`);
    addReason(reasons, record?.metadataOnly !== true, `evidence_metadata_boundary_invalid:${label}`);
    addReason(reasons, record?.protectedContentExcluded !== true, `evidence_protected_boundary_invalid:${label}`);
    addReason(reasons, hlcAfter(record?.lastVerifiedAtHlc, run?.asOfHlc), `evidence_verified_after_as_of:${label}`);

    const stale = isRecordStale(record, run?.asOfHlc);
    const resolution = stale ? evaluateResolution(record, policy, run, reasons) : { type: null, resolved: true };
    if (stale) {
      staleRefs.push(record.evidenceRef);
      if (hasText(resolution.type)) {
        resolutionTypes.push(resolution.type);
      }
      if (!resolution.resolved) {
        unresolvedStaleRefs.push(record.evidenceRef);
      }
    } else if (hasText(record?.evidenceRef)) {
      currentRefs.push(record.evidenceRef);
    }

    recordSummaries.push({
      ageMs: ageMs(record, run?.asOfHlc),
      evidenceRef: record?.evidenceRef ?? label,
      freshnessRemainingBasisPoints: freshnessBasisPoints(record, run?.asOfHlc),
      resolutionType: resolution.type,
      scopeFamily: record?.scopeFamily ?? 'unknown',
      status: stale ? (resolution.resolved ? 'stale_resolved' : 'stale_unresolved') : 'current',
    });
  });

  addReason(reasons, unresolvedStaleRefs.length > 0, 'readiness_claim_blocked_by_stale_evidence');

  return {
    currentRefs: uniqueSorted(currentRefs),
    records: recordSummaries.sort((left, right) => left.evidenceRef.localeCompare(right.evidenceRef)),
    resolutionTypes: uniqueSorted(resolutionTypes),
    scopeFamilies,
    staleRefs: uniqueSorted(staleRefs),
    unresolvedStaleRefs: uniqueSorted(unresolvedStaleRefs),
  };
}

function evaluateOwnerAssignments(assignments, staleRefs, reasons) {
  addReason(reasons, staleRefs.length > 0 && (!Array.isArray(assignments) || assignments.length === 0), 'stale_owner_assignments_absent');
  const assignmentByRef = new Map();
  if (Array.isArray(assignments)) {
    assignments.forEach((assignment, index) => {
      const label = hasText(assignment?.evidenceRef) ? assignment.evidenceRef : `index_${index}`;
      addReason(reasons, !hasText(assignment?.evidenceRef), `aging_assignment_evidence_ref_absent:${label}`);
      addReason(reasons, assignmentByRef.has(assignment?.evidenceRef), `aging_assignment_duplicate:${label}`);
      addReason(reasons, !hasText(assignment?.ownerRoleRef), `aging_assignment_owner_role_absent:${label}`);
      addReason(reasons, !isDigest(assignment?.ownerDidHash), `aging_assignment_owner_hash_invalid:${label}`);
      addReason(reasons, hlcTuple(assignment?.assignedAtHlc) === null, `aging_assignment_time_invalid:${label}`);
      addReason(reasons, hlcTuple(assignment?.dueAtHlc) === null, `aging_assignment_due_time_invalid:${label}`);
      addReason(reasons, assignment?.metadataOnly !== true, `aging_assignment_metadata_boundary_invalid:${label}`);
      addReason(reasons, hlcBefore(assignment?.dueAtHlc, assignment?.assignedAtHlc), `aging_assignment_due_before_assigned:${label}`);
      if (hasText(assignment?.evidenceRef)) {
        assignmentByRef.set(assignment.evidenceRef, assignment);
      }
    });
  }

  for (const staleRef of staleRefs) {
    addReason(reasons, !assignmentByRef.has(staleRef), `stale_evidence_owner_absent:${staleRef}`);
  }
  return assignmentByRef;
}

function evaluateHumanReview(review, run, records, reasons) {
  addReason(reasons, !hasText(review?.reviewerDid), 'aging_human_reviewer_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'aging_human_review_not_accepted');
  addReason(reasons, !isDigest(review?.reviewHash), 'aging_human_review_hash_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'aging_human_review_time_invalid');
  addReason(reasons, review?.metadataOnly !== true, 'aging_human_review_metadata_boundary_invalid');
  addReason(reasons, review?.protectedContentExcluded !== true, 'aging_human_review_protected_boundary_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, run?.asOfHlc), 'aging_human_review_before_run');

  for (const record of Array.isArray(records) ? records : []) {
    const resolvedAt = resolutionTime(record?.agingResolution);
    if (resolvedAt !== null) {
      addReason(reasons, hlcAfter(resolvedAt, review?.reviewedAtHlc), `aging_resolution_after_human_review:${evidenceLabel(record)}`);
    }
  }
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance === null || aiAssistance === undefined) {
    return;
  }
  addReason(reasons, aiAssistance.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, aiAssistance.used === true && !isDigest(aiAssistance.outputHash), 'ai_output_hash_invalid');
  addReason(reasons, aiAssistance.used === true && aiAssistance.reviewedByHuman !== true, 'ai_human_review_absent');
}

function buildDriftSignals(staleRecords, assignmentByRef, run) {
  return staleRecords
    .filter((record) => hasText(record?.evidenceRef))
    .sort((left, right) => left.evidenceRef.localeCompare(right.evidenceRef))
    .map((record) => {
      const assignment = assignmentByRef.get(record.evidenceRef);
      const basis = {
        asOfHlc: run.asOfHlc,
        evidenceHash: record.evidenceHash,
        evidenceRef: record.evidenceRef,
        lastVerifiedAtHlc: record.lastVerifiedAtHlc,
        resolutionType: record.agingResolution?.type ?? 'unresolved',
      };
      return {
        signalFamily: 'evidence_aging',
        signalHash: sha256Hex(basis),
        signalRef: `aging-signal-${sha256Hex(record.evidenceRef).slice(0, 16)}`,
        evidenceRef: record.evidenceRef,
        ownerRoleRef: assignment?.ownerRoleRef ?? record.ownerRoleRef,
        humanVisible: true,
        reviewable: true,
        metadataOnly: true,
        protectedContentExcluded: true,
      };
    });
}

function buildAgingRegister(input, recordSummary, assignmentByRef) {
  const staleRecords = input.evidenceRecords.filter((record) => isRecordStale(record, input.agingRun.asOfHlc));
  const driftSignals = buildDriftSignals(staleRecords, assignmentByRef, input.agingRun);
  const registerBasis = {
    asOfHlc: input.agingRun.asOfHlc,
    readinessClaimRef: input.agingRun.readinessClaimRef,
    staleEvidenceRefs: recordSummary.staleRefs,
    tenantId: input.tenantId,
  };

  return {
    schema: AGING_SCHEMA,
    registerId: `cmage_${sha256Hex(registerBasis).slice(0, 32)}`,
    trustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    tenantId: input.tenantId,
    runRef: input.agingRun.runRef,
    readinessClaimRef: input.agingRun.readinessClaimRef,
    readinessClaimAllowed: recordSummary.unresolvedStaleRefs.length === 0,
    scopeFamiliesCovered: recordSummary.scopeFamilies,
    currentEvidenceRefs: recordSummary.currentRefs,
    staleEvidenceRefs: recordSummary.staleRefs,
    resolvedStaleEvidenceRefs: recordSummary.staleRefs.filter((ref) => !recordSummary.unresolvedStaleRefs.includes(ref)),
    unresolvedStaleEvidenceRefs: recordSummary.unresolvedStaleRefs,
    resolutionTypes: recordSummary.resolutionTypes,
    evidenceSummaries: recordSummary.records,
    driftSignals,
    humanReviewHash: input.humanReview.reviewHash,
    sourceIndexHash: input.agingRun.sourceIndexHash,
    asOfHlc: input.agingRun.asOfHlc,
  };
}

function buildReceipt(input, agingRegister) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: sha256Hex(agingRegister),
    artifactType: 'evidence_aging_engine',
    artifactVersion: 'v1',
    classification: 'restricted_metadata_only',
    custodyDigest: sha256Hex({
      driftSignalRefs: agingRegister.driftSignals.map((signal) => signal.signalRef),
      humanReviewHash: input.humanReview.reviewHash,
      staleEvidenceRefs: agingRegister.staleEvidenceRefs,
    }),
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    sensitivityTags: ['evidence_aging', 'metadata_only'],
    sourceSystem: 'cybermedica',
    tenantId: input.tenantId,
  });
}

export function evaluateEvidenceAging(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluatePolicy(input?.agingPolicy, reasons);
  evaluateRun(input?.agingRun, input?.agingPolicy, reasons);
  const recordSummary = evaluateEvidenceRecords(input?.evidenceRecords, input?.agingPolicy, input?.agingRun, reasons);
  const assignmentByRef = evaluateOwnerAssignments(input?.ownerAssignments, recordSummary.staleRefs, reasons);
  evaluateHumanReview(input?.humanReview, input?.agingRun, input?.evidenceRecords, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      decision: 'denied',
      failClosed: true,
      reasons: unique,
    };
  }

  const agingRegister = buildAgingRegister(input, recordSummary, assignmentByRef);
  return {
    decision: 'permitted',
    failClosed: false,
    agingRegister,
    receipt: buildReceipt(input, agingRegister),
  };
}
