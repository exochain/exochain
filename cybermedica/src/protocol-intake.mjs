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
const REQUIRED_PERMISSION = 'protocol_intake';
const INTAKE_SCHEMA = 'cybermedica.protocol_intake.v1';
const DECISION_SCHEMA = 'cybermedica.protocol_intake_decision.v1';

const REQUIRED_ARTIFACT_TYPES = Object.freeze([
  'investigator_brochure',
  'protocol_amendment',
  'protocol_document',
  'sponsor_material',
  'trial_agreement',
]);

const ARTIFACT_COVERAGE_STATUSES = new Set(['received', 'not_applicable']);
const ARTIFACT_TYPES = new Set([
  ...REQUIRED_ARTIFACT_TYPES,
  'feasibility_questionnaire',
  'product_information',
  'regulatory_requirement',
]);
const CLASSIFICATIONS = new Set([
  'contract_metadata_only',
  'product_metadata_only',
  'protocol_metadata_only',
  'qms_metadata_only',
  'regulatory_metadata_only',
  'sponsor_confidential_metadata_only',
]);
const REVIEW_DECISIONS = new Set(['ready_for_feasibility', 'hold_for_intake_gap', 'reject_intake']);
const REQUIRED_CONFIDENTIALITY_FLAGS = Object.freeze([
  'directIdentifiersExcluded',
  'encryptedAtRest',
  'metadataOnly',
  'protectedContentExcluded',
  'sponsorConfidentialBoundaryAttested',
]);

const RAW_PROTOCOL_FIELDS = new Set([
  'agreementbody',
  'amendmentbody',
  'body',
  'content',
  'freetext',
  'fullprotocol',
  'investigatorbrochurebody',
  'protocolbody',
  'protocolnarrative',
  'rawagreement',
  'rawamendment',
  'rawinvestigatorbrochure',
  'rawprotocol',
  'rawprotocolbody',
  'rawsponsormaterial',
  'sourcedocumentbody',
  'sponsormaterialbody',
]);

const SECRET_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'apitoken',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credentialsecret',
  'password',
  'privatekey',
  'refreshtoken',
  'rootkey',
  'rootsigningkey',
  'secret',
  'servicetoken',
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

function assertNoProtocolPayloadOrSecrets(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoProtocolPayloadOrSecrets(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_PROTOCOL_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`protocol intake source content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`protocol intake secret field is not allowed at ${path}.${key}`);
    }
    assertNoProtocolPayloadOrSecrets(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoProtocolPayloadOrSecrets(input ?? {});
  canonicalize(input ?? {});
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [BigInt(hlc.physicalMs), BigInt(hlc.logical)];
}

function compareHlc(left, right) {
  if (left[0] < right[0]) {
    return -1;
  }
  if (left[0] > right[0]) {
    return 1;
  }
  if (left[1] < right[1]) {
    return -1;
  }
  if (left[1] > right[1]) {
    return 1;
  }
  return 0;
}

function hlcBefore(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) < 0;
}

function hlcAfterOrEqual(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) >= 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function basisPoints(numerator, denominator) {
  return Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
}

function artifactSort(left, right) {
  return (
    String(left.artifactType).localeCompare(String(right.artifactType)) ||
    String(left.artifactRef).localeCompare(String(right.artifactRef))
  );
}

function coverageSort(left, right) {
  return String(left.artifactType).localeCompare(String(right.artifactType));
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'protocol_intake_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePacket(packet, reasons) {
  addReason(reasons, !hasText(packet?.packetRef), 'intake_packet_ref_absent');
  addReason(reasons, !hasText(packet?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(packet?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(packet?.sponsorRef), 'sponsor_ref_absent');
  addReason(reasons, !hasText(packet?.croRef), 'cro_ref_absent');
  addReason(reasons, !hasText(packet?.studyRef), 'study_ref_absent');
  addReason(reasons, !hasText(packet?.intakePurpose), 'intake_purpose_absent');
  addReason(reasons, !hasText(packet?.sourceSystemRef), 'source_system_ref_absent');
  addReason(reasons, hlcTuple(packet?.receivedAtHlc) === null, 'received_time_invalid');
  addReason(reasons, hlcTuple(packet?.classifiedAtHlc) === null, 'classified_time_invalid');
  addReason(reasons, hlcTuple(packet?.reviewedAtHlc) === null, 'reviewed_time_invalid');
  addReason(reasons, hlcBefore(packet?.classifiedAtHlc, packet?.receivedAtHlc), 'classified_before_received');
  addReason(reasons, hlcBefore(packet?.reviewedAtHlc, packet?.classifiedAtHlc), 'reviewed_before_classified');
  addReason(reasons, packet?.metadataOnly !== true, 'intake_packet_metadata_boundary_absent');
  addReason(reasons, packet?.protectedContentExcluded !== true, 'intake_packet_protected_boundary_absent');
  addReason(reasons, packet?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function normalizeCoverage(input, reasons) {
  const coverage = Array.isArray(input?.artifactCoverage) ? [...input.artifactCoverage].sort(coverageSort) : [];
  addReason(reasons, coverage.length === 0, 'artifact_coverage_absent');

  const coverageByType = new Map();
  const normalizedCoverage = coverage.map((item) => {
    const artifactType = hasText(item?.artifactType) ? item.artifactType : 'unknown';
    const status = item?.status;
    addReason(reasons, !REQUIRED_ARTIFACT_TYPES.includes(artifactType), `artifact_coverage_type_invalid:${artifactType}`);
    addReason(reasons, coverageByType.has(artifactType), `artifact_coverage_duplicate:${artifactType}`);
    addReason(reasons, !ARTIFACT_COVERAGE_STATUSES.has(status), `artifact_coverage_status_invalid:${artifactType}`);
    addReason(
      reasons,
      status === 'not_applicable' && !isDigest(item?.rationaleHash),
      `artifact_not_applicable_rationale_invalid:${artifactType}`,
    );
    coverageByType.set(artifactType, {
      artifactType,
      rationaleHash: item?.rationaleHash ?? null,
      status,
    });
    return coverageByType.get(artifactType);
  });

  for (const artifactType of REQUIRED_ARTIFACT_TYPES) {
    addReason(reasons, !coverageByType.has(artifactType), `artifact_coverage_missing:${artifactType}`);
  }

  return { coverageByType, normalizedCoverage };
}

function normalizeArtifacts(input, coverageByType, packet, reasons) {
  const artifacts = Array.isArray(input?.artifacts) ? [...input.artifacts].sort(artifactSort) : [];
  addReason(reasons, artifacts.length === 0, 'artifacts_absent');

  const receivedTypes = new Set();
  const normalizedArtifacts = artifacts.map((artifact) => {
    const artifactRef = hasText(artifact?.artifactRef) ? artifact.artifactRef : 'unknown';
    const artifactType = hasText(artifact?.artifactType) ? artifact.artifactType : 'unknown';
    const receivedAtValid = hlcTuple(artifact?.receivedAtHlc) !== null;

    addReason(reasons, !hasText(artifact?.artifactRef), 'artifact_ref_absent');
    addReason(reasons, !ARTIFACT_TYPES.has(artifactType), `artifact_type_invalid:${artifactRef}`);
    addReason(reasons, !hasText(artifact?.versionRef), `artifact_version_absent:${artifactRef}`);
    addReason(reasons, !isDigest(artifact?.artifactHash), `artifact_hash_invalid:${artifactRef}`);
    addReason(reasons, !isDigest(artifact?.custodyDigest), `artifact_custody_digest_invalid:${artifactRef}`);
    addReason(reasons, !CLASSIFICATIONS.has(artifact?.classification), `artifact_classification_invalid:${artifactRef}`);
    addReason(reasons, !hasText(artifact?.sourcePartyRef), `artifact_source_party_absent:${artifactRef}`);
    addReason(reasons, !receivedAtValid, `artifact_received_time_invalid:${artifactRef}`);
    addReason(
      reasons,
      receivedAtValid && !hlcAfterOrEqual(artifact?.receivedAtHlc, packet?.receivedAtHlc),
      `artifact_received_before_packet:${artifactRef}`,
    );
    addReason(reasons, artifact?.humanReviewed !== true, `artifact_human_review_absent:${artifactRef}`);
    addReason(reasons, artifact?.phiBoundaryAttested !== true, `artifact_phi_boundary_unattested:${artifactRef}`);
    addReason(reasons, artifact?.protectedContentExcluded !== true, `artifact_protected_boundary_absent:${artifactRef}`);
    addReason(reasons, artifact?.metadataOnly !== true, `artifact_metadata_boundary_absent:${artifactRef}`);

    if (artifactType === 'protocol_amendment') {
      addReason(reasons, !hasText(artifact?.supersedesArtifactRef), `protocol_amendment_supersession_absent:${artifactRef}`);
      addReason(reasons, !isDigest(artifact?.amendmentImpactHash), `protocol_amendment_impact_hash_invalid:${artifactRef}`);
    }

    if (REQUIRED_ARTIFACT_TYPES.includes(artifactType)) {
      receivedTypes.add(artifactType);
    }

    return {
      artifactHash: artifact?.artifactHash ?? null,
      artifactRef,
      artifactType,
      classification: artifact?.classification ?? null,
      custodyDigest: artifact?.custodyDigest ?? null,
      metadataOnly: artifact?.metadataOnly === true,
      protectedContentExcluded: artifact?.protectedContentExcluded === true,
      receivedAtHlc: artifact?.receivedAtHlc ?? null,
      sourcePartyRef: artifact?.sourcePartyRef ?? null,
      supersedesArtifactRef: artifact?.supersedesArtifactRef ?? null,
      versionRef: artifact?.versionRef ?? null,
    };
  });

  for (const artifactType of REQUIRED_ARTIFACT_TYPES) {
    const coverage = coverageByType.get(artifactType);
    if (coverage?.status !== 'not_applicable') {
      addReason(reasons, !receivedTypes.has(artifactType), `artifact_required_but_absent:${artifactType}`);
    }
  }

  return {
    normalizedArtifacts,
    receivedArtifactTypes: [...receivedTypes].sort(),
  };
}

function evaluateConfidentialityProfile(profile, reasons) {
  addReason(reasons, !hasText(profile?.profileRef), 'confidentiality_profile_ref_absent');
  addReason(reasons, !hasText(profile?.accessPolicyRef), 'access_policy_ref_absent');
  addReason(reasons, !hasText(profile?.retentionScheduleRef), 'retention_schedule_ref_absent');
  addReason(reasons, sortedTextList(profile?.classificationRefs).length === 0, 'classification_refs_absent');
  addReason(reasons, profile?.externalAnchorEligible === true, 'external_anchor_must_be_disabled_for_intake');

  for (const flag of REQUIRED_CONFIDENTIALITY_FLAGS) {
    addReason(reasons, profile?.[flag] !== true, `${flag}_absent`);
  }

  addReason(reasons, profile?.encryptedAtRest !== true, 'confidentiality_encryption_absent');
  addReason(reasons, profile?.directIdentifiersExcluded !== true, 'direct_identifier_boundary_unattested');
  addReason(reasons, profile?.protectedContentExcluded !== true, 'protected_content_boundary_unattested');
  addReason(reasons, profile?.metadataOnly !== true, 'metadata_boundary_unattested');
  addReason(
    reasons,
    profile?.sponsorConfidentialBoundaryAttested !== true,
    'sponsor_confidential_boundary_unattested',
  );
}

function evaluateReview(input, reasons) {
  const review = input?.review;
  addReason(reasons, !hasText(review?.qualityReviewerDid), 'quality_reviewer_absent');
  addReason(reasons, review?.humanReviewed !== true, 'human_review_required');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, !REVIEW_DECISIONS.has(review?.reviewDecision), 'review_decision_invalid');
  addReason(reasons, review?.reviewDecision === 'hold_for_intake_gap', 'intake_review_held');
  addReason(reasons, review?.reviewDecision === 'reject_intake', 'intake_review_rejected');
  addReason(reasons, !isDigest(review?.reviewDecisionHash), 'review_decision_hash_invalid');
}

function evaluateDecisionForum(forum, reasons) {
  addReason(reasons, forum?.required !== true, 'decision_forum_required_flag_absent');
  addReason(reasons, forum?.verified !== true, 'decision_forum_unverified');
  addReason(reasons, forum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, forum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, forum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, forum?.openChallenge === true, 'challenge_open');
  addReason(reasons, !hasText(forum?.decisionId), 'decision_forum_id_absent');
  addReason(reasons, !hasText(forum?.workflowReceiptId), 'decision_forum_receipt_absent');
}

function notApplicableTypes(coverageByType) {
  return REQUIRED_ARTIFACT_TYPES.filter((artifactType) => coverageByType.get(artifactType)?.status === 'not_applicable').sort();
}

function coverageBasisPoints(coverageByType) {
  const covered = REQUIRED_ARTIFACT_TYPES.filter((artifactType) => {
    const status = coverageByType.get(artifactType)?.status;
    return status === 'received' || status === 'not_applicable';
  });
  return basisPoints(covered.length, REQUIRED_ARTIFACT_TYPES.length);
}

function buildProtocolIntake(input, reasons, normalizedCoverage, normalizedArtifacts, receivedArtifactTypes, coverageByType) {
  const finalReasons = uniqueReasons(reasons);
  const failClosed = finalReasons.length > 0;
  const coverageBps = coverageBasisPoints(coverageByType);
  const readinessStatus = failClosed ? 'blocked' : 'ready_for_feasibility';
  const escalationRoles = sortedTextList(input?.review?.requiredEscalationRoles);
  const packet = {
    schema: INTAKE_SCHEMA,
    aiFinalAuthority: input?.review?.aiFinalAuthority === true,
    artifactCoverage: normalizedCoverage,
    artifacts: normalizedArtifacts,
    classificationRefs: sortedTextList(input?.confidentialityProfile?.classificationRefs),
    coverageBasisPoints: coverageBps,
    exochainProductionClaim: false,
    intakeReady: !failClosed,
    notApplicableArtifactTypes: notApplicableTypes(coverageByType),
    packetId: sha256Hex({
      packetRef: input?.intakePacket?.packetRef ?? null,
      protocolRef: input?.intakePacket?.protocolRef ?? null,
      receivedArtifactTypes,
      schema: INTAKE_SCHEMA,
      tenantId: input?.tenantId ?? null,
    }),
    packetRef: input?.intakePacket?.packetRef ?? null,
    protocolRef: input?.intakePacket?.protocolRef ?? null,
    readinessStatus,
    receivedArtifactTypes,
    requiredEscalationRoles: escalationRoles,
    siteRef: input?.intakePacket?.siteRef ?? null,
    sponsorRef: input?.intakePacket?.sponsorRef ?? null,
    supportedArtifactTypes: [...REQUIRED_ARTIFACT_TYPES],
    trustState: 'inactive',
  };
  return packet;
}

function buildReceipt(input, protocolIntake) {
  if (!isDigest(input?.custodyDigest)) {
    return null;
  }
  return createEvidenceReceipt({
    actorDid: input?.actor?.did ?? 'unknown',
    artifactHash: sha256Hex(protocolIntake),
    artifactType: 'protocol_intake_packet',
    artifactVersion: protocolIntake.packetRef ?? 'unknown',
    classification: 'sponsor_confidential_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input?.intakePacket?.reviewedAtHlc ?? input?.intakePacket?.classifiedAtHlc ?? input?.intakePacket?.receivedAtHlc ?? {
      logical: 0,
      physicalMs: 0,
    },
    sensitivityTags: ['metadata_only', 'sponsor_confidential', 'no_phi_payload'],
    sourceSystem: input?.intakePacket?.sourceSystemRef ?? 'cybermedica-protocol-intake',
    tenantId: input?.tenantId ?? 'unknown',
  });
}

export function evaluateProtocolIntake(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluatePacket(input?.intakePacket, reasons);
  const { coverageByType, normalizedCoverage } = normalizeCoverage(input, reasons);
  const { normalizedArtifacts, receivedArtifactTypes } = normalizeArtifacts(
    input,
    coverageByType,
    input?.intakePacket,
    reasons,
  );
  evaluateConfidentialityProfile(input?.confidentialityProfile, reasons);
  evaluateReview(input, reasons);
  evaluateDecisionForum(input?.decisionForum, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const protocolIntake = buildProtocolIntake(
    input,
    reasons,
    normalizedCoverage,
    normalizedArtifacts,
    receivedArtifactTypes,
    coverageByType,
  );

  return {
    schema: DECISION_SCHEMA,
    decision: protocolIntake.intakeReady ? 'permitted' : 'denied',
    failClosed: !protocolIntake.intakeReady,
    protocolIntake,
    reasons: uniqueReasons(reasons),
    receipt: buildReceipt(input, protocolIntake),
  };
}
