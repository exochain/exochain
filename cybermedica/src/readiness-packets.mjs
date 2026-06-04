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
const PACKET_SET_SCHEMA = 'cybermedica.readiness_packet_set.v1';
const REQUIRED_PERMISSION = 'readiness_packet_publish';
const REQUIRED_PACKET_AUDIENCES = Object.freeze(['cro_operations', 'sponsor_facing']);
const PACKET_STATUSES = new Set(['ready']);
const DECISION_STATUSES = new Set(['approved']);
const HUMAN_REVIEW_STATUSES = new Set(['approved']);

const AUDIENCE_RECIPIENT_CLASS = Object.freeze({
  cro_operations: 'cro',
  sponsor_facing: 'sponsor',
});

const AUDIENCE_ROLE_REFS = Object.freeze({
  cro_operations: Object.freeze(['cro_portfolio_manager']),
  sponsor_facing: Object.freeze(['sponsor_viewer']),
});

const REQUIRED_PACKET_SECTIONS = Object.freeze({
  cro_operations: Object.freeze([
    'findings_capa_tracking',
    'monitoring_plan',
    'portfolio_readiness',
    'provider_coordination',
    'sponsor_reporting',
    'startup_status',
    'systemic_risk',
    'training_quality_trends',
  ]),
  sponsor_facing: Object.freeze([
    'access_limitations',
    'authorized_exports',
    'capa_status',
    'launch_gate',
    'open_findings',
    'provider_readiness',
    'readiness_status',
    'risk_summary',
  ]),
});

const REQUIRED_PACKET_EVIDENCE_HASHES = Object.freeze([
  'accessLimitationPolicyHash',
  'authorizedExportManifestHash',
  'capaStatusHash',
  'monitoringPlanHash',
  'openFindingsHash',
  'portfolioComparisonHash',
  'riskSummaryHash',
  'sponsorReportControlHash',
  'systemicRiskHash',
  'trainingQualityTrendHash',
]);

const RAW_PACKET_FIELDS = new Set([
  'analysisnarrative',
  'clinicalnarrative',
  'crooperationspacketbody',
  'dashboardpayload',
  'exportpayload',
  'freetext',
  'freetextnote',
  'participantlisting',
  'packetbody',
  'packetcontent',
  'packetpayload',
  'rawcrooperationspacket',
  'rawpacket',
  'rawpacketbody',
  'rawpacketcontent',
  'rawpacketpayload',
  'rawreadinesspacket',
  'rawsponsorpacket',
  'rawsponsorreadinesspacket',
  'rawsource',
  'rawsourcedata',
  'sourcecontent',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'sourcepayload',
  'sponsorpacketbody',
]);

const SECRET_PACKET_FIELDS = new Set([
  'accesstoken',
  'apikey',
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
  'sessionsecret',
  'signaturesecret',
  'signingkey',
  'token',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
}

function isBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 10_000;
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

function assertNoRawPacketContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawPacketContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_PACKET_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw readiness packet content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_PACKET_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`readiness packet secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawPacketContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawPacketContent(input ?? {});
  canonicalize(input ?? {});
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function basisPoints(numerator, denominator) {
  if (denominator === 0) {
    return 0;
  }
  return Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
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

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function audienceSort(left, right) {
  return String(left.audience).localeCompare(String(right.audience));
}

function byAudience(packets) {
  const map = new Map();
  for (const packet of Array.isArray(packets) ? packets : []) {
    if (hasText(packet?.audience) && !map.has(packet.audience)) {
      map.set(packet.audience, packet);
    }
  }
  return map;
}

function duplicateAudiences(packets) {
  const seen = new Set();
  const duplicates = new Set();
  for (const packet of Array.isArray(packets) ? packets : []) {
    if (!hasText(packet?.audience)) {
      continue;
    }
    if (seen.has(packet.audience)) {
      duplicates.add(packet.audience);
    }
    seen.add(packet.audience);
  }
  return [...duplicates].sort();
}

function includesAny(allowedValues, actualValues) {
  const actualSet = new Set(actualValues);
  return allowedValues.some((value) => actualSet.has(value));
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(input?.studyRef), 'study_ref_absent');
  addReason(reasons, !hasText(input?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_packet_publisher_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'readiness_packet_publish_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateLaunchGate(launchGate, reasons) {
  addReason(reasons, launchGate?.decision !== 'permitted' || launchGate?.enrollmentAuthorizationActive !== true, 'launch_gate_not_permitted');
  addReason(reasons, !hasText(launchGate?.receiptId), 'launch_gate_receipt_absent');
  addReason(reasons, !isDigest(launchGate?.gateHash), 'launch_gate_hash_invalid');
  addReason(reasons, hlcTuple(launchGate?.reviewedAtHlc) === null, 'launch_gate_review_time_invalid');
  addReason(reasons, launchGate?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function evaluateProviderReadiness(providerReadiness, reasons) {
  addReason(reasons, providerReadiness?.status !== 'ready', 'provider_readiness_not_ready');
  addReason(reasons, !isDigest(providerReadiness?.readinessHash), 'provider_readiness_hash_invalid');
  addReason(reasons, !hasText(providerReadiness?.receiptId), 'provider_readiness_receipt_absent');
  addReason(
    reasons,
    !isBasisPoints(providerReadiness?.providerReadinessBasisPoints) || providerReadiness.providerReadinessBasisPoints !== 10_000,
    'provider_readiness_incomplete',
  );
  addReason(reasons, hlcTuple(providerReadiness?.reviewedAtHlc) === null, 'provider_readiness_review_time_invalid');
  addReason(reasons, providerReadiness?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function evaluateReadinessDecision(readinessDecision, reasons) {
  addReason(reasons, !hasText(readinessDecision?.decisionRecordRef), 'readiness_decision_record_absent');
  addReason(reasons, !isDigest(readinessDecision?.decisionHash), 'readiness_decision_hash_invalid');
  addReason(reasons, !hasText(readinessDecision?.decisionForumMatterRef), 'decision_forum_matter_absent');
  addReason(reasons, !DECISION_STATUSES.has(readinessDecision?.status), 'readiness_decision_not_approved');
  addReason(reasons, readinessDecision?.humanGateVerified !== true, 'human_gate_unverified');
  addReason(reasons, readinessDecision?.quorumMet !== true, 'quorum_not_met');
  addReason(reasons, readinessDecision?.openChallenge === true, 'challenge_open');
  addReason(reasons, hlcTuple(readinessDecision?.reviewedAtHlc) === null, 'readiness_decision_review_time_invalid');
  addReason(reasons, readinessDecision?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
}

function evaluatePacketSet(packetSet, reasons) {
  addReason(reasons, !hasText(packetSet?.packetSetRef), 'packet_set_ref_absent');
  addReason(reasons, hlcTuple(packetSet?.generatedAtHlc) === null, 'packet_set_generated_time_invalid');
  addReason(reasons, packetSet?.metadataOnly !== true, 'packet_set_metadata_boundary_invalid');
  addReason(reasons, packetSet?.protectedContentExcluded !== true, 'packet_set_protected_boundary_invalid');
  addReason(reasons, packetSet?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function evaluatePacketEvidence(packetEvidence, reasons) {
  for (const field of REQUIRED_PACKET_EVIDENCE_HASHES) {
    addReason(reasons, !isDigest(packetEvidence?.[field]), `packet_evidence_hash_invalid:${field}`);
  }
  addReason(reasons, !isDigest(packetEvidence?.custodyDigest), 'packet_evidence_custody_digest_invalid');
}

function evaluateAudiencePacket(packet, readinessDecision, reasons) {
  const audience = hasText(packet?.audience) ? packet.audience : 'unknown';
  const sections = sortedTextList(packet?.sections);
  const expectedSections = REQUIRED_PACKET_SECTIONS[audience] ?? [];
  const authorizedRoleRefs = sortedTextList(packet?.authorizedRoleRefs);

  addReason(reasons, !REQUIRED_PACKET_AUDIENCES.includes(audience), `packet_audience_unsupported:${audience}`);
  addReason(reasons, !hasText(packet?.packetRef), `packet_ref_absent:${audience}`);
  addReason(reasons, !PACKET_STATUSES.has(packet?.status), `packet_not_ready:${audience}`);
  addReason(reasons, packet?.recipientClass !== AUDIENCE_RECIPIENT_CLASS[audience], `packet_recipient_class_invalid:${audience}`);
  addReason(
    reasons,
    !includesAny(AUDIENCE_ROLE_REFS[audience] ?? [], authorizedRoleRefs),
    `packet_authorized_roles_absent:${audience}`,
  );
  for (const section of expectedSections) {
    addReason(reasons, !sections.includes(section), `packet_section_missing:${audience}:${section}`);
  }
  for (const section of sections) {
    addReason(reasons, !expectedSections.includes(section), `packet_section_unsupported:${audience}:${section}`);
  }
  addReason(reasons, !isDigest(packet?.packetHash), `packet_hash_invalid:${audience}`);
  addReason(reasons, !isDigest(packet?.accessPolicyHash), `packet_access_policy_hash_invalid:${audience}`);
  addReason(reasons, !isDigest(packet?.disclosurePolicyHash), `packet_disclosure_policy_hash_invalid:${audience}`);
  addReason(reasons, !hasText(packet?.exportControlReceiptId), `packet_export_control_receipt_absent:${audience}`);
  addReason(reasons, hlcTuple(packet?.generatedAtHlc) === null, `packet_generated_time_invalid:${audience}`);
  addReason(
    reasons,
    hlcBefore(packet?.generatedAtHlc, readinessDecision?.reviewedAtHlc),
    `packet_generated_before_readiness_decision:${audience}`,
  );
  addReason(reasons, packet?.metadataOnly !== true, `packet_metadata_boundary_invalid:${audience}`);
  addReason(reasons, packet?.suppressedProtectedContent !== true, `packet_protected_content_suppression_absent:${audience}`);
  addReason(reasons, packet?.productionTrustClaim === true, 'production_trust_claim_forbidden');

  return {
    audience,
    accessPolicyHash: isDigest(packet?.accessPolicyHash) ? packet.accessPolicyHash : null,
    authorizedRoleRefs,
    disclosurePolicyHash: isDigest(packet?.disclosurePolicyHash) ? packet.disclosurePolicyHash : null,
    exportControlReceiptId: hasText(packet?.exportControlReceiptId) ? packet.exportControlReceiptId : null,
    generatedAtHlc: packet?.generatedAtHlc ?? null,
    metadataOnly: packet?.metadataOnly === true,
    packetHash: isDigest(packet?.packetHash) ? packet.packetHash : null,
    packetRef: hasText(packet?.packetRef) ? packet.packetRef : null,
    recipientClass: hasText(packet?.recipientClass) ? packet.recipientClass : null,
    sections,
    status: PACKET_STATUSES.has(packet?.status) ? packet.status : 'blocked',
    suppressedProtectedContent: packet?.suppressedProtectedContent === true,
  };
}

function evaluateAudiencePackets(input, reasons) {
  const packets = Array.isArray(input?.audiencePackets) ? [...input.audiencePackets].sort(audienceSort) : [];
  addReason(reasons, packets.length === 0, 'readiness_packets_absent');
  const packetMap = byAudience(packets);
  for (const audience of REQUIRED_PACKET_AUDIENCES) {
    addReason(reasons, !packetMap.has(audience), `packet_audience_missing:${audience}`);
  }
  for (const duplicate of duplicateAudiences(packets)) {
    addReason(reasons, true, `packet_audience_duplicate:${duplicate}`);
  }
  return packets.map((packet) => evaluateAudiencePacket(packet, input?.readinessDecision, reasons));
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, !HUMAN_REVIEW_STATUSES.has(review?.status), 'human_review_not_approved');
  addReason(reasons, !isDigest(review?.reviewHash), 'human_review_hash_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, input?.packetSet?.generatedAtHlc), 'human_review_before_packet_set_generation');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
}

function requiredPacketReadyCount(packetSummaries) {
  return new Set(
    packetSummaries
      .filter((packet) => REQUIRED_PACKET_AUDIENCES.includes(packet.audience) && packet.status === 'ready')
      .map((packet) => packet.audience),
  ).size;
}

function buildPacketSet(input, packetSummaries, reasons) {
  const coveredAudiences = sortedTextList(packetSummaries.map((packet) => packet.audience)).filter((audience) =>
    REQUIRED_PACKET_AUDIENCES.includes(audience),
  );
  const packetReadinessBasisPoints = basisPoints(requiredPacketReadyCount(packetSummaries), REQUIRED_PACKET_AUDIENCES.length);
  const packetSetCore = {
    audiencePackets: packetSummaries,
    coveredAudiences,
    launchGateHash: input?.launchGate?.gateHash ?? null,
    packetEvidence: input?.packetEvidence ?? null,
    packetSetRef: input?.packetSet?.packetSetRef ?? null,
    protocolRef: input?.protocolRef ?? null,
    providerReadinessHash: input?.providerReadiness?.readinessHash ?? null,
    readinessDecisionHash: input?.readinessDecision?.decisionHash ?? null,
    requiredAudiences: REQUIRED_PACKET_AUDIENCES,
    siteRef: input?.siteRef ?? null,
    studyRef: input?.studyRef ?? null,
    tenantId: input?.tenantId ?? null,
  };
  const packetSetHash = sha256Hex(packetSetCore);
  const denied = reasons.length > 0;

  return {
    schema: PACKET_SET_SCHEMA,
    packetSetRef: hasText(input?.packetSet?.packetSetRef) ? input.packetSet.packetSetRef : null,
    tenantId: hasText(input?.tenantId) ? input.tenantId : null,
    protocolRef: hasText(input?.protocolRef) ? input.protocolRef : null,
    studyRef: hasText(input?.studyRef) ? input.studyRef : null,
    siteRef: hasText(input?.siteRef) ? input.siteRef : null,
    status: denied ? 'blocked' : 'ready',
    trustState: 'inactive',
    exochainProductionClaim: false,
    requiredAudiences: REQUIRED_PACKET_AUDIENCES,
    coveredAudiences,
    packetReadinessBasisPoints,
    packetCount: packetSummaries.length,
    packets: packetSummaries,
    launchGateReceiptId: hasText(input?.launchGate?.receiptId) ? input.launchGate.receiptId : null,
    providerReadinessReceiptId: hasText(input?.providerReadiness?.receiptId) ? input.providerReadiness.receiptId : null,
    readinessDecisionRecordRef: hasText(input?.readinessDecision?.decisionRecordRef)
      ? input.readinessDecision.decisionRecordRef
      : null,
    decisionForumMatterRef: hasText(input?.readinessDecision?.decisionForumMatterRef)
      ? input.readinessDecision.decisionForumMatterRef
      : null,
    generatedAtHlc: input?.packetSet?.generatedAtHlc ?? null,
    packetSetHash,
  };
}

function buildReceipt(input, packetSet) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: packetSet.packetSetHash,
    artifactType: 'readiness_packet_set',
    artifactVersion: `${packetSet.protocolRef}:${packetSet.packetSetRef}`,
    classification: 'metadata-only readiness packet set',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: packetSet.generatedAtHlc,
    sensitivityTags: ['clinical_operations', 'metadata_only', 'readiness_packets', 'sponsor_cro_visibility'],
    sourceSystem: 'cybermedica-readiness-packets',
    tenantId: input.tenantId,
  });
}

export function evaluateReadinessPackets(input) {
  assertMetadataOnly(input);
  const reasons = [];

  evaluateTenantActorAuthority(input, reasons);
  evaluateLaunchGate(input?.launchGate, reasons);
  evaluateProviderReadiness(input?.providerReadiness, reasons);
  evaluateReadinessDecision(input?.readinessDecision, reasons);
  evaluatePacketSet(input?.packetSet, reasons);
  evaluatePacketEvidence(input?.packetEvidence, reasons);
  evaluateHumanReview(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const packetSummaries = evaluateAudiencePackets(input, reasons);
  const finalReasons = uniqueReasons(reasons);
  const packetSet = buildPacketSet(input, packetSummaries, finalReasons);
  const denied = finalReasons.length > 0;

  if (denied) {
    return {
      schema: 'cybermedica.readiness_packet_set_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: finalReasons,
      packetSet,
      receipt: null,
    };
  }

  return {
    schema: 'cybermedica.readiness_packet_set_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    packetSet,
    receipt: buildReceipt(input, packetSet),
  };
}
