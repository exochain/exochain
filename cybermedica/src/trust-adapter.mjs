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

export const TrustState = Object.freeze({
  INACTIVE: 'inactive',
  PENDING: 'pending',
  DENIED: 'denied',
  DEGRADED: 'degraded',
  VERIFIED: 'verified',
});

const REQUIRED_ROOT_CERTIFIERS = 13;
const REQUIRED_DKG_PARTICIPANTS = 13;
const REQUIRED_THRESHOLD_SIGNATURE = '7-of-13';
const HEX_64 = /^[0-9a-f]{64}$/u;
const EXOCHAIN_GATEWAY_SOURCE = 'exochain_gateway';
const EXOCHAIN_NODE_RECEIPT_SOURCE = 'exochain_node_receipt_store';
const EXOCHAIN_DECISION_FORUM_SOURCE = 'exochain_decision_forum';
const EXOCHAIN_DECISION_FORUM_RECEIPT_SOURCE = 'exochain_decision_forum_receipts';
const DISCLOSURE_FIELD_NAMES = new Set([
  'accesstoken',
  'address',
  'apikey',
  'authorizationheader',
  'authtoken',
  'bearertoken',
  'bootstraptoken',
  'clientsecret',
  'credential',
  'credentialsecret',
  'dateofbirth',
  'dob',
  'email',
  'freetextnote',
  'medicalrecordnumber',
  'mrn',
  'participantname',
  'patientname',
  'password',
  'phone',
  'privatekey',
  'rawcontent',
  'rawphi',
  'rawpii',
  'railwaytoken',
  'refreshtoken',
  'rootkey',
  'rootsigningkey',
  'secret',
  'sessionsecret',
  'signaturesecret',
  'signingkey',
  'socialsecuritynumber',
  'sponsorconfidential',
  'sponsorconfidentialcontent',
  'sourcedocumentbody',
  'ssn',
  'token',
  'privileged',
  'privilegedlegalmaterial',
]);
const DISCLOSURE_FIELD_NAME_PATTERNS = [
  /^(?:rawphi|rawpii|rawcontent)(?:attachment|body|content|material|payload|text|value)?$/u,
  /^(?:sponsorconfidential|privileged)(?:attachment|body|content|material|notes?|payload|text|value)$/u,
  /^(?:patientname|participantname|medicalrecordnumber|socialsecuritynumber|dateofbirth)(?:attachment|body|content|payload|text|value)?$/u,
  /^(?:accesstoken|authtoken|bearertoken|bootstraptoken|railwaytoken|refreshtoken|sessionsecret|sessiontoken)(?:payload|text|value)?$/u,
  /^(?:apikey|authorizationheader|clientsecret|credentialsecret|password|privatekey|rootkey|rootsigningkey|signaturesecret|signingkey)(?:payload|text|value)?$/u,
];
const DISCLOSURE_TEXT_PATTERNS = [
  /\b\d{3}-\d{2}-\d{4}\b/u,
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/iu,
  /\b(?:patient|participant)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/iu,
  /\b(?:mrn|medical record)\s*[:#]\s*[A-Z0-9-]+\b/iu,
  /\bauthorization\s*:\s*bearer\s+\S+/iu,
  /\bapi[_-]?key\s*[:=]\s*\S+/iu,
  /\bclient[_-]?secret\s*[:=]\s*\S+/iu,
  /\b(?:access|auth|bootstrap|railway|refresh|session)[_-]?token\s*[:=]\s*\S+/iu,
  /\b(?:private|root|signing)[_-]?key\s*[:=]\s*\S+/iu,
  /\bpassword\s*[:=]\s*\S+/iu,
];
const OBSERVABILITY_PAYLOAD_FIELDS = ['debugPayload', 'healthPayload', 'logPayload', 'telemetryPayload'];
const GATEWAY_PAYLOAD_FIELDS = ['actionPayload', 'adjudicationPayload', 'payload', 'requestPayload'];
const RECEIPT_PAYLOAD_FIELDS = ['dagPayload', 'nodePayload', 'payload', 'provenancePayload', 'receiptPayload'];
const DECISION_FORUM_PAYLOAD_FIELDS = [
  'decisionPayload',
  'evidencePayload',
  'payload',
  'provenancePayload',
  'receiptPayload',
  'rationalePayload',
  'transitionPayload',
  'votePayload',
];

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function fieldNameDisclosesPayload(fieldName) {
  const normalized = normalizeFieldName(fieldName);
  return DISCLOSURE_FIELD_NAMES.has(normalized) || DISCLOSURE_FIELD_NAME_PATTERNS.some((pattern) => pattern.test(normalized));
}

function containsDisclosedPayload(value) {
  if (value === null || value === undefined) {
    return false;
  }
  if (typeof value === 'string') {
    return DISCLOSURE_TEXT_PATTERNS.some((pattern) => pattern.test(value));
  }
  if (Array.isArray(value)) {
    return value.some((item) => containsDisclosedPayload(item));
  }
  if (typeof value === 'object') {
    return Object.entries(value).some(([key, nested]) => {
      return fieldNameDisclosesPayload(key) || containsDisclosedPayload(nested);
    });
  }
  return false;
}

function isVerified(value) {
  return value !== null && typeof value === 'object' && value.verified === true;
}

function sourceBoundaryBlocks(value, options) {
  const blocks = [];
  if (value?.[options.sourceField] !== options.expectedSource) {
    blocks.push(options.sourceBlock);
  }
  blocks.push(...replayBoundaryBlocks(value, options.replayPrefix));
  return blocks;
}

function replayBoundaryBlocks(value, replayPrefix) {
  const blocks = [];
  if (value?.locallySimulated === true || value?.simulated === true) {
    blocks.push(`${replayPrefix}_local_simulation_forbidden`);
  }
  if (value?.cacheHit === true || value?.cachedOutcome === true || value?.cachedReceipt === true) {
    blocks.push(`${replayPrefix}_cached_outcome_forbidden`);
  }
  if (value?.overrideApplied === true || value?.overrideUsed === true) {
    blocks.push(`${replayPrefix}_override_forbidden`);
  }
  return blocks;
}

function observabilityPayloadBlocks(value, blockName) {
  if (OBSERVABILITY_PAYLOAD_FIELDS.some((field) => containsDisclosedPayload(value?.[field]))) {
    return [blockName];
  }
  return [];
}

function dependencyPayloadBlocks(entries) {
  return entries.flatMap(([value, blockName]) => (containsDisclosedPayload(value) ? [blockName] : []));
}

function hasClassifiedPayloadDisclosure(blocks) {
  return blocks.some((block) => block.includes('payload_disclosure'));
}

function responsePayloadBlocks(value, existingBlocks, blockName) {
  if (!hasClassifiedPayloadDisclosure(existingBlocks) && containsDisclosedPayload(value)) {
    return [blockName];
  }
  return [];
}

function activationEvidencePayloadBlocks(activation) {
  return dependencyPayloadBlocks([
    [activation.rootBundle, 'root_bundle_activation_payload_disclosure'],
    [activation.gatewayAdapter, 'gateway_adapter_activation_payload_disclosure'],
    [activation.receiptPath, 'receipt_path_activation_payload_disclosure'],
    [activation.privacyBoundary, 'privacy_boundary_activation_payload_disclosure'],
    [activation.decisionForum, 'decision_forum_activation_payload_disclosure'],
  ]);
}

function activationReplayBoundaryBlocks(activation) {
  return [
    ...replayBoundaryBlocks(activation.rootBundle, 'root_bundle'),
    ...replayBoundaryBlocks(activation.gatewayAdapter, 'gateway_adapter'),
    ...replayBoundaryBlocks(activation.receiptPath, 'receipt_path'),
    ...replayBoundaryBlocks(activation.privacyBoundary, 'privacy_boundary'),
    ...replayBoundaryBlocks(activation.decisionForum, 'decision_forum'),
  ];
}

function gatewayPayloadBlocks(value) {
  if (GATEWAY_PAYLOAD_FIELDS.some((field) => containsDisclosedPayload(value?.[field]))) {
    return ['gateway_payload_disclosure'];
  }
  return [];
}

function receiptPayloadBlocks(value) {
  if (RECEIPT_PAYLOAD_FIELDS.some((field) => containsDisclosedPayload(value?.[field]))) {
    return ['receipt_payload_disclosure'];
  }
  return [];
}

function decisionForumPayloadBlocks(value) {
  if (DECISION_FORUM_PAYLOAD_FIELDS.some((field) => containsDisclosedPayload(value?.[field]))) {
    return ['decision_forum_payload_disclosure'];
  }
  return [];
}

function rootBundleBlocks(rootBundle) {
  if (rootBundle === null || rootBundle === undefined) {
    return [
      'root_bundle_absent',
      'root_certifier_roster_absent',
      'root_dkg_transcript_absent',
      'root_threshold_signature_absent',
      'root_verifier_absent',
    ];
  }

  const blocks = [];
  if (rootBundle.verified !== true) {
    blocks.push(rootBundle.status === 'pending' ? 'root_verifier_pending' : 'root_bundle_unverified');
  }
  if (rootBundle.certifierCount !== REQUIRED_ROOT_CERTIFIERS) {
    blocks.push('root_certifier_roster_absent');
  }
  if (rootBundle.dkgParticipantCount !== REQUIRED_DKG_PARTICIPANTS) {
    blocks.push('root_dkg_transcript_absent');
  }
  if (rootBundle.thresholdSignature !== REQUIRED_THRESHOLD_SIGNATURE) {
    blocks.push('root_threshold_signature_absent');
  }
  if (!hasText(rootBundle.verifierReceiptId)) {
    blocks.push('root_verifier_absent');
  }
  return blocks;
}

function dependencyBlock(value, blockName) {
  return isVerified(value) ? [] : [blockName];
}

function statusIs(value, expectedStatus) {
  return value !== null && typeof value === 'object' && value.status === expectedStatus;
}

function gatewayTimeout(response) {
  return response?.status === 'timeout' || response?.timeout === true;
}

function gatewayReceiptBlocks(provenance, expectedActionHash) {
  if (provenance === null || provenance === undefined) {
    return ['gateway_receipt_absent'];
  }

  const blocks = sourceBoundaryBlocks(provenance, {
    sourceField: 'receiptSource',
    expectedSource: EXOCHAIN_NODE_RECEIPT_SOURCE,
    sourceBlock: 'gateway_receipt_source_unverified',
    replayPrefix: 'gateway_receipt',
  });
  blocks.push(
    ...nestedReceiptStatusBlocks(provenance, {
      timeoutBlock: 'gateway_receipt_timeout',
      statusBlock: 'gateway_receipt_status_unverified',
    }),
  );
  if (!hasText(provenance.receiptId)) {
    blocks.push('gateway_receipt_id_absent');
  }
  if (!hasText(provenance.actionHash) || !HEX_64.test(provenance.actionHash)) {
    blocks.push('gateway_receipt_action_hash_invalid');
  }
  if (!hasText(expectedActionHash) || !HEX_64.test(expectedActionHash)) {
    blocks.push('expected_action_hash_invalid');
  } else if (provenance.actionHash !== expectedActionHash) {
    blocks.push('gateway_receipt_action_hash_mismatch');
  }
  if (!hasText(provenance.signature)) {
    blocks.push('gateway_receipt_signature_absent');
  }
  if (containsDisclosedPayload(provenance.anchorPayload)) {
    blocks.push('gateway_payload_disclosure');
  }
  return blocks;
}

function decisionForumTimeout(response) {
  return response?.status === 'timeout' || response?.timeout === true;
}

function receiptTimeout(response) {
  return response?.status === 'timeout' || response?.timeout === true;
}

function nestedReceiptStatusBlocks(provenance, options) {
  if (receiptTimeout(provenance)) {
    return [options.timeoutBlock];
  }
  if (hasText(provenance?.status) && provenance.status !== 'ok') {
    return [options.statusBlock];
  }
  return [];
}

function actorIsAi(response) {
  return (
    response?.actorKind === 'ai_agent' ||
    response?.actor?.kind === 'ai_agent' ||
    response?.humanGate?.actorKind === 'ai_agent'
  );
}

function decisionForumReceiptBlocks(provenance, expectedDecisionHash) {
  if (provenance === null || provenance === undefined) {
    return ['decision_forum_receipt_absent'];
  }

  const blocks = sourceBoundaryBlocks(provenance, {
    sourceField: 'receiptSource',
    expectedSource: EXOCHAIN_DECISION_FORUM_RECEIPT_SOURCE,
    sourceBlock: 'decision_forum_receipt_source_unverified',
    replayPrefix: 'decision_forum_receipt',
  });
  blocks.push(
    ...nestedReceiptStatusBlocks(provenance, {
      timeoutBlock: 'decision_forum_receipt_timeout',
      statusBlock: 'decision_forum_receipt_status_unverified',
    }),
  );
  if (!hasText(provenance.receiptId)) {
    blocks.push('decision_forum_receipt_id_absent');
  }
  if (!hasText(provenance.decisionHash) || !HEX_64.test(provenance.decisionHash)) {
    blocks.push('decision_forum_receipt_hash_invalid');
  }
  if (!hasText(expectedDecisionHash) || !HEX_64.test(expectedDecisionHash)) {
    blocks.push('expected_decision_hash_invalid');
  } else if (provenance.decisionHash !== expectedDecisionHash) {
    blocks.push('decision_forum_receipt_hash_mismatch');
  }
  if (!hasText(provenance.signature)) {
    blocks.push('decision_forum_receipt_signature_absent');
  }
  if (containsDisclosedPayload(provenance.anchorPayload)) {
    blocks.push('decision_forum_payload_disclosure');
  }
  return blocks;
}

function classifyFailureState(rootBundle, blocks) {
  if (blocks.length === 0) {
    return TrustState.VERIFIED;
  }
  if (rootBundle === null || rootBundle === undefined) {
    return TrustState.INACTIVE;
  }
  if (rootBundle.status === 'pending' && blocks.length === 1 && blocks[0] === 'root_verifier_pending') {
    return TrustState.PENDING;
  }
  return TrustState.DENIED;
}

export function evaluateProductionTrustActivation(input) {
  const activation = input ?? {};
  const blockedBy = [
    ...rootBundleBlocks(activation.rootBundle),
    ...dependencyBlock(activation.gatewayAdapter, 'gateway_adapter_unverified'),
    ...dependencyBlock(activation.receiptPath, 'receipt_path_unverified'),
    ...dependencyBlock(activation.privacyBoundary, 'privacy_boundary_unverified'),
    ...dependencyBlock(activation.decisionForum, 'decision_forum_unverified'),
    ...activationReplayBoundaryBlocks(activation),
    ...activationEvidencePayloadBlocks(activation),
  ];
  const state = classifyFailureState(activation.rootBundle, blockedBy);
  const allowed = state === TrustState.VERIFIED;

  return {
    schema: 'cybermedica.production_trust_activation.v1',
    claimId: hasText(activation.claimId) ? activation.claimId : 'unclassified',
    allowed,
    state,
    failClosed: !allowed,
    blockedBy,
    exochainProductionClaim: allowed,
    displayLabel: allowed ? 'Verified Exochain receipt path' : `Trust fabric ${state}`,
    claimLanguage: allowed
      ? 'Exochain receipt path verified for this CyberMedica action.'
      : 'Exochain production trust is not active for this CyberMedica action.',
  };
}

export function evaluateDecisionForumTransitionResponse(response, options = {}) {
  if (response === null || response === undefined) {
    return {
      schema: 'cybermedica.decision_forum_transition_response.v1',
      allowed: false,
      state: TrustState.DEGRADED,
      failClosed: true,
      blockedBy: ['decision_forum_service_unavailable'],
      decisionId: null,
      receiptId: null,
    };
  }

  if (decisionForumTimeout(response)) {
    return {
      schema: 'cybermedica.decision_forum_transition_response.v1',
      allowed: false,
      state: TrustState.DEGRADED,
      failClosed: true,
      blockedBy: ['decision_forum_timeout'],
      decisionId: hasText(response.decisionId) ? response.decisionId : null,
      receiptId: null,
    };
  }

  const blockedBy = sourceBoundaryBlocks(response, {
    sourceField: 'enforcementSource',
    expectedSource: EXOCHAIN_DECISION_FORUM_SOURCE,
    sourceBlock: 'decision_forum_enforcement_source_unverified',
    replayPrefix: 'decision_forum',
  });
  const expectedDecisionState = hasText(options.expectedDecisionState) ? options.expectedDecisionState : 'approved';

  if (response.status !== 'ok') {
    blockedBy.push('decision_forum_status_unverified');
  }
  if (response.transitionPath !== 'adjudicated') {
    blockedBy.push('decision_forum_raw_transition_forbidden');
  }
  if (response.decisionState !== expectedDecisionState) {
    blockedBy.push('decision_forum_state_unverified');
  }
  if (hasText(options.expectedDecisionId) && response.decisionId !== options.expectedDecisionId) {
    blockedBy.push('decision_forum_decision_mismatch');
  }
  if (hasText(options.expectedAction) && response.action !== options.expectedAction) {
    blockedBy.push('decision_forum_action_mismatch');
  }
  if (hasText(options.expectedActorDid) && response.actorDid !== options.expectedActorDid) {
    blockedBy.push('decision_forum_actor_mismatch');
  }
  if (hasText(options.expectedTenantId) && response.tenantId !== options.expectedTenantId) {
    blockedBy.push('decision_forum_tenant_mismatch');
  }
  if (options.requiresHumanGate !== false && (!isVerified(response.humanGate) || !statusIs(response.humanGate, 'verified'))) {
    blockedBy.push('human_gate_unverified');
  }
  blockedBy.push(...replayBoundaryBlocks(response.humanGate, 'human_gate'));
  if (actorIsAi(response)) {
    blockedBy.push('ai_final_authority_forbidden');
  }
  if (options.requiresQuorum !== false && (!isVerified(response.quorum) || !statusIs(response.quorum, 'met'))) {
    blockedBy.push('quorum_unverified');
  }
  blockedBy.push(...replayBoundaryBlocks(response.quorum, 'quorum'));
  if (options.requiresTnc !== false && (!isVerified(response.tnc) || !statusIs(response.tnc, 'passed'))) {
    blockedBy.push('tnc_unverified');
  }
  blockedBy.push(...replayBoundaryBlocks(response.tnc, 'tnc'));
  if (!isVerified(response.authority) || !statusIs(response.authority, 'valid')) {
    blockedBy.push('authority_chain_unverified');
  }
  blockedBy.push(...replayBoundaryBlocks(response.authority, 'authority'));
  if (options.requiresConsent === true && (!isVerified(response.consent) || !statusIs(response.consent, 'active'))) {
    blockedBy.push('consent_unverified');
  }
  blockedBy.push(...replayBoundaryBlocks(response.consent, 'consent'));
  if (!isVerified(response.kernelVerdict) || !statusIs(response.kernelVerdict, 'permitted')) {
    blockedBy.push('kernel_verdict_unverified');
  }
  blockedBy.push(...replayBoundaryBlocks(response.kernelVerdict, 'kernel_verdict'));
  if (!isVerified(response.invariants) || !statusIs(response.invariants, 'passed')) {
    blockedBy.push('invariants_unverified');
  }
  blockedBy.push(...replayBoundaryBlocks(response.invariants, 'invariants'));
  blockedBy.push(
    ...dependencyPayloadBlocks([
      [response.humanGate, 'human_gate_dependency_payload_disclosure'],
      [response.quorum, 'quorum_dependency_payload_disclosure'],
      [response.tnc, 'tnc_dependency_payload_disclosure'],
      [response.authority, 'authority_dependency_payload_disclosure'],
      [response.consent, 'consent_dependency_payload_disclosure'],
      [response.kernelVerdict, 'kernel_verdict_dependency_payload_disclosure'],
      [response.invariants, 'invariants_dependency_payload_disclosure'],
    ]),
  );
  if (response.openChallenge === true) {
    blockedBy.push('decision_forum_open_challenge');
  }
  blockedBy.push(...decisionForumPayloadBlocks(response));
  blockedBy.push(...observabilityPayloadBlocks(response, 'decision_forum_observability_payload_disclosure'));

  blockedBy.push(...decisionForumReceiptBlocks(response.provenance, options.expectedDecisionHash));
  blockedBy.push(
    ...responsePayloadBlocks(response, blockedBy, 'decision_forum_response_payload_disclosure'),
  );

  const allowed = blockedBy.length === 0;
  return {
    schema: 'cybermedica.decision_forum_transition_response.v1',
    allowed,
    state: allowed ? TrustState.VERIFIED : TrustState.DENIED,
    failClosed: !allowed,
    blockedBy,
    decisionId: hasText(response.decisionId) ? response.decisionId : null,
    receiptId: hasText(response.provenance?.receiptId) ? response.provenance.receiptId : null,
  };
}

export function evaluateGatewayAdjudicationResponse(response, options = {}) {
  if (response === null || response === undefined) {
    return {
      schema: 'cybermedica.gateway_adjudication_response.v1',
      allowed: false,
      state: TrustState.DEGRADED,
      failClosed: true,
      blockedBy: ['gateway_service_unavailable'],
      decision: null,
      receiptId: null,
    };
  }

  if (gatewayTimeout(response)) {
    return {
      schema: 'cybermedica.gateway_adjudication_response.v1',
      allowed: false,
      state: TrustState.DEGRADED,
      failClosed: true,
      blockedBy: ['gateway_timeout'],
      decision: hasText(response.decision) ? response.decision : null,
      receiptId: null,
    };
  }

  const blockedBy = sourceBoundaryBlocks(response, {
    sourceField: 'enforcementSource',
    expectedSource: EXOCHAIN_GATEWAY_SOURCE,
    sourceBlock: 'gateway_enforcement_source_unverified',
    replayPrefix: 'gateway',
  });
  if (response.status !== 'ok') {
    blockedBy.push('gateway_status_unverified');
  }
  if (response.decision !== 'permitted') {
    blockedBy.push('gateway_decision_not_permitted');
  }
  if (hasText(options.expectedAction) && response.action !== options.expectedAction) {
    blockedBy.push('gateway_action_mismatch');
  }
  if (hasText(options.expectedActorDid) && response.actorDid !== options.expectedActorDid) {
    blockedBy.push('gateway_actor_mismatch');
  }
  if (hasText(options.expectedTenantId) && response.tenantId !== options.expectedTenantId) {
    blockedBy.push('gateway_tenant_mismatch');
  }
  if (!isVerified(response.auth) || !statusIs(response.auth, 'verified')) {
    blockedBy.push('did_auth_unverified');
  }
  blockedBy.push(...replayBoundaryBlocks(response.auth, 'did_auth'));
  if (options.requiresConsent !== false && (!isVerified(response.consent) || !statusIs(response.consent, 'active'))) {
    blockedBy.push('consent_unverified');
  }
  blockedBy.push(...replayBoundaryBlocks(response.consent, 'consent'));
  if (!isVerified(response.authority) || !statusIs(response.authority, 'valid')) {
    blockedBy.push('authority_chain_unverified');
  }
  blockedBy.push(...replayBoundaryBlocks(response.authority, 'authority'));
  if (options.requiresQuorum !== false && (!isVerified(response.quorum) || !statusIs(response.quorum, 'met'))) {
    blockedBy.push('quorum_unverified');
  }
  blockedBy.push(...replayBoundaryBlocks(response.quorum, 'quorum'));
  if (!isVerified(response.invariants) || !statusIs(response.invariants, 'passed')) {
    blockedBy.push('invariants_unverified');
  }
  blockedBy.push(...replayBoundaryBlocks(response.invariants, 'invariants'));
  blockedBy.push(
    ...dependencyPayloadBlocks([
      [response.auth, 'did_auth_dependency_payload_disclosure'],
      [response.consent, 'consent_dependency_payload_disclosure'],
      [response.authority, 'authority_dependency_payload_disclosure'],
      [response.quorum, 'quorum_dependency_payload_disclosure'],
      [response.invariants, 'invariants_dependency_payload_disclosure'],
    ]),
  );
  blockedBy.push(...gatewayPayloadBlocks(response));
  blockedBy.push(...observabilityPayloadBlocks(response, 'gateway_observability_payload_disclosure'));

  blockedBy.push(...gatewayReceiptBlocks(response.provenance, options.expectedActionHash));
  blockedBy.push(...responsePayloadBlocks(response, blockedBy, 'gateway_response_payload_disclosure'));

  const allowed = blockedBy.length === 0;
  return {
    schema: 'cybermedica.gateway_adjudication_response.v1',
    allowed,
    state: allowed ? TrustState.VERIFIED : TrustState.DENIED,
    failClosed: !allowed,
    blockedBy,
    decision: hasText(response.decision) ? response.decision : null,
    receiptId: hasText(response.provenance?.receiptId) ? response.provenance.receiptId : null,
  };
}

export function evaluateReceiptCommitmentResponse(response, options = {}) {
  if (response === null || response === undefined) {
    return {
      schema: 'cybermedica.receipt_commitment_response.v1',
      allowed: false,
      state: TrustState.DEGRADED,
      failClosed: true,
      blockedBy: ['receipt_service_unavailable'],
      receiptId: null,
    };
  }

  if (receiptTimeout(response)) {
    return {
      schema: 'cybermedica.receipt_commitment_response.v1',
      allowed: false,
      state: TrustState.DEGRADED,
      failClosed: true,
      blockedBy: ['receipt_timeout'],
      receiptId: null,
    };
  }

  const blockedBy = sourceBoundaryBlocks(response, {
    sourceField: 'receiptSource',
    expectedSource: EXOCHAIN_NODE_RECEIPT_SOURCE,
    sourceBlock: 'receipt_source_unverified',
    replayPrefix: 'receipt',
  });
  const expectedActionHash = options.expectedActionHash;
  if (hasText(response.status) && response.status !== 'ok') {
    blockedBy.push('receipt_status_unverified');
  }
  if (!hasText(response.receiptId)) {
    blockedBy.push('receipt_id_absent');
  }
  if (!hasText(response.actionHash) || !HEX_64.test(response.actionHash)) {
    blockedBy.push('receipt_action_hash_invalid');
  }
  if (!hasText(expectedActionHash) || !HEX_64.test(expectedActionHash)) {
    blockedBy.push('expected_action_hash_invalid');
  } else if (response.actionHash !== expectedActionHash) {
    blockedBy.push('receipt_action_hash_mismatch');
  }
  if (!hasText(response.signature)) {
    blockedBy.push('receipt_signature_absent');
  }
  if (containsDisclosedPayload(response.anchorPayload)) {
    blockedBy.push('receipt_payload_disclosure');
  }
  blockedBy.push(...receiptPayloadBlocks(response));
  blockedBy.push(...observabilityPayloadBlocks(response, 'receipt_observability_payload_disclosure'));
  blockedBy.push(...responsePayloadBlocks(response, blockedBy, 'receipt_response_payload_disclosure'));

  const allowed = blockedBy.length === 0;
  return {
    schema: 'cybermedica.receipt_commitment_response.v1',
    allowed,
    state: allowed ? TrustState.VERIFIED : TrustState.DENIED,
    failClosed: !allowed,
    blockedBy,
    receiptId: hasText(response.receiptId) ? response.receiptId : null,
  };
}
