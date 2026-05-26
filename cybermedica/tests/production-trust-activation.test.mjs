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

async function loadTrustAdapter() {
  try {
    return await import('../src/trust-adapter.mjs');
  } catch (error) {
    assert.fail(`CyberMedica trust adapter module must exist and load: ${error.message}`);
  }
}

test('production Exochain trust claims remain inactive without verified root and adapter evidence', async () => {
  const { evaluateProductionTrustActivation } = await loadTrustAdapter();

  const result = evaluateProductionTrustActivation({
    claimId: 'PTAG-001',
    rootBundle: null,
    gatewayAdapter: null,
    receiptPath: null,
    privacyBoundary: null,
    decisionForum: null,
  });

  assert.equal(result.allowed, false);
  assert.equal(result.state, 'inactive');
  assert.equal(result.failClosed, true);
  assert.deepEqual(result.blockedBy, [
    'root_bundle_absent',
    'root_certifier_roster_absent',
    'root_dkg_transcript_absent',
    'root_threshold_signature_absent',
    'root_verifier_absent',
    'gateway_adapter_unverified',
    'receipt_path_unverified',
    'privacy_boundary_unverified',
    'decision_forum_unverified',
  ]);
  assert.equal(result.exochainProductionClaim, false);
  assert.match(result.displayLabel, /inactive/i);
  assert.doesNotMatch(result.claimLanguage, /root-backed production authority/i);
});

test('production activation distinguishes pending denied and verified evidence states', async () => {
  const { evaluateProductionTrustActivation } = await loadTrustAdapter();
  const verifiedDependency = { verified: true };

  const pending = evaluateProductionTrustActivation({
    claimId: 'PTAG-001',
    rootBundle: {
      status: 'pending',
      verified: false,
      certifierCount: 13,
      dkgParticipantCount: 13,
      thresholdSignature: '7-of-13',
      verifierReceiptId: 'root-verifier-pending-alpha',
    },
    gatewayAdapter: verifiedDependency,
    receiptPath: verifiedDependency,
    privacyBoundary: verifiedDependency,
    decisionForum: verifiedDependency,
  });

  assert.equal(pending.allowed, false);
  assert.equal(pending.state, 'pending');
  assert.equal(pending.failClosed, true);
  assert.deepEqual(pending.blockedBy, ['root_verifier_pending']);

  const denied = evaluateProductionTrustActivation({
    claimId: 'PTAG-001',
    rootBundle: {
      status: 'failed',
      verified: false,
      certifierCount: 12,
      dkgParticipantCount: 12,
      thresholdSignature: '6-of-13',
      verifierReceiptId: '',
    },
    gatewayAdapter: verifiedDependency,
    receiptPath: verifiedDependency,
    privacyBoundary: verifiedDependency,
    decisionForum: verifiedDependency,
  });

  assert.equal(denied.allowed, false);
  assert.equal(denied.state, 'denied');
  assert.ok(denied.blockedBy.includes('root_certifier_roster_absent'));
  assert.ok(denied.blockedBy.includes('root_dkg_transcript_absent'));
  assert.ok(denied.blockedBy.includes('root_threshold_signature_absent'));
  assert.ok(denied.blockedBy.includes('root_verifier_absent'));

  const verified = evaluateProductionTrustActivation({
    claimId: 'PTAG-001',
    rootBundle: {
      status: 'verified',
      verified: true,
      certifierCount: 13,
      dkgParticipantCount: 13,
      thresholdSignature: '7-of-13',
      verifierReceiptId: 'root-verifier-receipt-alpha',
    },
    gatewayAdapter: verifiedDependency,
    receiptPath: verifiedDependency,
    privacyBoundary: verifiedDependency,
    decisionForum: verifiedDependency,
  });

  assert.equal(verified.allowed, true);
  assert.equal(verified.state, 'verified');
  assert.equal(verified.exochainProductionClaim, true);
  assert.deepEqual(verified.blockedBy, []);
});

test('production activation rejects protected or secret material in activation evidence', async () => {
  const { evaluateProductionTrustActivation } = await loadTrustAdapter();

  const result = evaluateProductionTrustActivation({
    claimId: 'PTAG-001',
    rootBundle: {
      status: 'verified',
      verified: true,
      certifierCount: 13,
      dkgParticipantCount: 13,
      thresholdSignature: '7-of-13',
      verifierReceiptId: 'root-verifier-receipt-alpha',
      artifactStorePayload: { accessToken: 'redacted-access-token' },
    },
    gatewayAdapter: { verified: true, healthPayload: { apiKey: 'redacted-api-key' } },
    receiptPath: { verified: true, debugPayload: { participantName: 'Participant Alice Example' } },
    privacyBoundary: { verified: true, telemetryPayload: { rawPhi: 'Participant Alice Example MRN: A-123' } },
    decisionForum: { verified: true, logPayload: { clientSecret: 'redacted-client-secret' } },
  });

  assert.equal(result.allowed, false);
  assert.equal(result.state, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.exochainProductionClaim, false);
  assert.ok(result.blockedBy.includes('root_bundle_activation_payload_disclosure'));
  assert.ok(result.blockedBy.includes('gateway_adapter_activation_payload_disclosure'));
  assert.ok(result.blockedBy.includes('receipt_path_activation_payload_disclosure'));
  assert.ok(result.blockedBy.includes('privacy_boundary_activation_payload_disclosure'));
  assert.ok(result.blockedBy.includes('decision_forum_activation_payload_disclosure'));
  assert.doesNotMatch(JSON.stringify(result), /redacted-access-token|redacted-api-key|Participant Alice|redacted-client-secret/u);
});

test('production activation rejects simulated cached or overridden activation evidence', async () => {
  const { evaluateProductionTrustActivation } = await loadTrustAdapter();

  const result = evaluateProductionTrustActivation({
    claimId: 'PTAG-001',
    rootBundle: {
      status: 'verified',
      verified: true,
      certifierCount: 13,
      dkgParticipantCount: 13,
      thresholdSignature: '7-of-13',
      verifierReceiptId: 'root-verifier-receipt-alpha',
      locallySimulated: true,
    },
    gatewayAdapter: { verified: true, cacheHit: true },
    receiptPath: { verified: true, overrideApplied: true },
    privacyBoundary: { verified: true, cachedOutcome: true },
    decisionForum: { verified: true, simulated: true },
  });

  assert.equal(result.allowed, false);
  assert.equal(result.state, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.exochainProductionClaim, false);
  assert.ok(result.blockedBy.includes('root_bundle_local_simulation_forbidden'));
  assert.ok(result.blockedBy.includes('gateway_adapter_cached_outcome_forbidden'));
  assert.ok(result.blockedBy.includes('receipt_path_override_forbidden'));
  assert.ok(result.blockedBy.includes('privacy_boundary_cached_outcome_forbidden'));
  assert.ok(result.blockedBy.includes('decision_forum_local_simulation_forbidden'));
  assert.doesNotMatch(result.claimLanguage, /verified for this CyberMedica action/i);
});
