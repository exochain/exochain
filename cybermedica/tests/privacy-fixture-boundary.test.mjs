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
const DIGEST_E = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const DIGEST_F = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
const DIGEST_1 = '1111111111111111111111111111111111111111111111111111111111111111';
const DIGEST_2 = '2222222222222222222222222222222222222222222222222222222222222222';

const REQUIRED_SURFACE_FAMILIES = [
  'audit_log_record',
  'dag_payload',
  'debug_response',
  'export_manifest',
  'health_response',
  'receipt_anchor',
  'telemetry_event',
];

const REQUIRED_DETECTOR_RULE_IDS = [
  'hash_only_metadata_required',
  'protected_field_name',
  'protected_text_pattern',
  'secret_field_name',
  'secret_text_pattern',
  'unscoped_payload_field',
];

async function loadPrivacyFixtureBoundary() {
  try {
    return await import('../src/privacy-fixture-boundary.mjs');
  } catch (error) {
    assert.fail(`CyberMedica privacy fixture boundary module must exist and load: ${error.message}`);
  }
}

function digestFor(index) {
  return (index + 1).toString(16).padStart(2, '0').repeat(32);
}

function mergeDeep(base, overrides) {
  if (Array.isArray(base) || Array.isArray(overrides)) {
    return overrides === undefined ? base : overrides;
  }
  if (base === null || overrides === null || typeof base !== 'object' || typeof overrides !== 'object') {
    return overrides === undefined ? base : overrides;
  }
  return Object.fromEntries(
    [...new Set([...Object.keys(base), ...Object.keys(overrides)])].map((key) => [
      key,
      mergeDeep(base[key], overrides[key]),
    ]),
  );
}

function fixtureCase(surfaceFamily, index, overrides = {}) {
  return {
    fixtureRef: `privacy-fixture-${surfaceFamily}`,
    surfaceFamily,
    scannerRef: 'privacy-fixture-boundary-scan',
    scannerVersionHash: DIGEST_A,
    fixtureHash: digestFor(index + 20),
    negativeProbeHash: digestFor(index + 40),
    detectorRuleIds: REQUIRED_DETECTOR_RULE_IDS,
    scanStatus: 'passed',
    findingsCount: 0,
    rawSensitiveContentAbsent: true,
    secretMaterialAbsent: true,
    payloadSuppressed: true,
    hashOnlyMetadata: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    scannedAtHlc: { physicalMs: 1811000000350, logical: index },
    ...overrides,
  };
}

function privacyFixtureInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:privacy-fixture-reviewer-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'privacy_officer'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['privacy_fixture_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    privacyPolicy: {
      policyRef: 'privacy-fixture-boundary-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredSurfaceFamilies: REQUIRED_SURFACE_FAMILIES,
      requiredDetectorRuleIds: REQUIRED_DETECTOR_RULE_IDS,
      requireHashOnlyMetadata: true,
      requirePayloadSuppression: true,
      requireNoProductionTrustClaim: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1811000000100, logical: 0 },
    },
    fixtureSuite: {
      suiteRef: 'ptag-009-privacy-fixture-suite-alpha',
      sourceRef: 'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md#PTAG-009',
      openedAtHlc: { physicalMs: 1811000000200, logical: 0 },
      compiledAtHlc: { physicalMs: 1811000000300, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    fixtureCases: REQUIRED_SURFACE_FAMILIES.map(fixtureCase).reverse(),
    scanEvidence: {
      commandRefs: [
        'node --test tests/privacy-fixture-boundary.test.mjs',
        'npm run scan:secrets',
        'npm run scan:hazards',
      ],
      scannerRef: 'privacy-fixture-boundary-scan',
      scannerVersionHash: DIGEST_C,
      allFixturesPassed: true,
      findingsCount: 0,
      rawSensitiveFixturesAbsent: true,
      secretFixturesAbsent: true,
      exochainSourceExcluded: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      scanHash: DIGEST_D,
      scannedAtHlc: { physicalMs: 1811000000400, logical: 0 },
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-manager-alpha',
      reviewerRoleRefs: ['quality_manager', 'privacy_officer'],
      decision: 'privacy_fixture_boundary_accepted_inactive_trust',
      reviewHash: DIGEST_E,
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1811000000500, logical: 0 },
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_F,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    custodyDigest: DIGEST_1,
  };
  return mergeDeep(base, overrides);
}

test('privacy fixture boundary creates deterministic inactive evidence across sensitive output surfaces', async () => {
  const { evaluatePrivacyFixtureBoundary } = await loadPrivacyFixtureBoundary();

  const first = evaluatePrivacyFixtureBoundary(privacyFixtureInput());
  const second = evaluatePrivacyFixtureBoundary({
    ...privacyFixtureInput(),
    fixtureCases: [...privacyFixtureInput().fixtureCases].reverse(),
    privacyPolicy: {
      ...privacyFixtureInput().privacyPolicy,
      requiredSurfaceFamilies: [...REQUIRED_SURFACE_FAMILIES].reverse(),
      requiredDetectorRuleIds: [...REQUIRED_DETECTOR_RULE_IDS].reverse(),
    },
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.privacyFixtureBoundary.status, 'verified_metadata_only');
  assert.deepEqual(first.privacyFixtureBoundary.surfaceFamilies, REQUIRED_SURFACE_FAMILIES);
  assert.deepEqual(first.privacyFixtureBoundary.detectorRuleIds, REQUIRED_DETECTOR_RULE_IDS);
  assert.equal(first.privacyFixtureBoundary.fixtureCount, REQUIRED_SURFACE_FAMILIES.length);
  assert.equal(first.privacyFixtureBoundary.exochainProductionClaim, false);
  assert.deepEqual(first.privacyFixtureBoundary.activationGateIds, ['PTAG-009']);
  assert.equal(first.privacyFixtureBoundary.metadataOnly, true);
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.equal(first.receipt.anchorPayload.artifactType, 'privacy_fixture_boundary');
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.privacyFixtureBoundary.fixtureProofHash, second.privacyFixtureBoundary.fixtureProofHash);
});

test('privacy fixture scanner detects unsafe fields and text without echoing values', async () => {
  const { scanPrivacyFixtureEnvelope } = await loadPrivacyFixtureBoundary();
  const unsafeEnvelope = {
    receipt: {
      sourceDocumentBody: 'Participant Alice Example MRN: CM-123',
      authorizationHeader: 'Bearer redacted-token-placeholder',
      anchorPayload: { payload: { participantName: 'Alice Example' } },
    },
    telemetry: {
      debugPayload: 'patient Alice Example contacted coordinator',
    },
  };

  const findings = scanPrivacyFixtureEnvelope('tests/privacy-negative-probe.json', unsafeEnvelope);

  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    [
      'unscoped_payload_field',
      'unscoped_payload_field',
      'protected_field_name',
      'secret_field_name',
      'secret_text_pattern',
      'protected_field_name',
      'protected_text_pattern',
      'unscoped_payload_field',
      'protected_text_pattern',
    ],
  );
  assert.ok(findings.every((finding) => finding.metadataOnly === true));
  assert.ok(findings.every((finding) => /^[0-9a-f]{64}$/u.test(finding.matchDigest)));
  assert.doesNotMatch(JSON.stringify(findings), /Alice|CM-123|Bearer|sourceDocumentBody|debugPayload/u);
});

test('privacy fixture boundary fails closed for missing surfaces and dirty fixture results', async () => {
  const { evaluatePrivacyFixtureBoundary } = await loadPrivacyFixtureBoundary();
  const cases = REQUIRED_SURFACE_FAMILIES.map((surfaceFamily, index) => {
    if (surfaceFamily === 'receipt_anchor') {
      return fixtureCase(surfaceFamily, index, {
        scanStatus: 'failed',
        findingsCount: 2,
        rawSensitiveContentAbsent: false,
        payloadSuppressed: false,
      });
    }
    if (surfaceFamily === 'telemetry_event') {
      return fixtureCase(surfaceFamily, index, {
        detectorRuleIds: REQUIRED_DETECTOR_RULE_IDS.filter((ruleId) => ruleId !== 'secret_text_pattern'),
      });
    }
    return fixtureCase(surfaceFamily, index);
  }).filter((fixture) => fixture.surfaceFamily !== 'debug_response');

  const result = evaluatePrivacyFixtureBoundary(
    privacyFixtureInput({
      fixtureCases: cases,
      scanEvidence: {
        allFixturesPassed: false,
        findingsCount: 2,
        rawSensitiveFixturesAbsent: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.privacyFixtureBoundary.status, 'blocked');
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('surface_family_missing:debug_response'));
  assert.ok(result.reasons.includes('fixture_scan_not_passed:privacy-fixture-receipt_anchor'));
  assert.ok(result.reasons.includes('fixture_raw_sensitive_content_present:privacy-fixture-receipt_anchor'));
  assert.ok(result.reasons.includes('fixture_payload_not_suppressed:privacy-fixture-receipt_anchor'));
  assert.ok(result.reasons.includes('fixture_detector_rule_missing:privacy-fixture-telemetry_event:secret_text_pattern'));
  assert.ok(result.reasons.includes('scan_evidence_raw_sensitive_fixtures_present'));
});

test('privacy fixture boundary requires human authority safe HLC ordering and inactive trust posture', async () => {
  const { evaluatePrivacyFixtureBoundary } = await loadPrivacyFixtureBoundary();

  const result = evaluatePrivacyFixtureBoundary(
    privacyFixtureInput({
      actor: { did: '', kind: 'ai_agent' },
      fixtureSuite: {
        productionTrustClaim: true,
      },
      scanEvidence: {
        scannedAtHlc: { physicalMs: 1811000000600, logical: 0 },
      },
      humanReview: {
        aiFinalAuthority: true,
        noProductionTrustClaim: false,
        reviewedAtHlc: { physicalMs: 1811000000350, logical: 0 },
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('actor_did_absent'));
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('fixture_suite_production_trust_claim_attempted'));
  assert.ok(result.reasons.includes('human_review_ai_final_authority'));
  assert.ok(result.reasons.includes('human_review_before_scan'));
});

test('privacy fixture boundary rejects raw fixture content and secrets before receipt creation', async () => {
  const { ProtectedContentError, evaluatePrivacyFixtureBoundary } = await loadPrivacyFixtureBoundary();

  assert.throws(
    () =>
      evaluatePrivacyFixtureBoundary(
        privacyFixtureInput({
          rawFixtureBody: 'Participant Alice Example source material',
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluatePrivacyFixtureBoundary(
        privacyFixtureInput({
          fixtureCases: [
            fixtureCase('receipt_anchor', 0, {
              rootSigningKey: 'redacted-root-signing-key',
            }),
          ],
        }),
      ),
    ProtectedContentError,
  );
});
