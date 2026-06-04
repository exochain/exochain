#!/usr/bin/env node
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

import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const CONTEXT_SEED_REF = 'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md';

const EXPECTED_GUARDRAILS = Object.freeze([
  {
    number: 1,
    text: 'CyberMedica is an adjacent app, not Exochain core.',
  },
  {
    number: 2,
    text: 'CyberMedica may rely on Exochain primitives only where those primitives are verified by source path, runtime path, and tests.',
  },
  {
    number: 3,
    text: 'CyberMedica must not claim Exochain provenance where no receipt path exists.',
  },
  {
    number: 4,
    text: 'CyberMedica must not anchor raw PHI, PII, sponsor-confidential, or privileged content.',
  },
  {
    number: 5,
    text: 'CyberMedica must distinguish operational database state from immutable receipts.',
  },
  {
    number: 6,
    text: 'CyberMedica must treat clinical research QMS controls as evidence-backed objects.',
  },
  {
    number: 7,
    text: 'CyberMedica must use human governance for launch gates, enrollment gates, CAPA closure, consent controls, and Decision Forum decisions.',
  },
  {
    number: 8,
    text: 'CyberMedica must preserve AI as assistant, not final authority.',
  },
  {
    number: 9,
    text: 'CyberMedica must support tenant isolation, authority chains, revocation, contestation, and auditability.',
  },
  {
    number: 10,
    text: 'CyberMedica implementation tasks must trace to PRD IDs, Exochain primitives, tests, and deployment evidence.',
  },
  {
    number: 11,
    text: 'CyberMedica baseline development must proceed before 7/13 root activation by using explicit service contracts, deterministic fixtures, inactive trust-claim states, and fail-closed adapters.',
  },
  {
    number: 12,
    text: 'CyberMedica build tasks must be TDD-first, maintain >90% scoped coverage, and target near-100% coverage on trust boundaries.',
  },
  {
    number: 13,
    text: 'CyberMedica work must preserve the original PRD/context discipline and must not dilute blocked claims into implied support.',
  },
  {
    number: 14,
    text: 'CyberMedica work must not alter Exochain source code as part of adjacent-surface implementation.',
  },
  {
    number: 15,
    text: 'Final root verification gates production activation and claims, not baseline product development.',
  },
]);

const EXPECTED_PERMITTED_PRIMITIVE_FAMILIES = Object.freeze([
  'DAG/provenance',
  'DID identity',
  'Decision Forum adjudicated workflow',
  'TrustReceipt',
  'authority chains',
  'bailment/consent',
  'gatekeeper adjudication',
  'legal evidence custody',
  'root trust bundle verification',
  'tenant registry',
  'verified quorum/governance audit',
]);

const EXPECTED_FORBIDDEN_PRODUCTION_CLAIM_FAMILIES = Object.freeze([
  '0dentity behavioral/device axes',
  'Archon workflows',
  'CommandBase',
  'CrossChecked anchoring',
  'ExoForge',
  'any UI surface',
  'default-off proofs',
  'economy settlement',
  'raw admin governance',
]);

const REQUIRED_CONTEXT_SEED_TEXT_REFS = Object.freeze([
  'This seed permits CyberMedica to map these source-identified primitive families into baseline development service contracts now',
  'Production activation for root-backed authority still requires the 13-certifier DKG and 7-of-13 signing evidence.',
  'This seed does not permit CyberMedica to claim production support from default-off proofs',
  'Use this for the next CyberMedica baseline architecture/build pass.',
  'Do not wait for final root bundle verification to begin baseline development.',
  'Produce a TDD-first CyberMedica architecture with PRD traceability',
]);

const EXPECTED_CONTEXT_SEED_CONTRACTS = Object.freeze([
  {
    contractId: 'context_seed_ground_truth_contract',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/ground-truth-register.mjs',
        requiredTextRefs: Object.freeze([
          'context_seed',
          'REQUIRED_CONTEXT_DOC_REFS',
          'exochainSourceReadOnly',
          'baseline_development_blocked_by_open_questions',
          'productionTrustClaim === true',
        ]),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/ground-truth-register.test.mjs',
        requiredTextRefs: Object.freeze([
          'context_seed',
          'ground truth register permits deterministic metadata-only context source basis',
          'exochainSourceReadOnly',
          'ground_truth_human_final_authority_required',
        ]),
      },
    ]),
  },
  {
    contractId: 'context_seed_service_contract_publication',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/service-contract-publication.mjs',
        requiredTextRefs: Object.freeze([
          'REQUIRED_META_LAYERS',
          'REQUIRED_CONTRACT_KINDS',
          'REQUIRED_CONTEXT_REFS',
          'baseline_service_contracts',
          'publication_policy_inactive_trust_gate_absent',
          'exochainSourceReadOnly',
        ]),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/service-contract-publication.test.mjs',
        requiredTextRefs: Object.freeze([
          'REQUIRED_META_LAYERS',
          'REQUIRED_CONTRACT_KINDS',
          'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md#baseline-development',
          'service_contracts_publishable_inactive_trust',
        ]),
      },
    ]),
  },
  {
    contractId: 'context_seed_requirement_traceability',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/requirement-traceability.mjs',
        requiredTextRefs: Object.freeze([
          'REQUIRED_DOCTRINE_LAYERS',
          'REQUIRED_CONTEXT_DOC_REFS',
          'DEFAULT_ACTIVATION_BLOCKER_IDS',
          'root_verification_gate_absent',
          'requirement_blocks_baseline',
          'validation_exochain_read_only_absent',
        ]),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/requirement-traceability.test.mjs',
        requiredTextRefs: Object.freeze([
          'REQUIRED_DOCTRINE_LAYERS',
          'rootVerificationRequiredForTrustClaims: true',
          'activationOnlyBlockersAccepted',
          'requirement traceability matrix maps requirements',
        ]),
      },
    ]),
  },
  {
    contractId: 'context_seed_release_readiness',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/release-readiness-matrix.mjs',
        requiredTextRefs: Object.freeze([
          'REQUIRED_DOCTRINE_LAYERS',
          'RELEASE_DECISIONS',
          'baseline_ready_inactive_trust',
          'root_verification_gate_absent',
          'production_trust_claim_forbidden',
          'release_decision_exochain_read_only_absent',
        ]),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/release-readiness-matrix.test.mjs',
        requiredTextRefs: Object.freeze([
          'release readiness matrix creates deterministic inactive baseline release receipts',
          'baseline_ready_inactive_trust',
          'exochainSourceReadOnly: true',
          'rootVerificationRequiredForTrustClaims: true',
        ]),
      },
    ]),
  },
  {
    contractId: 'context_seed_quality_gate',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/ci-cd-quality-gates.mjs',
        requiredTextRefs: Object.freeze([
          'source_guard_tests',
          'production_trust_claim_before_activation',
          'exochain_backed_language_before_activation',
          'root_backed_authority_claim_before_activation',
          'source_guard_exochain_source_modified',
          'trust_boundary_coverage_below_threshold',
        ]),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/ci-cd-quality-gates.test.mjs',
        requiredTextRefs: Object.freeze([
          'source_guard_tests',
          'productionTrustClaim: false',
          'production_trust_claim_before_activation',
          'source_guard_exochain_source_modified',
          'trustBoundaryCoverageBasisPoints: 10000',
        ]),
      },
    ]),
  },
]);

function sha256Hex(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function readProjectFile(rootDir, pathRef) {
  const absolutePath = resolve(rootDir, pathRef);
  return existsSync(absolutePath) ? readFileSync(absolutePath, 'utf8') : null;
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function textRefFindings(text, pathRef, requiredTextRefs, ruleId) {
  if (text === null) {
    return [
      {
        ruleId: `${ruleId}_file_absent`,
        pathRef,
        requiredTextRef: null,
        metadataOnly: true,
      },
    ];
  }

  return requiredTextRefs
    .filter((requiredTextRef) => !text.includes(requiredTextRef))
    .map((requiredTextRef) => ({
      ruleId,
      pathRef,
      requiredTextRef,
      metadataOnly: true,
    }));
}

function contextSeedFindings(contextSeedText) {
  if (contextSeedText === null) {
    return [
      {
        ruleId: 'context_seed_file_absent',
        pathRef: CONTEXT_SEED_REF,
        metadataOnly: true,
      },
    ];
  }

  return [
    ...EXPECTED_GUARDRAILS.filter((guardrail) => !contextSeedText.includes(`${guardrail.number}. ${guardrail.text}`)).map(
      (guardrail) => ({
        ruleId: 'context_seed_guardrail_absent',
        pathRef: CONTEXT_SEED_REF,
        guardrailNumber: guardrail.number,
        metadataOnly: true,
      }),
    ),
    ...EXPECTED_PERMITTED_PRIMITIVE_FAMILIES.filter((family) => !contextSeedText.includes(family)).map((family) => ({
      ruleId: 'context_seed_permitted_primitive_absent',
      pathRef: CONTEXT_SEED_REF,
      primitiveFamily: family,
      metadataOnly: true,
    })),
    ...EXPECTED_FORBIDDEN_PRODUCTION_CLAIM_FAMILIES.filter((family) => !contextSeedText.includes(family)).map(
      (family) => ({
        ruleId: 'context_seed_forbidden_claim_family_absent',
        pathRef: CONTEXT_SEED_REF,
        claimFamily: family,
        metadataOnly: true,
      }),
    ),
    ...textRefFindings(
      contextSeedText,
      CONTEXT_SEED_REF,
      REQUIRED_CONTEXT_SEED_TEXT_REFS,
      'context_seed_required_text_absent',
    ),
  ];
}

function contractTextFindings(rootDir, contractId, pathRef, requiredTextRefs, kind) {
  const text = readProjectFile(rootDir, pathRef);
  if (text === null) {
    return [
      {
        ruleId: `context_seed_${kind}_file_absent`,
        contractId,
        pathRef,
        requiredTextRef: null,
        metadataOnly: true,
      },
    ];
  }

  return requiredTextRefs
    .filter((requiredTextRef) => !text.includes(requiredTextRef))
    .map((requiredTextRef) => ({
      ruleId: `context_seed_${kind}_text_absent`,
      contractId,
      pathRef,
      requiredTextRef,
      metadataOnly: true,
    }));
}

function contractFindings(rootDir) {
  return EXPECTED_CONTEXT_SEED_CONTRACTS.flatMap((contract) => [
    ...contract.sourceContracts.flatMap((sourceContract) =>
      contractTextFindings(
        rootDir,
        contract.contractId,
        sourceContract.pathRef,
        sourceContract.requiredTextRefs,
        'source',
      ),
    ),
    ...contract.testContracts.flatMap((testContract) =>
      contractTextFindings(rootDir, contract.contractId, testContract.pathRef, testContract.requiredTextRefs, 'test'),
    ),
  ]);
}

function compareFindings(left, right) {
  const idCompare = String(left.guardrailNumber ?? left.primitiveFamily ?? left.claimFamily ?? left.contractId).localeCompare(
    String(right.guardrailNumber ?? right.primitiveFamily ?? right.claimFamily ?? right.contractId),
  );
  if (idCompare !== 0) {
    return idCompare;
  }
  const pathCompare = String(left.pathRef).localeCompare(String(right.pathRef));
  if (pathCompare !== 0) {
    return pathCompare;
  }
  const textCompare = String(left.requiredTextRef).localeCompare(String(right.requiredTextRef));
  if (textCompare !== 0) {
    return textCompare;
  }
  return left.ruleId.localeCompare(right.ruleId);
}

export function scanContextSeedDoctrineCoverage(rootDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')) {
  const contextSeedText = readProjectFile(rootDir, CONTEXT_SEED_REF);
  const checkedSourceRefs = uniqueSorted(
    EXPECTED_CONTEXT_SEED_CONTRACTS.flatMap((contract) =>
      contract.sourceContracts.map((sourceContract) => sourceContract.pathRef),
    ),
  );
  const checkedTestRefs = uniqueSorted(
    EXPECTED_CONTEXT_SEED_CONTRACTS.flatMap((contract) =>
      contract.testContracts.map((testContract) => testContract.pathRef),
    ),
  );
  const findings = [...contextSeedFindings(contextSeedText), ...contractFindings(rootDir)].sort(compareFindings);

  return {
    schema: 'cybermedica.source_context_seed_guard.v1',
    status: findings.length === 0 ? 'passed' : 'failed',
    exitCode: findings.length === 0 ? 0 : 1,
    scannerRef: 'cybermedica-source-context-seed-guard',
    scannerVersionHash: sha256Hex(
      [
        EXPECTED_GUARDRAILS.map((guardrail) => `${guardrail.number}:${guardrail.text}`).join('|'),
        EXPECTED_PERMITTED_PRIMITIVE_FAMILIES.join(','),
        EXPECTED_FORBIDDEN_PRODUCTION_CLAIM_FAMILIES.join(','),
        EXPECTED_CONTEXT_SEED_CONTRACTS.map((contract) => {
          const sourceRefs = contract.sourceContracts.map(
            (sourceContract) => `${sourceContract.pathRef}:${sourceContract.requiredTextRefs.join(',')}`,
          );
          const testRefs = contract.testContracts.map(
            (testContract) => `${testContract.pathRef}:${testContract.requiredTextRefs.join(',')}`,
          );
          return `${contract.contractId}:${sourceRefs.join(';')}:${testRefs.join(';')}`;
        }).join('|'),
      ].join('|'),
    ),
    contextSeedRef: CONTEXT_SEED_REF,
    guardrailNumbers:
      contextSeedText === null
        ? []
        : EXPECTED_GUARDRAILS.filter((guardrail) => contextSeedText.includes(`${guardrail.number}. ${guardrail.text}`)).map(
            (guardrail) => guardrail.number,
          ),
    guardrailCount:
      contextSeedText === null
        ? 0
        : EXPECTED_GUARDRAILS.filter((guardrail) => contextSeedText.includes(`${guardrail.number}. ${guardrail.text}`))
            .length,
    permittedPrimitiveFamilies:
      contextSeedText === null
        ? []
        : EXPECTED_PERMITTED_PRIMITIVE_FAMILIES.filter((family) => contextSeedText.includes(family)),
    permittedPrimitiveFamilyCount:
      contextSeedText === null
        ? 0
        : EXPECTED_PERMITTED_PRIMITIVE_FAMILIES.filter((family) => contextSeedText.includes(family)).length,
    forbiddenProductionClaimFamilies:
      contextSeedText === null
        ? []
        : EXPECTED_FORBIDDEN_PRODUCTION_CLAIM_FAMILIES.filter((family) => contextSeedText.includes(family)),
    forbiddenProductionClaimFamilyCount:
      contextSeedText === null
        ? 0
        : EXPECTED_FORBIDDEN_PRODUCTION_CLAIM_FAMILIES.filter((family) => contextSeedText.includes(family)).length,
    checkedSourceRefs,
    checkedTestRefs,
    exochainSourceExcluded: [...checkedSourceRefs, ...checkedTestRefs].every(
      (pathRef) => !pathRef.startsWith('../exochain') && !pathRef.startsWith('/Users/bobstewart/dev/exochain/exochain'),
    ),
    findings,
    findingsCount: findings.length,
    metadataOnly: true,
  };
}

const invokedPath = process.argv[1] === undefined ? '' : resolve(process.argv[1]);
const modulePath = fileURLToPath(import.meta.url);

if (invokedPath === modulePath) {
  const rootDir = resolve(dirname(modulePath), '..');
  const report = scanContextSeedDoctrineCoverage(rootDir);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.exitCode;
}
