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

const GLOSSARY_REF = 'docs/context/EXOCHAIN_GLOSSARY_FOR_CYBERMEDICA.md';

const EXPECTED_GLOSSARY_TERMS = Object.freeze([
  '0dentity',
  '13-certifier DKG',
  '7-of-13 signing',
  'AVC',
  'Adjacent surface',
  'Authority chain',
  'AuthorityChainValid',
  'BCTS',
  'Bailment',
  'Baseline development',
  'Canonical CBOR',
  'Chain of custody',
  'Challenge',
  'CommandBase',
  'Commit certificate',
  'Consent gate',
  'Consent policy',
  'ConsentRequired',
  'Constitutional invariant',
  'Core runtime adapter',
  'CrossChecked anchor',
  'DAG node',
  'DID',
  'DID auth',
  'DecisionObject',
  'Determinism',
  'ExoForge/Archon',
  'Exochain core',
  'Gatekeeper',
  'Governance audit entry',
  'HLC',
  'Human gate',
  'HumanOverride',
  'KernelImmutability',
  'Legal evidence',
  'No floating point',
  'NoSelfGrant',
  'Permission',
  'Production activation',
  'ProvenanceVerifiable',
  'Quorum',
  'QuorumLegitimate',
  'Root genesis',
  'SeparationOfPowers',
  'Syntaxis',
  'TNC',
  'Trust claim by proximity',
  'TrustReceipt',
  'WorkflowReceipt',
  '`exo-proofs`',
]);

const REQUIRED_GLOSSARY_TEXT_REFS = Object.freeze([
  'This glossary is constrained to observed Exochain source paths',
  'Terms are not available for CyberMedica trust claims unless their implementation path and test requirement are also satisfied.',
  'CyberMedica is not core. It may call verified core APIs through adapters.',
  'Forbidden for CyberMedica.',
  'No receipt path, no Exochain-backed provenance claim.',
  'Gates claims, not baseline development.',
  'Do not claim ZK proofs.',
  'Do not use for CyberMedica claims.',
]);

const EXPECTED_GLOSSARY_CONTRACTS = Object.freeze([
  {
    contractId: 'glossary_ground_truth_register',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/ground-truth-register.mjs',
        requiredTextRefs: Object.freeze([
          'glossary',
          'docs/context/EXOCHAIN_GLOSSARY_FOR_CYBERMEDICA.md',
          'exochainSourceReadOnly',
          'productionTrustClaim === true',
        ]),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/ground-truth-register.test.mjs',
        requiredTextRefs: Object.freeze([
          'glossary',
          'docs/context/EXOCHAIN_GLOSSARY_FOR_CYBERMEDICA.md',
          'productionTrustClaim: false',
          'baselineDevelopmentBlocked: false',
        ]),
      },
    ]),
  },
  {
    contractId: 'glossary_service_contract_doctrine',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/service-contract-publication.mjs',
        requiredTextRefs: Object.freeze([
          'REQUIRED_META_LAYERS',
          'REQUIRED_CONTRACT_KINDS',
          'REQUIRED_CONTEXT_REFS',
          'baseline_service_contracts',
          'fail_closed_boundary',
          'inactive_trust_state',
        ]),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/service-contract-publication.test.mjs',
        requiredTextRefs: Object.freeze([
          'REQUIRED_META_LAYERS',
          'REQUIRED_CONTRACT_KINDS',
          'REQUIRED_CONTEXT_REFS',
          'service_contracts_publishable_inactive_trust',
          'human final authority',
          'safe HLC ordering',
        ]),
      },
    ]),
  },
  {
    contractId: 'glossary_adapter_runtime_boundary',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/trust-adapter.mjs',
        requiredTextRefs: Object.freeze([
          'EXOCHAIN_GATEWAY_SOURCE',
          'EXOCHAIN_NODE_RECEIPT_SOURCE',
          'EXOCHAIN_DECISION_FORUM_SOURCE',
          'TrustState.VERIFIED',
          'human_gate_unverified',
          'quorum_unverified',
          'invariants_unverified',
          'decision_forum_open_challenge',
        ]),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/adapter-fail-closed.test.mjs',
        requiredTextRefs: Object.freeze([
          'receipt_local_simulation_forbidden',
          'gateway_local_simulation_forbidden',
          'quorum_unverified',
          'invariants_unverified',
          'decision_forum_open_challenge',
        ]),
      },
    ]),
  },
  {
    contractId: 'glossary_decision_forum_governance',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/decision-forum-matters.mjs',
        requiredTextRefs: Object.freeze([
          'decision_forum_authority_missing',
          'quorum_unverified',
          'quorum_not_met',
          'challenge_resolution_quorum_unverified',
          'decision_forum_matter',
          'human_gate',
        ]),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/decision-forum-matters.test.mjs',
        requiredTextRefs: Object.freeze([
          'decision_forum_authority_missing',
          'quorum_unverified',
          'quorum_not_met',
          'challenge_resolution_quorum_unverified',
          'decision_forum_matter',
        ]),
      },
    ]),
  },
]);

const EXPECTED_CONFIDENCE_VALUES = new Set(['High', 'Medium', 'Low']);

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

function stripCell(value) {
  return value.trim();
}

function glossaryRowsFromText(text) {
  if (text === null) {
    return [];
  }

  return text
    .split(/\r?\n/u)
    .filter((line) => line.startsWith('|'))
    .map((line) => line.split('|').slice(1, -1).map(stripCell))
    .filter((cells) => cells.length === 8 && cells[0] !== 'Term' && !cells[0].startsWith('---'))
    .map((cells) => ({
      term: cells[0],
      meaning: cells[1],
      sourcePath: cells[2],
      evidenceType: cells[3],
      implementationStatus: cells[4],
      testDocStatus: cells[5],
      confidence: cells[6],
      useRule: cells[7],
    }));
}

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
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

function glossaryFindings(glossaryText) {
  if (glossaryText === null) {
    return [
      {
        ruleId: 'glossary_file_absent',
        pathRef: GLOSSARY_REF,
        metadataOnly: true,
      },
    ];
  }

  const rows = glossaryRowsFromText(glossaryText);
  const observedTerms = uniqueSorted(rows.map((row) => row.term));
  const observedTermSet = new Set(observedTerms);
  const expectedTermSet = new Set(EXPECTED_GLOSSARY_TERMS);

  return [
    ...EXPECTED_GLOSSARY_TERMS.filter((term) => !observedTermSet.has(term)).map((term) => ({
      ruleId: 'glossary_term_absent',
      pathRef: GLOSSARY_REF,
      term,
      metadataOnly: true,
    })),
    ...observedTerms.filter((term) => !expectedTermSet.has(term)).map((term) => ({
      ruleId: 'glossary_term_unexpected',
      pathRef: GLOSSARY_REF,
      term,
      metadataOnly: true,
    })),
    ...rows
      .filter(
        (row) =>
          !hasText(row.meaning) ||
          !hasText(row.sourcePath) ||
          !hasText(row.evidenceType) ||
          !hasText(row.implementationStatus) ||
          !hasText(row.testDocStatus) ||
          !EXPECTED_CONFIDENCE_VALUES.has(row.confidence) ||
          !hasText(row.useRule),
      )
      .map((row) => ({
        ruleId: 'glossary_row_incomplete',
        pathRef: GLOSSARY_REF,
        term: row.term,
        metadataOnly: true,
      })),
    ...textRefFindings(glossaryText, GLOSSARY_REF, REQUIRED_GLOSSARY_TEXT_REFS, 'glossary_required_text_absent'),
  ];
}

function contractTextFindings(rootDir, contractId, pathRef, requiredTextRefs, kind) {
  const text = readProjectFile(rootDir, pathRef);
  if (text === null) {
    return [
      {
        ruleId: `glossary_${kind}_file_absent`,
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
      ruleId: `glossary_${kind}_text_absent`,
      contractId,
      pathRef,
      requiredTextRef,
      metadataOnly: true,
    }));
}

function contractFindings(rootDir) {
  return EXPECTED_GLOSSARY_CONTRACTS.flatMap((contract) => [
    ...contract.sourceContracts.flatMap((sourceContract) =>
      contractTextFindings(rootDir, contract.contractId, sourceContract.pathRef, sourceContract.requiredTextRefs, 'source'),
    ),
    ...contract.testContracts.flatMap((testContract) =>
      contractTextFindings(rootDir, contract.contractId, testContract.pathRef, testContract.requiredTextRefs, 'test'),
    ),
  ]);
}

function compareFindings(left, right) {
  const idCompare = String(left.term ?? left.contractId).localeCompare(String(right.term ?? right.contractId));
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

export function scanGlossaryDoctrineCoverage(rootDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')) {
  const glossaryText = readProjectFile(rootDir, GLOSSARY_REF);
  const glossaryRows = glossaryRowsFromText(glossaryText);
  const checkedSourceRefs = uniqueSorted(
    EXPECTED_GLOSSARY_CONTRACTS.flatMap((contract) =>
      contract.sourceContracts.map((sourceContract) => sourceContract.pathRef),
    ),
  );
  const checkedTestRefs = uniqueSorted(
    EXPECTED_GLOSSARY_CONTRACTS.flatMap((contract) =>
      contract.testContracts.map((testContract) => testContract.pathRef),
    ),
  );
  const findings = [...glossaryFindings(glossaryText), ...contractFindings(rootDir)].sort(compareFindings);

  return {
    schema: 'cybermedica.source_glossary_guard.v1',
    status: findings.length === 0 ? 'passed' : 'failed',
    exitCode: findings.length === 0 ? 0 : 1,
    scannerRef: 'cybermedica-source-glossary-guard',
    scannerVersionHash: sha256Hex(
      [
        EXPECTED_GLOSSARY_TERMS.join('|'),
        REQUIRED_GLOSSARY_TEXT_REFS.join('|'),
        EXPECTED_GLOSSARY_CONTRACTS.map((contract) => {
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
    glossaryRef: GLOSSARY_REF,
    glossaryTerms: uniqueSorted(glossaryRows.map((row) => row.term).filter((term) => EXPECTED_GLOSSARY_TERMS.includes(term))),
    glossaryTermCount: uniqueSorted(
      glossaryRows.map((row) => row.term).filter((term) => EXPECTED_GLOSSARY_TERMS.includes(term)),
    ).length,
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
  const report = scanGlossaryDoctrineCoverage(rootDir);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.exitCode;
}
