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

const OPEN_QUESTION_REGISTER_REF = 'docs/context/EXOCHAIN_OPEN_QUESTIONS_FOR_BOB.md';
const COUNCIL_REVIEW_DEFAULTS_REF = 'docs/context/EXOCHAIN_COUNCIL_REVIEW_FOR_CYBERMEDICA_OPEN_QUESTIONS.md';
const COUNCIL_ESCALATION_REGISTER_REF = 'docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md';

const EXPECTED_OPEN_QUESTION_IDS = Object.freeze([
  'ADJ-001',
  'ADJ-002',
  'ADJ-003',
  'ADJ-004',
  'ADJ-005',
  'CONSENT-001',
  'CONSENT-002',
  'CONSENT-003',
  'DF-001',
  'DF-002',
  'DF-003',
  'DF-004',
  'DF-005',
  'ID-001',
  'ID-002',
  'ID-003',
  'ID-004',
  'ID-005',
  'PRIV-001',
  'PRIV-002',
  'ROOT-001',
  'ROOT-002',
  'ROOT-003',
  'ROOT-004',
  'ROOT-005',
  'RT-001',
  'RT-002',
  'RT-003',
  'RT-004',
  'RT-005',
]);

const EXPECTED_NARROWED_ESCALATION_IDS = Object.freeze([
  'ESC-CONSENT-LEGAL',
  'ESC-HUMAN-PROOFING',
  'ESC-OPS-SECRETS',
  'ESC-OPTIONAL-ADJACENT',
  'ESC-ROLE-MATRIX',
  'ESC-ROOT-ARTIFACT-STORE',
  'ESC-ROOT-DEPLOYMENT',
  'ESC-ROOT-OWNER',
  'ESC-ROOT-ROSTER',
  'ESC-RUNTIME',
]);

const REQUIRED_COUNCIL_REVIEW_TEXT_REFS = Object.freeze([
  'Baseline development must proceed using the consensus defaults below.',
  'Production Exochain/root-backed trust claims remain gated',
  'Only these non-consensus items should be escalated to Bob in conversation.',
]);

const REQUIRED_OPEN_QUESTION_REGISTER_TEXT_REFS = Object.freeze([
  'Do not treat this file as the current Bob escalation list.',
  'These questions do not block baseline development',
]);

const EXPECTED_OPEN_QUESTION_CONTRACTS = Object.freeze([
  {
    contractId: 'open_question_register_contract',
    sourceContracts: Object.freeze([
      {
        pathRef: 'src/open-question-register.mjs',
        requiredTextRefs: Object.freeze([
          'REQUIRED_QUESTION_FAMILIES',
          'ALLOWED_BOB_ESCALATION_IDS',
          'councilDefaultsRequired',
          'blocksBaselineDevelopment',
          'productionActivationOnly',
          'productionTrustClaim === true',
        ]),
      },
      {
        pathRef: 'src/ground-truth-register.mjs',
        requiredTextRefs: Object.freeze([
          'DEFAULT_BOB_ESCALATION_IDS',
          'baselineDevelopmentBlocked',
          'narrowedEscalationRegisterRef',
          'narrowedEscalationIds',
          'productionTrustClaim === true',
        ]),
      },
    ]),
    testContracts: Object.freeze([
      {
        pathRef: 'tests/open-question-register.test.mjs',
        requiredTextRefs: Object.freeze([
          'open question register creates deterministic visible inactive-trust records',
          'bob_escalation_not_allowed',
          'open_question_blocks_baseline',
          'open_question_escalation_not_activation_only',
          'productionTrustClaim',
        ]),
      },
      {
        pathRef: 'tests/ground-truth-register.test.mjs',
        requiredTextRefs: Object.freeze([
          'ground truth register permits deterministic metadata-only context source basis',
          'baseline_development_blocked_by_open_questions',
          'narrowedEscalationRegisterRef',
          'ESC-OPTIONAL-ADJACENT',
          'productionTrustClaim',
        ]),
      },
    ]),
  },
]);

const OPEN_QUESTION_ID_RE = /\b(?:ADJ|CONSENT|DF|ID|PRIV|ROOT|RT)-\d{3}\b/gu;
const ESCALATION_ID_RE = /\bESC-[A-Z0-9-]+\b/gu;

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

function idsFromText(text, pattern) {
  return uniqueSorted([...text.matchAll(pattern)].map((match) => match[0]));
}

function openQuestionIdsFromText(text) {
  return idsFromText(text, OPEN_QUESTION_ID_RE);
}

function escalationIdsFromText(text) {
  return idsFromText(text, ESCALATION_ID_RE);
}

function missingExpectedIdFindings(observedIds, expectedIds, ruleId, pathRef, idKey) {
  const observedSet = new Set(observedIds);
  return expectedIds
    .filter((id) => !observedSet.has(id))
    .map((id) => ({
      ruleId,
      [idKey]: id,
      pathRef,
      metadataOnly: true,
    }));
}

function unexpectedIdFindings(observedIds, expectedIds, ruleId, pathRef, idKey) {
  const expectedSet = new Set(expectedIds);
  return observedIds
    .filter((id) => !expectedSet.has(id))
    .map((id) => ({
      ruleId,
      [idKey]: id,
      pathRef,
      metadataOnly: true,
    }));
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

function openQuestionRegisterFindings(registerText) {
  if (registerText === null) {
    return [
      {
        ruleId: 'open_question_register_file_absent',
        openQuestionId: null,
        pathRef: OPEN_QUESTION_REGISTER_REF,
        metadataOnly: true,
      },
    ];
  }

  const observedIds = openQuestionIdsFromText(registerText);
  return [
    ...missingExpectedIdFindings(
      observedIds,
      EXPECTED_OPEN_QUESTION_IDS,
      'open_question_id_absent',
      OPEN_QUESTION_REGISTER_REF,
      'openQuestionId',
    ),
    ...unexpectedIdFindings(
      observedIds,
      EXPECTED_OPEN_QUESTION_IDS,
      'open_question_id_unexpected',
      OPEN_QUESTION_REGISTER_REF,
      'openQuestionId',
    ),
    ...textRefFindings(
      registerText,
      OPEN_QUESTION_REGISTER_REF,
      REQUIRED_OPEN_QUESTION_REGISTER_TEXT_REFS,
      'open_question_register_text_absent',
    ),
  ];
}

function councilReviewFindings(reviewText) {
  if (reviewText === null) {
    return [
      {
        ruleId: 'open_question_council_review_file_absent',
        pathRef: COUNCIL_REVIEW_DEFAULTS_REF,
        metadataOnly: true,
      },
    ];
  }

  const reviewQuestionIds = openQuestionIdsFromText(reviewText);
  const reviewEscalationIds = escalationIdsFromText(reviewText);
  return [
    ...missingExpectedIdFindings(
      reviewQuestionIds,
      EXPECTED_OPEN_QUESTION_IDS,
      'open_question_council_review_id_absent',
      COUNCIL_REVIEW_DEFAULTS_REF,
      'openQuestionId',
    ),
    ...unexpectedIdFindings(
      reviewQuestionIds,
      EXPECTED_OPEN_QUESTION_IDS,
      'open_question_council_review_id_unexpected',
      COUNCIL_REVIEW_DEFAULTS_REF,
      'openQuestionId',
    ),
    ...missingExpectedIdFindings(
      reviewEscalationIds,
      EXPECTED_NARROWED_ESCALATION_IDS,
      'open_question_council_review_escalation_id_absent',
      COUNCIL_REVIEW_DEFAULTS_REF,
      'escalationId',
    ),
    ...unexpectedIdFindings(
      reviewEscalationIds,
      EXPECTED_NARROWED_ESCALATION_IDS,
      'open_question_council_review_escalation_id_unexpected',
      COUNCIL_REVIEW_DEFAULTS_REF,
      'escalationId',
    ),
    ...textRefFindings(
      reviewText,
      COUNCIL_REVIEW_DEFAULTS_REF,
      REQUIRED_COUNCIL_REVIEW_TEXT_REFS,
      'open_question_council_review_text_absent',
    ),
  ];
}

function escalationRegisterFindings(escalationRegisterText) {
  if (escalationRegisterText === null) {
    return [
      {
        ruleId: 'open_question_escalation_register_file_absent',
        escalationId: null,
        pathRef: COUNCIL_ESCALATION_REGISTER_REF,
        metadataOnly: true,
      },
    ];
  }

  const registerEscalationIds = escalationIdsFromText(escalationRegisterText);
  return [
    ...missingExpectedIdFindings(
      registerEscalationIds,
      EXPECTED_NARROWED_ESCALATION_IDS,
      'open_question_escalation_id_absent',
      COUNCIL_ESCALATION_REGISTER_REF,
      'escalationId',
    ),
    ...unexpectedIdFindings(
      registerEscalationIds,
      EXPECTED_NARROWED_ESCALATION_IDS,
      'open_question_escalation_id_unexpected',
      COUNCIL_ESCALATION_REGISTER_REF,
      'escalationId',
    ),
  ];
}

function contractTextFindings(rootDir, contractId, pathRef, requiredTextRefs, kind) {
  const text = readProjectFile(rootDir, pathRef);
  if (text === null) {
    return [
      {
        ruleId: `open_question_${kind}_file_absent`,
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
      ruleId: `open_question_${kind}_text_absent`,
      contractId,
      pathRef,
      requiredTextRef,
      metadataOnly: true,
    }));
}

function contractFindings(rootDir) {
  return EXPECTED_OPEN_QUESTION_CONTRACTS.flatMap((contract) => [
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
  const idCompare = String(left.openQuestionId ?? left.escalationId ?? left.contractId).localeCompare(
    String(right.openQuestionId ?? right.escalationId ?? right.contractId),
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

export function scanOpenQuestionCoverage(rootDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')) {
  const openQuestionRegisterText = readProjectFile(rootDir, OPEN_QUESTION_REGISTER_REF);
  const councilReviewText = readProjectFile(rootDir, COUNCIL_REVIEW_DEFAULTS_REF);
  const escalationRegisterText = readProjectFile(rootDir, COUNCIL_ESCALATION_REGISTER_REF);

  const openQuestionIds =
    openQuestionRegisterText === null
      ? []
      : openQuestionIdsFromText(openQuestionRegisterText).filter((id) => EXPECTED_OPEN_QUESTION_IDS.includes(id));
  const narrowedEscalationIds =
    councilReviewText === null
      ? []
      : escalationIdsFromText(councilReviewText).filter((id) => EXPECTED_NARROWED_ESCALATION_IDS.includes(id));
  const checkedSourceRefs = uniqueSorted(
    EXPECTED_OPEN_QUESTION_CONTRACTS.flatMap((contract) =>
      contract.sourceContracts.map((sourceContract) => sourceContract.pathRef),
    ),
  );
  const checkedTestRefs = uniqueSorted(
    EXPECTED_OPEN_QUESTION_CONTRACTS.flatMap((contract) =>
      contract.testContracts.map((testContract) => testContract.pathRef),
    ),
  );
  const findings = [
    ...openQuestionRegisterFindings(openQuestionRegisterText),
    ...councilReviewFindings(councilReviewText),
    ...escalationRegisterFindings(escalationRegisterText),
    ...contractFindings(rootDir),
  ].sort(compareFindings);

  return {
    schema: 'cybermedica.source_open_question_guard.v1',
    status: findings.length === 0 ? 'passed' : 'failed',
    exitCode: findings.length === 0 ? 0 : 1,
    scannerRef: 'cybermedica-source-open-question-guard',
    scannerVersionHash: sha256Hex(
      [
        EXPECTED_OPEN_QUESTION_IDS.join(','),
        EXPECTED_NARROWED_ESCALATION_IDS.join(','),
        EXPECTED_OPEN_QUESTION_CONTRACTS.map((contract) => {
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
    openQuestionRegisterRef: OPEN_QUESTION_REGISTER_REF,
    councilReviewDefaultsRef: COUNCIL_REVIEW_DEFAULTS_REF,
    councilEscalationRegisterRef: COUNCIL_ESCALATION_REGISTER_REF,
    openQuestionIds,
    openQuestionCount: openQuestionIds.length,
    narrowedEscalationIds,
    narrowedEscalationCount: narrowedEscalationIds.length,
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
  const report = scanOpenQuestionCoverage(rootDir);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.exitCode;
}
