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
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { test } from 'node:test';

const root = resolve(import.meta.dirname, '..');
const testedAliases = new Map([
  [
    'trust-adapter.mjs',
    [
      'adapter-fail-closed.test.mjs',
      'production-trust-activation.test.mjs',
    ],
  ],
]);

function readProjectFile(path) {
  return readFileSync(resolve(root, path), 'utf8');
}

function listFiles(dir) {
  const absolute = resolve(root, dir);
  const entries = readdirSync(absolute, { withFileTypes: true });
  return entries.flatMap((entry) => {
    const fullPath = join(absolute, entry.name);
    const projectPath = fullPath.slice(root.length + 1);
    if (entry.isDirectory()) {
      return listFiles(projectPath);
    }
    return statSync(fullPath).isFile() ? [projectPath] : [];
  });
}

test('CyberMedica package exposes focused test and coverage gates', () => {
  const pkg = JSON.parse(readProjectFile('package.json'));

  assert.equal(pkg.private, true);
  assert.equal(pkg.type, 'module');
  assert.equal(pkg.scripts.test, 'node --test tests/*.test.mjs');
  assert.equal(pkg.scripts['test:coverage'], 'node --experimental-test-coverage --test tests/*.test.mjs');
  assert.equal(pkg.scripts.quality, 'npm run test && npm run test:coverage');
});

test('source files avoid deterministic runtime hazards and placeholder language', () => {
  for (const path of listFiles('src')) {
    const source = readProjectFile(path);
    assert.doesNotMatch(source, /\bDate\.now\b|\bnew Date\b|\bMath\.random\b|\bcrypto\.randomUUID\b/u, path);
    assert.doesNotMatch(source, /\bTODO\b|\bstub\b|\bmock\b|\bfuture phase\b/iu, path);
    assert.doesNotMatch(source, /root-backed production authority/iu, path);
  }
});

test('adjacent surface intake has concrete CyberMedica gates', () => {
  const intake = readProjectFile('docs/context/CYBERMEDICA_ADJACENT_SURFACE_DECISIONS.md');

  assert.doesNotMatch(intake, /To be defined when CyberMedica stack is initialized/i);
  assert.match(intake, /npm test/);
  assert.match(intake, /npm run test:coverage/);
  assert.match(intake, /node --test tests\/\*\.test\.mjs/);
});

test('implemented contracts stay documented classified and covered by tests', () => {
  const readme = readProjectFile('README.md');
  const pathClassification = readProjectFile('docs/implementation/PATH_CLASSIFICATION.md');
  const testFiles = new Set(readdirSync(resolve(root, 'tests')).filter((entry) => entry.endsWith('.test.mjs')));

  for (const sourcePath of listFiles('src').filter((path) => path.endsWith('.mjs')).sort()) {
    const sourceFile = sourcePath.slice('src/'.length);
    const sameNameTest = sourceFile.replace(/\.mjs$/u, '.test.mjs');
    const acceptedTests = testedAliases.get(sourceFile) ?? [sameNameTest];

    assert.match(readme, new RegExp(`\\\`src/${sourceFile}\\\``), `${sourcePath} missing README contract row`);
    assert.match(
      pathClassification,
      new RegExp(`/src/${sourceFile}\\\``),
      `${sourcePath} missing path-classification source row`,
    );

    for (const testFile of acceptedTests) {
      assert.ok(testFiles.has(testFile), `${sourcePath} expected test file ${testFile}`);
      assert.match(
        pathClassification,
        new RegExp(`/tests/${testFile}\\\``),
        `${sourcePath} missing path-classification test row for ${testFile}`,
      );
    }
  }
});
