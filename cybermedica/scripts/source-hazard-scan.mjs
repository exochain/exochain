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
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const DEFAULT_SCANNED_PATH_REFS = Object.freeze([
  'README.md',
  'docs/context',
  'docs/implementation',
  'package.json',
  'scripts',
  'src',
  'tests',
]);

const IGNORED_DIR_NAMES = new Set(['.git', '.codex', 'node_modules']);
const SCANNED_EXTENSIONS = new Set(['.json', '.mjs']);

const SOURCE_HAZARD_RULES = Object.freeze([
  {
    ruleId: 'system_time_source',
    pattern: /\b(?:Date\s*\.\s*now|new\s+Date|performance\s*\.\s*now|process\s*\.\s*hrtime)\b/gu,
  },
  {
    ruleId: 'randomness_source',
    pattern: /\b(?:Math\s*\.\s*random|crypto\s*\.\s*randomUUID|randomUUID\s*\()/gu,
  },
  {
    ruleId: 'floating_point_literal',
    pattern: /(?<![\w$])(?:\d+\.\d+|\.\d+)(?![\w$])/gu,
  },
  {
    ruleId: 'floating_point_api',
    pattern: /\b(?:parseFloat|Float32Array|Float64Array|Math\s*\.\s*fround|Number\s*\.\s*EPSILON)\b/gu,
  },
  {
    ruleId: 'dynamic_code_execution',
    pattern: /\b(?:eval|Function\s*\()\b/gu,
  },
  {
    ruleId: 'unbounded_while_loop',
    pattern: /\bwhile\s*\(\s*true\s*\)/gu,
  },
  {
    ruleId: 'unbounded_for_loop',
    pattern: /\bfor\s*\(\s*;\s*;\s*\)/gu,
  },
]);

function sha256Hex(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function extensionOf(pathRef) {
  const dotIndex = pathRef.lastIndexOf('.');
  return dotIndex === -1 ? '' : pathRef.slice(dotIndex);
}

function hasParentOrAbsolutePathRef(pathRef) {
  return (
    typeof pathRef !== 'string' ||
    pathRef.length === 0 ||
    pathRef.startsWith('/') ||
    pathRef.startsWith('..') ||
    pathRef.includes('/../') ||
    pathRef.includes('\\')
  );
}

function toProjectPath(rootDir, absolutePath) {
  return absolutePath.slice(resolve(rootDir).length + 1);
}

function listScannableFiles(rootDir, pathRef) {
  if (hasParentOrAbsolutePathRef(pathRef)) {
    return [];
  }

  const absolutePath = resolve(rootDir, pathRef);
  if (!existsSync(absolutePath)) {
    return [];
  }

  const stats = statSync(absolutePath);
  if (stats.isFile()) {
    return SCANNED_EXTENSIONS.has(extensionOf(pathRef)) ? [pathRef] : [];
  }
  if (!stats.isDirectory()) {
    return [];
  }

  return readdirSync(absolutePath, { withFileTypes: true })
    .sort((left, right) => left.name.localeCompare(right.name))
    .flatMap((entry) => {
      if (entry.isDirectory() && IGNORED_DIR_NAMES.has(entry.name)) {
        return [];
      }
      const nestedAbsolutePath = join(absolutePath, entry.name);
      const nestedProjectPath = toProjectPath(rootDir, nestedAbsolutePath);
      if (entry.isDirectory()) {
        return listScannableFiles(rootDir, nestedProjectPath);
      }
      if (!entry.isFile() || !SCANNED_EXTENSIONS.has(extensionOf(nestedProjectPath))) {
        return [];
      }
      return [nestedProjectPath];
    });
}

function lineNumberForIndex(text, index) {
  let lineNumber = 1;
  for (let cursor = 0; cursor < index; cursor += 1) {
    if (text.charCodeAt(cursor) === 10) {
      lineNumber += 1;
    }
  }
  return lineNumber;
}

function writeMasked(masked, source, start, end) {
  for (let index = start; index < end; index += 1) {
    masked[index] = source.charCodeAt(index) === 10 ? '\n' : ' ';
  }
}

function previousNonSpace(source, cursor) {
  for (let index = cursor - 1; index >= 0; index -= 1) {
    const char = source[index];
    if (!/\s/u.test(char)) {
      return char;
    }
  }
  return '';
}

function previousWord(source, cursor) {
  let index = cursor - 1;
  while (index >= 0 && /\s/u.test(source[index])) {
    index -= 1;
  }
  let end = index + 1;
  while (index >= 0 && /[A-Za-z_$]/u.test(source[index])) {
    index -= 1;
  }
  return source.slice(index + 1, end);
}

function startsRegexLiteral(source, cursor) {
  const previous = previousNonSpace(source, cursor);
  if (previous === '') {
    return true;
  }
  if ('=(:,[!&|?{};'.includes(previous)) {
    return true;
  }
  return previousWord(source, cursor) === 'return';
}

function maskQuoted(source, masked, cursor, quote) {
  let index = cursor + 1;
  let escaped = false;
  while (index < source.length) {
    const char = source[index];
    if (escaped) {
      escaped = false;
      index += 1;
      continue;
    }
    if (char === '\\') {
      escaped = true;
      index += 1;
      continue;
    }
    if (char === quote) {
      index += 1;
      break;
    }
    index += 1;
  }
  writeMasked(masked, source, cursor, index);
  return index;
}

function maskTemplate(source, masked, cursor) {
  let index = cursor + 1;
  let escaped = false;
  while (index < source.length) {
    const char = source[index];
    if (escaped) {
      escaped = false;
      index += 1;
      continue;
    }
    if (char === '\\') {
      escaped = true;
      index += 1;
      continue;
    }
    if (char === '`') {
      index += 1;
      break;
    }
    index += 1;
  }
  writeMasked(masked, source, cursor, index);
  return index;
}

function maskRegex(source, masked, cursor) {
  let index = cursor + 1;
  let escaped = false;
  let inCharacterClass = false;
  while (index < source.length) {
    const char = source[index];
    if (escaped) {
      escaped = false;
      index += 1;
      continue;
    }
    if (char === '\\') {
      escaped = true;
      index += 1;
      continue;
    }
    if (char === '[') {
      inCharacterClass = true;
      index += 1;
      continue;
    }
    if (char === ']') {
      inCharacterClass = false;
      index += 1;
      continue;
    }
    if (char === '/' && !inCharacterClass) {
      index += 1;
      while (index < source.length && /[a-z]/iu.test(source[index])) {
        index += 1;
      }
      break;
    }
    if (char === '\n') {
      break;
    }
    index += 1;
  }
  writeMasked(masked, source, cursor, index);
  return index;
}

function executableSourceView(source) {
  const material = typeof source === 'string' ? source : '';
  const masked = [...material];
  let cursor = 0;

  while (cursor < material.length) {
    const char = material[cursor];
    const next = material[cursor + 1] ?? '';

    if (char === '/' && next === '/') {
      let end = cursor + 2;
      while (end < material.length && material[end] !== '\n') {
        end += 1;
      }
      writeMasked(masked, material, cursor, end);
      cursor = end;
      continue;
    }

    if (char === '/' && next === '*') {
      let end = cursor + 2;
      while (end < material.length && !(material[end] === '*' && material[end + 1] === '/')) {
        end += 1;
      }
      end = Math.min(end + 2, material.length);
      writeMasked(masked, material, cursor, end);
      cursor = end;
      continue;
    }

    if (char === '"' || char === "'") {
      cursor = maskQuoted(material, masked, cursor, char);
      continue;
    }

    if (char === '`') {
      cursor = maskTemplate(material, masked, cursor);
      continue;
    }

    if (char === '/' && startsRegexLiteral(material, cursor)) {
      cursor = maskRegex(material, masked, cursor);
      continue;
    }

    cursor += 1;
  }

  return masked.join('');
}

export function scanTextForSourceHazards(pathRef, text) {
  const source = typeof text === 'string' ? text : '';
  const executable = executableSourceView(source);
  const findings = [];

  for (const rule of SOURCE_HAZARD_RULES) {
    const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);
    for (const match of executable.matchAll(pattern)) {
      findings.push({
        ruleId: rule.ruleId,
        severity: 'high',
        pathRef,
        lineNumber: lineNumberForIndex(executable, match.index ?? 0),
        matchDigest: sha256Hex(`${rule.ruleId}:${match[0]}`),
        metadataOnly: true,
      });
    }
  }

  return findings.sort((left, right) => {
    const pathCompare = left.pathRef.localeCompare(right.pathRef);
    if (pathCompare !== 0) {
      return pathCompare;
    }
    if (left.lineNumber !== right.lineNumber) {
      return left.lineNumber - right.lineNumber;
    }
    return left.ruleId.localeCompare(right.ruleId);
  });
}

export function scanPathRefs(rootDir = process.cwd(), pathRefs = DEFAULT_SCANNED_PATH_REFS) {
  const scannedPathRefs = [...new Set(pathRefs)].sort();
  const scannedFileRefs = [...new Set(scannedPathRefs.flatMap((pathRef) => listScannableFiles(rootDir, pathRef)))].sort();
  const findings = scannedFileRefs.flatMap((pathRef) => {
    const source = readFileSync(resolve(rootDir, pathRef), 'utf8');
    return scanTextForSourceHazards(pathRef, source);
  });

  return {
    schema: 'cybermedica.source_hazard_scan.v1',
    status: findings.length === 0 ? 'passed' : 'failed',
    exitCode: findings.length === 0 ? 0 : 1,
    scannerRef: 'cybermedica-source-hazard-scan',
    scannerVersionHash: sha256Hex(SOURCE_HAZARD_RULES.map((rule) => rule.ruleId).join('|')),
    scannedPathRefs,
    scannedFileRefs,
    exochainSourceExcluded: !scannedPathRefs.some(
      (pathRef) => pathRef.startsWith('../exochain') || pathRef.startsWith('/Users/bobstewart/dev/exochain/exochain'),
    ),
    deterministicHazardsAbsent: findings.length === 0,
    findings,
    findingsCount: findings.length,
    metadataOnly: true,
  };
}

const invokedPath = process.argv[1] === undefined ? '' : resolve(process.argv[1]);
const modulePath = fileURLToPath(import.meta.url);

if (invokedPath === modulePath) {
  const rootDir = resolve(dirname(modulePath), '..');
  const report = scanPathRefs(rootDir);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.exitCode;
}
