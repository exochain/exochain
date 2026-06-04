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
  'package-lock.json',
  'package.json',
  'scripts',
  'src',
  'tests',
]);

const IGNORED_DIR_NAMES = new Set(['.git', '.codex', 'node_modules']);
const SCANNED_EXTENSIONS = new Set(['.json', '.md', '.mjs']);

const SECRET_RULES = Object.freeze([
  {
    ruleId: 'aws_access_key_id',
    severity: 'high',
    pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/gu,
  },
  {
    ruleId: 'github_token',
    severity: 'high',
    pattern: /\bgh[pousr]_[A-Za-z0-9_]{30,}\b/gu,
  },
  {
    ruleId: 'google_api_key',
    severity: 'high',
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/gu,
  },
  {
    ruleId: 'jwt_token',
    severity: 'high',
    pattern: /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/gu,
  },
  {
    ruleId: 'openai_api_key',
    severity: 'high',
    pattern: /\bsk-[A-Za-z0-9]{40,}\b/gu,
  },
  {
    ruleId: 'private_key_block',
    severity: 'critical',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/gu,
  },
  {
    ruleId: 'stripe_live_secret_key',
    severity: 'high',
    pattern: /\bsk_live_[A-Za-z0-9]{24,}\b/gu,
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

export function scanTextForSecretFindings(pathRef, text) {
  const source = typeof text === 'string' ? text : '';
  const findings = [];

  for (const rule of SECRET_RULES) {
    const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);
    for (const match of source.matchAll(pattern)) {
      const matchedValue = match[0];
      findings.push({
        ruleId: rule.ruleId,
        severity: rule.severity,
        pathRef,
        lineNumber: lineNumberForIndex(source, match.index ?? 0),
        matchDigest: sha256Hex(matchedValue),
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
    return scanTextForSecretFindings(pathRef, source);
  });
  const highRiskFindingsCount = findings.filter(
    (finding) => finding.severity === 'critical' || finding.severity === 'high',
  ).length;

  return {
    schema: 'cybermedica.source_secret_scan.v1',
    status: findings.length === 0 ? 'passed' : 'failed',
    exitCode: findings.length === 0 ? 0 : 1,
    scannerRef: 'cybermedica-source-secret-scan',
    scannerVersionHash: sha256Hex(SECRET_RULES.map((rule) => `${rule.ruleId}:${rule.severity}`).join('|')),
    scannedPathRefs,
    scannedFileRefs,
    exochainSourceExcluded: !scannedPathRefs.some(
      (pathRef) => pathRef.startsWith('../exochain') || pathRef.startsWith('/Users/bobstewart/dev/exochain/exochain'),
    ),
    findings,
    findingsCount: findings.length,
    highRiskFindingsCount,
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
