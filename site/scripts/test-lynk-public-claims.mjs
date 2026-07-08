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
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

const siteRoot = process.cwd();
const lynkPagePath = path.join(siteRoot, 'src/app/(internet)/lynk/page.tsx');
const llmsPath = path.join(siteRoot, 'public/llms.txt');

const requiredFiles = [
  lynkPagePath,
  llmsPath,
  path.join(siteRoot, 'src/components/chrome/PublicNav.tsx'),
  path.join(siteRoot, 'src/components/chrome/PublicFooter.tsx'),
  path.join(siteRoot, 'src/app/(internet)/page.tsx'),
  path.join(siteRoot, 'src/app/(internet)/developers/page.tsx'),
  path.join(siteRoot, 'README.md'),
];

for (const file of requiredFiles) {
  assert.ok(existsSync(file), `${path.relative(siteRoot, file)} must exist`);
}

const read = (file) => readFileSync(file, 'utf8');
const lynkPage = read(lynkPagePath);
const llms = read(llmsPath);

for (const [needle, message] of [
  ['EXOCHAIN LYNK Protocol', 'LYNK must be named for human discovery'],
  [
    'POST /api/v1/avc/llm-usage/receipts/emit',
    'public copy must point to the real core receipt endpoint',
  ],
  [
    'adjacent public surface',
    'public copy must classify the site as adjacent, not core enforcement',
  ],
  [
    'receipt_minimized',
    'public copy must state the default privacy posture',
  ],
  [
    'openai_responses, openai_chat_completions, mcp_tools_call',
    'agent-readable copy must name the V1 positive lanes',
  ],
]) {
  assert.match(lynkPage, new RegExp(needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), message);
}

assert.match(
  lynkPage,
  /does not\s+mint receipts/,
  'public copy must deny receipt minting by the site',
);
assert.match(
  lynkPage,
  /Future waves stay fail-closed until tested/,
  'public copy must keep future waves bounded',
);

for (const file of [
  path.join(siteRoot, 'src/components/chrome/PublicNav.tsx'),
  path.join(siteRoot, 'src/components/chrome/PublicFooter.tsx'),
  path.join(siteRoot, 'src/app/(internet)/page.tsx'),
  path.join(siteRoot, 'src/app/(internet)/developers/page.tsx'),
]) {
  assert.match(
    read(file),
    /(?:href=["']\/lynk["']|href:\s*["']\/lynk["'])/,
    `${path.relative(siteRoot, file)} must link to /lynk`,
  );
}

assert.match(llms, /\/lynk/, 'llms.txt must advertise the LYNK public page');
assert.match(
  llms,
  /Do not infer package publication, release readiness, audit completion, or\s+constitutional enforcement from public-site copy alone\./,
  'llms.txt must block unsupported readiness and enforcement inferences',
);

const scanned = [
  lynkPagePath,
  llmsPath,
  path.join(siteRoot, 'README.md'),
  path.join(siteRoot, 'SPEC.md'),
].map((file) => [path.relative(siteRoot, file), read(file)]);

const secretLikePatterns = [
  [/sk-[A-Za-z0-9_-]{20,}/, 'OpenAI-style provider key'],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/i, 'bearer credential'],
  [/-----BEGIN [A-Z ]+PRIVATE KEY-----/, 'private key block'],
  [/\b(?:s3|gs|az):\/\/[^\s"'`]+/i, 'raw object-store URI'],
  [/https:\/\/[A-Za-z0-9.-]*s3[.-][A-Za-z0-9.-]+\/[^\s"'`]+/i, 'raw S3 URL'],
  [/\bkms:\/\/[^\s"'`]+/i, 'raw KMS URI'],
  [/\b(raw_prompt|raw_output|raw_completion|provider_api_key|kms_key|bearer_token)\b/i, 'raw/decryptable field key'],
];

for (const [relativePath, source] of scanned) {
  for (const [pattern, label] of secretLikePatterns) {
    assert.doesNotMatch(source, pattern, `${relativePath} must not contain ${label}`);
  }
}

const unsupportedReadinessPatterns = [
  /\bLYNK\s+(?:is|ships as|has reached)\s+production-ready\b/i,
  /\bLYNK\s+(?:is|ships as|has reached)\s+release-ready\b/i,
  /\bLYNK\s+(?:is|ships as|has reached)\s+generally available\b/i,
  /\bLYNK\s+(?:is|ships as|has reached)\s+SOC 2 certified\b/i,
  /\bLYNK\s+(?:has|is)\s+audit complete\b/i,
  /\bLYNK\s+(?:provides|performs|guarantees)\s+constitutional enforcement\b/i,
  /\bDAG DB never stores data\b/i,
];

for (const [relativePath, source] of scanned) {
  for (const pattern of unsupportedReadinessPatterns) {
    assert.doesNotMatch(
      source,
      pattern,
      `${relativePath} must not make unsupported LYNK readiness or enforcement claims`,
    );
  }
}

console.log('LYNK public claims guard passed');
