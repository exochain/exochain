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
import path from 'node:path';

const siteRoot = process.cwd();

function walk(dir) {
  const files = [];
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) {
      files.push(...walk(full));
    } else if (/\.(tsx|ts|mjs|txt|md)$/.test(entry)) {
      files.push(full);
    }
  }
  return files;
}

const srcFiles = walk(path.join(siteRoot, 'src'));
const publicCopy = [
  'src/app/(internet)/page.tsx',
  'src/app/(internet)/why/page.tsx',
  'src/app/(internet)/proof-of-authority/page.tsx',
  'src/app/(internet)/standards/page.tsx',
  'src/app/(internet)/developers/page.tsx',
  'src/app/(internet)/ecosystem/page.tsx',
  'src/app/(internet)/engagement/page.tsx',
  'src/app/(internet)/contact/page.tsx',
  'src/components/chrome/PublicFooter.tsx',
  'src/components/chrome/PublicNav.tsx',
  'src/components/commercial/IllustrativeCalls.tsx',
  'src/lib/public-site.ts',
  'public/llms.txt',
].map((relative) => [relative, readFileSync(path.join(siteRoot, relative), 'utf8')]);

const joined = publicCopy.map(([, source]) => source).join('\n');

for (const needle of [
  'Proven Agentic Action Authority',
  'Every agent action carries proof of who authorized it, the limits it ran under, and AI guarding with an E-STOP that fails closed.',
  "When an agent acts on your behalf, don't get left holding the bag.",
  'E-STOP is a current platform capability. Revocation, policy deny, and fail-closed gates stop an action that is outside authority.',
  'Proof of Authority',
  'working category concept',
  'not a new cryptographic primitive',
  'not an industry standard',
  'Illustrative API design — not the current EXOCHAIN SDK',
  'Payment authorization is not legitimate decision-making authority',
  'design-partner pilot',
  'v0.2.7',
  'v2.2',
  'Apache-2.0',
  'MCP',
  'A2A',
  'x402',
  'AP2',
  'CrossChecked',
  'AI-SDLC Institute',
  'EXOCHAIN PBC',
  'legal@exochain.com',
  'https://exochain.com',
  'exochain.ai',
  'exochain.net',
  'Pilot or implementation',
  'Platform licensing',
  'Managed governance services',
]) {
  assert.ok(joined.includes(needle), `public commercial copy must include ${needle}`);
}

for (const [relative, source] of publicCopy) {
  assert.doesNotMatch(
    source,
    /trust layer, not the empire/i,
    `${relative} must not publish the internal trust-layer line`,
  );
  assert.doesNotMatch(source, /\balpha\b/i, `${relative} must not say alpha`);
  assert.doesNotMatch(source, /production-certified/i, `${relative} must not say production-certified`);
  assert.doesNotMatch(source, /generally available/i, `${relative} must not say generally available`);
  assert.doesNotMatch(source, /\$\s?\d/, `${relative} must not publish prices`);
  for (const name of ['Palantir', 'Gartner', 'Workday', 'NetSuite', 'Accenture', 'MuleSoft']) {
    assert.doesNotMatch(source, new RegExp(name, 'i'), `${relative} must not name ${name}`);
  }
}

assert.match(
  readFileSync(path.join(siteRoot, 'src/app/(internet)/engagement/page.tsx'), 'utf8'),
  /does not include insurance, bonding, or assurance coverage/,
  'engagement page must refuse coverage claims',
);

for (const file of srcFiles) {
  const relative = path.relative(siteRoot, file);
  const source = readFileSync(file, 'utf8');
  assert.doesNotMatch(source, /\balpha\b/i, `${relative} must not say alpha`);
}

for (const relative of [
  'src/components/chrome/PublicNav.tsx',
  'src/components/chrome/PublicFooter.tsx',
  'src/app/(internet)/page.tsx',
  'src/app/(internet)/developers/page.tsx',
]) {
  assert.match(
    readFileSync(path.join(siteRoot, relative), 'utf8'),
    /(?:href=["']\/lynk["']|href:\s*["']\/lynk["'])/,
    `${relative} must link to /lynk`,
  );
}

console.log('commercial public claims guard passed');
