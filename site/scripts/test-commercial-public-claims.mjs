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
  'src/components/commercial/PilotBanner.tsx',
  'src/lib/public-site.ts',
  'public/llms.txt',
].map((relative) => [relative, readFileSync(path.join(siteRoot, relative), 'utf8')]);

const joined = publicCopy.map(([, source]) => source).join('\n').replace(/\s+/g, ' ');

for (const needle of [
  'Proven Agentic Action Authority',
  'Make autonomous commerce accountable.',
  'Explore enterprise deployment',
  'E-STOP',
  'Proof of Authority',
  'working category concept',
  'not a new cryptographic primitive',
  'not an industry standard',
  'Payment authorization is not legitimate decision-making authority',
  'Agree and entrust',
  'payment evidence',
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
  'Enterprise deployment',
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

const engagement = readFileSync(
  path.join(siteRoot, 'src/app/(internet)/engagement/page.tsx'), 'utf8',
).replace(/\s+/g, ' ');
assert.match(engagement, /EXOCHAIN is not the insurer, surety, or reinsurer/);
assert.match(engagement, /Coverage requires a separately issued provider instrument/);
assert.match(engagement, /never automatic/);
assert.match(engagement, /does not move funds/);
assert.match(engagement, /id="assurance"/, 'assurance links must resolve');

// Release facts must follow the canonical publication record, including a
// future approved GA record. A site-copy edit cannot grant release readiness.
for (const relative of [
  'src/app/(internet)/page.tsx',
  'src/app/(internet)/developers/page.tsx',
  'src/app/(internet)/docs/faq/page.tsx',
  'src/app/(internet)/status/page.tsx',
  'src/app/(internet)/trust-center/page.tsx',
  'src/app/(internet)/legal/terms/page.tsx',
  'src/components/chrome/PublicFooter.tsx',
]) {
  const source = readFileSync(path.join(siteRoot, relative), 'utf8');
  assert.match(source, /loadPublicStatus\(/, `${relative} must use canonical release facts`);
}

const publicSurfaces = [
  ...walk(path.join(siteRoot, 'src/app/(internet)')),
  path.join(siteRoot, 'src/components/chrome/PublicFooter.tsx'),
  path.join(siteRoot, 'src/lib/public-site.ts'),
  path.join(siteRoot, 'public/llms.txt'),
];
for (const file of publicSurfaces) {
  const source = readFileSync(file, 'utf8');
  assert.doesNotMatch(source, /\bv?0\.2\.7\b/, `${file} must not freeze the old release in copy`);
  assert.doesNotMatch(source, /EXOCHAIN is in beta/, `${file} must not assign maturity outside the release record`);
  assert.doesNotMatch(source, /exochain\.(verify|attest)\(/, `${file} must not advertise fictional SDK calls`);
}

const contact = readFileSync(path.join(siteRoot, 'src/app/(internet)/contact/page.tsx'), 'utf8');
assert.match(contact, /id="deployment"/, 'enterprise CTAs must resolve');
assert.match(contact, /id="pilot"/, 'existing inbound pilot links must keep resolving');
const banner = readFileSync(path.join(siteRoot, 'src/components/commercial/PilotBanner.tsx'), 'utf8');
assert.match(banner, /id="pilot"/, 'existing page-level pilot links must keep resolving');

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
