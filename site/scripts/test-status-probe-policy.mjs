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
const read = (file) => readFileSync(file, 'utf8');

const readme = read(path.join(siteRoot, 'README.md'));
const probe = read(path.join(siteRoot, 'src/components/status/LiveGatewayProbe.tsx'));
const loader = read(path.join(siteRoot, 'src/lib/public-status.ts'));
const statusPage = read(path.join(siteRoot, 'src/app/(internet)/status/page.tsx'));
const canonical = path.resolve(siteRoot, '../crates/exo-node/src/public-status.json');
const nodePage = path.resolve(siteRoot, '../crates/exo-node/src/public_status.rs');

assert.equal(
  existsSync(path.join(siteRoot, 'src/data/public-status.json')),
  false,
  'site must not keep a second copy of the status facts',
);
assert.ok(existsSync(canonical), 'node package must contain public-status.json');
JSON.parse(read(canonical));

assert.match(
  loader,
  /CANONICAL_PUBLIC_STATUS_PATH = '\.\.\/crates\/exo-node\/src\/public-status\.json'/,
  'site must read the node-packaged status facts',
);
assert.match(statusPage, /loadPublicStatus\(/, 'status page must load the canonical facts');
assert.match(statusPage, /<LiveGatewayProbe/, 'status page must mount the live probe');

for (const needle of [
  '## Status probe intake',
  'Trust boundary:',
  'Secrets / runtime configuration:',
  'npm run security:status-probe',
  'Rollback / disablement:',
]) {
  assert.ok(readme.includes(needle), `site README intake must include ${needle}`);
}

assert.match(probe, /new AbortController\(\)/, 'each probe must be abortable');
assert.match(probe, /PROBE_TIMEOUT_MS = 5000/, 'each probe must use a bounded timeout');
assert.match(probe, /readProbe\(path, controller\.signal\)/, 'fetch must receive the abort signal');
assert.match(probe, /setTimeout\(\(\) => controller\.abort\(\), PROBE_TIMEOUT_MS\)/);
assert.match(probe, /setProbes\(\(current\) =>/, 'each settled probe must render on its own');
assert.doesNotMatch(probe, /setText\(/, 'probes must not wait for one combined write');
assert.doesNotMatch(probe, /innerHTML/, 'probe text must not be parsed as HTML');

const nodeSource = read(nodePage);
assert.match(
  nodeSource,
  /include_str!\("public-status\.json"\)/,
  'node status facts must be packaged inside exochain-node',
);
assert.doesNotMatch(
  nodeSource,
  /site\/src\/data\/public-status\.json/,
  'node must not compile against the adjacent site tree',
);

console.log('status probe policy guard passed');
