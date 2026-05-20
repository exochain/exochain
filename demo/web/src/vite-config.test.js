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

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const webSrcDir = path.dirname(fileURLToPath(import.meta.url));
const demoRoot = path.resolve(webSrcDir, '..', '..');

function readDemoFile(relativePath) {
  return fs.readFileSync(path.join(demoRoot, relativePath), 'utf8');
}

function gatewayDefaultPort() {
  const source = readDemoFile('services/gateway-api/src/index.js');
  const match = source.match(/const PORT = process\.env\.PORT \|\| (\d+);/);

  expect(match).not.toBeNull();

  return Number(match[1]);
}

function viteApiProxyPort() {
  const source = readDemoFile('web/vite.config.js');
  const match = source.match(/['"]\/api['"]:\s*['"]http:\/\/localhost:(\d+)['"]/);

  expect(match).not.toBeNull();

  return Number(match[1]);
}

describe('Vite API proxy', () => {
  it('routes /api to the gateway-api port used by local demo entrypoints', () => {
    const gatewayPort = gatewayDefaultPort();
    const devScript = readDemoFile('scripts/dev.sh');
    const compose = readDemoFile('infra/docker-compose.yml');
    const readme = readDemoFile('README.md');

    expect(viteApiProxyPort()).toBe(gatewayPort);
    expect(devScript).toContain(`PORT=${gatewayPort} node services/gateway-api/src/index.js`);
    expect(devScript).toContain(`gateway-api:       http://localhost:${gatewayPort}`);
    expect(compose).toContain(`ports: ["${gatewayPort}:${gatewayPort}"]`);
    expect(compose).toContain(`PORT: ${gatewayPort}`);
    expect(readme).toContain(`| gateway-api | ${gatewayPort} |`);
  });
});
