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

'use strict';

const assert = require('node:assert/strict');
const { mkdtempSync, rmSync, mkdirSync, readFileSync } = require('node:fs');
const { join } = require('node:path');
const { spawn } = require('node:child_process');
const os = require('node:os');
const net = require('node:net');
const test = require('node:test');

function pickFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

async function waitForHttpReady(url) {
  const timeoutAt = Date.now() + 12_000;
  while (Date.now() < timeoutAt) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
      await new Promise((r) => setTimeout(r, 100));
    } catch (_err) {
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  throw new Error(`server failed to become ready at ${url}`);
}

function spawnCommandBaseServer(port, dbPath, tmpDir, extraEnv) {
  const env = { ...process.env };
  const serverPath = join(__dirname, 'server.js');
  env.PORT = String(port);
  env.NODE_ENV = 'test';
  env.DB_PATH = dbPath;
  env.INBOX_PATH = join(tmpDir, 'inbox');
  env.OUTBOX_PATH = join(tmpDir, 'outbox');
  env.TRUST_PROXY = 'loopback';
  Object.assign(env, extraEnv || {});

  mkdirSync(env.INBOX_PATH, { recursive: true });
  mkdirSync(env.OUTBOX_PATH, { recursive: true });

  const proc = spawn(process.execPath, [serverPath], {
    cwd: join(__dirname, '..'),
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const stderr = [];
  proc.stderr.setEncoding('utf8');
  proc.stderr.on('data', (chunk) => stderr.push(chunk.toString()));

  return { proc, stderr };
}

function stopCommandBaseServer(proc) {
  return new Promise((resolve) => {
    if (!proc || proc.killed || proc.exitCode !== null) {
      resolve();
      return;
    }

    proc.once('exit', () => resolve());
    proc.kill('SIGTERM');

    setTimeout(() => {
      if (!proc.killed && proc.exitCode === null) {
        proc.kill('SIGKILL');
      }
    }, 2000);
  });
}

test('ui bootstrap auth endpoint no longer leaks key material', { timeout: 60_000 }, async (t) => {
  const appSource = readFileSync(join(__dirname, 'public', 'app.js'), 'utf8');
  const whitepaperSource = readFileSync(join(__dirname, 'public', 'whitepaper.html'), 'utf8');

  assert.equal(
    appSource.includes('document.cookie = \'cb_auth=') || appSource.includes('document.cookie = \"cb_auth='),
    false,
    'command-base/app/public/app.js must not write cb_auth cookie from response body',
  );
  assert.equal(
    whitepaperSource.includes('document.cookie = \'cb_auth=') || whitepaperSource.includes('document.cookie = \"cb_auth='),
    false,
    'command-base/app/public/whitepaper.html must not write cb_auth cookie from response body',
  );

  const tmpDir = mkdtempSync(join(os.tmpdir(), 'cb-auth-status-'));
  const dbPath = join(tmpDir, 'command-base.db');
  const port = await pickFreePort();

  const { proc, stderr } = spawnCommandBaseServer(port, dbPath, tmpDir);
  t.after(() => {
    return stopCommandBaseServer(proc).finally(() => {
      rmSync(tmpDir, { recursive: true, force: true });
    });
  });

  let exitCode;
  proc.once('exit', (code) => {
    exitCode = code;
  });

  const baseUrl = `http://127.0.0.1:${port}`;
  await waitForHttpReady(`${baseUrl}/health`);

  const statusRes = await fetch(`${baseUrl}/api/auth/status`);
  assert.equal(statusRes.status, 200, 'auth status endpoint must remain reachable');

  const payload = await statusRes.json();
  assert.equal(payload.authenticated, true);
  assert.equal(Object.prototype.hasOwnProperty.call(payload, 'key'), false, 'auth status must not return API key');

  const rawSetCookie = statusRes.headers.get('set-cookie');
  assert.equal(!!rawSetCookie, true, 'auth status should set cb_auth cookie');
  assert.equal(/cb_auth=/.test(rawSetCookie), true, 'auth status should set cb_auth cookie');
  assert.equal(/HttpOnly/i.test(rawSetCookie), true, 'cb_auth cookie should be HttpOnly');
  assert.equal(/SameSite=Strict/i.test(rawSetCookie), true, 'cb_auth cookie should use SameSite=Strict');
  if (exitCode !== undefined) {
    assert.equal(exitCode, 0, `server exited unexpectedly; stderr: ${stderr.join('')}`);
  }
});

test('ui bootstrap auth endpoint denies non-loopback bootstrap', { timeout: 60_000 }, async (t) => {
  const tmpDir = mkdtempSync(join(os.tmpdir(), 'cb-auth-remote-'));
  const dbPath = join(tmpDir, 'command-base.db');
  const port = await pickFreePort();

  const { proc, stderr } = spawnCommandBaseServer(port, dbPath, tmpDir);
  t.after(() => {
    return stopCommandBaseServer(proc).finally(() => {
      rmSync(tmpDir, { recursive: true, force: true });
    });
  });

  let exitCode;
  proc.once('exit', (code) => {
    exitCode = code;
  });

  const baseUrl = `http://127.0.0.1:${port}`;
  await waitForHttpReady(`${baseUrl}/health`);

  const statusRes = await fetch(`${baseUrl}/api/auth/status`, {
    headers: { 'X-Forwarded-For': '203.0.113.42' },
  });
  assert.equal(statusRes.status, 403, 'remote clients must not receive auth bootstrap');

  const payload = await statusRes.json();
  assert.equal(payload.authenticated, false);
  assert.equal(Object.prototype.hasOwnProperty.call(payload, 'key'), false, 'remote denial must not return API key');
  assert.equal(statusRes.headers.get('set-cookie'), null, 'remote denial must not set cb_auth cookie');

  if (exitCode !== undefined) {
    assert.equal(exitCode, 0, `server exited unexpectedly; stderr: ${stderr.join('')}`);
  }
});

test('ui bootstrap auth endpoint accepts explicit operator bootstrap token', { timeout: 60_000 }, async (t) => {
  const tmpDir = mkdtempSync(join(os.tmpdir(), 'cb-auth-token-'));
  const dbPath = join(tmpDir, 'command-base.db');
  const port = await pickFreePort();
  const bootstrapToken = 'operator-bootstrap-token-for-test';

  const { proc, stderr } = spawnCommandBaseServer(port, dbPath, tmpDir, {
    COMMAND_BASE_AUTH_BOOTSTRAP_TOKEN: bootstrapToken,
  });
  t.after(() => {
    return stopCommandBaseServer(proc).finally(() => {
      rmSync(tmpDir, { recursive: true, force: true });
    });
  });

  let exitCode;
  proc.once('exit', (code) => {
    exitCode = code;
  });

  const baseUrl = `http://127.0.0.1:${port}`;
  await waitForHttpReady(`${baseUrl}/health`);

  const statusRes = await fetch(`${baseUrl}/api/auth/status`, {
    headers: {
      'X-Forwarded-For': '203.0.113.42',
      'X-Command-Base-Bootstrap-Token': bootstrapToken,
    },
  });
  assert.equal(statusRes.status, 200, 'operator bootstrap token should allow remote bootstrap');

  const payload = await statusRes.json();
  assert.equal(payload.authenticated, true);
  assert.equal(Object.prototype.hasOwnProperty.call(payload, 'key'), false, 'operator bootstrap must not return API key');
  assert.match(statusRes.headers.get('set-cookie') || '', /cb_auth=/, 'operator bootstrap should set cb_auth cookie');

  if (exitCode !== undefined) {
    assert.equal(exitCode, 0, `server exited unexpectedly; stderr: ${stderr.join('')}`);
  }
});
