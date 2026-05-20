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
const { existsSync, mkdtempSync, rmSync, mkdirSync } = require('node:fs');
const { join } = require('node:path');
const { spawn } = require('node:child_process');
const os = require('node:os');
const net = require('node:net');
const test = require('node:test');
const Database = require('better-sqlite3');

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

async function waitForHttpReady(url, stderr) {
  const timeoutAt = Date.now() + 12_000;
  while (Date.now() < timeoutAt) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch (_err) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  throw new Error(`server failed to become ready at ${url}; stderr: ${stderr.join('')}`);
}

function spawnCommandBaseServer(port, dbPath, tmpDir) {
  const env = { ...process.env };
  env.PORT = String(port);
  env.NODE_ENV = 'test';
  env.DB_PATH = dbPath;
  env.INBOX_PATH = join(tmpDir, 'inbox');
  env.OUTBOX_PATH = join(tmpDir, 'outbox');
  env.TRUST_PROXY = 'loopback';

  mkdirSync(env.INBOX_PATH, { recursive: true });
  mkdirSync(env.OUTBOX_PATH, { recursive: true });

  const proc = spawn(process.execPath, ['server.js'], {
    cwd: __dirname,
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

function cookieHeader(setCookie) {
  return (setCookie || '').split(';')[0];
}

async function postJson(baseUrl, cookie, path, body) {
  const res = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();

  assert.equal(res.ok, true, `${path} returned ${res.status}: ${text}`);

  return JSON.parse(text);
}

async function postJsonRaw(baseUrl, cookie, path, body) {
  const res = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

async function putJsonRaw(baseUrl, cookie, path, body) {
  const res = await fetch(`${baseUrl}${path}`, {
    method: 'PUT',
    headers: {
      Cookie: cookie,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

test('clean CommandBase bootstrap supports affected authenticated create routes', { timeout: 60_000 }, async (t) => {
  const tmpDir = mkdtempSync(join(os.tmpdir(), 'cb-schema-routes-'));
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
  await waitForHttpReady(`${baseUrl}/health`, stderr);

  const authRes = await fetch(`${baseUrl}/api/auth/status`);
  assert.equal(authRes.status, 200, 'loopback auth status should set the bootstrap cookie');
  const cookie = cookieHeader(authRes.headers.get('set-cookie'));
  assert.match(cookie, /^cb_auth=/, 'bootstrap response should include cb_auth cookie');

  await postJson(baseUrl, cookie, '/api/llm/providers', {
    name: 'Anthropic',
    type: 'claude',
    base_url: 'https://api.anthropic.com',
    api_key: 'sk-test',
    default_model: 'claude-sonnet',
    config: {},
  });
  await postJson(baseUrl, cookie, '/api/model-sources', {
    name: 'Local Ollama',
    type: 'ollama',
    endpoint: 'http://localhost:11434',
    label: 'Local',
    device: 'Mac',
    is_local: true,
    max_concurrent: 3,
  });
  await postJson(baseUrl, cookie, '/api/vault', {
    name: 'Anthropic key',
    provider: 'anthropic',
    credential_type: 'api_key',
    value: 'sk-test',
    metadata: { source: 'test' },
  });
  await postJson(baseUrl, cookie, '/api/ideas', {
    title: 'Receipt explorer',
    tagline: 'Traceable decisions',
    description: 'Show receipts',
    category: 'product',
    reference_material: 'notes',
    structure: 'app',
    market_notes: 'market',
    generated_by: 'Max',
  });
  await postJson(baseUrl, cookie, '/api/research-sessions', {
    title: 'Root receipts',
    goal: 'Validate receipts',
    success_criteria: 'no gaps',
    research_brief: 'inspect DAG',
    max_cycles: 50,
    model: 'sonnet',
    assigned_to: 'Briar',
    project_id: null,
  });

  if (exitCode !== undefined) {
    assert.equal(exitCode, 0, `server exited unexpectedly; stderr: ${stderr.join('')}`);
  }
});

test('model-source scan rejects unsafe ssh_host from existing rows before shell execution', { timeout: 60_000 }, async (t) => {
  const tmpDir = mkdtempSync(join(os.tmpdir(), 'cb-ssh-host-'));
  const dbPath = join(tmpDir, 'command-base.db');
  const markerPath = join(tmpDir, 'shell-executed');
  const port = await pickFreePort();

  const { proc, stderr } = spawnCommandBaseServer(port, dbPath, tmpDir);
  t.after(() => {
    return stopCommandBaseServer(proc).finally(() => {
      rmSync(tmpDir, { recursive: true, force: true });
    });
  });

  const baseUrl = `http://127.0.0.1:${port}`;
  await waitForHttpReady(`${baseUrl}/health`, stderr);

  const authRes = await fetch(`${baseUrl}/api/auth/status`);
  assert.equal(authRes.status, 200, 'loopback auth status should set the bootstrap cookie');
  const cookie = cookieHeader(authRes.headers.get('set-cookie'));
  assert.match(cookie, /^cb_auth=/, 'bootstrap response should include cb_auth cookie');

  const db = new Database(dbPath);
  try {
    const now = '2026-05-20T01:32:00.000-04:00';
    db.prepare(`
      INSERT INTO model_sources (name, type, endpoint, label, device, is_local, ssh_host, ssh_tunnel_port, max_concurrent, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      'Injected Remote',
      'ollama',
      'http://127.0.0.1:9',
      'Injected',
      'GPU',
      0,
      `127.0.0.1; touch ${markerPath}; true #`,
      null,
      1,
      now,
      now
    );
  } finally {
    db.close();
  }

  const response = await postJsonRaw(baseUrl, cookie, '/api/model-sources/1/scan', {});

  assert.equal(response.status, 400, 'unsafe ssh_host must be rejected before scan execution');
  assert.match(response.body.error, /ssh_host/i);
  assert.equal(existsSync(markerPath), false, 'scan must not execute shell metacharacters from ssh_host');
});

test('model-source create and update reject unsafe ssh_host tokens', { timeout: 60_000 }, async (t) => {
  const tmpDir = mkdtempSync(join(os.tmpdir(), 'cb-ssh-host-write-'));
  const dbPath = join(tmpDir, 'command-base.db');
  const port = await pickFreePort();

  const { proc, stderr } = spawnCommandBaseServer(port, dbPath, tmpDir);
  t.after(() => {
    return stopCommandBaseServer(proc).finally(() => {
      rmSync(tmpDir, { recursive: true, force: true });
    });
  });

  const baseUrl = `http://127.0.0.1:${port}`;
  await waitForHttpReady(`${baseUrl}/health`, stderr);

  const authRes = await fetch(`${baseUrl}/api/auth/status`);
  assert.equal(authRes.status, 200, 'loopback auth status should set the bootstrap cookie');
  const cookie = cookieHeader(authRes.headers.get('set-cookie'));

  const createResponse = await postJsonRaw(baseUrl, cookie, '/api/model-sources', {
    name: 'Injected Remote',
    type: 'ollama',
    endpoint: 'http://127.0.0.1:9',
    label: 'Injected',
    device: 'GPU',
    is_local: false,
    ssh_host: '127.0.0.1; touch /tmp/commandbase-pwned',
    max_concurrent: 1,
  });
  assert.equal(createResponse.status, 400);
  assert.match(createResponse.body.error, /ssh_host/i);

  const validSource = await postJson(baseUrl, cookie, '/api/model-sources', {
    name: 'Safe Remote',
    type: 'ollama',
    endpoint: 'http://127.0.0.1:9',
    label: 'Safe',
    device: 'GPU',
    is_local: false,
    ssh_host: 'operator@127.0.0.1',
    max_concurrent: 1,
  });

  const updateResponse = await putJsonRaw(baseUrl, cookie, `/api/model-sources/${validSource.id}`, {
    ssh_host: 'operator@127.0.0.1 && touch /tmp/commandbase-pwned',
  });
  assert.equal(updateResponse.status, 400);
  assert.match(updateResponse.body.error, /ssh_host/i);
});
