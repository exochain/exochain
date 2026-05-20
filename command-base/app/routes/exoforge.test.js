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
const Module = require('node:module');
const test = require('node:test');

function installWasmKernelStub(t, kernel) {
  const originalLoad = Module._load;
  Module._load = function(request, parent, isMain) {
    if (request === '@exochain/exochain-wasm') {
      return kernel;
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  t.after(() => {
    Module._load = originalLoad;
  });
}

function createAppHarness() {
  const routes = new Map();
  return {
    routes,
    app: {
      get(path, handler) {
        routes.set(`GET ${path}`, handler);
      },
      post(path, handler) {
        routes.set(`POST ${path}`, handler);
      },
    },
  };
}

class ExoForgeHealthDatabase {
  constructor() {
    this.receipts = [];
    this.nextReceiptId = 1;
  }

  prepare(sql) {
    const db = this;
    return {
      get(...params) {
        if (sql.includes('SELECT id, receipt_hash FROM governance_receipts')) {
          return db.receipts[db.receipts.length - 1] || null;
        }
        if (sql.includes('SELECT COUNT(*) as c FROM governance_receipts')) {
          return { c: db.receipts.length };
        }
        if (sql.includes('SELECT') && sql.includes('FROM constitutional_invariants')) {
          return { total: 10, enforced: 10 };
        }
        if (sql.includes('FROM exoforge_cycles WHERE status = ?')) {
          assert.equal(params[0], 'active');
          return null;
        }
        if (sql.includes('FROM exoforge_queue WHERE status = ?')) {
          assert.equal(params[0], 'triaged');
          return { c: 0 };
        }
        throw new Error(`unexpected get SQL: ${sql}`);
      },
      all() {
        if (sql.includes('SELECT receipt_hash, previous_hash FROM governance_receipts')) {
          return db.receipts.slice(-2).reverse();
        }
        throw new Error(`unexpected all SQL: ${sql}`);
      },
      run(...params) {
        if (sql.includes('CREATE TABLE IF NOT EXISTS')) {
          return { changes: 0 };
        }
        if (sql.includes('INSERT INTO governance_receipts')) {
          const receipt = {
            id: db.nextReceiptId,
            receipt_hash: params[8],
            previous_hash: params[7],
          };
          db.nextReceiptId += 1;
          db.receipts.push(receipt);
          return { lastInsertRowid: receipt.id };
        }
        if (sql.includes('INSERT INTO governance_audit_trail')) {
          return { lastInsertRowid: db.nextReceiptId };
        }
        throw new Error(`unexpected run SQL: ${sql}`);
      },
    };
  }
}

function invokeJson(handler) {
  return new Promise((resolve, reject) => {
    const req = {};
    const res = {
      statusCode: 200,
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(payload) {
        resolve({ statusCode: this.statusCode, payload });
      },
    };
    try {
      handler(req, res);
    } catch (error) {
      reject(error);
    }
  });
}

function registerExoForgeRoutes() {
  const { app, routes } = createAppHarness();
  const db = new ExoForgeHealthDatabase();
  require('./exoforge.js')(app, db, {
    localNow: () => '2026-05-19T09:50:00.000-04:00',
    broadcast: () => {},
  });
  const handler = routes.get('GET /api/exoforge/health');
  assert.equal(typeof handler, 'function', 'health route should be registered');
  return handler;
}

test('ExoForge health reports failed TNC verdicts as unhealthy', async (t) => {
  installWasmKernelStub(t, {
    wasm_create_decision(decisionId, title, decisionClass, constitutionHash, createdAtMs, createdAtLogical) {
      assert.equal(decisionId, '00000000-0000-0000-0000-0000000000ef');
      assert.equal(title, 'Health Check');
      assert.equal(decisionClass, '"Routine"');
      assert.equal(constitutionHash, '2'.repeat(64));
      assert.equal(createdAtMs, 1n);
      assert.equal(createdAtLogical, 0);
      return JSON.stringify({
        id: '00000000-0000-0000-0000-000000000123',
        title: 'Health Check',
        class: 'Routine',
        authority_chain: [],
        evidence_bundle: [],
      });
    },
    wasm_enforce_all_tnc() {
      return {
        ok: false,
        error: 'TNC violation: TNC-01: empty authority chain',
      };
    },
    wasm_workflow_stages() {
      return ['Draft', 'Submitted', 'Approved', 'Closed'];
    },
    wasm_audit_verify() {
      return { ok: true };
    },
  });

  const { statusCode, payload } = await invokeJson(registerExoForgeRoutes());

  assert.equal(statusCode, 200);
  assert.equal(payload.success, true);
  const tncCheck = payload.data.checks.find((check) => check.check === 'tnc_enforcement');
  assert.ok(tncCheck, 'TNC health check should be present');
  assert.equal(tncCheck.status, 'critical');
  assert.equal(tncCheck.score, 0);
  assert.equal(tncCheck.tnc_result.ok, false);
  assert.equal(payload.data.status, 'degraded');
});

test('ExoForge health preserves healthy status for passing TNC verdicts', async (t) => {
  installWasmKernelStub(t, {
    wasm_create_decision(decisionId, title, decisionClass, constitutionHash, createdAtMs, createdAtLogical) {
      assert.equal(decisionId, '00000000-0000-0000-0000-0000000000ef');
      assert.equal(title, 'Health Check');
      assert.equal(decisionClass, '"Routine"');
      assert.equal(constitutionHash, '2'.repeat(64));
      assert.equal(createdAtMs, 1n);
      assert.equal(createdAtLogical, 0);
      return JSON.stringify({
        id: '00000000-0000-0000-0000-000000000123',
        title: 'Health Check',
        class: 'Routine',
        authority_chain: [{ actor_did: 'did:exo:root' }],
        evidence_bundle: [{ hash: '2'.repeat(64) }],
      });
    },
    wasm_enforce_all_tnc() {
      return {
        ok: true,
        violations: [],
      };
    },
    wasm_workflow_stages() {
      return ['Draft', 'Submitted', 'Approved', 'Closed'];
    },
    wasm_audit_verify() {
      return { ok: true };
    },
  });

  const { statusCode, payload } = await invokeJson(registerExoForgeRoutes());

  assert.equal(statusCode, 200);
  assert.equal(payload.success, true);
  const tncCheck = payload.data.checks.find((check) => check.check === 'tnc_enforcement');
  assert.ok(tncCheck, 'TNC health check should be present');
  assert.equal(tncCheck.status, 'healthy');
  assert.equal(tncCheck.score, 1);
  assert.equal(tncCheck.tnc_result.ok, true);
  assert.equal(payload.data.status, 'healthy');
});
