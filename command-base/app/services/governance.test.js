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
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const test = require('node:test');

const source = readFileSync(join(__dirname, 'governance.js'), 'utf8');
const createGovernanceService = require('./governance');

function functionSource(name) {
  const start = source.indexOf(`function ${name}`);
  assert.notEqual(start, -1, `${name} source must be present`);
  const nextFunction = source.indexOf('\n  function ', start + 1);
  return nextFunction === -1 ? source.slice(start) : source.slice(start, nextFunction);
}

test('assignAdjudicationStage uses deterministic adjudicator ordering', () => {
  const body = functionSource('assignAdjudicationStage');

  assert.equal(
    /ORDER\s+BY\s+RANDOM\s*\(/i.test(body),
    false,
    'adjudicator selection must not use SQLite ORDER BY RANDOM()',
  );
  assert.match(
    body,
    /challenge_adjudication_stages[\s\S]+adjudicator_id\s*=\s*team_members\.id/i,
    'adjudicator ordering must account for existing adjudication load',
  );
  assert.match(
    body,
    /ORDER\s+BY[\s\S]+ASC[\s\S]+id\s+ASC/i,
    'adjudicator ordering must use a stable id tie-breaker',
  );
});

function createGovernanceDb(invariants) {
  const rows = {
    governance_receipts: [],
    governance_audit_trail: [],
    invariant_updates: [],
  };

  return {
    rows,
    prepare(sql) {
      const normalized = sql.replace(/\s+/g, ' ');

      if (normalized.includes('SELECT * FROM constitutional_invariants')) {
        return { all: () => invariants };
      }

      if (normalized.includes('UPDATE constitutional_invariants SET last_validated_at')) {
        return {
          run: (...params) => {
            rows.invariant_updates.push(params);
            return { changes: 1 };
          },
        };
      }

      if (normalized.includes('SELECT id, receipt_hash, payload_hash, previous_hash FROM governance_receipts')) {
        return {
          get: () => rows.governance_receipts.at(-1),
        };
      }

      if (normalized.includes('SELECT receipt_hash FROM governance_receipts WHERE id = ? - 1')) {
        return {
          get: (id) => rows.governance_receipts.find((receipt) => receipt.id === id - 1),
        };
      }

      if (normalized.includes('INSERT INTO governance_receipts')) {
        return {
          run: (...params) => {
            const id = rows.governance_receipts.length + 1;
            rows.governance_receipts.push({
              id,
              action_type: params[1],
              receipt_hash: params[8],
              previous_hash: params[7],
            });
            return { lastInsertRowid: id };
          },
        };
      }

      if (normalized.includes('INSERT INTO governance_audit_trail')) {
        return {
          run: (...params) => {
            const id = rows.governance_audit_trail.length + 1;
            rows.governance_audit_trail.push({ id, params });
            return { lastInsertRowid: id };
          },
        };
      }

      throw new Error(`unexpected SQL in governance test: ${sql}`);
    },
  };
}

function governanceServiceFor(invariants) {
  const db = createGovernanceDb(invariants);
  return {
    db,
    service: createGovernanceService(db, () => {}, {
      localNow: () => '2026-05-15T00:00:00.000-04:00',
    }),
  };
}

test('validateAgainstInvariants blocks receipt hash mutation without regex spelling', () => {
  const { service } = governanceServiceFor([
    { id: 7, code: 'INV-CHAIN', name: 'Governance Chain Immutable', enforcement_level: 'block' },
  ]);

  const result = service.validateAgainstInvariants(
    42,
    "operator output: UPDATE governance_receipts SET receipt_hash = 'abc' WHERE id = 1",
  );

  assert.equal(result.passed, false);
  assert.equal(result.block_count, 1);
  assert.match(result.violations[0].detail, /governance chain/i);
});

test('validateAgainstInvariants does not append a governance receipt from heuristic output scan', () => {
  const { db, service } = governanceServiceFor([
    { id: 9, code: 'INV-GOV', name: 'Governance Integrity', enforcement_level: 'warn' },
  ]);

  service.validateAgainstInvariants(101, 'routine status output with no structured governance evidence');

  assert.equal(
    db.rows.governance_receipts.length,
    0,
    'heuristic validation of untrusted output must not mutate the receipt hash chain',
  );
});
