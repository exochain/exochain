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
import test from 'node:test';

async function loadFreshSharedModule(label) {
  return import(`./index.js?case=${label}-${Date.now()}`);
}

test('getPool fails closed when DATABASE_URL is missing', async () => {
  const previousDatabaseUrl = process.env.DATABASE_URL;
  delete process.env.DATABASE_URL;
  try {
    const shared = await loadFreshSharedModule('missing-database-url');
    assert.throws(
      () => shared.getPool(),
      /DATABASE_URL must be configured for @exochain\/shared/,
    );
  } finally {
    if (previousDatabaseUrl === undefined) {
      delete process.env.DATABASE_URL;
    } else {
      process.env.DATABASE_URL = previousDatabaseUrl;
    }
  }
});

test('getPool uses the explicit runtime DATABASE_URL without fallback', async () => {
  const previousDatabaseUrl = process.env.DATABASE_URL;
  const runtimeDatabaseUrl = 'postgres://demo-user:demo-pass@demo-db:5432/demo';
  process.env.DATABASE_URL = runtimeDatabaseUrl;
  try {
    const shared = await loadFreshSharedModule('explicit-database-url');
    const pool = shared.getPool();
    assert.equal(pool.options.connectionString, runtimeDatabaseUrl);
    await pool.end();
  } finally {
    if (previousDatabaseUrl === undefined) {
      delete process.env.DATABASE_URL;
    } else {
      process.env.DATABASE_URL = previousDatabaseUrl;
    }
  }
});
