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
const test = require('node:test');
const Database = require('better-sqlite3');
const bootstrapSchema = require('./bootstrap-schema');

const REQUIRED_COLUMNS = {
  llm_providers: [
    'id', 'name', 'type', 'base_url', 'api_key', 'default_model', 'enabled',
    'config', 'created_at', 'updated_at',
  ],
  model_sources: [
    'id', 'name', 'type', 'endpoint', 'label', 'device', 'is_active',
    'is_local', 'ssh_host', 'ssh_tunnel_port', 'max_concurrent',
    'created_at', 'updated_at',
  ],
  credential_vault: [
    'id', 'name', 'provider', 'credential_type', 'encrypted_value', 'metadata',
    'created_at', 'updated_at',
  ],
  idea_board: [
    'id', 'title', 'tagline', 'description', 'category', 'reference_material',
    'structure', 'market_notes', 'status', 'generated_by',
    'related_project_id', 'created_at', 'updated_at',
  ],
  research_sessions: [
    'id', 'title', 'goal', 'success_criteria', 'research_brief', 'max_cycles',
    'model', 'assigned_to', 'project_id', 'current_cycle', 'status',
    'program_id', 'started_at', 'completed_at', 'summary',
    'created_at', 'updated_at',
  ],
};

function bootstrappedDatabase() {
  const db = new Database(':memory:');
  bootstrapSchema(db);
  return db;
}

function staleBootstrappedDatabase() {
  const db = new Database(':memory:');

  db.exec(`CREATE TABLE llm_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    provider_type TEXT NOT NULL DEFAULT 'api',
    config TEXT DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE model_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    is_active INTEGER DEFAULT 1,
    is_local INTEGER DEFAULT 0,
    max_concurrent INTEGER DEFAULT 3,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE credential_vault (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    encrypted_value TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE idea_board (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    tagline TEXT,
    description TEXT,
    category TEXT,
    status TEXT DEFAULT 'fresh',
    generated_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE research_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    goal TEXT,
    success_criteria TEXT,
    max_cycles INTEGER DEFAULT 50,
    model TEXT DEFAULT 'sonnet',
    current_cycle INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending',
    program_id INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  bootstrapSchema(db);
  return db;
}

function columnsFor(db, table) {
  return new Set(db.prepare(`PRAGMA table_info(${table})`).all().map((row) => row.name));
}

function assertRouteRequiredColumns(db) {
  for (const [table, expectedColumns] of Object.entries(REQUIRED_COLUMNS)) {
    const actualColumns = columnsFor(db, table);
    const missing = expectedColumns.filter((column) => !actualColumns.has(column));

    assert.deepEqual(missing, [], `${table} bootstrap schema is missing route-required columns`);
  }
}

function assertRouteCompatibleWrites(db) {
  const now = '2026-05-19T20:00:00.000-04:00';

  db.prepare(`
    INSERT INTO llm_providers (name, type, base_url, api_key, default_model, enabled, config, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
  `).run('Anthropic', 'claude', 'https://api.anthropic.com', 'sk-test', 'claude-sonnet', '{}', now, now);

  db.prepare(`
    INSERT INTO model_sources (name, type, endpoint, label, device, is_local, ssh_host, ssh_tunnel_port, max_concurrent, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run('Local Ollama', 'ollama', 'http://localhost:11434', 'Local', 'Mac', 1, null, null, 3, now, now);

  db.prepare(`
    INSERT INTO credential_vault (name, provider, credential_type, encrypted_value, metadata, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run('Anthropic key', 'anthropic', 'api_key', 'sk-test', '{}', now, now);

  db.prepare(`
    INSERT INTO idea_board (title, tagline, description, category, reference_material, structure, market_notes, generated_by, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run('Receipt explorer', 'Traceable decisions', 'Show receipts', 'product', 'notes', 'app', 'market', 'Max', now, now);

  db.prepare(`
    INSERT INTO research_sessions (title, goal, success_criteria, research_brief, max_cycles, model, assigned_to, project_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run('Root receipts', 'Validate receipts', 'no gaps', 'inspect DAG', 50, 'sonnet', 'Briar', null);

  assert.equal(db.prepare('SELECT COUNT(*) AS c FROM llm_providers').get().c, 1);
  assert.equal(db.prepare('SELECT COUNT(*) AS c FROM model_sources').get().c, 1);
  assert.equal(db.prepare('SELECT COUNT(*) AS c FROM credential_vault').get().c, 1);
  assert.equal(db.prepare('SELECT COUNT(*) AS c FROM idea_board').get().c, 1);
  assert.equal(db.prepare('SELECT COUNT(*) AS c FROM research_sessions').get().c, 1);
}

test('bootstrap schema includes every column used by clean-install routes', () => {
  const db = bootstrappedDatabase();

  try {
    assertRouteRequiredColumns(db);
  } finally {
    db.close();
  }
});

test('bootstrap schema supports fresh-install writes used by settings, ideas, and research routes', () => {
  const db = bootstrappedDatabase();

  try {
    assertRouteCompatibleWrites(db);
  } finally {
    db.close();
  }
});

test('bootstrap schema upgrades tables created by the stale bootstrap', () => {
  const db = staleBootstrappedDatabase();

  try {
    assertRouteRequiredColumns(db);
    assertRouteCompatibleWrites(db);
  } finally {
    db.close();
  }
});
