'use strict';
/**
 * Task Force Database — SEPARATE from the_team.db
 *
 * This is intentionally a standalone SQLite database so that:
 * 1. If the_team.db corrupts, task forces survive
 * 2. If Command Base server crashes, task force state persists
 * 3. Task forces can theoretically run without server.js at all
 *
 * Location: ../task_forces.db (same level as the_team.db)
 */

const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DB_PATH = path.join(__dirname, '..', '..', 'task_forces.db');

let db;

function getDb() {
  if (db) return db;

  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('busy_timeout = 5000');
  db.pragma('foreign_keys = ON');

  initSchema();
  return db;
}

function initSchema() {
  db.exec(`
    -- Task Forces: small dedicated external teams
    CREATE TABLE IF NOT EXISTS task_forces (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      mission TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','deploying','active','paused','completed','cancelled','failed')),
      project_target TEXT,
      project_id INTEGER,
      working_directory TEXT,
      composition_strategy TEXT DEFAULT 'auto',
      max_agents INTEGER DEFAULT 5,
      created_at TEXT NOT NULL,
      deployed_at TEXT,
      completed_at TEXT,
      cancelled_at TEXT,
      notes TEXT
    );

    -- Task Force Members: who's on this force + anti-bias tracking
    CREATE TABLE IF NOT EXISTS task_force_members (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      force_id INTEGER NOT NULL REFERENCES task_forces(id) ON DELETE CASCADE,
      role TEXT NOT NULL CHECK(role IN ('lead','builder','reviewer','analyst','specialist')),
      member_name TEXT NOT NULL,
      specialization TEXT,
      bias_tags TEXT DEFAULT '[]',
      assigned_at TEXT NOT NULL,
      status TEXT DEFAULT 'idle' CHECK(status IN ('idle','working','reviewing','done','removed'))
    );

    -- Task Force Processes: running agents, their PIDs, what device they're on
    CREATE TABLE IF NOT EXISTS task_force_processes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      force_id INTEGER NOT NULL REFERENCES task_forces(id) ON DELETE CASCADE,
      member_id INTEGER REFERENCES task_force_members(id),
      pid INTEGER,
      device TEXT NOT NULL DEFAULT 'mac' CHECK(device IN ('mac','spark','remote')),
      model TEXT,
      adapter TEXT DEFAULT 'claude_cli' CHECK(adapter IN ('claude_cli','ollama','http')),
      status TEXT DEFAULT 'starting' CHECK(status IN ('starting','running','completed','failed','killed')),
      cpu_percent REAL DEFAULT 0,
      ram_mb REAL DEFAULT 0,
      started_at TEXT NOT NULL,
      completed_at TEXT,
      output_summary TEXT,
      error TEXT
    );

    -- Task Force Activity Log
    CREATE TABLE IF NOT EXISTS task_force_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      force_id INTEGER NOT NULL REFERENCES task_forces(id) ON DELETE CASCADE,
      level TEXT DEFAULT 'info' CHECK(level IN ('debug','info','warn','error','critical')),
      source TEXT,
      message TEXT NOT NULL,
      metadata TEXT,
      created_at TEXT NOT NULL
    );

    -- Resource Profiles: per-device limits (FLEXIBLE, not hard-coded)
    CREATE TABLE IF NOT EXISTS resource_profiles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_name TEXT NOT NULL UNIQUE,
      device_type TEXT NOT NULL CHECK(device_type IN ('workstation','inference','remote')),
      ssh_host TEXT,
      ssh_user TEXT,
      ollama_endpoint TEXT,
      max_cpu_percent REAL DEFAULT 60,
      max_ram_percent REAL DEFAULT 60,
      warn_cpu_percent REAL DEFAULT 50,
      warn_ram_percent REAL DEFAULT 50,
      max_concurrent_models INTEGER DEFAULT 1,
      max_concurrent_agents INTEGER DEFAULT 3,
      is_dedicated_inference INTEGER DEFAULT 0,
      notes TEXT,
      updated_at TEXT NOT NULL
    );

    -- Anti-bias ledger: tracks who built what so reviewers are never the builders
    CREATE TABLE IF NOT EXISTS bias_ledger (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      force_id INTEGER NOT NULL REFERENCES task_forces(id) ON DELETE CASCADE,
      member_id INTEGER NOT NULL REFERENCES task_force_members(id),
      action TEXT NOT NULL CHECK(action IN ('built','designed','digested','reviewed','tested')),
      target_description TEXT NOT NULL,
      file_paths TEXT,
      created_at TEXT NOT NULL
    );

    -- Indexes for performance
    CREATE INDEX IF NOT EXISTS idx_tf_status ON task_forces(status);
    CREATE INDEX IF NOT EXISTS idx_tfm_force ON task_force_members(force_id);
    CREATE INDEX IF NOT EXISTS idx_tfp_force ON task_force_processes(force_id);
    CREATE INDEX IF NOT EXISTS idx_tfp_status ON task_force_processes(status);
    CREATE INDEX IF NOT EXISTS idx_tfl_force ON task_force_logs(force_id);
    CREATE INDEX IF NOT EXISTS idx_bias_member ON bias_ledger(member_id);
    CREATE INDEX IF NOT EXISTS idx_bias_force ON bias_ledger(force_id);
  `);

  // Seed default resource profiles if empty
  const count = db.prepare('SELECT COUNT(*) as c FROM resource_profiles').get().c;
  if (count === 0) {
    const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
    db.prepare(`INSERT INTO resource_profiles (device_name, device_type, max_cpu_percent, max_ram_percent, warn_cpu_percent, warn_ram_percent, max_concurrent_models, max_concurrent_agents, is_dedicated_inference, ollama_endpoint, ssh_host, ssh_user, notes, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
      'mac', 'workstation', 60, 60, 45, 45, 0, 3, 0, null, null, null,
      'Local Mac — NEVER run models here. Orchestration and Claude CLI only. All inference on Spark.', now
    );
    db.prepare(`INSERT INTO resource_profiles (device_name, device_type, max_cpu_percent, max_ram_percent, warn_cpu_percent, warn_ram_percent, max_concurrent_models, max_concurrent_agents, is_dedicated_inference, ollama_endpoint, ssh_host, ssh_user, notes, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
      'spark', 'inference', 98, 98, 90, 90, 3, 5, 1, 'http://localhost:11435', '192.168.1.35', 'maxstewart',
      'DGX Spark GB10 — dedicated inference hardware. Models routinely use 97-98% and that is NORMAL.', now
    );
  }
}

function close() {
  if (db) {
    db.close();
    db = null;
  }
}

module.exports = { getDb, close, DB_PATH };
