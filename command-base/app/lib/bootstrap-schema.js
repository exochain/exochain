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

/**
 * bootstrap-schema.js — Idempotent schema bootstrap for fresh CommandBase installs.
 *
 * Creates all core tables that server.js expects to exist before its
 * top-level INSERT/ALTER/CREATE INDEX statements run.  Every statement
 * uses CREATE TABLE IF NOT EXISTS so it's safe to run on existing DBs.
 */
'use strict';

module.exports = function bootstrapSchema(db) {

  db.exec(`CREATE TABLE IF NOT EXISTS system_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS llm_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    provider_type TEXT NOT NULL DEFAULT 'api',
    config TEXT DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS team_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL,
    profile_path TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','inactive','retired')),
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    execution_mode TEXT NOT NULL DEFAULT 'system' CHECK(execution_mode IN ('system','terminal','autonomous')),
    tier TEXT NOT NULL DEFAULT 'specialist' CHECK(tier IN ('board','c-suite','specialist','orchestrator','leader','co-leader','subagent')),
    reports_to INTEGER,
    did_identity TEXT,
    dedicated_role INTEGER NOT NULL DEFAULT 0,
    llm_provider_id INTEGER REFERENCES llm_providers(id),
    llm_model TEXT,
    adapter_type TEXT DEFAULT 'claude_local',
    adapter_config TEXT DEFAULT '{}',
    runtime_config TEXT DEFAULT '{}',
    capabilities TEXT DEFAULT '[]',
    permissions TEXT DEFAULT '[]',
    icon TEXT,
    metadata TEXT DEFAULT '{}',
    department TEXT
  )`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_team_members_status ON team_members(status)`);

  db.exec(`CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    summary TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    color TEXT DEFAULT '#3B82F6',
    exochain_governed INTEGER DEFAULT 0,
    company_id INTEGER,
    initiative_id INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    priority INTEGER DEFAULT 0
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new','routing','in_progress','review','completed','delivered')),
    priority TEXT NOT NULL DEFAULT 'normal' CHECK(priority IN ('low','normal','high','urgent')),
    assigned_to INTEGER REFERENCES team_members(id),
    source_file TEXT,
    started_at TEXT,
    completed_at TEXT,
    delivered_at TEXT,
    progress INTEGER DEFAULT 0,
    current_step TEXT,
    subagent_count INTEGER DEFAULT 1,
    original_priority TEXT,
    downgraded_by TEXT,
    downgraded_at TEXT,
    origin TEXT DEFAULT 'manual',
    identifier TEXT,
    started_at_actual TEXT,
    completed_at_actual TEXT,
    estimated_hours REAL,
    actual_hours REAL,
    blocked_by_task_id INTEGER,
    blocked_reason TEXT,
    is_pinned INTEGER NOT NULL DEFAULT 0,
    workflow TEXT DEFAULT 'simple',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER REFERENCES tasks(id),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    notes TEXT,
    category TEXT DEFAULT 'system',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL CHECK(type IN ('task_delivered','task_status','decision_needed','hire_completed','system','mentioned')),
    title TEXT NOT NULL,
    message TEXT,
    task_id INTEGER REFERENCES tasks(id),
    read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS task_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL REFERENCES tasks(id),
    file_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_type TEXT,
    direction TEXT NOT NULL DEFAULT 'input' CHECK(direction IN ('input','output','attachment')),
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS task_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL REFERENCES tasks(id),
    member_id INTEGER NOT NULL REFERENCES team_members(id),
    subagent_count INTEGER DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(task_id, member_id)
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS project_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id),
    task_id INTEGER NOT NULL REFERENCES tasks(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(project_id, task_id)
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS member_tools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER NOT NULL REFERENCES team_members(id),
    tool_name TEXT NOT NULL,
    tool_type TEXT NOT NULL,
    config TEXT NOT NULL DEFAULT '{}',
    enabled INTEGER NOT NULL DEFAULT 1,
    use_cases TEXT,
    guidelines TEXT,
    usage_limits TEXT,
    daily_limit INTEGER,
    daily_used INTEGER DEFAULT 0,
    last_reset_date TEXT,
    vault_id INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  // NOTE: skills, agent_skills, cost_events, optimization_log are created
  // by server.js with authoritative schemas — do NOT duplicate here.

  db.exec(`CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    question TEXT NOT NULL,
    answer TEXT,
    context TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    task_id INTEGER REFERENCES tasks(id),
    asked_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT,
    source TEXT,
    is_pinned INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    role TEXT,
    company TEXT,
    email TEXT,
    phone TEXT,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT,
    description TEXT,
    prompt_template TEXT,
    default_priority TEXT DEFAULT 'normal',
    default_assignments TEXT,
    auto_assign INTEGER DEFAULT 0,
    use_count INTEGER DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS taggables (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tag_id INTEGER NOT NULL REFERENCES tags(id),
    entity_type TEXT NOT NULL,
    entity_id INTEGER NOT NULL,
    UNIQUE(tag_id, entity_type, entity_id)
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS improvement_proposals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    category TEXT,
    impact TEXT,
    effort TEXT,
    proposed_by TEXT,
    status TEXT NOT NULL DEFAULT 'proposed',
    approved_by TEXT,
    approved_at TEXT,
    work_started_at TEXT,
    completed_at TEXT,
    progress_percent INTEGER DEFAULT 0,
    current_step TEXT,
    files_changed TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS improvement_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proposal_id INTEGER NOT NULL REFERENCES improvement_proposals(id),
    action TEXT NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS constitutional_invariants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    name TEXT,
    description TEXT NOT NULL,
    formal_spec TEXT,
    enforcement_level TEXT DEFAULT 'block' CHECK(enforcement_level IN ('block','warn','audit')),
    enforced INTEGER DEFAULT 1,
    severity TEXT DEFAULT 'critical',
    validation_logic TEXT,
    exochain_severity TEXT DEFAULT 'critical' CHECK(exochain_severity IN ('critical','high','medium','low')),
    remediation TEXT,
    category TEXT DEFAULT 'governance',
    exochain_ref TEXT,
    last_validated_at TEXT,
    violation_count INTEGER DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS governance_receipts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_hash TEXT,
    action TEXT NOT NULL,
    action_type TEXT,
    actor TEXT,
    subject_type TEXT,
    subject_id INTEGER,
    entity_type TEXT,
    entity_id INTEGER,
    description TEXT,
    payload_hash TEXT,
    previous_hash TEXT,
    invariants_checked TEXT,
    invariants_passed INTEGER,
    project_id INTEGER,
    hash_algorithm TEXT DEFAULT 'sha256',
    encoding TEXT DEFAULT 'json',
    branch TEXT DEFAULT 'executive' CHECK(branch IN ('legislative','executive','judicial')),
    invariant_id INTEGER REFERENCES constitutional_invariants(id),
    adjudication TEXT DEFAULT 'pass' CHECK(adjudication IN ('pass','fail','warn','defer')),
    metadata TEXT DEFAULT '{}',
    chain_depth INTEGER DEFAULT 0,
    verified INTEGER DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS provenance_chain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    output_hash TEXT,
    input_hashes TEXT,
    task_id INTEGER REFERENCES tasks(id),
    member_id INTEGER,
    action TEXT,
    model_used TEXT,
    project_id INTEGER,
    transformation TEXT,
    model_id TEXT,
    confidence REAL,
    verified INTEGER DEFAULT 0,
    verification_receipt_id INTEGER REFERENCES governance_receipts(id),
    subject_type TEXT,
    subject_id INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS active_processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER REFERENCES team_members(id),
    task_id INTEGER REFERENCES tasks(id),
    process_type TEXT NOT NULL DEFAULT 'task',
    status TEXT NOT NULL DEFAULT 'pending',
    pid INTEGER,
    started_at TEXT,
    completed_at TEXT,
    output_summary TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    metadata TEXT DEFAULT '{}'
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS execution_packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    packet_id TEXT NOT NULL,
    title TEXT NOT NULL,
    active_phase TEXT,
    source_authority TEXT,
    objective TEXT,
    user_visible_result TEXT,
    assigned_director_id INTEGER REFERENCES team_members(id),
    assigned_specialist_id INTEGER REFERENCES team_members(id),
    verifier_ids TEXT DEFAULT '[]',
    in_scope TEXT,
    out_of_scope TEXT,
    dependencies TEXT DEFAULT '[]',
    data_changes TEXT,
    api_changes TEXT,
    ui_changes TEXT,
    worker_changes TEXT,
    feature_flags TEXT DEFAULT '[]',
    acceptance_criteria TEXT,
    stop_checkpoint TEXT,
    escalation_triggers TEXT,
    status TEXT DEFAULT 'draft',
    project_id INTEGER REFERENCES projects(id),
    task_id INTEGER REFERENCES tasks(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS feature_flags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    project_id INTEGER REFERENCES projects(id),
    phase TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS founder_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_id TEXT NOT NULL,
    topic TEXT NOT NULL,
    context TEXT NOT NULL,
    options TEXT,
    decision TEXT,
    reason TEXT,
    applies_to TEXT,
    status TEXT DEFAULT 'pending',
    revisit_trigger TEXT,
    project_id INTEGER REFERENCES projects(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS linked_repos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    name TEXT,
    owner TEXT,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS linked_paths (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL UNIQUE,
    name TEXT,
    type TEXT NOT NULL CHECK(type IN ('file','folder')),
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS missions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    project_id INTEGER REFERENCES projects(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS mission_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id INTEGER NOT NULL REFERENCES missions(id),
    task_id INTEGER NOT NULL REFERENCES tasks(id),
    UNIQUE(mission_id, task_id)
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS session_handoffs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    packet_id TEXT,
    director_id INTEGER REFERENCES team_members(id),
    specialist_id INTEGER REFERENCES team_members(id),
    verifier_ids TEXT DEFAULT '[]',
    completed_items TEXT DEFAULT '[]',
    files_changed TEXT DEFAULT '[]',
    db_changes TEXT,
    api_changes TEXT,
    ui_changes TEXT,
    worker_changes TEXT,
    tests_added TEXT,
    acceptance_status TEXT,
    dossier_compliance TEXT,
    blockers TEXT DEFAULT '[]',
    recommended_next_packet TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS research_sessions (
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

  db.exec(`CREATE TABLE IF NOT EXISTS research_cycles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES research_sessions(id),
    cycle_number INTEGER NOT NULL,
    hypothesis TEXT,
    status TEXT DEFAULT 'running',
    finding_title TEXT,
    finding_content TEXT,
    evaluation_reason TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS research_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES research_sessions(id),
    cycle_id INTEGER REFERENCES research_cycles(id),
    title TEXT NOT NULL,
    content TEXT,
    confidence TEXT DEFAULT 'medium',
    status TEXT DEFAULT 'kept',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS tool_catalog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    type TEXT NOT NULL,
    description TEXT,
    setup_command TEXT,
    base_url TEXT,
    auth_type TEXT,
    free_tier INTEGER DEFAULT 0,
    documentation_url TEXT,
    config_template TEXT DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS idea_board (
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

  db.exec(`CREATE TABLE IF NOT EXISTS credential_vault (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    encrypted_value TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS escalation_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER REFERENCES projects(id),
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS project_phases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id),
    phase_number INTEGER NOT NULL,
    name TEXT,
    status TEXT DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS model_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    is_active INTEGER DEFAULT 1,
    is_local INTEGER DEFAULT 0,
    max_concurrent INTEGER DEFAULT 3,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  // ── Catapult: franchise incubator tables ─────────────────────────────────

  db.exec(`CREATE TABLE IF NOT EXISTS catapult_blueprints (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    business_model TEXT NOT NULL,
    constitution_hash TEXT,
    blueprint_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS catapult_newcos (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    franchise_id TEXT REFERENCES catapult_blueprints(id),
    phase TEXT NOT NULL DEFAULT 'Assessment',
    status TEXT NOT NULL DEFAULT 'Provisioning',
    newco_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_catapult_newcos_status ON catapult_newcos(status)`);

  db.exec(`CREATE TABLE IF NOT EXISTS catapult_roster (
    newco_id TEXT NOT NULL REFERENCES catapult_newcos(id),
    slot TEXT NOT NULL,
    member_id INTEGER REFERENCES team_members(id),
    did_identity TEXT,
    hired_at TEXT,
    PRIMARY KEY (newco_id, slot)
  )`);
};
