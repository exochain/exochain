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

/**
 * Catapult Routes — Express Router
 *
 * Backend routes for the Catapult franchise incubator.
 * Manages franchise blueprints, newco lifecycle, ODA roster,
 * heartbeat monitoring, budget enforcement, and goal alignment.
 *
 * Every mutating route:
 *   1. Extracts parameters from req.body
 *   2. Calls the catapult service function(s)
 *   3. Persists state to SQLite
 *   4. Creates a governance receipt
 *   5. Broadcasts a WebSocket event
 *   6. Returns { success, data, receipt }
 */

module.exports = function(app, db, helpers) {
  const { broadcast, localNow } = helpers;
  const path = require('path');
  const catapult = require('../services/catapult');
  const catapultProfiles = require('../services/catapult-profiles');
  const catapultBootstrap = require('../services/catapult-bootstrap');
  const governanceService = require('../services/governance');

  const TEAM_DIR = path.resolve(__dirname, '../../Team');

  function getGovernance() {
    return governanceService(db, broadcast || (() => {}), { localNow: localNow || (() => new Date().toISOString()) });
  }

  function createReceipt(actionType, entityType, entityId, actor, description, payload, projectId) {
    const gov = getGovernance();
    const receipt = gov.createReceipt(db, actionType, entityType, entityId, actor, description, payload, projectId);
    return { hash: receipt.receipt_hash, depth: receipt.chain_depth };
  }

  function ok(res, data, receipt) {
    return res.json({ success: true, data, receipt: receipt || null });
  }

  function fail(res, err) {
    return res.status(500).json({ success: false, error: err.message || String(err) });
  }

  // ===========================================================================
  // FRANCHISE BLUEPRINTS
  // ===========================================================================

  /**
   * POST /api/catapult/franchise
   * Create a new franchise blueprint.
   * Body: { name, businessModel, constitutionHashHex, actorDid }
   */
  app.post('/api/catapult/franchise', (req, res) => {
    try {
      const { name, businessModel, constitutionHashHex, actorDid } = req.body;
      const data = catapult.createFranchiseBlueprint(name, businessModel, constitutionHashHex);

      db.prepare(`INSERT INTO catapult_blueprints (id, name, business_model, constitution_hash, blueprint_json)
        VALUES (?, ?, ?, ?, ?)`).run(data.id, name, JSON.stringify(businessModel), constitutionHashHex, JSON.stringify(data));

      const receipt = createReceipt('franchise_create', 'franchise', data.id,
        actorDid || 'system', `Created franchise blueprint: ${name}`, data);
      broadcast('catapult:franchise:created', data);
      return ok(res, data, receipt);
    } catch (err) {
      return fail(res, err);
    }
  });

  /**
   * GET /api/catapult/franchise
   * List all franchise blueprints.
   */
  app.get('/api/catapult/franchise', (_req, res) => {
    try {
      const rows = db.prepare('SELECT * FROM catapult_blueprints ORDER BY created_at DESC').all();
      const data = rows.map(r => JSON.parse(r.blueprint_json));
      return ok(res, data);
    } catch (err) {
      return fail(res, err);
    }
  });

  // ===========================================================================
  // NEWCO LIFECYCLE
  // ===========================================================================

  /**
   * POST /api/catapult/newco
   * Instantiate a new company from a blueprint.
   * Body: { blueprintId, name, hrDid, researcherDid, actorDid }
   */
  app.post('/api/catapult/newco', (req, res) => {
    try {
      const { blueprintId, name, hrDid, researcherDid, actorDid } = req.body;

      const bpRow = db.prepare('SELECT blueprint_json FROM catapult_blueprints WHERE id = ?').get(blueprintId);
      if (!bpRow) return res.status(404).json({ success: false, error: `Blueprint not found: ${blueprintId}` });
      const blueprint = JSON.parse(bpRow.blueprint_json);

      const data = catapult.instantiateNewco(blueprint, name, hrDid, researcherDid);

      db.prepare(`INSERT INTO catapult_newcos (id, name, franchise_id, phase, status, newco_json)
        VALUES (?, ?, ?, ?, ?, ?)`).run(data.id, name, blueprintId, data.phase, data.status, JSON.stringify(data));

      // Provision all 12 ODA agent profiles and register in team_members
      const provisioned = catapultProfiles.provisionNewcoAgents(db, name, data.id, TEAM_DIR);

      const receipt = createReceipt('newco_create', 'newco', data.id,
        actorDid || hrDid, `Instantiated newco: ${name} from blueprint ${blueprintId}`, data);
      broadcast('catapult:newco:created', { ...data, provisioned });
      return ok(res, { newco: data, provisioned }, receipt);
    } catch (err) {
      return fail(res, err);
    }
  });

  /**
   * GET /api/catapult/newco/:id
   * Get newco status and health summary.
   */
  app.get('/api/catapult/newco/:id', (req, res) => {
    try {
      const row = db.prepare('SELECT * FROM catapult_newcos WHERE id = ?').get(req.params.id);
      if (!row) return res.status(404).json({ success: false, error: 'Newco not found' });
      const newco = JSON.parse(row.newco_json);
      const roster = db.prepare('SELECT * FROM catapult_roster WHERE newco_id = ?').all(req.params.id);
      return ok(res, { newco, roster, phase: row.phase, status: row.status });
    } catch (err) {
      return fail(res, err);
    }
  });

  /**
   * POST /api/catapult/newco/:id/phase
   * Advance to the next operational phase.
   * Body: { targetPhase, actorDid }
   */
  app.post('/api/catapult/newco/:id/phase', (req, res) => {
    try {
      const { targetPhase, actorDid } = req.body;
      const row = db.prepare('SELECT newco_json FROM catapult_newcos WHERE id = ?').get(req.params.id);
      if (!row) return res.status(404).json({ success: false, error: 'Newco not found' });

      const newco = JSON.parse(row.newco_json);
      const prevPhase = newco.phase;
      const data = catapult.transitionPhase(newco, targetPhase);

      db.prepare('UPDATE catapult_newcos SET phase = ?, status = ?, newco_json = ?, updated_at = datetime(\'now\') WHERE id = ?')
        .run(data.phase, data.status, JSON.stringify(data), req.params.id);

      // Seed founding tasks when entering Selection phase
      let seededTasks = null;
      if (targetPhase === 'Selection' && prevPhase === 'Assessment') {
        const bpRow = db.prepare('SELECT business_model FROM catapult_blueprints WHERE id = ?').get(data.franchise_id);
        const bizModel = bpRow ? bpRow.business_model : 'Unknown';
        seededTasks = catapultBootstrap.seedFoundingTasks(db, req.params.id, data.name, bizModel, broadcast);
      }

      const receipt = createReceipt('phase_transition', 'newco', req.params.id,
        actorDid, `Phase transition: ${prevPhase} → ${targetPhase}`, data);
      broadcast('catapult:newco:phase', { id: req.params.id, from: prevPhase, to: targetPhase, seededTasks });
      return ok(res, { newco: data, seededTasks }, receipt);
    } catch (err) {
      return fail(res, err);
    }
  });

  // ===========================================================================
  // ODA ROSTER
  // ===========================================================================

  /**
   * POST /api/catapult/newco/:id/hire
   * Hire an agent into an ODA slot.
   * Body: { agent, actorDid }
   */
  app.post('/api/catapult/newco/:id/hire', (req, res) => {
    try {
      const { agent, actorDid } = req.body;
      const row = db.prepare('SELECT newco_json FROM catapult_newcos WHERE id = ?').get(req.params.id);
      if (!row) return res.status(404).json({ success: false, error: 'Newco not found' });

      const newco = JSON.parse(row.newco_json);
      const data = catapult.hireAgent(newco, agent);

      db.prepare('UPDATE catapult_newcos SET newco_json = ?, updated_at = datetime(\'now\') WHERE id = ?')
        .run(JSON.stringify(data), req.params.id);

      _registerRosterSlot(req.params.id, agent.slot, agent.did);

      const receipt = createReceipt('agent_hire', 'newco', req.params.id,
        actorDid, `Hired ${agent.slot}: ${agent.display_name}`, { slot: agent.slot, did: agent.did });
      broadcast('catapult:agent:hired', { newcoId: req.params.id, slot: agent.slot });
      return ok(res, data, receipt);
    } catch (err) {
      return fail(res, err);
    }
  });

  /**
   * POST /api/catapult/newco/:id/release
   * Release an agent from an ODA slot.
   * Body: { slot, actorDid }
   */
  app.post('/api/catapult/newco/:id/release', (req, res) => {
    try {
      const { slot, actorDid } = req.body;
      const row = db.prepare('SELECT newco_json FROM catapult_newcos WHERE id = ?').get(req.params.id);
      if (!row) return res.status(404).json({ success: false, error: 'Newco not found' });

      const newco = JSON.parse(row.newco_json);
      const data = catapult.releaseAgent(newco, slot);

      db.prepare('UPDATE catapult_newcos SET newco_json = ?, updated_at = datetime(\'now\') WHERE id = ?')
        .run(JSON.stringify(data.newco), req.params.id);
      db.prepare('DELETE FROM catapult_roster WHERE newco_id = ? AND slot = ?').run(req.params.id, slot);

      const receipt = createReceipt('agent_release', 'newco', req.params.id,
        actorDid, `Released agent from slot: ${slot}`, data);
      broadcast('catapult:agent:released', { newcoId: req.params.id, slot });
      return ok(res, data, receipt);
    } catch (err) {
      return fail(res, err);
    }
  });

  /**
   * GET /api/catapult/newco/:id/roster
   * Get ODA roster status.
   */
  app.get('/api/catapult/newco/:id/roster', (req, res) => {
    try {
      const row = db.prepare('SELECT newco_json FROM catapult_newcos WHERE id = ?').get(req.params.id);
      if (!row) return res.status(404).json({ success: false, error: 'Newco not found' });

      const newco = JSON.parse(row.newco_json);
      const status = catapult.rosterStatus(newco);
      const authority = catapult.odaAuthorityChain(newco);
      const rosterRows = db.prepare('SELECT * FROM catapult_roster WHERE newco_id = ?').all(req.params.id);
      return ok(res, { status, authority, slots: rosterRows });
    } catch (err) {
      return fail(res, err);
    }
  });

  // ===========================================================================
  // HEARTBEAT
  // ===========================================================================

  /**
   * POST /api/catapult/newco/:id/heartbeat
   * Record an agent heartbeat.
   * Body: { record }
   */
  app.post('/api/catapult/newco/:id/heartbeat', (req, res) => {
    try {
      const { record } = req.body;
      const row = db.prepare('SELECT newco_json FROM catapult_newcos WHERE id = ?').get(req.params.id);
      if (!row) return res.status(404).json({ success: false, error: 'Newco not found' });

      // Use stored monitor or initialize empty
      const monitorRow = db.prepare("SELECT value FROM system_settings WHERE key = ?").get(`catapult_monitor_${req.params.id}`);
      const monitor = monitorRow ? JSON.parse(monitorRow.value) : { last_seen: {}, history: {}, warn_ms: 180000, timeout_ms: 300000 };

      const data = catapult.recordHeartbeat(monitor, record);

      db.prepare("INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)").run(
        `catapult_monitor_${req.params.id}`, JSON.stringify(data));

      return ok(res, { monitor: data });
    } catch (err) {
      return fail(res, err);
    }
  });

  /**
   * GET /api/catapult/newco/:id/health
   * Check heartbeat health.
   */
  app.get('/api/catapult/newco/:id/health', (req, res) => {
    try {
      const monitorRow = db.prepare("SELECT value FROM system_settings WHERE key = ?").get(`catapult_monitor_${req.params.id}`);
      const monitor = monitorRow ? JSON.parse(monitorRow.value) : { last_seen: {}, history: {}, warn_ms: 180000, timeout_ms: 300000 };
      const data = catapult.checkHeartbeatHealth(monitor, Date.now());
      return ok(res, data);
    } catch (err) {
      return fail(res, err);
    }
  });

  // ===========================================================================
  // BUDGET
  // ===========================================================================

  /**
   * POST /api/catapult/newco/:id/cost
   * Record a cost event.
   * Body: { event, actorDid }
   */
  app.post('/api/catapult/newco/:id/cost', (req, res) => {
    try {
      const { event, actorDid } = req.body;
      const row = db.prepare('SELECT newco_json FROM catapult_newcos WHERE id = ?').get(req.params.id);
      if (!row) return res.status(404).json({ success: false, error: 'Newco not found' });

      const newco = JSON.parse(row.newco_json);
      const updatedLedger = catapult.recordCostEvent(newco.budget, event);
      newco.budget = updatedLedger;

      db.prepare('UPDATE catapult_newcos SET newco_json = ?, updated_at = datetime(\'now\') WHERE id = ?')
        .run(JSON.stringify(newco), req.params.id);

      const receipt = createReceipt('cost_record', 'newco', req.params.id,
        actorDid || event.agent_did, `Cost: ${event.amount} ${event.metric}`, event);
      broadcast('catapult:budget:cost', { newcoId: req.params.id, amount: event.amount });
      return ok(res, { budget: updatedLedger }, receipt);
    } catch (err) {
      return fail(res, err);
    }
  });

  /**
   * GET /api/catapult/newco/:id/budget
   * Get budget status.
   */
  app.get('/api/catapult/newco/:id/budget', (req, res) => {
    try {
      const row = db.prepare('SELECT newco_json FROM catapult_newcos WHERE id = ?').get(req.params.id);
      if (!row) return res.status(404).json({ success: false, error: 'Newco not found' });

      const newco = JSON.parse(row.newco_json);
      const verdict = catapult.enforceBudget(newco);
      return ok(res, verdict);
    } catch (err) {
      return fail(res, err);
    }
  });

  // ===========================================================================
  // GOALS
  // ===========================================================================

  /**
   * POST /api/catapult/newco/:id/goal
   * Create a goal.
   * Body: { goal, actorDid }
   */
  app.post('/api/catapult/newco/:id/goal', (req, res) => {
    try {
      const { goal, actorDid } = req.body;
      const row = db.prepare('SELECT newco_json FROM catapult_newcos WHERE id = ?').get(req.params.id);
      if (!row) return res.status(404).json({ success: false, error: 'Newco not found' });

      const newco = JSON.parse(row.newco_json);
      const updatedTree = catapult.createGoal(newco.goals, goal);
      newco.goals = updatedTree;

      db.prepare('UPDATE catapult_newcos SET newco_json = ?, updated_at = datetime(\'now\') WHERE id = ?')
        .run(JSON.stringify(newco), req.params.id);

      const receipt = createReceipt('goal_create', 'newco', req.params.id,
        actorDid, `Created goal: ${goal.title}`, goal);
      broadcast('catapult:goal:created', { newcoId: req.params.id, goal });
      return ok(res, { goals: updatedTree }, receipt);
    } catch (err) {
      return fail(res, err);
    }
  });

  /**
   * PATCH /api/catapult/newco/:id/goal/:goalId
   * Update a goal's status.
   * Body: { status, actorDid }
   */
  app.patch('/api/catapult/newco/:id/goal/:goalId', (req, res) => {
    try {
      const { status, actorDid } = req.body;
      const row = db.prepare('SELECT newco_json FROM catapult_newcos WHERE id = ?').get(req.params.id);
      if (!row) return res.status(404).json({ success: false, error: 'Newco not found' });

      const newco = JSON.parse(row.newco_json);
      const updatedTree = catapult.updateGoalStatus(newco.goals, req.params.goalId, status);
      newco.goals = updatedTree;

      db.prepare('UPDATE catapult_newcos SET newco_json = ?, updated_at = datetime(\'now\') WHERE id = ?')
        .run(JSON.stringify(newco), req.params.id);

      const receipt = createReceipt('goal_update', 'newco', req.params.id,
        actorDid, `Updated goal ${req.params.goalId} → ${status}`, { goalId: req.params.goalId, status });
      broadcast('catapult:goal:updated', { newcoId: req.params.id, goalId: req.params.goalId, status });
      return ok(res, { goals: updatedTree }, receipt);
    } catch (err) {
      return fail(res, err);
    }
  });

  /**
   * GET /api/catapult/newco/:id/alignment
   * Get goal alignment score.
   */
  app.get('/api/catapult/newco/:id/alignment', (req, res) => {
    try {
      const row = db.prepare('SELECT newco_json FROM catapult_newcos WHERE id = ?').get(req.params.id);
      if (!row) return res.status(404).json({ success: false, error: 'Newco not found' });

      const newco = JSON.parse(row.newco_json);
      const score = catapult.goalAlignmentScore(newco.goals);
      return ok(res, { alignment_bps: score, alignment_pct: (score / 100).toFixed(1) });
    } catch (err) {
      return fail(res, err);
    }
  });

  // ===========================================================================
  // INTERNAL HELPERS
  // ===========================================================================

  function _registerRosterSlot(newcoId, slot, did) {
    db.prepare(`INSERT OR REPLACE INTO catapult_roster (newco_id, slot, did_identity, hired_at)
      VALUES (?, ?, ?, datetime('now'))`).run(newcoId, slot, did);
  }
};
