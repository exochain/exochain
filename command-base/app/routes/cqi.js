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
 * CQI Routes — Continuous Quality Improvement API endpoints
 *
 * Exposes the CQI orchestrator as HTTP endpoints:
 *   POST /api/cqi/cycle           — Start a new CQI self-improvement cycle
 *   GET  /api/cqi/cycle/:id       — Get cycle status
 *   GET  /api/cqi/cycle/:id/log   — Get cycle governance receipts
 *   POST /api/cqi/council-review  — Submit a proposal for 5-panel council review
 *   GET  /api/cqi/metrics         — Collect and return current system metrics
 *   GET  /api/cqi/proposals       — List all CQI proposals
 *
 * Follows the standard CommandBase route pattern:
 *   module.exports = function(app, db, helpers) { ... }
 */

module.exports = function(app, db, helpers) {
  const { localNow, broadcast } = helpers;

  // Lazy-init orchestrator (created on first use to avoid startup ordering issues)
  let _orchestrator = null;
  function getOrchestrator() {
    if (!_orchestrator) {
      const cqiModule = require('../services/cqi-orchestrator')(db, helpers);
      _orchestrator = cqiModule.createOrchestrator(db, helpers);
    }
    return _orchestrator;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // POST /api/cqi/cycle — Start a new CQI self-improvement cycle
  // ══════════════════════════════════════════════════════════════════════════

  app.post('/api/cqi/cycle', (req, res) => {
    try {
      const orchestrator = getOrchestrator();
      const cycleId = req.body.cycle_id || `cqi-${Date.now().toString(36)}`;
      const opts = {
        forceRun: req.body.force || false,
        skipCouncil: req.body.skip_council || false,
      };

      const result = orchestrator.runCycle(cycleId, opts);

      // Broadcast CQI cycle event for live dashboard updates
      if (broadcast) {
        broadcast({ type: 'cqi:cycle', data: { cycle_id: cycleId, result } });
      }

      res.json({
        success: true,
        data: result,
      });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // GET /api/cqi/cycle/:id — Get cycle status
  // ══════════════════════════════════════════════════════════════════════════

  app.get('/api/cqi/cycle/:id', (req, res) => {
    try {
      const cycle = db.prepare('SELECT * FROM cqi_cycles WHERE cycle_id = ?').get(req.params.id);
      if (!cycle) {
        return res.status(404).json({ success: false, error: 'Cycle not found' });
      }

      // Enrich with proposals
      const proposals = db.prepare('SELECT * FROM cqi_proposals WHERE cycle_id = ?').all(req.params.id);
      const verifications = db.prepare('SELECT * FROM cqi_verification_results WHERE cycle_id = ?').all(req.params.id);

      res.json({
        success: true,
        data: {
          ...cycle,
          metadata: JSON.parse(cycle.metadata || '{}'),
          proposals: proposals.map(p => ({
            ...p,
            affected_modules: JSON.parse(p.affected_modules || '[]'),
            test_criteria: JSON.parse(p.test_criteria || '[]'),
            panel_votes: JSON.parse(p.panel_votes || '{}'),
          })),
          verifications: verifications.map(v => ({
            ...v,
            test_results: JSON.parse(v.test_results || '{}'),
          })),
        },
      });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // GET /api/cqi/cycle/:id/log — Get governance receipts for a cycle
  // ══════════════════════════════════════════════════════════════════════════

  app.get('/api/cqi/cycle/:id/log', (req, res) => {
    try {
      // Collect ALL CQI-related receipts for this cycle:
      //  - entity_type='cqi_cycle' with entity_id=cycleId (deploy receipts)
      //  - entity_type='cqi_proposal' for proposals belonging to this cycle
      //  - entity_type='exoforge_queue' for dispatched implementations
      //  - any receipt whose action_type starts with 'cqi_' and description mentions the cycle
      const receipts = db.prepare(`
        SELECT * FROM governance_receipts
        WHERE (entity_type = 'cqi_cycle' AND entity_id = ?)
           OR (entity_type IN ('cqi_proposal', 'exoforge_queue')
               AND action_type LIKE 'cqi_%'
               AND description LIKE ?)
        ORDER BY id ASC
      `).all(req.params.id, `%${req.params.id}%`);

      res.json({
        success: true,
        data: {
          cycle_id: req.params.id,
          receipt_count: receipts.length,
          receipts,
        },
      });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // POST /api/cqi/council-review — Submit a proposal for 5-panel review
  // ══════════════════════════════════════════════════════════════════════════

  app.post('/api/cqi/council-review', (req, res) => {
    try {
      const orchestrator = getOrchestrator();
      const { proposal } = req.body;

      if (!proposal || !proposal.proposal_id) {
        return res.status(400).json({
          success: false,
          error: 'Provide { proposal: { proposal_id, title, ... } }',
        });
      }

      const review = orchestrator.councilReview(proposal);

      if (broadcast) {
        broadcast({
          type: 'cqi:council-review',
          data: { proposal_id: proposal.proposal_id, verdict: review.verdict },
        });
      }

      res.json({ success: true, data: review });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // GET /api/cqi/metrics — Collect current system metrics
  // ══════════════════════════════════════════════════════════════════════════

  app.get('/api/cqi/metrics', (req, res) => {
    try {
      const orchestrator = getOrchestrator();
      const telemetry = orchestrator.collectMetrics();

      res.json({ success: true, data: telemetry });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // GET /api/cqi/proposals — List all CQI proposals
  // ══════════════════════════════════════════════════════════════════════════

  app.get('/api/cqi/proposals', (req, res) => {
    try {
      // Ensure table exists
      getOrchestrator();

      const { status, cycle_id, limit: lim } = req.query;
      let sql = 'SELECT * FROM cqi_proposals WHERE 1=1';
      const params = [];

      if (status) { sql += ' AND status = ?'; params.push(status); }
      if (cycle_id) { sql += ' AND cycle_id = ?'; params.push(cycle_id); }

      sql += ' ORDER BY created_at DESC LIMIT ?';
      params.push(parseInt(lim) || 50);

      const proposals = db.prepare(sql).all(...params);

      res.json({
        success: true,
        data: proposals.map(p => ({
          ...p,
          affected_modules: JSON.parse(p.affected_modules || '[]'),
          test_criteria: JSON.parse(p.test_criteria || '[]'),
          panel_votes: JSON.parse(p.panel_votes || '{}'),
        })),
      });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });
};
