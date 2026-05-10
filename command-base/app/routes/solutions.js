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
 * Solutions Builder API Routes — Express route module
 *
 * Provides REST API endpoints for solution lifecycle management through ExoForge:
 *   GET    /api/solutions/templates       — List available solution templates
 *   POST   /api/solutions/create          — Create new solution from template + config
 *   GET    /api/solutions/:id             — Get solution status and details
 *   POST   /api/solutions/:id/deploy      — Deploy solution through ExoForge
 *   GET    /api/solutions/:id/workflow    — Get Syntaxis workflow for solution
 *   POST   /api/solutions/:id/cancel      — Cancel a running deployment
 *   GET    /api/solutions/:id/executions  — List all executions for solution
 *
 * Each route:
 *   1. Validates request parameters
 *   2. Performs solution or workflow operation
 *   3. Creates governance receipt
 *   4. Returns { success, data, receipt } or { error }
 *
 * Follows standard CommandBase route pattern:
 *   module.exports = function(app, db, helpers) { ... }
 */

const crypto = require('crypto');

module.exports = function(app, db, helpers) {
  const { localNow, broadcast } = helpers;

  // ──────────────────────────────────────────────────────────────────────────
  // ── Internal: Governance Receipt Creation ────────────────────────────────
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Hash data for governance chain.
   */
  function govHash(data) {
    return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
  }

  /**
   * Create governance receipt for solutions operations.
   */
  function createReceipt(actionType, entityType, entityId, actor, description, payload, projectId) {
    const now = localNow();
    const payloadHash = govHash(payload);
    const lastReceipt = db.prepare(
      'SELECT id, receipt_hash FROM governance_receipts ORDER BY id DESC LIMIT 1'
    ).get();
    const previousHash = lastReceipt
      ? lastReceipt.receipt_hash
      : '0000000000000000000000000000000000000000000000000000000000000000';
    const chainDepth = lastReceipt ? (lastReceipt.id || 0) : 0;

    const receiptData = {
      actionType,
      entityType,
      entityId,
      actor,
      payloadHash,
      previousHash,
      branch: 'executive',
      adjudication: 'pass',
      chainDepth,
      timestamp: now
    };
    const receiptHash = govHash(receiptData);

    try {
      const result = db.prepare(`
        INSERT INTO governance_receipts (
          action_type, entity_type, entity_id, actor, description,
          payload_hash, previous_hash, receipt_hash, invariants_checked, invariants_passed,
          project_id, created_at, hash_algorithm, encoding, branch,
          adjudication, metadata, chain_depth, verified
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        actionType, entityType, entityId, actor, description,
        payloadHash, previousHash, receiptHash, '[]', 1,
        projectId || null, now, 'sha256', 'json', 'executive',
        'pass', '{}', chainDepth + 1, 1
      );

      return {
        hash: receiptHash,
        depth: chainDepth + 1,
        id: Number(result.lastInsertRowid)
      };
    } catch (err) {
      return {
        hash: receiptHash,
        depth: chainDepth + 1,
        id: null,
        soft: true
      };
    }
  }

  // ──────────────────────────────────────────────────────────────────────────
  // ── Internal: Ensure Tables ──────────────────────────────────────────────
  // ──────────────────────────────────────────────────────────────────────────

  function ensureTables() {
    try {
      db.exec(`
        CREATE TABLE IF NOT EXISTS solution_templates (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL UNIQUE,
          description TEXT,
          category TEXT,
          template_config TEXT,
          workflow_steps_json TEXT,
          invariants_json TEXT,
          bcts_coverage_json TEXT,
          tags TEXT DEFAULT '[]',
          created_at TEXT NOT NULL,
          updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS solutions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          template_id INTEGER,
          name TEXT NOT NULL,
          description TEXT,
          status TEXT NOT NULL DEFAULT 'draft',
          configuration TEXT,
          deployment_config TEXT,
          bcts_state TEXT DEFAULT 'Draft',
          created_at TEXT NOT NULL,
          updated_at TEXT,
          deployed_at TEXT,
          FOREIGN KEY (template_id) REFERENCES solution_templates(id)
        );

        CREATE TABLE IF NOT EXISTS solution_deployments (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          solution_id INTEGER NOT NULL,
          deployment_id TEXT NOT NULL UNIQUE,
          queue_id INTEGER,
          status TEXT NOT NULL DEFAULT 'pending',
          started_at TEXT,
          completed_at TEXT,
          error_message TEXT,
          created_at TEXT NOT NULL,
          FOREIGN KEY (solution_id) REFERENCES solutions(id),
          FOREIGN KEY (queue_id) REFERENCES exoforge_queue(id)
        );
      `);
    } catch (_) {
      // Tables already exist
    }
  }

  /**
   * Seed the 7 built-in Syntaxis solution templates if the table is empty.
   * Maps the SolutionsBuilder templates to the solution_templates schema.
   */
  function seedTemplates() {
    const count = db.prepare('SELECT COUNT(*) as c FROM solution_templates').get();
    if (count && count.c > 0) return; // Already seeded

    const now = localNow();
    const templates = [
      {
        name: 'Governance Amendment',
        description: 'Proposes and ratifies changes to governance policies through council review and consent verification',
        category: 'GOVERNANCE',
        template_config: JSON.stringify({ amendmentScope: 'policy', requiresConsent: true, consentThreshold: 0.75 }),
        workflow_steps_json: JSON.stringify([
          'identity-verify', 'authority-check', 'governance-propose', 'consent-request',
          'consent-verify', 'governance-vote', 'governance-resolve'
        ]),
        invariants_json: JSON.stringify(['governance_quorum_met', 'consent_threshold_achieved', 'amendment_scope_valid']),
        bcts_coverage_json: JSON.stringify(['Submitted', 'IdentityResolved', 'ConsentValidated', 'Deliberated', 'Governed', 'Closed']),
        tags: JSON.stringify(['governance', 'amendment', 'policy', 'council'])
      },
      {
        name: 'Feature Implementation',
        description: 'End-to-end feature implementation with governance approval, invariant checking, and proof generation',
        category: 'DEVELOPMENT',
        template_config: JSON.stringify({ featureScope: 'module', testCoverage: 95, requiresCouncilReview: true }),
        workflow_steps_json: JSON.stringify([
          'identity-verify', 'authority-check', 'governance-propose', 'governance-vote',
          'governance-resolve', 'invariant-check', 'proof-generate', 'dag-append'
        ]),
        invariants_json: JSON.stringify(['test_coverage_threshold', 'no_regression_failures', 'api_contract_stable']),
        bcts_coverage_json: JSON.stringify(['Submitted', 'IdentityResolved', 'Deliberated', 'Governed', 'Approved', 'Executed', 'Recorded', 'Closed']),
        tags: JSON.stringify(['feature', 'development', 'implementation'])
      },
      {
        name: 'Bug Fix',
        description: 'Targeted bug fix with triage classification, minimal governance overhead, and verification',
        category: 'MAINTENANCE',
        template_config: JSON.stringify({ bugSeverity: 'medium', affectedComponents: [], testCoverage: 90, rollbackStrategy: 'automatic' }),
        workflow_steps_json: JSON.stringify([
          'identity-verify', 'authority-check', 'invariant-check', 'proof-generate',
          'proof-verify', 'state-transition', 'dag-append'
        ]),
        invariants_json: JSON.stringify(['bug_reproduction_confirmed', 'fix_verified', 'no_side_effects']),
        bcts_coverage_json: JSON.stringify(['Submitted', 'IdentityResolved', 'Verified', 'Executed', 'Recorded', 'Closed']),
        tags: JSON.stringify(['bug', 'fix', 'maintenance', 'patch'])
      },
      {
        name: 'Security Patch',
        description: 'Security-critical patch with full 5-panel council review, kernel adjudication, and tenant isolation',
        category: 'SECURITY',
        template_config: JSON.stringify({ patchSeverity: 'high', affectedSystems: [], testingRequired: true, rolloutPhase: 'canary' }),
        workflow_steps_json: JSON.stringify([
          'identity-verify', 'authority-check', 'governance-propose', 'governance-vote',
          'governance-resolve', 'kernel-adjudicate', 'tenant-isolate', 'invariant-check',
          'proof-generate', 'dag-append'
        ]),
        invariants_json: JSON.stringify(['vulnerability_patched', 'no_new_attack_vectors', 'tenant_isolation_maintained', 'audit_trail_complete']),
        bcts_coverage_json: JSON.stringify(['Submitted', 'IdentityResolved', 'ConsentValidated', 'Deliberated', 'Governed', 'Approved', 'Verified', 'Executed', 'Recorded', 'Closed']),
        tags: JSON.stringify(['security', 'patch', 'vulnerability', 'critical'])
      },
      {
        name: 'Infrastructure Change',
        description: 'Infrastructure modification with tenant isolation, MCP enforcement, and parallel validation gates',
        category: 'INFRASTRUCTURE',
        template_config: JSON.stringify({ affectedTenants: [], changeScope: 'regional', maintenanceWindow: '4h', blueGreenStrategy: true }),
        workflow_steps_json: JSON.stringify([
          'governance-propose', 'authority-check', 'tenant-isolate', 'mcp-enforce',
          'combinator-parallel', 'combinator-guard', 'proof-generate', 'dag-append'
        ]),
        invariants_json: JSON.stringify(['tenant_data_isolation', 'zero_downtime_deployment', 'rollback_tested']),
        bcts_coverage_json: JSON.stringify(['Submitted', 'IdentityResolved', 'Deliberated', 'Governed', 'Approved', 'Executed', 'Recorded', 'Closed']),
        tags: JSON.stringify(['infrastructure', 'deployment', 'tenant', 'mcp'])
      },
      {
        name: 'Access Control Update',
        description: 'Updates access control policies with identity verification, authority delegation, and consent management',
        category: 'SECURITY',
        template_config: JSON.stringify({ accessLevel: 'role', targetSubjects: [], grantDuration: '90d', permissions: [] }),
        workflow_steps_json: JSON.stringify([
          'identity-verify', 'authority-check', 'authority-delegate', 'consent-request',
          'consent-verify', 'invariant-check', 'proof-generate', 'dag-append'
        ]),
        invariants_json: JSON.stringify(['least_privilege_maintained', 'consent_recorded', 'audit_trail_complete']),
        bcts_coverage_json: JSON.stringify(['Submitted', 'IdentityResolved', 'ConsentValidated', 'Governed', 'Executed', 'Recorded', 'Closed']),
        tags: JSON.stringify(['access', 'control', 'permissions', 'delegation'])
      },
      {
        name: 'Escalation Resolution',
        description: 'Resolves escalated issues through human override, kernel adjudication, and governance resolution',
        category: 'GOVERNANCE',
        template_config: JSON.stringify({ escalationReason: '', disputeDetails: '', resolutionCriteria: '' }),
        workflow_steps_json: JSON.stringify([
          'escalation-trigger', 'human-override', 'kernel-adjudicate',
          'governance-resolve', 'proof-generate', 'dag-append'
        ]),
        invariants_json: JSON.stringify(['resolution_documented', 'all_parties_notified', 'precedent_recorded']),
        bcts_coverage_json: JSON.stringify(['Submitted', 'Escalated', 'Deliberated', 'Governed', 'Closed']),
        tags: JSON.stringify(['escalation', 'resolution', 'dispute', 'override'])
      }
    ];

    const insertStmt = db.prepare(`
      INSERT INTO solution_templates (name, description, category, template_config, workflow_steps_json, invariants_json, bcts_coverage_json, tags, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const insertAll = db.transaction(() => {
      for (const t of templates) {
        insertStmt.run(
          t.name, t.description, t.category, t.template_config,
          t.workflow_steps_json, t.invariants_json, t.bcts_coverage_json,
          t.tags, now
        );
      }
    });

    insertAll();
  }

  // ══════════════════════════════════════════════════════════════════════════
  // ROUTE: GET /api/solutions/templates
  // Returns list of available solution templates.
  // ══════════════════════════════════════════════════════════════════════════

  app.get('/api/solutions/templates', (req, res) => {
    try {
      ensureTables();
      seedTemplates();

      const { category, limit: lim } = req.query;
      let sql = 'SELECT id, name, description, category, tags, created_at FROM solution_templates WHERE 1=1';
      const params = [];

      if (category) {
        sql += ' AND category = ?';
        params.push(category);
      }

      sql += ' ORDER BY created_at DESC LIMIT ?';
      params.push(parseInt(lim) || 50);

      const templates = db.prepare(sql).all(...params);

      // Parse JSON fields
      const parsed = templates.map(t => ({
        ...t,
        tags: JSON.parse(t.tags || '[]')
      }));

      res.json({
        success: true,
        data: {
          templates: parsed,
          count: parsed.length
        }
      });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // ROUTE: POST /api/solutions/create
  // Create a new solution from template + configuration.
  // Body: { template_id, name, description, configuration }
  // ══════════════════════════════════════════════════════════════════════════

  app.post('/api/solutions/create', (req, res) => {
    try {
      ensureTables();

      const { template_id, name, description, configuration } = req.body;

      if (!template_id || !name) {
        return res.status(400).json({
          success: false,
          error: 'Provide template_id and name'
        });
      }

      // Verify template exists
      const template = db.prepare('SELECT * FROM solution_templates WHERE id = ?').get(template_id);
      if (!template) {
        return res.status(404).json({
          success: false,
          error: 'Template not found'
        });
      }

      const now = localNow();
      const result = db.prepare(`
        INSERT INTO solutions (
          template_id, name, description, status, configuration, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        template_id,
        name.trim(),
        description || null,
        'draft',
        JSON.stringify(configuration || {}),
        now,
        now
      );

      const solutionId = Number(result.lastInsertRowid);

      // Create receipt
      const receipt = createReceipt(
        'solution_created',
        'solution',
        solutionId,
        'user',
        `Solution '${name}' created from template '${template.name}'`,
        { template_id, name, solution_id: solutionId },
        null
      );

      res.status(201).json({
        success: true,
        data: {
          solution_id: solutionId,
          name,
          status: 'draft',
          created_at: now
        },
        receipt
      });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // ROUTE: GET /api/solutions/:id
  // Get solution status and details.
  // ══════════════════════════════════════════════════════════════════════════

  app.get('/api/solutions/:id', (req, res) => {
    try {
      ensureTables();

      const solutionId = parseInt(req.params.id);
      const solution = db.prepare(`
        SELECT s.*, t.name as template_name, t.description as template_description
        FROM solutions s
        LEFT JOIN solution_templates t ON s.template_id = t.id
        WHERE s.id = ?
      `).get(solutionId);

      if (!solution) {
        return res.status(404).json({ success: false, error: 'Solution not found' });
      }

      // Get latest deployment
      const latestDeployment = db.prepare(`
        SELECT * FROM solution_deployments WHERE solution_id = ? ORDER BY id DESC LIMIT 1
      `).get(solutionId);

      // Get all deployments summary
      const deploymentStats = db.prepare(`
        SELECT
          COUNT(*) as total,
          SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as successful,
          SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
          SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running
        FROM solution_deployments WHERE solution_id = ?
      `).get(solutionId);

      res.json({
        success: true,
        data: {
          solution: {
            ...solution,
            configuration: JSON.parse(solution.configuration || '{}'),
            deployment_config: JSON.parse(solution.deployment_config || '{}')
          },
          latest_deployment: latestDeployment,
          deployment_stats: deploymentStats
        }
      });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // ROUTE: POST /api/solutions/:id/deploy
  // Deploy solution through ExoForge dispatch pipeline.
  // Body: { deployment_config }
  // ══════════════════════════════════════════════════════════════════════════

  app.post('/api/solutions/:id/deploy', (req, res) => {
    try {
      ensureTables();

      const solutionId = parseInt(req.params.id);
      const { deployment_config } = req.body;

      // Verify solution exists
      const solution = db.prepare('SELECT * FROM solutions WHERE id = ?').get(solutionId);
      if (!solution) {
        return res.status(404).json({ success: false, error: 'Solution not found' });
      }

      // Check if already deploying
      const activeDeployment = db.prepare(
        'SELECT id FROM solution_deployments WHERE solution_id = ? AND status = ?'
      ).get(solutionId, 'running');

      if (activeDeployment) {
        return res.status(409).json({
          success: false,
          error: 'Solution is already being deployed'
        });
      }

      const now = localNow();
      const deploymentId = `deploy-${solutionId}-${Date.now().toString(36)}`;

      // Create exoforge queue item
      const queueResult = db.prepare(`
        INSERT INTO exoforge_queue (
          source, source_id, title, priority, status, labels, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        'solution',
        solutionId,
        `Deploy solution: ${solution.name}`,
        'high',
        'implementing',
        JSON.stringify(['type:solution', 'source:solutions-builder']),
        now
      );

      const queueId = Number(queueResult.lastInsertRowid);

      // Record deployment
      db.prepare(`
        INSERT INTO solution_deployments (
          solution_id, deployment_id, queue_id, status, started_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
      `).run(solutionId, deploymentId, queueId, 'running', now, now);

      // Update solution status
      db.prepare(`
        UPDATE solutions SET status = ?, deployment_config = ?, updated_at = ? WHERE id = ?
      `).run('deploying', JSON.stringify(deployment_config || {}), now, solutionId);

      // Create receipt
      const receipt = createReceipt(
        'solution_deployment_started',
        'solution_deployment',
        deploymentId,
        'user',
        `Deployment started for solution '${solution.name}'`,
        { solution_id: solutionId, deployment_id: deploymentId, queue_id: queueId },
        null
      );

      // Broadcast deployment event
      if (broadcast) {
        broadcast('solution:deployment_started', {
          solution_id: solutionId,
          deployment_id: deploymentId,
          queue_id: queueId,
          solution_name: solution.name
        });
      }

      res.json({
        success: true,
        data: {
          solution_id: solutionId,
          deployment_id: deploymentId,
          queue_id: queueId,
          status: 'running',
          started_at: now
        },
        receipt
      });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // ROUTE: GET /api/solutions/:id/workflow
  // Get the Syntaxis workflow definition for a solution.
  // ══════════════════════════════════════════════════════════════════════════

  app.get('/api/solutions/:id/workflow', (req, res) => {
    try {
      ensureTables();

      const solutionId = parseInt(req.params.id);

      // Get solution and template
      const solution = db.prepare(`
        SELECT s.*, t.workflow_steps_json, t.invariants_json, t.bcts_coverage_json
        FROM solutions s
        LEFT JOIN solution_templates t ON s.template_id = t.id
        WHERE s.id = ?
      `).get(solutionId);

      if (!solution) {
        return res.status(404).json({ success: false, error: 'Solution not found' });
      }

      // Build workflow with merged configuration
      const workflow = {
        name: solution.name,
        description: solution.description,
        composition: 'sequence',
        steps: JSON.parse(solution.workflow_steps_json || '[]'),
        invariants: JSON.parse(solution.invariants_json || '[]'),
        bcts_coverage: JSON.parse(solution.bcts_coverage_json || '[]'),
        configuration: JSON.parse(solution.configuration || '{}')
      };

      res.json({
        success: true,
        data: {
          workflow,
          source: 'template'
        }
      });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // ROUTE: POST /api/solutions/:id/cancel
  // Cancel a running solution deployment.
  // ══════════════════════════════════════════════════════════════════════════

  app.post('/api/solutions/:id/cancel', (req, res) => {
    try {
      ensureTables();

      const solutionId = parseInt(req.params.id);
      const now = localNow();

      // Find running deployment
      const deployment = db.prepare(
        'SELECT * FROM solution_deployments WHERE solution_id = ? AND status = ?'
      ).get(solutionId, 'running');

      if (!deployment) {
        return res.status(404).json({
          success: false,
          error: 'No running deployment found'
        });
      }

      // Cancel deployment
      db.prepare(`
        UPDATE solution_deployments SET status = ?, completed_at = ? WHERE id = ?
      `).run('cancelled', now, deployment.id);

      // Update queue item
      if (deployment.queue_id) {
        db.prepare(`UPDATE exoforge_queue SET status = ?, updated_at = ? WHERE id = ?`)
          .run('cancelled', now, deployment.queue_id);
      }

      // Update solution
      db.prepare(`UPDATE solutions SET status = ?, updated_at = ? WHERE id = ?`)
        .run('cancelled', now, solutionId);

      // Create receipt
      const receipt = createReceipt(
        'solution_deployment_cancelled',
        'solution_deployment',
        deployment.deployment_id,
        'user',
        'Deployment cancelled by user',
        { solution_id: solutionId, deployment_id: deployment.deployment_id },
        null
      );

      if (broadcast) {
        broadcast('solution:deployment_cancelled', {
          solution_id: solutionId,
          deployment_id: deployment.deployment_id
        });
      }

      res.json({
        success: true,
        data: {
          solution_id: solutionId,
          deployment_id: deployment.deployment_id,
          status: 'cancelled'
        },
        receipt
      });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // ROUTE: GET /api/solutions/:id/executions
  // List all workflow executions for a solution.
  // ══════════════════════════════════════════════════════════════════════════

  app.get('/api/solutions/:id/executions', (req, res) => {
    try {
      ensureTables();

      const solutionId = parseInt(req.params.id);
      const { limit: lim } = req.query;

      // Get all deployments
      const deployments = db.prepare(`
        SELECT sd.*, ewe.execution_id, ewe.nodes_executed, ewe.nodes_failed
        FROM solution_deployments sd
        LEFT JOIN exoforge_workflow_executions ewe ON sd.queue_id = ewe.queue_id
        WHERE sd.solution_id = ?
        ORDER BY sd.id DESC
        LIMIT ?
      `).all(solutionId, parseInt(lim) || 50);

      res.json({
        success: true,
        data: {
          solution_id: solutionId,
          executions: deployments,
          count: deployments.length
        }
      });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });
};
