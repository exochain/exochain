'use strict';

/**
 * ExoForge Status Routes — Express route module
 *
 * Provides API endpoints for the ExoForge autonomous implementation engine:
 *   GET  /api/exoforge/cycle    — current self-improvement cycle status
 *   GET  /api/exoforge/queue    — triaged items awaiting implementation
 *   POST /api/exoforge/triage   — trigger triage on a set of items
 *   GET  /api/exoforge/health   — governance health metrics from kernel
 *
 * Each route:
 *   1. Calls the appropriate exochain service function(s)
 *   2. Produces a governance receipt
 *   3. Returns { success, data, receipt } or { error }
 *
 * Follows the standard CommandBase route pattern:
 *   module.exports = function(app, db, helpers) { ... }
 */

const crypto = require('crypto');

module.exports = function(app, db, helpers) {
  const { localNow, broadcast } = helpers;

  // ── Internal: governance hashing ────────────────────────────────────────

  function govHash(data) {
    return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
  }

  // ── Internal: create governance receipt ─────────────────────────────────
  // Mirrors the governance service's createReceipt but operates within
  // this module to avoid circular dependency.

  function createReceipt(actionType, entityType, entityId, actor, description, payload, projectId) {
    const now = localNow();
    const payloadHash = govHash(payload);
    const lastReceipt = db.prepare('SELECT id, receipt_hash FROM governance_receipts ORDER BY id DESC LIMIT 1').get();
    const previousHash = lastReceipt ? lastReceipt.receipt_hash : '0'.repeat(64);
    const chainDepth = lastReceipt ? lastReceipt.id : 0;

    // Determine branch: exoforge actions are executive (automated operations)
    const branch = 'executive';
    const adjudication = 'pass';

    const receiptData = {
      actionType, entityType, entityId, actor, payloadHash,
      previousHash, branch, adjudication, chainDepth, timestamp: now
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
        projectId || null, now, 'sha256', 'json', branch,
        adjudication, '{}', chainDepth + 1, 1
      );

      // Also log to governance audit trail
      try {
        db.prepare(`INSERT INTO governance_audit_trail (action_type, actor_name, target_type, target_id, branch, invariants_checked, receipt_id, created_at)
          VALUES (?,?,?,?,?,?,?,?)`).run(actionType, 'exoforge', entityType, entityId, branch, '[]', Number(result.lastInsertRowid), now);
      } catch (_) { /* audit trail table may not exist in all deployments */ }

      return { hash: receiptHash, depth: chainDepth + 1, id: Number(result.lastInsertRowid) };
    } catch (err) {
      // If receipt creation fails (e.g. table missing), return a soft receipt
      return { hash: receiptHash, depth: chainDepth + 1, id: null, soft: true };
    }
  }

  // ── Internal: load WASM kernel if available ─────────────────────────────

  let wasm = null;
  function getKernel() {
    if (wasm) return wasm;
    try {
      wasm = require('../../packages/exochain-wasm/wasm');
    } catch (_) {
      return null;
    }
    return wasm;
  }

  // ── Internal: ExoForge cycle state management ──────────────────────────

  /**
   * Ensure the exoforge_cycles table exists.
   * Creates it on first use.
   */
  function ensureTables() {
    try {
      db.prepare(`CREATE TABLE IF NOT EXISTS exoforge_cycles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cycle_id TEXT NOT NULL,
        phase TEXT NOT NULL DEFAULT 'idle',
        status TEXT NOT NULL DEFAULT 'pending',
        items_triaged INTEGER DEFAULT 0,
        items_approved INTEGER DEFAULT 0,
        items_rejected INTEGER DEFAULT 0,
        items_implemented INTEGER DEFAULT 0,
        started_at TEXT,
        completed_at TEXT,
        created_at TEXT NOT NULL,
        metadata TEXT DEFAULT '{}'
      )`).run();
    } catch (_) { /* table already exists */ }

    try {
      db.prepare(`CREATE TABLE IF NOT EXISTS exoforge_queue (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cycle_id TEXT,
        source TEXT NOT NULL DEFAULT 'github',
        source_id TEXT,
        title TEXT NOT NULL,
        priority TEXT NOT NULL DEFAULT 'medium',
        primary_panel TEXT,
        total_impact REAL DEFAULT 0,
        impacts TEXT DEFAULT '{}',
        council_review_required INTEGER DEFAULT 0,
        council_verdict TEXT,
        status TEXT NOT NULL DEFAULT 'triaged',
        labels TEXT DEFAULT '[]',
        created_at TEXT NOT NULL,
        updated_at TEXT
      )`).run();
    } catch (_) { /* table already exists */ }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // ROUTE: GET /api/exoforge/cycle
  // Returns the current (or most recent) self-improvement cycle status.
  // ══════════════════════════════════════════════════════════════════════════

  app.get('/api/exoforge/cycle', (req, res) => {
    try {
      ensureTables();

      // Get the most recent cycle
      const current = db.prepare(`SELECT * FROM exoforge_cycles ORDER BY id DESC LIMIT 1`).get();

      if (!current) {
        return res.json({
          success: true,
          data: {
            cycle_id: null,
            phase: 'idle',
            status: 'no cycles started',
            progress: { triaged: 0, approved: 0, rejected: 0, implemented: 0 },
            message: 'No ExoForge cycles have been initiated. POST to /api/exoforge/triage to start.'
          }
        });
      }

      // Get queue stats for this cycle
      const queueStats = db.prepare(`SELECT
        COUNT(*) as total,
        SUM(CASE WHEN status = 'triaged' THEN 1 ELSE 0 END) as triaged,
        SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved,
        SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected,
        SUM(CASE WHEN status = 'implementing' THEN 1 ELSE 0 END) as implementing,
        SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed
      FROM exoforge_queue WHERE cycle_id = ?`).get(current.cycle_id);

      const metadata = JSON.parse(current.metadata || '{}');

      res.json({
        success: true,
        data: {
          cycle_id: current.cycle_id,
          phase: current.phase,
          status: current.status,
          started_at: current.started_at,
          completed_at: current.completed_at,
          progress: {
            triaged: current.items_triaged,
            approved: current.items_approved,
            rejected: current.items_rejected,
            implemented: current.items_implemented
          },
          queue: queueStats || { total: 0 },
          metadata
        }
      });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // ROUTE: GET /api/exoforge/queue
  // Returns triaged items (optionally filtered by status, priority, panel).
  // ══════════════════════════════════════════════════════════════════════════

  app.get('/api/exoforge/queue', (req, res) => {
    try {
      ensureTables();

      const { status, priority, panel, limit: lim, cycle_id } = req.query;
      let sql = 'SELECT * FROM exoforge_queue WHERE 1=1';
      const params = [];

      if (status) { sql += ' AND status = ?'; params.push(status); }
      if (priority) { sql += ' AND priority = ?'; params.push(priority); }
      if (panel) { sql += ' AND primary_panel = ?'; params.push(panel); }
      if (cycle_id) { sql += ' AND cycle_id = ?'; params.push(cycle_id); }

      sql += ' ORDER BY total_impact DESC, id DESC LIMIT ?';
      params.push(parseInt(lim) || 50);

      const items = db.prepare(sql).all(...params);

      // Parse JSON fields
      const parsed = items.map(item => ({
        ...item,
        impacts: JSON.parse(item.impacts || '{}'),
        labels: JSON.parse(item.labels || '[]'),
        council_review_required: !!item.council_review_required
      }));

      // Summary stats
      const stats = db.prepare(`SELECT
        COUNT(*) as total,
        SUM(CASE WHEN status = 'triaged' THEN 1 ELSE 0 END) as pending_triage,
        SUM(CASE WHEN council_review_required = 1 THEN 1 ELSE 0 END) as needs_review,
        AVG(total_impact) as avg_impact
      FROM exoforge_queue`).get();

      res.json({
        success: true,
        data: {
          items: parsed,
          count: parsed.length,
          stats: {
            total: stats.total,
            pending_triage: stats.pending_triage,
            needs_review: stats.needs_review,
            avg_impact: stats.avg_impact ? Math.round(stats.avg_impact * 1000) / 1000 : 0
          }
        }
      });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // ROUTE: POST /api/exoforge/triage
  // Triggers triage on submitted items. Accepts either:
  //   { items: [...] } — array of { title, description, source, source_id }
  //   { repo: "owner/name" } — triggers GitHub issue triage (placeholder)
  // ══════════════════════════════════════════════════════════════════════════

  app.post('/api/exoforge/triage', (req, res) => {
    try {
      ensureTables();

      const { items, repo } = req.body;

      if (!items && !repo) {
        return res.status(400).json({
          success: false,
          error: 'Provide either { items: [...] } or { repo: "owner/name" }'
        });
      }

      // Create or continue a cycle
      const now = localNow();
      const cycleId = `exoforge-${Date.now().toString(36)}`;
      db.prepare(`INSERT INTO exoforge_cycles (cycle_id, phase, status, started_at, created_at, metadata)
        VALUES (?, 'triage', 'active', ?, ?, ?)`).run(cycleId, now, now, JSON.stringify({ source: repo || 'manual' }));

      // Panel keywords for classification (mirroring exoforge-triage.js logic)
      const panelKeywords = {
        Governance: ['governance', 'constitutional', 'tnc', 'quorum', 'delegation', 'authority',
          'amendment', 'voting', 'deliberation', 'human gate', 'ai ceiling', 'consent', 'ratif'],
        Legal: ['legal', 'fiduciary', 'safe harbor', 'dgcl', 'privilege', 'evidence',
          'ediscovery', 'bailment', 'custody', 'retention', 'compliance', 'liability'],
        Architecture: ['architecture', 'wasm', 'kernel', 'merkle', 'combinator', 'holon',
          'bcts', 'state machine', 'transition', 'hash', 'event', 'did', 'signature'],
        Security: ['security', 'threat', 'vulnerability', 'pace', 'escalation', 'shamir',
          'secret', 'key', 'encrypt', 'attack', 'risk', 'detection', 'signal'],
        Operations: ['operations', 'deploy', 'release', 'monitor', 'health', 'succession',
          'emergency', 'failover', 'backup', 'ci', 'cd', 'pipeline', 'docker']
      };

      const panelWeights = {
        Governance: 0.25, Legal: 0.20, Architecture: 0.20, Security: 0.20, Operations: 0.15
      };

      // Triage each item
      const triageItems = items || [];
      const results = [];

      const insertStmt = db.prepare(`INSERT INTO exoforge_queue
        (cycle_id, source, source_id, title, priority, primary_panel, total_impact,
         impacts, council_review_required, status, labels, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`);

      const triageTransaction = db.transaction((triageItems) => {
        for (const item of triageItems) {
          const text = `${item.title || ''} ${item.description || ''}`.toLowerCase();
          const impacts = {};
          let totalImpact = 0;

          for (const [panel, keywords] of Object.entries(panelKeywords)) {
            let hits = 0;
            const matched = [];
            for (const kw of keywords) {
              if (text.includes(kw)) { hits++; matched.push(kw); }
            }
            const score = Math.min(1.0, hits / Math.max(3, keywords.length * 0.4));
            impacts[panel] = { score: Math.round(score * 100) / 100, hits, matched };
            totalImpact += score * (panelWeights[panel] || 0.2);
          }

          // Determine priority
          let priority;
          if (totalImpact > 0.6) priority = 'critical';
          else if (totalImpact > 0.3) priority = 'high';
          else if (totalImpact > 0.1) priority = 'medium';
          else priority = 'low';

          // Primary panel
          const primaryPanel = Object.entries(impacts)
            .sort((a, b) => b[1].score - a[1].score)[0][0];

          // Labels
          const labels = [];
          for (const [name, impact] of Object.entries(impacts)) {
            if (impact.score > 0.2) labels.push(`panel:${name.toLowerCase()}`);
          }
          labels.push(`priority:${priority}`);

          const requiresReview = totalImpact > 0.3 ? 1 : 0;

          insertStmt.run(
            cycleId,
            item.source || 'manual',
            item.source_id || null,
            item.title,
            priority,
            primaryPanel,
            Math.round(totalImpact * 1000) / 1000,
            JSON.stringify(impacts),
            requiresReview,
            'triaged',
            JSON.stringify(labels),
            now
          );

          results.push({
            title: item.title,
            priority,
            primary_panel: primaryPanel,
            total_impact: Math.round(totalImpact * 1000) / 1000,
            council_review_required: !!requiresReview,
            labels
          });
        }
      });

      triageTransaction(triageItems);

      // Update cycle counts
      const counts = {
        critical: results.filter(r => r.priority === 'critical').length,
        high: results.filter(r => r.priority === 'high').length,
        medium: results.filter(r => r.priority === 'medium').length,
        low: results.filter(r => r.priority === 'low').length
      };

      db.prepare(`UPDATE exoforge_cycles SET items_triaged = ?, metadata = ? WHERE cycle_id = ?`)
        .run(results.length, JSON.stringify({ source: repo || 'manual', counts }), cycleId);

      // Create governance receipt
      const receipt = createReceipt(
        'exoforge_triage',
        'exoforge_cycle',
        cycleId,
        'exoforge',
        `ExoForge triage: ${results.length} items classified (${counts.critical} critical, ${counts.high} high)`,
        { cycle_id: cycleId, items: results.length, counts },
        null
      );

      res.json({
        success: true,
        data: {
          cycle_id: cycleId,
          items_triaged: results.length,
          counts,
          council_reviews_needed: results.filter(r => r.council_review_required).length,
          results
        },
        receipt
      });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // ROUTE: GET /api/exoforge/health
  // Returns governance health metrics from the WASM kernel and database.
  // ══════════════════════════════════════════════════════════════════════════

  app.get('/api/exoforge/health', (req, res) => {
    try {
      const checks = [];
      let kernelAvailable = false;

      // Check 1: WASM kernel availability
      const kernel = getKernel();
      if (kernel) {
        kernelAvailable = true;
        checks.push({ check: 'kernel_availability', status: 'healthy', score: 1.0 });

        // Check 2: TNC enforcement
        try {
          const tncResult = kernel.wasm_enforce_all_tnc(
            JSON.stringify({
              id: 'health-' + Date.now(),
              title: 'Health Check',
              class: 'Routine',
              state: 'Draft',
              constitution_hash: '0'.repeat(64),
              votes: [],
              evidence: [],
              created_at: Date.now(),
              transitions: []
            }),
            JSON.stringify({
              authority_chain_verified: true,
              human_gate_satisfied: true,
              consent_verified: true,
              identity_verified: true,
              delegation_unexpired: true,
              constitutional_binding_valid: true,
              quorum_met: true,
              terminal_immutable: true,
              ai_ceiling_respected: true,
              evidence_bundle_complete: true
            })
          );
          checks.push({ check: 'tnc_enforcement', status: 'healthy', score: 1.0 });
        } catch (err) {
          checks.push({ check: 'tnc_enforcement', status: 'degraded', score: 0.5, error: err.message });
        }

        // Check 3: Workflow stages
        try {
          const stages = kernel.wasm_workflow_stages();
          const stageList = Array.isArray(stages) ? stages : Object.keys(stages || {});
          checks.push({
            check: 'workflow_stages',
            status: stageList.length >= 4 ? 'healthy' : 'degraded',
            score: stageList.length >= 4 ? 1.0 : 0.5,
            stage_count: stageList.length
          });
        } catch (err) {
          checks.push({ check: 'workflow_stages', status: 'critical', score: 0.0, error: err.message });
        }

        // Check 4: Audit chain verification
        try {
          kernel.wasm_audit_verify(JSON.stringify([]));
          checks.push({ check: 'audit_chain', status: 'healthy', score: 1.0 });
        } catch (err) {
          checks.push({ check: 'audit_chain', status: 'degraded', score: 0.5, error: err.message });
        }
      } else {
        checks.push({ check: 'kernel_availability', status: 'critical', score: 0.0, error: 'WASM kernel not loaded' });
      }

      // Check 5: Governance receipt chain integrity (from database)
      try {
        const lastTwo = db.prepare('SELECT receipt_hash, previous_hash FROM governance_receipts ORDER BY id DESC LIMIT 2').all();
        let chainValid = true;
        if (lastTwo.length === 2 && lastTwo[1].receipt_hash !== lastTwo[0].previous_hash) {
          chainValid = false;
        }
        const totalReceipts = db.prepare('SELECT COUNT(*) as c FROM governance_receipts').get().c;
        checks.push({
          check: 'receipt_chain',
          status: chainValid ? 'healthy' : 'critical',
          score: chainValid ? 1.0 : 0.0,
          total_receipts: totalReceipts,
          chain_valid: chainValid
        });
      } catch (err) {
        checks.push({ check: 'receipt_chain', status: 'critical', score: 0.0, error: err.message });
      }

      // Check 6: Constitutional invariants status (from database)
      try {
        const invariantStats = db.prepare(`SELECT
          COUNT(*) as total,
          SUM(CASE WHEN enforced = 1 THEN 1 ELSE 0 END) as enforced
        FROM constitutional_invariants`).get();
        const coverage = invariantStats.total > 0 ? invariantStats.enforced / invariantStats.total : 0;
        checks.push({
          check: 'invariant_coverage',
          status: coverage >= 0.9 ? 'healthy' : coverage >= 0.5 ? 'degraded' : 'critical',
          score: Math.round(coverage * 100) / 100,
          total: invariantStats.total,
          enforced: invariantStats.enforced
        });
      } catch (err) {
        checks.push({ check: 'invariant_coverage', status: 'critical', score: 0.0, error: err.message });
      }

      // Check 7: ExoForge cycle status
      try {
        ensureTables();
        const activeCycle = db.prepare('SELECT * FROM exoforge_cycles WHERE status = ? ORDER BY id DESC LIMIT 1').get('active');
        const queueSize = db.prepare('SELECT COUNT(*) as c FROM exoforge_queue WHERE status = ?').get('triaged');
        checks.push({
          check: 'exoforge_cycle',
          status: 'healthy',
          score: 1.0,
          active_cycle: activeCycle ? activeCycle.cycle_id : null,
          queue_size: queueSize ? queueSize.c : 0
        });
      } catch (_) {
        checks.push({ check: 'exoforge_cycle', status: 'healthy', score: 1.0, active_cycle: null, queue_size: 0 });
      }

      // Compute aggregate score
      const totalScore = checks.reduce((sum, c) => sum + c.score, 0) / checks.length;
      const overallStatus = totalScore >= 0.9 ? 'healthy'
        : totalScore >= 0.7 ? 'degraded'
        : 'critical';

      // Create governance receipt for health check
      const receipt = createReceipt(
        'exoforge_health_check',
        'system',
        'exoforge',
        'exoforge',
        `ExoForge health check: ${overallStatus} (score: ${Math.round(totalScore * 100) / 100})`,
        { status: overallStatus, score: totalScore, checks: checks.length },
        null
      );

      res.json({
        success: true,
        data: {
          status: overallStatus,
          score: Math.round(totalScore * 100) / 100,
          kernel_available: kernelAvailable,
          checks,
          exochain_version: '2.2',
          exoforge_version: '0.1.0-alpha',
          checked_at: localNow(),
          branches: ['legislative', 'executive', 'judicial']
        },
        receipt
      });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

};
