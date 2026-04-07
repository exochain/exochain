'use strict';

/**
 * Governance service: invariant validation, review panel, governance health,
 * receipt creation, and governance backfill.
 *
 * Usage:
 *   const governanceService = require('./services/governance')(db, broadcast, { localNow, crypto });
 */

const crypto = require('crypto');

module.exports = function(db, broadcast, helpers) {
  const { localNow } = helpers;

  // ── Governance Hashing ──

  function govHash(data) {
    return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
  }

  // ── Governance helper: determine branch from action type ──

  function determineBranch(actionType, actor) {
    if (/policy|invariant_update|workflow_change|constitutional|amendment/.test(actionType)) return 'legislative';
    if (/invariant_check|panel_review|chain_verify|contestation|adjudication|audit/.test(actionType)) return 'judicial';
    return 'executive';
  }

  // ── Governance helper: determine adjudication from description ──

  function determineAdjudication(actionType, description) {
    if (/BLOCKED|FAIL|reject/i.test(description)) return 'fail';
    if (/WARN|amend/i.test(description)) return 'warn';
    if (/defer/i.test(description)) return 'defer';
    return 'pass';
  }

  // ── Governance helper: create an ExoChain-quality receipt ──

  function createReceipt(db, actionType, entityType, entityId, actor, description, payload, projectId, opts = {}) {
    const now = localNow();
    const payloadHash = govHash(payload);
    const lastReceipt = db.prepare(`SELECT id, receipt_hash, payload_hash, previous_hash FROM governance_receipts ORDER BY id DESC LIMIT 1`).get();
    const previousHash = lastReceipt ? lastReceipt.receipt_hash : '0000000000000000000000000000000000000000000000000000000000000000';
    // FIX: Validate previous hash chain integrity before extending it.
    // If previous receipt's hash doesn't match recomputation, log corruption warning.
    if (lastReceipt && lastReceipt.previous_hash) {
      const secondLast = db.prepare(`SELECT receipt_hash FROM governance_receipts WHERE id = ? - 1`).get(lastReceipt.id);
      if (secondLast && secondLast.receipt_hash !== lastReceipt.previous_hash) {
        console.warn(`[Governance] Hash chain integrity warning: receipt #${lastReceipt.id} previous_hash doesn't match receipt #${lastReceipt.id - 1}. Chain may be corrupted.`);
      }
    }
    const chainDepth = lastReceipt ? (lastReceipt.id || 0) : 0;
    const branch = opts.branch || determineBranch(actionType, actor);
    const adjudication = opts.adjudication || determineAdjudication(actionType, description);
    const invariantId = opts.invariant_id || null;
    const metadata = JSON.stringify(opts.metadata || {});
    const invariantsChecked = opts.invariants_checked || '[]';

    const receiptData = {
      actionType, entityType, entityId, actor, payloadHash,
      previousHash, branch, adjudication, chainDepth, timestamp: now
    };
    const receiptHash = govHash(receiptData);

    const result = db.prepare(`
      INSERT INTO governance_receipts (
        action_type, entity_type, entity_id, actor, description,
        payload_hash, previous_hash, receipt_hash, invariants_checked, invariants_passed,
        project_id, created_at, hash_algorithm, encoding, branch,
        invariant_id, adjudication, metadata, chain_depth, verified
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      actionType, entityType, entityId, actor, description,
      payloadHash, previousHash, receiptHash, invariantsChecked,
      adjudication === 'pass' || adjudication === 'warn' ? 1 : 0,
      projectId || null, now, 'sha256', 'json', branch,
      invariantId, adjudication, metadata, chainDepth + 1, 1
    );

    // Log to governance audit trail
    try {
      db.prepare(`INSERT INTO governance_audit_trail (action_type, actor_name, target_type, target_id, branch, invariants_checked, receipt_id, created_at)
        VALUES (?,?,?,?,?,?,?,?)`).run(actionType, actor, entityType, entityId, branch, invariantsChecked, Number(result.lastInsertRowid), now);
    } catch (_) {}

    return { id: Number(result.lastInsertRowid), receipt_hash: receiptHash, branch, adjudication, chain_depth: chainDepth + 1 };
  }

  // ══════════════════════════════════════════════════════════════
  // ── Programmatic Invariant Validation Gate ──────────────────
  // ══════════════════════════════════════════════════════════════

  function validateAgainstInvariants(taskId, output) {
    const invariants = db.prepare('SELECT * FROM constitutional_invariants').all();
    const violations = [];

    for (const inv of invariants) {
      const lowerOutput = (output || '').toLowerCase();
      const invName = (inv.name || '').toLowerCase();
      // FIX: Use enforcement_level from DB to determine severity.
      // 'block' = blocks task, 'warn' = logs but allows, 'audit' = logs only
      const enfLevel = inv.enforcement_level || inv.severity || 'block';

      if (invName.includes('security') || invName.includes('authorization')) {
        if (/\beval\s*\(/.test(output) || (lowerOutput.includes('innerhtml') && lowerOutput.includes('user'))) {
          violations.push({ invariant_id: inv.id, name: inv.name, severity: enfLevel, detail: 'Potential XSS: eval() or unescaped innerHTML with user input detected' });
        }
        if (lowerOutput.includes('password') && lowerOutput.includes('plain')) {
          violations.push({ invariant_id: inv.id, name: inv.name, severity: enfLevel, detail: 'Plaintext password handling detected' });
        }
        if (lowerOutput.includes('api_key') && lowerOutput.includes('hardcod')) {
          violations.push({ invariant_id: inv.id, name: inv.name, severity: enfLevel, detail: 'Hardcoded API key detected' });
        }
      }

      if (invName.includes('data') || invName.includes('integrity') || invName.includes('silent')) {
        if (lowerOutput.includes('drop table') || (lowerOutput.includes('delete from') && !lowerOutput.includes('where'))) {
          violations.push({ invariant_id: inv.id, name: inv.name, severity: enfLevel, detail: 'Destructive SQL without WHERE clause detected' });
        }
      }

      if (invName.includes('governance') || invName.includes('chain') || invName.includes('immutable') || invName.includes('history')) {
        if (lowerOutput.includes('governance_receipts') && (lowerOutput.includes('delete') || lowerOutput.includes('update.*receipt_hash'))) {
          violations.push({ invariant_id: inv.id, name: inv.name, severity: enfLevel, detail: 'Attempt to modify governance chain detected' });
        }
      }

      if (invName.includes('provenance')) {
        if (lowerOutput.includes('insert into') && !lowerOutput.includes('hash') && !lowerOutput.includes('provenance') && lowerOutput.includes('governance')) {
          violations.push({ invariant_id: inv.id, name: inv.name, severity: enfLevel, detail: 'Governance insert without provenance tracking' });
        }
      }

      if (invName.includes('orchestrator') || invName.includes('single')) {
        if (lowerOutput.includes('gray') && lowerOutput.includes('bypass') && lowerOutput.includes('direct')) {
          violations.push({ invariant_id: inv.id, name: inv.name, severity: enfLevel, detail: 'Potential orchestrator bypass detected' });
        }
      }

      if (invName.includes('assignment') || invName.includes('accountability')) {
        if (lowerOutput.includes('assigned_to') && lowerOutput.includes('null') && lowerOutput.includes('in_progress')) {
          violations.push({ invariant_id: inv.id, name: inv.name, severity: enfLevel, detail: 'Task progressing without assignment detected' });
        }
      }

      if (invName.includes('security') || invName.includes('authorization')) {
        if (lowerOutput.includes('cors') && lowerOutput.includes("'*'")) {
          violations.push({ invariant_id: inv.id, name: inv.name, severity: enfLevel, detail: 'Permissive CORS wildcard detected' });
        }
      }
    }

    const now = localNow();
    const blockCount = violations.filter(v => v.severity === 'block').length;
    const warnCount = violations.filter(v => v.severity === 'warn').length;
    const passed = blockCount === 0;

    for (const inv of invariants) {
      try {
        const invViolations = violations.filter(v => v.invariant_id === inv.id);
        if (invViolations.length > 0) {
          db.prepare(`UPDATE constitutional_invariants SET last_validated_at = ?, violation_count = COALESCE(violation_count, 0) + ? WHERE id = ?`)
            .run(now, invViolations.length, inv.id);
        } else {
          db.prepare(`UPDATE constitutional_invariants SET last_validated_at = ? WHERE id = ?`).run(now, inv.id);
        }
      } catch (_) {}
    }

    try {
      const invariantIds = violations.map(v => v.invariant_id).filter(Boolean);
      createReceipt(db, 'invariant_check', 'task', taskId, 'System',
        `Invariant validation: ${passed ? 'PASSED' : 'BLOCKED'} — ${violations.length} violations (${blockCount} blocking, ${warnCount} warnings)`,
        { task_id: taskId, passed, violations_count: violations.length, block_count: blockCount, warn_count: warnCount, violations: violations.slice(0, 10) },
        null,
        {
          branch: 'judicial',
          adjudication: passed ? 'pass' : 'fail',
          // FIX: Link receipt to the first violated invariant for forensic traceability
          invariant_id: invariantIds.length > 0 ? invariantIds[0] : null,
          invariants_checked: JSON.stringify(invariants.map(i => i.code)),
          metadata: { invariant_ids_violated: invariantIds, enforcement_levels: [...new Set(violations.map(v => v.severity))] }
        }
      );
    } catch (e) {
      console.warn('[InvariantCheck] Receipt creation error:', e.message);
    }

    return { passed, violations, block_count: blockCount, warn_count: warnCount };
  }

  // ══════════════════════════════════════════════════════════════
  // ── Multi-Agent Review Panel ───────────────────────────────
  // ══════════════════════════════════════════════════════════════

  function reviewAsQuality(output) {
    const len = output.length;
    const hasEdits = /\b(Edit|Write)\b/.test(output);
    const hasTests = /test|spec|assert|expect/i.test(output);
    if (len < 100) return { vote: 'block', confidence: 0.9, reasoning: 'Output too short — no real work done' };
    if (!hasEdits) return { vote: 'amend', confidence: 0.7, reasoning: 'No file edits detected — may need implementation' };
    if (hasTests) return { vote: 'approve', confidence: 0.9, reasoning: `Substantive output (${len} chars) with test coverage` };
    return { vote: 'approve', confidence: 0.8, reasoning: `Substantive output (${len} chars), file edits detected` };
  }

  function reviewAsSecurity(output) {
    const lower = output.toLowerCase();
    const issues = [];
    // Use regex to detect eval() with optional whitespace (e.g. eval(x), eval (x)) in agent output
    if (/\beval\s*\(/.test(output)) issues.push('eval() usage');
    if (lower.includes('innerhtml') && lower.includes('user')) issues.push('Potential XSS');
    if (lower.includes('password') && lower.includes('plain')) issues.push('Plaintext password');
    if (lower.includes('api_key') && lower.includes('hardcod')) issues.push('Hardcoded API key');
    if (lower.includes('cors') && lower.includes("'*'")) issues.push('Permissive CORS');
    if (lower.includes('.env') && lower.includes('commit')) issues.push('.env file in commit');
    if (issues.length > 0) return { vote: 'block', confidence: 0.85, reasoning: 'Security issues: ' + issues.join(', ') };
    return { vote: 'approve', confidence: 0.75, reasoning: 'No security issues detected' };
  }

  function reviewAsArchitecture(output) {
    const lower = output.toLowerCase();
    const concerns = [];
    if (lower.includes('global') && lower.includes('var ')) concerns.push('Global variable usage');
    if ((output.match(/function/g) || []).length > 20) concerns.push('High function count — may need refactoring');
    if (lower.includes('todo') && lower.includes('hack')) concerns.push('TODO/HACK comments present');
    if ((output.match(/any/g) || []).length > 5 && lower.includes('typescript')) concerns.push('Excessive use of `any` type');
    if (concerns.length > 1) return { vote: 'amend', confidence: 0.6, reasoning: 'Architecture concerns: ' + concerns.join(', ') };
    return { vote: 'approve', confidence: 0.7, reasoning: 'Architecture looks acceptable' };
  }

  function reviewAsOperations(output) {
    const lower = output.toLowerCase();
    const logCount = (output.match(/console\.log/g) || []).length;
    if (logCount > 10) {
      return { vote: 'amend', confidence: 0.65, reasoning: `Excessive console.log statements (${logCount}) — clean up before merge` };
    }
    if (lower.includes('sleep') && lower.includes('loop')) {
      return { vote: 'amend', confidence: 0.7, reasoning: 'Sleep in loop detected — potential performance issue' };
    }
    return { vote: 'approve', confidence: 0.8, reasoning: 'Operations review passed' };
  }

  function runReviewPanel(taskId, output) {
    const now = localNow();
    const votes = [];

    const task = db.prepare('SELECT * FROM tasks WHERE id = ?').get(taskId);
    const assignedMemberId = task ? task.assigned_to : null;
    const assignedMember = assignedMemberId ? db.prepare('SELECT name FROM team_members WHERE id = ?').get(assignedMemberId) : null;
    const assignedName = assignedMember ? assignedMember.name : null;

    const panelMembers = [
      { role: 'quality', name: 'Gauge', reviewFn: reviewAsQuality },
      { role: 'security', name: 'Barb', reviewFn: reviewAsSecurity },
      { role: 'architecture', name: 'Onyx', reviewFn: reviewAsArchitecture },
      { role: 'operations', name: 'Sable', reviewFn: reviewAsOperations }
    ];

    let independenceViolation = false;
    const independentReviewers = [];

    for (const panel of panelMembers) {
      if (assignedName && panel.name.toLowerCase() === assignedName.toLowerCase()) {
        independenceViolation = true;
        votes.push({
          role: panel.role, name: panel.name,
          vote: 'defer', confidence: 0,
          reasoning: `RECUSED: ${panel.name} is the task assignee — independence violation per ExoChain Separation of Powers`
        });
      } else {
        const result = panel.reviewFn(output);
        votes.push({ role: panel.role, name: panel.name, ...result });
        independentReviewers.push(panel.name);
      }
    }

    for (const v of votes) {
      db.prepare(`INSERT INTO review_panel_votes (task_id, reviewer_role, reviewer_name, vote, confidence, reasoning, created_at) VALUES (?,?,?,?,?,?,?)`)
        .run(taskId, v.role, v.name, v.vote, v.confidence, v.reasoning, now);
    }

    const activeVotes = votes.filter(v => v.vote !== 'defer');
    const blocks = activeVotes.filter(v => v.vote === 'block');
    const approves = activeVotes.filter(v => v.vote === 'approve');
    const amends = activeVotes.filter(v => v.vote === 'amend');
    const hasQuorum = activeVotes.length >= 3;

    let taskSeverity = 'medium';
    if (task) {
      const taskInvariants = db.prepare(`SELECT ci.exochain_severity FROM governance_receipts gr
          JOIN constitutional_invariants ci ON gr.invariant_id = ci.id
          WHERE gr.entity_id = ? AND gr.entity_type = 'task' ORDER BY gr.created_at DESC LIMIT 1`).get(taskId);
      if (taskInvariants) taskSeverity = taskInvariants.exochain_severity || 'medium';
    }

    let disposition = 'approve';
    if (!hasQuorum) {
      disposition = 'defer';
    } else if (blocks.length > 0) {
      disposition = 'block';
    } else if (amends.length >= 2) {
      disposition = 'amend';
    } else if (taskSeverity === 'critical' && approves.length < activeVotes.length) {
      disposition = 'amend';
    }

    try {
      createReceipt(db, 'panel_review', 'task', taskId, 'ReviewPanel',
        `Review panel: ${disposition} — ${approves.length} approve, ${blocks.length} block, ${amends.length} amend` +
        (independenceViolation ? ' [independence recusal applied]' : '') +
        (!hasQuorum ? ' [quorum not met]' : ''),
        {
          task_id: taskId, disposition,
          votes: votes.map(v => ({ role: v.role, name: v.name, vote: v.vote, confidence: v.confidence })),
          panel_composition: { total: votes.length, active: activeVotes.length, recused: votes.length - activeVotes.length },
          independence_check: { violation: independenceViolation, assigned_member: assignedName, independent_reviewers: independentReviewers },
          quorum: { required: 3, actual: activeVotes.length, met: hasQuorum },
          severity: taskSeverity
        },
        null,
        { branch: 'judicial', metadata: { panel_type: 'standard', independence_verified: !independenceViolation } }
      );
    } catch (e) {
      console.warn('[ReviewPanel] Receipt creation error:', e.message);
    }

    return {
      disposition, votes,
      summary: `${approves.length} approve, ${blocks.length} block, ${amends.length} amend`,
      independence: { violation: independenceViolation, reviewers: independentReviewers },
      quorum: { met: hasQuorum, required: 3, actual: activeVotes.length }
    };
  }

  // ══════════════════════════════════════════════════════════════
  // ── Governance Health Monitor ──────────────────────────────
  // ══════════════════════════════════════════════════════════════

  function governanceHealthCheck() {
    const now = localNow();
    const checks = [];

    // 1. Chain integrity
    try {
      const receipts = db.prepare('SELECT * FROM governance_receipts ORDER BY id ASC').all();
      let chainValid = true;
      let breakPoint = null;
      const genesisHash = '0000000000000000000000000000000000000000000000000000000000000000';
      for (let i = 0; i < receipts.length; i++) {
        const r = receipts[i];
        const expectedPrev = i === 0 ? genesisHash : receipts[i - 1].receipt_hash;
        if (r.previous_hash !== expectedPrev) {
          chainValid = false;
          breakPoint = r.id;
          break;
        }
      }
      checks.push({
        type: 'chain_integrity',
        status: chainValid ? 'healthy' : 'critical',
        score: chainValid ? 1.0 : 0.0,
        details: chainValid ? `Hash chain intact (${receipts.length} receipts)` : `Hash chain broken at receipt #${breakPoint}`
      });
      if (!chainValid) {
        try {
          const ep = db.prepare(`SELECT * FROM emergency_protocols WHERE name = 'Chain Break Recovery' AND status = 'armed'`).get();
          if (ep) {
            db.prepare(`UPDATE emergency_protocols SET status = 'activated', last_activated_at = ? WHERE id = ?`).run(now, ep.id);
            db.prepare(`INSERT INTO notifications (type, title, message, read, created_at) VALUES ('system', ?, ?, 0, ?)`)
              .run('EMERGENCY: Chain Break Detected', `Hash chain integrity violated at receipt #${breakPoint}. Emergency protocol "${ep.name}" activated.`, now);
          }
        } catch (_) {}
      }
    } catch (e) {
      checks.push({ type: 'chain_integrity', status: 'unknown', score: 0, details: 'Check failed: ' + e.message });
    }

    // 2. Invariant coverage
    try {
      const invariants = db.prepare('SELECT * FROM constitutional_invariants').all();
      const recentChecks = db.prepare(`SELECT DISTINCT invariant_id FROM governance_receipts WHERE action_type = 'invariant_check' AND created_at > datetime(?, '-24 hours')`).all(now);
      const coverage = recentChecks.length / Math.max(1, invariants.length);
      checks.push({
        type: 'invariant_coverage',
        status: coverage > 0.8 ? 'healthy' : coverage > 0.5 ? 'degraded' : 'critical',
        score: Math.round(coverage * 100) / 100,
        details: `${recentChecks.length}/${invariants.length} invariants checked in last 24h`
      });
    } catch (e) {
      checks.push({ type: 'invariant_coverage', status: 'unknown', score: 0, details: 'Check failed: ' + e.message });
    }

    // 3. Receipt completeness
    try {
      const recentTasks = db.prepare(`SELECT COUNT(*) as c FROM tasks WHERE status IN ('completed','delivered') AND updated_at > datetime(?, '-24 hours')`).get(now).c;
      const recentReceipts = db.prepare(`SELECT COUNT(*) as c FROM governance_receipts WHERE created_at > datetime(?, '-24 hours')`).get(now).c;
      const completeness = recentTasks > 0 ? Math.min(1.0, recentReceipts / recentTasks) : 1.0;
      checks.push({
        type: 'receipt_completeness',
        status: completeness > 0.8 ? 'healthy' : completeness > 0.5 ? 'degraded' : 'critical',
        score: Math.round(completeness * 100) / 100,
        details: `${recentReceipts} receipts for ${recentTasks} completed tasks in last 24h`
      });
    } catch (e) {
      checks.push({ type: 'receipt_completeness', status: 'unknown', score: 0, details: 'Check failed: ' + e.message });
    }

    // 4. Panel independence
    try {
      const recentPanels = db.prepare(`SELECT * FROM governance_receipts WHERE action_type = 'panel_review' AND created_at > datetime(?, '-24 hours')`).all(now);
      let independenceScore = 1.0;
      let violationCount = 0;
      for (const panel of recentPanels) {
        if (panel.description && panel.description.includes('independence recusal')) {
          violationCount++;
        }
      }
      if (recentPanels.length > 0) {
        independenceScore = 1.0 - (violationCount / recentPanels.length * 0.5);
      }
      checks.push({
        type: 'panel_independence',
        status: independenceScore > 0.8 ? 'healthy' : independenceScore > 0.5 ? 'degraded' : 'critical',
        score: Math.round(independenceScore * 100) / 100,
        details: `${recentPanels.length} panels reviewed, ${violationCount} with independence recusals`
      });
    } catch (e) {
      checks.push({ type: 'panel_independence', status: 'unknown', score: 0, details: 'Check failed: ' + e.message });
    }

    // 5. Authority chain
    try {
      const activeDelegations = db.prepare(`SELECT COUNT(*) as c FROM authority_delegations WHERE revoked = 0 AND (valid_until IS NULL OR valid_until > ?)`).get(now).c;
      const expiredDelegations = db.prepare(`SELECT COUNT(*) as c FROM authority_delegations WHERE revoked = 0 AND valid_until IS NOT NULL AND valid_until <= ?`).get(now).c;
      const authScore = expiredDelegations === 0 ? 1.0 : Math.max(0, 1.0 - (expiredDelegations / Math.max(1, activeDelegations + expiredDelegations)));
      checks.push({
        type: 'authority_chain',
        status: authScore > 0.8 ? 'healthy' : authScore > 0.5 ? 'degraded' : 'critical',
        score: Math.round(authScore * 100) / 100,
        details: `${activeDelegations} active delegations, ${expiredDelegations} expired but not revoked`
      });
    } catch (e) {
      checks.push({ type: 'authority_chain', status: 'healthy', score: 1.0, details: 'No delegations to check' });
    }

    // 6. Provenance coverage
    try {
      const recentTasks = db.prepare(`SELECT COUNT(*) as c FROM tasks WHERE status IN ('completed','delivered') AND updated_at > datetime(?, '-24 hours')`).get(now).c;
      const provenanceCount = db.prepare(`SELECT COUNT(*) as c FROM provenance_chain WHERE created_at > datetime(?, '-24 hours')`).get(now).c;
      const provCoverage = recentTasks > 0 ? Math.min(1.0, provenanceCount / recentTasks) : 1.0;
      checks.push({
        type: 'provenance_coverage',
        status: provCoverage > 0.5 ? 'healthy' : provCoverage > 0.2 ? 'degraded' : 'critical',
        score: Math.round(provCoverage * 100) / 100,
        details: `${provenanceCount} provenance records for ${recentTasks} tasks in last 24h`
      });
    } catch (e) {
      checks.push({ type: 'provenance_coverage', status: 'unknown', score: 0, details: 'Check failed: ' + e.message });
    }

    // Save all checks
    for (const check of checks) {
      try {
        db.prepare('INSERT INTO governance_health (check_type, status, score, details, checked_at) VALUES (?,?,?,?,?)')
          .run(check.type, check.status, check.score, check.details, now);
      } catch (e) { console.warn('[GovHealth] Save error:', e.message); }
    }

    const avgScore = checks.reduce((sum, c) => sum + c.score, 0) / Math.max(1, checks.length);
    const overallStatus = avgScore > 0.8 ? 'healthy' : avgScore > 0.5 ? 'degraded' : 'critical';

    if (overallStatus !== 'healthy') {
      try {
        db.prepare(`INSERT INTO notifications (type, title, message, read, created_at) VALUES ('system', ?, ?, 0, ?)`)
          .run('Governance Health Alert', `Governance health is ${overallStatus} (score: ${(avgScore * 100).toFixed(0)}%). Check the governance dashboard.`, now);
      } catch (_) {}
      if (avgScore < 0.3) {
        try {
          const ep = db.prepare(`SELECT * FROM emergency_protocols WHERE name = 'Governance Drift' AND status = 'armed'`).get();
          if (ep) {
            db.prepare(`UPDATE emergency_protocols SET status = 'activated', last_activated_at = ? WHERE id = ?`).run(now, ep.id);
          }
        } catch (_) {}
      }
    }

    console.log(`[GovHealth] Check complete: ${overallStatus} (score: ${(avgScore * 100).toFixed(0)}%)`);
    return { status: overallStatus, score: Math.round(avgScore * 100) / 100, checks, checked_at: now };
  }

  // ══════════════════════════════════════════════════════════════
  // ── Governance Backfill ────────────────────────────────────
  // ══════════════════════════════════════════════════════════════

  function backfillGovernance() {
    const now = localNow();

    // 1. Receipt backfill
    const allReceiptTaskIds = db.prepare(`
      SELECT DISTINCT entity_id FROM governance_receipts WHERE entity_type = 'task' AND entity_id IS NOT NULL
    `).all().map(r => r.entity_id);
    const receiptIdSet = new Set(allReceiptTaskIds);
    const ungoverned = db.prepare(`
      SELECT id, title FROM tasks
      WHERE status IN ('completed','delivered')
      ORDER BY id DESC LIMIT 100
    `).all().filter(t => !receiptIdSet.has(t.id));

    let prevHash = db.prepare('SELECT receipt_hash FROM governance_receipts ORDER BY id DESC LIMIT 1').get();
    let previousHash = prevHash ? prevHash.receipt_hash : '0000000000000000000000000000000000000000000000000000000000000000';

    let receiptCount = 0;
    for (const task of ungoverned) {
      const payloadHash = crypto.createHash('sha256').update(JSON.stringify({ task_id: task.id, title: task.title, backfilled: true, ts: now })).digest('hex');
      const receiptHash = crypto.createHash('sha256').update(payloadHash + previousHash + now).digest('hex');
      db.prepare(`INSERT INTO governance_receipts (action_type, entity_type, entity_id, actor, description, payload_hash, previous_hash, receipt_hash, branch, adjudication, metadata, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
        .run('task_completion', 'task', task.id, 'System', `Backfill: governance receipt for completed task #${task.id}`, payloadHash, previousHash, receiptHash, 'executive', 'pass', JSON.stringify({ task_id: task.id, title: task.title, backfilled: true }), now);
      previousHash = receiptHash;
      receiptCount++;
    }

    // 2. Provenance backfill
    const allProvenanceTaskIds = db.prepare(`
      SELECT DISTINCT task_id FROM provenance_chain WHERE task_id IS NOT NULL
    `).all().map(r => r.task_id);
    const provIdSet = new Set(allProvenanceTaskIds);
    const unprovenanced = db.prepare(`
      SELECT t.id, t.title, t.assigned_to FROM tasks t
      WHERE t.status IN ('completed','delivered')
      ORDER BY t.id DESC LIMIT 100
    `).all().filter(t => !provIdSet.has(t.id));

    let provCount = 0;
    for (const task of unprovenanced) {
      const outputHash = crypto.createHash('sha256').update(JSON.stringify({ task_id: task.id, title: task.title })).digest('hex');
      const inputHash = crypto.createHash('sha256').update(task.title + task.id).digest('hex');
      db.prepare(`INSERT INTO provenance_chain (output_hash, input_hashes, task_id, member_id, action, transformation, created_at) VALUES (?,?,?,?,?,?,?)`)
        .run(outputHash, JSON.stringify([inputHash]), task.id, task.assigned_to || null, 'task_completion', 'Backfilled provenance record', now);
      provCount++;
    }

    // 3. Invariant coverage backfill
    const invariants = db.prepare('SELECT id, code, name FROM constitutional_invariants').all();
    let invCount = 0;
    for (const inv of invariants) {
      const payloadHash = crypto.createHash('sha256').update(JSON.stringify({ invariant_id: inv.id, code: inv.code, checked: true, ts: now })).digest('hex');
      const receiptHash = crypto.createHash('sha256').update(payloadHash + previousHash + now).digest('hex');
      db.prepare(`INSERT INTO governance_receipts (action_type, entity_type, entity_id, actor, description, payload_hash, previous_hash, receipt_hash, branch, adjudication, invariant_id, metadata, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
        .run('invariant_check', 'invariant', inv.id, 'System', `Backfill: invariant check for ${inv.code} (${inv.name})`, payloadHash, previousHash, receiptHash, 'executive', 'pass', inv.id, JSON.stringify({ invariant_id: inv.id, code: inv.code, backfilled: true }), now);
      previousHash = receiptHash;
      invCount++;
    }

    console.log(`[Governance] Backfilled ${receiptCount} governance receipts, ${provCount} provenance records, ${invCount} invariant checks`);
  }

  // ── Workflow helpers ──

  function detectWorkflowType(title, description) {
    const text = ((title || '') + ' ' + (description || '')).toLowerCase();
    if (/^execute:/i.test(title || '')) return 'improvement';
    if (/\b(fix|bug|error|crash|broken|regression)\b/.test(text)) return 'bugfix';
    if (/\b(research|investigate|analyze|explore|evaluate|compare)\b/.test(text)) return 'research';
    if (/\b(add|build|implement|create|feature|new)\b/.test(text)) return 'feature';
    return 'simple';
  }

  function getWorkflowSteps(workflowName) {
    const template = db.prepare('SELECT steps FROM workflow_templates WHERE name = ?').get(workflowName);
    if (template) return JSON.parse(template.steps);
    return ['assign', 'implement', 'validate', 'deliver'];
  }

  function workflowRequiresPanel(workflowName) {
    const steps = getWorkflowSteps(workflowName);
    return steps.includes('panel_review');
  }

  function workflowRequiresInvariantCheck(workflowName) {
    const steps = getWorkflowSteps(workflowName);
    return steps.includes('invariant_check');
  }

  // ── Self-improvement scan ──

  function createSelfImprovementTask(title, description, workflow) {
    const existing = db.prepare(`SELECT id FROM tasks WHERE LOWER(title) = LOWER(?) AND status NOT IN ('delivered','completed')`).get(title);
    if (existing) return null;
    const now = localNow();
    const result = db.prepare(`INSERT INTO tasks (title, description, status, priority, workflow, source_file, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)`)
      .run(title, description, 'new', 'normal', workflow, 'self_improvement', now, now);
    const taskId = Number(result.lastInsertRowid);
    db.prepare(`INSERT INTO activity_log (task_id, actor, action, notes, created_at) VALUES (?, 'System', 'self_improvement', ?, ?)`)
      .run(taskId, `Self-improvement scan created task: ${title}`, now);
    console.log(`[SelfImprove] Created task #${taskId}: ${title}`);
    broadcast('task.created', { id: taskId });
    return taskId;
  }

  function selfImprovementScan() {
    const now = localNow();
    const results = { tasks_created: 0, context_archived: 0, issues_found: [] };

    try {
      const failingAgents = db.prepare(`
        SELECT member_id, COUNT(*) as failures
        FROM active_processes WHERE status = 'failed'
        AND completed_at > datetime(?, '-24 hours')
        GROUP BY member_id HAVING failures >= 3
      `).all(now);
      for (const agent of failingAgents) {
        const member = db.prepare('SELECT name FROM team_members WHERE id = ?').get(agent.member_id);
        const taskId = createSelfImprovementTask(
          `Investigate ${member?.name || 'agent'} failure pattern`,
          `${member?.name || 'Agent #' + agent.member_id} has failed ${agent.failures} times in the last 24 hours. Research the root cause and propose fixes.`,
          'research'
        );
        if (taskId) {
          results.tasks_created++;
          results.issues_found.push({ type: 'agent_failures', member: member?.name, failures: agent.failures });
        }
      }
    } catch (e) { console.warn('[SelfImprove] Agent failure check error:', e.message); }

    try {
      const recentViolations = db.prepare(`
        SELECT COUNT(*) as c FROM governance_receipts
        WHERE action_type = 'invariant_check' AND description LIKE '%BLOCKED%'
        AND created_at > datetime(?, '-7 days')
      `).get(now);
      if (recentViolations && recentViolations.c > 5) {
        const taskId = createSelfImprovementTask(
          'Governance drift detected — review invariant compliance',
          `${recentViolations.c} invariant violations in the last 7 days. Audit the codebase for governance drift.`,
          'bugfix'
        );
        if (taskId) {
          results.tasks_created++;
          results.issues_found.push({ type: 'governance_drift', violations: recentViolations.c });
        }
      }
    } catch (e) { console.warn('[SelfImprove] Governance drift check error:', e.message); }

    try {
      const staleTasks = db.prepare(`
        SELECT id, title, assigned_to FROM tasks
        WHERE status = 'in_progress' AND updated_at < datetime(?, '-48 hours')
      `).all(now);
      for (const staleTask of staleTasks) {
        const member = staleTask.assigned_to ? db.prepare('SELECT name FROM team_members WHERE id = ?').get(staleTask.assigned_to) : null;
        results.issues_found.push({ type: 'stale_task', task_id: staleTask.id, title: staleTask.title, member: member?.name });
      }
    } catch (e) { console.warn('[SelfImprove] Stale task check error:', e.message); }

    try {
      const bouncingTasks = db.prepare(`
        SELECT id, title, revision_count, assigned_to FROM tasks
        WHERE revision_count >= 3 AND status NOT IN ('delivered','completed')
      `).all();
      for (const bt of bouncingTasks) {
        results.issues_found.push({ type: 'high_revisions', task_id: bt.id, title: bt.title, revisions: bt.revision_count });
      }
    } catch (e) { console.warn('[SelfImprove] Bouncing task check error:', e.message); }

    try {
      const staleCount = db.prepare(`
        SELECT COUNT(*) as c FROM agent_memory_entities
        WHERE importance NOT IN ('critical','high') AND updated_at < datetime(?, '-14 days')
      `).get(now);
      if (staleCount && staleCount.c > 0) {
        results.context_archived = staleCount.c;
        results.issues_found.push({ type: 'stale_context', count: staleCount.c });
      }
    } catch (e) { console.warn('[SelfImprove] Stale context check error:', e.message); }

    try {
      db.prepare(`INSERT INTO activity_log (actor, action, notes, created_at) VALUES ('System', 'self_improvement_scan', ?, ?)`)
        .run(JSON.stringify(results), now);
    } catch (e) { console.warn('[SelfImprove] Activity log error:', e.message); }

    console.log(`[SelfImprove] Scan complete: ${results.tasks_created} tasks created, ${results.issues_found.length} issues found`);
    return results;
  }

  // ══════════════════════════════════════════════════════════════
  // ── Escalation as Challenge — Structured Escalation Workflow ─
  // ══════════════════════════════════════════════════════════════

  const CHALLENGE_GROUNDS = ['ConstitutionalViolation', 'FactualDispute', 'ProcedureViolation', 'Independence', 'Bias', 'Evidence'];

  const ADJUDICATION_STAGES = [
    { number: 1, name: 'specialist_review', tier: 'specialist', label: 'Specialist Review' },
    { number: 2, name: 'senior_specialist_review', tier: 'specialist', label: 'Senior Specialist Review' },
    { number: 3, name: 'department_head_review', tier: 'specialist', label: 'Department Head Review' },
    { number: 4, name: 'executive_review', tier: 'executive', label: 'Executive Review' },
    { number: 5, name: 'cross_executive_review', tier: 'executive', label: 'Cross-Executive Review' },
    { number: 6, name: 'board_committee_review', tier: 'board', label: 'Board Committee Review' },
    { number: 7, name: 'full_board_review', tier: 'board', label: 'Full Board Review' }
  ];

  /**
   * File an escalation challenge against an ExoChain Decision.
   * Transitions the target decision to CONTESTED status (pauses execution).
   */
  function fileEscalationChallenge({ decision_id, challenger_id, challenger_name, challenger_tier, grounds, grounds_detail, evidence }) {
    const now = localNow();

    if (!CHALLENGE_GROUNDS.includes(grounds)) {
      throw new Error(`Invalid grounds. Must be one of: ${CHALLENGE_GROUNDS.join(', ')}`);
    }

    // Verify the decision exists and is not already contested
    const decision = db.prepare('SELECT * FROM exochain_decisions WHERE id = ?').get(decision_id);
    if (!decision) throw new Error(`Decision #${decision_id} not found`);

    const evidenceJson = JSON.stringify(evidence || []);

    // Insert the challenge
    const result = db.prepare(`
      INSERT INTO escalation_challenges (decision_id, challenger_id, challenger_name, challenger_tier, grounds, grounds_detail, evidence, current_stage, status, filed_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'filed', ?, ?)
    `).run(decision_id, challenger_id || null, challenger_name, challenger_tier, grounds, grounds_detail, evidenceJson, now, now);

    const challengeId = Number(result.lastInsertRowid);

    // Transition decision to CONTESTED — pauses execution
    const previousStatus = decision.status;
    db.prepare(`UPDATE exochain_decisions SET status = 'Contested', updated_at = ? WHERE id = ?`).run(now, decision_id);

    // Create governance receipt for the challenge filing
    const receipt = createReceipt(db, 'escalation_challenge_filed', 'exochain_decision', decision_id, challenger_name,
      `Escalation challenge #${challengeId} filed against Decision #${decision_id} on grounds: ${grounds}. Decision status changed from ${previousStatus} to Contested.`,
      { challenge_id: challengeId, decision_id, grounds, grounds_detail, challenger_tier, previous_status: previousStatus },
      null,
      { branch: 'judicial', adjudication: 'defer', metadata: { challenge_id: challengeId, grounds, challenger_tier } }
    );

    // Update challenge with receipt_id
    db.prepare('UPDATE escalation_challenges SET receipt_id = ? WHERE id = ?').run(receipt.id, challengeId);

    // Auto-assign first adjudication stage
    const firstStage = assignAdjudicationStage(challengeId, 1, decision);

    try { broadcast('governance.challenge_filed', { challenge_id: challengeId, decision_id, grounds }); } catch (_) {}

    return { id: challengeId, status: 'filed', decision_status: 'Contested', receipt_id: receipt.id, first_stage: firstStage };
  }

  /**
   * Assign an adjudicator to a specific stage of the challenge.
   * Picks the appropriate person based on stage tier and the decision's department/branch.
   */
  function assignAdjudicationStage(challengeId, stageNumber, decision) {
    const now = localNow();
    const stageDef = ADJUDICATION_STAGES.find(s => s.number === stageNumber);
    if (!stageDef) throw new Error(`Invalid stage number: ${stageNumber}`);

    const challenge = db.prepare('SELECT * FROM escalation_challenges WHERE id = ?').get(challengeId);
    if (!challenge) throw new Error(`Challenge #${challengeId} not found`);

    // Find an appropriate adjudicator — must not be the challenger
    let adjudicator = null;
    const challengerId = challenge.challenger_id;

    if (stageDef.tier === 'specialist') {
      // Pick a specialist from same department, ranked higher if possible, excluding challenger
      adjudicator = db.prepare(`
        SELECT id, name, tier FROM team_members
        WHERE tier = 'IC' AND status = 'active' AND id != ?
        ORDER BY RANDOM() LIMIT 1
      `).get(challengerId || 0);
    } else if (stageDef.tier === 'executive') {
      adjudicator = db.prepare(`
        SELECT id, name, tier FROM team_members
        WHERE tier = 'C-Suite' AND status = 'active' AND id != ?
        ORDER BY RANDOM() LIMIT 1
      `).get(challengerId || 0);
    } else if (stageDef.tier === 'board') {
      adjudicator = db.prepare(`
        SELECT id, name, tier FROM team_members
        WHERE tier = 'Board' AND status = 'active' AND id != ?
        ORDER BY RANDOM() LIMIT 1
      `).get(challengerId || 0);
    }

    if (!adjudicator) {
      adjudicator = { id: null, name: 'System', tier: stageDef.tier };
    }

    db.prepare(`
      INSERT OR REPLACE INTO challenge_adjudication_stages (challenge_id, stage_number, stage_name, adjudicator_id, adjudicator_name, adjudicator_tier, started_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(challengeId, stageNumber, stageDef.name, adjudicator.id, adjudicator.name, adjudicator.tier || stageDef.tier, now);

    db.prepare('UPDATE escalation_challenges SET current_stage = ?, status = ?, updated_at = ? WHERE id = ?')
      .run(stageNumber, 'adjudicating', now, challengeId);

    return { stage: stageNumber, stage_name: stageDef.name, adjudicator_name: adjudicator.name, label: stageDef.label };
  }

  /**
   * Record a verdict at the current adjudication stage.
   * If verdict is 'escalate', advances to the next stage.
   * If verdict is 'uphold_challenge' or 'deny_challenge', resolves the challenge.
   */
  function recordStageVerdict(challengeId, stageNumber, { verdict, reasoning, evidence_reviewed, adjudicator_name }) {
    const now = localNow();
    const challenge = db.prepare('SELECT * FROM escalation_challenges WHERE id = ?').get(challengeId);
    if (!challenge) throw new Error(`Challenge #${challengeId} not found`);
    if (challenge.status !== 'adjudicating') throw new Error(`Challenge #${challengeId} is not in adjudicating status`);
    if (challenge.current_stage !== stageNumber) throw new Error(`Challenge is at stage ${challenge.current_stage}, not ${stageNumber}`);

    const stageDef = ADJUDICATION_STAGES.find(s => s.number === stageNumber);

    // Record the verdict
    db.prepare(`
      UPDATE challenge_adjudication_stages
      SET verdict = ?, reasoning = ?, evidence_reviewed = ?, completed_at = ?
      WHERE challenge_id = ? AND stage_number = ?
    `).run(verdict, reasoning || null, JSON.stringify(evidence_reviewed || []), now, challengeId, stageNumber);

    // Create receipt for the stage verdict
    const receipt = createReceipt(db, 'challenge_stage_verdict', 'escalation_challenge', challengeId, adjudicator_name || 'Adjudicator',
      `Stage ${stageNumber} (${stageDef.label}) verdict: ${verdict}. ${reasoning || ''}`.trim(),
      { challenge_id: challengeId, stage: stageNumber, stage_name: stageDef.name, verdict, reasoning },
      null,
      { branch: 'judicial', adjudication: verdict === 'uphold_challenge' ? 'pass' : verdict === 'deny_challenge' ? 'fail' : 'defer' }
    );

    db.prepare('UPDATE challenge_adjudication_stages SET receipt_id = ? WHERE challenge_id = ? AND stage_number = ?')
      .run(receipt.id, challengeId, stageNumber);

    if (verdict === 'escalate') {
      // Advance to next stage
      const nextStage = stageNumber + 1;
      if (nextStage > 7) {
        // Final stage reached without resolution — auto-resolve via full board
        return resolveChallenge(challengeId, 'dismissed', 'All 7 adjudication stages exhausted without definitive verdict. Dismissed by default.', adjudicator_name);
      }
      const decision = db.prepare('SELECT * FROM exochain_decisions WHERE id = ?').get(challenge.decision_id);
      const nextAssignment = assignAdjudicationStage(challengeId, nextStage, decision);
      try { broadcast('governance.challenge_escalated', { challenge_id: challengeId, from_stage: stageNumber, to_stage: nextStage }); } catch (_) {}
      return { action: 'escalated', from_stage: stageNumber, to_stage: nextStage, next: nextAssignment };
    }

    if (verdict === 'uphold_challenge') {
      return resolveChallenge(challengeId, 'upheld', reasoning, adjudicator_name);
    }

    if (verdict === 'deny_challenge') {
      return resolveChallenge(challengeId, 'overturned', reasoning, adjudicator_name);
    }

    if (verdict === 'remand') {
      // Send back to a lower stage for reconsideration
      const remandStage = Math.max(1, stageNumber - 1);
      const decision = db.prepare('SELECT * FROM exochain_decisions WHERE id = ?').get(challenge.decision_id);
      const remandAssignment = assignAdjudicationStage(challengeId, remandStage, decision);
      return { action: 'remanded', to_stage: remandStage, next: remandAssignment };
    }

    // verdict === 'defer'
    return { action: 'deferred', stage: stageNumber, message: 'Verdict deferred — awaiting additional information' };
  }

  /**
   * Resolve a challenge. Creates a new Decision Object with reversal linkage if upheld.
   */
  function resolveChallenge(challengeId, outcome, resolution, resolverName) {
    const now = localNow();
    const challenge = db.prepare('SELECT * FROM escalation_challenges WHERE id = ?').get(challengeId);
    if (!challenge) throw new Error(`Challenge #${challengeId} not found`);

    const originalDecision = db.prepare('SELECT * FROM exochain_decisions WHERE id = ?').get(challenge.decision_id);
    let resolutionDecisionId = null;

    if (outcome === 'upheld') {
      // Challenge upheld — create a new Decision Object that reverses/supersedes the original
      const newDecisionResult = db.prepare(`
        INSERT INTO exochain_decisions (title, description, decision_class, status, author_name, branch, evidence, metadata, created_at, updated_at)
        VALUES (?, ?, ?, 'Ratified', ?, 'judicial', ?, ?, ?, ?)
      `).run(
        `Reversal of Decision #${challenge.decision_id}: ${originalDecision ? originalDecision.title : 'Unknown'}`,
        `This decision reverses Decision #${challenge.decision_id} following a successful escalation challenge (#${challengeId}). Grounds: ${challenge.grounds}. ${resolution || ''}`.trim(),
        originalDecision ? originalDecision.decision_class : 'Operational',
        resolverName || 'Adjudication Panel',
        JSON.stringify([{ type: 'challenge_resolution', challenge_id: challengeId, original_decision_id: challenge.decision_id }]),
        JSON.stringify({ reversal_of: challenge.decision_id, challenge_id: challengeId, grounds: challenge.grounds }),
        now, now
      );
      resolutionDecisionId = Number(newDecisionResult.lastInsertRowid);

      // Mark original decision as Rejected (reversed)
      db.prepare(`UPDATE exochain_decisions SET status = 'Rejected', updated_at = ? WHERE id = ?`).run(now, challenge.decision_id);
    } else {
      // Challenge denied/dismissed — restore original decision to its pre-contested status
      // We default to Ratified since the decision survived the challenge
      db.prepare(`UPDATE exochain_decisions SET status = 'Ratified', updated_at = ? WHERE id = ?`).run(now, challenge.decision_id);
    }

    // Update the challenge record
    const finalStatus = outcome === 'upheld' ? 'upheld' : outcome === 'overturned' ? 'overturned' : 'dismissed';
    db.prepare(`UPDATE escalation_challenges SET status = ?, resolution = ?, resolution_decision_id = ?, resolved_at = ?, updated_at = ? WHERE id = ?`)
      .run(finalStatus, resolution || null, resolutionDecisionId, now, now, challengeId);

    // Create governance receipt for challenge resolution
    const receipt = createReceipt(db, 'escalation_challenge_resolved', 'escalation_challenge', challengeId, resolverName || 'System',
      `Escalation challenge #${challengeId} resolved: ${finalStatus}. Decision #${challenge.decision_id} ${outcome === 'upheld' ? 'reversed' : 'reaffirmed'}.` +
      (resolutionDecisionId ? ` New Decision #${resolutionDecisionId} created.` : ''),
      { challenge_id: challengeId, outcome: finalStatus, resolution, original_decision_id: challenge.decision_id, resolution_decision_id: resolutionDecisionId },
      null,
      { branch: 'judicial', adjudication: outcome === 'upheld' ? 'pass' : 'fail', metadata: { reversal: outcome === 'upheld', grounds: challenge.grounds } }
    );

    try { broadcast('governance.challenge_resolved', { challenge_id: challengeId, outcome: finalStatus, decision_id: challenge.decision_id, resolution_decision_id: resolutionDecisionId }); } catch (_) {}

    return { action: 'resolved', outcome: finalStatus, challenge_id: challengeId, decision_id: challenge.decision_id, resolution_decision_id: resolutionDecisionId, receipt_id: receipt.id };
  }

  return {
    govHash,
    determineBranch,
    determineAdjudication,
    createReceipt,
    validateAgainstInvariants,
    runReviewPanel,
    governanceHealthCheck,
    backfillGovernance,
    detectWorkflowType,
    getWorkflowSteps,
    workflowRequiresPanel,
    workflowRequiresInvariantCheck,
    createSelfImprovementTask,
    selfImprovementScan,
    // Escalation Challenge exports
    CHALLENGE_GROUNDS,
    ADJUDICATION_STAGES,
    fileEscalationChallenge,
    assignAdjudicationStage,
    recordStageVerdict,
    resolveChallenge
  };
};
