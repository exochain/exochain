'use strict';
module.exports = function(app, db, helpers) {
  const { broadcast, localNow, createNotification, authRateLimiter, apiRateLimiter, spawnMemberTerminal } = helpers;
  const stmt = helpers.stmt || ((sql) => db.prepare(sql));

app.get('/api/governance/chain', (req, res) => {
  try {
    const receipts = db.prepare(`SELECT * FROM governance_receipts ORDER BY id ASC`).all();
    let valid = true;
    const genesisHash = '0000000000000000000000000000000000000000000000000000000000000000';

    for (let i = 0; i < receipts.length; i++) {
      const r = receipts[i];
      const expectedPrev = i === 0 ? genesisHash : receipts[i - 1].receipt_hash;
      if (r.previous_hash !== expectedPrev) {
        valid = false;
        break;
      }
    }

    const lastReceipt = receipts.length > 0 ? receipts[receipts.length - 1] : null;

    res.json({
      valid,
      receipt_count: receipts.length,
      last_receipt: lastReceipt ? lastReceipt.created_at : null,
      chain_length: receipts.length
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/governance/receipts', (req, res) => {
  try {
    const { limit: lim, project_id } = req.query;
    let sql = `SELECT * FROM governance_receipts`;
    const params = [];
    if (project_id) { sql += ` WHERE project_id = ?`; params.push(project_id); }
    sql += ` ORDER BY id DESC LIMIT ?`;
    params.push(parseInt(lim) || 50);
    res.json(db.prepare(sql).all(...params));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/governance/verify', (req, res) => {
  try {
    const receipts = db.prepare(`SELECT * FROM governance_receipts ORDER BY id ASC`).all();
    let valid = true;
    let brokenAt = null;
    const genesisHash = '0000000000000000000000000000000000000000000000000000000000000000';

    for (let i = 0; i < receipts.length; i++) {
      const r = receipts[i];
      const expectedPrev = i === 0 ? genesisHash : receipts[i - 1].receipt_hash;
      if (r.previous_hash !== expectedPrev) {
        valid = false;
        brokenAt = r.id;
        break;
      }
    }

    res.json({ valid, total_receipts: receipts.length, broken_at: brokenAt });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/governance/invariants', (req, res) => {
  try {
    res.json(db.prepare(`SELECT * FROM constitutional_invariants ORDER BY code`).all());
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/governance/invariants/:id', (req, res) => {
  try {
    const { enforced, severity, formal_spec, enforcement_level, validation_logic, exochain_severity, remediation, category } = req.body;
    const updates = [];
    const params = [];
    if (enforced !== undefined) { updates.push('enforced = ?'); params.push(enforced ? 1 : 0); }
    if (severity) { updates.push('severity = ?'); params.push(severity); }
    if (formal_spec) { updates.push('formal_spec = ?'); params.push(formal_spec); }
    if (enforcement_level) { updates.push('enforcement_level = ?'); params.push(enforcement_level); }
    if (validation_logic) { updates.push('validation_logic = ?'); params.push(validation_logic); }
    if (exochain_severity) { updates.push('exochain_severity = ?'); params.push(exochain_severity); }
    if (remediation) { updates.push('remediation = ?'); params.push(remediation); }
    if (category) { updates.push('category = ?'); params.push(category); }
    if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });
    params.push(req.params.id);
    db.prepare(`UPDATE constitutional_invariants SET ${updates.join(', ')} WHERE id = ?`).run(...params);
    // Log the update as a governance receipt
    createReceipt(db, 'invariant_update', 'invariant', parseInt(req.params.id), 'System',
      `Invariant #${req.params.id} updated: ${updates.map(u => u.split(' = ')[0]).join(', ')}`,
      req.body, null, { branch: 'legislative' });
    res.json({ message: 'Invariant updated', fields: updates.map(u => u.split(' = ')[0]) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/governance/provenance', (req, res) => {
  try {
    const { task_id, project_id } = req.query;
    let sql = `SELECT p.*, t.title as task_title, tm.name as member_name FROM provenance_chain p
      LEFT JOIN tasks t ON p.task_id = t.id LEFT JOIN team_members tm ON p.member_id = tm.id WHERE 1=1`;
    const params = [];
    if (task_id) { sql += ` AND p.task_id = ?`; params.push(task_id); }
    if (project_id) { sql += ` AND p.project_id = ?`; params.push(project_id); }
    sql += ` ORDER BY p.created_at DESC LIMIT 100`;
    res.json(db.prepare(sql).all(...params));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/governance/stats', (req, res) => {
  try {
    const totalReceipts = db.prepare(`SELECT COUNT(*) as c FROM governance_receipts`).get().c;
    const totalProvenance = db.prepare(`SELECT COUNT(*) as c FROM provenance_chain`).get().c;
    const governedProjects = db.prepare(`SELECT COUNT(*) as c FROM projects WHERE exochain_governed = 1`).get().c;
    const totalProjects = db.prepare(`SELECT COUNT(*) as c FROM projects`).get().c;
    const invariants = db.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN enforced = 1 THEN 1 ELSE 0 END) as enforced FROM constitutional_invariants`).get();

    // Quick chain verification
    const lastTwo = db.prepare(`SELECT receipt_hash, previous_hash FROM governance_receipts ORDER BY id DESC LIMIT 2`).all();
    let chainValid = true;
    if (lastTwo.length === 2 && lastTwo[1].receipt_hash !== lastTwo[0].previous_hash) chainValid = false;

    res.json({
      total_receipts: totalReceipts,
      total_provenance: totalProvenance,
      governed_projects: governedProjects,
      total_projects: totalProjects,
      invariants_total: invariants.total,
      invariants_enforced: invariants.enforced,
      chain_valid: chainValid
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/governance/receipt', (req, res) => {
  try {
    const { action_type, entity_type, entity_id, actor, description, payload, project_id } = req.body;
    if (!action_type || !entity_type || !actor || !description) {
      return res.status(400).json({ error: 'action_type, entity_type, actor, and description required' });
    }
    const receipt = createReceipt(db, action_type, entity_type, entity_id || null, actor, description, payload || {}, project_id);
    res.json(receipt);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/governance/health', (req, res) => {
  try {
    // Get most recent health check for each type
    const types = ['chain_integrity','invariant_coverage','receipt_completeness','panel_independence','authority_chain','provenance_coverage'];
    const checks = [];
    for (const t of types) {
      const latest = db.prepare('SELECT * FROM governance_health WHERE check_type = ? ORDER BY checked_at DESC LIMIT 1').get(t);
      if (latest) checks.push(latest);
    }
    const avgScore = checks.length > 0 ? checks.reduce((s, c) => s + c.score, 0) / checks.length : 1.0;
    const overallStatus = avgScore > 0.8 ? 'healthy' : avgScore > 0.5 ? 'degraded' : 'critical';
    const lastChecked = checks.length > 0 ? checks.reduce((latest, c) => c.checked_at > latest ? c.checked_at : latest, checks[0].checked_at) : null;

    res.json({
      status: overallStatus,
      score: Math.round(avgScore * 100) / 100,
      last_checked: lastChecked,
      checks: checks.map(c => ({ type: c.check_type, status: c.status, score: c.score, details: c.details, checked_at: c.checked_at })),
      exochain_version: '2.1',
      hash_algorithm: 'sha256',
      branches: ['legislative', 'executive', 'judicial']
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/governance/health/history', (req, res) => {
  try {
    const { check_type, limit: lim } = req.query;
    let sql = 'SELECT * FROM governance_health';
    const params = [];
    if (check_type) { sql += ' WHERE check_type = ?'; params.push(check_type); }
    sql += ' ORDER BY checked_at DESC LIMIT ?';
    params.push(parseInt(lim) || 100);
    res.json(db.prepare(sql).all(...params));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/governance/chain/verify', (req, res) => {
  try {
    const receipts = db.prepare('SELECT * FROM governance_receipts ORDER BY id ASC').all();
    let valid = true;
    let brokenAt = null;
    let brokenDetails = null;
    const genesisHash = '0000000000000000000000000000000000000000000000000000000000000000';

    for (let i = 0; i < receipts.length; i++) {
      const r = receipts[i];
      const expectedPrev = i === 0 ? genesisHash : receipts[i - 1].receipt_hash;
      if (r.previous_hash !== expectedPrev) {
        valid = false;
        brokenAt = r.id;
        brokenDetails = { receipt_id: r.id, expected_previous: expectedPrev, actual_previous: r.previous_hash, position: i };
        break;
      }
    }

    // Branch distribution
    const branchCounts = { legislative: 0, executive: 0, judicial: 0 };
    for (const r of receipts) {
      if (r.branch && branchCounts[r.branch] !== undefined) branchCounts[r.branch]++;
    }

    // Adjudication distribution
    const adjCounts = { pass: 0, fail: 0, warn: 0, defer: 0 };
    for (const r of receipts) {
      if (r.adjudication && adjCounts[r.adjudication] !== undefined) adjCounts[r.adjudication]++;
    }

    res.json({
      valid,
      total_receipts: receipts.length,
      chain_depth: receipts.length > 0 ? (receipts[receipts.length - 1].chain_depth || receipts.length) : 0,
      broken_at: brokenAt,
      broken_details: brokenDetails,
      hash_algorithm: 'sha256',
      branches: branchCounts,
      adjudications: adjCounts,
      first_receipt: receipts.length > 0 ? receipts[0].created_at : null,
      last_receipt: receipts.length > 0 ? receipts[receipts.length - 1].created_at : null
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/governance/audit', (req, res) => {
  try {
    const { action_type, actor_id, branch, limit: lim } = req.query;
    let sql = 'SELECT * FROM governance_audit_trail WHERE 1=1';
    const params = [];
    if (action_type) { sql += ' AND action_type = ?'; params.push(action_type); }
    if (actor_id) { sql += ' AND actor_id = ?'; params.push(actor_id); }
    if (branch) { sql += ' AND branch = ?'; params.push(branch); }
    sql += ' ORDER BY created_at DESC LIMIT ?';
    params.push(parseInt(lim) || 100);
    res.json(db.prepare(sql).all(...params));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/governance/contest', (req, res) => {
  try {
    const { target_type, target_id, contestant_id, reason, evidence } = req.body;
    if (!target_type || !target_id || !reason) {
      return res.status(400).json({ error: 'target_type, target_id, and reason are required' });
    }
    if (!['receipt','decision','task','review'].includes(target_type)) {
      return res.status(400).json({ error: 'target_type must be one of: receipt, decision, task, review' });
    }
    const now = localNow();
    const result = db.prepare(`INSERT INTO contestations (target_type, target_id, contestant_id, reason, evidence, status, created_at)
      VALUES (?,?,?,?,?,?,?)`).run(target_type, target_id, contestant_id || null, reason, evidence || null, 'filed', now);

    const contestId = Number(result.lastInsertRowid);

    // Create governance receipt for the contestation
    createReceipt(db, 'contestation_filed', target_type, target_id, contestant_id ? `Member #${contestant_id}` : 'Anonymous',
      `Contestation filed against ${target_type} #${target_id}: ${reason.slice(0, 100)}`,
      { contestation_id: contestId, target_type, target_id, reason }, null,
      { branch: 'judicial' });

    res.json({ id: contestId, status: 'filed', message: 'Contestation filed successfully' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/governance/contestations', (req, res) => {
  try {
    const { status, target_type, limit: lim } = req.query;
    let sql = 'SELECT c.*, tm.name as contestant_name FROM contestations c LEFT JOIN team_members tm ON c.contestant_id = tm.id WHERE 1=1';
    const params = [];
    if (status) { sql += ' AND c.status = ?'; params.push(status); }
    if (target_type) { sql += ' AND c.target_type = ?'; params.push(target_type); }
    sql += ' ORDER BY c.created_at DESC LIMIT ?';
    params.push(parseInt(lim) || 50);
    res.json(db.prepare(sql).all(...params));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/governance/contestations/:id', (req, res) => {
  try {
    const { status, resolution } = req.body;
    if (!status || !['under_review','upheld','overturned','dismissed'].includes(status)) {
      return res.status(400).json({ error: 'status must be one of: under_review, upheld, overturned, dismissed' });
    }
    const now = localNow();
    const resolvedAt = ['upheld','overturned','dismissed'].includes(status) ? now : null;
    db.prepare(`UPDATE contestations SET status = ?, resolution = ?, resolved_at = ? WHERE id = ?`)
      .run(status, resolution || null, resolvedAt, req.params.id);

    createReceipt(db, 'contestation_resolved', 'contestation', parseInt(req.params.id), 'System',
      `Contestation #${req.params.id} resolved: ${status}`, { status, resolution }, null,
      { branch: 'judicial' });

    res.json({ message: 'Contestation updated', status });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/governance/escalation-challenges', (req, res) => {
  try {
    const { status, grounds, decision_id, limit: lim } = req.query;
    let sql = `SELECT ec.*, tm.name as challenger_display_name,
      ed.title as decision_title, ed.status as decision_status, ed.decision_class
      FROM escalation_challenges ec
      LEFT JOIN team_members tm ON ec.challenger_id = tm.id
      LEFT JOIN exochain_decisions ed ON ec.decision_id = ed.id
      WHERE 1=1`;
    const params = [];
    if (status) { sql += ' AND ec.status = ?'; params.push(status); }
    if (grounds) { sql += ' AND ec.grounds = ?'; params.push(grounds); }
    if (decision_id) { sql += ' AND ec.decision_id = ?'; params.push(parseInt(decision_id)); }
    sql += ' ORDER BY ec.filed_at DESC LIMIT ?';
    params.push(parseInt(lim) || 50);
    const challenges = db.prepare(sql).all(...params);
    res.json(challenges);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/governance/escalation-challenges/meta', (req, res) => {
  res.json({ grounds: CHALLENGE_GROUNDS, stages: ADJUDICATION_STAGES });
});

app.get('/api/governance/escalation-challenges/:id', (req, res) => {
  try {
    const challenge = db.prepare(`
      SELECT ec.*, tm.name as challenger_display_name,
        ed.title as decision_title, ed.status as decision_status, ed.decision_class, ed.description as decision_description
      FROM escalation_challenges ec
      LEFT JOIN team_members tm ON ec.challenger_id = tm.id
      LEFT JOIN exochain_decisions ed ON ec.decision_id = ed.id
      WHERE ec.id = ?
    `).get(req.params.id);
    if (!challenge) return res.status(404).json({ error: 'Challenge not found' });

    const stages = db.prepare(`
      SELECT cas.*, tm.name as adjudicator_display_name
      FROM challenge_adjudication_stages cas
      LEFT JOIN team_members tm ON cas.adjudicator_id = tm.id
      WHERE cas.challenge_id = ?
      ORDER BY cas.stage_number ASC
    `).all(req.params.id);

    res.json({ ...challenge, stages, stage_definitions: ADJUDICATION_STAGES });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/governance/escalation-challenges', (req, res) => {
  try {
    const { decision_id, challenger_id, challenger_name, challenger_tier, grounds, grounds_detail, evidence } = req.body;
    if (!decision_id || !challenger_name || !grounds || !grounds_detail) {
      return res.status(400).json({ error: 'decision_id, challenger_name, grounds, and grounds_detail are required' });
    }
    if (!CHALLENGE_GROUNDS.includes(grounds)) {
      return res.status(400).json({ error: `Invalid grounds. Must be one of: ${CHALLENGE_GROUNDS.join(', ')}` });
    }
    const result = fileEscalationChallenge({
      decision_id: parseInt(decision_id),
      challenger_id: challenger_id ? parseInt(challenger_id) : null,
      challenger_name,
      challenger_tier: challenger_tier || 'specialist',
      grounds,
      grounds_detail,
      evidence: evidence || []
    });
    res.json(result);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.put('/api/governance/escalation-challenges/:id/verdict', (req, res) => {
  try {
    const { stage_number, verdict, reasoning, evidence_reviewed, adjudicator_name } = req.body;
    if (!verdict || !['uphold_challenge', 'deny_challenge', 'escalate', 'remand', 'defer'].includes(verdict)) {
      return res.status(400).json({ error: 'verdict must be one of: uphold_challenge, deny_challenge, escalate, remand, defer' });
    }
    const challenge = db.prepare('SELECT current_stage FROM escalation_challenges WHERE id = ?').get(req.params.id);
    if (!challenge) return res.status(404).json({ error: 'Challenge not found' });

    const result = recordStageVerdict(parseInt(req.params.id), stage_number || challenge.current_stage, {
      verdict, reasoning, evidence_reviewed, adjudicator_name
    });
    res.json(result);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.put('/api/governance/escalation-challenges/:id/withdraw', (req, res) => {
  try {
    const now = localNow();
    const challenge = db.prepare('SELECT * FROM escalation_challenges WHERE id = ?').get(req.params.id);
    if (!challenge) return res.status(404).json({ error: 'Challenge not found' });
    if (['upheld', 'overturned', 'dismissed', 'withdrawn'].includes(challenge.status)) {
      return res.status(400).json({ error: 'Challenge is already resolved' });
    }

    db.prepare('UPDATE escalation_challenges SET status = ?, resolution = ?, resolved_at = ?, updated_at = ? WHERE id = ?')
      .run('withdrawn', req.body.reason || 'Withdrawn by challenger', now, now, req.params.id);

    // Restore decision from Contested status
    db.prepare(`UPDATE exochain_decisions SET status = 'Ratified', updated_at = ? WHERE id = ?`).run(now, challenge.decision_id);

    createReceipt(db, 'escalation_challenge_withdrawn', 'escalation_challenge', parseInt(req.params.id), challenge.challenger_name,
      `Escalation challenge #${req.params.id} withdrawn. Decision #${challenge.decision_id} restored to Ratified.`,
      { challenge_id: parseInt(req.params.id), decision_id: challenge.decision_id, reason: req.body.reason },
      null, { branch: 'judicial' });

    try { broadcast('governance.challenge_withdrawn', { challenge_id: parseInt(req.params.id), decision_id: challenge.decision_id }); } catch (_) {}

    res.json({ message: 'Challenge withdrawn', decision_status: 'Ratified' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/governance/escalation-challenge-stats', (req, res) => {
  try {
    const total = db.prepare('SELECT COUNT(*) as c FROM escalation_challenges').get().c;
    const byStatus = db.prepare(`SELECT status, COUNT(*) as c FROM escalation_challenges GROUP BY status`).all();
    const byGrounds = db.prepare(`SELECT grounds, COUNT(*) as c FROM escalation_challenges GROUP BY grounds`).all();
    const active = db.prepare(`SELECT COUNT(*) as c FROM escalation_challenges WHERE status IN ('filed','adjudicating')`).get().c;
    const avgStages = db.prepare(`SELECT AVG(current_stage) as avg FROM escalation_challenges WHERE status NOT IN ('filed','adjudicating')`).get().avg || 0;
    const upheldRate = total > 0 ? db.prepare(`SELECT COUNT(*) as c FROM escalation_challenges WHERE status = 'upheld'`).get().c / total : 0;

    res.json({
      total, active, avg_stages_to_resolve: Math.round(avgStages * 10) / 10,
      upheld_rate: Math.round(upheldRate * 100),
      by_status: byStatus.reduce((acc, r) => { acc[r.status] = r.c; return acc; }, {}),
      by_grounds: byGrounds.reduce((acc, r) => { acc[r.grounds] = r.c; return acc; }, {})
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/governance/delegations', (req, res) => {
  try {
    const { active_only } = req.query;
    let sql = `SELECT ad.*, d.name as delegator_name, del.name as delegate_name
      FROM authority_delegations ad
      LEFT JOIN team_members d ON ad.delegator_id = d.id
      LEFT JOIN team_members del ON ad.delegate_id = del.id`;
    if (active_only === '1' || active_only === 'true') {
      sql += ` WHERE ad.revoked = 0 AND (ad.valid_until IS NULL OR ad.valid_until > datetime('now','localtime'))`;
    }
    sql += ' ORDER BY ad.created_at DESC LIMIT 100';
    res.json(db.prepare(sql).all());
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/governance/delegations', (req, res) => {
  try {
    const { delegator_id, delegate_id, scope, permissions, valid_until } = req.body;
    if (!delegator_id || !delegate_id || !scope) {
      return res.status(400).json({ error: 'delegator_id, delegate_id, and scope are required' });
    }
    if (delegator_id === delegate_id) {
      return res.status(400).json({ error: 'Cannot delegate to self (ExoChain NoSelfGrant invariant)' });
    }
    const now = localNow();
    const result = db.prepare(`INSERT INTO authority_delegations (delegator_id, delegate_id, scope, permissions, valid_from, valid_until, created_at)
      VALUES (?,?,?,?,?,?,?)`).run(delegator_id, delegate_id, scope, JSON.stringify(permissions || []), now, valid_until || null, now);

    const delegationId = Number(result.lastInsertRowid);

    const delegator = db.prepare('SELECT name FROM team_members WHERE id = ?').get(delegator_id);
    const delegate = db.prepare('SELECT name FROM team_members WHERE id = ?').get(delegate_id);

    createReceipt(db, 'delegation_created', 'delegation', delegationId,
      delegator ? delegator.name : `Member #${delegator_id}`,
      `Authority delegated from ${delegator?.name || delegator_id} to ${delegate?.name || delegate_id}: ${scope}`,
      { delegator_id, delegate_id, scope, permissions }, null,
      { branch: 'executive' });

    res.json({ id: delegationId, message: 'Delegation created' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/governance/delegations/:id', (req, res) => {
  try {
    const now = localNow();
    db.prepare(`UPDATE authority_delegations SET revoked = 1 WHERE id = ?`).run(req.params.id);
    createReceipt(db, 'delegation_revoked', 'delegation', parseInt(req.params.id), 'System',
      `Delegation #${req.params.id} revoked`, {}, null, { branch: 'executive' });
    res.json({ message: 'Delegation revoked' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/governance/emergencies', (req, res) => {
  try {
    res.json(db.prepare('SELECT * FROM emergency_protocols ORDER BY severity DESC, name').all());
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/governance/emergencies/:id/activate', (req, res) => {
  try {
    const protocol = db.prepare('SELECT * FROM emergency_protocols WHERE id = ?').get(req.params.id);
    if (!protocol) return res.status(404).json({ error: 'Protocol not found' });
    if (protocol.status === 'activated') return res.status(400).json({ error: 'Protocol already activated' });

    const now = localNow();
    db.prepare(`UPDATE emergency_protocols SET status = 'activated', last_activated_at = ? WHERE id = ?`).run(now, req.params.id);

    // Execute the protocol actions
    let actions = [];
    try { actions = JSON.parse(protocol.actions); } catch (_) {}

    // Create notification for each action
    for (const action of actions) {
      if (action.includes('notify_max') || action.includes('notify')) {
        createNotification('system', `EMERGENCY: ${protocol.name}`, `Protocol activated: ${protocol.trigger_condition}. Action: ${action}`);
      }
    }

    // Create governance receipt
    createReceipt(db, 'emergency_activation', 'emergency_protocol', parseInt(req.params.id), 'System',
      `Emergency protocol "${protocol.name}" activated: ${protocol.trigger_condition}`,
      { protocol_id: protocol.id, name: protocol.name, actions, severity: protocol.severity }, null,
      { branch: 'judicial', adjudication: 'fail' });

    res.json({ message: `Emergency protocol "${protocol.name}" activated`, actions });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/governance/emergencies/:id/resolve', (req, res) => {
  try {
    const now = localNow();
    db.prepare(`UPDATE emergency_protocols SET status = 'armed' WHERE id = ?`).run(req.params.id);
    createReceipt(db, 'emergency_resolved', 'emergency_protocol', parseInt(req.params.id), 'System',
      `Emergency protocol #${req.params.id} resolved and re-armed`, {}, null, { branch: 'judicial' });
    res.json({ message: 'Emergency protocol resolved and re-armed' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/governance/conflicts', (req, res) => {
  try {
    const { status, limit: lim } = req.query;
    let sql = 'SELECT * FROM conflict_records';
    const params = [];
    if (status) { sql += ' WHERE status = ?'; params.push(status); }
    sql += ' ORDER BY created_at DESC LIMIT ?';
    params.push(parseInt(lim) || 50);
    res.json(db.prepare(sql).all(...params));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/governance/conflicts', (req, res) => {
  try {
    const { conflict_type, parties, description, severity } = req.body;
    if (!conflict_type || !description) {
      return res.status(400).json({ error: 'conflict_type and description are required' });
    }
    const now = localNow();
    const result = db.prepare(`INSERT INTO conflict_records (conflict_type, parties, description, severity, status, created_at)
      VALUES (?,?,?,?,?,?)`).run(conflict_type, JSON.stringify(parties || []), description, severity || 'medium', 'detected', now);

    createReceipt(db, 'conflict_detected', 'conflict', Number(result.lastInsertRowid), 'System',
      `Conflict detected: ${conflict_type} — ${description.slice(0, 100)}`,
      { conflict_type, parties, severity }, null, { branch: 'judicial' });

    res.json({ id: Number(result.lastInsertRowid), message: 'Conflict recorded' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/governance/identities', (req, res) => {
  try {
    const identities = db.prepare(`SELECT mi.*, tm.name as member_name, tm.role as member_role
      FROM member_identities mi LEFT JOIN team_members tm ON mi.member_id = tm.id ORDER BY mi.created_at DESC`).all();
    res.json(identities);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/governance/consent', (req, res) => {
  try {
    const { member_id } = req.query;
    let sql = 'SELECT cr.*, tm.name as member_name FROM consent_records cr LEFT JOIN team_members tm ON cr.member_id = tm.id';
    const params = [];
    if (member_id) { sql += ' WHERE cr.member_id = ?'; params.push(member_id); }
    sql += ' ORDER BY cr.created_at DESC LIMIT 100';
    res.json(db.prepare(sql).all(...params));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/governance/health/run', (req, res) => {
  try {
    const result = governanceHealthCheck();
    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/governance/validate/:taskId', (req, res) => {
  try {
    const taskId = parseInt(req.params.taskId);
    const task = db.prepare('SELECT * FROM tasks WHERE id = ?').get(taskId);
    if (!task) return res.status(404).json({ error: 'Task not found' });

    // Get the most recent process output for this task
    const proc = db.prepare('SELECT output_summary FROM active_processes WHERE task_id = ? ORDER BY id DESC LIMIT 1').get(taskId);
    const output = proc ? proc.output_summary || '' : task.current_step || task.description || '';

    const result = validateAgainstInvariants(taskId, output);
    res.json({
      task_id: taskId,
      task_title: task.title,
      workflow: task.workflow || detectWorkflowType(task.title, task.description),
      passed: result.passed,
      violations: result.violations,
      violation_count: result.violations.length,
      block_count: result.violations.filter(v => v.severity === 'block').length,
      warn_count: result.violations.filter(v => v.severity === 'warn').length
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/escalations', (req, res) => {
  try {
    const conditions = [];
    const values = [];
    if (req.query.status) { conditions.push('el.status = ?'); values.push(req.query.status); }
    const where = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';
    const rows = db.prepare(`
      SELECT el.*, f.name as from_agent_name, t.name as to_agent_name, p.name as project_name
      FROM escalation_log el
      LEFT JOIN team_members f ON el.from_agent_id = f.id
      LEFT JOIN team_members t ON el.to_agent_id = t.id
      LEFT JOIN projects p ON el.project_id = p.id
      ${where}
      ORDER BY el.created_at DESC
    `).all(...values);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/escalations', (req, res) => {
  try {
    const { packet_id, from_agent_id, to_agent_id, reason, project_id } = req.body;
    if (!reason || !reason.trim()) return res.status(400).json({ error: 'reason is required' });

    const now = localNow();
    const result = db.prepare(`
      INSERT INTO escalation_log (packet_id, from_agent_id, to_agent_id, reason, status, project_id, created_at)
      VALUES (?, ?, ?, ?, 'open', ?, ?)
    `).run(packet_id || null, from_agent_id || null, to_agent_id || null, reason.trim(), project_id || null, now);
    res.json({ id: Number(result.lastInsertRowid), message: 'Escalation created' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/escalations/:id', (req, res) => {
  try {
    const existing = db.prepare('SELECT * FROM escalation_log WHERE id = ?').get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Escalation not found' });

    const { resolution, status } = req.body;
    const validStatuses = ['open', 'resolved', 'founder_required'];
    if (status && !validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status. Must be one of: ' + validStatuses.join(', ') });
    }

    const updates = [];
    const values = [];
    if (resolution !== undefined) { updates.push('resolution = ?'); values.push(resolution); }
    if (status !== undefined) {
      updates.push('status = ?');
      values.push(status);
      if (status === 'resolved') {
        updates.push('resolved_at = ?');
        values.push(localNow());
      }
    }
    if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });

    values.push(req.params.id);
    db.prepare(`UPDATE escalation_log SET ${updates.join(', ')} WHERE id = ?`).run(...values);
    res.json({ id: Number(req.params.id), message: 'Escalation updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/approvals/pending/count — count of pending approvals (must be before :id route)
app.get('/api/approvals/pending/count', (req, res, next) => {
  try {
    const row = db.prepare(`SELECT COUNT(*) as count FROM approvals WHERE status = 'pending'`).get();
    res.json({ count: row.count });
  } catch (err) { next(err); }
});

// GET /api/approvals — list approvals
app.get('/api/approvals', (req, res, next) => {
  try {
    const { status, type } = req.query;
    let sql = `SELECT a.*, tm.name as requester_member_name, p.name as project_name FROM approvals a LEFT JOIN team_members tm ON a.requested_by_member_id = tm.id LEFT JOIN projects p ON a.project_id = p.id WHERE 1=1`;
    const params = [];
    if (status) { sql += ' AND a.status = ?'; params.push(status); }
    if (type) { sql += ' AND a.approval_type = ?'; params.push(type); }
    sql += ' ORDER BY CASE a.priority WHEN \'urgent\' THEN 0 WHEN \'high\' THEN 1 WHEN \'normal\' THEN 2 WHEN \'low\' THEN 3 END, a.created_at DESC';
    const rows = db.prepare(sql).all(...params);
    res.json(rows);
  } catch (err) { next(err); }
});

// GET /api/approvals/:id — single approval with comments
app.get('/api/approvals/:id', (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const approval = db.prepare(`SELECT a.*, tm.name as requester_member_name, p.name as project_name FROM approvals a LEFT JOIN team_members tm ON a.requested_by_member_id = tm.id LEFT JOIN projects p ON a.project_id = p.id WHERE a.id = ?`).get(id);
    if (!approval) return res.status(404).json({ error: 'Approval not found' });
    const comments = db.prepare(`SELECT * FROM approval_comments WHERE approval_id = ? ORDER BY created_at ASC`).all(id);
    res.json({ ...approval, comments });
  } catch (err) { next(err); }
});

// POST /api/approvals — create an approval request
app.post('/api/approvals', (req, res, next) => {
  try {
    const { title, description, approval_type, requested_by_member_id, requested_by_name, task_id, project_id, priority, context_json, expires_at } = req.body;
    if (!title) throw badRequest('title is required');
    const now = localNow();
    const result = db.prepare(`INSERT INTO approvals (title, description, approval_type, requested_by_member_id, requested_by_name, task_id, project_id, status, priority, context_json, expires_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .run(title, description || null, approval_type || 'general', requested_by_member_id || null, requested_by_name || 'Gray', task_id || null, project_id || null, 'pending', priority || 'normal', context_json || '{}', expires_at || null, now, now);
    const approval = db.prepare('SELECT * FROM approvals WHERE id = ?').get(result.lastInsertRowid);
    createNotification('system', 'Approval Requested', `"${title}" needs approval`);
    broadcast('approval.created', { id: approval.id, title: approval.title });
    res.status(201).json(approval);
  } catch (err) { next(err); }
});

// PUT /api/approvals/:id — decide (approve/reject)
app.put('/api/approvals/:id', (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const existing = db.prepare('SELECT * FROM approvals WHERE id = ?').get(id);
    if (!existing) return res.status(404).json({ error: 'Approval not found' });
    const { status, decision_notes, decided_by } = req.body;
    const now = localNow();
    if (status && (status === 'approved' || status === 'rejected')) {
      db.prepare(`UPDATE approvals SET status = ?, decision_notes = ?, decided_by = ?, decided_at = ?, updated_at = ? WHERE id = ?`)
        .run(status, decision_notes || null, decided_by || 'Max', now, now, id);
      // Add a comment recording the decision
      db.prepare(`INSERT INTO approval_comments (approval_id, author_name, content, created_at) VALUES (?,?,?,?)`)
        .run(id, decided_by || 'Max', `${status === 'approved' ? 'Approved' : 'Rejected'}${decision_notes ? ': ' + decision_notes : ''}`, now);
      createNotification('system', `Approval ${status === 'approved' ? 'Approved' : 'Rejected'}`, `"${existing.title}" was ${status}`);
      broadcast('approval.decided', { id, status });
    } else {
      // General update (priority, description, etc.)
      const { priority, description, title } = req.body;
      db.prepare(`UPDATE approvals SET title = COALESCE(?, title), description = COALESCE(?, description), priority = COALESCE(?, priority), status = COALESCE(?, status), updated_at = ? WHERE id = ?`)
        .run(title || null, description || null, priority || null, status || null, now, id);
    }
    const updated = db.prepare('SELECT * FROM approvals WHERE id = ?').get(id);
    res.json(updated);
  } catch (err) { next(err); }
});

// DELETE /api/approvals/:id — withdraw
app.delete('/api/approvals/:id', (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const existing = db.prepare('SELECT * FROM approvals WHERE id = ?').get(id);
    if (!existing) return res.status(404).json({ error: 'Approval not found' });
    db.prepare('DELETE FROM approval_comments WHERE approval_id = ?').run(id);
    db.prepare('DELETE FROM approvals WHERE id = ?').run(id);
    broadcast('approval.deleted', { id });
    res.json({ deleted: true });
  } catch (err) { next(err); }
});

// POST /api/approvals/:id/comments — add comment
app.post('/api/approvals/:id/comments', (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const { author_name, content } = req.body;
    if (!content) throw badRequest('content is required');
    const now = localNow();
    const result = db.prepare(`INSERT INTO approval_comments (approval_id, author_name, content, created_at) VALUES (?,?,?,?)`)
      .run(id, author_name || 'Max', content, now);
    const comment = db.prepare('SELECT * FROM approval_comments WHERE id = ?').get(result.lastInsertRowid);
    broadcast('approval.comment', { approval_id: id });
    res.status(201).json(comment);
  } catch (err) { next(err); }
});


};
