'use strict';
module.exports = function(app, db, helpers) {
  const { broadcast, localNow, createNotification, authRateLimiter, apiRateLimiter, spawnMemberTerminal } = helpers;
  const stmt = helpers.stmt || ((sql) => db.prepare(sql));

// GET /api/context-usage — Context window tracking and high water marks
app.get('/api/context-usage', (req, res) => {
  try {
    // Get all context usage logs from recent spawns
    const recentUsage = db.prepare(`
      SELECT actor as member, notes, created_at FROM activity_log
      WHERE action = 'context_window_usage'
      ORDER BY id DESC LIMIT 50
    `).all().map(r => {
      try { return { member: r.member, ...JSON.parse(r.notes), created_at: r.created_at }; }
      catch { return { member: r.member, raw: r.notes, created_at: r.created_at }; }
    });

    // Get high water marks per member
    const hwmRows = db.prepare(`SELECT key, value FROM system_settings WHERE key LIKE 'context_hwm_%'`).all();
    const highWaterMarks = {};
    for (const r of hwmRows) {
      const name = r.key.replace('context_hwm_', '');
      highWaterMarks[name] = parseInt(r.value) || 0;
    }

    // Compute averages by tier
    const byTier = {};
    for (const u of recentUsage) {
      const tier = u.tier || 'unknown';
      if (!byTier[tier]) byTier[tier] = { count: 0, total_tokens: 0, max_tokens: 0 };
      byTier[tier].count++;
      byTier[tier].total_tokens += u.prompt_tokens_est || 0;
      byTier[tier].max_tokens = Math.max(byTier[tier].max_tokens, u.prompt_tokens_est || 0);
    }
    for (const tier of Object.keys(byTier)) {
      byTier[tier].avg_tokens = Math.round(byTier[tier].total_tokens / byTier[tier].count);
    }

    // Context window limits for reference
    const contextLimits = {
      haiku: 200000,
      sonnet: 200000,
      opus: 200000,
      'nemotron-cascade-2': 262144
    };

    res.json({
      recent_usage: recentUsage.slice(0, 20),
      high_water_marks: highWaterMarks,
      by_tier: byTier,
      context_limits: contextLimits,
      recommendations: [
        highWaterMarks.global > 10000 ? 'Global HWM is ' + highWaterMarks.global + ' tokens — consider trimming identity files' : null,
        byTier.full && byTier.full.avg_tokens > 8000 ? 'Full tier averages ' + byTier.full.avg_tokens + ' tokens — review if all context is necessary' : null,
        byTier.minimal && byTier.minimal.avg_tokens > 3000 ? 'Minimal tier averages ' + byTier.minimal.avg_tokens + ' tokens — should be under 2000' : null,
      ].filter(Boolean)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/context — list context items with filters
app.get('/api/context', (req, res) => {
  try {
    const { scope, type, department, member_id, importance, status: ctxStatus, limit: lim } = req.query;
    let query = 'SELECT cs.*, tm.name as author_name, tm.role as author_role, tm.tier as author_tier FROM context_store cs LEFT JOIN team_members tm ON cs.author_member_id = tm.id WHERE 1=1';
    const params = [];

    if (scope) { query += ' AND cs.scope = ?'; params.push(scope); }
    if (type) { query += ' AND cs.context_type = ?'; params.push(type); }
    if (department) { query += ' AND cs.department = ?'; params.push(department); }
    if (member_id) { query += ' AND cs.author_member_id = ?'; params.push(Number(member_id)); }
    if (importance) { query += ' AND cs.importance = ?'; params.push(importance); }
    if (ctxStatus) { query += ' AND cs.status = ?'; params.push(ctxStatus); }
    else { query += " AND cs.status = 'active'"; }

    query += ' ORDER BY CASE cs.importance WHEN \'critical\' THEN 0 WHEN \'high\' THEN 1 WHEN \'normal\' THEN 2 WHEN \'low\' THEN 3 END, cs.relevance_score DESC, cs.updated_at DESC';
    query += ' LIMIT ?';
    params.push(Number(lim) || 100);

    const items = db.prepare(query).all(...params);
    res.json(items);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/context/stats — overview stats
app.get('/api/context/stats', (req, res) => {
  try {
    const totalActive = db.prepare("SELECT COUNT(*) as c FROM context_store WHERE status = 'active'").get().c;
    const totalArchived = db.prepare("SELECT COUNT(*) as c FROM context_store WHERE status = 'archived'").get().c;

    const byScope = db.prepare("SELECT scope, COUNT(*) as count FROM context_store WHERE status = 'active' GROUP BY scope").all();
    const byType = db.prepare("SELECT context_type, COUNT(*) as count FROM context_store WHERE status = 'active' GROUP BY context_type").all();
    const byDepartment = db.prepare("SELECT department, COUNT(*) as count FROM context_store WHERE status = 'active' AND department IS NOT NULL GROUP BY department").all();
    const byImportance = db.prepare("SELECT importance, COUNT(*) as count FROM context_store WHERE status = 'active' GROUP BY importance").all();

    // Freshness: items updated in last 24h, 7d, 30d
    const now = localNow();
    const fresh24h = db.prepare("SELECT COUNT(*) as c FROM context_store WHERE status = 'active' AND updated_at > datetime(?, '-1 day')").get(now).c;
    const fresh7d = db.prepare("SELECT COUNT(*) as c FROM context_store WHERE status = 'active' AND updated_at > datetime(?, '-7 days')").get(now).c;
    const fresh30d = db.prepare("SELECT COUNT(*) as c FROM context_store WHERE status = 'active' AND updated_at > datetime(?, '-30 days')").get(now).c;
    const stale = totalActive - fresh30d;

    const avgRelevance = db.prepare("SELECT AVG(relevance_score) as avg FROM context_store WHERE status = 'active'").get().avg || 0;

    const escalationsPending = db.prepare("SELECT COUNT(*) as c FROM context_propagation WHERE acknowledged = 0").get().c;
    const totalPropagations = db.prepare("SELECT COUNT(*) as c FROM context_propagation").get().c;

    const totalSummaries = db.prepare("SELECT COUNT(*) as c FROM department_summaries").get().c;

    res.json({
      total_active: totalActive,
      total_archived: totalArchived,
      by_scope: byScope,
      by_type: byType,
      by_department: byDepartment,
      by_importance: byImportance,
      freshness: { last_24h: fresh24h, last_7d: fresh7d, last_30d: fresh30d, stale },
      avg_relevance: Math.round(avgRelevance * 100) / 100,
      escalations_pending: escalationsPending,
      total_propagations: totalPropagations,
      total_summaries: totalSummaries
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/context/member/:id — context visible to a specific member (tiered loading)
app.get('/api/context/member/:id', (req, res) => {
  try {
    const memberId = Number(req.params.id);
    const member = db.prepare('SELECT * FROM team_members WHERE id = ?').get(memberId);
    if (!member) return res.status(404).json({ error: 'Member not found' });

    const tier = member.tier;
    const dept = member.department;
    const now = localNow();

    let budget, scopes;
    switch (tier) {
      case 'board': budget = 50; scopes = ['company', 'department', 'team', 'escalated']; break;
      case 'c-suite': budget = 40; scopes = ['company', 'department', 'escalated']; break;
      case 'specialist': budget = 20; scopes = ['department', 'team', 'personal']; break;
      default: budget = 15; scopes = ['team', 'personal']; break;
    }

    const scopePlaceholders = scopes.map(() => '?').join(',');
    const items = db.prepare(`
      SELECT cs.*, tm.name as author_name, tm.role as author_role FROM context_store cs
      LEFT JOIN team_members tm ON cs.author_member_id = tm.id
      WHERE cs.status = 'active'
      AND (
        (cs.author_member_id = ?)
        OR (cs.scope IN (${scopePlaceholders}) AND (cs.department = ? OR cs.department IS NULL OR cs.scope = 'company'))
      )
      AND (cs.expires_at IS NULL OR cs.expires_at > ?)
      ORDER BY CASE cs.importance WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 WHEN 'low' THEN 3 END, cs.relevance_score DESC, cs.updated_at DESC
      LIMIT ?
    `).all(memberId, ...scopes, dept, now, budget);

    // Also include propagated context
    const propagated = db.prepare(`
      SELECT cs.*, tm.name as author_name, tm.role as author_role, cp.propagation_type, cp.acknowledged
      FROM context_store cs
      JOIN context_propagation cp ON cp.context_id = cs.id
      LEFT JOIN team_members tm ON cs.author_member_id = tm.id
      WHERE cp.to_member_id = ? AND cs.status = 'active'
      ORDER BY cp.created_at DESC LIMIT 10
    `).all(memberId);

    res.json({ member: { id: member.id, name: member.name, tier, department: dept }, budget, scopes, items, propagated, total: items.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/context/department/:dept — all context for a department
app.get('/api/context/department/:dept', (req, res) => {
  try {
    const dept = req.params.dept;
    const items = db.prepare(`
      SELECT cs.*, tm.name as author_name, tm.role as author_role FROM context_store cs
      LEFT JOIN team_members tm ON cs.author_member_id = tm.id
      WHERE cs.department = ? AND cs.status = 'active'
      ORDER BY cs.importance DESC, cs.relevance_score DESC, cs.updated_at DESC
      LIMIT 100
    `).all(dept);
    res.json(items);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/context/company — company-wide context
app.get('/api/context/company', (req, res) => {
  try {
    const items = db.prepare(`
      SELECT cs.*, tm.name as author_name, tm.role as author_role FROM context_store cs
      LEFT JOIN team_members tm ON cs.author_member_id = tm.id
      WHERE cs.scope = 'company' AND cs.status = 'active'
      ORDER BY cs.importance DESC, cs.relevance_score DESC, cs.updated_at DESC
      LIMIT 50
    `).all();
    res.json(items);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/context/escalations — pending escalations (must be before /:id)
app.get('/api/context/escalations', (req, res) => {
  try {
    const escalations = db.prepare(`
      SELECT cs.*, cp.propagation_type, cp.acknowledged, cp.created_at as escalated_at,
        tmf.name as from_name, tmf.role as from_role,
        tmt.name as to_name, tmt.role as to_role,
        tma.name as author_name, tma.role as author_role
      FROM context_propagation cp
      JOIN context_store cs ON cp.context_id = cs.id
      LEFT JOIN team_members tmf ON cp.from_member_id = tmf.id
      LEFT JOIN team_members tmt ON cp.to_member_id = tmt.id
      LEFT JOIN team_members tma ON cs.author_member_id = tma.id
      WHERE cp.acknowledged = 0 AND cs.status = 'active'
      ORDER BY cs.importance DESC, cp.created_at DESC
      LIMIT 50
    `).all();
    res.json(escalations);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/context/:id — single item with propagation history
app.get('/api/context/:id', (req, res) => {
  try {
    const id = Number(req.params.id);
    const item = db.prepare(`
      SELECT cs.*, tm.name as author_name, tm.role as author_role FROM context_store cs
      LEFT JOIN team_members tm ON cs.author_member_id = tm.id
      WHERE cs.id = ?
    `).get(id);
    if (!item) return res.status(404).json({ error: 'Context item not found' });

    const propagations = db.prepare(`
      SELECT cp.*, tmf.name as from_name, tmt.name as to_name
      FROM context_propagation cp
      LEFT JOIN team_members tmf ON cp.from_member_id = tmf.id
      LEFT JOIN team_members tmt ON cp.to_member_id = tmt.id
      WHERE cp.context_id = ?
      ORDER BY cp.created_at DESC
    `).all(id);

    item.propagations = propagations;
    res.json(item);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/context — create a context item
app.post('/api/context', (req, res) => {
  try {
    const { author_member_id, scope, department, context_type, title, content, importance, tags, source_task_id, source_project_id, source_type, expires_at } = req.body;
    if (!author_member_id || !context_type || !title || !content) {
      return res.status(400).json({ error: 'author_member_id, context_type, title, content are required' });
    }
    const now = localNow();
    const result = db.prepare(`INSERT INTO context_store (author_member_id, scope, department, context_type, title, content, importance, tags, source_task_id, source_project_id, source_type, expires_at, last_accessed_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .run(author_member_id, scope || 'personal', department || null, context_type, title, content, importance || 'normal', JSON.stringify(tags || []), source_task_id || null, source_project_id || null, source_type || 'manual', expires_at || null, now, now, now);

    const newItem = db.prepare('SELECT * FROM context_store WHERE id = ?').get(result.lastInsertRowid);

    // Auto-escalate high/critical items or escalated scope
    if (importance === 'critical' || importance === 'high' || scope === 'escalated') {
      escalateContext(newItem.id);
    }

    broadcast('context.created', { id: newItem.id, title: newItem.title, scope: newItem.scope, importance: newItem.importance });
    res.status(201).json(newItem);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PUT /api/context/:id — update a context item
app.put('/api/context/:id', (req, res) => {
  try {
    const id = Number(req.params.id);
    const existing = db.prepare('SELECT * FROM context_store WHERE id = ?').get(id);
    if (!existing) return res.status(404).json({ error: 'Context item not found' });

    const { scope, department, context_type, title, content, importance, tags, status: newStatus, expires_at } = req.body;
    const now = localNow();

    db.prepare(`UPDATE context_store SET scope = ?, department = ?, context_type = ?, title = ?, content = ?, importance = ?, tags = ?, status = ?, expires_at = ?, updated_at = ? WHERE id = ?`)
      .run(scope || existing.scope, department !== undefined ? department : existing.department, context_type || existing.context_type, title || existing.title, content || existing.content, importance || existing.importance, tags ? JSON.stringify(tags) : existing.tags, newStatus || existing.status, expires_at !== undefined ? expires_at : existing.expires_at, now, id);

    const updated = db.prepare('SELECT * FROM context_store WHERE id = ?').get(id);
    broadcast('context.updated', { id: updated.id });
    res.json(updated);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// DELETE /api/context/:id — archive (soft delete)
app.delete('/api/context/:id', (req, res) => {
  try {
    const id = Number(req.params.id);
    const existing = db.prepare('SELECT * FROM context_store WHERE id = ?').get(id);
    if (!existing) return res.status(404).json({ error: 'Context item not found' });

    db.prepare("UPDATE context_store SET status = 'archived', updated_at = ? WHERE id = ?").run(localNow(), id);
    broadcast('context.archived', { id });
    res.json({ success: true, archived: id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/context/:id/escalate — manually escalate up the chain
app.post('/api/context/:id/escalate', (req, res) => {
  try {
    const id = Number(req.params.id);
    const existing = db.prepare('SELECT * FROM context_store WHERE id = ?').get(id);
    if (!existing) return res.status(404).json({ error: 'Context item not found' });

    // Update scope to escalated
    db.prepare("UPDATE context_store SET scope = 'escalated', updated_at = ? WHERE id = ?").run(localNow(), id);
    escalateContext(id);

    const propagations = db.prepare('SELECT * FROM context_propagation WHERE context_id = ?').all(id);
    broadcast('context.escalated', { id, propagation_count: propagations.length });
    res.json({ success: true, escalated: id, propagations: propagations.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/context/:id/acknowledge — acknowledge a propagated context item
app.post('/api/context/:id/acknowledge', (req, res) => {
  try {
    const contextId = Number(req.params.id);
    const { member_id } = req.body;
    if (!member_id) return res.status(400).json({ error: 'member_id required' });

    db.prepare('UPDATE context_propagation SET acknowledged = 1 WHERE context_id = ? AND to_member_id = ?').run(contextId, member_id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/context/decay — manually trigger decay
app.post('/api/context/decay', (req, res) => {
  try {
    decayContextRelevance();
    res.json({ success: true, message: 'Context decay completed' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/context/cleanup — archive old low-relevance items
app.post('/api/context/cleanup', (req, res) => {
  try {
    const now = localNow();
    const archived = db.prepare(`
      UPDATE context_store SET status = 'archived', updated_at = ?
      WHERE status = 'active' AND relevance_score < 0.3 AND importance NOT IN ('critical', 'high')
      AND created_at < datetime(?, '-14 days')
    `).run(now, now);

    const expired = db.prepare(`
      UPDATE context_store SET status = 'expired', updated_at = ?
      WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at < ?
    `).run(now, now);

    res.json({ success: true, archived: archived.changes, expired: expired.changes });
  } catch (err) { res.status(500).json({ error: err.message }); }
});


};
