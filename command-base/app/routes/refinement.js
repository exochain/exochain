'use strict';
module.exports = function(app, db, helpers) {
  const { broadcast, localNow, createNotification, authRateLimiter, apiRateLimiter, spawnMemberTerminal } = helpers;
  const stmt = helpers.stmt || ((sql) => db.prepare(sql));

// GET /api/refinement/targets
app.get('/api/refinement/targets', (req, res) => {
  try {
    const targets = db.prepare(`
      SELECT rt.*, p.name as project_name,
        (SELECT COUNT(*) FROM refinement_candidates rc WHERE rc.target_id = rt.id AND rc.status = 'pending') as pending_count,
        (SELECT COUNT(*) FROM refinement_candidates rc WHERE rc.target_id = rt.id AND rc.status = 'in_progress') as in_progress_count,
        (SELECT COUNT(*) FROM refinement_candidates rc WHERE rc.target_id = rt.id AND rc.status = 'completed') as completed_count,
        (SELECT COUNT(*) FROM refinement_candidates rc WHERE rc.target_id = rt.id) as total_candidates,
        (SELECT COUNT(*) FROM refinement_team_assignments rta WHERE rta.target_id = rt.id AND rta.enabled = 1) as enabled_members
      FROM refinement_targets rt
      LEFT JOIN projects p ON rt.project_id = p.id
      ORDER BY rt.updated_at DESC
    `).all();
    res.json(targets);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/refinement/targets
app.post('/api/refinement/targets', (req, res) => {
  try {
    const { name, target_type, target_path, repo_url, project_id, scan_patterns, exclude_patterns } = req.body;
    if (!name || !target_type) return res.status(400).json({ error: 'name and target_type required' });
    const now = localNow();
    const result = db.prepare(`INSERT INTO refinement_targets (name, target_type, target_path, repo_url, project_id, scan_patterns, exclude_patterns, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)`)
      .run(name, target_type, target_path || null, repo_url || null, project_id || null, scan_patterns ? JSON.stringify(scan_patterns) : '["*.js","*.css","*.html"]', exclude_patterns ? JSON.stringify(exclude_patterns) : '["node_modules","*.lock",".git"]', now, now);
    const created = db.prepare('SELECT * FROM refinement_targets WHERE id = ?').get(Number(result.lastInsertRowid));
    broadcast('refinement.target_created', { id: created.id });
    res.status(201).json(created);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PUT /api/refinement/targets/:id
app.put('/api/refinement/targets/:id', (req, res) => {
  try {
    const id = Number(req.params.id);
    const existing = db.prepare('SELECT * FROM refinement_targets WHERE id = ?').get(id);
    if (!existing) return res.status(404).json({ error: 'Target not found' });
    const { name, target_path, repo_url, scan_patterns, exclude_patterns, auto_mode } = req.body;
    const now = localNow();
    db.prepare(`UPDATE refinement_targets SET name = ?, target_path = ?, repo_url = ?, scan_patterns = ?, exclude_patterns = ?, auto_mode = ?, updated_at = ? WHERE id = ?`)
      .run(name || existing.name, target_path !== undefined ? target_path : existing.target_path, repo_url !== undefined ? repo_url : existing.repo_url, scan_patterns ? JSON.stringify(scan_patterns) : existing.scan_patterns, exclude_patterns ? JSON.stringify(exclude_patterns) : existing.exclude_patterns, auto_mode !== undefined ? (auto_mode ? 1 : 0) : existing.auto_mode, now, id);
    const updated = db.prepare('SELECT * FROM refinement_targets WHERE id = ?').get(id);
    res.json(updated);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// DELETE /api/refinement/targets/:id
app.delete('/api/refinement/targets/:id', (req, res) => {
  try {
    const id = Number(req.params.id);
    stopRefinementLoop(id);
    db.prepare('DELETE FROM refinement_team_assignments WHERE target_id = ?').run(id);
    db.prepare('DELETE FROM refinement_candidates WHERE target_id = ?').run(id);
    db.prepare('DELETE FROM refinement_targets WHERE id = ?').run(id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/refinement/targets/:id/scan
app.post('/api/refinement/targets/:id/scan', (req, res) => {
  try {
    const result = scanForRefinementCandidates(Number(req.params.id));
    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/refinement/targets/:id/start
app.post('/api/refinement/targets/:id/start', (req, res) => {
  try {
    startRefinementLoop(Number(req.params.id));
    res.json({ success: true, status: 'running' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/refinement/targets/:id/stop
app.post('/api/refinement/targets/:id/stop', (req, res) => {
  try {
    stopRefinementLoop(Number(req.params.id));
    res.json({ success: true, status: 'stopped' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/refinement/targets/:id/candidates
app.get('/api/refinement/targets/:id/candidates', (req, res) => {
  try {
    const { category, status: cStatus, priority } = req.query;
    let query = `SELECT rc.*, tm.name as assigned_member_name FROM refinement_candidates rc LEFT JOIN team_members tm ON rc.assigned_member_id = tm.id WHERE rc.target_id = ?`;
    const params = [Number(req.params.id)];
    if (category) { query += ' AND rc.category = ?'; params.push(category); }
    if (cStatus) { query += ' AND rc.status = ?'; params.push(cStatus); }
    if (priority) { query += ' AND rc.priority = ?'; params.push(priority); }
    query += ` ORDER BY CASE rc.priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 END, rc.created_at DESC`;
    const candidates = db.prepare(query).all(...params);
    res.json(candidates);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PUT /api/refinement/candidates/:id
app.put('/api/refinement/candidates/:id', (req, res) => {
  try {
    const id = Number(req.params.id);
    const existing = db.prepare('SELECT * FROM refinement_candidates WHERE id = ?').get(id);
    if (!existing) return res.status(404).json({ error: 'Candidate not found' });
    const { status, assigned_member_id, priority } = req.body;
    const now = localNow();
    const newStatus = status || existing.status;
    const completedAt = newStatus === 'completed' ? now : existing.completed_at;
    db.prepare('UPDATE refinement_candidates SET status = ?, assigned_member_id = ?, priority = ?, completed_at = ?, updated_at = ? WHERE id = ?')
      .run(newStatus, assigned_member_id !== undefined ? assigned_member_id : existing.assigned_member_id, priority || existing.priority, completedAt, now, id);
    const updated = db.prepare('SELECT rc.*, tm.name as assigned_member_name FROM refinement_candidates rc LEFT JOIN team_members tm ON rc.assigned_member_id = tm.id WHERE rc.id = ?').get(id);
    broadcast('refinement.candidate_updated', { id, target_id: existing.target_id });
    res.json(updated);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/refinement/candidates/:id/refine
app.post('/api/refinement/candidates/:id/refine', (req, res) => {
  try {
    const id = Number(req.params.id);
    const candidate = db.prepare('SELECT rc.*, rt.target_path FROM refinement_candidates rc JOIN refinement_targets rt ON rc.target_id = rt.id WHERE rc.id = ?').get(id);
    if (!candidate) return res.status(404).json({ error: 'Candidate not found' });

    const now = localNow();
    let memberId = candidate.assigned_member_id;

    if (!memberId) {
      const assignment = db.prepare(`SELECT tm.id FROM refinement_team_assignments rta JOIN team_members tm ON rta.member_id = tm.id WHERE rta.target_id = ? AND rta.enabled = 1 AND tm.status = 'active' ORDER BY RANDOM() LIMIT 1`).get(candidate.target_id);
      if (!assignment) return res.status(400).json({ error: 'No enabled team members for this target' });
      memberId = assignment.id;
    }

    const programResult = db.prepare(`INSERT INTO research_programs (title, goal, target_file, metric_name, metric_command, experiment_timeout_seconds, working_directory, max_experiments, status, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`)
      .run(candidate.title, candidate.description, candidate.file_path, candidate.metric_name || 'quality', candidate.metric_command || null, 300, candidate.target_path || path.join(__dirname, '..'), 3, 'running', now);
    const programId = Number(programResult.lastInsertRowid);

    db.prepare('UPDATE refinement_candidates SET status = ?, assigned_member_id = ?, program_id = ?, updated_at = ? WHERE id = ?')
      .run('in_progress', memberId, programId, now, id);

    const taskResult = db.prepare(`INSERT INTO tasks (title, description, status, priority, assigned_to, source_file, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)`)
      .run(`Refine: ${candidate.title}`, candidate.description, 'in_progress', candidate.priority === 'critical' ? 'urgent' : candidate.priority, memberId, 'refinement', now, now);
    const taskId = Number(taskResult.lastInsertRowid);

    spawnMemberTerminal(taskId, memberId).catch(err => {
      console.error(`[Refinement] Spawn failed: ${err.message}`);
    });

    broadcast('refinement.started', { target_id: candidate.target_id, candidate_id: id, task_id: taskId });
    res.json({ success: true, task_id: taskId, program_id: programId });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// DELETE /api/refinement/candidates/:id
app.delete('/api/refinement/candidates/:id', (req, res) => {
  try {
    db.prepare('DELETE FROM refinement_candidates WHERE id = ?').run(Number(req.params.id));
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/refinement/targets/:id/team
app.get('/api/refinement/targets/:id/team', (req, res) => {
  try {
    const targetId = Number(req.params.id);
    const members = db.prepare(`
      SELECT tm.id, tm.name, tm.role, tm.tier,
        COALESCE(rta.enabled, 0) as enabled,
        (SELECT COUNT(*) FROM refinement_candidates rc WHERE rc.assigned_member_id = tm.id AND rc.target_id = ? AND rc.status = 'completed') as completed_count,
        (SELECT COUNT(*) FROM refinement_candidates rc WHERE rc.assigned_member_id = tm.id AND rc.target_id = ? AND rc.status = 'in_progress') as active_count
      FROM team_members tm
      LEFT JOIN refinement_team_assignments rta ON rta.member_id = tm.id AND rta.target_id = ?
      WHERE tm.status = 'active' AND tm.tier = 'specialist'
      ORDER BY tm.tier, tm.name
    `).all(targetId, targetId, targetId);
    res.json(members);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/refinement/targets/:id/team
app.post('/api/refinement/targets/:id/team', (req, res) => {
  try {
    const targetId = Number(req.params.id);
    const { member_ids } = req.body;
    if (!Array.isArray(member_ids)) return res.status(400).json({ error: 'member_ids array required' });
    const now = localNow();
    const stmt = db.prepare('INSERT OR IGNORE INTO refinement_team_assignments (target_id, member_id, enabled, created_at) VALUES (?, ?, 1, ?)');
    for (const mid of member_ids) {
      stmt.run(targetId, mid, now);
    }
    res.json({ success: true, assigned: member_ids.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PUT /api/refinement/targets/:id/team/:memberId
app.put('/api/refinement/targets/:id/team/:memberId', (req, res) => {
  try {
    const targetId = Number(req.params.id);
    const memberId = Number(req.params.memberId);
    const { enabled } = req.body;
    const now = localNow();
    const existing = db.prepare('SELECT * FROM refinement_team_assignments WHERE target_id = ? AND member_id = ?').get(targetId, memberId);
    if (existing) {
      db.prepare('UPDATE refinement_team_assignments SET enabled = ? WHERE target_id = ? AND member_id = ?').run(enabled ? 1 : 0, targetId, memberId);
    } else {
      db.prepare('INSERT INTO refinement_team_assignments (target_id, member_id, enabled, created_at) VALUES (?,?,?,?)').run(targetId, memberId, enabled ? 1 : 0, now);
    }
    res.json({ success: true, enabled: !!enabled });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/refinement/auto-detect
app.get('/api/refinement/auto-detect', (req, res) => {
  try {
    const suggestions = [];
    const existingTargets = db.prepare('SELECT target_type, target_path, repo_url, project_id FROM refinement_targets').all();
    const existingSet = new Set(existingTargets.map(t => `${t.target_type}:${t.target_path || t.repo_url || t.project_id}`));

    // Active projects
    const projects = db.prepare("SELECT id, name FROM projects WHERE status = 'active'").all();
    for (const p of projects) {
      if (!existingSet.has(`project:${p.id}`)) {
        suggestions.push({ name: p.name, target_type: 'project', project_id: p.id, source: 'project' });
      }
    }

    // The Team app itself
    const appPath = path.join(__dirname, '..');
    if (!existingSet.has(`website:${appPath}`)) {
      suggestions.push({ name: 'The Team Dashboard', target_type: 'website', target_path: appPath, source: 'self' });
    }

    // Linked repos
    const repos = db.prepare('SELECT * FROM linked_repos').all();
    for (const r of repos) {
      if (!existingSet.has(`repository:${r.url}`)) {
        suggestions.push({ name: r.name, target_type: 'repository', repo_url: r.url, source: 'linked_repo' });
      }
    }

    // Linked paths (folders only)
    const paths = db.prepare("SELECT * FROM linked_paths WHERE type = 'folder'").all();
    for (const lp of paths) {
      if (!existingSet.has(`folder:${lp.path}`)) {
        suggestions.push({ name: lp.name, target_type: 'folder', target_path: lp.path, source: 'linked_path' });
      }
    }

    res.json(suggestions);
  } catch (err) { res.status(500).json({ error: err.message }); }
});


};
