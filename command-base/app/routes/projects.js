'use strict';
module.exports = function(app, db, helpers) {
  const { broadcast, localNow, createNotification, authRateLimiter, apiRateLimiter, spawnMemberTerminal } = helpers;
  const stmt = helpers.stmt || ((sql) => db.prepare(sql));

app.get('/api/projects', (req, res) => {
  try {
    const companyFilter = req.query.company_id;
    let sql = `
      SELECT p.*,
        (SELECT COUNT(*) FROM project_tasks pt WHERE pt.project_id = p.id) as task_count,
        (SELECT tm.name FROM project_executives pe JOIN team_members tm ON pe.member_id = tm.id WHERE pe.project_id = p.id) as exec_name,
        c.name as company_name, c.color as company_color
      FROM projects p
      LEFT JOIN companies c ON p.company_id = c.id
    `;
    const params = [];
    if (companyFilter) {
      sql += ' WHERE p.company_id = ?';
      params.push(companyFilter);
    }
    sql += ' ORDER BY p.updated_at DESC';
    const rows = params.length ? stmt(sql).all(...params) : stmt(sql).all();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/projects/:id', (req, res) => {
  try {
    const project = stmt(`SELECT * FROM projects WHERE id = ?`).get(req.params.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const tasks = stmt(`
      SELECT t.id, t.title, t.status, t.priority, t.created_at, t.completed_at,
             t.started_at_actual, t.completed_at_actual, t.estimated_hours, t.actual_hours,
             t.blocked_by_task_id, t.progress,
             tm.name as assignee_name
      FROM project_tasks pt
      JOIN tasks t ON pt.task_id = t.id
      LEFT JOIN team_members tm ON t.assigned_to = tm.id
      WHERE pt.project_id = ?
      ORDER BY t.created_at DESC
    `).all(req.params.id);

    // Get task IDs for activity lookup
    const taskIds = tasks.map(t => t.id);
    let activity = [];
    if (taskIds.length > 0) {
      const placeholders = taskIds.map(() => '?').join(',');
      activity = db.prepare(`
        SELECT a.*, t.title as task_title
        FROM activity_log a
        LEFT JOIN tasks t ON a.task_id = t.id
        WHERE a.task_id IN (${placeholders})
        ORDER BY a.created_at DESC
        LIMIT 20
      `).all(...taskIds);
    }

    // Project team (affinity)
    const team = stmt(`
      SELECT pa.*, tm.name, tm.role, tm.tier
      FROM project_affinity pa
      JOIN team_members tm ON pa.member_id = tm.id
      WHERE pa.project_id = ? AND pa.status = 'active'
      ORDER BY pa.tasks_completed DESC, pa.hours_worked DESC
    `).all(req.params.id);

    // Project improvements summary
    const improvements = stmt(`
      SELECT pi.*, tm.name as assignee_name
      FROM project_improvements pi
      LEFT JOIN team_members tm ON pi.assigned_member_id = tm.id
      WHERE pi.project_id = ?
      ORDER BY CASE pi.status WHEN 'in_progress' THEN 0 WHEN 'queued' THEN 1 WHEN 'proposed' THEN 2 WHEN 'completed' THEN 4 ELSE 5 END, pi.updated_at DESC
      LIMIT 20
    `).all(req.params.id);

    // Project repos
    const repos = stmt(`SELECT * FROM project_repos WHERE project_id = ?`).all(req.params.id);

    // Autonomous status
    const autoSetting = stmt(`SELECT value FROM system_settings WHERE key = ?`).get(`project_autonomous_${req.params.id}`);
    const autonomous = autoSetting && autoSetting.value === '1';

    // Project executive
    const executive = stmt(`
      SELECT pe.*, tm.name as exec_name, tm.role as exec_role, tm.profile_path as exec_profile
      FROM project_executives pe
      JOIN team_members tm ON pe.member_id = tm.id
      WHERE pe.project_id = ?
    `).get(req.params.id) || null;

    res.json({ ...project, tasks, activity, team, improvements, repos, autonomous, executive });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/projects', (req, res) => {
  try {
    const { name, summary, status, exochain_governed, company_id } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Name is required' });
    }
    const projectStatus = ['active', 'completed', 'archived'].includes(status) ? status : 'active';
    const governed = exochain_governed ? 1 : 0;
    const now = localNow();
    const result = stmt(`
      INSERT INTO projects (name, summary, status, exochain_governed, company_id, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(name.trim(), (summary || '').trim() || null, projectStatus, governed, company_id || null, now, now);

    const projectId = Number(result.lastInsertRowid);

    // If governed, create the genesis receipt with ExoChain-quality metadata
    if (governed) {
      createReceipt(db, 'project_created', 'project', projectId, 'Max',
        `Project "${name.trim()}" created with ExoChain governance — full pipeline enabled (invariant validation, review panel, governance receipts, provenance tracking)`,
        {
          name: name.trim(), governed: true,
          governance_features: ['invariant_validation', 'review_panel', 'governance_receipts', 'provenance_tracking', 'three_branch_governance', 'chain_integrity'],
          exochain_version: '2.1', hash_algorithm: 'sha256'
        },
        projectId,
        { branch: 'legislative', metadata: { project_type: 'governed', created_by: 'Max' } }
      );
    }

    // Auto-spawn a Project Executive for this project
    let executive = null;
    try {
      executive = spawnProjectExecutive(projectId);
    } catch (execErr) {
      console.error(`[ProjectExec] Failed to spawn executive for project #${projectId}: ${execErr.message}`);
    }

    // Auto-create a private GitHub repo for this project
    try {
      createProjectRepo(projectId);
    } catch (repoErr) {
      console.warn(`[ProjectRepo] Failed to auto-create repo for project #${projectId}: ${repoErr.message}`);
    }

    res.json({ id: projectId, exochain_governed: governed, executive, message: 'Project created' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/projects/:id', (req, res) => {
  try {
    const existing = stmt(`SELECT * FROM projects WHERE id = ?`).get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Project not found' });

    const name = req.body.name !== undefined ? req.body.name.trim() : existing.name;
    const summary = req.body.summary !== undefined ? req.body.summary : existing.summary;
    const status = req.body.status !== undefined && ['active', 'completed', 'archived'].includes(req.body.status)
      ? req.body.status : existing.status;
    const governed = req.body.exochain_governed !== undefined ? (req.body.exochain_governed ? 1 : 0) : existing.exochain_governed;
    const company_id = req.body.company_id !== undefined ? (req.body.company_id || null) : existing.company_id;
    const now = localNow();

    stmt(`
      UPDATE projects SET name = ?, summary = ?, status = ?, exochain_governed = ?, company_id = ?, updated_at = ?
      WHERE id = ?
    `).run(name, summary, status, governed, company_id, now, req.params.id);

    // If governance was just enabled (was off, now on), create a governance receipt
    if (governed === 1 && existing.exochain_governed !== 1) {
      try {
        createReceipt(db, 'governance_enabled', 'project', parseInt(req.params.id), 'Max',
          `ExoChain governance enabled for project "${name}" — full pipeline now active`,
          { project_id: parseInt(req.params.id), name, previously_governed: false },
          parseInt(req.params.id),
          { branch: 'legislative', metadata: { action: 'governance_enabled' } }
        );
      } catch (_) {}
    }

    // If governance was just disabled, log it
    if (governed === 0 && existing.exochain_governed === 1) {
      try {
        db.prepare(`INSERT INTO activity_log (actor, action, notes, created_at) VALUES ('System', 'governance_disabled', ?, ?)`)
          .run(`ExoChain governance disabled for project #${req.params.id} "${name}"`, now);
      } catch (_) {}
    }

    res.json({ message: 'Project updated', exochain_governed: governed });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/projects/:id', (req, res) => {
  try {
    // CASCADE: clean up all related records (transactional)
    const result = db.transaction(() => {
      stmt(`DELETE FROM project_tasks WHERE project_id = ?`).run(req.params.id);
      stmt(`DELETE FROM project_goals WHERE project_id = ?`).run(req.params.id);
      stmt(`UPDATE visions SET project_id = NULL WHERE project_id = ?`).run(req.params.id);
      stmt(`DELETE FROM governance_receipts WHERE entity_type = 'project' AND entity_id = ?`).run(req.params.id);
      stmt(`DELETE FROM project_affinity WHERE project_id = ?`).run(req.params.id);
      stmt(`DELETE FROM project_improvements WHERE project_id = ?`).run(req.params.id);
      stmt(`DELETE FROM project_repos WHERE project_id = ?`).run(req.params.id);
      // Retire the project executive
      const execToRetire = stmt('SELECT member_id FROM project_executives WHERE project_id = ?').get(req.params.id);
      if (execToRetire) {
        stmt(`UPDATE team_members SET status = 'retired' WHERE id = ?`).run(execToRetire.member_id);
      }
      stmt(`DELETE FROM project_executives WHERE project_id = ?`).run(req.params.id);
      return stmt(`DELETE FROM projects WHERE id = ?`).run(req.params.id);
    })();
    if (result.changes === 0) return res.status(404).json({ error: 'Project not found' });
    res.json({ message: 'Project deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/projects/:id/tasks', (req, res) => {
  try {
    const { task_id } = req.body;
    if (!task_id) return res.status(400).json({ error: 'task_id is required' });

    const project = stmt(`SELECT id FROM projects WHERE id = ?`).get(req.params.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const task = stmt(`SELECT id FROM tasks WHERE id = ?`).get(task_id);
    if (!task) return res.status(404).json({ error: 'Task not found' });

    const now = localNow();
    const result = stmt(`
      INSERT OR IGNORE INTO project_tasks (project_id, task_id, created_at)
      VALUES (?, ?, ?)
    `).run(req.params.id, task_id, now);

    // Update project updated_at
    stmt(`UPDATE projects SET updated_at = ? WHERE id = ?`).run(now, req.params.id);

    res.json({ id: Number(result.lastInsertRowid), message: 'Task linked' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/projects/:id/tasks/:taskId', (req, res) => {
  try {
    const result = stmt(`
      DELETE FROM project_tasks WHERE project_id = ? AND task_id = ?
    `).run(req.params.id, req.params.taskId);
    if (result.changes === 0) return res.status(404).json({ error: 'Link not found' });

    const now = localNow();
    stmt(`UPDATE projects SET updated_at = ? WHERE id = ?`).run(now, req.params.id);

    res.json({ message: 'Task unlinked' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get unlinked tasks for a project (for the link dropdown)
app.get('/api/projects/:id/unlinked-tasks', (req, res) => {
  try {
    const rows = stmt(`
      SELECT t.id, t.title, t.status, t.priority, tm.name as assignee_name
      FROM tasks t
      LEFT JOIN team_members tm ON t.assigned_to = tm.id
      WHERE t.id NOT IN (
        SELECT task_id FROM project_tasks WHERE project_id = ?
      )
      ORDER BY t.created_at DESC
    `).all(req.params.id);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/projects/:id/team — members with affinity for this project
app.get('/api/projects/:id/team', (req, res) => {
  try {
    const rows = stmt(`
      SELECT pa.*, tm.name, tm.role, tm.tier, tm.status as member_status
      FROM project_affinity pa
      JOIN team_members tm ON pa.member_id = tm.id
      WHERE pa.project_id = ? AND pa.status = 'active'
      ORDER BY pa.tasks_completed DESC, pa.hours_worked DESC
    `).all(req.params.id);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/projects/:id/team — assign a member to a project
app.post('/api/projects/:id/team', (req, res) => {
  try {
    const { member_id, role_in_project } = req.body;
    if (!member_id) return res.status(400).json({ error: 'member_id is required' });
    const project = db.prepare('SELECT id FROM projects WHERE id = ?').get(req.params.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });
    const member = db.prepare('SELECT id, name FROM team_members WHERE id = ?').get(member_id);
    if (!member) return res.status(404).json({ error: 'Member not found' });
    const now = localNow();
    const result = db.prepare(`INSERT OR IGNORE INTO project_affinity (project_id, member_id, role_in_project, assigned_at) VALUES (?,?,?,?)`)
      .run(req.params.id, member_id, role_in_project || 'contributor', now);
    if (result.changes === 0) {
      // Already exists, update role if provided
      if (role_in_project) {
        db.prepare(`UPDATE project_affinity SET role_in_project = ? WHERE project_id = ? AND member_id = ?`).run(role_in_project, req.params.id, member_id);
      }
    }
    db.prepare(`INSERT INTO activity_log (actor, action, notes, created_at) VALUES ('Board', 'project_team_assign', ?, ?)`)
      .run(`Assigned ${member.name} to project #${req.params.id}`, now);
    res.json({ message: 'Member assigned to project', member_name: member.name });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// DELETE /api/projects/:id/team/:memberId — remove affinity
app.delete('/api/projects/:id/team/:memberId', (req, res) => {
  try {
    const result = db.prepare(`DELETE FROM project_affinity WHERE project_id = ? AND member_id = ?`).run(req.params.id, req.params.memberId);
    if (result.changes === 0) return res.status(404).json({ error: 'Affinity not found' });
    res.json({ message: 'Member removed from project' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/projects/:id/improvements — improvements for a project
app.get('/api/projects/:id/improvements', (req, res) => {
  try {
    const status = req.query.status;
    let rows;
    if (status) {
      rows = db.prepare(`
        SELECT pi.*, tm.name as assignee_name
        FROM project_improvements pi
        LEFT JOIN team_members tm ON pi.assigned_member_id = tm.id
        WHERE pi.project_id = ? AND pi.status = ?
        ORDER BY pi.created_at DESC
      `).all(req.params.id, status);
    } else {
      rows = db.prepare(`
        SELECT pi.*, tm.name as assignee_name
        FROM project_improvements pi
        LEFT JOIN team_members tm ON pi.assigned_member_id = tm.id
        WHERE pi.project_id = ?
        ORDER BY CASE pi.status WHEN 'in_progress' THEN 0 WHEN 'queued' THEN 1 WHEN 'proposed' THEN 2 WHEN 'approved' THEN 3 WHEN 'completed' THEN 4 ELSE 5 END, pi.updated_at DESC
      `).all(req.params.id);
    }
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/projects/:id/improvements — create project improvement
app.post('/api/projects/:id/improvements', (req, res) => {
  try {
    const { title, description, category, impact, effort } = req.body;
    if (!title) return res.status(400).json({ error: 'Title is required' });

    const validProjImpCategories = ['performance', 'ux', 'feature', 'design', 'infrastructure', 'architecture', 'bug', 'refactor', 'accessibility'];
    const validProjImpImpacts = ['low', 'medium', 'high'];
    const validProjImpEfforts = ['small', 'medium', 'large'];
    if (category && !validProjImpCategories.includes(category)) {
      return res.status(400).json({ error: 'Invalid category. Must be one of: ' + validProjImpCategories.join(', ') });
    }
    if (impact && !validProjImpImpacts.includes(impact)) {
      return res.status(400).json({ error: 'Invalid impact. Must be one of: ' + validProjImpImpacts.join(', ') });
    }
    if (effort && !validProjImpEfforts.includes(effort)) {
      return res.status(400).json({ error: 'Invalid effort. Must be one of: ' + validProjImpEfforts.join(', ') });
    }

    const project = db.prepare('SELECT id FROM projects WHERE id = ?').get(req.params.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });
    const now = localNow();
    const result = db.prepare(`INSERT INTO project_improvements (project_id, title, description, category, impact, effort, proposed_by, status, created_at, updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?)`)
      .run(req.params.id, title, description || '', category || 'feature', impact || 'medium', effort || 'medium', 'Manual', 'proposed', now, now);
    res.json({ id: Number(result.lastInsertRowid), message: 'Improvement created' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PUT /api/project-improvements/:id — update
app.put('/api/project-improvements/:id', (req, res) => {
  try {
    const imp = db.prepare('SELECT * FROM project_improvements WHERE id = ?').get(req.params.id);
    if (!imp) return res.status(404).json({ error: 'Improvement not found' });

    const { title, description, category, impact, effort, status } = req.body;
    const validPIStatuses = ['proposed', 'approved', 'queued', 'in_progress', 'completed', 'denied'];
    const validPICategories = ['performance', 'ux', 'feature', 'design', 'infrastructure', 'architecture', 'bug', 'refactor', 'accessibility'];
    const validPIImpacts = ['low', 'medium', 'high'];
    const validPIEfforts = ['small', 'medium', 'large'];
    if (status && !validPIStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status. Must be one of: ' + validPIStatuses.join(', ') });
    }
    if (category && !validPICategories.includes(category)) {
      return res.status(400).json({ error: 'Invalid category. Must be one of: ' + validPICategories.join(', ') });
    }
    if (impact && !validPIImpacts.includes(impact)) {
      return res.status(400).json({ error: 'Invalid impact. Must be one of: ' + validPIImpacts.join(', ') });
    }
    if (effort && !validPIEfforts.includes(effort)) {
      return res.status(400).json({ error: 'Invalid effort. Must be one of: ' + validPIEfforts.join(', ') });
    }

    const now = localNow();
    db.prepare(`UPDATE project_improvements SET
      title = COALESCE(?, title), description = COALESCE(?, description),
      category = COALESCE(?, category), impact = COALESCE(?, impact),
      effort = COALESCE(?, effort), status = COALESCE(?, status),
      updated_at = ? WHERE id = ?`)
      .run(title || null, description || null, category || null, impact || null, effort || null, status || null, now, req.params.id);
    res.json({ message: 'Improvement updated' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/project-improvements/:id/execute — execute (spawn member with project affinity)
app.post('/api/project-improvements/:id/execute', (req, res) => {
  try {
    const result = executeProjectImprovement(parseInt(req.params.id));
    if (!result) return res.status(400).json({ error: 'Could not execute improvement' });
    res.json({ message: 'Improvement execution started', ...result });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/projects/:id/improvements/chamber — project chamber (proposed items)
app.get('/api/projects/:id/improvements/chamber', (req, res) => {
  try {
    // Auto-fill if needed
    try { autoFillProjectChamber(parseInt(req.params.id)); } catch (_) {}
    const rows = db.prepare(`
      SELECT * FROM project_improvements
      WHERE project_id = ? AND status = 'proposed'
      ORDER BY CASE impact WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 END, created_at ASC
      LIMIT 10
    `).all(req.params.id);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/projects/:id/improvements/autonomous/start — start autonomous pipeline
app.post('/api/projects/:id/improvements/autonomous/start', (req, res) => {
  try {
    const projectId = parseInt(req.params.id);
    const project = db.prepare('SELECT * FROM projects WHERE id = ?').get(projectId);
    if (!project) return res.status(404).json({ error: 'Project not found' });
    const now = localNow();
    db.prepare(`INSERT OR REPLACE INTO system_settings (key, value, updated_at) VALUES (?, '1', ?)`)
      .run(`project_autonomous_${projectId}`, now);
    // Auto-fill chamber on start
    try { autoFillProjectChamber(projectId); } catch (_) {}
    // Trigger first cycle immediately
    setImmediate(() => { try { projectAutonomousCycle(projectId); } catch (_) {} });
    db.prepare(`INSERT INTO activity_log (actor, action, notes, created_at) VALUES ('Max', 'project_autonomous_start', ?, ?)`)
      .run(`Started autonomous pipeline for "${project.name}"`, now);
    createNotification('system', 'Project autonomous ON', `Autonomous pipeline started for "${project.name}"`);
    res.json({ message: `Autonomous mode started for "${project.name}"` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/projects/:id/improvements/autonomous/stop — stop
app.post('/api/projects/:id/improvements/autonomous/stop', (req, res) => {
  try {
    const projectId = parseInt(req.params.id);
    const now = localNow();
    db.prepare(`INSERT OR REPLACE INTO system_settings (key, value, updated_at) VALUES (?, '0', ?)`)
      .run(`project_autonomous_${projectId}`, now);
    db.prepare(`INSERT INTO activity_log (actor, action, notes, created_at) VALUES ('Max', 'project_autonomous_stop', ?, ?)`)
      .run(`Stopped autonomous pipeline for project #${projectId}`, now);
    res.json({ message: 'Autonomous mode stopped' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/projects/:id/improvements/autonomous/status
app.get('/api/projects/:id/improvements/autonomous/status', (req, res) => {
  try {
    const projectId = parseInt(req.params.id);
    const setting = db.prepare(`SELECT value FROM system_settings WHERE key = ?`).get(`project_autonomous_${projectId}`);
    const inProgress = db.prepare(`SELECT COUNT(*) as c FROM project_improvements WHERE project_id = ? AND status = 'in_progress'`).get(projectId).c;
    const queued = db.prepare(`SELECT COUNT(*) as c FROM project_improvements WHERE project_id = ? AND status = 'queued'`).get(projectId).c;
    const proposed = db.prepare(`SELECT COUNT(*) as c FROM project_improvements WHERE project_id = ? AND status = 'proposed'`).get(projectId).c;
    const completed = db.prepare(`SELECT COUNT(*) as c FROM project_improvements WHERE project_id = ? AND status = 'completed'`).get(projectId).c;
    res.json({
      enabled: setting && setting.value === '1',
      in_progress: inProgress,
      queued,
      proposed,
      completed
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/projects/:id/repos — linked repos
app.get('/api/projects/:id/repos', (req, res) => {
  try {
    const rows = db.prepare(`SELECT * FROM project_repos WHERE project_id = ? ORDER BY created_at DESC`).all(req.params.id);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/projects/:id/repos — link a repo
app.post('/api/projects/:id/repos', (req, res) => {
  try {
    const { repo_url, local_path, default_branch } = req.body;
    if (!repo_url) return res.status(400).json({ error: 'repo_url is required' });
    const project = db.prepare('SELECT id FROM projects WHERE id = ?').get(req.params.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });
    // Parse owner/name from URL
    let owner = '', name = '';
    const match = repo_url.match(/github\.com[/:]([^/]+)\/([^/.]+)/);
    if (match) { owner = match[1]; name = match[2]; }
    const now = localNow();
    const result = db.prepare(`INSERT OR IGNORE INTO project_repos (project_id, repo_url, repo_owner, repo_name, local_path, default_branch, created_at)
      VALUES (?,?,?,?,?,?,?)`)
      .run(req.params.id, repo_url, owner, name, local_path || null, default_branch || 'main', now);
    if (result.changes === 0) return res.status(409).json({ error: 'Repo already linked' });
    db.prepare(`INSERT INTO activity_log (actor, action, notes, created_at) VALUES ('Board', 'project_repo_link', ?, ?)`)
      .run(`Linked repo ${owner}/${name} to project #${req.params.id}`, now);
    res.json({ id: Number(result.lastInsertRowid), message: 'Repo linked', owner, name });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// DELETE /api/project-repos/:id — unlink
app.delete('/api/project-repos/:id', (req, res) => {
  try {
    const result = db.prepare(`DELETE FROM project_repos WHERE id = ?`).run(req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Repo not found' });
    res.json({ message: 'Repo unlinked' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/project-repos/:id/sync — trigger sync
app.post('/api/project-repos/:id/sync', (req, res) => {
  try {
    const repo = db.prepare('SELECT * FROM project_repos WHERE id = ?').get(req.params.id);
    if (!repo) return res.status(404).json({ error: 'Repo not found' });
    const now = localNow();
    db.prepare(`UPDATE project_repos SET last_sync_at = ? WHERE id = ?`).run(now, req.params.id);
    // Actual git sync would happen here via spawn — for now, mark as synced
    db.prepare(`INSERT INTO activity_log (actor, action, notes, created_at) VALUES ('Board', 'project_repo_sync', ?, ?)`)
      .run(`Synced repo ${repo.repo_owner}/${repo.repo_name}`, now);
    res.json({ message: 'Sync triggered', last_sync_at: now });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/projects/:id/executive — get the project's executive
app.get('/api/projects/:id/executive', (req, res) => {
  try {
    const exec = db.prepare(`
      SELECT pe.*, tm.name as exec_name, tm.role as exec_role, tm.profile_path as exec_profile, tm.status as exec_status
      FROM project_executives pe
      JOIN team_members tm ON pe.member_id = tm.id
      WHERE pe.project_id = ?
    `).get(req.params.id);
    if (!exec) return res.status(404).json({ error: 'No executive assigned to this project' });
    res.json(exec);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/projects/:id/executive/regenerate — regenerate the executive if needed
app.post('/api/projects/:id/executive/regenerate', (req, res) => {
  try {
    const project = db.prepare('SELECT * FROM projects WHERE id = ?').get(req.params.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });

    // Remove old executive
    const oldExec = db.prepare('SELECT pe.*, tm.name FROM project_executives pe JOIN team_members tm ON pe.member_id = tm.id WHERE pe.project_id = ?').get(req.params.id);
    if (oldExec) {
      db.prepare(`UPDATE team_members SET status = 'retired' WHERE id = ?`).run(oldExec.member_id);
      db.prepare(`DELETE FROM project_executives WHERE project_id = ?`).run(req.params.id);
      db.prepare(`UPDATE project_affinity SET status = 'completed' WHERE project_id = ? AND member_id = ?`).run(req.params.id, oldExec.member_id);
    }

    // Spawn new
    const executive = spawnProjectExecutive(parseInt(req.params.id));
    if (!executive) return res.status(500).json({ error: 'Failed to spawn new executive' });

    res.json({ message: 'Executive regenerated', executive });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// API: Start autonomous mode with optional timer
app.post('/api/improvements/autonomous/start', (req, res) => {
  try {
    const { timer_minutes } = req.body || {};
    const now = localNow();
    db.prepare(`INSERT OR REPLACE INTO system_settings (key, value, updated_at) VALUES ('autonomous_improvements', '1', ?)`).run(now);
    db.prepare(`INSERT OR REPLACE INTO system_settings (key, value, updated_at) VALUES ('autonomous_stop_reason', 'running', ?)`).run(now);
    db.prepare(`INSERT OR REPLACE INTO system_settings (key, value, updated_at) VALUES ('autonomous_stop_reason_at', ?, ?)`).run(now, now);
    if (timer_minutes && parseInt(timer_minutes) > 0) {
      db.prepare(`INSERT OR REPLACE INTO system_settings (key, value, updated_at) VALUES ('autonomous_improvement_timer', ?, ?)`).run(String(timer_minutes), now);
      db.prepare(`INSERT OR REPLACE INTO system_settings (key, value, updated_at) VALUES ('autonomous_improvement_timer_start', ?, ?)`).run(now, now);
    } else {
      db.prepare(`INSERT OR REPLACE INTO system_settings (key, value, updated_at) VALUES ('autonomous_improvement_timer', '0', ?)`).run(now);
    }
    db.prepare(`INSERT INTO activity_log (actor, action, notes, created_at) VALUES ('Max', 'autonomous_start', ?, ?)`)
      .run(`Autonomous improvement mode started${timer_minutes ? ' with ' + timer_minutes + 'm timer' : ' (unlimited)'}`, now);
    createNotification('system', 'Autonomous mode ON', `Improvement pipeline running${timer_minutes ? ' for ' + timer_minutes + ' minutes' : ' indefinitely'}`);
    // Trigger first cycle immediately
    setImmediate(() => { try { autonomousImprovementCycle(); } catch (_) {} });
    res.json({ message: 'Autonomous mode started', timer_minutes: timer_minutes || 'unlimited' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// API: Stop autonomous mode
app.post('/api/improvements/autonomous/stop', (req, res) => {
  try {
    const now = localNow();
    db.prepare(`INSERT OR REPLACE INTO system_settings (key, value, updated_at) VALUES ('autonomous_improvements', '0', ?)`).run(now);
    db.prepare(`INSERT OR REPLACE INTO system_settings (key, value, updated_at) VALUES ('autonomous_improvement_timer', '0', ?)`).run(now);
    db.prepare(`INSERT OR REPLACE INTO system_settings (key, value, updated_at) VALUES ('autonomous_stop_reason', 'manual_stop', ?)`).run(now);
    db.prepare(`INSERT OR REPLACE INTO system_settings (key, value, updated_at) VALUES ('autonomous_stop_reason_at', ?, ?)`).run(now, now);
    db.prepare(`INSERT INTO activity_log (actor, action, notes, created_at) VALUES ('Max', 'autonomous_stop', 'Autonomous improvement mode stopped', ?)`)
      .run(now);
    res.json({ message: 'Autonomous mode stopped' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// API: Get autonomous mode status
app.get('/api/improvements/autonomous/status', (req, res) => {
  try {
    const now = localNow();
    const enabled = db.prepare(`SELECT value FROM system_settings WHERE key = 'autonomous_improvements'`).get();
    const timer = db.prepare(`SELECT value FROM system_settings WHERE key = 'autonomous_improvement_timer'`).get();
    const timerStart = db.prepare(`SELECT value FROM system_settings WHERE key = 'autonomous_improvement_timer_start'`).get();
    const lastCycle = db.prepare(`SELECT value FROM system_settings WHERE key = 'autonomous_last_cycle'`).get();
    const inProgress = db.prepare(`SELECT COUNT(*) as c FROM improvement_proposals WHERE status = 'in_progress'`).get().c;
    const queued = db.prepare(`SELECT COUNT(*) as c FROM improvement_proposals WHERE status = 'queued'`).get().c;
    const proposed = db.prepare(`SELECT COUNT(*) as c FROM improvement_proposals WHERE status = 'proposed'`).get().c;
    const completedToday = db.prepare(`SELECT COUNT(*) as c FROM improvement_proposals WHERE status = 'completed' AND date(completed_at) = date(?)`).get(now).c;
    const deniedToday = db.prepare(`SELECT COUNT(*) as c FROM improvement_proposals WHERE status = 'denied' AND date(updated_at) = date(?)`).get(now).c;

    let remainingMinutes = null;
    if (timer && parseInt(timer.value) > 0 && timerStart && timerStart.value) {
      const elapsed = (Date.now() - new Date(timerStart.value.replace(' ', 'T')).getTime()) / 60000;
      remainingMinutes = Math.max(0, parseInt(timer.value) - Math.floor(elapsed));
    }

    // Stop reason tracking
    const stopReasonRow = db.prepare(`SELECT value FROM system_settings WHERE key = 'autonomous_stop_reason'`).get();
    const stopReasonAtRow = db.prepare(`SELECT value FROM system_settings WHERE key = 'autonomous_stop_reason_at'`).get();
    const queueExhaustedAtRow = db.prepare(`SELECT value FROM system_settings WHERE key = 'autonomous_queue_exhausted_at'`).get();

    const stopReason = stopReasonRow ? stopReasonRow.value : (enabled && enabled.value === '1' ? 'running' : 'unknown');
    const stopReasonAt = stopReasonAtRow ? stopReasonAtRow.value : null;
    const queueExhaustedAt = queueExhaustedAtRow ? queueExhaustedAtRow.value : null;

    // Token usage for this session
    let tokensUsedThisSession = 0;
    let costThisSession = 0;
    if (timerStart && timerStart.value) {
      const sessionTokens = db.prepare(`SELECT COALESCE(SUM(total_tokens),0) as tokens, COALESCE(SUM(cost_cents),0) as cost FROM cost_events WHERE created_at >= ?`).get(timerStart.value);
      tokensUsedThisSession = sessionTokens.tokens;
      costThisSession = sessionTokens.cost;
    }

    res.json({
      enabled: enabled && enabled.value === '1',
      timer_minutes: timer ? parseInt(timer.value) : 0,
      remaining_minutes: remainingMinutes,
      last_cycle: lastCycle ? lastCycle.value : null,
      in_progress: inProgress,
      queued,
      proposed,
      completed_today: completedToday,
      denied_today: deniedToday,
      stop_reason: stopReason,
      stop_reason_at: stopReasonAt,
      queue_exhausted_at: queueExhaustedAt,
      tokens_used_this_session: tokensUsedThisSession,
      cost_this_session_cents: costThisSession
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/improvements', (req, res) => {
  try {
    const { status, category } = req.query;
    let sql = `SELECT * FROM improvement_proposals WHERE 1=1`;
    const params = [];
    if (status) { sql += ` AND status = ?`; params.push(status); }
    if (category) { sql += ` AND category = ?`; params.push(category); }
    sql += ` ORDER BY CASE status WHEN 'proposed' THEN 0 WHEN 'approved' THEN 1 WHEN 'in_progress' THEN 2 WHEN 'completed' THEN 3 WHEN 'deferred' THEN 4 WHEN 'denied' THEN 5 END, CASE impact WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 END, created_at DESC`;
    const rows = db.prepare(sql).all(...params);

    // Enrich in_progress items with linked task info (assigned member, current step from task)
    const enriched = rows.map(row => {
      if (row.status === 'in_progress') {
        const linkedTask = db.prepare(`
          SELECT t.id as task_id, t.progress, t.current_step as task_step, t.assigned_to,
                 tm.name as assigned_member_name, tm.role as assigned_member_role,
                 ap.status as process_status
          FROM tasks t
          LEFT JOIN team_members tm ON t.assigned_to = tm.id
          LEFT JOIN active_processes ap ON ap.task_id = t.id AND ap.status = 'running'
          WHERE t.source_file = 'improvement' AND t.title LIKE ?
          ORDER BY t.created_at DESC LIMIT 1
        `).get(`Execute: ${row.title}`);
        if (linkedTask) {
          row.assigned_member_name = linkedTask.assigned_member_name;
          row.assigned_member_role = linkedTask.assigned_member_role;
          row.linked_task_id = linkedTask.task_id;
          row.has_running_process = linkedTask.process_status === 'running';
          // Use the task's more granular progress/step if available
          if (linkedTask.progress > (row.progress_percent || 0)) {
            row.progress_percent = linkedTask.progress;
          }
          if (linkedTask.task_step && linkedTask.task_step !== 'Starting execution') {
            row.current_step = linkedTask.task_step;
          }
        }
      }
      return row;
    });

    res.json(enriched);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/improvements/stats/summary', (req, res) => {
  try {
    const total = db.prepare(`SELECT COUNT(*) as c FROM improvement_proposals`).get().c;
    const proposed = db.prepare(`SELECT COUNT(*) as c FROM improvement_proposals WHERE status = 'proposed'`).get().c;
    const approved = db.prepare(`SELECT COUNT(*) as c FROM improvement_proposals WHERE status = 'approved'`).get().c;
    const completed = db.prepare(`SELECT COUNT(*) as c FROM improvement_proposals WHERE status = 'completed'`).get().c;
    const inProgress = db.prepare(`SELECT COUNT(*) as c FROM improvement_proposals WHERE status = 'in_progress'`).get().c;
    const denied = db.prepare(`SELECT COUNT(*) as c FROM improvement_proposals WHERE status = 'denied'`).get().c;
    res.json({ total, proposed, approved, completed, in_progress: inProgress, denied });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/improvements/chamber', (req, res) => {
  try {
    const config = getChamberConfig();
    const rows = db.prepare(`
      SELECT * FROM improvement_proposals
      WHERE status = 'proposed'
      ORDER BY
        CASE impact WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 END,
        CASE effort WHEN 'small' THEN 0 WHEN 'medium' THEN 1 WHEN 'large' THEN 2 END,
        created_at ASC
      LIMIT ?
    `).all(config.displayCount);
    const poolTotal = db.prepare(`SELECT COUNT(*) as c FROM improvement_proposals WHERE status = 'proposed'`).get().c;
    res.json({ items: rows, pool_total: poolTotal, pool_size: config.poolSize, display_count: config.displayCount, refill_threshold: config.refillThreshold });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/improvements/auto-queue/next', (req, res) => {
  try {
    const started = autoStartNextQueued();
    if (!started) return res.json({ message: 'No queued items', next_item: null });
    res.json({ message: 'Started next queued item', next_item: started });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/improvements/auto-queue/halt', (req, res) => {
  try {
    const now = localNow();
    const existing = db.prepare(`SELECT value FROM system_settings WHERE key = 'auto_execute_improvements'`).get();
    if (existing) {
      db.prepare(`UPDATE system_settings SET value = '0', updated_at = ? WHERE key = 'auto_execute_improvements'`).run(now);
    } else {
      db.prepare(`INSERT INTO system_settings (key, value, updated_at) VALUES ('auto_execute_improvements', '0', ?)`).run(now);
    }
    res.json({ halted: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/improvements/auto-queue/resume', (req, res) => {
  try {
    const now = localNow();
    const existing = db.prepare(`SELECT value FROM system_settings WHERE key = 'auto_execute_improvements'`).get();
    if (existing) {
      db.prepare(`UPDATE system_settings SET value = '1', updated_at = ? WHERE key = 'auto_execute_improvements'`).run(now);
    } else {
      db.prepare(`INSERT INTO system_settings (key, value, updated_at) VALUES ('auto_execute_improvements', '1', ?)`).run(now);
    }
    const nextItem = autoStartNextQueued();
    res.json({ resumed: true, next_item: nextItem || null });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/improvements/tests/all', (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT t.*, ip.title as improvement_title, ip.status as improvement_status
      FROM improvement_tests t
      JOIN improvement_proposals ip ON ip.id = t.proposal_id
      ORDER BY t.created_at DESC
    `).all();
    // Parse failed_checks JSON
    const parsed = rows.map(r => {
      let failed = [];
      try { failed = JSON.parse(r.failed_checks || '[]'); } catch {}
      return { ...r, failed_checks: failed };
    });
    res.json(parsed);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/improvements/:id', (req, res) => {
  try {
    const row = db.prepare(`SELECT * FROM improvement_proposals WHERE id = ?`).get(req.params.id);
    if (!row) return res.status(404).json({ error: 'Not found' });
    const log = db.prepare(`SELECT * FROM improvement_log WHERE proposal_id = ? ORDER BY created_at DESC`).all(req.params.id);
    res.json({ ...row, log });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/improvements', (req, res) => {
  try {
    const { title, description, category, impact, effort, proposed_by } = req.body;
    if (!title || !description) return res.status(400).json({ error: 'Title and description required' });

    const validCategories = ['performance', 'ux', 'feature', 'design', 'infrastructure', 'architecture', 'bug', 'refactor', 'accessibility'];
    const validImpacts = ['low', 'medium', 'high'];
    const validEfforts = ['small', 'medium', 'large'];
    if (category && !validCategories.includes(category)) {
      return res.status(400).json({ error: 'Invalid category. Must be one of: ' + validCategories.join(', ') });
    }
    if (impact && !validImpacts.includes(impact)) {
      return res.status(400).json({ error: 'Invalid impact. Must be one of: ' + validImpacts.join(', ') });
    }
    if (effort && !validEfforts.includes(effort)) {
      return res.status(400).json({ error: 'Invalid effort. Must be one of: ' + validEfforts.join(', ') });
    }

    const now = localNow();
    const r = db.prepare(`INSERT INTO improvement_proposals (title, description, category, impact, effort, proposed_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)`)
      .run(title, description, category || 'ux', impact || 'low', effort || 'small', proposed_by || 'Hone', now, now);
    const id = Number(r.lastInsertRowid);
    db.prepare(`INSERT INTO improvement_log (proposal_id, action, notes, created_at) VALUES (?, 'proposed', ?, ?)`).run(id, `Proposed by ${proposed_by || 'Hone'}: ${title}`, now);
    res.json({ id, message: 'Improvement proposed' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/improvements/:id', (req, res) => {
  try {
    const existing = db.prepare(`SELECT * FROM improvement_proposals WHERE id = ?`).get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Not found' });
    const { status, title, description, category, impact, effort, before_state, after_state, files_changed, approved_by } = req.body;

    const validImpStatuses = ['proposed', 'approved', 'queued', 'in_progress', 'completed', 'denied'];
    const validImpCategories = ['performance', 'ux', 'feature', 'design', 'infrastructure', 'architecture', 'bug', 'refactor', 'accessibility'];
    const validImpImpacts = ['low', 'medium', 'high'];
    const validImpEfforts = ['small', 'medium', 'large'];
    if (status && !validImpStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status. Must be one of: ' + validImpStatuses.join(', ') });
    }
    if (category && !validImpCategories.includes(category)) {
      return res.status(400).json({ error: 'Invalid category. Must be one of: ' + validImpCategories.join(', ') });
    }
    if (impact && !validImpImpacts.includes(impact)) {
      return res.status(400).json({ error: 'Invalid impact. Must be one of: ' + validImpImpacts.join(', ') });
    }
    if (effort && !validImpEfforts.includes(effort)) {
      return res.status(400).json({ error: 'Invalid effort. Must be one of: ' + validImpEfforts.join(', ') });
    }

    const now = localNow();
    const fields = [];
    const vals = [];

    if (status) { fields.push('status = ?'); vals.push(status); }
    if (title) { fields.push('title = ?'); vals.push(title); }
    if (description) { fields.push('description = ?'); vals.push(description); }
    if (category) { fields.push('category = ?'); vals.push(category); }
    if (impact) { fields.push('impact = ?'); vals.push(impact); }
    if (effort) { fields.push('effort = ?'); vals.push(effort); }
    if (before_state !== undefined) { fields.push('before_state = ?'); vals.push(before_state); }
    if (after_state !== undefined) { fields.push('after_state = ?'); vals.push(after_state); }
    if (files_changed !== undefined) { fields.push('files_changed = ?'); vals.push(files_changed); }
    if (approved_by) { fields.push('approved_by = ?'); vals.push(approved_by); }

    if (status === 'approved') { fields.push('approved_at = ?'); vals.push(now); fields.push('work_started_at = ?'); vals.push(null); }
    if (status === 'queued') { fields.push('queued_at = ?'); vals.push(now); fields.push('progress_percent = ?'); vals.push(0); }
    if (status === 'in_progress' && !existing.work_started_at) { fields.push('work_started_at = ?'); vals.push(now); }
    if (status === 'completed') { fields.push('completed_at = ?'); vals.push(now); fields.push('work_completed_at = ?'); vals.push(now); fields.push('progress_percent = ?'); vals.push(100); }
    if (req.body.current_step !== undefined) { fields.push('current_step = ?'); vals.push(req.body.current_step); }
    if (req.body.progress_percent !== undefined) { fields.push('progress_percent = ?'); vals.push(req.body.progress_percent); }

    fields.push('updated_at = ?'); vals.push(now);
    vals.push(req.params.id);

    db.prepare(`UPDATE improvement_proposals SET ${fields.join(', ')} WHERE id = ?`).run(...vals);

    // Log the status change
    if (status) {
      db.prepare(`INSERT INTO improvement_log (proposal_id, action, notes, created_at) VALUES (?, ?, ?, ?)`)
        .run(req.params.id, status, `Status changed to ${status}${approved_by ? ' by ' + approved_by : ''}`, now);
    }

    // Auto-start next queued item when this one completes
    let autoStarted = null;
    if (status === 'completed') {
      const autoSetting = db.prepare(`SELECT value FROM system_settings WHERE key = 'auto_execute_improvements'`).get();
      if (autoSetting && autoSetting.value === '1') {
        autoStarted = autoStartNextQueued();
      }
    }

    // Auto-fill chamber when an item leaves 'proposed' status
    if (status && status !== 'proposed' && existing.status === 'proposed') {
      try { autoFillChamber(); } catch (e) { console.warn('Chamber auto-fill failed:', e.message); }
    }

    res.json({ message: 'Updated', auto_started: autoStarted });
    broadcast('improvement.updated', { id: Number(req.params.id) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/improvements/:id', (req, res) => {
  try {
    db.prepare(`DELETE FROM improvement_log WHERE proposal_id = ?`).run(req.params.id);
    db.prepare(`DELETE FROM improvement_proposals WHERE id = ?`).run(req.params.id);
    res.json({ message: 'Deleted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/improvements/:id/recycle', (req, res) => {
  try {
    const existing = db.prepare(`SELECT * FROM improvement_proposals WHERE id = ?`).get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Not found' });

    const now = localNow();
    const { reason } = req.body;

    // Mark as recycled (denied with reason)
    db.prepare(`UPDATE improvement_proposals SET status = 'denied', approved_by = 'Max', updated_at = ? WHERE id = ?`).run(now, req.params.id);
    db.prepare(`INSERT INTO improvement_log (proposal_id, action, notes, created_at) VALUES (?, 'recycled', ?, ?)`)
      .run(req.params.id, reason ? `Recycled by Max: ${reason}` : 'Recycled by Max — wants a different idea', now);

    // Auto-fill chamber immediately with a new proposed improvement
    try { autoFillChamber(); } catch (e) { console.warn('Chamber auto-fill after recycle failed:', e.message); }

    broadcast('improvement.updated', { id: Number(req.params.id), recycled: true });
    res.json({ message: 'Recycled — replacement generated', recycled_id: existing.id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/improvements/:id/refine', (req, res) => {
  try {
    const existing = db.prepare(`SELECT * FROM improvement_proposals WHERE id = ?`).get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Not found' });

    const now = localNow();
    const { feedback } = req.body;

    db.prepare(`INSERT INTO improvement_log (proposal_id, action, notes, created_at) VALUES (?, 'refinement_requested', ?, ?)`)
      .run(req.params.id, `Max requested refinement: ${feedback || 'Make it better'}`, now);

    // Create a task for the appropriate active member to refine
    const assignee = findImprovementAssignee(existing.category);
    const assignedTo = assignee ? assignee.id : null;
    const assigneeName = assignee ? assignee.name : 'System';

    const result = db.prepare(`
      INSERT INTO tasks (title, description, status, priority, source_file, assigned_to, created_at, updated_at)
      VALUES (?, ?, 'new', 'normal', 'system', ?, ?, ?)
    `).run(
      `Refine improvement: ${existing.title}`,
      `Max wants proposal #${req.params.id} ("${existing.title}") refined. Feedback: "${feedback || 'Make it better'}". Update the proposal description and resubmit.`,
      assignedTo, now, now
    );

    res.json({ message: `Sent back to ${assigneeName} for refinement`, task_id: Number(result.lastInsertRowid) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/improvements/:id/test', (req, res) => {
  try {
    const imp = db.prepare(`SELECT * FROM improvement_proposals WHERE id = ?`).get(req.params.id);
    if (!imp) return res.status(404).json({ error: 'Improvement not found' });

    const now = localNow();
    const checks = [];
    const failedChecks = [];

    // Check 1: Has before_state?
    const hasBefore = !!(imp.before_state && imp.before_state.trim());
    checks.push({ name: 'has_before_state', passed: hasBefore, detail: 'Improvement documented what changed (before_state)' });
    if (!hasBefore) failedChecks.push('has_before_state');

    // Check 2: Has after_state?
    const hasAfter = !!(imp.after_state && imp.after_state.trim());
    checks.push({ name: 'has_after_state', passed: hasAfter, detail: 'Improvement documented the result (after_state)' });
    if (!hasAfter) failedChecks.push('has_after_state');

    // Check 3: Has files_changed?
    const hasFiles = !!(imp.files_changed && imp.files_changed.trim());
    checks.push({ name: 'has_files_changed', passed: hasFiles, detail: 'We know what files were modified' });
    if (!hasFiles) failedChecks.push('has_files_changed');

    // Check 4: Was it completed (not still in draft)?
    const isCompleted = imp.status === 'completed';
    checks.push({ name: 'is_completed', passed: isCompleted, detail: 'Improvement was completed (not still in draft)' });
    if (!isCompleted) failedChecks.push('is_completed');

    // Check 5: Completion time exists?
    const hasCompletionTime = !!(imp.completed_at || imp.work_completed_at);
    checks.push({ name: 'has_completion_time', passed: hasCompletionTime, detail: 'Completion timestamp exists' });
    if (!hasCompletionTime) failedChecks.push('has_completion_time');

    const totalChecks = checks.length;
    const passed = failedChecks.length === 0;

    const result = db.prepare(`
      INSERT INTO improvement_tests (proposal_id, test_type, passed, total_checks, failed_checks, coverage_notes, tested_by, created_at)
      VALUES (?, 'validation', ?, ?, ?, ?, 'System', ?)
    `).run(
      imp.id,
      passed ? 1 : 0,
      totalChecks,
      JSON.stringify(failedChecks),
      JSON.stringify(checks),
      now
    );

    const testId = Number(result.lastInsertRowid);

    res.json({ test_id: testId, passed, total_checks: totalChecks, failed_checks: failedChecks, checks });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/improvements/:id/tests', (req, res) => {
  try {
    const imp = db.prepare(`SELECT id FROM improvement_proposals WHERE id = ?`).get(req.params.id);
    if (!imp) return res.status(404).json({ error: 'Improvement not found' });

    const rows = db.prepare(`SELECT * FROM improvement_tests WHERE proposal_id = ? ORDER BY created_at DESC`).all(req.params.id);
    const parsed = rows.map(r => {
      let failed = [];
      let notes = null;
      try { failed = JSON.parse(r.failed_checks || '[]'); } catch {}
      try { notes = JSON.parse(r.coverage_notes || 'null'); } catch { notes = r.coverage_notes; }
      return { ...r, failed_checks: failed, coverage_notes: notes };
    });
    res.json(parsed);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/improvements/:id/execute', (req, res) => {
  try {
    const imp = db.prepare(`SELECT * FROM improvement_proposals WHERE id = ?`).get(req.params.id);
    if (!imp) return res.status(404).json({ error: 'Improvement not found' });

    const isRetry = imp.status === 'in_progress';
    if (!['queued', 'approved', 'proposed'].includes(imp.status) && !isRetry) {
      return res.status(400).json({ error: `Cannot execute improvement in status "${imp.status}". Must be queued, approved, proposed, or in_progress (retry).` });
    }

    const now = localNow();

    // If retrying, clean up the old failed task first
    if (isRetry) {
      const oldTasks = db.prepare(`SELECT id FROM tasks WHERE source_file = 'improvement' AND title LIKE ? AND status IN ('in_progress', 'completed', 'delivered')`)
        .all(`Execute: ${imp.title}`);
      for (const ot of oldTasks) {
        db.prepare(`UPDATE tasks SET status = 'completed', current_step = 'Superseded by retry', completed_at = ? WHERE id = ?`).run(now, ot.id);
        db.prepare(`UPDATE active_processes SET status = 'killed', completed_at = ? WHERE task_id = ? AND status = 'running'`).run(now, ot.id);
      }
    }

    // Set improvement to in_progress with progress tracking (reset for retry)
    db.prepare(`UPDATE improvement_proposals SET status = 'in_progress', work_started_at = ?, progress_percent = 10, current_step = 'Creating execution task', updated_at = ? WHERE id = ?`)
      .run(now, now, imp.id);

    db.prepare(`INSERT INTO improvement_log (proposal_id, action, notes, created_at) VALUES (?, 'in_progress', 'Execution started from browser', ?)`)
      .run(imp.id, now);

    // Determine the right active team member based on improvement category
    const assignee = findImprovementAssignee(imp.category);
    const assignedTo = assignee ? assignee.id : null;
    const assigneeName = assignee ? assignee.name : 'Unassigned';

    // Create a task for this improvement
    const taskResult = db.prepare(`
      INSERT INTO tasks (title, description, status, priority, source_file, assigned_to, started_at, progress, current_step, created_at, updated_at)
      VALUES (?, ?, 'in_progress', ?, 'improvement', ?, ?, 10, 'Starting execution', ?, ?)
    `).run(
      `Execute: ${imp.title}`,
      `Implement improvement #${imp.id}: ${imp.description}`,
      imp.impact === 'high' ? 'high' : 'normal',
      assignedTo,
      now,
      now,
      now
    );

    const taskId = Number(taskResult.lastInsertRowid);

    // Log activity
    db.prepare(`INSERT INTO activity_log (task_id, actor, action, notes, created_at) VALUES (?, ?, 'improvement_execution', ?, ?)`)
      .run(taskId, assigneeName, `Executing improvement: ${imp.title}`, now);

    // Create notification
    createNotification('task_status', `Executing: ${imp.title}`, `Assigned to ${assigneeName} — improvement #${imp.id}`, taskId);

    // Broadcast
    broadcast('improvement.updated', { id: Number(req.params.id) });
    broadcast('task.updated', { id: taskId });

    // Auto-spawn assigned member's CLI session (fire-and-forget)
    if (assignedTo) {
      setImmediate(() => {
        spawnMemberTerminal(taskId, assignedTo).catch(err => {
          console.error(`[AutoSpawn] Improvement execute spawn error: ${err.message}`);
        });
      });
    }

    res.json({ task_id: taskId, message: `Improvement execution started — assigned to ${assigneeName}` });
  } catch (err) {
    console.error('POST /api/improvements/:id/execute error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/projects/:id/color', (req, res) => {
  try {
    const { color } = req.body;
    if (!color || !/^#[0-9A-Fa-f]{3,8}$/.test(color)) {
      return res.status(400).json({ error: 'Invalid color. Must be a hex color like #2383E2' });
    }
    const project = db.prepare(`SELECT id FROM projects WHERE id = ?`).get(req.params.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });

    // Check if the color column exists; handle gracefully if it doesn't
    try {
      const now = localNow();
      db.prepare(`UPDATE projects SET color = ?, updated_at = ? WHERE id = ?`).run(color, now, req.params.id);
      res.json({ message: 'Project color updated', color });
    } catch (colErr) {
      if (colErr.message && colErr.message.includes('no column named color')) {
        // Column doesn't exist — try to add it
        db.prepare(`ALTER TABLE projects ADD COLUMN color TEXT`).run();
        const now = localNow();
        db.prepare(`UPDATE projects SET color = ?, updated_at = ? WHERE id = ?`).run(color, now, req.params.id);
        res.json({ message: 'Project color updated (column created)', color });
      } else {
        throw colErr;
      }
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/phases/:projectId', (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT pp.*, p.name as project_name
      FROM project_phases pp
      LEFT JOIN projects p ON pp.project_id = p.id
      WHERE pp.project_id = ?
      ORDER BY pp.phase_number ASC
    `).all(req.params.projectId);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/phases/:id', (req, res) => {
  try {
    const phase = db.prepare('SELECT * FROM project_phases WHERE id = ?').get(req.params.id);
    if (!phase) return res.status(404).json({ error: 'Phase not found' });

    const { status, name, description } = req.body;
    const validStatuses = ['locked', 'active', 'completed'];
    if (status && !validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status. Must be one of: ' + validStatuses.join(', ') });
    }

    const updates = [];
    const values = [];
    if (name !== undefined) { updates.push('name = ?'); values.push(name); }
    if (description !== undefined) { updates.push('description = ?'); values.push(description); }
    if (status !== undefined) {
      updates.push('status = ?');
      values.push(status);
      const now = localNow();
      if (status === 'active' && !phase.activated_at) {
        updates.push('activated_at = ?');
        values.push(now);
      }
      if (status === 'completed') {
        updates.push('completed_at = ?');
        values.push(now);
      }
    }
    if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });

    values.push(req.params.id);
    db.prepare(`UPDATE project_phases SET ${updates.join(', ')} WHERE id = ?`).run(...values);
    res.json({ id: Number(req.params.id), message: 'Phase updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


};
