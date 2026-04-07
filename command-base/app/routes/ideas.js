'use strict';
module.exports = function(app, db, helpers) {
  const { broadcast, localNow, createNotification, authRateLimiter, apiRateLimiter, spawnMemberTerminal } = helpers;
  const stmt = helpers.stmt || ((sql) => db.prepare(sql));

app.get('/api/ideas/fresh', (req, res) => {
  try {
    // Auto-fill brainstorm if needed before returning
    try { autoFillBrainstorm(); } catch (e) { console.warn('Brainstorm auto-fill failed:', e.message); }
    res.json(db.prepare(`SELECT * FROM idea_board WHERE status = 'fresh' ORDER BY created_at DESC LIMIT 5`).all());
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/ideas', (req, res) => {
  try {
    const { status, category } = req.query;
    let sql = `SELECT i.*, p.name as project_name FROM idea_board i LEFT JOIN projects p ON i.related_project_id = p.id WHERE 1=1`;
    const params = [];
    if (status) { sql += ` AND i.status = ?`; params.push(status); }
    if (category) { sql += ` AND i.category = ?`; params.push(category); }
    sql += ` ORDER BY CASE i.status WHEN 'fresh' THEN 0 WHEN 'liked' THEN 1 WHEN 'researching' THEN 2 WHEN 'fleshed_out' THEN 3 WHEN 'promoted' THEN 4 WHEN 'passed' THEN 5 END, i.created_at DESC`;
    res.json(db.prepare(sql).all(...params));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/ideas/:id', (req, res) => {
  try {
    const row = db.prepare(`SELECT i.*, p.name as project_name FROM idea_board i LEFT JOIN projects p ON i.related_project_id = p.id WHERE i.id = ?`).get(req.params.id);
    if (!row) return res.status(404).json({ error: 'Not found' });
    res.json(row);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/ideas', (req, res) => {
  try {
    const { title, tagline, description, category, reference_material, structure, market_notes, generated_by } = req.body;
    if (!title || !description) return res.status(400).json({ error: 'Title and description required' });
    const now = localNow();
    const r = db.prepare(`INSERT INTO idea_board (title, tagline, description, category, reference_material, structure, market_notes, generated_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)`)
      .run(title, tagline || null, description, category || 'product', reference_material || null, structure || null, market_notes || null, generated_by || 'Max', now, now);
    res.json({ id: Number(r.lastInsertRowid), message: 'Idea created' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/ideas/:id', (req, res) => {
  try {
    const existing = db.prepare(`SELECT * FROM idea_board WHERE id = ?`).get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Not found' });
    const fields = []; const vals = [];
    for (const f of ['title', 'tagline', 'description', 'category', 'reference_material', 'structure', 'market_notes', 'status', 'related_project_id']) {
      if (req.body[f] !== undefined) { fields.push(f + ' = ?'); vals.push(req.body[f]); }
    }
    if (fields.length === 0) return res.status(400).json({ error: 'No fields' });
    const now = localNow();
    fields.push('updated_at = ?'); vals.push(now); vals.push(req.params.id);
    db.prepare('UPDATE idea_board SET ' + fields.join(', ') + ' WHERE id = ?').run(...vals);

    const newStatus = req.body.status;

    // Bug fix: When an idea leaves 'fresh' status, auto-fill brainstorm with a new one
    if (newStatus && newStatus !== 'fresh' && existing.status === 'fresh') {
      try { autoFillBrainstorm(); } catch (e) { console.warn('Brainstorm auto-fill after status change failed:', e.message); }
    }

    // When an idea is set to 'researching', auto-create a research program + linked session
    if (newStatus === 'researching' && existing.status !== 'researching') {
      try {
        const ideaBrief = `${existing.description || ''}\n\n${existing.tagline ? 'Tagline: ' + existing.tagline : ''}\n${existing.reference_material ? 'References: ' + existing.reference_material : ''}`.trim();
        const result = db.prepare(`
          INSERT INTO research_sessions (title, goal, success_criteria, research_brief, max_cycles, model)
          VALUES (?, ?, ?, ?, ?, ?)
        `).run(
          existing.title,
          `Research idea: ${existing.title}`,
          `Determine viability and outline key findings for "${existing.title}"`,
          ideaBrief,
          50,
          'sonnet'
        );
        const sessionId = Number(result.lastInsertRowid);

        // Also create a research program linked to this session
        const progResult = db.prepare(`
          INSERT INTO research_programs (session_id, title, goal, methodology, max_experiments, time_budget_minutes, loop_interval_seconds, assigned_to, created_at)
          VALUES (?, ?, ?, ?, 50, 60, 60, 'Briar', ?)
        `).run(sessionId, existing.title, `Research idea: ${existing.title}`,
               `Evaluate viability of "${existing.title}". Investigate market fit, technical feasibility, competitive landscape, and key risks. ${ideaBrief}`, now);
        const progId = Number(progResult.lastInsertRowid);
        db.prepare(`UPDATE research_sessions SET program_id = ? WHERE id = ?`).run(progId, sessionId);

        db.prepare(`INSERT INTO activity_log (actor, action, notes, created_at, category) VALUES ('Gray', 'research_created', ?, ?, 'system')`)
          .run(`Auto-created research program for idea "${existing.title}" (idea #${req.params.id})`, now);
        broadcast('research.created', { session_id: sessionId, program_id: progId, idea_id: Number(req.params.id) });

        // Auto-spawn Pax for idea research
        setImmediate(() => {
          try {
            const pax = db.prepare(`SELECT id FROM team_members WHERE name = 'Briar' AND status = 'active'`).get();
            if (!pax) return;
            const irNow = localNow();
            const taskResult = db.prepare(`
              INSERT INTO tasks (title, description, status, priority, source_file, assigned_to, started_at, progress, current_step, created_at, updated_at)
              VALUES (?, ?, 'in_progress', 'high', 'idea_research', ?, ?, 10, 'Idea research started', ?, ?)
            `).run(
              `Research idea: ${existing.title}`,
              `Research viability of idea "${existing.title}": ${existing.description || ''}`,
              pax.id, irNow, irNow, irNow
            );
            const tId = Number(taskResult.lastInsertRowid);
            db.prepare(`INSERT INTO activity_log (task_id, actor, action, notes, created_at) VALUES (?, 'Pax', 'idea_research_spawn', ?, ?)`)
              .run(tId, `Auto-spawned Pax for idea research: ${existing.title}`, irNow);
            broadcast('task.updated', { id: tId });
            spawnMemberTerminal(tId, pax.id).catch(err => {
              console.error(`[AutoSpawn] Idea research spawn error: ${err.message}`);
            });
          } catch (err) {
            console.error(`[AutoSpawn] Idea research spawn setup error: ${err.message}`);
          }
        });
      } catch (e) { console.warn('Auto-create research session failed:', e.message); }
    }

    res.json({ message: 'Updated' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/ideas/:id', (req, res) => {
  try {
    const idea = db.prepare('SELECT id FROM idea_board WHERE id = ?').get(req.params.id);
    if (!idea) return res.status(404).json({ error: 'Idea not found' });
    db.prepare('DELETE FROM idea_board WHERE id = ?').run(req.params.id);
    res.json({ message: 'Deleted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/ideas/:id/promote', (req, res) => {
  try {
    const idea = db.prepare('SELECT * FROM idea_board WHERE id = ?').get(req.params.id);
    if (!idea) return res.status(404).json({ error: 'Not found' });
    const now = localNow();
    const summary = '# ' + idea.title + '\n\n' + (idea.tagline ? '**' + idea.tagline + '**\n\n' : '') + idea.description + '\n\n## Reference Material\n' + (idea.reference_material || 'TBD') + '\n\n## Structure\n' + (idea.structure || 'TBD') + '\n\n## Market Notes\n' + (idea.market_notes || 'TBD');
    const r = db.prepare('INSERT INTO projects (name, summary, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)').run(idea.title, summary, 'active', now, now);
    db.prepare('UPDATE idea_board SET status = ?, related_project_id = ?, updated_at = ? WHERE id = ?').run('promoted', r.lastInsertRowid, now, req.params.id);
    db.prepare('INSERT INTO activity_log (task_id, actor, action, notes, created_at) VALUES (NULL, ?, ?, ?, ?)').run('Max', 'idea_promoted', 'Idea "' + idea.title + '" promoted to project', now);
    res.json({ project_id: Number(r.lastInsertRowid), message: '"' + idea.title + '" is now a project' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});


};
