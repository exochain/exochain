'use strict';
module.exports = function(app, db, helpers) {
  const { broadcast, localNow, createNotification, authRateLimiter, apiRateLimiter, spawnMemberTerminal } = helpers;
  const stmt = helpers.stmt || ((sql) => db.prepare(sql));

// GET /api/research-sessions — alias endpoint for the Auto-Research page
app.get('/api/research-sessions', (req, res, next) => {
  try {
    const rows = db.prepare(`
      SELECT s.*,
        (SELECT COUNT(*) FROM research_cycles WHERE session_id = s.id) AS cycle_count,
        (SELECT COUNT(*) FROM research_findings WHERE session_id = s.id AND status IN ('kept','approved')) AS findings_kept,
        (SELECT COUNT(*) FROM research_findings WHERE session_id = s.id AND status IN ('discarded','rejected')) AS findings_discarded
      FROM research_sessions s
      ORDER BY s.created_at DESC
    `).all();
    const sessions = rows.map(r => ({
      ...r,
      hit_rate: r.cycle_count > 0 ? Math.round((r.findings_kept / r.cycle_count) * 100) : 0
    }));
    res.json(sessions);
  } catch (err) { next(err); }
});

// POST /api/research-sessions — create a new research session
app.post('/api/research-sessions', (req, res, next) => {
  try {
    const { title, goal, success_criteria, research_brief, max_cycles, model, assigned_to, project_id } = req.body;
    if (!title || !goal) throw badRequest('title and goal are required');
    const result = db.prepare(`
      INSERT INTO research_sessions (title, goal, success_criteria, research_brief, max_cycles, model, assigned_to, project_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(title, goal, success_criteria || null, research_brief || null, max_cycles || 50, model || 'sonnet', assigned_to || null, project_id || null);
    const session = db.prepare(`SELECT * FROM research_sessions WHERE id = ?`).get(result.lastInsertRowid);

    // Auto-spawn Pax (or assigned member) for this research session
    setImmediate(() => {
      try {
        const researcherName = assigned_to || 'Briar';
        const researcher = db.prepare(`SELECT id FROM team_members WHERE name = ? AND status = 'active'`).get(researcherName);
        if (!researcher) return;
        const rsNow = localNow();
        const taskResult = db.prepare(`
          INSERT INTO tasks (title, description, status, priority, source_file, assigned_to, started_at, progress, current_step, created_at, updated_at)
          VALUES (?, ?, 'in_progress', 'high', 'research', ?, ?, 10, 'Research session started', ?, ?)
        `).run(`Research: ${title}`, `${goal}\n\n${research_brief || ''}`.trim(), researcher.id, rsNow, rsNow, rsNow);
        const tId = Number(taskResult.lastInsertRowid);
        db.prepare(`INSERT INTO activity_log (task_id, actor, action, notes, created_at) VALUES (?, ?, 'research_spawn', ?, ?)`)
          .run(tId, researcherName, `Auto-spawned ${researcherName} for research session: ${title}`, rsNow);
        broadcast('task.updated', { id: tId });
        spawnMemberTerminal(tId, researcher.id).catch(err => {
          console.error(`[AutoSpawn] Research session spawn error: ${err.message}`);
        });
      } catch (err) {
        console.error(`[AutoSpawn] Research session spawn setup error: ${err.message}`);
      }
    });

    res.status(201).json(session);
  } catch (err) { next(err); }
});

// DELETE /api/research-sessions/:id — delete a research session
app.delete('/api/research-sessions/:id', (req, res, next) => {
  try {
    const session = db.prepare(`SELECT * FROM research_sessions WHERE id = ?`).get(req.params.id);
    if (!session) return res.status(404).json({ error: 'Research session not found' });

    // Clean up related data
    db.prepare(`DELETE FROM research_findings WHERE session_id = ?`).run(req.params.id);
    db.prepare(`DELETE FROM research_cycles WHERE session_id = ?`).run(req.params.id);
    db.prepare(`DELETE FROM research_sessions WHERE id = ?`).run(req.params.id);

    res.json({ message: 'Deleted' });
  } catch (err) { next(err); }
});

// List all research sessions with computed fields
app.get('/api/research', (req, res, next) => {
  try {
    const rows = db.prepare(`
      SELECT s.*,
        (SELECT COUNT(*) FROM research_cycles WHERE session_id = s.id) AS cycle_count,
        (SELECT COUNT(*) FROM research_findings WHERE session_id = s.id AND status IN ('kept','approved')) AS findings_kept,
        (SELECT COUNT(*) FROM research_findings WHERE session_id = s.id AND status IN ('discarded','rejected')) AS findings_discarded
      FROM research_sessions s
      ORDER BY s.created_at DESC
    `).all();
    const sessions = rows.map(r => ({
      ...r,
      hit_rate: r.cycle_count > 0 ? Math.round((r.findings_kept / r.cycle_count) * 100) : 0
    }));
    res.json(sessions);
  } catch (err) { next(err); }
});

// Create a new research session
app.post('/api/research', (req, res, next) => {
  try {
    const { title, goal, success_criteria, research_brief, max_cycles, model, assigned_to, project_id } = req.body;
    if (!title || !goal) throw badRequest('title and goal are required');
    const result = db.prepare(`
      INSERT INTO research_sessions (title, goal, success_criteria, research_brief, max_cycles, model, assigned_to, project_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(title, goal, success_criteria || null, research_brief || null, max_cycles || 50, model || 'sonnet', assigned_to || null, project_id || null);
    const session = db.prepare(`SELECT * FROM research_sessions WHERE id = ?`).get(result.lastInsertRowid);

    // Auto-spawn Pax (or assigned member) for this research session
    setImmediate(() => {
      try {
        const researcherName = assigned_to || 'Briar';
        const researcher = db.prepare(`SELECT id FROM team_members WHERE name = ? AND status = 'active'`).get(researcherName);
        if (!researcher) return;
        const rsNow = localNow();
        const taskResult = db.prepare(`
          INSERT INTO tasks (title, description, status, priority, source_file, assigned_to, started_at, progress, current_step, created_at, updated_at)
          VALUES (?, ?, 'in_progress', 'high', 'research', ?, ?, 10, 'Research session started', ?, ?)
        `).run(`Research: ${title}`, `${goal}\n\n${research_brief || ''}`.trim(), researcher.id, rsNow, rsNow, rsNow);
        const tId = Number(taskResult.lastInsertRowid);
        db.prepare(`INSERT INTO activity_log (task_id, actor, action, notes, created_at) VALUES (?, ?, 'research_spawn', ?, ?)`)
          .run(tId, researcherName, `Auto-spawned ${researcherName} for research session: ${title}`, rsNow);
        broadcast('task.updated', { id: tId });
        spawnMemberTerminal(tId, researcher.id).catch(err => {
          console.error(`[AutoSpawn] Research session spawn error: ${err.message}`);
        });
      } catch (err) {
        console.error(`[AutoSpawn] Research session spawn setup error: ${err.message}`);
      }
    });

    res.status(201).json(session);
  } catch (err) { next(err); }
});

// Session detail with last 10 cycles and kept/approved findings
app.get('/api/research/:id', (req, res, next) => {
  // Skip non-numeric IDs so /api/research/programs etc. can be handled by later routes
  if (isNaN(req.params.id)) return next();
  try {
    const session = db.prepare(`SELECT * FROM research_sessions WHERE id = ?`).get(req.params.id);
    if (!session) throw notFound('Research session not found');
    const cycles = db.prepare(`SELECT * FROM research_cycles WHERE session_id = ? ORDER BY cycle_number DESC LIMIT 10`).all(req.params.id);
    const findings = db.prepare(`SELECT * FROM research_findings WHERE session_id = ? AND status IN ('kept','approved') ORDER BY created_at DESC`).all(req.params.id);
    const cycle_count = db.prepare(`SELECT COUNT(*) AS c FROM research_cycles WHERE session_id = ?`).get(req.params.id).c;
    const findings_kept = db.prepare(`SELECT COUNT(*) AS c FROM research_findings WHERE session_id = ? AND status IN ('kept','approved')`).get(req.params.id).c;
    const findings_discarded = db.prepare(`SELECT COUNT(*) AS c FROM research_findings WHERE session_id = ? AND status IN ('discarded','rejected')`).get(req.params.id).c;
    res.json({
      ...session,
      cycle_count,
      findings_kept,
      findings_discarded,
      hit_rate: cycle_count > 0 ? Math.round((findings_kept / cycle_count) * 100) : 0,
      cycles,
      findings
    });
  } catch (err) { next(err); }
});

// Update session fields
app.put('/api/research/:id', (req, res, next) => {
  if (isNaN(req.params.id)) return next();
  try {
    const existing = db.prepare(`SELECT * FROM research_sessions WHERE id = ?`).get(req.params.id);
    if (!existing) throw notFound('Research session not found');
    const { title, goal, success_criteria, research_brief, max_cycles, model, assigned_to, project_id, summary } = req.body;
    db.prepare(`
      UPDATE research_sessions
      SET title = ?, goal = ?, success_criteria = ?, research_brief = ?, max_cycles = ?, model = ?, assigned_to = ?, project_id = ?, summary = ?
      WHERE id = ?
    `).run(
      title ?? existing.title, goal ?? existing.goal, success_criteria ?? existing.success_criteria,
      research_brief ?? existing.research_brief, max_cycles ?? existing.max_cycles, model ?? existing.model,
      assigned_to ?? existing.assigned_to, project_id ?? existing.project_id, summary ?? existing.summary,
      req.params.id
    );
    const updated = db.prepare(`SELECT * FROM research_sessions WHERE id = ?`).get(req.params.id);
    res.json(updated);
  } catch (err) { next(err); }
});

// Delete session + cascade cycles and findings
app.delete('/api/research/:id', (req, res, next) => {
  if (isNaN(req.params.id)) return next();
  try {
    const session = db.prepare(`SELECT * FROM research_sessions WHERE id = ?`).get(req.params.id);
    if (!session) throw notFound('Research session not found');
    db.prepare(`DELETE FROM research_findings WHERE session_id = ?`).run(req.params.id);
    db.prepare(`DELETE FROM research_cycles WHERE session_id = ?`).run(req.params.id);
    db.prepare(`DELETE FROM research_sessions WHERE id = ?`).run(req.params.id);
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// Start session
app.post('/api/research/:id/start', (req, res, next) => {
  if (isNaN(req.params.id)) return next();
  try {
    const session = db.prepare(`SELECT * FROM research_sessions WHERE id = ?`).get(req.params.id);
    if (!session) throw notFound('Research session not found');
    db.prepare(`UPDATE research_sessions SET status = 'running', started_at = datetime('now','localtime') WHERE id = ?`).run(req.params.id);
    broadcast('research.updated', { id: Number(req.params.id) });
    const updated = db.prepare(`SELECT * FROM research_sessions WHERE id = ?`).get(req.params.id);
    res.json(updated);
  } catch (err) { next(err); }
});

// Pause session
app.post('/api/research/:id/pause', (req, res, next) => {
  if (isNaN(req.params.id)) return next();
  try {
    const session = db.prepare(`SELECT * FROM research_sessions WHERE id = ?`).get(req.params.id);
    if (!session) throw notFound('Research session not found');
    db.prepare(`UPDATE research_sessions SET status = 'paused' WHERE id = ?`).run(req.params.id);
    broadcast('research.updated', { id: Number(req.params.id) });
    const updated = db.prepare(`SELECT * FROM research_sessions WHERE id = ?`).get(req.params.id);
    res.json(updated);
  } catch (err) { next(err); }
});

// Stop session
app.post('/api/research/:id/stop', (req, res, next) => {
  if (isNaN(req.params.id)) return next();
  try {
    const session = db.prepare(`SELECT * FROM research_sessions WHERE id = ?`).get(req.params.id);
    if (!session) throw notFound('Research session not found');
    db.prepare(`UPDATE research_sessions SET status = 'completed', completed_at = datetime('now','localtime') WHERE id = ?`).run(req.params.id);
    broadcast('research.updated', { id: Number(req.params.id) });
    const updated = db.prepare(`SELECT * FROM research_sessions WHERE id = ?`).get(req.params.id);
    res.json(updated);
  } catch (err) { next(err); }
});

// Paginated cycles for a session
app.get('/api/research/:id/cycles', (req, res, next) => {
  if (isNaN(req.params.id)) return next();
  try {
    const session = db.prepare(`SELECT id FROM research_sessions WHERE id = ?`).get(req.params.id);
    if (!session) throw notFound('Research session not found');
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
    const offset = (page - 1) * limit;
    const total = db.prepare(`SELECT COUNT(*) AS c FROM research_cycles WHERE session_id = ?`).get(req.params.id).c;
    const cycles = db.prepare(`SELECT * FROM research_cycles WHERE session_id = ? ORDER BY cycle_number DESC LIMIT ? OFFSET ?`).all(req.params.id, limit, offset);
    res.json({ page, limit, total, pages: Math.ceil(total / limit), cycles });
  } catch (err) { next(err); }
});

// Filtered findings for a session
app.get('/api/research/:id/findings', (req, res, next) => {
  if (isNaN(req.params.id)) return next();
  try {
    const session = db.prepare(`SELECT id FROM research_sessions WHERE id = ?`).get(req.params.id);
    if (!session) throw notFound('Research session not found');
    let sql = `SELECT * FROM research_findings WHERE session_id = ?`;
    const params = [req.params.id];
    if (req.query.status) {
      sql += ` AND status = ?`;
      params.push(req.query.status);
    }
    if (req.query.confidence) {
      sql += ` AND confidence = ?`;
      params.push(req.query.confidence);
    }
    sql += ` ORDER BY created_at DESC`;
    const findings = db.prepare(sql).all(...params);
    res.json(findings);
  } catch (err) { next(err); }
});

// Update finding status (approve/reject)
app.patch('/api/research/findings/:id', (req, res, next) => {
  try {
    const finding = db.prepare(`SELECT * FROM research_findings WHERE id = ?`).get(req.params.id);
    if (!finding) throw notFound('Finding not found');
    const { status } = req.body;
    if (!status || !['kept', 'discarded', 'approved', 'rejected'].includes(status)) {
      throw badRequest('status must be one of: kept, discarded, approved, rejected');
    }
    db.prepare(`UPDATE research_findings SET status = ? WHERE id = ?`).run(status, req.params.id);
    const updated = db.prepare(`SELECT * FROM research_findings WHERE id = ?`).get(req.params.id);
    res.json(updated);
  } catch (err) { next(err); }
});

// Export session as markdown
app.get('/api/research/:id/export', (req, res, next) => {
  if (isNaN(req.params.id)) return next();
  try {
    const session = db.prepare(`SELECT * FROM research_sessions WHERE id = ?`).get(req.params.id);
    if (!session) throw notFound('Research session not found');
    const findings = db.prepare(`SELECT * FROM research_findings WHERE session_id = ? AND status IN ('kept','approved') ORDER BY created_at ASC`).all(req.params.id);
    const cycle_count = db.prepare(`SELECT COUNT(*) AS c FROM research_cycles WHERE session_id = ?`).get(req.params.id).c;
    const findings_kept = findings.length;
    const findings_discarded = db.prepare(`SELECT COUNT(*) AS c FROM research_findings WHERE session_id = ? AND status IN ('discarded','rejected')`).get(req.params.id).c;
    const hit_rate = cycle_count > 0 ? Math.round((findings_kept / cycle_count) * 100) : 0;

    let md = `# Research: ${session.title}\n\n`;
    md += `## Goal\n${session.goal}\n\n`;
    md += `## Success Criteria\n${session.success_criteria || 'N/A'}\n\n`;
    md += `## Findings\n\n`;
    findings.forEach((f, i) => {
      md += `### ${i + 1}. ${f.title} (confidence: ${f.confidence})\n${f.content}\n\n`;
    });
    md += `## Stats\n`;
    md += `- Cycles: ${cycle_count}, Kept: ${findings_kept}, Discarded: ${findings_discarded}, Hit rate: ${hit_rate}%\n`;
    md += `- Model: ${session.model}\n`;
    md += `- Duration: ${session.started_at || 'not started'} to ${session.completed_at || 'ongoing'}\n`;

    res.set('Content-Type', 'text/markdown');
    res.set('Content-Disposition', `attachment; filename="research-${session.id}-export.md"`);
    res.send(md);
  } catch (err) { next(err); }
});

// List all programs (supports ?status=converged,completed,failed filtering)
app.get('/api/research/programs', (req, res, next) => {
  try {
    let query = `SELECT rp.*, (SELECT title FROM research_sessions WHERE id = rp.session_id) AS session_title FROM research_programs rp`;
    const params = [];
    if (req.query.status) {
      const statuses = req.query.status.split(',').map(s => s.trim()).filter(Boolean);
      if (statuses.length > 0) {
        query += ` WHERE rp.status IN (${statuses.map(() => '?').join(',')})`;
        params.push(...statuses);
      }
    }
    query += ` ORDER BY rp.created_at DESC`;
    const programs = db.prepare(query).all(...params);

    // Include experiment history for charting
    const includeExperiments = req.query.include_experiments === '1';
    const enriched = programs.map(p => {
      const result = {
        ...p,
        knowledge_base: JSON.parse(p.knowledge_base || '[]'),
        hit_rate: p.experiment_count > 0 ? Math.round((p.kept_count / p.experiment_count) * 100) : 0,
        is_looping: activeResearchLoops.has(p.id)
      };
      if (includeExperiments) {
        try {
          result.experiments = db.prepare(`
            SELECT id, experiment_number, status, decision, result_value, metric_value, delta, hypothesis, description, created_at, completed_at, commit_hash
            FROM research_experiments WHERE program_id = ? ORDER BY experiment_number ASC
          `).all(p.id);
        } catch (_) {
          result.experiments = [];
        }
      }
      return result;
    });
    res.json(enriched);
  } catch (err) { next(err); }
});

// Create a research program (auto-creates linked session)
app.post('/api/research/programs', (req, res, next) => {
  try {
    const { title, goal, methodology, success_metric, success_threshold, max_experiments,
            time_budget_minutes, loop_interval_seconds, assigned_to, project_id,
            target_file, metric_name, metric_command, experiment_timeout_seconds,
            working_branch, working_directory } = req.body;
    if (!title || !goal) throw badRequest('title and goal are required');

    // Check for duplicate research program with same title
    const existingProgram = db.prepare("SELECT id FROM research_programs WHERE title = ? AND status NOT IN ('converged')").get(title);
    if (existingProgram) return res.status(409).json({ error: 'Research program with this title already exists', existing_id: existingProgram.id });

    const now = localNow();

    // Resolve assigned_to to member ID
    let assigneeId = null;
    const assigneeName = assigned_to || 'Briar';
    const assigneeMember = db.prepare("SELECT id FROM team_members WHERE name = ? AND status = 'active'").get(assigneeName);
    if (assigneeMember) assigneeId = assigneeMember.id;

    // Create a linked research session
    const sessionResult = db.prepare(`
      INSERT INTO research_sessions (title, goal, success_criteria, research_brief, max_cycles, model, assigned_to, project_id, created_at)
      VALUES (?, ?, ?, ?, ?, 'sonnet', ?, ?, ?)
    `).run(title, goal, success_metric || null, methodology || null,
           max_experiments || 100, assigneeId, project_id || null, now);
    const sessionId = Number(sessionResult.lastInsertRowid);

    // Create the program with autoresearch experiment loop fields
    const result = db.prepare(`
      INSERT INTO research_programs (session_id, title, goal, methodology, success_metric, success_threshold,
        max_experiments, time_budget_minutes, loop_interval_seconds, assigned_to, project_id,
        target_file, metric_name, metric_command, experiment_timeout_seconds, working_branch, working_directory, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(sessionId, title, goal, methodology || null, success_metric || null,
           success_threshold || null, max_experiments || 100, time_budget_minutes || 60,
           loop_interval_seconds || 30, assigned_to || 'Briar', project_id || null,
           target_file || null, metric_name || 'quality', metric_command || null,
           experiment_timeout_seconds || 300, working_branch || null, working_directory || null, now);
    const programId = Number(result.lastInsertRowid);

    // Link session back to program
    db.prepare(`UPDATE research_sessions SET program_id = ? WHERE id = ?`).run(programId, sessionId);

    const program = db.prepare(`SELECT * FROM research_programs WHERE id = ?`).get(programId);
    program.knowledge_base = JSON.parse(program.knowledge_base || '[]');

    db.prepare(`INSERT INTO activity_log (actor, action, notes, created_at, category) VALUES ('Gray', 'research_program_created', ?, ?, 'research')`)
      .run(`Created research program: ${title}`, now);

    broadcast('research.program_created', { id: programId });
    res.status(201).json(program);
  } catch (err) { next(err); }
});

// Get program detail
app.get('/api/research/programs/:id', (req, res, next) => {
  try {
    const program = db.prepare(`SELECT * FROM research_programs WHERE id = ?`).get(req.params.id);
    if (!program) throw notFound('Research program not found');

    const experiments = db.prepare(`
      SELECT * FROM research_experiments WHERE program_id = ? ORDER BY experiment_number DESC LIMIT 50
    `).all(req.params.id);

    program.knowledge_base = JSON.parse(program.knowledge_base || '[]');
    program.experiments = experiments;
    program.hit_rate = program.experiment_count > 0 ? Math.round((program.kept_count / program.experiment_count) * 100) : 0;
    program.is_looping = activeResearchLoops.has(program.id);

    // Convergence data for charting (include both legacy status='kept' and new decision='keep')
    const keptExps = db.prepare(`
      SELECT experiment_number, result_value, metric_value, delta, decision, commit_hash FROM research_experiments
      WHERE program_id = ? AND (status = 'kept' OR decision = 'keep') AND (result_value IS NOT NULL OR metric_value IS NOT NULL)
      ORDER BY experiment_number ASC
    `).all(req.params.id);
    program.convergence_data = keptExps;

    res.json(program);
  } catch (err) { next(err); }
});

// Start a research program (begins autonomous loop)
app.post('/api/research/programs/:id/start', (req, res, next) => {
  try {
    const program = db.prepare(`SELECT * FROM research_programs WHERE id = ?`).get(req.params.id);
    if (!program) throw notFound('Research program not found');
    if (program.status === 'running') throw badRequest('Program is already running');
    // Allow restarting converged/completed programs
    if (program.status === 'converged' || program.status === 'completed') {
      db.prepare(`UPDATE research_programs SET converged_at = NULL WHERE id = ?`).run(req.params.id);
    }

    const now = localNow();
    const startedAt = program.started_at || now;
    db.prepare(`UPDATE research_programs SET status = 'running', started_at = ? WHERE id = ?`)
      .run(startedAt, req.params.id);

    if (program.session_id) {
      db.prepare(`UPDATE research_sessions SET status = 'running', started_at = COALESCE(started_at, ?) WHERE id = ?`)
        .run(startedAt, program.session_id);
    }

    // Run first cycle immediately, then start the loop
    runResearchCycle(Number(req.params.id)).catch(err => {
      console.error(`[ResearchEngine] Initial cycle error: ${err.message}`);
    });
    startResearchLoop(Number(req.params.id));

    broadcast('research.program_updated', { id: Number(req.params.id), status: 'running' });
    const updated = db.prepare(`SELECT * FROM research_programs WHERE id = ?`).get(req.params.id);
    updated.knowledge_base = JSON.parse(updated.knowledge_base || '[]');
    res.json(updated);
  } catch (err) { next(err); }
});

// Pause a research program
app.post('/api/research/programs/:id/pause', (req, res, next) => {
  try {
    const program = db.prepare(`SELECT * FROM research_programs WHERE id = ?`).get(req.params.id);
    if (!program) throw notFound('Research program not found');

    db.prepare(`UPDATE research_programs SET status = 'paused' WHERE id = ?`).run(req.params.id);
    stopResearchLoop(Number(req.params.id));

    if (program.session_id) {
      db.prepare(`UPDATE research_sessions SET status = 'paused' WHERE id = ?`).run(program.session_id);
    }

    broadcast('research.program_updated', { id: Number(req.params.id), status: 'paused' });
    const updated = db.prepare(`SELECT * FROM research_programs WHERE id = ?`).get(req.params.id);
    updated.knowledge_base = JSON.parse(updated.knowledge_base || '[]');
    res.json(updated);
  } catch (err) { next(err); }
});

// Stop a research program
app.post('/api/research/programs/:id/stop', (req, res, next) => {
  try {
    const program = db.prepare(`SELECT * FROM research_programs WHERE id = ?`).get(req.params.id);
    if (!program) throw notFound('Research program not found');
    const now = localNow();

    db.prepare(`UPDATE research_programs SET status = 'converged', converged_at = ? WHERE id = ?`)
      .run(now, req.params.id);
    stopResearchLoop(Number(req.params.id));

    if (program.session_id) {
      db.prepare(`UPDATE research_sessions SET status = 'completed', completed_at = ? WHERE id = ?`)
        .run(now, program.session_id);
    }

    broadcast('research.program_updated', { id: Number(req.params.id), status: 'converged' });
    const updated = db.prepare(`SELECT * FROM research_programs WHERE id = ?`).get(req.params.id);
    updated.knowledge_base = JSON.parse(updated.knowledge_base || '[]');
    res.json(updated);
  } catch (err) { next(err); }
});

// Run a single cycle manually
app.post('/api/research/programs/:id/run-cycle', async (req, res, next) => {
  try {
    const program = db.prepare(`SELECT * FROM research_programs WHERE id = ?`).get(req.params.id);
    if (!program) throw notFound('Research program not found');

    // Temporarily set to running if idle/paused
    if (program.status === 'idle' || program.status === 'paused') {
      const now = localNow();
      db.prepare(`UPDATE research_programs SET status = 'running', started_at = COALESCE(started_at, ?) WHERE id = ?`)
        .run(now, req.params.id);
    }

    const result = await runResearchCycle(Number(req.params.id));

    // Set back to paused if it was a manual one-off
    if (program.status === 'idle' || program.status === 'paused') {
      db.prepare(`UPDATE research_programs SET status = 'paused' WHERE id = ?`).run(req.params.id);
    }

    res.json(result);
  } catch (err) { next(err); }
});

// Record experiment results (called by agents or external systems)
app.post('/api/research/experiments/:id/result', (req, res, next) => {
  try {
    const result = recordExperimentResult(Number(req.params.id), req.body);
    if (!result) throw notFound('Experiment not found');
    res.json(result);
  } catch (err) { next(err); }
});

// Get experiments for a program
app.get('/api/research/programs/:id/experiments', (req, res, next) => {
  try {
    const program = db.prepare(`SELECT id FROM research_programs WHERE id = ?`).get(req.params.id);
    if (!program) throw notFound('Research program not found');
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
    const offset = (page - 1) * limit;
    const total = db.prepare(`SELECT COUNT(*) AS c FROM research_experiments WHERE program_id = ?`).get(req.params.id).c;
    const experiments = db.prepare(`SELECT * FROM research_experiments WHERE program_id = ? ORDER BY experiment_number DESC LIMIT ? OFFSET ?`)
      .all(req.params.id, limit, offset);
    res.json({ page, limit, total, pages: Math.ceil(total / limit), experiments });
  } catch (err) { next(err); }
});

// Delete a program + cascade
app.delete('/api/research/programs/:id', (req, res, next) => {
  try {
    const program = db.prepare(`SELECT * FROM research_programs WHERE id = ?`).get(req.params.id);
    if (!program) throw notFound('Research program not found');
    stopResearchLoop(Number(req.params.id));
    db.prepare(`DELETE FROM research_experiments WHERE program_id = ?`).run(req.params.id);
    if (program.session_id) {
      db.prepare(`DELETE FROM research_findings WHERE session_id = ?`).run(program.session_id);
      db.prepare(`DELETE FROM research_cycles WHERE session_id = ?`).run(program.session_id);
      db.prepare(`DELETE FROM research_sessions WHERE id = ?`).run(program.session_id);
    }
    db.prepare(`DELETE FROM research_programs WHERE id = ?`).run(req.params.id);
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// Get program knowledge base
app.get('/api/research/programs/:id/knowledge', (req, res, next) => {
  try {
    const program = db.prepare(`SELECT knowledge_base FROM research_programs WHERE id = ?`).get(req.params.id);
    if (!program) throw notFound('Research program not found');
    res.json(JSON.parse(program.knowledge_base || '[]'));
  } catch (err) { next(err); }
});

// Export program as markdown report
app.get('/api/research/programs/:id/export', (req, res, next) => {
  try {
    const program = db.prepare(`SELECT * FROM research_programs WHERE id = ?`).get(req.params.id);
    if (!program) throw notFound('Research program not found');
    const experiments = db.prepare(`SELECT * FROM research_experiments WHERE program_id = ? ORDER BY experiment_number ASC`).all(req.params.id);
    const kb = JSON.parse(program.knowledge_base || '[]');

    let md = `# Research Program: ${program.title}\n\n`;
    md += `## Goal\n${program.goal}\n\n`;
    md += `## Methodology\n${program.methodology || 'Open investigation'}\n\n`;
    if (program.target_file) md += `## Target File\n\`${program.target_file}\`\n\n`;
    if (program.metric_command) md += `## Metric Command\n\`${program.metric_command}\`\n\n`;
    if (program.working_directory) md += `## Working Directory\n\`${program.working_directory}\`\n\n`;
    md += `## Results Summary\n`;
    md += `- Total experiments: ${program.experiment_count}\n`;
    md += `- Kept: ${program.kept_count} | Discarded: ${program.discarded_count} | Crashes: ${program.crash_count}\n`;
    md += `- Hit rate: ${program.experiment_count > 0 ? Math.round((program.kept_count / program.experiment_count) * 100) : 0}%\n`;
    md += `- Metric: ${program.metric_name || 'quality'}\n`;
    md += `- Baseline: ${program.baseline_value ?? 'N/A'} | Best: ${program.current_best ?? 'N/A'}\n\n`;

    md += `## Experiment Log\n\n`;
    md += `| # | Hypothesis | Decision | Value | Delta | Commit | Description |\n`;
    md += `|---|-----------|----------|-------|-------|--------|-------------|\n`;
    experiments.forEach(e => {
      const dec = e.decision || e.status;
      const val = e.metric_value !== null && e.metric_value !== undefined ? e.metric_value : (e.result_value ?? '-');
      md += `| ${e.experiment_number} | ${(e.hypothesis || '').slice(0, 60)} | ${dec} | ${val} | ${e.delta ?? '-'} | ${e.commit_hash || '-'} | ${(e.description || '').slice(0, 60)} |\n`;
    });

    md += `\n## Accumulated Knowledge\n\n`;
    kb.forEach((k, i) => { md += `${i + 1}. ${k}\n`; });

    md += `\n## Duration\n`;
    md += `- Started: ${program.started_at || 'not started'}\n`;
    md += `- Ended: ${program.converged_at || 'ongoing'}\n`;

    res.set('Content-Type', 'text/markdown');
    res.set('Content-Disposition', `attachment; filename="research-program-${program.id}.md"`);
    res.send(md);
  } catch (err) { next(err); }
});


};
