'use strict';
module.exports = function(app, db, helpers) {
  const { broadcast, localNow, createNotification, authRateLimiter, apiRateLimiter, spawnMemberTerminal } = helpers;
  const stmt = helpers.stmt || ((sql) => db.prepare(sql));

// GET /api/workspace/active — all running processes with latest activity
app.get('/api/workspace/active', (req, res, next) => {
  try {
    // Running processes with member and task info
    // FIX: Also include agents running via heartbeat (agent_runtime_state) that may not
    // have a corresponding active_processes entry
    const running = db.prepare(`
      SELECT ap.id as process_id, ap.pid, ap.status, ap.started_at, ap.completed_at, ap.output_summary,
             ap.process_type,
             tm.id as member_id, tm.name as member_name, tm.role as member_role, tm.adapter_type, tm.tier as member_tier,
             t.id as task_id, t.title as task_title, t.progress, t.current_step, t.priority
      FROM active_processes ap
      LEFT JOIN team_members tm ON ap.member_id = tm.id
      LEFT JOIN tasks t ON ap.task_id = t.id
      WHERE ap.status = 'running'
      ORDER BY ap.started_at DESC
    `).all();

    // Also pull agents running via heartbeat that aren't in active_processes
    const heartbeatRunning = db.prepare(`
      SELECT ars.member_id, ars.current_task_id as task_id, ars.status, ars.last_heartbeat_at as started_at,
             tm.name as member_name, tm.role as member_role, tm.adapter_type, tm.tier as member_tier,
             t.title as task_title, t.progress, t.current_step, t.priority
      FROM agent_runtime_state ars
      JOIN team_members tm ON ars.member_id = tm.id
      LEFT JOIN tasks t ON ars.current_task_id = t.id
      WHERE ars.status = 'running'
      AND ars.member_id NOT IN (SELECT member_id FROM active_processes WHERE status = 'running')
    `).all();

    // Merge heartbeat agents into running list as synthetic entries
    for (const hb of heartbeatRunning) {
      running.push({
        process_id: null,
        pid: null,
        status: 'running',
        started_at: hb.started_at,
        completed_at: null,
        output_summary: null,
        process_type: 'heartbeat',
        member_id: hb.member_id,
        member_name: hb.member_name,
        member_role: hb.member_role,
        adapter_type: hb.adapter_type,
        member_tier: hb.member_tier,
        task_id: hb.task_id,
        task_title: hb.task_title,
        progress: hb.progress,
        current_step: hb.current_step,
        priority: hb.priority,
        event_counts: {},
        files_touched: [],
        last_event: null
      });
    }

    // Enrich with activity stream summaries
    for (const proc of running) {
      const counts = db.prepare(`
        SELECT event_type, COUNT(*) as cnt FROM agent_activity_stream
        WHERE process_id = ? GROUP BY event_type
      `).all(proc.process_id);
      proc.event_counts = {};
      for (const c of counts) proc.event_counts[c.event_type] = c.cnt;

      const files = db.prepare(`
        SELECT DISTINCT file_name FROM agent_activity_stream
        WHERE process_id = ? AND file_name IS NOT NULL
        ORDER BY created_at DESC LIMIT 20
      `).all(proc.process_id);
      proc.files_touched = files.map(f => f.file_name);

      const lastEvent = db.prepare(`
        SELECT * FROM agent_activity_stream WHERE process_id = ? ORDER BY id DESC LIMIT 1
      `).get(proc.process_id);
      proc.last_event = lastEvent || null;
    }

    // Recently completed/failed (last 10)
    const recent = db.prepare(`
      SELECT ap.id as process_id, ap.pid, ap.status, ap.started_at, ap.completed_at, ap.output_summary,
             ap.process_type,
             tm.id as member_id, tm.name as member_name, tm.role as member_role, tm.adapter_type, tm.tier as member_tier,
             t.id as task_id, t.title as task_title, t.progress, t.current_step, t.priority
      FROM active_processes ap
      LEFT JOIN team_members tm ON ap.member_id = tm.id
      LEFT JOIN tasks t ON ap.task_id = t.id
      WHERE ap.status IN ('completed', 'failed', 'killed')
      ORDER BY ap.completed_at DESC
      LIMIT 10
    `).all();

    // Update last_viewed_at for sessions with running processes
    const now = localNow();
    const sessionIds = new Set();
    for (const proc of running) {
      if (proc.task_id) {
        const sp = db.prepare('SELECT session_id FROM session_phases WHERE task_id = ?').get(proc.task_id);
        if (sp && sp.session_id) sessionIds.add(sp.session_id);
      }
    }
    for (const sid of sessionIds) {
      db.prepare('UPDATE workspace_sessions SET last_viewed_at = ? WHERE id = ?').run(now, sid);
    }

    res.json({ running, recent });
  } catch (err) { next(err); }
});

// GET /api/workspace/council-routing — currently active Council routing processes
app.get('/api/workspace/council-routing', (req, res, next) => {
  try {
    const active = db.prepare(`
      SELECT ap.id as process_id, ap.task_id, ap.started_at, ap.output_summary,
             t.title as task_title, t.priority, t.current_step
      FROM active_processes ap
      LEFT JOIN tasks t ON ap.task_id = t.id
      WHERE ap.process_type = 'council' AND ap.status = 'running'
      ORDER BY ap.started_at DESC
    `).all();

    // Also get recently completed council processes (last 5)
    const recent = db.prepare(`
      SELECT ap.id as process_id, ap.task_id, ap.started_at, ap.completed_at, ap.status, ap.output_summary,
             t.title as task_title
      FROM active_processes ap
      LEFT JOIN tasks t ON ap.task_id = t.id
      WHERE ap.process_type = 'council' AND ap.status IN ('completed', 'failed')
      ORDER BY ap.completed_at DESC
      LIMIT 5
    `).all();

    res.json({ active, recent });
  } catch (err) { next(err); }
});

// POST /api/workspace/submit — submit a big prompt for digestion
app.post('/api/workspace/submit', (req, res, next) => {
  try {
    const { title, prompt, project_id, priority } = req.body;
    if (!prompt) return res.status(400).json({ error: 'Prompt required' });

    const now = localNow();
    const promptChars = prompt.length;
    const promptTokensEst = Math.ceil(promptChars / 4);

    const result = db.prepare(`INSERT INTO workspace_sessions (title, raw_prompt, prompt_chars, prompt_tokens_est, project_id, priority, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)`)
      .run(title || 'New Project', prompt, promptChars, promptTokensEst, project_id || null, priority || 'normal', 'digesting', now, now);

    const sessionId = Number(result.lastInsertRowid);

    // Auto-digest: spawn Gray to create a plan
    setImmediate(() => digestSessionPrompt(sessionId));

    res.json({ id: sessionId, status: 'digesting', prompt_chars: promptChars, prompt_tokens_est: promptTokensEst });
  } catch (err) { next(err); }
});

// GET /api/workspace/history — unified history of all completed work
app.get('/api/workspace/history', (req, res, next) => {
  try {
    const results = [];

    // 1. Completed workspace sessions
    const sessions = db.prepare(`
      SELECT ws.id, ws.title, ws.status, ws.created_at, ws.completed_at, ws.updated_at,
        p.name as project_name
      FROM workspace_sessions ws
      LEFT JOIN projects p ON ws.project_id = p.id
      WHERE ws.status IN ('completed', 'cancelled', 'failed')
      ORDER BY ws.completed_at DESC
      LIMIT 30
    `).all();
    for (const s of sessions) {
      let durationSeconds = null;
      if (s.created_at && s.completed_at) {
        durationSeconds = Math.floor((new Date(s.completed_at.replace(' ', 'T')) - new Date(s.created_at.replace(' ', 'T'))) / 1000);
        if (durationSeconds < 0) durationSeconds = 0;
      }
      results.push({
        type: 'session',
        id: s.id,
        title: s.title,
        status: s.status,
        member_name: null,
        completed_at: s.completed_at || s.updated_at,
        duration_seconds: durationSeconds,
        source: s.project_name || 'workspace'
      });
    }

    // 2. Completed improvement executions
    const improvements = db.prepare(`
      SELECT ip.id, ip.title, ip.status, ip.completed_at, ip.work_started_at, ip.work_completed_at,
        ip.category, ip.current_step, ip.description,
        t.assigned_to, tm.name as member_name
      FROM improvement_proposals ip
      LEFT JOIN tasks t ON t.source_file = 'improvement' AND t.title LIKE 'Execute: ' || ip.title
      LEFT JOIN team_members tm ON t.assigned_to = tm.id
      WHERE ip.status = 'completed'
      GROUP BY ip.id
      ORDER BY ip.completed_at DESC
      LIMIT 30
    `).all();
    for (const imp of improvements) {
      let durationSeconds = null;
      const start = imp.work_started_at || imp.completed_at;
      const end = imp.work_completed_at || imp.completed_at;
      if (start && end) {
        durationSeconds = Math.floor((new Date(end.replace(' ', 'T')) - new Date(start.replace(' ', 'T'))) / 1000);
        if (durationSeconds < 0) durationSeconds = 0;
      }
      results.push({
        type: 'improvement',
        id: imp.id,
        title: imp.title,
        status: 'completed',
        member_name: imp.member_name || imp.category || null,
        completed_at: imp.completed_at,
        duration_seconds: durationSeconds,
        source: imp.category || 'site-builder',
        description: imp.description
      });
    }

    // 3. Completed tasks (non-improvement, auto-spawned or manual)
    // FIX: Limit to 50 most recent to prevent 3MB+ responses
    const tasks = db.prepare(`
      SELECT t.id, t.title, t.status, t.completed_at, t.started_at, t.source_file,
        t.current_step, SUBSTR(t.description, 1, 200) as description,
        tm.name as member_name
      FROM tasks t
      LEFT JOIN team_members tm ON t.assigned_to = tm.id
      WHERE t.status IN ('completed', 'delivered')
        AND (t.source_file IS NULL OR t.source_file <> 'improvement')
      ORDER BY COALESCE(t.completed_at, t.updated_at) DESC
      LIMIT 50
    `).all();
    for (const t of tasks) {
      let durationSeconds = null;
      if (t.started_at && t.completed_at) {
        durationSeconds = Math.floor((new Date(t.completed_at.replace(' ', 'T')) - new Date(t.started_at.replace(' ', 'T'))) / 1000);
        if (durationSeconds < 0) durationSeconds = 0;
      }
      results.push({
        type: 'task',
        id: t.id,
        title: t.title.replace(/^Execute: /, ''),
        status: t.status === 'delivered' ? 'completed' : t.status,
        member_name: t.member_name || null,
        completed_at: t.completed_at || t.updated_at,
        duration_seconds: durationSeconds,
        source: t.source_file || 'manual',
        description: t.description
      });
    }

    // Sort all results by completed_at descending
    results.sort(function(a, b) {
      const da = a.completed_at ? new Date(a.completed_at.replace(' ', 'T')) : new Date(0);
      const db2 = b.completed_at ? new Date(b.completed_at.replace(' ', 'T')) : new Date(0);
      return db2 - da;
    });

    res.json(results);
  } catch (err) { next(err); }
});

// GET /api/workspace/sessions — list all sessions (optional ?status=completed,cancelled,failed filter)
app.get('/api/workspace/sessions', (req, res, next) => {
  try {
    let query = `
      SELECT ws.*,
        (SELECT COUNT(*) FROM session_phases sp WHERE sp.session_id = ws.id) as phase_count,
        (SELECT COUNT(*) FROM session_phases sp WHERE sp.session_id = ws.id AND sp.status = 'completed') as completed_phases,
        p.name as project_name, p.color as project_color
      FROM workspace_sessions ws
      LEFT JOIN projects p ON ws.project_id = p.id
    `;
    const params = [];
    if (req.query.status) {
      const statuses = req.query.status.split(',').map(s => s.trim()).filter(Boolean);
      if (statuses.length > 0) {
        query += ` WHERE ws.status IN (${statuses.map(() => '?').join(',')})`;
        params.push(...statuses);
      }
    }
    query += ` ORDER BY ws.created_at DESC`;
    const sessions = db.prepare(query).all(...params);
    res.json(sessions);
  } catch (err) { next(err); }
});

// GET /api/workspace/:id — full session details including phases
app.get('/api/workspace/:id', (req, res, next) => {
  try {
    const id = req.params.id;
    if (id === 'active' || id === 'sessions' || id === 'running-count') return next(); // skip for other routes
    const session = db.prepare('SELECT * FROM workspace_sessions WHERE id = ?').get(id);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    const phases = db.prepare('SELECT * FROM session_phases WHERE session_id = ? ORDER BY phase_number').all(id);
    // Update last_viewed_at
    const now = localNow();
    db.prepare('UPDATE workspace_sessions SET last_viewed_at = ? WHERE id = ?').run(now, id);
    res.json({ ...session, phases });
  } catch (err) { next(err); }
});

// GET /api/workspace/:id/plan — plan with phases
app.get('/api/workspace/:id/plan', (req, res, next) => {
  try {
    const session = db.prepare('SELECT id, title, status, plan_json, plan_markdown FROM workspace_sessions WHERE id = ?').get(req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    const phases = db.prepare('SELECT * FROM session_phases WHERE session_id = ? ORDER BY phase_number').all(req.params.id);
    res.json({ ...session, phases });
  } catch (err) { next(err); }
});

// GET /api/workspace/:id/summary — what happened since last_viewed_at
app.get('/api/workspace/:id/summary', (req, res, next) => {
  try {
    const id = req.params.id;
    const session = db.prepare('SELECT * FROM workspace_sessions WHERE id = ?').get(id);
    if (!session) return res.status(404).json({ error: 'Session not found' });

    const since = session.last_viewed_at || session.created_at;
    const sinceDate = new Date(since.replace(' ', 'T'));
    const nowDate = new Date();
    const hoursElapsed = Math.round(((nowDate - sinceDate) / 3600000) * 10) / 10;

    // Phase stats
    const phases = db.prepare('SELECT * FROM session_phases WHERE session_id = ? ORDER BY phase_number').all(id);
    const phasesCompleted = phases.filter(p => p.status === 'completed' && p.completed_at && p.completed_at > since).length;
    const phasesRunning = phases.filter(p => p.status === 'in_progress').length;
    const phasesRemaining = phases.filter(p => p.status === 'pending').length;

    // Task IDs for this session
    const taskIds = phases.map(p => p.task_id).filter(Boolean);

    let tasksCompleted = 0;
    let filesModified = [];
    let totalEdits = 0;
    let totalReads = 0;
    let errors = 0;

    if (taskIds.length > 0) {
      const placeholders = taskIds.map(() => '?').join(',');

      // Count tasks completed since last view
      tasksCompleted = db.prepare(`SELECT COUNT(*) as c FROM tasks WHERE id IN (${placeholders}) AND status IN ('completed','delivered','review') AND updated_at > ?`).get(...taskIds, since).c;

      // Activity stream events since last view
      const activityCounts = db.prepare(`SELECT event_type, COUNT(*) as cnt FROM agent_activity_stream WHERE task_id IN (${placeholders}) AND created_at > ? GROUP BY event_type`).all(...taskIds, since);
      for (const ac of activityCounts) {
        if (ac.event_type === 'edit' || ac.event_type === 'write') totalEdits += ac.cnt;
        if (ac.event_type === 'read' || ac.event_type === 'grep' || ac.event_type === 'glob') totalReads += ac.cnt;
        if (ac.event_type === 'error') errors += ac.cnt;
      }

      // Files modified
      const files = db.prepare(`SELECT DISTINCT file_name FROM agent_activity_stream WHERE task_id IN (${placeholders}) AND created_at > ? AND file_name IS NOT NULL AND event_type IN ('edit','write')`).all(...taskIds, since);
      filesModified = files.map(f => f.file_name);
    }

    const parts = [];
    if (phasesCompleted > 0) parts.push(`${phasesCompleted} phase${phasesCompleted !== 1 ? 's' : ''} completed`);
    if (phasesRunning > 0) parts.push(`${phasesRunning} running`);
    if (phasesRemaining > 0) parts.push(`${phasesRemaining} remaining`);
    if (tasksCompleted > 0) parts.push(`${tasksCompleted} task${tasksCompleted !== 1 ? 's' : ''} done`);
    if (totalEdits > 0) parts.push(`${totalEdits} file edit${totalEdits !== 1 ? 's' : ''} across ${filesModified.length} file${filesModified.length !== 1 ? 's' : ''}`);
    if (errors > 0) parts.push(`${errors} error${errors !== 1 ? 's' : ''} (auto-retried)`);

    const summaryText = parts.length > 0
      ? `In the last ${hoursElapsed} hours: ${parts.join('. ')}.`
      : `No activity in the last ${hoursElapsed} hours.`;

    res.json({
      since,
      hours_elapsed: hoursElapsed,
      phases_completed: phasesCompleted,
      phases_running: phasesRunning,
      phases_remaining: phasesRemaining,
      tasks_completed: tasksCompleted,
      files_modified: filesModified,
      total_edits: totalEdits,
      total_reads: totalReads,
      errors,
      summary_text: summaryText
    });
  } catch (err) { next(err); }
});

// GET /api/workspace/:id/progress — session-level progress
app.get('/api/workspace/:id/progress', (req, res, next) => {
  try {
    const id = req.params.id;
    const session = db.prepare('SELECT * FROM workspace_sessions WHERE id = ?').get(id);
    if (!session) return res.status(404).json({ error: 'Session not found' });

    const phases = db.prepare('SELECT * FROM session_phases WHERE session_id = ? ORDER BY phase_number').all(id);
    const totalPhases = phases.length;
    const completed = phases.filter(p => p.status === 'completed').length;
    const running = phases.filter(p => p.status === 'in_progress').length;
    const pending = phases.filter(p => p.status === 'pending').length;
    const failed = phases.filter(p => p.status === 'failed').length;
    const overallProgress = totalPhases > 0 ? Math.round((completed / totalPhases) * 1000) / 10 : 0;

    // Estimate remaining time based on average phase duration
    let estimatedRemaining = null;
    const completedPhases = phases.filter(p => p.status === 'completed' && p.started_at && p.completed_at);
    if (completedPhases.length > 0) {
      const avgDurationMs = completedPhases.reduce((sum, p) => {
        return sum + (new Date(p.completed_at.replace(' ', 'T')) - new Date(p.started_at.replace(' ', 'T')));
      }, 0) / completedPhases.length;
      const remainingPhases = pending + running;
      const estMs = avgDurationMs * remainingPhases;
      const estMin = Math.ceil(estMs / 60000);
      estimatedRemaining = estMin > 60 ? `~${Math.round(estMin / 60)}h ${estMin % 60}m` : `~${estMin} minutes`;
    }

    const phaseDetails = phases.map(p => {
      let duration = null;
      if (p.started_at && p.completed_at) {
        const diff = Math.floor((new Date(p.completed_at.replace(' ', 'T')) - new Date(p.started_at.replace(' ', 'T'))) / 1000);
        const m = Math.floor(diff / 60);
        duration = m > 0 ? `${m}m` : `${diff}s`;
      }
      // Get task progress if running
      let progress = 0;
      let currentStep = null;
      if (p.task_id) {
        const task = db.prepare('SELECT progress, current_step FROM tasks WHERE id = ?').get(p.task_id);
        if (task) {
          progress = task.progress || 0;
          currentStep = task.current_step || null;
        }
      }
      if (p.status === 'completed') progress = 100;
      return {
        number: p.phase_number,
        title: p.title,
        status: p.status,
        duration,
        progress,
        current_step: currentStep,
        assigned_member: p.assigned_member_name
      };
    });

    res.json({
      session_status: session.status,
      total_phases: totalPhases,
      completed,
      running,
      pending,
      failed,
      overall_progress: overallProgress,
      estimated_remaining: estimatedRemaining,
      phases: phaseDetails
    });
  } catch (err) { next(err); }
});

// GET /api/workspace/running-count — count of running agents for sidebar badge
app.get('/api/workspace/running-count', (req, res, next) => {
  try {
    const count = db.prepare(`SELECT COUNT(*) as c FROM active_processes WHERE status = 'running'`).get().c;
    res.json({ count });
  } catch (err) { next(err); }
});

// PUT /api/workspace/:id/plan — edit plan phases or approve
app.put('/api/workspace/:id/plan', (req, res, next) => {
  try {
    const session = db.prepare('SELECT * FROM workspace_sessions WHERE id = ?').get(req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });

    const { action, phases } = req.body;
    const now = localNow();

    if (action === 'approve') {
      db.prepare('UPDATE workspace_sessions SET status = ?, updated_at = ? WHERE id = ?')
        .run('approved', now, req.params.id);
      broadcast('workspace.approved', { session_id: Number(req.params.id) });
      return res.json({ success: true, status: 'approved' });
    }

    if (action === 'redigest') {
      // Delete existing phases and redigest
      db.prepare('DELETE FROM session_phases WHERE session_id = ?').run(req.params.id);
      db.prepare('UPDATE workspace_sessions SET status = ?, plan_json = NULL, plan_markdown = NULL, updated_at = ? WHERE id = ?')
        .run('digesting', now, req.params.id);
      setImmediate(() => digestSessionPrompt(Number(req.params.id)));
      broadcast('workspace.redigesting', { session_id: Number(req.params.id) });
      return res.json({ success: true, status: 'digesting' });
    }

    // Update phases
    if (phases && Array.isArray(phases)) {
      // Delete existing and re-insert
      db.prepare('DELETE FROM session_phases WHERE session_id = ?').run(req.params.id);

      for (const phase of phases) {
        const member = phase.assigned_member_name
          ? db.prepare('SELECT id FROM team_members WHERE LOWER(name) = LOWER(?)').get(phase.assigned_member_name)
          : null;

        db.prepare(`INSERT INTO session_phases (session_id, phase_number, title, description, assigned_member_id, assigned_member_name, complexity, depends_on, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
          .run(req.params.id, phase.phase_number, phase.title, phase.description || '', member ? member.id : (phase.assigned_member_id || null), phase.assigned_member_name || '', phase.complexity || 'moderate', JSON.stringify(phase.depends_on || []), phase.status || 'pending', now, now);
      }

      // Rebuild plan markdown
      let planMd = `# Execution Plan\n\n`;
      for (const phase of phases) {
        planMd += `## Phase ${phase.phase_number}: ${phase.title}\n`;
        planMd += `**Assigned:** ${phase.assigned_member_name} | **Complexity:** ${phase.complexity}\n`;
        const deps = phase.depends_on || [];
        if (deps.length > 0) {
          planMd += `**Depends on:** Phase${deps.length > 1 ? 's' : ''} ${deps.join(', ')}\n`;
        }
        planMd += `\n${phase.description}\n\n`;
      }

      db.prepare('UPDATE workspace_sessions SET plan_json = ?, plan_markdown = ?, updated_at = ? WHERE id = ?')
        .run(JSON.stringify(phases), planMd, now, req.params.id);
    }

    res.json({ success: true });
  } catch (err) { next(err); }
});

// POST /api/workspace/:id/execute — start executing the plan
app.post('/api/workspace/:id/execute', async (req, res, next) => {
  try {
    const session = db.prepare('SELECT * FROM workspace_sessions WHERE id = ?').get(req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    if (session.status !== 'approved' && session.status !== 'pending_approval') {
      return res.status(400).json({ error: 'Session must be approved before execution' });
    }

    const now = localNow();
    const phases = db.prepare('SELECT * FROM session_phases WHERE session_id = ? ORDER BY phase_number').all(req.params.id);

    if (phases.length === 0) return res.status(400).json({ error: 'No phases to execute' });

    // Update session status
    db.prepare('UPDATE workspace_sessions SET status = ?, updated_at = ? WHERE id = ?')
      .run('executing', now, req.params.id);

    broadcast('workspace.executing', { session_id: Number(req.params.id) });

    // Find phases with no dependencies (or all deps completed)
    const launchable = [];
    for (const phase of phases) {
      const deps = JSON.parse(phase.depends_on || '[]');
      if (deps.length === 0) {
        launchable.push(phase);
      } else {
        // Check if all deps are completed
        const completedDeps = db.prepare(`SELECT COUNT(*) as c FROM session_phases WHERE session_id = ? AND phase_number IN (${deps.map(() => '?').join(',')}) AND status = 'completed'`)
          .get(req.params.id, ...deps);
        if (completedDeps.c === deps.length) {
          launchable.push(phase);
        }
      }
    }

    const spawned = [];
    for (const phase of launchable) {
      // Create a task for this phase
      const taskResult = db.prepare(`INSERT INTO tasks (title, description, status, priority, assigned_to, created_at, updated_at) VALUES (?,?,?,?,?,?,?)`)
        .run(`[Session #${req.params.id}] Phase ${phase.phase_number}: ${phase.title}`, phase.description || '', 'in_progress', session.priority || 'normal', phase.assigned_member_id, now, now);

      const taskId = Number(taskResult.lastInsertRowid);

      // Link task to phase
      db.prepare('UPDATE session_phases SET task_id = ?, status = ?, started_at = ?, updated_at = ? WHERE id = ?')
        .run(taskId, 'in_progress', now, now, phase.id);

      // Link task to project if session has one
      if (session.project_id) {
        db.prepare('INSERT OR IGNORE INTO project_tasks (project_id, task_id) VALUES (?,?)').run(session.project_id, taskId);
      }

      // Spawn the member
      if (phase.assigned_member_id) {
        spawnMemberTerminal(taskId, phase.assigned_member_id).catch(err => {
          console.error(`[Workspace] Failed to spawn for phase ${phase.phase_number}: ${err.message}`);
        });
      }

      spawned.push({ phase_number: phase.phase_number, task_id: taskId, member: phase.assigned_member_name });
    }

    createNotification('system', 'Execution Started', `"${session.title}" execution started with ${spawned.length} initial phase(s)`);

    res.json({ success: true, status: 'executing', spawned });
  } catch (err) { next(err); }
});

// POST /api/workspace/:id/pause — pause entire session
app.post('/api/workspace/:id/pause', (req, res, next) => {
  try {
    const session = db.prepare('SELECT * FROM workspace_sessions WHERE id = ?').get(req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });

    const now = localNow();

    // Kill all running processes for this session's phases
    const runningPhases = db.prepare(`
      SELECT sp.*, t.id as tid FROM session_phases sp
      JOIN tasks t ON sp.task_id = t.id
      WHERE sp.session_id = ? AND sp.status = 'in_progress'
    `).all(req.params.id);

    for (const phase of runningPhases) {
      // Kill running processes
      const procs = db.prepare('SELECT id FROM active_processes WHERE task_id = ? AND status = ?').all(phase.tid, 'running');
      for (const proc of procs) {
        const info = runningProcesses.get(proc.id);
        if (info && info.child) {
          try { info.child.kill('SIGTERM'); } catch {}
          runningProcesses.delete(proc.id);
        }
        db.prepare('UPDATE active_processes SET status = ?, completed_at = ?, output_summary = ? WHERE id = ?')
          .run('killed', now, 'Session paused', proc.id);
      }
      db.prepare('UPDATE session_phases SET status = ?, updated_at = ? WHERE id = ?').run('pending', now, phase.id);
      db.prepare('UPDATE tasks SET status = ?, current_step = ?, updated_at = ? WHERE id = ?').run('new', 'Session paused', now, phase.tid);
    }

    db.prepare('UPDATE workspace_sessions SET status = ?, updated_at = ? WHERE id = ?').run('approved', now, req.params.id);
    broadcast('workspace.paused', { session_id: Number(req.params.id) });
    res.json({ success: true, message: 'Session paused' });
  } catch (err) { next(err); }
});

// POST /api/workspace/:id/cancel — cancel entire session
app.post('/api/workspace/:id/cancel', (req, res, next) => {
  try {
    const session = db.prepare('SELECT * FROM workspace_sessions WHERE id = ?').get(req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });

    const now = localNow();

    // Kill all running processes
    const allPhases = db.prepare(`
      SELECT sp.*, t.id as tid FROM session_phases sp
      LEFT JOIN tasks t ON sp.task_id = t.id
      WHERE sp.session_id = ?
    `).all(req.params.id);

    for (const phase of allPhases) {
      if (phase.tid) {
        const procs = db.prepare('SELECT id FROM active_processes WHERE task_id = ? AND status = ?').all(phase.tid, 'running');
        for (const proc of procs) {
          const info = runningProcesses.get(proc.id);
          if (info && info.child) {
            try { info.child.kill('SIGTERM'); } catch {}
            runningProcesses.delete(proc.id);
          }
          db.prepare('UPDATE active_processes SET status = ?, completed_at = ?, output_summary = ? WHERE id = ?')
            .run('killed', now, 'Session cancelled', proc.id);
        }
      }
      if (phase.status !== 'completed') {
        db.prepare('UPDATE session_phases SET status = ?, updated_at = ? WHERE id = ?').run('skipped', now, phase.id);
      }
    }

    db.prepare('UPDATE workspace_sessions SET status = ?, updated_at = ? WHERE id = ?').run('cancelled', now, req.params.id);
    broadcast('workspace.cancelled', { session_id: Number(req.params.id) });
    res.json({ success: true, message: 'Session cancelled' });
  } catch (err) { next(err); }
});

// GET /api/workspaces
app.get('/api/workspaces', (req, res) => {
  try {
    const workspaces = db.prepare(`
      SELECT ew.*, tm.name as member_name, t.title as task_title
      FROM execution_workspaces ew
      LEFT JOIN team_members tm ON ew.member_id = tm.id
      LEFT JOIN tasks t ON ew.task_id = t.id
      WHERE ew.status != 'deleted'
      ORDER BY ew.created_at DESC
    `).all();
    res.json(workspaces);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/workspaces
app.post('/api/workspaces', (req, res) => {
  try {
    const { name, member_id, task_id, workspace_path, branch_name, base_branch } = req.body;
    if (!name) return res.status(400).json({ error: 'name is required' });
    const now = localNow();
    const result = db.prepare(`INSERT INTO execution_workspaces (name, member_id, task_id, workspace_path, branch_name, base_branch, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)`)
      .run(name, member_id || null, task_id || null, workspace_path || null, branch_name || null, base_branch || 'main', now, now);
    // Log the create operation
    db.prepare('INSERT INTO workspace_operations (workspace_id, operation_type, detail, created_at) VALUES (?,?,?,?)')
      .run(result.lastInsertRowid, 'create', `Created workspace "${name}"`, now);
    const workspace = db.prepare('SELECT * FROM execution_workspaces WHERE id = ?').get(result.lastInsertRowid);
    broadcast('workspace.created', workspace);
    res.status(201).json(workspace);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/workspaces/:id
app.get('/api/workspaces/:id', (req, res) => {
  try {
    const ws = db.prepare(`
      SELECT ew.*, tm.name as member_name, t.title as task_title
      FROM execution_workspaces ew
      LEFT JOIN team_members tm ON ew.member_id = tm.id
      LEFT JOIN tasks t ON ew.task_id = t.id
      WHERE ew.id = ?
    `).get(Number(req.params.id));
    if (!ws) return res.status(404).json({ error: 'Workspace not found' });
    ws.operations = db.prepare('SELECT * FROM workspace_operations WHERE workspace_id = ? ORDER BY created_at DESC LIMIT 50').all(ws.id);
    res.json(ws);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// DELETE /api/workspaces/:id
app.delete('/api/workspaces/:id', (req, res) => {
  try {
    const id = Number(req.params.id);
    const now = localNow();
    db.prepare("UPDATE execution_workspaces SET status = 'deleted', updated_at = ? WHERE id = ?").run(now, id);
    db.prepare('INSERT INTO workspace_operations (workspace_id, operation_type, detail, created_at) VALUES (?,?,?,?)')
      .run(id, 'delete', 'Workspace archived/deleted', now);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/workspaces/:id/operations
app.get('/api/workspaces/:id/operations', (req, res) => {
  try {
    const ops = db.prepare('SELECT * FROM workspace_operations WHERE workspace_id = ? ORDER BY created_at DESC LIMIT 100').all(Number(req.params.id));
    res.json(ops);
  } catch (err) { res.status(500).json({ error: err.message }); }
});


};
