'use strict';
const path = require('path');
const fs = require('fs');
module.exports = function(app, db, helpers) {
  const { broadcast, localNow, createNotification, authRateLimiter, apiRateLimiter, spawnMemberTerminal } = helpers;
  const stmt = helpers.stmt || ((sql) => db.prepare(sql));

app.get('/api/org-chart', (req, res) => {
  try {
    const members = db.prepare(`
      SELECT m.id, m.name, m.role, m.tier, m.department, m.reports_to, m.status, m.icon,
        boss.name as reports_to_name,
        (SELECT COUNT(*) FROM tasks t WHERE t.assigned_to = m.id AND t.status NOT IN ('completed','delivered')) as active_task_count,
        (SELECT COUNT(*) FROM active_processes ap WHERE ap.member_id = m.id AND ap.status = 'running') as running_processes
      FROM team_members m
      LEFT JOIN team_members boss ON m.reports_to = boss.id
      WHERE m.status = 'active'
      ORDER BY m.name
    `).all();

    // Separate by tier
    const chairman = members.find(m => m.tier === 'board' && m.name === 'Max Stewart') || null;
    const board = members.filter(m => m.tier === 'board' && m.name !== 'Max Stewart');
    const csuite = members.filter(m => m.tier === 'c-suite');
    const specialists = members.filter(m => m.tier === 'specialist');

    // Walk the reports_to chain to group specialists under their c-suite executive
    const memberMap = buildMemberMap(members);
    const departments = {};
    for (const exec of csuite) {
      departments[exec.id] = {
        executive: exec,
        members: []
      };
    }
    const unassigned = [];
    for (const spec of specialists) {
      if (!spec.reports_to) { unassigned.push(spec); continue; }
      const exec = findCsuiteExec(spec.reports_to, memberMap);
      if (exec && departments[exec.id]) {
        departments[exec.id].members.push(spec);
      } else {
        unassigned.push(spec);
      }
    }

    // Group specialists by department name as well (for display)
    const deptByName = {};
    for (const spec of specialists) {
      const dept = spec.department || 'Unassigned';
      if (!deptByName[dept]) deptByName[dept] = [];
      deptByName[dept].push(spec);
    }

    res.json({
      chairman,
      board,
      csuite,
      specialists,
      departments,
      departmentsByName: deptByName,
      unassigned,
      stats: {
        total: members.length,
        board_count: board.length + (chairman ? 1 : 0),
        csuite_count: csuite.length,
        specialist_count: specialists.length,
        dept_count: Object.keys(deptByName).length
      }
    });
  } catch (err) {
    console.error('GET /api/org-chart error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/org-chart/projects', (req, res) => {
  try {
    const projects = db.prepare(`
      SELECT p.id, p.name, p.status, p.color, p.summary,
        pe.member_id as exec_member_id,
        tm.name as exec_name, tm.role as exec_role, tm.icon as exec_icon,
        (SELECT COUNT(*) FROM project_affinity pa WHERE pa.project_id = p.id AND pa.status = 'active') as team_count,
        (SELECT COUNT(*) FROM project_tasks pt JOIN tasks t ON pt.task_id = t.id WHERE pt.project_id = p.id AND t.status NOT IN ('completed','delivered')) as active_tasks
      FROM projects p
      LEFT JOIN project_executives pe ON pe.project_id = p.id
      LEFT JOIN team_members tm ON pe.member_id = tm.id
      WHERE p.status = 'active'
      ORDER BY p.name
    `).all();

    res.json(projects);
  } catch (err) {
    console.error('GET /api/org-chart/projects error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/org-chart/companies', (req, res) => {
  try {
    const companies = db.prepare(`
      SELECT c.id, c.name, c.status, c.color, c.description,
        c.ceo_member_id, c.cto_member_id,
        (SELECT tm.name FROM team_members tm WHERE tm.id = c.ceo_member_id) as ceo_name,
        (SELECT tm.name FROM team_members tm WHERE tm.id = c.cto_member_id) as cto_name,
        (SELECT COUNT(*) FROM company_members cm WHERE cm.company_id = c.id AND cm.status = 'active') as member_count,
        (SELECT COUNT(*) FROM projects p WHERE p.company_id = c.id AND p.status = 'active') as project_count
      FROM companies c
      WHERE c.status = 'active'
      ORDER BY c.name
    `).all();
    res.json(companies);
  } catch (err) {
    console.error('GET /api/org-chart/companies error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/org-chart/project/:id', (req, res) => {
  try {
    const projectId = parseInt(req.params.id);
    const project = db.prepare(`SELECT * FROM projects WHERE id = ?`).get(projectId);
    if (!project) return res.status(404).json({ error: 'Project not found' });

    // Get project executive
    const execRow = db.prepare(`
      SELECT pe.*, tm.name, tm.role, tm.tier, tm.department, tm.icon, tm.status,
        (SELECT COUNT(*) FROM tasks t WHERE t.assigned_to = tm.id AND t.status NOT IN ('completed','delivered')) as active_task_count,
        (SELECT COUNT(*) FROM active_processes ap WHERE ap.member_id = tm.id AND ap.status = 'running') as running_processes
      FROM project_executives pe
      JOIN team_members tm ON pe.member_id = tm.id
      WHERE pe.project_id = ?
    `).get(projectId);

    // Get all team members with affinity to this project
    const affinityMembers = db.prepare(`
      SELECT pa.role_in_project, pa.hours_worked, pa.tasks_completed as affinity_tasks_completed,
        pa.status as affinity_status,
        tm.id, tm.name, tm.role, tm.tier, tm.department, tm.icon, tm.status,
        (SELECT COUNT(*) FROM tasks t WHERE t.assigned_to = tm.id AND t.status NOT IN ('completed','delivered')) as active_task_count,
        (SELECT COUNT(*) FROM active_processes ap WHERE ap.member_id = tm.id AND ap.status = 'running') as running_processes
      FROM project_affinity pa
      JOIN team_members tm ON pa.member_id = tm.id
      WHERE pa.project_id = ? AND pa.status = 'active' AND pa.role_in_project != 'executive'
      ORDER BY tm.department, tm.name
    `).all(projectId);

    // Also find members who have worked on tasks linked to this project
    const taskMembers = db.prepare(`
      SELECT DISTINCT tm.id, tm.name, tm.role, tm.tier, tm.department, tm.icon, tm.status,
        COUNT(DISTINCT ta.task_id) as project_tasks,
        (SELECT COUNT(*) FROM tasks t WHERE t.assigned_to = tm.id AND t.status NOT IN ('completed','delivered')) as active_task_count,
        (SELECT COUNT(*) FROM active_processes ap WHERE ap.member_id = tm.id AND ap.status = 'running') as running_processes
      FROM task_assignments ta
      JOIN tasks t ON ta.task_id = t.id
      JOIN project_tasks pt ON pt.task_id = t.id AND pt.project_id = ?
      JOIN team_members tm ON ta.member_id = tm.id
      WHERE tm.status = 'active'
      GROUP BY tm.id
      ORDER BY project_tasks DESC
    `).all(projectId);

    // Merge affinity + task-based members (affinity takes priority)
    const seenIds = new Set(affinityMembers.map(m => m.id));
    if (execRow) seenIds.add(execRow.member_id);
    const additionalFromTasks = taskMembers.filter(m => !seenIds.has(m.id));

    const allTeam = [...affinityMembers, ...additionalFromTasks];

    // Group by department
    const deptGroups = {};
    for (const m of allTeam) {
      const dept = m.department || 'General';
      if (!deptGroups[dept]) deptGroups[dept] = [];
      deptGroups[dept].push(m);
    }

    res.json({
      project,
      executive: execRow || null,
      team: allTeam,
      departmentGroups: deptGroups,
      stats: {
        team_size: allTeam.length + (execRow ? 1 : 0),
        dept_count: Object.keys(deptGroups).length,
        from_affinity: affinityMembers.length,
        from_tasks: additionalFromTasks.length
      }
    });
  } catch (err) {
    console.error('GET /api/org-chart/project/:id error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/export/tasks', (req, res) => {
  try {
    const format = (req.query.format || 'json').toLowerCase();
    const rows = db.prepare(`
      SELECT t.id, t.title, t.description, t.status, t.priority,
             t.source_file, t.revision_count, t.original_priority,
             t.downgraded_by, t.downgraded_at,
             tm.name as assignee_name, t.created_at, t.updated_at
      FROM tasks t
      LEFT JOIN team_members tm ON t.assigned_to = tm.id
      ORDER BY t.created_at DESC
    `).all();
    const cols = ['id','title','description','status','priority','assignee_name','source_file','revision_count','original_priority','downgraded_by','downgraded_at','created_at','updated_at'];
    sendExport(res, rows, cols, format, 'tasks');
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/export/notes', (req, res) => {
  try {
    const format = (req.query.format || 'json').toLowerCase();
    const rows = db.prepare(`
      SELECT id, title, content, created_at, updated_at FROM notes ORDER BY created_at DESC
    `).all();
    const cols = ['id','title','content','created_at','updated_at'];
    sendExport(res, rows, cols, format, 'notes');
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/export/activity', (req, res) => {
  try {
    const format = (req.query.format || 'json').toLowerCase();
    const rows = db.prepare(`
      SELECT a.id, a.actor, a.action, a.notes, a.task_id,
             t.title as task_title, a.created_at
      FROM activity_log a
      LEFT JOIN tasks t ON a.task_id = t.id
      ORDER BY a.created_at DESC
    `).all();
    const cols = ['id','actor','action','notes','task_id','task_title','created_at'];
    sendExport(res, rows, cols, format, 'activity');
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/export/calendar', (req, res) => {
  try {
    const format = (req.query.format || 'json').toLowerCase();
    const rows = db.prepare(`
      SELECT e.id, e.title, e.description, e.start_time, e.end_time,
             e.all_day, e.calendar_type, e.source, e.location,
             e.recurrence, e.status, p.name as project_name,
             e.created_at, e.updated_at
      FROM calendar_events e
      LEFT JOIN projects p ON e.project_id = p.id
      ORDER BY e.start_time ASC
    `).all();
    const cols = ['id','title','description','start_time','end_time','all_day','calendar_type','source','location','recurrence','status','project_name','created_at','updated_at'];
    sendExport(res, rows, cols, format, 'calendar');
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/export/contacts', (req, res) => {
  try {
    const format = (req.query.format || 'json').toLowerCase();
    const rows = db.prepare(`
      SELECT id, name, role, company, email, phone, notes, created_at, updated_at
      FROM contacts
      ORDER BY name ASC
    `).all();
    const cols = ['id','name','role','company','email','phone','notes','created_at','updated_at'];
    sendExport(res, rows, cols, format, 'contacts');
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/system/local-mode', (req, res) => {
    res.json({ enabled: isLocalMode() });
});

app.post('/api/system/local-mode', authRateLimiter, (req, res) => {
    const { enabled } = req.body;
    const value = enabled ? '1' : '0';
    db.prepare(`INSERT OR REPLACE INTO system_settings (key, value, updated_at) VALUES ('local_mode', ?, ?)`).run(value, localNow());

    if (enabled) {
        // Kill all running processes gracefully
        const running = db.prepare("SELECT pid FROM active_processes WHERE status = 'running' AND pid IS NOT NULL").all();
        for (const proc of running) {
            try { process.kill(proc.pid, 'SIGTERM'); } catch (_) {}
        }
        db.prepare("UPDATE active_processes SET status = 'paused' WHERE status = 'running'").run();
    } else {
    }

    broadcast('system.mode_changed', { local_mode: enabled });
    res.json({ local_mode: enabled, message: enabled ? 'Local mode ON — AI features disabled, UI fully functional' : 'Local mode OFF — AI features enabled' });
});

app.get('/api/system/health', (req, res) => {
    const now = localNow();

    // Server uptime
    const uptimeSeconds = process.uptime();
    const uptimeHours = (uptimeSeconds / 3600).toFixed(1);

    // Database stats
    const dbStats = {
        tables: db.prepare("SELECT COUNT(*) as c FROM sqlite_master WHERE type='table'").get().c,
        size_mb: (fs.statSync(process.env.DB_PATH || path.join(__dirname, '..', 'the_team.db')).size / 1024 / 1024).toFixed(1),
        total_rows: 0
    };

    // Key table row counts
    const tableCounts = {};
    const keyTables = ['team_members','tasks','improvement_proposals','active_processes','activity_log','notifications','governance_receipts','context_store','agent_activity_stream','agent_memory_entities','agent_daily_notes','projects','workspace_sessions','session_phases','review_panel_votes','heartbeat_runs','cost_events','budget_policies','approvals','goals','task_comments','routines','plugins','eval_suites','eval_runs','skills','adapter_types','emergency_protocols','contestations','conflict_records'];
    for (const t of keyTables) {
        try {
            const count = db.prepare(`SELECT COUNT(*) as c FROM ${t}`).get().c;
            tableCounts[t] = count;
            dbStats.total_rows += count;
        } catch (_) { tableCounts[t] = 'N/A'; }
    }

    // Team stats
    const teamStats = {
        total: db.prepare("SELECT COUNT(*) as c FROM team_members WHERE status='active'").get().c,
        by_tier: db.prepare("SELECT tier, COUNT(*) as c FROM team_members WHERE status='active' GROUP BY tier").all(),
        retired: db.prepare("SELECT COUNT(*) as c FROM team_members WHERE status='retired'").get().c,
        with_identity_files: db.prepare("SELECT COUNT(DISTINCT member_id) as c FROM agent_identity_files").get().c,
        with_memory: db.prepare("SELECT COUNT(DISTINCT member_id) as c FROM agent_memory_entities").get().c
    };

    // Task stats
    const taskStats = {
        total: db.prepare("SELECT COUNT(*) as c FROM tasks").get().c,
        by_status: db.prepare("SELECT status, COUNT(*) as c FROM tasks GROUP BY status").all(),
        completed_today: db.prepare("SELECT COUNT(*) as c FROM tasks WHERE status IN ('completed','delivered') AND date(completed_at) = date(?)").get(now).c,
        completed_week: db.prepare("SELECT COUNT(*) as c FROM tasks WHERE status IN ('completed','delivered') AND completed_at > datetime(?, '-7 days')").get(now).c
    };

    // Improvement pipeline
    const pipelineStats = {
        total: db.prepare("SELECT COUNT(*) as c FROM improvement_proposals").get().c,
        by_status: db.prepare("SELECT status, COUNT(*) as c FROM improvement_proposals GROUP BY status").all(),
        completed_today: db.prepare("SELECT COUNT(*) as c FROM improvement_proposals WHERE status='completed' AND date(completed_at)=date(?)").get(now).c,
        autonomous_enabled: db.prepare("SELECT value FROM system_settings WHERE key='autonomous_improvements'").get()?.value === '1',
        queue_length: db.prepare("SELECT COUNT(*) as c FROM improvement_proposals WHERE status='queued'").get().c,
        chamber_pool: db.prepare("SELECT COUNT(*) as c FROM improvement_proposals WHERE status='proposed'").get().c
    };

    // Process stats
    const processStats = {
        total: db.prepare("SELECT COUNT(*) as c FROM active_processes").get().c,
        running: db.prepare("SELECT COUNT(*) as c FROM active_processes WHERE status='running'").get().c,
        completed: db.prepare("SELECT COUNT(*) as c FROM active_processes WHERE status='completed'").get().c,
        failed: db.prepare("SELECT COUNT(*) as c FROM active_processes WHERE status='failed'").get().c,
        success_rate: 0
    };
    const totalFinished = processStats.completed + processStats.failed;
    processStats.success_rate = totalFinished > 0 ? Math.round((processStats.completed / totalFinished) * 100) : 0;

    // Governance health
    let govHealth = { status: 'unknown', score: 0, checks: [] };
    try {
        const latestChecks = db.prepare("SELECT check_type, status, score, details FROM governance_health ORDER BY id DESC LIMIT 6").all();
        const avgScore = latestChecks.length > 0 ? latestChecks.reduce((s, c) => s + c.score, 0) / latestChecks.length : 0;
        govHealth = {
            status: avgScore > 0.8 ? 'healthy' : avgScore > 0.5 ? 'degraded' : 'critical',
            score: Math.round(avgScore * 100),
            checks: latestChecks
        };
    } catch (_) {}

    // Context stats
    const contextStats = {
        total: db.prepare("SELECT COUNT(*) as c FROM context_store WHERE status='active'").get().c,
        by_scope: db.prepare("SELECT scope, COUNT(*) as c FROM context_store WHERE status='active' GROUP BY scope").all(),
        dept_summaries: db.prepare("SELECT COUNT(*) as c FROM department_summaries").get().c
    };

    // Project stats
    const projectStats = {
        total: db.prepare("SELECT COUNT(*) as c FROM projects WHERE status='active'").get().c,
        with_executives: db.prepare("SELECT COUNT(*) as c FROM project_executives").get().c,
        governed: db.prepare("SELECT COUNT(*) as c FROM projects WHERE exochain_governed=1").get().c
    };

    // API endpoint count (approximate from route count)
    const endpointCount = 38;

    // Notification stats
    const notifStats = {
        total: db.prepare("SELECT COUNT(*) as c FROM notifications").get().c,
        unread: db.prepare("SELECT COUNT(*) as c FROM notifications WHERE read=0").get().c
    };

    // Workspace stats
    const workspaceStats = {
        sessions: db.prepare("SELECT COUNT(*) as c FROM workspace_sessions").get().c,
        phases: db.prepare("SELECT COUNT(*) as c FROM session_phases").get().c
    };

    // Budget stats
    let budgetStats = { spent_today: 0, spent_month: 0, limit: 0 };
    try {
        budgetStats.spent_today = db.prepare("SELECT COALESCE(SUM(cost_cents),0) as c FROM cost_events WHERE date(created_at)=date(?)").get(now).c;
        budgetStats.spent_month = db.prepare("SELECT COALESCE(SUM(cost_cents),0) as c FROM cost_events WHERE strftime('%Y-%m',created_at)=strftime('%Y-%m',?)").get(now).c;
        const policy = db.prepare("SELECT limit_cents FROM budget_policies WHERE scope='global' AND status='active' LIMIT 1").get();
        budgetStats.limit = policy ? policy.limit_cents : 0;
    } catch (_) {}

    // Token usage stats
    let tokenUsage = { today: { cost: 0, tokens: 0 }, this_week: { cost: 0, tokens: 0 }, total: { cost: 0, tokens: 0 }, by_member: [] };
    try {
        tokenUsage.today = db.prepare("SELECT COALESCE(SUM(cost_cents),0) as cost, COALESCE(SUM(total_tokens),0) as tokens FROM cost_events WHERE date(created_at) = date(?)").get(now);
        tokenUsage.this_week = db.prepare("SELECT COALESCE(SUM(cost_cents),0) as cost, COALESCE(SUM(total_tokens),0) as tokens FROM cost_events WHERE created_at > datetime(?, '-7 days')").get(now);
        tokenUsage.total = db.prepare("SELECT COALESCE(SUM(cost_cents),0) as cost, COALESCE(SUM(total_tokens),0) as tokens FROM cost_events").get();
        tokenUsage.by_member = db.prepare("SELECT tm.name, COALESCE(SUM(ce.cost_cents),0) as cost, COALESCE(SUM(ce.total_tokens),0) as tokens FROM cost_events ce JOIN team_members tm ON ce.member_id = tm.id GROUP BY ce.member_id ORDER BY cost DESC LIMIT 10").all();
    } catch (_) {}

    // Skills and adapters
    const skillCount = db.prepare("SELECT COUNT(*) as c FROM skills WHERE status='active'").get().c;
    const adapterCount = db.prepare("SELECT COUNT(*) as c FROM adapter_types WHERE status='active'").get().c;

    // Emergency protocols
    const emergencyStats = {
        total: db.prepare("SELECT COUNT(*) as c FROM emergency_protocols").get().c,
        armed: db.prepare("SELECT COUNT(*) as c FROM emergency_protocols WHERE status='armed'").get().c,
        activated: db.prepare("SELECT COUNT(*) as c FROM emergency_protocols WHERE status='activated'").get().c
    };

    // Work distribution score (0-100, higher = more even)
    let distributionStats = { score: 0, members_with_work: 0, total_eligible: 0, top_5: [], bottom_5: [] };
    try {
        const distRows = db.prepare(`
            SELECT tm.name,
                (SELECT COUNT(*) FROM active_processes WHERE member_id = tm.id AND status = 'completed') as tasks
            FROM team_members tm
            WHERE tm.status = 'active' AND tm.tier = 'specialist'
            ORDER BY tasks DESC
        `).all();

        const taskCounts = distRows.map(d => d.tasks).filter(t => t > 0);
        const membersWithWork = taskCounts.length;
        const totalEligible = distRows.length;
        const distributionScore = totalEligible > 0 ? Math.round((membersWithWork / totalEligible) * 100) : 0;

        distributionStats = {
            score: distributionScore,
            members_with_work: membersWithWork,
            total_eligible: totalEligible,
            top_5: distRows.slice(0, 5).map(d => ({ name: d.name, tasks: d.tasks })),
            bottom_5: distRows.slice(-5).map(d => ({ name: d.name, tasks: d.tasks }))
        };
    } catch (_) {}

    res.json({
        server: { uptime_hours: uptimeHours, uptime_seconds: Math.round(uptimeSeconds), port: process.env.PORT || 3000, node_version: process.version, timestamp: now },
        database: { ...dbStats, tables_detail: tableCounts },
        team: teamStats,
        tasks: taskStats,
        pipeline: pipelineStats,
        processes: processStats,
        governance: govHealth,
        context: contextStats,
        projects: projectStats,
        workspace: workspaceStats,
        budget: budgetStats,
        token_usage: tokenUsage,
        notifications: notifStats,
        endpoints: endpointCount,
        skills: skillCount,
        adapters: adapterCount,
        emergencies: emergencyStats,
        distribution: distributionStats,
        local_mode: isLocalMode()
    });
});

app.get('/api/system-status', (req, res) => {
  try {
    const uptimeSeconds = Math.floor((Date.now() - SERVER_START_TIME) / 1000);
    const uptimeDays = Math.floor(uptimeSeconds / 86400);
    const uptimeHours = Math.floor((uptimeSeconds % 86400) / 3600);
    const uptimeMinutes = Math.floor((uptimeSeconds % 3600) / 60);
    const uptimeSecondsRemainder = uptimeSeconds % 60;
    const uptimeHuman = [
      uptimeDays > 0 ? `${uptimeDays}d` : null,
      uptimeHours > 0 || uptimeDays > 0 ? `${uptimeHours}h` : null,
      `${uptimeMinutes}m`,
      `${uptimeSecondsRemainder}s`
    ].filter(Boolean).join(' ');

    let dbHealthy = true;
    try { db.prepare('SELECT 1').get(); } catch (_) { dbHealthy = false; }

    const activeAgents = (() => {
      try { return db.prepare(`SELECT COUNT(*) as c FROM active_processes WHERE status = 'running'`).get().c; } catch (_) { return 0; }
    })();

    const deliveredToday = (() => {
      try {
        return db.prepare(`
          SELECT COUNT(*) as c FROM tasks
          WHERE status IN ('completed', 'delivered')
            AND date(updated_at) = date('now', 'localtime')
        `).get().c;
      } catch (_) { return 0; }
    })();

    res.json({
      uptime: uptimeHuman,
      db_healthy: dbHealthy,
      active_agents: activeAgents,
      tasks_delivered_today: deliveredToday
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/export', (req, res) => {
  try {
    const type = req.query.type || 'tasks';
    const format = req.query.format === 'csv' ? 'csv' : 'json';

    const ALLOWED_TYPES = ['tasks', 'notes', 'contacts', 'activity'];
    if (!ALLOWED_TYPES.includes(type)) {
      return res.status(400).json({ error: 'Invalid type. Must be one of: ' + ALLOWED_TYPES.join(', ') });
    }

    let rows = [];
    const now = new Date().toISOString().slice(0, 10);
    const filename = `${type}_export_${now}.${format}`;

    if (type === 'tasks') {
      rows = db.prepare(`
        SELECT t.id, t.title, t.description, t.status, t.priority, t.source,
          t.assigned_to, tm.name as assignee_name,
          t.revision_count, t.original_priority,
          t.created_at, t.updated_at
        FROM tasks t
        LEFT JOIN team_members tm ON t.assigned_to = tm.id
        ORDER BY t.created_at DESC
      `).all();
    } else if (type === 'notes') {
      rows = db.prepare(`
        SELECT id, title, content, created_at, updated_at
        FROM notes
        ORDER BY created_at DESC
      `).all();
    } else if (type === 'contacts') {
      rows = db.prepare(`
        SELECT id, name, role, company, email, phone, notes, created_at, updated_at
        FROM contacts
        ORDER BY name ASC
      `).all();
    } else if (type === 'activity') {
      rows = db.prepare(`
        SELECT a.id, a.actor, a.action, a.notes, a.task_id, t.title as task_title,
          a.created_at
        FROM activity_log a
        LEFT JOIN tasks t ON a.task_id = t.id
        ORDER BY a.created_at DESC
        LIMIT 10000
      `).all();
    }

    if (format === 'csv') {
      const csv = rowsToCsv(rows);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      return res.send(csv);
    } else {
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      return res.json({ type, exported_at: new Date().toISOString(), count: rows.length, data: rows });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── White Paper: Live Data API ───────────────────────────────────
// Returns all live statistics, roster, and system state for the auto-updating white paper.
app.get('/api/whitepaper/data', (req, res) => {
  try {
    const now = localNow();

    // ── Roster by tier ──
    const roster = {
      board: db.prepare("SELECT id, name, role, department, tier, icon FROM team_members WHERE status='active' AND tier='board' ORDER BY name").all(),
      csuite: db.prepare("SELECT id, name, role, department, tier, icon FROM team_members WHERE status='active' AND tier='c-suite' ORDER BY name").all(),
      specialists: db.prepare("SELECT id, name, role, department, tier, icon FROM team_members WHERE status='active' AND tier='specialist' ORDER BY department, name").all(),
      total_active: (db.prepare("SELECT COUNT(*) as c FROM team_members WHERE status='active'").get() || {}).c || 0,
      total_all: (db.prepare("SELECT COUNT(*) as c FROM team_members").get() || {}).c || 0
    };

    // ── Department breakdown ──
    const departments = db.prepare(`
      SELECT department, COUNT(*) as member_count
      FROM team_members WHERE status='active' AND department IS NOT NULL
      GROUP BY department ORDER BY department
    `).all();

    // ── Task statistics ──
    const taskStats = {
      total: (db.prepare("SELECT COUNT(*) as c FROM tasks").get() || {}).c || 0,
      by_status: db.prepare("SELECT status, COUNT(*) as count FROM tasks GROUP BY status ORDER BY CASE status WHEN 'new' THEN 1 WHEN 'routing' THEN 2 WHEN 'in_progress' THEN 3 WHEN 'review' THEN 4 WHEN 'completed' THEN 5 WHEN 'delivered' THEN 6 END").all(),
      by_priority: db.prepare("SELECT priority, COUNT(*) as count FROM tasks GROUP BY priority ORDER BY CASE priority WHEN 'urgent' THEN 1 WHEN 'high' THEN 2 WHEN 'normal' THEN 3 WHEN 'low' THEN 4 END").all(),
      completed_today: (db.prepare("SELECT COUNT(*) as c FROM tasks WHERE status IN ('completed','delivered') AND date(completed_at)=date(?)").get(now) || {}).c || 0,
      completed_this_week: (db.prepare("SELECT COUNT(*) as c FROM tasks WHERE status IN ('completed','delivered') AND completed_at > datetime(?,'-7 days')").get(now) || {}).c || 0,
      completed_this_month: (db.prepare("SELECT COUNT(*) as c FROM tasks WHERE status IN ('completed','delivered') AND strftime('%Y-%m',completed_at)=strftime('%Y-%m',?)").get(now) || {}).c || 0,
      avg_revision_count: (db.prepare("SELECT ROUND(AVG(revision_count),2) as avg FROM tasks WHERE status IN ('completed','delivered')").get() || {}).avg || 0
    };

    // ── Top assignees (most tasks completed) ──
    const topAssignees = db.prepare(`
      SELECT tm.name, tm.role, tm.department, COUNT(*) as completed
      FROM tasks t
      JOIN team_members tm ON t.assigned_to = tm.id
      WHERE t.status IN ('completed','delivered')
      GROUP BY t.assigned_to
      ORDER BY completed DESC LIMIT 15
    `).all();

    // ── Project statistics ──
    const projectStats = {
      total: (db.prepare("SELECT COUNT(*) as c FROM projects").get() || {}).c || 0,
      by_status: db.prepare("SELECT status, COUNT(*) as count FROM projects GROUP BY status").all(),
      details: db.prepare(`
        SELECT p.id, p.name, p.status, p.summary, p.exochain_governed, p.color, p.created_at,
          (SELECT COUNT(*) FROM project_tasks pt WHERE pt.project_id = p.id) as task_count,
          (SELECT COUNT(*) FROM project_tasks pt JOIN tasks t ON pt.task_id = t.id WHERE pt.project_id = p.id AND t.status IN ('completed','delivered')) as completed_tasks,
          (SELECT COUNT(*) FROM project_tasks pt JOIN tasks t ON pt.task_id = t.id WHERE pt.project_id = p.id AND t.status = 'in_progress') as active_tasks
        FROM projects p ORDER BY p.status, p.name
      `).all()
    };

    // ── Mission statistics ──
    const missionStats = {
      total: (db.prepare("SELECT COUNT(*) as c FROM missions").get() || {}).c || 0,
      by_status: db.prepare("SELECT status, COUNT(*) as count FROM missions GROUP BY status").all()
    };

    // ── Active processes ──
    const activeProcesses = {
      running: (db.prepare("SELECT COUNT(*) as c FROM active_processes WHERE status='running'").get() || {}).c || 0,
      total: (db.prepare("SELECT COUNT(*) as c FROM active_processes").get() || {}).c || 0,
      by_status: db.prepare("SELECT status, COUNT(*) as count FROM active_processes GROUP BY status").all()
    };

    // ── Governance stats ──
    const governance = {
      receipts_total: (db.prepare("SELECT COUNT(*) as c FROM governance_receipts").get() || {}).c || 0,
      receipts_by_branch: db.prepare("SELECT branch, COUNT(*) as count FROM governance_receipts GROUP BY branch").all(),
      invariants: db.prepare("SELECT id, code, name, description, enforced, severity, violation_count FROM constitutional_invariants ORDER BY id").all(),
      provenance_entries: (db.prepare("SELECT COUNT(*) as c FROM provenance_chain").get() || {}).c || 0,
      health: db.prepare("SELECT status, score, checked_at as created_at FROM governance_health ORDER BY id DESC LIMIT 1").get() || { status: 'unknown', score: 0 },
      exochain_decisions: {
        total: (db.prepare("SELECT COUNT(*) as c FROM exochain_decisions").get() || {}).c || 0,
        by_status: db.prepare("SELECT status, COUNT(*) as count FROM exochain_decisions GROUP BY status").all(),
        by_class: db.prepare("SELECT decision_class, COUNT(*) as count FROM exochain_decisions GROUP BY decision_class").all()
      }
    };

    // ── Knowledge base stats ──
    const knowledge = {
      notes: (db.prepare("SELECT COUNT(*) as c FROM notes").get() || {}).c || 0,
      contacts: (db.prepare("SELECT COUNT(*) as c FROM contacts").get() || {}).c || 0,
      decisions: {
        total: (db.prepare("SELECT COUNT(*) as c FROM decisions").get() || {}).c || 0,
        by_status: db.prepare("SELECT status, COUNT(*) as count FROM decisions GROUP BY status").all()
      },
      tags: (db.prepare("SELECT COUNT(*) as c FROM tags").get() || {}).c || 0
    };

    // ── Cost & budget ──
    let costStats = { total_cents: 0, this_month: 0, by_model: [], by_department: [] };
    try {
      costStats = {
        total_cents: (db.prepare("SELECT COALESCE(SUM(cost_cents),0) as c FROM cost_events").get() || {}).c || 0,
        this_month: (db.prepare("SELECT COALESCE(SUM(cost_cents),0) as c FROM cost_events WHERE strftime('%Y-%m',created_at)=strftime('%Y-%m',?)").get(now) || {}).c || 0,
        total_tokens: (db.prepare("SELECT COALESCE(SUM(total_tokens),0) as c FROM cost_events").get() || {}).c || 0,
        by_model: db.prepare("SELECT model, COUNT(*) as calls, COALESCE(SUM(cost_cents),0) as total_cents, COALESCE(SUM(total_tokens),0) as tokens FROM cost_events WHERE model IS NOT NULL GROUP BY model ORDER BY total_cents DESC LIMIT 10").all(),
        by_department: db.prepare(`
          SELECT tm.department, COUNT(*) as calls, COALESCE(SUM(ce.cost_cents),0) as total_cents
          FROM cost_events ce
          JOIN team_members tm ON ce.member_id = tm.id
          WHERE tm.department IS NOT NULL
          GROUP BY tm.department ORDER BY total_cents DESC
        `).all()
      };
    } catch (_) { /* cost tables may be empty */ }

    // ── Activity log stats ──
    const activityStats = {
      total: (db.prepare("SELECT COUNT(*) as c FROM activity_log").get() || {}).c || 0,
      today: (db.prepare("SELECT COUNT(*) as c FROM activity_log WHERE date(created_at)=date(?)").get(now) || {}).c || 0,
      this_week: (db.prepare("SELECT COUNT(*) as c FROM activity_log WHERE created_at > datetime(?,'-7 days')").get(now) || {}).c || 0,
      recent: db.prepare("SELECT actor, action, notes, created_at FROM activity_log ORDER BY id DESC LIMIT 20").all()
    };

    // ── System settings (non-sensitive) ──
    const settings = db.prepare("SELECT key, value, updated_at FROM system_settings WHERE key NOT LIKE '%token%' AND key NOT LIKE '%secret%' AND key NOT LIKE '%password%' AND key NOT LIKE '%key%' ORDER BY key").all();

    // ── Integrations ──
    const integrations = db.prepare("SELECT type, enabled, created_at, updated_at FROM integrations").all();

    // ── Templates ──
    const templateStats = {
      total: (db.prepare("SELECT COUNT(*) as c FROM templates").get() || {}).c || 0,
      by_category: db.prepare("SELECT category, COUNT(*) as count FROM templates GROUP BY category ORDER BY count DESC").all()
    };

    // ── Linked repos & paths ──
    const linked = {
      repos: db.prepare("SELECT id, name, url, owner, default_branch FROM linked_repos ORDER BY name").all(),
      paths: db.prepare("SELECT id, name, path, type, description FROM linked_paths ORDER BY name").all()
    };

    // ── Goals, visions, end goals ──
    let goals = { end_goals: [], visions: [] };
    try {
      goals = {
        end_goals: db.prepare("SELECT id, title, description, target_date, status FROM end_goals ORDER BY sort_order").all(),
        visions: db.prepare("SELECT id, title, description, target_date, status, project_id FROM visions ORDER BY sort_order").all()
      };
    } catch (_) {}

    // ── Peer reviews ──
    let peerReviewStats = { total: 0, avg_quality: 0, by_verdict: [] };
    try {
      peerReviewStats = {
        total: (db.prepare("SELECT COUNT(*) as c FROM peer_reviews").get() || {}).c || 0,
        avg_quality: (db.prepare("SELECT ROUND(AVG(quality_score),2) as avg FROM peer_reviews WHERE quality_score IS NOT NULL").get() || {}).avg || 0,
        by_verdict: db.prepare("SELECT verdict, COUNT(*) as count FROM peer_reviews GROUP BY verdict").all()
      };
    } catch (_) {}

    // ── Escalation stats ──
    let escalationStats = { total: 0, open: 0, resolved: 0 };
    try {
      escalationStats = {
        total: (db.prepare("SELECT COUNT(*) as c FROM escalation_log").get() || {}).c || 0,
        open: (db.prepare("SELECT COUNT(*) as c FROM escalation_log WHERE status='open'").get() || {}).c || 0,
        resolved: (db.prepare("SELECT COUNT(*) as c FROM escalation_log WHERE status='resolved'").get() || {}).c || 0
      };
    } catch (_) {}

    // ── Notification stats ──
    const notifications = {
      total: (db.prepare("SELECT COUNT(*) as c FROM notifications").get() || {}).c || 0,
      unread: (db.prepare("SELECT COUNT(*) as c FROM notifications WHERE read=0").get() || {}).c || 0,
      by_type: db.prepare("SELECT type, COUNT(*) as count FROM notifications GROUP BY type ORDER BY count DESC").all()
    };

    // ── Team utilization ──
    const totalSpecialists = (db.prepare("SELECT COUNT(*) as c FROM team_members WHERE status='active' AND tier='specialist'").get() || {}).c || 0;
    const activeSpecialists = (db.prepare("SELECT COUNT(DISTINCT member_id) as c FROM active_processes WHERE status='running'").get() || {}).c || 0;

    // ── Table inventory ──
    const tableCount = (db.prepare("SELECT COUNT(*) as c FROM sqlite_master WHERE type='table'").get() || {}).c || 0;

    res.json({
      generated_at: now,
      roster,
      departments,
      taskStats,
      topAssignees,
      projectStats,
      missionStats,
      activeProcesses,
      governance,
      knowledge,
      costStats,
      activityStats,
      settings,
      integrations,
      templateStats,
      linked,
      goals,
      peerReviewStats,
      escalationStats,
      notifications,
      utilization: { total_specialists: totalSpecialists, active_specialists: activeSpecialists, pct: Math.round((activeSpecialists / Math.max(totalSpecialists, 1)) * 100) },
      database: { table_count: tableCount }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── White Paper: Database Schema ─────────────────────────────────
// Returns full schema for all tables for the white paper's schema section.
app.get('/api/whitepaper/schema', (req, res) => {
  try {
    const tables = db.prepare("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all();
    const indexes = db.prepare("SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL ORDER BY tbl_name, name").all();

    // Get row counts for each table
    const counts = {};
    for (const t of tables) {
      try {
        counts[t.name] = (db.prepare(`SELECT COUNT(*) as c FROM "${t.name}"`).get() || {}).c || 0;
      } catch (_) {
        counts[t.name] = 0;
      }
    }

    res.json({
      generated_at: localNow(),
      table_count: tables.length,
      index_count: indexes.length,
      tables: tables.map(t => ({
        name: t.name,
        sql: t.sql,
        row_count: counts[t.name] || 0
      })),
      indexes
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── White Paper: API Route Catalog ───────────────────────────────
// Returns a catalog of all registered Express routes for the white paper.
app.get('/api/whitepaper/routes', (req, res) => {
  try {
    const routes = [];
    app._router.stack.forEach(middleware => {
      if (middleware.route) {
        const methods = Object.keys(middleware.route.methods).map(m => m.toUpperCase());
        routes.push({ path: middleware.route.path, methods });
      } else if (middleware.name === 'router' && middleware.handle && middleware.handle.stack) {
        middleware.handle.stack.forEach(handler => {
          if (handler.route) {
            const methods = Object.keys(handler.route.methods).map(m => m.toUpperCase());
            routes.push({ path: handler.route.path, methods });
          }
        });
      }
    });

    // Group by domain
    const grouped = {};
    for (const route of routes) {
      const parts = route.path.split('/').filter(Boolean);
      const domain = parts.length >= 2 ? parts.slice(0, 2).join('/') : parts[0] || 'root';
      if (!grouped[domain]) grouped[domain] = [];
      grouped[domain].push(route);
    }

    res.json({
      generated_at: localNow(),
      total_routes: routes.length,
      routes,
      grouped
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── White Paper: Code Snippets from Source Files ────────────────
// Returns key code sections from the actual source files for display with syntax highlighting.
app.get('/api/whitepaper/code', (req, res) => {
  try {
    const snippets = {};

    // Helper: read lines from a file (1-indexed, inclusive)
    const readLines = (filePath, startLine, endLine) => {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n');
        const start = Math.max(0, startLine - 1);
        const end = Math.min(lines.length, endLine);
        return lines.slice(start, end).join('\n');
      } catch (e) {
        return `// Error reading ${filePath}: ${e.message}`;
      }
    };

    const serverPath = path.join(__dirname, 'server.js');
    const appPath = path.join(__dirname, 'public', 'app.js');
    const claudeMdPath = path.resolve(__dirname, '..', 'CLAUDE.md');

    // ── server.js snippets ──
    const serverContent = fs.readFileSync(serverPath, 'utf8');
    const serverLines = serverContent.split('\n');

    // Find key sections by scanning for comment headers
    const findSection = (lines, marker, maxLines) => {
      maxLines = maxLines || 120;
      const idx = lines.findIndex(l => l.includes(marker));
      if (idx === -1) return null;
      // Read from marker up to next major section header or maxLines
      let end = idx + maxLines;
      for (let i = idx + 1; i < Math.min(idx + maxLines, lines.length); i++) {
        if (lines[i].match(/^\/\/ ── .+ ──/) && i > idx + 5) {
          end = i;
          break;
        }
      }
      return { start: idx + 1, end: end, code: lines.slice(idx, end).join('\n') };
    };

    // Key server.js sections
    snippets.server_imports = {
      title: 'Server — Imports & Setup',
      description: 'The server boots by loading Express, the SQLite driver (better-sqlite3), and core Node modules. It opens the database in WAL (Write-Ahead Logging) mode for concurrent read access, configures memory-mapped I/O (256 MB), and sets a busy timeout for lock contention. This initialization block is the foundation that every API route and background process depends on.',
      language: 'javascript',
      file: 'server.js',
      code: readLines(serverPath, 1, 50)
    };

    const taskLifecycle = findSection(serverLines, 'Task Lifecycle');
    if (taskLifecycle) {
      snippets.task_lifecycle = {
        title: 'Task Lifecycle Management',
        language: 'javascript',
        file: 'server.js',
        lines: `${taskLifecycle.start}-${taskLifecycle.end}`,
        code: taskLifecycle.code
      };
    }

    const autoSpawn = findSection(serverLines, 'Auto-Spawn') || findSection(serverLines, 'auto_spawn') || findSection(serverLines, 'spawnTerminal');
    if (autoSpawn) {
      snippets.auto_spawn = {
        title: 'Auto-Spawn Terminal System',
        language: 'javascript',
        file: 'server.js',
        lines: `${autoSpawn.start}-${autoSpawn.end}`,
        code: autoSpawn.code
      };
    }

    const chainOfCommand = findSection(serverLines, 'Chain of Command') || findSection(serverLines, 'chain-of-command') || findSection(serverLines, 'chainOfCommand');
    if (chainOfCommand) {
      snippets.chain_of_command = {
        title: 'Chain of Command Routing',
        language: 'javascript',
        file: 'server.js',
        lines: `${chainOfCommand.start}-${chainOfCommand.end}`,
        code: chainOfCommand.code
      };
    }

    const wsSection = findSection(serverLines, 'WebSocket');
    if (wsSection) {
      snippets.websocket = {
        title: 'WebSocket Server',
        language: 'javascript',
        file: 'server.js',
        lines: `${wsSection.start}-${wsSection.end}`,
        code: wsSection.code
      };
    }

    const exochain = findSection(serverLines, 'ExoChain') || findSection(serverLines, 'exochain');
    if (exochain) {
      snippets.exochain = {
        title: 'ExoChain Governance',
        language: 'javascript',
        file: 'server.js',
        lines: `${exochain.start}-${exochain.end}`,
        code: exochain.code
      };
    }

    // API routes sample — whitepaper endpoints themselves
    const wpDataSection = findSection(serverLines, 'White Paper: Live Data API');
    if (wpDataSection) {
      snippets.whitepaper_api = {
        title: 'White Paper API — Live Data Endpoint',
        language: 'javascript',
        file: 'server.js',
        lines: `${wpDataSection.start}-${wpDataSection.end}`,
        code: wpDataSection.code
      };
    }

    // ── app.js snippets ──
    try {
      const appContent = fs.readFileSync(appPath, 'utf8');
      const appLines = appContent.split('\n');

      snippets.app_imports = {
        title: 'Client App — Initialization',
        language: 'javascript',
        file: 'public/app.js',
        code: appLines.slice(0, Math.min(60, appLines.length)).join('\n')
      };

      const appWs = findSection(appLines, 'WebSocket');
      if (appWs) {
        snippets.app_websocket = {
          title: 'Client — WebSocket Handling',
          language: 'javascript',
          file: 'public/app.js',
          lines: `${appWs.start}-${appWs.end}`,
          code: appWs.code
        };
      }

      const missionControl = findSection(appLines, 'Mission Control') || findSection(appLines, 'missionControl');
      if (missionControl) {
        snippets.mission_control = {
          title: 'Mission Control UI',
          language: 'javascript',
          file: 'public/app.js',
          lines: `${missionControl.start}-${missionControl.end}`,
          code: missionControl.code
        };
      }
    } catch (_) {
      snippets.app_error = { title: 'app.js', language: 'text', file: 'public/app.js', code: '// Could not read app.js' };
    }

    // ── Database schema (SQL from sqlite_master) ──
    try {
      const tables = db.prepare("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all();
      snippets.database_schema = {
        title: 'Database Schema (All Tables)',
        language: 'sql',
        file: 'the_team.db',
        code: tables.map(t => `${t.sql};`).join('\n\n')
      };
    } catch (_) {}

    // ── CLAUDE.md system instructions ──
    try {
      const claudeContent = fs.readFileSync(claudeMdPath, 'utf8');
      snippets.claude_md = {
        title: 'System Instructions (CLAUDE.md)',
        language: 'markdown',
        file: 'CLAUDE.md',
        code: claudeContent
      };
    } catch (_) {
      snippets.claude_md = { title: 'CLAUDE.md', language: 'markdown', file: 'CLAUDE.md', code: '<!-- Could not read CLAUDE.md -->' };
    }

    // ── Summary stats ──
    const totalSnippets = Object.keys(snippets).length;
    const totalLines = Object.values(snippets).reduce((sum, s) => sum + (s.code ? s.code.split('\n').length : 0), 0);

    res.json({
      generated_at: localNow(),
      snippet_count: totalSnippets,
      total_lines: totalLines,
      snippets
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── White Paper: Custom Content — Load ──────────────────────────
// Returns all custom content sections saved by the user.
app.get('/api/whitepaper/content', (req, res) => {
  try {
    const rows = db.prepare("SELECT section_id, custom_content, updated_at FROM whitepaper_content ORDER BY section_id").all();
    const sections = {};
    for (const row of rows) {
      sections[row.section_id] = { content: row.custom_content, updated_at: row.updated_at };
    }
    res.json({ sections, count: rows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── White Paper: Custom Content — Save ──────────────────────────
// Saves or updates custom content for a specific section. Send section_id=null content to delete.
app.post('/api/whitepaper/content', (req, res) => {
  try {
    const { section_id, content } = req.body;
    if (!section_id || typeof section_id !== 'string') {
      return res.status(400).json({ error: 'section_id is required and must be a string' });
    }

    const now = localNow();

    // If content is null/empty, delete the custom override (reset to auto)
    if (content === null || content === undefined || content === '') {
      db.prepare("DELETE FROM whitepaper_content WHERE section_id = ?").run(section_id);
      return res.json({ ok: true, action: 'deleted', section_id });
    }

    if (typeof content !== 'string') {
      return res.status(400).json({ error: 'content must be a string' });
    }

    // Upsert: insert or replace
    db.prepare(`
      INSERT INTO whitepaper_content (section_id, custom_content, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(section_id) DO UPDATE SET
        custom_content = excluded.custom_content,
        updated_at = excluded.updated_at
    `).run(section_id, content, now);

    res.json({ ok: true, action: 'saved', section_id, updated_at: now });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── White Paper: Custom Content — Delete (Reset to Auto) ────────
// Resets a specific section back to auto-generated content.
app.delete('/api/whitepaper/content/:sectionId', (req, res) => {
  try {
    const { sectionId } = req.params;
    const result = db.prepare("DELETE FROM whitepaper_content WHERE section_id = ?").run(sectionId);
    res.json({ ok: true, deleted: result.changes > 0, section_id: sectionId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── White Paper: Export as Markdown ──────────────────────────────
// Compiles all whitepaper data into a single downloadable markdown file.
app.get('/api/whitepaper/export', (req, res) => {
  try {
    const now = localNow();
    const lines = [];
    const h = (level, text) => lines.push(`${'#'.repeat(level)} ${text}\n`);
    const p = (text) => lines.push(`${text}\n`);
    const blank = () => lines.push('');

    h(1, 'The Team — White Paper');
    p(`> Auto-generated on ${now}`);
    blank();

    // ── CLAUDE.md System Instructions ──
    try {
      const claudeMdPath = path.resolve(__dirname, '..', '..', 'CLAUDE.md');
      const claudeContent = fs.readFileSync(claudeMdPath, 'utf8');
      h(2, 'System Instructions (CLAUDE.md)');
      blank();
      lines.push(claudeContent);
      blank();
    } catch (_) {
      h(2, 'System Instructions');
      p('_Could not read CLAUDE.md_');
      blank();
    }

    // ── Roster ──
    h(2, 'Team Roster');
    blank();
    const roster = {
      board: db.prepare("SELECT name, role, department FROM team_members WHERE status='active' AND tier='board' ORDER BY name").all(),
      csuite: db.prepare("SELECT name, role, department FROM team_members WHERE status='active' AND tier='c-suite' ORDER BY name").all(),
      specialists: db.prepare("SELECT name, role, department FROM team_members WHERE status='active' AND tier='specialist' ORDER BY department, name").all()
    };
    const totalActive = (db.prepare("SELECT COUNT(*) as c FROM team_members WHERE status='active'").get() || {}).c || 0;
    const totalAll = (db.prepare("SELECT COUNT(*) as c FROM team_members").get() || {}).c || 0;
    p(`**Total members:** ${totalAll} (${totalActive} active)`);
    blank();

    h(3, 'Board of Directors');
    blank();
    p('| Name | Role |');
    p('|------|------|');
    for (const m of roster.board) p(`| ${m.name} | ${m.role} |`);
    blank();

    h(3, 'C-Suite Executives');
    blank();
    p('| Name | Role | Department |');
    p('|------|------|------------|');
    for (const m of roster.csuite) p(`| ${m.name} | ${m.role} | ${m.department || '—'} |`);
    blank();

    h(3, 'Specialists');
    blank();
    p('| Name | Role | Department |');
    p('|------|------|------------|');
    for (const m of roster.specialists) p(`| ${m.name} | ${m.role} | ${m.department || '—'} |`);
    blank();

    // ── Departments ──
    h(2, 'Departments');
    blank();
    const departments = db.prepare("SELECT department, COUNT(*) as member_count FROM team_members WHERE status='active' AND department IS NOT NULL GROUP BY department ORDER BY department").all();
    p('| Department | Members |');
    p('|------------|---------|');
    for (const d of departments) p(`| ${d.department} | ${d.member_count} |`);
    blank();

    // ── Task Statistics ──
    h(2, 'Task Statistics');
    blank();
    const taskTotal = (db.prepare("SELECT COUNT(*) as c FROM tasks").get() || {}).c || 0;
    const byStatus = db.prepare("SELECT status, COUNT(*) as count FROM tasks GROUP BY status ORDER BY CASE status WHEN 'new' THEN 1 WHEN 'routing' THEN 2 WHEN 'in_progress' THEN 3 WHEN 'review' THEN 4 WHEN 'completed' THEN 5 WHEN 'delivered' THEN 6 END").all();
    const byPriority = db.prepare("SELECT priority, COUNT(*) as count FROM tasks GROUP BY priority ORDER BY CASE priority WHEN 'urgent' THEN 1 WHEN 'high' THEN 2 WHEN 'normal' THEN 3 WHEN 'low' THEN 4 END").all();
    const completedToday = (db.prepare("SELECT COUNT(*) as c FROM tasks WHERE status IN ('completed','delivered') AND date(completed_at)=date(?)").get(now) || {}).c || 0;
    const completedWeek = (db.prepare("SELECT COUNT(*) as c FROM tasks WHERE status IN ('completed','delivered') AND completed_at > datetime(?,'-7 days')").get(now) || {}).c || 0;
    const completedMonth = (db.prepare("SELECT COUNT(*) as c FROM tasks WHERE status IN ('completed','delivered') AND strftime('%Y-%m',completed_at)=strftime('%Y-%m',?)").get(now) || {}).c || 0;
    const avgRevisions = (db.prepare("SELECT ROUND(AVG(revision_count),2) as avg FROM tasks WHERE status IN ('completed','delivered')").get() || {}).avg || 0;

    p(`- **Total tasks:** ${taskTotal}`);
    p(`- **Completed today:** ${completedToday}`);
    p(`- **Completed this week:** ${completedWeek}`);
    p(`- **Completed this month:** ${completedMonth}`);
    p(`- **Average revision count:** ${avgRevisions}`);
    blank();

    h(3, 'By Status');
    blank();
    p('| Status | Count |');
    p('|--------|-------|');
    for (const s of byStatus) p(`| ${s.status} | ${s.count} |`);
    blank();

    h(3, 'By Priority');
    blank();
    p('| Priority | Count |');
    p('|----------|-------|');
    for (const pr of byPriority) p(`| ${pr.priority} | ${pr.count} |`);
    blank();

    // ── Top Assignees ──
    h(3, 'Top Assignees');
    blank();
    const topAssignees = db.prepare("SELECT tm.name, tm.role, tm.department, COUNT(*) as completed FROM tasks t JOIN team_members tm ON t.assigned_to = tm.id WHERE t.status IN ('completed','delivered') GROUP BY t.assigned_to ORDER BY completed DESC LIMIT 15").all();
    p('| Name | Role | Department | Completed |');
    p('|------|------|------------|-----------|');
    for (const a of topAssignees) p(`| ${a.name} | ${a.role} | ${a.department || '—'} | ${a.completed} |`);
    blank();

    // ── Projects ──
    h(2, 'Projects');
    blank();
    const projectTotal = (db.prepare("SELECT COUNT(*) as c FROM projects").get() || {}).c || 0;
    const projByStatus = db.prepare("SELECT status, COUNT(*) as count FROM projects GROUP BY status").all();
    p(`**Total projects:** ${projectTotal}`);
    blank();
    p('| Status | Count |');
    p('|--------|-------|');
    for (const ps of projByStatus) p(`| ${ps.status} | ${ps.count} |`);
    blank();
    const projDetails = db.prepare("SELECT p.name, p.status, p.summary, (SELECT COUNT(*) FROM project_tasks pt WHERE pt.project_id = p.id) as task_count, (SELECT COUNT(*) FROM project_tasks pt JOIN tasks t ON pt.task_id = t.id WHERE pt.project_id = p.id AND t.status IN ('completed','delivered')) as completed_tasks FROM projects p ORDER BY p.status, p.name").all();
    for (const proj of projDetails) {
      h(3, proj.name);
      p(`- **Status:** ${proj.status}`);
      p(`- **Tasks:** ${proj.completed_tasks}/${proj.task_count} completed`);
      if (proj.summary) p(`- **Summary:** ${proj.summary.substring(0, 300)}${proj.summary.length > 300 ? '...' : ''}`);
      blank();
    }

    // ── Governance ──
    h(2, 'Governance (ExoChain)');
    blank();
    const receiptsTotal = (db.prepare("SELECT COUNT(*) as c FROM governance_receipts").get() || {}).c || 0;
    const provenanceEntries = (db.prepare("SELECT COUNT(*) as c FROM provenance_chain").get() || {}).c || 0;
    let govHealth = { status: 'unknown', score: 0 };
    try { govHealth = db.prepare("SELECT status, score FROM governance_health ORDER BY id DESC LIMIT 1").get() || govHealth; } catch (_) {}
    p(`- **Governance receipts:** ${receiptsTotal}`);
    p(`- **Provenance entries:** ${provenanceEntries}`);
    p(`- **Health status:** ${govHealth.status} (score: ${govHealth.score})`);
    blank();

    h(3, 'Constitutional Invariants');
    blank();
    const invariants = db.prepare("SELECT code, name, description, enforced, severity, violation_count FROM constitutional_invariants ORDER BY id").all();
    p('| Code | Name | Severity | Enforced | Violations |');
    p('|------|------|----------|----------|------------|');
    for (const inv of invariants) p(`| ${inv.code} | ${inv.name} | ${inv.severity} | ${inv.enforced ? 'Yes' : 'No'} | ${inv.violation_count} |`);
    blank();

    let exoTotal = 0, exoByStatus = [], exoByClass = [];
    try {
      exoTotal = (db.prepare("SELECT COUNT(*) as c FROM exochain_decisions").get() || {}).c || 0;
      exoByStatus = db.prepare("SELECT status, COUNT(*) as count FROM exochain_decisions GROUP BY status").all();
      exoByClass = db.prepare("SELECT decision_class, COUNT(*) as count FROM exochain_decisions GROUP BY decision_class").all();
    } catch (_) {}
    if (exoTotal > 0) {
      h(3, 'ExoChain Decisions');
      blank();
      p(`**Total:** ${exoTotal}`);
      blank();
      p('| Status | Count |');
      p('|--------|-------|');
      for (const e of exoByStatus) p(`| ${e.status} | ${e.count} |`);
      blank();
      p('| Decision Class | Count |');
      p('|----------------|-------|');
      for (const e of exoByClass) p(`| ${e.decision_class} | ${e.count} |`);
      blank();
    }

    // ── Knowledge Base ──
    h(2, 'Knowledge Base');
    blank();
    const notesCount = (db.prepare("SELECT COUNT(*) as c FROM notes").get() || {}).c || 0;
    const contactsCount = (db.prepare("SELECT COUNT(*) as c FROM contacts").get() || {}).c || 0;
    const decisionsCount = (db.prepare("SELECT COUNT(*) as c FROM decisions").get() || {}).c || 0;
    const tagsCount = (db.prepare("SELECT COUNT(*) as c FROM tags").get() || {}).c || 0;
    p(`- **Notes:** ${notesCount}`);
    p(`- **Contacts:** ${contactsCount}`);
    p(`- **Decisions logged:** ${decisionsCount}`);
    p(`- **Tags:** ${tagsCount}`);
    blank();

    // ── Cost & Budget ──
    h(2, 'Cost & Budget');
    blank();
    try {
      const totalCents = (db.prepare("SELECT COALESCE(SUM(cost_cents),0) as c FROM cost_events").get() || {}).c || 0;
      const monthCents = (db.prepare("SELECT COALESCE(SUM(cost_cents),0) as c FROM cost_events WHERE strftime('%Y-%m',created_at)=strftime('%Y-%m',?)").get(now) || {}).c || 0;
      const totalTokens = (db.prepare("SELECT COALESCE(SUM(total_tokens),0) as c FROM cost_events").get() || {}).c || 0;
      p(`- **Total spend:** $${(totalCents / 100).toFixed(2)}`);
      p(`- **This month:** $${(monthCents / 100).toFixed(2)}`);
      p(`- **Total tokens:** ${totalTokens.toLocaleString()}`);
      blank();
      const byModel = db.prepare("SELECT model, COUNT(*) as calls, COALESCE(SUM(cost_cents),0) as total_cents, COALESCE(SUM(total_tokens),0) as tokens FROM cost_events WHERE model IS NOT NULL GROUP BY model ORDER BY total_cents DESC LIMIT 10").all();
      if (byModel.length > 0) {
        h(3, 'By Model');
        blank();
        p('| Model | Calls | Cost | Tokens |');
        p('|-------|-------|------|--------|');
        for (const m of byModel) p(`| ${m.model} | ${m.calls} | $${(m.total_cents / 100).toFixed(2)} | ${m.tokens.toLocaleString()} |`);
        blank();
      }
    } catch (_) {
      p('_Cost data not available._');
      blank();
    }

    // ── System Settings ──
    h(2, 'System Settings');
    blank();
    const settings = db.prepare("SELECT key, value FROM system_settings WHERE key NOT LIKE '%token%' AND key NOT LIKE '%secret%' AND key NOT LIKE '%password%' AND key NOT LIKE '%key%' ORDER BY key").all();
    p('| Setting | Value |');
    p('|---------|-------|');
    for (const s of settings) p(`| ${s.key} | ${String(s.value || '').substring(0, 100)} |`);
    blank();

    // ── Integrations ──
    h(2, 'Integrations');
    blank();
    const integrations = db.prepare("SELECT type, enabled FROM integrations").all();
    if (integrations.length > 0) {
      p('| Type | Enabled |');
      p('|------|---------|');
      for (const i of integrations) p(`| ${i.type} | ${i.enabled ? 'Yes' : 'No'} |`);
    } else {
      p('_No integrations configured._');
    }
    blank();

    // ── Linked Repos & Paths ──
    h(2, 'Linked Repos & Paths');
    blank();
    const repos = db.prepare("SELECT name, url, owner, default_branch FROM linked_repos ORDER BY name").all();
    const paths = db.prepare("SELECT name, path, type, description FROM linked_paths ORDER BY name").all();
    if (repos.length > 0) {
      h(3, 'Repositories');
      blank();
      p('| Name | Owner | Branch | URL |');
      p('|------|-------|--------|-----|');
      for (const r of repos) p(`| ${r.name} | ${r.owner || '—'} | ${r.default_branch || '—'} | ${r.url} |`);
      blank();
    }
    if (paths.length > 0) {
      h(3, 'Linked Paths');
      blank();
      p('| Name | Type | Path | Description |');
      p('|------|------|------|-------------|');
      for (const lp of paths) p(`| ${lp.name} | ${lp.type} | \`${lp.path}\` | ${lp.description || '—'} |`);
      blank();
    }

    // ── Database Schema ──
    h(2, 'Database Schema');
    blank();
    const tables = db.prepare("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all();
    const indexes = db.prepare("SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL ORDER BY tbl_name, name").all();
    p(`**Tables:** ${tables.length} | **Indexes:** ${indexes.length}`);
    blank();
    for (const t of tables) {
      let rowCount = 0;
      try { rowCount = (db.prepare(`SELECT COUNT(*) as c FROM "${t.name}"`).get() || {}).c || 0; } catch (_) {}
      h(3, `${t.name} (${rowCount} rows)`);
      blank();
      lines.push('```sql');
      lines.push(t.sql + ';');
      lines.push('```');
      blank();
    }

    // ── API Route Catalog ──
    h(2, 'API Route Catalog');
    blank();
    const routeList = [];
    app._router.stack.forEach(middleware => {
      if (middleware.route) {
        const methods = Object.keys(middleware.route.methods).map(m => m.toUpperCase());
        routeList.push({ path: middleware.route.path, methods });
      } else if (middleware.name === 'router' && middleware.handle && middleware.handle.stack) {
        middleware.handle.stack.forEach(handler => {
          if (handler.route) {
            const methods = Object.keys(handler.route.methods).map(m => m.toUpperCase());
            routeList.push({ path: handler.route.path, methods });
          }
        });
      }
    });
    p(`**Total routes:** ${routeList.length}`);
    blank();
    p('| Methods | Path |');
    p('|---------|------|');
    for (const r of routeList) p(`| ${r.methods.join(', ')} | \`${r.path}\` |`);
    blank();

    // ── Activity Summary ──
    h(2, 'Activity Summary');
    blank();
    const actTotal = (db.prepare("SELECT COUNT(*) as c FROM activity_log").get() || {}).c || 0;
    const actToday = (db.prepare("SELECT COUNT(*) as c FROM activity_log WHERE date(created_at)=date(?)").get(now) || {}).c || 0;
    const actWeek = (db.prepare("SELECT COUNT(*) as c FROM activity_log WHERE created_at > datetime(?,'-7 days')").get(now) || {}).c || 0;
    p(`- **Total activity entries:** ${actTotal}`);
    p(`- **Today:** ${actToday}`);
    p(`- **This week:** ${actWeek}`);
    blank();

    // ── Peer Reviews ──
    try {
      const prTotal = (db.prepare("SELECT COUNT(*) as c FROM peer_reviews").get() || {}).c || 0;
      const prAvg = (db.prepare("SELECT ROUND(AVG(quality_score),2) as avg FROM peer_reviews WHERE quality_score IS NOT NULL").get() || {}).avg || 0;
      if (prTotal > 0) {
        h(2, 'Peer Reviews');
        blank();
        p(`- **Total reviews:** ${prTotal}`);
        p(`- **Average quality score:** ${prAvg}`);
        blank();
      }
    } catch (_) {}

    // ── Escalation Stats ──
    try {
      const escTotal = (db.prepare("SELECT COUNT(*) as c FROM escalation_log").get() || {}).c || 0;
      if (escTotal > 0) {
        const escOpen = (db.prepare("SELECT COUNT(*) as c FROM escalation_log WHERE status='open'").get() || {}).c || 0;
        const escResolved = (db.prepare("SELECT COUNT(*) as c FROM escalation_log WHERE status='resolved'").get() || {}).c || 0;
        h(2, 'Escalations');
        blank();
        p(`- **Total:** ${escTotal}`);
        p(`- **Open:** ${escOpen}`);
        p(`- **Resolved:** ${escResolved}`);
        blank();
      }
    } catch (_) {}

    // ── Team Utilization ──
    h(2, 'Team Utilization');
    blank();
    const totalSpecialists = (db.prepare("SELECT COUNT(*) as c FROM team_members WHERE status='active' AND tier='specialist'").get() || {}).c || 0;
    const activeSpecialists = (db.prepare("SELECT COUNT(DISTINCT member_id) as c FROM active_processes WHERE status='running'").get() || {}).c || 0;
    const pct = Math.round((activeSpecialists / Math.max(totalSpecialists, 1)) * 100);
    p(`- **Active specialists:** ${activeSpecialists} / ${totalSpecialists} (${pct}%)`);
    blank();

    // ── Architecture ──
    h(2, 'System Architecture');
    blank();
    p('**Stack:** Express.js (Node.js) + SQLite (better-sqlite3) + Vanilla JS SPA + WebSocket (ws)');
    p('**Backend:** Core server.js (~22,500 lines) + 16 route modules in app/routes/ (~11,000 lines)');
    p('**Frontend:** app.js (~36,000 lines) + styles.css (~34,000 lines) + index.html');
    p('**Databases:** the_team.db (main, WAL mode) + task_forces.db (external task forces, separate for durability)');
    p('**Auth:** API key middleware — auto-generated 256-bit key, X-API-Key header or cb_auth cookie');
    p('**AI Inference:** Claude CLI (Sonnet/Opus/Haiku) for code tasks + Ollama on DGX Spark for free analysis');
    blank();
    h(3, 'Route Modules (app/routes/)');
    blank();
    p('| Module | Routes | Domain |');
    p('|--------|--------|--------|');
    p('| governance.js | 44 | ExoChain, approvals, escalations |');
    p('| projects.js | 47 | Projects, improvements, phases |');
    p('| system.js | 39 | System map, white paper, org chart, export |');
    p('| settings.js | 37 | Config, LLM, vault, integrations |');
    p('| analytics.js | 30 | Metrics, costs, leaderboard |');
    p('| companies.js | 27 | Company CRUD, members, domains |');
    p('| research.js | 27 | Programs, experiments, findings |');
    p('| members.js | 22 | Member profiles, tools, adapters |');
    p('| workspace.js | 19 | Workspace sessions, operations |');
    p('| goals.js | 17 | Goals, visions, milestones |');
    p('| context.js | 15 | Context store, propagation |');
    p('| refinement.js | 15 | Refinement targets, reviews |');
    p('| plugins.js | 14 | Plugins, MCP servers |');
    p('| notes.js | 12 | Notes, contacts, decisions |');
    p('| calendar.js | 11 | Events, Google Calendar sync |');
    p('| ideas.js | 7 | Idea board |');
    blank();

    // ── Chain of Command ──
    h(2, 'Chain of Command');
    blank();
    p('```');
    p('Delegation (DOWN):  Board → Executive → Specialist → Delivery');
    p('Escalation (UP):    Specialist fails → higher-ranked specialist → Executive → Board → Max');
    p('```');
    blank();
    p('**Rules:**');
    p('- Board NEVER does work — only routes and governs');
    p('- Executives NEVER do regular tasks — only orchestrate');
    p('- Specialists do ALL actual work and compete on merit');
    p('- Max can bypass chain and address any member directly');
    blank();
    p('**Escalation limits:** 3 retries max per quality gate. 6 total failures = circuit breaker (auto-complete + notify Max).');
    blank();

    // ── Agent Spawn System ──
    h(2, 'Agent Spawn System (spawnMemberTerminal)');
    blank();
    p('When a task is assigned, the system auto-spawns a Claude CLI terminal session:');
    blank();
    p('1. Check `auto_spawn_enabled` setting');
    p('2. Budget enforcement (estimate 50 cents/run, block if policy exceeded)');
    p('3. Duplicate check (no two processes for same task+member)');
    p('4. Load member profile from `Team/{name}.md` (up to 4000 chars)');
    p('5. Load task details, assignments, project context');
    p('6. Build prompt using **3-tier system**:');
    p('   - **Minimal** (peer reviews, retries): persona + task only (~500-1000 tokens)');
    p('   - **Standard** (most tasks): SOUL.md + 5 memories + task (~2000-4000 tokens)');
    p('   - **Full** (urgent+complex): all identity files + 10 memories + tacit + daily notes (~5000-8000 tokens)');
    p('7. Select model using **4-tier routing**:');
    p('   - **Nemotron/qwen3-coder** ($0, Spark): peer reviews, QA, docs, simple tasks');
    p('   - **Claude Haiku** (low cost): simple tasks when Spark offline');
    p('   - **Claude Sonnet** (medium): most implementation work (default)');
    p('   - **Claude Opus** (high): urgent complex planning, architecture');
    p('8. Register in active_processes, broadcast WebSocket event');
    p('9. Spawn: `claude --print --verbose --model <flag> --max-turns <N> --dangerously-skip-permissions --output-format stream-json`');
    p('10. Pipe prompt via stdin, capture stdout/stderr');
    p('11. On completion: parse output, record cost, trigger peer review if configured');
    blank();

    // ── DGX Spark ──
    h(2, 'DGX Spark Integration');
    blank();
    p('**Hardware:** NVIDIA GB10, 128GB unified RAM, 20 cores, CUDA 13.0');
    p('**SSH:** `ssh spark` (192.168.1.35, key-based auth)');
    p('**Tunnel:** `ssh -f -N -L 11435:localhost:11434 spark`');
    p('**Models:** Nemotron (42GB, general) + qwen3-coder:30b (18GB, code)');
    p('**Cost:** $0 per query — dedicated inference hardware');
    p('**Concurrency:** Max 3 simultaneous on GB10 GPU');
    p('**Fallback:** If Ollama fails or output <50 chars, auto-retry with Claude Haiku');
    blank();
    p('Ollama path: POST to `http://localhost:11435/v1/chat/completions` (OpenAI-compatible).');
    p('Model selection: code tasks prefer qwen3-coder:30b, general prefer nemotron:latest.');
    blank();

    // ── Task Forces ──
    h(2, 'Task Force System');
    blank();
    p('External execution teams that operate independently from Command Base.');
    blank();
    p('- **Separate database:** task_forces.db — survives server crashes');
    p('- **Tables:** task_forces, task_force_members, task_force_processes, task_force_logs, resource_profiles, bias_ledger');
    p('- **Adapters:** claude_cli (file access, code editing) and ollama (Spark analysis, $0 cost)');
    p('- **Anti-bias:** Bias ledger tracks who built/designed/digested what. Builders cannot review their own work.');
    p('- **Auto-guardian:** Every 30s checks for zombie PIDs, stale requests (>10min), respawns failed agents up to 5 attempts');
    p('- **Resource profiles:** Mac: 60% CPU/RAM cap (protect user). Spark: 98% (dedicated inference). Process breakdown groups by app name.');
    p('- **Instant kill:** SIGTERM → 3s grace → SIGKILL. Emergency kill-all per device.');
    blank();

    // ── Company Founding Standard ──
    h(2, 'New Company Founding Standard');
    blank();
    p('Day 1 — **3 members:** CEO + CTO + Talent Lead. No board on day one.');
    p('CEO and CTO MUST deliberate together on projects. Single-executive decisions produce worse results.');
    p('Hiring rules: bottlenecks not headcount, one hire at a time, mentor for new hires, probation period.');
    blank();

    // ── Feature Inventory ──
    h(2, 'Feature Inventory (UI Pages)');
    blank();
    p('| Page | Route | Description |');
    p('|------|-------|-------------|');
    p('| Board Room | #board-room | Primary command interface. Send directives to Board. |');
    p('| Inbox | #inbox | Deliverables from the team — completed outputs, files, reports. |');
    p('| Dashboard | #dashboard | Activity overview, task status, team utilization. |');
    p('| Tasks | #tasks | Full task list, filtering, sorting, live agent monitor. |');
    p('| Agents | #workspace | Live agent monitoring, heartbeat, progress, output streaming. |');
    p('| Projects | #projects | Project management with phases, executive assignment, improvements. |');
    p('| Task Forces | #task-forces | External execution teams, resource monitoring, kill buttons. |');
    p('| Companies | #companies | Multi-company management, team, domains, revenue. |');
    p('| Team | #team | Member profiles, identity files, skills, rankings. |');
    p('| Org Chart | #org-chart | Visual chain of command. |');
    p('| Notes | #notes | Knowledge capture, contacts, decisions. |');
    p('| Calendar | #calendar | Google Calendar sync, events, deadlines. |');
    p('| Resources | #resources | Linked repos, folders, file paths. |');
    p('| Analytics | #analytics | Metrics, costs, token usage, budget monitoring. |');
    p('| Research | #research | Research programs, experiments, findings. |');
    p('| Settings | #settings | Config, LLM providers, model sources, API keys. |');
    p('| White Paper | #white-paper | This document — auto-updating system documentation. |');
    blank();

    // ── Code Structure ──
    h(2, 'Code Structure');
    blank();
    p('```');
    p('The Team/');
    p('  CLAUDE.md                  # System instructions (~660 lines)');
    p('  the_team.db                # Main SQLite database (WAL mode)');
    p('  task_forces.db             # Separate DB for Task Forces');
    p('  Teams inbox:Result/        # INPUT: task files dropped here');
    p('  Team/                      # Member profiles (.md files)');
    p("  Stew's inbox:Owner/        # OUTPUT: deliverables placed here");
    p('  app/');
    p('    server.js                # Core backend (~22,500 lines)');
    p('    logger.js                # Structured JSON logger');
    p('    routes/                  # 16 route modules (~11,000 lines)');
    p('      governance.js          # 44 routes');
    p('      companies.js           # 27 routes');
    p('      projects.js            # 47 routes');
    p('      analytics.js           # 30 routes');
    p('      settings.js            # 37 routes');
    p('      system.js              # 39 routes');
    p('      research.js            # 27 routes');
    p('      members.js             # 22 routes');
    p('      workspace.js           # 19 routes');
    p('      context.js             # 15 routes');
    p('      refinement.js          # 15 routes');
    p('      goals.js               # 17 routes');
    p('      notes.js               # 12 routes');
    p('      calendar.js            # 11 routes');
    p('      plugins.js             # 14 routes');
    p('      ideas.js               #  7 routes');
    p('    lib/');
    p('      task-force-db.js       # Separate SQLite DB for Task Forces');
    p('      task-force-engine.js   # Spawn, kill, guardian, anti-bias');
    p('      db.js                  # Database pool utilities');
    p('      broadcast.js           # WebSocket broadcast helpers');
    p('    services/');
    p('      governance.js          # ExoChain governance service');
    p('      heartbeat.js           # Agent heartbeat monitoring');
    p('      exochain.js            # Cryptographic receipt chain');
    p('    public/');
    p('      index.html             # HTML shell — sidebar nav, overlays');
    p('      app.js                 # Client SPA (~36,000 lines)');
    p('      styles.css             # Dark theme (~34,000 lines)');
    p('      whitepaper.html        # This white paper');
    p('```');
    blank();

    // ── Footer ──
    lines.push('---');
    p(`_Generated by The Team Mission Control — ${now}_`);

    const markdown = lines.join('\n');

    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="The-Team-White-Paper.md"');
    res.send(markdown);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/system-map/org-hierarchy — Full org chart data for the system map page
app.get('/api/system-map/org-hierarchy', (req, res) => {
  try {
    const members = db.prepare(`
      SELECT m.id, m.name, m.role, m.tier, m.department, m.reports_to, m.icon,
        boss.name as reports_to_name,
        (SELECT COUNT(*) FROM tasks t WHERE t.assigned_to = m.id AND t.status NOT IN ('completed','delivered')) as active_tasks,
        (SELECT COUNT(*) FROM active_processes ap WHERE ap.member_id = m.id AND ap.status = 'running') as running_processes,
        (SELECT COUNT(*) FROM active_processes ap2 WHERE ap2.member_id = m.id AND ap2.status = 'completed') as tasks_completed
      FROM team_members m
      LEFT JOIN team_members boss ON m.reports_to = boss.id
      WHERE m.status = 'active'
      ORDER BY
        CASE m.tier WHEN 'board' THEN 0 WHEN 'c-suite' THEN 1 WHEN 'specialist' THEN 2 ELSE 3 END,
        m.department, m.name
    `).all();

    const chairman = members.find(m => m.tier === 'board' && !m.reports_to);
    const board = members.filter(m => m.tier === 'board' && m.reports_to);
    const csuite = members.filter(m => m.tier === 'c-suite');
    const specialists = members.filter(m => m.tier === 'specialist');

    // Group specialists by c-suite executive
    const specialistsByExec = {};
    for (const s of specialists) {
      const key = s.reports_to || 0;
      if (!specialistsByExec[key]) specialistsByExec[key] = [];
      specialistsByExec[key].push(s);
    }

    const csuiteWithReports = csuite.map(exec => ({
      ...exec,
      direct_reports: specialistsByExec[exec.id] || []
    }));

    const deptGroups = {};
    for (const s of specialists) {
      const dept = s.department || 'Unassigned';
      if (!deptGroups[dept]) deptGroups[dept] = [];
      deptGroups[dept].push(s);
    }

    const totalActive = db.prepare(`SELECT COUNT(*) as c FROM tasks WHERE status NOT IN ('completed','delivered')`).get().c;
    const totalProcesses = db.prepare(`SELECT COUNT(*) as c FROM active_processes WHERE status = 'running'`).get().c;

    // Active projects with their executives
    const projects = db.prepare(`
      SELECT p.id, p.name, p.status, p.color,
        pe.member_id as exec_id, tm.name as exec_name,
        (SELECT COUNT(*) FROM project_affinity pa WHERE pa.project_id = p.id AND pa.status = 'active') as team_size
      FROM projects p
      LEFT JOIN project_executives pe ON pe.project_id = p.id
      LEFT JOIN team_members tm ON pe.member_id = tm.id
      WHERE p.status = 'active'
      ORDER BY p.name
    `).all();

    res.json({
      chairman, board, csuite: csuiteWithReports, specialists, deptGroups, projects,
      stats: {
        total_members: members.length,
        board_count: (chairman ? 1 : 0) + board.length,
        csuite_count: csuite.length, specialist_count: specialists.length,
        dept_count: Object.keys(deptGroups).length,
        active_tasks: totalActive, running_processes: totalProcesses,
        project_count: projects.length
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/system-map — Full map: nodes (with saved positions) + connections + live stats
app.get('/api/system-map', (req, res) => {
  try {
    const getMap = db.transaction(() => {
      // Merge defaults with user-saved positions/custom nodes
      const defaults = getDefaultSystemMapNodes();
      const savedRows = stmt(`SELECT * FROM system_map_nodes`).all();
      const savedMap = new Map(savedRows.map(r => [r.id, r]));

      const nodes = defaults.map(def => {
        const saved = savedMap.get(def.id);
        if (saved) {
          return {
            ...def,
            x: saved.x,
            y: saved.y,
            label: saved.label || def.label,
            subtitle: saved.subtitle || def.subtitle,
            color: saved.color || def.color,
            config: saved.config ? JSON.parse(saved.config) : null,
          };
        }
        return def;
      });

      // Add custom user-created nodes
      for (const [id, saved] of savedMap) {
        if (saved.is_custom && !defaults.find(d => d.id === id)) {
          nodes.push({
            id: saved.id,
            category: saved.category,
            label: saved.label,
            subtitle: saved.subtitle,
            icon: saved.icon,
            color: saved.color,
            x: saved.x,
            y: saved.y,
            node_type: saved.node_type,
            is_custom: true,
            config: saved.config ? JSON.parse(saved.config) : null,
          });
        }
      }

      // Connections: merge saved custom connections with defaults
      const defaultConns = getDefaultSystemMapConnections();
      const savedConns = stmt(`SELECT * FROM system_map_connections`).all();
      const connKey = (s, t) => `${s}→${t}`;
      const savedConnMap = new Map(savedConns.map(c => [connKey(c.source_id, c.target_id), c]));

      const connections = defaultConns.map(def => {
        const saved = savedConnMap.get(connKey(def.source_id, def.target_id));
        if (saved) {
          return { ...def, ...saved, id: saved.id };
        }
        return def;
      });

      // Add custom connections not in defaults
      for (const [key, saved] of savedConnMap) {
        if (!defaultConns.find(d => connKey(d.source_id, d.target_id) === key)) {
          connections.push(saved);
        }
      }

      // ── Live Stats ──
      const tasksByStatus = stmt(`SELECT status, COUNT(*) as count FROM tasks GROUP BY status`).all();
      const taskStatusMap = {};
      let totalActive = 0;
      for (const r of tasksByStatus) {
        taskStatusMap[r.status] = r.count;
        if (!['completed', 'delivered'].includes(r.status)) totalActive += r.count;
      }

      const runningProcesses = stmt(`SELECT COUNT(*) as c FROM active_processes WHERE status = 'running'`).get().c;
      const teamCount = stmt(`SELECT COUNT(*) as c FROM team_members WHERE status = 'active'`).get().c;

      let boardCount = 0, execCount = 0, specCount = 0;
      try {
        boardCount = stmt(`SELECT COUNT(*) as c FROM team_members WHERE status='active' AND tier='board'`).get().c;
        execCount = stmt(`SELECT COUNT(*) as c FROM team_members WHERE status='active' AND tier='executive'`).get().c;
        specCount = stmt(`SELECT COUNT(*) as c FROM team_members WHERE status='active' AND tier='specialist'`).get().c;
      } catch (_) {}

      const pendingDecisions = stmt(`SELECT COUNT(*) as c FROM decisions WHERE status='pending'`).get().c;
      const governanceReceipts = stmt(`SELECT COUNT(*) as c FROM governance_receipts`).get().c;

      let invariantCount = 0;
      try { invariantCount = stmt(`SELECT COUNT(*) as c FROM constitutional_invariants`).get().c; } catch (_) {}

      let provenanceCount = 0;
      try { provenanceCount = stmt(`SELECT COUNT(*) as c FROM provenance_chain`).get().c; } catch (_) {}

      const autoSpawnEnabled = stmt(`SELECT value FROM system_settings WHERE key='auto_spawn_enabled'`).get();

      return {
        nodes,
        connections,
        stats: {
          tasks: taskStatusMap,
          tasks_active: totalActive,
          running_processes: runningProcesses,
          team_total: teamCount,
          board_count: boardCount,
          exec_count: execCount,
          specialist_count: specCount,
          pending_decisions: pendingDecisions,
          governance_receipts: governanceReceipts,
          invariant_count: invariantCount,
          provenance_count: provenanceCount,
          auto_spawn_enabled: autoSpawnEnabled ? autoSpawnEnabled.value : '1',
        },
      };
    });

    res.json(getMap());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/system-map/live-stats — Lightweight poll endpoint for real-time node badges
app.get('/api/system-map/live-stats', (req, res) => {
  try {
    const getStats = db.transaction(() => {
      const tasksByStatus = stmt(`SELECT status, COUNT(*) as count FROM tasks GROUP BY status`).all();
      const taskStatusMap = {};
      let totalActive = 0;
      for (const r of tasksByStatus) {
        taskStatusMap[r.status] = r.count;
        if (!['completed', 'delivered'].includes(r.status)) totalActive += r.count;
      }

      const runningProcesses = stmt(`SELECT COUNT(*) as c FROM active_processes WHERE status = 'running'`).get().c;

      let deptCounts = [];
      try {
        deptCounts = stmt(`
          SELECT department, COUNT(*) as count
          FROM team_members WHERE status='active' AND tier='specialist'
          GROUP BY department
        `).all();
      } catch (_) {}

      // Recent activity indicator (anything in last 5 minutes = "active")
      let recentActivityCount = 0;
      try {
        recentActivityCount = stmt(`
          SELECT COUNT(*) as c FROM activity_log
          WHERE created_at > datetime('now','localtime','-5 minutes')
        `).get().c;
      } catch (_) {}

      // Active WebSocket connections count
      let wsConnections = 0;
      try { wsConnections = wss.clients.size; } catch (_) {}

      const autoSpawnEnabled = stmt(`SELECT value FROM system_settings WHERE key='auto_spawn_enabled'`).get();

      return {
        tasks: taskStatusMap,
        tasks_active: totalActive,
        running_processes: runningProcesses,
        department_counts: deptCounts,
        recent_activity: recentActivityCount,
        ws_connections: wsConnections,
        auto_spawn_enabled: autoSpawnEnabled ? autoSpawnEnabled.value : '1',
        timestamp: new Date().toISOString(),
      };
    });

    res.json(getStats());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/system-map/nodes — Batch save node positions (drag result)
app.post('/api/system-map/nodes', (req, res) => {
  try {
    const { nodes } = req.body;
    if (!Array.isArray(nodes)) {
      return res.status(400).json({ error: 'nodes must be an array' });
    }

    const upsert = db.prepare(`
      INSERT INTO system_map_nodes (id, x, y, node_type, category, label, subtitle, icon, color, is_custom, config, updated_at)
      VALUES (@id, @x, @y, @node_type, @category, @label, @subtitle, @icon, @color, @is_custom, @config, datetime('now','localtime'))
      ON CONFLICT(id) DO UPDATE SET
        x = excluded.x,
        y = excluded.y,
        label = COALESCE(excluded.label, system_map_nodes.label),
        subtitle = COALESCE(excluded.subtitle, system_map_nodes.subtitle),
        color = COALESCE(excluded.color, system_map_nodes.color),
        icon = COALESCE(excluded.icon, system_map_nodes.icon),
        config = COALESCE(excluded.config, system_map_nodes.config),
        updated_at = datetime('now','localtime')
    `);

    const saveAll = db.transaction(() => {
      for (const node of nodes) {
        upsert.run({
          id: node.id,
          x: node.x ?? 0,
          y: node.y ?? 0,
          node_type: node.node_type || 'default',
          category: node.category || 'custom',
          label: node.label || '',
          subtitle: node.subtitle || null,
          icon: node.icon || null,
          color: node.color || null,
          is_custom: node.is_custom ? 1 : 0,
          config: node.config ? JSON.stringify(node.config) : null,
        });
      }
    });

    saveAll();
    res.json({ ok: true, saved: nodes.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/system-map/nodes/:id — Update a single node
app.put('/api/system-map/nodes/:id', (req, res) => {
  try {
    const { id } = req.params;
    const { x, y, label, subtitle, color, icon, config } = req.body;

    const existing = stmt(`SELECT * FROM system_map_nodes WHERE id = ?`).get(id);
    if (existing) {
      db.prepare(`
        UPDATE system_map_nodes
        SET x = COALESCE(?, x), y = COALESCE(?, y),
            label = COALESCE(?, label), subtitle = COALESCE(?, subtitle),
            color = COALESCE(?, color), icon = COALESCE(?, icon),
            config = COALESCE(?, config),
            updated_at = datetime('now','localtime')
        WHERE id = ?
      `).run(x ?? null, y ?? null, label ?? null, subtitle ?? null, color ?? null, icon ?? null, config ? JSON.stringify(config) : null, id);
    } else {
      // Create from default or as new
      const defaults = getDefaultSystemMapNodes();
      const def = defaults.find(d => d.id === id);
      db.prepare(`
        INSERT INTO system_map_nodes (id, x, y, node_type, category, label, subtitle, icon, color, is_custom, config)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        x ?? (def ? def.x : 0),
        y ?? (def ? def.y : 0),
        'default',
        def ? def.category : 'custom',
        label || (def ? def.label : id),
        subtitle || (def ? def.subtitle : null),
        icon || (def ? def.icon : null),
        color || (def ? def.color : null),
        def ? 0 : 1,
        config ? JSON.stringify(config) : null
      );
    }

    res.json({ ok: true, id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/system-map/nodes/:id — Remove a custom node
app.delete('/api/system-map/nodes/:id', (req, res) => {
  try {
    const { id } = req.params;
    // Only delete custom nodes — default nodes just get their saved position removed
    const node = stmt(`SELECT is_custom FROM system_map_nodes WHERE id = ?`).get(id);
    if (node && node.is_custom) {
      db.prepare(`DELETE FROM system_map_nodes WHERE id = ?`).run(id);
      db.prepare(`DELETE FROM system_map_connections WHERE source_id = ? OR target_id = ?`).run(id, id);
      res.json({ ok: true, deleted: true, id });
    } else if (node) {
      // Reset to default position by removing saved row
      db.prepare(`DELETE FROM system_map_nodes WHERE id = ?`).run(id);
      res.json({ ok: true, reset: true, id });
    } else {
      res.json({ ok: true, deleted: false, id });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/system-map/connections — Add or update a connection
app.post('/api/system-map/connections', (req, res) => {
  try {
    const { source_id, target_id, label, line_type, color, animated } = req.body;
    if (!source_id || !target_id) {
      return res.status(400).json({ error: 'source_id and target_id required' });
    }
    db.prepare(`
      INSERT INTO system_map_connections (source_id, target_id, label, line_type, color, animated)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(source_id, target_id) DO UPDATE SET
        label = excluded.label,
        line_type = excluded.line_type,
        color = excluded.color,
        animated = excluded.animated
    `).run(source_id, target_id, label || null, line_type || 'bezier', color || null, animated ? 1 : 0);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/system-map/connections — Remove a connection
app.delete('/api/system-map/connections', (req, res) => {
  try {
    const { source_id, target_id } = req.body;
    if (!source_id || !target_id) {
      return res.status(400).json({ error: 'source_id and target_id required' });
    }
    const result = db.prepare(`DELETE FROM system_map_connections WHERE source_id = ? AND target_id = ?`).run(source_id, target_id);
    res.json({ ok: true, deleted: result.changes > 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/system-map/reset — Reset all positions to defaults
app.post('/api/system-map/reset', (req, res) => {
  try {
    const resetAll = db.transaction(() => {
      // Only remove non-custom nodes (reset positions) — keep custom nodes
      db.prepare(`DELETE FROM system_map_nodes WHERE is_custom = 0`).run();
      // Remove custom connections that override defaults
      db.prepare(`DELETE FROM system_map_connections`).run();
    });
    resetAll();
    res.json({ ok: true, message: 'System map reset to defaults' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/layout-templates — list all templates
app.get('/api/layout-templates', (req, res) => {
  try {
    const rows = stmt(`SELECT * FROM layout_templates ORDER BY is_builtin DESC, name ASC`).all();
    const templates = rows.map(r => ({
      ...r,
      panels: JSON.parse(r.panels),
      grid_config: JSON.parse(r.grid_config),
      is_builtin: !!r.is_builtin,
      is_active: !!r.is_active
    }));
    res.json({ templates });
  } catch (err) {
    console.error('GET /api/layout-templates error:', err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/layout-templates/active — get the active template
app.get('/api/layout-templates/active', (req, res) => {
  try {
    const row = stmt(`SELECT * FROM layout_templates WHERE is_active = 1 LIMIT 1`).get();
    if (!row) {
      // Fallback to first built-in
      const fallback = stmt(`SELECT * FROM layout_templates WHERE is_builtin = 1 ORDER BY id ASC LIMIT 1`).get();
      if (!fallback) return res.status(404).json({ error: 'No layout templates found' });
      const template = { ...fallback, panels: JSON.parse(fallback.panels), grid_config: JSON.parse(fallback.grid_config), is_builtin: true, is_active: false };
      return res.json({ template });
    }
    const template = { ...row, panels: JSON.parse(row.panels), grid_config: JSON.parse(row.grid_config), is_builtin: !!row.is_builtin, is_active: true };
    res.json({ template });
  } catch (err) {
    console.error('GET /api/layout-templates/active error:', err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/layout-templates/:id — get single template
app.get('/api/layout-templates/:id', (req, res) => {
  try {
    const row = stmt(`SELECT * FROM layout_templates WHERE id = ?`).get(Number(req.params.id));
    if (!row) return res.status(404).json({ error: 'Template not found' });
    const template = { ...row, panels: JSON.parse(row.panels), grid_config: JSON.parse(row.grid_config), is_builtin: !!row.is_builtin, is_active: !!row.is_active };
    res.json({ template });
  } catch (err) {
    console.error('GET /api/layout-templates/:id error:', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/layout-templates — create a new user template
app.post('/api/layout-templates', (req, res) => {
  try {
    const { name, panels, grid_config } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'name is required' });
    }
    if (!Array.isArray(panels)) {
      return res.status(400).json({ error: 'panels must be an array' });
    }

    // Validate each panel has required fields
    for (const panel of panels) {
      if (typeof panel.id !== 'string' || panel.x == null || panel.y == null || panel.w == null || panel.h == null) {
        return res.status(400).json({ error: 'Each panel must have id (string), x, y, w, h (numbers)' });
      }
    }

    // Check for duplicate name
    const existing = stmt(`SELECT id FROM layout_templates WHERE name = ?`).get(name.trim());
    if (existing) {
      return res.status(409).json({ error: 'A template with that name already exists' });
    }

    const now = localNow();
    const panelsJson = JSON.stringify(panels);
    const gridJson = grid_config ? JSON.stringify(grid_config) : '{"columns":24,"rowHeight":60,"margin":10,"containerPadding":10}';

    const result = stmt(`
      INSERT INTO layout_templates (name, is_builtin, is_active, panels, grid_config, created_at, updated_at)
      VALUES (?, 0, 0, ?, ?, ?, ?)
    `).run(name.trim(), panelsJson, gridJson, now, now);

    const id = Number(result.lastInsertRowid);
    const row = stmt(`SELECT * FROM layout_templates WHERE id = ?`).get(id);
    const template = { ...row, panels: JSON.parse(row.panels), grid_config: JSON.parse(row.grid_config), is_builtin: false, is_active: false };

    res.status(201).json({ template });
    broadcast('layout.updated', { id });
  } catch (err) {
    console.error('POST /api/layout-templates error:', err);
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/layout-templates/:id — update a template (panels, name, grid_config)
app.put('/api/layout-templates/:id', (req, res) => {
  try {
    const id = Number(req.params.id);
    const row = stmt(`SELECT * FROM layout_templates WHERE id = ?`).get(id);
    if (!row) return res.status(404).json({ error: 'Template not found' });

    // Built-in templates: only allow toggling panel visibility, not renaming or restructuring
    if (row.is_builtin && req.body.name && req.body.name.trim() !== row.name) {
      return res.status(403).json({ error: 'Cannot rename built-in templates' });
    }

    const { name, panels, grid_config } = req.body;

    // If renaming, check for duplicate
    if (name && name.trim() !== row.name) {
      const dup = stmt(`SELECT id FROM layout_templates WHERE name = ? AND id != ?`).get(name.trim(), id);
      if (dup) return res.status(409).json({ error: 'A template with that name already exists' });
    }

    if (panels && !Array.isArray(panels)) {
      return res.status(400).json({ error: 'panels must be an array' });
    }

    const now = localNow();
    const updatedName = name ? name.trim() : row.name;
    const updatedPanels = panels ? JSON.stringify(panels) : row.panels;
    const updatedGrid = grid_config ? JSON.stringify(grid_config) : row.grid_config;

    stmt(`
      UPDATE layout_templates SET name = ?, panels = ?, grid_config = ?, updated_at = ? WHERE id = ?
    `).run(updatedName, updatedPanels, updatedGrid, now, id);

    const updated = stmt(`SELECT * FROM layout_templates WHERE id = ?`).get(id);
    const template = { ...updated, panels: JSON.parse(updated.panels), grid_config: JSON.parse(updated.grid_config), is_builtin: !!updated.is_builtin, is_active: !!updated.is_active };

    res.json({ template });
    broadcast('layout.updated', { id });
  } catch (err) {
    console.error('PUT /api/layout-templates/:id error:', err);
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/layout-templates/:id — delete a user-created template
app.delete('/api/layout-templates/:id', (req, res) => {
  try {
    const id = Number(req.params.id);
    const row = stmt(`SELECT * FROM layout_templates WHERE id = ?`).get(id);
    if (!row) return res.status(404).json({ error: 'Template not found' });

    if (row.is_builtin) {
      return res.status(403).json({ error: 'Cannot delete built-in templates' });
    }

    // If deleting the active template, activate the Default built-in
    if (row.is_active) {
      stmt(`UPDATE layout_templates SET is_active = 1 WHERE is_builtin = 1 AND name = 'Default'`).run();
    }

    stmt(`DELETE FROM layout_templates WHERE id = ?`).run(id);

    res.json({ success: true, id });
    broadcast('layout.updated', { id: null });
  } catch (err) {
    console.error('DELETE /api/layout-templates/:id error:', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/layout-templates/active — set the active template by id
app.post('/api/layout-templates/active', (req, res) => {
  try {
    const { id } = req.body;
    if (!id) return res.status(400).json({ error: 'id is required' });

    const row = stmt(`SELECT * FROM layout_templates WHERE id = ?`).get(Number(id));
    if (!row) return res.status(404).json({ error: 'Template not found' });

    db.transaction(() => {
      stmt(`UPDATE layout_templates SET is_active = 0`).run();
      stmt(`UPDATE layout_templates SET is_active = 1 WHERE id = ?`).run(Number(id));
    })();

    const updated = stmt(`SELECT * FROM layout_templates WHERE id = ?`).get(Number(id));
    const template = { ...updated, panels: JSON.parse(updated.panels), grid_config: JSON.parse(updated.grid_config), is_builtin: !!updated.is_builtin, is_active: true };

    res.json({ template });
    broadcast('layout.updated', { id: Number(id), active: true });
  } catch (err) {
    console.error('POST /api/layout-templates/active error:', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/layout-templates/:id/duplicate — duplicate a template with a new name
app.post('/api/layout-templates/:id/duplicate', (req, res) => {
  try {
    const id = Number(req.params.id);
    const source = stmt(`SELECT * FROM layout_templates WHERE id = ?`).get(id);
    if (!source) return res.status(404).json({ error: 'Template not found' });

    // Generate unique name
    let baseName = (req.body.name || `${source.name} Copy`).trim();
    let newName = baseName;
    let suffix = 1;
    while (stmt(`SELECT id FROM layout_templates WHERE name = ?`).get(newName)) {
      suffix++;
      newName = `${baseName} ${suffix}`;
    }

    const now = localNow();
    const result = stmt(`
      INSERT INTO layout_templates (name, is_builtin, is_active, panels, grid_config, created_at, updated_at)
      VALUES (?, 0, 0, ?, ?, ?, ?)
    `).run(newName, source.panels, source.grid_config, now, now);

    const newId = Number(result.lastInsertRowid);
    const row = stmt(`SELECT * FROM layout_templates WHERE id = ?`).get(newId);
    const template = { ...row, panels: JSON.parse(row.panels), grid_config: JSON.parse(row.grid_config), is_builtin: false, is_active: false };

    res.status(201).json({ template });
    broadcast('layout.updated', { id: newId });
  } catch (err) {
    console.error('POST /api/layout-templates/:id/duplicate error:', err);
    res.status(500).json({ error: err.message });
  }
});


};
