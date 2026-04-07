'use strict';
module.exports = function(app, db, helpers) {
  const { broadcast, localNow, createNotification, authRateLimiter, apiRateLimiter, spawnMemberTerminal } = helpers;
  const stmt = helpers.stmt || ((sql) => db.prepare(sql));

app.get('/api/analytics/overview', (req, res) => {
  try {
    const totalTasks = db.prepare(`SELECT COUNT(*) as c FROM tasks`).get().c;
    const deliveredTasks = db.prepare(`SELECT COUNT(*) as c FROM tasks WHERE status = 'delivered'`).get().c;
    const completedTasks = db.prepare(`SELECT COUNT(*) as c FROM tasks WHERE status IN ('completed','delivered')`).get().c;
    const totalProjects = db.prepare(`SELECT COUNT(*) as c FROM projects`).get().c;
    const totalRevisions = db.prepare(`SELECT COALESCE(SUM(revision_count),0) as c FROM tasks`).get().c;
    const avgRevisions = totalTasks > 0 ? (totalRevisions / totalTasks).toFixed(1) : 0;

    res.json({ totalTasks, deliveredTasks, completedTasks, totalProjects, totalRevisions, avgRevisions });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/analytics/status-pipeline', (req, res) => {
  try {
    const rows = db.prepare(`SELECT status, COUNT(*) as count FROM tasks GROUP BY status ORDER BY
      CASE status WHEN 'new' THEN 0 WHEN 'routing' THEN 1 WHEN 'in_progress' THEN 2 WHEN 'review' THEN 3 WHEN 'completed' THEN 4 WHEN 'delivered' THEN 5 END`).all();
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/analytics/momentum', (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT date(t.delivered_at) as day, p.name as project_name, p.id as project_id, COUNT(*) as count
      FROM tasks t
      LEFT JOIN project_tasks pt ON pt.task_id = t.id
      LEFT JOIN projects p ON pt.project_id = p.id
      WHERE t.delivered_at IS NOT NULL
      GROUP BY day, p.id
      ORDER BY day ASC
    `).all();
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/analytics/project-progress', (req, res) => {
  try {
    const projects = db.prepare(`SELECT * FROM projects ORDER BY name`).all();
    const result = projects.map(p => {
      const tasks = db.prepare(`
        SELECT t.status, COUNT(*) as count
        FROM tasks t JOIN project_tasks pt ON pt.task_id = t.id
        WHERE pt.project_id = ?
        GROUP BY t.status
      `).all(p.id);
      const total = tasks.reduce((s, t) => s + t.count, 0);
      const done = tasks.filter(t => ['completed', 'delivered'].includes(t.status)).reduce((s, t) => s + t.count, 0);
      return { ...p, tasks, total, done, percent: total > 0 ? Math.round((done / total) * 100) : 0 };
    });
    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/analytics/team-workload', (req, res) => {
  try {
    // Collect all task_ids per member: union of assigned_to and task_assignments
    const rows = db.prepare(`
      SELECT tm.id, tm.name, tm.role, tm.tier, COALESCE(tm.department, 'Other') as department,
        COUNT(CASE WHEN t.status NOT IN ('completed','delivered') THEN 1 END) as active_tasks,
        COUNT(CASE WHEN t.status IN ('completed','delivered') THEN 1 END) as completed_tasks,
        COUNT(CASE WHEN t.status = 'new' THEN 1 END) as new_tasks,
        COUNT(CASE WHEN t.status = 'routing' THEN 1 END) as routing_tasks,
        COUNT(CASE WHEN t.status = 'in_progress' THEN 1 END) as in_progress_tasks,
        COUNT(CASE WHEN t.status = 'review' THEN 1 END) as review_tasks,
        COUNT(CASE WHEN t.priority = 'urgent' AND t.status NOT IN ('completed','delivered') THEN 1 END) as urgent_tasks,
        COUNT(CASE WHEN t.priority = 'high' AND t.status NOT IN ('completed','delivered') THEN 1 END) as high_tasks,
        COALESCE(SUM(t.revision_count), 0) as total_revisions
      FROM team_members tm
      LEFT JOIN (
        SELECT assigned_to AS member_id, id, status, priority, revision_count FROM tasks WHERE assigned_to IS NOT NULL
        UNION
        SELECT ta.member_id, t2.id, t2.status, t2.priority, t2.revision_count
        FROM task_assignments ta JOIN tasks t2 ON t2.id = ta.task_id
      ) t ON t.member_id = tm.id
      WHERE tm.status = 'active'
      GROUP BY tm.id
      ORDER BY active_tasks DESC, tm.name
    `).all();
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/analytics/workload-dept', (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT
        COALESCE(tm.department, 'Other') as department,
        COUNT(DISTINCT tm.id) as member_count,
        COUNT(CASE WHEN t.status NOT IN ('completed','delivered') THEN 1 END) as active_tasks,
        COUNT(CASE WHEN t.priority = 'urgent' AND t.status NOT IN ('completed','delivered') THEN 1 END) as urgent_tasks,
        COUNT(CASE WHEN t.priority = 'high' AND t.status NOT IN ('completed','delivered') THEN 1 END) as high_tasks
      FROM team_members tm
      LEFT JOIN (
        SELECT assigned_to AS member_id, id, status, priority FROM tasks WHERE assigned_to IS NOT NULL
        UNION
        SELECT ta.member_id, t2.id, t2.status, t2.priority
        FROM task_assignments ta JOIN tasks t2 ON t2.id = ta.task_id
      ) t ON t.member_id = tm.id
      WHERE tm.status = 'active'
      GROUP BY COALESCE(tm.department, 'Other')
      ORDER BY active_tasks DESC, department
    `).all();
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/analytics/trends', (req, res) => {
  try {
    // Tasks delivered this week vs last week
    const deliveredCurrent = db.prepare(`
      SELECT COUNT(*) as c FROM tasks
      WHERE status IN ('delivered', 'completed')
        AND updated_at >= date('now', '-7 days')
    `).get().c;

    const deliveredPrevious = db.prepare(`
      SELECT COUNT(*) as c FROM tasks
      WHERE status IN ('delivered', 'completed')
        AND updated_at >= date('now', '-14 days')
        AND updated_at < date('now', '-7 days')
    `).get().c;

    // Tasks created this week vs last week
    const createdCurrent = db.prepare(`
      SELECT COUNT(*) as c FROM tasks
      WHERE created_at >= date('now', '-7 days')
    `).get().c;

    const createdPrevious = db.prepare(`
      SELECT COUNT(*) as c FROM tasks
      WHERE created_at >= date('now', '-14 days')
        AND created_at < date('now', '-7 days')
    `).get().c;

    // Active members (distinct actors in activity_log last 7 days)
    const activeMembers = db.prepare(`
      SELECT COUNT(DISTINCT actor) as c FROM activity_log
      WHERE created_at >= date('now', '-7 days')
    `).get().c;

    // Daily counts for last 14 days
    const dailyCounts = db.prepare(`
      SELECT
        d.date,
        COALESCE(del.delivered, 0) as delivered,
        COALESCE(cr.created, 0) as created
      FROM (
        SELECT date('now', '-' || n || ' days') as date
        FROM (
          SELECT 0 as n UNION SELECT 1 UNION SELECT 2 UNION SELECT 3
          UNION SELECT 4 UNION SELECT 5 UNION SELECT 6 UNION SELECT 7
          UNION SELECT 8 UNION SELECT 9 UNION SELECT 10 UNION SELECT 11
          UNION SELECT 12 UNION SELECT 13
        )
      ) d
      LEFT JOIN (
        SELECT date(updated_at) as day, COUNT(*) as delivered
        FROM tasks WHERE status IN ('delivered', 'completed')
        GROUP BY date(updated_at)
      ) del ON del.day = d.date
      LEFT JOIN (
        SELECT date(created_at) as day, COUNT(*) as created
        FROM tasks
        GROUP BY date(created_at)
      ) cr ON cr.day = d.date
      ORDER BY d.date ASC
    `).all();

    res.json({
      tasks_delivered: {
        current_week: deliveredCurrent,
        previous_week: deliveredPrevious,
        delta: deliveredCurrent - deliveredPrevious
      },
      tasks_created: {
        current_week: createdCurrent,
        previous_week: createdPrevious,
        delta: createdCurrent - createdPrevious
      },
      active_members: { current: activeMembers },
      daily_counts: dailyCounts
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/analytics/activity-timeline', (req, res) => {
  try {
    const { project_id, limit: lim } = req.query;
    let sql = `SELECT a.*, t.title as task_title, date(a.created_at) as day
      FROM activity_log a LEFT JOIN tasks t ON a.task_id = t.id`;
    const params = [];
    if (project_id) {
      sql += ` WHERE a.task_id IN (SELECT task_id FROM project_tasks WHERE project_id = ?)`;
      params.push(project_id);
    }
    sql += ` ORDER BY a.created_at DESC LIMIT ?`;
    params.push(parseInt(lim) || 100);
    res.json(db.prepare(sql).all(...params));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/analytics/calendar-allocation', (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT calendar_type,
        COUNT(*) as event_count,
        ROUND(SUM(
          CASE WHEN end_time IS NOT NULL
            THEN (julianday(end_time) - julianday(start_time)) * 24
            ELSE 1
          END
        ), 1) as total_hours
      FROM calendar_events
      WHERE status != 'cancelled'
      GROUP BY calendar_type
    `).all();
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/analytics/priority-heatmap', (req, res) => {
  try {
    // Active tasks (not completed/delivered)
    const active = db.prepare(`
      SELECT
        CASE CAST(strftime('%w', created_at) AS INTEGER)
          WHEN 0 THEN 'Sun' WHEN 1 THEN 'Mon' WHEN 2 THEN 'Tue' WHEN 3 THEN 'Wed'
          WHEN 4 THEN 'Thu' WHEN 5 THEN 'Fri' WHEN 6 THEN 'Sat' END as day_name,
        CAST(strftime('%w', created_at) AS INTEGER) as day_num,
        priority, COUNT(*) as count
      FROM tasks WHERE status NOT IN ('completed', 'delivered')
      GROUP BY day_num, priority
      ORDER BY day_num
    `).all();

    // Completed tasks
    const completed = db.prepare(`
      SELECT
        CASE CAST(strftime('%w', created_at) AS INTEGER)
          WHEN 0 THEN 'Sun' WHEN 1 THEN 'Mon' WHEN 2 THEN 'Tue' WHEN 3 THEN 'Wed'
          WHEN 4 THEN 'Thu' WHEN 5 THEN 'Fri' WHEN 6 THEN 'Sat' END as day_name,
        CAST(strftime('%w', created_at) AS INTEGER) as day_num,
        priority, COUNT(*) as count
      FROM tasks WHERE status IN ('completed', 'delivered')
      GROUP BY day_num, priority
      ORDER BY day_num
    `).all();

    res.json({ active, completed });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/analytics/website-progression', (req, res) => {
  try {
    const stats = {
      total_improvements: db.prepare(`SELECT COUNT(*) as c FROM improvement_proposals`).get().c,
      completed: db.prepare(`SELECT COUNT(*) as c FROM improvement_proposals WHERE status = 'completed'`).get().c,
      in_progress: db.prepare(`SELECT COUNT(*) as c FROM improvement_proposals WHERE status = 'in_progress'`).get().c,
      approved: db.prepare(`SELECT COUNT(*) as c FROM improvement_proposals WHERE status = 'approved'`).get().c,
      proposed: db.prepare(`SELECT COUNT(*) as c FROM improvement_proposals WHERE status = 'proposed'`).get().c,
      denied: db.prepare(`SELECT COUNT(*) as c FROM improvement_proposals WHERE status = 'denied'`).get().c
    };

    // Completed improvements timeline
    const timeline = db.prepare(`
      SELECT id, title, category, impact, completed_at, files_changed
      FROM improvement_proposals WHERE status = 'completed'
      ORDER BY completed_at DESC
    `).all();

    // By category breakdown
    const byCategory = db.prepare(`
      SELECT category, COUNT(*) as total,
        COUNT(CASE WHEN status = 'completed' THEN 1 END) as done
      FROM improvement_proposals GROUP BY category ORDER BY total DESC
    `).all();

    res.json({ stats, timeline, by_category: byCategory });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/analytics/hierarchy', (req, res) => {
  try {
    const goals = db.prepare(`SELECT * FROM end_goals ORDER BY sort_order`).all();
    const visions = db.prepare(`SELECT v.*, p.name as project_name FROM visions v LEFT JOIN projects p ON v.project_id = p.id ORDER BY v.sort_order`).all();
    const projects = db.prepare(`SELECT * FROM projects`).all();
    const missions = db.prepare(`SELECT * FROM missions`).all();

    // Project-goal links
    const pg = db.prepare(`SELECT * FROM project_goals`).all();
    // Vision-goal links
    const vg = db.prepare(`SELECT * FROM vision_goals`).all();
    // Project task counts
    const ptCounts = db.prepare(`SELECT pt.project_id, COUNT(*) as total,
      COUNT(CASE WHEN t.status IN ('completed','delivered') THEN 1 END) as done
      FROM project_tasks pt JOIN tasks t ON pt.task_id = t.id GROUP BY pt.project_id`).all();

    res.json({ goals, visions, projects, missions, project_goals: pg, vision_goals: vg, project_task_counts: ptCounts });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/analytics/org-chart', (req, res) => {
  try {
    const members = db.prepare(`
      SELECT m.id, m.name, m.role, m.tier, m.department, m.status, m.reports_to, m.icon,
        boss.name as reports_to_name,
        (SELECT COUNT(*) FROM tasks t WHERE t.assigned_to = m.id AND t.status NOT IN ('completed','delivered')) as active_task_count,
        (SELECT COUNT(*) FROM active_processes ap WHERE ap.member_id = m.id AND ap.status = 'running') as running_processes
      FROM team_members m
      LEFT JOIN team_members boss ON m.reports_to = boss.id
      WHERE m.status = 'active'
      ORDER BY
        CASE m.tier WHEN 'board' THEN 0 WHEN 'c-suite' THEN 1 WHEN 'specialist' THEN 2 WHEN 'orchestrator' THEN 3 WHEN 'leader' THEN 4 WHEN 'co-leader' THEN 5 WHEN 'subagent' THEN 6 END,
        m.department, m.name
    `).all();

    // Build structured hierarchy for frontend rendering
    const chairman = members.find(m => m.tier === 'board' && !m.reports_to);
    const board = members.filter(m => m.tier === 'board' && m.reports_to);
    const csuite = members.filter(m => m.tier === 'c-suite');
    const specialists = members.filter(m => m.tier === 'specialist');

    // Walk reports_to chain to group specialists under their c-suite executive
    const memberMap = buildMemberMap(members);
    const { byExec: specialistsByExec, unassigned: unassignedSpecs } = groupSpecialistsByExec(specialists, memberMap);

    // Build c-suite with their direct reports
    const csuiteWithReports = csuite.map(exec => ({
      ...exec,
      direct_reports: specialistsByExec[exec.id] || []
    }));

    // Group by department
    const deptGroups = {};
    for (const s of specialists) {
      const dept = s.department || 'Unassigned';
      if (!deptGroups[dept]) deptGroups[dept] = [];
      deptGroups[dept].push(s);
    }

    res.json({
      chairman,
      board,
      csuite: csuiteWithReports,
      specialists,
      deptGroups,
      unassigned: unassignedSpecs,
      stats: {
        total_members: members.length,
        board_count: (chairman ? 1 : 0) + board.length,
        csuite_count: csuite.length,
        specialist_count: specialists.length,
        dept_count: Object.keys(deptGroups).length
      },
      // Flat list for backward compat
      members
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/analytics/agents', (req, res) => {
  try {
    const agents = db.prepare(`
        SELECT tm.id, tm.name, tm.role, tm.tier, tm.department,
            (SELECT COUNT(DISTINCT task_id) FROM active_processes WHERE member_id = tm.id AND status = 'completed') as tasks_completed,
            (SELECT COUNT(DISTINCT ap2.task_id) FROM active_processes ap2
              WHERE ap2.member_id = tm.id AND ap2.status = 'failed'
              AND ap2.task_id NOT IN (SELECT task_id FROM active_processes WHERE member_id = tm.id AND status = 'completed')
            ) as tasks_failed,
            (SELECT COUNT(*) FROM active_processes WHERE member_id = tm.id AND status = 'running') as currently_running,
            (SELECT COALESCE(AVG(duration_ms), 0) FROM heartbeat_runs WHERE member_id = tm.id AND status = 'completed') as avg_duration_ms,
            (SELECT COALESCE(SUM(cost_cents), 0) FROM cost_events WHERE member_id = tm.id) as total_cost_cents,
            (SELECT MAX(completed_at) FROM active_processes WHERE member_id = tm.id AND status = 'completed') as last_completed,
            (SELECT COUNT(*) FROM context_store WHERE author_member_id = tm.id) as context_items
        FROM team_members tm
        WHERE tm.status = 'active' AND tm.tier = 'specialist'
        ORDER BY tasks_completed DESC
    `).all();

    // Calculate success rate and efficiency score
    for (const agent of agents) {
        const total = agent.tasks_completed + agent.tasks_failed;
        agent.success_rate = total > 0 ? Math.round((agent.tasks_completed / total) * 100) : 0;
        agent.avg_duration_min = Math.round(agent.avg_duration_ms / 60000);
        // Efficiency = high completion + low failure + fast execution
        agent.efficiency_score = agent.tasks_completed > 0
            ? Math.round((agent.success_rate * 0.5) + (Math.max(0, 100 - agent.avg_duration_min) * 0.3) + (Math.min(agent.tasks_completed, 20) * 5 * 0.2))
            : 0;
    }

    res.json(agents);
  } catch (err) {
    console.error('GET /api/analytics/agents error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/analytics/team-usage', (req, res) => {
  try {
    const now = localNow();

    // All active members with their usage stats
    const members = db.prepare(`
        SELECT tm.id, tm.name, tm.role, tm.tier, tm.department,
            (SELECT COUNT(*) FROM active_processes WHERE member_id = tm.id AND status = 'completed') as completed,
            (SELECT COUNT(*) FROM active_processes WHERE member_id = tm.id AND status = 'failed') as failed,
            (SELECT COUNT(*) FROM active_processes WHERE member_id = tm.id AND status = 'running') as running,
            (SELECT COUNT(DISTINCT task_id) FROM active_processes WHERE member_id = tm.id AND status = 'completed') as unique_tasks,
            (SELECT COUNT(*) FROM agent_memory_entities WHERE member_id = tm.id) as memory_items,
            (SELECT COUNT(*) FROM agent_tacit_knowledge WHERE member_id = tm.id) as tacit_items,
            (SELECT COALESCE(SUM(cost_cents),0) FROM cost_events WHERE member_id = tm.id) as total_cost,
            (SELECT MAX(completed_at) FROM active_processes WHERE member_id = tm.id AND status = 'completed') as last_active
        FROM team_members tm
        WHERE tm.status = 'active' AND tm.tier = 'specialist'
        ORDER BY completed DESC
    `).all();

    // Calculate success rates
    for (const m of members) {
        const total = m.completed + m.failed;
        m.success_rate = total > 0 ? Math.round((m.completed / total) * 100) : 0;
        m.total_tasks = total;
    }

    // Usage by category (what types of work each member has done)
    const categoryUsage = db.prepare(`
        SELECT tm.name,
            t.source_file as category,
            COUNT(*) as count
        FROM active_processes ap
        JOIN team_members tm ON ap.member_id = tm.id
        JOIN tasks t ON ap.task_id = t.id
        WHERE ap.status = 'completed' AND tm.status = 'active'
        GROUP BY tm.id, t.source_file
        ORDER BY tm.name, count DESC
    `).all();

    // Usage over time (daily breakdown for last 14 days)
    const dailyUsage = db.prepare(`
        SELECT date(ap.completed_at) as day,
            tm.name,
            COUNT(*) as tasks
        FROM active_processes ap
        JOIN team_members tm ON ap.member_id = tm.id
        WHERE ap.status = 'completed'
        AND ap.completed_at > datetime(?, '-14 days')
        GROUP BY day, tm.name
        ORDER BY day
    `).all(now);

    // Usage by tier
    const tierUsage = db.prepare(`
        SELECT tm.tier,
            COUNT(DISTINCT tm.id) as members,
            COUNT(ap.id) as total_tasks,
            COUNT(DISTINCT CASE WHEN ap.status = 'completed' THEN ap.member_id END) as active_members
        FROM team_members tm
        LEFT JOIN active_processes ap ON tm.id = ap.member_id
        WHERE tm.status = 'active' AND tm.tier = 'specialist'
        GROUP BY tm.tier
    `).all();

    // Usage by department
    const deptUsage = db.prepare(`
        SELECT tm.department,
            COUNT(DISTINCT tm.id) as members,
            COUNT(CASE WHEN ap.status = 'completed' THEN 1 END) as completed_tasks,
            COUNT(DISTINCT CASE WHEN ap.status = 'completed' THEN ap.member_id END) as active_members
        FROM team_members tm
        LEFT JOIN active_processes ap ON tm.id = ap.member_id
        WHERE tm.status = 'active' AND tm.tier = 'specialist'
        AND tm.department IS NOT NULL
        GROUP BY tm.department
        ORDER BY completed_tasks DESC
    `).all();

    // Distribution score
    const withWork = members.filter(m => m.completed > 0).length;
    const totalEligible = members.length;
    const distributionScore = Math.round((withWork / Math.max(totalEligible, 1)) * 100);

    // Growth metrics (members who gained knowledge recently)
    const recentGrowth = db.prepare(`
        SELECT tm.name, COUNT(*) as new_knowledge
        FROM agent_tacit_knowledge atk
        JOIN team_members tm ON atk.member_id = tm.id
        WHERE atk.created_at > datetime(?, '-7 days')
        GROUP BY tm.id
        ORDER BY new_knowledge DESC LIMIT 10
    `).all(now);

    res.json({
        members,
        category_usage: categoryUsage,
        daily_usage: dailyUsage,
        tier_usage: tierUsage,
        department_usage: deptUsage,
        distribution: { score: distributionScore, with_work: withWork, total: totalEligible, idle: totalEligible - withWork },
        recent_growth: recentGrowth
    });
  } catch (err) {
    console.error('GET /api/analytics/team-usage error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/analytics/operations', (req, res) => {
  try {
    const now = localNow();

    const getOpsMetrics = db.transaction(() => {
      // ── 1. Cycle Time Metrics ──
      // Avg time (hours) spent in each pipeline stage for delivered tasks
      const cycleTimes = stmt(`
        SELECT
          COUNT(*) as sample_size,
          ROUND(AVG(CASE WHEN started_at IS NOT NULL AND created_at IS NOT NULL
            THEN (julianday(started_at) - julianday(created_at)) * 24 END), 1) as avg_wait_hours,
          ROUND(AVG(CASE WHEN completed_at IS NOT NULL AND started_at IS NOT NULL
            THEN (julianday(completed_at) - julianday(started_at)) * 24 END), 1) as avg_work_hours,
          ROUND(AVG(CASE WHEN delivered_at IS NOT NULL AND completed_at IS NOT NULL
            THEN (julianday(delivered_at) - julianday(completed_at)) * 24 END), 1) as avg_review_hours,
          ROUND(AVG(CASE WHEN delivered_at IS NOT NULL AND created_at IS NOT NULL
            THEN (julianday(delivered_at) - julianday(created_at)) * 24 END), 1) as avg_total_hours,
          ROUND(MIN(CASE WHEN delivered_at IS NOT NULL AND created_at IS NOT NULL
            THEN (julianday(delivered_at) - julianday(created_at)) * 24 END), 1) as min_total_hours,
          ROUND(MAX(CASE WHEN delivered_at IS NOT NULL AND created_at IS NOT NULL
            THEN (julianday(delivered_at) - julianday(created_at)) * 24 END), 1) as max_total_hours
        FROM tasks
        WHERE status IN ('completed', 'delivered')
          AND created_at IS NOT NULL
      `).get();

      // Cycle time by priority
      const cycleByPriority = stmt(`
        SELECT priority,
          COUNT(*) as count,
          ROUND(AVG(CASE WHEN delivered_at IS NOT NULL AND created_at IS NOT NULL
            THEN (julianday(delivered_at) - julianday(created_at)) * 24 END), 1) as avg_hours
        FROM tasks
        WHERE status IN ('completed', 'delivered')
        GROUP BY priority
        ORDER BY CASE priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 WHEN 'low' THEN 3 END
      `).all();

      // ── 2. Throughput Metrics ──
      // Rolling 7-day and 30-day completion rates
      const throughput7d = stmt(`
        SELECT COUNT(*) as count FROM tasks
        WHERE status IN ('completed', 'delivered')
          AND updated_at >= datetime(?, '-7 days')
      `).get(now).count;

      const throughput30d = stmt(`
        SELECT COUNT(*) as count FROM tasks
        WHERE status IN ('completed', 'delivered')
          AND updated_at >= datetime(?, '-30 days')
      `).get(now).count;

      const created7d = stmt(`
        SELECT COUNT(*) as count FROM tasks
        WHERE created_at >= datetime(?, '-7 days')
      `).get(now).count;

      const created30d = stmt(`
        SELECT COUNT(*) as count FROM tasks
        WHERE created_at >= datetime(?, '-30 days')
      `).get(now).count;

      // Daily throughput for last 14 days
      const dailyThroughput = stmt(`
        SELECT d.date,
          COALESCE(c.created, 0) as created,
          COALESCE(f.finished, 0) as finished
        FROM (
          SELECT date(?, '-' || n || ' days') as date
          FROM (SELECT 0 as n UNION SELECT 1 UNION SELECT 2 UNION SELECT 3
                UNION SELECT 4 UNION SELECT 5 UNION SELECT 6 UNION SELECT 7
                UNION SELECT 8 UNION SELECT 9 UNION SELECT 10 UNION SELECT 11
                UNION SELECT 12 UNION SELECT 13)
        ) d
        LEFT JOIN (SELECT date(created_at) as day, COUNT(*) as created FROM tasks GROUP BY day) c ON c.day = d.date
        LEFT JOIN (SELECT date(updated_at) as day, COUNT(*) as finished FROM tasks WHERE status IN ('completed','delivered') GROUP BY day) f ON f.day = d.date
        ORDER BY d.date ASC
      `).all(now);

      // ── 3. Bottleneck Detection ──
      // Tasks currently stuck in each status (with age)
      const bottlenecks = stmt(`
        SELECT status,
          COUNT(*) as count,
          ROUND(AVG((julianday(?) - julianday(updated_at)) * 24), 1) as avg_age_hours,
          ROUND(MAX((julianday(?) - julianday(updated_at)) * 24), 1) as max_age_hours
        FROM tasks
        WHERE status NOT IN ('completed', 'delivered')
        GROUP BY status
        ORDER BY CASE status WHEN 'new' THEN 0 WHEN 'routing' THEN 1 WHEN 'in_progress' THEN 2 WHEN 'review' THEN 3 END
      `).all(now, now);

      // Oldest stale tasks (tasks not updated in 24+ hours that aren't done)
      const staleTasks = stmt(`
        SELECT t.id, t.title, t.status, t.priority, t.updated_at, tm.name as assignee_name,
          ROUND((julianday(?) - julianday(t.updated_at)) * 24, 1) as stale_hours
        FROM tasks t
        LEFT JOIN team_members tm ON t.assigned_to = tm.id
        WHERE t.status NOT IN ('completed', 'delivered')
          AND (julianday(?) - julianday(t.updated_at)) * 24 > 24
        ORDER BY stale_hours DESC
        LIMIT 10
      `).all(now, now);

      // ── 4. Failure & Retry Rates ──
      const failureStats = stmt(`
        SELECT
          COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed,
          COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed,
          COUNT(CASE WHEN status = 'running' THEN 1 END) as running,
          ROUND(AVG(CASE WHEN status = 'failed' THEN retry_count END), 1) as avg_retries_on_fail
        FROM active_processes
      `).get();

      const failureRate = (failureStats.completed + failureStats.failed) > 0
        ? Math.round((failureStats.failed / (failureStats.completed + failureStats.failed)) * 100)
        : 0;

      // Failures by member (top offenders)
      const failuresByMember = stmt(`
        SELECT tm.name,
          COUNT(CASE WHEN ap.status = 'completed' THEN 1 END) as completed,
          COUNT(CASE WHEN ap.status = 'failed' THEN 1 END) as failed
        FROM active_processes ap
        JOIN team_members tm ON ap.member_id = tm.id
        GROUP BY tm.id
        HAVING failed > 0
        ORDER BY failed DESC
        LIMIT 10
      `).all();

      // ── 5. Revision Rate ──
      const revisionStats = stmt(`
        SELECT
          ROUND(AVG(revision_count), 2) as avg_revisions,
          MAX(revision_count) as max_revisions,
          COUNT(CASE WHEN revision_count > 0 THEN 1 END) as tasks_with_revisions,
          COUNT(*) as total_tasks
        FROM tasks
      `).get();

      // ── 6. Queue Health ──
      const queueDepth = stmt(`
        SELECT
          COUNT(CASE WHEN status = 'new' THEN 1 END) as new_count,
          COUNT(CASE WHEN status = 'routing' THEN 1 END) as routing_count,
          COUNT(CASE WHEN status = 'in_progress' THEN 1 END) as in_progress_count,
          COUNT(CASE WHEN status = 'review' THEN 1 END) as review_count,
          COUNT(*) as total_open
        FROM tasks
        WHERE status NOT IN ('completed', 'delivered')
      `).get();

      // Net flow: are we keeping up?
      const netFlow = created7d - throughput7d;

      return {
        cycle_times: {
          ...cycleTimes,
          by_priority: cycleByPriority
        },
        throughput: {
          completed_7d: throughput7d,
          completed_30d: throughput30d,
          created_7d: created7d,
          created_30d: created30d,
          daily_rate_7d: Math.round((throughput7d / 7) * 10) / 10,
          daily_rate_30d: Math.round((throughput30d / 30) * 10) / 10,
          net_flow_7d: netFlow,
          flow_status: netFlow > 5 ? 'backlog_growing' : netFlow < -5 ? 'clearing_backlog' : 'balanced',
          daily: dailyThroughput
        },
        bottlenecks: {
          by_status: bottlenecks,
          stale_tasks: staleTasks
        },
        failures: {
          ...failureStats,
          failure_rate_pct: failureRate,
          by_member: failuresByMember
        },
        revisions: revisionStats,
        queue: {
          ...queueDepth,
          health: queueDepth.total_open > 50 ? 'overloaded' : queueDepth.total_open > 20 ? 'busy' : 'healthy'
        }
      };
    });

    res.json(getOpsMetrics());
  } catch (err) {
    console.error('GET /api/analytics/operations error:', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/costs — log a cost event (Phase 4 compatible)
app.post('/api/costs', (req, res, next) => {
  try {
    const { provider, adapter_type, model, member_id, task_id, process_id, heartbeat_run_id, prompt_tokens, input_tokens, completion_tokens, output_tokens, total_tokens, cost_cents, description } = req.body;
    const actualAdapter = adapter_type || provider;
    const actualInput = input_tokens || prompt_tokens || 0;
    const actualOutput = output_tokens || completion_tokens || 0;
    const actualTotal = total_tokens || (actualInput + actualOutput);
    const now = localNow();
    const result = db.prepare(`INSERT INTO cost_events
      (member_id, task_id, process_id, heartbeat_run_id, adapter_type, model, input_tokens, output_tokens, total_tokens, cost_cents, description, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(member_id || null, task_id || null, process_id || null, heartbeat_run_id || null,
           actualAdapter || 'unknown', model || 'unknown', actualInput, actualOutput, actualTotal, cost_cents || 0, description || null, now);
    // Update budget policies
    if (member_id && cost_cents) {
      try {
        const policies = db.prepare(`SELECT * FROM budget_policies WHERE (member_id = ? OR (scope = 'global' AND member_id IS NULL)) AND status = 'active'`).all(member_id);
        for (const policy of policies) {
          db.prepare(`UPDATE budget_policies SET spent_cents = spent_cents + ?, updated_at = ? WHERE id = ?`).run(cost_cents, now, policy.id);
        }
      } catch (_) {}
    }
    res.status(201).json({ id: result.lastInsertRowid });
  } catch (err) { next(err); }
});

// GET /api/costs/summary — monthly totals, by adapter, by member (Phase 4 compatible)
app.get('/api/costs/summary', (req, res, next) => {
  try {
    const monthStr = localNow().slice(0, 7) + '-01';

    const totalRow = db.prepare(`SELECT COALESCE(SUM(cost_cents), 0) as total_cents,
      COALESCE(SUM(input_tokens), 0) as total_input_tokens,
      COALESCE(SUM(output_tokens), 0) as total_output_tokens,
      COALESCE(SUM(total_tokens), 0) as total_tokens,
      COUNT(*) as request_count
      FROM cost_events WHERE created_at >= ?`).get(monthStr);

    const byAdapter = db.prepare(`SELECT adapter_type,
      COALESCE(SUM(cost_cents), 0) as cost_cents, COUNT(*) as requests,
      COALESCE(SUM(total_tokens), 0) as tokens
      FROM cost_events WHERE created_at >= ? GROUP BY adapter_type ORDER BY cost_cents DESC`).all(monthStr);

    const byMember = db.prepare(`SELECT ce.member_id, tm.name as member_name,
      COALESCE(SUM(ce.cost_cents), 0) as cost_cents, COUNT(*) as requests,
      COALESCE(SUM(ce.total_tokens), 0) as tokens
      FROM cost_events ce LEFT JOIN team_members tm ON tm.id = ce.member_id
      WHERE ce.created_at >= ? GROUP BY ce.member_id ORDER BY cost_cents DESC`).all(monthStr);

    const byModel = db.prepare(`SELECT model,
      COALESCE(SUM(cost_cents), 0) as cost_cents, COUNT(*) as requests,
      COALESCE(SUM(total_tokens), 0) as tokens
      FROM cost_events WHERE created_at >= ? GROUP BY model ORDER BY cost_cents DESC`).all(monthStr);

    const dailySpend = db.prepare(`SELECT DATE(created_at) as day,
      COALESCE(SUM(cost_cents), 0) as cost_cents, COUNT(*) as requests
      FROM cost_events WHERE created_at >= DATE('now', '-30 days')
      GROUP BY DATE(created_at) ORDER BY day`).all();

    // Compare to budget if a global policy exists
    const globalPolicy = db.prepare(`SELECT * FROM budget_policies WHERE scope = 'global' AND member_id IS NULL LIMIT 1`).get();
    let budgetComparison = null;
    if (globalPolicy) {
      const percent = globalPolicy.limit_cents > 0
        ? Math.round((totalRow.total_cents / globalPolicy.limit_cents) * 100)
        : 0;
      budgetComparison = {
        limit_cents: globalPolicy.limit_cents,
        spent_cents: totalRow.total_cents,
        percent,
        warning: percent >= (globalPolicy.threshold_percent || 80),
        over_budget: percent >= 100
      };
    }

    res.json({
      month: monthStr,
      total: totalRow,
      by_adapter: byAdapter,
      by_member: byMember,
      by_model: byModel,
      daily_spend: dailySpend,
      budget: budgetComparison
    });
  } catch (err) { next(err); }
});

// GET /api/costs/budget — current spend vs budget policies, warnings (Phase 4 compatible)
app.get('/api/costs/budget', (req, res, next) => {
  try {
    const policies = db.prepare(`SELECT * FROM budget_policies ORDER BY scope`).all();
    // Use local-time month start so comparisons against created_at (stored in local time) are correct
    const monthStr = localNow().slice(0, 7) + '-01';

    const enriched = policies.map(p => {
      let spent;
      if (p.scope === 'global') {
        spent = db.prepare(`SELECT COALESCE(SUM(cost_cents), 0) as v FROM cost_events WHERE created_at >= ?`).get(monthStr).v;
      } else if (p.scope === 'member' && p.member_id) {
        spent = db.prepare(`SELECT COALESCE(SUM(cost_cents), 0) as v FROM cost_events WHERE member_id = ? AND created_at >= ?`).get(p.member_id, monthStr).v;
      } else {
        spent = p.spent_cents || 0;
      }
      const percent = p.limit_cents > 0 ? Math.round((spent / p.limit_cents) * 100) : 0;
      return {
        ...p,
        spent_cents_live: spent,
        percent,
        warning: percent >= (p.threshold_percent || 80),
        hard_stopped: p.action_at_limit === 'block' && percent >= 100
      };
    });

    res.json(enriched);
  } catch (err) { next(err); }
});

// POST /api/costs/budget — create/update budget policy (legacy compat + Phase 4)
app.post('/api/costs/budget', (req, res, next) => {
  try {
    const { scope, member_id, limit_cents, monthly_limit_cents, threshold_percent, warn_at_percent, action_at_limit, hard_stop, name } = req.body;
    if (!scope || !['global', 'project', 'member', 'adapter'].includes(scope)) {
      throw badRequest('scope must be global, project, member, or adapter');
    }
    const actualLimit = limit_cents || monthly_limit_cents;
    if (actualLimit == null) throw badRequest('limit_cents is required');
    const actualThreshold = threshold_percent || warn_at_percent || 80;
    const actualAction = action_at_limit || (hard_stop ? 'block' : 'warn');

    // Upsert
    const existing = scope === 'global'
      ? db.prepare(`SELECT id FROM budget_policies WHERE scope = 'global' AND member_id IS NULL`).get()
      : db.prepare(`SELECT id FROM budget_policies WHERE scope = ? AND member_id = ?`).get(scope, member_id || null);

    const now = localNow();
    if (existing) {
      db.prepare(`UPDATE budget_policies SET limit_cents = ?, threshold_percent = ?, action_at_limit = ?, name = COALESCE(?, name), updated_at = ? WHERE id = ?`)
        .run(actualLimit, actualThreshold, actualAction, name || null, now, existing.id);
      res.json({ id: existing.id, updated: true });
    } else {
      const result = db.prepare(`INSERT INTO budget_policies (name, scope, member_id, limit_cents, threshold_percent, action_at_limit, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)`)
        .run(name || `${scope} Budget`, scope, member_id || null, actualLimit, actualThreshold, actualAction, now, now);
      res.status(201).json({ id: result.lastInsertRowid, created: true });
    }
  } catch (err) { next(err); }
});

// GET /api/costs/check — quick check: am I over budget? (Phase 4 compatible)
app.get('/api/costs/check', (req, res, next) => {
  try {
    const { scope, member_id } = req.query;

    let policy = null;
    if (scope && scope !== 'global' && member_id) {
      policy = db.prepare(`SELECT * FROM budget_policies WHERE scope = ? AND member_id = ?`).get(scope, member_id);
    }
    if (!policy) {
      policy = db.prepare(`SELECT * FROM budget_policies WHERE scope = 'global' AND member_id IS NULL LIMIT 1`).get();
    }

    if (!policy) {
      return res.json({ ok: true, percent: 0, warning: false, hard_stop: false, message: 'No budget policy configured' });
    }

    const percent = policy.limit_cents > 0 ? Math.round(((policy.spent_cents || 0) / policy.limit_cents) * 100) : 0;
    const warning = percent >= (policy.threshold_percent || 80);
    const hardStop = policy.action_at_limit === 'block' && percent >= 100;

    res.json({
      ok: !hardStop,
      percent,
      spent_cents: policy.spent_cents || 0,
      limit_cents: policy.limit_cents,
      warning,
      hard_stop: hardStop,
      policy_scope: policy.scope,
      policy_id: policy.id
    });
  } catch (err) { next(err); }
});

// GET /api/costs — list cost events with filters
app.get('/api/costs', (req, res, next) => {
  try {
    const { member_id, task_id, since, until } = req.query;
    let sql = 'SELECT ce.*, tm.name as member_name FROM cost_events ce LEFT JOIN team_members tm ON ce.member_id = tm.id WHERE 1=1';
    const params = [];
    if (member_id) { sql += ' AND ce.member_id = ?'; params.push(Number(member_id)); }
    if (task_id) { sql += ' AND ce.task_id = ?'; params.push(Number(task_id)); }
    if (since) { sql += ' AND ce.created_at >= ?'; params.push(since); }
    if (until) { sql += ' AND ce.created_at <= ?'; params.push(until); }
    sql += ' ORDER BY ce.created_at DESC LIMIT 500';
    const rows = db.prepare(sql).all(...params);
    res.json(rows);
  } catch (err) { next(err); }
});

// GET /api/costs/member/:id — costs for a specific member
app.get('/api/costs/member/:id', (req, res, next) => {
  try {
    const memberId = Number(req.params.id);
    const rows = db.prepare(`SELECT * FROM cost_events WHERE member_id = ? ORDER BY created_at DESC LIMIT 200`).all(memberId);
    const total = db.prepare(`SELECT COALESCE(SUM(cost_cents), 0) as total_cents, COALESCE(SUM(total_tokens), 0) as total_tokens, COUNT(*) as count FROM cost_events WHERE member_id = ?`).get(memberId);
    res.json({ events: rows, summary: total });
  } catch (err) { next(err); }
});

// GET /api/costs/dgx-projection — DGX Spark cost savings projection
app.get('/api/costs/dgx-projection', (req, res, next) => {
  try {
    const now = localNow();

    // ── Current spending by model ──
    const byModel = db.prepare(`
      SELECT model, COUNT(*) as calls,
        COALESCE(SUM(cost_cents), 0) as cost_cents,
        COALESCE(SUM(input_tokens), 0) as input_tokens,
        COALESCE(SUM(output_tokens), 0) as output_tokens,
        COALESCE(SUM(total_tokens), 0) as total_tokens
      FROM cost_events WHERE model IS NOT NULL
      GROUP BY model ORDER BY cost_cents DESC
    `).all();

    // ── Monthly spending trend ──
    const monthlySpend = db.prepare(`
      SELECT strftime('%Y-%m', created_at) as month,
        COUNT(*) as calls,
        COALESCE(SUM(cost_cents), 0) as cost_cents,
        COALESCE(SUM(total_tokens), 0) as total_tokens
      FROM cost_events
      GROUP BY strftime('%Y-%m', created_at)
      ORDER BY month DESC LIMIT 6
    `).all();

    // ── Current month stats ──
    const currentMonth = db.prepare(`
      SELECT COUNT(*) as calls,
        COALESCE(SUM(cost_cents), 0) as cost_cents,
        COALESCE(SUM(total_tokens), 0) as total_tokens
      FROM cost_events
      WHERE strftime('%Y-%m', created_at) = strftime('%Y-%m', ?)
    `).get(now);

    // ── Days elapsed this month for projection ──
    const dayOfMonth = new Date(now).getDate() || 1;
    const daysInMonth = new Date(new Date(now).getFullYear(), new Date(now).getMonth() + 1, 0).getDate();
    const projectedMonthly = Math.round((currentMonth.cost_cents / dayOfMonth) * daysInMonth);

    // ── DGX Spark offload modeling ──
    // Classification: which model tiers can go local
    // Haiku → 100% offloadable (simple routing, QA checks, tagging)
    // Sonnet → 70% offloadable (routine coding, peer reviews, standard tasks)
    // Opus → 15% offloadable (only trivial uses that don't need deep reasoning)
    const offloadRates = { haiku: 1.0, sonnet: 0.70, opus: 0.15 };
    const modelTiers = {};
    let totalCurrentCents = 0;
    let totalOffloadCents = 0;
    let totalOffloadCalls = 0;
    let totalOffloadTokens = 0;

    for (const row of byModel) {
      const modelKey = (row.model || '').toLowerCase();
      let tier = 'unknown';
      let offloadRate = 0;
      if (modelKey.includes('opus')) { tier = 'opus'; offloadRate = offloadRates.opus; }
      else if (modelKey.includes('sonnet')) { tier = 'sonnet'; offloadRate = offloadRates.sonnet; }
      else if (modelKey.includes('haiku')) { tier = 'haiku'; offloadRate = offloadRates.haiku; }
      else { offloadRate = 0.5; } // unknown models: conservative 50%

      const offloadCents = Math.round(row.cost_cents * offloadRate);
      const offloadCalls = Math.round(row.calls * offloadRate);
      const offloadTokens = Math.round(row.total_tokens * offloadRate);

      modelTiers[row.model] = {
        tier,
        calls: row.calls,
        cost_cents: row.cost_cents,
        input_tokens: row.input_tokens,
        output_tokens: row.output_tokens,
        total_tokens: row.total_tokens,
        offload_rate: offloadRate,
        offloadable_calls: offloadCalls,
        offloadable_cents: offloadCents,
        remaining_api_cents: row.cost_cents - offloadCents
      };

      totalCurrentCents += row.cost_cents;
      totalOffloadCents += offloadCents;
      totalOffloadCalls += offloadCalls;
      totalOffloadTokens += offloadTokens;
    }

    // ── Projected monthly savings ──
    const savingsRate = totalCurrentCents > 0 ? totalOffloadCents / totalCurrentCents : 0;
    const projectedMonthlySavings = Math.round(projectedMonthly * savingsRate);
    const projectedAnnualSavings = projectedMonthlySavings * 12;

    // ── DGX Spark specs (for dashboard context) ──
    const dgxSparkSpecs = {
      model: 'Nemotron Cascade 2 30B MoE',
      active_params: '3B',
      quantization: 'NVFP4',
      context_window: 262144,
      throughput_single: '59.2 tok/s',
      throughput_peak: '643 tok/s at c=32',
      ttft: '186ms',
      kv_cache: '6.37M tokens',
      tool_calling: true,
      reasoning: true,
      cost_per_token: 0
    };

    res.json({
      current: {
        total_cost_cents: totalCurrentCents,
        total_calls: byModel.reduce((s, r) => s + r.calls, 0),
        total_tokens: byModel.reduce((s, r) => s + r.total_tokens, 0),
        projected_monthly_cents: projectedMonthly,
        day_of_month: dayOfMonth,
        days_in_month: daysInMonth
      },
      with_dgx_spark: {
        offloadable_cost_cents: totalOffloadCents,
        offloadable_calls: totalOffloadCalls,
        offloadable_tokens: totalOffloadTokens,
        remaining_api_cents: totalCurrentCents - totalOffloadCents,
        savings_rate_pct: Math.round(savingsRate * 100),
        projected_monthly_savings_cents: projectedMonthlySavings,
        projected_annual_savings_cents: projectedAnnualSavings
      },
      by_model: modelTiers,
      monthly_trend: monthlySpend,
      dgx_spark_specs: dgxSparkSpecs,
      offload_rates: offloadRates
    });
  } catch (err) { next(err); }
});

// GET /api/department-summaries — list summaries
app.get('/api/department-summaries', (req, res) => {
  try {
    const { department, type: summaryType, limit: lim } = req.query;
    let query = 'SELECT * FROM department_summaries WHERE 1=1';
    const params = [];
    if (department) { query += ' AND department = ?'; params.push(department); }
    if (summaryType) { query += ' AND summary_type = ?'; params.push(summaryType); }
    query += ' ORDER BY period_end DESC, department LIMIT ?';
    params.push(Number(lim) || 50);
    res.json(db.prepare(query).all(...params));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/department-summaries/generate — trigger summary generation
app.post('/api/department-summaries/generate', (req, res) => {
  try {
    generateDepartmentSummaries();
    res.json({ success: true, message: 'Department summaries generated' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/leaderboard — returns all specialists ranked by overall score
app.get('/api/leaderboard', (req, res) => {
  try {
    const periodDays = parseInt(req.query.period) || 7;
    const department = req.query.department || null;

    let query = `
      SELECT id, name, role, tier, department
      FROM team_members
      WHERE status = 'active' AND tier = 'specialist'
    `;
    const params = [];
    if (department && department !== 'all') {
      query += ' AND department = ?';
      params.push(department);
    }
    query += ' ORDER BY name';

    const members = db.prepare(query).all(...params);
    const results = [];

    for (const m of members) {
      const score = calculateMemberScore(m.id, periodDays);
      results.push({
        id: m.id,
        name: m.name,
        role: m.role,
        tier: m.tier,
        department: m.department,
        ...score
      });
    }

    // Sort by overall score descending
    results.sort((a, b) => b.overall - a.overall);

    // Assign rank positions
    results.forEach((r, i) => { r.rank = i + 1; });

    // Check for department leaders (4+ consecutive weeks at #1 in their department)
    // In the 3-tier system, top specialists earn a "Leader" badge in their department
    for (const r of results) {
      r.promotionCandidate = false;
      r.departmentLeader = false;
      if (r.tier === 'specialist' && r.department) {
        const weeklyRanks = db.prepare(`
          SELECT rank_position FROM member_rankings
          WHERE member_id = ? AND period = 'weekly'
          ORDER BY period_start DESC LIMIT 4
        `).all(r.id);

        if (weeklyRanks.length >= 4 && weeklyRanks.every(w => w.rank_position === 1)) {
          r.promotionCandidate = true;
          r.departmentLeader = true;
        }
      }
    }

    res.json(results);
  } catch (err) {
    console.error('GET /api/leaderboard error:', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/leaderboard/recalculate — force recalculation and snapshot
app.post('/api/leaderboard/recalculate', (req, res) => {
  try {
    const now = localNow();
    const periodStart = now.slice(0, 10); // YYYY-MM-DD

    // Get all ICs and Senior ICs
    const members = db.prepare(`
      SELECT id, name, role, tier, department
      FROM team_members
      WHERE status = 'active' AND tier = 'specialist'
    `).all();

    const results = [];

    for (const m of members) {
      const score = calculateMemberScore(m.id, 7);
      results.push({ ...m, ...score });
    }

    // Sort by overall score descending
    results.sort((a, b) => b.overall - a.overall);

    // Group by department for per-department rankings
    const deptGroups = {};
    for (const r of results) {
      const dept = r.department || 'General';
      if (!deptGroups[dept]) deptGroups[dept] = [];
      deptGroups[dept].push(r);
    }

    // Save global rankings
    const upsert = db.prepare(`
      INSERT INTO member_rankings (member_id, period, period_start, tasks_completed, tasks_failed,
        success_rate, quality_score, efficiency_score, growth_score, overall_rank, rank_position, created_at)
      VALUES (?, 'weekly', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(member_id, period, period_start) DO UPDATE SET
        tasks_completed = excluded.tasks_completed,
        tasks_failed = excluded.tasks_failed,
        success_rate = excluded.success_rate,
        quality_score = excluded.quality_score,
        efficiency_score = excluded.efficiency_score,
        growth_score = excluded.growth_score,
        overall_rank = excluded.overall_rank,
        rank_position = excluded.rank_position
    `);

    const saveAll = db.transaction(() => {
      results.forEach((r, i) => {
        upsert.run(r.id, periodStart, r.completed, r.failed,
          r.successRate, r.qualityRate, r.efficiency, r.growthScore,
          r.overall, i + 1, now);
      });
    });
    saveAll();

    // Check for department leaders: #1 in department for 4+ consecutive weeks
    // In the 3-tier system, top specialists earn leadership recognition
    for (const [dept, deptMembers] of Object.entries(deptGroups)) {
      if (deptMembers.length === 0) continue;
      const topMember = deptMembers[0];

      // Only flag specialists for leadership recognition
      if (topMember.tier !== 'specialist') continue;

      // Check if they've been #1 in their department for 4+ weeks
      // We need per-department rank — check their global ranking history
      // and see if they've consistently been the top performer in their dept
      const recentWeeks = db.prepare(`
        SELECT mr.period_start, mr.overall_rank, mr.rank_position
        FROM member_rankings mr
        WHERE mr.member_id = ? AND mr.period = 'weekly'
        ORDER BY mr.period_start DESC LIMIT 4
      `).all(topMember.id);

      if (recentWeeks.length >= 4) {
        // Check if they were #1 in their department each week
        // (since we save global rank, we check if they were the highest-ranked member in their dept)
        let consecutiveTop = 0;
        for (const week of recentWeeks) {
          // Get all dept members' rankings for that week
          const deptRanks = db.prepare(`
            SELECT mr.member_id, mr.overall_rank
            FROM member_rankings mr
            JOIN team_members tm ON mr.member_id = tm.id
            WHERE mr.period = 'weekly' AND mr.period_start = ?
            AND tm.department = ? AND tm.tier = 'specialist'
            ORDER BY mr.overall_rank DESC LIMIT 1
          `).get(week.period_start, dept);

          if (deptRanks && deptRanks.member_id === topMember.id) {
            consecutiveTop++;
          } else {
            break;
          }
        }

        if (consecutiveTop >= 4) {
          // Create promotion notification
          const existingNotif = db.prepare(`
            SELECT id FROM notifications
            WHERE type = 'system' AND title LIKE ? AND read = 0
          `).get(`%${topMember.name}%Promotion%`);

          if (!existingNotif) {
            createNotification('system', `${topMember.name} — Department Leader`, `${topMember.name} has been #1 in ${dept} for ${consecutiveTop} consecutive weeks. Top specialist — consider for Executive promotion by Board. Current score: ${topMember.overall}`);
          }
        }
      }
    }

    db.prepare(`INSERT INTO activity_log (actor, action, notes, created_at) VALUES ('Gray', 'leaderboard_recalculated', ?, ?)`)
      .run(`Recalculated rankings for ${results.length} members. Top: ${results[0]?.name || 'none'} (${results[0]?.overall || 0})`, now);

    res.json({ success: true, ranked: results.length, top3: results.slice(0, 3).map(r => ({ name: r.name, overall: r.overall })) });
  } catch (err) {
    console.error('POST /api/leaderboard/recalculate error:', err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/leaderboard/history — ranking history for a member
app.get('/api/leaderboard/history', (req, res) => {
  try {
    const memberId = parseInt(req.query.member_id);
    if (!memberId) return res.status(400).json({ error: 'member_id required' });

    const history = db.prepare(`
      SELECT * FROM member_rankings
      WHERE member_id = ? ORDER BY period_start DESC LIMIT 12
    `).all(memberId);

    res.json(history);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/leaderboard/departments — list departments with active specialists
app.get('/api/leaderboard/departments', (req, res) => {
  try {
    const depts = db.prepare(`
      SELECT DISTINCT department FROM team_members
      WHERE status = 'active' AND tier = 'specialist' AND department IS NOT NULL
      ORDER BY department
    `).all();
    res.json(depts.map(d => d.department));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


};
