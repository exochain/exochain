'use strict';
module.exports = function(app, db, helpers) {
  const { broadcast, localNow, createNotification, authRateLimiter, apiRateLimiter, spawnMemberTerminal } = helpers;
  const stmt = helpers.stmt || ((sql) => db.prepare(sql));

// End Goals
app.get('/api/end-goals', (req, res) => {
  try { res.json(db.prepare(`SELECT * FROM end_goals ORDER BY sort_order`).all()); }
  catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/end-goals', (req, res) => {
  try {
    const { title, description, target_date } = req.body;
    if (!title) return res.status(400).json({ error: 'Title required' });
    const now = localNow();
    const r = db.prepare(`INSERT INTO end_goals (title, description, target_date, created_at, updated_at) VALUES (?,?,?,?,?)`).run(title, description||null, target_date||null, now, now);
    res.json({ id: Number(r.lastInsertRowid), message: 'End goal created' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.put('/api/end-goals/:id', (req, res) => {
  try {
    const now = localNow();
    const fields = [];
    const vals = [];
    if (req.body.title !== undefined) { fields.push('title = ?'); vals.push(req.body.title); }
    if (req.body.description !== undefined) { fields.push('description = ?'); vals.push(req.body.description); }
    if (req.body.target_date !== undefined) { fields.push('target_date = ?'); vals.push(req.body.target_date); }
    if (req.body.status !== undefined) {
      const validGoalStatuses = ['active', 'achieved', 'abandoned'];
      if (!validGoalStatuses.includes(req.body.status)) {
        return res.status(400).json({ error: 'Invalid status. Must be one of: ' + validGoalStatuses.join(', ') });
      }
      fields.push('status = ?'); vals.push(req.body.status);
    }
    if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });
    fields.push('updated_at = ?');
    vals.push(now);
    vals.push(req.params.id);
    db.prepare(`UPDATE end_goals SET ${fields.join(', ')} WHERE id = ?`).run(...vals);
    res.json({ message: 'Updated' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.delete('/api/end-goals/:id', (req, res) => {
  try {
    db.prepare(`DELETE FROM project_goals WHERE end_goal_id = ?`).run(req.params.id);
    db.prepare(`DELETE FROM vision_goals WHERE end_goal_id = ?`).run(req.params.id);
    db.prepare(`DELETE FROM end_goals WHERE id = ?`).run(req.params.id);
    res.json({ message: 'Deleted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Visions
app.get('/api/visions', (req, res) => {
  try { res.json(db.prepare(`SELECT v.*, p.name as project_name FROM visions v LEFT JOIN projects p ON v.project_id = p.id ORDER BY v.sort_order`).all()); }
  catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/visions', (req, res) => {
  try {
    const { title, description, project_id, target_date } = req.body;
    if (!title) return res.status(400).json({ error: 'Title required' });
    const now = localNow();
    const r = db.prepare(`INSERT INTO visions (title, description, project_id, target_date, created_at, updated_at) VALUES (?,?,?,?,?,?)`).run(title, description||null, project_id||null, target_date||null, now, now);
    res.json({ id: Number(r.lastInsertRowid), message: 'Vision created' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.put('/api/visions/:id', (req, res) => {
  try {
    const { title, description, project_id, target_date, status, sort_order } = req.body;
    const now = localNow();
    const fields = [];
    const vals = [];
    if (title !== undefined) { fields.push('title = ?'); vals.push(title); }
    if (description !== undefined) { fields.push('description = ?'); vals.push(description || null); }
    if (project_id !== undefined) { fields.push('project_id = ?'); vals.push(project_id || null); }
    if (target_date !== undefined) { fields.push('target_date = ?'); vals.push(target_date || null); }
    if (status !== undefined) {
      const validVisionStatuses = ['active', 'reached', 'abandoned'];
      if (!validVisionStatuses.includes(status)) {
        return res.status(400).json({ error: 'Invalid status. Must be one of: ' + validVisionStatuses.join(', ') });
      }
      fields.push('status = ?'); vals.push(status);
      if (status === 'reached') { fields.push('reached_at = ?'); vals.push(now); }
    }
    if (sort_order !== undefined) { fields.push('sort_order = ?'); vals.push(sort_order); }
    if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });
    fields.push('updated_at = ?'); vals.push(now);
    vals.push(req.params.id);
    const result = db.prepare(`UPDATE visions SET ${fields.join(', ')} WHERE id = ?`).run(...vals);
    if (result.changes === 0) return res.status(404).json({ error: 'Vision not found' });
    res.json({ id: Number(req.params.id), message: 'Vision updated' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.delete('/api/visions/:id', (req, res) => {
  try {
    db.prepare(`DELETE FROM vision_goals WHERE vision_id = ?`).run(req.params.id);
    const result = db.prepare(`DELETE FROM visions WHERE id = ?`).run(req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Vision not found' });
    res.json({ message: 'Vision deleted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/goals — list all goals with filters
app.get('/api/goals', (req, res) => {
  try {
    let sql = `SELECT g.*, tm.name as owner_name, p.name as project_name
               FROM goals g
               LEFT JOIN team_members tm ON g.owner_member_id = tm.id
               LEFT JOIN projects p ON g.project_id = p.id
               WHERE 1=1`;
    const params = [];
    if (req.query.type) { sql += ` AND g.goal_type = ?`; params.push(req.query.type); }
    if (req.query.status) { sql += ` AND g.status = ?`; params.push(req.query.status); }
    if (req.query.project_id) { sql += ` AND g.project_id = ?`; params.push(Number(req.query.project_id)); }
    if (req.query.owner_member_id) { sql += ` AND g.owner_member_id = ?`; params.push(Number(req.query.owner_member_id)); }
    sql += ` ORDER BY CASE g.goal_type WHEN 'company' THEN 0 WHEN 'team' THEN 1 WHEN 'agent' THEN 2 WHEN 'milestone' THEN 3 END, g.created_at DESC`;
    const goals = db.prepare(sql).all(...params);
    // Attach task counts
    goals.forEach(g => {
      g.task_count = db.prepare('SELECT COUNT(*) as c FROM task_goals WHERE goal_id = ?').get(g.id).c;
    });
    res.json(goals);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/goals/tree — returns goals as a nested tree structure
app.get('/api/goals/tree', (req, res) => {
  try {
    const goals = db.prepare(`SELECT g.*, tm.name as owner_name, p.name as project_name
                              FROM goals g
                              LEFT JOIN team_members tm ON g.owner_member_id = tm.id
                              LEFT JOIN projects p ON g.project_id = p.id
                              ORDER BY g.created_at ASC`).all();
    function buildGoalTree(goals, parentId) {
      return goals
        .filter(g => (parentId === null ? g.parent_goal_id === null : g.parent_goal_id === parentId))
        .map(g => ({
          ...g,
          children: buildGoalTree(goals, g.id),
          task_count: db.prepare('SELECT COUNT(*) as c FROM task_goals WHERE goal_id = ?').get(g.id).c
        }));
    }
    res.json(buildGoalTree(goals, null));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/goals/:id — single goal with linked tasks, child goals, and progress
app.get('/api/goals/:id', (req, res) => {
  try {
    const goal = db.prepare(`SELECT g.*, tm.name as owner_name, p.name as project_name
                             FROM goals g
                             LEFT JOIN team_members tm ON g.owner_member_id = tm.id
                             LEFT JOIN projects p ON g.project_id = p.id
                             WHERE g.id = ?`).get(Number(req.params.id));
    if (!goal) return res.status(404).json({ error: 'Goal not found' });

    // Child goals
    goal.children = db.prepare(`SELECT * FROM goals WHERE parent_goal_id = ? ORDER BY created_at ASC`)
      .all(goal.id);

    // Linked tasks
    goal.tasks = db.prepare(`SELECT t.id, t.title, t.status, t.priority, tm.name as assignee_name
                             FROM task_goals tg
                             JOIN tasks t ON tg.task_id = t.id
                             LEFT JOIN team_members tm ON t.assigned_to = tm.id
                             WHERE tg.goal_id = ?
                             ORDER BY t.created_at DESC`).all(goal.id);

    goal.task_count = goal.tasks.length;
    res.json(goal);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/goals — create a goal
app.post('/api/goals', (req, res) => {
  try {
    const { title, description, parent_goal_id, project_id, owner_member_id, goal_type, status, priority, target_date, success_criteria } = req.body;
    if (!title) return res.status(400).json({ error: 'Title is required' });
    const now = localNow();
    const result = db.prepare(`INSERT INTO goals (title, description, parent_goal_id, project_id, owner_member_id, goal_type, status, priority, target_date, success_criteria, created_at, updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
      .run(title, description || null, parent_goal_id || null, project_id || null, owner_member_id || null,
           goal_type || 'team', status || 'active', priority || 'normal', target_date || null, success_criteria || null, now, now);
    const goal = db.prepare('SELECT * FROM goals WHERE id = ?').get(result.lastInsertRowid);
    res.status(201).json(goal);
    broadcast('goal.created', { id: goal.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/goals/:id — update a goal
app.put('/api/goals/:id', (req, res) => {
  try {
    const goal = db.prepare('SELECT * FROM goals WHERE id = ?').get(Number(req.params.id));
    if (!goal) return res.status(404).json({ error: 'Goal not found' });
    const allowedFields = ['title', 'description', 'parent_goal_id', 'project_id', 'owner_member_id', 'goal_type', 'status', 'priority', 'target_date', 'success_criteria', 'progress'];
    const updates = [];
    const values = [];
    const now = localNow();
    for (const f of allowedFields) {
      if (req.body[f] !== undefined) {
        updates.push(`${f} = ?`);
        values.push(req.body[f]);
      }
    }
    if (req.body.status === 'completed' && goal.status !== 'completed') {
      updates.push('completed_at = ?');
      values.push(now);
    }
    if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });
    updates.push('updated_at = ?');
    values.push(now);
    values.push(Number(req.params.id));
    db.prepare(`UPDATE goals SET ${updates.join(', ')} WHERE id = ?`).run(...values);
    const updated = db.prepare('SELECT * FROM goals WHERE id = ?').get(Number(req.params.id));
    res.json(updated);
    broadcast('goal.updated', { id: updated.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/goals/:id — delete (cascade unlink tasks, reparent children)
app.delete('/api/goals/:id', (req, res) => {
  try {
    const goal = db.prepare('SELECT * FROM goals WHERE id = ?').get(Number(req.params.id));
    if (!goal) return res.status(404).json({ error: 'Goal not found' });
    // Reparent children to this goal's parent
    db.prepare('UPDATE goals SET parent_goal_id = ? WHERE parent_goal_id = ?')
      .run(goal.parent_goal_id || null, goal.id);
    // Unlink tasks
    db.prepare('DELETE FROM task_goals WHERE goal_id = ?').run(goal.id);
    // Delete the goal
    db.prepare('DELETE FROM goals WHERE id = ?').run(goal.id);
    res.json({ message: 'Goal deleted', id: goal.id });
    broadcast('goal.deleted', { id: goal.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/goals/:id/tasks — tasks linked to this goal
app.get('/api/goals/:id/tasks', (req, res) => {
  try {
    const tasks = db.prepare(`SELECT t.*, tm.name as assignee_name
                              FROM task_goals tg
                              JOIN tasks t ON tg.task_id = t.id
                              LEFT JOIN team_members tm ON t.assigned_to = tm.id
                              WHERE tg.goal_id = ?
                              ORDER BY t.created_at DESC`).all(Number(req.params.id));
    res.json(tasks);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/goals/:id/tasks — link a task to a goal
app.post('/api/goals/:id/tasks', (req, res) => {
  try {
    const goalId = Number(req.params.id);
    const taskId = Number(req.body.task_id);
    if (!taskId) return res.status(400).json({ error: 'task_id is required' });
    const goal = db.prepare('SELECT id FROM goals WHERE id = ?').get(goalId);
    if (!goal) return res.status(404).json({ error: 'Goal not found' });
    const task = db.prepare('SELECT id FROM tasks WHERE id = ?').get(taskId);
    if (!task) return res.status(404).json({ error: 'Task not found' });
    db.prepare('INSERT OR IGNORE INTO task_goals (task_id, goal_id, created_at) VALUES (?,?,?)')
      .run(taskId, goalId, localNow());
    recalcGoalProgress(goalId);
    res.status(201).json({ message: 'Task linked to goal', task_id: taskId, goal_id: goalId });
    broadcast('goal.updated', { id: goalId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/goals/:id/tasks/:taskId — unlink
app.delete('/api/goals/:id/tasks/:taskId', (req, res) => {
  try {
    const goalId = Number(req.params.id);
    const taskId = Number(req.params.taskId);
    db.prepare('DELETE FROM task_goals WHERE goal_id = ? AND task_id = ?').run(goalId, taskId);
    recalcGoalProgress(goalId);
    res.json({ message: 'Task unlinked from goal', task_id: taskId, goal_id: goalId });
    broadcast('goal.updated', { id: goalId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


};
