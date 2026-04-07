'use strict';
module.exports = function(app, db, helpers) {
  const { broadcast, localNow, createNotification, authRateLimiter, apiRateLimiter, spawnMemberTerminal } = helpers;
  const stmt = helpers.stmt || ((sql) => db.prepare(sql));

app.get('/api/calendar/events', (req, res) => {
  try {
    const { start, end, type, source } = req.query;
    let sql = `SELECT e.*, e.locked, e.lock_type, e.lock_until, p.name as project_name, p.color as project_color FROM calendar_events e LEFT JOIN projects p ON e.project_id = p.id WHERE 1=1`;
    const params = [];

    if (start && end) {
      // Catch multi-day events that span into the visible range
      sql += ` AND (e.start_time <= ? AND (e.end_time >= ? OR (e.end_time IS NULL AND e.start_time >= ?)))`;
      params.push(end, start, start);
    } else if (start) {
      sql += ` AND (e.end_time >= ? OR (e.end_time IS NULL AND e.start_time >= ?))`;
      params.push(start, start);
    } else if (end) {
      sql += ` AND e.start_time <= ?`;
      params.push(end);
    }
    if (type) { sql += ` AND e.calendar_type = ?`; params.push(type); }
    if (source) { sql += ` AND e.source = ?`; params.push(source); }

    sql += ` ORDER BY e.start_time ASC`;
    const rows = db.prepare(sql).all(...params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/calendar/events/:id', (req, res) => {
  try {
    const row = db.prepare(`SELECT e.*, p.name as project_name, p.color as project_color FROM calendar_events e LEFT JOIN projects p ON e.project_id = p.id WHERE e.id = ?`).get(req.params.id);
    if (!row) return res.status(404).json({ error: 'Event not found' });
    res.json(row);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/calendar/events', (req, res) => {
  try {
    const { title, description, start_time, end_time, all_day, calendar_type, source, external_id, project_id, color, location, recurrence, status } = req.body;
    if (!title || !start_time) return res.status(400).json({ error: 'Title and start_time required' });
    if (title.trim().length < 3) return res.status(400).json({ error: 'Title must be at least 3 characters' });

    const validCalendarTypes = ['personal', 'work', 'project', 'deadline', 'reminder'];
    const validEventStatuses = ['confirmed', 'tentative', 'cancelled'];
    if (calendar_type && !validCalendarTypes.includes(calendar_type)) {
      return res.status(400).json({ error: 'Invalid calendar_type. Must be one of: ' + validCalendarTypes.join(', ') });
    }
    if (status && !validEventStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status. Must be one of: ' + validEventStatuses.join(', ') });
    }

    // Validate end_time > start_time
    if (end_time && start_time && new Date(end_time) <= new Date(start_time)) {
      return res.status(400).json({ error: 'end_time must be after start_time' });
    }

    const now = localNow();

    // Check for overlapping events
    let warning = null;
    if (start_time && end_time) {
      const overlaps = db.prepare(`
        SELECT title FROM calendar_events
        WHERE start_time < ? AND end_time > ?
      `).all(end_time, start_time);
      if (overlaps.length > 0) {
        warning = 'Overlaps with: ' + overlaps.map(e => e.title).join(', ');
      }
    }

    const result = db.prepare(`
      INSERT INTO calendar_events (title, description, start_time, end_time, all_day, calendar_type, source, external_id, project_id, color, location, recurrence, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      title, description || null, start_time, end_time || null,
      all_day ? 1 : 0, calendar_type || 'personal', source || 'manual',
      external_id || null, project_id || null, color || null,
      location || null, recurrence || null, status || 'confirmed', now, now
    );
    const response = { id: Number(result.lastInsertRowid), message: 'Event created' };
    if (warning) response.warning = warning;
    res.json(response);
    broadcast('calendar.updated', { id: Number(result.lastInsertRowid) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/calendar/events/:id', (req, res) => {
  try {
    const existing = db.prepare(`SELECT * FROM calendar_events WHERE id = ?`).get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Event not found' });

    // Resolve effective start/end for validation
    const effectiveStart = req.body.start_time !== undefined ? req.body.start_time : existing.start_time;
    const effectiveEnd = req.body.end_time !== undefined ? req.body.end_time : existing.end_time;

    // Validate end_time > start_time when both are available
    if (effectiveEnd && effectiveStart && new Date(effectiveEnd) <= new Date(effectiveStart)) {
      return res.status(400).json({ error: 'end_time must be after start_time' });
    }

    // Validate enum fields
    const validCalTypes = ['personal', 'work', 'project', 'deadline', 'reminder'];
    const validEvtStatuses = ['confirmed', 'tentative', 'cancelled'];
    if (req.body.calendar_type !== undefined && !validCalTypes.includes(req.body.calendar_type)) {
      return res.status(400).json({ error: 'Invalid calendar_type. Must be one of: ' + validCalTypes.join(', ') });
    }
    if (req.body.status !== undefined && !validEvtStatuses.includes(req.body.status)) {
      return res.status(400).json({ error: 'Invalid status. Must be one of: ' + validEvtStatuses.join(', ') });
    }

    const fields = ['title', 'description', 'start_time', 'end_time', 'all_day', 'calendar_type', 'source', 'external_id', 'project_id', 'color', 'location', 'recurrence', 'status'];
    const updates = [];
    const values = [];
    for (const f of fields) {
      if (req.body[f] !== undefined) {
        updates.push(`${f} = ?`);
        values.push(f === 'all_day' ? (req.body[f] ? 1 : 0) : req.body[f]);
      }
    }
    if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });

    // Check for overlapping events (excluding self)
    let warning = null;
    if (effectiveStart && effectiveEnd) {
      const overlaps = db.prepare(`
        SELECT title FROM calendar_events
        WHERE id != ? AND start_time < ? AND end_time > ?
      `).all(req.params.id, effectiveEnd, effectiveStart);
      if (overlaps.length > 0) {
        warning = 'Overlaps with: ' + overlaps.map(e => e.title).join(', ');
      }
    }

    updates.push(`updated_at = ?`);
    values.push(localNow());
    values.push(req.params.id);

    db.prepare(`UPDATE calendar_events SET ${updates.join(', ')} WHERE id = ?`).run(...values);
    const response = { message: 'Event updated' };
    if (warning) response.warning = warning;
    res.json(response);
    broadcast('calendar.updated', { id: Number(req.params.id) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/calendar/events/:id', (req, res) => {
  try {
    const result = db.prepare(`DELETE FROM calendar_events WHERE id = ?`).run(req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Event not found' });
    res.json({ message: 'Event deleted' });
    broadcast('calendar.updated', { id: Number(req.params.id) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/calendar/sync', (req, res) => {
  try {
    const { source } = req.body;
    if (!['google', 'notion'].includes(source)) return res.status(400).json({ error: 'Source must be google or notion' });
    const now = localNow();
    db.prepare(`UPDATE calendar_syncs SET status = 'syncing', last_synced = ?, error_message = NULL WHERE source = ?`).run(now, source);

    // Create a task for the terminal/worker to pick up the sync
    const result = db.prepare(`
      INSERT INTO tasks (title, description, status, priority, source_file, created_at, updated_at)
      VALUES (?, ?, 'new', 'high', 'system', ?, ?)
    `).run(`Sync ${source} calendar`, `Cadence: Sync events from ${source} calendar into the local database. Use the ${source === 'google' ? 'Google Calendar MCP tools' : 'Notion MCP tools'} to fetch events and upsert into calendar_events table.`, now, now);

    db.prepare(`INSERT INTO activity_log (task_id, actor, action, notes, created_at) VALUES (?, 'Cadence', 'calendar_sync', ?, ?)`)
      .run(result.lastInsertRowid, `Initiated ${source} calendar sync`, now);

    res.json({ message: `${source} sync initiated`, task_id: Number(result.lastInsertRowid) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/calendar/sync', (req, res) => {
  try {
    const rows = db.prepare(`SELECT * FROM calendar_syncs`).all();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/calendar/today', (req, res) => {
  try {
    const today = localNow().split(' ')[0];
    const [ty, tm, td] = today.split('-').map(Number);
    const tomorrowObj = new Date(ty, tm - 1, td + 1);
    const tomorrow = `${tomorrowObj.getFullYear()}-${String(tomorrowObj.getMonth() + 1).padStart(2, '0')}-${String(tomorrowObj.getDate()).padStart(2, '0')}`;
    const rows = db.prepare(`
      SELECT * FROM calendar_events
      WHERE start_time >= ? AND start_time < ? AND status != 'cancelled'
      ORDER BY start_time ASC
    `).all(today, tomorrow);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/calendar/events/:id/lock', (req, res) => {
  try {
    const { locked, lock_type, lock_until } = req.body;
    const existing = db.prepare(`SELECT * FROM calendar_events WHERE id = ?`).get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Event not found' });

    const now = localNow();
    if (locked) {
      // Lock it
      const lt = ['permanent', 'date_range', 'single_day'].includes(lock_type) ? lock_type : 'permanent';
      db.prepare(`UPDATE calendar_events SET locked = 1, lock_type = ?, lock_until = ?, updated_at = ? WHERE id = ?`)
        .run(lt, lock_until || null, now, req.params.id);
      res.json({ message: `Event locked (${lt})` });
    } else {
      // Unlock it
      db.prepare(`UPDATE calendar_events SET locked = 0, lock_type = NULL, lock_until = NULL, updated_at = ? WHERE id = ?`)
        .run(now, req.params.id);
      res.json({ message: 'Event unlocked' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/calendar/command', (req, res) => {
  try {
    const { command } = req.body;
    if (!command || !command.trim()) return res.status(400).json({ error: 'Command required' });

    const now = localNow();

    // Create a task for the terminal/worker to process
    const result = db.prepare(`
      INSERT INTO tasks (title, description, status, priority, source_file, created_at, updated_at)
      VALUES (?, ?, 'new', 'high', 'calendar', ?, ?)
    `).run(
      `Calendar: ${command.trim().slice(0, 100)}`,
      `Cadence: Process this calendar command from Max.\n\nCommand: "${command.trim()}"\n\nInstructions:\n- Parse the natural language request\n- Create, update, or reorganize calendar events as requested\n- Respect locked events — never move or overlap them\n- Use the calendar_events table and the API endpoints\n- When scheduling tasks from the task queue, find open time slots that don't conflict with existing events\n- Notify Max when done`,
      now, now
    );

    const taskId = result.lastInsertRowid;

    db.prepare(`INSERT INTO activity_log (task_id, actor, action, notes, created_at) VALUES (?, 'Cadence', 'calendar_command', ?, ?)`)
      .run(taskId, `Calendar command: ${command.trim().slice(0, 200)}`, now);

    createNotification('system', 'Calendar command received', `"${command.trim().slice(0, 100)}" — Cadence is on it.`, taskId);

    // Auto-spawn Cadence for this calendar command
    setImmediate(() => {
      try {
        const cadence = db.prepare(`SELECT id FROM team_members WHERE role LIKE '%Calendar%' OR role LIKE '%Time%' AND status = 'active'`).get();
        if (cadence) {
          // Assign task to Cadence
          db.prepare(`UPDATE tasks SET assigned_to = ?, status = 'in_progress', started_at = ?, updated_at = ? WHERE id = ?`)
            .run(cadence.id, now, now, Number(taskId));
          db.prepare(`INSERT INTO activity_log (task_id, actor, action, notes, created_at) VALUES (?, 'Cadence', 'calendar_spawn', ?, ?)`)
            .run(Number(taskId), `Auto-spawned Cadence for calendar command: ${command.trim().slice(0, 100)}`, now);
          broadcast('task.updated', { id: Number(taskId) });
          spawnMemberTerminal(Number(taskId), cadence.id).catch(err => {
            console.error(`[AutoSpawn] Calendar command spawn error: ${err.message}`);
          });
        }
      } catch (err) {
        console.error(`[AutoSpawn] Calendar command spawn setup error: ${err.message}`);
      }
    });

    res.json({ task_id: Number(taskId), message: 'Calendar command sent to Cadence' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/calendar/auto-schedule', (req, res) => {
  try {
    const now = localNow();

    // Create a task for Cadence to auto-schedule
    const result = db.prepare(`
      INSERT INTO tasks (title, description, status, priority, source_file, created_at, updated_at)
      VALUES (?, ?, 'new', 'high', 'calendar', ?, ?)
    `).run(
      'Auto-schedule: Layout tasks on calendar',
      `Cadence: Review all open tasks in the task queue and schedule them on the calendar.\n\nRules:\n- Never overlap or move LOCKED events\n- Meetings always take priority over task scheduling\n- Only schedule into open time slots\n- Respect Max's working hours (6am-2pm PT based on existing schedule)\n- Group related project tasks together when possible\n- Higher priority tasks get earlier/better time slots\n- Create calendar_events for each scheduled task block\n- Notify Max with a summary of the schedule`,
      now, now
    );

    db.prepare(`INSERT INTO activity_log (task_id, actor, action, notes, created_at) VALUES (?, 'Cadence', 'auto_schedule', 'Auto-scheduling tasks into open calendar slots', ?)`)
      .run(result.lastInsertRowid, now);

    // Auto-spawn Cadence for auto-schedule
    const autoSchedTaskId = Number(result.lastInsertRowid);
    setImmediate(() => {
      try {
        const cadence = db.prepare(`SELECT id FROM team_members WHERE role LIKE '%Calendar%' OR role LIKE '%Time%' AND status = 'active'`).get();
        if (cadence) {
          db.prepare(`UPDATE tasks SET assigned_to = ?, status = 'in_progress', started_at = ?, updated_at = ? WHERE id = ?`)
            .run(cadence.id, now, now, autoSchedTaskId);
          db.prepare(`INSERT INTO activity_log (task_id, actor, action, notes, created_at) VALUES (?, 'Cadence', 'auto_schedule_spawn', 'Auto-spawned Cadence for auto-scheduling', ?)`)
            .run(autoSchedTaskId, now);
          broadcast('task.updated', { id: autoSchedTaskId });
          spawnMemberTerminal(autoSchedTaskId, cadence.id).catch(err => {
            console.error(`[AutoSpawn] Auto-schedule spawn error: ${err.message}`);
          });
        }
      } catch (err) {
        console.error(`[AutoSpawn] Auto-schedule spawn setup error: ${err.message}`);
      }
    });

    res.json({ task_id: Number(result.lastInsertRowid), message: 'Auto-schedule initiated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


};
