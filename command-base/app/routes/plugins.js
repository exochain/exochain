'use strict';
module.exports = function(app, db, helpers) {
  const { broadcast, localNow, createNotification, authRateLimiter, apiRateLimiter, spawnMemberTerminal } = helpers;
  const stmt = helpers.stmt || ((sql) => db.prepare(sql));

// GET /api/mcp/servers — list all registered MCP servers
app.get('/api/mcp/servers', (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT s.*, m.name as member_name
      FROM mcp_servers s
      LEFT JOIN team_members m ON s.member_id = m.id
      ORDER BY s.created_at DESC
    `).all();
    const parsed = rows.map(r => ({
      ...r,
      args: JSON.parse(r.args || '[]'),
      env_vars: JSON.parse(r.env_vars || '{}')
    }));
    res.json(parsed);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/mcp/servers — register a new MCP server
app.post('/api/mcp/servers', (req, res) => {
  try {
    const { name, description, command, args, env_vars, member_id } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: 'name is required' });
    if (!command || !command.trim()) return res.status(400).json({ error: 'command is required' });

    const now = localNow();
    const argsStr = JSON.stringify(args || []);
    const envStr = JSON.stringify(env_vars || {});
    const result = db.prepare(`
      INSERT INTO mcp_servers (name, description, command, args, env_vars, enabled, member_id, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
    `).run(name.trim(), description || null, command.trim(), argsStr, envStr, member_id || null, now, now);
    res.json({
      id: Number(result.lastInsertRowid),
      name: name.trim(),
      description: description || null,
      command: command.trim(),
      args: args || [],
      env_vars: env_vars || {},
      enabled: 1,
      member_id: member_id || null,
      created_at: now,
      updated_at: now
    });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint')) {
      return res.status(409).json({ error: 'An MCP server with that name already exists' });
    }
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/mcp/servers/:id — update an MCP server
app.put('/api/mcp/servers/:id', (req, res) => {
  try {
    const existing = db.prepare('SELECT * FROM mcp_servers WHERE id = ?').get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'MCP server not found' });

    const fields = ['name', 'description', 'command', 'args', 'env_vars', 'enabled', 'member_id'];
    const updates = [];
    const values = [];
    for (const f of fields) {
      if (req.body[f] !== undefined) {
        if (f === 'args') {
          updates.push('args = ?');
          values.push(JSON.stringify(req.body[f]));
        } else if (f === 'env_vars') {
          updates.push('env_vars = ?');
          values.push(JSON.stringify(req.body[f]));
        } else if (f === 'enabled') {
          updates.push('enabled = ?');
          values.push(req.body[f] ? 1 : 0);
        } else {
          updates.push(`${f} = ?`);
          values.push(req.body[f]);
        }
      }
    }
    if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });

    updates.push('updated_at = ?');
    values.push(localNow());
    values.push(req.params.id);

    db.prepare(`UPDATE mcp_servers SET ${updates.join(', ')} WHERE id = ?`).run(...values);
    const updated = db.prepare('SELECT * FROM mcp_servers WHERE id = ?').get(req.params.id);
    res.json({
      ...updated,
      args: JSON.parse(updated.args || '[]'),
      env_vars: JSON.parse(updated.env_vars || '{}')
    });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint')) {
      return res.status(409).json({ error: 'An MCP server with that name already exists' });
    }
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/mcp/servers/:id
app.delete('/api/mcp/servers/:id', (req, res) => {
  try {
    const result = db.prepare('DELETE FROM mcp_servers WHERE id = ?').run(req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'MCP server not found' });
    res.json({ message: 'MCP server deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/mcp/servers/:id/toggle — enable/disable
app.put('/api/mcp/servers/:id/toggle', (req, res) => {
  try {
    const existing = db.prepare('SELECT * FROM mcp_servers WHERE id = ?').get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'MCP server not found' });

    const newEnabled = existing.enabled ? 0 : 1;
    db.prepare('UPDATE mcp_servers SET enabled = ?, updated_at = ? WHERE id = ?')
      .run(newEnabled, localNow(), req.params.id);

    const updated = db.prepare('SELECT * FROM mcp_servers WHERE id = ?').get(req.params.id);
    res.json({
      ...updated,
      args: JSON.parse(updated.args || '[]'),
      env_vars: JSON.parse(updated.env_vars || '{}')
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/plugins
app.get('/api/plugins', (req, res) => {
  try {
    const plugins = db.prepare('SELECT * FROM plugins ORDER BY display_name').all();
    res.json(plugins);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/plugins/:id
app.get('/api/plugins/:id', (req, res) => {
  try {
    const plugin = db.prepare('SELECT * FROM plugins WHERE id = ?').get(Number(req.params.id));
    if (!plugin) return res.status(404).json({ error: 'Plugin not found' });
    plugin.state = db.prepare('SELECT * FROM plugin_state WHERE plugin_id = ?').all(plugin.id);
    plugin.recent_logs = db.prepare('SELECT * FROM plugin_logs WHERE plugin_id = ? ORDER BY created_at DESC LIMIT 20').all(plugin.id);
    res.json(plugin);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/plugins
app.post('/api/plugins', (req, res) => {
  try {
    const { name, display_name, description, version, author, plugin_type, entry_point, config_schema, settings } = req.body;
    if (!name || !display_name) return res.status(400).json({ error: 'name and display_name are required' });
    const now = localNow();
    const result = db.prepare(`INSERT INTO plugins (name, display_name, description, version, author, plugin_type, entry_point, config_schema, settings, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
      .run(name, display_name, description || null, version || '1.0.0', author || null, plugin_type || 'extension', entry_point || null, JSON.stringify(config_schema || {}), JSON.stringify(settings || {}), now, now);
    const plugin = db.prepare('SELECT * FROM plugins WHERE id = ?').get(result.lastInsertRowid);
    broadcast('plugin.installed', plugin);
    res.status(201).json(plugin);
  } catch (err) {
    if (err.message && err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Plugin with this name already exists' });
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/plugins/:id
app.put('/api/plugins/:id', (req, res) => {
  try {
    const id = Number(req.params.id);
    const existing = db.prepare('SELECT * FROM plugins WHERE id = ?').get(id);
    if (!existing) return res.status(404).json({ error: 'Plugin not found' });
    const { display_name, description, version, author, plugin_type, entry_point, config_schema, status, settings } = req.body;
    const now = localNow();
    db.prepare(`UPDATE plugins SET display_name = ?, description = ?, version = ?, author = ?, plugin_type = ?, entry_point = ?, config_schema = ?, status = ?, settings = ?, updated_at = ? WHERE id = ?`)
      .run(display_name || existing.display_name, description !== undefined ? description : existing.description, version || existing.version, author !== undefined ? author : existing.author, plugin_type || existing.plugin_type, entry_point !== undefined ? entry_point : existing.entry_point, config_schema ? JSON.stringify(config_schema) : existing.config_schema, status || existing.status, settings ? JSON.stringify(settings) : existing.settings, now, id);
    const updated = db.prepare('SELECT * FROM plugins WHERE id = ?').get(id);
    // Log status changes
    if (status && status !== existing.status) {
      db.prepare('INSERT INTO plugin_logs (plugin_id, log_level, message, created_at) VALUES (?,?,?,?)')
        .run(id, 'info', `Plugin status changed from ${existing.status} to ${status}`, now);
    }
    broadcast('plugin.updated', updated);
    res.json(updated);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// DELETE /api/plugins/:id
app.delete('/api/plugins/:id', (req, res) => {
  try {
    const id = Number(req.params.id);
    db.prepare('DELETE FROM plugin_logs WHERE plugin_id = ?').run(id);
    db.prepare('DELETE FROM plugin_state WHERE plugin_id = ?').run(id);
    db.prepare('DELETE FROM plugins WHERE id = ?').run(id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/plugins/:id/state
app.get('/api/plugins/:id/state', (req, res) => {
  try {
    const state = db.prepare('SELECT * FROM plugin_state WHERE plugin_id = ?').all(Number(req.params.id));
    res.json(state);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PUT /api/plugins/:id/state/:key
app.put('/api/plugins/:id/state/:key', (req, res) => {
  try {
    const pluginId = Number(req.params.id);
    const key = req.params.key;
    const { value } = req.body;
    const now = localNow();
    db.prepare('INSERT INTO plugin_state (plugin_id, state_key, state_value, updated_at) VALUES (?,?,?,?) ON CONFLICT(plugin_id, state_key) DO UPDATE SET state_value = ?, updated_at = ?')
      .run(pluginId, key, value, now, value, now);
    res.json({ success: true, key, value });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/plugins/:id/logs
app.get('/api/plugins/:id/logs', (req, res) => {
  try {
    const limit = Number(req.query.limit) || 50;
    const logs = db.prepare('SELECT * FROM plugin_logs WHERE plugin_id = ? ORDER BY created_at DESC LIMIT ?').all(Number(req.params.id), limit);
    res.json(logs);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/plugins/:id/execute
app.post('/api/plugins/:id/execute', (req, res) => {
  try {
    const id = Number(req.params.id);
    const plugin = db.prepare('SELECT * FROM plugins WHERE id = ?').get(id);
    if (!plugin) return res.status(404).json({ error: 'Plugin not found' });
    if (plugin.status !== 'active') return res.status(400).json({ error: 'Plugin is not active' });
    const now = localNow();
    const { action, params } = req.body;
    // Log the execution
    db.prepare('INSERT INTO plugin_logs (plugin_id, log_level, message, metadata, created_at) VALUES (?,?,?,?,?)')
      .run(id, 'info', `Executed action: ${action || 'default'}`, JSON.stringify(params || {}), now);
    broadcast('plugin.executed', { plugin_id: id, action, params });
    res.json({ success: true, plugin_id: id, action: action || 'default', message: 'Plugin action queued' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});


};
