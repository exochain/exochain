'use strict';
module.exports = function(app, db, helpers) {
  const { broadcast, localNow, createNotification, authRateLimiter, apiRateLimiter, spawnMemberTerminal } = helpers;
  const stmt = helpers.stmt || ((sql) => db.prepare(sql));

// GET /api/members/:id/tools — all tools for a member
app.get('/api/members/:id/tools', (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT * FROM member_tools WHERE member_id = ? ORDER BY created_at DESC
    `).all(req.params.id);
    const parsed = rows.map(r => ({
      ...r,
      config: maskSensitiveConfig(JSON.parse(r.config || '{}'))
    }));
    res.json(parsed);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/members/:id/tools — add a tool
// If the tool has an API key in config, also save it to credential_vault and link via vault_id
app.post('/api/members/:id/tools', authRateLimiter, (req, res) => {
  try {
    const { tool_name, tool_type, config, use_cases, guidelines, usage_limits, daily_limit, vault_id } = req.body;
    if (!tool_name || !tool_name.trim()) {
      return res.status(400).json({ error: 'tool_name is required' });
    }
    if (!tool_type || !['api_key', 'oauth_token', 'session_token', 'mcp_server', 'skill', 'custom'].includes(tool_type)) {
      return res.status(400).json({ error: 'Invalid tool_type' });
    }
    const now = localNow();
    const configObj = config || {};
    let linkedVaultId = vault_id || null;

    // If there's an API key in config and no vault_id provided, save to credential_vault
    const apiKey = configObj.key || configObj.api_key || configObj.apiKey;
    if (apiKey && !linkedVaultId) {
      // Check if a vault entry already exists for this provider/name
      const existingVault = db.prepare(
        'SELECT id FROM credential_vault WHERE provider = ? AND credential_type = ?'
      ).get(tool_name.trim(), 'api_key');
      if (existingVault) {
        // Update the existing vault entry with the new key
        db.prepare('UPDATE credential_vault SET encrypted_value = ?, updated_at = ? WHERE id = ?')
          .run(apiKey, now, existingVault.id);
        linkedVaultId = existingVault.id;
      } else {
        // Create a new vault entry
        const vaultResult = db.prepare(`
          INSERT INTO credential_vault (name, provider, credential_type, encrypted_value, metadata, created_at, updated_at)
          VALUES (?, ?, 'api_key', ?, '{}', ?, ?)
        `).run(tool_name.trim() + ' API Key', tool_name.trim(), apiKey, now, now);
        linkedVaultId = Number(vaultResult.lastInsertRowid);
      }
    }

    const configStr = JSON.stringify(configObj);
    const result = db.prepare(`
      INSERT INTO member_tools (member_id, tool_name, tool_type, config, enabled, use_cases, guidelines, usage_limits, daily_limit, daily_used, last_reset_date, vault_id, created_at, updated_at)
      VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, 0, ?, ?, ?, ?)
    `).run(req.params.id, tool_name.trim(), tool_type, configStr, use_cases || null, guidelines || null, usage_limits || null, daily_limit != null ? daily_limit : null, now.split(' ')[0], linkedVaultId, now, now);
    res.json({
      id: Number(result.lastInsertRowid),
      member_id: Number(req.params.id),
      tool_name: tool_name.trim(),
      tool_type,
      config: maskSensitiveConfig(configObj),
      enabled: 1,
      use_cases: use_cases || null,
      guidelines: guidelines || null,
      usage_limits: usage_limits || null,
      daily_limit: daily_limit != null ? daily_limit : null,
      daily_used: 0,
      last_reset_date: now.split(' ')[0],
      vault_id: linkedVaultId,
      created_at: now,
      updated_at: now
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/members/:id/projects — projects a member has affinity for
app.get('/api/members/:id/projects', (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT pa.*, p.name as project_name, p.status as project_status, p.color
      FROM project_affinity pa
      JOIN projects p ON pa.project_id = p.id
      WHERE pa.member_id = ? AND pa.status = 'active'
      ORDER BY pa.last_active_at DESC NULLS LAST
    `).all(req.params.id);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/members/:id/activate', (req, res) => {
  try {
    const { active } = req.body;
    const newStatus = active ? 'active' : 'inactive';
    const result = db.prepare(`UPDATE team_members SET status = ? WHERE id = ?`).run(newStatus, req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Member not found' });
    invalidateCache('team_members');
    const member = db.prepare(`SELECT name FROM team_members WHERE id = ?`).get(req.params.id);
    res.json({ message: `${member.name} ${newStatus}` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/members/:id/execution-mode', (req, res) => {
  try {
    const { mode } = req.body;
    if (!['system', 'terminal', 'autonomous'].includes(mode)) {
      return res.status(400).json({ error: 'Mode must be system, terminal, or autonomous' });
    }
    const result = db.prepare(`UPDATE team_members SET execution_mode = ? WHERE id = ?`).run(mode, req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Member not found' });
    res.json({ message: 'Member execution mode updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/members/:id/llm — assign a provider+model to a member
app.put('/api/members/:id/llm', (req, res) => {
  try {
    const member = db.prepare('SELECT * FROM team_members WHERE id = ?').get(req.params.id);
    if (!member) return res.status(404).json({ error: 'Member not found' });

    const { provider_id, model } = req.body;

    if (provider_id !== undefined && provider_id !== null) {
      const provider = db.prepare('SELECT * FROM llm_providers WHERE id = ?').get(provider_id);
      if (!provider) return res.status(404).json({ error: 'Provider not found' });
    }

    db.prepare(`
      UPDATE team_members SET llm_provider_id = ?, llm_model = ? WHERE id = ?
    `).run(provider_id !== undefined ? provider_id : member.llm_provider_id,
           model !== undefined ? model : member.llm_model,
           req.params.id);

    const updated = db.prepare('SELECT * FROM team_members WHERE id = ?').get(req.params.id);
    res.json({
      id: updated.id,
      name: updated.name,
      llm_provider_id: updated.llm_provider_id,
      llm_model: updated.llm_model
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/members/:id/llm — get member's current LLM assignment
app.get('/api/members/:id/llm', (req, res) => {
  try {
    const member = db.prepare('SELECT * FROM team_members WHERE id = ?').get(req.params.id);
    if (!member) return res.status(404).json({ error: 'Member not found' });

    let provider = null;
    if (member.llm_provider_id) {
      provider = db.prepare('SELECT * FROM llm_providers WHERE id = ?').get(member.llm_provider_id);
      if (provider) {
        provider = {
          ...provider,
          api_key: maskApiKey(provider.api_key),
          config: JSON.parse(provider.config || '{}')
        };
      }
    }

    res.json({
      member_id: member.id,
      member_name: member.name,
      llm_provider_id: member.llm_provider_id,
      llm_model: member.llm_model,
      provider
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/members/:id/skills — skills assigned to a member
app.get('/api/members/:id/skills', (req, res) => {
  try {
    const skills = db.prepare(`
      SELECT s.*, agent_skills.priority, agent_skills.id as assignment_id
      FROM skills s
      JOIN agent_skills ON s.id = agent_skills.skill_id
      WHERE agent_skills.member_id = ?
      ORDER BY agent_skills.priority DESC, s.name
    `).all(Number(req.params.id));
    res.json(skills);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/members/:id/skills — assign a skill to a member
app.post('/api/members/:id/skills', (req, res) => {
  try {
    const { skill_id, priority } = req.body;
    if (!skill_id) return res.status(400).json({ error: 'skill_id is required' });
    const now = localNow();
    db.prepare('INSERT OR IGNORE INTO agent_skills (member_id, skill_id, priority, created_at) VALUES (?,?,?,?)')
      .run(Number(req.params.id), Number(skill_id), priority || 0, now);
    const skills = db.prepare(`
      SELECT s.*, agent_skills.priority, agent_skills.id as assignment_id
      FROM skills s
      JOIN agent_skills ON s.id = agent_skills.skill_id
      WHERE agent_skills.member_id = ?
      ORDER BY agent_skills.priority DESC, s.name
    `).all(Number(req.params.id));
    res.json(skills);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// DELETE /api/members/:id/skills/:skillId — unassign a skill
app.delete('/api/members/:id/skills/:skillId', (req, res) => {
  try {
    db.prepare('DELETE FROM agent_skills WHERE member_id = ? AND skill_id = ?')
      .run(Number(req.params.id), Number(req.params.skillId));
    res.json({ message: 'Skill unassigned' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PUT /api/members/:id/adapter — change a member's adapter type and config
app.put('/api/members/:id/adapter', (req, res) => {
  try {
    const member = db.prepare('SELECT * FROM team_members WHERE id = ?').get(Number(req.params.id));
    if (!member) return res.status(404).json({ error: 'Member not found' });
    const { adapter_type, adapter_config, runtime_config, capabilities } = req.body;
    const now = localNow();
    if (adapter_type !== undefined) db.prepare('UPDATE team_members SET adapter_type = ? WHERE id = ?').run(adapter_type, Number(req.params.id));
    if (adapter_config !== undefined) db.prepare('UPDATE team_members SET adapter_config = ? WHERE id = ?').run(typeof adapter_config === 'string' ? adapter_config : JSON.stringify(adapter_config), Number(req.params.id));
    if (runtime_config !== undefined) db.prepare('UPDATE team_members SET runtime_config = ? WHERE id = ?').run(typeof runtime_config === 'string' ? runtime_config : JSON.stringify(runtime_config), Number(req.params.id));
    if (capabilities !== undefined) db.prepare('UPDATE team_members SET capabilities = ? WHERE id = ?').run(typeof capabilities === 'string' ? capabilities : JSON.stringify(capabilities), Number(req.params.id));
    const updated = db.prepare('SELECT * FROM team_members WHERE id = ?').get(Number(req.params.id));
    res.json(updated);
    broadcast('member.updated', { id: Number(req.params.id) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/members/:id/adapter — get member's adapter info
app.get('/api/members/:id/adapter', (req, res) => {
  try {
    const member = db.prepare('SELECT id, name, role, adapter_type, adapter_config, runtime_config, capabilities FROM team_members WHERE id = ?').get(Number(req.params.id));
    if (!member) return res.status(404).json({ error: 'Member not found' });
    res.json(member);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/members/:id/memory — all memory entities for a member
app.get('/api/members/:id/memory', (req, res) => {
  try {
    const memberId = Number(req.params.id);
    let query = 'SELECT * FROM agent_memory_entities WHERE member_id = ?';
    const params = [memberId];

    if (req.query.type) {
      query += ' AND entity_type = ?';
      params.push(req.query.type);
    }
    if (req.query.importance) {
      query += ' AND importance = ?';
      params.push(req.query.importance);
    }

    query += " ORDER BY CASE importance WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 WHEN 'low' THEN 3 END, updated_at DESC";

    if (req.query.limit) {
      query += ' LIMIT ?';
      params.push(Number(req.query.limit));
    }

    const memories = db.prepare(query).all(...params);
    res.json(memories);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/members/:id/memory — add a memory entity
app.post('/api/members/:id/memory', (req, res) => {
  try {
    const memberId = Number(req.params.id);
    const { entity_type, title, content, tags, importance, project_id, source_task_id, expires_at } = req.body;
    if (!entity_type || !title || !content) return res.status(400).json({ error: 'entity_type, title, and content are required' });
    const now = localNow();
    const result = db.prepare('INSERT INTO agent_memory_entities (member_id, entity_type, title, content, tags, importance, project_id, source_task_id, expires_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
      .run(memberId, entity_type, title, content, JSON.stringify(tags || []), importance || 'normal', project_id || null, source_task_id || null, expires_at || null, now, now);
    const memory = db.prepare('SELECT * FROM agent_memory_entities WHERE id = ?').get(result.lastInsertRowid);
    res.status(201).json(memory);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/members/:id/daily-notes — daily notes for a member
app.get('/api/members/:id/daily-notes', (req, res) => {
  try {
    const memberId = Number(req.params.id);
    let query = 'SELECT * FROM agent_daily_notes WHERE member_id = ?';
    const params = [memberId];
    if (req.query.since) { query += ' AND note_date >= ?'; params.push(req.query.since); }
    if (req.query.until) { query += ' AND note_date <= ?'; params.push(req.query.until); }
    query += ' ORDER BY note_date DESC';
    if (req.query.limit) { query += ' LIMIT ?'; params.push(Number(req.query.limit)); }
    const notes = db.prepare(query).all(...params);
    res.json(notes);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/members/:id/daily-notes/:date — specific day's note
app.get('/api/members/:id/daily-notes/:date', (req, res) => {
  try {
    const note = db.prepare('SELECT * FROM agent_daily_notes WHERE member_id = ? AND note_date = ?').get(Number(req.params.id), req.params.date);
    if (!note) return res.status(404).json({ error: 'No note for that date' });
    res.json(note);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/members/:id/daily-notes — create/update daily note
app.post('/api/members/:id/daily-notes', (req, res) => {
  try {
    const memberId = Number(req.params.id);
    const { note_date, content, tasks_worked, files_touched, lessons_learned, blockers } = req.body;
    if (!content) return res.status(400).json({ error: 'content is required' });
    const date = note_date || localNow().split(' ')[0];
    const now = localNow();
    const existing = db.prepare('SELECT * FROM agent_daily_notes WHERE member_id = ? AND note_date = ?').get(memberId, date);
    if (existing) {
      db.prepare('UPDATE agent_daily_notes SET content = ?, tasks_worked = ?, files_touched = ?, lessons_learned = ?, blockers = ?, updated_at = ? WHERE id = ?')
        .run(content, JSON.stringify(tasks_worked || JSON.parse(existing.tasks_worked || '[]')), JSON.stringify(files_touched || JSON.parse(existing.files_touched || '[]')), lessons_learned || existing.lessons_learned, blockers || existing.blockers, now, existing.id);
      const updated = db.prepare('SELECT * FROM agent_daily_notes WHERE id = ?').get(existing.id);
      res.json(updated);
    } else {
      const result = db.prepare('INSERT INTO agent_daily_notes (member_id, note_date, content, tasks_worked, files_touched, lessons_learned, blockers, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)')
        .run(memberId, date, content, JSON.stringify(tasks_worked || []), JSON.stringify(files_touched || []), lessons_learned || null, blockers || null, now, now);
      const note = db.prepare('SELECT * FROM agent_daily_notes WHERE id = ?').get(result.lastInsertRowid);
      res.status(201).json(note);
    }
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/members/:id/tacit — tacit knowledge for a member
app.get('/api/members/:id/tacit', (req, res) => {
  try {
    const memberId = Number(req.params.id);
    const tacit = db.prepare('SELECT * FROM agent_tacit_knowledge WHERE member_id = ? ORDER BY confidence DESC, times_applied DESC').all(memberId);
    res.json(tacit);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/members/:id/tacit — add tacit knowledge
app.post('/api/members/:id/tacit', (req, res) => {
  try {
    const memberId = Number(req.params.id);
    const { knowledge_type, subject, insight, confidence, source_description } = req.body;
    if (!knowledge_type || !subject || !insight) return res.status(400).json({ error: 'knowledge_type, subject, and insight are required' });
    const now = localNow();
    const result = db.prepare('INSERT INTO agent_tacit_knowledge (member_id, knowledge_type, subject, insight, confidence, source_description, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)')
      .run(memberId, knowledge_type, subject, insight, confidence || 'medium', source_description || null, now, now);
    const tk = db.prepare('SELECT * FROM agent_tacit_knowledge WHERE id = ?').get(result.lastInsertRowid);
    res.status(201).json(tk);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/members/:id/identity — identity files (SOUL, HEARTBEAT, AGENTS)
app.get('/api/members/:id/identity', (req, res) => {
  try {
    const memberId = Number(req.params.id);
    const files = db.prepare('SELECT * FROM agent_identity_files WHERE member_id = ? ORDER BY file_type').all(memberId);
    res.json(files);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PUT /api/members/:id/identity/:fileType — update an identity file
app.put('/api/members/:id/identity/:fileType', (req, res) => {
  try {
    const memberId = Number(req.params.id);
    const fileType = req.params.fileType;
    const { content } = req.body;
    if (!content) return res.status(400).json({ error: 'content is required' });
    const now = localNow();
    const existing = db.prepare('SELECT * FROM agent_identity_files WHERE member_id = ? AND file_type = ?').get(memberId, fileType);
    if (existing) {
      db.prepare('UPDATE agent_identity_files SET content = ?, version = version + 1, updated_at = ? WHERE id = ?')
        .run(content, now, existing.id);
    } else {
      db.prepare('INSERT INTO agent_identity_files (member_id, file_type, file_name, content, created_at, updated_at) VALUES (?,?,?,?,?,?)')
        .run(memberId, fileType, `${fileType.toUpperCase()}.md`, content, now, now);
    }
    const file = db.prepare('SELECT * FROM agent_identity_files WHERE member_id = ? AND file_type = ?').get(memberId, fileType);
    res.json(file);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/members/:id/identity/generate — regenerate from profile
app.post('/api/members/:id/identity/generate', (req, res) => {
  try {
    const memberId = Number(req.params.id);
    generateIdentityFiles(memberId);
    const files = db.prepare('SELECT * FROM agent_identity_files WHERE member_id = ? ORDER BY file_type').all(memberId);
    res.json({ success: true, files });
  } catch (err) { res.status(500).json({ error: err.message }); }
});


};
