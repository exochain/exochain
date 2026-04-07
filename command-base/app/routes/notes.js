'use strict';
module.exports = function(app, db, helpers) {
  const { broadcast, localNow, createNotification, authRateLimiter, apiRateLimiter, spawnMemberTerminal } = helpers;
  const stmt = helpers.stmt || ((sql) => db.prepare(sql));

app.get('/api/notes', (req, res) => {
  try {
    const rows = stmt(`
      SELECT * FROM notes ORDER BY created_at DESC
    `).all();

    const notes = attachTags(rows, 'note');

    // Attach action items to notes
    const enriched = notes.map(note => ({
      ...note,
    }));

    res.json(enriched);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/notes/:id', (req, res) => {
  try {
    const note = stmt(`SELECT * FROM notes WHERE id = ?`).get(req.params.id);
    if (!note) return res.status(404).json({ error: 'Note not found' });

    const title = req.body.title !== undefined ? req.body.title : note.title;
    const content = req.body.content !== undefined ? req.body.content : note.content;
    const now = localNow();

    stmt(`UPDATE notes SET title = ?, content = ?, updated_at = ? WHERE id = ?`)
      .run(title, content, now, req.params.id);

    res.json({ message: 'Note updated' });
    broadcast('note.updated', { id: Number(req.params.id) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/notes/:id', (req, res) => {
  try {
    const note = stmt(`SELECT id FROM notes WHERE id = ?`).get(req.params.id);
    if (!note) return res.status(404).json({ error: 'Note not found' });

    db.transaction(() => {
      stmt(`DELETE FROM taggables WHERE entity_type = 'note' AND entity_id = ?`).run(req.params.id);
      stmt(`DELETE FROM notes WHERE id = ?`).run(req.params.id);
    })();

    res.json({ message: 'Note deleted' });
    broadcast('note.updated', { id: Number(req.params.id) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/contacts', (req, res) => {
  try {
    const rows = stmt(`
      SELECT * FROM contacts ORDER BY name ASC
    `).all();
    res.json(attachTags(rows, 'contact'));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/contacts', (req, res) => {
  try {
    const { name, role, company, email, phone, notes } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: 'Name is required' });
    const now = localNow();
    const result = stmt(`
      INSERT INTO contacts (name, role, company, email, phone, notes, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(name.trim(), role || null, company || null, email || null, phone || null, notes || null, now, now);
    res.json({ id: Number(result.lastInsertRowid), message: 'Contact created' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/contacts/:id', (req, res) => {
  try {
    const existing = stmt(`SELECT * FROM contacts WHERE id = ?`).get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Contact not found' });

    const fields = ['name', 'role', 'company', 'email', 'phone', 'notes'];
    const updates = [];
    const values = [];
    for (const f of fields) {
      if (req.body[f] !== undefined) {
        updates.push(`${f} = ?`);
        values.push(req.body[f]);
      }
    }
    if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });

    updates.push(`updated_at = ?`);
    values.push(localNow());
    values.push(req.params.id);

    db.prepare(`UPDATE contacts SET ${updates.join(', ')} WHERE id = ?`).run(...values);
    res.json({ message: 'Contact updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/contacts/:id', (req, res) => {
  try {
    const contact = stmt(`SELECT id FROM contacts WHERE id = ?`).get(req.params.id);
    if (!contact) return res.status(404).json({ error: 'Contact not found' });

    db.transaction(() => {
      stmt(`DELETE FROM taggables WHERE entity_type = 'contact' AND entity_id = ?`).run(req.params.id);
      stmt(`DELETE FROM contacts WHERE id = ?`).run(req.params.id);
    })();
    res.json({ message: 'Contact deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/decisions', (req, res) => {
  try {
    const rows = stmt(`
      SELECT d.*, t.title as task_title
      FROM decisions d
      LEFT JOIN tasks t ON d.task_id = t.id
      ORDER BY d.asked_at DESC
    `).all();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/decisions', (req, res) => {
  try {
    const { question, context, task_id } = req.body;
    if (!question) return res.status(400).json({ error: 'question is required' });
    const now = localNow();
    const result = stmt(`
      INSERT INTO decisions (question, context, task_id, status, asked_at)
      VALUES (?, ?, ?, 'pending', ?)
    `).run(question, context || null, task_id || null, now);
    res.json({ id: Number(result.lastInsertRowid), message: 'Decision created' });
    broadcast('decision.updated', { id: Number(result.lastInsertRowid) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/decisions/:id', (req, res) => {
  try {
    const existing = stmt(`SELECT * FROM decisions WHERE id = ?`).get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Decision not found' });

    const { answer, status, context } = req.body;
    const now = localNow();
    const fields = [];
    const vals = [];

    if (answer !== undefined) {
      fields.push('answer = ?');
      vals.push(answer);
      // When answering, auto-set status and timestamp
      fields.push('status = ?');
      vals.push('answered');
      fields.push('answered_at = ?');
      vals.push(now);
    }
    if (status !== undefined && answer === undefined) {
      const validDecisionStatuses = ['pending', 'answered', 'superseded'];
      if (!validDecisionStatuses.includes(status)) {
        return res.status(400).json({ error: 'Invalid status. Must be one of: ' + validDecisionStatuses.join(', ') });
      }
      fields.push('status = ?');
      vals.push(status);
    }
    if (context !== undefined) {
      fields.push('context = ?');
      vals.push(context);
    }

    if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });

    vals.push(req.params.id);
    db.prepare(`UPDATE decisions SET ${fields.join(', ')} WHERE id = ?`).run(...vals);
    res.json({ id: Number(req.params.id), message: 'Decision updated' });
    broadcast('decision.updated', { id: Number(req.params.id) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/tags', (req, res) => {
  try {
    const tags = stmt(`SELECT * FROM tags ORDER BY name ASC`).all();

    const countStmt = stmt(`
      SELECT entity_type, COUNT(*) as count
      FROM taggables WHERE tag_id = ?
      GROUP BY entity_type
    `);

    const entitiesStmt = stmt(`
      SELECT tg.entity_type, tg.entity_id
      FROM taggables tg
      WHERE tg.tag_id = ?
    `);

    const enriched = tags.map(tag => {
      const counts = countStmt.all(tag.id);
      const entities = entitiesStmt.all(tag.id);

      // Resolve entity names
      const resolved = entities.map(e => {
        let name = `${e.entity_type}#${e.entity_id}`;
        if (e.entity_type === 'task') {
          const t = stmt(`SELECT title FROM tasks WHERE id = ?`).get(e.entity_id);
          if (t) name = t.title;
        } else if (e.entity_type === 'note') {
          const n = stmt(`SELECT title FROM notes WHERE id = ?`).get(e.entity_id);
          if (n) name = n.title || `Note #${e.entity_id}`;
        } else if (e.entity_type === 'contact') {
          const c = stmt(`SELECT name FROM contacts WHERE id = ?`).get(e.entity_id);
          if (c) name = c.name;
        }
        return { ...e, name };
      });

      return {
        ...tag,
        counts: counts.reduce((acc, c) => { acc[c.entity_type] = c.count; return acc; }, {}),
        total: counts.reduce((sum, c) => sum + c.count, 0),
        entities: resolved
      };
    });

    const bodyT = JSON.stringify(enriched);
    const etagT = `"${crypto.createHash('md5').update(bodyT).digest('hex')}"`;
    res.setHeader('ETag', etagT);
    res.setHeader('Cache-Control', 'no-cache');
    if (req.headers['if-none-match'] === etagT) return res.status(304).end();
    res.json(enriched);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/notes', (req, res) => {
  try {
    const { title, content } = req.body;
    if (!content || !content.trim()) {
      return res.status(400).json({ error: 'Content is required' });
    }
    if (content.trim().length < 3) {
      return res.status(400).json({ error: 'Content must be at least 3 characters' });
    }

    const now = localNow();

    // Extract action items from note content
    const extracted = extractActionItems(content.trim());

    // Transactional: create note + action items atomically
    const { noteId, actionItemIds } = db.transaction(() => {
      const result = db.prepare(`
        INSERT INTO notes (title, content, source, created_at, updated_at)
        VALUES (?, ?, 'browser', ?, ?)
      `).run(
        (title || '').trim() || 'Untitled Note',
        content.trim(),
        now,
        now
      );

      const nId = Number(result.lastInsertRowid);
      const aiIds = [];

      for (const desc of extracted) {
        const aiResult = db.prepare(`
          VALUES (?, ?, 'pending', ?)
        `).run(nId, desc, now);
        aiIds.push(Number(aiResult.lastInsertRowid));
      }

      return { noteId: nId, actionItemIds: aiIds };
    })();

    // Auto-execute all extracted action items (async, don't block response)
    if (actionItemIds.length > 0) {
      (async () => {
        const results = [];
        for (const aiId of actionItemIds) {
          try {
            const r = await autoExecuteActionItem(aiId);
            results.push(r);
          } catch (err) {
            console.error(`[ActionItem] Auto-execute error for #${aiId}: ${err.message}`);
          }
        }
      })();
    }

    res.json({
      note_id: noteId,
      message: 'Note saved',
    });
    broadcast('note.updated', { id: noteId });
  } catch (err) {
    console.error('POST /api/notes error:', err);
    res.status(500).json({ error: err.message });
  }
});


};
