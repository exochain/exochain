'use strict';
module.exports = function(app, db, helpers) {
  const { broadcast, localNow, createNotification, authRateLimiter, apiRateLimiter, spawnMemberTerminal } = helpers;
  const stmt = helpers.stmt || ((sql) => db.prepare(sql));

app.get('/api/companies', (req, res) => {
  try {
    const rows = stmt(`
      SELECT c.*,
        (SELECT COUNT(*) FROM projects p WHERE p.company_id = c.id) as project_count,
        (SELECT COUNT(*) FROM company_members cm WHERE cm.company_id = c.id AND cm.status = 'active') as member_count,
        (SELECT tm.name FROM team_members tm WHERE tm.id = c.ceo_member_id) as ceo_name,
        (SELECT tm.name FROM team_members tm WHERE tm.id = c.cto_member_id) as cto_name
      FROM companies c
      ORDER BY c.name ASC
    `).all();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/companies/:id', (req, res) => {
  try {
    const company = stmt(`SELECT * FROM companies WHERE id = ?`).get(req.params.id);
    if (!company) return res.status(404).json({ error: 'Company not found' });

    const projects = stmt(`
      SELECT p.*,
        (SELECT COUNT(*) FROM project_tasks pt WHERE pt.project_id = p.id) as task_count,
        (SELECT tm.name FROM project_executives pe JOIN team_members tm ON pe.member_id = tm.id WHERE pe.project_id = p.id) as exec_name
      FROM projects p
      WHERE p.company_id = ?
      ORDER BY p.updated_at DESC
    `).all(req.params.id);

    const members = stmt(`
      SELECT cm.*, tm.name, tm.role, tm.tier, tm.department, tm.status as member_status, tm.icon
      FROM company_members cm
      JOIN team_members tm ON cm.member_id = tm.id
      WHERE cm.company_id = ? AND cm.status = 'active'
      ORDER BY tm.tier DESC, tm.name ASC
    `).all(req.params.id);

    const ceoData = company.ceo_member_id ? stmt(`SELECT id, name, role, tier FROM team_members WHERE id = ?`).get(company.ceo_member_id) : null;
    const ctoData = company.cto_member_id ? stmt(`SELECT id, name, role, tier FROM team_members WHERE id = ?`).get(company.cto_member_id) : null;

    // FIX: Frontend expects team_members (not members), ceo_name/cto_name (not ceo/cto objects)
    res.json({ ...company, projects, team_members: members, ceo: ceoData, cto: ctoData, ceo_name: ceoData ? ceoData.name : null, cto_name: ctoData ? ctoData.name : null });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/companies', (req, res) => {
  try {
    const { name, description, status, ceo_member_id, cto_member_id, color } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: 'Name is required' });
    const companyStatus = ['active', 'inactive', 'archived'].includes(status) ? status : 'active';
    const now = localNow();
    const result = stmt(`
      INSERT INTO companies (name, description, status, ceo_member_id, cto_member_id, color, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(name.trim(), (description || '').trim() || null, companyStatus, ceo_member_id || null, cto_member_id || null, color || null, now, now);
    const companyId = Number(result.lastInsertRowid);
    const companyName = name.trim();

    // Auto-create founding team: CEO + CTO + Talent Lead
    // Each company starts lean and grows organically based on need.
    if (!ceo_member_id && !cto_member_id) {
      try {
        // Generate unique names based on company
        const prefix = companyName.split(/\s+/)[0].slice(0, 4);
        const ceoName = prefix + '-CEO';
        const ctoName = prefix + '-CTO';
        const talentName = prefix + '-Talent';

        // Check names don't conflict
        const nameExists = (n) => db.prepare(`SELECT id FROM team_members WHERE name = ?`).get(n);

        const safeCeoName = nameExists(ceoName) ? companyName + ' CEO' : ceoName;
        const safeCtoName = nameExists(ctoName) ? companyName + ' CTO' : ctoName;
        const safeTalentName = nameExists(talentName) ? companyName + ' Talent' : talentName;

        // Create CEO
        const ceoResult = db.prepare(`INSERT INTO team_members (name, role, status, tier, department, reports_to, created_at)
          VALUES (?, ?, 'active', 'c-suite', ?, 49, ?)`).run(safeCeoName, `CEO — ${companyName}`, companyName, now);
        const ceoId = Number(ceoResult.lastInsertRowid);

        // Create CTO (reports to CEO)
        const ctoResult = db.prepare(`INSERT INTO team_members (name, role, status, tier, department, reports_to, created_at)
          VALUES (?, ?, 'active', 'c-suite', ?, ?, ?)`).run(safeCtoName, `CTO — ${companyName}`, companyName, ceoId, now);
        const ctoId = Number(ctoResult.lastInsertRowid);

        // Create Talent Lead (reports to CEO)
        const talentResult = db.prepare(`INSERT INTO team_members (name, role, status, tier, department, reports_to, created_at)
          VALUES (?, ?, 'active', 'specialist', ?, ?, ?)`).run(safeTalentName, `Talent Lead — ${companyName}`, companyName, ceoId, now);
        const talentId = Number(talentResult.lastInsertRowid);

        // Create Directive Analyst (reports to CEO)
        const analystName = prefix + '-Analyst';
        const safeAnalystName = nameExists(analystName) ? companyName + ' Analyst' : analystName;
        const analystResult = db.prepare(`INSERT INTO team_members (name, role, status, tier, department, reports_to, created_at)
          VALUES (?, ?, 'active', 'specialist', ?, ?, ?)`).run(safeAnalystName, `Directive Analyst — ${companyName}`, companyName, ceoId, now);
        const analystId = Number(analystResult.lastInsertRowid);

        // Assign to company
        db.prepare(`UPDATE companies SET ceo_member_id = ?, cto_member_id = ? WHERE id = ?`).run(ceoId, ctoId, companyId);
        db.prepare(`INSERT OR IGNORE INTO company_members (company_id, member_id, role_in_company) VALUES (?,?,?)`).run(companyId, ceoId, 'ceo');
        db.prepare(`INSERT OR IGNORE INTO company_members (company_id, member_id, role_in_company) VALUES (?,?,?)`).run(companyId, ctoId, 'cto');
        db.prepare(`INSERT OR IGNORE INTO company_members (company_id, member_id, role_in_company) VALUES (?,?,?)`).run(companyId, talentId, 'talent_lead');
        db.prepare(`INSERT OR IGNORE INTO company_members (company_id, member_id, role_in_company) VALUES (?,?,?)`).run(companyId, analystId, 'analyst');

        // Create founding memories for each
        db.prepare(`INSERT INTO agent_memory_entities (member_id, entity_type, title, content, importance, created_at, updated_at)
          VALUES (?, 'experience', ?, ?, 'high', ?, ?)`).run(ceoId, `Founding ${companyName}`,
          `I was created as the founding CEO of ${companyName}. My job is to own the vision, set priorities, and make the business decisions. I start with a clean slate and build institutional knowledge through every task.`, now, now);
        db.prepare(`INSERT INTO agent_memory_entities (member_id, entity_type, title, content, importance, created_at, updated_at)
          VALUES (?, 'experience', ?, ?, 'high', ?, ?)`).run(ctoId, `Founding ${companyName}`,
          `I was created as the founding CTO of ${companyName}. I own the architecture, technical standards, and code quality. Every technical decision I make shapes the company's foundation.`, now, now);
        db.prepare(`INSERT INTO agent_memory_entities (member_id, entity_type, title, content, importance, created_at, updated_at)
          VALUES (?, 'experience', ?, ?, 'high', ?, ?)`).run(talentId, `Founding ${companyName}`,
          `I'm the Talent Lead for ${companyName}. My job is to hire and train new team members as the company grows. I hire for bottlenecks — one at a time, mentor each new hire through 3 supervised tasks, and never hire faster than I can train. Quality over quantity.`, now, now);
        db.prepare(`INSERT INTO agent_memory_entities (member_id, entity_type, title, content, importance, created_at, updated_at)
          VALUES (?, 'experience', ?, ?, 'high', ?, ?)`).run(analystId, `Founding ${companyName}`,
          `I'm the Directive Analyst for ${companyName}. Every message the Chairman sends to our Board Room comes to me first. I read everything — every file, every attachment, every line. I produce a structured brief so the Council can focus on planning instead of reading. I classify the directive, extract deliverables, identify phases, flag risks, and recommend how the Council should approach it.`, now, now);

        // Create basic profiles
        const profileDir = path.join(__dirname, '..', 'Team');
        for (const [mid, mname, mrole, mdesc] of [
          [ceoId, safeCeoName, `CEO — ${companyName}`, `Founding CEO. Owns vision, priorities, and business decisions for ${companyName}.`],
          [ctoId, safeCtoName, `CTO — ${companyName}`, `Founding CTO. Owns architecture, technical standards, and code quality for ${companyName}.`],
          [talentId, safeTalentName, `Talent Lead — ${companyName}`, `Hiring and onboarding specialist. Evaluates team needs, recruits specialists, mentors new hires through supervised tasks. Hires for bottlenecks, never preemptively. One hire at a time.`],
          [analystId, safeAnalystName, `Directive Analyst — ${companyName}`, `Reads and analyzes every Board Room directive before the Council sees it. Produces structured briefs with classification, deliverables, phases, technical requirements, and risk flags. Separates digestion from deliberation.`]
        ]) {
          const profilePath = path.join(profileDir, mname.toLowerCase().replace(/ /g, '-') + '.md');
          try {
            fs.writeFileSync(profilePath, `# ${mname} — ${mrole}\n\n## Identity\n- **Name:** ${mname}\n- **Title:** ${mrole}\n- **Company:** ${companyName}\n- **Tier:** ${mid === talentId ? 'Specialist' : 'C-Suite'}\n\n## Persona\n${mdesc}\n`, 'utf-8');
          } catch (_) {}
        }

        db.prepare(`INSERT INTO activity_log (actor, action, notes, created_at) VALUES ('System', 'company_founded', ?, ?)`)
          .run(`${companyName} founded with ${safeCeoName} (CEO), ${safeCtoName} (CTO), ${safeTalentName} (Talent Lead)`, now);

        // Post to Board Room
        try {
          db.prepare(`INSERT INTO board_chats (company_id, sender_name, sender_role, message, message_type, created_at)
            VALUES (?, 'System', 'System', ?, 'system', ?)`)
            .run(companyId, `${companyName} founded. Founding team: ${safeCeoName} (CEO), ${safeCtoName} (CTO), ${safeTalentName} (Talent Lead). The company starts lean — the Talent Lead will hire as bottlenecks emerge.`, now);
        } catch (_) {}

      } catch (foundingErr) {
        console.warn(`[Company] Failed to create founding team for ${companyName}: ${foundingErr.message}`);
      }
    }

    res.json({ id: companyId, message: 'Company created' });
  } catch (err) {
    if (err.message && err.message.includes('UNIQUE constraint')) return res.status(409).json({ error: 'Company name already exists' });
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/companies/:id', (req, res) => {
  try {
    const existing = stmt(`SELECT * FROM companies WHERE id = ?`).get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Company not found' });
    const name = req.body.name !== undefined ? req.body.name.trim() : existing.name;
    const description = req.body.description !== undefined ? req.body.description : existing.description;
    const status = req.body.status !== undefined && ['active', 'inactive', 'archived'].includes(req.body.status) ? req.body.status : existing.status;
    const ceo_member_id = req.body.ceo_member_id !== undefined ? (req.body.ceo_member_id || null) : existing.ceo_member_id;
    const cto_member_id = req.body.cto_member_id !== undefined ? (req.body.cto_member_id || null) : existing.cto_member_id;
    const color = req.body.color !== undefined ? req.body.color : existing.color;
    const now = localNow();
    stmt(`
      UPDATE companies SET name = ?, description = ?, status = ?, ceo_member_id = ?, cto_member_id = ?, color = ?, updated_at = ?
      WHERE id = ?
    `).run(name, description, status, ceo_member_id, cto_member_id, color, now, req.params.id);
    res.json({ message: 'Company updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/companies/:id', (req, res) => {
  try {
    // Unlink projects from this company (don't delete them)
    stmt(`UPDATE projects SET company_id = NULL WHERE company_id = ?`).run(req.params.id);
    stmt(`DELETE FROM company_members WHERE company_id = ?`).run(req.params.id);
    const result = stmt(`DELETE FROM companies WHERE id = ?`).run(req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Company not found' });
    res.json({ message: 'Company deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Company member management
app.post('/api/companies/:id/members', (req, res) => {
  try {
    const { member_id, role_in_company } = req.body;
    if (!member_id) return res.status(400).json({ error: 'member_id is required' });
    const now = localNow();
    stmt(`
      INSERT OR REPLACE INTO company_members (company_id, member_id, role_in_company, assigned_at, status)
      VALUES (?, ?, ?, ?, 'active')
    `).run(req.params.id, member_id, role_in_company || 'contributor', now);
    res.json({ message: 'Member added to company' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/companies/:id/members/:memberId', (req, res) => {
  try {
    const result = stmt(`DELETE FROM company_members WHERE company_id = ? AND member_id = ?`).run(req.params.id, req.params.memberId);
    if (result.changes === 0) return res.status(404).json({ error: 'Member not found in company' });
    res.json({ message: 'Member removed from company' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/companies/:id/domains', (req, res) => {
  try {
    const company = stmt(`SELECT id FROM companies WHERE id = ?`).get(req.params.id);
    if (!company) return res.status(404).json({ error: 'Company not found' });
    const rows = stmt(`SELECT * FROM company_domains WHERE company_id = ? ORDER BY created_at DESC`).all(req.params.id);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/companies/:id/domains', (req, res) => {
  try {
    const company = stmt(`SELECT id FROM companies WHERE id = ?`).get(req.params.id);
    if (!company) return res.status(404).json({ error: 'Company not found' });
    const { domain, status, notes, registrar, expiry_date, auto_renew, annual_cost } = req.body;
    if (!domain || !domain.trim()) return res.status(400).json({ error: 'domain is required' });
    const domainStatus = ['active', 'inactive', 'parked'].includes(status) ? status : 'active';
    const now = localNow();
    const result = stmt(`
      INSERT INTO company_domains (company_id, domain, status, notes, registrar, expiry_date, auto_renew, annual_cost, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(req.params.id, domain.trim(), domainStatus, notes || null, registrar || null, expiry_date || null, auto_renew ? 1 : 0, annual_cost != null ? Number(annual_cost) : null, now, now);
    res.json({ id: Number(result.lastInsertRowid), message: 'Domain created' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/companies/:id/domains/:domainId', (req, res) => {
  try {
    const existing = stmt(`SELECT * FROM company_domains WHERE id = ? AND company_id = ?`).get(req.params.domainId, req.params.id);
    if (!existing) return res.status(404).json({ error: 'Domain not found' });
    const domain = req.body.domain !== undefined ? req.body.domain.trim() : existing.domain;
    const status = req.body.status !== undefined && ['active', 'inactive', 'parked'].includes(req.body.status) ? req.body.status : existing.status;
    const notes = req.body.notes !== undefined ? req.body.notes : existing.notes;
    const registrar = req.body.registrar !== undefined ? req.body.registrar : existing.registrar;
    const expiry_date = req.body.expiry_date !== undefined ? req.body.expiry_date : existing.expiry_date;
    const auto_renew = req.body.auto_renew !== undefined ? (req.body.auto_renew ? 1 : 0) : existing.auto_renew;
    const annual_cost = req.body.annual_cost !== undefined ? (req.body.annual_cost != null ? Number(req.body.annual_cost) : null) : existing.annual_cost;
    const now = localNow();
    stmt(`UPDATE company_domains SET domain = ?, status = ?, notes = ?, registrar = ?, expiry_date = ?, auto_renew = ?, annual_cost = ?, updated_at = ? WHERE id = ? AND company_id = ?`)
      .run(domain, status, notes, registrar, expiry_date, auto_renew, annual_cost, now, req.params.domainId, req.params.id);
    res.json({ message: 'Domain updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/companies/:id/domains/:domainId', (req, res) => {
  try {
    const result = stmt(`DELETE FROM company_domains WHERE id = ? AND company_id = ?`).run(req.params.domainId, req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Domain not found' });
    res.json({ message: 'Domain deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/companies/:id/revenue', (req, res) => {
  try {
    const company = stmt(`SELECT id FROM companies WHERE id = ?`).get(req.params.id);
    if (!company) return res.status(404).json({ error: 'Company not found' });
    const rows = stmt(`SELECT * FROM company_revenue WHERE company_id = ? ORDER BY recorded_at DESC`).all(req.params.id);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/companies/:id/revenue', (req, res) => {
  try {
    const company = stmt(`SELECT id FROM companies WHERE id = ?`).get(req.params.id);
    if (!company) return res.status(404).json({ error: 'Company not found' });
    const { amount, currency, source, period, notes, recorded_at, description, is_recurring, interval, amount_cents } = req.body;
    if (amount === undefined || amount === null || isNaN(Number(amount))) return res.status(400).json({ error: 'amount is required and must be a number' });
    const computedCents = amount_cents != null ? Number(amount_cents) : Math.round(Number(amount) * 100);
    const now = localNow();
    const result = stmt(`
      INSERT INTO company_revenue (company_id, amount, currency, source, period, notes, recorded_at, description, is_recurring, interval, amount_cents, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(req.params.id, Number(amount), currency || 'USD', source || null, period || null, notes || null, recorded_at || now, description || null, is_recurring ? 1 : 0, interval || null, computedCents, now, now);
    res.json({ id: Number(result.lastInsertRowid), message: 'Revenue entry created' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/companies/:id/revenue/:revenueId', (req, res) => {
  try {
    const existing = stmt(`SELECT * FROM company_revenue WHERE id = ? AND company_id = ?`).get(req.params.revenueId, req.params.id);
    if (!existing) return res.status(404).json({ error: 'Revenue entry not found' });
    const amount = req.body.amount !== undefined ? Number(req.body.amount) : existing.amount;
    if (isNaN(amount)) return res.status(400).json({ error: 'amount must be a number' });
    const currency = req.body.currency !== undefined ? req.body.currency : existing.currency;
    const source = req.body.source !== undefined ? req.body.source : existing.source;
    const period = req.body.period !== undefined ? req.body.period : existing.period;
    const notes = req.body.notes !== undefined ? req.body.notes : existing.notes;
    const recorded_at = req.body.recorded_at !== undefined ? req.body.recorded_at : existing.recorded_at;
    const description = req.body.description !== undefined ? req.body.description : existing.description;
    const is_recurring = req.body.is_recurring !== undefined ? (req.body.is_recurring ? 1 : 0) : existing.is_recurring;
    const interval = req.body.interval !== undefined ? req.body.interval : existing.interval;
    const amount_cents = req.body.amount_cents !== undefined ? Number(req.body.amount_cents) : Math.round(amount * 100);
    const now = localNow();
    stmt(`UPDATE company_revenue SET amount = ?, currency = ?, source = ?, period = ?, notes = ?, recorded_at = ?, description = ?, is_recurring = ?, interval = ?, amount_cents = ?, updated_at = ? WHERE id = ? AND company_id = ?`)
      .run(amount, currency, source, period, notes, recorded_at, description, is_recurring, interval, amount_cents, now, req.params.revenueId, req.params.id);
    res.json({ message: 'Revenue entry updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/companies/:id/revenue/:revenueId', (req, res) => {
  try {
    const result = stmt(`DELETE FROM company_revenue WHERE id = ? AND company_id = ?`).run(req.params.revenueId, req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Revenue entry not found' });
    res.json({ message: 'Revenue entry deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/companies/:id/expenses', (req, res) => {
  try {
    const company = stmt(`SELECT id FROM companies WHERE id = ?`).get(req.params.id);
    if (!company) return res.status(404).json({ error: 'Company not found' });
    const rows = stmt(`SELECT * FROM company_expenses WHERE company_id = ? ORDER BY recorded_at DESC`).all(req.params.id);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/companies/:id/expenses', (req, res) => {
  try {
    const company = stmt(`SELECT id FROM companies WHERE id = ?`).get(req.params.id);
    if (!company) return res.status(404).json({ error: 'Company not found' });
    const { amount, currency, category, description, period, notes, recorded_at, vendor, is_recurring, interval, amount_cents } = req.body;
    if (amount === undefined || amount === null || isNaN(Number(amount))) return res.status(400).json({ error: 'amount is required and must be a number' });
    const computedCents = amount_cents != null ? Number(amount_cents) : Math.round(Number(amount) * 100);
    const now = localNow();
    const result = stmt(`
      INSERT INTO company_expenses (company_id, amount, currency, category, description, period, notes, recorded_at, vendor, is_recurring, interval, amount_cents, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(req.params.id, Number(amount), currency || 'USD', category || null, description || null, period || null, notes || null, recorded_at || now, vendor || null, is_recurring ? 1 : 0, interval || null, computedCents, now, now);
    res.json({ id: Number(result.lastInsertRowid), message: 'Expense entry created' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/companies/:id/expenses/:expenseId', (req, res) => {
  try {
    const existing = stmt(`SELECT * FROM company_expenses WHERE id = ? AND company_id = ?`).get(req.params.expenseId, req.params.id);
    if (!existing) return res.status(404).json({ error: 'Expense entry not found' });
    const amount = req.body.amount !== undefined ? Number(req.body.amount) : existing.amount;
    if (isNaN(amount)) return res.status(400).json({ error: 'amount must be a number' });
    const currency = req.body.currency !== undefined ? req.body.currency : existing.currency;
    const category = req.body.category !== undefined ? req.body.category : existing.category;
    const description = req.body.description !== undefined ? req.body.description : existing.description;
    const period = req.body.period !== undefined ? req.body.period : existing.period;
    const notes = req.body.notes !== undefined ? req.body.notes : existing.notes;
    const recorded_at = req.body.recorded_at !== undefined ? req.body.recorded_at : existing.recorded_at;
    const vendor = req.body.vendor !== undefined ? req.body.vendor : existing.vendor;
    const is_recurring = req.body.is_recurring !== undefined ? (req.body.is_recurring ? 1 : 0) : existing.is_recurring;
    const interval = req.body.interval !== undefined ? req.body.interval : existing.interval;
    const amount_cents = req.body.amount_cents !== undefined ? Number(req.body.amount_cents) : Math.round(amount * 100);
    const now = localNow();
    stmt(`UPDATE company_expenses SET amount = ?, currency = ?, category = ?, description = ?, period = ?, notes = ?, recorded_at = ?, vendor = ?, is_recurring = ?, interval = ?, amount_cents = ?, updated_at = ? WHERE id = ? AND company_id = ?`)
      .run(amount, currency, category, description, period, notes, recorded_at, vendor, is_recurring, interval, amount_cents, now, req.params.expenseId, req.params.id);
    res.json({ message: 'Expense entry updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/companies/:id/expenses/:expenseId', (req, res) => {
  try {
    const result = stmt(`DELETE FROM company_expenses WHERE id = ? AND company_id = ?`).run(req.params.expenseId, req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Expense entry not found' });
    res.json({ message: 'Expense entry deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/companies/:id/campaigns', (req, res) => {
  try {
    const company = stmt(`SELECT id FROM companies WHERE id = ?`).get(req.params.id);
    if (!company) return res.status(404).json({ error: 'Company not found' });
    const rows = stmt(`SELECT * FROM company_campaigns WHERE company_id = ? ORDER BY created_at DESC`).all(req.params.id);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/companies/:id/campaigns', (req, res) => {
  try {
    const company = stmt(`SELECT id FROM companies WHERE id = ?`).get(req.params.id);
    if (!company) return res.status(404).json({ error: 'Company not found' });
    const { name, type, platform, budget_cents, spent_cents, start_date, end_date, status } = req.body;
    if (!name) return res.status(400).json({ error: 'name is required' });
    const validTypes = ['ad', 'social', 'email'];
    const resolvedType = type || 'ad';
    if (!validTypes.includes(resolvedType)) return res.status(400).json({ error: 'type must be one of: ad, social, email' });
    const validStatuses = ['active', 'paused', 'completed', 'cancelled'];
    const resolvedStatus = status || 'active';
    if (!validStatuses.includes(resolvedStatus)) return res.status(400).json({ error: 'status must be one of: active, paused, completed, cancelled' });
    const now = localNow();
    const result = stmt(`
      INSERT INTO company_campaigns (company_id, name, type, platform, budget_cents, spent_cents, start_date, end_date, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(req.params.id, name, resolvedType, platform || null, budget_cents != null ? Number(budget_cents) : 0, spent_cents != null ? Number(spent_cents) : 0, start_date || null, end_date || null, resolvedStatus, now, now);
    res.json({ id: Number(result.lastInsertRowid), message: 'Campaign created' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/companies/:id/campaigns/:campaignId', (req, res) => {
  try {
    const existing = stmt(`SELECT * FROM company_campaigns WHERE id = ? AND company_id = ?`).get(req.params.campaignId, req.params.id);
    if (!existing) return res.status(404).json({ error: 'Campaign not found' });
    const name = req.body.name !== undefined ? req.body.name : existing.name;
    const type = req.body.type !== undefined ? req.body.type : existing.type;
    const validTypes = ['ad', 'social', 'email'];
    if (!validTypes.includes(type)) return res.status(400).json({ error: 'type must be one of: ad, social, email' });
    const status = req.body.status !== undefined ? req.body.status : existing.status;
    const validStatuses = ['active', 'paused', 'completed', 'cancelled'];
    if (!validStatuses.includes(status)) return res.status(400).json({ error: 'status must be one of: active, paused, completed, cancelled' });
    const platform = req.body.platform !== undefined ? req.body.platform : existing.platform;
    const budget_cents = req.body.budget_cents !== undefined ? Number(req.body.budget_cents) : existing.budget_cents;
    const spent_cents = req.body.spent_cents !== undefined ? Number(req.body.spent_cents) : existing.spent_cents;
    const start_date = req.body.start_date !== undefined ? req.body.start_date : existing.start_date;
    const end_date = req.body.end_date !== undefined ? req.body.end_date : existing.end_date;
    const now = localNow();
    stmt(`UPDATE company_campaigns SET name = ?, type = ?, platform = ?, budget_cents = ?, spent_cents = ?, start_date = ?, end_date = ?, status = ?, updated_at = ? WHERE id = ? AND company_id = ?`)
      .run(name, type, platform, budget_cents, spent_cents, start_date, end_date, status, now, req.params.campaignId, req.params.id);
    res.json({ message: 'Campaign updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/companies/:id/campaigns/:campaignId', (req, res) => {
  try {
    const result = stmt(`DELETE FROM company_campaigns WHERE id = ? AND company_id = ?`).run(req.params.campaignId, req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Campaign not found' });
    res.json({ message: 'Campaign deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/companies/:id/social-posts', (req, res) => {
  try {
    const company = stmt(`SELECT id FROM companies WHERE id = ?`).get(req.params.id);
    if (!company) return res.status(404).json({ error: 'Company not found' });
    const rows = stmt(`
      SELECT sp.*, c.name as campaign_name
      FROM company_social_posts sp
      LEFT JOIN company_campaigns c ON sp.campaign_id = c.id
      WHERE sp.company_id = ?
      ORDER BY sp.posted_at DESC, sp.created_at DESC
    `).all(req.params.id);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/companies/:id/social-posts', (req, res) => {
  try {
    const company = stmt(`SELECT id FROM companies WHERE id = ?`).get(req.params.id);
    if (!company) return res.status(404).json({ error: 'Company not found' });
    const { campaign_id, platform, content, post_url, likes, shares, comments, impressions, posted_at } = req.body;
    if (!platform) return res.status(400).json({ error: 'platform is required' });
    const now = localNow();
    const result = stmt(`
      INSERT INTO company_social_posts (company_id, campaign_id, platform, content, post_url, likes, shares, comments, impressions, posted_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(req.params.id, campaign_id || null, platform, content || null, post_url || null, likes != null ? Number(likes) : 0, shares != null ? Number(shares) : 0, comments != null ? Number(comments) : 0, impressions != null ? Number(impressions) : 0, posted_at || now, now);
    res.json({ id: Number(result.lastInsertRowid), message: 'Social post created' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/companies/:id/social-posts/:postId', (req, res) => {
  try {
    const existing = stmt(`SELECT * FROM company_social_posts WHERE id = ? AND company_id = ?`).get(req.params.postId, req.params.id);
    if (!existing) return res.status(404).json({ error: 'Social post not found' });
    const campaign_id = req.body.campaign_id !== undefined ? req.body.campaign_id : existing.campaign_id;
    const platform = req.body.platform !== undefined ? req.body.platform : existing.platform;
    const content = req.body.content !== undefined ? req.body.content : existing.content;
    const post_url = req.body.post_url !== undefined ? req.body.post_url : existing.post_url;
    const likes = req.body.likes !== undefined ? Number(req.body.likes) : existing.likes;
    const shares = req.body.shares !== undefined ? Number(req.body.shares) : existing.shares;
    const comments = req.body.comments !== undefined ? Number(req.body.comments) : existing.comments;
    const impressions = req.body.impressions !== undefined ? Number(req.body.impressions) : existing.impressions;
    const posted_at = req.body.posted_at !== undefined ? req.body.posted_at : existing.posted_at;
    stmt(`UPDATE company_social_posts SET campaign_id = ?, platform = ?, content = ?, post_url = ?, likes = ?, shares = ?, comments = ?, impressions = ?, posted_at = ? WHERE id = ? AND company_id = ?`)
      .run(campaign_id, platform, content, post_url, likes, shares, comments, impressions, posted_at, req.params.postId, req.params.id);
    res.json({ message: 'Social post updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/companies/:id/social-posts/:postId', (req, res) => {
  try {
    const result = stmt(`DELETE FROM company_social_posts WHERE id = ? AND company_id = ?`).run(req.params.postId, req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Social post not found' });
    res.json({ message: 'Social post deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


};
