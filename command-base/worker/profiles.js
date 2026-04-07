// Reads team member profiles and tools from the database

function getMemberProfile(db, memberId) {
  const member = db.prepare(`SELECT * FROM team_members WHERE id = ?`).get(memberId);
  if (!member) return null;

  const tools = db.prepare(`
    SELECT * FROM member_tools WHERE member_id = ? AND enabled = 1
  `).all(memberId);

  return { ...member, tools };
}

function getAssignments(db, taskId) {
  return db.prepare(`
    SELECT ta.*, tm.name as member_name, tm.role as member_role, tm.execution_mode
    FROM task_assignments ta
    JOIN team_members tm ON ta.member_id = tm.id
    WHERE ta.task_id = ?
  `).all(taskId);
}

function buildMemberPrompt(member) {
  let prompt = `You are ${member.name}, ${member.role}.\n\n`;

  if (member.tools && member.tools.length > 0) {
    prompt += `## Your Tools\n`;
    for (const tool of member.tools) {
      let config = {};
      try { config = typeof tool.config === 'string' ? JSON.parse(tool.config) : tool.config; } catch {}
      prompt += `- **${tool.tool_name}** (${tool.tool_type})`;
      if (config.endpoint) prompt += ` — endpoint: ${config.endpoint}`;
      if (config.description) prompt += ` — ${config.description}`;
      prompt += `\n`;
    }
    prompt += `\n`;
  }

  return prompt;
}

function getSetting(db, key) {
  const row = db.prepare(`SELECT value FROM system_settings WHERE key = ?`).get(key);
  return row ? row.value : '';
}

function setSetting(db, key, value) {
  db.prepare(`UPDATE system_settings SET value = ?, updated_at = datetime('now', 'localtime') WHERE key = ?`).run(value, key);
}

module.exports = { getMemberProfile, getAssignments, buildMemberPrompt, getSetting, setSetting };
