'use strict';
/**
 * Task Force Engine — External, Durable Execution Teams
 *
 * KEY ARCHITECTURE DECISIONS:
 * 1. EXTERNAL: Uses its own DB (task_forces.db), not the_team.db
 * 2. DURABLE: Processes survive server.js crashes, state persists independently
 * 3. ANTI-BIAS: Enforced architecturally — builders can't review their own work
 * 4. INSTANT CANCEL: SIGTERM -> SIGKILL with resource cleanup
 * 5. FLEXIBLE LIMITS: Per-device resource profiles, not hard-coded thresholds
 * 6. BLIND REVIEW: Separate from internal Command Base perspective
 */

const { spawn, execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { getDb, close: closeDb } = require('./task-force-db');

const activeChildren = new Map();

function now() {
  return new Date().toISOString().replace('T', ' ').slice(0, 19);
}

function log(forceId, level, source, message, metadata) {
  try {
    const db = getDb();
    db.prepare(`INSERT INTO task_force_logs (force_id, level, source, message, metadata, created_at) VALUES (?,?,?,?,?,?)`)
      .run(forceId, level, source, message, metadata ? JSON.stringify(metadata) : null, now());
  } catch (_) {}
}

// ── Resource Monitoring ──

function getLocalResourceUsage() {
  const cpus = os.cpus();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  let totalIdle = 0, totalTick = 0;
  for (const cpu of cpus) {
    for (const type in cpu.times) totalTick += cpu.times[type];
    totalIdle += cpu.times.idle;
  }
  const cpuPercent = ((1 - totalIdle / totalTick) * 100);
  return {
    cpu_percent: Math.round(cpuPercent * 10) / 10,
    ram_used_mb: Math.round(usedMem / 1024 / 1024),
    ram_total_mb: Math.round(totalMem / 1024 / 1024),
    ram_percent: Math.round((usedMem / totalMem) * 1000) / 10,
    ram_free_mb: Math.round(freeMem / 1024 / 1024)
  };
}

function getSparkResourceUsage() {
  try {
    const result = execSync(
      `ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no spark "free -m | grep Mem && nproc && uptime"`,
      { timeout: 8000, encoding: 'utf-8' }
    );
    const lines = result.trim().split('\n');
    const memParts = lines[0].split(/\s+/);
    const totalMb = parseInt(memParts[1]) || 128000;
    const usedMb = parseInt(memParts[2]) || 0;
    const uptimeLine = lines[2] || '';
    const loadMatch = uptimeLine.match(/load average:\s*([\d.]+)/);
    const cores = parseInt(lines[1]) || 20;
    const load1m = loadMatch ? parseFloat(loadMatch[1]) : 0;
    const cpuPercent = Math.min(100, (load1m / cores) * 100);
    return {
      cpu_percent: Math.round(cpuPercent * 10) / 10,
      ram_used_mb: usedMb, ram_total_mb: totalMb,
      ram_percent: Math.round((usedMb / totalMb) * 1000) / 10,
      ram_free_mb: totalMb - usedMb, online: true
    };
  } catch (err) {
    return { cpu_percent: 0, ram_used_mb: 0, ram_total_mb: 0, ram_percent: 0, ram_free_mb: 0, online: false, error: err.message };
  }
}

function getResourceUsage(device) {
  if (device === 'spark') return getSparkResourceUsage();
  return { ...getLocalResourceUsage(), online: true };
}

function getProcessBreakdown(device) {
  if (device === 'spark') return _getSparkProcessBreakdown();
  return _getLocalProcessBreakdown();
}

function _getLocalProcessBreakdown() {
  try {
    const raw = execSync(`ps aux -m | head -80`, { timeout: 5000, encoding: 'utf-8' });
    const lines = raw.trim().split('\n').slice(1); // skip header
    const appMap = {};

    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 11) continue;
      const cpu = parseFloat(parts[2]) || 0;
      const ramMb = Math.round((parseInt(parts[5]) || 0) / 1024);
      const cmd = parts.slice(10).join(' ');

      // Derive a clean app name from the command
      let appName = _classifyProcess(cmd);
      if (!appName) continue;

      if (!appMap[appName]) appMap[appName] = { name: appName, ram_mb: 0, cpu_percent: 0, count: 0, pids: [] };
      appMap[appName].ram_mb += ramMb;
      appMap[appName].cpu_percent = Math.round((appMap[appName].cpu_percent + cpu) * 10) / 10;
      appMap[appName].count++;
      if (appMap[appName].pids.length < 3) appMap[appName].pids.push(parts[1]);
    }

    // Sort by RAM descending, take top 10
    const sorted = Object.values(appMap).sort((a, b) => b.ram_mb - a.ram_mb).slice(0, 10);
    // Tag any that look like local LLMs
    for (const app of sorted) {
      app.is_llm = /ollama|llama|nemotron|ggml|llm|whisper|stable.diffusion/i.test(app.name);
    }
    return sorted;
  } catch (err) {
    return [{ name: 'Error reading processes', ram_mb: 0, cpu_percent: 0, count: 0, error: err.message }];
  }
}

function _getSparkProcessBreakdown() {
  try {
    const raw = execSync(
      `ssh -o ConnectTimeout=3 spark "ps aux --sort=-rss | head -30"`,
      { timeout: 10000, encoding: 'utf-8' }
    );
    const lines = raw.trim().split('\n').slice(1);
    const appMap = {};

    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 11) continue;
      const cpu = parseFloat(parts[2]) || 0;
      const ramMb = Math.round((parseInt(parts[5]) || 0) / 1024);
      const cmd = parts.slice(10).join(' ');
      let appName = _classifyProcess(cmd);
      if (!appName) continue;

      if (!appMap[appName]) appMap[appName] = { name: appName, ram_mb: 0, cpu_percent: 0, count: 0, pids: [] };
      appMap[appName].ram_mb += ramMb;
      appMap[appName].cpu_percent = Math.round((appMap[appName].cpu_percent + cpu) * 10) / 10;
      appMap[appName].count++;
      if (appMap[appName].pids.length < 3) appMap[appName].pids.push(parts[1]);
    }

    const sorted = Object.values(appMap).sort((a, b) => b.ram_mb - a.ram_mb).slice(0, 10);
    for (const app of sorted) {
      app.is_llm = /ollama|llama|nemotron|ggml|llm|whisper|stable.diffusion/i.test(app.name);
    }
    return sorted;
  } catch (err) {
    return [{ name: 'Spark offline', ram_mb: 0, cpu_percent: 0, count: 0, error: err.message }];
  }
}

function _classifyProcess(cmd) {
  // Skip kernel/system noise
  if (/^\(/.test(cmd) || /^\/usr\/libexec\/|^\/usr\/sbin\//.test(cmd)) return null;
  if (/launchd|cfprefsd|distnoted|trustd|securityd/.test(cmd)) return null;

  // App classifications — group related processes under one name
  if (/Google Chrome Helper \(Renderer\)/.test(cmd)) return 'Chrome (tabs)';
  if (/Google Chrome Helper \(GPU\)/.test(cmd)) return 'Chrome (GPU)';
  if (/Google Chrome Helper/.test(cmd)) return 'Chrome (helper)';
  if (/Google Chrome\.app/.test(cmd)) return 'Chrome (main)';
  if (/Google Drive/.test(cmd)) return 'Google Drive';
  if (/Microsoft Teams/.test(cmd)) return 'Microsoft Teams';
  if (/Discord/.test(cmd)) return 'Discord';
  if (/Claude\.app/.test(cmd) || /Claude Helper/.test(cmd)) return 'Claude Desktop';
  if (/Comet\.app|Comet Helper|Comet Framework/.test(cmd)) return 'Comet (Perplexity)';
  if (/Messages\.app/.test(cmd)) return 'Messages';
  if (/Slack/.test(cmd)) return 'Slack';
  if (/Spotify/.test(cmd)) return 'Spotify';
  if (/Firefox/.test(cmd)) return 'Firefox';
  if (/Safari/.test(cmd)) return 'Safari';
  if (/Code\.app|Code Helper/.test(cmd)) return 'VS Code';
  if (/Cursor/.test(cmd)) return 'Cursor';
  if (/Figma/.test(cmd)) return 'Figma';
  if (/Notion/.test(cmd)) return 'Notion';
  if (/Docker/.test(cmd)) return 'Docker';
  if (/Xcode/.test(cmd)) return 'Xcode';
  if (/Terminal\.app/.test(cmd)) return 'Terminal';
  if (/iTerm/.test(cmd)) return 'iTerm';
  if (/Warp\.app/.test(cmd)) return 'Warp';
  if (/ollama/.test(cmd)) return 'Ollama (LLM)';
  if (/llama|ggml/.test(cmd)) return 'Local LLM';
  if (/nemotron/.test(cmd)) return 'Nemotron (LLM)';
  if (/stable.diffusion|comfyui/i.test(cmd)) return 'Stable Diffusion';
  if (/whisper/i.test(cmd)) return 'Whisper (STT)';
  if (/openclaw/.test(cmd)) return 'OpenClaw Gateway';
  if (/node server\.js/.test(cmd)) return 'Command Base';
  if (/node.*firebase/.test(cmd)) return 'Firebase MCP';
  if (/node.*claude/.test(cmd)) return 'Claude CLI';
  if (/^node\b/.test(cmd)) return 'Node.js';
  if (/^claude\b/.test(cmd)) return 'Claude CLI';
  if (/spotlightknowledged|corespotlightd|mdworker/.test(cmd)) return 'Spotlight (indexing)';
  if (/speechrecognition/i.test(cmd)) return 'Speech Recognition';
  if (/com\.apple\.WebKit/.test(cmd)) return 'WebKit (system)';
  if (/WindowServer/.test(cmd)) return 'WindowServer (display)';
  if (/kernel_task/.test(cmd)) return 'macOS Kernel';
  if (/AXVisualSupport/.test(cmd)) return 'Accessibility';

  // Generic fallback: extract app name from path
  const appMatch = cmd.match(/\/Applications\/([^/]+)\.app/);
  if (appMatch) return appMatch[1];
  const binMatch = cmd.match(/\/([^/\s]+)$/);
  if (binMatch && binMatch[1].length > 2) return binMatch[1];

  return null;
}

function getAllResourceUsage() {
  const db = getDb();
  const profiles = db.prepare(`SELECT * FROM resource_profiles`).all();
  const result = {};
  for (const profile of profiles) {
    const usage = getResourceUsage(profile.device_name);
    result[profile.device_name] = {
      ...usage, profile,
      within_limits: usage.online ? (usage.cpu_percent <= profile.max_cpu_percent && usage.ram_percent <= profile.max_ram_percent) : null,
      warning: usage.online ? (usage.cpu_percent >= profile.warn_cpu_percent || usage.ram_percent >= profile.warn_ram_percent) : null
    };
  }
  return result;
}

function checkCanSpawnOnDevice(device) {
  const db = getDb();
  const profile = db.prepare(`SELECT * FROM resource_profiles WHERE device_name = ?`).get(device);
  if (!profile) return { allowed: true, reason: 'no_profile' };
  // Mac NEVER runs models — zero concurrent models means no inference allowed
  if (profile.max_concurrent_models === 0 && device === 'mac') {
    // Still allow Claude CLI agents (they're API calls, not local inference)
    // This check is only hit for ollama/model tasks
  }
  const usage = getResourceUsage(device);
  if (!usage.online) return { allowed: false, reason: 'device_offline', usage };
  const running = db.prepare(`SELECT COUNT(*) as c FROM task_force_processes WHERE device = ? AND status = 'running'`).get(device).c;
  if (running >= profile.max_concurrent_agents) {
    return { allowed: false, reason: 'max_agents_reached', running, max: profile.max_concurrent_agents, usage };
  }
  if (profile.is_dedicated_inference) {
    if (usage.cpu_percent > 99 && usage.ram_percent > 99) return { allowed: false, reason: 'device_saturated', usage };
    return { allowed: true, reason: 'dedicated_inference_ok', usage };
  }
  if (usage.ram_percent > profile.max_ram_percent) return { allowed: false, reason: 'ram_limit_exceeded', usage, limit: profile.max_ram_percent };
  if (usage.cpu_percent > profile.max_cpu_percent) return { allowed: false, reason: 'cpu_limit_exceeded', usage, limit: profile.max_cpu_percent };
  return { allowed: true, reason: 'within_limits', usage };
}

function updateResourceProfile(deviceName, updates) {
  const db = getDb();
  const existing = db.prepare(`SELECT * FROM resource_profiles WHERE device_name = ?`).get(deviceName);
  if (!existing) throw new Error(`No resource profile for device: ${deviceName}`);
  const sets = [], vals = [];
  for (const [key, val] of Object.entries(updates)) {
    if (['max_cpu_percent', 'max_ram_percent', 'warn_cpu_percent', 'warn_ram_percent',
         'max_concurrent_models', 'max_concurrent_agents', 'is_dedicated_inference',
         'ollama_endpoint', 'ssh_host', 'ssh_user', 'notes'].includes(key)) {
      sets.push(`${key} = ?`); vals.push(val);
    }
  }
  if (sets.length === 0) return existing;
  sets.push('updated_at = ?'); vals.push(now()); vals.push(deviceName);
  db.prepare(`UPDATE resource_profiles SET ${sets.join(', ')} WHERE device_name = ?`).run(...vals);
  return db.prepare(`SELECT * FROM resource_profiles WHERE device_name = ?`).get(deviceName);
}

// ── Anti-Bias System ──

function recordBiasAction(forceId, memberId, action, targetDescription, filePaths) {
  const db = getDb();
  db.prepare(`INSERT INTO bias_ledger (force_id, member_id, action, target_description, file_paths, created_at) VALUES (?,?,?,?,?,?)`)
    .run(forceId, memberId, action, targetDescription, filePaths ? JSON.stringify(filePaths) : null, now());
}

function checkBias(forceId, memberId, proposedAction, targetDescription) {
  const db = getDb();
  if (proposedAction === 'reviewed' || proposedAction === 'tested') {
    const built = db.prepare(`SELECT * FROM bias_ledger WHERE force_id = ? AND member_id = ? AND action IN ('built','designed','digested') AND target_description = ?`)
      .all(forceId, memberId, targetDescription);
    if (built.length > 0) {
      return { biased: true, reason: `Member already ${built[0].action} this target`, conflicting_actions: built };
    }
  }
  if (proposedAction === 'built') {
    const digested = db.prepare(`SELECT * FROM bias_ledger WHERE force_id = ? AND member_id = ? AND action = 'digested' AND target_description = ?`)
      .all(forceId, memberId, targetDescription);
    if (digested.length > 0) {
      return { biased: true, reason: 'Member digested this content — cannot implement (interpretation bias)', conflicting_actions: digested };
    }
  }
  return { biased: false };
}

function getUnbiasedReviewer(forceId, targetDescription) {
  const db = getDb();
  const members = db.prepare(`SELECT * FROM task_force_members WHERE force_id = ? AND status != 'removed'`).all(forceId);
  const biasedIds = db.prepare(`SELECT DISTINCT member_id FROM bias_ledger WHERE force_id = ? AND action IN ('built','designed','digested') AND target_description = ?`)
    .all(forceId, targetDescription).map(r => r.member_id);
  const unbiased = members.filter(m => !biasedIds.includes(m.id));
  return unbiased.find(m => m.role === 'reviewer') || unbiased[0] || null;
}

// ── Task Force CRUD ──

function createTaskForce(name, mission, options = {}) {
  const db = getDb();
  const result = db.prepare(`INSERT INTO task_forces (name, mission, status, project_target, project_id, working_directory, composition_strategy, max_agents, created_at, notes) VALUES (?,?,?,?,?,?,?,?,?,?)`)
    .run(name, mission, 'draft', options.project_target || null, options.project_id || null, options.working_directory || null, options.composition_strategy || 'auto', options.max_agents || 5, now(), options.notes || null);
  const forceId = Number(result.lastInsertRowid);
  log(forceId, 'info', 'engine', `Task force "${name}" created`, { mission, options });
  return getTaskForce(forceId);
}

function getTaskForce(forceId) {
  const db = getDb();
  const force = db.prepare(`SELECT * FROM task_forces WHERE id = ?`).get(forceId);
  if (!force) return null;
  force.members = db.prepare(`SELECT * FROM task_force_members WHERE force_id = ? ORDER BY role, assigned_at`).all(forceId);
  force.processes = db.prepare(`SELECT * FROM task_force_processes WHERE force_id = ? ORDER BY started_at DESC`).all(forceId);
  force.recent_logs = db.prepare(`SELECT * FROM task_force_logs WHERE force_id = ? ORDER BY created_at DESC LIMIT 20`).all(forceId);
  return force;
}

function listTaskForces(statusFilter) {
  const db = getDb();
  let forces;
  if (statusFilter) {
    forces = db.prepare(`SELECT * FROM task_forces WHERE status = ? ORDER BY created_at DESC`).all(statusFilter);
  } else {
    forces = db.prepare(`SELECT * FROM task_forces ORDER BY created_at DESC`).all();
  }
  for (const f of forces) {
    f.member_count = db.prepare(`SELECT COUNT(*) as c FROM task_force_members WHERE force_id = ?`).get(f.id).c;
    f.active_processes = db.prepare(`SELECT COUNT(*) as c FROM task_force_processes WHERE force_id = ? AND status = 'running'`).get(f.id).c;
  }
  return forces;
}

function addMember(forceId, role, memberName, specialization) {
  const db = getDb();
  const result = db.prepare(`INSERT INTO task_force_members (force_id, role, member_name, specialization, assigned_at) VALUES (?,?,?,?,?)`)
    .run(forceId, role, memberName, specialization || null, now());
  log(forceId, 'info', 'engine', `Member "${memberName}" added as ${role}`, { specialization });
  return { id: Number(result.lastInsertRowid), force_id: forceId, role, member_name: memberName };
}

function removeMember(memberId) {
  const db = getDb();
  const member = db.prepare(`SELECT * FROM task_force_members WHERE id = ?`).get(memberId);
  if (!member) throw new Error('Member not found');
  const running = db.prepare(`SELECT * FROM task_force_processes WHERE member_id = ? AND status = 'running'`).all(memberId);
  for (const proc of running) { killProcess(proc.id); }
  db.prepare(`UPDATE task_force_members SET status = 'removed' WHERE id = ?`).run(memberId);
  log(member.force_id, 'info', 'engine', `Member "${member.member_name}" removed`);
}

// ── Agent Spawning ──

function spawnAgent(forceId, memberId, options = {}) {
  const db = getDb();
  const force = db.prepare(`SELECT * FROM task_forces WHERE id = ?`).get(forceId);
  if (!force) throw new Error('Task force not found');
  if (force.status !== 'active' && force.status !== 'deploying') throw new Error(`Task force status is "${force.status}" — must be active or deploying`);
  const member = db.prepare(`SELECT * FROM task_force_members WHERE id = ?`).get(memberId);
  if (!member) throw new Error('Member not found');
  const adapter = options.adapter || 'claude_cli';
  // RULE: Ollama/model inference ALWAYS on Spark, NEVER on Mac. Mac is orchestration only.
  const device = adapter === 'ollama' ? 'spark' : (options.device || 'mac');
  const model = options.model || 'sonnet';
  const prompt = options.prompt || force.mission;
  // Claude CLI = API calls to Anthropic, lightweight. Only block local model inference.
  if (adapter !== 'claude_cli') {
    const resourceCheck = checkCanSpawnOnDevice(device);
    if (!resourceCheck.allowed) {
      log(forceId, 'warn', 'engine', `Cannot spawn on ${device}: ${resourceCheck.reason}`, resourceCheck);
      return { success: false, reason: resourceCheck.reason, details: resourceCheck };
    }
  }
  const result = db.prepare(`INSERT INTO task_force_processes (force_id, member_id, device, model, adapter, status, started_at) VALUES (?,?,?,?,?,?,?)`)
    .run(forceId, memberId, device, model, adapter, 'starting', now());
  const processId = Number(result.lastInsertRowid);
  log(forceId, 'info', 'engine', `Spawning ${member.member_name} on ${device} (${model})`, { processId });
  if (adapter === 'claude_cli') _spawnClaudeCli(forceId, processId, member, force, prompt, model, device);
  else if (adapter === 'ollama') _spawnOllama(forceId, processId, member, force, prompt, model, device);
  return { success: true, process_id: processId, device, model, member_name: member.member_name };
}

function _spawnClaudeCli(forceId, processId, member, force, prompt, model, device) {
  const db = getDb();
  const modelFlag = model === 'opus' ? 'claude-opus-4-6' : model === 'haiku' ? 'claude-haiku-4-5-20251001' : 'claude-sonnet-4-6';
  const fullPrompt = [
    `You are ${member.member_name}, a member of Task Force "${force.name}".`,
    `Your role: ${member.role}${member.specialization ? ` (${member.specialization})` : ''}.`,
    '', '## CRITICAL: External Perspective',
    'You are an EXTERNAL task force, not an internal team member.',
    'You evaluate objectively. You do NOT have attachment to existing code.',
    'If something is poorly designed, say so. If it works well, say so.',
    'You have NO bias toward any prior work — judge everything on merit.',
    '', `## Mission`, force.mission, '', `## Task`, prompt,
    '', '## Working Rules', '- Be thorough but efficient', '- Report findings clearly',
    '- If you built or designed something, you CANNOT review or QA it',
    '- Checkpoint your progress to .claude/checkpoints/ for durability',
    force.working_directory ? `- Working directory: ${force.working_directory}` : ''
  ].filter(Boolean).join('\n');
  const cliArgs = ['--print', '--model', modelFlag, '--max-turns', '15', '--dangerously-skip-permissions'];
  const cwd = force.working_directory || process.cwd();
  const child = spawn('claude', cliArgs, { stdio: ['pipe', 'pipe', 'pipe'], detached: false, cwd, env: { ...process.env, FORCE_COLOR: '0' } });
  child.stdin.write(fullPrompt);
  child.stdin.end();
  const pid = child.pid;
  db.prepare(`UPDATE task_force_processes SET pid = ?, status = 'running' WHERE id = ?`).run(pid, processId);
  db.prepare(`UPDATE task_force_members SET status = 'working' WHERE id = ?`).run(member.id);
  activeChildren.set(processId, { child, device, model, forceId, pid });
  let output = '';
  child.stdout.on('data', (data) => { output += data.toString(); });
  child.stderr.on('data', (data) => {
    const err = data.toString();
    if (err.includes('error') || err.includes('Error')) log(forceId, 'warn', member.member_name, `stderr: ${err.slice(0, 500)}`);
  });
  child.on('close', (code) => {
    const n = now();
    activeChildren.delete(processId);
    const status = code === 0 ? 'completed' : 'failed';
    const summary = output.slice(-10000);
    db.prepare(`UPDATE task_force_processes SET status = ?, completed_at = ?, output_summary = ?, error = ? WHERE id = ?`)
      .run(status, n, summary.slice(0, 10000), code !== 0 ? `Exit code: ${code}` : null, processId);
    db.prepare(`UPDATE task_force_members SET status = 'done' WHERE id = ?`).run(member.id);
    log(forceId, code === 0 ? 'info' : 'error', member.member_name, `Process completed with code ${code}`, { output_length: output.length });
    _checkForceCompletion(forceId);
  });
  log(forceId, 'info', 'engine', `Claude CLI spawned for ${member.member_name} (PID ${pid})`, { processId, model: modelFlag });
}

function _spawnOllama(forceId, processId, member, force, prompt, model, device) {
  const db = getDb();
  // ALWAYS use Spark for Ollama inference — never local Mac
  const sparkProfile = db.prepare(`SELECT * FROM resource_profiles WHERE device_name = 'spark'`).get();
  const endpoint = sparkProfile?.ollama_endpoint || 'http://localhost:11435';
  const fullPrompt = [
    `You are ${member.member_name}, a member of Task Force "${force.name}".`,
    `Role: ${member.role}. Mission: ${force.mission}`, '',
    'You are an EXTERNAL evaluator. Judge everything on merit, no bias.', '', prompt
  ].join('\n');
  const http = require('http');
  const url = new URL(endpoint + '/v1/chat/completions');
  const payload = JSON.stringify({ model: model || 'nemotron:latest', messages: [{ role: 'user', content: fullPrompt }], stream: false, options: { num_predict: 8192 } });
  db.prepare(`UPDATE task_force_processes SET status = 'running' WHERE id = ?`).run(processId);
  db.prepare(`UPDATE task_force_members SET status = 'working' WHERE id = ?`).run(member.id);
  const req = http.request({
    hostname: url.hostname, port: url.port || 80, path: url.pathname, method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }, timeout: 600000
  }, (res) => {
    let body = '';
    res.on('data', chunk => { body += chunk; });
    res.on('end', () => {
      const n = now();
      try {
        const parsed = JSON.parse(body);
        const output = parsed.choices?.[0]?.message?.content || '';
        db.prepare(`UPDATE task_force_processes SET status = 'completed', completed_at = ?, output_summary = ? WHERE id = ?`).run(n, output.slice(0, 10000), processId);
        log(forceId, 'info', member.member_name, `Ollama completed (${output.length} chars)`, { model });
      } catch (err) {
        db.prepare(`UPDATE task_force_processes SET status = 'failed', completed_at = ?, error = ? WHERE id = ?`).run(n, `Parse error: ${err.message}`, processId);
        log(forceId, 'error', member.member_name, `Ollama parse error: ${err.message}`);
      }
      db.prepare(`UPDATE task_force_members SET status = 'done' WHERE id = ?`).run(member.id);
      _checkForceCompletion(forceId);
    });
  });
  req.on('error', (err) => {
    const n = now();
    db.prepare(`UPDATE task_force_processes SET status = 'failed', completed_at = ?, error = ? WHERE id = ?`).run(n, err.message, processId);
    db.prepare(`UPDATE task_force_members SET status = 'done' WHERE id = ?`).run(member.id);
    log(forceId, 'error', member.member_name, `Ollama connection error: ${err.message}`);
    _checkForceCompletion(forceId);
  });
  req.on('timeout', () => {
    req.destroy();
    const n = now();
    db.prepare(`UPDATE task_force_processes SET status = 'failed', completed_at = ?, error = ? WHERE id = ?`).run(n, 'Timeout (10 minutes)', processId);
    db.prepare(`UPDATE task_force_members SET status = 'done' WHERE id = ?`).run(member.id);
    log(forceId, 'error', member.member_name, 'Ollama request timed out');
    _checkForceCompletion(forceId);
  });
  activeChildren.set(processId, { request: req, device, model, forceId, type: 'ollama' });
  req.write(payload); req.end();
  log(forceId, 'info', 'engine', `Ollama request sent for ${member.member_name} (${model} on ${device})`);
}

function _checkForceCompletion(forceId) {
  const db = getDb();
  const running = db.prepare(`SELECT COUNT(*) as c FROM task_force_processes WHERE force_id = ? AND status IN ('starting','running')`).get(forceId).c;
  if (running === 0) {
    const force = db.prepare(`SELECT * FROM task_forces WHERE id = ?`).get(forceId);
    if (force && force.status === 'active') {
      const failed = db.prepare(`SELECT COUNT(*) as c FROM task_force_processes WHERE force_id = ? AND status = 'failed'`).get(forceId).c;
      const newStatus = failed > 0 ? 'failed' : 'completed';
      if (newStatus === 'completed') {
        db.prepare(`UPDATE task_forces SET status = 'completed', completed_at = ? WHERE id = ?`).run(now(), forceId);
      } else {
        db.prepare(`UPDATE task_forces SET status = 'failed' WHERE id = ?`).run(forceId);
      }
      log(forceId, 'info', 'engine', `Task force ${newStatus} (${failed} failures)`);
    }
  }
}

// ── Instant Kill ──

function killProcess(processId) {
  const db = getDb();
  const proc = db.prepare(`SELECT * FROM task_force_processes WHERE id = ?`).get(processId);
  if (!proc) throw new Error('Process not found');
  const tracked = activeChildren.get(processId);
  if (tracked) {
    if (tracked.child) {
      try { tracked.child.kill('SIGTERM'); } catch (_) {}
      setTimeout(() => { try { tracked.child.kill('SIGKILL'); } catch (_) {} }, 3000);
    }
    if (tracked.request) { try { tracked.request.destroy(); } catch (_) {} }
    activeChildren.delete(processId);
  } else if (proc.pid) {
    try { process.kill(proc.pid, 'SIGTERM'); } catch (_) {}
    setTimeout(() => { try { process.kill(proc.pid, 'SIGKILL'); } catch (_) {} }, 3000);
  }
  db.prepare(`UPDATE task_force_processes SET status = 'killed', completed_at = ? WHERE id = ?`).run(now(), processId);
  if (proc.member_id) db.prepare(`UPDATE task_force_members SET status = 'idle' WHERE id = ?`).run(proc.member_id);
  log(proc.force_id, 'warn', 'engine', `Process #${processId} killed (PID: ${proc.pid})`);
  return { killed: true, pid: proc.pid };
}

function killForce(forceId) {
  const db = getDb();
  const force = db.prepare(`SELECT * FROM task_forces WHERE id = ?`).get(forceId);
  if (!force) throw new Error('Task force not found');
  const running = db.prepare(`SELECT * FROM task_force_processes WHERE force_id = ? AND status IN ('starting','running')`).all(forceId);
  const killed = [];
  for (const proc of running) { try { killProcess(proc.id); killed.push(proc.id); } catch (_) {} }
  db.prepare(`UPDATE task_forces SET status = 'cancelled', cancelled_at = ? WHERE id = ?`).run(now(), forceId);
  log(forceId, 'warn', 'engine', `Task force cancelled — ${killed.length} processes killed`);
  return { cancelled: true, processes_killed: killed.length };
}

function deployForce(forceId, agentConfigs) {
  const db = getDb();
  const force = db.prepare(`SELECT * FROM task_forces WHERE id = ?`).get(forceId);
  if (!force) throw new Error('Task force not found');
  if (force.status !== 'draft') throw new Error(`Cannot deploy — status is "${force.status}"`);
  const members = db.prepare(`SELECT * FROM task_force_members WHERE force_id = ? AND status != 'removed'`).all(forceId);
  if (members.length === 0) throw new Error('No members assigned');
  db.prepare(`UPDATE task_forces SET status = 'deploying', deployed_at = ? WHERE id = ?`).run(now(), forceId);
  log(forceId, 'info', 'engine', `Deploying task force with ${members.length} members`);
  const results = [];
  for (let i = 0; i < members.length; i++) {
    const member = members[i];
    const config = (agentConfigs && agentConfigs[i]) || {};
    try {
      const cfgAdapter = config.adapter || 'claude_cli';
      // Ollama ALWAYS on Spark. Claude CLI on Mac (API calls, not local inference).
      const cfgDevice = cfgAdapter === 'ollama' ? 'spark' : (config.device || 'mac');
      const result = spawnAgent(forceId, member.id, { device: cfgDevice, model: config.model || 'sonnet', adapter: cfgAdapter, prompt: config.prompt || force.mission });
      results.push(result);
    } catch (err) {
      log(forceId, 'error', 'engine', `Failed to spawn ${member.member_name}: ${err.message}`);
      results.push({ success: false, error: err.message, member_name: member.member_name });
    }
  }
  db.prepare(`UPDATE task_forces SET status = 'active' WHERE id = ?`).run(forceId);
  startGuardian(); // Auto-start guardian when any force deploys
  return { force_id: forceId, deployed: results.filter(r => r.success).length, failed: results.filter(r => !r.success).length, results };
}

function pauseForce(forceId) {
  const db = getDb();
  const running = db.prepare(`SELECT * FROM task_force_processes WHERE force_id = ? AND status IN ('starting','running')`).all(forceId);
  for (const proc of running) {
    try {
      killProcess(proc.id);
      // Mark the reason after killProcess sets status='killed'
      db.prepare(`UPDATE task_force_processes SET error = 'paused_by_user' WHERE id = ?`).run(proc.id);
    } catch (_) {}
  }
  db.prepare(`UPDATE task_forces SET status = 'paused' WHERE id = ?`).run(forceId);
  log(forceId, 'info', 'engine', `Task force paused — ${running.length} processes stopped`);
  return { paused: true, processes_stopped: running.length };
}

function reconnectOrphans() {
  const db = getDb();
  const orphans = db.prepare(`SELECT * FROM task_force_processes WHERE status = 'running'`).all();
  let alive = 0, dead = 0;
  for (const proc of orphans) {
    if (!proc.pid) { dead++; continue; }
    try {
      process.kill(proc.pid, 0);
      alive++;
      log(proc.force_id, 'info', 'engine', `Reconnected to orphan process #${proc.id} (PID ${proc.pid})`);
    } catch (_) {
      db.prepare(`UPDATE task_force_processes SET status = 'failed', completed_at = ?, error = 'orphaned_after_restart' WHERE id = ?`).run(now(), proc.id);
      dead++;
      log(proc.force_id, 'warn', 'engine', `Orphan process #${proc.id} (PID ${proc.pid}) is dead`);
    }
  }
  return { alive, dead };
}

// ── Auto-Guardian: self-healing loop ──
// Checks for failed/stalled agents and respawns them automatically.
// Runs every 30 seconds when a force is active.

let guardianInterval = null;

function startGuardian() {
  if (guardianInterval) return;
  guardianInterval = setInterval(() => {
    try {
      const db = getDb();
      // Guard active AND failed forces (failed may have members that need respawn)
      const activeForces = db.prepare(`SELECT * FROM task_forces WHERE status IN ('active','failed')`).all();
      if (activeForces.length === 0) { stopGuardian(); return; }
      // Re-activate failed forces only if at least one member still has retries left
      for (const f of activeForces) {
        if (f.status === 'failed') {
          const fMembers = db.prepare(`SELECT * FROM task_force_members WHERE force_id = ? AND status != 'removed'`).all(f.id);
          const fProcs = db.prepare(`SELECT * FROM task_force_processes WHERE force_id = ?`).all(f.id);
          const canRetry = fMembers.some(m => {
            const memberProcs = fProcs.filter(p => p.member_id === m.id);
            const hasCompleted = memberProcs.some(p => p.status === 'completed');
            const failCount = memberProcs.filter(p => p.status === 'failed' || p.status === 'killed').length;
            return !hasCompleted && failCount < 3;
          });
          if (canRetry) {
            db.prepare(`UPDATE task_forces SET status = 'active' WHERE id = ?`).run(f.id);
            log(f.id, 'info', 'guardian', 'Re-activated failed force for retry');
          } else {
            log(f.id, 'warn', 'guardian', 'Force stays failed — all members exhausted retry limit (3 failures each)');
          }
        }
      }

      for (const force of activeForces) {
        const members = db.prepare(`SELECT * FROM task_force_members WHERE force_id = ? AND status != 'removed'`).all(force.id);
        const processes = db.prepare(`SELECT * FROM task_force_processes WHERE force_id = ?`).all(force.id);

        for (const member of members) {
          const memberProcs = processes.filter(p => p.member_id === member.id);
          const runningProcs = memberProcs.filter(p => p.status === 'running' || p.status === 'starting');
          const hasCompleted = memberProcs.some(p => p.status === 'completed');
          const failCount = memberProcs.filter(p => p.status === 'failed' || p.status === 'killed').length;

          // Detect zombie processes — marked running but PID is dead
          for (const rp of runningProcs) {
            if (rp.pid) {
              try { process.kill(rp.pid, 0); } catch (_) {
                // PID is dead but DB says running — mark as failed
                db.prepare(`UPDATE task_force_processes SET status = 'failed', completed_at = ?, error = 'guardian: process died silently' WHERE id = ?`).run(now(), rp.id);
                db.prepare(`UPDATE task_force_members SET status = 'idle' WHERE id = ?`).run(member.id);
                log(force.id, 'warn', 'guardian', `Detected zombie: ${member.member_name} PID ${rp.pid} is dead, marking failed`);
              }
            }
            // Ollama processes have no PID — check if they've been "running" too long (>10 min)
            if (!rp.pid && rp.adapter === 'ollama' && rp.started_at) {
              const startedMs = new Date(rp.started_at.replace(' ', 'T') + 'Z').getTime();
              if (Date.now() - startedMs > 600000) {
                db.prepare(`UPDATE task_force_processes SET status = 'failed', completed_at = ?, error = 'guardian: ollama timeout >10min' WHERE id = ?`).run(now(), rp.id);
                db.prepare(`UPDATE task_force_members SET status = 'idle' WHERE id = ?`).run(member.id);
                log(force.id, 'warn', 'guardian', `Detected stale Ollama: ${member.member_name} running >10min, marking failed`);
              }
            }
          }

          // Re-check after zombie cleanup
          const stillRunning = memberProcs.some(p => {
            const freshProc = db.prepare(`SELECT status FROM task_force_processes WHERE id = ?`).get(p.id);
            return freshProc && (freshProc.status === 'running' || freshProc.status === 'starting');
          });
          const freshFailCount = db.prepare(`SELECT COUNT(*) as c FROM task_force_processes WHERE member_id = ? AND status IN ('failed','killed')`).get(member.id).c;

          if (!stillRunning && !hasCompleted && freshFailCount > 0 && freshFailCount < 5) {
            const lastProc = memberProcs.sort((a,b) => b.id - a.id)[0];
            const lastAdapter = lastProc?.adapter || 'claude_cli';
            const lastModel = lastProc?.model || 'sonnet';
            const lastDevice = lastProc?.device || 'mac';

            log(force.id, 'warn', 'guardian', `Auto-respawning ${member.member_name} (failed ${freshFailCount}x, attempt ${freshFailCount+1})`);
            db.prepare(`UPDATE task_force_members SET status = 'idle' WHERE id = ?`).run(member.id);

            try {
              spawnAgent(force.id, member.id, {
                adapter: lastAdapter,
                device: lastAdapter === 'ollama' ? 'spark' : lastDevice,
                model: lastModel,
                prompt: force.mission
              });
            } catch (err) {
              log(force.id, 'error', 'guardian', `Failed to respawn ${member.member_name}: ${err.message}`);
            }
          }
        }

        // Check if force is done
        const stillRunning = db.prepare(`SELECT COUNT(*) as c FROM task_force_processes WHERE force_id = ? AND status IN ('starting','running')`).get(force.id).c;
        const allMembers = members.length;
        const completedMembers = members.filter(m => {
          return processes.some(p => p.member_id === m.id && p.status === 'completed');
        }).length;

        if (stillRunning === 0 && completedMembers === allMembers) {
          db.prepare(`UPDATE task_forces SET status = 'completed', completed_at = ? WHERE id = ?`).run(now(), force.id);
          log(force.id, 'info', 'guardian', 'All members completed. Force marked complete.');
        }
      }
    } catch (err) {
      console.error('[Guardian] Error:', err.message);
    }
  }, 30000); // Every 30 seconds
  console.log('[Guardian] Started — monitoring active task forces every 30s');
}

function stopGuardian() {
  if (guardianInterval) { clearInterval(guardianInterval); guardianInterval = null; }
}

function emergencyKillDevice(deviceName) {
  const db = getDb();
  const running = db.prepare(`SELECT * FROM task_force_processes WHERE device = ? AND status IN ('starting','running')`).all(deviceName);
  let killed = 0;
  for (const proc of running) { try { killProcess(proc.id); killed++; } catch (_) {} }
  if (deviceName === 'mac') { try { execSync('pkill -f "ollama serve" 2>/dev/null || true', { timeout: 5000 }); } catch (_) {} }
  // Log per-force so we don't violate the FK constraint (force_id=0 doesn't exist)
  const affectedForceIds = [...new Set(running.map(p => p.force_id))];
  for (const fid of affectedForceIds) {
    log(fid, 'critical', 'engine', `Emergency kill on ${deviceName}: ${killed} processes terminated`);
  }
  if (affectedForceIds.length === 0) {
    // No running processes — still useful to note in console
    console.warn(`[engine] Emergency kill on ${deviceName}: no active processes`);
  }
  return { device: deviceName, killed };
}

module.exports = {
  createTaskForce, getTaskForce, listTaskForces, addMember, removeMember,
  deployForce, spawnAgent, pauseForce,
  killProcess, killForce, emergencyKillDevice,
  getResourceUsage, getAllResourceUsage, getProcessBreakdown, checkCanSpawnOnDevice, updateResourceProfile,
  recordBiasAction, checkBias, getUnbiasedReviewer,
  reconnectOrphans, startGuardian, stopGuardian, closeDb
};
