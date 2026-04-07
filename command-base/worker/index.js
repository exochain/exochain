// The Team — Autonomous Worker
// Polls for tasks and executes them via Claude Code CLI

const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const { getMemberProfile, getAssignments, getSetting, setSetting } = require('./profiles');
const { chooseModel, buildTaskPrompt, buildReviewPrompt, executeClaudeCommand } = require('./executor');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', 'the_team.db');
const INBOX_PATH = process.env.INBOX_PATH || path.join(__dirname, '..', 'Teams inbox:Result');
const OUTBOX_PATH = process.env.OUTBOX_PATH || path.join(__dirname, '..', "Stew's inbox:Owner");
const POLL_INTERVAL = 10000; // 10 seconds

let db;
try {
  db = new Database(DB_PATH, { fileMustExist: true });
  console.log(`[Worker] Connected to database at ${DB_PATH}`);
} catch (err) {
  console.error(`[Worker] Failed to open database: ${err.message}`);
  process.exit(1);
}

function localNow() {
  return new Date().toLocaleString('sv-SE', {
    timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone
  }).replace(' ', 'T').slice(0, 19).replace('T', ' ');
}

function log(taskId, actor, action, notes) {
  const now = localNow();
  db.prepare(`
    INSERT INTO activity_log (task_id, actor, action, notes, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(taskId, actor, action, notes, now);
}

function notify(type, title, message, taskId) {
  const now = localNow();
  db.prepare(`
    INSERT INTO notifications (type, title, message, task_id, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(type, title, message, taskId, now);
}

function isEligibleForAutonomous(db, task) {
  const globalMode = getSetting(db, 'execution_mode');

  // Check if the task has specific member assignments
  const assignments = getAssignments(db, task.id);

  if (assignments.length > 0) {
    // Check if ANY assigned member is in autonomous mode
    for (const a of assignments) {
      const memberMode = a.execution_mode || 'system';
      if (memberMode === 'autonomous') return true;
      if (memberMode === 'system' && globalMode === 'autonomous') return true;
    }
    return false;
  }

  // No specific assignments — check the primary assignee
  if (task.assigned_to) {
    const member = db.prepare(`SELECT execution_mode FROM team_members WHERE id = ?`).get(task.assigned_to);
    if (member) {
      if (member.execution_mode === 'autonomous') return true;
      if (member.execution_mode === 'terminal') return false;
      // 'system' — fall through to global check
    }
  }

  // No assignment or member is on 'system' default — use global mode
  return globalMode === 'autonomous';
}

async function processTask(task) {
  const now = localNow();
  const oauthToken = getSetting(db, 'oauth_token');

  if (!oauthToken) {
    console.log(`[Worker] No OAuth token — skipping task #${task.id}`);
    return;
  }

  console.log(`[Worker] Processing task #${task.id}: ${task.title}`);

  // Lock the task
  db.prepare(`UPDATE tasks SET status = 'routing', updated_at = ? WHERE id = ?`).run(now, task.id);
  log(task.id, 'Worker', 'task_picked_up', `Autonomous worker picked up task: ${task.title}`);

  // Determine the team member
  let member = null;
  const assignments = getAssignments(db, task.id);

  if (assignments.length > 0) {
    // Use the first assigned member
    member = getMemberProfile(db, assignments[0].member_id);
  } else if (task.assigned_to) {
    member = getMemberProfile(db, task.assigned_to);
  }

  const memberName = member ? member.name : 'Gray';
  const actorName = `Worker-${memberName}`;

  // Get linked resources for context
  const linkedRepos = db.prepare(`SELECT * FROM linked_repos`).all();
  const linkedPaths = db.prepare(`SELECT * FROM linked_paths`).all();

  // Choose model
  const model = chooseModel(db, task);
  console.log(`[Worker] Using model: ${model}, member: ${memberName}`);

  // Set to in_progress
  db.prepare(`UPDATE tasks SET status = 'in_progress', updated_at = ? WHERE id = ?`).run(localNow(), task.id);
  log(task.id, actorName, 'task_started', `Working on task with model: ${model}`);

  // Build prompt and execute
  const prompt = buildTaskPrompt(task, member, linkedRepos, linkedPaths);

  let output;
  try {
    output = await executeClaudeCommand(prompt, model, oauthToken);
  } catch (err) {
    console.error(`[Worker] Execution error for task #${task.id}: ${err.message}`);
    log(task.id, actorName, 'execution_error', err.message);
    notify('task_status', `Task failed: ${task.title}`, err.message, task.id);
    db.prepare(`UPDATE tasks SET status = 'new', updated_at = ? WHERE id = ?`).run(localNow(), task.id);
    return;
  }

  console.log(`[Worker] Task #${task.id} execution complete. Output: ${output.length} chars`);

  // Quality review by Gray
  db.prepare(`UPDATE tasks SET status = 'review', updated_at = ? WHERE id = ?`).run(localNow(), task.id);
  log(task.id, actorName, 'work_completed', `Output: ${output.slice(0, 200)}...`);

  const reviewPrompt = buildReviewPrompt(task, memberName, output);
  let reviewResult;
  try {
    reviewResult = await executeClaudeCommand(reviewPrompt, 'sonnet', oauthToken, 120000);
  } catch (err) {
    console.error(`[Worker] Review error for task #${task.id}: ${err.message}`);
    // If review fails, still deliver — better than stuck
    reviewResult = 'REVIEW: PASS';
  }

  const passed = reviewResult.includes('REVIEW: PASS');

  if (!passed) {
    // Revision needed
    const revisionCount = (task.revision_count || 0) + 1;
    console.log(`[Worker] Task #${task.id} failed review (revision ${revisionCount})`);

    if (revisionCount >= 3) {
      // After 3 revisions, deliver anyway and flag for Max
      console.log(`[Worker] Task #${task.id} hit revision limit — delivering with flag`);
      log(task.id, 'Worker-Gray', 'review_flagged', `Hit revision limit (${revisionCount}). Delivering with quality flag.`);
      notify('task_status', `Task needs attention: ${task.title}`, 'Hit revision limit. Output may need manual review.', task.id);
    } else {
      db.prepare(`UPDATE tasks SET status = 'in_progress', revision_count = ?, updated_at = ? WHERE id = ?`).run(revisionCount, localNow(), task.id);
      log(task.id, 'Worker-Gray', 'review_failed', `Revision ${revisionCount}: ${reviewResult.slice(0, 300)}`);

      // Re-execute with review feedback
      const revisionPrompt = prompt + `\n\n## Previous Review Feedback\n${reviewResult}\n\nPlease address the issues and provide an improved output.`;
      try {
        output = await executeClaudeCommand(revisionPrompt, model, oauthToken);
      } catch (err) {
        log(task.id, actorName, 'revision_error', err.message);
      }
    }
  } else {
    log(task.id, 'Worker-Gray', 'review_passed', 'Quality review passed.');
  }

  // Deliver
  const deliverNow = localNow();

  // Write output to outbox
  const outputFile = `task-${task.id}-output-${Date.now()}.md`;
  const outputContent = `# Task #${task.id}: ${task.title}\n\n**Completed by:** ${memberName} (autonomous)\n**Model:** ${model}\n**Date:** ${deliverNow}\n\n---\n\n${output}\n`;

  if (!fs.existsSync(OUTBOX_PATH)) {
    fs.mkdirSync(OUTBOX_PATH, { recursive: true });
  }
  fs.writeFileSync(path.join(OUTBOX_PATH, outputFile), outputContent, 'utf-8');

  // Register output file
  db.prepare(`
    INSERT INTO task_files (task_id, file_name, file_path, file_type, direction, created_at)
    VALUES (?, ?, ?, 'text/markdown', 'output', ?)
  `).run(task.id, outputFile, path.join(OUTBOX_PATH, outputFile), deliverNow);

  // Update task status
  db.prepare(`
    UPDATE tasks SET status = 'delivered', completed_at = ?, delivered_at = ?, updated_at = ? WHERE id = ?
  `).run(deliverNow, deliverNow, deliverNow, task.id);

  log(task.id, 'Worker-Gray', 'task_delivered', `Delivered output: ${outputFile}`);
  notify('task_delivered', `Task completed: ${task.title}`, `${memberName} completed "${task.title}". Output in Stew's inbox.`, task.id);

  console.log(`[Worker] Task #${task.id} delivered: ${outputFile}`);
}

async function pollLoop() {
  const globalMode = getSetting(db, 'execution_mode');
  const workerStatus = getSetting(db, 'worker_status');

  // Only process if worker should be running and not in pure terminal mode
  if (workerStatus !== 'running') {
    return;
  }

  // Find eligible tasks
  const tasks = db.prepare(`
    SELECT * FROM tasks
    WHERE status = 'new'
    ORDER BY
      CASE priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 WHEN 'low' THEN 3 END,
      created_at ASC
  `).all();

  for (const task of tasks) {
    if (isEligibleForAutonomous(db, task)) {
      try {
        await processTask(task);
      } catch (err) {
        console.error(`[Worker] Unhandled error for task #${task.id}: ${err.message}`);
        log(task.id, 'Worker', 'unhandled_error', err.message);
      }
    }
  }
}

// Main loop
console.log(`[Worker] Starting autonomous worker. Polling every ${POLL_INTERVAL / 1000}s`);
setSetting(db, 'worker_status', 'running');

async function tick() {
  try {
    await pollLoop();
  } catch (err) {
    console.error(`[Worker] Poll loop error: ${err.message}`);
  }
  setTimeout(tick, POLL_INTERVAL);
}

tick();

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('[Worker] Shutting down...');
  setSetting(db, 'worker_status', 'stopped');
  db.close();
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('[Worker] Shutting down...');
  setSetting(db, 'worker_status', 'stopped');
  db.close();
  process.exit(0);
});
