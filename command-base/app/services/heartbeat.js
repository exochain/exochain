'use strict';

/**
 * Heartbeat service: heartbeat scheduler, execution, and process watchdog.
 *
 * Usage:
 *   const heartbeatService = require('./services/heartbeat')(db, broadcast, { localNow }, { spawnMemberTerminal, runningProcesses });
 */

module.exports = function(db, broadcast, helpers, deps) {
  const { localNow, isLocalMode } = helpers;
  // deps.spawnMemberTerminal and deps.runningProcesses are injected after spawn module loads
  let spawnMemberTerminal = deps.spawnMemberTerminal;
  let runningProcesses = deps.runningProcesses;

  // Allow late-binding of spawn dependencies (circular dep resolution)
  function setSpawnDeps(newDeps) {
    if (newDeps.spawnMemberTerminal) spawnMemberTerminal = newDeps.spawnMemberTerminal;
    if (newDeps.runningProcesses) runningProcesses = newDeps.runningProcesses;
  }

  // ── Process Watchdog ──

  function processWatchdog() {
    try {
      const runningProcs = db.prepare(`SELECT ap.*, t.priority, t.title as task_title, tm.name as member_name, tm.id as member_id_ref
        FROM active_processes ap
        LEFT JOIN tasks t ON ap.task_id = t.id
        LEFT JOIN team_members tm ON ap.member_id = tm.id
        WHERE ap.status = 'running'`).all();

      const now = localNow();
      const nowMs = Date.now();

      for (const proc of runningProcs) {
        let alive = false;
        if (proc.pid) {
          try { process.kill(proc.pid, 0); alive = true; } catch { alive = false; }
        }

        if (!alive && proc.pid) {
          console.log(`[Watchdog] Process #${proc.id} (${proc.member_name || 'Unknown'}) PID ${proc.pid} is dead`);
          db.prepare(`UPDATE active_processes SET status = 'failed', completed_at = ?, output_summary = COALESCE(output_summary, '') || ' [PID died]' WHERE id = ? AND status = 'running'`)
            .run(now, proc.id);
          db.prepare(`INSERT INTO activity_log (task_id, actor, action, notes, created_at) VALUES (?, ?, 'watchdog_detected', ?, ?)`)
            .run(proc.task_id, proc.member_name || 'Watchdog', `Process #${proc.id} PID ${proc.pid} died unexpectedly`, now);
          broadcast('process.failed', { process_id: proc.id, task_id: proc.task_id, error: 'Process died (detected by watchdog)' });

          const retryCount = proc.retry_count || 0;
          // Token audit v2: Smarter doomed-spawn detection.
          // output_summary ALWAYS has the spawn message ("Spawning X on Y") so length > 0 was
          // never catching truly doomed spawns. Now we check if output contains actual work
          // indicators beyond the initial spawn message — tool calls, file edits, or meaningful content.
          const maxRetries = (proc.priority === 'urgent' || proc.priority === 'high') ? 2 : 1;
          const prevOutput = (proc.output_summary || '').trim();
          const hasRealWork = prevOutput.length > 100 && !/^Spawning \w+ on ".+"$/.test(prevOutput);
          const shouldRetry = retryCount < maxRetries && proc.member_id_ref && proc.task_id && hasRealWork;
          if (shouldRetry) {
            const newRetryCount = retryCount + 1;
            console.log(`[Watchdog] Auto-retrying task #${proc.task_id} (attempt ${newRetryCount} of ${maxRetries})`);
            db.prepare(`UPDATE tasks SET current_step = ?, updated_at = ? WHERE id = ?`)
              .run(`Auto-retrying (attempt ${newRetryCount} of ${maxRetries})...`, now, proc.task_id);
            db.prepare(`INSERT INTO activity_log (task_id, actor, action, notes, created_at) VALUES (?, 'Watchdog', 'auto_retry', ?, ?)`)
              .run(proc.task_id, `Auto-retrying after process death (attempt ${newRetryCount}/${maxRetries})`, now);
            db.prepare(`INSERT INTO notifications (type, title, message, task_id, read, created_at) VALUES ('system', ?, ?, ?, 0, ?)`)
              .run(`${proc.member_name || 'Agent'} auto-retrying`, `Process died on "${proc.task_title || 'task'}" -- auto-retrying (attempt ${newRetryCount}/${maxRetries})`, proc.task_id, now);
            setTimeout(() => {
              spawnMemberTerminal(proc.task_id, proc.member_id_ref).then(result => {
                if (result && result.process_id) {
                  db.prepare(`UPDATE active_processes SET retry_count = ? WHERE id = ?`).run(newRetryCount, result.process_id);
                }
              }).catch(err => {
                console.error(`[Watchdog] Auto-retry spawn failed: ${err.message}`);
              });
            }, 60000); // Token audit v5: doubled from 30s to reduce retry cascade contention
          } else if (retryCount >= maxRetries || !shouldRetry) {
            const failReason = !hasRealWork ? 'no meaningful output (doomed spawn)' : `${retryCount} retry attempts exhausted`;
            db.prepare(`UPDATE tasks SET current_step = ?, updated_at = ? WHERE id = ?`)
              .run(`Failed: ${failReason}`, now, proc.task_id);
            db.prepare(`INSERT INTO notifications (type, title, message, task_id, read, created_at) VALUES ('system', ?, ?, ?, 0, ?)`)
              .run(`${proc.member_name || 'Agent'} failed`, `"${proc.task_title || 'task'}" — ${failReason}`, proc.task_id, now);
          }
          continue;
        }

        if (proc.started_at) {
          const startedMs = new Date(proc.started_at.replace(' ', 'T')).getTime();
          const timeoutMs = (proc.priority === 'urgent' || proc.priority === 'high') ? 1800000 : 900000;
          const elapsed = nowMs - startedMs;
          if (elapsed > timeoutMs) {
            const lastEvent = db.prepare(`SELECT created_at FROM agent_activity_stream WHERE process_id = ? ORDER BY id DESC LIMIT 1`).get(proc.id);
            let lastActivityMs = startedMs;
            if (lastEvent && lastEvent.created_at) {
              lastActivityMs = new Date(lastEvent.created_at.replace(' ', 'T')).getTime();
            }
            const silentMinutes = Math.floor((nowMs - lastActivityMs) / 60000);
            if (silentMinutes >= 5) {
              console.log(`[Watchdog] Process #${proc.id} (${proc.member_name || 'Unknown'}) may be stuck: ${silentMinutes}m since last activity, ${Math.floor(elapsed / 60000)}m total elapsed`);
              db.prepare(`INSERT OR REPLACE INTO activity_log (task_id, actor, action, notes, created_at) VALUES (?, 'Watchdog', 'stuck_warning', ?, ?)`)
                .run(proc.task_id, `Process #${proc.id} possibly stuck: ${silentMinutes}m idle, ${Math.floor(elapsed / 60000)}m total`, now);
            }
          }
        }
      }
    } catch (err) {
      console.error(`[Watchdog] Error: ${err.message}`);
    }
  }

  // ── Heartbeat Scheduler ──

  function heartbeatScheduler() {
    if (isLocalMode && isLocalMode()) return;
    const now = localNow();
    try {
      const wakeups = db.prepare(`SELECT * FROM agent_wakeup_requests WHERE status = 'pending' ORDER BY created_at ASC LIMIT 5`).all();
      for (const wakeup of wakeups) {
        db.prepare(`UPDATE agent_wakeup_requests SET status = 'processing', processed_at = ? WHERE id = ?`).run(now, wakeup.id);
        executeHeartbeat(wakeup.member_id, 'wakeup', wakeup.reason);
        db.prepare(`UPDATE agent_wakeup_requests SET status = 'completed' WHERE id = ?`).run(wakeup.id);
      }

      const dueAgents = db.prepare(`
        SELECT ars.*, tm.name as member_name
        FROM agent_runtime_state ars
        JOIN team_members tm ON ars.member_id = tm.id
        WHERE ars.status != 'paused'
        AND ars.next_heartbeat_at IS NOT NULL
        AND ars.next_heartbeat_at <= ?
        AND tm.status = 'active'
      `).all(now);
      for (const agent of dueAgents) {
        executeHeartbeat(agent.member_id, 'scheduled', 'Scheduled heartbeat');
      }
    } catch (err) {
      console.error(`[Heartbeat] Scheduler error: ${err.message}`);
    }
  }

  // ── Execute Heartbeat ──

  async function executeHeartbeat(memberId, triggerType, reason) {
    const now = localNow();
    const member = db.prepare('SELECT * FROM team_members WHERE id = ?').get(memberId);
    if (!member) return;

    const running = db.prepare("SELECT * FROM heartbeat_runs WHERE member_id = ? AND status = 'running'").get(memberId);
    if (running) return;

    const run = db.prepare(`INSERT INTO heartbeat_runs (member_id, status, trigger_type, trigger_reason, started_at, created_at) VALUES (?,?,?,?,?,?)`)
      .run(memberId, 'running', triggerType, reason, now, now);
    const runId = Number(run.lastInsertRowid);

    db.prepare(`INSERT OR REPLACE INTO agent_runtime_state (member_id, last_heartbeat_at, status, updated_at) VALUES (?,?,?,?)`)
      .run(memberId, now, 'running', now);
    db.prepare(`INSERT INTO heartbeat_run_events (run_id, step_number, step_name, event_type, detail, created_at) VALUES (?,?,?,?,?,?)`)
      .run(runId, 1, 'Find task', 'step_start', 'Looking for next task to work on', now);

    const task = db.prepare(`
      SELECT t.* FROM tasks t
      LEFT JOIN task_checkouts tc ON tc.task_id = t.id AND tc.status = 'active'
      WHERE t.assigned_to = ? AND t.status IN ('new','routing','in_progress')
      AND tc.id IS NULL
      ORDER BY CASE t.priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 WHEN 'low' THEN 3 END, t.created_at ASC
      LIMIT 1
    `).get(memberId);

    if (!task) {
      db.prepare(`UPDATE heartbeat_runs SET status = 'completed', completed_at = ?, current_step = 'No tasks assigned', steps_completed = 1, duration_ms = 0 WHERE id = ?`).run(now, runId);
      db.prepare(`INSERT INTO heartbeat_run_events (run_id, step_number, step_name, event_type, detail, created_at) VALUES (?,?,?,?,?,?)`)
        .run(runId, 1, 'Find task', 'step_complete', 'No tasks found — idle', now);
      db.prepare(`UPDATE agent_runtime_state SET status = 'idle', consecutive_idle_count = COALESCE(consecutive_idle_count, 0) + 1, next_heartbeat_at = datetime(?, '+' || COALESCE(heartbeat_interval_seconds, 300) || ' seconds'), updated_at = ? WHERE member_id = ?`)
        .run(now, now, memberId);
      broadcast('heartbeat.completed', { run_id: runId, member_id: memberId, status: 'idle' });
      return;
    }

    try {
      db.prepare(`INSERT INTO task_checkouts (task_id, member_id, checked_out_at) VALUES (?,?,?)`).run(task.id, memberId, now);
    } catch (e) {
      db.prepare(`UPDATE heartbeat_runs SET status = 'failed', error_message = 'Task already checked out', completed_at = ? WHERE id = ?`).run(now, runId);
      db.prepare(`INSERT INTO heartbeat_run_events (run_id, step_number, step_name, event_type, detail, created_at) VALUES (?,?,?,?,?,?)`)
        .run(runId, 2, 'Checkout', 'error', `Task #${task.id} already checked out by another agent`, now);
      db.prepare(`UPDATE agent_runtime_state SET status = 'idle', updated_at = ? WHERE member_id = ?`).run(now, memberId);
      broadcast('heartbeat.failed', { run_id: runId, member_id: memberId, error: 'checkout_conflict' });
      return;
    }

    db.prepare(`UPDATE heartbeat_runs SET task_id = ?, current_step = 'Spawning agent', steps_completed = 2 WHERE id = ?`).run(task.id, runId);
    db.prepare(`INSERT INTO heartbeat_run_events (run_id, step_number, step_name, event_type, detail, created_at) VALUES (?,?,?,?,?,?)`)
      .run(runId, 2, 'Checkout', 'step_complete', `Checked out task #${task.id}: ${task.title}`, now);
    db.prepare(`UPDATE agent_runtime_state SET current_task_id = ?, updated_at = ? WHERE member_id = ?`).run(task.id, now, memberId);

    try {
      const result = await spawnMemberTerminal(task.id, memberId);
      if (result && result.process_id) {
        db.prepare(`UPDATE heartbeat_runs SET process_id = ?, current_step = 'Agent working' WHERE id = ?`).run(result.process_id, runId);
        db.prepare(`INSERT INTO heartbeat_run_events (run_id, step_number, step_name, event_type, detail, created_at) VALUES (?,?,?,?,?,?)`)
          .run(runId, 3, 'Spawn', 'step_complete', `Spawned process #${result.process_id} for ${member.name}`, now);
      }
      broadcast('heartbeat.spawned', { run_id: runId, member_id: memberId, task_id: task.id });
    } catch (err) {
      db.prepare(`UPDATE heartbeat_runs SET status = 'failed', error_message = ?, completed_at = ? WHERE id = ?`).run(err.message, now, runId);
      db.prepare(`INSERT INTO heartbeat_run_events (run_id, step_number, step_name, event_type, detail, created_at) VALUES (?,?,?,?,?,?)`)
        .run(runId, 3, 'Spawn', 'error', `Spawn failed: ${err.message}`, now);
      db.prepare(`UPDATE task_checkouts SET status = 'released', released_at = ? WHERE task_id = ? AND member_id = ? AND status = 'active'`).run(now, task.id, memberId);
      db.prepare(`UPDATE agent_runtime_state SET status = 'error', consecutive_error_count = COALESCE(consecutive_error_count, 0) + 1, current_task_id = NULL, updated_at = ? WHERE member_id = ?`).run(now, memberId);
      broadcast('heartbeat.failed', { run_id: runId, member_id: memberId, error: err.message });
    }

    const interval = db.prepare('SELECT heartbeat_interval_seconds FROM agent_runtime_state WHERE member_id = ?').get(memberId);
    const intervalSec = (interval && interval.heartbeat_interval_seconds) || 300;
    db.prepare(`UPDATE agent_runtime_state SET next_heartbeat_at = datetime(?, '+' || ? || ' seconds'), consecutive_idle_count = 0, updated_at = ? WHERE member_id = ?`)
      .run(now, intervalSec, now, memberId);
  }

  return {
    processWatchdog,
    heartbeatScheduler,
    executeHeartbeat,
    setSpawnDeps
  };
};
