/**
 * Structured logger — supports levels (debug, info, warn, error) and optional file output.
 *
 * Configuration (environment variables):
 *   LOG_LEVEL  — minimum level to emit (debug|info|warn|error, default: info)
 *   LOG_FILE   — path to write log lines (JSON, one per line). Disabled if unset.
 *   LOG_FORMAT — output format (json|text, default: text for TTY, json otherwise)
 *
 * Usage:
 *   const logger = require('./logger');
 *   logger.info('Server started', { port: 3000 });
 *   logger.error('DB error', { err: err.message });
 *
 * Drop-in console override (call once at startup):
 *   logger.overrideConsole();  // routes console.log→info, console.error→error, etc.
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ── Level definitions ──────────────────────────────────────────
const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };

const ENV_LEVEL  = (process.env.LOG_LEVEL  || 'info').toLowerCase();
const ENV_FILE   = process.env.LOG_FILE    || null;
const ENV_FORMAT = process.env.LOG_FORMAT  || (process.stdout.isTTY ? 'text' : 'json');

const MIN_LEVEL  = LEVELS[ENV_LEVEL] !== undefined ? LEVELS[ENV_LEVEL] : LEVELS.info;

// ── Optional file stream ───────────────────────────────────────
let fileStream = null;
if (ENV_FILE) {
  try {
    const dir = path.dirname(ENV_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fileStream = fs.createWriteStream(ENV_FILE, { flags: 'a' });
  } catch (e) {
    process.stderr.write(`[logger] Could not open log file "${ENV_FILE}": ${e.message}\n`);
  }
}

// ── ANSI colour helpers (text format, TTY only) ────────────────
const COLORS = {
  debug: '\x1b[36m',  // cyan
  info:  '\x1b[32m',  // green
  warn:  '\x1b[33m',  // yellow
  error: '\x1b[31m',  // red
  reset: '\x1b[0m',
  dim:   '\x1b[2m',
};
const useColor = process.stdout.isTTY;

// ── Core emit function ─────────────────────────────────────────
function emit(level, args) {
  if (LEVELS[level] < MIN_LEVEL) return;

  const ts      = new Date().toISOString();
  const message = formatArgs(args);

  if (ENV_FORMAT === 'json') {
    const entry = JSON.stringify({ ts, level, message });
    const target = level === 'error' ? process.stderr : process.stdout;
    target.write(entry + '\n');
    if (fileStream) fileStream.write(entry + '\n');
  } else {
    // Human-readable text
    const color  = useColor ? COLORS[level] : '';
    const dim    = useColor ? COLORS.dim    : '';
    const reset  = useColor ? COLORS.reset  : '';
    const lvlTag = `[${level.toUpperCase().padEnd(5)}]`;
    const line   = `${dim}${ts}${reset} ${color}${lvlTag}${reset} ${message}`;

    const target = level === 'error' ? process.stderr : process.stdout;
    target.write(line + '\n');

    if (fileStream) {
      // File always gets plain JSON (no ANSI codes)
      fileStream.write(JSON.stringify({ ts, level, message }) + '\n');
    }
  }
}

// ── Argument formatter ─────────────────────────────────────────
function formatArgs(args) {
  return args.map(a => {
    if (typeof a === 'string') return a;
    if (a instanceof Error)    return a.stack || a.message;
    try { return JSON.stringify(a); } catch { return String(a); }
  }).join(' ');
}

// ── Public logger API ──────────────────────────────────────────
const logger = {
  debug(...args) { emit('debug', args); },
  info (...args) { emit('info',  args); },
  warn (...args) { emit('warn',  args); },
  error(...args) { emit('error', args); },

  /** Route global console.* to structured logger (call once at startup). */
  overrideConsole() {
    console.log   = (...a) => emit('info',  a);
    console.info  = (...a) => emit('info',  a);
    console.warn  = (...a) => emit('warn',  a);
    console.error = (...a) => emit('error', a);
    console.debug = (...a) => emit('debug', a);
  },

  /** Current minimum level string (e.g. "info"). */
  get level() { return ENV_LEVEL; },
};

module.exports = logger;
