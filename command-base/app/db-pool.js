'use strict';

/**
 * db-pool.js — SQLite connection pool for better-sqlite3
 *
 * better-sqlite3 is synchronous, so "pooling" means keeping N open connections
 * with WAL mode enabled so reads can proceed concurrently with writes.
 *
 * Usage:
 *   const pool = require('./db-pool');
 *   const conn = pool.acquire();
 *   try {
 *     const rows = conn.prepare('SELECT * FROM tasks').all();
 *   } finally {
 *     pool.release(conn);
 *   }
 *
 *   // Or use the helper:
 *   const rows = pool.read(conn => conn.prepare('SELECT * FROM tasks').all());
 */

const Database = require('better-sqlite3');
const path = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', 'the_team.db');

// Number of read connections to keep open. One write connection (in server.js)
// plus READ_POOL_SIZE read connections covers most concurrent traffic patterns.
const READ_POOL_SIZE = parseInt(process.env.DB_READ_POOL_SIZE || '4', 10);

function applyPragmas(conn) {
  conn.pragma('journal_mode = WAL');
  conn.pragma('foreign_keys = ON');
  conn.pragma('busy_timeout = 5000');
  conn.pragma('synchronous = NORMAL');
  conn.pragma('cache_size = -65536');  // 64 MB
  conn.pragma('temp_store = MEMORY');
  conn.pragma('mmap_size = 268435456'); // 256 MB
  conn.pragma('query_only = ON');       // read connections are read-only
}

class DbPool {
  constructor(dbPath, poolSize) {
    this._path = dbPath;
    this._size = poolSize;
    this._slots = [];

    for (let i = 0; i < poolSize; i++) {
      const conn = new Database(dbPath, { fileMustExist: true, readonly: true });
      applyPragmas(conn);
      this._slots.push({ conn, busy: false });
    }
  }

  /**
   * Acquire a read connection from the pool.
   * Returns the first idle connection, or null if all are busy.
   * Callers must call release() when done.
   */
  acquire() {
    const slot = this._slots.find(s => !s.busy);
    if (!slot) return null; // all busy — caller falls back to write connection
    slot.busy = true;
    return slot.conn;
  }

  /**
   * Return a connection to the pool.
   */
  release(conn) {
    const slot = this._slots.find(s => s.conn === conn);
    if (slot) slot.busy = false;
  }

  /**
   * Execute a read callback with a pooled connection.
   * Automatically acquires and releases. Falls back to the primary write
   * connection (passed as `fallback`) if the pool is exhausted.
   *
   * @param {function(Database): any} fn
   * @param {Database} [fallback] - primary db connection to use if pool is full
   * @returns {any}
   */
  read(fn, fallback) {
    const conn = this.acquire();
    if (conn) {
      try {
        return fn(conn);
      } finally {
        this.release(conn);
      }
    }
    // Pool exhausted — use fallback (write connection handles reads fine in WAL mode)
    if (fallback) return fn(fallback);
    throw new Error('[db-pool] Pool exhausted and no fallback provided');
  }

  /**
   * Pool stats for monitoring / health checks.
   */
  stats() {
    const busy = this._slots.filter(s => s.busy).length;
    return { size: this._size, busy, idle: this._size - busy };
  }

  /**
   * Close all pooled connections (call on process exit).
   */
  close() {
    for (const slot of this._slots) {
      try { slot.conn.close(); } catch (_) {}
    }
    this._slots = [];
  }
}

const pool = new DbPool(DB_PATH, READ_POOL_SIZE);

// Graceful shutdown
process.once('exit', () => pool.close());
process.once('SIGINT', () => { pool.close(); process.exit(0); });
process.once('SIGTERM', () => { pool.close(); process.exit(0); });

module.exports = pool;
