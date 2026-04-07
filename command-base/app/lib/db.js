'use strict';

const Database = require('better-sqlite3');
const path = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', '..', 'the_team.db');

let db;
try {
  db = new Database(DB_PATH, { fileMustExist: true });
  console.log(`Connected to database at ${DB_PATH}`);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');
  db.pragma('synchronous = NORMAL');
  db.pragma('cache_size = -65536');
  db.pragma('temp_store = MEMORY');
  db.pragma('mmap_size = 268435456');
  console.log('[DB] WAL mode enabled, busy_timeout=5s, 64MB cache, 256MB mmap');
} catch (err) {
  console.error('Failed to open database:', err.message);
  process.exit(1);
}

function localNow() {
  return new Date().toLocaleString('sv-SE', { timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone }).replace(' ', 'T').slice(0, 19).replace('T', ' ');
}

module.exports = { db, DB_PATH, localNow };
