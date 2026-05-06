const assert = require('node:assert/strict');
const Module = require('node:module');
const test = require('node:test');

function loadEngineWithDb(getDb = () => {
  throw new Error('unexpected DB access');
}) {
  const enginePath = require.resolve('./task-force-engine');
  const dbPath = require.resolve('./task-force-db');
  const originalLoad = Module._load;
  delete require.cache[enginePath];

  Module._load = function patchedLoad(request, parent, isMain) {
    const resolved = Module._resolveFilename(request, parent, isMain);
    if (resolved === dbPath) {
      return { getDb, close: () => {} };
    }
    return originalLoad.apply(this, arguments);
  };

  try {
    return require('./task-force-engine');
  } finally {
    Module._load = originalLoad;
  }
}

test('task-force log insert failures are surfaced with context', () => {
  const engine = loadEngineWithDb();
  assert.equal(typeof engine.__test.recordTaskForceLog, 'function');

  const failingDb = {
    prepare(sql) {
      assert.match(sql, /INSERT INTO task_force_logs/);
      return {
        run() {
          throw new Error('readonly database');
        },
      };
    },
  };

  assert.throws(
    () =>
      engine.__test.recordTaskForceLog(
        () => failingDb,
        42,
        'error',
        'guardian',
        'zombie process detected',
        { pid: 1234 },
      ),
    /task force log insert failed for force_id=42 source=guardian level=error: readonly database/,
  );
});

test('task-force log helper writes deterministic metadata JSON', () => {
  const engine = loadEngineWithDb();
  const calls = [];
  const db = {
    prepare(sql) {
      assert.match(sql, /INSERT INTO task_force_logs/);
      return {
        run(...args) {
          calls.push(args);
          return { changes: 1 };
        },
      };
    },
  };

  const result = engine.__test.recordTaskForceLog(
    () => db,
    7,
    'info',
    'engine',
    'force deployed',
    { adapter: 'claude_cli', device: 'mac' },
    () => '2026-05-06 01:02:03',
  );

  assert.deepEqual(result, { changes: 1 });
  assert.deepEqual(calls, [
    [
      7,
      'info',
      'engine',
      'force deployed',
      '{"adapter":"claude_cli","device":"mac"}',
      '2026-05-06 01:02:03',
    ],
  ]);
});
