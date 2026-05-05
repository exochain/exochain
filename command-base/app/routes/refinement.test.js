'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const registerRefinementRoutes = require('./refinement');

function createFakeApp() {
  const routes = new Map();
  const register = (method) => (route, handler) => {
    routes.set(`${method} ${route}`, handler);
  };
  return {
    routes,
    get: register('GET'),
    post: register('POST'),
    put: register('PUT'),
    delete: register('DELETE')
  };
}

function createResponse() {
  return {
    statusCode: 200,
    body: undefined,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    }
  };
}

function createDb(sqlAssertions) {
  return {
    prepare(sql) {
      return {
        get(...params) {
          if (sql.includes('FROM refinement_candidates rc JOIN refinement_targets rt')) {
            return {
              id: 7,
              target_id: 3,
              title: 'Reduce query latency',
              description: 'Tune the slow path',
              file_path: 'app/services/search.js',
              metric_name: 'latency_ms',
              metric_command: 'npm test',
              priority: 'high',
              target_path: '/tmp/commandbase',
              assigned_member_id: null
            };
          }
          if (sql.includes('FROM refinement_team_assignments rta')) {
            sqlAssertions.push(sql);
            assert.doesNotMatch(
              sql,
              /ORDER\s+BY\s+RANDOM\s*\(\)/i,
              'refinement assignment must not select team members randomly'
            );
            assert.match(
              sql,
              /ORDER\s+BY\s+COUNT\s*\(\s*active\.id\s*\)\s+ASC,\s*tm\.id\s+ASC/i,
              'refinement assignment must use least-active load and stable id tie-break'
            );
            assert.deepStrictEqual(params, [3]);
            return { id: 11, name: 'Ada' };
          }
          return null;
        },
        run() {
          if (sql.includes('INSERT INTO research_programs')) {
            return { lastInsertRowid: 101 };
          }
          if (sql.includes('INSERT INTO tasks')) {
            return { lastInsertRowid: 202 };
          }
          return { changes: 1, lastInsertRowid: 0 };
        },
        all() {
          return [];
        }
      };
    }
  };
}

test('POST /api/refinement/candidates/:id/refine assigns least-active enabled member deterministically', async () => {
  const app = createFakeApp();
  const sqlAssertions = [];
  const db = createDb(sqlAssertions);
  const broadcasts = [];

  registerRefinementRoutes(app, db, {
    localNow: () => '2026-05-05 12:00:00',
    broadcast: (event, payload) => broadcasts.push({ event, payload }),
    spawnMemberTerminal: async () => {}
  });

  const handler = app.routes.get('POST /api/refinement/candidates/:id/refine');
  assert.equal(typeof handler, 'function');

  const req = { params: { id: '7' } };
  const res = createResponse();

  await handler(req, res);

  assert.equal(res.statusCode, 200);
  assert.deepStrictEqual(res.body, { success: true, task_id: 202, program_id: 101 });
  assert.equal(sqlAssertions.length, 1);
  assert.deepStrictEqual(broadcasts, [
    {
      event: 'refinement.started',
      payload: { target_id: 3, candidate_id: 7, task_id: 202 }
    }
  ]);
});

test('refinement assignment source has no random selector in route or legacy server loop', () => {
  const appDir = path.resolve(__dirname, '..');
  const routeSource = fs.readFileSync(path.join(appDir, 'routes', 'refinement.js'), 'utf8');
  const serverSource = fs.readFileSync(path.join(appDir, 'server.js'), 'utf8');
  const loopStart = serverSource.indexOf('function runRefinementCycle');
  assert.notEqual(loopStart, -1, 'server refinement loop must exist');
  const loopEnd = serverSource.indexOf('const refinementTimers', loopStart);
  assert.notEqual(loopEnd, -1, 'server refinement loop section must have a stable end marker');
  const loopSource = serverSource.slice(loopStart, loopEnd);

  for (const [label, source] of [
    ['routes/refinement.js', routeSource],
    ['server.js runRefinementCycle', loopSource]
  ]) {
    assert.doesNotMatch(
      source,
      /ORDER\s+BY\s+RANDOM\s*\(\)/i,
      `${label} must not use random team-member assignment`
    );
    assert.match(
      source,
      /ORDER\s+BY\s+COUNT\s*\(\s*active\.id\s*\)\s+ASC,\s*tm\.id\s+ASC/i,
      `${label} must use least-active load and stable id tie-break`
    );
  }
});
