'use strict';

const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const APP_ROOT = __dirname;

function readAppFile(relativePath) {
  return fs.readFileSync(path.join(APP_ROOT, relativePath), 'utf8');
}

test('server auth status route never returns the raw API key', () => {
  const source = readAppFile('server.js');
  const statusRouteStart = source.indexOf("app.get('/api/auth/status'");
  assert.notEqual(statusRouteStart, -1, 'auth status route must exist');

  const statusRouteEnd = source.indexOf("app.use('/api'", statusRouteStart);
  assert.notEqual(statusRouteEnd, -1, 'auth middleware must follow status route');
  const statusRoute = source.slice(statusRouteStart, statusRouteEnd);

  assert.match(statusRoute, /buildAuthStatus/);
  assert.doesNotMatch(statusRoute, /key\s*:\s*getApiAuthKey\(\)/);
  assert.doesNotMatch(statusRoute, /res\.json\(\s*\{\s*authenticated\s*:\s*true\s*,\s*key\s*:/);
});

test('API middleware does not exempt auth status from authorization checks', () => {
  const source = readAppFile('server.js');
  const middlewareStart = source.indexOf("app.use('/api'");
  assert.notEqual(middlewareStart, -1, 'API middleware must exist');

  const rateLimiterStart = source.indexOf('// -- In-memory rate limiter', middlewareStart);
  const middleware = source.slice(middlewareStart, rateLimiterStart);

  assert.doesNotMatch(middleware, /req\.path\s*===\s*['"]\/auth\/status['"]/);
  assert.match(middleware, /isApiAuthenticated/);
});

test('browser surfaces do not bootstrap by reading a raw auth status key', () => {
  for (const relativePath of ['public/app.js', 'public/whitepaper.html']) {
    const source = readAppFile(relativePath);
    assert.doesNotMatch(source, /\bd\.key\b|\bauthData\.key\b/);
    assert.doesNotMatch(source, /document\.cookie\s*=\s*['"]cb_auth=.*(?:d\.key|authData\.key)/);
    assert.doesNotMatch(source, /auto-authenticates via \/api\/auth\/status bootstrap/i);
  }
});

test('browser GET helper sends caller-provided API key without requiring a cookie', () => {
  const source = readAppFile('public/app.js');
  const helperStart = source.indexOf('async function api(endpoint)');
  assert.notEqual(helperStart, -1, 'GET helper must exist');

  const helperEnd = source.indexOf('function invalidateCache', helperStart);
  const helper = source.slice(helperStart, helperEnd);

  assert.match(helper, /opts\.headers/);
  assert.match(helper, /_cbApiKey/);
  assert.match(helper, /X-API-Key/);
});
