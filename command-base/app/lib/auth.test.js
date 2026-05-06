'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

function runAuthSnippet(env, source) {
  const result = spawnSync(process.execPath, ['-e', source], {
    cwd: __dirname + '/..',
    env: {
      ...process.env,
      EXOCHAIN_AUTH_SECRET: '',
      NODE_ENV: 'production',
      ...env,
    },
    encoding: 'utf8',
  });
  assert.equal(
    result.status,
    0,
    `auth snippet failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
}

test('HMAC fallback refuses to sign with an absent secret', () => {
  runAuthSnippet(
    { EXOCHAIN_AUTH_SECRET: '' },
    `
      const { createToken } = require('./lib/auth');
      try {
        createToken('did:exo:alice', 'governance:full', null);
      } catch (err) {
        if (String(err.message).includes('EXOCHAIN_AUTH_SECRET')) process.exit(0);
        throw err;
      }
      throw new Error('createToken unexpectedly signed without EXOCHAIN_AUTH_SECRET');
    `,
  );
});

test('HMAC fallback refuses the historical development secret', () => {
  runAuthSnippet(
    { EXOCHAIN_AUTH_SECRET: 'exochain-dev-secret-change-in-production' },
    `
      const { createToken } = require('./lib/auth');
      try {
        createToken('did:exo:alice', 'governance:full', null);
      } catch (err) {
        if (String(err.message).includes('development HMAC secret')) process.exit(0);
        throw err;
      }
      throw new Error('createToken unexpectedly signed with the development HMAC secret');
    `,
  );
});

test('HMAC fallback signs and verifies with an explicit deployment secret', () => {
  runAuthSnippet(
    { EXOCHAIN_AUTH_SECRET: 'test-only-commandbase-auth-secret-32b' },
    `
      const { createToken, verifyToken } = require('./lib/auth');
      const token = createToken('did:exo:alice', 'governance:full', 'delegation-1');
      const verified = verifyToken(token);
      if (!verified.valid) throw new Error(verified.error || 'token did not verify');
      if (verified.payload.did !== 'did:exo:alice') throw new Error('payload DID mismatch');
      const parts = token.split('.');
      parts[2] = parts[2].slice(0, -2);
      const tampered = verifyToken(parts.join('.'));
      if (tampered.valid) throw new Error('tampered token unexpectedly verified');
    `,
  );
});
