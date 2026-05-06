'use strict';

const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const AUTH_PATH = path.join(__dirname, 'auth.js');

function reloadAuthWithSecret(secret) {
  delete require.cache[require.resolve(AUTH_PATH)];
  if (secret === undefined) {
    delete process.env.EXOCHAIN_AUTH_SECRET;
  } else {
    process.env.EXOCHAIN_AUTH_SECRET = secret;
  }
  return require(AUTH_PATH);
}

test('HMAC signing has no hardcoded development secret fallback', () => {
  const source = fs.readFileSync(AUTH_PATH, 'utf8');

  assert.doesNotMatch(source, /exochain-dev-secret-change-in-production/);
  assert.doesNotMatch(source, /EXOCHAIN_AUTH_SECRET\s*\|\|/);
});

test('HMAC fallback fails closed when EXOCHAIN_AUTH_SECRET is absent', () => {
  const auth = reloadAuthWithSecret(undefined);

  assert.throws(
    () => auth._sign('header.payload'),
    /EXOCHAIN_AUTH_SECRET/,
  );
});

test('HMAC fallback accepts an explicit high-entropy secret', () => {
  const auth = reloadAuthWithSecret('0123456789abcdef0123456789abcdef');
  const token = auth.createToken('did:exo:alice', 'governance:full', 'delegation-1', {
    ttl: 60,
  });

  const result = auth.verifyToken(token);

  assert.equal(result.valid, true);
  assert.equal(result.payload.did, 'did:exo:alice');
});
