'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  buildAuthStatus,
  isApiAuthenticated,
} = require('./api-key-auth');

test('auth status reports authentication without exposing the API key', () => {
  const apiKey = '0123456789abcdef0123456789abcdef';
  const req = {
    headers: {
      'x-api-key': apiKey,
      cookie: `cb_auth=${apiKey}`,
    },
  };

  const status = buildAuthStatus(req, apiKey);

  assert.deepEqual(status, {
    authenticated: true,
    auth_required: true,
  });
  assert.equal(Object.hasOwn(status, 'key'), false);
  assert.equal(JSON.stringify(status).includes(apiKey), false);
});

test('auth status stays unauthenticated without a matching header or cookie', () => {
  const apiKey = '0123456789abcdef0123456789abcdef';

  assert.equal(isApiAuthenticated({ headers: {} }, apiKey), false);
  assert.equal(isApiAuthenticated({ headers: { 'x-api-key': 'wrong' } }, apiKey), false);
  assert.equal(
    isApiAuthenticated({ headers: { cookie: 'cb_auth=wrong' } }, apiKey),
    false,
  );
});

test('auth accepts the configured key from header or cookie only', () => {
  const apiKey = '0123456789abcdef0123456789abcdef';

  assert.equal(isApiAuthenticated({ headers: { 'x-api-key': apiKey } }, apiKey), true);
  assert.equal(isApiAuthenticated({ headers: { cookie: `cb_auth=${apiKey}` } }, apiKey), true);
  assert.equal(isApiAuthenticated({ headers: { authorization: `Bearer ${apiKey}` } }, apiKey), false);
});
