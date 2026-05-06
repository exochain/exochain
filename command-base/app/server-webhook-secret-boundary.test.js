const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const serverSource = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');

test('inbound webhooks do not seed or preserve an empty-open secret boundary', () => {
  assert.equal(
    /empty\s*=\s*open/.test(serverSource),
    false,
    'webhook configuration must not document an empty secret as an open boundary'
  );
  assert.equal(
    /VALUES\s*\(\s*'webhook_secret'\s*,\s*''\s*\)/.test(serverSource),
    false,
    'webhook_secret must not be seeded as an empty string literal'
  );
  assert.equal(
    /if\s*\(\s*webhookSecret\s*&&\s*webhookSecret\.value\s*\)/.test(serverSource),
    false,
    'webhook handlers must not skip authentication when the stored secret is absent or empty'
  );
});

test('inbound webhook authentication uses a shared fail-closed header boundary', () => {
  assert.equal(
    /requireWebhookSecret/.test(serverSource),
    true,
    'both webhook handlers should use the shared fail-closed webhook authenticator'
  );
  assert.equal(
    /req\.query\.secret/.test(serverSource),
    false,
    'webhook secrets must not be accepted through URL query parameters'
  );
});
