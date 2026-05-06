'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  configureWebhookSecretSetting,
  requireWebhookSecret,
} = require('./webhook-auth');

class SettingsDb {
  constructor(initialValue, hasRow = true) {
    this.hasRow = hasRow;
    this.value = initialValue;
    this.operations = [];
  }

  prepare(sql) {
    return {
      get: (key) => {
        this.operations.push(['get', sql, key]);
        if (key !== 'webhook_secret' || !this.hasRow) return undefined;
        return { value: this.value };
      },
      run: (...params) => {
        this.operations.push(['run', sql, ...params]);
        if (/INSERT OR IGNORE INTO system_settings/.test(sql)) {
          const [key, value] = params;
          if (key === 'webhook_secret' && !this.hasRow) {
            this.hasRow = true;
            this.value = value;
          }
          return { changes: this.hasRow ? 0 : 1 };
        }
        if (/UPDATE system_settings/.test(sql)) {
          const [value, key] = params;
          if (key === 'webhook_secret' && this.hasRow) {
            this.value = value;
            return { changes: 1 };
          }
        }
        return { changes: 0 };
      },
    };
  }
}

function requestWithSecret(secret) {
  return { headers: { 'x-webhook-secret': secret } };
}

test('missing webhook secret setting fails closed before payload handling', () => {
  const result = requireWebhookSecret({ headers: {} }, new SettingsDb(undefined, false));

  assert.equal(result.ok, false);
  assert.equal(result.status, 503);
  assert.deepEqual(result.body, { error: 'Webhook secret is not configured' });
});

test('empty webhook secret setting fails closed before payload handling', () => {
  const result = requireWebhookSecret({ headers: {} }, new SettingsDb(''));

  assert.equal(result.ok, false);
  assert.equal(result.status, 503);
  assert.deepEqual(result.body, { error: 'Webhook secret is not configured' });
});

test('configured webhook secret rejects missing, query, and incorrect credentials', () => {
  const db = new SettingsDb('shared-secret');

  assert.deepEqual(
    requireWebhookSecret({ headers: {} }, db),
    { ok: false, status: 401, body: { error: 'Unauthorized' } }
  );
  assert.deepEqual(
    requireWebhookSecret({ headers: {}, query: { secret: 'shared-secret' } }, db),
    { ok: false, status: 401, body: { error: 'Unauthorized' } }
  );
  assert.deepEqual(
    requireWebhookSecret(requestWithSecret('wrong-secret'), db),
    { ok: false, status: 401, body: { error: 'Unauthorized' } }
  );
});

test('configured webhook secret accepts only the matching header value', () => {
  const result = requireWebhookSecret(requestWithSecret('shared-secret'), new SettingsDb('shared-secret'));

  assert.deepEqual(result, { ok: true });
});

test('webhook secret bootstrap uses environment configuration without overwriting a configured secret', () => {
  const emptyDb = new SettingsDb('', true);
  configureWebhookSecretSetting(emptyDb, { COMMANDBASE_WEBHOOK_SECRET: 'configured-secret' });
  assert.equal(emptyDb.value, 'configured-secret');

  const missingDb = new SettingsDb(undefined, false);
  configureWebhookSecretSetting(missingDb, { COMMANDBASE_WEBHOOK_SECRET: 'configured-secret' });
  assert.equal(missingDb.value, 'configured-secret');

  const existingDb = new SettingsDb('existing-secret', true);
  configureWebhookSecretSetting(existingDb, { COMMANDBASE_WEBHOOK_SECRET: 'configured-secret' });
  assert.equal(existingDb.value, 'existing-secret');
});

test('webhook secret bootstrap permits an unset secret only as a fail-closed placeholder', () => {
  const db = new SettingsDb(undefined, false);

  configureWebhookSecretSetting(db, {});

  assert.equal(db.value, '');
  assert.equal(requireWebhookSecret(requestWithSecret('anything'), db).status, 503);
});
