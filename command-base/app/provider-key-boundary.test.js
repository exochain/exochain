const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const appSource = fs.readFileSync(path.join(__dirname, 'public', 'app.js'), 'utf8');
const settingsRouteSource = fs.readFileSync(path.join(__dirname, 'routes', 'settings.js'), 'utf8');

function sourceBetween(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  assert.notEqual(start, -1, `${startMarker} must exist`);
  const end = source.indexOf(endMarker, start);
  assert.notEqual(end, -1, `${endMarker} must exist after ${startMarker}`);
  return source.slice(start, end);
}

test('provider cards do not store revealable API key material in DOM attributes', () => {
  const card = sourceBetween(appSource, 'function renderProviderCard', 'function renderProviderForm');
  const wiring = sourceBetween(appSource, 'function wireLLMProviderActions', 'function wireProviderFormActions');

  assert.doesNotMatch(
    card,
    /data-full-key|provider-key-toggle/,
    'provider cards must render only the masked key and must not add reveal controls'
  );
  assert.doesNotMatch(
    wiring,
    /dataset\.fullKey|provider-key-toggle/,
    'provider action wiring must not reveal API key material from DOM data attributes'
  );
});

test('provider edit form never pre-fills masked API keys as replacement secrets', () => {
  const form = sourceBetween(appSource, 'function renderProviderForm', 'function renderMcpServerCard');

  assert.doesNotMatch(
    form,
    /class="pf-api-key" value="' \+ escHtml\(p\.api_key \|\| ''\)/,
    'edit form must not prefill API key input with the masked API key returned by the API'
  );
  assert.match(
    form,
    /isEdit \? '' :/,
    'edit form must leave the API key field blank unless the user supplies a replacement'
  );
});

test('provider save payload preserves existing key unless edit supplies replacement', () => {
  const save = sourceBetween(appSource, 'function wireProviderFormActions', 'function wireLLMAssignmentActions');

  assert.doesNotMatch(
    save,
    /api_key: api_key/,
    'save payload must not always include api_key because edit pages only know a masked value'
  );
  assert.match(
    save,
    /if \(!existingProvider \|\| api_key\)/,
    'save payload must include api_key only for create or explicit edit replacement'
  );
});

test('provider update route rejects masked API key sentinels from stale clients', () => {
  const putRoute = sourceBetween(
    settingsRouteSource,
    "app.put('/api/llm/providers/:id'",
    '// DELETE /api/llm/providers/:id'
  );

  assert.match(
    settingsRouteSource,
    /function looksMaskedSecretValue/,
    'settings route must define a masked-secret sentinel guard'
  );
  assert.match(
    putRoute,
    /looksMaskedSecretValue\(req\.body\[f\]\)/,
    'provider update route must reject masked API key values before writing them'
  );
});
