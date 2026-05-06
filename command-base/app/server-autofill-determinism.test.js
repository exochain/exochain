const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const serverSource = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');

function sourceBetween(startMarker, endMarker) {
  const start = serverSource.indexOf(startMarker);
  assert.notEqual(start, -1, `${startMarker} must exist`);
  const end = serverSource.indexOf(endMarker, start);
  assert.notEqual(end, -1, `${endMarker} must exist after ${startMarker}`);
  return serverSource.slice(start, end);
}

test('project chamber autofill ranks available seeds deterministically', () => {
  const section = sourceBetween('function autoFillProjectChamber', 'function superviseProjectImprovement');

  assert.doesNotMatch(
    section,
    /Math\.random|sort\(\(\)\s*=>\s*Math\.random\(\)\s*-\s*0\.5\)/,
    'project chamber autofill must not randomly shuffle candidate seeds'
  );
  assert.match(
    section,
    /rankTemplatesDeterministically/,
    'project chamber autofill must use the shared deterministic template ordering helper'
  );
});

test('brainstorm autofill ranks available templates deterministically', () => {
  const section = sourceBetween('function autoFillBrainstorm', '// Fill brainstorm on startup');

  assert.doesNotMatch(
    section,
    /Math\.random|sort\(\(\)\s*=>\s*Math\.random\(\)\s*-\s*0\.5\)/,
    'brainstorm autofill must not randomly shuffle candidate templates'
  );
  assert.match(
    section,
    /rankTemplatesDeterministically/,
    'brainstorm autofill must use the shared deterministic template ordering helper'
  );
});

test('server source has no random-sort autofill shuffles', () => {
  assert.doesNotMatch(
    serverSource,
    /sort\(\(\)\s*=>\s*Math\.random\(\)\s*-\s*0\.5\)/,
    'CommandBase server must not use random comparator shuffles for deterministic work selection'
  );
});
