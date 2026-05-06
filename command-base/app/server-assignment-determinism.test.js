'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

function serverSection(startMarker, endMarker) {
  const source = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
  const start = source.indexOf(startMarker);
  assert.notEqual(start, -1, `${startMarker} must exist`);
  const end = source.indexOf(endMarker, start);
  assert.notEqual(end, -1, `${endMarker} must follow ${startMarker}`);
  return source.slice(start, end);
}

test('assignMember routes deterministically without SQL or runtime randomness', () => {
  const section = serverSection('function assignMember', 'function findImprovementAssignee');

  assert.doesNotMatch(section, /ORDER\s+BY\s+RANDOM\s*\(\)/i);
  assert.doesNotMatch(section, /,\s*RANDOM\s*\(\)/i);
  assert.doesNotMatch(section, /Math\.random\s*\(/);
  assert.match(
    section,
    /ORDER\s+BY\s+[\s\S]*running_tasks\s+ASC,[\s\S]*completed_tasks\s+ASC,[\s\S]*tm\.id\s+ASC/i,
    'primary assignee query must use load ordering and stable member-id tie-break'
  );
  assert.match(
    section,
    /ORDER\s+BY\s+[\s\S]*running_tasks\s+ASC,[\s\S]*completed_tasks\s+ASC,[\s\S]*id\s+ASC/i,
    'fallback assignee query must use load ordering and stable member-id tie-break'
  );
});

test('assignMember deterministically prefers first load-sorted affinity member', () => {
  const section = serverSection('function assignMember', 'function findImprovementAssignee');

  assert.match(section, /if\s*\(\s*affinityMember\s*\)\s*\{\s*return affinityMember;\s*\}/);
  assert.doesNotMatch(section, /70\/30|growth opportunity|chance/i);
});
