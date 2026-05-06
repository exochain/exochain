'use strict';

const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');

const commandBaseRoot = join(__dirname, '..', '..');
const readme = readFileSync(join(commandBaseRoot, 'README.md'), 'utf8');
const intake = readFileSync(join(commandBaseRoot, 'ADJACENT-SURFACE-INTAKE.md'), 'utf8');
const canonicalBoundaryPattern = /not the canonical\s+EXOCHAIN\s+Rust trust fabric/i;

assert.match(
  intake,
  canonicalBoundaryPattern,
  'CommandBase intake must classify the surface outside the canonical Rust trust fabric',
);

assert.match(
  readme,
  /adjacent/i,
  'CommandBase README must identify the surface as adjacent',
);
assert.match(
  readme,
  canonicalBoundaryPattern,
  'CommandBase README must not imply it is the canonical Rust trust fabric',
);
assert.doesNotMatch(
  readme,
  /no overrides,\s*no exceptions/i,
  'CommandBase README must not make unconditional kernel-enforcement claims for the adjacent surface',
);

console.log('CommandBase surface policy OK');
