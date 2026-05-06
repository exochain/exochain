'use strict';

const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');

const appRoot = join(__dirname, '..');
const pkg = JSON.parse(readFileSync(join(appRoot, 'package.json'), 'utf8'));
const lock = JSON.parse(readFileSync(join(appRoot, 'package-lock.json'), 'utf8'));

const scripts = pkg.scripts || {};

function dependencyRange(name) {
  const range = pkg.dependencies && pkg.dependencies[name];
  assert.ok(range, `${name} must be declared as a production dependency`);
  return range;
}

function lockedPackage(name) {
  const entry = lock.packages && lock.packages[`node_modules/${name}`];
  assert.ok(entry, `${name} must be present in package-lock.json`);
  return entry;
}

function majorFromVersion(version, name) {
  const major = Number.parseInt(String(version).replace(/^[^\d]*/, '').split('.')[0], 10);
  assert.ok(Number.isSafeInteger(major), `${name} version must start with a numeric major`);
  return major;
}

const multerRange = dependencyRange('multer');
assert.ok(
  majorFromVersion(multerRange, 'multer dependency range') >= 2,
  `multer dependency range must require 2.x or newer, got ${multerRange}`,
);

const lockedMulter = lockedPackage('multer');
assert.ok(
  majorFromVersion(lockedMulter.version, 'locked multer') >= 2,
  `package-lock.json must resolve multer 2.x or newer, got ${lockedMulter.version}`,
);
assert.equal(
  lockedMulter.deprecated,
  undefined,
  `locked multer package must not be deprecated: ${lockedMulter.deprecated}`,
);

for (const [name, command] of Object.entries(scripts)) {
  assert.ok(
    !/\bnpm\s+audit\b.*\|\|\s*true/.test(command),
    `${name} must not suppress npm audit failures with || true`,
  );
}

console.log('CommandBase dependency policy OK');
