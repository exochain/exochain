#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
  printf 'commandbase supply-chain test failed: %s\n' "$1" >&2
  exit 1
}

manifest="command-base/app/package.json"
lockfile="command-base/app/package-lock.json"

[[ -f "$manifest" ]] || fail "$manifest is missing"
[[ -f "$lockfile" ]] || fail "$lockfile is missing"

node <<'NODE'
const fs = require('fs');

const fail = (message) => {
  console.error(`commandbase supply-chain test failed: ${message}`);
  process.exit(1);
};

const pkg = JSON.parse(fs.readFileSync('command-base/app/package.json', 'utf8'));
const lock = JSON.parse(fs.readFileSync('command-base/app/package-lock.json', 'utf8'));

const scripts = pkg.scripts || {};
const preinstall = scripts.preinstall || '';

if (scripts['audit:check'] !== 'npm audit --audit-level=high') {
  fail('command-base/app must keep a high-severity npm audit check');
}

if (preinstall && /(^|[;&|])\s*true\b|\|\|/.test(preinstall)) {
  fail('preinstall must not suppress npm audit failures with || true or a true fallback');
}

if (preinstall && preinstall !== 'npm audit --audit-level=critical') {
  fail('preinstall must fail closed with npm audit --audit-level=critical when present');
}

const dependencies = pkg.dependencies || {};
if (dependencies.multer !== '2.1.1') {
  fail(`multer must be exactly pinned to 2.1.1; found ${dependencies.multer || '<missing>'}`);
}

const rootPackage = lock.packages && lock.packages[''];
if (!rootPackage || !rootPackage.dependencies || rootPackage.dependencies.multer !== '2.1.1') {
  fail('package-lock root dependencies must pin multer to 2.1.1');
}

const lockedMulter = lock.packages && lock.packages['node_modules/multer'];
if (!lockedMulter || lockedMulter.version !== '2.1.1') {
  fail(`package-lock must resolve node_modules/multer to 2.1.1; found ${lockedMulter ? lockedMulter.version : '<missing>'}`);
}
NODE

printf 'commandbase supply-chain test passed\n'
