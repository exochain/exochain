#!/usr/bin/env node
// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const MAX_JSON_BYTES = 1024 * 1024;
const MAX_EXPECTED_MANIFEST_BYTES = 8 * 1024 * 1024;
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES = 256 * 1024 * 1024;
const MAX_FILES = 10_000;
const MAX_DEPTH = 64;

function fail(message) {
  console.error(`npm release package verification failed: ${message}`);
  process.exit(1);
}

class StrictJsonScanner {
  constructor(text) {
    this.text = text;
    this.index = 0;
  }

  error(message) {
    throw new Error(message);
  }

  whitespace() {
    while (/\s/u.test(this.text[this.index] ?? '')) this.index += 1;
  }

  string() {
    const start = this.index;
    if (this.text[this.index] !== '"') this.error('expected string');
    this.index += 1;
    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index);
      if (code === 0x22) {
        this.index += 1;
        return JSON.parse(this.text.slice(start, this.index));
      }
      if (code < 0x20) this.error('unescaped control character');
      if (code === 0x5c) {
        this.index += 1;
        const escape = this.text[this.index];
        if (escape === 'u') {
          if (!/^[0-9a-fA-F]{4}$/u.test(this.text.slice(this.index + 1, this.index + 5))) {
            this.error('malformed Unicode escape');
          }
          this.index += 5;
          continue;
        }
        if (!['"', '\\', '/', 'b', 'f', 'n', 'r', 't'].includes(escape)) {
          this.error('malformed escape');
        }
      }
      this.index += 1;
    }
    this.error('unterminated string');
  }

  value(depth) {
    if (depth > MAX_DEPTH) this.error('nesting exceeds the accepted depth');
    this.whitespace();
    const character = this.text[this.index];
    if (character === '{') return this.object(depth + 1);
    if (character === '[') return this.array(depth + 1);
    if (character === '"') {
      this.string();
      return;
    }
    for (const literal of ['true', 'false', 'null']) {
      if (this.text.startsWith(literal, this.index)) {
        this.index += literal.length;
        return;
      }
    }
    const number = this.text.slice(this.index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u)?.[0];
    if (number !== undefined) {
      if (!Number.isFinite(Number(number))) this.error('non-finite number');
      this.index += number.length;
      return;
    }
    this.error('unexpected token');
  }

  object(depth) {
    this.index += 1;
    this.whitespace();
    const keys = new Set();
    if (this.text[this.index] === '}') {
      this.index += 1;
      return;
    }
    for (;;) {
      const key = this.string();
      if (keys.has(key)) this.error(`duplicate object key ${JSON.stringify(key)}`);
      keys.add(key);
      this.whitespace();
      if (this.text[this.index] !== ':') this.error("expected ':'");
      this.index += 1;
      this.value(depth);
      this.whitespace();
      if (this.text[this.index] === '}') {
        this.index += 1;
        return;
      }
      if (this.text[this.index] !== ',') this.error("expected ',' or '}'");
      this.index += 1;
      this.whitespace();
    }
  }

  array(depth) {
    this.index += 1;
    this.whitespace();
    if (this.text[this.index] === ']') {
      this.index += 1;
      return;
    }
    for (;;) {
      this.value(depth);
      this.whitespace();
      if (this.text[this.index] === ']') {
        this.index += 1;
        return;
      }
      if (this.text[this.index] !== ',') this.error("expected ',' or ']'");
      this.index += 1;
      this.whitespace();
    }
  }

  scan() {
    this.whitespace();
    this.value(0);
    this.whitespace();
    if (this.index !== this.text.length) this.error('trailing data');
  }
}

function stableStat(value) {
  return [value.dev, value.ino, value.mode, value.nlink, value.size, value.mtimeNs, value.ctimeNs].join(':');
}

function readRegularFile(filePath, sizeLimit, label) {
  if (typeof fs.constants.O_NOFOLLOW !== 'number' || typeof fs.constants.O_NONBLOCK !== 'number') {
    fail('platform lacks secure file-open flags');
  }
  let descriptor;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
    );
  } catch (error) {
    fail(`cannot securely open ${label}: ${error.message}`);
  }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n) {
      fail(`${label} must be a regular non-symlink, non-hardlinked file`);
    }
    if (before.size < 0n || before.size > BigInt(sizeLimit)) {
      fail(`${label} size is outside the accepted range`);
    }
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, null);
      if (count === 0) fail(`${label} was truncated while it was read`);
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (stableStat(before) !== stableStat(after)) fail(`${label} changed while it was read`);
    return bytes;
  } finally {
    fs.closeSync(descriptor);
  }
}

function parseStrictJson(bytes) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    new StrictJsonScanner(text).scan();
    return JSON.parse(text);
  } catch (error) {
    fail(`package.json is not valid strict JSON: ${error.message}`);
  }
}

const [profile, requestedPackageDir] = process.argv.slice(2);
if (!['wasm', 'llm', 'llm-source'].includes(profile) || !requestedPackageDir) {
  fail('usage: verify_npm_release_package.mjs <wasm|llm|llm-source> <package-directory>');
}

let packageDir;
try {
  if (requestedPackageDir.includes('\0') || requestedPackageDir.includes('\n')) {
    fail('package directory path is unsafe');
  }
  const requestedStat = fs.lstatSync(requestedPackageDir);
  if (!requestedStat.isDirectory() || requestedStat.isSymbolicLink()) {
    fail('requested package directory must be a real directory, not a symlink');
  }
  packageDir = fs.realpathSync(requestedPackageDir);
} catch (error) {
  fail(`cannot resolve package directory: ${error.message}`);
}
const packageDirStat = fs.lstatSync(packageDir);
if (!packageDirStat.isDirectory() || packageDirStat.isSymbolicLink()) {
  fail('package directory must be a real directory, not a symlink');
}

const packageJsonPath = path.join(packageDir, 'package.json');
let manifest;
manifest = parseStrictJson(readRegularFile(packageJsonPath, MAX_JSON_BYTES, 'package.json'));
if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
  fail('package.json must contain an object');
}
if (manifest.private === true) {
  fail('release package must not be private');
}
const expectedVersion = process.env.RELEASE_EXPECTED_VERSION;
if (!expectedVersion || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z-]*(?:\.[0-9A-Za-z][0-9A-Za-z-]*)*)?$/.test(expectedVersion)) {
  fail('RELEASE_EXPECTED_VERSION must be an exact semantic version');
}
if (manifest.version !== expectedVersion) {
  fail(`package version ${manifest.version} does not match release ${expectedVersion}`);
}
if (manifest.license !== 'Apache-2.0') {
  fail('release package license must be Apache-2.0');
}
if (Object.hasOwn(manifest, 'publishConfig')) {
  fail('publishConfig is forbidden because the workflow binds publication policy');
}

const profilePolicy = profile === 'wasm'
  ? {
      name: '@exochain/exochain-wasm',
      files: [
        'LICENSE',
        'exochain_wasm.d.ts',
        'exochain_wasm.js',
        'exochain_wasm_bg.wasm',
      ],
      forbidAllScripts: true,
    }
  : {
      name: '@exochain/llm-proxy',
      files: ['LICENSE', 'dist', 'README.md', 'AGENTS.md', 'examples', 'snippets'],
      forbidAllScripts: false,
      strictRootInventory: profile === 'llm',
    };
if (profile === 'wasm') {
  profilePolicy.strictRootInventory = true;
}

if (manifest.name !== profilePolicy.name) {
  fail(`package name ${manifest.name} does not match ${profilePolicy.name}`);
}
if (!Array.isArray(manifest.files) || manifest.files.some((entry) => typeof entry !== 'string')) {
  fail('package files must be an explicit string allowlist');
}
const actualFiles = [...manifest.files].sort();
const expectedFiles = [...profilePolicy.files].sort();
if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) {
  fail(`package files must equal the reviewed ${profile} release allowlist`);
}

const scripts = manifest.scripts ?? {};
if (!scripts || typeof scripts !== 'object' || Array.isArray(scripts)) {
  fail('package scripts must be an object when present');
}
const scriptNames = Object.keys(scripts);
if (profilePolicy.forbidAllScripts && scriptNames.length !== 0) {
  fail('generated WASM packages must not contain scripts');
}
const forbiddenLifecycleHooks = new Set([
  'dependencies',
  'install',
  'postinstall',
  'postpack',
  'postprepare',
  'postpublish',
  'preinstall',
  'prepack',
  'prepare',
  'preprepare',
  'prepublish',
  'prepublishOnly',
  'publish',
]);
for (const scriptName of scriptNames) {
  if (forbiddenLifecycleHooks.has(scriptName)) {
    fail(`npm lifecycle hook is forbidden in a release package: ${scriptName}`);
  }
}

const forbiddenControlFiles = new Set([
  '.gitignore',
  '.npmignore',
  '.npmrc',
  '.pnpmfile.cjs',
  '.yarnrc',
  '.yarnrc.yml',
  'npmrc',
  'pnpm-workspace.yaml',
]);

const packageManifestRecords = [];
let packageFileCount = 0;
let packageTotalBytes = 0;

function recordPackageFile(candidatePath) {
  const relativePath = path.relative(packageDir, candidatePath);
  const bytes = readRegularFile(candidatePath, MAX_FILE_BYTES, `staged package file ${relativePath}`);
  packageFileCount += 1;
  packageTotalBytes += bytes.length;
  if (packageFileCount > MAX_FILES || packageTotalBytes > MAX_TOTAL_BYTES) {
    fail('staged package exceeds the accepted file-count or aggregate-size limit');
  }
  const digest = crypto.createHash('sha256').update(bytes).digest('hex');
  packageManifestRecords.push(`f\t${relativePath}\t${digest}\0`);
}

function inspectStagedPath(candidatePath, depth = 0) {
  if (depth > MAX_DEPTH) fail('staged package nesting exceeds the accepted depth');
  const relativePath = path.relative(packageDir, candidatePath);
  if (!relativePath || relativePath.startsWith('..') || path.isAbsolute(relativePath) || relativePath.includes('\n')) {
    fail(`staged package contains an unsafe path: ${candidatePath}`);
  }
  const entryName = path.basename(candidatePath);
  if (forbiddenControlFiles.has(entryName)) {
    fail(`staged package contains forbidden package-manager configuration: ${candidatePath}`);
  }

  const stat = fs.lstatSync(candidatePath);
  if (stat.isSymbolicLink()) {
    fail(`staged package paths must not be symbolic links: ${candidatePath}`);
  }
  if (stat.isDirectory()) {
    for (const child of fs.readdirSync(candidatePath)) {
      inspectStagedPath(path.join(candidatePath, child), depth + 1);
    }
    return;
  }
  if (!stat.isFile()) {
    fail(`staged package paths must be regular files or directories: ${candidatePath}`);
  }
  recordPackageFile(candidatePath);
}

for (const entry of fs.readdirSync(packageDir)) {
  if (forbiddenControlFiles.has(entry)) {
    fail(`package root contains forbidden package-manager configuration: ${entry}`);
  }
  if (entry.includes('\n')) {
    fail('package root contains a newline-bearing path');
  }
  if (profilePolicy.strictRootInventory && entry !== 'package.json' && !profilePolicy.files.includes(entry)) {
    fail(`package root contains a file outside the reviewed release inventory: ${entry}`);
  }
}
for (const stagedEntry of profilePolicy.files) {
  const stagedPath = path.join(packageDir, stagedEntry);
  if (!fs.existsSync(stagedPath)) {
    fail(`reviewed staged package path is missing: ${stagedEntry}`);
  }
  inspectStagedPath(stagedPath);
}

recordPackageFile(packageJsonPath);
packageManifestRecords.sort();
const packageManifest = Buffer.from(packageManifestRecords.join(''), 'utf8');
const manifestOutput = process.env.RELEASE_PACKAGE_MANIFEST_OUTPUT;
const expectedManifestPath = process.env.RELEASE_EXPECTED_PACKAGE_MANIFEST;
if (manifestOutput && expectedManifestPath) {
  fail('only one package-manifest operation may be requested');
}
if (manifestOutput) {
  if (!path.isAbsolute(manifestOutput) || manifestOutput.includes('\n')) {
    fail('RELEASE_PACKAGE_MANIFEST_OUTPUT must be an absolute safe path');
  }
  const resolvedParent = fs.realpathSync(path.dirname(manifestOutput));
  if (resolvedParent === packageDir || resolvedParent.startsWith(`${packageDir}${path.sep}`)) {
    fail('package manifest output must be outside the staged package');
  }
  fs.writeFileSync(manifestOutput, packageManifest, { flag: 'wx', mode: 0o600 });
}
if (expectedManifestPath) {
  if (!path.isAbsolute(expectedManifestPath) || expectedManifestPath.includes('\n')) {
    fail('RELEASE_EXPECTED_PACKAGE_MANIFEST must be an absolute safe path');
  }
  let expectedManifest;
  try {
    expectedManifest = readRegularFile(
      expectedManifestPath,
      MAX_EXPECTED_MANIFEST_BYTES,
      'expected package manifest',
    );
  } catch (error) {
    fail(`cannot read expected package manifest: ${error.message}`);
  }
  if (!packageManifest.equals(expectedManifest)) {
    fail('packed package file/type/byte manifest differs from the reviewed staged package');
  }
}

console.log(`Verified ${profilePolicy.name} package controls and staged-file allowlist`);
