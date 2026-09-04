#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

fail() {
  printf 'SDK npm release package verifier test failed: %s\n' "$1" >&2
  exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
verifier="$repo_root/tools/verify_npm_release_package.mjs"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/exochain-sdk-verifier-test.XXXXXX")"
trap '/bin/rm -rf -- "$test_root"' EXIT
package_root="$test_root/package"
mkdir -p "$package_root/dist"

node - "$package_root" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const root = process.argv[2];
const modules = [
  'authority/chain', 'authority/index', 'client', 'consent/bailment',
  'consent/index', 'crypto/hash', 'crypto/index', 'errors',
  'governance/decision', 'governance/index', 'governance/vote',
  'identity/did', 'identity/index', 'identity/keypair', 'index',
  'transport/http', 'transport/index', 'types', 'validation',
];
const manifest = {
  name: '@exochain/sdk',
  version: '0.2.6',
  license: 'Apache-2.0',
  type: 'module',
  main: './dist/index.js',
  types: './dist/index.d.ts',
  exports: {
    '.': { types: './dist/index.d.ts', import: './dist/index.js' },
    './identity': { types: './dist/identity/index.d.ts', import: './dist/identity/index.js' },
    './consent': { types: './dist/consent/index.d.ts', import: './dist/consent/index.js' },
    './governance': { types: './dist/governance/index.d.ts', import: './dist/governance/index.js' },
    './authority': { types: './dist/authority/index.d.ts', import: './dist/authority/index.js' },
    './crypto': { types: './dist/crypto/index.d.ts', import: './dist/crypto/index.js' },
  },
  files: ['LICENSE', 'dist', 'README.md'],
  scripts: { build: 'tsc', test: 'node --test', lint: 'tsc --noEmit' },
};
fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify(manifest));
fs.writeFileSync(path.join(root, 'LICENSE'), 'Apache License 2.0\n');
fs.writeFileSync(path.join(root, 'README.md'), '# EXOCHAIN SDK\n' + 'Public SDK documentation.\n'.repeat(50));
for (const moduleName of modules) {
  for (const extension of ['.d.ts', '.d.ts.map', '.js', '.js.map']) {
    const file = path.join(root, 'dist', `${moduleName}${extension}`);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, `// ${moduleName}${extension}\n${'export const verified = true;\n'.repeat(8)}`);
  }
}
NODE

RELEASE_EXPECTED_VERSION=0.2.6 node "$verifier" sdk "$package_root" >/dev/null \
  || fail "exact useful SDK inventory and entrypoints were rejected"

wrong_export="$test_root/wrong-export"
/bin/cp -R "$package_root" "$wrong_export"
node - "$wrong_export/package.json" <<'NODE'
const fs=require('node:fs'); const file=process.argv[2]; const value=JSON.parse(fs.readFileSync(file));
value.exports['./identity'].import='./dist/identity/missing.js'; fs.writeFileSync(file,JSON.stringify(value));
NODE
if RELEASE_EXPECTED_VERSION=0.2.6 node "$verifier" sdk "$wrong_export" >/dev/null 2>&1; then
  fail "SDK export pointing to a missing/unreviewed file was accepted"
fi

extra_file="$test_root/extra-file"
/bin/cp -R "$package_root" "$extra_file"
printf 'malicious extra\n' > "$extra_file/dist/postinstall.js"
if RELEASE_EXPECTED_VERSION=0.2.6 node "$verifier" sdk "$extra_file" >/dev/null 2>&1; then
  fail "extra SDK dist file was accepted"
fi

placeholder="$test_root/placeholder"
/bin/cp -R "$package_root" "$placeholder"
: > "$placeholder/dist/index.js"
if RELEASE_EXPECTED_VERSION=0.2.6 node "$verifier" sdk "$placeholder" >/dev/null 2>&1; then
  fail "placeholder SDK entrypoint was accepted"
fi

printf 'SDK npm release package verifier test passed\n'
