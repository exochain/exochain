import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const appRoot = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const source = (path) => readFileSync(join(appRoot, path), 'utf8');

const intake = source('ADJACENT-SURFACE-INTAKE.md');
assert.match(
  intake,
  /not the canonical\s+EXOCHAIN\s+Rust trust fabric/i,
  'LiveSafe intake must classify the app outside the canonical Rust trust fabric',
);

for (const path of [
  'src/pages/Login.tsx',
  'src/pages/Landing.tsx',
  'src/components/Navigation.tsx',
  'src/pages/Settings.tsx',
]) {
  const text = source(path);
  assert.doesNotMatch(
    text,
    /@\/wasm\/exochain_wasm|wasm_generate_x25519_keypair|Powered by EXOCHAIN|Trust Fabric:\s*EXOCHAIN|Secure kernel ready/i,
    `${path} must not call disabled WASM entrypoints or make unsupported EXOCHAIN trust-fabric claims`,
  );
}

console.log('LiveSafe surface policy OK');
