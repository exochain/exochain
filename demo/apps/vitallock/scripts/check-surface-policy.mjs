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
  'VitalLock intake must classify the app outside the canonical Rust trust fabric',
);

const cryptoSource = source('src/lib/crypto.ts');
for (const forbidden of [
  'wasm_generate_x25519_keypair',
  'wasm_ed25519_public_from_secret',
  'wasm_shamir_split',
  'wasm_encrypt_message',
]) {
  assert.equal(
    cryptoSource.includes(forbidden),
    false,
    `VitalLock browser crypto must not call disabled raw-secret WASM entrypoint ${forbidden}`,
  );
}

for (const path of [
  'src/components/Navigation.tsx',
  'src/pages/Login.tsx',
  'src/pages/Settings.tsx',
]) {
  const text = source(path);
  assert.doesNotMatch(
    text,
    /Powered by EXOCHAIN|Trust Fabric:\s*EXOCHAIN|EXOCHAIN CGR Kernel ready/i,
    `${path} must not make unsupported EXOCHAIN trust-fabric claims`,
  );
}

console.log('VitalLock surface policy OK');
