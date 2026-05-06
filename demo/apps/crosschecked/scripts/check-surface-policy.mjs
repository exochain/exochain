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
  'CrossChecked intake must classify the app outside the canonical Rust trust fabric',
);

for (const path of [
  'index.html',
  'src/pages/Landing.tsx',
  'src/pages/Settings.tsx',
]) {
  const text = source(path);
  assert.doesNotMatch(
    text,
    /EXOCHAIN\s+Trust Fabric|EXOCHAIN CGR Kernel|Powered by\s*<|Constitutional governance/i,
    `${path} must not make unsupported EXOCHAIN trust-fabric claims`,
  );
}

console.log('CrossChecked surface policy OK');
