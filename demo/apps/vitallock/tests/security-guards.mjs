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

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');

function readSource(path) {
  return readFileSync(resolve(root, path), 'utf8');
}

const login = readSource('src/pages/Login.tsx');
const settings = readSource('src/pages/Settings.tsx');
const compose = readSource('src/pages/Compose.tsx');
const auth = readSource('src/hooks/useAuth.ts');
const crypto = readSource('src/lib/crypto.ts');

assert(
  !login.includes('ed25519PublicHex = ed25519SecretHex'),
  'VitalLock login must not publish the passphrase-derived signing seed as an Ed25519 public key',
);

assert(
  !settings.includes('auth?.ed25519SecretHex') && !settings.includes('auth?.ed25519PublicHex'),
  'VitalLock settings must not display or copy passphrase-derived Ed25519 key material',
);

assert(
  !compose.includes('auth!.ed25519SecretHex') && !compose.includes('auth.ed25519SecretHex'),
  'VitalLock compose must not pass a session-stored passphrase hash as a signing secret',
);

assert(
  !auth.includes('ed25519SecretHex: string;') && !auth.includes('ed25519PublicHex: string;'),
  'VitalLock auth state must not persist passphrase-derived Ed25519 key material',
);

assert(
  !crypto.includes('wasm_ed25519_public_from_secret') && !crypto.includes('senderSigningKeyHex'),
  'VitalLock crypto wrapper must not expose raw-secret public derivation or raw signing-key parameters',
);
