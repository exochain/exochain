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

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));

function read(relativePath) {
  return readFileSync(join(root, relativePath), 'utf8');
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

const auth = read('src/lib/auth.ts');
const middleware = read('src/middleware.ts');
const intranetLogin = read('src/app/internal-login/page.tsx');
const extranetLogin = read('src/app/login/page.tsx');

assert(
  auth.includes('createSessionCookieValue') && auth.includes('verifySessionCookieValue'),
  'auth library must seal and verify signed session cookie values',
);
assert(
  auth.includes('EXO_SITE_SESSION_SECRET') && auth.includes('timingSafeEqual'),
  'server session verification must use a configured HMAC secret and constant-time comparison',
);
assert(
  !auth.includes('JSON.parse(raw) as Partial<Session>'),
  'server session reads must not trust raw JSON cookies',
);

assert(
  middleware.includes('async function verifySessionCookieValue') && middleware.includes('EXO_SITE_SESSION_SECRET'),
  'middleware must verify signed session cookies before granting protected surface access',
);
assert(
  !middleware.includes('return JSON.parse(raw) as SessionShape'),
  'middleware must not trust raw JSON cookies',
);
assert(
  middleware.includes("matcher: ['/app/:path*', '/login', '/internal/:path*', '/internal-login']"),
  'middleware matcher must include direct login endpoints as protected dev-login boundaries',
);
const directLoginBypass = middleware.indexOf("pathname === '/login' || pathname === '/internal-login'");
const internalPrefixCheck = middleware.indexOf("pathname.startsWith('/internal')");
assert(
  directLoginBypass !== -1 && internalPrefixCheck !== -1 && directLoginBypass < internalPrefixCheck,
  'middleware must handle direct login endpoints before the /internal prefix check',
);

for (const [name, source] of [
  ['extranet login', extranetLogin],
  ['intranet login', intranetLogin],
]) {
  assert(
    source.includes('isDevLoginEnabled') && source.includes('notFound()'),
    `${name} must fail closed unless local development login is explicitly enabled`,
  );
  assert(
    source.includes('createSessionCookieValue') && !source.includes('JSON.stringify(session)'),
    `${name} must write only signed session cookies`,
  );
}

assert(
  !intranetLogin.includes("?? 'super_admin'") && !intranetLogin.includes('defaultValue="super_admin"'),
  'intranet development login must not default to super_admin',
);

console.log('Auth boundary guard passed.');
