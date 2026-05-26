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
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import ts from 'typescript';

const siteRoot = process.cwd();
const policyPath = path.join(siteRoot, 'src/lib/contact-intake-policy.ts');
const routePath = path.join(siteRoot, 'src/app/api/contact/route.ts');
const storagePath = path.join(siteRoot, 'src/lib/contact-submissions.ts');

assert.ok(existsSync(policyPath), 'contact intake policy module must exist');

const source = readFileSync(policyPath, 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: {
    module: ts.ModuleKind.CommonJS,
    target: ts.ScriptTarget.ES2022,
    esModuleInterop: true,
  },
  fileName: policyPath,
});
const moduleState = { exports: {} };
vm.runInNewContext(compiled.outputText, {
  module: moduleState,
  exports: moduleState.exports,
  require: () => {
    throw new Error('contact-intake-policy.ts must remain dependency-free for policy tests');
  },
}, { filename: policyPath });

const policy = moduleState.exports;

const valid = policy.validateContactPayload({
  name: '  Ada Lovelace  ',
  email: '  ADA@Example.COM ',
  organization: ' Analytical Engines ',
  role: 'Researcher',
  intendedUse: 'Constitutional trust fabric evaluation',
});
assert.equal(valid.ok, true, 'valid contact payload must pass server-side policy');
assert.equal(valid.payload.name, 'Ada Lovelace');
assert.equal(valid.payload.email, 'ada@example.com');
assert.equal(valid.payload.organization, 'Analytical Engines');

const missingEmail = policy.validateContactPayload({ name: 'Ada' });
assert.equal(missingEmail.ok, false);
assert.equal(missingEmail.status, 400);
assert.match(missingEmail.error, /email/i);

const malformedEmail = policy.validateContactPayload({
  name: 'Ada',
  email: 'not-an-email',
});
assert.equal(malformedEmail.ok, false);
assert.equal(malformedEmail.status, 400);
assert.match(malformedEmail.error, /valid email/i);

const oversized = policy.validateContactPayload({
  name: 'Ada',
  email: 'ada@example.com',
  intendedUse: 'x'.repeat(policy.CONTACT_FIELD_LIMITS.intendedUse + 1),
});
assert.equal(oversized.ok, false);
assert.equal(oversized.status, 413);
assert.match(oversized.error, /Intended use/i);

const honeypot = policy.validateContactPayload({
  name: 'Ada',
  email: 'ada@example.com',
  website: 'https://spam.example',
});
assert.equal(honeypot.ok, true);
assert.equal(honeypot.deliver, false, 'honeypot submissions must not queue or send mail');

assert.equal(
  policy.normalizeClientAddress(' 203.0.113.7 '),
  '203.0.113.7',
  'client key may use a single trusted runtime address',
);
assert.equal(
  policy.normalizeClientAddress(' 203.0.113.7, 10.0.0.1 '),
  'unknown',
  'client key must not trust spoofable forwarded address chains',
);
assert.equal(
  policy.normalizeClientAddress(''),
  'unknown',
  'missing client address must collapse to a bounded unknown bucket',
);

const buckets = policy.getContactRateLimitBuckets({
  email: 'ada@example.com',
  clientAddress: '203.0.113.7',
});
assert.equal(
  JSON.stringify(buckets.map((bucket) => bucket.bucket)),
  JSON.stringify([
    'contact:global:minute',
    'contact:ip:203.0.113.7:hour',
    'contact:email:ada@example.com:day',
    'contact:global:day',
  ]),
  'rate limit buckets must cover global, client-address, and normalized-email budgets',
);
assert.ok(buckets.every((bucket) => Number.isInteger(bucket.maxRequests)));
assert.ok(buckets.every((bucket) => Number.isInteger(bucket.windowSeconds)));

const unknownClientBuckets = policy.getContactRateLimitBuckets({
  email: 'ada@example.com',
  clientAddress: 'unknown',
});
assert.ok(
  !unknownClientBuckets.some((bucket) => bucket.bucket === 'contact:ip:unknown:hour'),
  'unknown client identity must not collapse all visitors into a three-request shared IP bucket',
);

const routeSource = readFileSync(routePath, 'utf8');
assert.match(routeSource, /request\.text\(\)/, 'contact route must bound raw body before JSON parse');
assert.doesNotMatch(routeSource, /request\.json\(\)/, 'contact route must not parse unbounded JSON directly');
assert.match(routeSource, /CONTACT_BODY_MAX_BYTES/, 'contact route must enforce a byte limit');
assert.match(routeSource, /assertContactSubmissionRateLimit/, 'contact route must enforce database-backed rate limits');
assert.match(routeSource, /getContactRateLimitBuckets/, 'contact route must derive rate-limit buckets from normalized inputs');
assert.doesNotMatch(
  routeSource,
  /x-forwarded-for|x-real-ip/i,
  'contact route must not trust spoofable forwarded headers for client rate-limit identity',
);
assert.match(
  routeSource,
  /runtimeClientIp\(request\)/,
  'contact route must derive client rate-limit identity from runtime peer metadata',
);

const storageSource = readFileSync(storagePath, 'utf8');
assert.match(storageSource, /site_contact_rate_limits/, 'contact storage must include a rate-limit table');
assert.match(storageSource, /ON CONFLICT \(bucket\) DO UPDATE/, 'contact rate limit must be atomic per bucket');
