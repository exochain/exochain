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

import { Pool, type PoolClient } from 'pg';
import type { ContactRateLimitBucket } from './contact-intake-policy';

export type ContactSubmissionInput = {
  name: string;
  email: string;
  organization: string;
  role: string;
  intendedUse: string;
  userAgent: string;
  forwardedFor: string;
};

export type ContactSubmission = ContactSubmissionInput & {
  id: string;
  submittedAt: string;
  notificationStatus: string;
  notificationError: string;
};

type ContactSubmissionRow = {
  id: string;
  submitted_at: string;
  name: string;
  email: string;
  organization: string;
  role: string;
  intended_use: string;
  user_agent: string;
  forwarded_for: string;
  notification_status: string;
  notification_error: string;
};

type ContactRateLimitRow = {
  request_count: number | string;
};

type ContactSubmissionPoolGlobal = typeof globalThis & {
  __exoContactSubmissionPool?: Pool;
  __exoContactSubmissionSchemaReady?: Promise<void>;
};

const CONTACT_DATABASE_URL_ENV = 'CONTACT_DATABASE_URL';
const DATABASE_URL_ENV = 'DATABASE_URL';
const MAX_TEXT_LENGTH = 1000;

function normalizeSecret(value: string | undefined): string {
  let normalized = value?.trim() || '';
  const hasDoubleQuotes = normalized.startsWith('"') && normalized.endsWith('"');
  const hasSingleQuotes = normalized.startsWith("'") && normalized.endsWith("'");

  if (normalized.length >= 2 && (hasDoubleQuotes || hasSingleQuotes)) {
    normalized = normalized.slice(1, -1).trim();
  }

  return normalized;
}

function getDatabaseUrl(): string {
  const contactDatabaseUrl = normalizeSecret(process.env[CONTACT_DATABASE_URL_ENV]);
  const databaseUrl = normalizeSecret(process.env[DATABASE_URL_ENV]);
  const resolved = contactDatabaseUrl || databaseUrl;

  if (!resolved) {
    throw new Error(
      `Contact submission database is not configured. Set ${CONTACT_DATABASE_URL_ENV} on the site service.`,
    );
  }

  return resolved;
}

function getPool(): Pool {
  const globalState = globalThis as ContactSubmissionPoolGlobal;

  if (!globalState.__exoContactSubmissionPool) {
    globalState.__exoContactSubmissionPool = new Pool({
      connectionString: getDatabaseUrl(),
      max: 4,
      ssl: { rejectUnauthorized: false },
    });
  }

  return globalState.__exoContactSubmissionPool;
}

function truncate(value: string): string {
  return value.slice(0, MAX_TEXT_LENGTH);
}

function fromRow(row: ContactSubmissionRow): ContactSubmission {
  return {
    id: row.id,
    submittedAt: row.submitted_at,
    name: row.name,
    email: row.email,
    organization: row.organization,
    role: row.role,
    intendedUse: row.intended_use,
    userAgent: row.user_agent,
    forwardedFor: row.forwarded_for,
    notificationStatus: row.notification_status,
    notificationError: row.notification_error,
  };
}

async function ensureSchemaWithClient(client: PoolClient): Promise<void> {
  await client.query(`
    CREATE TABLE IF NOT EXISTS site_contact_submissions (
      id BIGSERIAL PRIMARY KEY,
      submitted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      organization TEXT NOT NULL DEFAULT '',
      role TEXT NOT NULL DEFAULT '',
      intended_use TEXT NOT NULL DEFAULT '',
      user_agent TEXT NOT NULL DEFAULT '',
      forwarded_for TEXT NOT NULL DEFAULT '',
      notification_status TEXT NOT NULL DEFAULT 'pending',
      notification_error TEXT NOT NULL DEFAULT ''
    )
  `);

  await client.query(`
    CREATE INDEX IF NOT EXISTS site_contact_submissions_submitted_at_idx
      ON site_contact_submissions (submitted_at DESC, id DESC)
  `);

  await client.query(`
    CREATE INDEX IF NOT EXISTS site_contact_submissions_email_idx
      ON site_contact_submissions (email)
  `);

  await client.query(`
    CREATE TABLE IF NOT EXISTS site_contact_rate_limits (
      bucket TEXT PRIMARY KEY,
      window_started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      request_count INTEGER NOT NULL DEFAULT 0
    )
  `);

  await client.query(`
    CREATE INDEX IF NOT EXISTS site_contact_rate_limits_window_idx
      ON site_contact_rate_limits (window_started_at)
  `);
}

export async function ensureContactSubmissionSchema(): Promise<void> {
  const globalState = globalThis as ContactSubmissionPoolGlobal;

  if (!globalState.__exoContactSubmissionSchemaReady) {
    globalState.__exoContactSubmissionSchemaReady = (async () => {
      const client = await getPool().connect();
      try {
        await ensureSchemaWithClient(client);
      } finally {
        client.release();
      }
    })();
  }

  return globalState.__exoContactSubmissionSchemaReady;
}

export async function createContactSubmission(
  input: ContactSubmissionInput,
): Promise<ContactSubmission> {
  await ensureContactSubmissionSchema();

  const result = await getPool().query<ContactSubmissionRow>(
    `
      INSERT INTO site_contact_submissions (
        name,
        email,
        organization,
        role,
        intended_use,
        user_agent,
        forwarded_for
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING
        id::text,
        submitted_at::text,
        name,
        email,
        organization,
        role,
        intended_use,
        user_agent,
        forwarded_for,
        notification_status,
        notification_error
    `,
    [
      truncate(input.name),
      truncate(input.email),
      truncate(input.organization),
      truncate(input.role),
      truncate(input.intendedUse),
      truncate(input.userAgent),
      truncate(input.forwardedFor),
    ],
  );

  const row = result.rows[0];
  if (!row) {
    throw new Error('Contact submission insert did not return a row.');
  }

  return fromRow(row);
}

async function incrementContactRateLimit(
  bucket: ContactRateLimitBucket,
): Promise<number> {
  await ensureContactSubmissionSchema();

  const result = await getPool().query<ContactRateLimitRow>(
    `
      INSERT INTO site_contact_rate_limits (
        bucket,
        window_started_at,
        request_count
      )
      VALUES ($1, CURRENT_TIMESTAMP, 1)
      ON CONFLICT (bucket) DO UPDATE
      SET window_started_at = CASE
            WHEN site_contact_rate_limits.window_started_at <=
              CURRENT_TIMESTAMP - ($2::integer * INTERVAL '1 second')
            THEN CURRENT_TIMESTAMP
            ELSE site_contact_rate_limits.window_started_at
          END,
          request_count = CASE
            WHEN site_contact_rate_limits.window_started_at <=
              CURRENT_TIMESTAMP - ($2::integer * INTERVAL '1 second')
            THEN 1
            ELSE site_contact_rate_limits.request_count + 1
          END
      RETURNING request_count
    `,
    [bucket.bucket, bucket.windowSeconds],
  );

  const row = result.rows[0];
  if (!row) {
    throw new Error('Contact rate-limit update did not return a row.');
  }

  return Number(row.request_count);
}

export async function assertContactSubmissionRateLimit(
  buckets: ContactRateLimitBucket[],
): Promise<boolean> {
  for (const bucket of buckets) {
    const requestCount = await incrementContactRateLimit(bucket);
    if (requestCount > bucket.maxRequests) {
      return false;
    }
  }

  return true;
}

export async function updateContactSubmissionNotification(
  id: string,
  status: 'sent' | 'not_configured' | 'failed',
  error: string,
): Promise<void> {
  await ensureContactSubmissionSchema();

  await getPool().query(
    `
      UPDATE site_contact_submissions
      SET notification_status = $2,
          notification_error = $3
      WHERE id = $1
    `,
    [id, status, truncate(error)],
  );
}

export async function listRecentContactSubmissions(): Promise<ContactSubmission[]> {
  await ensureContactSubmissionSchema();

  const result = await getPool().query<ContactSubmissionRow>(`
    SELECT
      id::text,
      submitted_at::text,
      name,
      email,
      organization,
      role,
      intended_use,
      user_agent,
      forwarded_for,
      notification_status,
      notification_error
    FROM site_contact_submissions
    ORDER BY submitted_at DESC, id DESC
    LIMIT 50
  `);

  return result.rows.map(fromRow);
}
