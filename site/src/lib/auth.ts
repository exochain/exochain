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

import { cookies } from 'next/headers';
import { createHmac, timingSafeEqual } from 'node:crypto';
import {
  EXTRANET_ROLES,
  INTRANET_ROLES,
  isExtranetRole,
  isIntranetRole,
  type ExtranetRole,
  type IntranetRole,
  type Role
} from './roles';

export const SESSION_COOKIE = 'exo-session';
const SESSION_SECRET_ENV = 'EXO_SITE_SESSION_SECRET';
const DEV_LOGIN_ENV = 'EXO_SITE_ENABLE_DEV_LOGIN';

export interface Session {
  userId: string;
  email: string;
  role: Role;
  surface: 'extranet' | 'intranet';
  org?: string;
}

function getSessionSecret(): string | null {
  const secret = process.env[SESSION_SECRET_ENV];
  if (typeof secret !== 'string' || Buffer.byteLength(secret, 'utf8') < 32) {
    return null;
  }
  return secret;
}

export function isDevLoginEnabled(): boolean {
  return process.env[DEV_LOGIN_ENV] === '1' && process.env.NODE_ENV !== 'production';
}

function normalizeSession(input: unknown): Session | null {
  if (!input || typeof input !== 'object') return null;

  const parsed = input as Record<string, unknown>;
  if (
    typeof parsed.userId !== 'string' ||
    typeof parsed.email !== 'string' ||
    typeof parsed.role !== 'string' ||
    (parsed.surface !== 'extranet' && parsed.surface !== 'intranet')
  ) {
    return null;
  }

  const role = parsed.role as Role;
  const surface = parsed.surface;
  if (surface === 'extranet' && !isExtranetRole(role)) return null;
  if (surface === 'intranet' && !isIntranetRole(role)) return null;

  const session: Session = {
    userId: parsed.userId,
    email: parsed.email,
    role,
    surface
  };
  if (typeof parsed.org === 'string' && parsed.org.length > 0) {
    session.org = parsed.org;
  }
  return session;
}

function canonicalSessionPayload(session: Session): string {
  return JSON.stringify({
    email: session.email,
    org: session.org ?? null,
    role: session.role,
    surface: session.surface,
    userId: session.userId
  });
}

function signPayload(payload: string, secret: string): string {
  return createHmac('sha256', secret).update(payload).digest('base64url');
}

function signaturesEqual(expected: string, actual: string): boolean {
  const expectedBytes = Buffer.from(expected, 'utf8');
  const actualBytes = Buffer.from(actual, 'utf8');
  if (expectedBytes.length !== actualBytes.length) return false;
  return timingSafeEqual(expectedBytes, actualBytes);
}

export function createSessionCookieValue(session: Session): string {
  const normalized = normalizeSession(session);
  const secret = getSessionSecret();
  if (!normalized || !secret) {
    throw new Error('signed session cookie cannot be created without a valid session secret');
  }

  const payload = canonicalSessionPayload(normalized);
  const encodedPayload = Buffer.from(payload, 'utf8').toString('base64url');
  const signature = signPayload(payload, secret);
  return `${encodedPayload}.${signature}`;
}

export function verifySessionCookieValue(raw: string | undefined): Session | null {
  if (!raw) return null;
  const secret = getSessionSecret();
  if (!secret) return null;

  const parts = raw.split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;

  try {
    const payload = Buffer.from(parts[0], 'base64url').toString('utf8');
    const parsed = JSON.parse(payload);
    const normalized = normalizeSession(parsed);
    if (!normalized) return null;

    const canonicalPayload = canonicalSessionPayload(normalized);
    if (payload !== canonicalPayload) return null;

    const expectedSignature = signPayload(canonicalPayload, secret);
    if (!signaturesEqual(expectedSignature, parts[1])) return null;

    return normalized;
  } catch {
    return null;
  }
}

export function getSession(): Session | null {
  const raw = cookies().get(SESSION_COOKIE)?.value;
  return verifySessionCookieValue(raw);
}

export function requireExtranet(): Session {
  const s = getSession();
  if (!s || s.surface !== 'extranet') {
    // Components calling this server-side should redirect at the layout level;
    // the throw is a defense-in-depth signal.
    throw new Error('extranet session required');
  }
  return s;
}

export function requireIntranet(): Session {
  const s = getSession();
  if (!s || s.surface !== 'intranet') {
    throw new Error('intranet session required');
  }
  return s;
}

export const DEV_EXTRANET_ROLES: ExtranetRole[] = EXTRANET_ROLES;
export const DEV_INTRANET_ROLES: IntranetRole[] = INTRANET_ROLES;
