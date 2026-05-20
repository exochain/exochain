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

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { isExtranetRole, isIntranetRole, type Role } from './lib/roles';

// Hard surface separation: /app/* requires extranet session, /internal/*
// requires intranet session. Login pages are served outside these protected
// app shells and are only usable when local development login is enabled.

const EXO_SESSION = 'exo-session';
const SESSION_SECRET_ENV = 'EXO_SITE_SESSION_SECRET';

interface SessionShape {
  userId: string;
  email: string;
  surface?: 'extranet' | 'intranet';
  role?: string;
  org?: string;
}

function getSessionSecret(): string | null {
  const secret = process.env[SESSION_SECRET_ENV];
  if (typeof secret !== 'string' || new TextEncoder().encode(secret).length < 32) {
    return null;
  }
  return secret;
}

function base64UrlToBytes(value: string): Uint8Array {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function normalizeSession(input: unknown): SessionShape | null {
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

  const session: SessionShape = {
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

function canonicalSessionPayload(session: SessionShape): string {
  return JSON.stringify({
    email: session.email,
    org: session.org ?? null,
    role: session.role,
    surface: session.surface,
    userId: session.userId
  });
}

function constantTimeEqual(expected: string, actual: string): boolean {
  if (expected.length !== actual.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i += 1) {
    diff |= expected.charCodeAt(i) ^ actual.charCodeAt(i);
  }
  return diff === 0;
}

async function signPayload(payload: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  return bytesToBase64Url(new Uint8Array(signature));
}

async function verifySessionCookieValue(raw: string | undefined): Promise<SessionShape | null> {
  if (!raw) return null;
  const secret = getSessionSecret();
  if (!secret) return null;

  const parts = raw.split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;

  try {
    const payload = new TextDecoder().decode(base64UrlToBytes(parts[0]));
    const normalized = normalizeSession(JSON.parse(payload));
    if (!normalized) return null;

    const canonicalPayload = canonicalSessionPayload(normalized);
    if (payload !== canonicalPayload) return null;

    const expectedSignature = await signPayload(canonicalPayload, secret);
    if (!constantTimeEqual(expectedSignature, parts[1])) return null;

    return normalized;
  } catch {
    return null;
  }
}

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  if (pathname === '/login' || pathname === '/internal-login') {
    return NextResponse.next();
  }

  if (pathname.startsWith('/app')) {
    if (pathname === '/app/login') {
      const loginUrl = req.nextUrl.clone();
      loginUrl.pathname = '/login';
      return NextResponse.rewrite(loginUrl);
    }
    const sess = await verifySessionCookieValue(req.cookies.get(EXO_SESSION)?.value);
    if (!sess || sess.surface !== 'extranet') {
      const url = req.nextUrl.clone();
      url.pathname = '/app/login';
      url.searchParams.set('next', pathname);
      return NextResponse.redirect(url);
    }
    return NextResponse.next();
  }

  if (pathname.startsWith('/internal')) {
    if (pathname === '/internal/login') {
      const loginUrl = req.nextUrl.clone();
      loginUrl.pathname = '/internal-login';
      return NextResponse.rewrite(loginUrl);
    }
    const sess = await verifySessionCookieValue(req.cookies.get(EXO_SESSION)?.value);
    if (!sess || sess.surface !== 'intranet') {
      const url = req.nextUrl.clone();
      url.pathname = '/internal/login';
      url.searchParams.set('next', pathname);
      return NextResponse.redirect(url);
    }
    return NextResponse.next();
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/app/:path*', '/login', '/internal/:path*', '/internal-login']
};
