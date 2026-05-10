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

// Hard surface separation: /app/* requires extranet session, /internal/*
// requires intranet session. Login pages are served outside these protected
// app shells so they do not run the layout redirect checks.
//
// In v0 the cookie payload is a JSON string. In v0.5+ this becomes a JWT
// with audience claims and signature verification.

const EXO_SESSION = 'exo-session';

interface SessionShape {
  surface?: 'extranet' | 'intranet';
  role?: string;
}

function readSession(req: NextRequest): SessionShape | null {
  const raw = req.cookies.get(EXO_SESSION)?.value;
  if (!raw) return null;
  try {
    return JSON.parse(raw) as SessionShape;
  } catch {
    return null;
  }
}

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  if (pathname.startsWith('/app')) {
    if (pathname === '/app/login') {
      const loginUrl = req.nextUrl.clone();
      loginUrl.pathname = '/login';
      return NextResponse.rewrite(loginUrl);
    }
    const sess = readSession(req);
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
    const sess = readSession(req);
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
  matcher: ['/app/:path*', '/internal/:path*']
};
