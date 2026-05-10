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

// Mock auth for v0. Replace with OIDC + WebAuthn in v0.5+.
// All session reads happen server-side; the cookie is HTTP-only and not exposed
// to client JS. There are no real credentials here — the dev login pages
// at /app/login and /internal/login simply set the chosen role.

import { cookies } from 'next/headers';
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

export interface Session {
  userId: string;
  email: string;
  role: Role;
  surface: 'extranet' | 'intranet';
  org?: string;
}

export function getSession(): Session | null {
  const raw = cookies().get(SESSION_COOKIE)?.value;
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Partial<Session>;
    if (
      typeof parsed.userId === 'string' &&
      typeof parsed.email === 'string' &&
      typeof parsed.role === 'string' &&
      (parsed.surface === 'extranet' || parsed.surface === 'intranet')
    ) {
      const role = parsed.role as Role;
      const surface = parsed.surface;
      if (surface === 'extranet' && !isExtranetRole(role)) return null;
      if (surface === 'intranet' && !isIntranetRole(role)) return null;
      return {
        userId: parsed.userId,
        email: parsed.email,
        role,
        surface,
        org: parsed.org
      };
    }
  } catch {
    return null;
  }
  return null;
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
