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

import { notFound, redirect } from 'next/navigation';
import { cookies } from 'next/headers';
import Link from 'next/link';
import { createSessionCookieValue, isDevLoginEnabled, SESSION_COOKIE } from '@/lib/auth';
import { EXTRANET_ROLES, ROLE_LABEL, isExtranetRole, type ExtranetRole } from '@/lib/roles';
import { Section, Eyebrow, H1, Lede } from '@/components/ui/Section';
import { Pill } from '@/components/ui/Pill';

export const metadata = { title: 'Sign in · Extranet' };

async function signIn(formData: FormData) {
  'use server';
  if (!isDevLoginEnabled()) {
    throw new Error('development login is disabled');
  }
  const roleValue = String(formData.get('role') ?? 'developer');
  if (!isExtranetRole(roleValue)) {
    throw new Error('invalid extranet role');
  }
  const role: ExtranetRole = roleValue;
  const next = String(formData.get('next') ?? '/app');
  const session = {
    userId: 'dev_user_001',
    email: 'dev@aperture.example',
    role,
    surface: 'extranet' as const,
    org: 'Aperture Holdings'
  };
  cookies().set(SESSION_COOKIE, createSessionCookieValue(session), {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 60 * 60 * 8
  });
  redirect(next);
}

async function signOut() {
  'use server';
  cookies().delete(SESSION_COOKIE);
  redirect('/app/login');
}

export default function Page({
  searchParams
}: {
  searchParams: { next?: string };
}) {
  if (!isDevLoginEnabled()) {
    notFound();
  }

  const next = searchParams.next ?? '/app';
  return (
    <div className="min-h-dvh grid place-items-center px-6">
      <Section width="prose" className="py-12 w-full">
        <Eyebrow>Extranet · alpha</Eyebrow>
        <H1 className="mt-3">Sign in to EXOCHAIN.</H1>
        <Lede className="mt-4">
          Local development login is explicitly enabled for this environment.
          Choose a role to preview the extranet under that capability set.
        </Lede>
        <div className="mt-3 flex gap-2">
          <Pill tone="signal">dev login</Pill>
          <Pill tone="custody">no real credentials</Pill>
        </div>
        <form action={signIn} className="mt-8 space-y-4">
          <input type="hidden" name="next" value={next} />
          <label className="block text-sm">
            <div className="text-eyebrow text-ink/60 dark:text-vellum-soft/60">Role</div>
            <select
              name="role"
              defaultValue="developer"
              className="mt-1 w-full border hairline rounded-sm px-3 py-2 bg-transparent"
            >
              {EXTRANET_ROLES.map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABEL[r]}
                </option>
              ))}
            </select>
          </label>
          <div className="flex items-center gap-3">
            <button className="border hairline rounded-sm px-3 py-2 text-sm bg-ink text-vellum-soft">
              Sign in
            </button>
            <Link href="/" className="text-sm underline">
              Back to public site
            </Link>
          </div>
        </form>
        <form action={signOut} className="mt-3">
          <button className="text-xs underline text-ink/60 dark:text-vellum-soft/60">
            Clear session
          </button>
        </form>
      </Section>
    </div>
  );
}
