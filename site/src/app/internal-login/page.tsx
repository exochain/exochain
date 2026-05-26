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
import { INTRANET_ROLES, ROLE_LABEL, isIntranetRole, type IntranetRole } from '@/lib/roles';
import { Section, Eyebrow, H1, Lede } from '@/components/ui/Section';
import { Pill } from '@/components/ui/Pill';
import { Disclaimer } from '@/components/ui/Disclaimer';

export const metadata = { title: 'Sign in · Intranet' };

async function signIn(formData: FormData) {
  'use server';
  if (!isDevLoginEnabled()) {
    throw new Error('development login is disabled');
  }
  const roleValue = String(formData.get('role') ?? 'auditor_internal');
  if (!isIntranetRole(roleValue)) {
    throw new Error('invalid intranet role');
  }
  const role: IntranetRole = roleValue;
  const next = String(formData.get('next') ?? '/internal');
  const session = {
    userId: 'op_user_001',
    email: 'ops@exochain.io',
    role,
    surface: 'intranet' as const
  };
  cookies().set(SESSION_COOKIE, createSessionCookieValue(session), {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 60 * 60 * 4
  });
  redirect(next);
}

async function signOut() {
  'use server';
  cookies().delete(SESSION_COOKIE);
  redirect('/internal/login');
}

export default function Page({
  searchParams
}: {
  searchParams: { next?: string };
}) {
  if (!isDevLoginEnabled()) {
    notFound();
  }

  const next = searchParams.next ?? '/internal';
  return (
    <div className="min-h-dvh grid place-items-center px-6 bg-ink text-vellum-soft">
      <Section width="prose" className="py-12 w-full">
        <Eyebrow>Intranet · internal use only</Eyebrow>
        <H1 className="mt-3 text-vellum-soft">EXOCHAIN operations</H1>
        <Lede className="mt-4 text-vellum-soft/80">
          Local development login is explicitly enabled for this environment.
          Choose a role to preview the intranet with that capability set.
        </Lede>
        <div className="mt-3 flex gap-2">
          <Pill tone="signal">dev login</Pill>
          <Pill tone="alert">step-up MFA pending</Pill>
        </div>
        <form action={signIn} className="mt-8 space-y-4">
          <input type="hidden" name="next" value={next} />
          <label className="block text-sm">
            <div className="text-eyebrow text-vellum-soft/60">Role</div>
            <select
              name="role"
              defaultValue="auditor_internal"
              className="mt-1 w-full border border-vellum-soft/20 rounded-sm px-3 py-2 bg-transparent"
            >
              {INTRANET_ROLES.map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABEL[r]}
                </option>
              ))}
            </select>
          </label>
          <div className="flex items-center gap-3">
            <button className="border border-vellum-soft/40 rounded-sm px-3 py-2 text-sm bg-vellum-soft text-ink">
              Sign in
            </button>
            <Link href="/" className="text-sm underline text-vellum-soft/80">
              Back to public site
            </Link>
          </div>
        </form>
        <form action={signOut} className="mt-3">
          <button className="text-xs underline text-vellum-soft/60">
            Clear session
          </button>
        </form>
        <div className="mt-8">
          <Disclaimer>
            All intranet actions are recorded in append-only audit logs and
            reviewed by internal audit and security.
          </Disclaimer>
        </div>
      </Section>
    </div>
  );
}
