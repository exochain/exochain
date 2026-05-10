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

import Link from 'next/link';
import { Logo } from './Logo';
import { Pill } from '../ui/Pill';
import type { Session } from '@/lib/auth';
import { ROLE_LABEL } from '@/lib/roles';

const NAV: { href: string; label: string }[] = [
  { href: '/app', label: 'Dashboard' },
  { href: '/app/org', label: 'Organization' },
  { href: '/app/actors', label: 'Actors' },
  { href: '/app/avcs', label: 'AVCs' },
  { href: '/app/avcs/issue', label: '— Issue' },
  { href: '/app/avcs/validate', label: '— Validate' },
  { href: '/app/revocations', label: 'Revocations' },
  { href: '/app/trust-receipts', label: 'Trust Receipts' },
  { href: '/app/settlement-quotes', label: 'Settlement · Quotes' },
  { href: '/app/settlement-receipts', label: 'Settlement · Receipts' },
  { href: '/app/custody-trails', label: 'Custody Trails' },
  { href: '/app/policy-domains', label: 'Policy Domains' },
  { href: '/app/consent-records', label: 'Consent Records' },
  { href: '/app/nodes', label: 'Nodes' },
  { href: '/app/validators', label: 'Validators' },
  { href: '/app/api-keys', label: 'API Keys' },
  { href: '/app/webhooks', label: 'Webhooks' },
  { href: '/app/audit-exports', label: 'Audit Exports' },
  { href: '/app/support', label: 'Support' },
  { href: '/app/security-requests', label: 'Security Requests' },
  { href: '/app/settings', label: 'Settings' }
];

export function AppShell({
  session,
  children
}: {
  session: Session;
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-dvh grid grid-cols-1 md:grid-cols-[260px_1fr]">
      <aside className="border-r hairline bg-white/40 dark:bg-ink-soft px-4 py-5">
        <Link href="/app">
          <Logo />
        </Link>
        <div className="mt-1 text-eyebrow text-ink/50 dark:text-vellum-soft/50">
          Extranet
        </div>
        <nav className="mt-5 space-y-0.5 text-sm">
          {NAV.map((n) => (
            <Link
              key={n.href}
              href={n.href}
              className={`block px-2 py-1.5 rounded-sm hover:bg-ink/5 dark:hover:bg-vellum-soft/10 ${
                n.label.startsWith('—')
                  ? 'pl-6 text-ink/60 dark:text-vellum-soft/60'
                  : 'text-ink/80 dark:text-vellum-soft/80'
              }`}
            >
              {n.label}
            </Link>
          ))}
        </nav>
        <div className="mt-6 border-t hairline pt-4 text-xs space-y-2">
          <div className="text-ink/60 dark:text-vellum-soft/60">
            Signed in as
          </div>
          <div className="font-mono">{session.email}</div>
          <Pill tone="custody">{ROLE_LABEL[session.role]}</Pill>
          {session.org && <div className="text-ink/60 dark:text-vellum-soft/60">org · {session.org}</div>}
          <Link href="/app/login" className="block text-xs underline">
            Switch role / sign out
          </Link>
        </div>
      </aside>
      <div className="min-w-0">
        <div className="border-b hairline px-6 py-3 flex flex-wrap items-center gap-3 justify-between">
          <div className="flex items-center gap-3">
            <Pill tone="signal">alpha</Pill>
            <Pill tone="custody">zero-priced launch</Pill>
            <span className="text-sm text-ink/70 dark:text-vellum-soft/70">
              EXOCHAIN extranet — every administrative action writes to the audit log.
            </span>
          </div>
          <div className="flex items-center gap-3 text-xs">
            <Link href="/" className="underline">
              Public site
            </Link>
          </div>
        </div>
        <main className="px-6 md:px-10 py-8">
          <div className="max-w-page mx-auto">{children}</div>
        </main>
      </div>
    </div>
  );
}
