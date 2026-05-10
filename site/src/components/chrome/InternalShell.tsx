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
  { href: '/internal', label: 'Operations' },
  { href: '/internal/network', label: 'Network' },
  { href: '/internal/nodes', label: '— Node Health' },
  { href: '/internal/validators', label: '— Validators' },
  { href: '/internal/actors', label: 'Actor Registry' },
  { href: '/internal/avcs', label: 'AVC Registry' },
  { href: '/internal/revocations', label: 'Revocation Console' },
  { href: '/internal/trust-receipts', label: 'Trust Receipts' },
  { href: '/internal/settlement', label: 'Settlement' },
  { href: '/internal/pricing-policy', label: 'Pricing Policy' },
  { href: '/internal/governance', label: 'Governance' },
  { href: '/internal/security', label: 'Security Queue' },
  { href: '/internal/incidents', label: 'Incidents' },
  { href: '/internal/audit', label: 'Audit Exports' },
  { href: '/internal/content', label: 'Content' },
  { href: '/internal/docs-mgmt', label: '— Docs Mgmt' },
  { href: '/internal/users', label: 'Users / Orgs' },
  { href: '/internal/support', label: 'Support Queue' },
  { href: '/internal/research', label: 'Research Library' },
  { href: '/internal/releases', label: 'Releases' },
  { href: '/internal/feature-flags', label: '— Feature Flags' },
  { href: '/internal/logs', label: 'System Logs' }
];

export function InternalShell({
  session,
  children
}: {
  session: Session;
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-dvh grid grid-cols-1 md:grid-cols-[280px_1fr] bg-vellum dark:bg-ink-deep">
      <aside className="border-r hairline bg-ink text-vellum-soft px-4 py-5">
        <Link href="/internal">
          <Logo className="text-vellum-soft" />
        </Link>
        <div className="mt-1 text-eyebrow text-vellum-soft/50">
          Intranet · Internal use only
        </div>
        <nav className="mt-5 space-y-0.5 text-sm">
          {NAV.map((n) => (
            <Link
              key={n.href}
              href={n.href}
              className={`block px-2 py-1.5 rounded-sm hover:bg-vellum-soft/10 ${
                n.label.startsWith('—')
                  ? 'pl-6 text-vellum-soft/60'
                  : 'text-vellum-soft/85'
              }`}
            >
              {n.label}
            </Link>
          ))}
        </nav>
        <div className="mt-6 border-t border-vellum-soft/15 pt-4 text-xs space-y-2">
          <div className="text-vellum-soft/60">Signed in as</div>
          <div className="font-mono">{session.email}</div>
          <Pill tone="signal">{ROLE_LABEL[session.role]}</Pill>
          <Link href="/internal/login" className="block underline">
            Switch role / sign out
          </Link>
        </div>
      </aside>
      <div className="min-w-0">
        <div className="bg-alert-deep text-white px-6 py-2 text-xs flex items-center justify-between">
          <span className="font-semibold tracking-eyebrow uppercase">
            Internal · alpha-testnet · redaction-on by default
          </span>
          <Link href="/" className="underline">
            Public site
          </Link>
        </div>
        <main className="px-6 md:px-10 py-8">
          <div className="max-w-page mx-auto">{children}</div>
        </main>
      </div>
    </div>
  );
}
