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
import { loadPublicStatus } from '@/lib/public-status';
import { CORE_LICENSE, LEGAL_EMAIL, LEGAL_ENTITY } from '@/lib/public-site';

const cols = [
  {
    heading: 'Trust fabric',
    links: [
      { href: '/why', label: 'The problem' },
      { href: '/proof-of-authority', label: 'Proof of Authority' },
      { href: '/standards', label: 'Standards' },
      { href: '/ecosystem', label: 'Ecosystem' },
      { href: '/engagement', label: 'Engagement' },
    ],
  },
  {
    heading: 'Build',
    links: [
      { href: '/developers', label: 'Developers' },
      { href: '/lynk', label: 'LYNK Protocol' },
      { href: '/docs', label: 'Docs' },
      { href: '/api', label: 'API Reference' },
      { href: '/node', label: 'Run a Node' },
      { href: '/app', label: 'Sign in' },
    ],
  },
  {
    heading: 'Protocol',
    links: [
      { href: '/avc', label: 'AVC credential' },
      { href: '/chain-of-custody', label: 'Chain-of-Custody' },
      { href: '/trust-receipts', label: 'Trust Receipts' },
      { href: '/custody-native-blockchain', label: 'Custody-Native Blockchain' },
      { href: '/governance', label: 'Governance' },
    ],
  },
  {
    heading: 'Company',
    links: [
      { href: '/contact', label: 'Contact' },
      { href: '/trust-center', label: 'Trust Center' },
      { href: '/security', label: 'Security' },
      { href: '/status', label: 'Status' },
      { href: '/research', label: 'Research' },
      { href: '/blog', label: 'Field Notes' },
      { href: '/brand', label: 'Brand & Press' },
      { href: '/legal/privacy', label: 'Privacy' },
      { href: '/legal/terms', label: 'Terms' },
    ],
  },
];

export function PublicFooter() {
  const publicStatus = loadPublicStatus();
  return (
    <footer className="mt-24 border-t hairline">
      <div className="max-w-page mx-auto px-6 md:px-10 py-12 grid gap-10 md:grid-cols-5">
        <div className="md:col-span-1">
          <Logo className="text-brand-vault dark:text-brand-white" />
          <p className="mt-4 text-sm text-brand-midnight/75 dark:text-brand-white/70 max-w-xs">
            The trust fabric for autonomous commerce.
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            <Pill tone="neutral" className="border border-brand-charter/40 bg-brand-charter/10 text-brand-vault">
              {publicStatus.maturity} v{publicStatus.publication.version}
            </Pill>
            <Pill tone="neutral" className="border border-brand-signal/25 bg-brand-signal/10 text-brand-cerulean">
              spec v{publicStatus.spec.normative_version}
            </Pill>
          </div>
          <p className="mt-4 text-xs text-brand-midnight/70 dark:text-brand-white/65">
            {LEGAL_ENTITY}
            <br />
            <a className="underline" href={`mailto:${LEGAL_EMAIL}`}>
              {LEGAL_EMAIL}
            </a>
          </p>
        </div>
        {cols.map((col) => (
          <div key={col.heading}>
            <div className="text-eyebrow text-ink/50 dark:text-vellum-soft/50">
              {col.heading}
            </div>
            <ul className="mt-3 space-y-2 text-sm">
              {col.links.map((l) => (
                <li key={l.href}>
                  <Link
                    href={l.href}
                    className="text-brand-midnight/80 hover:text-brand-vault dark:text-brand-white/75 dark:hover:text-brand-white"
                  >
                    {l.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
      <div className="border-t hairline">
        <div className="max-w-page mx-auto px-6 md:px-10 py-5 flex flex-wrap items-center gap-3 justify-between text-xs text-brand-midnight/65 dark:text-brand-white/60">
          <div>
            © {new Date().getFullYear()} {LEGAL_ENTITY}. Core software is {CORE_LICENSE}.
          </div>
          <div className="max-w-xl text-right">
            {publicStatus.maturity_summary}{' '}
            <Link href="/status" className="underline">
              Publication and deployment scope
            </Link>.
            {' '}The same pages are served at exochain.com, exochain.ai, and
            exochain.net. Canonical URLs use https://exochain.com.
          </div>
        </div>
      </div>
    </footer>
  );
}
