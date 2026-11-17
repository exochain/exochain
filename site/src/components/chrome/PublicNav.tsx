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
import { LinkButton } from '../ui/Button';

const PRIMARY_LINKS = [
  { href: '/why', label: 'Problem' },
  { href: '/proof-of-authority', label: 'Proof of Authority' },
  { href: '/standards', label: 'Standards' },
  { href: '/developers', label: 'Developers' },
  { href: '/ecosystem', label: 'Ecosystem' },
  { href: '/engagement', label: 'Engagement' },
  { href: '/lynk', label: 'LYNK' },
];

export function PublicNav() {
  return (
    <header className="sticky top-0 z-30 bg-brand-porcelain/95 dark:bg-brand-vault/95 border-b hairline">
      <div className="max-w-page mx-auto px-6 md:px-10 h-14 flex items-center justify-between gap-4">
        <Link href="/" aria-label="EXOCHAIN home" className="text-brand-vault dark:text-brand-white shrink-0">
          <Logo />
        </Link>
        <nav className="hidden xl:flex items-center gap-4 text-sm" aria-label="Primary">
          {PRIMARY_LINKS.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              className="text-brand-midnight/70 hover:text-brand-vault dark:text-brand-white/70 dark:hover:text-brand-white"
            >
              {l.label}
            </Link>
          ))}
        </nav>
        <div className="flex items-center gap-2">
          <details className="xl:hidden relative">
            <summary className="list-none cursor-pointer h-8 px-3 inline-flex items-center text-sm border border-brand-frost rounded-sm">
              Menu
            </summary>
            <nav
              aria-label="Mobile"
              className="absolute right-0 mt-2 w-56 border hairline bg-brand-porcelain p-3 shadow-sm"
            >
              <ul className="space-y-2 text-sm">
                {PRIMARY_LINKS.map((l) => (
                  <li key={l.href}>
                    <Link href={l.href} className="block py-1">
                      {l.label}
                    </Link>
                  </li>
                ))}
                <li>
                  <Link href="/docs" className="block py-1">
                    Docs
                  </Link>
                </li>
                <li>
                  <Link href="/app" className="block py-1">
                    Sign in
                  </Link>
                </li>
              </ul>
            </nav>
          </details>
          <LinkButton href="/contact#deployment" variant="primary" size="sm">
            Enterprise deployment
          </LinkButton>
          <Link
            href="/app"
            className="hidden sm:inline text-sm text-brand-midnight/70 hover:text-brand-vault"
          >
            Sign in
          </Link>
        </div>
      </div>
    </header>
  );
}
