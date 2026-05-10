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
  { href: '/why', label: 'Why' },
  { href: '/avc', label: 'AVC' },
  { href: '/chain-of-custody', label: 'Chain-of-Custody' },
  { href: '/trust-receipts', label: 'Trust Receipts' },
  { href: '/custody-native-blockchain', label: 'Blockchain' },
  { href: '/developers', label: 'Developers' },
  { href: '/docs', label: 'Docs' },
  { href: '/trust-center', label: 'Trust Center' },
  { href: '/research', label: 'Research' },
  { href: '/status', label: 'Status' }
];

export function PublicNav() {
  return (
    <header className="sticky top-0 z-30 backdrop-blur bg-vellum-soft/80 dark:bg-ink-deep/80 border-b hairline">
      <div className="max-w-page mx-auto px-6 md:px-10 h-14 flex items-center justify-between gap-4">
        <Link href="/" aria-label="EXOCHAIN home">
          <Logo />
        </Link>
        <nav className="hidden lg:flex items-center gap-5 text-sm">
          {PRIMARY_LINKS.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              className="text-ink/70 hover:text-ink dark:text-vellum-soft/70 dark:hover:text-vellum-soft"
            >
              {l.label}
            </Link>
          ))}
        </nav>
        <div className="flex items-center gap-2">
          <LinkButton href="/contact" variant="secondary" size="sm">
            Early Access
          </LinkButton>
          <LinkButton href="/app" variant="primary" size="sm">
            Sign in
          </LinkButton>
        </div>
      </div>
    </header>
  );
}
