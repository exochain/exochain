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
import { Section, Eyebrow, H1 } from '@/components/ui/Section';
import { Pill } from '@/components/ui/Pill';

const DOC_NAV: { href: string; label: string }[] = [
  { href: '/docs/getting-started', label: 'Getting Started' },
  { href: '/docs/concepts', label: 'Concepts' },
  { href: '/docs/avc', label: 'AVC' },
  { href: '/docs/trust-receipts', label: 'Trust Receipts' },
  { href: '/docs/settlement', label: 'Settlement' },
  { href: '/docs/node-api', label: 'Node API' },
  { href: '/docs/validator-guide', label: 'Validator Guide' },
  { href: '/docs/security', label: 'Security Model' },
  { href: '/docs/governance', label: 'Governance Model' },
  { href: '/docs/glossary', label: 'Glossary' },
  { href: '/docs/faq', label: 'FAQ' }
];

export function DocPage({
  title,
  unstable,
  children
}: {
  title: string;
  unstable?: boolean;
  children: React.ReactNode;
}) {
  return (
    <Section className="py-12">
      <div className="grid lg:grid-cols-[220px_1fr] gap-10">
        <aside>
          <Eyebrow>Docs</Eyebrow>
          <nav className="mt-3 space-y-0.5 text-sm">
            {DOC_NAV.map((n) => (
              <Link
                key={n.href}
                href={n.href}
                className="block px-2 py-1 rounded-sm hover:bg-ink/5 dark:hover:bg-vellum-soft/10"
              >
                {n.label}
              </Link>
            ))}
          </nav>
        </aside>
        <article className="min-w-0 max-w-prose">
          <Eyebrow>Documentation</Eyebrow>
          <div className="flex items-center gap-3 mt-2">
            <H1 className="text-3xl">{title}</H1>
            {unstable && <Pill tone="unstable">Unstable</Pill>}
          </div>
          <div className="prose-exo mt-6">{children}</div>
        </article>
      </div>
    </Section>
  );
}
