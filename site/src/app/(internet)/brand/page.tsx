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

import { Section, Eyebrow, H1, H2, Lede } from '@/components/ui/Section';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { Logo } from '@/components/chrome/Logo';
import { publicMetadata } from '@/lib/public-site';

export const metadata = publicMetadata({
  title: 'Brand & Press Kit',
  description: 'Brand & Press Kit. EXOCHAIN is the trust fabric for autonomous commerce.',
  path: '/brand',
});

const colors = [
  { name: 'Vault', value: '#081E26', note: 'Primary dark background' },
  { name: 'Deep Teal', value: '#0E4459', note: 'Retained AVC foundation' },
  { name: 'Cerulean', value: '#186B8C', note: 'Institutional headings' },
  { name: 'Signal', value: '#2C96BF', note: 'Links and active states' },
  { name: 'Ice', value: '#91D8E8', note: 'Support only' },
  { name: 'Charter Gold', value: '#B8955A', note: 'Legal/governance accent' },
  { name: 'Midnight', value: '#1A2B35', note: 'Panels and cards' },
  { name: 'Frost', value: '#C8D8DC', note: 'Borders and dividers' },
  { name: 'Porcelain', value: '#F0F4F5', note: 'Light surface' },
  { name: 'White', value: '#FFFFFF', note: 'Type on dark fields' }
];

export default function Page() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Brand</Eyebrow>
        <H1 className="mt-3 font-light tracking-normal text-brand-vault">
          Brand & visual identity.
        </H1>
        <Lede className="mt-5 max-w-prose text-brand-midnight/80">
          EXOCHAIN&apos;s brand reads as evidentiary trust substrate, not crypto
          startup. Use the marks and language consistently with the
          guidance below.
        </Lede>
      </Section>
      <Section className="py-8">
        <H2>Marks</H2>
        <div className="mt-6 grid md:grid-cols-2 gap-5">
          <Card>
            <CardHeader title="Wordmark" />
            <CardBody>
              <div className="py-6 text-brand-vault"><Logo /></div>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Mark" />
            <CardBody>
              <div className="py-6 text-brand-vault"><Logo variant="mark" className="h-10 w-10" /></div>
            </CardBody>
          </Card>
        </div>
      </Section>
      <Section className="py-8">
        <H2>Voice</H2>
        <ul className="mt-3 list-disc pl-5 text-sm space-y-1.5 max-w-prose">
          <li>Serious, technical, trustworthy, and operationally mature.</li>
          <li>Custody and accountability — not crypto buzzwords.</li>
          <li>Generous whitespace and thin strokes signal precision.</li>
          <li>Use monospace for hashes, receipt IDs, and credential strings.</li>
        </ul>
      </Section>
      <Section className="py-8">
        <H2>Color tokens</H2>
        <div className="mt-5 grid grid-cols-2 md:grid-cols-5 gap-3 text-sm">
          {colors.map((t) => (
            <div key={t.name} className="border hairline rounded-md overflow-hidden bg-brand-white/40">
              <div className="h-12" style={{ background: t.value }} />
              <div className="px-3 py-2 text-xs">
                <div className="flex items-center justify-between font-mono">
                  <span>{t.name}</span>
                  <span>{t.value}</span>
                </div>
                <p className="mt-1 text-[11px] leading-snug text-brand-midnight/65">
                  {t.note}
                </p>
              </div>
            </div>
          ))}
        </div>
      </Section>
      <Section className="py-8">
        <H2>Do / avoid</H2>
        <div className="mt-5 grid md:grid-cols-2 gap-5 text-sm">
          <Card>
            <CardHeader title="Do" />
            <CardBody>
              <ul className="list-disc pl-5 space-y-1.5">
                <li>Keep marks one color and legible at small sizes.</li>
                <li>Use Charter Gold sparingly: one accent per screen.</li>
                <li>Use flat fields, precise borders, and calm spacing.</li>
              </ul>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Avoid" />
            <CardBody>
              <ul className="list-disc pl-5 space-y-1.5">
                <li>No neon glow, bloom, or crypto particle effects.</li>
                <li>No chain-link or hexagon iconography.</li>
                <li>No all-caps body copy.</li>
              </ul>
            </CardBody>
          </Card>
        </div>
      </Section>
    </>
  );
}
