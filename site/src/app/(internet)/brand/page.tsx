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

export const metadata = { title: 'Brand & Press Kit' };

export default function Page() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Brand</Eyebrow>
        <H1 className="mt-3">Brand & press kit.</H1>
        <Lede className="mt-5 max-w-prose">
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
              <div className="py-6"><Logo /></div>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Mark" />
            <CardBody>
              <div className="py-6"><Logo variant="mark" className="h-10 w-10" /></div>
            </CardBody>
          </Card>
        </div>
      </Section>
      <Section className="py-8">
        <H2>Voice</H2>
        <ul className="mt-3 list-disc pl-5 text-sm space-y-1.5 max-w-prose">
          <li>Serious, technical, trustworthy, future-forward.</li>
          <li>Custody and accountability — not crypto buzzwords.</li>
          <li>Avoid mystical or hype-laden language on public copy.</li>
          <li>Use the listed vocabulary consistently (see Glossary).</li>
        </ul>
      </Section>
      <Section className="py-8">
        <H2>Color tokens</H2>
        <div className="mt-5 grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
          {[
            { name: 'ink', value: '#0B0E14' },
            { name: 'vellum', value: '#F5F2EA' },
            { name: 'custody', value: '#3FB6C8' },
            { name: 'signal', value: '#D9A24E' },
            { name: 'verify', value: '#5A8C5C' },
            { name: 'alert', value: '#C0524A' }
          ].map((t) => (
            <div key={t.name} className="border hairline rounded-md overflow-hidden">
              <div className="h-12" style={{ background: t.value }} />
              <div className="px-3 py-2 flex items-center justify-between text-xs font-mono">
                <span>{t.name}</span>
                <span>{t.value}</span>
              </div>
            </div>
          ))}
        </div>
      </Section>
    </>
  );
}
