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
import { Section, Eyebrow, H1, H2, Lede } from '@/components/ui/Section';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { Pill } from '@/components/ui/Pill';
import { Disclaimer } from '@/components/ui/Disclaimer';
import { ZeroPriceBanner } from '@/components/ui/ZeroPriceBanner';
import { SurfaceMapDiagram } from '@/components/diagrams/SurfaceMap';

export const metadata = { title: 'Trust Center' };

export default function Page() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Trust Center</Eyebrow>
        <H1 className="mt-3">Trust posture, plainly stated.</H1>
        <Lede className="mt-5 max-w-prose">
          What we have today, what we are working on, and what we have not
          yet earned the right to claim. Every line on this page is meant
          to be defensible to an auditor.
        </Lede>
      </Section>

      <Section className="py-8">
        <div className="grid md:grid-cols-2 gap-5">
          <Card>
            <CardHeader
              eyebrow="Today"
              title="Current capabilities"
              right={<Pill tone="verify">verified</Pill>}
            />
            <CardBody>
              <ul className="text-sm space-y-1.5 list-disc pl-5">
                <li>Deterministic AVC validation with structured reason codes.</li>
                <li>ML-DSA-65 (CRYSTALS-Dilithium) signatures and hybrid mode.</li>
                <li>Hash-chained trust receipts.</li>
                <li>Zero-priced launch settlement with explicit ZeroFeeReason.</li>
                <li>Constitutional governance kernel on governance paths.</li>
                <li>Twenty CI quality gates plus aggregator on the reference implementation.</li>
              </ul>
            </CardBody>
          </Card>
          <Card>
            <CardHeader
              eyebrow="Roadmap"
              title="Earned, not yet claimed"
              right={<Pill tone="roadmap">roadmap</Pill>}
            />
            <CardBody>
              <ul className="text-sm space-y-1.5 list-disc pl-5">
                <li>Independent third-party security audit.</li>
                <li>SOC 2 Type I readiness statement.</li>
                <li>Public bug bounty.</li>
                <li>Validator hardware attestation v2.</li>
                <li>Mainnet membership rules.</li>
                <li>NIST AI RMF and emerging AI policy framework mappings.</li>
              </ul>
            </CardBody>
          </Card>
        </div>
      </Section>

      <Section className="py-8">
        <H2>Three surfaces, three trust postures</H2>
        <p className="mt-3 text-sm max-w-prose">
          EXOCHAIN&apos;s web presence is split across three surfaces with hard
          separation. Each surface enforces its own auth and capability
          rules at the route boundary.
        </p>
        <div className="mt-6 border hairline rounded-md p-4">
          <SurfaceMapDiagram />
        </div>
      </Section>

      <Section className="py-8">
        <H2>Cryptographic assumptions</H2>
        <p className="mt-3 text-sm max-w-prose">
          Statements here reflect implemented primitives at the time of
          writing. EXOCHAIN treats post-quantum readiness as a baseline and
          tracks evolving guidance. See{' '}
          <Link href="/docs/security" className="underline">/docs/security</Link>.
        </p>
      </Section>

      <Section className="py-8">
        <H2>Responsible disclosure</H2>
        <p className="mt-3 text-sm max-w-prose">
          Coordinated disclosure intake is at{' '}
          <Link href="/security" className="underline">/security</Link>.
          Provide reproduction steps and an intended public disclosure date;
          we will respond with an acknowledgement window and assigned
          severity.
        </p>
      </Section>

      <Section className="py-8">
        <H2>Privacy and data custody</H2>
        <p className="mt-3 text-sm max-w-prose">
          AVC payloads are minimized by default. Consent records carry only
          a scope hash, not the underlying data. PII is not required to
          register an actor. Aggregate metrics shared with researchers are
          anonymized.
        </p>
      </Section>

      <Section className="py-8">
        <ZeroPriceBanner />
      </Section>

      <Section className="py-8">
        <Disclaimer>
          EXOCHAIN is in alpha. Nothing on this page should be read as a
          claim of completed third-party audit or regulatory approval unless
          a linked artifact says otherwise.
        </Disclaimer>
      </Section>
    </>
  );
}
