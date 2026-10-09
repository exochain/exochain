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
import { Pill } from '@/components/ui/Pill';
import { LiveGatewayProbe } from '@/components/status/LiveGatewayProbe';
import publicStatus from '@/data/public-status.json';

export const metadata = { title: 'Status' };

export default function Page() {
  const release = publicStatus.publication;
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Status</Eyebrow>
        <H1 className="mt-3">EXOCHAIN public status.</H1>
        <Lede className="mt-5 max-w-prose">{publicStatus.maturity_summary}</Lede>
        <div className="mt-4 flex flex-wrap gap-2">
          <Pill tone="signal">{publicStatus.maturity}</Pill>
          <Pill tone="custody">spec v{publicStatus.spec.normative_version}</Pill>
          <Pill tone="neutral">v{release.version}</Pill>
        </div>
      </Section>

      <Section className="py-8">
        <H2>Published release</H2>
        <div className="mt-4 max-w-prose space-y-3 text-sm">
          <p>
            Reviewed snapshot <span className="font-mono">v{release.version}</span>,
            observed <span className="font-mono">{release.observed_at}</span>.
            GitHub Release published{' '}
            <span className="font-mono">{release.github_published_at}</span>:{' '}
            <a className="underline" href={release.github_url}>
              {release.github_url}
            </a>
            .
          </p>
          <p>
            Native archives contain {release.native_archive_contents}. Runtime
            deployment claimed by that release:{' '}
            <span className="font-mono">
              {release.runtime_deployment_claimed ? 'yes' : 'no'}
            </span>
            .
          </p>
          <p>
            PyPI package <span className="font-mono">{release.pypi_package}</span>{' '}
            was observed at the same version. crates.io and npm package names are
            in{' '}
            <span className="font-mono">
              governance/releases/published-release-snapshot.json
            </span>
            .
          </p>
        </div>
      </Section>

      <Section className="py-8">
        <H2>Specification</H2>
        <p className="mt-4 max-w-prose text-sm">
          Normative specification v{publicStatus.spec.normative_version} (
          <span className="font-mono">{publicStatus.spec.normative_document}</span>
          ), recorded in{' '}
          <span className="font-mono">{publicStatus.spec.authority_record}</span>.
          Engineering elaboration v{publicStatus.spec.engineering_version} (
          <span className="font-mono">{publicStatus.spec.engineering_document}</span>
          ) is subordinate to that specification. A v2.3 specification is{' '}
          {publicStatus.spec.v2_3_present_in_repository ? 'present' : 'not present'}{' '}
          in this repository.
        </p>
      </Section>

      <Section className="py-8">
        <H2>Same-origin gateway probe</H2>
        <p className="mt-4 max-w-prose text-sm">
          <span className="font-mono">GET /ready</span> is served by exo-gateway,
          not by this Next.js site, and its version field is the binary&apos;s{' '}
          <span className="font-mono">CARGO_PKG_VERSION</span>. The text below is
          the raw same-origin response. A 404 means this website process is not
          the gateway. This page does not invent validator counts, peer counts,
          committed height, uptime percent, or incidents.
        </p>
        <LiveGatewayProbe />
      </Section>

      <Section className="py-8">
        <H2>Default-off boundaries</H2>
        <ul className="mt-4 max-w-prose space-y-3 text-sm">
          {publicStatus.default_off_features.map((feature) => (
            <li key={`${feature.package}/${feature.feature}`}>
              <span className="font-mono">
                {feature.package}/{feature.feature}
              </span>
              {' — '}
              {feature.boundary}
            </li>
          ))}
        </ul>
      </Section>

      <Section className="py-8">
        <H2>Bounded capabilities</H2>
        <ul className="mt-4 max-w-prose space-y-3 text-sm">
          {publicStatus.bounded_capabilities.map((capability) => (
            <li key={capability.name}>
              <strong>{capability.name}.</strong> {capability.posture}
            </li>
          ))}
        </ul>
      </Section>

      <Section className="py-8">
        <H2>Gap ledger</H2>
        <p className="mt-4 max-w-prose text-sm">{publicStatus.gap_registry.note}</p>
        <p className="mt-3 max-w-prose text-xs text-ink/60 dark:text-vellum-soft/60">
          <span className="font-mono">{publicStatus.gap_registry.path}</span> header
          amended {publicStatus.gap_registry.header_amended}; that header records{' '}
          {publicStatus.gap_registry.header_records_release}.
        </p>
      </Section>
    </>
  );
}
