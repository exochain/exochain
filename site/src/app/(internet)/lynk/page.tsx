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
import { LinkButton } from '@/components/ui/Button';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { Code, Pre } from '@/components/ui/Code';
import { Disclaimer } from '@/components/ui/Disclaimer';
import { Pill } from '@/components/ui/Pill';
import { Eyebrow, H1, H2, Lede, Section } from '@/components/ui/Section';

export const metadata = {
  title: 'LYNK Protocol',
  description:
    'EXOCHAIN LYNK Protocol discovery for receipted OpenAI and MCP usage, bounded to the tested core receipt adapter path.'
};

const supportedLanes = [
  {
    lane: 'OpenAI Responses',
    status: 'V1 tested lane',
    note: 'Provider usage is summarized into signed AVC evidence before receipt emission.'
  },
  {
    lane: 'OpenAI Chat Completions',
    status: 'V1 tested lane',
    note: 'Output delivery remains gated on the receipt outcome reported by EXOCHAIN.'
  },
  {
    lane: 'MCP tools/call',
    status: 'V1 tested lane',
    note: 'Tool usage can produce signed LYNK evidence; EXOCHAIN core emits the receipt.'
  }
];

const waveLanes = [
  {
    wave: 'Wave 2',
    scope: 'Anthropic Messages',
    posture: 'Unsupported until a separate provider adapter and positive tests land.'
  },
  {
    wave: 'Wave 3',
    scope: 'Generic OpenAI-compatible endpoints and wrapper modes',
    posture: 'Unsupported beyond the already tested OpenAI-compatible v1 paths.'
  },
  {
    wave: 'Wave 4',
    scope: 'Expanded MCP and workflow producers',
    posture: 'May create signed evidence; must not mint EXOCHAIN receipts directly.'
  }
];

export default function LynkPage() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <div className="max-w-4xl">
          <Eyebrow>EXOCHAIN LYNK Protocol</Eyebrow>
          <H1 className="mt-3">
            Receipted LLM and MCP usage, anchored to the core receipt path.
          </H1>
          <Lede className="mt-5 max-w-prose">
            LYNK is the EXOCHAIN adapter package for services that need to
            withhold model or tool output until an AVC-backed usage receipt is
            accepted by EXOCHAIN core.
          </Lede>
          <div className="mt-6 flex flex-wrap gap-2">
            <Pill tone="custody">core runtime adapter</Pill>
            <Pill tone="signal">coverage-first gates</Pill>
            <Pill tone="verify">receipt_minimized default</Pill>
          </div>
          <div className="mt-8 flex flex-wrap gap-3">
            <LinkButton href="/developers" size="lg">
              Developer quickstart
            </LinkButton>
            <LinkButton href="/docs/trust-receipts" variant="secondary" size="lg">
              Receipt model
            </LinkButton>
            <LinkButton href="/contact" variant="ghost" size="lg">
              Discuss integration
            </LinkButton>
          </div>
        </div>
      </Section>

      <Section className="py-8">
        <div className="grid lg:grid-cols-3 gap-5">
          <Card>
            <CardHeader title="What LYNK does" />
            <CardBody>
              <p className="text-sm text-ink/80 dark:text-vellum-soft/80">
                The adapter wraps OpenAI Responses, OpenAI Chat Completions,
                and MCP <Code>tools/call</Code> usage in signed AVC evidence,
                then submits it to the core receipt endpoint.
              </p>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="What EXOCHAIN does" />
            <CardBody>
              <p className="text-sm text-ink/80 dark:text-vellum-soft/80">
                EXOCHAIN validates the AVC evidence and emits the node-signed
                receipt through <Code>POST /api/v1/avc/llm-usage/receipts/emit</Code>.
              </p>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="What this site does not do" />
            <CardBody>
              <p className="text-sm text-ink/80 dark:text-vellum-soft/80">
                This public page is an adjacent public surface. It does not
                mint receipts, validate credentials, or imply constitutional
                enforcement beyond the tested EXOCHAIN core/API receipt path.
              </p>
            </CardBody>
          </Card>
        </div>
      </Section>

      <Section className="py-8">
        <div className="grid lg:grid-cols-[0.9fr_1.1fr] gap-8 items-start">
          <div>
            <Eyebrow>Privacy boundary</Eyebrow>
            <H2 className="mt-3">Receipt-minimized by default.</H2>
            <p className="mt-4 text-sm leading-6 text-ink/80 dark:text-vellum-soft/80">
              LYNK receipts are designed to carry hashes, integer usage
              counters, safe metadata, custody policy hashes, and
              receipt/finality links. They are not a place for prompts,
              completions, tool arguments, tool results, provider keys, bearer
              credentials, KMS material, object-store locations, or decryptable
              payload material.
            </p>
          </div>
          <Card>
            <CardHeader title="Agent-readable boundary" />
            <CardBody>
              <Pre caption="LYNK public discovery contract">
{`name: EXOCHAIN LYNK Protocol
classification: core runtime adapter
public_site_classification: adjacent public surface
v1_positive_lanes: openai_responses, openai_chat_completions, mcp_tools_call
receipt_endpoint: POST /api/v1/avc/llm-usage/receipts/emit
default_custody_mode: receipt_minimized
unsupported_claims: site_enforcement, release_readiness_without_gates
secret_material_in_public_copy: forbidden`}
              </Pre>
            </CardBody>
          </Card>
        </div>
      </Section>

      <Section className="py-8">
        <Eyebrow>Coverage-first scope</Eyebrow>
        <H2 className="mt-3 max-w-2xl">
          V1 is narrow on purpose. Future waves stay fail-closed until tested.
        </H2>
        <div className="mt-6 grid md:grid-cols-3 gap-5">
          {supportedLanes.map((item) => (
            <Card key={item.lane}>
              <CardHeader eyebrow={item.status} title={item.lane} />
              <CardBody>
                <p className="text-sm text-ink/80 dark:text-vellum-soft/80">
                  {item.note}
                </p>
              </CardBody>
            </Card>
          ))}
        </div>
        <div className="mt-6 grid md:grid-cols-3 gap-5">
          {waveLanes.map((item) => (
            <Card key={item.wave}>
              <CardHeader eyebrow={item.wave} title={item.scope} />
              <CardBody>
                <p className="text-sm text-ink/80 dark:text-vellum-soft/80">
                  {item.posture}
                </p>
              </CardBody>
            </Card>
          ))}
        </div>
      </Section>

      <Section className="py-8" width="prose">
        <Disclaimer>
          LYNK is discoverable here for humans and AI coding agents, but this
          page is not proof of package publication, deployment readiness, audit
          completion, or runtime enforcement. Treat the package gates, core
          tests, and the receipt endpoint as the authority.
        </Disclaimer>
        <p className="mt-5 text-sm text-ink/75 dark:text-vellum-soft/75">
          For broader EXOCHAIN concepts, read the{' '}
          <Link href="/avc" className="underline">
            AVC explainer
          </Link>
          ,{' '}
          <Link href="/trust-receipts" className="underline">
            trust receipt anatomy
          </Link>
          , and{' '}
          <Link href="/developers" className="underline">
            developer guide
          </Link>
          .
        </p>
      </Section>
    </>
  );
}
