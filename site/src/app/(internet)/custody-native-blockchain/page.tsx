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
import { Pill } from '@/components/ui/Pill';
import { ZeroPriceBanner } from '@/components/ui/ZeroPriceBanner';

export const metadata = { title: 'Custody-Native Blockchain' };

export default function CustodyNativeBlockchainPage() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Custody-native blockchain</Eyebrow>
        <H1 className="mt-3">The mechanism preserved. The purpose reframed.</H1>
        <Lede className="mt-5 max-w-prose">
          EXOCHAIN keeps every property you expect from a serious
          distributed ledger — deterministic ordering, cryptographic
          signatures, quorum, finality, post-quantum readiness — and reframes
          the chain as a chain-of-custody for autonomous action.
        </Lede>
      </Section>

      <Section className="py-8">
        <H2>Properties</H2>
        <div className="mt-6 grid md:grid-cols-2 lg:grid-cols-3 gap-5">
          <Card>
            <CardHeader title="Deterministic" />
            <CardBody className="text-sm">
              No floating-point arithmetic anywhere in the protocol;{' '}
              <code>#[deny(clippy::float_arithmetic)]</code> at the workspace
              root. Validation results are reproducible bit-for-bit.
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Post-quantum" />
            <CardBody className="text-sm">
              ML-DSA-65 (CRYSTALS-Dilithium) per NIST FIPS 204 is wired
              throughout signing and verification, with hybrid signature
              support for transitional deployments.
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Constitutional governance" />
            <CardBody className="text-sm">
              A constitutional governance kernel enforces invariants on every
              governance path. Pricing policy edits, validator changes, and
              critical revocations route through quorum.
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Custody verifiers, not just block producers" />
            <CardBody className="text-sm">
              Validators in EXOCHAIN are <em>custody verifiers</em>. Block
              production is custody attestation, not just transaction
              ordering.
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Independence of trust and economy" />
            <CardBody className="text-sm">
              AVC validation never consults pricing or settlement state.
              Settlement issuance never gates trust on payment availability.
              The two layers can evolve separately.
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Open reference implementation" />
            <CardBody className="text-sm">
              Apache-2.0 licensed Rust reference implementation. Twenty
              numbered CI quality gates plus aggregator. See the public
              repository.
            </CardBody>
          </Card>
        </div>
      </Section>

      <Section id="economy" className="py-10">
        <Eyebrow>Zero-priced launch settlement</Eyebrow>
        <H2 className="mt-3">Trust is not paywalled.</H2>
        <p className="mt-4 text-ink/80 dark:text-vellum-soft/80 max-w-prose">
          The economic layer ships the full transaction mechanism: quotes,
          settlements, revenue-share lines, and hash-chained settlement
          receipts. The launch policy resolves every active price to{' '}
          <span className="font-mono">0 EXO</span> with an explicit{' '}
          <span className="font-mono">ZeroFeeReason</span>. Future governance
          amendments can switch nonzero pricing on by policy without modifying
          AVC validation.
        </p>
        <div className="mt-6 flex flex-wrap gap-2">
          <Pill tone="custody">launch_policy_zero</Pill>
          <Pill tone="custody">governance_subsidy</Pill>
          <Pill tone="custody">humanitarian_carve_out</Pill>
        </div>
        <div className="mt-8">
          <ZeroPriceBanner />
        </div>
      </Section>
    </>
  );
}
