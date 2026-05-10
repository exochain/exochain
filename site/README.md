<!--
Copyright 2026 Exochain Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
-->

# EXOCHAIN web presence (`/site`)

This directory contains the EXOCHAIN web presence: the public **Internet**
site, the authenticated **Extranet**, and the internal **Intranet**, served
by a single Next.js 14 app.

The full specification is in [`SPEC.md`](./SPEC.md). This README is a quick
operator guide.

> **Note:** the existing Vite SPA at `../web/` is left untouched. This new
> presence lives at `../site/` to avoid disturbing it.

---

## Stack

- **Next.js 14** App Router
- **React 18** server components by default
- **TypeScript** strict
- **Tailwind CSS** with a hand-tuned restrained palette
- **No external UI kit** — primitives are hand-authored
- **Hand-authored SVG** for all five named diagrams (no runtime diagram lib)
- **No telemetry** in v0

## Running locally

```bash
cd site
npm install
npm run dev
# http://localhost:3000
```

Useful scripts:

```bash
npm run typecheck    # tsc --noEmit
npm run lint         # next lint
npm run build        # production build
npm start            # serve the production build
```

## Surfaces and routes

| Surface | Route prefix | Auth | Login |
|---|---|---|---|
| Internet | `/` (and named pages) | none | — |
| Extranet | `/app/*` | mock cookie session | `/app/login` |
| Intranet | `/internal/*` | mock cookie session | `/internal/login` |

Hard surface separation is enforced by `middleware.ts`. Unauthenticated
requests to `/app/*` and `/internal/*` are redirected to the corresponding
login page.

The dev login pages let you pick any role from the role enum to preview
that surface under that capability set. **No real credentials are involved
in v0.** Real OIDC + WebAuthn arrives in v0.5.

### Public sitemap (excerpt)

```
/  /why  /chain-of-custody  /avc  /trust-receipts
/custody-native-blockchain  /developers  /docs  /api  /node
/trust-center  /security  /governance  /research  /status
/blog  /contact  /brand  /legal/privacy  /legal/terms
/docs/{getting-started,concepts,avc,trust-receipts,settlement,
       node-api,validator-guide,security,governance,glossary,faq}
```

### Extranet sitemap

```
/app
/app/login  /app/org  /app/actors
/app/avcs   /app/avcs/issue  /app/avcs/validate
/app/revocations  /app/trust-receipts
/app/settlement-quotes  /app/settlement-receipts
/app/custody-trails  /app/policy-domains  /app/consent-records
/app/nodes  /app/validators
/app/api-keys  /app/webhooks
/app/audit-exports  /app/support  /app/security-requests  /app/settings
```

### Intranet sitemap

```
/internal
/internal/login  /internal/network  /internal/nodes
/internal/validators  /internal/actors  /internal/avcs
/internal/revocations  /internal/trust-receipts  /internal/settlement
/internal/pricing-policy  /internal/governance  /internal/security
/internal/incidents  /internal/audit  /internal/content
/internal/docs-mgmt  /internal/users  /internal/support
/internal/research  /internal/releases  /internal/feature-flags
/internal/logs
```

## What's mocked vs. real

- **No live network calls.** All data renders from typed mocks in
  `src/lib/mock-data.ts`. Numeric metrics are visibly labeled `mock`.
- **No real auth.** The `exo-session` cookie is a JSON blob. Replace with
  OIDC + signed JWT in v0.5 (see `src/lib/auth.ts`).
- **No real settlement.** All settlement-related views show the
  `ZeroPriceBanner` and amount = `0 EXO`.
- **No fake claims.** The Trust Center, Security page, and copy generally
  distinguish *current capabilities* from *roadmap items*.

## Design system

Tokens live in `tailwind.config.ts`. Palette is intentionally restrained:
ink, vellum, slate, custody (cyan), signal (amber), verify (sage), alert
(brick). No neon. No glow. No crypto clichés.

Primitives:

- `Button`, `LinkButton`
- `Pill`, `StatusPill`
- `Card`, `CardHeader`, `CardBody`
- `KPI`, `DataTable`, `Section`, `Eyebrow`, `H1/H2/Lede`, `Code`, `Pre`
- `ZeroPriceBanner`, `Disclaimer`

Diagrams (SVG):

- `CustodyFlowDiagram` — Human → AVC → Agent → EXOCHAIN → Trust Receipt
- `IdentityToCustodyDiagram` — Identity → Authority → Volition → Consent → Execution → Custody Receipt
- `MechanismVsPurposeDiagram` — blockchain mechanism vs. chain-of-custody purpose
- `SurfaceMapDiagram` — Internet / Extranet / Intranet
- `ZeroPricedSettlementDiagram` — quote → receipt with `ZeroFeeReason`

## Roadmap (excerpt)

- **v0.5** — real OIDC + WebAuthn, MDX docs, OG images, status feed wired,
  webhook signing, OpenAPI mounted at `/api`.
- **v1.0** — production gating, live AVC issuance against `exo-node` /
  `exo-gateway`, audit packets backed by the real settlement chain, public
  bug bounty.
- **v1.5+** — validator dashboard, holon registry, governance proposal
  authoring, multi-region status, public sandbox.

See `SPEC.md` §11 for the full breakdown and `SPEC.md` §13 for v0
acceptance criteria.

## Acceptance criteria check (v0)

- ✅ All Internet routes render and link correctly.
- ✅ All Extranet routes render and reflect the role badge.
- ✅ All Intranet routes render with the environment banner and redaction
  defaults.
- ✅ Five named diagrams render at all viewports without overflow.
- ✅ `ZeroPriceBanner` appears on every settlement-related page.
- ✅ Status page shows `mock` labels on every numeric metric.
- ✅ Middleware blocks unauthenticated `/app/*` and `/internal/*` requests
  and redirects to the corresponding login.
- ✅ No copy on the public site claims completed audits, regulatory
  approval, or production decentralization.
- ✅ Every administrative action page shows a clear "this writes to the
  audit log" affordance.

## Layout

```
site/
├── SPEC.md                        # specification (start here)
├── README.md                      # this file
├── package.json
├── tsconfig.json
├── next.config.mjs
├── tailwind.config.ts
├── postcss.config.mjs
├── middleware.ts                  # surface separation + auth gate
└── src/
    ├── app/
    │   ├── layout.tsx             # root layout
    │   ├── globals.css
    │   ├── (internet)/...         # public pages
    │   ├── app/...                # extranet
    │   └── internal/...           # intranet
    ├── components/
    │   ├── chrome/                # PublicNav, PublicFooter, AppShell, InternalShell, Logo
    │   ├── content/               # DocPage, AppPageHead, IntPageHead
    │   ├── diagrams/              # five SVG diagrams
    │   └── ui/                    # primitives (Button, Card, Pill, KPI, …)
    └── lib/
        ├── types.ts               # frontend view types
        ├── roles.ts               # role + capability matrix
        ├── auth.ts                # mock session
        ├── mock-data.ts           # typed mocks
        └── format.ts              # date/number helpers
```
