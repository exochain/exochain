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
npm run security:auth-boundary
npm run security:lynk-public-claims
npm run security:status-probe
npm start            # serve the production build
```

## Surfaces and routes

| Surface | Route prefix | Auth | Login |
|---|---|---|---|
| Internet | `/` (and named pages) | none | — |
| Extranet | `/app/*` | signed cookie session | `/app/login` |
| Intranet | `/internal/*` | signed cookie session | `/internal/login` |

Hard surface separation is enforced by `middleware.ts`. Unauthenticated or
unsigned-cookie requests to `/app/*` and `/internal/*` are redirected to the
corresponding login page.

Development login is disabled by default and is not available in production.
To use it locally, set `EXO_SITE_ENABLE_DEV_LOGIN=1`,
`NODE_ENV=development`, and `EXO_SITE_SESSION_SECRET` to a 32-byte-or-longer
secret. Session cookies are HMAC signed; raw JSON `exo-session` cookies are
rejected by middleware and server-side session loading.

### Public sitemap (excerpt)

```
/  /why  /proof-of-authority  /standards  /developers  /ecosystem  /engagement
/chain-of-custody  /avc  /trust-receipts
/lynk  /custody-native-blockchain  /docs  /api  /node
/trust-center  /security  /governance  /research  /status
/blog  /contact  /brand  /legal/privacy  /legal/terms
/docs/{getting-started,concepts,avc,trust-receipts,settlement,
       node-api,validator-guide,security,governance,glossary,faq}
```

The same pages are served for `exochain.com`, `exochain.ai`, and `exochain.net`.
Copy does not vary by hostname. Canonical URLs use `https://exochain.com`
(`src/lib/public-site.ts`). Mirror hosts are listed in page metadata.
`exochain.io` is the node dashboard, not this app. Railway should keep the
website service root at `site/` and attach all three marketing domains to
that one service.

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

- **Public status is repository data.** `/status` reads
  `crates/exo-node/src/public-status.json` (the file packaged with the
  node) and, in the browser, the raw same-origin `/health` and `/ready`
  bodies. It does not invent network metrics. The site build's working
  directory is `site/`; the loader resolves the crate file from there.
- **Extranet and intranet consoles are mocks.** Those routes still render
  typed mocks in `src/lib/mock-data.ts`. Numeric metrics there are labeled
  `mock`.
- **Local-only development auth.** The `exo-session` cookie is signed with
  `EXO_SITE_SESSION_SECRET`; development login fails closed unless explicitly
  enabled outside production.
- **No real settlement.** All settlement-related views show the
  `ZeroPriceBanner` and amount = `0 EXO`.
- **No fake claims.** The Trust Center, Security page, and copy generally
  distinguish *current capabilities* from *roadmap items*.

## LYNK adjacent public-surface intake

- **Classification:** `/site` is an adjacent public surface.
- **Owner / maintainer:** EXOCHAIN Foundation public-site maintainers.
- **Deployment status:** production public website; LYNK package readiness
  remains gated by the coverage-first plan and package/core tests.
- **Allowed claims:** `/lynk` may make LYNK discoverable, name the V1 tested
  lanes, and describe the core receipt endpoint
  `POST /api/v1/avc/llm-usage/receipts/emit`.
- **Disallowed claims:** the public site must not imply it mints receipts,
  validates AVCs, publishes packages, completes audits, or provides
  constitutional enforcement beyond the actual EXOCHAIN core/API receipt path.
- **Core access:** the public LYNK page and `public/llms.txt` do not read or
  write EXOCHAIN core state, signatures, governance outcomes, consent records,
  provenance records, prompts, outputs, provider keys, bearer credentials, KMS
  material, object-store locations, or decryptable payload material.
- **Trust boundary:** site copy is discovery and routing only; the LYNK adapter
  produces signed evidence and EXOCHAIN core performs receipt validation and
  emission.
- **Site-specific gate:** `npm run security:lynk-public-claims` checks LYNK
  discovery links, privacy language, endpoint scoping, and unsupported readiness
  claims.
- **Runtime configuration:** no LYNK secrets or provider runtime configuration
  are required by the public page.
- **Rollback path:** remove `/lynk`, `public/llms.txt`, and the public links
  from navigation, footer, home, and developer resources.

## Status probe intake

`LiveGatewayProbe` is adjacent-surface code. When this site is served from
the same origin as exo-gateway or exo-node, the browser reads those
processes' public probes and displays the raw response text.

- **Classification:** adjacent public surface. It is not the constitutional
  trust fabric.
- **Owner / maintainer:** EXOCHAIN Foundation public-site maintainers.
- **Deployment status:** production public website when this Next.js app is
  deployed. The probe does not by itself claim a runtime deployment. The
  v0.2.7 release notes claim no runtime deployment; a live response describes
  that process only.
- **Allowed claims:** show the HTTP status and body returned by same-origin
  `GET /health` and `GET /ready`. Publication facts stay in
  `crates/exo-node/src/public-status.json`.
- **Disallowed claims:** the probe must not be described as general
  availability, a production network, validator counts, peer counts,
  committed height, uptime percent, or an incident history. It must not
  imply the site mints consent, authority, provenance, or governance
  outcomes.
- **Core access:** read-only `GET` of `/health` and `/ready` on the page's
  own origin. The component does not write EXOCHAIN core state, signatures,
  credentials, governance outcomes, consent records, or provenance records.
- **Trust boundary:** the browser calls only the site origin. Response
  bodies are untrusted text and are rendered as text. A missing route,
  network failure, or timeout is shown for that probe alone. This component
  does not proxy to a configured upstream URL. If the site origin is not
  exo-gateway, the probe shows whatever that origin returns, including a
  404.
- **Secrets / runtime configuration:** none. The component reads no
  `DATABASE_URL`, bearer token, tenant id, gateway URL, or other secret.
  The only repository input for the surrounding page is
  `crates/exo-node/src/public-status.json`, resolved from the `site/`
  working directory. Each probe aborts after 5000 ms.
- **Test / CI gate:** from `site/`, `npm run security:status-probe`. The
  node page's gateway header is covered by
  `cargo test -p exochain-gateway -- gateway_status_path_allows_status_assets_csp`
  and
  `cargo test -p exochain-node --bin exochain status_route_renders_repository_facts_without_fictional_metrics`.
- **Rollback / disablement:** remove `<LiveGatewayProbe />` from
  `src/app/(internet)/status/page.tsx`. The published-release facts remain.
  Deleting the component stops the browser fetches. No secret rotation is
  required.

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

- Real OIDC + WebAuthn, MDX docs, OG images, status feed wiring, webhook
  signing, and OpenAPI mounted at `/api`.
- Production gating, live AVC issuance against `exo-node` / `exo-gateway`,
  audit packets backed by the real settlement chain, and public bug bounty.
- Validator dashboard, holon registry, governance proposal authoring,
  multi-region status, and public sandbox.

See `SPEC.md` §11 for the full breakdown and `SPEC.md` §13 for v0
acceptance criteria.

## Acceptance criteria check (v0)

- ✅ All Internet routes render and link correctly.
- ✅ All Extranet routes render and reflect the role badge.
- ✅ All Intranet routes render with the environment banner and redaction
  defaults.
- ✅ Five named diagrams render at all viewports without overflow.
- ✅ `ZeroPriceBanner` appears on every settlement-related page.
- ✅ Status page shows the published release and does not invent network metrics.
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
        ├── auth.ts                # signed development session
        ├── mock-data.ts           # typed mocks
        └── format.ts              # date/number helpers
```
