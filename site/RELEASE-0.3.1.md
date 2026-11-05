<!-- Copyright 2026 Exochain Foundation. SPDX-License-Identifier: Apache-2.0 -->

# 0.3.1 public-site release companion

## Purpose

Present EXOCHAIN as the trust fabric for accountable autonomous commerce.
Preserve the visual system and navigation while moving the commercial entry
point to enterprise deployment. The public workflow connects delegated
authority, bailment obligations, execution, payment evidence, and independent
verification. Financial assurance is described through separately issued
provider instruments and the requirements of the covered transaction.

This is an adjacent-surface change. It neither publishes 0.3.1 nor changes the
release's approved capability scope. Coordinate publication with the release
owners; this document is the website handoff, not a core release authorization.

## One source for publication facts

The homepage, footer, developer page, FAQ, Trust Center, and Terms now use
`loadPublicStatus()` from `src/lib/public-status.ts`, as `/status` already does.
Its input is `../crates/exo-node/src/public-status.json`. There is no site-owned
copy of the release version, maturity, or normative specification. Static
metadata and `public/llms.txt` direct readers to `/status` for those facts.

When the release owners publish the approved release:

1. Update the canonical node-packaged publication record through the release
   process, including version, maturity, maturity summary, artifact scope, and
   capability boundaries. A version bump alone must not establish GA.
2. Rebuild and deploy the site from that same source revision. These server
   components are rendered at build time; changing the JSON without rebuilding
   does not update an existing deployment.
3. Confirm that `/`, `/developers`, `/docs/faq`, `/trust-center`, `/legal/terms`,
   and `/status` show the same approved release scope.

An approved GA record will be displayed as supplied. There is no permanent
site-level beta label to remove in a later marketing edit. A release that still
records beta remains accurately represented until the record changes.

## Commercial deployment evidence

Publish a named deployment example only when its owner has approved the exact
public description. For each example, obtain:

- Organization/product name and relationship: customer, partner, affiliated
  product, or reference implementation.
- Commercial workflow, deployed release, and acceptance date.
- The actual EXOCHAIN API/adapter boundary and the actions it enforces.
- A publishable, redacted result with a verification procedure or evidence link.
- Consent to use the name, logo, quote, and any outcome metrics.

Use only the approved scope and outcome. An affiliated application demonstrates
reuse; it must not silently count as an independent paying customer. Keep the
public ecosystem page useful without inventing logos, testimonials, deployment
counts, or performance statistics.

The homepage's **Explore the transaction flow** link opens an explanatory
workflow. Change it to **See a verified transaction** only when a real,
accessible verification example exists. A successful example needs the
authorized action, a rejected unauthorized variant, attributable outcome
evidence, and a verification procedure the counterparty can reproduce. Remove
private transaction data and credentials before publication.

## Protocol and provider acceptance

Confirm each advertised integration against the approved release and deployed
path. MCP tool access, A2A discovery/task support, x402 verification, payment
settlement, and an assurance instrument are distinct acceptance items.

- **Authority:** identify the principal, delegation, scope, consent, revocation,
  and execution-boundary enforcement; include a negative-path result.
- **Bailment:** identify the supported agreement lifecycle and entrusted
  resources. Do not infer counteroffers or multi-party execution from bilateral
  consent alone.
- **Payment:** identify the payment provider and settlement result separately
  from EXOCHAIN's authorization and evidence binding. A verified payment header
  or an internal zero-priced ledger receipt does not prove external settlement.
- **Assurance:** identify the actual issuer, instrument, covered obligation or
  risk, beneficiary, limits, exclusions, effective period, and claims route.
  Reinsurance supports the provider under its own agreement. A schema, pricing
  classifier, or interface does not issue coverage.

## Adjacent-surface intake and regression boundary

| Item | Record |
| --- | --- |
| Classification | Adjacent public surface: every changed path is under `site/`. |
| Owner and accountable maintainer | EXOCHAIN Foundation public-site maintainers; repository CODEOWNERS route review. EXOCHAIN PBC remains the published legal entity. |
| Deployment status | Existing production public website; this change is its 0.3.1 companion. Website deployment does not assert a production core network. |
| Allowed claims | Explain the commercial workflow and link to approved release facts, supported SDK methods, and scoped provider responsibilities. |
| Trust boundary | Public copy does not issue credentials, authorize actions, mint receipts, settle payments, or issue coverage. The existing read-only status probe remains same-origin. |
| Core access | Canonical release facts are read from the repository. Existing `/health` and `/ready` probes are unchanged. No new core calls or writes are introduced. |
| Contact boundary | Existing contact submission API, validation, rate limits, storage, and disclosure controls are unchanged; only visible inquiry categories and copy change. |
| Secrets and configuration | No new secrets or configuration. Existing site configuration remains documented in `.env.example`; no core signing or bootstrap keys are used by this change. |
| Validation | `npm test`, `npm run typecheck`, `npm run lint`, and `npm run build` from `site/`; inspect the public routes, CTAs, canonical metadata, and mobile layout. |
| CI gate | Existing `npm test` includes the commercial-claims guard. Run the site commands for this PR; the core CI workflow does not independently run the site suite. |
| Rollback | Revert this site's commit and redeploy the preceding site revision. Do not roll back core governance, credentials, receipts, or release records to undo a website change. |

No `crates/`, `packages/`, `governance/`, `tools/`, CI workflow, deployment
contract, authentication, API route, or dependency change is part of this PR.
Private commercial strategy, transaction objectives, and negotiating terms do
not belong in the public website or this handoff.
