# @exochain/x402-edge — authorization facilitator translator

Cloudflare Worker that speaks x402 HTTP status/headers at the edge and
calls Exochain AVC `validate` / LYNK `receipts/emit` as the authorization
facilitator. This is **not** a second payments stack and **not** a USDC
verifier.

## Adjacent-surface / runtime-adapter intake

- **Owner / accountable maintainer:** Exochain Foundation (AVC / node
  maintainers).
- **Deployment status:** `prototype`.
- **Constitutional trust claims:** none unless the live path calls
  `exo-node` `POST /api/v1/avc/validate` and
  `POST /api/v1/avc/llm-usage/receipts/emit` and tests prove fail-closed
  behavior when those APIs reject, time out, or are unconfigured. This
  Worker does not mint, cache, or simulate consent, authority,
  provenance, or governance outcomes.
- **Core state access:** read-only validate; receipt emit writes an AVC
  trust receipt through the node. The Worker does not hold bootstrap
  tokens, signing keys, or tenant secrets.
- **Trust boundary:** Coinbase/Cloudflare (or MPP) remain the *payment*
  facilitator. Exochain remains the *authorization* facilitator and
  receipt issuer. Money moving without `Allow` is rejected (Deny → 403).
- **Test command / CI gate:** `npm test` in `packages/exo-x402-edge`
  (TypeScript compile + `node --test`). Not part of the Cargo workspace.
- **Secrets / config:** `EXO_NODE_BASE_URL`, `EXO_ORIGIN_BASE_URL`.
  Missing config fails closed with `502 authorization_facilitator_unconfigured`.
  No development fallbacks and no secrets in health/status bodies.
- **Rollback / disablement:** unroute the Worker (remove the DNS/route
  binding). Origin and `exo-node` keep serving; commercial hops lose the
  translator.

## HTTP mapping

| AVC decision | HTTP |
| --- | --- |
| `Deny` | 403 |
| `HumanApprovalRequired` | 428 |
| `ChallengeRequired` / unpaid | 402 + `PAYMENT-REQUIRED` (AVC reason codes as extension) |
| `Allow` + settled payment | execute + emit receipt + 200 + `PAYMENT-RESPONSE` |

Constitutional paths are never paywalled: `/api/v1/avc/validate`,
0dentity identity lookup, and agent consent.

## Classification

**Core runtime adapter** — transports AVC decisions across HTTP. It is
not adjacent product code and must not claim kernel enforcement by
proximity.
