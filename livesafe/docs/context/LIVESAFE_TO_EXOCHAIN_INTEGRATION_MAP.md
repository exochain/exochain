# LiveSafe To EXOCHAIN Integration Map

## Source Basis

- `AGENTS.md`
- `README.md`
- `docs/EXOCHAIN_APP_BOUNDARY.md`
- `docs/TEST_PLAN.md`
- `docs/context/LIVESAFE_CONTEXT_SEED.md`
- `docs/context/LIVESAFE_PRODUCT_ARCHITECTURE.md`
- `docs/context/LIVESAFE_PRODUCTION_TRUST_ACTIVATION_GATES.md`
- `config/exochain-primitives.json`
- `config/exochain-production-trust.json`
- `railway.json`
- `fly.toml`
- `server/index.js`
- `server/utils/exochain-production-trust-evidence.js`
- `server/utils/public-adapter-output-authorization.js`
- `server/utils/livesafe-exochain-adapter.js`
- `server/utils/exochain-client.js`
- `scripts/exochain-public-output-evidence-hash.mjs`
- `src/exochain-root-trust-state.ts`
- `src/exochain-boundary.ts`
- `src/exochain_adapter_activation.rs`
- `tests/exochain-production-trust-evidence.test.ts`
- `tests/public-output-evidence-summary.test.ts`
- `tests/public-exochain-copy-boundary.test.ts`
- `tests/exochain-root-trust-state.test.ts`
- Read-only EXOCHAIN commit `3fb81ea457e727c010052beafcfe49735ebd0546`.
- Read-only EXOCHAIN workspace file `/Users/bobstewart/dev/exochain/Cargo.toml`
  lists `crates/exo-root` as a current workspace member.
- Read-only EXOCHAIN `crates/exo-root/Cargo.toml` describes `exo-root` as
  `EXOCHAIN root genesis authority ceremony, FROST DKG, threshold signatures,
  and trust bundle verification`.
- Read-only EXOCHAIN `crates/exo-root/src/ceremony.rs` defines
  `ROOT_GENESIS_THRESHOLD: 7` and `ROOT_GENESIS_SIGNERS: 13`.
- Read-only EXOCHAIN `crates/exo-root/src/lib.rs` exports
  `verify_root_bundle`, `run_complete_dkg`, `threshold_sign`, and
  `verify_root_signature`.
- Live health check on 2026-06-05 against
  `https://livesafe-api-production.up.railway.app/api/health` returned JSON
  including `{"status":"ok","database":"connected","exochain_connected":false,...}`.
- Live header check on 2026-06-05 against the same route returned `HTTP/2 200`
  with `server: railway-hikari`, `cache-control: no-store`, and
  `x-railway-edge: railway/us-east4-eqdc4a`.
- Live trust-status probe on 2026-06-05 against
  `https://livesafe-api-production.up.railway.app/api/trust/status` returned
  `HTTP/2 200` with `cache-control: no-store` and JSON including
  `{"state":"not-verified","machine_state":"not_verified","public_claims_allowed":false,...}`.
- `railway status --json` succeeded on 2026-06-05 and confirmed Railway
  project `livesafe` in the `ARMORCLOUD` workspace, production environment,
  repo-linked service `livesafe-api`, public domain
  `livesafe-api-production.up.railway.app`, and `Postgres` service. Live
  project, service, deployment, and instance ids are closeout-only evidence;
  deployment ids are volatile release evidence and closeout verification must
  read them live from Railway CLI.
- EXOCHAIN production `/health` and `/ready` returned `HTTP/2 200` with
  `{"status":"ok","version":"0.1.0-beta",...}` on 2026-06-03.
- EXOCHAIN root-trust bundle
  `7d9954a797ef244c15ad1b733cf77598125ccef0f812a404137e827c192d6a58`
  verified with EXOCHAIN `origin/main` commit
  `379a45e1d9ab092ecd446d095a7b524570530efd` at
  `2026-06-03T21:24:50Z`.
- EXOCHAIN production sentinels reported `Liveness` and `ReceiptIntegrity`
  healthy, with `QuorumHealth` below BFT minimum as a non-blocking LiveSafe
  observation.

## Ground Truth

LiveSafe runs as an adjacent application surface in
`/Users/bobstewart/dev/livesafe`. EXOCHAIN under
`/Users/bobstewart/dev/exochain` is read-only evidence from this repo.

The current integration state is fail-closed and incomplete:

- The public runtime health route is live on Railway.
- The public runtime health route now redacts raw database error text and keeps
  failure output bounded to safe availability metadata.
- The runtime now defines a trust-status route that stays explicitly inactive,
  machine-readable, redacted about adapter state, and explicit about verified
  EXOCHAIN production evidence.
- The public trust-status route is live on Railway and remains fail-closed with
  `state: not-verified`, `machine_state: not_verified`, and
  `public_claims_allowed: false`.
- The trust-status contract reports
  `exochain_production_evidence_state: verified`,
  `exochain_root_trust_bundle_verified: true`, and
  `public_claims_allowed: false` until the LiveSafe runtime adapter is also
  verified.
- Railway CLI verification is currently available and agrees with the public
  runtime truth for the active deployment.
- Current read-only EXOCHAIN source evidence justifies the intermediate
  classification `exochain_root_evidence_verified`.
- Current EXOCHAIN production evidence verifies the AVC root-trust bundle, but
  this does not authorize LiveSafe public trust claims without adapter proof.
- The canonical public-output evidence summary hash is deterministic AVC
  ceremony input for public adapter-output authorization. It is generated from
  non-secret public metadata only and does not authorize public claims by
  itself.
- The runtime reports `exochain_connected: false` in current production health
  evidence.
- The repo contains EXOCHAIN-facing client code, a fail-closed runtime adapter
  facade, and policy contracts, but no verified runtime adapter path is wired
  for production authority claims.
- LiveSafe may describe EXOCHAIN root primitives as present in first-party
  source, but not as an active production enforcement path.

## Runtime Integration Inventory

| Surface | Path | Current role | Integration state |
| --- | --- | --- | --- |
| API server | `server/index.js` | Express runtime, database startup, health route, route mounting | active runtime |
| Health route | `GET /api/health` in `server/index.js`; `server/utils/health-status.js`; `server/utils/exochain-connectivity-status.js` | Returns app, database, and EXOCHAIN connection status | active runtime, reports `exochain_connected: false` in live production evidence, skips raw EXOCHAIN probes while the adapter remains unverified, and redacts raw database error text from the public failure payload |
| Trust-status route | `GET /api/trust/status` in `server/index.js`; `server/utils/trust-status.js` | Returns explicit inactive trust-state metadata for API consumers | active runtime, live production evidence reports `state: not-verified`, `machine_state: not_verified`, and `public_claims_allowed: false` |
| EXOCHAIN production evidence evaluator | `config/exochain-production-trust.json`; `server/utils/exochain-production-trust-evidence.js` | Evaluates source-backed EXOCHAIN production health, readiness, root-trust bundle verification, and sentinel observations | active repo contract, reports verified EXOCHAIN production evidence while keeping public LiveSafe claims gated by adapter proof |
| Public-output evidence summary hash | `server/utils/exochain-production-trust-evidence.js`; `scripts/exochain-public-output-evidence-hash.mjs` | Builds and hashes sorted-key canonical public evidence metadata for AVC public adapter-output binding | adjacent operator contract; emits non-secret `sha256:<hex>` evidence only and keeps `public_claims_allowed: false` until separate proof-bearing authorization passes |
| Runtime adapter facade | `server/utils/livesafe-exochain-adapter.js` | Fail-closed LiveSafe boundary around EXOCHAIN-facing runtime calls | active in runtime, but still inactive because `runtimeAdapterStatus` remains `not-wired` |
| EXOCHAIN client | `server/utils/exochain-client.js` | GraphQL client for identity, audit, scan, consent, and P.A.C.E. calls | subordinate transport only; now wrapped by the runtime adapter facade and fails closed on malformed direct-client audit inputs, identity/P.A.C.E. subscriber DIDs, scan/consent identifiers, missing consent input objects, and optional authority fields |
| Boundary evaluator | `src/exochain-boundary.ts` | Denies trust claims and core access without a verified adapter | implemented policy gate |
| Adapter activation contract | `src/exochain_adapter_activation.rs` | Defines permit-only activation and redaction requirements | implemented contract, not wired to a runtime route |
| Primitive registry | `config/exochain-primitives.json` | Lists local EXOCHAIN evidence paths and adapter status | evidence-only, `runtimeAdapterStatus: not-wired` |

The runtime code still carries historical EXOCHAIN integration intent in
`server/utils/exochain-client.js`, including GraphQL calls for identity,
consent, audit, and P.A.C.E. status. The current repo now wraps those client
surfaces through `server/utils/livesafe-exochain-adapter.js`, covering
identity reads, registration, audit anchors, `scan`, `consent`, and
P.A.C.E.-status reads behind the same fail-closed boundary while exposing only
a redacted wrapped-operation inventory through runtime status surfaces. The
facade stays fail-closed until the adapter is
explicitly verified, so the repo still stops short of a production-safe
verified adapter path under the gate requirements in `docs/TEST_PLAN.md` and
`docs/context/LIVESAFE_PRODUCTION_TRUST_ACTIVATION_GATES.md`.

## EXOCHAIN Evidence Inventory

The current adjacent repo records EXOCHAIN as local evidence through
`config/exochain-primitives.json` and `docs/EXOCHAIN_APP_BOUNDARY.md`.

| Evidence class | Local path recorded by LiveSafe | Status in LiveSafe |
| --- | --- | --- |
| Core deterministic primitives | `crates/exo-core` | evidence-only |
| Identity | `crates/exo-identity` | evidence-only |
| Consent | `crates/exo-consent` | evidence-only |
| Authority | `crates/exo-authority` | evidence-only |
| Gatekeeper | `crates/exo-gatekeeper` | evidence-only |
| DAG | `crates/exo-dag` | evidence-only |
| Proofs | `crates/exo-proofs` | evidence-only |
| API | `crates/exo-api` | evidence-only |
| Gateway | `crates/exo-gateway` | evidence-only |
| Messaging | `crates/exo-messaging` | evidence-only |
| AVC | `crates/exo-avc` | evidence-only |
| Economy | `crates/exo-economy` | evidence-only |
| Rust SDK facade | `crates/exochain-sdk` | evidence-only |
| TypeScript SDK | `packages/exochain-sdk` | evidence-only |
| WASM bridge | `packages/exochain-wasm` | evidence-only |

This inventory supports local architecture and boundary analysis only. It does
not authorize LiveSafe to claim runtime enforcement, custody proof, consent
proof, revocation proof, or root-backed public trust.

Additional read-only root evidence is now source-backed:

| Evidence class | Read-only EXOCHAIN path | Fact | LiveSafe meaning |
| --- | --- | --- | --- |
| Root workspace membership | `/Users/bobstewart/dev/exochain/Cargo.toml` | `crates/exo-root` is a current workspace member | EXOCHAIN root primitives are not absent |
| Root crate declaration | `/Users/bobstewart/dev/exochain/crates/exo-root/Cargo.toml` | crate description explicitly names ceremony, FROST DKG, threshold signatures, and trust bundle verification | root-primitives evidence exists |
| Root ceremony policy | `/Users/bobstewart/dev/exochain/crates/exo-root/src/ceremony.rs` | `ROOT_GENESIS_THRESHOLD: 7` and `ROOT_GENESIS_SIGNERS: 13` | 7-of-13 FROST root policy is source-backed |
| Root DKG path | `/Users/bobstewart/dev/exochain/crates/exo-root/src/dkg.rs` | DKG types and helpers are implemented | distributed key generation path exists |
| Root bundle verification | `/Users/bobstewart/dev/exochain/crates/exo-root/src/bundle.rs` | `verify_root_bundle` validates config, package, signature, and bundle id | root trust bundle verification path exists |
| Root signature verification | `/Users/bobstewart/dev/exochain/crates/exo-root/src/signing.rs` | `threshold_sign` and `verify_root_signature` are implemented | root threshold signature path exists |

Additional EXOCHAIN production/root-trust evidence is now source-backed:

| Evidence class | Source | Fact | LiveSafe meaning |
| --- | --- | --- | --- |
| Production health | `https://exochain-production.up.railway.app/health` | `HTTP/2 200`, `status: ok`, version `0.1.0-beta` | EXOCHAIN production health is verified for the production-evidence gate |
| Production readiness | `https://exochain-production.up.railway.app/ready` | `HTTP/2 200`, `status: ok`, version `0.1.0-beta` | EXOCHAIN production readiness is verified for the production-evidence gate |
| Root-trust bundle verifier | `/tmp/exochain-origin-main-verify` at commit `379a45e1d9ab092ecd446d095a7b524570530efd` | `genesis verify-bundle` returned `{"verified":true}` for bundle id `7d9954a797ef244c15ad1b733cf77598125ccef0f812a404137e827c192d6a58` | EXOCHAIN production/root evidence is verified, but LiveSafe public trust claims remain blocked until adapter proof |
| Production sentinels | `https://exochain-production.up.railway.app/api/v1/sentinels` | `Liveness` and `ReceiptIntegrity` healthy; `QuorumHealth` below BFT minimum | quorum state is a non-blocking observation for this LiveSafe evidence gate, not a public LiveSafe trust activation |

This inventory supports local architecture and boundary analysis only. It does
authorize the intermediate statement that EXOCHAIN root evidence is verified in
read-only source review. It does not authorize LiveSafe to claim runtime
enforcement, custody proof, consent proof, revocation proof, or root-backed
public trust.

## Trust-State Ladder

| Ladder state | Current state | Meaning |
| --- | --- | --- |
| EXOCHAIN root evidence verified | yes | current read-only EXOCHAIN source proves root primitives exist |
| EXOCHAIN production evidence verified | yes | production health/readiness and root-trust bundle verification pass |
| LiveSafe adapter verified | no | no verified LiveSafe runtime adapter path is wired |
| Public trust claims allowed | no | live trust-status route remains `not_verified` and `public_claims_allowed: false` |

## Deployment Drift

The repo still shows two deployment stories:

- `railway.json` defines the active deployment control with Dockerfile build
  and `/api/health` as the health check.
- The live production endpoint
  `https://livesafe-api-production.up.railway.app/api/health` currently serves
  from Railway and reports healthy database connectivity.
- The live production trust-status endpoint
  `https://livesafe-api-production.up.railway.app/api/trust/status` currently
  serves from Railway and remains fail-closed.
- The EXOCHAIN production endpoint
  `https://exochain-production.up.railway.app` is verified separately from
  LiveSafe and is recorded only as production root-trust evidence for the
  adjacent LiveSafe trust-status payload.
- Railway CLI verification is currently available and confirms the repo-linked
  `livesafe-api` service tracks `main`; deployment ids are volatile release
  evidence and must be read live during closeout.
- `docs/context/LIVESAFE_CONTEXT_SEED.md` records Railway project `livesafe`,
  production environment, `livesafe-api` service, `Postgres`, and region
  `us-east4-eqdc4a`.
- `fly.toml` still records a prior `livesafe-api` Fly deployment shape with
  `primary_region = "iad"` and its own `/api/health` check.
- `README.md` now describes Railway as the current deployment target and
  classifies `fly.toml` as a historical drift artifact.

Current source-backed conclusion: Railway is the live deployment truth, while
Fly artifacts remain as historical drift in repo configuration. User-facing
docs should treat Railway as current and classify Fly files as historical.
Latest live public probes stayed fail-closed on 2026-06-05, but their exact
timestamps belong in automation closeout evidence rather than this control doc.

## Adapter Activation Boundary

LiveSafe remains on the inactive side of the EXOCHAIN boundary until all of the
following become true:

1. A runtime route or library path invokes a verified EXOCHAIN adapter.
2. Tests prove denial on `deny`, `rejected`, `timeout`, `unavailable`,
   `not-called`, `stale`, `revoked`, and `contradicted` EXOCHAIN responses.
3. Tests prove malformed credentials, signatures, consent records, authority
   chains, provenance records, custody receipts, tenant identifiers, and
   emergency-access grants fail closed.
4. Tests prove raw sensitive payloads remain off-chain and out of receipt
   paths.
5. Health, status, debug, telemetry, and error routes stay redacted.
6. Public copy and status payloads keep `public_claims_allowed: false` unless
   both EXOCHAIN production evidence and LiveSafe adapter gates pass.

Current repo evidence stops short of that boundary:

- `src/exochain-boundary.ts` denies trust claims unless the adapter state is
  `verified`.
- `src/exochain-root-trust-state.ts` treats root evidence as distinct from
  adapter verification and public claims.
- `src/exochain_adapter_activation.rs` requires an available dependency,
  `permit` response, well-formed authority inputs, metadata-only payloads, and
  redacted status routes.
- `server/utils/livesafe-exochain-adapter.js` now enforces an inactive-by-default
  route boundary for `getIdentity`, `registerIdentity`, `anchorAuditReceipt`,
  `anchorScan`, `anchorConsent`, and `getPaceStatus`, denies transport calls
  while the adapter stays `not-wired`, rejects malformed audit-receipt hashes
  and unsupported audit-anchor event types before any EXOCHAIN write attempt,
  collapses thrown EXOCHAIN transport failures into fail-closed `timeout` or
  `unavailable` states instead of letting exceptions escape the adapter
  boundary,
  rejects malformed identity DIDs before any EXOCHAIN identity or P.A.C.E.
  status call, rejects malformed required `scan` and `consent` identifiers
  including whitespace-only string ids before any EXOCHAIN write attempt,
  rejects malformed `scan` wrapper inputs such as invalid responder DIDs,
  non-negative integer epoch-millisecond timestamps, or audit-receipt hashes
  before any EXOCHAIN write attempt, and preserves explicit zero-valued
  timestamp fields when the wrapped GraphQL client builds its transport
  payload,
  rejects malformed `consent` wrapper inputs such as invalid provider DIDs,
  whitespace-bearing or otherwise malformed scope tokens, or non-negative
  integer epoch-millisecond timestamps before any EXOCHAIN write attempt, and
  preserves explicit zero-valued timestamp fields when the wrapped GraphQL
  client builds its transport payload, and the wrapped GraphQL client itself
  now redacts thrown direct-client gateway transport failures into bounded
  `EXOCHAIN_TIMEOUT` or `EXOCHAIN_UNAVAILABLE` error codes and redacts non-OK
  gateway responses into `EXOCHAIN_GATEWAY_REJECTED` instead of reflecting raw
  socket, DNS, or upstream exception text through its direct-client error
  shape, and the wrapped GraphQL client itself now rejects malformed
  direct-client identity and P.A.C.E. subscriber DIDs
  before `registerIdentity`, `getIdentity`, or `getPaceStatus` can issue a
  GraphQL query, rejects malformed direct-client audit subscriber DIDs,
  malformed audit-receipt hashes, and unsupported audit event types before
  `anchorAuditReceipt` can issue a GraphQL query, and rejects malformed
  direct-client `scan` and `consent`
  identifiers before any GraphQL query is sent instead of coercing them into
  transport payload strings, while also rejecting malformed optional
  responder/provider DIDs, malformed scope tokens, invalid optional
  epoch-millisecond timestamps, malformed audit-receipt hashes, missing
  consent input objects, and any explicit raw-sensitive `location` field
  before any GraphQL query is sent, while omitting the `location` field
  entirely from metadata-only scan anchor transport payloads,
  rejects raw-sensitive scan payloads including any explicit `location` field
  before any EXOCHAIN write attempt, and exposes only a redacted
  wrapped-operation inventory through runtime status helpers.
- `server/routes/scan.js` now builds metadata-only EXOCHAIN anchor payloads
  before it crosses into the runtime adapter boundary, passing scan
  identifiers, responder/subscriber DIDs, timestamps, and audit hashes while
  omitting explicit raw-sensitive location values from the adapter call site.
- `server/routes/scan.js` now routes `GET /api/scan/access/:accessToken`
  through bounded helpers that expose the emergency subset and expiry metadata
  without echoing raw access tokens, internal scan ids, subscriber-linked row
  ids, or trustee DID metadata through the token-gated public response
  surface.
- `server/routes/pace.js` now keeps governance and identity-recovery audit
  receipts fail-closed when no verified adapter path is invoked, storing local
  audit metadata with explicit `exochain_anchor_state: not_called`,
  `runtime_adapter_state: not-wired`, `public_claims_allowed: false`, and
  response copy that no longer claims the event was recorded on EXOCHAIN.
- `server/routes/subscribers.js` and `server/routes/records.js` now keep
  deletion-audit receipts fail-closed when no verified adapter path is
  invoked, storing local audit metadata with explicit
  `exochain_anchor_state: not_called`, `runtime_adapter_state: not-wired`,
  `public_claims_allowed: false`, and notes that no longer claim EXOCHAIN
  preservation for subscriber-account or medical-record deletion events.
- `server/routes/notifications.js` now returns bounded subscriber-notification
  summaries through `server/utils/notification-response.js` so authenticated
  notification list, create, and mark-read responses keep user-visible
  content fields while avoiding recipient DID echoes, recipient-type routing,
  channel internals, or wildcard notification row exposure, and notification
  read-all, dismiss, dismiss-all, and unread-count routes now return bounded
  acknowledgement and count metadata without reflecting raw notification ids
  through adjacent response surfaces.
- `server/routes/alerts.js` now routes alert dispatch, history, P.A.C.E.
  alert-history, and trustee-notification responses through
  `server/utils/alert-response.js` so adjacent alert surfaces keep bounded
  role, channel, and response-status metadata without echoing trustee email
  addresses, recipient DIDs, raw notification rows, scan locations,
  subscriber DIDs, or scan ids, and trustee P.A.C.E.-response acknowledgements
  now return bounded response status, response copy, and timestamp metadata
  without reflecting raw notification ids through `POST /api/alerts/respond/:notificationId`.
- `server/routes/alerts.js` and `server/utils/alert-response.js` now keep the
  authenticated subscriber alert-event history route fail-closed by reusing
  the bounded alert-detail sanitization path, exposing only event counts,
  read-state, and allowlisted card-scan or trustee-response detail fields
  instead of reflecting raw notification bodies, embedded subscriber DIDs,
  trustee DIDs, scan locations, or scan ids through
  `GET /api/alerts/subscriber-events/:subscriberDid`.
- `server/routes/alerts.js` and `server/utils/alert-response.js` now keep the
  subscriber-facing P.A.C.E. alert-history route fail-closed by routing
  `GET /api/alerts/pace-alerts/:subscriberDid` through a bounded helper that
  exposes only sanitized alert entries, unread and total counts, and trustee
  count metadata instead of hand-building a route-level wrapper around raw
  notification rows.
- `server/routes/credentials.js` and
  `server/utils/credential-custody-receipt.js` now keep advance-directive and
  power-of-attorney custody receipts fail-closed when no verified adapter path
  is invoked, storing metadata-only encrypted local custody receipts with
  explicit `exochain_anchor_state: not_called`,
  `runtime_adapter_state: not-wired`, `public_claims_allowed: false`, and
  success copy that no longer claims EXOCHAIN bailment or on-chain storage.
- `server/routes/credentials.js` now keeps credential update acknowledgements
  fail-closed by reusing `sanitizeCredentialForResponse(result.rows[0])`
  instead of reflecting raw encrypted file metadata, document paths, or
  unsanitized vault row payloads through `PUT /api/credentials/:id`.
- `server/routes/credentials.js` now keeps insurance-card upload
  acknowledgements fail-closed by reusing
  `sanitizeCredentialForResponse(result.rows[0])` and by omitting the raw
  server-side upload filename from the returned `file` metadata, so
  `POST /api/credentials/insurance` no longer reflects internal storage-path
  handles or unsanitized vault row payloads through its adjacent credential
  upload response.
- `server/routes/card.js` and
  `server/utils/card-issuance-audit-metadata.js` now keep emergency-card
  issuance audit receipts fail-closed when no verified adapter path is
  invoked, storing explicit local-audit metadata with
  `exochain_anchor_state: not_called`, `runtime_adapter_state: not-wired`,
  `public_claims_allowed: false`, and notes that no longer carry EXOCHAIN
  event markers for card issuance.
- `server/utils/card-response.js`, `server/routes/card.js`, and
  `client/src/pages/Card.jsx` now keep emergency-card issue, status, and NFC
  metadata surfaces fail-closed by returning bounded card-status and
  pointer-state metadata instead of reflecting raw `qr_data`, `nfc_payload`,
  `emergency_consent_token`, or responder scan URLs through adjacent card APIs
  or the card UI.
- `server/routes/consent.js` and
  `server/utils/consent-audit-metadata.js` now keep consent grant and
  revocation audit receipts fail-closed when no verified adapter path is
  invoked, storing explicit local-audit metadata with
  `exochain_anchor_state: not_called`, `runtime_adapter_state: not-wired`,
  `public_claims_allowed: false`, and response copy that no longer implies
  EXOCHAIN anchoring for local consent receipts.
- `server/utils/consent-response.js` and `server/routes/consent.js` now keep
  direct consent-event list, grant, revoke, check, legacy list, and approval
  responses fail-closed by returning bounded scope, timing, provider-summary,
  and derived status metadata instead of reflecting internal subscriber or
  provider ids, provider email addresses, or raw `exochain_receipt` fields
  through the adjacent consent API surface.
- `server/utils/consent-response.js` and `server/routes/consent.js` also now
  keep verified provider-directory listings, subscriber access-request lists,
  provider access-request lists, provider request-create acknowledgements, and
  access-request approval acknowledgements fail-closed by returning bounded
  provider-summary, request-status, and subscriber-name metadata instead of
  reflecting provider DIDs, provider email addresses, free-text request
  messages, or raw request rows through the adjacent consent API surface.
- `server/utils/consent-response.js` and `server/routes/consent.js` now also
  keep idempotent grant, revoke, access-check, expiry-check, and access-request
  denial acknowledgements fail-closed by returning bounded consent, status,
  and count metadata instead of reflecting internal consent ids or raw request
  rows through adjacent consent acknowledgement paths.
- `server/routes/scan.js` now keeps local emergency-card scan audit receipts
  fail-closed when no verified adapter path is invoked, storing explicit
  local-audit metadata with `exochain_anchor_state: not_called`,
  `runtime_adapter_state: not-wired`, `public_claims_allowed: false`, and a
  note that no longer carries an EXOCHAIN event marker for local scan
  receipts.
- `server/routes/scan.js` also keeps successful scan responses fail-closed
  when downstream P.A.C.E. alert delivery fails, returning bounded
  `pace_alert_delivery.status: failed` and
  `pace_alert_delivery.reason: notification_delivery_failed` metadata instead
  of reflecting raw provider exception text through the public response body,
  and now routes both successful and degraded `POST /api/scan` responses
  through a bounded summary helper that does not reflect raw access tokens,
  raw location values, internal database identifiers, or trustee recipient
  identifiers through responder-facing response payloads.
- `server/utils/pace-invitations.js` now keeps P.A.C.E. invitation delivery
  fail-closed when configured email or SMS providers throw, returning bounded
  `delivery.email.reason: notification_delivery_failed` and
  `delivery.sms.reason: notification_delivery_failed` metadata instead of
  reflecting raw provider exception text through trustee invitation response
  surfaces or persisted delivery-error codes.
- `server/routes/pace.js` now keeps trustee nomination validation fail-closed
  by returning bounded invalid-email, missing-SMS-phone, and duplicate-role
  response codes instead of reflecting nominee email addresses through public
  validation error payloads.
- `server/routes/pace.js` now keeps emergency-access-override initiation
  acknowledgements fail-closed by routing both the existing-pending and
  created workflow responses through a bounded helper that exposes only
  workflow ids, signer counts, deadlines, approval-remaining metadata,
  normalized initiator role, and trustee-notified counts instead of
  reflecting workflow signer internals or metadata through public initiation
  payloads.
- `server/routes/pace.js` now keeps the unauthenticated expired-invitation
  resend request fail-closed by returning a bounded acknowledgement code
  instead of reflecting subscriber names, trustee email addresses, or role
  labels through the public response body.
- `server/routes/pace.js` now keeps trustee nomination, invitation send, and
  resend responses fail-closed by returning bounded role, status, and
  delivery-state metadata instead of reflecting trustee email addresses, invite
  phone numbers, invitation tokens, invitation URLs, or provider message ids
  through the public response body.
- `server/routes/pace.js` now keeps unauthenticated invitation validate and
  decline responses fail-closed by returning bounded role metadata and decline
  acknowledgement fields instead of reflecting subscriber names or trustee
  email addresses through public response bodies.
- `server/routes/pace.js` now keeps governance and identity-recovery workflow
  status and signing responses fail-closed by returning bounded signer role
  summaries, signer counts, timestamps, and safe metadata summaries instead of
  reflecting signer email addresses, raw workflow metadata, raw recovery
  records, or raw audit-receipt payloads through public response bodies.
- `server/routes/pace.js` now keeps trustee-replacement and identity-recovery
  workflow initiation responses fail-closed by returning bounded workflow ids,
  signer counts, role summaries, and deadlines instead of reflecting cosigner
  ids, recovery-record ids, or workflow creation timestamps through public
  acknowledgement payloads.
- `server/routes/pace.js` now keeps trustee invitation-acceptance responses
  fail-closed by returning bounded trusteeship and VSS-enrollment summaries
  instead of reflecting trustee email addresses, raw shard references, or VSS
  master-key hashes through the acceptance response body.
- `server/routes/pace.js` now keeps public identity-recovery status summaries
  fail-closed by returning bounded recovery state and audit event fields
  instead of reflecting internal recovery-record ids or audit-receipt
  timestamps through recovery status payloads.
- `server/routes/pace.js` now keeps the unauthenticated P.A.C.E. VSS-status
  route fail-closed by returning bounded ceremony and trustee-shard summary
  fields instead of reflecting trustee email addresses, raw shard references,
  master-key hashes, or trigger metadata through the public response body.
- `server/routes/pace.js` now keeps the unauthenticated P.A.C.E.
  trustee-directory route fail-closed by returning bounded role and VSS
  enrollment summaries instead of reflecting trustee email addresses, invite
  phone numbers, invitation URLs, delivery-state internals, or master-key
  hashes through the public response body.
- `server/routes/pace.js`, `server/routes/auth.js`, and
  `server/utils/trustee-vss-summary.js` now keep trustee-facing subscriber
  detail and trusteeship surfaces fail-closed by returning bounded
  `has_vss_shard` and `shard_status` fields instead of reflecting raw shard
  references through trustee-facing API responses or UI payloads.
- `server/routes/scan.js` now keeps expanded-access governance workflow
  request, status, and approved-access responses fail-closed by returning
  bounded workflow ids, signer counts, deadlines, approval timestamps,
  signer role/timestamp summaries, and bounded no-workflow status copy
  instead of reflecting responder ids, raw workflow metadata, or signer
  email or DID fields through public responses.
- `server/routes/scan.js` now keeps approved expanded-data responses
  fail-closed by returning bounded subscriber emergency fields, credential
  summaries, and medical-record metadata instead of reflecting raw credential
  ids, subscriber ids, or medical-record storage paths through the responder
  payload.
- `server/routes/scan.js` now keeps expanded-access initiation acknowledgements
  fail-closed by routing both duplicate-pending and newly created governance
  workflow wrappers through a bounded helper that exposes only workflow ids,
  signer counts, deadlines, approvals remaining, trustee-notification counts,
  and stable acknowledgement copy instead of reflecting raw workflow metadata,
  responder ids, or notification rows.
- `server/routes/scan.js` now keeps agency-admin scan roster and flagged-scan
  responses fail-closed by returning bounded scan summary fields instead of
  reflecting raw access tokens, raw location values, subscriber email
  addresses, or internal database identifiers through agency roster payloads.
- `server/routes/scan.js` now keeps scan follow-up flag acknowledgements
  fail-closed by returning bounded status and note-presence metadata instead of
  reflecting raw scan ids or freeform `followup_notes` bodies through
  `PATCH /api/scan/:scanId/flag`.
- `server/routes/scan.js` now keeps the agency-admin responder filter route
  fail-closed by returning bounded responder summary fields instead of
  reflecting responder DIDs or raw responder rows through
  `GET /api/scan/agency/responders`.
- `server/utils/admin-responder-response.js` and `server/routes/admin.js` now
  keep agency-admin responder roster and activation responses fail-closed by
  returning bounded responder summary fields instead of reflecting responder
  DIDs, internal `agency_id` bindings, or raw responder rows through
  `GET /api/admin/agencies/:id/responders` or `PATCH /api/admin/responders/:id`.
- `server/utils/admin-subscriber-response.js` and `server/routes/admin.js` now
  keep platform-admin subscriber list, detail, and account-update responses
  fail-closed by returning bounded subscriber summary fields instead of
  reflecting subscriber DIDs or raw subscriber rows through
  `GET /api/admin/subscribers`, `GET /api/admin/subscribers/:id`, or
  `PATCH /api/admin/subscribers/:id`.
- `server/utils/admin-audit-response.js` and `server/routes/admin.js` now keep
  platform-admin audit reads fail-closed by returning bounded audit-event
  summaries instead of reflecting subject DIDs, previous-hash links,
  EXOCHAIN receipt references, subscriber email joins, or raw audit rows
  through `GET /api/admin/audit`.
- `server/utils/admin-subscriber-response.js` and `server/routes/subscribers.js`
  now keep the legacy subscriber-management alias fail-closed by requiring
  subscriber-admin authentication on `GET /api/subscribers`,
  `PATCH /api/subscribers/:did`, and `DELETE /api/subscribers/:id`, while
  routing the legacy list alias through the bounded admin subscriber helper so
  it no longer reflects subscriber DIDs, blood type, birth date, or raw
  subscriber rows through the adjacent subscriber API surface.
- `server/utils/admin-subscriber-response.js` and `server/routes/subscribers.js`
  now keep the legacy subscriber create/detail routes fail-closed by routing
  `POST /api/subscribers` and `GET /api/subscribers/:did` through the bounded
  admin subscriber helper instead of reflecting raw subscriber rows, DIDs,
  blood type, or birth date through the adjacent subscriber API surface.
- `server/utils/subscriber-profile-response.js` and
  `server/routes/subscribers.js` now keep authenticated subscriber-owned
  profile read and update responses fail-closed by returning bounded profile,
  allergy, medication, condition, and emergency-contact metadata instead of
  reflecting subscriber DIDs, roles, or raw subscriber-bound rows through
  `GET /api/subscribers/profile` or `PUT /api/subscribers/profile`.
- `server/utils/subscriber-profile-response.js` and
  `server/routes/subscribers.js` now keep authenticated emergency-contact
  create and update acknowledgements fail-closed by returning bounded contact
  metadata instead of reflecting `subscriber_id` bindings or raw
  emergency-contact rows through
  `POST /api/subscribers/profile/emergency-contacts` or
  `PUT /api/subscribers/profile/emergency-contacts/:id`.
- `server/utils/subscriber-profile-response.js` and
  `server/routes/subscribers.js` now keep authenticated allergy, medication,
  and condition create acknowledgements fail-closed by returning bounded
  medical-entry metadata and bounded `odentity_claim` summaries instead of
  reflecting `subscriber_id` bindings, raw claim rows, or raw
  subscriber-owned medical-entry rows through
  `POST /api/subscribers/profile/allergies`,
  `POST /api/subscribers/profile/medications`, or
  `POST /api/subscribers/profile/conditions`.
- `server/utils/subscriber-profile-response.js` and
  `server/routes/subscribers.js` now keep authenticated allergy, medication,
  condition, and emergency-contact delete acknowledgements fail-closed by
  returning bounded success messages instead of reflecting raw row ids through
  `DELETE /api/subscribers/profile/allergies/:id`,
  `DELETE /api/subscribers/profile/medications/:id`,
  `DELETE /api/subscribers/profile/conditions/:id`, or
  `DELETE /api/subscribers/profile/emergency-contacts/:id`.
- `server/utils/subscriber-profile-response.js` and `server/routes/subscribers.js` now keep authenticated subscriber alert-settings and consent-defaults reads and writes fail-closed by
  returning bounded settings metadata, bounded option lists, and bounded
  success messages instead of reflecting subscriber ids, DIDs, or raw
  subscriber rows through `GET /api/subscribers/alert-settings`,
  `PUT /api/subscribers/alert-settings`,
  `GET /api/subscribers/consent-defaults`, or
  `PUT /api/subscribers/consent-defaults`.
- `server/utils/admin-agency-response.js`, `server/routes/admin.js`, and
  `client/src/pages/AdminDashboard.jsx` now keep platform-admin agency list,
  deactivation, and reactivation flows fail-closed by returning and consuming
  bounded agency summary plus responder-count metadata instead of reflecting
  `admin_email` values, expecting stale `reactivated_responders` counters, or
  rendering raw responder rows through `GET /api/admin/agencies`,
  `DELETE /api/admin/agencies/:id`, or
  `POST /api/admin/agencies/:id/reactivate`.
- `server/utils/admin-stats-response.js` and `server/routes/admin.js` now keep
  platform-admin stats reads fail-closed by returning bounded numeric count
  metadata instead of hand-building public payloads from raw aggregate query
  rows through `GET /api/admin/stats`.
- `server/utils/auth-responder-response.js` and `server/routes/auth.js` now
  keep responder registration, responder login/profile, and agency
  registration responses fail-closed by returning bounded responder and agency
  summary fields instead of reflecting internal `agency_id` bindings,
  agency-admin email echoes, raw responder rows, or inline responder or agency
  registration/login session wrappers through
  `POST /api/auth/responder/register`, `POST /api/auth/responder/login`,
  `GET /api/auth/responder/me`, or `POST /api/auth/agency/register`.
- `server/utils/auth-responder-response.js` and `server/routes/auth.js` now
  keep the public agency registration-directory route fail-closed by returning
  bounded agency identity and verification metadata instead of reflecting
  `created_at` timestamps or raw agency rows through `GET /api/auth/agencies`.
- `server/utils/auth-subscriber-response.js` and `server/routes/auth.js` now
  keep subscriber registration, subscriber login, and current-user responses
  fail-closed by returning bounded subscriber identity, tier, and verification
  metadata instead of reflecting password hashes, verification tokens,
  `created_at` timestamps, or raw subscriber rows through
  `POST /api/auth/register`, `POST /api/auth/login`, or `GET /api/auth/me`.
- `server/routes/scan.js`, `client/src/pages/ScanHistory.jsx`, and
  `client/src/pages/ScanDetail.jsx` now keep subscriber scan-history and
  scan-detail responses fail-closed by returning bounded scan timing, type,
  responder-role, agency, and `location_recorded` metadata instead of
  reflecting responder email addresses, responder DIDs, raw location values,
  access tokens, follow-up notes, or internal scan row fields through the
  subscriber history surface.
- `server/routes/scan.js` now keeps responder-authenticated emergency-subset
  responses fail-closed by returning bounded emergency-only subscriber,
  medication, condition, contact, and emergency-visible insurance fields
  instead of reflecting subscriber-linked row ids, credential visibility
  internals, or other raw credential metadata through
  `GET /api/scan/data/:subscriberDid`.
- `server/routes/records.js` and
  `server/utils/record-extracted-data.js` now keep XML, C-CDA, FHIR, and JSON
  upload parsing fail-closed by storing bounded `parse_error` codes and
  `parse_error_stage` metadata instead of reflecting raw parser exception text
  or document fragments through upload responses or persisted
  `medical_records.extracted_data`.
- `server/routes/records.js`, `server/utils/record-request-response.js`, and
  `client/src/pages/Records.jsx` now keep HIPAA Right-of-Access request create,
  list, legacy DID list, and status-update responses fail-closed by returning
  bounded provider, status, readiness, and timestamp metadata instead of
  reflecting `subscriber_id`, raw letter-storage paths, or free-form internal
  status notes through records-request API payloads or the records UI; the
  active authenticated `GET /api/records/requests` route now reuses that
  bounded helper directly, and the duplicate raw-row list handler was removed
  so the live runtime path matches the documented fail-closed contract.
- `server/routes/records.js` and
  `server/utils/medical-record-response.js` now keep authenticated
  medical-record upload, list, detail, version-history, visibility-update,
  annotation-update, and delete-acknowledgement responses fail-closed by
  returning bounded medical-record metadata, version-history envelopes,
  encryption-status payloads, and deletion acknowledgements instead of
  reflecting `subscriber_id`, raw file-storage paths, file hashes,
  version-chain parent identifiers, or deletion timestamps through the records
  API surface.
- `server/routes/records.js` and
  `server/utils/record-provider-response.js` now keep the verified-provider
  directory for records requests fail-closed by returning bounded provider id,
  name, NPI, facility, specialty, and verification-state metadata instead of
  reflecting raw provider rows; the duplicate shadow `/api/records/providers`
  handler was removed so the active runtime path cannot drift away from the
  bounded helper contract.
- `server/routes/records.js`,
  `server/utils/clinical-note-response.js`, and
  `client/src/pages/Records.jsx` now keep provider clinical-note create,
  subscriber list, provider list, approve, and reject responses fail-closed by
  routing both note bodies and route-level acknowledgement/list envelopes
  through bounded helpers that return only safe note, participant-name, and
  count metadata instead of reflecting provider email addresses, provider or
  subscriber DIDs, raw provider or subscriber ids, or rejection reasons
  through the records API surface or records UI.
- `server/utils/odentity-claim-response.js` and `server/routes/odentity.js`
  now keep authenticated 0dentity claim reads fail-closed by returning bounded
  claim type, dimension, points, issuer, and issuance metadata instead of
  reflecting raw `subscriber_id`, `credential_hash`, or row timestamps through
  `GET /api/odentity/me/claims`; the legacy
  `GET /api/odentity/:subscriberId/claims` path now also requires
  authentication plus same-subscriber ownership instead of returning raw claim
  rows anonymously.
- `server/routes/odentity.js` now keeps the legacy
  `GET /api/odentity/:subscriberId/gated-features` path ownership-scoped by
  requiring authentication plus same-subscriber access instead of exposing
  0dentity feature-unlock metadata anonymously through a subscriber-id route.
- `server/utils/odentity-gated-features-response.js` and
  `server/routes/odentity.js` now keep authenticated 0dentity gated-features
  reads fail-closed by returning bounded composite-score and feature-unlock
  metadata instead of reflecting top-level `subscriber_id` bindings through
  `GET /api/odentity/me/gated-features` or the ownership-scoped
  `GET /api/odentity/:subscriberId/gated-features` route.
- `server/utils/odentity-score-response.js` and `server/routes/odentity.js`
  now keep authenticated 0dentity score reads fail-closed by returning bounded
  dimension, weight, score, claim-count, composite-score, and polygon-area
  metadata instead of reflecting raw `subscriber_id` bindings or score-row
  timestamps through `GET /api/odentity/me/score` or the legacy
  `GET /api/odentity/:subscriberId/score` route.
- `server/utils/odentity-export-response.js` and `server/routes/odentity.js`
  now keep authenticated 0dentity verifiable-credential exports fail-closed by
  returning bounded score and claim metadata instead of reflecting raw claim
  ids, claim issuers, per-claim issuance timestamps, or score-row subscriber
  bindings through `GET /api/odentity/me/export-vc`.
- `server/utils/odentity-claim-response.js` and `server/routes/odentity.js`
  now keep 0dentity claim import and revoke acknowledgements fail-closed by
  returning bounded claim metadata instead of reflecting raw
  `odentity_claims` rows, `subscriber_id` bindings, or `credential_hash`
  values through `POST /api/odentity/claims/import` or
  `POST /api/odentity/claims/:claimId/revoke`.
- `server/routes/odentity.js` now keeps `POST /api/odentity/claims/import`
  fail-closed on authority by requiring subscriber authentication plus
  same-subscriber ownership or admin authority instead of accepting anonymous
  claim writes for arbitrary `subscriber_id` values through the local
  0dentity claim-import path.
- `server/utils/odentity-trust-event-response.js` and
  `server/routes/odentity.js` now keep local 0dentity trust-event
  acknowledgements fail-closed by returning bounded event metadata instead of
  reflecting raw `actor_subscriber_id`, `target_subscriber_id`, or
  `exochain_receipt` fields through `POST /api/odentity/events/record`.
- `server/routes/odentity.js` now keeps `POST /api/odentity/events/record`
  fail-closed on authority by requiring subscriber authentication plus
  same-subscriber actor and target scope for non-admin callers instead of
  accepting anonymous or cross-subscriber trust-event writes through the local
  0dentity trust-event path.
- `server/utils/audit-immutability-policy.js`, `server/routes/audit.js`, and
  `server/routes/admin.js` now keep audit-immutability responses and PDF
  export footer copy fail-closed when no verified adapter path is invoked,
  storing explicit local-audit classification with
  `exochain_anchor_state: not_called`, `runtime_adapter_state: not-wired`,
  `public_claims_allowed: false`, and copy that no longer claims tamper-proof
  EXOCHAIN policy enforcement for local database audit receipts.
- `server/utils/auth-provider-response.js` and `server/routes/auth.js` now
  keep provider registration, login, and current-user responses fail-closed by
  returning bounded provider identity, facility, specialty, verification, and
  consent-summary metadata instead of reflecting raw provider rows,
  `subscriber_id` bindings, or provider-row timestamps through the adjacent
  provider-auth API surface.
- `server/utils/auth-provider-response.js` and `server/routes/auth.js` now
  keep the public provider NPI lookup route fail-closed by returning bounded
  provider name, taxonomy, facility, status, enumeration, and coarse address
  metadata instead of reflecting split first-name or last-name fields or raw
  address internals through `GET /api/auth/provider/npi-lookup/:npi`.
- `server/utils/auth-trustee-response.js`, `server/utils/trustee-vss-summary.js`,
  and `server/routes/auth.js` now keep trustee login and current-user
  responses fail-closed by returning bounded trustee identity, trusteeship,
  and shard-status metadata instead of reflecting password hashes,
  subscriber DIDs, or raw shard references through the adjacent trustee-auth
  API surface.
- `server/utils/verification-response.js`, `server/routes/auth.js`,
  `server/routes/subscribers.js`, `client/src/pages/VerifyEmail.jsx`, and
  `client/src/pages/Profile.jsx` now keep email-verification and
  phone-verification acknowledgements fail-closed by returning bounded
  verification status, masked verification-target hints, expiry metadata, and
  dev-only verification codes instead of reflecting raw subscriber email or
  phone values through adjacent auth or subscriber verification routes.
- `server/utils/audit-response.js`, `server/routes/audit.js`,
  `client/src/pages/AuditTrail.jsx`, and `client/src/pages/Settings.jsx` now
  keep audit-trail read payloads and audit-facing subscriber copy fail-closed
  by returning bounded event fields plus allowlisted deletion details only,
  while preserving append-only local-audit wording instead of reflecting raw
  audit chain internals or active EXOCHAIN immutability claims.
- `server/utils/research-response.js` and `server/routes/research.js` now keep
  subscriber-facing research opt-in, audit, and trial-consent response
  boundaries plus trial-match
  responses bounded to opt-in state, audit summaries, and enrollment metadata
  without echoing subscriber DIDs, CyberMedica consent references, ZK proof
  references, or raw audit `details` payloads through the adjacent research
  API surface.
- `server/utils/device-response.js`, `server/routes/devices.js`, and
  `client/src/pages/Settings.jsx` now keep subscriber device-management flows
  fail-closed by exposing bounded `device_id`, display-name, active-state,
  timestamp, and device-token fields while using `device_id` as the public
  revoke handle instead of echoing internal `key_ref` bindings, revoke
  reasons, or other device-signing-key internals through the API or settings
  surface.
- `client/src/pages/Research.jsx`, `client/src/pages/ProviderAccess.jsx`, and
  `client/src/pages/Settings.jsx` now keep research, provider-consent, and
  DID-status copy fail-closed by preserving local-audit and inactive-adapter
  wording instead of claiming active EXOCHAIN consent anchoring, immutable
  EXOCHAIN enforcement, or cryptographically anchored DID status through
  customer-facing UI.
- `server/utils/exochain-connectivity-status.js` now keeps startup and health
  connectivity reporting fail-closed by skipping direct EXOCHAIN health probes
  whenever the runtime adapter status is anything other than `verified`, and
  normalizes verified-adapter probe failures to an unavailable state instead of
  leaking raw transport behavior through status surfaces.
- `server/utils/health-status.js` now keeps `/api/health` fail-closed on
  database errors by returning bounded availability metadata instead of raw
  database error text through the public status surface.
- `server/utils/errorHandler.js`, `server/index.js`, `server/routes/auth.js`,
  `server/routes/credentials.js`, and `server/routes/records.js` now keep
  auth, upload, and top-level API error responses redacted by returning
  bounded upload, database, and unexpected-failure payloads instead of raw
  exception text through public error surfaces.
- `server/utils/exochain-production-trust-evidence.js` evaluates EXOCHAIN
  production evidence from source-backed config without invoking LiveSafe
  adapter authority, and `server/utils/trust-status.js` exposes the verified
  production evidence while keeping LiveSafe public claims fail-closed until
  adapter proof passes.
- `tests/public-exochain-copy-boundary.test.ts` keeps public UI and metadata
  copy from claiming active EXOCHAIN bailment, audit, sovereignty, or trust
  before the adapter boundary is verified.
- `config/exochain-primitives.json` records `runtimeAdapterStatus` as
  `not-wired`.
- Live production health evidence currently reports `exochain_connected: false`.

## Disablement And Rollback

- Path classification: adjacent surface documentation and boundary mapping.
- Runtime exposure added by this slice: `GET /api/trust/status` as a read-only,
  explicitly inactive trust-state route.
- Rollback path: revert this document and any linked slice-map updates if the
  documented evidence becomes incorrect.
- Production-evidence rollback path: revert
  `config/exochain-production-trust.json`,
  `server/utils/exochain-production-trust-evidence.js`, the trust-status
  production-evidence payload fields, and the public-copy boundary changes.
- Operational disablement path for EXOCHAIN-facing behavior today: keep the
  runtime in its current unwired posture by keeping
  `config/exochain-primitives.json` at `runtimeAdapterStatus: not-wired`,
  keep trust-bearing UI in inactive or internal-proof states, and do not route
  product authority decisions past `server/utils/livesafe-exochain-adapter.js`
  until verified adapter gates pass.
