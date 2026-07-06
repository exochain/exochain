# Test Plan

## Current Gate

```bash
npm run quality
```

Focused validation for the current EXOCHAIN-client transport redaction,
invitation-delivery, trustee-validation redaction, invitation-response
redaction, invitation-send response redaction, workflow-response redaction,
workflow-initiation redaction, invitation-acceptance response redaction,
VSS-status redaction, trustee-facing VSS summary redaction, scan
expanded-access workflow redaction, scan agency roster redaction, subscriber
scan-history/detail redaction, scan emergency-subset response redaction, and
medical-record parse-redaction slice:

```bash
npm test -- tests/exochain-client.test.ts tests/pace-invitation-delivery.test.ts tests/pace-trustee-validation.test.ts tests/pace-request-resend-redaction.test.ts tests/pace-create-response-redaction.test.ts tests/pace-create-response-route-redaction.test.ts tests/pace-send-response-redaction.test.ts tests/pace-send-route-redaction.test.ts tests/pace-invitation-response-redaction.test.ts tests/pace-invitation-response-route.test.ts tests/pace-workflow-response-redaction.test.ts tests/pace-workflow-route-redaction.test.ts tests/pace-workflow-initiation-redaction.test.ts tests/pace-workflow-initiation-route-redaction.test.ts tests/pace-acceptance-response-redaction.test.ts tests/pace-acceptance-route-redaction.test.ts tests/pace-vss-status-redaction.test.ts tests/pace-vss-status-route-redaction.test.ts tests/pace-trustee-directory-redaction.test.ts tests/pace-trustee-directory-route-redaction.test.ts tests/trustee-vss-summary.test.ts tests/trustee-vss-route-redaction.test.ts tests/trustee-vss-ui-redaction.test.ts tests/scan-expanded-access-redaction.test.ts tests/scan-expanded-access-route-redaction.test.ts tests/scan-expanded-data-response-redaction.test.ts tests/scan-agency-redaction.test.ts tests/scan-agency-route-redaction.test.ts tests/scan-history-response-redaction.test.ts tests/scan-history-route-redaction.test.ts tests/scan-history-ui-redaction.test.ts tests/scan-emergency-subset-response-redaction.test.ts tests/scan-emergency-subset-route-redaction.test.ts tests/record-extracted-data.test.ts
npm test -- tests/exochain-client.test.ts tests/pace-invitation-delivery.test.ts tests/pace-trustee-validation.test.ts tests/pace-request-resend-redaction.test.ts tests/pace-create-response-redaction.test.ts tests/pace-create-response-route-redaction.test.ts tests/pace-send-response-redaction.test.ts tests/pace-send-route-redaction.test.ts tests/pace-invitation-response-redaction.test.ts tests/pace-invitation-response-route.test.ts tests/pace-workflow-response-redaction.test.ts tests/pace-workflow-route-redaction.test.ts tests/pace-workflow-initiation-redaction.test.ts tests/pace-workflow-initiation-route-redaction.test.ts tests/pace-acceptance-response-redaction.test.ts tests/pace-acceptance-route-redaction.test.ts tests/pace-vss-status-redaction.test.ts tests/pace-vss-status-route-redaction.test.ts tests/pace-trustee-directory-redaction.test.ts tests/pace-trustee-directory-route-redaction.test.ts tests/trustee-vss-summary.test.ts tests/trustee-vss-route-redaction.test.ts tests/trustee-vss-ui-redaction.test.ts tests/scan-expanded-access-redaction.test.ts tests/scan-expanded-access-route-redaction.test.ts tests/scan-expanded-data-response-redaction.test.ts tests/scan-agency-redaction.test.ts tests/scan-agency-route-redaction.test.ts tests/scan-history-response-redaction.test.ts tests/scan-history-route-redaction.test.ts tests/scan-history-ui-redaction.test.ts tests/scan-access-response-redaction.test.ts tests/scan-access-route-redaction.test.ts tests/scan-emergency-subset-response-redaction.test.ts tests/scan-emergency-subset-route-redaction.test.ts tests/record-extracted-data.test.ts
```

Focused validation for the human-safety opportunity inception slice:

```bash
cargo test --test human_safety_opportunity
npm test -- tests/context-docs.test.ts
npm run quality
```

Focused validation for the notification response and acknowledgement redaction slice:

```bash
npm test -- tests/notifications-response-redaction.test.ts tests/notifications-route-redaction.test.ts
npm test -- tests/context-docs.test.ts
npm run quality
```

Focused validation for the alert response redaction slice:

```bash
npm test -- tests/alerts-response-redaction.test.ts tests/alerts-route-redaction.test.ts
npm test -- tests/context-docs.test.ts
npm run quality
```

Focused validation for the subscriber alert-event response redaction slice:

```bash
npm test -- tests/alerts-response-redaction.test.ts tests/alerts-route-redaction.test.ts
npm test -- tests/context-docs.test.ts
npm run quality
```

Focused validation for the alert response acknowledgement redaction slice:

```bash
npm test -- tests/alerts-response-redaction.test.ts tests/alerts-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the P.A.C.E. alert-history envelope redaction slice:

```bash
npm test -- tests/alerts-response-redaction.test.ts tests/alerts-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the scan expanded-access initiation acknowledgement redaction slice:

```bash
npm test -- tests/scan-expanded-access-redaction.test.ts tests/scan-expanded-access-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the audit trail response and copy redaction slice:

```bash
npm test -- tests/audit-response-redaction.test.ts tests/audit-route-redaction.test.ts tests/public-exochain-copy-boundary.test.ts
npm test -- tests/context-docs.test.ts
npm run quality
```

Focused validation for the admin stats response redaction slice:

```bash
npm test -- tests/admin-stats-response-redaction.test.ts tests/admin-stats-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the scan follow-up acknowledgement redaction slice:

```bash
npm test -- tests/scan-agency-redaction.test.ts tests/scan-agency-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the research opt-in, audit, and trial-consent response redaction slice:

```bash
npm test -- tests/research-response-redaction.test.ts tests/research-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the consent-event response redaction slice:

```bash
npm test -- tests/consent-response-redaction.test.ts tests/consent-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the consent provider-directory and access-request response redaction slice:

```bash
npm test -- tests/consent-response-redaction.test.ts tests/consent-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the consent provider request-create acknowledgement redaction slice:

```bash
npm test -- tests/consent-response-redaction.test.ts tests/consent-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the device-management response redaction slice:

```bash
npm test -- tests/device-response-redaction.test.ts tests/device-route-redaction.test.ts tests/device-settings-public-handle.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the record-request response redaction slice:

```bash
npm test -- tests/record-request-response-redaction.test.ts tests/record-request-route-redaction.test.ts tests/record-request-ui-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the record-provider directory redaction slice:

```bash
npm test -- tests/record-provider-response-redaction.test.ts tests/medical-record-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the subscriber profile, medical-entry, and emergency-contact response redaction slice:

```bash
npm test -- tests/subscriber-profile-response-redaction.test.ts tests/subscriber-profile-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the subscriber settings response redaction slice:

```bash
npm test -- tests/subscriber-profile-response-redaction.test.ts tests/subscriber-profile-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the 0dentity claims response redaction slice:

```bash
npm test -- tests/odentity-claims-response-redaction.test.ts tests/odentity-claims-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the 0dentity gated-features ownership slice:

```bash
npm test -- tests/odentity-gated-features-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the 0dentity score response redaction slice:

```bash
npm test -- tests/odentity-score-response-redaction.test.ts tests/odentity-score-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the 0dentity export VC response redaction slice:

```bash
npm test -- tests/odentity-export-response-redaction.test.ts tests/odentity-export-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the 0dentity claim-write and revoke response redaction slice:

```bash
npm test -- tests/odentity-claim-write-response-redaction.test.ts tests/odentity-claim-write-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the 0dentity claim-import ownership hardening slice:

```bash
npm test -- tests/odentity-claim-write-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the 0dentity gated-features response redaction slice:

```bash
npm test -- tests/odentity-gated-features-response-redaction.test.ts tests/odentity-gated-features-response-route-redaction.test.ts tests/odentity-gated-features-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the 0dentity trust-event acknowledgement redaction slice:

```bash
npm test -- tests/odentity-trust-event-response-redaction.test.ts tests/odentity-trust-event-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the 0dentity trust-event authority hardening slice:

```bash
npm test -- tests/odentity-trust-event-route-redaction.test.ts tests/odentity-trust-event-response-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the responder auth response redaction slice:

```bash
npm test -- tests/auth-responder-response-redaction.test.ts tests/auth-responder-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the public agency directory redaction slice:

```bash
npm test -- tests/auth-responder-response-redaction.test.ts tests/auth-responder-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the responder auth session redaction slice:

```bash
npm test -- tests/auth-responder-response-redaction.test.ts tests/auth-responder-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the responder registration session redaction slice:

```bash
npm test -- tests/auth-responder-response-redaction.test.ts tests/auth-responder-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the subscriber auth response redaction slice:

```bash
npm test -- tests/auth-subscriber-response-redaction.test.ts tests/auth-subscriber-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the provider auth response redaction slice:

```bash
npm test -- tests/auth-provider-response-redaction.test.ts tests/auth-provider-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the provider NPI lookup response redaction slice:

```bash
npm test -- tests/auth-provider-response-redaction.test.ts tests/auth-provider-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the trustee auth response redaction slice:

```bash
npm test -- tests/auth-trustee-response-redaction.test.ts tests/auth-trustee-route-redaction.test.ts tests/trustee-vss-route-redaction.test.ts tests/trustee-vss-summary.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the verification acknowledgement redaction slice:

```bash
npm test -- tests/verification-response-redaction.test.ts tests/verification-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the medical-record response redaction slice:

```bash
npm test -- tests/medical-record-response-redaction.test.ts tests/medical-record-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the medical-record version-envelope and encryption-status redaction slice:

```bash
npm test -- tests/medical-record-response-redaction.test.ts tests/medical-record-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the medical-record deletion-acknowledgement redaction slice:

```bash
npm test -- tests/medical-record-response-redaction.test.ts tests/medical-record-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the clinical-note response and wrapper redaction slice:

```bash
npm test -- tests/clinical-note-response-redaction.test.ts tests/clinical-note-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the credential update response redaction slice:

```bash
npm test -- tests/credential-update-response-redaction.test.ts tests/credential-update-route-redaction.test.ts
npm test -- tests/context-docs.test.ts
npm run quality
```

Focused validation for the credential upload response redaction slice:

```bash
npm test -- tests/credential-upload-response-redaction.test.ts tests/credential-upload-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the agency responder directory redaction slice:

```bash
npm test -- tests/scan-agency-redaction.test.ts tests/scan-agency-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the emergency-card response redaction slice:

```bash
npm test -- tests/card-response-redaction.test.ts tests/card-route-redaction.test.ts tests/card-page-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the admin responder response redaction slice:

```bash
npm test -- tests/admin-responder-response-redaction.test.ts tests/admin-responder-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the admin subscriber response redaction slice:

```bash
npm test -- tests/admin-subscriber-response-redaction.test.ts tests/admin-subscriber-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the admin agency response redaction slice:

```bash
npm test -- tests/admin-agency-response-redaction.test.ts tests/admin-agency-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the admin agency dashboard payload alignment slice:

```bash
npm test -- tests/admin-agency-dashboard-alignment.test.ts tests/admin-agency-response-redaction.test.ts tests/admin-agency-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the admin audit response redaction slice:

```bash
npm test -- tests/admin-audit-response-redaction.test.ts tests/admin-audit-route-redaction.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the legacy subscriber management hardening slice:

```bash
npm test -- tests/subscriber-management-route-hardening.test.ts tests/context-docs.test.ts
npm run quality
```

Focused validation for the public EXOCHAIN copy fail-closed slice:

```bash
npm test -- tests/public-exochain-copy-boundary.test.ts
npm test -- tests/context-docs.test.ts
npm run quality
```

The gate runs:

- `npm run context:lint`
- `npm run typecheck`
- `npm test`
- `npm run rust:fmt`
- `npm run rust:clippy`
- `npm run rust:test`

## Current Coverage

- Context records must keep source basis, fact versus inference, artifact
  inventory, and conflict sections.
- Unsupported EXOCHAIN trust claims are blocked in public copy, metadata, and
  project docs.
- The primitive registry stays evidence-only until an adapter is implemented.
- The surface intake stays fail-closed: no core reads, no core writes, no
  consent/authority/provenance/governance minting, and no secrets in repo.
- The workspace configuration contract validates fail-closed surface intake,
  EXOCHAIN evidence-only primitive registry posture, and local evidence-path
  resolution when the read-only EXOCHAIN repo is present.
- The 0dentity claims redaction contract validates that authenticated claim
  reads expose only bounded claim metadata and that the legacy
  `:subscriberId/claims` route now fails closed on cross-subscriber access
  instead of returning raw `odentity_claims` rows.
- The 0dentity score redaction contract validates that authenticated score
  reads expose only bounded dimension, score, and polygon metadata without
  reflecting raw `subscriber_id` bindings or score-row timestamps through
  either score route.
- The 0dentity export VC redaction contract validates that authenticated
  verifiable-credential exports expose only bounded subscriber score and claim
  metadata without reflecting raw claim ids, claim issuers, per-claim
  issuance timestamps, or score-row subscriber bindings through the export
  payload.
- The 0dentity claim-import ownership contract validates that
  `POST /api/odentity/claims/import` now requires subscriber authentication
  and same-subscriber ownership or admin authority instead of accepting
  anonymous claim writes for arbitrary `subscriber_id` values.
- The responder auth response redaction contract validates that responder
  registration, login, profile, and agency registration responses expose only
  bounded responder and agency summary metadata without echoing internal
  `agency_id` bindings, agency-admin email echoes, or raw responder rows
  through the adjacent auth API surface.
- The responder auth session redaction contract validates that responder login
  now routes its session wrapper through a bounded helper so the documented
  responder auth boundary is enforced by runtime route truth instead of an
  inline `{ user, token }` response.
- The responder registration session redaction contract validates that
  responder registration and agency registration now route their session
  wrappers through bounded helpers so the documented responder auth boundary
  is enforced by runtime route truth instead of inline registration payload
  assembly.
- The subscriber auth response redaction contract validates that subscriber
  registration, login, and current-user responses expose only bounded
  subscriber identity, tier, and verification metadata without password hashes,
  verification tokens, `created_at` timestamps, or raw subscriber rows through
  the adjacent auth API surface.
- The provider auth response redaction contract validates that provider
  registration, login, and current-user responses expose only bounded provider
  identity, facility, specialty, verification, and consent-summary metadata
  without password hashes, `subscriber_id` bindings, `created_at` timestamps,
  or raw provider rows through the adjacent auth API surface.
- The trustee auth response redaction contract validates that trustee login
  and current-user profile responses expose only bounded trustee identity,
  trusteeship, and shard-status metadata without password hashes,
  subscriber DIDs, or raw shard references through the adjacent auth API
  surface.
- The verification acknowledgement redaction contract validates that email and
  phone verification acknowledgements expose only bounded verification status,
  masked verification-target hints, expiry metadata, and dev-only verification
  codes without echoing raw subscriber email or phone values through adjacent
  auth or subscriber verification routes.
- The public agency directory redaction contract validates that
  `GET /api/auth/agencies` exposes only bounded agency identity and
  verification metadata without reflecting agency `created_at` timestamps or
  raw directory rows through the public registration dropdown surface.
- The boundary evaluator denies trust claims without a verified adapter.
- The boundary evaluator denies raw sensitive data on-chain.
- The boundary evaluator denies any verified-adapter action unless EXOCHAIN
  returns `permit`.
- The storage entitlement contract validates initial storage levels,
  content-addressed provider requirements, encrypted provider writes, safe
  EXOCHAIN anchor fields, quota behavior, and Tier-0 emergency read behavior.
- The onboarding and P.A.C.E. progression contract validates distinct
  P.A.C.E. roles, no self-grant, accepted-obligation notification eligibility,
  next-best-action progression, medical-jacket completion, and entitlement
  selection.
- The human-safety opportunity contract validates the create-card,
  invite-your-four, protect-your-people loop, year-one segment priority,
  integer readiness metrics, Safety Circle readiness-grant boundary language,
  and denial of raw sensitive payloads, full medical-jacket prerequisites,
  genetic/trial prerequisites, unsupported responder adoption requirements,
  guaranteed-response claims, and unsupported EXOCHAIN/root-backed claims.
- The Safety Circle full-funnel copy contract validates the create-card,
  invite-your-four loop across home, onboarding, dashboard, P.A.C.E., card,
  and trustee acceptance surfaces while blocking legacy Custodial copy from
  user-facing screens.
- The P.A.C.E. invitation delivery contract validates canonical Primary,
  Alternate, Contingent, and Emergency role handling, local and Railway-backed
  invitation URL resolution, channel normalization, fail-closed email/SMS
  transport status reporting, bounded `notification_delivery_failed` redaction
  for provider exceptions, and no stored invitation message bodies.
- The P.A.C.E. trustee nomination validation contract validates that invalid
  email, missing-SMS-phone, and duplicate-role nomination responses stay
  fail-closed and stop reflecting nominee email addresses through response
  payloads.
- The P.A.C.E. expired-invitation resend acknowledgement contract validates
  that the unauthenticated resend-request route records the request without
  reflecting subscriber names, trustee email addresses, or role labels through
  its public acknowledgement payload.
- The P.A.C.E. trustee nomination response contract validates that trustee
  creation responses reuse the bounded invitation-delivery shape without
  reflecting trustee email addresses, invite phone numbers, invitation tokens,
  invitation URLs, or delivery-state internals through the response payload.
- The P.A.C.E. invitation send response redaction contract validates that the
  send or resend route exposes only bounded role, status, and delivery-state
  metadata without reflecting trustee email addresses, invitation tokens,
  invitation URLs, or provider message ids through its public response body.
- The P.A.C.E. invitation validate and decline response contract validates
  that unauthenticated invitation-token routes expose only bounded role
  metadata and decline acknowledgement fields without reflecting subscriber
  names or trustee email addresses through public response bodies.
- The P.A.C.E. workflow response redaction contract validates that governance
  and identity-recovery workflow status and signing routes expose only bounded
  signer roles, counts, timestamps, and safe workflow summaries without
  reflecting signer email addresses, raw workflow metadata, raw recovery
  records, or raw audit-receipt payloads through public responses.
- The P.A.C.E. workflow initiation response redaction contract validates that
  trustee-replacement, emergency-override, and identity-recovery initiation
  acknowledgements expose only bounded workflow ids, signer counts, role
  summaries, deadlines, and approval-remaining metadata without reflecting
  cosigner ids, recovery-record ids, workflow metadata, or creation
  timestamps through public response payloads.
- The P.A.C.E. invitation acceptance response redaction contract validates
  that trustee-account activation acknowledgements expose only bounded
  trusteeship and VSS-enrollment summaries without reflecting trustee email
  addresses, raw shard references, or VSS master-key hashes through the
  acceptance response payload.
- The P.A.C.E. recovery summary redaction contract validates that public
  recovery workflow status exposes only bounded recovery state and audit event
  fields without reflecting internal recovery-record ids or audit-receipt
  timestamps through public summary payloads.
- The P.A.C.E. VSS-status redaction contract validates that the unauthenticated
  VSS-status route exposes only bounded ceremony and trustee-shard summary
  fields without reflecting trustee email addresses, raw shard references,
  master-key hashes, or trigger metadata through its public response body.
- The P.A.C.E. trustee-directory redaction contract validates that the
  unauthenticated trustee-directory route exposes only bounded role and VSS
  enrollment summaries without reflecting trustee email addresses, invite
  phone numbers, invitation URLs, delivery-state internals, or master-key
  hashes through its public response body.
- The trustee-facing VSS summary redaction contract validates that trustee
  detail and trustee-profile API responses expose only bounded shard presence
  metadata without reflecting raw shard references through trustee-facing API
  payloads or UI surfaces.
- The scan expanded-access workflow redaction contract validates that scan
  governance workflow request, status, and approved-access responses expose
  only bounded workflow ids, signer counts, deadlines, approval timestamps,
  signer role/timestamp summaries, approvals-remaining counts, bounded
  initiation acknowledgements, and bounded no-workflow status copy without
  reflecting responder ids, raw workflow metadata, notification rows, or
  signer email or DID fields through public responses.
- The scan expanded-data response redaction contract validates that approved
  expanded-access responses expose only bounded subscriber emergency fields,
  credential summaries, and medical-record metadata without reflecting raw
  credential ids, subscriber ids, or medical-record storage paths through the
  response body.
- The scan agency roster redaction contract validates that agency-admin scan
  list and flagged-scan responses expose only bounded scan summary fields
  instead of reflecting raw access tokens, raw location values, subscriber
  email addresses, or internal database identifiers through agency roster
  payloads.
- The agency responder directory redaction contract validates that the
  agency-admin responder filter route exposes only bounded responder ids,
  email, role, and certification fields without reflecting responder DIDs or
  raw responder rows through the responder-directory surface.
- The admin responder response redaction contract validates that agency-admin
  responder roster and activation responses expose only bounded responder ids,
  email, role, certification, military-status, active-state, and timestamp
  fields without reflecting responder DIDs, `agency_id` bindings, or raw
  responder rows through the admin API surface.
- The admin subscriber response redaction contract validates that platform-admin
  subscriber list, detail, and account-update responses expose only bounded
  subscriber ids, email, name, role, verification, and timestamp fields
  without reflecting subscriber DIDs or raw subscriber rows through the admin
  API surface.
- The admin agency response redaction contract validates that platform-admin
  agency list, deactivation, and reactivation responses expose only bounded
  agency identity, type, active-state, responder-count, and timestamp
  metadata without reflecting `admin_email` values or raw responder rows
  through the admin API surface.
- The admin audit response redaction contract validates that platform-admin
  audit reads expose only bounded actor DID, event type, scope, allowlisted
  detail fields, receipt hash, and timestamp metadata without reflecting
  subject DIDs, prior hashes, EXOCHAIN receipt references, subscriber email
  joins, or raw audit rows through the admin API surface.
- The subscriber profile response redaction contract validates that
  authenticated subscriber-owned profile reads and writes expose only bounded
  profile, allergy, medication, condition, and emergency-contact metadata
  without reflecting subscriber DIDs, roles, or raw subscriber-bound rows
  through `GET /api/subscribers/profile` or `PUT /api/subscribers/profile`.
- The subscriber medical-entry response redaction contract validates that
  authenticated allergy, medication, and condition create acknowledgements
  expose only bounded entry metadata and bounded `odentity_claim` summaries
  without reflecting `subscriber_id` bindings, raw claim rows, or raw
  subscriber-owned medical-entry rows through
  `POST /api/subscribers/profile/allergies`,
  `POST /api/subscribers/profile/medications`, or
  `POST /api/subscribers/profile/conditions`.
- The emergency-contact response redaction contract validates that
  authenticated emergency-contact create and update acknowledgements expose
  only bounded contact metadata without reflecting `subscriber_id` bindings or
  raw emergency-contact rows through
  `POST /api/subscribers/profile/emergency-contacts` or
  `PUT /api/subscribers/profile/emergency-contacts/:id`.
- The subscriber delete-acknowledgement redaction contract validates that
  authenticated allergy, medication, condition, and emergency-contact delete
  acknowledgements expose only bounded success messages without reflecting raw
  row ids through `DELETE /api/subscribers/profile/allergies/:id`,
  `DELETE /api/subscribers/profile/medications/:id`,
  `DELETE /api/subscribers/profile/conditions/:id`, or
  `DELETE /api/subscribers/profile/emergency-contacts/:id`.
- The subscriber settings response redaction contract validates that
  authenticated subscriber alert-settings and consent-defaults reads and
  writes expose only bounded settings metadata, option lists, and success
  messages without reflecting subscriber ids, DIDs, or raw subscriber rows
  through `GET /api/subscribers/alert-settings`,
  `PUT /api/subscribers/alert-settings`,
  `GET /api/subscribers/consent-defaults`, or
  `PUT /api/subscribers/consent-defaults`.
- The legacy subscriber management hardening contract validates that legacy
  subscriber list, account-update, and delete-by-id routes now require
  subscriber-admin authentication and that the list alias exposes only bounded
  subscriber ids, email, name, role, verification, and timestamp fields
  instead of reflecting subscriber DIDs, blood type, birth date, or raw
  subscriber rows through the adjacent subscriber API surface.
- The legacy subscriber create/detail redaction contract validates that
  `POST /api/subscribers` and `GET /api/subscribers/:did` now reuse the
  bounded admin subscriber helper instead of reflecting raw subscriber rows
  through the adjacent subscriber API surface.
- The subscriber scan history and detail redaction contract validates that
  subscriber-facing scan-history and scan-detail responses expose only bounded
  timing, type, responder-role, agency, and location-recorded metadata instead
  of reflecting responder email addresses, responder DIDs, raw location
  values, access tokens, or internal scan-row fields through subscriber
  history surfaces.
- The scan creation response redaction contract validates that successful and
  degraded `POST /api/scan` responses expose only bounded scan summary and
  alert-delivery metadata instead of reflecting raw access tokens, raw
  location values, internal database identifiers, or trustee recipient
  identifiers through responder-facing response payloads.
- The scan token-access response redaction contract validates that
  `GET /api/scan/access/:accessToken` exposes only the emergency subset and
  expiry metadata without echoing raw access tokens, internal scan ids,
  subscriber-linked row ids, or trustee DID metadata through token-gated
  public response payloads.
- The scan responder emergency-subset redaction contract validates that
  `GET /api/scan/data/:subscriberDid` exposes only bounded emergency-subset
  fields without echoing subscriber-linked row ids, insurance visibility
  internals, or other raw credential fields through the responder-authenticated
  response payload.
- The medical-record extracted-data contract validates bounded XML, C-CDA,
  FHIR, and JSON parse-failure metadata so upload responses and persisted
  extracted-data snapshots stay machine-readable without echoing raw parser
  exception text or document fragments.
- The medical-record response redaction contract validates that upload, list,
  detail, version-history, visibility-update, and annotation-update responses
  expose only bounded medical-record metadata without echoing `subscriber_id`,
  raw file-storage paths, file hashes, or version-chain parent identifiers
  through the authenticated records API surface.
- The clinical-note response redaction contract validates that provider-note
  create, subscriber list, provider list, approve, and reject responses
  keep both note payloads and route-level acknowledgement/list envelopes
  bounded, exposing only safe note, participant-name, and derived count
  metadata without echoing provider email addresses, provider or subscriber
  DIDs, raw provider or subscriber ids, or rejection reasons through the
  records API or UI.
- The record-request response redaction contract validates that HIPAA
  Right-of-Access request create, list, legacy DID list, and status-update
  responses expose only bounded provider, status, readiness, and timestamp
  metadata without echoing `subscriber_id`, raw letter-storage paths, or
  free-form internal status notes through the records-request API or UI.
- The notification response redaction contract validates that subscriber
  notification list, create, and mark-read responses expose only bounded
  notification content fields without echoing recipient DIDs, recipient-type
  routing, channel internals, or wildcard notification rows through the API
  surface.
- The alert response redaction contract validates that alert dispatch, history,
  P.A.C.E. alert-history, and trustee-notification responses expose only
  bounded alert metadata without echoing trustee email addresses, recipient
  DIDs, raw notification rows, scan locations, subscriber DIDs, or scan ids
  through the alert API surface.
- The subscriber alert-event response redaction contract validates that
  subscriber-owned alert-event history exposes only bounded event counts,
  read-state, and sanitized alert details without echoing raw notification
  bodies, subscriber DIDs inside event details, trustee DIDs, scan locations,
  or scan ids through the subscriber event-history surface.
- The alert response acknowledgement redaction contract validates that
  trustee P.A.C.E. response acknowledgements expose only bounded response
  status, response copy, and timestamp metadata without echoing raw
  notification ids or trustee DID bindings through the alert API surface.
- The research opt-in, audit, and trial-consent response redaction contract
  validates that subscriber-facing research bridge responses expose only
  bounded opt-in, audit-summary, enrollment-status, and trial-match metadata
  without echoing subscriber DIDs, CyberMedica consent references, ZK proof
  references, or raw audit `details` payloads through the adjacent research
  API surface.
- The consent-event response redaction contract validates that direct
  subscriber-facing consent list, grant, revoke, check, legacy list, and
  approval responses expose only bounded scope, timing, provider-summary, and
  derived status metadata without echoing subscriber ids, provider ids,
  provider email addresses, or raw `exochain_receipt` fields through the
  adjacent consent API surface.
- The consent provider-directory and access-request response redaction
  contract validates that verified provider listings, subscriber access-request
  lists, provider access-request lists, provider request-create
  acknowledgements, and approval acknowledgements expose only bounded
  provider-summary, request-status, and subscriber-name metadata without
  echoing provider DIDs, provider email addresses, free-text request messages,
  or raw request rows through the adjacent consent API surface.
- The consent acknowledgement and status response redaction contract validates
  that idempotent grant, revoke, access-check, expiry-check, approval, and
  denial responses expose only bounded consent, request-status, and count
  metadata without echoing internal consent ids, provider email addresses, or
  raw request rows through adjacent consent acknowledgement paths.
- The device-management response redaction contract validates that subscriber
  device register, list, revoke, verify, and settings UI flows expose only
  bounded `device_id`, display-name, active-state, timestamp, and device-token
  fields without echoing internal `key_ref` bindings, revoke reasons, or other
  device-signing-key internals through the public API or subscriber settings
  surface.
- The ICE card packet contract validates required identity and QR panels,
  shared version state, safe QR pointers, stale endpoint denial, printable
  cut/fold instructions, legal/privacy presence, and explicit acceptance for
  optional legal or directive panels.
- The printable card render contract validates synthetic PDF generation,
  cut/fold instruction rendering, shared version and trust-state display,
  configuration-backed printed contact surfaces, current QR pointer policy,
  and optional panel acceptance evidence.
- The feedback and mandated reporter contract validates safe metadata, bounded
  feedback fields, status workflow, hold/release behavior, deduplicated
  upvotes, privacy-risk redaction, unanswered/confusion thresholds, and gated
  redacted agent-dispatch payloads.
- The feedback board read-model contract validates deterministic board
  ordering, target/work-batch/item lookups, chronological activity logs, safe
  metadata projection, and aggregate stats without enabling write paths.
- The AI help manual contract validates required knowledge-base topic
  coverage, manual-only prompt guardrails, classifier-line requirements, and
  the feedback fallback when the docs do not cover a question.
- The AI help usage summary read-model contract validates seven-day session
  filtering, outcome totals, topic counters, normalized question summaries,
  unresolved-topic reporting, and generated-feedback counts without enabling
  help, feedback writes, mandated reporting, or agent dispatch.
- The AI-help usage-summary typed-query contract validates the single
  usage-summary read-query vocabulary, fixed seven-day window, zero-parameter
  query shape, exact result-field inventory, and blocked execution until a
  backend is selected and tested.
- The AI-help session-transcript typed-query contract validates the bounded
  transcript and active-session-index query vocabulary, fixed seven-day
  retention window, required transcript session-id shape, exact transcript and
  active-index field inventory, and blocked execution until a backend is
  selected and tested.
- The AI-help unanswered-topic typed-query contract validates the single
  unresolved-topic query vocabulary, fixed seven-day retention window, exact
  per-topic counter field inventory, deterministic ordering contract, and
  blocked execution until a backend is selected and tested.
- The AI help persistence namespace contract validates the `livesafe:` key
  inventory, seven-day retention constants, and fail-closed id validation for
  future session, message, recent-session-index, and unanswered-topic
  backends without enabling runtime writes.
- The feedback-board persistence namespace contract validates the `livesafe:`
  feedback key inventory, canonical status and target partitions, and
  fail-closed id and parameter validation without enabling runtime reads or
  writes.
- The feedback board status API contract validates an explicit inactive
  typed-route payload, a read-only status surface, query inventory visibility,
  and disabled board-query and feedback-write runtime posture.
- The feedback board typed-query contract validates the supported read-query
  vocabulary, deterministic workflow-status normalization, required target,
  work-batch, and feedback identifiers, safe token boundaries, and blocked
  execution until a backend is selected and tested.
- The feedback code-hints registry contract validates the source-backed UI
  component vocabulary, repo-local file/spec references, safe storage-key and
  API-operation tokens, and fail-closed rejection of unsupported components or
  traversal-like paths.
- The AI help session transcript TTL read-model contract validates seven-day
  session retention, transcript lookup by session id, active-session index
  ordering, and deterministic message ordering without enabling help,
  feedback writes, mandated reporting, or agent dispatch.
- The AI help unanswered-topic counter read-model contract validates seven-day
  unresolved-topic filtering, unanswered versus confusion counter separation,
  deterministic topic ordering, and per-session topic deduplication without
  enabling help, feedback writes, mandated reporting, or agent dispatch.
- The EXOCHAIN adapter activation contract validates wired dependency
  requirements, permit-only activation, malformed authority-input denial,
  raw-sensitive payload denial, and status-route redaction.
- The EXOCHAIN runtime adapter facade validates the inactive-by-default route
  boundary around identity, `auth`, `scan`, and `consent` EXOCHAIN calls,
  current P.A.C.E. status reads, redacted wrapped-operation inventory for the
  runtime status surface,
  no-call denial while `runtimeAdapterStatus` stays `not-wired`, fail-closed
  handling for deny/rejected/timeout/unavailable/not-called/stale/revoked/
  contradicted transport states, fail-closed normalization of thrown transport
  exceptions into `timeout` or `unavailable`, canonical audit-receipt hash and
  event-type enforcement, malformed identity DIDs, malformed required `scan` and
  `consent` identifiers including whitespace-only string ids, malformed `scan`
  and `consent` wrapper input denial for optional DIDs, non-negative integer
  epoch-millisecond timestamps, bounded scope tokens, and audit-receipt hashes,
  raw-sensitive scan payload rejection including any explicit `location` field,
  malformed authority input denial, and redacted runtime status metadata.
- The EXOCHAIN GraphQL client preserves explicit zero-valued epoch-millisecond
  timestamps for `scan` and `consent` payloads instead of rewriting them to
  `Date.now()` or `null`.
- The EXOCHAIN GraphQL client redacts thrown gateway transport exceptions into
  bounded `EXOCHAIN_TIMEOUT` or `EXOCHAIN_UNAVAILABLE` error codes and
  redacts non-OK gateway responses into `EXOCHAIN_GATEWAY_REJECTED` instead of
  reflecting raw socket, DNS, or upstream exception text through the direct
  client error shape.
- The EXOCHAIN GraphQL client rejects malformed direct-client `scan` and
  `consent` identifiers before query execution instead of coercing them into
  transport payload strings.
- The EXOCHAIN GraphQL client also rejects malformed direct-client optional
  `scan` and `consent` authority inputs such as invalid optional DIDs,
  malformed scope tokens, non-negative integer epoch-millisecond timestamp
  violations, malformed audit-receipt hashes, any missing direct-client
  consent input object, and any explicit raw-sensitive `location` field before
  query execution while omitting the `location` key entirely from
  metadata-only scan anchor payloads.
- The EXOCHAIN GraphQL client rejects malformed direct-client identity and
  P.A.C.E. subscriber DIDs before `registerIdentity`, `getIdentity`, or
  `getPaceStatus` can issue a GraphQL query.
- The EXOCHAIN GraphQL client rejects malformed direct-client audit anchor
  subscriber DIDs, receipt hashes, and unsupported event types before
  `anchorAuditReceipt` can issue a GraphQL query.
- The P.A.C.E. governance and identity-recovery EXOCHAIN claim boundary
  validates that quorum-completion audit metadata and response copy stay
  fail-closed, record local audit receipts only, and emit explicit
  `not_called` EXOCHAIN anchor state until a verified runtime adapter path is
  actually invoked.
- The subscriber-account and medical-record deletion audit boundary validates
  that local deletion receipts keep EXOCHAIN anchoring fail-closed, record
  explicit `not_called` adapter state, and avoid claiming EXOCHAIN
  preservation until a verified adapter path is actually invoked.
- The credential custody receipt boundary validates that advance-directive and
  power-of-attorney uploads record encrypted local custody receipts with
  explicit `not_called` adapter state, metadata-only hashes, and fail-closed
  success copy instead of claiming EXOCHAIN bailment or on-chain storage until
  a verified adapter path is actually invoked.
- The emergency-card issuance audit boundary validates that card-issuance audit
  receipts record explicit local-audit metadata with `not_called` adapter
  state and fail-closed wording instead of carrying EXOCHAIN event markers
  before a verified adapter path is actually invoked.
- The emergency-card response redaction contract validates that card issue,
  card status, and NFC metadata surfaces return pointer-only status fields
  instead of reflecting raw `qr_data`, `nfc_payload`,
  `emergency_consent_token`, or responder scan URLs through adjacent card APIs
  or the card UI.
- The scan local-audit boundary validates that emergency-card scan receipts
  record explicit local-audit metadata with `not_called` adapter state and
  fail-closed wording instead of carrying EXOCHAIN event markers before a
  verified adapter path is actually invoked.
- The scan post-action alert boundary validates that successful emergency-card
  scan responses keep P.A.C.E. alert follow-up failures machine-readable and
  bounded as `notification_delivery_failed`, while the scan-create response
  surface stays redacted and does not reflect raw access tokens, raw location
  values, internal database identifiers, or trustee recipient identifiers.
- The audit immutability claim boundary validates that subscriber and admin
  audit-protection surfaces describe append-only local audit receipts with
  explicit `not_called` adapter state and fail-closed wording instead of
  claiming tamper-proof EXOCHAIN policy enforcement before a verified adapter
  path is actually invoked.
- The audit trail response and copy redaction contract validates that audit
  read endpoints expose only bounded event fields and allowlisted deletion
  details, while audit-facing UI copy stays on append-only local-audit wording
  instead of reflecting subject DIDs, chain internals, raw detail blobs, or
  active EXOCHAIN immutability claims.
- The consent local-audit claim boundary validates that consent grant and
  revocation receipts record explicit local-audit metadata with `not_called`
  adapter state and fail-closed response copy instead of implying EXOCHAIN
  anchoring before a verified adapter path is actually invoked.
- The consent and revocation receipt contract validates inactive adapter
  posture, EXOCHAIN-only receipt provenance, safe receipt metadata, and
  verified-proof copy gating.
- The trust-state view contract validates inactive, genesis-pending,
  internal-proof, and externally-verified display tokens; blocks unsupported
  public trust-bearing claims; and requires accessible plus machine-readable
  status fields.
- The genesis development trust contract validates source provenance,
  classified third-party intake for internal development, ExoForge internal
  genesis use, exact 7-of-13 FROST profile requirements, verified-adapter
  gating, and blocked external trust signaling before proof completion.
- The emergency-profile contract validates allowed field names, synthetic value
  references, direct-contact/location/QR redaction boundaries, release-bound
  emergency fields, blocked expanded responder disclosure, and fail-closed
  responder projection.
- The QR pointer contract validates synthetic token metadata, current
  configuration-backed policy references, stale-target denial, raw-sensitive
  payload denial, direct-contact/location-trace denial, and rotation
  disablement references.
- The QR activation contract validates synthetic activation references,
  dependency on a passing QR pointer policy, metadata-only payloads,
  emergency-subset responder landing, permit-only responder/network activation,
  verified-claim gating, and disablement references.
- The VitalLock vault contract validates synthetic interaction references,
  storage/custody dependency checks, metadata-only payloads, responder and
  delegated permit gating, emergency-subset or metadata-only scope limits, and
  full-export denial until verified policy exists.
- The Ambient signal contract validates synthetic interaction references,
  marketplace-template and consent dependencies, metadata-only payloads,
  recipient-visible permit gating, and verified-claim denial until permit
  evidence exists.
- The responder-access display contract validates synthetic session/policy/
  disablement references, accessible and machine-readable responder status,
  emergency-subset-only panel inventory, dependency on emergency/QR/vault
  contracts, and verified-claim denial until permit evidence exists.
- The trust-status API contract validates an explicit inactive trust payload,
  machine-readable status fields, adapter-derived `verified_runtime_adapter`
  reporting, redacted runtime-adapter operation inventory, fail-closed
  public-claim posture, and the read-only runtime handler shape.
- The EXOCHAIN production trust evidence evaluator validates production
  health/readiness, AVC root-trust bundle verification, root bundle and issuer
  identifiers, required sentinel health, non-blocking `QuorumHealth`
  observation handling, and fail-closed blocked states when verifier or
  readiness evidence is missing.
- The shared API error-response contract validates that auth, upload, and
  top-level runtime failures return bounded redacted payloads for upload,
  database, and unexpected exceptions instead of reflecting raw error text.
- The trust-status API contract also validates verified EXOCHAIN production
  evidence fields, including `exochain_production_evidence_state`,
  root-trust bundle id, issuer DID, verifier commit, verified timestamp, and
  non-blocking observations while keeping `public_claims_allowed: false`
  unless LiveSafe adapter proof also passes.
- The public-output evidence summary hash contract validates sorted-key
  canonical JSON determinism, hash changes for required public evidence field
  changes, fail-closed rejection for missing or false production, EXOCHAIN
  connectivity, runtime-adapter, or pre-authorization public-claim evidence,
  explicit timestamp freshness without system time, secret/sensitive material
  rejection, and the one-command non-secret machine-readable operator output.
- The public EXOCHAIN copy boundary validates that customer-facing UI and
  public metadata do not claim active EXOCHAIN trust, bailment, audit,
  sovereignty, on-chain custody, active consent anchoring, or immutable
  EXOCHAIN enforcement before LiveSafe adapter proof exists.
- The heroes registration copy and payload contract validates the free Heroes
  positioning across registration and settings copy, plus the `is_hero` and
  legacy `is_military` request/response alias behavior in the current auth
  surface.
- The subscriber registration schema contract validates `is_hero` and legacy
  `is_military` subscriber columns plus additive migration coverage for new and
  existing databases.
- The AI-help status API contract validates an explicit inactive feature-gate
  payload, read-only runtime shape, disabled-by-default write posture, and
  configuration-backed threshold reporting without activating help, feedback
  writes, or agent dispatch.
- The AI-help usage summary status API contract validates an explicit inactive
  typed-query payload, seven-day summary field inventory, read-only runtime
  shape, and blocked transcript/help/write posture without exposing summary
  data or transcript content.
- The AI-help session transcript status API contract validates an explicit
  inactive typed-query payload, transcript-query and active-session-index field
  inventory, seven-day retention metadata, read-only runtime shape, and
  blocked transcript/help/write posture without exposing transcript data.
- The AI-help unanswered-topic status API contract validates an explicit
  inactive typed-query payload, unresolved-topic query inventory, seven-day
  retention metadata, deterministic ordering fields, read-only runtime shape,
  and blocked counter/help/write posture without exposing counter data.
- The feedback code-hints status API contract validates an explicit inactive
  read-only payload, approved component vocabulary exposure, exact code-hint
  field inventory, and blocked runtime posture without enabling code-hint
  generation, persistence, or dispatch.
- The runtime status-route contract validates the documented read-only status
  endpoint inventory, including `GET /api/health` and the plural
  unanswered-topics path plus the feedback code-hints status path, requires
  GET-only method guards for every shared status surface, and applies
  `cache-control: no-store` across those shared status responses.
- The EXOCHAIN connectivity status contract validates that health and startup
  reporting stay fail-closed, skip raw EXOCHAIN probes while the runtime
  adapter remains `not-wired`, and normalize verified-adapter probe failures
  into an unavailable status.
- The health-status payload contract validates that the public `GET /api/health`
  failure shape redacts raw database error text and returns only bounded
  availability metadata.
- The scan-route EXOCHAIN payload contract validates that responder scan
  handling builds metadata-only adapter payloads, carries identifiers and
  audit hashes only, and omits any explicit raw-sensitive `location` field
  before the runtime adapter boundary is invoked.
- The EXOCHAIN root trust-state ladder contract validates the intermediate
  `exochain_root_evidence_verified` state from read-only `exo-root` evidence
  while keeping `public_trust_claims_allowed` blocked until LiveSafe adapter
  and production-status gates also pass.
- The P.A.C.E. readiness grant contract validates exactly four distinct
  accepted P.A.C.E. obligations, notification eligibility, decline/revocation
  rights, self/duplicate/revoked/raw-metadata denials, exact four-month grant
  duration, private circle-strength language, and blocked dispatch, Stripe,
  responder expansion, vault disclosure, genetic import, trial matching, and
  public EXOCHAIN claims.

## Adapter Activation Test Requirements

Before any LiveSafe runtime route reads or writes EXOCHAIN state, tests must
prove:

1. Denial when EXOCHAIN rejects the action.
2. Denial when EXOCHAIN times out.
3. Denial when EXOCHAIN is unavailable.
4. Denial when credentials, signatures, consent records, authority chains,
   provenance records, custody receipts, tenant identifiers, or emergency
   access grants are malformed.
5. No health, status, debug, telemetry, or error route leaks secrets or raw
   sensitive records.
6. Raw sensitive records remain off-chain.

## Multi-Repo Gate

Every added `bob-stewart` repo mapped into LiveSafe must define:

- owner
- repository URL
- path classification
- deployment status
- EXOCHAIN dependency boundary
- secret source
- local test command
- CI gate
- disablement path

## Printable Emergency Card Gate

Before a generated emergency card is accepted, tests must prove:

1. The generated PDF renders without clipped text, overlap, unreadable glyphs,
   or missing page sections.
2. Cover-page and margin instructions for cutting and folding are visible.
3. Cut and fold guides align with the wallet-card dimensions.
4. The card can be generated from account preferences using synthetic fixture
   data.
5. The QR payload contains only a retrieval or activation pointer, never raw
   sensitive emergency or medical data.
6. The QR pointer resolves through current server-side access policy.
7. Expired, replaced, revoked, malformed, or obsolete QR targets are denied.
8. Printed phone numbers, URLs, and legal/privacy copy are derived from current
   configuration at generation time.
9. Regenerating a card after profile, consent, contact, QR target, or legal-copy
   changes produces a new dated artifact.
10. Multi-panel packets render each selected panel independently, including
    identity/QR, medical release, legacy directive, and rights assertion panels
    when enabled.
11. Legal or medical authorization panels require explicit user acceptance,
    signature or confirmation fields, effective dates, expiry or termination
    rules, and revocation instructions.
12. Disabling an optional panel removes its text from the generated print packet
    and scan-visible metadata.
13. Tests and screenshots use synthetic names, portraits, contacts, dates, and
   URLs.

## Enterprise Onboarding And Entitlement Gate

Before LiveSafe onboarding, marketplace, or billing behavior is accepted, tests
must prove:

1. Basic accounts can be represented without paid entitlements.
2. Family plans, team plans, trials, paid capabilities, marketplace add-ons, and
   gift subscriptions are represented as explicit entitlement states.
3. P.A.C.E. invitation flow tracks invite, acceptance, obligation, role,
   replacement, revocation, and notification eligibility.
4. Onboarding progress can move from emergency-card setup to medical-jacket
   completion without exposing raw sensitive records in logs, fixtures, or
   generated artifacts.
5. Phenotypical medical-record classes and genotypical import classes are
   separately classified before consent, custody, export, or matching logic.
6. Precision-medicine clinical-trial matching remains opt-in and inactive until
   consent, data-class, and eligibility contracts pass.
7. Frontline cohort eligibility for free basic family plans is represented with
   deterministic metadata and does not require raw proof documents in fixtures.
8. Stripe catalog identifiers, trial states, gift states, and payment outcomes
   are configuration-driven and use synthetic test values.
9. Marketplace templates declare rule scope, plan gate, required consent, audit
   behavior, and disablement behavior.
10. Initial storage levels include basic included storage, personal paid
    storage, family paid storage, and team paid storage.
11. Paid storage levels require Stripe catalog binding or custom-contract
    classification.
12. Initial storage levels include IPFS or another content-addressed provider
    option.
13. IPFS, Filecoin, object storage, and managed vault providers receive only
    encrypted blobs with opaque metadata.
14. EXOCHAIN storage anchors include only content-addressed references,
    commitments, policy references, retention-policy references,
    encryption-key commitments, and custody receipts.
15. Storage write operations enforce quota and billing state.
16. Tier-0 emergency reads do not consult payment or quota state, but still
    require authorization.

Implemented Rust coverage:

- `tests/ai_help_manual.rs`
- `tests/ai_help_session_transcript.rs`
- `tests/ai_help_unanswered_topic.rs`
- `tests/ai_help_usage_summary.rs`
- `tests/ai_help_topics.rs`
- `tests/consent_revocation_receipt.rs`
- `tests/exochain_adapter_activation.rs`
- `tests/feedback_mandated_reporter.rs`
- `tests/feedback_board_read_model.rs`
- `tests/emergency_profile.rs`
- `tests/ice_card_packet.rs`
- `tests/onboarding_pace.rs`
- `tests/qr_pointer.rs`
- `tests/qr_activation.rs`
- `tests/storage_entitlement.rs`
- `tests/medical_jacket_custody.rs`
- `tests/entitlement_marketplace.rs`
- `tests/genesis_development_trust.rs`
- `tests/vitallock_vault.rs`

Implemented TypeScript coverage:

- `tests/config.test.ts`
- `tests/heroes-registration-copy.test.ts`
- `tests/schema-subscriber-registration.test.ts`
- `tests/printable-card-render.test.ts`
- `tests/feedback-board-status.test.ts`
- `tests/ai-help-usage-summary-query.test.ts`
- `tests/ai-help-usage-summary-status.test.ts`
- `tests/ai-help-session-transcript-query.test.ts`
- `tests/ai-help-session-transcript-status.test.ts`
- `tests/ai-help-unanswered-topic-status.test.ts`
- `tests/status-route-contract.test.ts`
- `tests/ambient_signal.rs`
- `tests/responder_access_display.rs`
- `tests/trust-status.test.ts`
- `tests/ai-help-status.test.ts`
- `tests/ai-help-persistence.test.ts`

## AI Help Feedback And Agent Gate

Before AI help, feedback, mandated reporting, or agent dispatch behavior is
accepted, tests must prove:

1. AI help denies when disabled.
2. Feedback write operations deny when disabled.
3. Mandated reporting denies auto-create when disabled.
4. Agent dispatch denies when disabled.
5. Help-topic matching is deterministic and includes the active context topic
   when available.
6. AI responses are parsed into cleaned text, outcome, and cited topic ids.
7. Missing AI classification lines default to a partial-answer outcome.
8. Feedback item validation enforces target, category, priority, title, body,
   metadata, and author boundaries.
9. Feedback metadata rejects raw sensitive fields, raw QR payloads, payment
   secrets, eligibility documents, and unsafe screenshots.
10. Feedback status transitions enforce hold, validation accept, validation
    reject, and deployment rules.
11. Feedback activities are appended for creation, status changes, comments,
    holds, hold release, upvotes, validation actions, and agent dispatch.
12. Upvotes deduplicate by voter.
13. Bug-indicated AI sessions create or update high-priority bug feedback.
14. Repeated unanswered or confusion outcomes create or update documentation or
    UX feedback only after the configured threshold.
15. Privacy or safety-risk outcomes create redacted critical feedback.
16. Daily summaries deduplicate by date.
17. Agent dispatch is rate-limited per feedback item and sends only redacted
    payload fields.

## Exo Legacy Dependency Gate

Before LiveSafe accepts legacy-charter, genetic bequest, posthumous
representation, mausoleum export, erasure, or legacy capability behavior, tests
must prove:

1. Missing `exo-legacy` adapter yields inactive trust state.
2. Missing charter hash yields denial.
3. Failed invariant validation yields denial.
4. Charter contents are never stored in receipt metadata.
5. Genetic data classes are never stored in receipt metadata.
6. Interaction-memory text is never stored in receipt metadata.
7. Emergency Tier-0 access remains independent from payment and quorum state.
8. Erasure state is represented as key-destruction receipt evidence, not as a
   storage deletion guarantee.
9. Legacy capabilities are inactive unless verified by an adapter response.
10. Product copy and API responses do not claim posthumous, genetic, or erasure
    guarantees without verified code and policy evidence.

## Proprietary IP Handling Gate

Before LiveSafe architecture, transfer packages, implementation prompts, or
source-backed requirements are exported outside a private repository or
controlled agent session, tests and review must prove:

1. The artifact has source provenance.
2. The artifact has an explicit IP classification.
3. Proprietary internal artifacts are denied for public targets.
4. Private source evidence is denied for public targets.
5. Detailed architecture, transfer artifacts, and implementation prompts require
   explicit public-release approval.
6. Sensitive operational data is denied in every IP artifact.
7. Public materials are owner-approved summaries, not copied transfer packages.

## Civic Source Handling Gate

Before LiveSafe uses constitutional or civic language in product copy, doctrine,
runtime authority descriptions, or public materials, tests and review must
prove:

1. "We the People" is attributed to the U.S. Constitution Preamble.
2. "Of the people, by the people, for the people" is attributed separately to
   the Gettysburg Address.
3. Public-domain civic text is not classified as proprietary IP.
4. Civic language does not imply governmental authority or state action.
5. Civic language alone is not used as a legal-enforcement, consent, custody, or
   EXOCHAIN runtime claim.

## Genesis Development Trust Gate

Before LiveSafe treats ExoForge, root, FROST, or EXOCHAIN-adjacent development
outputs as externally signalable trust, tests and review must prove:

1. ExoForge is allowed for internal development planning, implementation
   workflow, review routing, and validation support.
2. ExoForge output is not treated as binding council decision, runtime
   authority, settlement, ratification, consent, custody, provenance, or
   authority-chain enforcement.
3. Source provenance is present for every trusted development input.
4. External trust signaling is denied until internal proof is complete.
5. External trust signaling is denied until the 7-of-13 FROST keygen ceremony is
   complete.
6. External trust signaling is denied unless the exact ceremony profile is 7
   threshold participants out of 13 participants.
7. External trust signaling is denied until the specific runtime adapter is
   verified.
8. Internal development can continue during genesis with synthetic fixtures,
   inactive trust-state views, fail-closed adapters, and private validation
   reports.

## Outward Trust Signal Gate

Before a public, customer-facing, printed, or API trust-bearing output is
accepted, tests and review must prove:

1. The output includes an AVC badge.
2. The output includes a lock-style or shield-style symbol.
3. The output includes colorized status treatment.
4. The output includes CSS glow treatment.
5. The output includes human-readable status text.
6. The output includes machine-readable status.
7. `not-verified` uses red treatment and exact display text `THIS IS NOT YET
   VERIFIED`.
8. `genesis-pending` uses yellow treatment and denies external trust claims.
9. `internal-proof` uses blue treatment and denies external trust claims.
10. `externally-verified` uses green treatment only after proof gates pass.

## Trust Signal Homologation Gate

Before a localized, jurisdiction-specific, device-specific, or holonic trust
display is accepted, tests and review must prove:

1. Jurisdiction code is present.
2. Language tag is present.
3. Locale and region codes are present.
4. Script code is supported, including Latin and relevant non-Latin scripts such
   as Japanese `Jpan` for Kanji/Kana presentation.
5. Canonical machine state is preserved.
6. Canonical display meaning is preserved.
7. Localized status text is present.
8. Cultural-symbol review is present for the target audience.
9. Trust state does not rely on color alone.
10. Assistive-technology support is present.
11. Mobile and tablet trust controls use at least 44px touch targets.
12. Holonic layouts remain stable across individual, family, P.A.C.E. network,
    responder, organization, and agent contexts.
