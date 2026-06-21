# Railway AVC Durability Context - 2026-06-21

## Purpose

This note records the Railway database and timestamp-authority answers needed by
future EXOCHAIN automation and remediation loops. Treat it as deployment
evidence plus operator context, not as proof of a code change.

## Path Classification

- `docs/audit/RAILWAY-AVC-DURABILITY-CONTEXT-2026-06-21.md`:
  imported deployment evidence and core runtime adapter operations context.
- No EXOCHAIN core Rust, governance invariant, CI, or deployment contract was
  changed by this note.

## Current Recorded Time

- Record created: `2026-06-21T03:45:52Z`.
- Railway config deployment created: `2026-06-21T03:40:12.028Z`.

## Verified Railway Target

- Workspace: `ARMORCLOUD`.
- Railway project: `exochain`.
- Railway project id: `ca52ac39-820a-488b-8f29-df17d76a9270`.
- Environment: `production`.
- Service: `exochain`.
- Service id: `e6538b78-5c05-4b37-b308-57a1249ad243`.
- Public Railway domain variable: `exochain.io`.
- Deployment id after config change: `7038665e-65ba-467a-b444-3d558c60877a`.
- Deployment status after polling: `SUCCESS`.

The local checkout used to record this was detached at
`ccf9d8d82ef226d9aae89df3bf7bd603f86bf422`; `origin/main` was
`5ea25f6c358a1544439d542d951adb9e7c73ca77`.

## Database Answer

`DATABASE_URL` was already present on the Railway `production` `exochain`
service. Its secret value was not printed or copied into this repo.

`EXO_AVC_REQUIRE_POSTGRES_DURABILITY=true` was set on the same service through
Railway CLI. This is the fail-closed guard for production AVC durability: if a
deployment starts without `DATABASE_URL`, startup must fail instead of silently
using the local AVC file fallback.

Read-back after the write showed:

```text
DATABASE_URL set
EXO_AVC_REQUIRE_POSTGRES_DURABILITY set
```

Relevant deployment logs after the write included:

```text
DATABASE_URL configured - initializing gateway readiness pool
AVC root trust issuer registered from verified bundle
AVC router ready - /api/v1/avc/{issue,validate,receipts,receipts/emit,protocol,delegate,revoke,:id}, /api/v1/agents/:did/avcs
```

No matching `PRODUCTION AVC DURABILITY WARNING`, `local file fallback`, or
`Postgres-backed` warning/error log lines appeared in the checked deployment
logs for deployment `7038665e-65ba-467a-b444-3d558c60877a`.

## What DATABASE_URL Does And Does Not Prove

`DATABASE_URL` is the production durability floor for AVC runtime records. With
it configured, AVC credentials, revocations, and trust receipts can use
Postgres-backed durability and the production AVC receipt timestamp source can
use Postgres `clock_timestamp()`.

`DATABASE_URL` is not a court-grade timestamp authority. It does not provide
RFC 3161, eIDAS qualified timestamping, blockchain anchoring, or independent
third-party notarization. It only proves that this deployment has a durable
database-backed runtime path available.

## Court-Grade Timestamp Answer

The correct court-grade shape is:

1. Canonicalize and hash the evidence package.
2. Mint an EXOCHAIN-signed receipt only after consent and authority validation.
3. Commit the receipt hash into EXOCHAIN DAG/BCTS ordering with the applicable
   commit certificate or receipt-chain proof.
4. Send the evidence digest to an independent RFC 3161 or eIDAS-qualified time
   stamp authority and store the raw timestamp token plus certificate chain.
5. Anchor a Merkle checkpoint of receipt hashes to an independent external
   public chain or notary ledger.
6. Emit a verification bundle that lets a third party verify hash, signature,
   authority, consent, DAG/BCTS inclusion, TSA token, and external anchor.

Assurance labels for future remediation:

- `operational_exochain_receipt`: EXOCHAIN-signed receipt with runtime
  provenance but no independent external timestamp.
- `ordered_exochain_receipt`: EXOCHAIN-signed receipt with DAG/BCTS ordering.
- `court_grade_external_time`: EXOCHAIN-signed, ordered receipt with independent
  RFC 3161 or eIDAS timestamp plus external anchor proof.

Do not describe Postgres `clock_timestamp()`, local HLC, or app-reported time as
court-grade external time.

## Public Runtime Probe Result

After Railway deployment success, public probes still returned rate limiting:

```text
https://exochain.io/ready  -> 429 gateway rate limit exceeded
https://exochain.io/health -> 429 gateway rate limit exceeded
```

This means Railway-side config and deployment status were verified, but public
HTTP readiness remained non-verifying because of rate limiting.

## Automation Loop Guidance

When an automation loop is triaging AVC receipt issues, use this note to avoid
three common conflations:

- Do not treat `DATABASE_URL` as the court-grade timestamp fix.
- Do not treat missing public `/ready` proof as proof that Railway config failed
  when the public edge is returning `429`.
- Do not set Railway variables against the locally linked project without first
  resolving the explicit project, environment, and service. On 2026-06-21 the
  local Railway context was `commandbase`, not the EXOCHAIN `exochain` project.

Safe read-only verification commands:

```bash
railway variable list \
  --project ca52ac39-820a-488b-8f29-df17d76a9270 \
  --environment production \
  --service exochain \
  --json | jq -r 'to_entries[] | select(.key == "DATABASE_URL" or .key == "EXO_AVC_REQUIRE_POSTGRES_DURABILITY") | [.key, (if ((.value|tostring|length) > 0) then "set" else "empty" end)] | @tsv'

railway service list \
  --project ca52ac39-820a-488b-8f29-df17d76a9270 \
  --environment production \
  --json | jq -r '.[]? | select(.name=="exochain") | {name,id,latestDeployment}'
```

Do not print or commit the raw `DATABASE_URL` secret.

