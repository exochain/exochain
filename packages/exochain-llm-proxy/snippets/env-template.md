# LYNK Environment Template

Use local secret managers for real values. Do not paste live secrets into issue
bodies, PR comments, chat prompts, or agent task briefs.

```bash
export EXOCHAIN_GATEWAY_URL="https://exochain.example"
export EXOCHAIN_TENANT_ID="tenant-alpha"
export EXOCHAIN_NAMESPACE="default"
export EXOCHAIN_ACTOR_DID="did:exo:agent"
export EXOCHAIN_LYNK_ADAPTER_DID="did:exo:lynk-adapter"
export EXOCHAIN_LYNK_CUSTODY_POLICY_HASH="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
export EXOCHAIN_LYNK_STORAGE_MODE="receipt_minimized"
export EXOCHAIN_LYNK_IDEMPOTENCY_KEY="tenant-alpha-run-001"
```

Supported storage modes are `receipt_minimized`, `external_payload_ref`, and
`dagdb_custody`.
