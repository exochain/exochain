# Receipt Pending Runbook

`receipt_pending` means the provider or MCP server returned successfully but the
EXOCHAIN receipt path did not commit. Production callers must withhold output.

Operator steps:

1. Preserve the returned idempotency hash and receipt intent.
2. Check EXOCHAIN `/ready` and the AVC route health from the deployment surface
   declared canonical for this tenant.
3. Retry receipt emission with the same intent.
4. If retry returns the same committed receipt, release output through the
   caller's normal authorized path.
5. If retry reports an idempotency conflict, escalate as a custody/provenance
   incident and do not release output.

Do not reconstruct evidence from provider payload memory during retry. Reuse the
original receipt intent.
