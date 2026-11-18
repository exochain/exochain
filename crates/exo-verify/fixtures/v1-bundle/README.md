# Version 1 receipt bundle

`receipt-bundle.json` is the offline fixture bundle exactly as it was on
`main` at commit `e6ecf438`, before the version 2 format added the required
tree-head `chain_id` and the chain-binding paths. It is kept unchanged so the
tests can check that a real version 1 bundle is rejected with
`UnsupportedBundleVersion` at the JSON boundary, rather than with a
missing-field error.

Do not regenerate it.
