# Offline verification fixture

A complete AVC receipt bundle that an outside party can verify with only the
`exochain-verify` crate and the files in this directory, with networking
disabled. It covers the four level-3 properties (#910) for issue #897.

| File | What it is |
|---|---|
| `receipt-bundle.json` | The receipt and its inclusion proof (`exo.verify.receipt_bundle.v1`). The receipt embeds the validator's raw signed bytes (`signed_payload`), the subject attestation with the subject's raw signed bytes, and the RFC 3161 token. |
| `trust-inputs.json` | Caller trust inputs: the versioned `did:exo` key bundle (`exo.verify.key_bundle.v1`), the pinned TSA issuing-CA SPKI, and the accepted TSA policy OID. |
| `validator-signed-bytes.cbor` | Copy of the bytes the validator signed. |
| `subject-signed-bytes.cbor` | Copy of the bytes the subject (agent) signed. |
| `rfc3161-timestamp-token.der` | Copy of the RFC 3161 `TimeStampToken`. |
| `tsa/test-tsa-root-ca.crt.pem` | Test TSA root CA certificate (its SPKI is the pin in `trust-inputs.json`). |
| `tsa/test-tsa-signer.crt.pem` | Test TSA signing certificate (also embedded in the token). |

The copies must equal the material embedded in `receipt-bundle.json`; the
test suite checks this.

## What the fixture shows

- The receipt is an `Allow` decision at position 2 of a 5-receipt chain,
  proven against a tree head signed by the receipt's own validator. Two
  extra paths under the same root bind the position to the chain: the leaf
  before the receipt is its `previous_receipt_hash`, and the signed
  `chain_head` is the last leaf.
- The agent key must be valid both at the RFC 3161 time and at the time the
  agent signed.
- The subject's signed action carries a nonempty, signed human approval.
  Verifying that approval signature offline is out of scope (#911); the
  verifier reports only that it is present.
- The subject signed at a different time from the trusted receipt time:
  `subject_attestation.validation_now` is about five seconds before
  `created_at`, which equals the RFC 3161 `genTime`.

## Verify it

```sh
cargo run -p exochain-verify --example verify_bundle -- \
    crates/exo-verify/fixtures/offline-bundle/receipt-bundle.json \
    crates/exo-verify/fixtures/offline-bundle/trust-inputs.json
```

To prove no network is used on Linux, run the built example inside an empty
network namespace, for example `unshare -rn target/debug/examples/verify_bundle ...`.

The negative tests in `crates/exo-verify/tests/offline_fixture.rs` show that
tampered bytes, a wrong position, an unknown key, and a missing, corrupted or
untrusted timestamp each fail with a distinct `VerifyError`.

## Test-only trust material

The timestamp authority and every key here are throwaway test identities
created by the generator. They have no meaning outside this fixture. No
private key is stored in the repository.

## Regenerate

Regenerate only when the bundle format changes. It requires the `openssl`
CLI (3.x), and every run creates new keys and times:

```sh
cargo run -p exochain-verify --example generate_offline_fixture -- \
    crates/exo-verify/fixtures/offline-bundle
```
