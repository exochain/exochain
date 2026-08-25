# CrossChecked anchor V1 locked fixtures

These files lock the exact commitment-only 16-key request, 10-key response,
signature preimages, signatures, commitment hashes, nested receipt item, and
verification public keys. They contain deterministic test-only keys and no
production credentials.

`cargo run -p exochain-api --example generate_crosschecked_anchor_fixtures`
regenerates the binary files through the independent literal CBOR builder in
`tests/support/crosschecked_anchor_fixture_reference.rs`. That builder is also
executed by the fixture tests and deliberately does not import or call the
production `exo_api::crosschecked_anchor` codec. Tests byte-compare every file,
verify this SHA-256 manifest, validate both signed messages through production,
and require every single-byte request/response poison to fail closed.

The nested receipt adapter encodes its HLC timestamp as `[physical_ms, logical]`
only for this anchor protocol. Generic `TrustReceipt` and RFC 3161 serialization
remain unchanged.
