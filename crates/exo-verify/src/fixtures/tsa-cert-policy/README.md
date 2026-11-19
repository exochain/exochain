# TSA certificate policy fixtures

Test-only certificates for the RFC 3161 section 2.3 certificate checks in
`rfc3161.rs`. They are not used to sign anything; only their extensions are
checked. No private keys are kept.

- `ca_critical.der`: CA with critical `basicConstraints CA:TRUE` (accepted).
- `ca_noncritical.der`: same CA key with non-critical `basicConstraints` (rejected).
- `leaf_good.der`: critical EKU `timeStamping` only, `keyUsage digitalSignature` (accepted).
- `leaf_eku_noncritical.der`: non-critical EKU `timeStamping` (rejected).
- `leaf_eku_multi.der`: critical EKU `timeStamping, serverAuth` (rejected).
- `leaf_no_key_usage.der`: no `keyUsage` extension (rejected).

Regenerate with OpenSSL 3, using the extension sections in `ext.cnf`:

```sh
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out leaf.key
openssl req -new -key ca.key -subj "/CN=EXOCHAIN Test TSA Policy CA" -out ca.csr
openssl x509 -req -in ca.csr -signkey ca.key -extfile ext.cnf -extensions ca_critical \
  -not_before 20260101000000Z -not_after 20460101000000Z -outform DER -out ca_critical.der
# repeat with -extensions ca_noncritical, then sign each leaf_* section with
# -CA ca_critical.pem -CAkey ca.key using leaf.csr.
```
