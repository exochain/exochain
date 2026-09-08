#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

fail() {
  printf 'npm registry attestation verifier test failed: %s\n' "$1" >&2
  exit 1
}

case "${1:-}" in
  '') benign_only=false ;;
  --benign-only) benign_only=true ;;
  *) fail "usage: $0 [--benign-only]" ;;
esac
[ "$#" -le 1 ] || fail "usage: $0 [--benign-only]"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/exochain-npm-attestation-test.XXXXXX")"
trap '/bin/rm -rf -- "$test_root"' EXIT

# Read literal publisher data without sourcing or executing its credentialed path.
# Materialize the declared helpers, then invoke the exact declared verifier path.
verifier="$(node - "$repo_root" "$test_root" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const [repoRoot, testRoot] = process.argv.slice(2);
const publisher = fs.readFileSync(path.join(repoRoot, 'tools/publish_release_npm_package.sh'), 'utf8');
const assignments = [...publisher.matchAll(/^registry_verifier="\$publish_root\/([A-Za-z0-9._-]+)"$/gm)];
const materializers = [...publisher.matchAll(/^for helper in ([A-Za-z0-9._ -]+); do$/gm)];
if (assignments.length !== 1 || materializers.length !== 1) {
  throw new Error('publisher must declare one literal verifier path and helper materialization list');
}
const publishRoot = path.join(testRoot, 'publisher-helpers');
fs.mkdirSync(publishRoot, { mode: 0o700 });
for (const helper of materializers[0][1].split(' ')) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(helper)) {
    throw new Error('publisher helper must be a simple owned filename');
  }
  fs.copyFileSync(path.join(repoRoot, 'tools', helper), path.join(publishRoot, helper), fs.constants.COPYFILE_EXCL);
}
process.stdout.write(path.join(publishRoot, assignments[0][1]));
NODE
)"
[[ -f "$verifier" ]] || fail "publisher verifier was not materialized: ${verifier##*/}"

node - "$test_root" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const root = process.argv[2];
const integrity = `sha512-${Buffer.alloc(64, 7).toString('base64')}`;
const registry = {
  name: '@exochain/sdk', version: '0.2.6',
  maintainers: [{ name: 'bob-stewart', email: 'stewart@exochain.com' }],
  _npmUser: { name: 'bob-stewart', email: 'stewart@exochain.com' },
  dist: {
    integrity,
    tarball: 'https://registry.npmjs.org/@exochain/sdk/-/sdk-0.2.6.tgz',
    signatures: [{ keyid: 'SHA256:test', sig: 'test' }],
    attestations: {
      url: 'https://registry.npmjs.org/-/npm/v1/attestations/%40exochain%2Fsdk@0.2.6',
      provenance: { predicateType: 'https://slsa.dev/provenance/v1' },
    },
  },
};
fs.writeFileSync(path.join(root, 'registry.json'), JSON.stringify(registry));
fs.writeFileSync(path.join(root, 'expected-integrity'), integrity);
NODE
integrity="$(<"$test_root/expected-integrity")"
node "$verifier" registry "$test_root/registry.json" '@exochain/sdk' 0.2.6 \
  "$integrity" bob-stewart stewart@exochain.com >/dev/null \
  || fail "materialized publisher verifier rejected the exact registry identity"
if [ "$benign_only" = true ]; then
  printf 'npm publisher benign verifier materialization and registry-identity test passed\n'
  exit 0
fi

openssl_config="$test_root/openssl.cnf"
cat > "$openssl_config" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = extensions
prompt = no
[dn]
CN = npm-attestation-test
[extensions]
subjectAltName = URI:https://github.com/exochain/exochain/.github/workflows/release.yml@refs/tags/v0.2.6
EOF
/usr/bin/openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -nodes -days 1 -config "$openssl_config" -keyout "$test_root/key.pem" \
  -out "$test_root/cert.pem" >/dev/null 2>&1
/usr/bin/openssl x509 -in "$test_root/cert.pem" -outform DER -out "$test_root/cert.der"

node - "$test_root" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');

const root = process.argv[2];
const name = '@exochain/sdk';
const version = '0.2.6';
const commit = '1'.repeat(40);
const ref = 'refs/tags/v0.2.6';
const integrity = `sha512-${Buffer.alloc(64, 7).toString('base64')}`;
const subject = [{
  name: `pkg:npm/%40exochain/sdk@${version}`,
  digest: { sha512: Buffer.alloc(64, 7).toString('hex') },
}];
const bundle = (statement, verificationMaterial) => ({
  mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.2',
  verificationMaterial,
  dsseEnvelope: {
    payload: Buffer.from(JSON.stringify(statement)).toString('base64'),
    payloadType: 'application/vnd.in-toto+json',
    signatures: [{ sig: Buffer.from('verified signature').toString('base64'), keyid: '' }],
  },
});
const publishType = 'https://github.com/npm/attestation/tree/main/specs/publish/v0.1';
const provenanceType = 'https://slsa.dev/provenance/v1';
const publish = {
  _type: 'https://in-toto.io/Statement/v0.1',
  subject,
  predicateType: publishType,
  predicate: { name, version, registry: 'https://registry.npmjs.org' },
};
const provenance = {
  _type: 'https://in-toto.io/Statement/v1',
  subject,
  predicateType: provenanceType,
  predicate: {
    buildDefinition: {
      buildType: 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1',
      externalParameters: {
        workflow: {
          ref,
          repository: 'https://github.com/exochain/exochain',
          path: '.github/workflows/release.yml',
        },
      },
      internalParameters: { github: { event_name: 'workflow_dispatch' } },
      resolvedDependencies: [{
        uri: `git+https://github.com/exochain/exochain@${ref}`,
        digest: { gitCommit: commit },
      }],
    },
    runDetails: { builder: { id: 'https://github.com/actions/runner/github-hosted' } },
  },
};
const certificate = fs.readFileSync(path.join(root, 'cert.der')).toString('base64');
const audit = {
  invalid: [],
  missing: [],
  verified: [{
    name,
    version,
    registry: 'https://registry.npmjs.org/',
    attestations: { provenance: { predicateType: provenanceType } },
    attestationBundles: [
      { predicateType: publishType, bundle: bundle(publish, { tlogEntries: [{ logIndex: '1' }] }) },
      { predicateType: provenanceType, bundle: bundle(provenance, {
        x509CertificateChain: { certificates: [{ rawBytes: certificate }] },
        tlogEntries: [{ logIndex: '2' }],
      }) },
    ],
  }],
};
fs.writeFileSync(path.join(root, 'audit.json'), JSON.stringify(audit));
NODE

node "$verifier" audit "$test_root/audit.json" '@exochain/sdk' 0.2.6 \
  "$integrity" "$(printf '1%.0s' {1..40})" refs/tags/v0.2.6 >/dev/null \
  || fail "exact registry signature and provenance proof was rejected"

expect_audit_rejected() {
  local label="$1"
  local file="$2"
  local commit="${3:-$(printf '1%.0s' {1..40})}"
  if node "$verifier" audit "$file" '@exochain/sdk' 0.2.6 \
      "$integrity" "$commit" refs/tags/v0.2.6 >/dev/null 2>&1; then
    fail "$label was accepted"
  fi
}

wrong_maintainer="$test_root/wrong-maintainer.json"
node - "$test_root/registry.json" "$wrong_maintainer" <<'NODE'
const fs=require('node:fs'); const value=JSON.parse(fs.readFileSync(process.argv[2]));
value.maintainers[0].name='attacker'; fs.writeFileSync(process.argv[3],JSON.stringify(value));
NODE
if node "$verifier" registry "$wrong_maintainer" '@exochain/sdk' 0.2.6 \
    "$integrity" bob-stewart stewart@exochain.com >/dev/null 2>&1; then
  fail "wrong exact maintainer was accepted"
fi

wrong_repository="$test_root/wrong-repository.json"
node - "$test_root/audit.json" "$wrong_repository" <<'NODE'
const fs=require('node:fs'); const value=JSON.parse(fs.readFileSync(process.argv[2]));
const item=value.verified[0].attestationBundles.find(v=>v.predicateType==='https://slsa.dev/provenance/v1');
const statement=JSON.parse(Buffer.from(item.bundle.dsseEnvelope.payload,'base64'));
statement.predicate.buildDefinition.externalParameters.workflow.repository='https://github.com/attacker/exochain';
item.bundle.dsseEnvelope.payload=Buffer.from(JSON.stringify(statement)).toString('base64');
fs.writeFileSync(process.argv[3],JSON.stringify(value));
NODE
expect_audit_rejected "wrong provenance repository" "$wrong_repository"

missing_publish="$test_root/missing-publish.json"
node - "$test_root/audit.json" "$missing_publish" <<'NODE'
const fs=require('node:fs'); const value=JSON.parse(fs.readFileSync(process.argv[2]));
value.verified[0].attestationBundles=value.verified[0].attestationBundles.filter(v=>v.predicateType==='https://slsa.dev/provenance/v1');
fs.writeFileSync(process.argv[3],JSON.stringify(value));
NODE
expect_audit_rejected "missing registry publish attestation" "$missing_publish"
expect_audit_rejected "wrong exact provenance commit" "$test_root/audit.json" "$(printf '2%.0s' {1..40})"

wrong_certificate="$test_root/wrong-certificate.json"
node - "$test_root/audit.json" "$wrong_certificate" <<'NODE'
const fs=require('node:fs'); const value=JSON.parse(fs.readFileSync(process.argv[2]));
const item=value.verified[0].attestationBundles.find(v=>v.predicateType==='https://slsa.dev/provenance/v1');
item.bundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes='d3Jvbmc=';
fs.writeFileSync(process.argv[3],JSON.stringify(value));
NODE
expect_audit_rejected "malformed provenance certificate" "$wrong_certificate"

printf 'npm registry attestation verifier test passed\n'
