#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

fail() {
  printf 'Python release package verifier test failed: %s\n' "$1" >&2
  exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
guard="$repo_root/tools/verify_python_release_package.py"
[[ -f "$guard" ]] || fail "$guard is missing"

test_root="$(mktemp -d "${TMPDIR:-/tmp}/exochain-python-package-test.XXXXXX")"
trap '/bin/rm -rf -- "$test_root"' EXIT
dist="$test_root/dist"
mkdir "$dist"

python3 - "$dist" "$test_root" <<'PY'
from __future__ import annotations

import base64
import csv
import datetime
import hashlib
import io
import json
import pathlib
import sys
import tarfile
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

dist = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
version = "0.2.6"
commit = "1" * 40
ref = "refs/tags/v0.2.6"
repository = "exochain/exochain"
workflow = "release.yml"
metadata = (
    "Metadata-Version: 2.3\n"
    "Name: exochain\n"
    f"Version: {version}\n"
    "License-Expression: Apache-2.0\n"
    "Requires-Python: >=3.11\n"
    "Requires-Dist: blake3>=0.4.1\n"
    "Requires-Dist: cryptography>=42.0.0\n"
    "Requires-Dist: httpx>=0.25.0\n"
    "Requires-Dist: pydantic>=2.5.0\n"
    "Provides-Extra: dev\n"
    "Requires-Dist: mypy>=1.7; extra == 'dev'\n"
    "Requires-Dist: pytest-asyncio>=0.23; extra == 'dev'\n"
    "Requires-Dist: pytest>=7.4; extra == 'dev'\n"
    "Requires-Dist: ruff>=0.1.8; extra == 'dev'\n\n"
).encode()
source_names = {
    "exochain/__init__.py",
    "exochain/authority/__init__.py",
    "exochain/authority/chain.py",
    "exochain/client.py",
    "exochain/consent/__init__.py",
    "exochain/consent/bailment.py",
    "exochain/crypto/__init__.py",
    "exochain/crypto/hash.py",
    "exochain/errors.py",
    "exochain/governance/__init__.py",
    "exochain/governance/decision.py",
    "exochain/governance/vote.py",
    "exochain/identity/__init__.py",
    "exochain/identity/did.py",
    "exochain/identity/keypair.py",
    "exochain/py.typed",
    "exochain/transport/__init__.py",
    "exochain/transport/http.py",
    "exochain/types.py",
}
support_names = {
    ".gitignore",
    "README.md",
    "examples/create_identity.py",
    "examples/governance_decision.py",
    "examples/propose_bailment.py",
    "pyproject.toml",
    "tests/__init__.py",
    "tests/test_authority.py",
    "tests/test_consent.py",
    "tests/test_crypto.py",
    "tests/test_governance.py",
    "tests/test_identity.py",
    "tests/test_transport.py",
}


def body(name: str, size: int = 2300) -> bytes:
    prefix = f'"""Meaningful fixture for {name}."""\nVALUE = "verified"\n'.encode()
    return prefix + b"# deterministic implementation fixture\n" * ((size - len(prefix)) // 35 + 1)


wheel_members: dict[str, bytes] = {
    name: (b"typed\n" if name.endswith("py.typed") else body(name)) for name in source_names
}
dist_info = f"exochain-{version}.dist-info"
wheel_members[f"{dist_info}/METADATA"] = metadata
wheel_members[f"{dist_info}/WHEEL"] = (
    b"Wheel-Version: 1.0\nGenerator: exochain-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
)
record_name = f"{dist_info}/RECORD"
record_rows = []
for name, contents in sorted(wheel_members.items()):
    digest = base64.urlsafe_b64encode(hashlib.sha256(contents).digest()).rstrip(b"=").decode()
    record_rows.append([name, f"sha256={digest}", str(len(contents))])
record_rows.append([record_name, "", ""])
record_stream = io.StringIO(newline="")
csv.writer(record_stream, lineterminator="\n").writerows(record_rows)
wheel_members[record_name] = record_stream.getvalue().encode()

wheel = dist / f"exochain-{version}-py3-none-any.whl"
with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
    for name, contents in sorted(wheel_members.items()):
        archive.writestr(name, contents)

sdist_members = {name: wheel_members[name] for name in source_names}
for name in support_names:
    sdist_members[name] = body(name, 1500)
sdist_members["pyproject.toml"] = body("pyproject.toml", 1500) + (
    b"\n[build-system]\nrequires=['hatchling']\nbuild-backend='hatchling.build'\n"
)
sdist_members["PKG-INFO"] = metadata
sdist = dist / f"exochain-{version}.tar.gz"
with tarfile.open(sdist, "w:gz") as archive:
    for name, contents in sorted(sdist_members.items()):
        info = tarfile.TarInfo(f"exochain-{version}/{name}")
        info.size = len(contents)
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(contents))

artifact_digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
statement = {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [{"name": wheel.name, "digest": {"sha256": artifact_digest}}],
    "predicateType": "https://docs.pypi.org/attestations/publish/v1",
    "predicate": None,
}
workflow_uri = f"https://github.com/{repository}/.github/workflows/{workflow}@{ref}"
key = ec.generate_private_key(ec.SECP256R1())
now = datetime.datetime.now(datetime.timezone.utc)
builder = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")]))
    .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")]))
    .public_key(key.public_key())
    .serial_number(1)
    .not_valid_before(now - datetime.timedelta(minutes=1))
    .not_valid_after(now + datetime.timedelta(minutes=1))
    .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(workflow_uri)]), True)
)
for oid, value in {
    "1.3.6.1.4.1.57264.1.1": "https://token.actions.githubusercontent.com",
    "1.3.6.1.4.1.57264.1.2": "workflow_dispatch",
    "1.3.6.1.4.1.57264.1.3": commit,
    "1.3.6.1.4.1.57264.1.5": repository,
    "1.3.6.1.4.1.57264.1.6": ref,
    "1.3.6.1.4.1.57264.1.11": "github-hosted",
}.items():
    builder = builder.add_extension(x509.UnrecognizedExtension(ObjectIdentifier(oid), value.encode()), False)
certificate = builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
provenance = {
    "version": 1,
    "attestation_bundles": [{
        "publisher": {
            "kind": "GitHub",
            "repository": repository,
            "workflow": workflow,
            "environment": "release",
            "claims": None,
        },
        "attestations": [{
            "version": 1,
            "envelope": {
                "statement": base64.b64encode(
                    json.dumps(statement, separators=(",", ":")).encode()
                ).decode(),
                "signature": base64.b64encode(b"test signature").decode(),
            },
            "verification_material": {
                "certificate": base64.b64encode(certificate).decode(),
                "transparency_entries": [{"logIndex": "1"}],
            },
        }],
    }],
}
(root / "provenance.json").write_text(json.dumps(provenance, separators=(",", ":")))
PY

manifest="$test_root/artifact-manifest.tsv"
python3 -I -B "$guard" artifacts "$dist" exochain 0.2.6 --write-manifest "$manifest" \
  || fail "valid meaningful wheel and sdist were rejected"
[[ $(wc -l < "$manifest") -eq 2 ]] || fail "manifest must contain both distributions"
python3 -I -B "$guard" artifacts "$dist" exochain 0.2.6 --expect-manifest "$manifest" \
  || fail "exact artifact manifest was rejected"

registry="$test_root/registry.json"
python3 - "$manifest" "$registry" <<'PY'
import json
import pathlib
import sys

urls = []
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    filename, digest, size = line.split("\t")
    urls.append({"filename": filename, "digests": {"sha256": digest}, "size": int(size)})
pathlib.Path(sys.argv[2]).write_text(json.dumps({
    "info": {"name": "exochain", "version": "0.2.6"},
    "urls": urls,
}))
PY
python3 -I -B "$guard" registry-response "$registry" exochain 0.2.6 "$manifest" \
  || fail "exact PyPI registry response was rejected"

python3 - "$guard" <<'PY' \
  || fail "unreviewed optional Python dependency metadata was accepted"
from importlib.util import module_from_spec, spec_from_file_location
import sys

spec = spec_from_file_location("release_verifier", sys.argv[1])
assert spec is not None and spec.loader is not None
module = module_from_spec(spec)
spec.loader.exec_module(module)
metadata = (
    "Metadata-Version: 2.3\n"
    "Name: exochain\n"
    "Version: 0.2.6\n"
    "License-Expression: Apache-2.0\n"
    "Requires-Python: >=3.11\n"
    "Requires-Dist: blake3>=0.4.1\n"
    "Requires-Dist: cryptography>=42.0.0\n"
    "Requires-Dist: httpx>=0.25.0\n"
    "Requires-Dist: pydantic>=2.5.0\n"
    "Provides-Extra: dev\n"
    "Requires-Dist: attacker-package; extra == 'dev'\n\n"
).encode()
try:
    module.verify_metadata(metadata, "exochain", "0.2.6", "malicious metadata")
except SystemExit:
    raise SystemExit(0)
raise SystemExit(1)
PY

wheel="$dist/exochain-0.2.6-py3-none-any.whl"
provenance="$test_root/provenance.json"
python3 -B "$guard" provenance "$provenance" "$wheel" \
  exochain/exochain release.yml release refs/tags/v0.2.6 "$(printf '1%.0s' {1..40})" \
  || fail "exact PyPI provenance identity was rejected"

expect_provenance_rejected() {
  local label="$1"
  local expected_commit="$2"
  local expected_environment="$3"
  if python3 -B "$guard" provenance "$provenance" "$wheel" \
      exochain/exochain release.yml "$expected_environment" refs/tags/v0.2.6 "$expected_commit" \
      >/dev/null 2>&1; then
    fail "$label was accepted"
  fi
}
expect_provenance_rejected "wrong provenance commit" "$(printf '2%.0s' {1..40})" release
expect_provenance_rejected "wrong trusted-publisher environment" "$(printf '1%.0s' {1..40})" staging

wrong_claims="$test_root/wrong-claims.json"
python3 - "$provenance" "$wrong_claims" <<'PY'
import json
from pathlib import Path
import sys

value = json.loads(Path(sys.argv[1]).read_text())
value["attestation_bundles"][0]["publisher"]["claims"] = {"sub": "unreviewed"}
Path(sys.argv[2]).write_text(json.dumps(value, separators=(",", ":")))
PY
if python3 -B "$guard" provenance "$wrong_claims" "$wheel" \
    exochain/exochain release.yml release refs/tags/v0.2.6 "$(printf '1%.0s' {1..40})" \
    >/dev/null 2>&1; then
  fail "unreviewed trusted-publisher claims were accepted"
fi

python3 - "$registry" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
path.write_text(text.replace('"name": "exochain"', '"name": "attacker", "name": "exochain"'))
PY
if python3 -I -B "$guard" registry-response "$registry" exochain 0.2.6 "$manifest" >/dev/null 2>&1; then
  fail "duplicate JSON keys were accepted"
fi

placeholder="$test_root/placeholder"
mkdir "$placeholder"
python3 - "$placeholder" <<'PY'
import io
import pathlib
import sys
import tarfile
import zipfile

root = pathlib.Path(sys.argv[1])
metadata = b"Metadata-Version: 2.3\nName: exochain\nVersion: 0.2.6\nLicense-Expression: Apache-2.0\nRequires-Python: >=3.11\n\n"
with zipfile.ZipFile(root / "exochain-0.2.6-py3-none-any.whl", "w") as archive:
    archive.writestr("exochain/__init__.py", b"pass\n")
    archive.writestr("exochain-0.2.6.dist-info/METADATA", metadata)
with tarfile.open(root / "exochain-0.2.6.tar.gz", "w:gz") as archive:
    for name, contents in {"PKG-INFO": metadata, "pyproject.toml": b"[project]\n"}.items():
        info = tarfile.TarInfo(f"exochain-0.2.6/{name}")
        info.size = len(contents)
        archive.addfile(info, io.BytesIO(contents))
PY
if python3 -I -B "$guard" artifacts "$placeholder" exochain 0.2.6 \
    --expect-manifest "$manifest" >/dev/null 2>&1; then
  fail "placeholder/minimal Python archives were accepted"
fi

mismatched="$test_root/mismatched"
/bin/cp -R "$dist" "$mismatched"
python3 - "$mismatched/exochain-0.2.6.tar.gz" <<'PY'
from __future__ import annotations

import io
from pathlib import Path
import sys
import tarfile

path = Path(sys.argv[1])
replacement = path.with_suffix(".replacement")
with tarfile.open(path, "r:gz") as source, tarfile.open(replacement, "w:gz") as target:
    for member in source.getmembers():
        stream = source.extractfile(member)
        contents = b"" if stream is None else stream.read()
        if member.name.endswith("/exochain/client.py"):
            contents += b"\n# wheel/sdist source mismatch\n"
            member.size = len(contents)
        target.addfile(member, io.BytesIO(contents) if member.isfile() else None)
replacement.replace(path)
PY
if python3 -I -B "$guard" artifacts "$mismatched" exochain 0.2.6 \
    --write-manifest "$test_root/mismatched-manifest.tsv" >/dev/null 2>&1; then
  fail "wheel and sdist with divergent Python source were accepted"
fi

symlink_response="$test_root/symlink.json"
/bin/ln -s "$manifest" "$symlink_response"
if python3 -I -B "$guard" registry-response "$symlink_response" exochain 0.2.6 "$manifest" >/dev/null 2>&1; then
  fail "symlinked registry response was accepted"
fi

printf 'Python release package verifier test passed\n'
