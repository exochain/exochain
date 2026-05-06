#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

manifest="Cargo.toml"

python3 - <<'PY'
import sys
import tomllib

with open("Cargo.toml", "rb") as manifest:
    dependencies = tomllib.load(manifest)["workspace"]["dependencies"]

unpinned = []
for name, spec in sorted(dependencies.items()):
    version = spec if isinstance(spec, str) else spec.get("version")
    if version and not version.startswith("="):
        unpinned.append(f"{name} ({version})")

if unpinned:
    print("workspace dependencies must be exactly pinned:", file=sys.stderr)
    for dependency in unpinned:
        print(f"  - {dependency}", file=sys.stderr)
    sys.exit(1)
PY

require_exact_pin() {
  local crate="$1"
  local version="$2"
  if grep -Eq "^${crate}[[:space:]]*=[[:space:]]*\"=${version}\"([[:space:]]*(#.*)?)?$" "$manifest"; then
    return 0
  fi
  if grep -Eq "^${crate}[[:space:]]*=[[:space:]]*\\{[^}]*version[[:space:]]*=[[:space:]]*\"=${version}\"" "$manifest"; then
    return 0
  fi

  echo "security-critical dependency is not exactly pinned: ${crate} must use =${version}" >&2
  return 1
}

require_exact_pin "serde" "1.0.228"
require_exact_pin "serde_json" "1.0.145"
require_exact_pin "ciborium" "0.2.2"
require_exact_pin "blake3" "1.8.2"
require_exact_pin "ed25519-dalek" "2.2.0"
require_exact_pin "x25519-dalek" "2.0.1"
require_exact_pin "sha2" "0.10.9"
require_exact_pin "hmac" "0.12.1"
require_exact_pin "chacha20poly1305" "0.10.1"
require_exact_pin "hkdf" "0.12.4"
require_exact_pin "rand" "0.8.6"
require_exact_pin "zeroize" "1.8.2"
require_exact_pin "ml-dsa" "0.1.0-rc.7"

echo "workspace dependency exact pin test passed"
