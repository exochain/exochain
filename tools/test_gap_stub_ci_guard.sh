#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "GAP stub CI guard test failed: $*" >&2
  exit 1
}

workflow=".github/workflows/ci.yml"

scan_gap_stubs() {
  grep -rEn \
    "(STUB.*GAP-0[0-9][0-9]|GAP-0[0-9][0-9].*STUB)" \
    --include='*.rs' \
    --include='*.ts' \
    --include='*.tsx' \
    --include='*.js' \
    --include='*.jsx' \
    --include='*.mjs' \
    --include='*.py' \
    "$@" 2>/dev/null || true
}

grep -F "bash tools/test_gap_stub_ci_guard.sh" "$workflow" >/dev/null \
  || fail "CI must run tools/test_gap_stub_ci_guard.sh"

if grep -F "[^\\n]" "$workflow" >/dev/null; then
  fail "CI GAP stub scan must not use grep ERE [^\\n]; it excludes literal n characters"
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

mkdir -p "$tmp_dir/crates" "$tmp_dir/packages" "$tmp_dir/web/src"
printf '%s\n' '// STUB pending GAP-001' > "$tmp_dir/web/src/StubFixture.tsx"
printf '%s\n' '// GAP-002 temporary STUB' > "$tmp_dir/crates/lib.rs"
printf '%s\n' '// STUB remediation GAP-003' > "$tmp_dir/packages/index.js"

fixture_matches="$(scan_gap_stubs "$tmp_dir/crates" "$tmp_dir/packages" "$tmp_dir/web/src")"
for expected in "StubFixture.tsx" "lib.rs" "index.js"; do
  if ! grep -F "$expected" <<<"$fixture_matches" >/dev/null; then
    fail "scan did not catch fixture $expected"
  fi
done

matches="$(scan_gap_stubs crates packages web/src)"
if [ -n "$matches" ]; then
  echo "::error::GAP stubs remain in code:"
  echo "$matches"
  exit 1
fi

echo "GAP stub CI guard test passed"
