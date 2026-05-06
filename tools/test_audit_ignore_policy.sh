#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

command -v cargo-audit >/dev/null 2>&1 || {
  echo "cargo-audit is required for audit ignore policy validation" >&2
  exit 1
}

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

audit_json="$tmp_dir/audit-without-local-config.json"

(
  cd "$tmp_dir"
  cargo audit \
    --file "$OLDPWD/Cargo.lock" \
    --no-fetch \
    --deny unsound \
    --deny unmaintained \
    --format json >"$audit_json" || true
)

python3 - "$audit_json" <<'PY'
import json
import sys
import tomllib

audit_path = sys.argv[1]

with open(audit_path, "r", encoding="utf-8") as report_file:
    report = json.load(report_file)

active_ids = {
    item["advisory"]["id"]
    for item in report.get("vulnerabilities", {}).get("list", [])
}

for warning_items in report.get("warnings", {}).values():
    active_ids.update(item["advisory"]["id"] for item in warning_items)

with open(".cargo/audit.toml", "rb") as config_file:
    configured_ids = set(
        tomllib.load(config_file)
        .get("advisories", {})
        .get("ignore", [])
    )

stale_ids = sorted(configured_ids - active_ids)
undocumented_ids = sorted(active_ids - configured_ids)

if stale_ids:
    print("stale cargo-audit advisory ignores:", file=sys.stderr)
    for advisory_id in stale_ids:
        print(f"  - {advisory_id}", file=sys.stderr)

if undocumented_ids:
    print("active cargo-audit advisories must be fixed or documented:", file=sys.stderr)
    for advisory_id in undocumented_ids:
        print(f"  - {advisory_id}", file=sys.stderr)

if stale_ids or undocumented_ids:
    sys.exit(1)
PY

echo "audit ignore policy test passed"
