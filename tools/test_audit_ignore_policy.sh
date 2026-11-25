#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

cd "$(dirname "$0")/.."

expiry_only=0
if [ "${1:-}" = "--expiry-only" ]; then
  expiry_only=1
elif [ "$#" -gt 0 ]; then
  echo "usage: $0 [--expiry-only]" >&2
  exit 2
fi

audit_json=""
tmp_dir=""
if [ "$expiry_only" -eq 0 ]; then
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
fi

python3 - "$audit_json" "$expiry_only" <<'PY'
import datetime
import json
import os
import re
import sys
import tomllib

audit_path = sys.argv[1]
expiry_only = sys.argv[2] == "1"


def validate_expiry_policies(
    audit_ids: set[str],
    deny_ids: set[str],
    exceptions: dict[str, dict[str, str]],
    today: datetime.date,
) -> list[str]:
    errors: list[str] = []
    for advisory_id, meta in sorted(exceptions.items()):
        if not isinstance(meta, dict):
            errors.append(f"exception {advisory_id} must be a table")
            continue
        raw_expires = meta.get("expires")
        if not isinstance(raw_expires, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw_expires):
            errors.append(f"exception {advisory_id} has invalid expires format: {raw_expires!r}")
            continue
        try:
            expires_date = datetime.date.fromisoformat(raw_expires)
        except ValueError as exc:
            errors.append(f"exception {advisory_id} has invalid calendar date {raw_expires!r}: {exc}")
            continue

        if advisory_id not in audit_ids or advisory_id not in deny_ids:
            errors.append(
                f"stale expiry policy entry {advisory_id}: must exist in both .cargo/audit.toml and deny.toml"
            )

        if today > expires_date:
            tracking = meta.get("tracking_issue", "untracked")
            errors.append(
                f"advisory exception {advisory_id} expired on {expires_date.isoformat()} "
                f"(today {today.isoformat()}, tracking: {tracking})"
            )
    return errors


# Deterministic boundary self-tests: final allowed day passes, day after fails.
sample_exceptions = {
    "RUSTSEC-2026-0534": {
        "expires": "2027-01-31",
        "tracking_issue": "https://github.com/exochain/exochain/issues/922",
    }
}
assert not validate_expiry_policies(
    {"RUSTSEC-2026-0534"},
    {"RUSTSEC-2026-0534"},
    sample_exceptions,
    datetime.date(2027, 1, 31),
), "boundary self-test failed: 2027-01-31 should be allowed"
expired_errs = validate_expiry_policies(
    {"RUSTSEC-2026-0534"},
    {"RUSTSEC-2026-0534"},
    sample_exceptions,
    datetime.date(2027, 2, 1),
)
assert len(expired_errs) == 1 and "expired on 2027-01-31" in expired_errs[0], (
    f"boundary self-test failed: 2027-02-01 should fail, got {expired_errs!r}"
)

with open(".cargo/audit.toml", "rb") as config_file:
    audit_text = config_file.read().decode("utf-8")
    configured_ids = set(
        tomllib.loads(audit_text)
        .get("advisories", {})
        .get("ignore", [])
    )

with open("deny.toml", "rb") as deny_file:
    deny_text = deny_file.read().decode("utf-8")
    deny_entries = tomllib.loads(deny_text).get("advisories", {}).get("ignore", [])
    deny_ids = {
        entry["id"] if isinstance(entry, dict) else entry
        for entry in deny_entries
    }

with open(".cargo/audit-expiry.toml", "rb") as expiry_file:
    expiry_cfg = tomllib.load(expiry_file)
exceptions = expiry_cfg.get("exceptions", {})

# Ensure any advisory entry whose reason or nearby comment declares an expiry date
# is backed by a structured rule in .cargo/audit-expiry.toml.
for entry in deny_entries:
    if isinstance(entry, dict):
        reason = entry.get("reason", "")
        if "expire" in reason.lower() and entry["id"] not in exceptions:
            print(
                f"deny.toml ignore {entry['id']} mentions expiry in reason text without "
                "a matching rule in .cargo/audit-expiry.toml",
                file=sys.stderr,
            )
            sys.exit(1)

raw_today = os.environ.get("EXOCHAIN_AUDIT_POLICY_TODAY")
if raw_today:
    today = datetime.date.fromisoformat(raw_today)
else:
    today = datetime.datetime.now(datetime.timezone.utc).date()

expiry_errors = validate_expiry_policies(configured_ids, deny_ids, exceptions, today)
if expiry_errors:
    print("advisory exception expiry policy check failed:", file=sys.stderr)
    for err in expiry_errors:
        print(f"  - {err}", file=sys.stderr)
    sys.exit(1)

if configured_ids != deny_ids:
    only_audit = sorted(configured_ids - deny_ids)
    only_deny = sorted(deny_ids - configured_ids)
    print("advisory ignore sets differ between .cargo/audit.toml and deny.toml:", file=sys.stderr)
    if only_audit:
        print(f"  only in .cargo/audit.toml: {only_audit}", file=sys.stderr)
    if only_deny:
        print(f"  only in deny.toml: {only_deny}", file=sys.stderr)
    sys.exit(1)

if not expiry_only:
    with open(audit_path, "r", encoding="utf-8") as report_file:
        report = json.load(report_file)

    active_ids = {
        item["advisory"]["id"]
        for item in report.get("vulnerabilities", {}).get("list", [])
    }

    for warning_items in report.get("warnings", {}).values():
        active_ids.update(
            advisory["id"]
            for item in warning_items
            if (advisory := item.get("advisory")) is not None
            and advisory.get("id")
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
