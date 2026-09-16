#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
"""Validate a dated publication claim; Git tags cannot prove publication.

This is an offline consistency check of reviewed provider observations, not a
fresh registry query, signature verifier, or authorization to publish.
"""

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import sys


SNAPSHOT_PATH = "governance/releases/published-release-snapshot.json"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate snapshot key: {key}")
        result[key] = value
    return result


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value
    ):
        raise ValueError("timestamps must be complete UTC observations")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def validate(readme, snapshot):
    if not isinstance(snapshot, dict) or type(snapshot.get("schema_version")) is not int \
            or snapshot["schema_version"] != 1:
        raise ValueError("unsupported publication snapshot schema")
    version = snapshot.get("version")
    if not isinstance(version, str) or not re.fullmatch(
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version
    ):
        raise ValueError("snapshot must identify a stable release version")
    observed_at = snapshot.get("observed_at")
    observed = timestamp(observed_at)
    github = snapshot.get("github")
    if not isinstance(github, dict):
        raise ValueError("GitHub publication record is missing")
    if type(github.get("release_id")) is not int or github["release_id"] <= 0:
        raise ValueError("GitHub release ID must identify a published release")
    if github.get("draft") is not False or github.get("prerelease") is not False:
        raise ValueError("drafts and prereleases cannot support a stable publication claim")
    if github.get("url") != f"https://github.com/exochain/exochain/releases/tag/v{version}":
        raise ValueError("GitHub release URL must bind the claimed EXOCHAIN version")
    if timestamp(github.get("published_at")) > observed:
        raise ValueError("publication cannot follow the recorded observation")

    for provider, pattern in (
        ("crates_io", r"exochain-[a-z0-9]+(?:-[a-z0-9]+)*"),
        ("npm", r"@exochain/[a-z0-9]+(?:-[a-z0-9]+)*"),
    ):
        record = snapshot.get(provider)
        if not isinstance(record, dict) or record.get("version") != version:
            raise ValueError(f"{provider} must confirm the same published version")
        packages = record.get("packages")
        if not isinstance(packages, list) or not packages:
            raise ValueError(f"{provider} must list the observed package inventory")
        seen = []
        for package in packages:
            if not isinstance(package, str) or not re.fullmatch(pattern, package):
                raise ValueError(f"{provider} contains an unsupported package name")
            if package in seen:
                raise ValueError(f"{provider} contains a duplicate package")
            seen.append(package)

    claims = []
    for line in readme.splitlines():
        if not line.lstrip().startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().split("|")[1:-1]]
        if cells and "published release" in cells[0].casefold():
            claims.append(cells)
    if len(claims) != 1 or len(claims[0]) != 3 \
            or claims[0][0] != "Last verified published release":
        raise ValueError("README requires exactly one dated, last-verified publication row")
    expected = f"`v{version}` (observed `{observed_at}`; packages listed in snapshot)"
    if claims[0][1] != expected or f"]({SNAPSHOT_PATH})" not in claims[0][2]:
        raise ValueError("README publication version/date/source does not match the snapshot")
    if "Git tags are not publication evidence." not in readme:
        raise ValueError("README must distinguish Git tags from publication evidence")
    return version, observed_at


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--readme", type=Path, default=root / "README.md")
    parser.add_argument("--snapshot", type=Path, default=root / SNAPSHOT_PATH)
    args = parser.parse_args()
    try:
        snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"),
                              object_pairs_hook=unique_object)
        version, observed_at = validate(args.readme.read_text(encoding="utf-8"), snapshot)
    except (OSError, ValueError) as error:
        print(f"publication claim failed: {error}", file=sys.stderr)
        return 1
    print(f"Publication claim matches reviewed snapshot: v{version}, observed {observed_at}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
