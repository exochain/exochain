#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
"""Record successful CI for one verified commit; never authorize publication."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib


def build_report(env, version):
    needs = json.loads(env.get("CI_NEEDS_JSON", "null"))
    if not isinstance(needs, dict) or set(needs) != {"all-gates"}:
        raise ValueError("candidate requires the complete all-gates dependency")
    gate = needs["all-gates"]
    if not isinstance(gate, dict) or gate.get("result") != "success":
        raise ValueError("all-gates must have succeeded")
    patterns = {
        "GITHUB_SHA": r"[0-9a-f]{40}",
        "GITHUB_REPOSITORY": r"[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+",
        "GITHUB_RUN_ID": r"[1-9][0-9]*",
        "GITHUB_RUN_ATTEMPT": r"[1-9][0-9]*",
    }
    for key, pattern in patterns.items():
        if re.fullmatch(pattern, env.get(key, "")) is None:
            raise ValueError(f"missing or malformed {key}")
    repository = env["GITHUB_REPOSITORY"]
    workflow_ref = env.get("GITHUB_WORKFLOW_REF", "")
    if re.fullmatch(re.escape(repository) + r"/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml@[^\s]+", workflow_ref) is None:
        raise ValueError("workflow identity must belong to the candidate repository")
    if not isinstance(version, str) or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", version) is None:
        raise ValueError("invalid workspace release version")
    return {
        "schema": "exochain.ci-candidate.v1",
        "status": "quality-gates-passed",
        "repository": repository,
        "source_commit": env["GITHUB_SHA"],
        "workspace_version": version,
        "workflow_ref": workflow_ref,
        "run_id": env["GITHUB_RUN_ID"],
        "run_attempt": env["GITHUB_RUN_ATTEMPT"],
        "run_url": f"https://github.com/{repository}/actions/runs/{env['GITHUB_RUN_ID']}/attempts/{env['GITHUB_RUN_ATTEMPT']}",
        "publication_authorized": False,
    }


def verify_source(env):
    guard_env = dict(env, EXPECTED_COMMIT_SHA=env["GITHUB_SHA"],
                     TRUSTED_RELEASE_REF=env["GITHUB_SHA"], RELEASE_SOURCE_CLEAN_MODE="all")
    guard = Path(__file__).resolve().with_name("verify_release_source.sh")
    subprocess.run(["/bin/bash", "--noprofile", "--norc", "-p", str(guard)],
                   env=guard_env, check=True, capture_output=True, text=True)


def main():
    if len(sys.argv) != 2:
        raise ValueError("usage: write_ci_candidate.py OUTPUT_JSON")
    # Validate the run before touching source or creating evidence. The existing
    # release guard then checks the object graph, checkout bytes, index and SHA.
    build_report(os.environ, "0.0.0")
    verify_source(os.environ)
    root = Path(os.environ["GITHUB_WORKSPACE"])
    with (root / "Cargo.toml").open("rb") as source:
        version = tomllib.load(source)["workspace"]["package"]["version"]
    report = build_report(os.environ, version)
    with Path(sys.argv[1]).open("x", encoding="utf-8") as output:
        json.dump(report, output, sort_keys=True, indent=2)
        output.write("\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as output:
            output.write(f"### Release candidate readiness\n\nCommit `{report['source_commit']}` passed all constitutional CI gates.\n\n")
            output.write("This record does not authorize publication. Signed tags, both release environment gates, fresh artifact verification and provenance remain required.\n")
    print(f"Candidate readiness recorded for {report['source_commit']} (publication not authorized).")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(f"candidate readiness failed: {error}", file=sys.stderr)
        sys.exit(1)
