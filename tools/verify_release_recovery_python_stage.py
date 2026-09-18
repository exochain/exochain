#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
"""Exact, non-executable workspace exceptions for the pinned PyPI Docker action."""
import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location("recovery_custody", Path(__file__).with_name("verify_release_recovery_027.py"))
custody = importlib.util.module_from_spec(spec)
spec.loader.exec_module(custody)
ACTION_PATH = ".github/.tmp/.generated-actions/run-pypi-publish-in-docker-container/action.yml"
ACTION_IMAGE = "docker://ghcr.io/pypa/gh-action-pypi-publish:cef221092ed1bacb1cc03d23a2d87d1d172e277b"
ACTION_DESCRIPTION = "Run Docker container to upload Python distribution packages to PyPI"
ACTION_INPUTS = ("user", "password", "repository-url", "packages-dir", "verify-metadata", "skip-existing", "verbose", "print-hash", "attestations")
STAGE = ".release-recovery-python-stage"


def validate_stage(workspace, state_path, phase, sha, ref, inventory):
    custody.require(phase in ("staged", "readback"), "unknown Python workspace phase")
    state = custody.load_json(state_path, "private Python stage state")
    custody.keys(state, ("schema", "controller_sha", "controller_ref", "staged"), "Python stage state")
    custody.exact(state["schema"], "exochain-python-recovery-stage/v1", "Python stage schema")
    custody.exact(state["controller_sha"], sha, "Python stage controller")
    custody.exact(state["controller_ref"], ref, "Python stage ref")
    staged = state["staged"]
    custody.require(type(staged) is list and all(type(name) is str for name in staged), "invalid staged filenames")
    custody.require(len(staged) <= 2 and len(staged) == len(set(staged)), "duplicate or oversized staged inventory")
    custody.require(staged == [name for name in inventory if name in staged], "staged inventory is not a canonical subset")
    published = phase == "readback" and bool(staged)
    expected = set(staged)
    if published:
        expected.update(name + ".publish.attestation" for name in staged)
    allowed = []
    with ExitStack() as stack:
        root = custody.directory_fd(workspace)
        stack.callback(os.close, root)
        stage = custody.directory_fd(STAGE, root)
        stack.callback(os.close, stage)
        custody.require(set(os.listdir(stage)) == expected, "Python stage has missing or unexpected action files")
        for name in staged:
            data = custody.read_regular(name, custody.MAX_ZIP_BYTES, "staged distribution", stage)
            custody.exact(len(data), inventory[name]["size"], "staged distribution size")
            custody.exact(hashlib.sha256(data).hexdigest(), inventory[name]["sha256"], "staged distribution digest")
            allowed.append(STAGE + "/" + name)
            if published:
                sidecar = name + ".publish.attestation"
                custody.parse_json(custody.read_regular(sidecar, custody.MAX_JSON_BYTES, "local attestation sidecar", stage), "local attestation sidecar")
                allowed.append(STAGE + "/" + sidecar)
        # Walk every parent without following a link, including action-created
        # directories; a pathname prefix is never sufficient proof of custody.
        parent = root
        parts = ACTION_PATH.split("/")
        found = True
        for part in parts[:-1]:
            if part not in os.listdir(parent):
                found = False
                break
            parent = custody.directory_fd(part, parent)
            stack.callback(os.close, parent)
        action_present = found and parts[-1] in os.listdir(parent)
        custody.require(action_present == published, "unexpected presence or absence of PyPI action trampoline")
        if action_present:
            action = custody.parse_json(custody.read_regular(parts[-1], 65536, "pinned PyPI action trampoline", parent), "pinned PyPI action trampoline")
            custody.keys(action, ("name", "description", "inputs", "runs"), "pinned PyPI action")
            custody.exact(action["name"], "🏃", "pinned action name")
            custody.exact(action["description"], ACTION_DESCRIPTION, "pinned action description")
            custody.exact(action["runs"], {"using":"docker", "image":ACTION_IMAGE}, "pinned Docker action identity")
            custody.keys(action["inputs"], ACTION_INPUTS, "pinned action inputs")
            for value in action["inputs"].values():
                custody.keys(value, ("description", "required"), "pinned action input")
                custody.exact(value["required"], False, "pinned action input requirement")
                custody.require(type(value["description"]) is str and 0 < len(value["description"]) < 512, "invalid action input description")
            allowed.append(ACTION_PATH)
    return allowed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "workspace", "state"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--phase", choices=("staged", "readback"), required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--ref", required=True)
    args = parser.parse_args()
    manifest = custody.load_manifest(args.manifest)
    custody.verify_controller(args.sha, args.ref, args.ref.removeprefix("refs/tags/"))
    lane = next(item for item in manifest["artifacts"] if item["lane"] == "python")
    inventory = {item["path"].removeprefix("dist/"):item for item in lane["files"] if item["path"].startswith("dist/")}
    # The caller converts these fixed validated paths to the unchanged source
    # guard's newline allowlist; they can never be shell instructions.
    print(json.dumps({"allowed_paths":validate_stage(args.workspace, args.state, args.phase, args.sha, args.ref, inventory)}, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"Python recovery workspace rejected: {error}", file=sys.stderr)
        raise SystemExit(1) from error
