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

cd "$(git rev-parse --show-toplevel)"

python3 - <<'PY'
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path


def fail(message: str) -> None:
    print(f"python SDK CI boundary test failed: {message}", file=sys.stderr)
    raise SystemExit(1)


workflow_path = Path(".github/workflows/ci.yml")
pyproject_path = Path("packages/exochain-py/pyproject.toml")
if not workflow_path.is_file():
    fail(f"{workflow_path} is missing")
if not pyproject_path.is_file():
    fail(f"{pyproject_path} is missing")

workflow = workflow_path.read_text(encoding="utf-8")
pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))


def job_block(name: str) -> str:
    matches = list(re.finditer(rf"^  {re.escape(name)}:\s*$", workflow, re.MULTILINE))
    if not matches:
        fail(f"jobs.{name} is missing")
    if len(matches) != 1:
        fail(f"jobs.{name} must be declared exactly once")
    match = matches[0]
    next_job = re.search(r"^  [A-Za-z0-9_-]+:\s*$", workflow[match.end() :], re.MULTILINE)
    end = len(workflow) if next_job is None else match.end() + next_job.start()
    return workflow[match.start() : end]


python_job = job_block("python-sdk")
hygiene_job = job_block("hygiene")
all_gates_job = job_block("all-gates")

if "continue-on-error:" in python_job or re.search(r"^\s+if:", python_job, re.MULTILINE):
    fail("jobs.python-sdk must run unconditionally and fail closed")

required_python_job_patterns = {
    "an Ubuntu hosted runner": r'^    runs-on:\s+ubuntu-latest\s*$',
    "a pinned checkout action": r'^      - uses:\s+actions/checkout@[0-9a-f]{40}\s*$',
    "a pinned setup-python action": r'^      - uses:\s+actions/setup-python@[0-9a-f]{40}\s*$',
    "the Python SDK development dependencies": (
        r"^        run:\s+python -m pip install --disable-pip-version-check "
        r"-e 'packages/exochain-py\[dev\]'\s*$"
    ),
    "the complete Python SDK test suite": (
        r'^        run:\s+python -m pytest packages/exochain-py/tests\s*$'
    ),
    "Ruff over the complete Python SDK": (
        r'^        run:\s+python -m ruff check packages/exochain-py\s*$'
    ),
    "strict mypy over the Python SDK source": (
        r'^        run:\s+python -m mypy --config-file '
        r'packages/exochain-py/pyproject\.toml packages/exochain-py/exochain\s*$'
    ),
}
for requirement, pattern in required_python_job_patterns.items():
    if re.search(pattern, python_job, re.MULTILINE) is None:
        fail(f"jobs.python-sdk must enforce {requirement}")

version_matches = re.findall(
    r'^          python-version:\s+"([0-9]+\.[0-9]+\.[0-9]+)"\s*$',
    python_job,
    re.MULTILINE,
)
if len(version_matches) != 1:
    fail("jobs.python-sdk must pin a full CPython patch version")
python_version = version_matches[0]
if not python_version.startswith("3.11."):
    fail("jobs.python-sdk must exercise the supported CPython 3.11 minimum")

classifiers = pyproject.get("project", {}).get("classifiers", [])
if "Programming Language :: Python :: 3.11" not in classifiers:
    fail("CPython 3.11 must remain a declared supported Python SDK runtime")

install_command = "python -m pip install --disable-pip-version-check -e 'packages/exochain-py[dev]'"
ordered_markers = [
    "actions/setup-python@",
    install_command,
    "python -m pytest packages/exochain-py/tests",
    "python -m ruff check packages/exochain-py",
    (
        "python -m mypy --config-file packages/exochain-py/pyproject.toml "
        "packages/exochain-py/exochain"
    ),
]
positions = [python_job.find(marker) for marker in ordered_markers]
if any(position < 0 for position in positions):
    fail("jobs.python-sdk must install the dev extra before all test and static checks")
if positions != sorted(positions):
    fail("jobs.python-sdk must set up Python and install dependencies before its checks")

guard_runs = re.findall(
    r"^        run:\s+bash tools/test_python_sdk_ci_boundary\.sh\s*$",
    hygiene_job,
    re.MULTILINE,
)
if len(guard_runs) != 1:
    fail("jobs.hygiene must run this Python SDK CI boundary guard")
needs_match = re.search(
    r"^    needs:\s*$\n(?P<needs>.*?)^    steps:\s*$",
    all_gates_job,
    re.MULTILINE | re.DOTALL,
)
if needs_match is None:
    fail("jobs.all-gates must declare an explicit needs list")
python_needs = re.findall(
    r"^      - python-sdk\s*$",
    needs_match.group("needs"),
    re.MULTILINE,
)
if len(python_needs) != 1:
    fail("jobs.all-gates must require jobs.python-sdk")

print("python SDK CI boundary test passed")
PY
