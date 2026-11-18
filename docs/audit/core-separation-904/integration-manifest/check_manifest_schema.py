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
"""Check the draft integration manifest schema against its example and cases.

Usage:
    python -I check_manifest_schema.py [manifest.json ...]

With no argument it checks, and exits non-zero on any failure:

  1. the schema is itself a valid JSON Schema (draft 2020-12);
  2. the example manifest validates;
  3. each case below, made by changing the example, is accepted or
     rejected as stated, and every error of a rejection lies under the
     schema path the case names. Where a case notes that two rules
     reject it, the path named covers both.

An accepted case shows only that the shape is allowed. It does not show
that such an integration would meet the level it records.

With arguments it validates each named manifest and prints every error.

It needs the third-party `jsonschema` package. It checks the shape of a
manifest. It cannot check that a statement in a manifest is true.
"""

import copy
import json
import os
import sys

import jsonschema

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as handle:
        return json.load(handle)


def put(doc, path, value):
    for key in path[:-1]:
        doc = doc[key]
    doc[path[-1]] = value


def drop(doc, path):
    for key in path[:-1]:
        doc = doc[key]
    del doc[path[-1]]


def claims(allowed, target, achieved, result):
    return {"allowed": allowed, "target_level": target, "achieved_level": achieved,
            "result_file": result}


def verify_only(doc):
    """Make the example a coherent verify-only integration."""
    doc["interfaces"] = [doc["interfaces"][1]]
    doc["actions"] = []
    doc["core_access"]["core_state"] = {"read": False, "write": False}
    doc["credentials_model"] = "No credential. Trust anchors come from the core's operator."
    doc["secrets"] = {"inventory": [], "source": "None needed.", "holds": []}


def mcp_only(doc):
    """Make the example an integration that reaches the core only through MCP."""
    doc["interfaces"] = [MCP]
    doc["actions"][0]["core_decision"] = MCP["tools"][0]
    doc["trust_claims"] = claims(True, 2, 2, RESULT)


def library_only(doc):
    doc["interfaces"] = [LIBRARY]
    doc["actions"] = []


def add_embedded(doc, target=None, achieved=None, allowed=False):
    doc["interfaces"].append(EMBEDDED)
    doc["trust_claims"] = claims(allowed, target, achieved, None)


RESULT = "conformance/result.json"
EMBEDDED = {"profile": "embedded", "package": "exochain-sdk", "source": "registry", "version": "0.4.0"}
LIBRARY = {"profile": "library", "package": "exochain-avc", "source": "registry", "version": "0.4.0"}
GIT_LIBRARY = {"profile": "library", "package": "exochain-avc", "source": "git", "revision": "86e9a029"}
PROBE = {"name": "probe", "entry_point": "health check", "core_decision": "GET /health",
         "gating": "no_decision", "effect": "Reopens the connection."}
POST_PROBE = dict(PROBE, core_decision="POST /api/v1/dag-db/writeback")
SHARED = {"description": "The node's shared admin token", "issued_to_self": False}
L1 = "allOf/3/then/properties/"
MCP = {"profile": "mcp", "protocol_version": "2024-11-05",
       "tools": ["exochain_verify_authority_chain"]}
IF = "properties/interfaces/items/oneOf/"
TC = "properties/trust_claims/"

# (description, change applied to a copy of the example)
VALID = [
    ("no level sought", lambda d: put(d, ["trust_claims"], claims(False, None, None, None))),
    ("level 0 reached, no result file", lambda d: put(d, ["trust_claims"], claims(False, 2, 0, None))),
    ("level 0 reached with a result file",
     lambda d: put(d, ["trust_claims"], claims(False, 0, 0, RESULT))),
    ("level 1 reached with a result file",
     lambda d: put(d, ["trust_claims"], claims(False, 2, 1, RESULT))),
    ("level 2 reached, claim allowed", lambda d: put(d, ["trust_claims"], claims(True, 2, 2, RESULT))),
    ("level 2 reached, claim not made",
     lambda d: put(d, ["trust_claims"], claims(False, 3, 2, RESULT))),
    # Shape only: the schema cannot tell whether the listed route yields a receipt.
    ("level 3 recorded with http and verify interfaces (shape only)",
     lambda d: put(d, ["trust_claims"], claims(True, 3, 3, RESULT))),
    ("mcp interface", lambda d: d["interfaces"].append(MCP)),
    ("verify-only integration with no actions", verify_only),
    ("embedded interface, no level", add_embedded),
    ("release with build metadata", lambda d: put(d, ["core", "release"], "0.4.0+build.7")),
    ("release with a pre-release tag", lambda d: put(d, ["core", "release"], "0.4.0-rc.1")),
    ("a HEAD route", lambda d: put(d, ["interfaces", 0, "routes"], ["HEAD /health"])),
    ("a team handle as maintainer",
     lambda d: put(d, ["integration", "accountable_maintainer"], "@example-org/platform-team")),
    ("a secret name of 128 characters", lambda d: put(d, ["secrets", "inventory"], ["A" * 128])),
    ("library interface at level 2",
     lambda d: (d["interfaces"].append(LIBRARY), put(d, ["trust_claims"], claims(True, 2, 2, RESULT)))),
    ("git-sourced library with no level reached", lambda d: d["interfaces"].append(GIT_LIBRARY)),
    ("core named by commit only", lambda d: put(d, ["core"], {"revision": "86e9a029"})),
    ("no threat model yet, no level reached", lambda d: put(d, ["threat_model"], None)),
    ("a shared credential held, no level reached", lambda d: d["secrets"]["holds"].append(SHARED)),
    ("an ungated action, no level reached", lambda d: put(d, ["actions", 0, "gating"], "not_gated")),
    ("a no-decision action beside a gated one at level 2",
     lambda d: (d["actions"].append(PROBE), put(d, ["trust_claims"], claims(True, 2, 2, RESULT)))),
    ("http interface with a host", lambda d: put(d, ["interfaces", 0, "host"], "node")),
    ("mcp-only integration at level 2", mcp_only),
    ("library beside http at level 1",
     lambda d: (d["interfaces"].append(LIBRARY), put(d, ["trust_claims"], claims(False, 1, 1, RESULT)))),
    ("manifest version written 1.0", lambda d: put(d, ["manifest_version"], 1.0)),
    ("core named by release and commit", lambda d: put(d, ["core", "revision"], "86e9a029")),
    ("a 40-digit commit", lambda d: put(d, ["core"], {"revision": "a" * 40})),
]

# (description, change, text that every error's schema path must contain)
INVALID = [
    ("claim allowed with no level reached",
     lambda d: put(d, ["trust_claims"], claims(True, 2, None, RESULT)),
     TC + "allOf/0/then/properties/achieved_level"),
    ("claim allowed at level 1", lambda d: put(d, ["trust_claims"], claims(True, 2, 1, RESULT)),
     TC + "allOf/0/then/properties/achieved_level"),
    ("level 1 reached without a result file",
     lambda d: put(d, ["trust_claims"], claims(False, 2, 1, None)),
     TC + "allOf/1/then/properties/result_file"),
    ("level 1 reached with an empty result file",
     lambda d: put(d, ["trust_claims"], claims(False, 2, 1, "")), TC + "properties/result_file"),
    ("a level reached with no target", lambda d: put(d, ["trust_claims"], claims(False, None, 0, None)),
     TC + "allOf/2/then"),
    ("level 1 reached with target 0", lambda d: put(d, ["trust_claims"], claims(False, 0, 1, RESULT)),
     TC + "allOf/3/then"),
    ("level 2 reached with target 1", lambda d: put(d, ["trust_claims"], claims(False, 1, 2, RESULT)),
     TC + "allOf/4/then"),
    ("level 3 reached with target 2", lambda d: put(d, ["trust_claims"], claims(False, 2, 3, RESULT)),
     TC + "allOf/5/then"),
    ("level 2 reached with no actions",
     lambda d: (put(d, ["actions"], []), put(d, ["trust_claims"], claims(False, 2, 2, RESULT))),
     "allOf/0/then/properties/actions/contains"),
    ("level 2 reached with an ungated action",
     lambda d: (d["actions"].append(dict(PROBE, gating="not_gated")),
                put(d, ["trust_claims"], claims(False, 2, 2, RESULT))),
     "allOf/0/then/properties/actions/not"),
    ("level 2 reached with only a no-decision action",
     lambda d: (put(d, ["actions"], [PROBE]), put(d, ["trust_claims"], claims(False, 2, 2, RESULT))),
     "allOf/0/then/properties/actions/contains"),
    ("level 1 reached with a git-sourced package",
     lambda d: (d["interfaces"].append(GIT_LIBRARY),
                put(d, ["trust_claims"], claims(False, 2, 1, RESULT))), L1 + "interfaces/not"),
    ("level 1 reached with the core named by commit only",
     lambda d: (put(d, ["core"], {"revision": "86e9a029"}),
                put(d, ["trust_claims"], claims(False, 2, 1, RESULT))), L1 + "core/required"),
    ("level 1 reached with no threat model",
     lambda d: (put(d, ["threat_model"], None),
                put(d, ["trust_claims"], claims(False, 2, 1, RESULT))), L1 + "threat_model"),
    ("level 1 reached while holding a shared credential",
     lambda d: (d["secrets"]["holds"].append(SHARED),
                put(d, ["trust_claims"], claims(False, 2, 1, RESULT))), L1 + "secrets"),
    ("action without a gating answer", lambda d: drop(d, ["actions", 0, "gating"]),
     "properties/actions/items/required"),
    ("unknown gating answer", lambda d: put(d, ["actions", 0, "gating"], "mostly"),
     "properties/gating/enum"),
    ("registry package without a version", lambda d: drop(d, ["interfaces", 1, "version"]),
     IF + "2/allOf/0/then/required"),
    ("git package without a commit",
     lambda d: d["interfaces"].append({"profile": "library", "package": "x", "source": "git"}),
     IF + "2/allOf/1/then/required"),
    ("package without a source", lambda d: drop(d, ["interfaces", 1, "source"]),
     IF + "2/required"),
    ("unknown http host", lambda d: put(d, ["interfaces", 0, "host"], "edge"),
     IF + "0/properties/host/enum"),
    ("core with neither release nor commit", lambda d: put(d, ["core"], {}), "properties/core/anyOf"),
    ("core commit that is not hex", lambda d: put(d, ["core"], {"revision": "main"}),
     "properties/revision"),
    ("a held credential given as plain text", lambda d: put(d, ["secrets", "holds"], ["a key"]),
     "holds/items"),
    ("level 2 reached with only a verify interface",
     lambda d: (put(d, ["interfaces"], [d["interfaces"][1]]),
                put(d, ["trust_claims"], claims(False, 2, 2, RESULT))),
     "allOf/0/then/properties/interfaces/contains"),
    ("level 3 reached without a verify interface",
     lambda d: (put(d, ["interfaces"], [d["interfaces"][0]]),
                put(d, ["trust_claims"], claims(False, 3, 3, RESULT))),
     "allOf/1/then/properties/interfaces/contains"),
    ("embedded interface with level 0 sought and recorded", lambda d: add_embedded(d, 0, 0),
     "allOf/2/then/" + TC + "properties/"),
    ("embedded interface with a level sought", lambda d: add_embedded(d, 1, None),
     "allOf/2/then/" + TC + "properties/target_level"),
    # Two rules reject this one: the embedded rule, and "a claim needs level 2 or 3".
    ("embedded interface with a claim allowed", lambda d: add_embedded(d, None, None, True),
     "properties/trust_claims"),
    ("an access category left out", lambda d: drop(d, ["core_access", "consent_records"]),
     "properties/core_access/required"),
    ("an access category with no write answer",
     lambda d: drop(d, ["core_access", "signatures", "write"]),
     "properties/core_access/properties/signatures/required"),
    ("an access answer that is not true or false",
     lambda d: put(d, ["core_access", "signatures", "read"], "no"), "properties/read/type"),
    ("threat model left out", lambda d: drop(d, ["threat_model"]), "required"),
    ("credentials model left out", lambda d: drop(d, ["credentials_model"]), "required"),
    ("disablement empty", lambda d: put(d, ["disablement"], ""), "properties/disablement"),
    ("disablement only spaces", lambda d: put(d, ["disablement"], "   "),
     "properties/disablement"),
    ("trust boundary with a line break", lambda d: put(d, ["trust_boundary"], "one\ntwo"),
     "properties/trust_boundary"),
    ("no interface listed", lambda d: put(d, ["interfaces"], []), "properties/interfaces/minItems"),
    ("the same interface listed twice", lambda d: d["interfaces"].append(d["interfaces"][1]),
     "properties/interfaces/uniqueItems"),
    ("unknown interface profile", lambda d: put(d, ["interfaces", 0, "profile"], "file"),
     IF),
    ("http interface without a contract", lambda d: drop(d, ["interfaces", 0, "contract"]),
     IF + "0/required"),
    ("route without a method",
     lambda d: put(d, ["interfaces", 0, "routes"], ["/api/v1/dag-db/writeback"]),
     IF + "0/properties/routes/items/pattern"),
    ("route with a tab in it",
     lambda d: put(d, ["interfaces", 0, "routes"], ["POST /api/v1/dag-db/write\tback"]),
     IF + "0/properties/routes/items"),
    ("route ending in a line break",
     lambda d: put(d, ["interfaces", 0, "routes"], ["POST /api/v1/dag-db/writeback\n"]),
     IF + "0/properties/routes/items/not"),
    ("the same route listed twice",
     lambda d: put(d, ["interfaces", 0, "routes"], ["POST /a", "POST /a"]),
     IF + "0/properties/routes/uniqueItems"),
    ("mcp interface with no tools", lambda d: d["interfaces"].append(dict(MCP, tools=[])),
     IF + "1/properties/tools/minItems"),
    ("verify interface with a version that is not one",
     lambda d: put(d, ["interfaces", 1, "version"], "latest"),
     IF + "2/properties/version/pattern"),
    ("an email address as maintainer",
     lambda d: put(d, ["integration", "accountable_maintainer"], "someone@example.org"),
     "properties/accountable_maintainer"),
    ("an email address as owner",
     lambda d: put(d, ["integration", "owner"], "Example Org <owner@example.org>"),
     "properties/owner"),
    ("unknown deployment status", lambda d: put(d, ["integration", "deployment_status"], "beta"),
     "properties/deployment_status/enum"),
    ("a secret inventory entry that is not a name",
     lambda d: put(d, ["secrets", "inventory"], ["a value with spaces = 123"]), "inventory/items"),
    ("a secret name ending in a line break",
     lambda d: put(d, ["secrets", "inventory"], ["EXAMPLE_CORE_CREDENTIAL\n"]), "inventory/items"),
    ("a secret name of 129 characters", lambda d: put(d, ["secrets", "inventory"], ["A" * 129]),
     "inventory/items"),
    ("the same secret name twice", lambda d: put(d, ["secrets", "inventory"], ["A", "A"]),
     "inventory/uniqueItems"),
    ("an unknown top-level field", lambda d: put(d, ["certified"], True), "additionalProperties"),
    ("an unknown field inside trust_claims", lambda d: put(d, ["trust_claims", "certified"], True),
     TC + "additionalProperties"),
    ("action without a core decision", lambda d: drop(d, ["actions", 0, "core_decision"]),
     "properties/actions/items/required"),
    ("core release that is not a version", lambda d: put(d, ["core", "release"], "latest"),
     "properties/release"),
    ("core release with a leading zero", lambda d: put(d, ["core", "release"], "00.4.0"),
     "properties/release"),
    ("core release ending in a line break", lambda d: put(d, ["core", "release"], "0.4.0\n"),
     "properties/release"),
    ("manifest version 2", lambda d: put(d, ["manifest_version"], 2), "manifest_version/const"),
    ("manifest version true", lambda d: put(d, ["manifest_version"], True),
     "manifest_version/const"),
    ("achieved level false", lambda d: put(d, ["trust_claims", "achieved_level"], False),
     "properties/achieved_level/enum"),
    ("claim permission given as 1", lambda d: put(d, ["trust_claims", "allowed"], 1),
     "properties/allowed/type"),
    ("a library package with no http or mcp interface", library_only,
     "allOf/4/then/properties/interfaces/contains"),
    ("level 2 reached where the only gated action calls a GET route",
     lambda d: (put(d, ["interfaces", 0, "routes"], ["GET /health"]),
                put(d, ["actions", 0, "core_decision"], "GET /health"),
                put(d, ["trust_claims"], claims(False, 2, 2, RESULT))),
     "allOf/0/then/properties/actions/contains"),
    ("level 2 reached with a no-decision action on a POST route",
     lambda d: (d["actions"].append(POST_PROBE), put(d, ["trust_claims"], claims(False, 2, 2, RESULT))),
     "allOf/0/then/properties/actions/items/then"),
    ("level 1 reached with a path-sourced package",
     lambda d: (d["interfaces"].append(dict(LIBRARY, source="path")),
                put(d, ["trust_claims"], claims(False, 2, 1, RESULT))), L1 + "interfaces/not"),
    ("level 1 reached with a vendored package",
     lambda d: (d["interfaces"].append(dict(LIBRARY, source="vendored")),
                put(d, ["trust_claims"], claims(False, 2, 1, RESULT))), L1 + "interfaces/not"),
    ("secrets named but none described as held", lambda d: put(d, ["secrets", "holds"], []),
     "properties/secrets/allOf/0/then/properties/holds/minItems"),
    ("the same held secret twice", lambda d: d["secrets"]["holds"].append(d["secrets"]["holds"][0]),
     "holds/uniqueItems"),
    ("a held secret with no issued_to_self answer",
     lambda d: drop(d, ["secrets", "holds", 0, "issued_to_self"]), "holds/items/required"),
    ("an issued_to_self answer that is not true or false",
     lambda d: put(d, ["secrets", "holds", 0, "issued_to_self"], "yes"),
     "properties/issued_to_self/type"),
    ("the same mcp tool twice", lambda d: d["interfaces"].append(dict(MCP, tools=["a", "a"])),
     IF + "1/properties/tools/uniqueItems"),
    ("core commit ending in a line break", lambda d: put(d, ["core"], {"revision": "86e9a029\n"}),
     "properties/core/properties/revision/not"),
    ("core commit in capitals", lambda d: put(d, ["core"], {"revision": "86E9A029"}),
     "properties/core/properties/revision/pattern"),
    ("core commit of 6 digits", lambda d: put(d, ["core"], {"revision": "86e9a0"}),
     "properties/core/properties/revision/pattern"),
    ("trust boundary with a line separator", lambda d: put(d, ["trust_boundary"], "one\u2028two"),
     "properties/trust_boundary/not"),
    ("deployment boundary with a C1 control character",
     lambda d: put(d, ["deployment_boundary"], "A\u0080B"), "properties/deployment_boundary/not"),
    ("an unknown field inside an action", lambda d: put(d, ["actions", 0, "claimed"], True),
     "properties/actions/items/additionalProperties"),
    ("an unknown field inside secrets", lambda d: put(d, ["secrets", "values"], []),
     "properties/secrets/additionalProperties"),
]


def branch_errors(error):
    """Errors inside a failed oneOf, from the branch the entry was meant for.

    A failed oneOf reports one error and hides the reason in its context.
    For an interface entry the intended branch is the one whose `profile`
    matched. If no branch can be singled out, every branch's errors are
    returned, or none when the validator gives no context.
    """
    by_branch = {}
    for inner in error.context or []:
        by_branch.setdefault(inner.relative_schema_path[0], []).append(inner)
    meant = [errors for errors in by_branch.values()
             if not any(list(e.relative_schema_path)[-2:-1] == ["profile"] for e in errors)]
    if len(meant) == 1:
        return meant[0]
    return [e for errors in by_branch.values() for e in errors]


def schema_paths(validator, doc):
    paths = []
    for error in validator.iter_errors(doc):
        base = "/".join(str(p) for p in error.absolute_schema_path)
        inner = branch_errors(error) if error.validator == "oneOf" else []
        if inner:
            paths.extend(base + "/" + "/".join(str(p) for p in e.relative_schema_path) for e in inner)
        else:
            paths.append(base)
    return paths


def check_files(validator, names):
    bad = 0
    for name in names:
        try:
            with open(name, encoding="utf-8") as handle:
                doc = json.load(handle)
        except (OSError, json.JSONDecodeError) as error:
            print(name, "cannot be read as JSON:", error)
            bad += 1
            continue
        errors = sorted(validator.iter_errors(doc), key=lambda e: [str(p) for p in e.path])
        print(name, "valid in shape" if not errors else f"{len(errors)} error(s)")
        for error in errors:
            print("  ", "/".join(str(p) for p in error.path) or "(root)", "-", error.message)
        bad += bool(errors)
    return bad


def main():
    schema = load("exochain-integration.schema.json")
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    if len(sys.argv) > 1:
        sys.exit(1 if check_files(validator, sys.argv[1:]) else 0)
    example = load("example.exochain-integration.json")
    failures = []
    if not validator.is_valid(example):
        failures.append("the example manifest does not validate")
    for description, change in VALID:
        doc = copy.deepcopy(example)
        change(doc)
        paths = schema_paths(validator, doc)
        if paths:
            failures.append(f"{description}: expected valid, got {paths}")
    for description, change, where in INVALID:
        doc = copy.deepcopy(example)
        change(doc)
        paths = schema_paths(validator, doc)
        if not paths:
            failures.append(f"{description}: expected invalid")
        elif not all(where in path for path in paths):
            failures.append(f"{description}: rejected, but not only by '{where}': {paths}")
    print("cases", len(VALID) + len(INVALID), "expected valid", len(VALID),
          "expected invalid", len(INVALID))
    for failure in failures:
        print("FAIL", failure)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
