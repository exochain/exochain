#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for the fixed-scope crates.io 0.2.3 retirement helper."""

from __future__ import annotations

import copy
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "tools" / "retire_crates_023.py"
EXPECTED_CRATES = (
    "exochain-core",
    "exochain-dag-db-api",
    "exochain-identity",
    "exochain-api",
    "exochain-authority",
    "exochain-avc",
    "exochain-consent",
    "exochain-dag-db-core",
    "exochain-dag-db-graph",
    "exochain-dag-db-domain",
    "exochain-dag-db-retrieval",
    "exochain-dag-db-exchange",
    "exochain-dag",
    "exochain-dag-db-postgres",
    "exochain-gatekeeper",
    "exochain-proofs",
    "exochain-governance",
    "exochain-escalation",
    "exochain-tenant",
    "exochain-catapult",
    "exochain-legal",
    "exochain-decision-forum",
    "exochain-consensus",
    "exochain-dag-db-lab",
    "exochain-economy",
    "exochain-gateway",
    "exochain-messaging",
    "exochain-root",
    "exochain-sdk",
    "exochain-node",
    "exochain-wasm",
)


def load_helper(test_case: unittest.TestCase):
    if not HELPER_PATH.is_file():
        test_case.fail(f"retirement helper is missing: {HELPER_PATH}")
    specification = importlib.util.spec_from_file_location("retire_crates_023", HELPER_PATH)
    if specification is None or specification.loader is None:
        test_case.fail("could not load retirement helper")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def version_record(crate: str, version: str, *, yanked: bool = False) -> dict:
    offset = EXPECTED_CRATES.index(crate) + (1 if version == "0.2.3" else 101)
    return {
        "version": {
            "id": offset,
            "crate": crate,
            "num": version,
            "checksum": f"{offset:064x}",
            "yanked": yanked,
        }
    }


def complete_state(*, target_yanked: bool = False) -> dict[tuple[str, str], dict]:
    state = {}
    for crate in EXPECTED_CRATES:
        state[(crate, "0.2.3")] = version_record(crate, "0.2.3", yanked=target_yanked)
        state[(crate, "0.2.7")] = version_record(crate, "0.2.7")
    return state


class RegistryTransport:
    """API-shaped in-memory registry; the state machine under test stays real."""

    def __init__(self, state: dict[tuple[str, str], dict]) -> None:
        self.state = copy.deepcopy(state)
        self.operations: list[tuple[str, str, str | None]] = []
        self.read_counts: dict[tuple[str, str], int] = {}
        self.read_overrides: dict[tuple[str, str, int], object] = {}
        self.delete_responses: dict[str, object] = {}

    def __call__(self, method: str, path: str, token: str | None = None):
        self.operations.append((method, path, token))
        parts = path.split("/")
        if method == "GET" and len(parts) == 6 and parts[1:4] == ["api", "v1", "crates"]:
            crate, version = parts[4], parts[5]
            key = (crate, version)
            count = self.read_counts.get(key, 0) + 1
            self.read_counts[key] = count
            override = self.read_overrides.get((crate, version, count))
            if isinstance(override, BaseException):
                raise override
            if override is not None:
                return copy.deepcopy(override)
            if key not in self.state:
                raise RuntimeError("registry returned HTTP 404 with untrusted response body")
            return copy.deepcopy(self.state[key])
        if (
            method == "DELETE"
            and len(parts) == 7
            and parts[1:4] == ["api", "v1", "crates"]
            and parts[5:] == ["0.2.3", "yank"]
        ):
            crate = parts[4]
            response = self.delete_responses.get(crate, {"ok": True})
            if isinstance(response, BaseException):
                raise response
            if response == {"ok": True}:
                self.state[(crate, "0.2.3")]["version"]["yanked"] = True
            return copy.deepcopy(response)
        raise AssertionError(f"unexpected operation: {method} {path}")


class FakeResponse:
    def __init__(
        self,
        body: bytes,
        *,
        status: int = 200,
        content_type: str = "application/json",
        content_length: str | None = None,
    ) -> None:
        self.status = status
        self._body = body
        self._headers = {"content-type": content_type}
        if content_length is not None:
            self._headers["content-length"] = content_length

    def getheader(self, name: str, default=None):
        return self._headers.get(name.lower(), default)

    def read(self, amount: int | None = None) -> bytes:
        if amount is None:
            return self._body
        return self._body[:amount]


class FakeConnection:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.calls: list[tuple[str, str, bytes | None, dict]] = []
        self.closed = False

    def request(self, method: str, path: str, body=None, headers=None) -> None:
        self.calls.append((method, path, body, dict(headers or {})))

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


class FlushTrackingStream(io.StringIO):
    def __init__(self) -> None:
        super().__init__()
        self.flush_count = 0

    def flush(self) -> None:
        self.flush_count += 1
        super().flush()


class RetirementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.helper = load_helper(self)

    def test_inventory_is_the_literal_canonical_set_minus_unpublished_pdp(self) -> None:
        self.assertEqual(self.helper.CRATES, EXPECTED_CRATES)
        completed = subprocess.run(
            [sys.executable, "-B", str(HELPER_PATH), "--inventory"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.splitlines(), list(EXPECTED_CRATES))

    def test_jsonl_receipt_output_flushes_each_record(self) -> None:
        output = FlushTrackingStream()
        with redirect_stdout(output):
            self.helper._emit_json({"status": "verified", "crate": EXPECTED_CRATES[0]})
        self.assertEqual(output.getvalue(), '{"crate":"exochain-core","status":"verified"}\n')
        self.assertGreaterEqual(output.flush_count, 1)

    def test_public_preflight_reads_every_pair_without_sending_a_token(self) -> None:
        transport = RegistryTransport(complete_state())
        receipts: list[dict] = []
        result = self.helper.retire(False, "ignored-secret", transport, receipts.append)
        self.assertEqual(result, {"status": "completed", "mode": "preflight", "verified": 31})
        self.assertEqual(len(transport.operations), 62)
        self.assertTrue(all(method == "GET" and token is None for method, _, token in transport.operations))
        self.assertEqual(receipts[-1], result)

    def test_malformed_target_identity_and_boolean_fields_fail_closed(self) -> None:
        mutations = {
            "wrong crate": ("crate", "substituted-crate"),
            "wrong version": ("num", "0.2.7"),
            "boolean id": ("id", True),
            "nonboolean yanked": ("yanked", 0),
            "invalid checksum": ("checksum", "a" * 63),
        }
        for label, (field, value) in mutations.items():
            with self.subTest(label=label):
                state = complete_state()
                state[(EXPECTED_CRATES[0], "0.2.3")]["version"][field] = value
                transport = RegistryTransport(state)
                receipts: list[dict] = []
                with self.assertRaises(self.helper.RetirementError):
                    self.helper.retire(False, None, transport, receipts.append)
                self.assertEqual([op for op in transport.operations if op[0] == "DELETE"], [])
                self.assertEqual(receipts[-1]["status"], "failed")

    def test_missing_last_replacement_prevents_every_delete(self) -> None:
        state = complete_state()
        del state[(EXPECTED_CRATES[-1], "0.2.7")]
        transport = RegistryTransport(state)
        receipts: list[dict] = []
        with self.assertRaises(self.helper.RetirementError):
            self.helper.retire(True, "valid-token", transport, receipts.append)
        self.assertEqual([op for op in transport.operations if op[0] == "DELETE"], [])
        self.assertEqual(receipts[-1]["remaining"], list(EXPECTED_CRATES))

    def test_replacement_must_be_exact_non_yanked_027(self) -> None:
        for field, value in (("crate", "wrong"), ("num", "0.2.3"), ("yanked", True)):
            with self.subTest(field=field):
                state = complete_state()
                state[(EXPECTED_CRATES[4], "0.2.7")]["version"][field] = value
                transport = RegistryTransport(state)
                with self.assertRaises(self.helper.RetirementError):
                    self.helper.retire(True, "valid-token", transport, lambda _record: None)
                self.assertFalse(any(op[0] == "DELETE" for op in transport.operations))

    def test_already_yanked_targets_are_verified_without_delete(self) -> None:
        transport = RegistryTransport(complete_state(target_yanked=True))
        receipts: list[dict] = []
        result = self.helper.retire(True, "valid-token", transport, receipts.append)
        self.assertEqual(result, {"status": "completed", "mode": "apply", "verified": 31})
        self.assertFalse(any(op[0] == "DELETE" for op in transport.operations))
        transitions = [record for record in receipts if record.get("status") == "verified"]
        self.assertEqual(len(transitions), 31)
        self.assertTrue(all(record["transition"] == "already_yanked" for record in transitions))

    def test_target_id_or_checksum_change_between_preflight_and_recheck_stops(self) -> None:
        for field, value in (("id", 999999), ("checksum", "f" * 64)):
            with self.subTest(field=field):
                transport = RegistryTransport(complete_state())
                changed = version_record(EXPECTED_CRATES[0], "0.2.3")
                changed["version"][field] = value
                transport.read_overrides[(EXPECTED_CRATES[0], "0.2.3", 2)] = changed
                with self.assertRaises(self.helper.RetirementError):
                    self.helper.retire(True, "valid-token", transport, lambda _record: None)
                self.assertFalse(any(op[0] == "DELETE" for op in transport.operations))

    def test_non_true_yank_response_stops_without_retry(self) -> None:
        transport = RegistryTransport(complete_state())
        transport.delete_responses[EXPECTED_CRATES[0]] = {"ok": False}
        receipts: list[dict] = []
        with self.assertRaises(self.helper.RetirementError):
            self.helper.retire(True, "valid-token", transport, receipts.append)
        deletes = [op for op in transport.operations if op[0] == "DELETE"]
        self.assertEqual(deletes, [("DELETE", f"/api/v1/crates/{EXPECTED_CRATES[0]}/0.2.3/yank", "valid-token")])
        self.assertEqual(receipts[-1]["remaining"], list(EXPECTED_CRATES))

    def test_unknown_mutation_result_is_not_retried_or_read_back(self) -> None:
        transport = RegistryTransport(complete_state())
        transport.delete_responses[EXPECTED_CRATES[0]] = RuntimeError(
            "untrusted body and credential valid-token"
        )
        receipts: list[dict] = []
        with self.assertRaises(self.helper.RetirementError) as raised:
            self.helper.retire(True, "valid-token", transport, receipts.append)
        self.assertEqual(sum(op[0] == "DELETE" for op in transport.operations), 1)
        self.assertEqual(transport.read_counts[(EXPECTED_CRATES[0], "0.2.3")], 2)
        self.assertEqual(
            receipts[-1]["error"],
            "registry yank result is unknown for exochain-core 0.2.3",
        )
        serialized = json.dumps(receipts) + str(raised.exception)
        self.assertNotIn("valid-token", serialized)
        self.assertNotIn("untrusted body", serialized)

    def test_readback_requires_same_identity_checksum_and_positive_yanked(self) -> None:
        mutations = (("crate", "wrong"), ("id", 123456), ("checksum", "e" * 64), ("yanked", False))
        for field, value in mutations:
            with self.subTest(field=field):
                transport = RegistryTransport(complete_state())
                altered = version_record(EXPECTED_CRATES[0], "0.2.3", yanked=True)
                altered["version"][field] = value
                transport.read_overrides[(EXPECTED_CRATES[0], "0.2.3", 3)] = altered
                with self.assertRaises(self.helper.RetirementError):
                    self.helper.retire(True, "valid-token", transport, lambda _record: None)
                self.assertEqual(sum(op[0] == "DELETE" for op in transport.operations), 1)

    def test_partial_failure_preserves_completed_state_and_safe_rerun_resumes(self) -> None:
        transport = RegistryTransport(complete_state())
        failing_crate = EXPECTED_CRATES[2]
        transport.delete_responses[failing_crate] = {"ok": False}
        first_receipts: list[dict] = []
        with self.assertRaises(self.helper.RetirementError):
            self.helper.retire(True, "valid-token", transport, first_receipts.append)
        self.assertTrue(transport.state[(EXPECTED_CRATES[0], "0.2.3")]["version"]["yanked"])
        self.assertTrue(transport.state[(EXPECTED_CRATES[1], "0.2.3")]["version"]["yanked"])
        self.assertFalse(transport.state[(failing_crate, "0.2.3")]["version"]["yanked"])
        self.assertEqual(first_receipts[-1]["remaining"], list(EXPECTED_CRATES[2:]))

        transport.delete_responses.clear()
        prior_deletes = sum(op[0] == "DELETE" for op in transport.operations)
        result = self.helper.retire(True, "valid-token", transport, lambda _record: None)
        later_deletes = [op for op in transport.operations if op[0] == "DELETE"][prior_deletes:]
        self.assertEqual(result["status"], "completed")
        self.assertEqual(
            [op[1].split("/")[4] for op in later_deletes],
            list(EXPECTED_CRATES[2:]),
        )
        self.assertTrue(all(record["version"]["yanked"] for key, record in transport.state.items() if key[1] == "0.2.3"))

    def test_invalid_token_bytes_fail_before_any_registry_read(self) -> None:
        for token in (
            None,
            "",
            "space token",
            "tab\ttoken",
            "line\nbreak",
            "carriage\rreturn",
            "nul\x00byte",
            "control\x1fbyte",
            "unicode-🙂",
        ):
            with self.subTest(token=repr(token)):
                transport = RegistryTransport(complete_state())
                with self.assertRaises(self.helper.RetirementError):
                    self.helper.retire(True, token, transport, lambda _record: None)
                self.assertEqual(transport.operations, [])

    def _request_with(self, response: FakeResponse, method: str = "GET", token=None):
        connection = FakeConnection(response)
        with mock.patch.object(
            self.helper.http.client,
            "HTTPSConnection",
            return_value=connection,
        ):
            result = self.helper.request(
                method,
                f"/api/v1/crates/{EXPECTED_CRATES[0]}/0.2.3"
                + ("/yank" if method == "DELETE" else ""),
                token,
            )
        return result, connection

    def test_network_boundary_uses_public_get_and_exact_authenticated_delete(self) -> None:
        body = json.dumps(version_record(EXPECTED_CRATES[0], "0.2.3")).encode()
        result, public_connection = self._request_with(FakeResponse(body))
        self.assertEqual(result, version_record(EXPECTED_CRATES[0], "0.2.3"))
        self.assertEqual(public_connection.calls[0][0:2], ("GET", f"/api/v1/crates/{EXPECTED_CRATES[0]}/0.2.3"))
        self.assertNotIn("Authorization", public_connection.calls[0][3])
        result, mutation_connection = self._request_with(
            FakeResponse(b'{"ok":true}'), method="DELETE", token="valid-token"
        )
        self.assertEqual(result, {"ok": True})
        self.assertEqual(
            mutation_connection.calls[0][0:2],
            ("DELETE", f"/api/v1/crates/{EXPECTED_CRATES[0]}/0.2.3/yank"),
        )
        self.assertEqual(mutation_connection.calls[0][3]["Authorization"], "valid-token")

    def test_http_redirect_auth_and_server_failures_do_not_leak_body_or_token(self) -> None:
        for status in (302, 401, 403, 500):
            with self.subTest(status=status):
                with self.assertRaises(self.helper.RetirementError) as raised:
                    self._request_with(
                        FakeResponse(b'{"errors":[{"detail":"raw-secret"}]}', status=status),
                        method="DELETE",
                        token="valid-token",
                    )
                message = str(raised.exception)
                self.assertIn(str(status), message)
                self.assertNotIn("raw-secret", message)
                self.assertNotIn("valid-token", message)

    def test_duplicate_keys_excess_depth_and_oversize_json_are_rejected(self) -> None:
        bodies = (
            b'{"version":{"id":1,"id":2}}',
            (b'[' * 70) + b'null' + (b']' * 70),
            b" " * (1024 * 1024 + 1),
        )
        for body in bodies:
            with self.subTest(length=len(body)):
                with self.assertRaises(self.helper.RetirementError):
                    self._request_with(FakeResponse(body))

    def test_malformed_content_metadata_and_non_json_are_rejected(self) -> None:
        cases = (
            FakeResponse(b"{}", content_type="text/html"),
            FakeResponse(b"{}", content_length="+2"),
            FakeResponse(b"{}", content_length=str(1024 * 1024 + 1)),
            FakeResponse(b"{}", content_length="3"),
            FakeResponse(b"not-json"),
            FakeResponse(b'{"value":NaN}'),
            FakeResponse(b'{"value":1e999}'),
        )
        for response in cases:
            with self.subTest(headers=response._headers, body=response._body[:20]):
                with self.assertRaises(self.helper.RetirementError):
                    self._request_with(response)


if __name__ == "__main__":
    unittest.main()
