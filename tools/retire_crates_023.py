#!/usr/bin/env python3
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

"""Retire the fixed EXOCHAIN 0.2.3 crates.io inventory.

The public preflight and the authenticated mutation path deliberately share the
same state machine.  No endpoint, crate, version, token source, or inverse
operation is caller-configurable.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import http.client
import json
import os
import re
import ssl
import sys
from typing import Any, Callable, NoReturn


CRATES = (
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

TARGET_VERSION = "0.2.3"
REPLACEMENT_VERSION = "0.2.7"
CRATES_IO_HOST = "crates.io"
CRATES_IO_PORT = 443
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 64
NETWORK_TIMEOUT_SECONDS = 15
MAX_TOKEN_BYTES = 4096
SHA256 = re.compile(r"[0-9a-f]{64}")


class RetirementError(RuntimeError):
    """Registry state or a security boundary failed closed."""


@dataclass(frozen=True)
class _Version:
    identifier: int
    crate: str
    number: str
    checksum: str
    yanked: bool


def _reject(message: str) -> NoReturn:
    raise RetirementError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _reject("registry JSON contains a duplicate object key")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> NoReturn:
    _reject("registry JSON contains a non-finite number")


def _invalid_float(_value: str) -> NoReturn:
    _reject("registry JSON contains a floating-point number")


def _check_json_depth(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        _reject("registry JSON exceeds the nesting limit")
    if type(value) is dict:
        for child in value.values():
            _check_json_depth(child, depth + 1)
    elif type(value) is list:
        for child in value:
            _check_json_depth(child, depth + 1)


def _parse_json(payload: bytes) -> Any:
    if not payload or len(payload) > MAX_RESPONSE_BYTES:
        _reject("registry response size is outside the accepted range")
    try:
        parsed = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
            parse_float=_invalid_float,
        )
        _check_json_depth(parsed)
        return parsed
    except RetirementError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        _reject("registry response is malformed JSON")


def _valid_token(token: str | None) -> str:
    if not isinstance(token, str) or not token:
        _reject("CARGO_REGISTRY_TOKEN is missing or malformed")
    try:
        encoded = token.encode("ascii")
    except UnicodeEncodeError:
        _reject("CARGO_REGISTRY_TOKEN is missing or malformed")
    if len(encoded) > MAX_TOKEN_BYTES or any(ord(character) < 0x21 or ord(character) > 0x7E for character in token):
        _reject("CARGO_REGISTRY_TOKEN is missing or malformed")
    return token


def _version_path(crate: str, version: str) -> str:
    return f"/api/v1/crates/{crate}/{version}"


def _yank_path(crate: str) -> str:
    return f"/api/v1/crates/{crate}/{TARGET_VERSION}/yank"


def _allowed_request(method: str, path: str, token: str | None) -> str | None:
    if method == "GET" and token is None:
        for crate in CRATES:
            if path in (
                _version_path(crate, TARGET_VERSION),
                _version_path(crate, REPLACEMENT_VERSION),
            ):
                return None
        _reject("public registry request path is outside the fixed inventory")
    if method == "DELETE":
        for crate in CRATES:
            if path == _yank_path(crate):
                return _valid_token(token)
        _reject("registry mutation path is outside the fixed inventory")
    if method == "GET":
        _reject("public registry reads must not carry a credential")
    _reject("registry request method is not permitted")


def request(method: str, path: str, token: str | None = None) -> Any:
    """Perform one bounded request against the fixed crates.io HTTPS origin."""

    authenticated_token = _allowed_request(method, path, token)
    headers = {
        "Accept": "application/json",
        "User-Agent": "exochain-retirement-controller (https://github.com/exochain/exochain)",
    }
    if authenticated_token is not None:
        headers["Authorization"] = authenticated_token

    connection = None
    try:
        connection = http.client.HTTPSConnection(
            CRATES_IO_HOST,
            CRATES_IO_PORT,
            timeout=NETWORK_TIMEOUT_SECONDS,
            context=ssl.create_default_context(),
        )
        connection.request(method, path, body=None, headers=headers)
        response = connection.getresponse()
        content_type = response.getheader("Content-Type")
        if not isinstance(content_type, str) or content_type.split(";", 1)[0].strip().lower() != "application/json":
            _reject("crates.io returned an unexpected content type")
        content_length = response.getheader("Content-Length")
        if content_length is not None:
            if not isinstance(content_length, str) or re.fullmatch(r"(?:0|[1-9][0-9]*)", content_length) is None:
                _reject("crates.io returned a malformed Content-Length")
            if int(content_length) <= 0 or int(content_length) > MAX_RESPONSE_BYTES:
                _reject("crates.io declared a response outside the accepted size")
        payload = response.read(MAX_RESPONSE_BYTES + 1)
        if len(payload) > MAX_RESPONSE_BYTES:
            _reject("crates.io response exceeds the size limit")
        if content_length is not None and len(payload) != int(content_length):
            _reject("crates.io response length does not match Content-Length")
        if response.status != 200:
            _reject(f"crates.io returned unexpected HTTP status {response.status}")
        return _parse_json(payload)
    except RetirementError:
        raise
    except (OSError, ssl.SSLError, http.client.HTTPException):
        _reject("secure crates.io request failed")
    finally:
        if connection is not None:
            try:
                connection.close()
            except (OSError, ssl.SSLError, http.client.HTTPException):
                pass


def _read_version(
    request_fn: Callable[[str, str, str | None], Any],
    crate: str,
    version: str,
) -> _Version:
    path = _version_path(crate, version)
    try:
        payload = request_fn("GET", path, None)
    except Exception:
        _reject(f"public registry read failed for {crate} {version}")
    if type(payload) is not dict or type(payload.get("version")) is not dict:
        _reject(f"registry record is invalid for {crate} {version}")
    record = payload["version"]
    identifier = record.get("id")
    checksum = record.get("checksum")
    yanked = record.get("yanked")
    if type(identifier) is not int or identifier <= 0 or identifier > (1 << 63) - 1:
        _reject(f"registry record has an invalid id for {crate} {version}")
    if record.get("crate") != crate or type(record.get("crate")) is not str:
        _reject(f"registry record has the wrong crate identity for {crate} {version}")
    if record.get("num") != version or type(record.get("num")) is not str:
        _reject(f"registry record has the wrong version identity for {crate} {version}")
    if type(checksum) is not str or SHA256.fullmatch(checksum) is None:
        _reject(f"registry record has an invalid checksum for {crate} {version}")
    if type(yanked) is not bool:
        _reject(f"registry record has an invalid yanked field for {crate} {version}")
    return _Version(identifier, crate, version, checksum, yanked)


def _same_identity(left: _Version, right: _Version) -> bool:
    return (
        left.identifier == right.identifier
        and left.crate == right.crate
        and left.number == right.number
        and left.checksum == right.checksum
    )


def _request_mutation(
    request_fn: Callable[[str, str, str | None], Any],
    crate: str,
    token: str,
) -> Any:
    try:
        return request_fn("DELETE", _yank_path(crate), token)
    except Exception:
        _reject(f"registry yank result is unknown for {crate} {TARGET_VERSION}")


def _emit(emit: Callable[[dict[str, Any]], None], record: dict[str, Any]) -> None:
    try:
        emit(dict(record))
    except Exception:
        _reject("receipt sink failed")


def _failure_receipt(
    mode: str,
    phase: str,
    remaining: list[str],
    error: RetirementError,
) -> dict[str, Any]:
    return {
        "status": "failed",
        "mode": mode,
        "phase": phase,
        "remaining": list(remaining),
        "error": str(error),
    }


def retire(
    apply: bool,
    token: str | None,
    request: Callable[[str, str, str | None], Any],
    emit: Callable[[dict[str, Any]], None],
) -> dict[str, Any]:
    """Preflight, optionally yank, and independently verify the fixed batch."""

    mode = "apply" if apply is True else "preflight"
    phase = "input"
    remaining = list(CRATES)
    try:
        if type(apply) is not bool:
            _reject("apply must be a boolean")
        if not callable(request) or not callable(emit):
            _reject("request and emit must be callable")
        authenticated_token = _valid_token(token) if apply else None

        phase = "preflight"
        snapshots: dict[str, tuple[_Version, _Version]] = {}
        for crate in CRATES:
            target = _read_version(request, crate, TARGET_VERSION)
            replacement = _read_version(request, crate, REPLACEMENT_VERSION)
            if replacement.yanked:
                _reject(f"replacement is yanked for {crate} {REPLACEMENT_VERSION}")
            snapshots[crate] = (target, replacement)

        for crate in CRATES:
            target, replacement = snapshots[crate]
            _emit(
                emit,
                {
                    "status": "preflight_verified",
                    "crate": crate,
                    "target": TARGET_VERSION,
                    "target_id": target.identifier,
                    "target_checksum": target.checksum,
                    "target_yanked": target.yanked,
                    "replacement": REPLACEMENT_VERSION,
                    "replacement_id": replacement.identifier,
                    "replacement_checksum": replacement.checksum,
                },
            )

        if not apply:
            completed = {"status": "completed", "mode": mode, "verified": len(CRATES)}
            _emit(emit, completed)
            return completed

        if authenticated_token is None:
            _reject("CARGO_REGISTRY_TOKEN is missing or malformed")
        phase = "apply"
        for index, crate in enumerate(CRATES):
            expected_target, expected_replacement = snapshots[crate]
            current_target = _read_version(request, crate, TARGET_VERSION)
            current_replacement = _read_version(request, crate, REPLACEMENT_VERSION)
            if not _same_identity(expected_target, current_target):
                _reject(f"target identity changed after preflight for {crate} {TARGET_VERSION}")
            if expected_target.yanked and not current_target.yanked:
                _reject(f"target yanked state regressed after preflight for {crate} {TARGET_VERSION}")
            if not _same_identity(expected_replacement, current_replacement):
                _reject(f"replacement identity changed after preflight for {crate} {REPLACEMENT_VERSION}")
            if current_replacement.yanked:
                _reject(f"replacement became yanked for {crate} {REPLACEMENT_VERSION}")

            transition = "already_yanked"
            if not current_target.yanked:
                response = _request_mutation(request, crate, authenticated_token)
                if type(response) is not dict or response.get("ok") is not True or type(response.get("ok")) is not bool:
                    _reject(f"registry did not confirm yank for {crate} {TARGET_VERSION}")
                phase = "readback"
                readback = _read_version(request, crate, TARGET_VERSION)
                if not _same_identity(current_target, readback) or not readback.yanked:
                    _reject(f"registry readback did not verify yank for {crate} {TARGET_VERSION}")
                transition = "yanked"
                phase = "apply"

            _emit(
                emit,
                {
                    "status": "verified",
                    "crate": crate,
                    "version": TARGET_VERSION,
                    "transition": transition,
                    "id": current_target.identifier,
                    "checksum": current_target.checksum,
                    "yanked": True,
                },
            )
            remaining = list(CRATES[index + 1 :])

        completed = {"status": "completed", "mode": mode, "verified": len(CRATES)}
        _emit(emit, completed)
        return completed
    except RetirementError as error:
        failure = _failure_receipt(mode, phase, remaining, error)
        try:
            _emit(emit, failure)
        except RetirementError:
            _reject("retirement failed and the receipt sink also failed")
        raise


def _emit_json(record: dict[str, Any]) -> None:
    print(json.dumps(record, sort_keys=True, separators=(",", ":")), flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--inventory", action="store_true", help="print the fixed crate inventory")
    selection.add_argument("--apply", action="store_true", help="apply and verify the fixed retirement")
    args = parser.parse_args()

    environment_token = os.environ.pop("CARGO_REGISTRY_TOKEN", None)
    if args.inventory:
        for crate in CRATES:
            print(crate)
        return 0
    try:
        retire(args.apply, environment_token if args.apply else None, request, _emit_json)
    except RetirementError as error:
        print(f"retirement failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
