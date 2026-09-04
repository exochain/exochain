#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

"""Compare the sealed uploader metadata with Cargo's actual publish request.

The oracle is pinned Cargo 1.97.1. It publishes a disposable fixture to an
ephemeral loopback sparse registry, whose HTTP handler captures the framed PUT
body. No request can leave loopback and the process is terminated immediately
after capture, before Cargo's post-upload index polling.
"""

from __future__ import annotations

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tarfile
import tempfile
import threading
from typing import Any


EXPECTED_CARGO_RELEASE = "1.97.1"
EXPECTED_CARGO_COMMIT = "c980f4866141969fab6254a680546a277789d6f0"
CRATE = "sealed-publish-oracle"
VERSION = "0.2.6"
MAX_CAPTURE_BYTES = 12 * 1024 * 1024
REPO_ROOT = Path(__file__).resolve().parents[1]
PUBLISHER_PATH = REPO_ROOT / "tools" / "publish_sealed_crate.py"


def fail(message: str) -> None:
    raise RuntimeError(message)


def load_publisher() -> Any:
    spec = importlib.util.spec_from_file_location("publish_sealed_crate", PUBLISHER_PATH)
    if spec is None or spec.loader is None:
        fail("could not load the sealed crate publisher")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sparse_path(crate: str) -> str:
    lowered = crate.lower()
    if len(lowered) == 1:
        return f"1/{lowered}"
    if len(lowered) == 2:
        return f"2/{lowered}"
    if len(lowered) == 3:
        return f"3/{lowered[0]}/{lowered}"
    return f"{lowered[:2]}/{lowered[2:4]}/{lowered}"


def write_fixture(root: Path, index_url: str) -> None:
    (root / ".cargo").mkdir()
    (root / "src").mkdir()
    (root / ".cargo" / "config.toml").write_text(
        f'[registries.oracle]\nindex = "sparse+{index_url}"\n',
        encoding="utf-8",
    )
    (root / "Cargo.toml").write_text(
        f'''[package]
name = "{CRATE}"
version = "{VERSION}"
edition = "2024"
authors = ["EXOCHAIN <security@exochain.com>"]
description = "Cargo publish protocol parity oracle"
documentation = "https://docs.rs/{CRATE}"
homepage = "https://exochain.com"
readme = "README.md"
license = "Apache-2.0"
repository = "https://github.com/exochain/exochain"
rust-version = "1.85"
publish = true

[dependencies.renamed-normal]
package = "oracle-normal"
version = "1"
registry = "oracle"
features = ["fixture"]
optional = true
default-features = false

[dev-dependencies.oracle-dev]
version = "0.19"
registry = "oracle"

[build-dependencies.oracle-build]
version = "0.3"
registry = "oracle"

[target.'cfg(target_arch = "wasm32")'.dependencies.oracle-target]
version = "3"
registry = "oracle"
''',
        encoding="utf-8",
    )
    (root / "src" / "lib.rs").write_text("pub fn oracle() {}\n", encoding="utf-8")
    (root / "README.md").write_text("# Sealed publish oracle\n", encoding="utf-8")


def index_record(name: str, version: str) -> bytes:
    record = {
        "name": name,
        "vers": version,
        "deps": [],
        "cksum": hashlib.sha256(f"{name}-{version}".encode()).hexdigest(),
        "features": {"fixture": []},
        "yanked": False,
    }
    return json.dumps(record, separators=(",", ":"), sort_keys=True).encode() + b"\n"


def decode_publish_body(body: bytes) -> tuple[dict[str, Any], bytes]:
    if len(body) < 8:
        fail("Cargo oracle body is shorter than the registry framing")
    metadata_length = struct.unpack_from("<I", body, 0)[0]
    metadata_end = 4 + metadata_length
    if metadata_end + 4 > len(body):
        fail("Cargo oracle metadata length exceeds the captured body")
    archive_length = struct.unpack_from("<I", body, metadata_end)[0]
    archive = body[metadata_end + 4 :]
    if len(archive) != archive_length:
        fail("Cargo oracle archive length does not consume the exact captured body")
    metadata = json.loads(body[4:metadata_end])
    if not isinstance(metadata, dict):
        fail("Cargo oracle metadata is not one JSON object")
    return metadata, archive


def sorted_dependencies(metadata: dict[str, Any]) -> dict[str, Any]:
    copied = dict(metadata)
    dependencies = copied.get("deps")
    if not isinstance(dependencies, list):
        fail("publish metadata has no dependency array")
    copied["deps"] = sorted(
        dependencies,
        key=lambda item: (
            item["kind"],
            item.get("target") or "",
            item.get("explicit_name_in_toml") or item["name"],
        ),
    )
    return copied


def python_metadata_from_cargo_archive(publisher: Any, archive: bytes) -> dict[str, Any]:
    selected: dict[str, bytes] = {}
    prefix = f"{CRATE}-{VERSION}/"
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
        for member in package.getmembers():
            if not member.isfile() or not member.name.startswith(prefix):
                continue
            relative = member.name[len(prefix) :]
            if relative not in {"Cargo.toml", "README.md"}:
                continue
            handle = package.extractfile(member)
            if handle is None:
                fail(f"Cargo oracle archive member {relative} is unreadable")
            selected[relative] = handle.read()
    manifest = selected.get("Cargo.toml")
    if manifest is None or selected.get("README.md") is None:
        fail("Cargo oracle archive lacks its normalized manifest or README")
    # The loopback fixture names its target registry so Cargo can resolve all
    # dependencies without contacting crates.io. Cargo normalizes those entries
    # to `registry-index`, but omits the registry from NewCrateDependency because
    # it is also the publish target. Remove only those fixture-local TOML lines
    # before invoking the crates.io-only helper.
    manifest = re.sub(br'^registry(?:-index)? = "[^"\n]+"\n', b"", manifest, flags=re.MULTILINE)
    return publisher.build_publish_metadata(manifest, selected, CRATE, VERSION)


def main() -> int:
    cargo = os.environ.get("CARGO", "cargo")
    version = subprocess.run(
        [cargo, "--version", "--verbose"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout
    release = re.search(r"^release: (.+)$", version, re.MULTILINE)
    commit = re.search(r"^commit-hash: ([0-9a-f]{40})$", version, re.MULTILINE)
    if release is None or release.group(1) != EXPECTED_CARGO_RELEASE:
        fail(f"Cargo oracle requires exact release {EXPECTED_CARGO_RELEASE}")
    if commit is None or commit.group(1) != EXPECTED_CARGO_COMMIT:
        fail("Cargo oracle commit differs from the reviewed Cargo source")

    captured: dict[str, bytes] = {}
    captured_event = threading.Event()
    dependency_records = {
        sparse_path("oracle-normal"): index_record("oracle-normal", "1.2.3"),
        sparse_path("oracle-dev"): index_record("oracle-dev", "0.19.3"),
        sparse_path("oracle-build"): index_record("oracle-build", "0.3.4"),
        sparse_path("oracle-target"): index_record("oracle-target", "3.1.0"),
    }

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def reply(self, status: int, payload: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:  # noqa: N802 - HTTP handler API
            if self.path == "/index/config.json":
                origin = f"http://127.0.0.1:{self.server.server_port}"
                payload = json.dumps(
                    {"dl": f"{origin}/api/v1/crates", "api": origin},
                    separators=(",", ":"),
                ).encode()
                self.reply(200, payload, "application/json")
                return
            prefix = "/index/"
            record = dependency_records.get(self.path.removeprefix(prefix)) \
                if self.path.startswith(prefix) else None
            if record is not None:
                self.reply(200, record, "text/plain")
                return
            self.reply(404, b"", "text/plain")

        def do_PUT(self) -> None:  # noqa: N802 - HTTP handler API
            if self.path != "/api/v1/crates/new":
                self.reply(404, b"", "application/json")
                return
            raw_length = self.headers.get("Content-Length")
            if raw_length is None or not raw_length.isdigit():
                self.reply(411, b"", "application/json")
                return
            length = int(raw_length)
            if length <= 0 or length > MAX_CAPTURE_BYTES:
                self.reply(413, b"", "application/json")
                return
            body = self.rfile.read(length)
            if len(body) != length:
                self.reply(400, b"", "application/json")
                return
            captured["body"] = body
            self.reply(200, b"{}", "application/json")
            captured_event.set()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="sealed-cargo-oracle-") as temp:
            root = Path(temp)
            index_url = f"http://127.0.0.1:{server.server_port}/index/"
            write_fixture(root, index_url)
            environment = {
                "CARGO_HOME": str(root / "cargo-home"),
                "CARGO_REGISTRIES_ORACLE_TOKEN": "loopback-oracle-token",
                "HOME": str(root),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": os.environ.get("PATH", ""),
                "RUSTUP_HOME": os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup")),
                "TZ": "UTC",
            }
            if "RUSTUP_TOOLCHAIN" in os.environ:
                environment["RUSTUP_TOOLCHAIN"] = os.environ["RUSTUP_TOOLCHAIN"]
            process = subprocess.Popen(
                [
                    cargo,
                    "publish",
                    "--manifest-path",
                    str(root / "Cargo.toml"),
                    "--registry",
                    "oracle",
                    "--allow-dirty",
                    "--no-verify",
                ],
                cwd=root,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            if not captured_event.wait(15):
                output, _ = process.communicate(timeout=5)
                fail(f"Cargo oracle did not issue a publish PUT: {output[-2000:]}")
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)

    cargo_metadata, archive = decode_publish_body(captured["body"])
    python_metadata = python_metadata_from_cargo_archive(load_publisher(), archive)
    if sorted_dependencies(cargo_metadata) != sorted_dependencies(python_metadata):
        fail(
            "sealed uploader metadata differs from Cargo 1.97.1:\n"
            + json.dumps(
                {"cargo": sorted_dependencies(cargo_metadata), "uploader": python_metadata},
                indent=2,
                sort_keys=True,
            )
        )
    print("sealed crate metadata matches Cargo 1.97.1 publish protocol")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
