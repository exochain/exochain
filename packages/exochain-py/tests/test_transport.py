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

"""Tests for HTTP transport error mapping."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest

from exochain import ExochainClient, TransportError
from exochain.transport.http import HttpTransport


class _FalseyPathSegment(str):
    def __bool__(self) -> bool:
        return False


class _ChunkStream(httpx.AsyncByteStream):
    def __init__(self, *chunks: bytes) -> None:
        self._chunks = chunks
        self.read_count = 0
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            self.read_count += 1
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


class _FalseyLyingBytes(bytes):
    def __buffer__(self, _flags: int) -> memoryview:
        return memoryview(b"")

    def __bool__(self) -> bool:
        return False

    def __bytes__(self) -> bytes:
        return b""

    def __len__(self) -> int:
        return 0


class _HostileLimit(int):
    def __index__(self) -> int:
        raise AssertionError("an int subclass must not control limit accounting")

    def __le__(self, _other: object) -> bool:
        raise AssertionError("an int subclass must not control limit validation")


PATH_SEGMENT_VECTORS = [
    ("ordinary-id", "ordinary-id"),
    ("did:exo:alice", "did%3Aexo%3Aalice"),
    ("segment/child", "segment%2Fchild"),
    (".", "%2E"),
    ("..", "%2E%2E"),
    ("segment?admin=true", "segment%3Fadmin%3Dtrue"),
    ("segment#fragment", "segment%23fragment"),
    ("already%2Fencoded", "already%252Fencoded"),
    ("雪/盾", "%E9%9B%AA%2F%E7%9B%BE"),
    (_FalseyPathSegment("../admin?role=root"), "..%2Fadmin%3Frole%3Droot"),
]


def _json_object_with_size(size: int) -> bytes:
    prefix = b'{"value":"'
    suffix = b'"}'
    assert size >= len(prefix) + len(suffix)
    return prefix + (b"x" * (size - len(prefix) - len(suffix))) + suffix


async def _install_mock_client(
    transport: HttpTransport,
    backend: httpx.AsyncBaseTransport,
    *,
    timeout: httpx.Timeout | float = 1.0,
) -> None:
    await transport._client.aclose()
    transport._client = httpx.AsyncClient(
        base_url="https://fabric.example",
        transport=backend,
        timeout=timeout,
    )


@pytest.mark.parametrize(
    "invalid_limit",
    [0, -1, True, False, 1.5, "64", _HostileLimit(64)],
)
def test_http_transport_rejects_non_positive_or_non_builtin_limits(
    invalid_limit: object,
) -> None:
    """Only positive built-in integers may control response allocation."""
    with pytest.raises(ValueError) as exc_info:
        HttpTransport(  # type: ignore[arg-type]
            "https://fabric.example",
            max_response_bytes=invalid_limit,
        )

    assert str(exc_info.value) == "max_response_bytes must be a positive built-in int"


@pytest.mark.asyncio
async def test_http_transport_default_response_limit_is_finite_and_preflighted() -> None:
    """The default rejects a declared body above one MiB before reading it."""
    stream = _ChunkStream(b"{}")

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Length": str((1024 * 1024) + 1)},
            stream=stream,
        )

    transport = HttpTransport("https://fabric.example")
    await _install_mock_client(transport, httpx.MockTransport(handler))

    with pytest.raises(TransportError) as exc_info:
        await transport.get("/health")

    assert str(exc_info.value) == "response body exceeds configured maximum of 1048576 bytes"
    assert exc_info.value.status == 200
    assert exc_info.value.body is None
    assert stream.read_count == 0
    assert stream.closed

    await transport.close()


@pytest.mark.asyncio
async def test_http_transport_accepts_chunked_json_at_exact_configured_limit() -> None:
    """A no-Content-Length response at the exact byte limit remains valid."""
    max_response_bytes = 64
    payload = _json_object_with_size(max_response_bytes)
    stream = _ChunkStream(payload[:17], payload[17:43], payload[43:])

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=stream)

    transport = HttpTransport(
        "https://fabric.example",
        max_response_bytes=max_response_bytes,
    )
    await _install_mock_client(transport, httpx.MockTransport(handler))

    result = await transport.get("/health")

    assert result == {"value": "x" * (max_response_bytes - 12)}
    assert stream.read_count == 3
    assert stream.closed

    await transport.close()


@pytest.mark.asyncio
async def test_http_transport_rejects_declared_success_body_at_limit_plus_one() -> None:
    """An accurate over-limit Content-Length fails without reading the stream."""
    max_response_bytes = 64
    payload = _json_object_with_size(max_response_bytes + 1)
    stream = _ChunkStream(payload)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Length": str(len(payload))},
            stream=stream,
        )

    transport = HttpTransport(
        "https://fabric.example",
        max_response_bytes=max_response_bytes,
    )
    await _install_mock_client(transport, httpx.MockTransport(handler))

    with pytest.raises(TransportError) as exc_info:
        await transport.get("/health")

    assert str(exc_info.value) == "response body exceeds configured maximum of 64 bytes"
    assert exc_info.value.status == 200
    assert exc_info.value.body is None
    assert stream.read_count == 0
    assert stream.closed

    await transport.close()


@pytest.mark.asyncio
async def test_http_transport_stream_limit_ignores_dishonestly_small_content_length() -> None:
    """The streamed byte count remains authoritative when metadata understates it."""
    max_response_bytes = 64
    payload = _json_object_with_size(max_response_bytes + 1)
    stream = _ChunkStream(payload[:32], payload[32:])

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Length": "1"},
            stream=stream,
        )

    transport = HttpTransport(
        "https://fabric.example",
        max_response_bytes=max_response_bytes,
    )
    await _install_mock_client(transport, httpx.MockTransport(handler))

    with pytest.raises(TransportError) as exc_info:
        await transport.get("/health")

    assert str(exc_info.value) == "response body exceeds configured maximum of 64 bytes"
    assert exc_info.value.status == 200
    assert exc_info.value.body is None
    assert stream.read_count == 2
    assert stream.closed

    await transport.close()


@pytest.mark.asyncio
async def test_http_transport_stops_chunked_error_body_at_limit_plus_one() -> None:
    """Oversized HTTP-error content is neither fully consumed nor reflected."""
    stream = _ChunkStream(b"x" * 32, b"y" * 33, b"attacker-controlled-trailer")

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, stream=stream)

    transport = HttpTransport("https://fabric.example", max_response_bytes=64)
    await _install_mock_client(transport, httpx.MockTransport(handler))

    with pytest.raises(TransportError) as exc_info:
        await transport.post("/kernel/actions", {"action": "test"})

    assert str(exc_info.value) == "response body exceeds configured maximum of 64 bytes"
    assert exc_info.value.status == 503
    assert exc_info.value.body is None
    assert stream.read_count == 2
    assert stream.closed

    await transport.close()


@pytest.mark.asyncio
async def test_http_transport_preserves_error_body_at_exact_configured_limit() -> None:
    """A bounded error body remains available at the exact byte boundary."""
    payload = b"e" * 64
    stream = _ChunkStream(payload[:31], payload[31:])

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, stream=stream)

    transport = HttpTransport("https://fabric.example", max_response_bytes=64)
    await _install_mock_client(transport, httpx.MockTransport(handler))

    with pytest.raises(TransportError) as exc_info:
        await transport.get("/governance/decisions")

    assert exc_info.value.status == 429
    assert exc_info.value.body == payload.decode("ascii")
    assert stream.read_count == 2
    assert stream.closed

    await transport.close()


@pytest.mark.asyncio
async def test_http_transport_builtin_accounting_defeats_falsey_bytes_subclass() -> None:
    """A stream chunk cannot overload truth or length to bypass the byte limit."""
    stream = _ChunkStream(_FalseyLyingBytes(b"x" * 65))

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=stream)

    transport = HttpTransport("https://fabric.example", max_response_bytes=64)
    await _install_mock_client(transport, httpx.MockTransport(handler))

    with pytest.raises(TransportError) as exc_info:
        await transport.get("/health")

    assert str(exc_info.value) == "response body exceeds configured maximum of 64 bytes"
    assert exc_info.value.status == 200
    assert exc_info.value.body is None
    assert stream.closed

    await transport.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("content_length", [b"+65", b"64x", b"1, 65", b"\xff"])
async def test_http_transport_rejects_malformed_content_length_stably(
    content_length: bytes,
) -> None:
    """Malformed length metadata cannot reach integer parsing or body reads."""
    stream = _ChunkStream(b"{}")

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers=[(b"Content-Length", content_length)],
            stream=stream,
        )

    transport = HttpTransport("https://fabric.example", max_response_bytes=64)
    await _install_mock_client(transport, httpx.MockTransport(handler))

    with pytest.raises(TransportError) as exc_info:
        await transport.get("/health")

    assert str(exc_info.value) == "response Content-Length is malformed"
    assert exc_info.value.status == 200
    assert exc_info.value.body is None
    assert stream.read_count == 0
    assert stream.closed

    await transport.close()


@pytest.mark.asyncio
async def test_http_transport_rejects_encoded_response_before_decompression() -> None:
    """A server cannot turn a small compressed stream into an oversized JSON allocation."""
    stream = _ChunkStream(b"compressed-attacker-content")

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Encoding": "gzip"},
            stream=stream,
        )

    transport = HttpTransport("https://fabric.example", max_response_bytes=64)
    await _install_mock_client(transport, httpx.MockTransport(handler))

    with pytest.raises(TransportError) as exc_info:
        await transport.get("/health")

    assert str(exc_info.value) == "response Content-Encoding must be identity"
    assert exc_info.value.status == 200
    assert exc_info.value.body is None
    assert stream.read_count == 0
    assert stream.closed

    await transport.close()


@pytest.mark.asyncio
async def test_streaming_transport_preserves_configured_phase_timeouts() -> None:
    """Switching to streamed sends retains all four configured timeout phases."""
    configured = httpx.Timeout(connect=1.0, read=2.0, write=3.0, pool=4.0)
    observed: dict[str, float] | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal observed
        observed = request.extensions.get("timeout")
        assert request.headers["Accept-Encoding"] == "identity"
        return httpx.Response(200, json={})

    transport = HttpTransport(
        "https://fabric.example",
        timeout=configured,
        max_response_bytes=64,
    )
    original_backend = transport._client._transport
    await original_backend.aclose()
    transport._client._transport = httpx.MockTransport(handler)

    assert await transport.get("/health") == {}
    assert observed == {"connect": 1.0, "read": 2.0, "write": 3.0, "pool": 4.0}

    await transport.close()


@pytest.mark.asyncio
async def test_http_transport_preserves_status_and_body() -> None:
    """HTTP status failures carry structured status and body fields."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/kernel/actions"
        return httpx.Response(503, text="maintenance")

    transport = HttpTransport(
        "https://fabric.example",
        timeout=httpx.Timeout(1.0),
    )
    await transport._client.aclose()
    transport._client = httpx.AsyncClient(
        base_url="https://fabric.example",
        transport=httpx.MockTransport(handler),
        timeout=httpx.Timeout(1.0),
    )

    with pytest.raises(TransportError) as exc_info:
        await transport.post("/kernel/actions", {"action": "test"})

    assert exc_info.value.status == 503
    assert exc_info.value.body == "maintenance"

    await transport.close()


@pytest.mark.asyncio
async def test_http_transport_preserves_bounded_error_body_charset() -> None:
    """Bounded error reflection retains httpx's declared-charset semantics."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            content=b"\xe9",
            headers={"Content-Type": "text/plain; charset=iso-8859-1"},
        )

    transport = HttpTransport("https://fabric.example", max_response_bytes=64)
    await _install_mock_client(transport, httpx.MockTransport(handler))

    with pytest.raises(TransportError) as exc_info:
        await transport.get("/identity/missing")

    assert exc_info.value.status == 400
    assert exc_info.value.body == "é"

    await transport.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("charset", "payload", "expected_body"),
    [
        ("zlib", b"bounded-error", "bounded-error"),
        ("idna", b"\xff", "�"),
    ],
)
async def test_http_transport_falls_back_for_non_text_error_body_codec(
    charset: str,
    payload: bytes,
    expected_body: str,
) -> None:
    """A recognized but unsuitable codec cannot escape typed error mapping."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            content=payload,
            headers={"Content-Type": f"text/plain; charset={charset}"},
        )

    transport = HttpTransport("https://fabric.example", max_response_bytes=64)
    await _install_mock_client(transport, httpx.MockTransport(handler))

    with pytest.raises(TransportError) as exc_info:
        await transport.get("/identity/missing")

    assert exc_info.value.status == 400
    assert exc_info.value.body == expected_body

    await transport.close()


@pytest.mark.asyncio
async def test_client_accepts_configured_httpx_timeout() -> None:
    """The high-level client accepts per-phase httpx timeout configuration."""
    client = ExochainClient(
        "https://fabric.example",
        timeout=httpx.Timeout(connect=1.0, read=2.0, write=3.0, pool=4.0),
    )
    assert isinstance(client.transport, HttpTransport)
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(("did", "encoded"), PATH_SEGMENT_VECTORS)
async def test_resolve_did_percent_encodes_identifier_as_one_path_segment(
    did: str, encoded: str
) -> None:
    """DID-controlled delimiters cannot escape the identity route segment."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.raw_path == f"/identity/{encoded}".encode("ascii")
        return httpx.Response(200, json={})

    transport = HttpTransport("https://fabric.example", timeout=httpx.Timeout(1.0))
    await transport._client.aclose()
    transport._client = httpx.AsyncClient(
        base_url="https://fabric.example",
        transport=httpx.MockTransport(handler),
        timeout=httpx.Timeout(1.0),
    )
    client = ExochainClient.from_transport(transport)

    await client.resolve_did(did)

    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(("decision_id", "encoded"), PATH_SEGMENT_VECTORS)
async def test_cast_vote_percent_encodes_identifier_as_one_path_segment(
    decision_id: str, encoded: str
) -> None:
    """Decision-controlled delimiters cannot escape the governance route segment."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.raw_path == (f"/governance/decisions/{encoded}/votes".encode("ascii"))
        return httpx.Response(200, json={})

    transport = HttpTransport("https://fabric.example", timeout=httpx.Timeout(1.0))
    await transport._client.aclose()
    transport._client = httpx.AsyncClient(
        base_url="https://fabric.example",
        transport=httpx.MockTransport(handler),
        timeout=httpx.Timeout(1.0),
    )
    client = ExochainClient.from_transport(transport)

    await client.cast_vote(decision_id, {"choice": "approve"})

    await client.close()


@pytest.mark.asyncio
async def test_client_discover_validates_public_discovery_document() -> None:
    """The high-level client validates the well-known discovery payload."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/.well-known/exochain.json"
        return httpx.Response(
            200,
            json={
                "base_url": "https://exochain.io",
                "routes": {
                    "health": "/health",
                    "ready": "/ready",
                    "avc": {
                        "issue": "/api/v1/avc/issue",
                        "validate": "/api/v1/avc/validate",
                        "receipts_emit": "/api/v1/avc/receipts/emit",
                        "receipts_get": "/api/v1/avc/receipts/:hash",
                        "protocol": "/api/v1/avc/protocol",
                    },
                },
                "sdk": {
                    "rust": "crates/exochain-sdk",
                    "typescript": "packages/exochain-sdk",
                    "python": "packages/exochain-py",
                },
                "mcp": {
                    "public_transport": False,
                    "transports": ["stdio", "loopback-sse"],
                    "capabilities": ["tools", "resources", "prompts"],
                },
            },
        )

    transport = HttpTransport("https://fabric.example", timeout=httpx.Timeout(1.0))
    await transport._client.aclose()
    transport._client = httpx.AsyncClient(
        base_url="https://fabric.example",
        transport=httpx.MockTransport(handler),
        timeout=httpx.Timeout(1.0),
    )
    client = ExochainClient.from_transport(transport)

    discovery = await client.discover()

    assert discovery.base_url == "https://exochain.io"
    assert discovery.routes.avc.validate_route == "/api/v1/avc/validate"
    assert discovery.routes.avc.receipts_emit == "/api/v1/avc/receipts/emit"
    assert discovery.sdk.python == "packages/exochain-py"
    assert discovery.mcp.public_transport is False
    assert discovery.mcp.transports == ("stdio", "loopback-sse")
    assert discovery.mcp.capabilities == ("tools", "resources", "prompts")

    await client.close()


@pytest.mark.asyncio
async def test_client_discover_rejects_malformed_mcp_metadata() -> None:
    """Malformed MCP discovery metadata fails closed."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "base_url": "https://exochain.io",
                "routes": {
                    "health": "/health",
                    "ready": "/ready",
                    "avc": {
                        "issue": "/api/v1/avc/issue",
                        "validate": "/api/v1/avc/validate",
                        "receipts_emit": "/api/v1/avc/receipts/emit",
                        "receipts_get": "/api/v1/avc/receipts/:hash",
                        "protocol": "/api/v1/avc/protocol",
                    },
                },
                "sdk": {
                    "rust": "crates/exochain-sdk",
                    "typescript": "packages/exochain-sdk",
                    "python": "packages/exochain-py",
                },
                "mcp": {
                    "public_transport": "false",
                    "transports": ["stdio", "loopback-sse"],
                    "capabilities": ["tools", "resources", "prompts"],
                },
            },
        )

    transport = HttpTransport("https://fabric.example", timeout=httpx.Timeout(1.0))
    await transport._client.aclose()
    transport._client = httpx.AsyncClient(
        base_url="https://fabric.example",
        transport=httpx.MockTransport(handler),
        timeout=httpx.Timeout(1.0),
    )
    client = ExochainClient.from_transport(transport)

    with pytest.raises(TransportError):
        await client.discover()

    await client.close()
