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

import httpx
import pytest

from exochain import ExochainClient, TransportError
from exochain.transport.http import HttpTransport


class _FalseyPathSegment(str):
    def __bool__(self) -> bool:
        return False


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
