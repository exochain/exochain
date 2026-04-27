"""Tests for HTTP transport error mapping."""

from __future__ import annotations

import httpx
import pytest

from exochain import ExochainClient, TransportError
from exochain.transport.http import HttpTransport


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
