"""
Integration tests for the FastAPI control plane and HAL-backed modules.

These tests run against the ASGI app directly (no Docker required) and
therefore do not need hardware. They assert routing, accepted payloads,
and happy-path job creation flows for read-only endpoints.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from fastapi import FastAPI

from urban_hs.ui.api.main import app as api_app


@pytest.fixture
def app() -> FastAPI:
    return api_app


@pytest.mark.asyncio
async def test_healthz(app) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/v1/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_system_info(app) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/v1/info")
    assert r.status_code == 200
    body = r.json()
    assert "version" in body
    assert "platform" in body
    assert "machine" in body
    assert "release" in body


@pytest.mark.asyncio
async def test_wifi_interfaces(app) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/v1/wifi/interfaces")
    assert r.status_code == 200
    body = r.json()
    assert "interfaces" in body
    assert isinstance(body["interfaces"], list)
