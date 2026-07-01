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
from urban_hs.ui.api.auth import create_access_token
from urban_hs.ui.api.rate_limit import limiter


@pytest.fixture
def app() -> FastAPI:
    return api_app


@pytest.fixture
def auth_headers() -> dict[str, str]:
    token = create_access_token(subject="test-user")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    limiter.reset()
    yield
    limiter.reset()


@pytest.mark.asyncio
async def test_healthz(app) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_system_info(app, auth_headers) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/v1/info", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert "version" in body
    assert "platform" in body
    assert "machine" in body
    assert "release" in body


@pytest.mark.asyncio
async def test_system_info_unauthorized(app) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/v1/info")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_wifi_interfaces(app, auth_headers) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/v1/wifi/interfaces", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert "interfaces" in body
    assert isinstance(body["interfaces"], list)


@pytest.mark.asyncio
async def test_wifi_interfaces_unauthorized(app) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/v1/wifi/interfaces")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_wifi_scan_rate_limited_after_threshold(app, auth_headers) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        statuses = [
            (await client.post("/api/v1/wifi/scan", headers=auth_headers)).status_code
            for _ in range(11)
        ]
    assert statuses[-1] == 429
