"""Smoke test to validate that importing and running FastAPI lifecycle does not hang."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from urban_hs.ui.api.main import app
from urban_hs.ui.api.auth import create_access_token


@pytest.mark.asyncio
async def test_fastapi_app_starts_and_stops() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/v1/healthz")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"


@pytest.mark.asyncio
async def test_auth_token_endpoint() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post("/api/v1/auth/token")
        assert r.status_code == 200
        body = r.json()
        assert "access_token" in body
        assert body["token_type"] == "bearer"
