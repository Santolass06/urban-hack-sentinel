"""Smoke test to validate that importing and running FastAPI lifecycle does not hang."""

from __future__ import annotations

import asyncio

import pytest
from httpx import ASGITransport, AsyncClient

from urban_hs.ui.api.main import app


@pytest.mark.asyncio
async def test_fastapi_app_starts_and_stops() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/healthz")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
