"""T10.1 — attack inventory."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import AsyncClient, ASGITransport

from urban_hs.ui.api.main import app as api_app
from urban_hs.ui.api.auth import create_access_token


@pytest.fixture()
def application() -> FastAPI:
    return api_app


@pytest.fixture()
def auth_headers() -> dict[str, str]:
    token = create_access_token(subject="test-user")
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.anyio
async def test_list_attacks_returns_grouped_modules(application: FastAPI, auth_headers: dict) -> None:
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/attacks", headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["total"] >= 1
    assert len(body["attacks"]) == body["total"]


@pytest.mark.anyio
async def test_attack_inventory_items_have_required_fields(application: FastAPI, auth_headers: dict) -> None:
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/attacks", headers=auth_headers)

    assert response.status_code == 200
    for item in response.json()["attacks"]:
        assert "name" in item
        assert "plugin_type" in item
        assert "description" in item
