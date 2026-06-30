"""T10.6 — attack execution."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from urban_hs.ui.api.main import app as api_app
from urban_hs.ui.api.auth import create_access_token


@pytest.fixture()
def application() -> FastAPI:
    return api_app


@pytest.fixture()
def client(application: FastAPI):
    with TestClient(app=application) as c:
        yield c


@pytest.fixture()
def auth_headers() -> dict[str, str]:
    token = create_access_token(subject="test-user")
    return {"Authorization": f"Bearer {token}"}


def test_execute_known_attack_returns_job(client: TestClient, auth_headers: dict) -> None:
    from urban_hs.modules import list_modules

    attack_name = next(iter(list_modules()))

    response = client.post(
        f"/api/v1/attacks/{attack_name}/execute",
        json={"params": {"dry_run": True}},
        headers=auth_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["attack"] == attack_name
    assert "job_id" in body


def test_execute_unknown_attack_returns_404(client: TestClient, auth_headers: dict) -> None:
    response = client.post(
        "/api/v1/attacks/does_not_exist/execute",
        json={"params": {}},
        headers=auth_headers,
    )

    assert response.status_code == 404


def test_execute_dry_run_returns_job_without_process(client: TestClient, auth_headers: dict) -> None:
    from urban_hs.modules import list_modules

    attack_name = next(iter(list_modules()))

    response = client.post(
        f"/api/v1/attacks/{attack_name}/execute",
        json={"params": {}, "dry_run": True},
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert response.json()["job_id"]


def test_execute_unauthorized_returns_401(client: TestClient) -> None:
    response = client.post(
        "/api/v1/attacks/some_attack/execute",
        json={"params": {}},
    )
    assert response.status_code == 401
