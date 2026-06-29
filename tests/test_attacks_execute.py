"""T10.6 — attack execution."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from urban_hs.ui.api.main import app as api_app


@pytest.fixture()
def application() -> FastAPI:
    return api_app


@pytest.fixture()
def client(application: FastAPI):
    with TestClient(app=application) as c:
        yield c


def test_execute_known_attack_returns_job(client: TestClient) -> None:
    from urban_hs.modules import list_modules

    attack_name = next(iter(list_modules()))

    response = client.post(
        f"/api/v1/attacks/{attack_name}/execute",
        json={"params": {"dry_run": True}},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["attack"] == attack_name
    assert "job_id" in body


def test_execute_unknown_attack_returns_404(client: TestClient) -> None:
    response = client.post(
        "/api/v1/attacks/does_not_exist/execute",
        json={"params": {}},
    )

    assert response.status_code == 404


def test_execute_dry_run_returns_job_without_process(client: TestClient) -> None:
    from urban_hs.modules import list_modules

    attack_name = next(iter(list_modules()))

    response = client.post(
        f"/api/v1/attacks/{attack_name}/execute",
        json={"params": {}, "dry_run": True},
    )

    assert response.status_code == 200
    assert response.json()["job_id"]
