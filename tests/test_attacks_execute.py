"""T10.6 — attack execution."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from urban_hs.core.config import get_config
from urban_hs.core.session_scope import SessionScope
from urban_hs.ui.api.main import app as api_app
from urban_hs.ui.api.auth import create_access_token
from urban_hs.ui.api.rate_limit import limiter
from urban_hs.ui.api.routers.attacks import set_session_scope


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


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Each test gets a clean rate-limit bucket; the limiter is a process-wide singleton."""
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture(autouse=True)
def _open_session_scope():
    """Default to an open scope so non-exploit tests pass."""
    original = SessionScope()
    set_session_scope(SessionScope(
        allow_active=True,
        allowed_targets={"*"},
        allowed_categories={"wifi", "ble", "network", "exploit"},
    ))
    yield
    set_session_scope(original)


def test_execute_known_attack_returns_job(client: TestClient, auth_headers: dict) -> None:
    from urban_hs.modules import list_modules

    attack_name = next(iter(list_modules()))

    response = client.post(
        f"/api/v1/attacks/{attack_name}/execute",
        json={"params": {"target": "10.0.0.1"}, "dry_run": True},
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


def test_execute_exploit_without_guard_rails_returns_403(client: TestClient, auth_headers: dict) -> None:
    cfg = get_config()
    cfg.wifi.enable_active_attacks = False
    cfg.wifi.legal_warning_shown = False
    # Configure session scope to allow exploit so the exploit-specific guard rail is tested
    set_session_scope(SessionScope(
        allow_active=True,
        allowed_targets={"10.0.0.5", "*"},
        allowed_categories={"exploit"},
    ))
    try:
        response = client.post(
            "/api/v1/attacks/exploit/execute",
            json={"params": {"exploit_id": "1", "target": "10.0.0.5"}},
            headers=auth_headers,
        )

        assert response.status_code == 403
        assert "enable_active_attacks" in response.json()["detail"]
    finally:
        cfg.wifi.enable_active_attacks = False


def test_execute_exploit_with_only_one_guard_rail_still_denied(client: TestClient, auth_headers: dict) -> None:
    cfg = get_config()
    cfg.wifi.enable_active_attacks = True
    cfg.wifi.legal_warning_shown = False
    set_session_scope(SessionScope(
        allow_active=True,
        allowed_targets={"10.0.0.5", "*"},
        allowed_categories={"exploit"},
    ))
    try:
        response = client.post(
            "/api/v1/attacks/exploit/execute",
            json={"params": {"exploit_id": "1", "target": "10.0.0.5"}},
            headers=auth_headers,
        )
        assert response.status_code == 403
    finally:
        cfg.wifi.enable_active_attacks = False


def test_execute_exploit_with_guard_rails_satisfied_dispatches_real_runner(
    client: TestClient, auth_headers: dict, tmp_path
) -> None:
    cfg = get_config()
    cfg.wifi.enable_active_attacks = True
    cfg.wifi.legal_warning_shown = True
    cfg.storage.artifact_root = str(tmp_path / "artifacts")
    set_session_scope(SessionScope(
        allow_active=True,
        allowed_targets={"10.0.0.5", "*"},
        allowed_categories={"exploit"},
    ))
    try:
        response = client.post(
            "/api/v1/attacks/exploit/execute",
            json={"params": {"exploit_id": "1", "target": "10.0.0.5"}},
            headers=auth_headers,
        )
        # Guard rails pass -> the real ExploitRunner is invoked (no searchsploit
        # backend configured in tests, so it fails internally, but the HTTP
        # call itself must succeed — the gate, not the exploit, decides 403 vs 200).
        assert response.status_code == 200
        assert response.json()["attack"] == "exploit"
    finally:
        cfg.wifi.enable_active_attacks = False
        cfg.wifi.legal_warning_shown = False
        cfg.storage.artifact_root = ""


def test_execute_dry_run_bypasses_guard_rails(client: TestClient, auth_headers: dict) -> None:
    cfg = get_config()
    cfg.wifi.enable_active_attacks = False
    cfg.wifi.legal_warning_shown = False

    response = client.post(
        "/api/v1/attacks/exploit/execute",
        json={"params": {}, "dry_run": True},
        headers=auth_headers,
    )

    assert response.status_code == 200


def test_execute_rate_limit_triggers_429(client: TestClient, auth_headers: dict) -> None:
    last_status = None
    for _ in range(11):
        last_status = client.post(
            "/api/v1/attacks/wifi/execute",
            json={"params": {}, "dry_run": True},
            headers=auth_headers,
        ).status_code

    assert last_status == 429
