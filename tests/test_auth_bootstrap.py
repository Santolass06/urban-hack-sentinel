"""B002: POST /auth/token must honor the optional bootstrap-token gate."""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import patch

from fastapi.testclient import TestClient

from urban_hs.core.config import get_config


@contextmanager
def _client_with_bootstrap(token: str):
    # Patch must stay active during requests: create_token reads
    # cfg.api.bootstrap_token at request time, not build time.
    cfg = get_config()
    with patch.object(cfg.api, "bootstrap_token", token):
        from urban_hs.ui.api.main import _build_app

        with TestClient(_build_app()) as client:
            yield client


def test_token_requires_bootstrap_when_configured() -> None:
    with _client_with_bootstrap("s3cr3t") as client:
        assert client.post("/api/v1/auth/token").status_code == 401
        assert (
            client.post("/api/v1/auth/token", headers={"X-Bootstrap-Token": "nope"}).status_code
            == 401
        )
        ok = client.post("/api/v1/auth/token", headers={"X-Bootstrap-Token": "s3cr3t"})
        assert ok.status_code == 200
        assert ok.json()["access_token"]


def test_token_open_when_bootstrap_unset() -> None:
    with _client_with_bootstrap("") as client:
        assert client.post("/api/v1/auth/token").status_code == 200
