"""WebSocket /events must require the same Bearer auth as the REST endpoints."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from urban_hs.ui.api.main import app as api_app
from urban_hs.ui.api.auth import create_access_token


@pytest.fixture()
def application() -> FastAPI:
    return api_app


@pytest.fixture()
def client(application: FastAPI):
    with TestClient(app=application) as c:
        yield c


def test_websocket_events_without_token_rejected(client: TestClient) -> None:
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/events"):
            pass


def test_websocket_events_with_invalid_token_rejected(client: TestClient) -> None:
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/events?token=not-a-real-token"):
            pass


def test_websocket_events_with_valid_token_connects(client: TestClient) -> None:
    token = create_access_token(subject="test-user")
    with client.websocket_connect(f"/events?token={token}"):
        pass  # connection accepted, no exception


def test_websocket_events_with_valid_authorization_header_connects(client: TestClient) -> None:
    token = create_access_token(subject="test-user")
    with client.websocket_connect("/events", headers={"Authorization": f"Bearer {token}"}):
        pass
