"""TUI smoke tests for phase 10."""

from __future__ import annotations

import pytest
from urban_hs.ui.tui.app import TUIApp, EventMessage


def _app() -> TUIApp:
    return TUIApp()


def test_tui_app_has_attack_actions() -> None:
    app = _app()
    assert hasattr(app, "_wifi_deauth")
    assert hasattr(app, "_wifi_wps_pixie")
    assert hasattr(app, "_wifi_wps_pin")
    assert hasattr(app, "_wifi_handshake")
    assert hasattr(app, "_wifi_pmkid")
    assert hasattr(app, "_ble_whisperpair")
    assert hasattr(app, "_publish_attack")


def test_tui_event_handler_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app()
    calls: list[str] = []

    class FakeTerminal:
        def write(self, line: str) -> None:
            calls.append(line)

    class FakeLog:
        def write(self, line: str) -> None:
            calls.append(line)

    fake_terminal = FakeTerminal()
    fake_log = FakeLog()
    monkeypatch.setattr(app, "query_one", lambda sel, cls, *args, **kwargs: fake_terminal if "terminal" in str(sel) else fake_log)
    message = EventMessage(event_type="attack.started", payload={"attack": "x"})
    app.on_event_message(message)
    assert any("[yellow]START[/yellow]" in line for line in app._attack_log)
