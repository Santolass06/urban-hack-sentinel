"""TUI smoke tests for phase 10."""

from __future__ import annotations

import asyncio

import pytest
from textual.widgets import Button

from urban_hs.ui.tui.app import EventMessage, TUIApp


def _app() -> TUIApp:
    return TUIApp()


class _RecordingApp(TUIApp):
    """TUIApp that records every EventMessage the UI actually receives."""

    def __init__(self) -> None:
        super().__init__()
        self.seen_events: list[str] = []

    def on_event_message(self, message: EventMessage) -> None:
        self.seen_events.append(message.event_type)
        super().on_event_message(message)


async def test_tui_mounts_and_wires_event_bus() -> None:
    """Headless mount: regression guard for the three bugs that broke the TUI.

    Would have caught: EventMessage not being a textual Message (post_message
    RuntimeError), FastPairScanner(scan_all=...) TypeError, and the event bus
    never being started / no attack plugin subscribed.
    """
    from urban_hs.core import event_bus

    app = _RecordingApp()
    try:
        async with app.run_test() as pilot:
            await pilot.pause()
            await asyncio.sleep(0.5)

            # Event bus wired: UI forwarder + wifi + ble attack handlers.
            handler_names = {type(h).__name__ for h in app._bus_handlers}
            assert "_UIForwarder" in handler_names
            assert "WiFiEventHandler" in handler_names
            assert "BLEEventHandler" in handler_names

            # Confirming a Deauth must dispatch through the bus and come back:
            # the default-deny session scope denies it, proving the loop works.
            app.query_one("#btn-wifi-deauth", Button).press()
            await pilot.pause()
            app.query_one("#modal-confirm", Button).press()
            await asyncio.sleep(0.5)

        assert "wifi.attack_request" in app.seen_events
        assert "wifi.attack_denied" in app.seen_events
    finally:
        # This test starts the process-wide event bus singleton; reset it so
        # its workers (bound to this test's loop) don't leak into other tests.
        # Cancel workers directly instead of stop() to avoid queue.join() hangs.
        bus = event_bus._event_bus
        event_bus._event_bus = None
        if bus is not None:
            bus._running = False
            for worker in bus._workers:
                worker.cancel()


def test_tui_app_has_attack_actions() -> None:
    app = _app()
    assert hasattr(app, "_wifi_deauth")
    assert hasattr(app, "_wifi_wps_pixie")
    assert hasattr(app, "_wifi_wps_pin")
    assert hasattr(app, "_wifi_handshake")
    assert hasattr(app, "_wifi_pmkid")
    assert hasattr(app, "_wifi_wpa3_downgrade")
    assert hasattr(app, "_wifi_ft")
    assert hasattr(app, "_wifi_krook")
    assert hasattr(app, "_wifi_gps_wardrive")
    assert hasattr(app, "_ble_whisperpair")
    assert hasattr(app, "_ble_hid")
    assert hasattr(app, "_net_nuclei")
    assert hasattr(app, "_net_camera")
    assert hasattr(app, "_net_esp32")
    assert hasattr(app, "_net_mqtt")
    # Newly exposed attack modules (all wired to real backends).
    assert hasattr(app, "_ssid_confusion")
    assert hasattr(app, "_wifi_fragattacks")
    assert hasattr(app, "_ble_exploit")
    assert hasattr(app, "_net_router")
    assert hasattr(app, "_exploit_search")
    assert hasattr(app, "_exploit_msf")
    assert hasattr(app, "_hid_local")
    assert hasattr(app, "_publish_wifi_attack")


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
    monkeypatch.setattr(
        app,
        "query_one",
        lambda sel, cls, *args, **kwargs: fake_terminal if "terminal" in str(sel) else fake_log,
    )
    message = EventMessage(event_type="attack.started", payload={"attack": "x"})
    app.on_event_message(message)
    assert any("[yellow]START[/yellow]" in line for line in app._attack_log)
