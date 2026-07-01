"""Guard-rail tests for the event-bus attack path.

These tests close the SessionScope bypass: before this fix, attack events
published on the event bus (wifi.attack_request / ble.exploit_request)
reached real execution without ever passing through SessionScope — only
the REST endpoint (ui/api/routers/attacks.py) was gated.

Each scenario ships with a **positive control**: the same correctly-shaped
event under an *open* scope must reach execution. Without it, a "not
executed" assertion would also pass on the pre-existing ``if not bssid``
early-return, proving nothing about the guard.

The urban_hack / ble.plugin handlers pull in an optional D-Bus dependency
at import time; where it is unavailable (e.g. minimal CI images) those
tests skip rather than error. The WiFi handler has no such dependency and
always runs — it is the core proof.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from urban_hs.core.event_bus import Event
from urban_hs.core.session_scope import SessionScope, set_active_scope
from urban_hs.modules.wifi.plugin import WiFiEventHandler

try:
    from urban_hs.modules.urban_hack import UrbanHackEventHandler
    _URBAN_OK = True
except Exception:  # pragma: no cover - optional D-Bus dependency missing
    _URBAN_OK = False

try:
    from urban_hs.modules.ble.plugin import BLEEventHandler
    _BLE_OK = True
except Exception:  # pragma: no cover - optional D-Bus dependency missing
    _BLE_OK = False


TARGET_BSSID = "AA:BB:CC:DD:EE:FF"
TARGET_ADDR = "11:22:33:44:55:66"


@pytest.fixture(autouse=True)
def _reset_scope():
    """Default to a closed scope; restore it after each test."""
    set_active_scope(SessionScope())
    yield
    set_active_scope(SessionScope())


def _published_types(bus_mock: MagicMock) -> list[str]:
    return [c.args[0].type for c in bus_mock.publish.call_args_list]


def _wifi_event() -> Event:
    return Event(
        type="wifi.attack_request",
        payload={"type": "deauth", "bssid": TARGET_BSSID, "channel": 1, "count": 5},
        source="test",
        correlation_id="req-1",
    )


def _ble_exploit_event() -> Event:
    return Event(
        type="ble.exploit_request",
        payload={"address": TARGET_ADDR},
        source="test",
        correlation_id="req-2",
    )


def _wifi_plugin_mock() -> MagicMock:
    plugin = MagicMock()
    plugin.execute_deauth = AsyncMock(return_value=MagicMock(to_dict=lambda: {}))
    return plugin


# ----------------------------------------------------------------------
# WiFi attack handler — wifi/plugin.py:_handle_attack_request
# ----------------------------------------------------------------------

@pytest.mark.asyncio()
async def test_wifi_attack_blocked_by_closed_scope():
    plugin = _wifi_plugin_mock()
    handler = WiFiEventHandler(plugin)
    bus_mock = MagicMock()
    bus_mock.publish = AsyncMock()

    with patch("urban_hs.modules.wifi.plugin.get_event_bus", return_value=bus_mock):
        await handler.handle(_wifi_event())

    plugin.execute_deauth.assert_not_awaited()
    assert "wifi.attack_denied" in _published_types(bus_mock)


@pytest.mark.asyncio()
async def test_wifi_attack_allowed_by_open_scope():
    """Positive control: with an open scope the same event MUST execute."""
    set_active_scope(SessionScope(
        allow_active=True,
        allowed_targets={TARGET_BSSID},
        allowed_categories={"wifi"},
    ))
    plugin = _wifi_plugin_mock()
    handler = WiFiEventHandler(plugin)
    bus_mock = MagicMock()
    bus_mock.publish = AsyncMock()

    with patch("urban_hs.modules.wifi.plugin.get_event_bus", return_value=bus_mock):
        await handler.handle(_wifi_event())

    plugin.execute_deauth.assert_awaited_once()
    assert "wifi.attack_denied" not in _published_types(bus_mock)


# ----------------------------------------------------------------------
# WiFi attack handler — urban_hack.py:_handle_wifi_attack
# ----------------------------------------------------------------------

@pytest.mark.skipif(not _URBAN_OK, reason="urban_hack requires optional D-Bus dependency")
@pytest.mark.asyncio()
async def test_urban_wifi_attack_blocked_by_closed_scope():
    plugin = _wifi_plugin_mock()
    handler = UrbanHackEventHandler(plugin)
    bus_mock = MagicMock()
    bus_mock.publish = AsyncMock()

    with patch("urban_hs.modules.urban_hack.get_event_bus", return_value=bus_mock):
        await handler.handle(_wifi_event())

    plugin.execute_deauth.assert_not_awaited()
    assert "wifi.attack_denied" in _published_types(bus_mock)


@pytest.mark.skipif(not _URBAN_OK, reason="urban_hack requires optional D-Bus dependency")
@pytest.mark.asyncio()
async def test_urban_wifi_attack_allowed_by_open_scope():
    """Positive control for the urban_hack handler."""
    set_active_scope(SessionScope(
        allow_active=True,
        allowed_targets={TARGET_BSSID},
        allowed_categories={"wifi"},
    ))
    plugin = _wifi_plugin_mock()
    handler = UrbanHackEventHandler(plugin)
    bus_mock = MagicMock()
    bus_mock.publish = AsyncMock()

    with patch("urban_hs.modules.urban_hack.get_event_bus", return_value=bus_mock):
        await handler.handle(_wifi_event())

    plugin.execute_deauth.assert_awaited_once()


# ----------------------------------------------------------------------
# BLE exploit handler — urban_hack.py:_handle_ble_exploit
# ----------------------------------------------------------------------

@pytest.mark.skipif(not _URBAN_OK, reason="urban_hack requires optional D-Bus dependency")
@pytest.mark.asyncio()
async def test_urban_ble_exploit_blocked_by_closed_scope():
    plugin = MagicMock()
    plugin.config.ble_whisperpair_exploit_enabled = True  # config gate open
    handler = UrbanHackEventHandler(plugin)
    bus_mock = MagicMock()
    bus_mock.publish = AsyncMock()

    with patch("urban_hs.modules.urban_hack.get_event_bus", return_value=bus_mock):
        await handler.handle(_ble_exploit_event())

    types = _published_types(bus_mock)
    assert "ble.attack_denied" in types
    assert "ble.exploit_complete" not in types


@pytest.mark.skipif(not _URBAN_OK, reason="urban_hack requires optional D-Bus dependency")
@pytest.mark.asyncio()
async def test_urban_ble_exploit_allowed_by_open_scope():
    """Positive control: open scope lets the (stub) exploit body run."""
    set_active_scope(SessionScope(
        allow_active=True,
        allowed_targets={TARGET_ADDR},
        allowed_categories={"ble"},
    ))
    plugin = MagicMock()
    plugin.config.ble_whisperpair_exploit_enabled = True
    handler = UrbanHackEventHandler(plugin)
    bus_mock = MagicMock()
    bus_mock.publish = AsyncMock()

    with patch("urban_hs.modules.urban_hack.get_event_bus", return_value=bus_mock):
        await handler.handle(_ble_exploit_event())

    types = _published_types(bus_mock)
    assert "ble.exploit_complete" in types
    assert "ble.attack_denied" not in types


# ----------------------------------------------------------------------
# BLE exploit handler — ble/plugin.py:_handle_exploit_request
# (the actually-subscribed handler for ble.exploit_request)
# ----------------------------------------------------------------------

@pytest.mark.skipif(not _BLE_OK, reason="ble.plugin requires optional D-Bus dependency")
@pytest.mark.asyncio()
async def test_ble_plugin_exploit_blocked_by_closed_scope():
    plugin = MagicMock()
    plugin.config.whisperpair_exploit_enabled = True
    handler = BLEEventHandler(plugin)
    bus_mock = MagicMock()
    bus_mock.publish = AsyncMock()

    with patch("urban_hs.modules.ble.plugin.get_event_bus", return_value=bus_mock):
        await handler.handle(_ble_exploit_event())

    types = _published_types(bus_mock)
    assert "ble.attack_denied" in types
    assert "ble.exploit_complete" not in types


@pytest.mark.skipif(not _BLE_OK, reason="ble.plugin requires optional D-Bus dependency")
@pytest.mark.asyncio()
async def test_ble_plugin_exploit_allowed_by_open_scope():
    """Positive control for the BLE plugin exploit handler."""
    set_active_scope(SessionScope(
        allow_active=True,
        allowed_targets={TARGET_ADDR},
        allowed_categories={"ble"},
    ))
    plugin = MagicMock()
    plugin.config.whisperpair_exploit_enabled = True
    handler = BLEEventHandler(plugin)
    bus_mock = MagicMock()
    bus_mock.publish = AsyncMock()

    with patch("urban_hs.modules.ble.plugin.get_event_bus", return_value=bus_mock):
        await handler.handle(_ble_exploit_event())

    types = _published_types(bus_mock)
    assert "ble.exploit_complete" in types
    assert "ble.attack_denied" not in types
