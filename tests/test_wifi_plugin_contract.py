"""
Contract tests for ``urban_hs.modules.wifi.plugin``.

Validates happy-path flows for WiFiPlugin:
- initialization
- start/stop lifecycle
- event handling (scan_request, attack_request)
- inventory helpers
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from urban_hs.core.event_bus import Event
from urban_hs.modules.wifi.plugin import WiFiPlugin, WiFiModuleConfig


@pytest.fixture()
def plugin():
    plugin = WiFiPlugin(
        config=WiFiModuleConfig(
            interface="wlan0",
            enable_active_attacks=True,
            mac_randomize_interval=0,
        )
    )
    plugin.scanner = MagicMock()
    plugin.scanner.get_known_networks.return_value = []
    plugin.mac_changer = MagicMock()
    plugin.geo_mapper = MagicMock()
    plugin.geo_mapper.is_fixed.return_value = False
    plugin._handshake_attack = MagicMock()
    plugin._handshake_attack.execute = AsyncMock(
        return_value=MagicMock(status="success", to_dict=MagicMock(return_value={}))
    )
    plugin._pmkid_attack = MagicMock()
    plugin._pmkid_attack.execute = AsyncMock(
        return_value=MagicMock(status="failed", to_dict=MagicMock(return_value={}))
    )
    plugin._wps_pixie_attack = MagicMock()
    plugin._wps_pixie_attack.execute = AsyncMock(
        return_value=MagicMock(status="running", to_dict=MagicMock(return_value={}))
    )
    plugin._wps_pin_attack = MagicMock()
    plugin._wps_pin_attack.execute = AsyncMock(
        return_value=MagicMock(status="success", to_dict=MagicMock(return_value={}))
    )
    plugin._deauth_attack = MagicMock()
    plugin._deauth_attack.execute = AsyncMock(
        return_value=MagicMock(status="success", to_dict=MagicMock(return_value={}))
    )
    plugin._attack_semaphore = asyncio.Semaphore(3)
    return plugin


@pytest.mark.asyncio()
async def test_initialize_plugin(plugin):
    with patch("urban_hs.modules.wifi.plugin.WiFiScanner", return_value=plugin.scanner):
        await plugin.initialize()

    assert plugin.scanner is not None
    assert plugin.handshake_mgr is not None
    assert plugin.mac_changer is not None
    assert plugin.geo_mapper is not None


@pytest.mark.asyncio()
async def test_start_then_stop(plugin):
    plugin._running = False

    bus_mock = MagicMock()
    bus_mock.publish = AsyncMock()
    bus_mock.subscribe = MagicMock()

    with patch("urban_hs.modules.wifi.plugin.WiFiScanner", return_value=plugin.scanner):
        await plugin.initialize()

    with patch("urban_hs.modules.wifi.plugin.get_event_bus", return_value=bus_mock):
        await plugin.start()
        assert plugin._running is True

        await plugin.stop()
        assert plugin._running is False


@pytest.mark.asyncio()
async def test_scan_request_event(plugin):
    payload = {"channels": [1, 6, 11], "duration": 5}
    event = Event(type="wifi.scan_request", payload=payload, source="test", correlation_id="abc")

    plugin.scanner.manager.scan = AsyncMock(return_value=[])

    from urban_hs.modules.wifi.plugin import WiFiEventHandler
    handler = WiFiEventHandler(plugin)
    await handler.handle(event)

    plugin.scanner.manager.scan.assert_awaited_once_with(channels=[1, 6, 11], duration=5)


@pytest.mark.asyncio()
async def test_attack_execution(plugin):
    from urban_hs.core.session_scope import SessionScope, set_active_scope

    with patch("urban_hs.modules.wifi.plugin.WiFiScanner", return_value=plugin.scanner):
        await plugin.initialize()

    bus_mock = MagicMock()
    bus_mock.publish = AsyncMock()

    # Open the shared session scope so the guard rail permits execution.
    set_active_scope(SessionScope(
        allow_active=True,
        allowed_targets={"AA:BB:CC:DD:EE:FF"},
        allowed_categories={"wifi"},
    ))

    from urban_hs.modules.wifi.plugin import WiFiEventHandler
    handler = WiFiEventHandler(plugin)

    try:
        for attack_type in ("handshake", "pmkid", "wps_pixie", "wps_pin", "deauth"):
            event = Event(
                type="wifi.attack_request",
                payload={
                    "type": attack_type,
                    "bssid": "AA:BB:CC:DD:EE:FF",
                    "channel": 1,
                    "count": 5,
                },
                source="test",
                correlation_id="req-1",
            )
            await handler.handle(event)
    finally:
        # Restore the default closed scope so it does not leak to other tests.
        set_active_scope(SessionScope())


def test_get_known_networks_returns_scanner_list(plugin):
    plugin.scanner.get_known_networks.return_value = ["net"]
    assert plugin.get_known_networks() == ["net"]


def test_get_known_networks_without_scanner():
    plugin = WiFiPlugin()
    plugin.scanner = None
    assert plugin.get_known_networks() == []
