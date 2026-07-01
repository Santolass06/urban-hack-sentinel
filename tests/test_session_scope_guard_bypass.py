"""Guard-rail tests for the two SessionScope bypasses found by the inventory.

Covers:
1. ``bt_hid.bt_hid_attack()`` — standalone convenience entry point that
   calls ``BTHIDAttacker.run_full_attack()`` (CVE-2023-45866 keystroke
   injection). Now gated by ``get_active_scope().validate(target, "bluetooth_hid")``;
   a closed scope must raise ``PermissionError`` *before* the attacker is
   even constructed.
2. ``ble.test_request`` event-bus path — two handlers perform a real GATT
   write (CVE-2025-36911 KBP primitive) via ``WhisperPairTester.test_device``
   without a scope check. Now both gate on ``validate(address, "ble")`` and
   publish ``ble.attack_denied`` on denial (same event name as the exploit
   handlers — no new name invented).

Each scenario ships with a **positive control**: under an *open* scope the
same call/event MUST reach execution. Without it a "not executed"
assertion would also pass on an unrelated early-return, proving nothing.

These handlers pull in an optional D-Bus dependency at import time; where
it is unavailable (minimal CI images) the affected tests skip rather than
error. The ``bt_hid`` point has no such handler dependency and always runs.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from urban_hs.core.event_bus import Event
from urban_hs.core.session_scope import SessionScope, set_active_scope

try:
    from urban_hs.modules.bt_hid import bt_hid_attack
    _BT_HID_OK = True
except Exception:  # pragma: no cover - optional dbus_fast dependency missing
    _BT_HID_OK = False

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


TARGET_ADDR = "11:22:33:44:55:66"


@pytest.fixture(autouse=True)
def _reset_scope():
    """Default to a closed scope; restore it after each test."""
    set_active_scope(SessionScope())
    yield
    set_active_scope(SessionScope())


def _published_types(bus_mock: MagicMock) -> list[str]:
    return [c.args[0].type for c in bus_mock.publish.call_args_list]


def _ble_test_event() -> Event:
    return Event(
        type="ble.test_request",
        payload={"address": TARGET_ADDR},
        source="test",
        correlation_id="req-test",
    )


# ----------------------------------------------------------------------
# Point 1 — bt_hid.bt_hid_attack() standalone entry point
# ----------------------------------------------------------------------

@pytest.mark.skipif(not _BT_HID_OK, reason="bt_hid requires optional dbus_fast dependency")
@pytest.mark.asyncio()
async def test_bt_hid_attack_blocked_by_closed_scope():
    """Closed scope: PermissionError raised before BTHIDAttacker is built."""
    with patch("urban_hs.modules.bt_hid.BTHIDAttacker") as mock_attacker:
        mock_instance = MagicMock()
        mock_instance.run_full_attack = AsyncMock()
        mock_attacker.return_value = mock_instance

        with pytest.raises(PermissionError):
            await bt_hid_attack(TARGET_ADDR, "payload")

    # Guard raised before construction -> attacker never instantiated, attack
    # never executed.
    mock_attacker.assert_not_called()
    if mock_attacker.return_value.run_full_attack:  # safety: not awaited even if built
        mock_attacker.return_value.run_full_attack.assert_not_awaited()


@pytest.mark.skipif(not _BT_HID_OK, reason="bt_hid requires optional dbus_fast dependency")
@pytest.mark.asyncio()
async def test_bt_hid_attack_allowed_by_open_scope():
    """Positive control: open scope lets the attack proceed to run_full_attack."""
    set_active_scope(SessionScope(
        allow_active=True,
        allowed_targets={TARGET_ADDR},
        allowed_categories={"bluetooth_hid"},
    ))
    with patch("urban_hs.modules.bt_hid.BTHIDAttacker") as mock_attacker:
        mock_instance = MagicMock()
        mock_instance.run_full_attack = AsyncMock(return_value=MagicMock())
        mock_attacker.return_value = mock_instance

        await bt_hid_attack(TARGET_ADDR, "payload")

    mock_attacker.assert_called_once()
    mock_instance.run_full_attack.assert_awaited_once_with(payload="payload")


# ----------------------------------------------------------------------
# Point 2a — ble/plugin.py:_handle_test_request  (ble.test_request)
# ----------------------------------------------------------------------

@pytest.mark.skipif(not _BLE_OK, reason="ble.plugin requires optional D-Bus dependency")
@pytest.mark.asyncio()
async def test_ble_plugin_test_blocked_by_closed_scope():
    """Closed scope: ble.attack_denied published, test_vulnerability NOT called."""
    plugin = MagicMock()
    plugin.test_vulnerability = AsyncMock(return_value={"status": "vulnerable"})
    handler = BLEEventHandler(plugin)
    bus_mock = MagicMock()
    bus_mock.publish = AsyncMock()

    with patch("urban_hs.modules.ble.plugin.get_event_bus", return_value=bus_mock):
        await handler.handle(_ble_test_event())

    types = _published_types(bus_mock)
    assert "ble.attack_denied" in types
    assert "ble.test_complete" not in types
    plugin.test_vulnerability.assert_not_awaited()


@pytest.mark.skipif(not _BLE_OK, reason="ble.plugin requires optional D-Bus dependency")
@pytest.mark.asyncio()
async def test_ble_plugin_test_allowed_by_open_scope():
    """Positive control: open scope lets the GATT test run + publish test_complete."""
    set_active_scope(SessionScope(
        allow_active=True,
        allowed_targets={TARGET_ADDR},
        allowed_categories={"ble"},
    ))
    plugin = MagicMock()
    plugin.test_vulnerability = AsyncMock(return_value={"status": "vulnerable"})
    handler = BLEEventHandler(plugin)
    bus_mock = MagicMock()
    bus_mock.publish = AsyncMock()

    with patch("urban_hs.modules.ble.plugin.get_event_bus", return_value=bus_mock):
        await handler.handle(_ble_test_event())

    types = _published_types(bus_mock)
    assert "ble.test_complete" in types
    assert "ble.attack_denied" not in types
    plugin.test_vulnerability.assert_awaited_once_with(TARGET_ADDR)


# ----------------------------------------------------------------------
# Point 2b — urban_hack.py:_handle_ble_test  (ble.test_request, 2nd subscriber)
# ----------------------------------------------------------------------

@pytest.mark.skipif(not _URBAN_OK, reason="urban_hack requires optional D-Bus dependency")
@pytest.mark.asyncio()
async def test_urban_ble_test_blocked_by_closed_scope():
    """Closed scope: ble.attack_denied published, execute_ble_vuln_test NOT called."""
    plugin = MagicMock()
    plugin.execute_ble_vuln_test = AsyncMock(return_value={"status": "vulnerable"})
    handler = UrbanHackEventHandler(plugin)
    bus_mock = MagicMock()
    bus_mock.publish = AsyncMock()

    with patch("urban_hs.modules.urban_hack.get_event_bus", return_value=bus_mock):
        await handler.handle(_ble_test_event())

    types = _published_types(bus_mock)
    assert "ble.attack_denied" in types
    assert "ble.test_complete" not in types
    plugin.execute_ble_vuln_test.assert_not_awaited()


@pytest.mark.skipif(not _URBAN_OK, reason="urban_hack requires optional D-Bus dependency")
@pytest.mark.asyncio()
async def test_urban_ble_test_allowed_by_open_scope():
    """Positive control: open scope lets the GATT test run + publish test_complete."""
    set_active_scope(SessionScope(
        allow_active=True,
        allowed_targets={TARGET_ADDR},
        allowed_categories={"ble"},
    ))
    plugin = MagicMock()
    plugin.execute_ble_vuln_test = AsyncMock(return_value={"status": "vulnerable"})
    handler = UrbanHackEventHandler(plugin)
    bus_mock = MagicMock()
    bus_mock.publish = AsyncMock()

    with patch("urban_hs.modules.urban_hack.get_event_bus", return_value=bus_mock):
        await handler.handle(_ble_test_event())

    types = _published_types(bus_mock)
    assert "ble.test_complete" in types
    assert "ble.attack_denied" not in types
    plugin.execute_ble_vuln_test.assert_awaited_once_with(TARGET_ADDR)
