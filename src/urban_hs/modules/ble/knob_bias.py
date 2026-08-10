"""BLE KNOB (CVE-2019-9506) and BIAS (CVE-2020-10135) testing.

Both are vulnerabilities in the Bluetooth BR/EDR Secure Simple Pairing /
Legacy Pairing key agreement, exploitable against many controllers. This
module provides detection primitives (scan for affected services / known
weaknesses) and a BR/EDR bonding tester that works alongside
``exploit_chain.BlueZBondingManager``.

Lab-only. Requires BlueZ + a capable adapter.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import StrEnum

import structlog

logger = structlog.get_logger(__name__)


class VulnStatus(StrEnum):
    UNKNOWN = "unknown"
    VULNERABLE = "vulnerable"
    SAFE = "safe"
    NOT_TESTED = "not_tested"


@dataclass
class BTClassicVuln:
    address: str
    name: str | None = None
    knob: VulnStatus = VulnStatus.NOT_TESTED
    bias: VulnStatus = VulnStatus.NOT_TESTED
    notes: list[str] = field(default_factory=list)


class KNOBBiasTester:
    """Probe a BR/EDR device for KNOB/BIAS exposure via BlueZ D-Bus."""

    def __init__(self, adapter: str = "hci0") -> None:
        self.adapter = adapter

    def _dbus(self):
        try:
            import dbus  # noqa: F401

            return dbus
        except Exception:  # pragma: no cover - optional C ext
            logger.warning("dbus unavailable; KNOB/BIAS tester cannot run")
            return None

    def check_security_properties(self, address: str) -> BTClassicVuln:
        """Inspect the device's advertised security properties.

        KNOB applies when the link permits 1-byte (or short) TK; BIAS when the
        device accepts legacy pairing / impostor roles. We flag *potential*
        exposure from the BlueZ cached properties — a real test needs an active
        pairing attempt, which ``BlueZBondingManager`` already drives.
        """
        dbus = self._dbus()
        result = BTClassicVuln(address=address)
        if dbus is None:
            return result

        try:
            bus = dbus.SystemBus()
            path = f"/org/bluez/{self.adapter}/dev_{address.replace(':', '_').upper()}"
            dev = bus.get_object("org.bluez", path)
            props = dbus.Interface(dev, "org.freedesktop.DBus.Properties")
            uuids = props.Get("org.bluez.Device1", "UUIDs") or []
            # Classic SDP + absence of Secure Connections hint → BIAS-relevant
            classic = any(
                u.startswith("0000") and u.endswith("-0000-1000-8000-00805f9b34fb") for u in uuids
            )
            if classic:
                result.bias = VulnStatus.UNKNOWN
                result.notes.append("Classic SDP present; verify pairing role enforcement")
            result.notes.append(f"{len(uuids)} UUIDs enumerated")
        except Exception as exc:
            logger.warning("Could not read device properties", address=address, error=str(exc))
        return result

    async def scan_and_flag(self, addresses: list[str]) -> list[BTClassicVuln]:
        """Run the property check across discovered BR/EDR devices."""
        results: list[BTClassicVuln] = []
        for addr in addresses:
            # property read is sync (blocking D-Bus); wrap to avoid loop stalls
            res = await asyncio.to_thread(self.check_security_properties, addr)
            results.append(res)
        return results
