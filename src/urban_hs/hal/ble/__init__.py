"""
Bluetooth hardware abstraction layer.

Provides BLEBackend implementations:
- _BleakBackend: bleak-based (works on Raspberry Pi and most systems)
- _BlueZBackend: D-Bus direct (faster on desktop Linux with BlueZ 5.50+)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from urban_hs.hal.types import BLEDevice, BLEDeviceType


class BLEBackend(ABC):
    @abstractmethod
    async def scan(self, duration: int = 10) -> List[Any]:
        ...

    @abstractmethod
    async def start(self) -> None:
        ...

    @abstractmethod
    async def stop(self) -> None:
        ...

    @abstractmethod
    def devices(self) -> List[Any]:
        ...

    @abstractmethod
    def name(self) -> str:
        ...


class _BleakBackend(BLEBackend):
    """Current implementation based on bleak."""

    def __init__(self, adapter: str = "hci0") -> None:
        self.adapter = adapter
        self._scanner: Any = None
        self._devices: Dict[str, Any] = {}

    async def start(self) -> None:
        try:
            from urban_hs.modules.ble.fastpair import FastPairScanner
            self._scanner = FastPairScanner(adapter=self.adapter)
            await self._scanner.start()
        except Exception as exc:
            raise RuntimeError(f"bleak backend failed: {exc}") from exc

    async def stop(self) -> None:
        if self._scanner:
            try:
                await self._scanner.stop()
            except Exception:
                pass

    async def scan(self, duration: int = 10) -> List[Any]:
        await self.start()
        import asyncio
        await asyncio.sleep(duration)
        await self.stop()
        self._devices = {d.address: d for d in self._scanner.get_devices()}
        return list(self._devices.values())

    def devices(self) -> List[Any]:
        return list(self._devices.values())

    def name(self) -> str:
        return "bleak"


class _BlueZBackend(BLEBackend):
    """BlueZ D-Bus backend for fast HCI interaction on desktop Linux.

    Uses dbus-fast to communicate directly with BlueZ over D-Bus,
    providing faster and more reliable scanning than bleak on systems
    with BlueZ 5.50+ and experimental features enabled.
    """

    def __init__(self, adapter: str = "hci0") -> None:
        self.adapter = adapter
        self._devices: Dict[str, Any] = {}
        self._bus: Any = None
        self._adapter_path = f"/org/bluez/{adapter}"
        self._scanning = False

    async def start(self) -> None:
        try:
            from dbus_fast.aio import MessageBus
            from dbus_fast import BusType

            self._bus = MessageBus(bus_type=BusType.SYSTEM)
            await self._bus.connect()

            # Enable the adapter
            introspection = await self._bus.introspect(
                "org.bluez", self._adapter_path
            )
            proxy = self._bus.get_proxy_object(
                "org.bluez", self._adapter_path, introspection
            )
            props = proxy.get_interface("org.freedesktop.DBus.Properties")
            await props.call_set("org.bluez.Adapter1", "Powered", "b", True)
            logger.info("BlueZ adapter powered on", adapter=self.adapter)
        except ImportError:
            raise RuntimeError("dbus_fast not installed — cannot use BlueZ backend")
        except Exception as exc:
            raise RuntimeError(f"BlueZ D-Bus init failed: {exc}") from exc

    async def stop(self) -> None:
        if self._scanning and self._bus:
            try:
                introspection = await self._bus.introspect(
                    "org.bluez", self._adapter_path
                )
                proxy = self._bus.get_proxy_object(
                    "org.bluez", self._adapter_path, introspection
                )
                iface = proxy.get_interface("org.bluez.LEAdvertisingManager1")
                # Stop discovery
                props = proxy.get_interface("org.freedesktop.DBus.Properties")
                await props.call_set(
                    "org.bluez.Adapter1", "Discovering", "b", False
                )
                self._scanning = False
            except Exception:
                pass
        if self._bus:
            self._bus.disconnect()
            self._bus = None

    async def scan(self, duration: int = 10) -> List[Any]:
        if not self._bus:
            await self.start()

        try:
            # Start discovery
            introspection = await self._bus.introspect(
                "org.bluez", self._adapter_path
            )
            proxy = self._bus.get_proxy_object(
                "org.bluez", self._adapter_path, introspection
            )
            props = proxy.get_interface("org.freedesktop.DBus.Properties")
            await props.call_set("org.bluez.Adapter1", "Discovering", "b", True)
            self._scanning = True

            # Wait for discovery
            import asyncio
            await asyncio.sleep(duration)

            # Get discovered devices
            await self._poll_devices()

            # Stop discovery
            await props.call_set("org.bluez.Adapter1", "Discovering", "b", False)
            self._scanning = False

        except Exception as exc:
            logger.error("BlueZ scan failed", error=str(exc))
            self._scanning = False

        return list(self._devices.values())

    async def _poll_devices(self) -> None:
        """Enumerate known devices from BlueZ via D-Bus ObjectManager."""
        try:
            introspection = await self._bus.introspect("org.bluez", "/")
            proxy = self._bus.get_proxy_object("org.bluez", "/", introspection)
            om = proxy.get_interface("org.freedesktop.DBus.ObjectManager")
            objects = await om.call_get_managed_objects()

            for obj_path, interfaces in objects.items():
                if "org.bluez.Device1" not in interfaces:
                    continue
                props = interfaces["org.bluez.Device1"]
                address = props.get("Address", "")
                name = props.get("Alias") or props.get("Name", "")
                rssi = props.get("RSSI", -100)

                if address and address not in self._devices:
                    self._devices[address] = BLEDevice(
                        address=address,
                        name=name,
                        rssi=rssi,
                    )
        except Exception as exc:
            logger.debug("BlueZ device enumeration failed", error=str(exc))

    def devices(self) -> List[Any]:
        return list(self._devices.values())

    def name(self) -> str:
        return "bluez"


def create_ble_backend(adapter: str = "hci0") -> BLEBackend:
    """Select BLE backend.

    Tries BlueZ D-Bus backend first (faster on desktop Linux with BlueZ 5.50+),
    falls back to bleak if D-Bus is unavailable (e.g., on Raspberry Pi or
    in containers without system bus access).
    """
    try:
        import dbus_fast  # noqa: F401
        return _BlueZBackend(adapter=adapter)
    except ImportError:
        return _BleakBackend(adapter=adapter)
