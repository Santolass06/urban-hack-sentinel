"""
Bluetooth hardware abstraction layer.

Currently wraps the existing ``FastPairScanner`` (bleak-based) and
provides a future ``BlueZDBusBackend`` for faster HCI interaction on
desktop Linux.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


try:
    from urban_hs.modules.ble.fastpair import BLEDevice  # type: ignore[attr-defined]
except Exception:
    @dataclass
    class BLEDevice:  # type: ignore[no-redef]
        address: str
        name: Optional[str] = None
        rssi: int = -100
        device_type: str = "STANDARD_BLE"
        fast_pair_model_id: Optional[str] = None
        fast_pair_in_pairing_mode: bool = False
        has_account_key_filter: bool = False

        def to_dict(self) -> Dict[str, Any]:
            return {k: getattr(self, k) for k in self.__dataclass_fields__.keys()}


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
    """Placeholder for a future BlueZ D-Bus backend.

    On desktop x86 with modern bluez + experimental features, direct
    D-Bus interaction is often faster and more reliable than bleak.
    Not yet implemented — structured so we can drop it in without
    touching callers.
    """

    def __init__(self, adapter: str = "hci0") -> None:
        self.adapter = adapter
        self._devices: List[Any] = []

    async def start(self) -> None:
        raise NotImplementedError("BlueZ D-Bus backend not yet implemented")

    async def stop(self) -> None:
        pass

    async def scan(self, duration: int = 10) -> List[Any]:
        raise NotImplementedError("BlueZ D-Bus backend not yet implemented")

    def devices(self) -> List[Any]:
        return self._devices

    def name(self) -> str:
        return "bluez"


def create_ble_backend(adapter: str = "hci0") -> BLEBackend:
    """Select BLE backend.

    On Raspberry Pi (ARM64) the existing bleak implementation works
    fine with the built-in Bluetooth adapter.  On x86 we keep the
    same path for now, but the bluez backend is stubbed for future.
    """
    return _BleakBackend(adapter=adapter)
