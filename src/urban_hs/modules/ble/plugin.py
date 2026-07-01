"""
BLE Module Plugin - Integrates Fast Pair scanning and WhisperPair exploit.
"""

import asyncio
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

import structlog

from urban_hs.core import Event, get_event_bus, get_storage
from urban_hs.core.event_bus import Event, EventHandler
from urban_hs.core.session_scope import get_active_scope
from urban_hs.modules.ble import (
    BLEDevice,
    FastPairScanner,
    WhisperPairExploit,
    WhisperPairTester,
)

logger = structlog.get_logger(__name__)


@dataclass
class BLEModuleConfig:
    """Configuration for BLE module."""
    enabled: bool = True
    adapter: str = "hci0"
    scan_interval: int = 30
    fast_pair_scan_enabled: bool = True
    whisperpair_test_enabled: bool = True
    whisperpair_exploit_enabled: bool = False  # Requires explicit opt-in
    account_key_flood_enabled: bool = False
    hfp_audio_enabled: bool = False
    device_quirks_db: str = "/etc/urban-hs/device_quirks.json"


class BLEPlugin:
    """
    BLE Module Plugin for Urban Hack Sentinel.
    
    Provides:
    - Fast Pair device discovery (Service UUID 0xFE2C)
    - WhisperPair (CVE-2025-36911) vulnerability testing
    - WhisperPair exploit chain (KBP bypass -> BR/EDR bonding -> HFP audio)
    - Device quirks database for exploit reliability
    """

    def __init__(self, config: Optional[BLEModuleConfig] = None):
        self.config = config or BLEModuleConfig()
        self.scanner: Optional[FastPairScanner] = None
        self.tester: Optional[WhisperPairTester] = None
        self.exploit: Optional[WhisperPairExploit] = None
        self._running = False
        self._scan_task: Optional[asyncio.Task] = None
        self._attack_semaphore = asyncio.Semaphore(2)  # Max 2 concurrent BLE attacks

    async def initialize(self) -> None:
        """Initialize BLE module components."""
        logger.info("Initializing BLE plugin", adapter=self.config.adapter)
        
        self.scanner = FastPairScanner(
            adapter=self.config.adapter,
        )
        
        self.tester = WhisperPairTester(adapter=self.config.adapter)
        self.exploit = WhisperPairExploit(adapter=self.config.adapter)
        
        logger.info("BLE plugin initialized", adapter=self.config.adapter)

    async def start(self) -> None:
        """Start the BLE module (continuous scanning)."""
        if self._running:
            return
        
        self._running = True
        
        # Start continuous scanning if enabled
        if self.config.fast_pair_scan_enabled:
            self._scan_task = asyncio.create_task(self._continuous_scan())
        
        # Subscribe to events
        bus = get_event_bus()
        bus.subscribe(BLEEventHandler(self))
        
        logger.info("BLE module started")

    async def stop(self) -> None:
        """Stop the BLE module."""
        self._running = False
        
        if self._scan_task:
            self._scan_task.cancel()
            try:
                await self._scan_task
            except asyncio.CancelledError:
                pass
        
        if self.scanner:
            await self.scanner.stop()
        
        logger.info("BLE module stopped")

    async def _continuous_scan(self) -> None:
        """Continuous Fast Pair scanning loop."""
        while self._running:
            try:
                if self.scanner:
                    await self.scanner.start(scan_all=False)
                    await asyncio.sleep(self.config.scan_interval)
                    await self.scanner.stop()
                    
                    # Publish discovered devices
                    devices = self.scanner.get_fast_pair_devices()
                    if devices:
                        bus = get_event_bus()
                        await get_event_bus().publish(Event(
                            type="ble.devices_updated",
                            payload={"devices": [d.to_dict() for d in devices]},
                            source="ble_scanner",
                        ))
                        
                        # Save to storage
                        await self._save_devices(devices)
                
            except Exception as e:
                logger.error("BLE scan error", error=str(e))
            
            await asyncio.sleep(self.config.scan_interval)

    async def _save_devices(self, devices: List[BLEDevice]) -> None:
        """Save discovered devices to storage."""
        storage = get_storage()
        for device in devices:
            await storage.upsert_device({
                "id": f"ble_{device.address.replace(':', '_')}",
                "first_seen": device.last_seen,
                "last_seen": device.last_seen,
                "type": "ble_device",
                "mac": device.address,
                "vendor": None,
                "labels": ["ble", "fast_pair"] if device.is_fast_pair else ["ble"],
                "meta": device.to_dict(),
            })

    async def test_vulnerability(
        self,
        address: str,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, Any]:
        """Test a device for WhisperPair vulnerability."""
        if not self.config.whisperpair_test_enabled:
            return {"status": "disabled", "error": "WhisperPair testing disabled in config"}
        
        if not self.tester:
            self.tester = WhisperPairTester(adapter=self.config.adapter)
        
        def progress_cb(msg: str):
            if progress_callback:
                progress_callback(msg)
        
        return await self.tester.test_device(address)


# Event handler for BLE events
class BLEEventHandler(EventHandler):
    """Event handler for BLE module events."""

    def __init__(self, plugin: "BLEPlugin"):
        self.plugin = plugin

    @property
    def event_types(self) -> set[str]:
        return {"config.loaded", "config.reloaded", "ble.scan_request", "ble.test_request", "ble.exploit_request"}

    async def handle(self, event: Event) -> None:
        if event.type == "config.loaded" or event.type == "config.reloaded":
            await self._update_config(event.payload)
        elif event.type == "ble.scan_request":
            await self._handle_scan_request(event)
        elif event.type == "ble.test_request":
            await self._handle_test_request(event)
        elif event.type == "ble.exploit_request":
            await self._handle_exploit_request(event)

    async def _update_config(self, config_data: Dict[str, Any]) -> None:
        """Update plugin configuration from config payload."""
        ble_config = config_data.get("ble", {})
        for key, value in ble_config.items():
            if hasattr(self.plugin.config, key):
                setattr(self.plugin.config, key, value)

    async def _handle_scan_request(self, event: Event) -> None:
        """Handle scan request event."""
        payload = event.payload
        duration = payload.get("duration", 30)
        
        # For now, just do a single scan
        if self.plugin.scanner:
            await self.plugin.scanner.start(scan_all=payload.get("scan_all", False))
            await asyncio.sleep(duration)
            await self.plugin.scanner.stop()
            
            networks = self.plugin.scanner.get_devices()
            
            bus = get_event_bus()
            await bus.publish(Event(
                type="ble.scan_complete",
                payload={"devices": [n.to_dict() for n in networks]},
                source="ble.plugin",
                correlation_id=event.correlation_id,
            ))

    async def _handle_test_request(self, event: Event) -> None:
        """Handle vulnerability test request."""
        payload = event.payload
        address = payload.get("address")
        
        if not address:
            return
        
        result = await self.plugin.test_vulnerability(address)
        
        bus = get_event_bus()
        await bus.publish(Event(
            type="ble.test_complete",
            payload={"result": result},
            source="ble.plugin",
            correlation_id=event.correlation_id,
        ))

    async def _handle_exploit_request(self, event: Event) -> None:
        """Handle exploit request (requires explicit enable)."""
        if not self.plugin.config.whisperpair_exploit_enabled:
            bus = get_event_bus()
            await bus.publish(Event(
                type="ble.exploit_failed",
                payload={"error": "Exploit not enabled in config"},
                source="ble.plugin",
                correlation_id=event.correlation_id,
            ))
            return
        
        # TODO: Implement full exploit chain
        payload = event.payload
        address = payload.get("address")

        if not address:
            return

        # Session-scope guard rail (same shared scope as the REST path).
        try:
            get_active_scope().validate(address, "ble")
        except PermissionError as exc:
            bus = get_event_bus()
            await bus.publish(Event(
                type="ble.attack_denied",
                payload={"address": address, "reason": str(exc)},
                source="ble.plugin",
                correlation_id=event.correlation_id,
            ))
            return

        result = {"status": "not_implemented", "message": "Full exploit chain requires BlueZ D-Bus integration"}
        
        bus = get_event_bus()
        await bus.publish(Event(
            type="ble.exploit_complete",
            payload={"result": result},
            source="ble.plugin",
            correlation_id=event.correlation_id,
        ))


# Plugin entry point
async def create_ble_plugin(config: Optional[BLEModuleConfig] = None) -> "BLEPlugin":
    """Factory function to create BLE plugin."""
    plugin = BLEPlugin(config)
    await plugin.initialize()
    return plugin


# Module exports
__all__ = [
    "BLEPlugin",
    "BLEModuleConfig",
    "BLEEventHandler",
    "create_ble_plugin",
]