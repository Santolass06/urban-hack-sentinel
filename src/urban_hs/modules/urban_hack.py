"""
Urban Hack Sentinel v3 - Main Plugin
Unified plugin managing WiFi, BLE, and future modules.
"""

import asyncio
import structlog
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable, Set

from urban_hs.core import get_event_bus, Event, get_config, get_storage, get_process_manager
from urban_hs.core.event_bus import EventHandler, Event
from urban_hs.modules.wifi import (
    WiFiScanner, NetworkInfo, ScanStrategy, CHANNELS_2GHZ, CHANNELS_5GHZ,
    HandshakeAttack, PMKIDAttack, WPSPixieAttack, WPSPinAttack, DeauthAttack,
    AttackResult, AttackStatus,
    HandshakeManager, MACChanger, GeoMapper,
)
from urban_hs.modules.ble import (
    FastPairScanner, WhisperPairTester, WhisperPairExploit,
    BLEDevice, BLEDeviceType,
)

logger = structlog.get_logger(__name__)


@dataclass
class UrbanHackConfig:
    """Master configuration for Urban Hack Sentinel."""
    # WiFi
    wifi_enabled: bool = True
    wifi_interface: str = "wlan0"
    wifi_scan_strategy: str = "passive_only"
    wifi_scan_interval: int = 30
    wifi_channels_2ghz: List[int] = field(default_factory=lambda: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13])
    wifi_channels_5ghz: List[int] = field(default_factory=lambda: [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144])
    wifi_channels_6ghz: List[int] = field(default_factory=list)
    wifi_attack_timeout: int = 60
    wifi_handshake_timeout: int = 60
    wifi_pmkid_timeout: int = 60
    wifi_wps_timeout: int = 120
    wifi_deauth_count: int = 10
    wifi_enable_active_attacks: bool = False
    wifi_mac_randomize_interval: int = 0

    # BLE
    ble_enabled: bool = True
    ble_adapter: str = "hci0"
    ble_scan_interval: int = 30
    ble_fast_pair_scan_enabled: bool = True
    ble_whisperpair_test_enabled: bool = True
    ble_whisperpair_exploit_enabled: bool = False
    ble_account_key_flood_enabled: bool = False
    ble_hfp_audio_enabled: bool = False

    # MAC
    mac_randomize_interval: int = 0

    # GPS
    gpsd_host: str = "localhost"
    gpsd_port: int = 2947

    # Core
    debug: bool = False
    dry_run: bool = False


class UrbanHackPlugin:
    """
    Main Urban Hack Sentinel Plugin.
    
    Manages all modules:
    - WiFi: scanning, handshake/PMKID/WPS/deauth attacks
    - BLE: Fast Pair scanning, WhisperPair vulnerability/exploit
    - Network: Nmap, Nuclei, camera discovery
    - Metasploit: RPC integration
    - HID/USB: DuckyScript, USB gadgets
    """

    def __init__(self, config: Optional[UrbanHackConfig] = None):
        self.config = config or UrbanHackConfig()
        
        # WiFi components
        self.wifi_scanner = None
        self.wifi_handshake_mgr = None
        self.wifi_mac_changer = None
        self.wifi_geo_mapper = None
        self._handshake_attack = None
        self._pmkid_attack = None
        self._wps_pixie_attack = None
        self._wps_pin_attack = None
        self._deauth_attack = None
        
        # BLE components
        self.ble_scanner = None
        self.ble_tester = None
        self.ble_exploit = None
        
        # Shared
        self.geo_mapper = None
        self.handshake_mgr = None
        self.mac_changer = None
        self.geo_mapper = None
        
        self._running = False
        self._wifi_scan_task = None
        self._ble_scan_task = None
        self._attack_semaphore = asyncio.Semaphore(3)

    async def initialize(self) -> None:
        """Initialize all plugin components."""
        logger.info("Initializing Urban Hack Sentinel plugin")

        # Initialize WiFi components
        if self.config.wifi_enabled:
            strategy_map = {
                "passive_only": ScanStrategy.PASSIVE_ONLY,
                "mode_switch": ScanStrategy.MODE_SWITCH,
                "direct": ScanStrategy.DIRECT,
            }
            strategy = strategy_map.get(self.config.wifi_scan_strategy, ScanStrategy.PASSIVE_ONLY)
            
            self.wifi_scanner = WiFiScanner(
                interface=self.config.wifi_interface,
                strategy=strategy,
                output_dir="/var/log/urban-hs/wifi_scans",
            )
            self.handshake_mgr = HandshakeManager()
            self.wifi_mac_changer = MACChanger(self.config.wifi_interface)
            self.wifi_geo_mapper = GeoMapper()
            self.wifi_mac_changer.save_original_mac()

            self._handshake_attack = HandshakeAttack(
                interface=self.config.wifi_interface,
                attack_timeout=self.config.wifi_handshake_timeout,
                deauth_count=self.config.wifi_deauth_count,
            )
            self._pmkid_attack = PMKIDAttack(
                interface=self.config.wifi_interface,
                attack_timeout=self.config.wifi_pmkid_timeout,
            )
            self._wps_pixie_attack = WPSPixieAttack(
                interface=self.config.wifi_interface,
                attack_timeout=self.config.wifi_wps_timeout,
            )
            self._wps_pin_attack = WPSPinAttack(
                interface=self.config.wifi_interface,
                attack_timeout=self.config.wifi_wps_timeout,
            )
            self._deauth_attack = DeauthAttack(
                interface=self.config.wifi_interface,
                attack_timeout=self.config.wifi_attack_timeout,
            )

        # Initialize BLE components
        if self.config.ble_enabled:
            self.ble_scanner = FastPairScanner(adapter=self.config.ble_adapter)
            self.ble_tester = WhisperPairTester(adapter=self.config.ble_adapter)
            self.exploit = WhisperPairExploit(adapter=self.config.ble_adapter)

        # Shared components
        self.geo_mapper = GeoMapper(gpsd_host=self.config.gpsd_host, gpsd_port=self.config.gpsd_port)
        self.mac_changer = MACChanger(self.config.wifi_interface)
        self.mac_changer.save_original_mac()

        logger.info("Urban Hack Sentinel plugin initialized")

    async def start(self) -> None:
        """Start all enabled modules."""
        if self._running:
            return

        self._running = True

        # Start GPS
        await self.geo_mapper.start()

        # Start MAC randomization if configured
        if self.config.mac_randomize_interval > 0:
            asyncio.create_task(self._mac_randomization_loop())

        # Start WiFi continuous scanning
        if self.config.wifi_enabled:
            self._wifi_scan_task = asyncio.create_task(self._continuous_wifi_scan())

        # Start BLE continuous scanning
        if self.config.ble_enabled and self.config.ble_fast_pair_scan_enabled:
            self._ble_scan_task = asyncio.create_task(self._continuous_ble_scan())

        # Subscribe to events
        bus = get_event_bus()
        bus.subscribe(UrbanHackEventHandler(self))

        logger.info("Urban Hack Sentinel started")

    async def stop(self) -> None:
        """Stop all modules."""
        self._running = False

        if self._wifi_scan_task:
            self._wifi_scan_task.cancel()
            try:
                await self._wifi_scan_task
            except asyncio.CancelledError:
                pass

        if self._ble_scan_task:
            self._ble_scan_task.cancel()
            try:
                await self._ble_scan_task
            except asyncio.CancelledError:
                pass

        if self.ble_scanner:
            await self.ble_scanner.stop()

        await self.geo_mapper.stop()

        # Restore original MAC
        self.mac_changer.restore_original_mac()

        logger.info("Urban Hack Sentinel stopped")

    async def _continuous_wifi_scan(self) -> None:
        """Continuous WiFi scanning loop."""
        while self._running:
            try:
                if self.wifi_scanner:
                    networks = await self.wifi_scanner.manager.scan(
                        channels=self._get_all_wifi_channels(),
                        duration=self.config.wifi_scan_interval,
                    )

                    # Enrich with GPS
                    if self.geo_mapper.is_fixed():
                        pos = self.geo_mapper.get_position()
                        for net in networks:
                            net.gps_lat = pos["lat"]
                            net.gps_lon = pos["lon"]
                            net.gps_alt = pos.get("alt")
                            net.gps_accuracy = pos.get("accuracy")

                    # Save to storage
                    await self._save_wifi_networks(networks)

                    # Publish event
                    bus = get_event_bus()
                    await bus.publish(Event(
                        type="wifi.networks_updated",
                        payload={"networks": [n.to_dict() for n in networks]},
                        source="wifi_scanner",
                    ))

            except Exception as e:
                logger.error("WiFi scan error", error=str(e))

            await asyncio.sleep(self.config.wifi_scan_interval)

    async def _continuous_ble_scan(self) -> None:
        """Continuous BLE scanning loop."""
        while self._running:
            try:
                if self.ble_scanner:
                    await self.ble_scanner.start(scan_all=False)
                    await asyncio.sleep(self.config.ble_scan_interval)
                    await self.ble_scanner.stop()

                    devices = self.ble_scanner.get_fast_pair_devices()
                    if devices:
                        bus = get_event_bus()
                        await bus.publish(Event(
                            type="ble.devices_updated",
                            payload={"devices": [d.to_dict() for d in devices]},
                            source="ble_scanner",
                        ))

                        await self._save_ble_devices(devices)

            except Exception as e:
                logger.error("BLE scan error", error=str(e))

            await asyncio.sleep(self.config.ble_scan_interval)

    def _get_all_wifi_channels(self) -> List[int]:
        channels = []
        channels.extend(self.config.wifi_channels_2ghz)
        channels.extend(self.config.wifi_channels_5ghz)
        channels.extend(self.config.wifi_channels_6ghz)
        return channels

    async def _save_wifi_networks(self, networks: List[NetworkInfo]) -> None:
        storage = get_storage()
        for net in networks:
            await storage.upsert_device({
                "id": f"wifi_{net.bssid.replace(':', '_')}",
                "first_seen": net.last_seen,
                "last_seen": net.last_seen,
                "type": "wifi_ap",
                "mac": net.bssid,
                "vendor": net.vendor,
                "labels": ["wifi", "access_point"],
                "meta": net.to_dict(),
            })

    async def _save_ble_devices(self, devices: List[BLEDevice]) -> None:
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

    async def _mac_randomization_loop(self) -> None:
        interval = self.config.mac_randomize_interval
        while self._running:
            await asyncio.sleep(interval)
            if self._running and self.mac_changer:
                new_mac = self.mac_changer.randomize_mac("random")
                if new_mac:
                    logger.info("MAC randomized", new_mac=new_mac)

    # WiFi Attack execution methods
    async def execute_handshake_attack(
        self,
        bssid: str,
        essid: Optional[str] = None,
        channel: int = 1,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> AttackResult:
        async with self._attack_semaphore:
            if not self._handshake_attack:
                return AttackResult(
                    attack_type="handshake", target_bssid=bssid, target_essid=essid,
                    status=AttackStatus.FAILED, started_at=datetime.utcnow(),
                    error_message="Handshake attack not initialized"
                )
            return await self._handshake_attack.execute(
                target_bssid=bssid, target_essid=essid, channel=channel, callback=progress_callback
            )

    async def execute_pmkid_attack(
        self,
        bssid: str,
        essid: Optional[str] = None,
        channel: int = 1,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> AttackResult:
        async with self._attack_semaphore:
            if not self._pmkid_attack:
                return AttackResult(
                    attack_type="pmkid", target_bssid=bssid, target_essid=essid,
                    status=AttackStatus.FAILED, started_at=datetime.utcnow(),
                    error_message="PMKID attack not initialized"
                )
            return await self._pmkid_attack.execute(
                target_bssid=bssid, target_essid=essid, channel=channel, callback=progress_callback
            )

    async def execute_wps_pixie_attack(
        self,
        bssid: str,
        essid: Optional[str] = None,
        channel: int = 1,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> AttackResult:
        async with self._attack_semaphore:
            if not self._wps_pixie_attack:
                return AttackResult(
                    attack_type="wps_pixie", target_bssid=bssid, target_essid=essid,
                    status=AttackStatus.FAILED, started_at=datetime.utcnow(),
                    error_message="WPS Pixie attack not initialized"
                )
            return await self._wps_pixie_attack.execute(
                target_bssid=bssid, target_essid=essid, channel=channel, callback=progress_callback
            )

    async def execute_wps_pin_attack(
        self,
        bssid: str,
        essid: Optional[str] = None,
        channel: int = 1,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> AttackResult:
        async with self._attack_semaphore:
            if not self._wps_pin_attack:
                return AttackResult(
                    attack_type="wps_pin", target_bssid=bssid, target_essid=essid,
                    status=AttackStatus.FAILED, started_at=datetime.utcnow(),
                    error_message="WPS PIN attack not initialized"
                )
            return await self._wps_pin_attack.execute(
                target_bssid=bssid, target_essid=essid, channel=channel, callback=progress_callback
            )

    async def execute_deauth(
        self,
        bssid: str,
        essid: Optional[str] = None,
        channel: int = 1,
        client_mac: Optional[str] = None,
        count: int = 10,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> AttackResult:
        if not self.config.wifi_enable_active_attacks:
            raise RuntimeError("Active attacks disabled in configuration")

        async with self._attack_semaphore:
            if not self._deauth_attack:
                return AttackResult(
                    attack_type="deauth", target_bssid=bssid, target_essid=essid,
                    status=AttackStatus.FAILED, started_at=datetime.utcnow(),
                    error_message="Deauth attack not initialized"
                )
            return await self._deauth_attack.execute(
                target_bssid=bssid, target_essid=essid, channel=channel,
                client_mac=client_mac, count=count, callback=progress_callback
            )

    async def execute_ble_vuln_test(
        self,
        address: str,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, Any]:
        """Test a BLE device for WhisperPair vulnerability."""
        if not self.config.ble_whisperpair_test_enabled:
            return {"status": "disabled", "error": "WhisperPair testing disabled"}
        
        if not self.ble_tester:
            from urban_hs.modules.ble import WhisperPairTester
            self.ble_tester = WhisperPairTester(adapter=self.config.ble_adapter)

        def progress_cb(msg: str):
            if progress_callback:
                progress_callback(msg)

        return await self.ble_tester.test_device(address)


# Event handler for all events
class UrbanHackEventHandler(EventHandler):
    """Event handler for Urban Hack Sentinel."""

    def __init__(self, plugin: "UrbanHackPlugin"):
        self.plugin = plugin

    @property
    def event_types(self) -> Set[str]:
        return {
            "config.loaded", "config.reloaded",
            "wifi.scan_request", "wifi.attack_request",
            "ble.scan_request", "ble.test_request", "ble.exploit_request",
            "network.scan_request", "camera.discovery_request",
        }

    async def handle(self, event: Event) -> None:
        if event.type in ("config.loaded", "config.reloaded"):
            await self._update_config(event.payload)
        elif event.type == "wifi.scan_request":
            await self._handle_wifi_scan(event)
        elif event.type == "wifi.attack_request":
            await self._handle_wifi_attack(event)
        elif event.type == "ble.scan_request":
            await self._handle_ble_scan(event)
        elif event.type == "ble.test_request":
            await self._handle_ble_test(event)
        elif event.type == "ble.exploit_request":
            await self._handle_ble_exploit(event)

    async def _update_config(self, config_data: Dict[str, Any]) -> None:
        for key, value in config_data.items():
            if hasattr(self.plugin.config, key):
                setattr(self.plugin.config, key, value)

    async def _handle_wifi_scan(self, event: Event) -> None:
        payload = event.payload
        channels = payload.get("channels")
        duration = payload.get("duration", 30)

        networks = await self.plugin.wifi_scanner.manager.scan(
            channels=channels, duration=duration
        )

        bus = get_event_bus()
        await bus.publish(Event(
            type="wifi.scan_complete",
            payload={"networks": [n.to_dict() for n in networks]},
            source="urban_hack.plugin",
            correlation_id=event.correlation_id,
        ))

    async def _handle_wifi_attack(self, event: Event) -> None:
        payload = event.payload
        attack_type = payload.get("type")
        bssid = payload.get("bssid")

        if not bssid:
            return

        progress_updates = []
        def progress_cb(msg: str):
            progress_updates.append(msg)

        result = None
        try:
            if attack_type == "handshake":
                result = await self.plugin.execute_handshake_attack(
                    bssid=bssid, essid=payload.get("essid"),
                    channel=payload.get("channel", 1), progress_callback=lambda m: progress_updates.append(m)
                )
            elif attack_type == "pmkid":
                result = await self.plugin.execute_pmkid_attack(
                    bssid=bssid, essid=payload.get("essid"),
                    channel=payload.get("channel", 1), progress_callback=lambda m: progress_updates.append(m)
                )
            elif attack_type == "wps_pixie":
                result = await self.plugin.execute_wps_pixie_attack(
                    bssid=bssid, essid=payload.get("essid"),
                    channel=payload.get("channel", 1), progress_callback=lambda m: progress_updates.append(m)
                )
            elif attack_type == "wps_pin":
                result = await self.plugin.execute_wps_pin_attack(
                    bssid=bssid, essid=payload.get("essid"),
                    channel=payload.get("channel", 1), progress_callback=lambda m: progress_updates.append(m)
                )
            elif attack_type == "deauth":
                result = await self.plugin.execute_deauth(
                    bssid=bssid, essid=payload.get("essid"),
                    channel=payload.get("channel", 1),
                    client_mac=payload.get("client_mac"),
                    count=payload.get("count", 10),
                    progress_callback=lambda m: progress_updates.append(m)
                )

            bus = get_event_bus()
            await bus.publish(Event(
                type="wifi.attack_complete",
                payload={"result": result.to_dict() if result else None, "progress": progress_updates},
                source="urban_hack.plugin", correlation_id=event.correlation_id,
            ))

        except Exception as e:
            logger.error("WiFi attack failed", error=str(e))
            bus = get_event_bus()
            await bus.publish(Event(
                type="wifi.attack_failed", payload={"error": str(e)},
                source="urban_hack.plugin", correlation_id=event.correlation_id,
            ))

    async def _handle_ble_scan(self, event: Event) -> None:
        payload = event.payload
        duration = payload.get("duration", 30)

        if self.plugin.ble_scanner:
            await self.plugin.ble_scanner.start(scan_all=payload.get("scan_all", False))
            await asyncio.sleep(duration)
            await self.plugin.ble_scanner.stop()

            devices = self.plugin.ble_scanner.get_fast_pair_devices()

            bus = get_event_bus()
            await bus.publish(Event(
                type="ble.scan_complete",
                payload={"devices": [d.to_dict() for d in devices]},
                source="urban_hack.plugin", correlation_id=event.correlation_id,
            ))

    async def _handle_ble_test(self, event: Event) -> None:
        payload = event.payload
        address = payload.get("address")

        if not address:
            return

        result = await self.plugin.execute_ble_vuln_test(address)

        bus = get_event_bus()
        await bus.publish(Event(
            type="ble.test_complete",
            payload={"result": result},
            source="urban_hack.plugin", correlation_id=event.correlation_id,
        ))

    async def _handle_ble_exploit(self, event: Event) -> None:
        if not self.plugin.config.ble_whisperpair_exploit_enabled:
            bus = get_event_bus()
            await bus.publish(Event(
                type="ble.exploit_failed",
                payload={"error": "Exploit not enabled in config"},
                source="urban_hack.plugin", correlation_id=event.correlation_id,
            ))
            return

        # TODO: Full exploit chain
        payload = event.payload
        address = payload.get("address")

        if not address:
            return

        result = {"status": "not_implemented", "message": "Full exploit chain requires BlueZ D-Bus integration"}

        bus = get_event_bus()
        await bus.publish(Event(
            type="ble.exploit_complete",
            payload={"result": result},
            source="urban_hack.plugin", correlation_id=event.correlation_id,
        ))


# Plugin entry point
async def create_urban_hack_plugin(config: Optional[UrbanHackConfig] = None) -> "UrbanHackPlugin":
    """Factory function to create Urban Hack plugin."""
    plugin = UrbanHackPlugin(config)
    await plugin.initialize()
    return plugin


# Module exports
__all__ = [
    "UrbanHackPlugin",
    "UrbanHackConfig",
    "UrbanHackEventHandler",
    "create_urban_hack_plugin",
]