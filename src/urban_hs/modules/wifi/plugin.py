"""
WiFi Module Plugin - Integrates WiFi scanning and attacks into the core system.
"""

import asyncio
import structlog
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable, Set

from urban_hs.core import get_event_bus, Event, get_config, get_storage, get_process_manager
from urban_hs.core.event_bus import EventHandler, Event
from urban_hs.modules.wifi.scanner import WiFiScanner, NetworkInfo, ScanStrategy, CHANNELS_2GHZ, CHANNELS_5GHZ
from urban_hs.modules.wifi.attacks import (
    HandshakeAttack,
    PMKIDAttack,
    WPSPixieAttack,
    WPSPinAttack,
    DeauthAttack,
    AttackResult,
    AttackStatus,
)
from urban_hs.modules.wifi.managers import HandshakeManager, MACChanger, GeoMapper

logger = structlog.get_logger(__name__)


@dataclass
class WiFiModuleConfig:
    """Configuration for WiFi module."""
    enabled: bool = True
    interface: str = "wlan0"
    scan_strategy: str = "passive_only"
    scan_interval: int = 30
    channels_2ghz: List[int] = field(default_factory=lambda: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13])
    channels_5ghz: List[int] = field(default_factory=lambda: [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144])
    channels_6ghz: List[int] = field(default_factory=list)
    attack_timeout: int = 60
    handshake_timeout: int = 60
    pmkid_timeout: int = 60
    wps_timeout: int = 120
    deauth_count: int = 10
    enable_active_attacks: bool = False
    mac_randomize_interval: int = 0


class WiFiPlugin:
    """
    WiFi Module Plugin for Urban Hack Sentinel.

    Provides:
    - WiFi network discovery (passive/active)
    - Handshake/PMKID capture
    - WPS attacks (Pixie Dust, PIN dictionary)
    - Deauthentication attacks
    - MAC randomization
    - GPS wardriving integration
    - Handshake management and cracking
    """

    def __init__(self, config: Optional[WiFiModuleConfig] = None):
        self.config = config or WiFiModuleConfig()
        self.scanner: Optional[WiFiScanner] = None
        self.handshake_mgr: Optional[HandshakeManager] = None
        self.mac_changer: Optional[MACChanger] = None
        self.geo_mapper: Optional[GeoMapper] = None
        self._running = False
        self._scan_task: Optional[asyncio.Task] = None
        self._handshake_attack: Optional[HandshakeAttack] = None
        self._pmkid_attack: Optional[PMKIDAttack] = None
        self._wps_pixie_attack: Optional[WPSPixieAttack] = None
        self._wps_pin_attack: Optional[WPSPinAttack] = None
        self._deauth_attack: Optional[DeauthAttack] = None
        self._attack_semaphore = asyncio.Semaphore(3)

    async def initialize(self) -> None:
        """Initialize WiFi module components."""
        logger.info("Initializing WiFi plugin", interface=self.config.interface)

        # Determine scan strategy
        strategy_map = {
            "passive_only": ScanStrategy.PASSIVE_ONLY,
            "mode_switch": ScanStrategy.MODE_SWITCH,
            "direct": ScanStrategy.DIRECT,
        }
        strategy = strategy_map.get(self.config.scan_strategy, ScanStrategy.PASSIVE_ONLY)

        # Initialize components
        self.scanner = WiFiScanner(
            interface=self.config.interface,
            strategy=strategy,
            output_dir=get_config().storage.resolve_wifi_scans_dir(),
        )

        self.handshake_mgr = HandshakeManager()
        self.mac_changer = MACChanger(self.config.interface)
        self.geo_mapper = GeoMapper()

        # Save original MAC
        self.mac_changer.save_original_mac()

        # Initialize attack classes
        self._handshake_attack = HandshakeAttack(
            interface=self.config.interface,
            attack_timeout=self.config.handshake_timeout,
            deauth_count=self.config.deauth_count,
        )
        self._pmkid_attack = PMKIDAttack(
            interface=self.config.interface,
            attack_timeout=self.config.pmkid_timeout,
        )
        self._wps_pixie_attack = WPSPixieAttack(
            interface=self.config.interface,
            attack_timeout=self.config.wps_timeout,
        )
        self._wps_pin_attack = WPSPinAttack(
            interface=self.config.interface,
            attack_timeout=self.config.wps_timeout,
        )
        self._deauth_attack = DeauthAttack(
            interface=self.config.interface,
            attack_timeout=self.config.attack_timeout,
        )

        logger.info("WiFi plugin initialized", interface=self.config.interface)

    async def start(self) -> None:
        """Start the WiFi module (continuous scanning)."""
        if self._running:
            return

        self._running = True

        # Start GPS
        await self.geo_mapper.start()

        # Start MAC randomization if configured
        if self.config.mac_randomize_interval > 0:
            asyncio.create_task(self._mac_randomization_loop())

        # Start continuous scanning
        self._scan_task = asyncio.create_task(self._continuous_scan())

        # Subscribe to events
        bus = get_event_bus()
        bus.subscribe(WiFiEventHandler(self))

        logger.info("WiFi module started")

    async def stop(self) -> None:
        """Stop the WiFi module."""
        self._running = False

        if self._scan_task:
            self._scan_task.cancel()
            try:
                await self._scan_task
            except asyncio.CancelledError:
                pass

        await self.geo_mapper.stop()

        # Restore original MAC
        self.mac_changer.restore_original_mac()

        logger.info("WiFi module stopped")

    async def _continuous_scan(self) -> None:
        """Continuous scanning loop."""
        while self._running:
            try:
                networks = await self.scanner.manager.scan(
                    channels=self._get_all_channels(),
                    duration=self.config.scan_interval,
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
                await self._save_networks(networks)

                # Publish event
                bus = get_event_bus()
                await bus.publish(Event(
                    type="wifi.networks_updated",
                    payload={"networks": [n.to_dict() for n in networks]},
                    source="wifi_scanner",
                ))

            except Exception as e:
                logger.error("Scan error", error=str(e))

            await asyncio.sleep(self.config.scan_interval)

    def _get_all_channels(self) -> List[int]:
        """Get all configured channels."""
        channels = []
        channels.extend(self.config.channels_2ghz)
        channels.extend(self.config.channels_5ghz)
        channels.extend(self.config.channels_6ghz)
        return channels

    async def _save_networks(self, networks: List[NetworkInfo]) -> None:
        """Save networks to storage."""
        storage = get_storage()
        for net in networks:
            # Store as device
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

    async def _mac_randomization_loop(self) -> None:
        """Periodically randomize MAC address."""
        interval = self.config.mac_randomize_interval
        while self._running:
            await asyncio.sleep(interval)
            if self._running and self.mac_changer:
                new_mac = self.mac_changer.randomize_mac("random")
                if new_mac:
                    logger.info("MAC randomized", new_mac=new_mac)

    # Attack execution methods
    async def execute_handshake_attack(
        self,
        bssid: str,
        essid: Optional[str] = None,
        channel: int = 1,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> "AttackResult":
        """Execute handshake capture attack."""
        async with self._attack_semaphore:
            return await self._handshake_attack.execute(
                target_bssid=bssid,
                target_essid=essid,
                channel=channel,
                callback=progress_callback,
            )

    async def execute_pmkid_attack(
        self,
        bssid: str,
        essid: Optional[str] = None,
        channel: int = 1,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> "AttackResult":
        """Execute PMKID attack."""
        async with self._attack_semaphore:
            return await self._pmkid_attack.execute(
                target_bssid=bssid,
                target_essid=essid,
                channel=channel,
                callback=progress_callback,
            )

    async def execute_wps_pixie_attack(
        self,
        bssid: str,
        essid: Optional[str] = None,
        channel: int = 1,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> "AttackResult":
        """Execute WPS Pixie Dust attack."""
        async with self._attack_semaphore:
            return await self._wps_pixie_attack.execute(
                target_bssid=bssid,
                target_essid=essid,
                channel=channel,
                callback=progress_callback,
            )

    async def execute_wps_pin_attack(
        self,
        bssid: str,
        essid: Optional[str] = None,
        channel: int = 1,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> "AttackResult":
        """Execute WPS PIN dictionary attack."""
        async with self._attack_semaphore:
            return await self._wps_pin_attack.execute(
                target_bssid=bssid,
                target_essid=essid,
                channel=channel,
                callback=progress_callback,
            )

    async def execute_deauth(
        self,
        bssid: str,
        essid: Optional[str] = None,
        channel: int = 1,
        client_mac: Optional[str] = None,
        count: int = 10,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> "AttackResult":
        """Execute deauthentication attack."""
        if not self.config.enable_active_attacks:
            raise RuntimeError("Active attacks disabled in configuration")

        async with self._attack_semaphore:
            return await self._deauth_attack.execute(
                target_bssid=bssid,
                target_essid=essid,
                channel=channel,
                client_mac=client_mac,
                count=count,
                callback=progress_callback,
            )

    def get_known_networks(self) -> List[NetworkInfo]:
        """Get all known networks."""
        if self.scanner:
            return self.scanner.get_known_networks()
        return []

    def get_handshake_manager(self) -> HandshakeManager:
        return self.handshake_mgr

    def get_mac_changer(self) -> MACChanger:
        return self.mac_changer

    def get_geo_mapper(self) -> GeoMapper:
        return self.geo_mapper


class WiFiEventHandler(EventHandler):
    """Event handler for WiFi module events."""

    def __init__(self, plugin: "WiFiPlugin"):
        self.plugin = plugin

    @property
    def event_types(self) -> Set[str]:
        return {"config.loaded", "config.reloaded", "wifi.scan_request", "wifi.attack_request"}

    async def handle(self, event: Event) -> None:
        if event.type == "config.loaded" or event.type == "config.reloaded":
            await self._update_config(event.payload)
        elif event.type == "wifi.scan_request":
            await self._handle_scan_request(event)
        elif event.type == "wifi.attack_request":
            await self._handle_attack_request(event)

    async def _update_config(self, config_data: Dict[str, Any]) -> None:
        """Update plugin configuration from config payload."""
        wifi_config = config_data.get("wifi", {})
        for key, value in wifi_config.items():
            if hasattr(self.plugin.config, key):
                setattr(self.plugin.config, key, value)

    async def _handle_scan_request(self, event: Event) -> None:
        """Handle scan request event."""
        payload = event.payload
        channels = payload.get("channels")
        duration = payload.get("duration", 30)

        networks = await self.plugin.scanner.manager.scan(
            channels=channels,
            duration=duration,
        )

        bus = get_event_bus()
        await bus.publish(Event(
            type="wifi.scan_complete",
            payload={"networks": [n.to_dict() for n in networks]},
            source="wifi.plugin",
            correlation_id=event.correlation_id,
        ))

    async def _handle_attack_request(self, event: Event) -> None:
        """Handle attack request event."""
        payload = event.payload
        attack_type = payload.get("type")
        bssid = payload.get("bssid")

        if not bssid:
            return

        progress_updates = []

        def progress_cb(msg: str):
            progress_updates.append(msg)

        try:
            result = None

            if attack_type == "handshake":
                result = await self.plugin.execute_handshake_attack(
                    bssid=bssid,
                    essid=payload.get("essid"),
                    channel=payload.get("channel", 1),
                    progress_callback=lambda m: progress_updates.append(m),
                )
            elif attack_type == "pmkid":
                result = await self.plugin.execute_pmkid_attack(
                    bssid=bssid,
                    essid=payload.get("essid"),
                    channel=payload.get("channel", 1),
                    progress_callback=lambda m: progress_updates.append(m),
                )
            elif attack_type == "wps_pixie":
                result = await self.plugin.execute_wps_pixie_attack(
                    bssid=bssid,
                    essid=payload.get("essid"),
                    channel=payload.get("channel", 1),
                    progress_callback=lambda m: progress_updates.append(m),
                )
            elif attack_type == "wps_pin":
                result = await self.plugin.execute_wps_pin_attack(
                    bssid=bssid,
                    essid=payload.get("essid"),
                    channel=payload.get("channel", 1),
                    progress_callback=lambda m: progress_updates.append(m),
                )
            elif attack_type == "deauth":
                result = await self.plugin.execute_deauth(
                    bssid=bssid,
                    essid=payload.get("essid"),
                    channel=payload.get("channel", 1),
                    client_mac=payload.get("client_mac"),
                    count=payload.get("count", 10),
                    progress_callback=lambda m: progress_updates.append(m),
                )

            bus = get_event_bus()
            await bus.publish(Event(
                type="wifi.attack_complete",
                payload={
                    "result": result.to_dict() if result else None,
                    "progress": progress_updates,
                },
                source="wifi.plugin",
                correlation_id=event.correlation_id,
            ))

        except Exception as e:
            logger.error("Attack failed", error=str(e))
            bus = get_event_bus()
            await bus.publish(Event(
                type="wifi.attack_failed",
                payload={"error": str(e)},
                source="wifi.plugin",
                correlation_id=event.correlation_id,
            ))


# Plugin entry point
async def create_wifi_plugin(config: Optional[WiFiModuleConfig] = None) -> "WiFiPlugin":
    """Factory function to create WiFi plugin."""
    plugin = WiFiPlugin(config)
    await plugin.initialize()
    return plugin


# Module exports
__all__ = [
    "WiFiPlugin",
    "WiFiModuleConfig",
    "WiFiEventHandler",
    "create_wifi_plugin",
]