"""
Shared types for the HAL layer.

These types are used by both HAL backends and module implementations,
eliminating the dependency inversion where HAL imported from Modules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


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
            "device_type": self.device_type.value if isinstance(self.device_type, BLEDeviceType) else self.device_type,
            "fast_pair_model_id": self.fast_pair_model_id,
            "fast_pair_in_pairing_mode": self.fast_pair_in_pairing_mode,
            "has_account_key_filter": self.has_account_key_filter,
            "last_seen": self.last_seen,
            "gps_lat": self.gps_lat,
            "gps_lon": self.gps_lon,
            "metadata": self.metadata,
            "service_uuids": self.service_uuids,
        }
