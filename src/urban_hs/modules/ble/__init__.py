"""
BLE Module - Fast Pair, WhisperPair, and Bluetooth LE auditing.
"""

from urban_hs.modules.ble.fastpair import (
    FastPairScanner,
    WhisperPairTester,
    WhisperPairExploit,
    BLEDevice,
    BLEDeviceType,
    FAST_PAIR_SERVICE_UUID,
    MODEL_ID_UUID,
    KEY_BASED_PAIRING_UUID,
    PASSKEY_UUID,
    ACCOUNT_KEY_UUID,
    get_device_quirks,
    _load_device_quirks,
    DEVICE_QUIRKS,
)
from urban_hs.modules.ble.exploit_chain import (
    AccountKeyManager,
    BlueZBondingManager,
    BondedDevice,
    BondingStatus,
    HFPAudioCapture,
    WhisperPairFullExploit,
)
from urban_hs.modules.ble.bettercap import BettercapBLEClient, BettercapBLEDevice

__all__ = [
    "FastPairScanner",
    "WhisperPairTester",
    "WhisperPairExploit",
    "BLEDevice",
    "BLEDeviceType",
    "FAST_PAIR_SERVICE_UUID",
    "MODEL_ID_UUID",
    "KEY_BASED_PAIRING_UUID",
    "PASSKEY_UUID",
    "ACCOUNT_KEY_UUID",
    "get_device_quirks",
    "_load_device_quirks",
    "DEVICE_QUIRKS",
    "BlueZBondingManager",
    "BondedDevice",
    "BondingStatus",
    "AccountKeyManager",
    "HFPAudioCapture",
    "WhisperPairFullExploit",
    "BettercapBLEClient",
    "BettercapBLEDevice",
]