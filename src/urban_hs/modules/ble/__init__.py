"""
BLE Module - Fast Pair, WhisperPair, and Bluetooth LE auditing.
"""

from urban_hs.modules.ble.exploit_chain import (
    AccountKeyManager,
    BlueZBondingManager,
    BondedDevice,
    BondingStatus,
    HFPAudioCapture,
    WhisperPairFullExploit,
)
from urban_hs.modules.ble.fastpair import (
    ACCOUNT_KEY_UUID,
    DEVICE_QUIRKS,
    FAST_PAIR_SERVICE_UUID,
    KEY_BASED_PAIRING_UUID,
    MODEL_ID_UUID,
    PASSKEY_UUID,
    BLEDevice,
    BLEDeviceType,
    FastPairScanner,
    WhisperPairExploit,
    WhisperPairTester,
    _load_device_quirks,
    get_device_quirks,
)

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
]