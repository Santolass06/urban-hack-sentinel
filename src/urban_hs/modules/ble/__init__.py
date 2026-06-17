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
    DEVICE_QUIRKS,
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
    "DEVICE_QUIRKS",
]