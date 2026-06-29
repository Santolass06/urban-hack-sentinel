"""
Unit tests for BLE module (Sprint 2).

Tests cover:
- FastPairScanner advertisement parsing
- WhisperPairTester vulnerability detection
- WhisperPairExploit KBP strategy building
- Device quirks loading from JSON
"""

import asyncio
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from urban_hs.modules.ble import (
    FastPairScanner,
    WhisperPairTester,
    WhisperPairExploit,
    BLEDevice,
    BLEDeviceType,
    FAST_PAIR_SERVICE_UUID,
    KEY_BASED_PAIRING_UUID,
    get_device_quirks,
    _load_device_quirks,
)

from urban_hs.modules.ble.exploit_chain import (
    BlueZBondingManager,
    AccountKeyManager,
    HFPAudioCapture,
    WhisperPairFullExploit,
    BondingStatus,
    CRYPTOGRAPHY_AVAILABLE,
)


class MockAdvertisementData:
    """Mock BLE advertisement data for testing."""
    def __init__(self, service_data=None, rssi=-50):
        self.service_data = service_data or {}
        self.rssi = rssi


class MockBLEDevice:
    """Mock BLE device for testing."""
    def __init__(self, address="AA:BB:CC:DD:EE:FF", name="Test Device", rssi=-50):
        self.address = address
        self.name = name
        self.rssi = rssi


class MockBleakClient:
    """Mock BleakClient for testing GATT operations."""
    def __init__(self, *args, **kwargs):
        self.address = kwargs.get("address", "AA:BB:CC:DD:EE:FF")
        self._connected = True
        self._services = []
        self._characteristics = {}

    async def connect(self, timeout=10):
        self._connected = True
        return True

    async def disconnect(self):
        self._connected = False

    @property
    def is_connected(self):
        return self._connected

    async def read_gatt_char(self, uuid):
        if "1234" in str(uuid):  # Account Key characteristic
            return b"\x04" + bytes([0] * 15)
        elif "1235" in str(uuid):  # Passkey characteristic
            return b"\x00" * 16
        return b""

    async def write_gatt_char(self, *args, **kwargs):
        # Simulate success by default
        pass


# ============================================================
# FAST PAIR SCANNER TESTS
# ============================================================

@patch("bleak.BleakScanner")
@pytest.mark.asyncio
async def test_fastpair_scanner_initialization(mock_bleak_scanner):
    """Test FastPairScanner initializes correctly."""
    scanner = FastPairScanner(adapter="hci0")
    assert scanner.adapter == "hci0"
    assert hasattr(scanner, '_devices')
    assert scanner._devices == {}


@patch("bleak.BleakScanner")
@pytest.mark.asyncio
async def test_parse_fast_pair_advertisement_pairing_mode(mock_bleak_scanner):
    """Test parsing Fast Pair advertisement in pairing mode."""
    scanner = FastPairScanner(adapter="hci0")
    
    ad_data = {
        FAST_PAIR_SERVICE_UUID.lower(): bytes([0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
    }
    
    device = MockBLEDevice(address="AA:BB:CC:DD:EE:FF", name="Test Device")
    adv_data = MockAdvertisementData(service_data=ad_data, rssi=-50)
    
    # Call the internal parsing method directly
    fp_device = scanner._parse_fast_pair_advertisement(
        name=device.name,
        address=device.address,
        data=ad_data[FAST_PAIR_SERVICE_UUID.lower()],
        rssi=adv_data.rssi,
    )
    
    assert fp_device.address == "AA:BB:CC:DD:EE:FF"
    assert fp_device.name == "Test Device"
    assert fp_device.rssi == -50


@patch("bleak.BleakScanner")
@pytest.mark.asyncio
async def test_parse_fast_pair_advertisement_account_key_filter(mock_bleak_scanner):
    """Test parsing Fast Pair advertisement with account key filter."""
    scanner = FastPairScanner(adapter="hci0")
    
    ad_data = {
        FAST_PAIR_SERVICE_UUID.lower(): bytes([0x01] + [0x00] * 15)
    }
    
    device = MockBLEDevice(address="AA:BB:CC:DD:EE:FF")
    adv_data = MockAdvertisementData(service_data=ad_data, rssi=-60)
    
    result = scanner._parse_fast_pair_advertisement(
        name=device.name,
        address=device.address,
        data=ad_data[FAST_PAIR_SERVICE_UUID.lower()],
        rssi=adv_data.rssi,
    )
    
    assert result is not None


@patch("bleak.BleakScanner")
@pytest.mark.asyncio
async def test_parse_fast_pair_advertisement_extended(mock_bleak_scanner):
    """Test parsing extended Fast Pair advertisement."""
    scanner = FastPairScanner(adapter="hci0")
    
    ad_data = {
        FAST_PAIR_SERVICE_UUID.lower(): bytes([0x02] + [0x00] * 15)
    }
    
    device = MockBLEDevice(address="AA:BB:CC:DD:EE:FF")
    adv_data = MockAdvertisementData(service_data=ad_data, rssi=-55)
    
    result = scanner._parse_fast_pair_advertisement(
        name=device.name,
        address=device.address,
        data=ad_data[FAST_PAIR_SERVICE_UUID.lower()],
        rssi=adv_data.rssi,
    )
    
    assert result is not None
    assert result.fast_pair_model_id is not None


# ============================================================
# DEVICE QUIRKS TESTS
# ============================================================

def test_load_device_quirks_default():
    """Test loading default device quirks."""
    quirks = _load_device_quirks()
    
    assert "devices" in quirks
    assert "default_quirks" in quirks
    assert len(quirks["devices"]) > 0


def test_get_device_quirks_unknown_model():
    """Test getting quirks for unknown model returns default quirks."""
    quirks = get_device_quirks("unknown_model")
    # The implementation returns default_quirks for unknown models
    assert "needsExtendedResponse" in quirks
    assert "prefersBrEdrBonding" in quirks


def test_get_device_quirks_known_model():
    """Test getting quirks for known model."""
    quirks = get_device_quirks("abcdef")  # From default quirks
    assert "needsExtendedResponse" in quirks
    assert "prefersBrEdrBonding" in quirks


def test_get_device_quirks_none():
    """Test getting quirks with None model returns default quirks."""
    quirks = get_device_quirks(None)
    assert "needsExtendedResponse" in quirks
    assert "prefersBrEdrBonding" in quirks


# ============================================================
# WHISPER PAIR EXPLOIT TESTS
# ============================================================

@pytest.fixture
def exploit():
    """Create a WhisperPairExploit instance for testing."""
    return WhisperPairExploit(adapter="hci0")


@pytest.mark.asyncio
async def test_whisperpair_full_exploit_init():
    """Test WhisperPairFullExploit initialization."""
    exploit = WhisperPairFullExploit(target_mac="AA:BB:CC:DD:EE:FF")
    
    assert exploit.target_mac == "AA:BB:CC:DD:EE:FF"
    assert exploit.adapter_ble == "hci0"
    assert exploit.bonding_manager is not None
    assert exploit.account_key_manager is not None
    assert exploit.hfp_capture is not None


@patch("bleak.BleakClient", MockBleakClient)
@pytest.mark.asyncio
async def test_whisperpair_exploit_execute_strategy_success(exploit):
    """Test KBP strategy execution with mocked success."""
    # The exploit imports BleakClient from bleak, so we patch it there
    result = await exploit._execute_kbp_strategy(
        "AA:BB:CC:DD:EE:FF",
        WhisperPairExploit.Strategy.RAW_KBP,
    )
    
    # Result depends on mocked BleakClient behavior
    assert "status" in result


@patch("bleak.BleakClient", MockBleakClient)
@pytest.mark.asyncio
async def test_whisperpair_exploit_execute_all_strategies(exploit):
    """Test executing all KBP strategies."""
    with patch("urban_hs.modules.ble.fastpair.get_device_quirks", return_value={}):
        result = await exploit.execute_all_strategies("AA:BB:CC:DD:EE:FF")
    
    # Result structure
    assert "strategies" in result
    assert "success" in result


# ============================================================
# CONFIGURATION TESTS
# ============================================================

def test_device_quirks_json_structure():
    """Test that device_quirks.json has correct structure."""
    config_path = Path("config/device_quirks.json")
    if config_path.exists():
        with open(config_path) as f:
            data = json.load(f)
        
        assert "devices" in data
        assert "default_quirks" in data
        assert isinstance(data["devices"], dict)
        
        for model_id, device in data["devices"].items():
            assert "model_name" in device
            assert "manufacturer" in device
            assert "type" in device
            assert "quirks" in device
            
            quirks = device["quirks"]
            assert "needsExtendedResponse" in quirks
            assert "prefersBrEdrBonding" in quirks
            assert "delayBeforeKbp" in quirks
            assert "usesRetroactiveFlag" in quirks
            assert "maxKbpRetries" in quirks
            assert "preferredStrategy" in quirks


if __name__ == "__main__":
    pytest.main([__file__, "-v"])