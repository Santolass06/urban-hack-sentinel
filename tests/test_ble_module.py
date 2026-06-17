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
from unittest.mock import AsyncMock, MagicMock, patch, mock_open
from dataclasses import dataclass

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
    BLEDeviceType,
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
    def __init__(self, address, name=None, rssi=-50):
        self.address = address
        self.name = name
        self.rssi = rssi


# --- FastPairScanner Tests ---

def test_fastpair_scanner_initialization():
    """Test FastPairScanner initialization."""
    scanner = FastPairScanner(adapter="hci0")
    assert scanner.adapter == "hci0"
    assert scanner.callback is None
    assert scanner._devices == {}
    assert scanner._running is False


def test_parse_fast_pair_advertisement_pairing_mode():
    """Test parsing Fast Pair advertisement in pairing mode."""
    scanner = FastPairScanner()
    
    # Pairing mode: 3 bytes, bit 7 = 0 (first byte < 0x80)
    # Use 0x21 as first byte (bit 7 = 0, not an account key filter)
    data = bytes.fromhex("21B2C3")  # Model ID with bit 7 = 0
    device = scanner._parse_fast_pair_advertisement(
        name="Test Earbuds",
        address="AA:BB:CC:DD:EE:FF",
        data=data,
        rssi=-60,
    )
    
    assert device.device_type == BLEDeviceType.FAST_PAIR
    assert device.fast_pair_model_id == "21B2C3"
    assert device.fast_pair_in_pairing_mode is True
    assert device.has_account_key_filter is False


def test_parse_fast_pair_advertisement_account_key_filter():
    """Test parsing Fast Pair advertisement with account key filter."""
    scanner = FastPairScanner()
    
    # Account Key Filter: bits 5-6 of first byte != 0
    data = bytes.fromhex("20")  # 0x20 = bit 5 set
    device = scanner._parse_fast_pair_advertisement(
        name="Test Earbuds",
        address="AA:BB:CC:DD:EE:FF",
        data=data,
        rssi=-60,
    )
    
    assert device.device_type == BLEDeviceType.FAST_PAIR
    assert device.fast_pair_in_pairing_mode is False
    assert device.has_account_key_filter is True


def test_parse_fast_pair_advertisement_extended():
    """Test parsing Fast Pair advertisement with extended data."""
    scanner = FastPairScanner()
    
    # Extended data: >3 bytes, bit 7 = 0, bits 5-6 = 0 (not account key filter)
    # Use 0x01 as first byte (bit 7 = 0, bits 5-6 = 0)
    data = bytes.fromhex("01B2C3D4E5F6")
    device = scanner._parse_fast_pair_advertisement(
        name="Test Earbuds",
        address="AA:BB:CC:DD:EE:FF",
        data=data,
        rssi=-60,
    )
    
    assert device.fast_pair_model_id == "01B2C3"
    assert device.fast_pair_in_pairing_mode is False


# --- Device Quirks Tests ---

def test_load_device_quirks_default():
    """Test loading device quirks with default when file not found."""
    # Patch the config paths to non-existent paths
    with patch("urban_hs.modules.ble.fastpair.Path") as mock_path:
        mock_path.return_value.exists.return_value = False
        mock_path.return_value.parent.parent.parent.parent.__truediv__ = lambda s, o: mock_path.return_value
        
        quirks = _load_device_quirks()
        assert "devices" in quirks
        assert "default_quirks" in quirks
        assert "000000" in quirks["devices"]


def test_get_device_quirks_unknown_model():
    """Test getting quirks for unknown model ID returns defaults."""
    with patch("urban_hs.modules.ble.fastpair._load_device_quirks", return_value={
        "devices": {},
        "default_quirks": {
            "needsExtendedResponse": False,
            "prefersBrEdrBonding": True,
            "delayBeforeKbp": 0,
            "usesRetroactiveFlag": False,
            "maxKbpRetries": 3,
            "preferredStrategy": "RAW_KBP"
        }
    }):
        quirks = get_device_quirks("UNKNOWN123")
        assert quirks["needsExtendedResponse"] is False
        assert quirks["prefersBrEdrBonding"] is True


def test_get_device_quirks_known_model():
    """Test getting quirks for known model ID."""
    with patch("urban_hs.modules.ble.fastpair._load_device_quirks", return_value={
        "devices": {
            "ABCDEF": {
                "quirks": {
                    "needsExtendedResponse": True,
                    "prefersBrEdrBonding": True,
                    "delayBeforeKbp": 500,
                    "usesRetroactiveFlag": True,
                    "maxKbpRetries": 5,
                    "preferredStrategy": "EXTENDED_RESPONSE"
                }
            },
            "default_quirks": {}
        }
    }):
        quirks = get_device_quirks("abcdef")
        assert quirks["needsExtendedResponse"] is True
        assert quirks["usesRetroactiveFlag"] is True
        assert quirks["preferredStrategy"] == "EXTENDED_RESPONSE"


def test_get_device_quirks_none():
    """Test getting quirks with None model ID returns defaults."""
    with patch("urban_hs.modules.ble.fastpair._load_device_quirks", return_value={
        "devices": {},
        "default_quirks": {
            "needsExtendedResponse": False,
            "prefersBrEdrBonding": True
        }
    }):
        quirks = get_device_quirks(None)
        assert quirks["needsExtendedResponse"] is False
        assert quirks["prefersBrEdrBonding"] is True


# --- WhisperPairExploit Tests ---

@pytest.fixture
def exploit():
    """Create WhisperPairExploit instance for testing."""
    return WhisperPairExploit(adapter="hci0")


def test_build_kbp_request_raw_kbp(exploit):
    """Test building KBP request for RAW_KBP strategy."""
    request = exploit._build_kbp_request("AA:BB:CC:DD:EE:FF", WhisperPairExploit.Strategy.RAW_KBP)
    
    assert request[0] == 0x00  # Message type
    assert request[1] == 0x11  # Flags (INITIATE_BONDING | EXTENDED_RESPONSE)
    assert len(request) == 1 + 1 + 6 + 6 + 8  # type + flags + target + seeker + salt


def test_build_kbp_request_raw_with_seeker(exploit):
    """Test building KBP request for RAW_WITH_SEEKER strategy."""
    request = exploit._build_kbp_request("AA:BB:CC:DD:EE:FF", WhisperPairExploit.Strategy.RAW_WITH_SEEKER)
    
    assert request[0] == 0x00
    assert request[1] == 0x11
    assert len(request) == 22


def test_build_kbp_request_retroactive(exploit):
    """Test building KBP request for RETROACTIVE strategy."""
    request = exploit._build_kbp_request("AA:BB:CC:DD:EE:FF", WhisperPairExploit.Strategy.RETROACTIVE)
    
    assert request[1] == 0x11 | 0x04  # RETROACTIVE flag set


def test_build_kbp_request_extended_response(exploit):
    """Test building KBP request for EXTENDED_RESPONSE strategy."""
    request = exploit._build_kbp_request("AA:BB:CC:DD:EE:FF", WhisperPairExploit.Strategy.EXTENDED_RESPONSE)
    
    assert request[1] == 0x11 | 0x08  # EXTENDED_RESPONSE flag set


def test_build_kbp_request_with_custom_seeker(exploit):
    """Test building KBP request with custom seeker address."""
    seeker = "11:22:33:44:55:66"
    request = exploit._build_kbp_request("AA:BB:CC:DD:EE:FF", WhisperPairExploit.Strategy.RAW_KBP, seeker_address=seeker)
    
    # Bytes 2-7 should be target, 8-13 should be seeker
    target_bytes = request[2:8]
    seeker_bytes = request[8:14]
    assert target_bytes == bytes.fromhex("AABBCCDDEEFF")
    assert seeker_bytes == bytes.fromhex("112233445566")


# --- AccountKeyManager Tests ---

@pytest.fixture
def account_key_manager():
    """Create AccountKeyManager instance for testing."""
    return AccountKeyManager(adapter="hci0")


def test_generate_account_key(account_key_manager):
    """Test generating account key."""
    key = account_key_manager._generate_account_key()
    
    assert len(key) == 16
    assert key[0] == 0x04  # Account Key type


def test_generate_account_key_with_shared_secret(account_key_manager):
    """Test generating account key with shared secret encryption."""
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography not available")
    
    shared_secret = os.urandom(16)
    key = account_key_manager._generate_account_key(shared_secret)
    
    assert len(key) == 16
    assert key[0] == 0x04
    # Encrypted key should be different from unencrypted
    key2 = account_key_manager._generate_account_key()
    # Very unlikely to be the same (16 bytes)
    assert key != key2


# --- HFPAudioCapture Tests ---

@pytest.fixture
def hfp_capture():
    """Create HFPAudioCapture instance for testing."""
    return HFPAudioCapture(adapter="hci0")


def test_hfp_capture_init(hfp_capture):
    """Test HFPAudioCapture initialization."""
    assert hfp_capture.adapter == "hci0"
    assert hfp_capture.capture_active is False
    assert hfp_capture.capture_process is None
    assert hfp_capture.sample_rate == 8000
    assert hfp_capture.channels == 1
    assert hfp_capture.format == "S16_LE"


# --- WhisperPairFullExploit Tests ---

def test_whisperpair_full_exploit_init():
    """Test WhisperPairFullExploit initialization."""
    exploit = WhisperPairFullExploit(
        target_mac="AA:BB:CC:DD:EE:FF",
        adapter_ble="hci0",
        hfp_enabled=True,
        audio_duration=120,
    )
    
    assert exploit.target_mac == "AA:BB:CC:DD:EE:FF"
    assert exploit.adapter_ble == "hci0"
    assert exploit.hfp_enabled is True
    assert exploit.audio_duration == 120
    assert exploit.exploit_state == "init"


# --- BlueZBondingManager Tests ---

def test_bluez_bonding_manager_init():
    """Test BlueZBondingManager initialization."""
    manager = BlueZBondingManager(adapter="hci0")
    assert manager.adapter == "hci0"
    assert manager.adapter_path == "/org/bluez/hci0"


# --- Integration Tests (Mock) ---

class MockBleakClient:
    """Mock bleak BleakClient for integration testing."""
    def __init__(self, *args, **kwargs):
        self.is_connected = True
        # Create mock Fast Pair service with KBP characteristic
        from unittest.mock import MagicMock
        
        # Create mock characteristic
        mock_char = MagicMock()
        mock_char.uuid = KEY_BASED_PAIRING_UUID
        
        # Create mock service
        mock_service = MagicMock()
        mock_service.uuid = FAST_PAIR_SERVICE_UUID
        mock_service.characteristics = [mock_char]
        
        self.is_connected = True
        self.services = [mock_service]
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, *args):
        pass
    
    async def write_gatt_char(self, *args, **kwargs):
        # Simulate success by default
        pass


@patch("bleak.BleakClient", MockBleakClient)
@pytest.mark.asyncio
async def test_whisperpair_exploit_execute_strategy_success(exploit):
    """Test KBP strategy execution with mocked success."""
    # The exploit imports BleakClient from bleak, so we patch it there
    result = await exploit._execute_kbp_strategy(
        "AA:BB:CC:DD:EE:FF",
        WhisperPairExploit.Strategy.RAW_KBP,
    )
    
    assert result["status"] == "vulnerable"
    assert result["strategy"] == "raw_kbp"


@patch("bleak.BleakClient", MockBleakClient)
@pytest.mark.asyncio
async def test_whisperpair_exploit_execute_all_strategies(exploit):
    """Test executing all KBP strategies."""
    with patch("urban_hs.modules.ble.fastpair.get_device_quirks", return_value={}):
        result = await exploit.execute_all_strategies("AA:BB:CC:DD:EE:FF")
    
    # The first strategy (raw_kbp) succeeds and returns early
    assert "strategies" in result
    assert "raw_kbp" in result["strategies"]
    assert result["success"] is True
    assert result["winning_strategy"] == "raw_kbp"


# --- Test Configuration JSON Loading ---

def test_device_quirks_json_structure():
    """Test that device_quirks.json has correct structure."""
    config_path = Path("/home/andresantos/Desktop/Projects/urban-hack-sentinel/config/device_quirks.json")
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


# Run tests if executed directly
if __name__ == "__main__":
    pytest.main([__file__, "-v"])