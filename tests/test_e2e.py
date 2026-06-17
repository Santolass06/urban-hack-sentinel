"""
E2E Integration Tests - mac80211_hwsim WiFi simulation + Mock BlueZ.

These tests run against virtual WiFi interfaces (mac80211_hwsim) and
mocked BlueZ D-Bus for complete hardware-free CI/CD testing.
"""

import asyncio
import pytest
import tempfile
import os
from unittest.mock import AsyncMock, Mock, patch
from pathlib import Path
import subprocess
import sys

# Import modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from urban_hs.modules.wifi import WiFiScanner, ScanStrategy
from urban_hs.modules.ble import FastPairScanner, WhisperPairTester, WhisperPairExploit
from urban_hs.modules.network import NmapScanner, ScanType
from urban_hs.core.concurrency import get_resource_manager, ResourceType
from urban_hs.core.memory import MemoryProfiler, detect_gc_leaks
from urban_hs.core.security import harden_process, CapabilitySet, Capability
from urban_hs.core.storage import Storage


# ============================================================
# mac80211_hwsim Fixture - Virtual WiFi for CI
# ============================================================

class MockHwsim:
    """Manage mac80211_hwsim virtual WiFi interfaces."""
    
    def __init__(self, num_radios: int = 2):
        self.num_radios = num_radios
        self.interface_names = [f"wlan{i}" for i in range(num_radios)]
        self._loaded = False
    
    def load(self) -> bool:
        """Load mac80211_hwsim kernel module."""
        try:
            result = subprocess.run(
                ["modprobe", "mac80211_hwsim", f"radios={self.num_radios}"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                self._loaded = True
                return True
            else:
                print(f"Failed to load mac80211_hwsim: {result.stderr}")
                return False
        except Exception as e:
            print(f"Error loading mac80211_hwsim: {e}")
            return False
    
    def unload(self) -> bool:
        """Unload mac80211_hwsim kernel module."""
        try:
            result = subprocess.run(
                ["modprobe", "-r", "mac80211_hwsim"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                self._loaded = False
                return True
            return False
        except Exception:
            return False
    
    def get_interfaces(self) -> list:
        """Get list of virtual interfaces."""
        return self.interface_names
    
    def __enter__(self):
        if self.load():
            return self
        raise RuntimeError("Failed to load mac80211_hwsim")
    
    def __exit__(self, *args):
        self.unload()


# Session-scoped fixture for mac80211_hwsim
@pytest.fixture(scope="session")
def hwsim():
    """Session-scoped mac80211_hwsim fixture."""
    hwsim = MockHwsim(num_radios=2)
    if hwsim.load():
        yield hwsim
        hwsim.unload()
    else:
        pytest.skip("mac80211_hwsim not available, skipping WiFi tests")


# ============================================================
# Mock BlueZ Fixture - Virtual BLE for CI
# ============================================================

class MockBlueZ:
    """Mock BlueZ D-Bus for BLE testing without hardware."""
    
    def __init__(self):
        self.devices = {}
        self.adapters = {}
        self._running = False
    
    def add_mock_device(self, address: str, name: str = "Mock Device", 
                       services: list = None, manufacturer_data: dict = None,
                       rssi: int = -50):
        """Add a mock BLE device."""
        self.devices[address] = {
            "address": address,
            "name": name,
            "rssi": rssi,
            "services": services or [],
            "manufacturer_data": manufacturer_data or {},
        }
    
    def add_mock_adapter(self, adapter_name: str = "hci0"):
        """Add a mock Bluetooth adapter."""
        self.adapters[adapter_name] = {
            "name": adapter_name,
            "address": "00:00:00:00:00:00",
            "powered": True,
            "discoverable": True,
        }
    
    async def mock_discover(self, timeout: int = 5) -> list:
        """Mock device discovery."""
        await asyncio.sleep(0.1)  # Simulate scan time
        return list(self.devices.values())


@pytest.fixture
def mock_bluez():
    """Mock BlueZ fixture for BLE tests."""
    bluez = MockBlueZ()
    
    # Add some mock devices
    bluez.add_mock_device("AA:BB:CC:DD:EE:FF", "Test Headphones", 
                          ["0000180d-0000-1000-8000-00805f9b34fb"],
                          {0x02E5: b"\x01\x02\x03"})
    bluez.add_mock_device("11:22:33:44:55:66", "ESP32 Device",
                          ["0000180a-0000-1000-8000-00805f9b34fb"],
                          {0x02E5: b"\x04\x05\x06"})
    bluez.add_mock_adapter("hci0")
    
    return bluez


# ============================================================
# Testcontainers-like Fixtures for Integration Tests
# ============================================================

class MockServiceContainer:
    """Mock service container for integration tests (similar to testcontainers)."""
    
    def __init__(self, image: str, port: int = None):
        self.image = image
        self.port = port
        self.container_id = None
        self._host_port = port
    
    async def start(self) -> str:
        """Start the container."""
        return f"localhost:{self._host_port}"
    
    async def stop(self):
        """Stop the container."""
        pass


@pytest.fixture
async def nmap_container():
    """Nmap container for network scanning tests."""
    container = MockServiceContainer("nmap", 0)
    await container.start()
    yield container
    await container.stop()


@pytest.fixture
async def metasploit_container():
    """Metasploit container for exploitation tests."""
    container = MockServiceContainer("metasploitframework/metasploit-framework", 55553)
    await container.start()
    yield container
    await container.stop()


# ============================================================
# E2E Test Classes
# ============================================================

class TestWiFiE2E:
    """End-to-end WiFi tests with mac80211_hwsim."""
    
    @pytest.mark.asyncio
    async def test_wifi_scan_with_hwsim(self, hwsim):
        """Test WiFi scanning with virtual interfaces."""
        print(f"Available interfaces: {hwsim.get_interfaces()}")
        
        scanner = WiFiScanner(interface=hwsim.get_interfaces()[0])
        
        # Test passive scan - mock the subprocess calls
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate.return_value = (b'[]', b'')
            mock_exec.return_value = mock_proc
            
            networks = await scanner.scan(interface=hwsim.get_interfaces()[0], duration=2)
            
            # Should return empty list (no real networks in simulation)
            assert isinstance(networks, list)
    
    @pytest.mark.asyncio
    async def test_handshake_attack_simulation(self, hwsim):
        """Test handshake attack with simulated networks."""
        from urban_hs.modules.wifi import HandshakeAttack
        
        attack = HandshakeAttack(
            interface=hwsim.get_interfaces()[0],
            output_dir="/tmp/handshakes",
            deauth_count=1
        )
        
        # Mock the subprocess calls
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate.return_value = (b"handshake captured", b"")
            mock_exec.return_value = mock_proc
            
            result = await attack.execute(
                target_bssid="AA:BB:CC:DD:EE:FF",
                target_essid="TestNetwork",
                channel=6
            )
            
            # Result structure should be valid
            assert hasattr(result, 'success')
            assert hasattr(result, 'message')


class TestBLEE2E:
    """End-to-end BLE tests with mock BlueZ."""
    
    @pytest.mark.asyncio
    async def test_fastpair_scan(self, mock_bluez):
        from urban_hs.modules.ble import FastPairScanner
        
        scanner = FastPairScanner(adapter="hci0")
        
        # Test initialization
        assert scanner.adapter == "hci0"
    
    @pytest.mark.asyncio
    async def test_whisperpair_vulnerability_test(self, mock_bluez):
        from urban_hs.modules.ble import WhisperPairTester
        
        tester = WhisperPairTester(
            adapter="hci0"
        )
        
        # Mock BleakClient to avoid real BLE connections
        with patch("bleak.BleakClient") as mock_client:
            mock_client = AsyncMock()
            mock_client.is_connected = True
            mock_client.services = Mock()
            mock_client.services.get_characteristic.return_value = Mock(uuid="fe2c1234-8366-4814-8eb0-01de32100bea")
            mock_client.write_gatt_char = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class = mock_client
            mock_client_class.return_value = mock_client
            
            # Test vulnerability check - use correct method name
            result = await tester.test_device("AA:BB:CC:DD:EE:FF")
        
        # Result should have expected structure
        assert result is not None
        assert isinstance(result, dict)
    
    @pytest.mark.asyncio
    async def test_whisperpair_exploit_chain(self, mock_bluez):
        from urban_hs.modules.ble import WhisperPairExploit
        
        exploit = WhisperPairExploit(
            adapter="hci0"
        )
        
        # Mock BleakClient to avoid real BLE connections
        with patch("bleak.BleakClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.is_connected = True
            mock_client.services = Mock()
            mock_client.services.get_characteristic.return_value = Mock(uuid="fe2c1234-8366-4814-8eb0-01de32100bea")
            mock_client.write_gatt_char = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client
            
            # Test exploit chain
            result = await exploit.execute_all_strategies(
                target_address="AA:BB:CC:DD:EE:FF",
                model_id=None
            )
        
        # Should have expected structure
        assert isinstance(result, dict)
        assert "target" in result
        assert "strategies" in result
        assert "success" in result


class TestNetworkE2E:
    """End-to-end Network scanning tests."""
    
    @pytest.mark.asyncio
    async def test_nmap_scan_localhost(self):
        from urban_hs.modules.network import NmapScanner, ScanType
        
        scanner = NmapScanner()
        
        # Test host discovery on localhost
        results = await scanner.scan("127.0.0.1/32", ScanType.HOST_DISCOVERY, timeout=10)
        
        assert isinstance(results, list)
    
    @pytest.mark.asyncio
    async def test_nuclei_scan(self):
        from urban_hs.modules.network import NucleiRunner
        
        runner = NucleiRunner(severity_levels=["critical", "high"])
        
        # Test template execution
        results = await runner.scan("127.0.0.1")
        
        assert isinstance(results, list)


class TestConcurrencyE2E:
    """End-to-end Concurrency tests."""
    
    @pytest.mark.asyncio
    async def test_resource_acquisition(self):
        """Test resource acquisition and release."""
        rm = get_resource_manager()
        
        # Acquire radio resource
        acquired = await rm.pool.acquire(ResourceType.RADIO, "test_holder")
        assert acquired
        
        # Try to acquire again (should fail - max 1)
        acquired2 = await rm.pool.acquire(ResourceType.RADIO, "test_holder2", max_wait=0.1)
        assert not acquired2
        
        # Release first
        await rm.pool.release(ResourceType.RADIO, "test_holder")
        
        # Now second should succeed
        acquired3 = await rm.pool.acquire(ResourceType.RADIO, "test_holder2")
        assert acquired3
        
        await rm.pool.release(ResourceType.RADIO, "test_holder2")


class TestMemoryE2E:
    """End-to-end Memory profiling tests."""
    
    @pytest.mark.asyncio
    async def test_memory_profiling(self):
        """Test memory profiler basic functionality."""
        profiler = MemoryProfiler(tracing=True, leak_threshold_mb=100)
        
        profiler.start()
        
        # Allocate some memory
        data = [b"x" * 1024 * 1024 for _ in range(10)]  # 10MB
        
        snapshot = profiler._take_snapshot("test")
        
        assert snapshot.object_count > 0
        assert snapshot.rss_mb >= 0
        
        profiler.stop()
    
    def test_gc_leak_detection(self):
        """Test GC leak detection."""
        report = detect_gc_leaks(threshold_count=5)
        
        assert hasattr(report, 'leaks')
        assert hasattr(report, 'top_modules')
        assert isinstance(report.leaks, list)


class TestSecurityE2E:
    """End-to-end Security hardening tests."""
    
    @pytest.mark.asyncio
    async def test_harden_process_wifi(self):
        """Test security hardening for WiFi module."""
        results = await harden_process("wifi_scanner")
        
        assert "capabilities" in results
        assert isinstance(results, dict)
    
    def test_capability_set(self):
        """Test capability set operations."""
        caps = CapabilitySet.from_module("wifi_scanner")
        
        assert Capability.CAP_NET_RAW in caps.bounding
        assert Capability.CAP_NET_ADMIN in caps.bounding
        
        caps.drop_all_except({Capability.CAP_NET_RAW})
        
        assert Capability.CAP_NET_RAW in caps.bounding
        assert Capability.CAP_NET_ADMIN not in caps.bounding


class TestStorageE2E:
    """End-to-end Storage tests with SQLite optimization."""
    
    @pytest.mark.asyncio
    async def test_storage_optimization(self):
        """Test SQLite optimization functions."""
        from urban_hs.core.storage import Storage
        
        # Use temporary database
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        try:
            storage = Storage(sqlite_path=db_path, redis_url="redis://localhost:6379/0")
            await storage.initialize()
            
            # Create composite indices
            await storage.create_composite_indices()
            
            # Optimize database
            results = await storage.optimize_database()
            
            assert "analyze" in results
            assert "pragma_optimize" in results
            assert "wal_checkpoint" in results
            assert "stats" in results
            
            await storage.shutdown()
        finally:
            os.unlink(db_path)
    
    @pytest.mark.asyncio
    async def test_vacuum_database(self):
        """Test database vacuum."""
        from urban_hs.core.storage import Storage
        
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        try:
            storage = Storage(sqlite_path=db_path, redis_url="redis://localhost:6379/0")
            await storage.initialize()
            
            # Insert some data
            import aiosqlite
            async with aiosqlite.connect(db_path) as conn:
                await conn.execute(
                    "INSERT INTO devices (id, first_seen, last_seen, type, mac) VALUES (?, ?, ?, ?, ?)",
                    ("test1", 1000, 2000, "wifi_ap", "aa:bb:cc:dd:ee:ff")
                )
                await conn.commit()
            
            # Run vacuum
            results = await storage.vacuum_database(full=False)
            
            assert "vacuum_type" in results
            assert "space_reclaimed_mb" in results
            
            await storage.shutdown()
        finally:
            os.unlink(db_path)


# ============================================================
# Pytest Configuration
# ============================================================

def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "e2e: End-to-end integration tests")
    config.addinivalue_line("markers", "hwsim: Tests requiring mac80211_hwsim")
    config.addinivalue_line("markers", "hardware: Tests requiring physical hardware")
    config.addinivalue_line("markers", "integration: Integration tests")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])