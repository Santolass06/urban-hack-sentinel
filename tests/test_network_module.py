"""Tests for network module types and classes."""

import pytest
from datetime import datetime
from urban_hs.modules.network.types import (
    ScanType, Severity, PortInfo, HostInfo, Vulnerability,
)


class TestScanType:
    def test_values(self):
        assert ScanType.HOST_DISCOVERY.value == "host_discovery"
        assert ScanType.PORT_SCAN.value == "port_scan"
        assert ScanType.FULL_SCAN.value == "full_scan"

    def test_all_members(self):
        assert len(ScanType) == 6


class TestSeverity:
    def test_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"

    def test_ordering(self):
        assert Severity.CRITICAL.value < Severity.HIGH.value


class TestPortInfo:
    def test_creation(self):
        p = PortInfo(port=80, protocol="tcp", state="open")
        assert p.port == 80
        assert p.protocol == "tcp"
        assert p.state == "open"
        assert p.service is None

    def test_with_service(self):
        p = PortInfo(
            port=22, protocol="tcp", state="open",
            service="ssh", version="8.9", product="OpenSSH",
        )
        assert p.service == "ssh"
        assert p.version == "8.9"


class TestHostInfo:
    def test_creation(self):
        h = HostInfo(ip="192.168.1.1")
        assert h.ip == "192.168.1.1"
        assert h.state == "up"
        assert h.ports == []

    def test_with_ports(self):
        port = PortInfo(port=443, protocol="tcp", state="open")
        h = HostInfo(ip="10.0.0.1", ports=[port])
        assert len(h.ports) == 1
        assert h.ports[0].port == 443


class TestVulnerability:
    def test_creation(self):
        v = Vulnerability(id="TEST-001", name="Test Vuln")
        assert v.id == "TEST-001"
        assert v.severity == Severity.UNKNOWN
        assert v.status == "identified"

    def test_with_cve(self):
        v = Vulnerability(
            id="CVE-2024-1234",
            cve_id="CVE-2024-1234",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
        )
        assert v.cve_id == "CVE-2024-1234"
        assert v.cvss_score == 9.8


class TestNmapScanner:
    @pytest.mark.asyncio
    async def test_scan_invalid_targets(self):
        from urban_hs.modules.network.scanner import NmapScanner
        scanner = NmapScanner()
        result = await scanner.scan("'; rm -rf /")
        assert result == []

    @pytest.mark.asyncio
    async def test_scan_empty_targets(self):
        from urban_hs.modules.network.scanner import NmapScanner
        scanner = NmapScanner()
        result = await scanner.scan([])
        assert result == []

    def test_parse_xml_empty(self):
        from urban_hs.modules.network.scanner import NmapScanner
        scanner = NmapScanner()
        result = scanner._parse_xml_output("<nmaprun></nmaprun>")
        assert result == []

    def test_parse_xml_invalid(self):
        from urban_hs.modules.network.scanner import NmapScanner
        scanner = NmapScanner()
        result = scanner._parse_xml_output("not xml")
        assert result == []


class TestSearchSploitIntegration:
    @pytest.mark.asyncio
    async def test_search_invalid_exploit_id(self):
        from urban_hs.modules.network.searchsploit import SearchSploitIntegration
        ss = SearchSploitIntegration()
        result = await ss.get_exploit("'; rm -rf /", "/tmp")
        assert result is None

    @pytest.mark.asyncio
    async def test_search_non_numeric_id(self):
        from urban_hs.modules.network.searchsploit import SearchSploitIntegration
        ss = SearchSploitIntegration()
        result = await ss.get_exploit("abc123", "/tmp")
        assert result is None
