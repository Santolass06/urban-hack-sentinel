"""
Hardware / software compatibility layer for Urban Hack Sentinel.

Only production checks live here: real commands, interfaces, chipsets.
Mock/Stub/Fake behaviour belongs in ``tests/`` only.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class Capability(StrEnum):
    WIFI_AIRODUMP = "wifi:airodump"
    WIFI_HCXD_TOOL = "wifi:hcxdumptool"
    WIFI_REAVER = "wifi:reaver"
    WIFI_CYPRESS_CHIPSET = "wifi:cypress_chipset"
    WIFI_INTERFACE = "wifi:interface"
    WIFI_MONITOR_MODE = "wifi:monitor_mode"
    WIFI_PACKET_INJECTION = "wifi:packet_injection"
    BLE_BLUEZ = "ble:bluez"
    BLE_BETTERCAP = "ble:bettercap"
    BLE_ADAPTER = "ble:adapter"
    BT_HID = "bt_hid"
    HID_GADGET = "hid:gadget"
    ESP32 = "esp32"
    NMAP = "network:nmap"
    NUCLEI = "network:nuclei"
    METASPLOIT = "metasploit:rpc"


@dataclass
class CompatibilityResult:
    capability: Capability
    supported: bool
    reason: str = ""
    remediation: str = ""
    detail: str | None = None


@dataclass
class ModuleCompatibilityReport:
    module: str
    results: list[CompatibilityResult] = field(default_factory=list)

    @property
    def supported(self) -> bool:
        return all(item.supported for item in self.results)

    @property
    def unsupported(self) -> list[CompatibilityResult]:
        return [item for item in self.results if not item.supported]

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "supported": self.supported,
            "checks": [
                {
                    "capability": item.capability.value,
                    "supported": item.supported,
                    "reason": item.reason or None,
                    "remediation": item.remediation or None,
                    "detail": item.detail or None,
                }
                for item in self.results
            ],
            "unsupported": [
                {
                    "capability": item.capability.value,
                    "reason": item.reason,
                    "remediation": item.remediation,
                    "detail": item.detail,
                }
                for item in self.unsupported
            ],
        }


class HardwareCompatibilityChecker:
    def __init__(self, interface: str = "wlan0") -> None:
        self.interface = interface

    def _which(self, command: str) -> str | None:
        return shutil.which(command)

    def _path_exists(self, path: str | None) -> bool:
        if not path:
            return False
        return Path(path).exists()

    def check_command(self, capability: Capability, command: str, *, remediation: str = "") -> CompatibilityResult:
        path = self._which(command)
        supported = path is not None
        return CompatibilityResult(
            capability=capability,
            supported=supported,
            reason=f"{command} not found on PATH" if not supported else "",
            remediation=remediation or f"Install {command} and retry.",
            detail=path or None,
        )

    def check_interface(self, capability: Capability = Capability.WIFI_INTERFACE, *, remediation: str = "") -> CompatibilityResult:
        path = Path(f"/sys/class/net/{self.interface}")
        supported = path.exists()
        return CompatibilityResult(
            capability=capability,
            supported=supported,
            reason=f"Interface {self.interface} not present." if not supported else "",
            remediation=remediation or "Create or select an existing wireless interface.",
            detail=str(path) if supported else None,
        )

    def check_wireless_extensions(self) -> CompatibilityResult:
        """Check if wireless extensions are supported by the interface."""
        try:
            output = self._run_iw_info()
            supported = "Interface" in output or "wiphy" in output.lower()
            return CompatibilityResult(
                capability=Capability.WIFI_INTERFACE,
                supported=supported,
                reason="Wireless extensions not supported" if not supported else "",
                remediation="Use a wireless interface with nl80211 support.",
                detail=output.strip()[:160],
            )
        except FileNotFoundError:
            return CompatibilityResult(
                capability=Capability.WIFI_INTERFACE,
                supported=False,
                reason="iw is not installed.",
                remediation="Install iw and retry.",
            )
        except Exception as exc:
            return CompatibilityResult(
                capability=Capability.WIFI_INTERFACE,
                supported=False,
                reason=f"Wireless check failed: {exc}",
                remediation="Inspect wireless adapter and driver support.",
            )

    def check_monitor_mode(self) -> CompatibilityResult:
        """Check if the interface supports monitor mode."""
        try:
            output = self._run_iw_info()
            supported = "monitor" in output.lower() or "AP" in output
            detail = output.strip()[:200]
        except FileNotFoundError:
            return CompatibilityResult(
                capability=Capability.WIFI_MONITOR_MODE,
                supported=False,
                reason="iw not installed; cannot inspect monitor mode support.",
                remediation="Install iw and retry.",
            )
        except Exception as exc:
            return CompatibilityResult(
                capability=Capability.WIFI_MONITOR_MODE,
                supported=False,
                reason=f"Monitor mode probe failed: {exc}",
                remediation="Verify wireless adapter supports monitor mode.",
            )

        if supported:
            return CompatibilityResult(
                capability=Capability.WIFI_MONITOR_MODE,
                supported=True,
                detail=detail,
            )

        # Try alternative check via airmon-ng
        airmon_path = self._which("airmon-ng")
        if airmon_path:
            try:
                proc = subprocess.run(
                    ["airmon-ng", "check", self.interface],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if "monitor mode" in proc.stdout.lower() or "monitor mode" in proc.stderr.lower():
                    return CompatibilityResult(
                        capability=Capability.WIFI_MONITOR_MODE,
                        supported=True,
                        detail="airmon-ng indicates monitor mode support.",
                    )
            except Exception:
                pass

        return CompatibilityResult(
            capability=Capability.WIFI_MONITOR_MODE,
            supported=False,
            reason="Monitor mode not detected on this interface.",
            remediation="Ensure your adapter supports monitor mode and drivers are loaded.",
        )

    def check_packet_injection(self) -> CompatibilityResult:
        """Check if the interface supports packet injection."""
        # First check via iw
        try:
            output = self._run_iw_info()
            if "other bss" in output.lower() or "monitor" in output.lower():
                return CompatibilityResult(
                    capability=Capability.WIFI_PACKET_INJECTION,
                    supported=True,
                    detail="Driver appears to support injection based on iw info.",
                )
        except Exception:
            pass

        # ponytail: read-only check — never toggle interface state here.
        # Report injection support only if the interface is ALREADY in
        # monitor mode; otherwise leave it to a dedicated enable step.
        mon_sysfs = Path(f"/sys/class/net/{self.interface}/type")
        if mon_sysfs.exists():
            try:
                if mon_sysfs.read_text().strip() == "803":
                    return CompatibilityResult(
                        capability=Capability.WIFI_PACKET_INJECTION,
                        supported=True,
                        detail="Interface already in monitor mode (implies injection support).",
                    )
            except OSError:
                pass

        return CompatibilityResult(
            capability=Capability.WIFI_PACKET_INJECTION,
            supported=False,
            reason="Could not confirm packet injection; put the interface in monitor mode to verify.",
            remediation="Use a known-compatible adapter (e.g., Atheros AR9271, Ralink RT5370) and enable monitor mode.",
        )

    def check_ble_adapter(self) -> CompatibilityResult:
        """Check if a Bluetooth LE adapter is present and powered."""
        adapter = getattr(self, 'ble_adapter', 'hci0')
        hci_path = Path(f"/sys/class/bluetooth/{adapter}")

        if not hci_path.exists():
            return CompatibilityResult(
                capability=Capability.BLE_ADAPTER,
                supported=False,
                reason=f"Bluetooth adapter {adapter} not found.",
                remediation="Connect a BLE-capable Bluetooth adapter.",
            )

        # Check if powered
        powered_path = hci_path / "powered"
        if powered_path.exists():
            try:
                powered = powered_path.read_text().strip()
                if powered != "1":
                    return CompatibilityResult(
                        capability=Capability.BLE_ADAPTER,
                        supported=False,
                        reason=f"Bluetooth adapter {adapter} is powered off.",
                        remediation=f"Power on the adapter: `btmgmt {adapter} power on` or via bluetoothctl.",
                    )
            except Exception as exc:
                return CompatibilityResult(
                    capability=Capability.BLE_ADAPTER,
                    supported=False,
                    reason=f"Cannot read power state of {adapter}: {exc}",
                    remediation="Check Bluetooth service status.",
                )

        # Check via bluetoothctl
        try:
            proc = subprocess.run(
                ["bluetoothctl", "show", adapter],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0:
                powered = "Powered: yes" in proc.stdout
                if not powered:
                    return CompatibilityResult(
                        capability=Capability.BLE_ADAPTER,
                        supported=False,
                        reason=f"Adapter {adapter} is not powered.",
                        remediation="Power on via bluetoothctl or system settings.",
                    )
                return CompatibilityResult(
                    capability=Capability.BLE_ADAPTER,
                    supported=True,
                    detail=proc.stdout.strip()[:200],
                )
        except Exception as exc:
            return CompatibilityResult(
                capability=Capability.BLE_ADAPTER,
                supported=False,
                reason=f"bluetoothctl check failed: {exc}",
                remediation="Install or start BlueZ Bluetooth stack.",
            )

        return CompatibilityResult(
            capability=Capability.BLE_ADAPTER,
            supported=True,
            detail=f"Adapter {adapter} present.",
        )

    def check_cypress_chipset(self) -> CompatibilityResult:
        try:
            output = self._run_iw_info()
        except FileNotFoundError:
            return CompatibilityResult(
                capability=Capability.WIFI_CYPRESS_CHIPSET,
                supported=False,
                reason="iw is not installed; cannot inspect wireless capability.",
                remediation="Install iw and retry.",
            )
        except Exception as exc:  # pragma: no cover - defensive
            return CompatibilityResult(
                capability=Capability.WIFI_CYPRESS_CHIPSET,
                supported=False,
                reason=f"Chipset probe failed: {exc}",
                remediation="Inspect wireless adapter and driver support.",
            )

        output_lower = output.lower()
        indicators = ["cypress", "cyw43438", "cyw43455", "cyw43456", "cyw4354", "cyw4356", "cyw4345", "cyw4349", "brcmfmac"]

        if any(indicator in output_lower for indicator in indicators):
            return CompatibilityResult(
                capability=Capability.WIFI_CYPRESS_CHIPSET,
                supported=True,
                detail=output.strip()[:160],
            )

        if "brcmfmac" in output_lower:
            return CompatibilityResult(
                capability=Capability.WIFI_CYPRESS_CHIPSET,
                supported=False,
                reason="Broadcom FullMAC driver detected; FragAttacks targets Cypress chipsets.",
                remediation="Attach a supported Cypress adapter before running FragAttacks.",
            )

        return CompatibilityResult(
            capability=Capability.WIFI_CYPRESS_CHIPSET,
            supported=False,
            reason="No Cypress chipset detected.",
            remediation="FragAttacks requires Cypress chipsets (CYW43438, CYW43455, etc.).",
        )

    def _run_iw_info(self) -> str:
        return subprocess.check_output(["iw", "dev", self.interface, "info"], text=True, stderr=subprocess.STDOUT)

    def fragattacks_requirements(self) -> ModuleCompatibilityReport:
        return ModuleCompatibilityReport(
            module="wifi.fragattacks",
            results=[
                self.check_command(Capability.WIFI_AIRODUMP, "airodump-ng"),
                self.check_command(Capability.WIFI_HCXD_TOOL, "hcxdumptool", remediation="Install hcxtools."),
                self.check_command(Capability.WIFI_REAVER, "reaver", remediation="Install reaver-wps-fork."),
                self.check_interface(),
                self.check_cypress_chipset(),
                self.check_monitor_mode(),
                self.check_packet_injection(),
            ],
        )

    def ble_requirements(self) -> ModuleCompatibilityReport:
        return ModuleCompatibilityReport(
            module="ble",
            results=[
                self.check_command(Capability.BLE_BLUEZ, "bluetoothctl", remediation="Install BlueZ utils."),
                self.check_command(Capability.BLE_BETTERCAP, "bettercap", remediation="Install bettercap."),
                self.check_ble_adapter(),
            ],
        )

    def wifi_requirements(self) -> ModuleCompatibilityReport:
        return ModuleCompatibilityReport(
            module="wifi",
            results=[
                self.check_interface(),
                self.check_wireless_extensions(),
                self.check_monitor_mode(),
                self.check_packet_injection(),
                self.check_command(Capability.WIFI_AIRODUMP, "airodump-ng"),
                self.check_command(Capability.NMAP, "nmap"),
            ],
        )
