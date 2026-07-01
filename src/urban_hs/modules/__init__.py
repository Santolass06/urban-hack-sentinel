"""
Urban Hack Sentinel v3 — Plugin Modules package.

Exposes module discovery and plugin infrastructure. Individual
subpackages (wifi, ble, network, camera, metasploit, hid, mqtt,
reporting, credential, exploit) live under this namespace and are
importable directly (e.g. ``from urban_hs.modules import wifi``).

Robustness rules
----------------
* Optional native dependencies are imported lazily where possible so
  that ``import urban_hs`` never fails on a minimal install.
* Subpackages that have side-effects (network scan, BLE stack) are
  **not** auto-imported here. Consumers import them explicitly.
"""

from __future__ import annotations

from typing import Dict

from urban_hs.core.plugins import PluginMetadata, PluginType, urban_plugin

# Registry of available module plugins. Keys are the module name as
# used in configuration (``modules.wifi.enabled = true``). Values are
# lazily-resolved plugin class strings so we don't pay import cost upfront.
_MODULE_REGISTRY: Dict[str, str] = {
    "wifi": "urban_hs.modules.wifi.plugin:WiFiPlugin",
    "ble": "urban_hs.modules.ble.plugin:BLEPlugin",
    "network": "urban_hs.modules.network:NetworkModule",
    "camera": "urban_hs.modules.camera:CameraModule",
    "metasploit": "urban_hs.modules.metasploit:MetasploitModule",
    "hid": "urban_hs.modules.hid:HIDModule",
    "mqtt": "urban_hs.modules.mqtt:MQTTModule",
    "reporting": "urban_hs.modules.reporting:ReportingModule",
    "credential": "urban_hs.modules.credential:CredentialModule",
    "exploit": "urban_hs.modules.exploit:ExploitModule",
    "ssid_confusion": "urban_hs.modules.ssid_confusion:SSIDConfusionModule",
    "esp32": "urban_hs.modules.esp32:ESP32Module",
    "bt_hid": "urban_hs.modules.bt_hid:BTHIDModule",
    "urban_hack": "urban_hs.modules.urban_hack:UrbanHackPlugin",
}


def list_modules() -> Dict[str, str]:
    """Return a snapshot of the module registry."""
    return dict(_MODULE_REGISTRY)


# Subpackages that are safe to re-export at this level. These are
# intentionally kept small to avoid circular-import risk.
from urban_hs.modules.wifi import (  # noqa: E402
    CHANNELS_2GHZ,
    CHANNELS_5GHZ,
    CHANNELS_6GHZ,
    ScanStrategy,
    WiFiScanner,
)

__all__ = [
    "list_modules",
    "WiFiScanner",
    "ScanStrategy",
    "CHANNELS_2GHZ",
    "CHANNELS_5GHZ",
    "CHANNELS_6GHZ",
]
