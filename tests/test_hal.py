"""
Hardware Abstraction Layer (HAL) tests.
"""

from __future__ import annotations

import asyncio

import pytest

from urban_hs.hal.platform import Arch, Platform, detect_platform
from urban_hs.hal.wifi import WiFiBackend, create_wifi_backend


def test_platform_detection() -> None:
    info = detect_platform()
    assert isinstance(info, Platform)
    assert info.arch in {Arch.X86_64, Arch.X86, Arch.ARM64}
    assert info.system in {"Linux", "Windows", "Darwin"}


def test_wifi_backend_fallback() -> None:
    backend = asyncio.run(create_wifi_backend(interface="wlan99", strategy="passive_only"))
    assert isinstance(backend, WiFiBackend)
    assert backend.name() in {"iw", "scapy"}
