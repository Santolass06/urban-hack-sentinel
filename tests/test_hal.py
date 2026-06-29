"""
Tests for the hardware abstraction layer.
"""

from __future__ import annotations

import platform
import asyncio
from unittest.mock import patch

import pytest

from urban_hs.hal import platform as p
from urban_hs.hal.wifi import create_wifi_backend, _IWBackend, _ScapyBackend
from urban_hs.hal.ble import create_ble_backend, _BleakBackend


# -----------------------------------------------------------------------
# Platform
# -----------------------------------------------------------------------
class TestPlatform:
    def test_arm64_detection(self) -> None:
        with patch("platform.machine", return_value="aarch64"):
            pl = p.detect_platform()
        assert pl.arch == p.Arch.ARM64
        assert pl.is_arm64 is True
        assert pl.is_x86 is False

    def test_x86_64_detection(self) -> None:
        with patch("platform.machine", return_value="x86_64"):
            pl = p.detect_platform()
        assert pl.arch == p.Arch.X86_64
        assert pl.is_x86 is True
        assert pl.is_arm64 is False

    def test_unknown_detection(self) -> None:
        with patch("platform.machine", return_value="mips"):
            pl = p.detect_platform()
        assert pl.arch == p.Arch.UNKNOWN


# -----------------------------------------------------------------------
# WiFi HAL
# -----------------------------------------------------------------------
class TestWiFiHAL:
    def test_factory_returns_iw_on_arm64(self) -> None:
        with patch("platform.machine", return_value="aarch64"):
            backend = create_wifi_backend(interface="wlan0")
        assert isinstance(backend, _IWBackend)
        assert backend.name() == "iw"

    def test_factory_returns_iw_on_x86(self) -> None:
        with patch("platform.machine", return_value="x86_64"):
            backend = create_wifi_backend(interface="wlan0")
        # Current factory keeps classic iw backend on x86 too
        assert isinstance(backend, _IWBackend)

    @pytest.mark.asyncio
    async def test_iw_backend_set_channel_false_when_iw_missing(self) -> None:
        backend = _IWBackend(interface="wlan0")
        # We do NOT want to invoke real iw during tests.
        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError):
            result = await backend.set_channel(6)
        assert result is False


# -----------------------------------------------------------------------
# BLE HAL
# -----------------------------------------------------------------------
class TestBLEHAL:
    def test_bleak_backend_creation(self) -> None:
        backend = create_ble_backend(adapter="hci0")
        assert isinstance(backend, _BleakBackend)
        assert backend.name() == "bleak"


# -----------------------------------------------------------------------
# API
# -----------------------------------------------------------------------
class TestAPI:
    @pytest.mark.asyncio
    async def test_healthz(self) -> None:
        from httpx import AsyncClient, ASGITransport
        from urban_hs.ui.api.main import app

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r = await client.get("/healthz")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    @pytest.mark.asyncio
    async def test_system_info(self) -> None:
        from httpx import AsyncClient, ASGITransport
        from urban_hs.ui.api.main import app

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r = await client.get("/api/v1/system/info")
        assert r.status_code == 200
        body = r.json()
        assert body["arch"] == platform.machine()

    @pytest.mark.asyncio
    async def test_wifi_interfaces(self) -> None:
        from httpx import AsyncClient, ASGITransport
        from urban_hs.ui.api.main import app

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r = await client.get("/api/v1/wifi/interfaces")
        assert r.status_code == 200
        body = r.json()
        assert "interfaces" in body
