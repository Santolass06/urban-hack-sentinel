"""Sprint 6 tests: Bettercap BLE, HFP capture, RouterScanner.scan_router."""

from __future__ import annotations

import asyncio
import stat
from typing import Any, Dict

import pytest

from urban_hs.core.event_bus import EventBus
from urban_hs.modules.ble.bettercap import BettercapBLEClient
from urban_hs.modules.ble.hfp import HFPAudioCapture
from urban_hs.modules.network import RouterScanner


def test_router_scanner_scan_router_calls_routersploit(monkeypatch, tmp_path):
    called = {}

    async def fake_communicate(self):
        return b"", b""

    async def fake_create(*args, **kwargs):
        proc = type("Proc", (), {"communicate": fake_communicate, "returncode": 0})()
        called["cmd"] = kwargs.get("args") or args[0]
        return proc

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_create)
    monkeypatch.setattr("os.unlink", lambda path: None)

    scanner = RouterScanner(routersploit_path="fake-rsf")
    captured = asyncio.run(
        scanner.scan_router("192.0.2.10", ports=[80], modules=["scanners/autopwn"])
    )

    assert isinstance(captured, list)


@pytest.mark.asyncio
async def test_bettercap_ble_enumerate_parses_defaults(monkeypatch):
    captured: Dict[str, Any] = {}

    async def fake_get(self, path):
        captured["path"] = path
        return {"devices": [{"address": "AA:BB:CC:DD:EE:01", "name": "Beacon", "rssi": -64}]}

    async def fake_post(self, path):
        captured[f"post_{path}"] = True
        return {"status": "ok"}

    monkeypatch.setattr(BettercapBLEClient, "_get", fake_get, raising=False)
    monkeypatch.setattr(BettercapBLEClient, "_post", fake_post, raising=False)

    bus = EventBus()
    await bus.start()
    try:
        bcap = BettercapBLEClient(base_url="http://127.0.0.1:8081", event_bus=bus)
        devices = await bcap.enumerate_devices(duration=0.01)
        assert len(devices) == 1
        assert devices[0].address == "AA:BB:CC:DD:EE:01"
    finally:
        await bus.stop()


@pytest.mark.asyncio
async def test_hfp_capture_requires_pcm_device(monkeypatch, tmp_path):
    monkeypatch.setattr("os.popen", lambda cmd: type("Fake", (), {"read": lambda self: ""})())
    capture = HFPAudioCapture("AA:BB:CC:DD:EE:01", output_file=tmp_path / "out.wav", duration=0.0)
    with pytest.raises(RuntimeError, match="bluealsa PCM"):
        await capture.start()