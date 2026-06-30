"""GPS, GeoMapper, NMEA, WardriveMode tests."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from urban_hs.core.event_bus import Event, EventBus
from urban_hs.modules.wifi.managers import GeoMapper, NMEAParser, WardriveMode


class _FakeGPS:
    fixed = True
    position = {"lat": 41.15, "lon": -8.62, "alt": 12.0, "accuracy": 2.5}

    def start(self): ...
    def stop(self): ...
    def is_fixed(self): ...
    def get_position(self): ...
    def add_snapshot(self, **kwargs): ...


def test_nmea_parser_valid_gpgga():
    line = "$GPGGA,092750.000,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47"
    parsed = NMEAParser.parse_line(line)
    assert parsed is not None
    assert parsed["sentence"] == "GPGGA"
    assert abs(parsed["lat"] - 48.1173) < 1e-4
    assert abs(parsed["lon"] - 11.5166) < 1e-4
    assert parsed["alt"] == 545.4


def test_nmea_parser_gprmc():
    line = "$GPRMC,092750.000,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A"
    parsed = NMEAParser.parse_line(line)
    assert parsed is not None
    assert parsed["sentence"] == "GPRMC"
    assert abs(parsed["lat"] - 48.1173) < 1e-4
    assert abs(parsed["lon"] - 11.5166) < 1e-4


def test_geomapper_add_snapshot_and_exports(tmp_path: Path):
    bus = EventBus()
    mapper = GeoMapper(event_bus=bus)
    snap = mapper.add_snapshot(bssid="aa:bb:cc:dd:ee:ff", essid="TestNet", channel=6, signal_dbm=-67)
    assert snap["bssid"] == "aa:bb:cc:dd:ee:ff"
    assert snap["essid"] == "TestNet"

    kml_file = tmp_path / "out.kml"
    assert mapper.export_kml(kml_file) == 0

    csv_file = tmp_path / "out.csv"
    assert mapper.export_wigle_csv(csv_file) == 0

    xml_file = tmp_path / "out.netxml"
    assert mapper.export_kismet_netxml(xml_file) == 0

    jsonl_file = tmp_path / "out.jsonl"
    assert mapper.export_jsonl(jsonl_file) == 0


def test_geomapper_export_when_fixed(tmp_path: Path):
    bus = EventBus()
    mapper = GeoMapper(gpsd_host="localhost", gpsd_port=2947, event_bus=bus)
    mapper._gps_data = {
        "lat": 41.15,
        "lon": -8.62,
        "alt": 12.0,
        "mode": 2,
        "epx": 1.0,
        "epy": 1.0,
    }
    assert mapper.is_fixed() is True
    mapper.add_snapshot(bssid="aa:bb:cc:dd:ee:ff", essid="TestNet")

    csv_file = tmp_path / "wigle.csv"
    count = mapper.export_wigle_csv(csv_file)
    assert count == 1
    assert "TestNet" in csv_file.read_text()


def test_wardrive_mode_lifecycle():
    async def _run():
        bus = EventBus()
        await bus.start()
        mapper = GeoMapper(event_bus=bus)
        mode = WardriveMode(mapper, scanner=_FakeGPS(), event_bus=bus)
        await mode.start(scan_interval=0.01)
        await asyncio.sleep(0.05)
        await mode.stop()
        await bus.stop()

    asyncio.run(_run())
