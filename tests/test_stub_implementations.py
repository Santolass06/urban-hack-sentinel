"""Regression tests for stubs that were replaced with real implementations."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from xml.dom import minidom


# --- HID keycode map (was: US-only, no shift, duplicate '2' key) -------------
def test_hid_keycode_map_covers_shift_and_symbols() -> None:
    from urban_hs.modules.hid.injector import UInputInjector as U

    assert U._char_to_keycode("a") == (30, False)
    assert U._char_to_keycode("A") == (30, True)
    assert U._char_to_keycode("1") == (2, False)
    assert U._char_to_keycode("!") == (2, True)  # shifted digit
    assert U._char_to_keycode("?") == (53, True)  # shifted punctuation
    assert U._char_to_keycode("/") == (53, False)
    assert U._char_to_keycode(" ") == (57, False)
    assert U._char_to_keycode("€") is None  # not on a US keyboard


# --- Bluetooth HID SDP record (was: b"") -------------------------------------
def test_bt_hid_sdp_record_is_wellformed_xml() -> None:
    from urban_hs.modules.bt_hid import BlueZHIDProfile, BTHIDConfig

    record = BlueZHIDProfile(BTHIDConfig(target_address="AA:BB:CC:DD:EE:FF")).sdp_record
    assert isinstance(record, str)
    minidom.parseString(record)  # raises on malformed XML
    hexval = re.search(r'encoding="hex" value="([0-9a-f]+)"', record).group(1)
    bytes.fromhex(hexval)  # report descriptor is valid hex


# --- hashcat 22000 PMKID parsing (was: bssid="", essid=None) ------------------
def test_pmkid_hash_parsing(tmp_path: Path) -> None:
    from urban_hs.modules.wifi.managers import HandshakeManager

    manager = HandshakeManager.__new__(HandshakeManager)
    line = "WPA*01*" + "0" * 32 + "*4604ba734d4e*89acf0e761f4*546573744e6574*"
    hash_file = tmp_path / "h.22000"
    hash_file.write_text(line + "\n")

    info = manager._parse_hash_file(hash_file)
    assert info.bssid == "46:04:ba:73:4d:4e"
    assert info.essid == "TestNet"


# --- Kismet netXML export (was: return 0) ------------------------------------
def test_kismet_netxml_export(tmp_path: Path) -> None:
    from urban_hs.modules.wifi.managers import HandshakeInfo, HandshakeManager

    manager = HandshakeManager.__new__(HandshakeManager)
    manager._handshakes = {
        "a": HandshakeInfo(
            id="a",
            bssid="46:04:ba:73:4d:4e",
            essid="Test<&>Net",
            capture_path="",
            hash_path="",
            hashcat_mode=22000,
            gps_lat=1.5,
            gps_lon=-2.5,
        )
    }
    out = tmp_path / "o.netxml"
    count = manager.export_kismet_netxml(out)

    assert count == 1
    minidom.parseString(out.read_text())
    assert "Test&lt;&amp;&gt;Net" in out.read_text()  # XML-escaped essid


# --- HTTP Digest auth (was: returns verified=False) --------------------------
def test_digest_auth_matches_rfc2617_vector() -> None:
    from urban_hs.modules.camera.enumeration import CameraEnumerator

    h = lambda s: hashlib.md5(s.encode()).hexdigest()  # noqa: E731
    ha1 = h("Mufasa:testrealm@host.com:Circle Of Life")
    ha2 = h("GET:/dir/index.html")

    challenge = (
        'Digest realm="testrealm@host.com", qop="auth", '
        'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c"'
    )
    params = CameraEnumerator._parse_digest_challenge(challenge)
    assert params["realm"] == "testrealm@host.com"

    header = CameraEnumerator._build_digest_header(
        "Mufasa", "Circle Of Life", "GET", "/dir/index.html", params
    )
    fields = {k: (a or b) for k, a, b in re.findall(r'(\w+)=(?:"([^"]*)"|([^,\s]+))', header)}
    expected = h(f"{ha1}:{fields['nonce']}:{fields['nc']}:{fields['cnonce']}:{fields['qop']}:{ha2}")
    assert fields["response"] == expected
    assert fields["opaque"] == "5ccc069c"


# --- FragAttacks affected-frame counting (was: 0 hardcoded) ------------------
def test_fragattacks_affected_frame_count() -> None:
    from urban_hs.modules.wifi.fragattacks import FragAttacksWrapper as F

    assert F._count_affected_frames("Injected 12 frames total") == 12
    assert F._count_affected_frames("Injected frame\nReceived frame\nfragment") == 3
    assert F._count_affected_frames("nothing") == 0


# --- SLSA provenance verification (was: return True unconditionally) ----------
async def test_slsa_verification_fails_closed_without_verifier() -> None:
    from urban_hs.core import security

    verifier_cls = next(
        obj
        for obj in vars(security).values()
        if isinstance(obj, type) and "verify_slsa_provenance" in obj.__dict__
    )
    config_cls = next(
        obj
        for obj in vars(security).values()
        if isinstance(obj, type)
        and obj.__name__.endswith("Config")
        and "SupplyChain" in obj.__name__
    )
    verifier = verifier_cls(config_cls())

    # slsa-verifier is absent here — must fail closed (False), never trust.
    result = await verifier.verify_slsa_provenance("/nonexistent/artifact")
    assert result is False


# --- WPA3 transition-downgrade detection + Kr00k/WPA3 handler wiring ----------
def test_wpa3_transition_detection_and_plugin_wiring() -> None:
    from urban_hs.modules.wifi.attacks.deauth import WPA3DowngradeAttack
    from urban_hs.modules.wifi.plugin import WiFiPlugin

    # Only WPA3 transition-mode (PMF not required) is downgradable.
    assert WPA3DowngradeAttack.is_transition_mode({"encryption": "WPA3", "pmf": "optional"}) is True
    assert (
        WPA3DowngradeAttack.is_transition_mode({"encryption": "WPA3", "pmf": "required"}) is False
    )
    assert (
        WPA3DowngradeAttack.is_transition_mode({"encryption": "WPA2", "pmf": "disabled"}) is False
    )

    # Previously silent no-op buttons now have real backends.
    assert hasattr(WiFiPlugin, "execute_kr00k")
    assert hasattr(WiFiPlugin, "execute_wpa3_downgrade")
    import inspect

    handler_src = inspect.getsource(
        WiFiPlugin.__module__ and __import__("urban_hs.modules.wifi.plugin", fromlist=["x"])
    )
    assert '"krook"' in handler_src and '"wpa3_downgrade"' in handler_src


# --- RouterSploit autopwn scan (was: scan_router returned []) -----------------
def test_router_autopwn_output_parsing() -> None:
    from urban_hs.modules.network.router import RouterScanner

    sample = (
        "[+] 10.0.0.1 exploits/routers/dlink/dir_300_600_rce is vulnerable\n"
        "[-] 10.0.0.1 exploits/routers/asus/infosvr_auth_bypass is not vulnerable\n"
        "[-] 10.0.0.1 exploits/routers/netgear/x is non-vulnerable\n"
        "[*] 10.0.0.1 creds/generic/http_basic_bruteforce is vulnerable\n"
    )
    findings = RouterScanner._parse_autopwn_output(sample, "10.0.0.1")
    modules = sorted(f["module"] for f in findings)
    assert modules == [
        "creds/generic/http_basic_bruteforce",
        "exploits/routers/dlink/dir_300_600_rce",
    ]
    assert all(f["vulnerable"] and f["ip"] == "10.0.0.1" for f in findings)


# --- attack_all parallel fan-out (from hermes/correction) --------------------
async def test_attack_all_fans_out_and_respects_gates() -> None:
    from unittest.mock import AsyncMock, patch

    from urban_hs.modules.urban_hack import UrbanHackConfig, UrbanHackPlugin

    plugin = UrbanHackPlugin(UrbanHackConfig(max_parallel_attacks=5))
    # Config-driven semaphore (was hardcoded to 3).
    assert plugin._attack_semaphore._value == 5

    calls: list[str] = []

    async def _rec(name: str, **kw):
        calls.append(name)
        return {"status": "ok"}

    plugin.execute_handshake_attack = lambda **kw: _rec("handshake", **kw)
    plugin.execute_pmkid_attack = lambda **kw: _rec("pmkid", **kw)
    plugin.execute_wps_pixie_attack = lambda **kw: _rec("wps_pixie", **kw)
    plugin.execute_wps_pin_attack = lambda **kw: _rec("wps_pin", **kw)
    plugin.execute_deauth = lambda **kw: _rec("deauth", **kw)
    plugin.execute_ble_vuln_test = lambda *a, **kw: _rec("ble_test")

    storage = AsyncMock()
    storage.list_devices = AsyncMock(
        side_effect=lambda device_type, **kw: (
            [{"mac": "AA:BB:CC:DD:EE:FF", "meta": {"channel": 6}}]
            if device_type == "wifi_ap"
            else [{"mac": "11:22:33:44:55:66"}]
        )
    )

    with patch("urban_hs.modules.urban_hack.get_storage", return_value=storage):
        summary = await plugin.attack_all()

    # 4 passive WiFi variants + 1 BLE test; deauth skipped (active attacks off).
    assert sorted(set(calls)) == ["ble_test", "handshake", "pmkid", "wps_pin", "wps_pixie"]
    assert "deauth" not in calls
    assert summary["dispatched"] == 5 and summary["ok"] == 5
