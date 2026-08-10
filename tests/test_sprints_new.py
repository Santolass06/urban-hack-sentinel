"""
Unit & Integration Tests for Sprints 1 to 4 Features.
"""


import pytest

from urban_hs.core.offloading import HashtopolisClient
from urban_hs.hal.wifi import InterfaceCapabilities, detect_interface_capabilities
from urban_hs.modules.wifi.attacks.wpa import FastTransitionAttack, WPA3DowngradeAttack
from urban_hs.modules.wifi.wigle import WigleClient


@pytest.mark.asyncio
async def test_sprint1_interface_capabilities():
    caps = await detect_interface_capabilities("wlan0")
    assert isinstance(caps, InterfaceCapabilities)
    assert caps.interface == "wlan0"
    data = caps.to_dict()
    assert "monitor_supported" in data
    assert "bands_supported" in data


@pytest.mark.asyncio
async def test_sprint2_wigle_client_no_creds():
    client = WigleClient(api_name=None, api_key=None)
    loc = await client.search_bssid("00:11:22:33:44:55")
    assert loc is None


@pytest.mark.asyncio
async def test_sprint3_wpa3_downgrade_attack():
    attack = WPA3DowngradeAttack(interface="wlan0")
    result = await attack.execute(target_bssid="00:11:22:33:44:55", channel=6)
    assert result.attack_type == "wpa3_downgrade"
    assert result.status.value == "success"
    assert result.metadata.get("downgrade_forced") is True


@pytest.mark.asyncio
async def test_sprint3_fast_transition_attack():
    attack = FastTransitionAttack(interface="wlan0")
    result = await attack.execute(target_bssid="00:11:22:33:44:55", channel=36)
    assert result.attack_type == "fast_transition_ft"
    assert result.status.value == "success"
    assert result.metadata.get("ft_cap_captured") is True


@pytest.mark.asyncio
async def test_sprint4_hashtopolis_client_no_token(tmp_path):
    hash_file = tmp_path / "test.22000"
    hash_file.write_text("WPA*01*test*", encoding="utf-8")
    client = HashtopolisClient(server_url="http://localhost:8080", api_token="")
    task = await client.upload_hash_file(hash_file)
    assert task is None
