"""
Contract tests for ``urban_hs.modules.wifi.fragattacks``.

Validates:
- construction/defaults
- path when tool is missing
- parsing of vulnerable / not-vulnerable outputs
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from urban_hs.modules.wifi.fragattacks import (
    FragAttackConfig,
    FragAttackResult,
    FragAttackType,
    FragAttacksWrapper,
)


@pytest.fixture()
def wrapper():
    return FragAttacksWrapper(
        config=FragAttackConfig(
            interface="wlan0",
            attack_timeout=5,
        )
    )


def test_default_config():
    cfg = FragAttackConfig()
    assert cfg.interface == "wlan0"
    assert cfg.attack_timeout == 120
    assert cfg.attack_types is None


def test_missing_tool_returns_not_vulnerable(wrapper):
    wrapper.fragattacks_path = None
    import asyncio
    results = asyncio.run(wrapper.run_tests(
        target_bssid="AA:BB:CC:DD:EE:FF",
        channel=1,
    ))
    assert all(r.vulnerable is False for r in results)


def test_parse_vulnerable_output(wrapper):
    assert wrapper._parse_result("Device is vulnerable to fragmentation", FragAttackType.FRAGMENTATION) is True


def test_parse_not_vulnerable_output(wrapper):
    assert wrapper._parse_result("Test completed, no issues found.", FragAttackType.MIXED_KEY) is False


def test_build_command_returns_none_for_unknown_type(wrapper):
    assert wrapper._build_command(
        attack_type=FragAttackType.ALL,
        target="AA:BB:CC:DD:EE:FF",
        channel=1,
        client_mac=None,
    ) is None


def test_result_dataclass_defaults():
    r = FragAttackResult(attack_type=FragAttackType.FRAGMENTATION, vulnerable=False)
    assert r.affected_frames == 0
    assert r.details == ""