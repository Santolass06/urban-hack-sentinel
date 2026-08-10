"""Hardware compatibility checker (rescued/wired from the hermes audit)."""

from __future__ import annotations

from urban_hs.core.hardware_compatibility import Capability, HardwareCompatibilityChecker


def test_check_command_present_and_absent() -> None:
    checker = HardwareCompatibilityChecker(interface="lo")
    # A tool that certainly exists on any Linux box.
    present = checker.check_command(Capability.NMAP, "sh")
    assert present.supported is True
    # A tool that certainly does not.
    absent = checker.check_command(Capability.NUCLEI, "definitely-not-a-real-binary-xyz")
    assert absent.supported is False
    assert absent.remediation or absent.reason  # gives the operator a hint


def test_requirements_reports_are_structured() -> None:
    checker = HardwareCompatibilityChecker(interface="lo")
    wifi = checker.wifi_requirements()
    ble = checker.ble_requirements()
    assert wifi.module and ble.module
    for rep in (wifi, ble):
        assert rep.results, "each report lists concrete capability checks"
        assert isinstance(rep.supported, bool)
        assert isinstance(rep.to_dict(), dict)
