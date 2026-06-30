"""Tests for attack base classes and types."""

import pytest
from datetime import datetime
from urban_hs.modules.wifi.attacks.base import AttackStatus, AttackResult


class TestAttackStatus:
    def test_values(self):
        assert AttackStatus.PENDING.value == "pending"
        assert AttackStatus.RUNNING.value == "running"
        assert AttackStatus.SUCCESS.value == "success"
        assert AttackStatus.FAILED.value == "failed"
        assert AttackStatus.TIMEOUT.value == "timeout"
        assert AttackStatus.CANCELLED.value == "cancelled"

    def test_all_members(self):
        assert len(AttackStatus) == 6


class TestAttackResult:
    def test_creation(self):
        result = AttackResult(
            attack_type="handshake",
            target_bssid="AA:BB:CC:DD:EE:FF",
            target_essid="TestNetwork",
            status=AttackStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        assert result.attack_type == "handshake"
        assert result.status == AttackStatus.RUNNING
        assert result.duration_seconds is None

    def test_duration(self):
        start = datetime(2025, 1, 1, 12, 0, 0)
        end = datetime(2025, 1, 1, 12, 0, 30)
        result = AttackResult(
            attack_type="test",
            target_bssid="AA:BB:CC:DD:EE:FF",
            target_essid=None,
            status=AttackStatus.SUCCESS,
            started_at=start,
            finished_at=end,
        )
        assert result.duration_seconds == 30.0

    def test_to_dict(self):
        result = AttackResult(
            attack_type="pmkid",
            target_bssid="AA:BB:CC:DD:EE:FF",
            target_essid="Test",
            status=AttackStatus.SUCCESS,
            started_at=datetime(2025, 1, 1, 12, 0, 0),
            finished_at=datetime(2025, 1, 1, 12, 0, 10),
        )
        d = result.to_dict()
        assert d["attack_type"] == "pmkid"
        assert d["status"] == "success"
        assert d["duration_seconds"] == 10.0

    def test_to_dict_no_finish(self):
        result = AttackResult(
            attack_type="test",
            target_bssid="AA:BB:CC:DD:EE:FF",
            target_essid=None,
            status=AttackStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        d = result.to_dict()
        assert d["finished_at"] is None
        assert d["duration_seconds"] is None

    def test_metadata(self):
        result = AttackResult(
            attack_type="test",
            target_bssid="AA:BB:CC:DD:EE:FF",
            target_essid=None,
            status=AttackStatus.SUCCESS,
            started_at=datetime.utcnow(),
            metadata={"key": "value"},
        )
        assert result.metadata["key"] == "value"

    def test_error_message(self):
        result = AttackResult(
            attack_type="test",
            target_bssid="AA:BB:CC:DD:EE:FF",
            target_essid=None,
            status=AttackStatus.FAILED,
            started_at=datetime.utcnow(),
            error_message="Something went wrong",
        )
        assert result.error_message == "Something went wrong"

    def test_output_files(self):
        result = AttackResult(
            attack_type="test",
            target_bssid="AA:BB:CC:DD:EE:FF",
            target_essid=None,
            status=AttackStatus.SUCCESS,
            started_at=datetime.utcnow(),
            output_files=["/tmp/capture.pcap", "/tmp/handshake.cap"],
        )
        assert len(result.output_files) == 2
