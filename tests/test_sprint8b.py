"""
Tests for Sprint 8B forensics primitives:
- MAC anonymisation
- Evidence bundle hashing/indexing
- Retention policy expiry
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from urban_hs.core.mac_anonymiser import (
    pseudonymise_mac,
    pseudonymise_macs,
    redact_text,
)
from urban_hs.core.forensics import EvidenceBundle, RetentionPolicy


class TestMacAnonymiser:
    def test_pseudonymise_mac_preserves_format_and_is_deterministic(self):
        mac = "aa:bb:cc:dd:ee:ff"
        first = pseudonymise_mac(mac)
        second = pseudonymise_mac(mac)
        assert first == second
        assert len(first) == len(mac)
        assert first.count(":") == mac.count(":")

    def test_pseudonymise_mac_returns_empty_string_for_none(self):
        assert pseudonymise_mac(None) == ""
        assert pseudonymise_mac("") == ""

    def test_pseudonymise_macs_redacts_dict_fields(self):
        sample = {
            "mac": "aa:bb:cc:dd:ee:ff",
            "bssid": "11:22:33:44:55:66",
            "name": "known-ssid",
        }
        redacted = pseudonymise_macs(sample)
        assert redacted["mac"] != sample["mac"]
        assert redacted["bssid"] != sample["bssid"]
        assert redacted["name"] == sample["name"]

    def test_pseudonymise_macs_handles_nested_structures(self):
        sample = {
            "devices": [
                {"mac": "aa:bb:cc:dd:ee:ff"},
                {"mac": "11:22:33:44:55:66"},
            ]
        }
        redacted = pseudonymise_macs(sample)
        assert redacted["devices"][0]["mac"] != "aa:bb:cc:dd:ee:ff"
        assert redacted["devices"][0]["mac"] != redacted["devices"][1]["mac"]

    def test_redact_text_replaces_mac_addresses(self):
        text = "client aa:bb:cc:dd:ee:ff used bssid 11:22:33:44:55:66"
        cleaned = redact_text(text)
        assert "aa:bb:cc:dd:ee:ff" not in cleaned
        assert "11:22:33:44:55:66" not in cleaned


class TestRetentionPolicy:
    def test_expired_future_timestamp_is_false(self):
        policy = RetentionPolicy(default_ttl_days=30, grace_days=7)
        future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        assert policy.expired(future) is False

    def test_expired_old_timestamp_is_true(self):
        policy = RetentionPolicy(default_ttl_days=0, grace_days=0)
        old = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        assert policy.expired(old) is True

    def test_expired_none_is_true(self):
        policy = RetentionPolicy()
        assert policy.expired(None) is True


class TestEvidenceBundle:
    def test_add_indexes_artifact(self, tmp_path):
        bundle = EvidenceBundle(session_id="s1", base_dir=str(tmp_path))
        target = tmp_path / "artifact.txt"
        target.write_text("urban-hs-forensics", encoding="utf-8")

        record = bundle.add(str(target))

        assert record["sha256"]
        assert record["blake2b"]
        assert record["path"] == str(target)
        assert record["size_bytes"] == target.stat().st_size
        assert len(bundle.records) == 1

    def test_write_index_creates_json(self, tmp_path):
        bundle = EvidenceBundle(session_id="s1", base_dir=str(tmp_path))
        target = tmp_path / "artifact.txt"
        target.write_text("urban-hs-forensics", encoding="utf-8")
        bundle.add(str(target))

        index = bundle.write_index()
        data = json.loads(Path(index).read_text(encoding="utf-8"))

        assert data["session_id"] == "s1"
        assert len(data["artifacts"]) == 1
        assert len(data["custody"]) == 1

    def test_add_missing_file_raises(self, tmp_path):
        bundle = EvidenceBundle(session_id="s1", base_dir=str(tmp_path))
        with pytest.raises(FileNotFoundError):
            bundle.add(str(tmp_path / "missing.txt"))
