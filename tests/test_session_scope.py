"""Tests for SessionScope — target/category allowlist and guard-rails."""

from __future__ import annotations

import pytest

from urban_hs.core.session_scope import SessionScope


# ------------------------------------------------------------------
# Construction defaults
# ------------------------------------------------------------------

class TestSessionScopeDefaults:
    def test_empty_scope_blocks_active(self) -> None:
        scope = SessionScope()
        assert scope.allow_active is False
        assert scope.allowed_targets == set()
        assert scope.allowed_categories == set()

    def test_empty_scope_blocks_everything(self) -> None:
        scope = SessionScope()
        assert scope.is_target_allowed("192.168.1.1") is False
        assert scope.is_category_allowed("wifi") is False
        assert scope.can_execute("192.168.1.1", "wifi") is False


# ------------------------------------------------------------------
# Guard rails — empty scope
# ------------------------------------------------------------------

class TestEmptyScopeBlocksActive:
    def test_no_targets_blocks(self) -> None:
        scope = SessionScope(allow_active=True, allowed_categories={"wifi"})
        assert scope.is_target_allowed("192.168.1.1") is False

    def test_no_categories_blocks(self) -> None:
        scope = SessionScope(allow_active=True, allowed_targets={"192.168.1.1"})
        assert scope.is_category_allowed("wifi") is False

    def test_allow_active_false_blocks_regardless(self) -> None:
        scope = SessionScope(
            allow_active=False,
            allowed_targets={"192.168.1.1"},
            allowed_categories={"wifi"},
        )
        assert scope.is_target_allowed("192.168.1.1") is False
        assert scope.is_category_allowed("wifi") is False
        assert scope.can_execute("192.168.1.1", "wifi") is False


# ------------------------------------------------------------------
# Allowlist — positive cases
# ------------------------------------------------------------------

class TestAllowlistPositive:
    def test_target_in_allowlist(self) -> None:
        scope = SessionScope(
            allow_active=True,
            allowed_targets={"192.168.1.1", "AA:BB:CC:DD:EE:FF"},
            allowed_categories={"wifi"},
        )
        assert scope.is_target_allowed("192.168.1.1") is True
        assert scope.is_target_allowed("AA:BB:CC:DD:EE:FF") is True

    def test_category_in_allowlist(self) -> None:
        scope = SessionScope(
            allow_active=True,
            allowed_targets={"10.0.0.1"},
            allowed_categories={"wifi", "ble"},
        )
        assert scope.is_category_allowed("wifi") is True
        assert scope.is_category_allowed("ble") is True

    def test_can_execute_allowed(self) -> None:
        scope = SessionScope(
            allow_active=True,
            allowed_targets={"10.0.0.1"},
            allowed_categories={"wifi"},
        )
        assert scope.can_execute("10.0.0.1", "wifi") is True


# ------------------------------------------------------------------
# Allowlist — negative cases
# ------------------------------------------------------------------

class TestAllowlistNegative:
    def test_target_not_in_allowlist(self) -> None:
        scope = SessionScope(
            allow_active=True,
            allowed_targets={"192.168.1.1"},
            allowed_categories={"wifi"},
        )
        assert scope.is_target_allowed("10.0.0.99") is False
        assert scope.can_execute("10.0.0.99", "wifi") is False

    def test_category_not_in_allowlist(self) -> None:
        scope = SessionScope(
            allow_active=True,
            allowed_targets={"192.168.1.1"},
            allowed_categories={"wifi"},
        )
        assert scope.is_category_allowed("ble") is False
        assert scope.can_execute("192.168.1.1", "ble") is False

    def test_wrong_category_with_valid_target(self) -> None:
        """Target is allowed but category is not — must block."""
        scope = SessionScope(
            allow_active=True,
            allowed_targets={"10.0.0.1"},
            allowed_categories={"network"},
        )
        assert scope.can_execute("10.0.0.1", "wifi") is False


# ------------------------------------------------------------------
# validate() — raises PermissionError
# ------------------------------------------------------------------

class TestValidateRaises:
    def test_validate_blocks_when_inactive(self) -> None:
        scope = SessionScope()
        with pytest.raises(PermissionError, match="Active attacks are disabled"):
            scope.validate("10.0.0.1", "wifi")

    def test_validate_blocks_empty_targets(self) -> None:
        scope = SessionScope(allow_active=True, allowed_categories={"wifi"})
        with pytest.raises(PermissionError, match="No targets in allowlist"):
            scope.validate("10.0.0.1", "wifi")

    def test_validate_blocks_empty_categories(self) -> None:
        scope = SessionScope(allow_active=True, allowed_targets={"10.0.0.1"})
        with pytest.raises(PermissionError, match="No attack categories in allowlist"):
            scope.validate("10.0.0.1", "wifi")

    def test_validate_blocks_unknown_target(self) -> None:
        scope = SessionScope(
            allow_active=True,
            allowed_targets={"10.0.0.1"},
            allowed_categories={"wifi"},
        )
        with pytest.raises(PermissionError, match="not in the session allowlist"):
            scope.validate("10.0.0.99", "wifi")

    def test_validate_blocks_unknown_category(self) -> None:
        scope = SessionScope(
            allow_active=True,
            allowed_targets={"10.0.0.1"},
            allowed_categories={"wifi"},
        )
        with pytest.raises(PermissionError, match="not in the session allowlist"):
            scope.validate("10.0.0.1", "ble")

    def test_validate_passes_for_valid(self) -> None:
        scope = SessionScope(
            allow_active=True,
            allowed_targets={"10.0.0.1"},
            allowed_categories={"wifi"},
        )
        scope.validate("10.0.0.1", "wifi")


# ------------------------------------------------------------------
# Edge cases
# ------------------------------------------------------------------

class TestEdgeCases:
    def test_ssid_as_target(self) -> None:
        scope = SessionScope(
            allow_active=True,
            allowed_targets={"MyWiFiNetwork"},
            allowed_categories={"wifi"},
        )
        assert scope.is_target_allowed("MyWiFiNetwork") is True
        assert scope.can_execute("MyWiFiNetwork", "wifi") is True

    def test_multiple_categories(self) -> None:
        scope = SessionScope(
            allow_active=True,
            allowed_targets={"10.0.0.1"},
            allowed_categories={"wifi", "ble", "network"},
        )
        for cat in ("wifi", "ble", "network"):
            assert scope.is_category_allowed(cat) is True
        assert scope.is_category_allowed("exploit") is False

    def test_scope_with_only_active_toggle(self) -> None:
        """allow_active=True but empty sets should still block."""
        scope = SessionScope(allow_active=True)
        assert scope.can_execute("anything", "anything") is False
