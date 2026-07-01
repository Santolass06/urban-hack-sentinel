"""Session scope — allowlist of targets and attack categories.

A ``SessionScope`` defines which targets (IP, MAC, SSID) and which
categories of attacks (wifi, ble, network) are permitted for the
current session.  Guard-rails ensure that:

* An **empty** scope (no allowlist) blocks all active attacks.
* A target not in the allowlist is rejected.
* A category not in the allowed set is rejected even if the target is
  allowed.

This module is intentionally standalone — it does not import any
hardware or scanner code so it can be tested without dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Set


@dataclass
class SessionScope:
    """Defines the permitted targets and attack categories for a session.

    Attributes:
        allowed_targets: Set of target identifiers (IP addresses, MAC
            addresses, SSIDs).  An empty set means **no** target is
            allowed for active attacks.
        allowed_categories: Set of attack category names (e.g.
            ``"wifi"``, ``"ble"``, ``"network"``).  An empty set means
            **no** category is allowed.
        allow_active: Master toggle.  When *False*, all active attacks
            are blocked regardless of target/category.
    """

    allowed_targets: Set[str] = field(default_factory=set)
    allowed_categories: Set[str] = field(default_factory=set)
    allow_active: bool = False

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def is_target_allowed(self, target: str) -> bool:
        """Return *True* if *target* is in the allowlist."""
        if not self.allow_active:
            return False
        if not self.allowed_targets:
            return False
        return target in self.allowed_targets

    def is_category_allowed(self, category: str) -> bool:
        """Return *True* if *category* is in the allowed set."""
        if not self.allow_active:
            return False
        if not self.allowed_categories:
            return False
        return category in self.allowed_categories

    def can_execute(self, target: str, category: str) -> bool:
        """Return *True* if an attack on *target* in *category* may proceed.

        Both the target and the category must be explicitly allowed.
        """
        return self.is_target_allowed(target) and self.is_category_allowed(category)

    def validate(self, target: str, category: str) -> None:
        """Raise ``PermissionError`` if the attack is not permitted.

        The error message is human-readable and suitable for display
        in the TUI / Web UI.
        """
        if not self.allow_active:
            raise PermissionError(
                "Active attacks are disabled. "
                "Set allow_active=True or provide an explicit scope."
            )
        if not self.allowed_targets:
            raise PermissionError(
                "No targets in allowlist. "
                "Add at least one target to SessionScope.allowed_targets."
            )
        if not self.allowed_categories:
            raise PermissionError(
                "No attack categories in allowlist. "
                "Add at least one category to SessionScope.allowed_categories."
            )
        if target not in self.allowed_targets:
            raise PermissionError(
                f"Target '{target}' is not in the session allowlist."
            )
        if category not in self.allowed_categories:
            raise PermissionError(
                f"Category '{category}' is not in the session allowlist."
            )


# ----------------------------------------------------------------------
# Process-wide active scope — single source of truth
# ----------------------------------------------------------------------
#
# Both the REST execution path (ui/api/routers/attacks.py) and the
# event-bus attack handlers (modules/wifi/plugin.py,
# modules/urban_hack.py) must consult the *same* scope instance, otherwise
# a scope configured on one path would not gate the other. The singleton
# lives here in ``core`` (the lowest layer) so module handlers can import
# it without depending on the UI layer.

_active_scope: SessionScope = SessionScope()


def get_active_scope() -> SessionScope:
    """Return the process-wide active session scope."""
    return _active_scope


def set_active_scope(scope: SessionScope) -> None:
    """Replace the process-wide active session scope."""
    global _active_scope
    _active_scope = scope
