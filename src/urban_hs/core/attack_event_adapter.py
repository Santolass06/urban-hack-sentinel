"""
Standardizes module-specific events into the UI-facing attack contract.

Listens for legacy/category-specific events and republishes them as
canonical `attack.*` events so the TUI and Web UI only need to know
one contract.
"""

from __future__ import annotations

import uuid
from typing import Set

from urban_hs.core.event_bus import Event, EventHandler, EventPriority, get_event_bus

_CANONICAL_TYPES = {
    "wifi.scan_complete",
    "wifi.attack_complete",
    "wifi.attack_failed",
    "ble.scan_complete",
    "ble.attack_complete",
    "ble.attack_failed",
    "network.scan_complete",
    "network.scan_failed",
}


class AttackEventNormalizer(EventHandler):
    """Bridge between module-specific events and the UI attack contract."""

    @property
    def event_types(self) -> Set[str]:
        return set(_CANONICAL_TYPES)

    async def handle(self, event: Event) -> None:
        bus = get_event_bus()
        source = event.source or "module"
        payload = dict(event.payload or {})

        if event.type == "wifi.scan_complete":
            payload.setdefault("attack", "wifi_scan")
            await bus.publish(
                Event(
                    type="attack.completed",
                    payload=payload,
                    timestamp=event.timestamp,
                    correlation_id=event.correlation_id,
                    source=source,
                    priority=EventPriority.NORMAL,
                    metadata={"original_type": event.type},
                )
            )

        elif event.type == "wifi.attack_complete":
            payload.setdefault("attack", "wifi_attack")
            await bus.publish(
                Event(
                    type="attack.completed",
                    payload=payload,
                    timestamp=event.timestamp,
                    correlation_id=event.correlation_id,
                    source=source,
                    priority=EventPriority.NORMAL,
                    metadata={"original_type": event.type},
                )
            )

        elif event.type == "wifi.attack_failed":
            payload.setdefault("attack", "wifi_attack")
            payload.setdefault("error", str(payload.get("error", "Unknown error")))
            await bus.publish(
                Event(
                    type="attack.error",
                    payload=payload,
                    timestamp=event.timestamp,
                    correlation_id=event.correlation_id,
                    source=source,
                    priority=EventPriority.HIGH,
                    metadata={"original_type": event.type},
                )
            )

        elif event.type == "ble.scan_complete":
            payload.setdefault("attack", "ble_scan")
            await bus.publish(
                Event(
                    type="attack.completed",
                    payload=payload,
                    timestamp=event.timestamp,
                    correlation_id=event.correlation_id,
                    source=source,
                    priority=EventPriority.NORMAL,
                    metadata={"original_type": event.type},
                )
            )

        elif event.type == "ble.attack_complete":
            payload.setdefault("attack", "ble_attack")
            await bus.publish(
                Event(
                    type="attack.completed",
                    payload=payload,
                    timestamp=event.timestamp,
                    correlation_id=event.correlation_id,
                    source=source,
                    priority=EventPriority.NORMAL,
                    metadata={"original_type": event.type},
                )
            )

        elif event.type == "ble.attack_failed":
            payload.setdefault("attack", "ble_attack")
            payload.setdefault("error", str(payload.get("error", "Unknown error")))
            await bus.publish(
                Event(
                    type="attack.error",
                    payload=payload,
                    timestamp=event.timestamp,
                    correlation_id=event.correlation_id,
                    source=source,
                    priority=EventPriority.HIGH,
                    metadata={"original_type": event.type},
                )
            )

        elif event.type == "network.scan_complete":
            payload.setdefault("attack", "network_scan")
            await bus.publish(
                Event(
                    type="attack.completed",
                    payload=payload,
                    timestamp=event.timestamp,
                    correlation_id=event.correlation_id,
                    source=source,
                    priority=EventPriority.NORMAL,
                    metadata={"original_type": event.type},
                )
            )

        elif event.type == "network.scan_failed":
            payload.setdefault("attack", "network_scan")
            payload.setdefault("error", str(payload.get("error", "Unknown error")))
            await bus.publish(
                Event(
                    type="attack.error",
                    payload=payload,
                    timestamp=event.timestamp,
                    correlation_id=event.correlation_id,
                    source=source,
                    priority=EventPriority.HIGH,
                    metadata={"original_type": event.type},
                )
            )
