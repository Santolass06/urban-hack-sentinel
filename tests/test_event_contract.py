"""T10.7 — attack event contract."""

from __future__ import annotations

import asyncio
from typing import Set

import pytest
from urban_hs.core.event_bus import Event, EventHandler, get_event_bus
from urban_hs.core.attack_event_adapter import AttackEventNormalizer


class _Collector(EventHandler):
    def __init__(self) -> None:
        self.events: list[Event] = []

    @property
    def event_types(self) -> Set[str]:
        return {"*"}

    async def handle(self, event: Event) -> None:
        self.events.append(event)


@pytest.mark.anyio
async def test_wifi_scan_complete_is_normalized_to_attack_completed() -> None:
    bus = get_event_bus()
    normalizer = AttackEventNormalizer()
    await bus.start()
    collector = _Collector()
    try:
        bus.subscribe(collector)
        bus.subscribe(normalizer)

        await bus.publish(
            Event(
                type="wifi.scan_complete",
                payload={"networks": []},
                source="wifi.plugin",
                correlation_id="corr-1",
            )
        )

        await bus._queue.join()
        await asyncio.sleep(0)

        normalized = [e for e in collector.events if e.type == "attack.completed"]
        assert len(normalized) == 1, collector.events
        assert normalized[0].payload["attack"] == "wifi_scan"
        assert normalized[0].correlation_id == "corr-1"
    finally:
        bus.unsubscribe(normalizer)
        bus.unsubscribe(collector)
        await bus.stop()
