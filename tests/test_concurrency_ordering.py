"""B016: acquire_multiple must lock in a deterministic global order."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from urban_hs.core.concurrency import ResourceManager, ResourcePriority, ResourceType


@pytest.mark.asyncio
async def test_acquire_multiple_uses_global_lock_order() -> None:
    manager = ResourceManager.__new__(ResourceManager)
    from collections import defaultdict

    manager._holder_resources = defaultdict(set)

    order: list[str] = []

    async def fake_acquire(rt, holder, prio, wait):
        order.append(rt.name)
        return True

    manager.pool = AsyncMock()
    manager.pool.acquire = fake_acquire

    # Two callers request the same set in opposite insertion orders.
    a = {ResourceType.RADIO: ResourcePriority.HIGH, ResourceType.CPU: ResourcePriority.LOW}
    b = {ResourceType.CPU: ResourcePriority.LOW, ResourceType.RADIO: ResourcePriority.HIGH}

    order.clear()
    await manager.acquire_multiple(a, "holderA")
    order_a = list(order)
    order.clear()
    await manager.acquire_multiple(b, "holderB")
    order_b = list(order)

    # Both acquire in the same sorted order -> no lock-ordering deadlock.
    assert order_a == order_b == sorted(order_a)
