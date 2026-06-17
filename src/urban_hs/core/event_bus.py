"""
Event Bus - Central pub/sub system for decoupled module communication.

Uses asyncio.Queue for async event delivery with backpressure support.
Supports typed events, dead letter queue, and subscriber priorities.
"""

import asyncio
import logging
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Type, TypeVar
from weakref import WeakSet

import structlog

logger = structlog.get_logger(__name__)

T = TypeVar("T")


class EventPriority(Enum):
    LOW = 0
    NORMAL = 50
    HIGH = 100
    CRITICAL = 200


@dataclass
class Event:
    """Base event class with metadata."""
    type: str
    payload: Any = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: Optional[str] = None
    priority: EventPriority = EventPriority.NORMAL
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __lt__(self, other: "Event") -> bool:
        return self.priority.value > other.priority.value  # Higher priority first


class EventHandler(ABC):
    """Abstract base for event handlers."""

    @abstractmethod
    async def handle(self, event: Event) -> None:
        pass

    @property
    @abstractmethod
    def event_types(self) -> Set[str]:
        pass


class DeadLetterQueue:
    """Stores events that failed processing for later inspection."""

    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self._queue: asyncio.Queue[tuple[Event, Exception]] = asyncio.Queue(maxsize=max_size)

    async def add(self, event: Event, error: Exception) -> None:
        try:
            self._queue.put_nowait((event, error))
        except asyncio.QueueFull:
            logger.warning("DLQ full, dropping oldest", dropped=event.type)
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            await self.add(event, error)

    async def get_all(self) -> List[tuple[Event, Exception]]:
        items = []
        while not self._queue.empty():
            try:
                items.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return items


class EventBus:
    """
    Central event bus for pub/sub communication between modules.
    
    Features:
    - Typed event subscription
    - Priority-based delivery
    - Dead letter queue for failed events
    - Subscriber weak references (auto-cleanup)
    - Backpressure via queue limits
    """

    def __init__(
        self,
        max_queue_size: int = 10000,
        dlq_max_size: int = 1000,
        worker_count: int = 4,
    ):
        self.max_queue_size = max_queue_size
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=max_queue_size)
        self._subscribers: Dict[str, WeakSet[EventHandler]] = defaultdict(WeakSet)
        self._running = False
        self._workers: List[asyncio.Task] = []
        self._worker_count = worker_count
        self._dlq = DeadLetterQueue(dlq_max_size)
        self._stats = {
            "published": 0,
            "delivered": 0,
            "failed": 0,
            "dlq_size": 0,
        }

    async def start(self) -> None:
        """Start the event processing workers."""
        if self._running:
            return
        self._running = True
        self._workers = [
            asyncio.create_task(self._worker(f"worker-{i}"))
            for i in range(self._worker_count)
        ]
        logger.info("Event bus started", workers=self._worker_count)

    async def stop(self, timeout: float = 5.0) -> None:
        """Stop the event bus gracefully."""
        if not self._running:
            return
        self._running = False
        # Wait for queue to drain
        await asyncio.wait_for(self._queue.join(), timeout=timeout)
        # Cancel workers
        for w in self._workers:
            w.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        logger.info("Event bus stopped", stats=self._stats)

    def subscribe(self, handler: EventHandler) -> None:
        """Register an event handler for its declared event types."""
        for event_type in handler.event_types:
            self._subscribers[event_type].add(handler)
            logger.debug("Subscribed handler", event_type=event_type, handler=type(handler).__name__)

    def unsubscribe(self, handler: EventHandler) -> None:
        """Unregister an event handler."""
        for event_type in handler.event_types:
            self._subscribers[event_type].discard(handler)

    async def publish(self, event: Event) -> bool:
        """
        Publish an event to the bus.
        
        Returns True if queued, False if queue full (backpressure).
        """
        if not self._running:
            logger.warning("Event bus not running, dropping event", event_type=event.type)
            return False

        try:
            self._queue.put_nowait(event)
            self._stats["published"] += 1
            return True
        except asyncio.QueueFull:
            logger.warning("Event bus queue full, backpressure", event_type=event.type)
            return False

    async def publish_async(self, event: Event) -> None:
        """Publish with await (blocks if queue full)."""
        if not self._running:
            raise RuntimeError("Event bus not running")
        await self._queue.put(event)
        self._stats["published"] += 1

    async def _worker(self, name: str) -> None:
        """Worker task that processes events from the queue."""
        logger.debug("Event worker started", name=name)
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                await self._dispatch(event)
                self._queue.task_done()
                self._stats["delivered"] += 1
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Worker error", name=name, error=str(e))
                self._stats["failed"] += 1

    async def _dispatch(self, event: Event) -> None:
        """Dispatch event to all matching subscribers."""
        handlers = self._subscribers.get(event.type, set())
        
        # Also dispatch to wildcard subscribers
        wildcard_handlers = self._subscribers.get("*", set())
        all_handlers = list(handlers) + list(wildcard_handlers)

        if not all_handlers:
            logger.debug("No handlers for event", event_type=event.type)
            return

        # Execute all handlers concurrently
        tasks = [self._safe_handle(h, event) for h in all_handlers]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _safe_handle(self, handler: EventHandler, event: Event) -> None:
        """Safely execute handler, capturing errors to DLQ."""
        try:
            await handler.handle(event)
        except Exception as e:
            self._stats["failed"] += 1
            logger.error(
                "Handler failed",
                handler=type(handler).__name__,
                event_type=event.type,
                error=str(e),
            )
            await self._dlq.add(event, e)

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "queue_size": self._queue.qsize(),
            "subscriber_counts": {k: len(v) for k, v in self._subscribers.items()},
            "dlq_size": self._dlq.max_size,
        }

    async def get_dlq_events(self) -> List[tuple[Event, Exception]]:
        return await self._dlq.get_all()


# Singleton instance for global access
_event_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus


async def init_event_bus(**kwargs) -> EventBus:
    global _event_bus
    _event_bus = EventBus(**kwargs)
    await _event_bus.start()
    return _event_bus


async def shutdown_event_bus() -> None:
    global _event_bus
    if _event_bus:
        await _event_bus.stop()
        _event_bus = None