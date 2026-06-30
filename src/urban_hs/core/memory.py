"""
Memory Profiling - Memory analysis, leak detection, and streaming parsers.

Provides:
- Memory profiling with memray/objgraph integration
- Leak detection and allocation tracking
- Streaming parsers for large outputs (pcap, logs, JSONL)
- Memory-efficient processing of large datasets
"""

import asyncio
import gc
import json
import time
import tracemalloc
import weakref
from abc import ABC, abstractmethod
from collections import defaultdict
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any, AsyncIterator, Callable, Dict, Generic, List, Optional, TypeVar

import structlog

try:
    import memray
    MEMRAY_AVAILABLE = True
except ImportError:
    MEMRAY_AVAILABLE = False
    memray = None

try:
    import objgraph
    OBJGRAPH_AVAILABLE = True
except ImportError:
    OBJGRAPH_AVAILABLE = False
    objgraph = None

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None

logger = structlog.get_logger(__name__)

T = TypeVar("T")


@dataclass
class MemorySnapshot:
    """Memory usage snapshot."""
    timestamp: datetime
    rss_mb: float
    vms_mb: float
    heap_mb: float
    gc_counts: tuple
    object_count: int
    memray_file: Optional[str] = None


@dataclass
class AllocationRecord:
    """Memory allocation record."""
    size: int
    count: int
    traceback: List[str]
    module: str
    line: int


@dataclass
class LeakReport:
    """Memory leak detection report."""
    timestamp: datetime
    leaks: List[AllocationRecord]
    total_leaked_bytes: int
    top_modules: Dict[str, int]


class StreamingParser(ABC, Generic[T]):
    """Abstract base for memory-efficient streaming parsers."""
    
    @abstractmethod
    def parse_chunk(self, chunk: bytes) -> List[T]:
        """Parse a chunk of data and return parsed items."""
        pass
    
    @abstractmethod
    def finalize(self) -> List[T]:
        """Finalize parsing and return any remaining items."""
        pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Get parsing statistics."""
        return {}


class JSONLStreamingParser(StreamingParser[Dict[str, Any]]):
    """Memory-efficient JSONL parser for large log files."""
    
    def __init__(self, max_chunk_size: int = 65536):
        self.max_chunk_size = max_chunk_size
        self._buffer = b""
        self._parsed_count = 0
        self._error_count = 0
    
    def parse_chunk(self, chunk: bytes) -> List[Dict[str, Any]]:
        results = []
        self._buffer += chunk
        
        # Process complete lines
        while b"\n" in self._buffer:
            line, self._buffer = self._buffer.split(b"\n", 1)
            line = line.strip()
            if line:
                try:
                    results.append(json.loads(line))
                    self._parsed_count += 1
                except json.JSONDecodeError:
                    self._error_count += 1
        
        return results
    
    def finalize(self) -> List[Dict[str, Any]]:
        results = []
        if self._buffer.strip():
            try:
                results.append(json.loads(self._buffer.strip()))
                self._parsed_count += 1
            except json.JSONDecodeError:
                self._error_count += 1
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "parsed": self._parsed_count,
            "errors": self._error_count,
            "buffer_size": len(self._buffer),
        }


class PCAPStreamingParser(StreamingParser[Dict[str, Any]]):
    """Memory-efficient PCAP packet parser using scapy streaming."""
    
    def __init__(self, max_packets_per_chunk: int = 1000):
        self.max_packets_per_chunk = max_packets_per_chunk
        self._packet_buffer = []
        self._packet_count = 0
    
    def parse_chunk(self, chunk: bytes) -> List[Dict[str, Any]]:
        results = []
        self._packet_buffer.append(chunk)
        
        # In a real implementation, we'd use RawPcapReader with a buffer
        # This is a placeholder for the streaming logic
        try:
            import io

            from scapy.layers.dot11 import Dot11
            from scapy.utils import RawPcapReader
            
            # Combine buffered chunks
            combined = b"".join(self._packet_buffer)
            reader = RawPcapReader(io.BytesIO(combined))
            count = 0
            for pkt_data, _ in reader:
                if count >= self.max_packets_per_chunk:
                    break
                pkt = Dot11(pkt_data)
                results.append({
                    "type": pkt.name,
                    "len": len(pkt_data),
                })
                count += 1
                self._packet_count += 1
            # Keep unprocessed data
            if len(results) > 0:
                self._packet_buffer = [self._packet_buffer[-1]]
        except Exception as e:
            logger.warning("PCAP parse error", error=str(e))
        
        return results
    
    def finalize(self) -> List[Dict[str, Any]]:
        return []
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_packets": self._packet_count,
            "buffer_size": len(self._packet_buffer),
        }


class MemoryProfiler:
    """
    Memory profiler with memray/objgraph integration.
    """
    
    def __init__(
        self,
        tracing: bool = True,
        objgraph_tracking: bool = False,
        leak_threshold_mb: float = 10.0,
    ):
        self.tracing = tracing
        self.objgraph_tracking = objgraph_tracking and OBJGRAPH_AVAILABLE
        self.leak_threshold_mb = leak_threshold_mb
        
        self._snapshots: List[MemorySnapshot] = []
        self._memray_session: Optional[Any] = None
        self._baseline_snapshot: Optional[MemorySnapshot] = None
        
        # Type tracking for leak detection
        self._type_counts: Dict[str, int] = {}
        self._weak_refs: Dict[str, List[weakref.ref]] = {}
    
    def start(self) -> None:
        """Start memory profiling."""
        if self.tracing:
            tracemalloc.start(25)  # Store 25 frames
            logger.info("Memory tracing started")
        
        if self.objgraph_tracking:
            # Track common types
            self._track_common_types()
            logger.info("Object graph tracking started")
        
        self._baseline_snapshot = self._take_snapshot("baseline")
    
    def stop(self) -> Optional[str]:
        """Stop profiling and optionally generate memray report."""
        report_file = None
        
        if self._memray_session and MEMRAY_AVAILABLE:
            report_file = f"/tmp/memray_{int(time.time())}.bin"
            self._memray_session.stop()
            logger.info("Memray profiling stopped", file=report_file)
        
        if self.tracing:
            tracemalloc.stop()
            logger.info("Memory tracing stopped")
        
        # Final snapshot
        final_snapshot = self._take_snapshot("final")
        
        return report_file
    
    def _track_common_types(self) -> None:
        """Track common Python types for leak detection."""
        if not OBJGRAPH_AVAILABLE:
            return
        
        types_to_track = ["dict", "list", "tuple", "str", "bytes", "set", "frozenset"]
        for t in types_to_track:
            count = objgraph.count(t)
            self._type_counts[f"builtin.{t}"] = count
            
            # Create weak references for tracking
            refs = []
            for obj in objgraph.by_type(t)[:100]:  # Limit to 100
                refs.append(weakref.ref(obj))
            self._weak_refs[t] = refs
    
    def _take_snapshot(self, label: str) -> MemorySnapshot:
        """Take a memory snapshot."""
        if PSUTIL_AVAILABLE and psutil is not None:
            process = psutil.Process()
            mem_info = process.memory_info()
            rss_mb = mem_info.rss / (1024 * 1024)
            vms_mb = mem_info.vms / (1024 * 1024)
        else:
            rss_mb = 0.0
            vms_mb = 0.0
        
        gc_counts = gc.get_count()
        
        # Count objects
        obj_count = len(gc.get_objects())
        
        heap_mb = 0.0
        if self.tracing:
            current, peak = tracemalloc.get_traced_memory()
            heap_mb = peak / (1024 * 1024)
        
        snapshot = MemorySnapshot(
            timestamp=datetime.utcnow(),
            rss_mb=rss_mb,
            vms_mb=vms_mb,
            heap_mb=heap_mb,
            gc_counts=gc_counts,
            object_count=obj_count,
        )
        
        self._snapshots.append(snapshot)
        logger.debug(f"Memory snapshot ({label})", rss=f"{snapshot.rss_mb:.1f}MB", objects=obj_count)
        
        return snapshot
    
    def detect_leaks(self, threshold_mb: Optional[float] = None) -> LeakReport:
        """Detect memory leaks by comparing snapshots."""
        if len(self._snapshots) < 2:
            raise ValueError("Need at least 2 snapshots to detect leaks")
        
        baseline = self._snapshots[0]
        current = self._snapshots[-1]
        
        leaked = current.rss_mb - baseline.rss_mb
        threshold = threshold_mb or self.leak_threshold_mb
        
        leaks = []
        if leaked > threshold:
            # Try to identify leaking types
            if OBJGRAPH_AVAILABLE:
                for type_name, baseline_count in self._type_counts.items():
                    current_count = objgraph.count(type_name.split(".")[-1])
                    if current_count > baseline_count * 2:  # 100% growth
                        growth = current_count - baseline_count
                        leaks.append(AllocationRecord(
                            size=0,  # Unknown exact size
                            count=growth,
                            traceback=[],
                            module=type_name,
                            line=0,
                        ))
        
        # Group by module
        top_modules = defaultdict(int)
        for leak in leaks:
            top_modules[leak.module] += leak.count
        
        return LeakReport(
            timestamp=datetime.utcnow(),
            leaks=leaks,
            total_leaked_bytes=int(leaked * 1024 * 1024),
            top_modules=dict(top_modules),
        )
    
    def get_summary(self) -> Dict[str, Any]:
        """Get profiling summary."""
        if not self._snapshots:
            return {"status": "no_snapshots"}
        
        first = self._snapshots[0]
        last = self._snapshots[-1]
        
        return {
            "snapshots": len(self._snapshots),
            "duration_sec": (last.timestamp - first.timestamp).total_seconds(),
            "rss_growth_mb": last.rss_mb - first.rss_mb,
            "heap_growth_mb": last.heap_mb - first.heap_mb,
            "object_growth": last.object_count - first.object_count,
            "rss_mb": last.rss_mb,
            "heap_mb": last.heap_mb,
            "object_count": last.object_count,
            "leaks_detected": (last.rss_mb - first.rss_mb) > self.leak_threshold_mb,
        }


@asynccontextmanager
async def memory_profile(
    tracing: bool = True,
    objgraph_tracking: bool = False,
    leak_threshold_mb: float = 10.0,
) -> AsyncIterator[MemoryProfiler]:
    """Context manager for memory profiling."""
    profiler = MemoryProfiler(tracing, objgraph_tracking, leak_threshold_mb)
    profiler.start()
    try:
        yield profiler
    finally:
        profiler.stop()


def stream_parse_jsonl(file_path: str, chunk_size: int = 65536):
    """Stream parse JSONL file with minimal memory - returns async generator."""
    async def _async_gen():
        parser = JSONLStreamingParser()
        
        loop = asyncio.get_event_loop()
        with open(file_path, "rb") as f:
            while True:
                chunk = await loop.run_in_executor(None, f.read, 65536)
                if not chunk:
                    break
                results = parser.parse_chunk(chunk)
                for item in results:
                    yield item
        
        # Finalize
        for item in parser.finalize():
            yield item
    
    return _async_gen()


def stream_parse_pcap(file_path: str, max_packets: int = 10000):
    """Stream parse PCAP file with Scapy - returns async generator."""
    async def _async_gen():
        parser = PCAPStreamingParser(max_packets)
        
        loop = asyncio.get_event_loop()
        with open(file_path, "rb") as f:
            while True:
                chunk = await loop.run_in_executor(None, f.read, 65536)
                if not chunk:
                    break
                results = parser.parse_chunk(chunk)
                for item in results:
                    yield item
            
            # Finalize
            for item in parser.finalize():
                yield item
    
    return _async_gen()


def detect_gc_leaks(threshold_count: int = 10000) -> LeakReport:
    """Run garbage collection and detect leaks."""
    # Force GC
    gc.collect()
    
    # Get object counts
    counts = {}
    for obj in gc.get_objects():
        typename = type(obj).__name__
        counts[typename] = counts.get(typename, 0) + 1
    
    # Find large counts
    leaks = []
    for typename, count in counts.items():
        if count > threshold_count:
            leaks.append(AllocationRecord(
                size=0,
                count=count,
                traceback=[],
                module=typename,
                line=0,
            ))
    
    top_modules = defaultdict(int)
    for leak in leaks:
        top_modules[leak.module] += leak.count
    
    return LeakReport(
        timestamp=datetime.utcnow(),
        leaks=leaks,
        total_leaked_bytes=0,
        top_modules=dict(top_modules),
    )


# Memory-efficient async iterators

async def abatch(iterable: AsyncIterator[T], size: int) -> AsyncIterator[List[T]]:
    """Batch async iterator into chunks of size N."""
    batch = []
    async for item in iterable:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


async def alimit(iterable: AsyncIterator[T], limit: int) -> AsyncIterator[T]:
    """Limit async iterator to N items."""
    count = 0
    async for item in iterable:
        if count >= limit:
            break
        yield item
        count += 1


async def afilter(predicate: Callable[[T], bool], iterable: AsyncIterator[T]) -> AsyncIterator[T]:
    """Filter async iterator."""
    async for item in iterable:
        if await predicate(item):
            yield item


async def amap(func: Callable[[T], T], iterable: AsyncIterator[T]) -> AsyncIterator[T]:
    """Map function over async iterator."""
    async for item in iterable:
        if asyncio.iscoroutinefunction(func):
            yield await func(item)
        else:
            yield func(item)
    # type: ignore[return-value]


# Top-level exports
__all__ = [
    # Profiling
    "MemorySnapshot",
    "AllocationRecord",
    "LeakReport",
    "MemoryProfiler",
    "memory_profile",
    "detect_gc_leaks",
    
    # Streaming parsers
    "StreamingParser",
    "JSONLStreamingParser",
    "PCAPStreamingParser",
    "stream_parse_jsonl",
    "stream_parse_pcap",
    
    # GC utilities
    "detect_gc_leaks",
    
    # Async iterator utils
    "abatch",
    "alimit",
    "afilter",
    "amap",
]