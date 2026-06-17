"""
Health Checks and Prometheus Metrics for Urban Hack Sentinel.

Provides:
- /healthz - Liveness probe (process is alive)
- /readyz - Readiness probe (dependencies available)
- /metrics - Prometheus metrics exposition
"""

import asyncio
import os
import platform
import structlog
import time
import psutil
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Awaitable
from urllib.parse import urlparse

try:
    from prometheus_client import Counter, Gauge, Histogram, CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

logger = structlog.get_logger(__name__)


class HealthStatus(Enum):
    """Health status levels."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class HealthCheckResult:
    """Result of a single health check."""
    name: str
    status: HealthStatus
    message: str = ""
    latency_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SystemMetrics:
    """System-level metrics."""
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    memory_available_mb: float = 0.0
    disk_percent: float = 0.0
    disk_free_gb: float = 0.0
    network_connections: int = 0
    process_count: int = 0
    uptime_seconds: float = 0.0
    load_average: List[float] = field(default_factory=list)


class HealthChecker:
    """
    Health check orchestrator for Urban Hack Sentinel.
    
    Runs configurable health checks and provides:
    - Liveness (/healthz) - Is the process alive?
    - Readiness (/readyz) - Are dependencies available?
    - Detailed health status with metadata
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.checks: Dict[str, Callable[[], Awaitable[HealthCheckResult]]] = {}
        self.start_time = time.time()
        self._register_default_checks()
        
        # Prometheus metrics
        if PROMETHEUS_AVAILABLE:
            self.registry = CollectorRegistry()
            self._setup_prometheus_metrics()
        else:
            self.registry = None
            logger.warning("prometheus_client not available, metrics disabled")

    def _register_default_checks(self):
        """Register built-in health checks."""
        self.register_check("process_alive", self._check_process_alive)
        self.register_check("disk_space", self._check_disk_space)
        self.register_check("memory_usage", self._check_memory_usage)
        self.register_check("cpu_usage", self._check_cpu_usage)
        
        # Check critical paths
        for path_name, path_str in [
            ("chroot", "/opt/urban-hs/chroot/alpine"),
            ("evidence_dir", "/var/lib/urban-hs/evidence"),
            ("reports_dir", "/var/lib/urban-hs/reports"),
            ("credentials_dir", "/var/lib/urban-hs/credentials"),
            ("artifacts_dir", "/var/lib/urban-hs/artifacts"),
        ]:
            self.register_check(f"path_{path_name}", self._make_path_check(path_str))
        
        # Check systemd services if applicable
        self.register_check("systemd", self._check_systemd_services)

    def _make_path_check(self, path_str: str) -> Callable[[], Awaitable[HealthCheckResult]]:
        """Create a path existence check."""
        async def check() -> HealthCheckResult:
            start = time.time()
            path = Path(path_str)
            try:
                if path.exists():
                    return HealthCheckResult(
                        name=f"path_{path_str}",
                        status=HealthStatus.HEALTHY,
                        message=f"Path exists: {path_str}",
                        latency_ms=(time.time() - start) * 1000,
                        metadata={"path": path_str, "is_dir": path.is_dir()}
                    )
                else:
                    return HealthCheckResult(
                        name=f"path_{path_str}",
                        status=HealthStatus.UNHEALTHY,
                        message=f"Path missing: {path_str}",
                        latency_ms=(time.time() - start) * 1000,
                        metadata={"path": path_str}
                    )
            except Exception as e:
                return HealthCheckResult(
                    name=f"path_{path_str}",
                    status=HealthStatus.UNHEALTHY,
                    message=f"Error checking path: {e}",
                    latency_ms=(time.time() - start) * 1000,
                    metadata={"path": path_str, "error": str(e)}
                )
        return check

    def register_check(self, name: str, check_func: Callable[[], Awaitable[HealthCheckResult]]):
        """Register a custom health check."""
        self.checks[name] = check_func
        logger.debug("Health check registered", name=name)

    def unregister_check(self, name: str):
        """Unregister a health check."""
        self.checks.pop(name, None)

    async def _check_process_alive(self) -> HealthCheckResult:
        """Basic liveness check - process is running."""
        return HealthCheckResult(
            name="process_alive",
            status=HealthStatus.HEALTHY,
            message="Process is alive",
            metadata={"pid": os.getpid(), "uptime_seconds": time.time() - self.start_time}
        )

    async def _check_disk_space(self) -> HealthCheckResult:
        """Check available disk space."""
        start = time.time()
        try:
            usage = psutil.disk_usage("/")
            free_gb = usage.free / (1024**3)
            percent = (usage.used / usage.total) * 100
            
            if percent > 95:
                status = HealthStatus.UNHEALTHY
                message = f"Critical disk usage: {percent:.1f}%"
            elif percent > 85:
                status = HealthStatus.DEGRADED
                message = f"High disk usage: {percent:.1f}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"Disk usage OK: {percent:.1f}%"
            
            return HealthCheckResult(
                name="disk_space",
                status=status,
                message=message,
                latency_ms=(time.time() - start) * 1000,
                metadata={"free_gb": round(free_gb, 2), "usage_percent": round(percent, 1)}
            )
        except Exception as e:
            return HealthCheckResult(
                name="disk_space",
                status=HealthStatus.UNHEALTHY,
                message=f"Error checking disk: {e}",
                latency_ms=(time.time() - start) * 1000
            )

    async def _check_memory_usage(self) -> HealthCheckResult:
        """Check memory usage."""
        start = time.time()
        try:
            mem = psutil.virtual_memory()
            available_mb = mem.available / (1024**2)
            percent = mem.percent
            
            if percent > 95:
                status = HealthStatus.UNHEALTHY
                message = f"Critical memory usage: {percent:.1f}%"
            elif percent > 85:
                status = HealthStatus.DEGRADED
                message = f"High memory usage: {percent:.1f}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"Memory usage OK: {percent:.1f}%"
            
            return HealthCheckResult(
                name="memory_usage",
                status=status,
                message=message,
                latency_ms=(time.time() - start) * 1000,
                metadata={"available_mb": round(available_mb, 1), "usage_percent": round(percent, 1)}
            )
        except Exception as e:
            return HealthCheckResult(
                name="memory_usage",
                status=HealthStatus.UNHEALTHY,
                message=f"Error checking memory: {e}",
                latency_ms=(time.time() - start) * 1000
            )

    async def _check_cpu_usage(self) -> HealthCheckResult:
        """Check CPU usage."""
        start = time.time()
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            load_avg = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else [0, 0, 0]
            
            if cpu_percent > 95:
                status = HealthStatus.UNHEALTHY
                message = f"Critical CPU usage: {cpu_percent:.1f}%"
            elif cpu_percent > 85:
                status = HealthStatus.DEGRADED
                message = f"High CPU usage: {cpu_percent:.1f}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"CPU usage OK: {cpu_percent:.1f}%"
            
            return HealthCheckResult(
                name="cpu_usage",
                status=status,
                message=message,
                latency_ms=(time.time() - start) * 1000,
                metadata={"cpu_percent": round(cpu_percent, 1), "load_average": [round(x, 2) for x in load_avg]}
            )
        except Exception as e:
            return HealthCheckResult(
                name="cpu_usage",
                status=HealthStatus.UNHEALTHY,
                message=f"Error checking CPU: {e}",
                latency_ms=(time.time() - start) * 1000
            )

    async def _check_systemd_services(self) -> HealthCheckResult:
        """Check critical systemd services."""
        start = time.time()
        critical_services = [
            "bluetooth",  # For BLE
            "gpsd",       # For GPS
        ]
        
        results = {}
        all_ok = True
        
        for service in critical_services:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "systemctl", "is-active", service,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                is_active = stdout.decode().strip() == "active"
                results[service] = "active" if is_active else "inactive"
                if not is_active:
                    all_ok = False
            except Exception as e:
                results[service] = f"error: {e}"
                all_ok = False
        
        return HealthCheckResult(
            name="systemd_services",
            status=HealthStatus.HEALTHY if all_ok else HealthStatus.DEGRADED,
            message="All critical services active" if all_ok else "Some services inactive",
            latency_ms=(time.time() - start) * 1000,
            metadata={"services": results}
        )

    async def run_checks(self, check_names: Optional[List[str]] = None) -> Dict[str, HealthCheckResult]:
        """Run specified health checks or all if none specified."""
        names = check_names or list(self.checks.keys())
        results = {}
        
        for name in names:
            if name in self.checks:
                try:
                    results[name] = await self.checks[name]()
                except Exception as e:
                    results[name] = HealthCheckResult(
                        name=name,
                        status=HealthStatus.UNHEALTHY,
                        message=f"Check failed with exception: {e}",
                        metadata={"error": str(e)}
                    )
            else:
                results[name] = HealthCheckResult(
                    name=name,
                    status=HealthStatus.UNKNOWN,
                    message="Check not registered"
                )
        
        return results

    async def get_overall_status(self, results: Optional[Dict[str, HealthCheckResult]] = None) -> HealthStatus:
        """Determine overall health status from check results."""
        if results is None:
            results = await self.run_checks()
        
        if not results:
            return HealthStatus.UNKNOWN
        
        statuses = [r.status for r in results.values()]
        
        if HealthStatus.UNHEALTHY in statuses:
            return HealthStatus.UNHEALTHY
        if HealthStatus.DEGRADED in statuses:
            return HealthStatus.DEGRADED
        if all(s == HealthStatus.HEALTHY for s in statuses):
            return HealthStatus.HEALTHY
        return HealthStatus.DEGRADED

    def get_system_metrics(self) -> SystemMetrics:
        """Collect current system metrics."""
        try:
            cpu = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            net_conns = len(psutil.net_connections())
            proc_count = len(psutil.pids())
            uptime = time.time() - self.start_time
            load_avg = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else [0, 0, 0]
            
            return SystemMetrics(
                cpu_percent=cpu,
                memory_percent=mem.percent,
                memory_available_mb=mem.available / (1024**2),
                disk_percent=(disk.used / disk.total) * 100,
                disk_free_gb=disk.free / (1024**3),
                network_connections=net_conns,
                process_count=proc_count,
                uptime_seconds=uptime,
                load_average=[round(x, 2) for x in load_avg]
            )
        except Exception as e:
            logger.error("Failed to collect system metrics", error=str(e))
            return SystemMetrics()

    def _setup_prometheus_metrics(self):
        """Setup Prometheus metrics."""
        # System metrics
        self.prom_cpu = Gauge('uhs_cpu_percent', 'CPU usage percent', registry=self.registry)
        self.prom_memory = Gauge('uhs_memory_percent', 'Memory usage percent', registry=self.registry)
        self.prom_memory_available = Gauge('uhs_memory_available_mb', 'Available memory in MB', registry=self.registry)
        self.prom_disk = Gauge('uhs_disk_percent', 'Disk usage percent', registry=self.registry)
        self.prom_disk_free = Gauge('uhs_disk_free_gb', 'Free disk space in GB', registry=self.registry)
        self.prom_uptime = Gauge('uhs_uptime_seconds', 'Process uptime in seconds', registry=self.registry)
        self.prom_load = Gauge('uhs_load_average', 'Load average', ['period'], registry=self.registry)
        
        # Health check metrics
        self.prom_health = Gauge('uhs_health_status', 'Health check status (1=healthy, 0.5=degraded, 0=unhealthy)', ['check'], registry=self.registry)
        self.prom_health_latency = Histogram('uhs_health_check_latency_ms', 'Health check latency', ['check'], registry=self.registry)
        
        # Application metrics
        self.prom_scans_total = Counter('uhs_scans_total', 'Total scans performed', ['type'], registry=self.registry)
        self.prom_attacks_total = Counter('uhs_attacks_total', 'Total attacks attempted', ['type', 'result'], registry=self.registry)
        self.prom_vulns_found = Counter('uhs_vulns_found_total', 'Total vulnerabilities found', ['severity'], registry=self.registry)
        self.prom_credentials = Counter('uhs_credentials_total', 'Total credentials captured', ['type'], registry=self.registry)
        self.prom_active_connections = Gauge('uhs_active_connections', 'Active network connections', registry=self.registry)

    def update_prometheus_metrics(self):
        """Update Prometheus metrics from current system state."""
        if not PROMETHEUS_AVAILABLE or not self.registry:
            return
        
        try:
            metrics = self.get_system_metrics()
            
            self.prom_cpu.set(metrics.cpu_percent)
            self.prom_memory.set(metrics.memory_percent)
            self.prom_memory_available.set(metrics.memory_available_mb)
            self.prom_disk.set(metrics.disk_percent)
            self.prom_disk_free.set(metrics.disk_free_gb)
            self.prom_uptime.set(metrics.uptime_seconds)
            self.prom_active_connections.set(metrics.network_connections)
            
            for i, period in enumerate(['1m', '5m', '15m']):
                if i < len(metrics.load_average):
                    self.prom_load.labels(period=period).set(metrics.load_average[i])
            
        except Exception as e:
            logger.error("Failed to update Prometheus metrics", error=str(e))

    def record_health_check(self, result: HealthCheckResult):
        """Record health check result in Prometheus."""
        if not PROMETHEUS_AVAILABLE or not self.registry:
            return
        
        try:
            status_map = {
                HealthStatus.HEALTHY: 1.0,
                HealthStatus.DEGRADED: 0.5,
                HealthStatus.UNHEALTHY: 0.0,
                HealthStatus.UNKNOWN: 0.0,
            }
            self.prom_health.labels(check=result.name).set(status_map.get(result.status, 0.0))
            self.prom_health_latency.labels(check=result.name).observe(result.latency_ms)
        except Exception as e:
            logger.error("Failed to record health check metric", error=str(e))

    def get_prometheus_metrics(self) -> bytes:
        """Get Prometheus metrics in exposition format."""
        if not PROMETHEUS_AVAILABLE or not self.registry:
            return b"# Prometheus not available\n"
        
        self.update_prometheus_metrics()
        return generate_latest(self.registry)

    def get_health_summary(self) -> Dict[str, Any]:
        """Get a summary suitable for JSON response."""
        return {
            "status": "healthy",  # Will be updated by run_all
            "timestamp": datetime.utcnow().isoformat(),
            "uptime_seconds": time.time() - self.start_time,
            "version": "3.0.0",
            "platform": platform.platform(),
            "python_version": platform.python_version(),
        }


class HealthCheckMiddleware:
    """ASGI middleware for health check endpoints."""

    def __init__(self, app, health_checker: HealthChecker):
        self.app = app
        self.health = health_checker

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        path = scope.get("path", "")
        
        if path == "/healthz":
            await self._handle_liveness(scope, receive, send)
        elif path == "/readyz":
            await self._handle_readiness(scope, receive, send)
        elif path == "/metrics":
            await self._handle_metrics(scope, receive, send)
        elif path == "/health":
            await self._handle_detailed(scope, receive, send)
        else:
            await self.app(scope, receive, send)

    async def _handle_liveness(self, scope, receive, send):
        """Liveness probe - process is alive."""
        result = await self.health._check_process_alive()
        await self._send_json(send, 200 if result.status == HealthStatus.HEALTHY else 503, {
            "status": result.status.value,
            "message": result.message,
            "timestamp": result.timestamp.isoformat(),
        })

    async def _handle_readiness(self, scope, receive, send):
        """Readiness probe - dependencies available."""
        results = await self.health.run_checks([
            "disk_space", "memory_usage", "cpu_usage",
            "path_chroot", "path_evidence_dir", "path_reports_dir",
            "path_credentials_dir", "path_artifacts_dir"
        ])
        overall = await self.health.get_overall_status(results)
        
        await self._send_json(send, 200 if overall == HealthStatus.HEALTHY else 503, {
            "status": overall.value,
            "checks": {k: {"status": v.status.value, "message": v.message} for k, v in results.items()},
            "timestamp": datetime.utcnow().isoformat(),
        })

    async def _handle_metrics(self, scope, receive, send):
        """Prometheus metrics endpoint."""
        metrics_data = self.health.get_prometheus_metrics()
        
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", CONTENT_TYPE_LATEST.encode()),
                (b"content-length", str(len(metrics_data)).encode()),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": metrics_data,
        })

    async def _handle_detailed(self, scope, receive, send):
        """Detailed health status with all checks."""
        results = await self.health.run_checks()
        overall = await self.health.get_overall_status(results)
        summary = self.health.get_health_summary()
        summary["status"] = overall.value
        summary["checks"] = {
            k: {
                "status": v.status.value,
                "message": v.message,
                "latency_ms": v.latency_ms,
                "metadata": v.metadata,
            }
            for k, v in results.items()
        }
        
        await self._send_json(send, 200 if overall == HealthStatus.HEALTHY else 503, summary)

    async def _send_json(self, send, status: int, data: Dict[str, Any]):
        """Send JSON response."""
        import json
        body = json.dumps(data).encode()
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": body,
        })


# Convenience function to create health checker with default config
def create_health_checker(config: Optional[Dict[str, Any]] = None) -> HealthChecker:
    """Create a health checker with default configuration."""
    return HealthChecker(config)


# Export all public classes
__all__ = [
    "HealthStatus",
    "HealthCheckResult",
    "SystemMetrics",
    "HealthChecker",
    "HealthCheckMiddleware",
    "create_health_checker",
]