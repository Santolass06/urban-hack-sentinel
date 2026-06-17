"""
Scheduler - Cron-style and interval-based task scheduling for Urban Hack Sentinel.

Provides:
- Interval-based scheduling (every N seconds/minutes/hours)
- Cron-style scheduling (cron expressions)
- One-shot delayed tasks
- Task persistence and recovery
- Integration with EventBus for job events
"""

import asyncio
import structlog
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Callable, Awaitable, Set
from functools import partial

try:
    from croniter import croniter
    CRONITER_AVAILABLE = True
except ImportError:
    CRONITER_AVAILABLE = False

logger = structlog.get_logger(__name__)


class TriggerType(Enum):
    """Types of schedule triggers."""
    INTERVAL = "interval"
    CRON = "cron"
    ONCE = "once"
    STARTUP = "startup"
    SHUTDOWN = "shutdown"


class JobStatus(Enum):
    """Job execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


@dataclass
class ScheduledJob:
    """A scheduled job definition."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    func: Callable[..., Awaitable[Any]] = None
    args: tuple = field(default_factory=tuple)
    kwargs: Dict[str, Any] = field(default_factory=dict)
    trigger_type: TriggerType = TriggerType.INTERVAL
    trigger_config: Dict[str, Any] = field(default_factory=dict)
    
    # Scheduling
    next_run: Optional[float] = None
    last_run: Optional[float] = None
    run_count: int = 0
    max_runs: Optional[int] = None
    
    # Status
    status: JobStatus = JobStatus.PENDING
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Error handling
    retry_count: int = 0
    max_retries: int = 3
    retry_delay: float = 5.0  # seconds
    last_error: Optional[str] = None
    
    # Timezone
    timezone: str = "UTC"

    def __post_init__(self):
        if not self.name:
            self.name = f"job_{self.id[:8]}"
        if self.func is None:
            raise ValueError("Job function is required")
        
        # Calculate initial next_run
        if self.next_run is None:
            self.next_run = self._calculate_next_run()

    def _calculate_next_run(self) -> Optional[float]:
        """Calculate next run time based on trigger."""
        now = time.time()
        
        if self.trigger_type == TriggerType.ONCE:
            # Run at specific time or after delay
            if "run_at" in self.trigger_config:
                run_at = self.trigger_config["run_at"]
                if isinstance(run_at, (int, float)):
                    return run_at
                elif isinstance(run_at, datetime):
                    return run_at.timestamp()
            elif "delay" in self.trigger_config:
                return now + self.trigger_config["delay"]
            return now
        
        elif self.trigger_type == TriggerType.INTERVAL:
            interval = self.trigger_config.get("seconds", 60)
            if "minutes" in self.trigger_config:
                interval = self.trigger_config["minutes"] * 60
            elif "hours" in self.trigger_config:
                interval = self.trigger_config["hours"] * 3600
            return now + interval
        
        elif self.trigger_type == TriggerType.CRON:
            if not CRONITER_AVAILABLE:
                logger.warning("croniter not available, cannot schedule cron job", job_id=self.id)
                return None
            
            cron_expr = self.trigger_config.get("expression", "0 * * * *")  # Default: hourly
            try:
                cron = croniter(cron_expr, datetime.fromtimestamp(now))
                next_dt = cron.get_next(datetime)
                return next_dt.timestamp()
            except Exception as e:
                logger.error("Invalid cron expression", expression=cron_expr, error=str(e))
                return None
        
        elif self.trigger_type == TriggerType.STARTUP:
            return now
        
        elif self.trigger_type == TriggerType.SHUTDOWN:
            # Run on shutdown signal
            return None
        
        return None

    def calculate_next_run(self) -> Optional[float]:
        """Calculate next run time after current execution."""
        if self.trigger_type == TriggerType.ONCE:
            return None  # One-shot jobs don't repeat
        
        if self.trigger_type == TriggerType.STARTUP:
            return None  # Only runs once on startup
        
        if self.trigger_type == TriggerType.SHUTDOWN:
            return None  # Triggered externally
        
        base_time = self.last_run if self.last_run else time.time()
        
        if self.trigger_type == TriggerType.INTERVAL:
            interval = self.trigger_config.get("seconds", 60)
            if "minutes" in self.trigger_config:
                interval = self.trigger_config["minutes"] * 60
            elif "hours" in self.trigger_config:
                interval = self.trigger_config["hours"] * 3600
            return base_time + interval
        
        elif self.trigger_type == TriggerType.CRON:
            if not CRONITER_AVAILABLE:
                return None
            
            cron_expr = self.trigger_config.get("expression", "0 * * * *")
            try:
                cron = croniter(cron_expr, datetime.fromtimestamp(base_time))
                next_dt = cron.get_next(datetime)
                return next_dt.timestamp()
            except Exception as e:
                logger.error("Invalid cron expression", expression=cron_expr, error=str(e))
                return None
        
        return None

    def should_run(self) -> bool:
        """Check if job should run now."""
        if not self.enabled:
            return False
        
        if self.max_runs is not None and self.run_count >= self.max_runs:
            return False
        
        if self.next_run is None:
            return False
        
        return time.time() >= self.next_run

    def mark_running(self):
        """Mark job as running."""
        self.status = JobStatus.RUNNING
        self.last_run = time.time()

    def mark_completed(self):
        """Mark job as completed."""
        self.status = JobStatus.COMPLETED
        self.run_count += 1
        self.retry_count = 0
        self.last_error = None
        
        # Calculate next run
        self.next_run = self.calculate_next_run()
        
        # Check if max runs reached
        if self.max_runs is not None and self.run_count >= self.max_runs:
            self.enabled = False
            self.status = JobStatus.COMPLETED

    def mark_failed(self, error: str):
        """Mark job as failed with retry logic."""
        self.last_error = error
        self.retry_count += 1
        
        if self.retry_count >= self.max_retries:
            self.status = JobStatus.FAILED
            self.enabled = False
            logger.error("Job failed permanently after retries", job_id=self.id, error=error)
        else:
            self.status = JobStatus.PENDING
            # Schedule retry
            self.next_run = time.time() + self.retry_delay
            logger.warning("Job failed, will retry", job_id=self.id, attempt=self.retry_count, error=error)

    def mark_skipped(self, reason: str = ""):
        """Mark job as skipped."""
        self.status = JobStatus.SKIPPED
        self.last_error = reason
        self.next_run = self.calculate_next_run()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize job to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "trigger_type": self.trigger_type.value,
            "trigger_config": self.trigger_config,
            "next_run": self.next_run,
            "last_run": self.last_run,
            "run_count": self.run_count,
            "max_runs": self.max_runs,
            "status": self.status.value,
            "enabled": self.enabled,
            "tags": self.tags,
            "metadata": self.metadata,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "last_error": self.last_error,
        }


class Scheduler:
    """
    Async job scheduler with multiple trigger types.
    
    Features:
    - Interval, cron, one-shot, startup, shutdown triggers
    - Job persistence (in-memory with optional Redis backend)
    - Concurrency control with semaphores
    - EventBus integration for job events
    - Graceful shutdown handling
    """

    def __init__(
        self,
        event_bus: Optional[Any] = None,
        max_concurrent_jobs: int = 10,
        default_timezone: str = "UTC",
    ):
        self.event_bus = event_bus
        self.max_concurrent_jobs = max_concurrent_jobs
        self.default_timezone = default_timezone
        
        self._jobs: Dict[str, ScheduledJob] = {}
        self._running: bool = False
        self._scheduler_task: Optional[asyncio.Task] = None
        self._semaphore = asyncio.Semaphore(max_concurrent_jobs)
        self._shutdown_event = asyncio.Event()
        
        # Job groups for organized management
        self._job_groups: Dict[str, Set[str]] = {}

    def add_job(
        self,
        func: Callable[..., Awaitable[Any]],
        name: str = "",
        trigger: TriggerType = TriggerType.INTERVAL,
        trigger_config: Optional[Dict[str, Any]] = None,
        args: tuple = (),
        kwargs: Optional[Dict[str, Any]] = None,
        max_runs: Optional[int] = None,
        max_retries: int = 3,
        retry_delay: float = 5.0,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        group: Optional[str] = None,
    ) -> ScheduledJob:
        """Add a new scheduled job."""
        job = ScheduledJob(
            name=name,
            func=func,
            args=args,
            kwargs=kwargs or {},
            trigger_type=trigger,
            trigger_config=trigger_config or {},
            max_runs=max_runs,
            max_retries=max_retries,
            retry_delay=retry_delay,
            tags=tags or [],
            metadata=metadata or {},
        )
        
        self._jobs[job.id] = job
        
        if group:
            if group not in self._job_groups:
                self._job_groups[group] = set()
            self._job_groups[group].add(job.id)
        
        logger.info(
            "Job scheduled",
            job_id=job.id,
            name=job.name,
            trigger=trigger.value,
            next_run=job.next_run,
            group=group,
        )
        
        # Emit event
        if self.event_bus:
            asyncio.create_task(self.event_bus.publish("scheduler.job_added", job.to_dict()))
        
        return job

    def remove_job(self, job_id: str) -> bool:
        """Remove a scheduled job."""
        if job_id in self._jobs:
            job = self._jobs.pop(job_id)
            
            # Remove from groups
            for group, jobs in self._job_groups.items():
                jobs.discard(job_id)
            
            logger.info("Job removed", job_id=job_id, name=job.name)
            
            if self.event_bus:
                asyncio.create_task(self.event_bus.publish("scheduler.job_removed", {"job_id": job_id}))
            
            return True
        return False

    def get_job(self, job_id: str) -> Optional[ScheduledJob]:
        """Get a job by ID."""
        return self._jobs.get(job_id)

    def get_jobs(self, group: Optional[str] = None) -> List[ScheduledJob]:
        """Get all jobs, optionally filtered by group."""
        if group and group in self._job_groups:
            return [self._jobs[jid] for jid in self._job_groups[group] if jid in self._jobs]
        
        if group:
            return []
        
        return list(self._jobs.values())

    def enable_job(self, job_id: str) -> bool:
        """Enable a job."""
        job = self._jobs.get(job_id)
        if job:
            job.enabled = True
            if job.next_run is None:
                job.next_run = job._calculate_next_run()
            return True
        return False

    def disable_job(self, job_id: str) -> bool:
        """Disable a job."""
        job = self._jobs.get(job_id)
        if job:
            job.enabled = False
            return True
        return False

    def trigger_job(self, job_id: str) -> bool:
        """Manually trigger a job to run immediately."""
        job = self._jobs.get(job_id)
        if job:
            job.next_run = time.time()
            return True
        return False

    async def start(self):
        """Start the scheduler."""
        if self._running:
            logger.warning("Scheduler already running")
            return
        
        self._running = True
        self._shutdown_event.clear()
        
        # Run startup jobs
        await self._run_startup_jobs()
        
        # Start main scheduler loop
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())
        
        logger.info("Scheduler started", job_count=len(self._jobs))

    async def stop(self, timeout: float = 30.0):
        """Stop the scheduler gracefully."""
        if not self._running:
            return
        
        logger.info("Stopping scheduler...")
        self._running = False
        self._shutdown_event.set()
        
        # Run shutdown jobs
        await self._run_shutdown_jobs()
        
        # Wait for scheduler task to finish
        if self._scheduler_task:
            try:
                await asyncio.wait_for(self._scheduler_task, timeout=timeout)
            except asyncio.TimeoutError:
                logger.warning("Scheduler task did not finish in time, cancelling")
                self._scheduler_task.cancel()
                try:
                    await self._scheduler_task
                except asyncio.CancelledError:
                    pass
        
        logger.info("Scheduler stopped")

    async def _run_startup_jobs(self):
        """Run jobs with STARTUP trigger."""
        startup_jobs = [j for j in self._jobs.values() if j.trigger_type == TriggerType.STARTUP]
        
        for job in startup_jobs:
            if job.enabled:
                asyncio.create_task(self._execute_job(job))

    async def _run_shutdown_jobs(self):
        """Run jobs with SHUTDOWN trigger."""
        shutdown_jobs = [j for j in self._jobs.values() if j.trigger_type == TriggerType.SHUTDOWN]
        
        if shutdown_jobs:
            # Run shutdown jobs sequentially
            for job in shutdown_jobs:
                if job.enabled:
                    await self._execute_job(job)

    async def _scheduler_loop(self):
        """Main scheduler loop."""
        while self._running:
            try:
                # Check for jobs to run
                now = time.time()
                jobs_to_run = []
                
                for job in self._jobs.values():
                    if job.enabled and job.should_run():
                        jobs_to_run.append(job)
                
                # Execute jobs
                for job in jobs_to_run:
                    if self._running:
                        asyncio.create_task(self._execute_job(job))
                
                # Sleep until next check
                wait_time = min(1.0, self._get_min_wait_time())
                
                try:
                    await asyncio.wait_for(self._shutdown_event.wait(), timeout=wait_time)
                    break  # Shutdown event triggered
                except asyncio.TimeoutError:
                    continue  # Normal loop iteration
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Scheduler loop error", error=str(e))
                await asyncio.sleep(1.0)
    
    def _get_min_wait_time(self) -> float:
        """Get minimum time until next job should run."""
        min_wait = 60.0  # Default: check every minute
        now = time.time()
        
        for job in self._jobs.values():
            if job.enabled and job.next_run is not None:
                wait = job.next_run - now
                if wait > 0 and wait < min_wait:
                    min_wait = wait
        
        return max(0.1, min(min_wait, 60.0))

    async def _execute_job(self, job: ScheduledJob):
        """Execute a single job with error handling and retries."""
        async with self._semaphore:
            if not job.enabled or not job.should_run():
                return
            
            job.mark_running()
            
            logger.info("Executing job", job_id=job.id, name=job.name, run_count=job.run_count + 1)
            
            start_time = time.time()
            
            if self.event_bus:
                await self.event_bus.publish("scheduler.job_started", job.to_dict())
            
            try:
                # Execute the job function
                if asyncio.iscoroutinefunction(job.func):
                    await job.func(*job.args, **job.kwargs)
                else:
                    # Run sync function in thread pool
                    await asyncio.to_thread(job.func, *job.args, **job.kwargs)
                
                duration = time.time() - start_time
                job.mark_completed()
                
                logger.info("Job completed", job_id=job.id, name=job.name, duration_ms=round(duration * 1000, 2))
                
                if self.event_bus:
                    await self.event_bus.publish("scheduler.job_completed", {
                        **job.to_dict(),
                        "duration_ms": round(duration * 1000, 2),
                    })
                
            except Exception as e:
                duration = time.time() - start_time
                error_msg = f"{type(e).__name__}: {e}"
                job.mark_failed(error_msg)
                
                logger.error("Job failed", job_id=job.id, name=job.name, error=error_msg, duration_ms=round(duration * 1000, 2))
                
                if self.event_bus:
                    await self.event_bus.publish("scheduler.job_failed", {
                        **job.to_dict(),
                        "error": error_msg,
                        "duration_ms": round(duration * 1000, 2),
                    })

    # Convenience methods for common schedules
    def every_seconds(self, seconds: int, func: Callable, name: str = "", **kwargs) -> ScheduledJob:
        """Schedule job to run every N seconds."""
        return self.add_job(
            func=func,
            name=name,
            trigger=TriggerType.INTERVAL,
            trigger_config={"seconds": seconds},
            **kwargs
        )

    def every_minutes(self, minutes: int, func: Callable, name: str = "", **kwargs) -> ScheduledJob:
        """Schedule job to run every N minutes."""
        return self.add_job(
            func=func,
            name=name,
            trigger=TriggerType.INTERVAL,
            trigger_config={"minutes": minutes},
            **kwargs
        )

    def every_hours(self, hours: int, func: Callable, name: str = "", **kwargs) -> ScheduledJob:
        """Schedule job to run every N hours."""
        return self.add_job(
            func=func,
            name=name,
            trigger=TriggerType.INTERVAL,
            trigger_config={"hours": hours},
            **kwargs
        )

    def cron(self, expression: str, func: Callable, name: str = "", **kwargs) -> ScheduledJob:
        """Schedule job with cron expression."""
        return self.add_job(
            func=func,
            name=name,
            trigger=TriggerType.CRON,
            trigger_config={"expression": expression},
            **kwargs
        )

    def once(self, delay: float = 0, func: Callable = None, name: str = "", run_at: Optional[float] = None, **kwargs) -> ScheduledJob:
        """Schedule a one-shot job."""
        if run_at is not None:
            trigger_config = {"run_at": run_at}
        else:
            trigger_config = {"delay": delay}
        
        return self.add_job(
            func=func,
            name=name,
            trigger=TriggerType.ONCE,
            trigger_config=trigger_config,
            **kwargs
        )

    def on_startup(self, func: Callable, name: str = "", **kwargs) -> ScheduledJob:
        """Schedule job to run on scheduler startup."""
        return self.add_job(
            func=func,
            name=name,
            trigger=TriggerType.STARTUP,
            trigger_config={},
            **kwargs
        )

    def on_shutdown(self, func: Callable, name: str = "", **kwargs) -> ScheduledJob:
        """Schedule job to run on scheduler shutdown."""
        return self.add_job(
            func=func,
            name=name,
            trigger=TriggerType.SHUTDOWN,
            trigger_config={},
            **kwargs
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get scheduler statistics."""
        status_counts = {}
        for status in JobStatus:
            status_counts[status.value] = 0
        
        for job in self._jobs.values():
            status_counts[job.status.value] = status_counts.get(job.status.value, 0) + 1
        
        return {
            "total_jobs": len(self._jobs),
            "running": self._running,
            "status_counts": status_counts,
            "groups": {g: len(jobs) for g, jobs in self._job_groups.items()},
            "max_concurrent": self.max_concurrent_jobs,
        }


# Export all public classes
__all__ = [
    "TriggerType",
    "JobStatus",
    "ScheduledJob",
    "Scheduler",
]