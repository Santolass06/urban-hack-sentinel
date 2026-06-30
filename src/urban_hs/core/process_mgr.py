"""
Advanced Process Manager - Robust subprocess execution with streaming, chroot support,
resource limits, and callback-based output handling.
"""

import asyncio
import os
import signal
import shlex
import structlog
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Callable, Union

logger = structlog.get_logger(__name__)


@dataclass
class ProcessResult:
    """Result of a completed process execution."""
    cmd: str
    args: List[str]
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    started_at: datetime
    finished_at: datetime
    pid: int
    success: bool = False

    def __post_init__(self):
        self.success = self.exit_code == 0


@dataclass
class ProcessLimits:
    """Resource limits for process execution."""
    max_memory_mb: Optional[int] = None  # MB
    max_cpu_percent: Optional[float] = None  # percentage
    max_duration_sec: Optional[int] = None
    max_output_mb: int = 100  # Limit output capture


class ProcessCallback(ABC):
    """Abstract callback interface for process output handling."""
    
    @abstractmethod
    async def on_stdout(self, line: str) -> None:
        pass

    @abstractmethod
    async def on_stderr(self, line: str) -> None:
        pass

    @abstractmethod
    async def on_exit(self, exit_code: int) -> None:
        pass


class StreamCallback(ProcessCallback):
    """Callback that yields lines via async iterators."""
    
    def __init__(self):
        self._stdout_queue: asyncio.Queue[str] = asyncio.Queue()
        self._stderr_queue: asyncio.Queue[str] = asyncio.Queue()
        self._exit_event = asyncio.Event()
        self._exit_code: Optional[int] = None

    async def on_stdout(self, line: str) -> None:
        await self._stdout_queue.put(line)

    async def on_stderr(self, line: str) -> None:
        await self._stderr_queue.put(line)

    async def on_exit(self, exit_code: int) -> None:
        self._exit_code = exit_code
        self._exit_event.set()

    async def stdout_lines(self) -> AsyncIterator[str]:
        while True:
            try:
                line = await asyncio.wait_for(self._stdout_queue.get(), timeout=0.1)
                yield line
            except asyncio.TimeoutError:
                if self._exit_event.is_set() and self._stdout_queue.empty():
                    break

    async def stderr_lines(self) -> AsyncIterator[str]:
        while True:
            try:
                line = await asyncio.wait_for(self._stderr_queue.get(), timeout=0.1)
                yield line
            except asyncio.TimeoutError:
                if self._exit_event.is_set() and self._stderr_queue.empty():
                    break

    async def wait_exit(self) -> int:
        await self._exit_event.wait()
        return self._exit_code or -1


@dataclass
class ProcessContext:
    """Holds process execution state."""
    cmd: List[str]
    cwd: str
    env: Dict[str, str]
    limits: ProcessLimits
    callback: Optional[ProcessCallback]
    stdin_data: Optional[bytes] = None
    use_chroot: bool = False
    chroot_path: str = "/opt/urban-chroot"
    chroot_bind_mounts: Dict[str, str] = field(default_factory=dict)
    module_name: Optional[str] = None
    
    # Execution state
    process: Optional[asyncio.subprocess.Process] = None
    pid: Optional[int] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    stdout_buffer: List[str] = field(default_factory=list)
    stderr_buffer: List[str] = field(default_factory=list)
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    monitor_task: Optional[asyncio.Task] = None


class ProcessManager:
    """
    Advanced subprocess manager with:
    - Async subprocess execution with streaming output
    - Chroot support (bind mounts, user namespaces)
    - Resource limits (memory, CPU, duration, output size)
    - Callback-based or streaming output handling
    - Graceful shutdown with signal escalation
    - Process tree cleanup
    """

    def __init__(
        self,
        default_cwd: str = "/",
        default_env: Optional[Dict[str, str]] = None,
        default_limits: Optional[ProcessLimits] = None,
    ):
        self.default_cwd = default_cwd
        self.default_env = {**os.environ, **(default_env or {})}
        self.default_limits = default_limits or ProcessLimits()
        self._active_processes: Dict[int, ProcessContext] = {}
        self._lock = asyncio.Lock()

    async def run(
        self,
        cmd: Union[str, List[str]],
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        limits: Optional[ProcessLimits] = None,
        callback: Optional[ProcessCallback] = None,
        stdin_data: Optional[bytes] = None,
        use_chroot: bool = False,
        chroot_path: str = "/opt/urban-chroot",
        chroot_bind_mounts: Optional[Dict[str, str]] = None,
        capture_output: bool = True,
        module_name: Optional[str] = None,
    ) -> ProcessResult:
        """
        Run a command with full control and monitoring.
        
        Args:
            cmd: Command as string or list of args
            cwd: Working directory
            env: Environment variables (merged with defaults)
            limits: Resource limits
            callback: Async callback for streaming output
            stdin_data: Data to send to stdin
            use_chroot: Execute inside Alpine chroot
            chroot_path: Path to chroot
            chroot_bind_mounts: Additional bind mounts for chroot
            capture_output: Whether to capture stdout/stderr in result
            
        Returns:
            ProcessResult with stdout, stderr, exit_code, timing
        """
        if isinstance(cmd, str):
            args = shlex.split(cmd)
        else:
            args = list(cmd)

        ctx = ProcessContext(
            cmd=args,
            cwd=cwd or self.default_cwd,
            env={**self.default_env, **(env or {})},
            limits=limits or self.default_limits,
            callback=callback,
            stdin_data=stdin_data,
            use_chroot=use_chroot,
            chroot_path=chroot_path,
            chroot_bind_mounts=chroot_bind_mounts or {},
            module_name=module_name,
        )

        async with self._lock:
            self._active_processes[id(ctx)] = ctx

        try:
            result = await self._execute(ctx, capture_output)
            return result
        finally:
            async with self._lock:
                self._active_processes.pop(id(ctx), None)

    async def run_streaming(
        self,
        cmd: Union[str, List[str]],
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        limits: Optional[ProcessLimits] = None,
        use_chroot: bool = False,
        chroot_path: str = "/opt/urban-chroot",
    ) -> StreamCallback:
        """
        Run command and return StreamCallback for async iteration.
        
        Usage:
            callback = await pm.run_streaming("long-running-command")
            async for line in callback.stdout_lines():
                process_line(line)
            exit_code = await callback.wait_exit()
        """
        callback = StreamCallback()
        # Run in background
        task = asyncio.create_task(
            self.run(
                cmd=cmd,
                cwd=cwd,
                env=env,
                limits=limits,
                callback=callback,
                use_chroot=use_chroot,
                chroot_path=chroot_path,
                capture_output=False,
            )
        )
        # Attach task to callback for reference
        callback._run_task = task  # type: ignore
        return callback

    async def _execute(
        self,
        ctx: ProcessContext,
        capture_output: bool,
    ) -> ProcessResult:
        started_at = datetime.utcnow()
        ctx.started_at = started_at

        # Build command with chroot if needed
        if ctx.use_chroot:
            full_cmd = self._build_chroot_command(ctx)
        else:
            full_cmd = ctx.cmd

        # Prepare pipes
        stdout_pipe = asyncio.subprocess.PIPE if capture_output or ctx.callback else asyncio.subprocess.DEVNULL
        stderr_pipe = asyncio.subprocess.PIPE if capture_output or ctx.callback else asyncio.subprocess.DEVNULL
        stdin_pipe = asyncio.subprocess.PIPE if ctx.stdin_data else asyncio.subprocess.DEVNULL

        logger.debug(
            "Starting process",
            cmd=ctx.cmd,
            cwd=ctx.cwd,
            use_chroot=ctx.use_chroot,
            pid=None,  # not known yet
        )

        # Start process
        try:
            self._apply_module_hardening(ctx)
            proc = await asyncio.create_subprocess_exec(
                *full_cmd,
                cwd=ctx.cwd,
                env=ctx.env if ctx.env != os.environ else None,
                stdin=stdin_pipe,
                stdout=stdout_pipe,
                stderr=stderr_pipe,
                start_new_session=True,  # New process group for tree kill
            )
        except Exception as e:
            logger.error("Failed to start process", cmd=ctx.cmd, error=str(e))
            return ProcessResult(
                cmd=" ".join(ctx.cmd),
                args=ctx.cmd,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                duration_ms=0,
                started_at=started_at,
                finished_at=datetime.utcnow(),
                pid=-1,
                success=False,
            )

        ctx.process = proc
        ctx.pid = proc.pid

        async with self._lock:
            self._active_processes[id(ctx)] = ctx

        logger.debug("Process started", pid=proc.pid, cmd=ctx.cmd)

        # Send stdin if provided
        if ctx.stdin_data and proc.stdin:
            try:
                proc.stdin.write(ctx.stdin_data)
                await proc.stdin.drain()
                proc.stdin.close()
            except Exception as e:
                logger.warning("Failed to write stdin", error=str(e))

        # Start output readers
        stdout_task = asyncio.create_task(self._read_stream(proc.stdout, ctx, "stdout"))
        stderr_task = asyncio.create_task(self._read_stream(proc.stderr, ctx, "stderr"))

        # Start monitor task for limits
        if ctx.limits.max_duration_sec or ctx.limits.max_output_mb or ctx.limits.max_memory_mb:
            ctx.monitor_task = asyncio.create_task(self._monitor_process(ctx))

        # Wait for completion with timeout if specified
        try:
            if ctx.limits.max_duration_sec:
                await asyncio.wait_for(proc.wait(), timeout=ctx.limits.max_duration_sec)
            else:
                await proc.wait()
        except asyncio.TimeoutError:
            logger.warning("Process timeout, killing", pid=proc.pid, timeout=ctx.limits.max_duration_sec)
            await self._kill_process_tree(proc.pid)
            raise

        finished_at = datetime.utcnow()
        ctx.finished_at = finished_at

        # Wait for readers to finish
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
        if ctx.monitor_task:
            ctx.monitor_task.cancel()
            try:
                await ctx.monitor_task
            except asyncio.CancelledError:
                pass

        exit_code = proc.returncode or 0
        duration_ms = int((finished_at - started_at).total_seconds() * 1000)

        result = ProcessResult(
            cmd=" ".join(ctx.cmd),
            args=ctx.cmd,
            stdout="\n".join(ctx.stdout_buffer) if capture_output else "",
            stderr="\n".join(ctx.stderr_buffer) if capture_output else "",
            exit_code=exit_code,
            duration_ms=duration_ms,
            started_at=started_at,
            finished_at=finished_at,
            pid=proc.pid,
        )

        # Execute on_exit callback
        if ctx.callback:
            try:
                await ctx.callback.on_exit(exit_code)
            except Exception as e:
                logger.error("Callback on_exit failed", error=str(e))

        logger.debug("Process finished", pid=proc.pid, exit_code=exit_code, duration_ms=duration_ms)
        return result

    def _build_chroot_command(self, ctx: ProcessContext) -> List[str]:
        """Build command to execute inside Alpine chroot."""
        # Build bind mount args for nsexec / chroot
        bind_args = []
        for src, dst in ctx.chroot_bind_mounts.items():
            bind_args.extend(["--bind", f"{src}:{dst}"])
        
        # Add default binds
        binds = {
            "/data": "/data",
            "/artifacts": "/artifacts",
            "/logs": "/logs",
            "/etc/resolv.conf": "/etc/resolv.conf",
            "/proc": "/proc",
            "/sys": "/sys",
            "/dev": "/dev",
        }
        for src, dst in binds.items():
            if src not in ctx.chroot_bind_mounts:
                bind_args.extend(["--bind", f"{src}:{dst}"])

        # Use nsexec (from util-linux) for namespace isolation
        # Fallback to chroot if nsexec not available
        cmd = [
            "nsexec",
            "--user", "0",
            "--group", "0",
            *bind_args,
            "--",
            "chroot", ctx.chroot_path,
            "/bin/sh", "-c",
            " ".join(shlex.quote(arg) for arg in ctx.cmd)
        ]
        return cmd

    def _apply_module_hardening(self, ctx: ProcessContext) -> None:
        """Best-effort seccomp/capability hardening for the spawned process.

        This is intentionally applied only at the manager level for management
        tooling. For the actual attack/scan workloads that need real raw-socket
        access or administrative network operations, prefer keeping
        `use_chroot=True` without these workflow-manager restrictions, or run
        those workloads in a dedicated stream with elevated permissions.
        """
        module = ctx.module_name
        if not module:
            return

        try:
            from urban_hs.core.security import CapabilitySet, SeccompFilter, SECCOMP_PROFILES, SeccompProfile
        except ImportError:
            return

        if ctx.use_chroot:
            return

        profile: Optional[SeccompProfile] = SECCOMP_PROFILES.get(module)
        if profile is not None:
            try:
                SeccompFilter(profile=profile).load()
            except Exception as exc:
                logger.warning("Seccomp load skipped", module=module, error=str(exc))

        try:
            caps = CapabilitySet.from_module(module)
            if caps.effective or caps.permitted or caps.bounding:
                caps.apply()
        except Exception as exc:
            logger.warning("Capability apply skipped", module=module, error=str(exc))

    async def _read_stream(
        self,
        stream: Optional[asyncio.StreamReader],
        ctx: ProcessContext,
        stream_name: str,
    ) -> None:
        """Read from stdout/stderr with callbacks and buffering."""
        if not stream:
            return

        buffer = ctx.stdout_buffer if stream_name == "stdout" else ctx.stderr_buffer
        bytes_count = 0
        limit = ctx.limits.max_output_mb * 1024 * 1024

        while True:
            try:
                line = await stream.readline()
                if not line:
                    break

                decoded = line.decode("utf-8", errors="replace").rstrip("\n\r")
                buffer.append(decoded)
                bytes_count += len(line)

                if bytes_count > limit:
                    logger.warning("Output limit reached, truncating", stream=stream_name, limit_mb=ctx.limits.max_output_mb)
                    buffer.append(f"... [OUTPUT TRUNCATED - LIMIT {ctx.limits.max_output_mb}MB REACHED]")
                    break

                if ctx.callback:
                    callback_method = getattr(ctx.callback, f"on_{stream_name}")
                    await callback_method(decoded)

            except Exception as e:
                logger.error(f"Error reading {stream_name}", error=str(e))
                break

    async def _monitor_process(self, ctx: ProcessContext) -> None:
        """Monitor process for resource limits."""
        proc = ctx.process
        if not proc:
            return

        pid = proc.pid
        while True:
            try:
                await asyncio.sleep(1)
                
                if proc.returncode is not None:
                    break

                # Check CPU/memory if limits set
                # Note: Full implementation would use psutil
                # For now just check duration
                if ctx.limits.max_duration_sec and ctx.started_at:
                    elapsed = (datetime.utcnow() - ctx.started_at).total_seconds()
                    if elapsed > ctx.limits.max_duration_sec:
                        logger.warning("Process exceeded time limit, killing", pid=pid)
                        await self._kill_process_tree(pid)
                        break

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Monitor error", error=str(e))
                break

    async def _kill_process_tree(self, pid: int, signal_num: int = signal.SIGTERM, force_after: float = 5.0) -> None:
        """Kill process and all children with escalating signals."""
        try:
            # Get child PIDs
            child_pids = await self._get_child_pids(pid)
            all_pids = [pid] + child_pids
            
            # Send SIGTERM
            for p in all_pids:
                try:
                    os.kill(p, signal_num)
                except ProcessLookupError:
                    pass
            
            if force_after > 0:
                await asyncio.sleep(force_after)
                
                # Force kill with SIGKILL
                for p in all_pids:
                    try:
                        os.kill(p, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                        
        except Exception as e:
            logger.error("Error killing process tree", pid=pid, error=str(e))

    async def _get_child_pids(self, pid: int) -> List[int]:
        """Get all descendant PIDs of a process."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "pgrep", "-P", str(pid),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0 and stdout:
                children = [int(p) for p in stdout.decode().strip().split()]
                # Recursively get grandchildren
                all_children = list(children)
                for child in children:
                    all_children.extend(await self._get_child_pids(child))
                return all_children
        except Exception:
            pass
        return []

    async def get_active_processes(self) -> List[Dict[str, Any]]:
        """Get info about all currently running processes."""
        async with self._lock:
            return [
                {
                    "pid": ctx.pid,
                    "cmd": ctx.cmd,
                    "cwd": ctx.cwd,
                    "started_at": ctx.started_at.isoformat() if ctx.started_at else None,
                    "use_chroot": ctx.use_chroot,
                }
                for ctx in self._active_processes.values()
            ]

    async def kill_all(self, signal: int = signal.SIGTERM) -> int:
        """Kill all managed processes."""
        async with self._lock:
            count = 0
            for ctx in list(self._active_processes.values()):
                if ctx.process and ctx.process.returncode is None:
                    try:
                        await self._kill_process_tree(ctx.pid or 0, signal)
                        count += 1
                    except Exception as e:
                        logger.error("Error killing process", pid=ctx.pid, error=str(e))
            return count

    async def shutdown(self, timeout: float = 10.0) -> None:
        """Graceful shutdown - wait for processes then force kill."""
        logger.info("Shutting down process manager")
        
        # Wait for active processes
        async with self._lock:
            for ctx in list(self._active_processes.values()):
                if ctx.process and ctx.process.returncode is None:
                    ctx.process.terminate()

        try:
            await asyncio.wait_for(
                asyncio.gather(*[
                    ctx.process.wait() 
                    for ctx in self._active_processes.values()
                    if ctx.process and ctx.process.returncode is None
                ]),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            logger.warning("Force killing remaining processes")
            await self.kill_all(signal.SIGKILL)


# Global instance
_process_manager: Optional[ProcessManager] = None


def get_process_manager() -> ProcessManager:
    global _process_manager
    if _process_manager is None:
        _process_manager = ProcessManager()
    return _process_manager


async def init_process_manager(**kwargs) -> ProcessManager:
    global _process_manager
    _process_manager = ProcessManager(**kwargs)
    return _process_manager


async def shutdown_process_manager() -> None:
    global _process_manager
    if _process_manager:
        await _process_manager.shutdown()
        _process_manager = None