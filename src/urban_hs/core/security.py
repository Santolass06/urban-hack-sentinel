"""
Security Hardening - Seccomp profiles, capability dropping, rootless chroot, supply chain security.

Provides:
- Seccomp-bpf filter profiles per module
- Capability dropping for least privilege
- Rootless chroot with user namespaces
- GPG supply chain verification (cosign/SLSA)
- Secure defaults and audit logging
"""

import asyncio
import json
import os
import structlog
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Set, Tuple

logger = structlog.get_logger(__name__)


class Capability(Enum):
    """Linux capabilities for fine-grained privilege control."""
    CAP_CHOWN = "CAP_CHOWN"
    CAP_DAC_OVERRIDE = "CAP_DAC_OVERRIDE"
    CAP_DAC_READ_SEARCH = "CAP_DAC_READ_SEARCH"
    CAP_FOWNER = "CAP_FOWNER"
    CAP_FSETID = "CAP_FSETID"
    CAP_KILL = "CAP_KILL"
    CAP_SETGID = "CAP_SETGID"
    CAP_SETUID = "CAP_SETUID"
    CAP_SETPCAP = "CAP_SETPCAP"
    CAP_LINUX_IMMUTABLE = "CAP_LINUX_IMMUTABLE"
    CAP_NET_BIND_SERVICE = "CAP_NET_BIND_SERVICE"
    CAP_NET_BROADCAST = "CAP_NET_BROADCAST"
    CAP_NET_ADMIN = "CAP_NET_ADMIN"
    CAP_NET_RAW = "CAP_NET_RAW"
    CAP_IPC_LOCK = "CAP_IPC_LOCK"
    CAP_IPC_OWNER = "CAP_IPC_OWNER"
    CAP_SYS_MODULE = "CAP_SYS_MODULE"
    CAP_SYS_RAWIO = "CAP_SYS_RAWIO"
    CAP_SYS_CHROOT = "CAP_SYS_CHROOT"
    CAP_SYS_PTRACE = "CAP_SYS_PTRACE"
    CAP_SYS_PACCT = "CAP_SYS_PACCT"
    CAP_SYS_ADMIN = "CAP_SYS_ADMIN"
    CAP_SYS_BOOT = "CAP_SYS_BOOT"
    CAP_SYS_NICE = "CAP_SYS_NICE"
    CAP_SYS_RESOURCE = "CAP_SYS_RESOURCE"
    CAP_SYS_TIME = "CAP_SYS_TIME"
    CAP_SYS_TTY_CONFIG = "CAP_SYS_TTY_CONFIG"
    CAP_MKNOD = "CAP_MKNOD"
    CAP_LEASE = "CAP_LEASE"
    CAP_AUDIT_WRITE = "CAP_AUDIT_WRITE"
    CAP_AUDIT_CONTROL = "CAP_AUDIT_CONTROL"
    CAP_SETFCAP = "CAP_SETFCAP"
    CAP_MAC_OVERRIDE = "CAP_MAC_OVERRIDE"
    CAP_MAC_ADMIN = "CAP_MAC_ADMIN"
    CAP_SYSLOG = "CAP_SYSLOG"
    CAP_WAKE_ALARM = "CAP_WAKE_ALARM"
    CAP_BLOCK_SUSPEND = "CAP_BLOCK_SUSPEND"
    CAP_AUDIT_READ = "CAP_AUDIT_READ"
    CAP_PERFMON = "CAP_PERFMON"
    CAP_BPF = "CAP_BPF"


class SeccompAction(Enum):
    """Seccomp filter actions."""
    KILL_PROCESS = "SCMP_ACT_KILL_PROCESS"
    KILL_THREAD = "SCMP_ACT_KILL_THREAD"
    KILL = "SCMP_ACT_KILL"
    TRAP = "SCMP_ACT_TRAP"
    ERRNO = "SCMP_ACT_ERRNO"
    TRACE = "SCMP_ACT_TRACE"
    LOG = "SCMP_ACT_LOG"
    ALLOW = "SCMP_ACT_ALLOW"
    NOTIFY = "SCMP_ACT_NOTIFY"


@dataclass
class SeccompRule:
    """Single seccomp filter rule."""
    syscall: str
    action: SeccompAction = SeccompAction.ALLOW
    args: List[Tuple[int, int, int]] = field(default_factory=list)  # (index, op, value)
    comment: str = ""


@dataclass
class SeccompProfile:
    """Complete seccomp-bpf filter profile."""
    name: str
    default_action: SeccompAction = SeccompAction.ERRNO
    rules: List[SeccompRule] = field(default_factory=list)
    
    def to_json(self) -> str:
        """Export profile as JSON for libseccomp."""
        import json
        return json.dumps({
            "defaultAction": self.default_action.value,
            "syscalls": [
                {
                    "name": rule.syscall,
                    "action": rule.action.value,
                    "args": [{"index": a[0], "op": a[1], "value": a[2]} for a in rule.args],
                }
                for rule in self.rules
            ]
        }, indent=2)


# Predefined capability sets per module
MODULE_CAPABILITIES: Dict[str, List[Capability]] = {
    "wifi_scanner": [
        Capability.CAP_NET_RAW,
        Capability.CAP_NET_ADMIN,
        Capability.CAP_DAC_READ_SEARCH,
    ],
    "wifi_attacker": [
        Capability.CAP_NET_RAW,
        Capability.CAP_NET_ADMIN,
        Capability.CAP_DAC_READ_SEARCH,
        Capability.CAP_DAC_OVERRIDE,
    ],
    "ble_scanner": [
        Capability.CAP_NET_RAW,
        Capability.CAP_NET_ADMIN,
    ],
    "bt_hid": [
        Capability.CAP_NET_RAW,
        Capability.CAP_NET_ADMIN,
        Capability.CAP_DAC_READ_SEARCH,
    ],
    "network_scanner": [
        Capability.CAP_NET_RAW,
        Capability.CAP_NET_ADMIN,
    ],
    "camera_enum": [
        Capability.CAP_NET_RAW,
        Capability.CAP_DAC_READ_SEARCH,
    ],
    "chroot_manager": [
        Capability.CAP_SYS_CHROOT,
        Capability.CAP_SYS_ADMIN,
        Capability.CAP_DAC_OVERRIDE,
        Capability.CAP_MKNOD,
    ],
    "process_manager": [
        Capability.CAP_SYS_RESOURCE,
        Capability.CAP_SYS_ADMIN,
        Capability.CAP_SYS_PTRACE,
    ],
    "gps": [
        Capability.CAP_DAC_READ_SEARCH,
    ],
}


# Minimal seccomp profiles per module
SECCOMP_PROFILES: Dict[str, SeccompProfile] = {
    "wifi_scanner": SeccompProfile(
        name="wifi_scanner",
        default_action=SeccompAction.ERRNO,
        rules=[
            SeccompRule("socket", SeccompAction.ALLOW),
            SeccompRule("bind", SeccompAction.ALLOW),
            SeccompRule("connect", SeccompAction.ALLOW),
            SeccompRule("sendto", SeccompAction.ALLOW),
            SeccompRule("recvfrom", SeccompAction.ALLOW),
            SeccompRule("ioctl", SeccompAction.ALLOW),
            SeccompRule("read", SeccompAction.ALLOW),
            SeccompRule("write", SeccompAction.ALLOW),
            SeccompRule("close", SeccompAction.ALLOW),
            SeccompRule("epoll_ctl", SeccompAction.ALLOW),
            SeccompRule("epoll_wait", SeccompAction.ALLOW),
            SeccompRule("clock_gettime", SeccompAction.ALLOW),
            SeccompRule("nanosleep", SeccompAction.ALLOW),
            SeccompRule("rt_sigaction", SeccompAction.ALLOW),
            SeccompRule("rt_sigprocmask", SeccompAction.ALLOW),
            SeccompRule("munmap", SeccompAction.ALLOW),
            SeccompRule("mmap", SeccompAction.ALLOW),
            SeccompRule("brk", SeccompAction.ALLOW),
            SeccompRule("access", SeccompAction.ALLOW),
            SeccompRule("stat", SeccompAction.ALLOW),
            SeccompRule("fstat", SeccompAction.ALLOW),
            SeccompRule("openat", SeccompAction.ALLOW),
            SeccompRule("getrandom", SeccompAction.ALLOW),
        ],
    ),
    "network_scanner": SeccompProfile(
        name="network_scanner",
        default_action=SeccompAction.ERRNO,
        rules=[
            SeccompRule("socket", SeccompAction.ALLOW),
            SeccompRule("connect", SeccompAction.ALLOW),
            SeccompRule("sendto", SeccompAction.ALLOW),
            SeccompRule("recvfrom", SeccompAction.ALLOW),
            SeccompRule("poll", SeccompAction.ALLOW),
            SeccompRule("epoll_wait", SeccompAction.ALLOW),
            SeccompRule("clock_gettime", SeccompAction.ALLOW),
            SeccompRule("nanosleep", SeccompAction.ALLOW),
            SeccompRule("read", SeccompAction.ALLOW),
            SeccompRule("write", SeccompAction.ALLOW),
        ],
    ),
    "bt_hid": SeccompProfile(
        name="bt_hid",
        default_action=SeccompAction.ERRNO,
        rules=[
            SeccompRule("socket", SeccompAction.ALLOW),
            SeccompRule("bind", SeccompAction.ALLOW),
            SeccompRule("listen", SeccompAction.ALLOW),
            SeccompRule("accept", SeccompAction.ALLOW),
            SeccompRule("connect", SeccompAction.ALLOW),
            SeccompRule("send", SeccompAction.ALLOW),
            SeccompRule("recv", SeccompAction.ALLOW),
            SeccompRule("ioctl", SeccompAction.ALLOW),
            SeccompRule("read", SeccompAction.ALLOW),
            SeccompRule("write", SeccompAction.ALLOW),
            SeccompRule("close", SeccompAction.ALLOW),
        ],
    ),
}


@dataclass
class CapabilitySet:
    """Set of capabilities with effective/permitted/inheritable flags."""
    effective: Set[Capability] = field(default_factory=set)
    permitted: Set[Capability] = field(default_factory=set)
    inheritable: Set[Capability] = field(default_factory=set)
    bounding: Set[Capability] = field(default_factory=set)
    
    @classmethod
    def from_module(cls, module_name: str) -> "CapabilitySet":
        """Create capability set for a module."""
        caps = MODULE_CAPABILITIES.get(module_name, [])
        return cls(
            effective=set(caps),
            permitted=set(caps),
            inheritable=set(),
            bounding=set(caps),
        )
    
    def apply(self) -> bool:
        """Apply capability set to current process."""
        try:
            import libcap
            cap = libcap.Capabilities()
            
            # Clear all
            cap.effective = []
            cap.permitted = []
            cap.inheritable = []
            
            # Set required capabilities
            for cap_name in self.bounding:
                libcap.cap_set_flag(cap.effective, libcap.CAP_SET, 1, [cap_name.value])
                libcap.cap_set_flag(cap.permitted, libcap.CAP_SET, 1, [cap_name.value])
                libcap.cap_set_flag(cap.bounding, libcap.CAP_SET, 1, [cap_name.value])
            
            cap.set_proc()
            return True
        except ImportError:
            logger.warning("libcap not available, skipping capability drop")
            return False
        except Exception as e:
            logger.error("Failed to drop capabilities", error=str(e))
            return False
    
    def drop_all_except(self, keep: Set[Capability]) -> bool:
        """Drop all capabilities except those in 'keep'."""
        self.effective &= keep
        self.permitted &= keep
        self.bounding &= keep
        return self.apply()


@dataclass
class SeccompFilter:
    """Seccomp filter manager."""
    profile: SeccompProfile
    _filter: Optional[Any] = None
    
    def load(self) -> bool:
        """Load seccomp filter into kernel."""
        try:
            import libseccomp as seccomp
            
            ctx = seccomp.SyscallFilter(defaction=self.profile.default_action.value)
            
            for rule in self.profile.rules:
                ctx.add_rule(
                    rule.action.value,
                    rule.syscall,
                    *[seccomp.Arg(a[0], a[1], a[2]) for a in rule.args]
                )
            
            ctx.load()
            self._filter = ctx
            logger.info("Seccomp profile loaded", profile=self.profile.name)
            return True
        except ImportError:
            logger.warning("libseccomp not available, skipping seccomp")
            return False
        except Exception as e:
            logger.error("Failed to load seccomp profile", profile=self.profile.name, error=str(e))
            return False
    
    def unload(self) -> None:
        """Unload seccomp filter (requires restart)."""
        logger.warning("Seccomp filter cannot be unloaded without process restart")


@dataclass
class RootlessChrootConfig:
    """Configuration for rootless chroot with user namespaces."""
    chroot_path: str = "/opt/urban-chroot"
    user_map: str = "0 100000 65536"  # Map root (0) to UID 100000+
    group_map: str = "0 100000 65536"
    bind_mounts: Dict[str, str] = field(default_factory=lambda: {
        "/data": "/data",
        "/artifacts": "/artifacts",
        "/logs": "/logs",
        "/var/log": "/var/log",
        "/etc/resolv.conf": "/etc/resolv.conf",
        "/proc": "/proc",
        "/sys": "/sys",
        "/dev": "/dev",
    })
    env: Dict[str, str] = field(default_factory=lambda: {
        "HOME": "/root",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "TERM": "xterm-256color",
    })


class RootlessChroot:
    """Manage rootless chroot with user namespaces."""
    
    def __init__(self, config: RootlessChrootConfig):
        self.config = config
        self._ns_pid: Optional[int] = None
    
    async def enter(self) -> bool:
        """Enter rootless chroot using user namespaces."""
        try:
            # Check if user namespaces are enabled
            with open("/proc/sys/kernel/unprivileged_userns_clone", "r") as f:
                if f.read().strip() != "1":
                    logger.warning("User namespaces not enabled")
                    return False
            
            # Prepare bind mounts
            bind_args = []
            for src, dst in self.config.bind_mounts.items():
                if Path(src).exists():
                    bind_args.extend(["--bind", f"{src}:{dst}"])
            
            # Use nsexec for namespace isolation
            # This requires root or user namespace support
            cmd = [
                "unshare",
                "--user", "--map-root-user",
                "--mount", "--map-root-user",
                "--pid", "--fork",
                "--",
                "chroot", self.config.chroot_path,
                "/bin/sh", "-c",
                "exec /bin/bash --login",
            ]
            
            # Start the chroot process
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                env={**os.environ, **self.config.env},
                start_new_session=True,
            )
            
            self._ns_pid = proc.pid
            logger.info("Rootless chroot entered", pid=proc.pid)
            return True
            
        except Exception as e:
            logger.error("Failed to enter rootless chroot", error=str(e))
            return False
    
    async def run_in_chroot(self, command: List[str], env: Optional[Dict[str, str]] = None) -> int:
        """Run a command inside the chroot."""
        if self._ns_pid is None:
            raise RuntimeError("Chroot not entered")
        
        # Use nsenter to execute in the namespace
        cmd = [
            "nsenter",
            "--target", str(self._ns_pid),
            "--user", "--mount", "--pid",
            "--",
            *command,
        ]
        
        env = {**os.environ, **(env or {})}
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            env=env,
        )
        
        return await proc.wait()
    
    async def exit(self) -> bool:
        """Exit the chroot."""
        if self._ns_pid:
            try:
                os.kill(self._ns_pid, 15)  # SIGTERM
                await asyncio.sleep(1)
            except ProcessLookupError:
                pass
            self._ns_pid = None
            return True
        return False


@dataclass
class SupplyChainConfig:
    """Configuration for supply chain security."""
    cosign_public_key: Optional[str] = None
    cosign_key_path: Optional[str] = None
    slsa_provenance: bool = True
    sbom_format: str = "spdx-json"
    verify_signatures: bool = True
    trusted_keys: List[str] = field(default_factory=list)


class SupplyChainVerifier:
    """Supply chain security: cosign signing/verification, SLSA, SBOM."""
    
    def __init__(self, config: SupplyChainConfig):
        self.config = config
    
    async def sign_artifact(self, artifact_path: str) -> Optional[str]:
        """Sign artifact with cosign, return signature path."""
        if not self.config.cosign_key_path:
            logger.warning("No cosign key configured")
            return None
        
        sig_path = f"{artifact_path}.sig"
        
        cmd = [
            "cosign", "sign-blob",
            "--key", self.config.cosign_key_path,
            "--output-signature", sig_path,
            artifact_path,
        ]
        
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        
        if proc.returncode == 0:
            logger.info("Artifact signed", artifact=artifact_path, signature=sig_path)
            return sig_path
        else:
            logger.error("Signing failed", error=stderr.decode())
            return None
    
    async def verify_signature(self, artifact_path: str, signature_path: str) -> bool:
        """Verify artifact signature with cosign."""
        if not self.config.cosign_public_key:
            logger.warning("No public key configured for verification")
            return False
        
        cmd = [
            "cosign", "verify-blob",
            "--key", self.config.cosign_public_key,
            "--signature", signature_path,
            artifact_path,
        ]
        
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        
        return proc.returncode == 0
    
    async def generate_sbom(self, target_dir: str, output_path: str) -> bool:
        """Generate SBOM using Syft."""
        cmd = [
            "syft", target_dir,
            "-o", f"{self.config.sbom_format}={output_path}",
        ]
        
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        
        if proc.returncode == 0:
            logger.info("SBOM generated", output=output_path)
            return True
        else:
            logger.error("SBOM generation failed", error=stderr.decode())
            return False
    
    async def verify_slsa_provenance(self, artifact_path: str) -> bool:
        """Verify SLSA provenance (placeholder)."""
        # SLSA verification would check:
        # - Build provenance exists and is signed
        # - Build was performed on trusted infrastructure
        # - Source matches expected commit
        logger.info("SLSA provenance verification", artifact=artifact_path)
        return True  # Placeholder


async def drop_privileges(module_name: str, keep: Optional[List[str]] = None) -> bool:
    """Drop all unnecessary capabilities/privileges for a module."""
    caps = CapabilitySet.from_module(module_name)
    
    if keep:
        # Add explicitly kept capabilities
        for cap_name in keep:
            try:
                caps.bounding.add(Capability(cap_name))
            except ValueError:
                logger.warning("Unknown capability", name=cap_name)
    
    return caps.apply()


async def harden_process(module_name: str) -> Dict[str, bool]:
    """Apply all available hardening to current process."""
    results = {}
    
    # Drop capabilities
    results["capabilities"] = await drop_privileges(module_name)
    
    # Load seccomp profile
    profile = SECCOMP_PROFILES.get(module_name)
    if profile:
        seccomp_filter = SeccompFilter(profile)
        results["seccomp"] = seccomp_filter.load()
    
    # Drop supplementary groups
    try:
        os.setgroups([])
        results["drop_groups"] = True
    except Exception:
        results["drop_groups"] = False
    
    # Set no-new-privs
    try:
        import prctl
        prctl.set_no_new_privs(True)
        results["no_new_privs"] = True
    except ImportError:
        results["no_new_privs"] = False
    
    # Set securebits
    try:
        import prctl
        prctl.set_securebits(
            prctl.SECURE_NOROOT | prctl.SECURE_NO_SETUID_FIXUP
        )
        results["securebits"] = True
    except ImportError:
        results["securebits"] = False
    
    logger.info("Process hardening applied", module=module_name, results=results)
    return results


# ============================================================
# Exports
# ============================================================

__all__ = [
    # Capabilities
    "Capability",
    "CapabilitySet",
    "MODULE_CAPABILITIES",
    "drop_privileges",
    
    # Seccomp
    "SeccompAction",
    "SeccompRule",
    "SeccompProfile",
    "SeccompFilter",
    "SECCOMP_PROFILES",
    
    # Rootless chroot
    "RootlessChrootConfig",
    "RootlessChroot",
    
    # Supply chain
    "SupplyChainConfig",
    "SupplyChainVerifier",
    
    # Hardening
    "harden_process",
]