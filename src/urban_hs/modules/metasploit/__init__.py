"""
Metasploit Module - RPC client and console wrapper.
"""

from urban_hs.modules.metasploit.console import (
    ConsoleOutputType,
    ConsoleResult,
    MetasploitConsole,
    ResourceScript,
)
from urban_hs.modules.metasploit.rpc import (
    MetasploitRPC,
    MsfConfig,
    MsfJob,
    MsfModule,
    MsfModuleType,
    MsfSession,
    MsfSessionType,
)

__all__ = [
    "MsfModuleType",
    "MsfSessionType",
    "MsfModule",
    "MsfSession",
    "MsfJob",
    "MsfConfig",
    "MetasploitRPC",
    "ConsoleOutputType",
    "ConsoleResult",
    "ResourceScript",
    "MetasploitConsole",
]