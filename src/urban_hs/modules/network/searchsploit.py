"""
SearchSploit integration for ExploitDB searches.
"""

import asyncio
import json
import re
import structlog
from typing import Any, Dict, List, Optional

logger = structlog.get_logger(__name__)


class SearchSploitIntegration:
    """
    Local ExploitDB search integration using searchsploit.
    """

    def __init__(self, searchsploit_path: str = "searchsploit"):
        self.searchsploit_path = searchsploit_path

    async def search(self, query: str, exact: bool = False, json_output: bool = True) -> List[Dict[str, Any]]:
        cmd = [self.searchsploit_path]

        if json_output:
            cmd.append("-j")
        if exact:
            cmd.append("-e")

        cmd.append(query)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)

            if proc.returncode != 0:
                logger.warning("searchsploit failed", stderr=stderr.decode()[:200])
                return []

            if json_output:
                try:
                    data = json.loads(stdout.decode())
                    return data.get("RESULTS_EXPLOIT", [])
                except json.JSONDecodeError:
                    logger.warning("Failed to parse searchsploit JSON output")
                    return []

        except Exception as e:
            logger.error("searchsploit error", error=str(e))
            return []

        return []

    async def get_exploit(self, exploit_id: str, output_dir: str) -> Optional[str]:
        if not re.match(r'^\d+$', exploit_id):
            logger.error("Invalid exploit_id format", exploit_id=exploit_id)
            return None

        try:
            cmd = [self.searchsploit_path, "-m", exploit_id, "-p", output_dir]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                output = stdout.decode()
                for line in output.split("\n"):
                    if "Copied" in line or "saved" in line:
                        parts = line.split()
                        for part in parts:
                            if part.endswith((".py", ".c", ".rb", ".pl", ".sh", ".txt", ".html")):
                                return part
            return None
        except Exception as e:
            logger.error("Failed to download exploit", error=str(e))
            return None
