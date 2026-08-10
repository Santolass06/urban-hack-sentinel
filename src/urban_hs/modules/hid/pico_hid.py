"""HID over Raspberry Pi Pico / CircuitPython (BadUSB via serial).

Alternative ao ConfigFS gadget (``hid/gadget.py``) para alvos sem USB
gadget mode (ex: um Pi Pico com firmware CircuitPython a atuar como
teclado USB). Envia keystrokes via porta série (``/dev/ttyACMx``).

O Pico deve correr um ``code.py`` que aceite linhas ``KEY:<hid_usage>``
ou texto cru. Este módulo só envia; o firmware no Pico faz a tradução
HID. Lab-only.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class PicoHIDResult:
    port: str
    sent: int = 0
    error: str | None = None


class PicoHIDInjector:
    """Drive a CircuitPython Pico acting as a USB keyboard over serial."""

    def __init__(self, port: str = "/dev/ttyACM0", baud: int = 9600) -> None:
        self.port = port
        self.baud = baud

    async def send_keys(self, keys: list[str]) -> PicoHIDResult:
        """Send a list of HID key tokens (or raw lines) to the Pico.

        Each entry is written as ``KEY:<token>\\n``; the Pico firmware maps
        the token to a HID usage and injects the keystroke.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                "python3",
                "-c",
                (
                    "import sys,serial,time\n"
                    f"s=serial.Serial(sys.argv[1],{self.baud})\n"
                    "time.sleep(1)\n"
                    "for line in sys.argv[2:]:\n"
                    "    s.write(('KEY:'+line+'\\n').encode()); time.sleep(0.05)\n"
                ),
                self.port,
                *keys,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, err = await proc.communicate()
            if proc.returncode != 0:
                return PicoHIDResult(
                    port=self.port, error=err.decode(errors="ignore") or "serial send failed"
                )
            return PicoHIDResult(port=self.port, sent=len(keys))
        except (OSError, ValueError) as exc:
            return PicoHIDResult(port=self.port, error=str(exc))

    async def type_text(self, text: str) -> PicoHIDResult:
        """Type arbitrary text by sending each character as a key token."""
        keys = [c for c in text if c.isprintable()]
        return await self.send_keys(keys)
