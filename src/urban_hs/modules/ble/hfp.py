"""
HFP Audio Capture — SCO link via BlueZ + bluealsa.

This is a best-effort capture layer. A production deployment needs:
- bluealsa service running
- ofono or pulseaudio module-bluetooth-discover for SCO routing
- the target device already paired and trusted

This module only coordinates the capture; audio plumbing is host-dependent.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import tempfile
from dataclasses import dataclass
from pathlib import Path

import structlog

from urban_hs.core.event_bus import EventBus

logger = structlog.get_logger(__name__)


@dataclass
class HFPSession:
    target_address: str
    audio_file: Path | None = None
    pcm_device: str | None = None


class HFPAudioCapture:
    """Record audio from a Bluetooth HFP/SCO link."""

    def __init__(
        self,
        target_address: str,
        output_file: Path | None = None,
        duration: float | None = None,
        event_bus: EventBus | None = None,
    ):
        if not target_address:
            raise ValueError("target_address is required for HFP audio capture")
        self.target_address = target_address
        self.output_file = output_file or Path(
            tempfile.gettempdir()
        ) / f"hfp_{target_address.replace(':', '')}.wav"
        self.duration = duration
        self.event_bus = event_bus
        self._process: asyncio.subprocess.Process | None = None
        self.session = HFPSession(target_address=target_address)

    async def start(self) -> None:
        logger.info("Starting HFP capture", target=self.target_address, output=str(self.output_file))
        pcm = self._detect_pcm_device()
        if pcm is None:
            raise RuntimeError(
                "No bluealsa PCM device found. "
                "Verify bluealsa is running and the headset is connected."
            )
        self.session.pcm_device = pcm
        if self.event_bus is not None:
            try:
                await self.event_bus.publish(
                    "hfp.started",
                    {"target_address": self.target_address, "pcm": pcm, "output": str(self.output_file)},
                )
            except Exception as exc:
                logger.debug("hfp.started publish failed", error=str(exc))

    async def stop(self) -> Path:
        logger.info("Stopping HFP capture", target=self.target_address)
        if self._process is not None:
            try:
                self._process.terminate()
                await self._process.wait()
            except ProcessLookupError:
                pass
            finally:
                self._process = None
        if not self.output_file.exists():
            raise FileNotFoundError(f"HFP output not created: {self.output_file}")
        logger.info("HFP capture complete", output=str(self.output_file))
        if self.event_bus is not None:
            try:
                await self.event_bus.publish(
                    "hfp.completed",
                    {"target_address": self.target_address, "output": str(self.output_file)},
                )
            except Exception as exc:
                logger.debug("hfp.completed publish failed", error=str(exc))
        return self.output_file

    async def record(self) -> Path:
        await self.start()
        try:
            if self.duration is not None:
                await asyncio.sleep(self.duration)
            else:
                raise RuntimeError("duration must be set for record()")
        finally:
            return await self.stop()

    def _detect_pcm_device(self) -> str | None:
        """Return the first matching bluealsa HFP PCM device."""
        try:
            cmd = shlex.join(["find", "/dev/snd", "-name", "bluealsa*"])
            output = os.popen(cmd).read()
        except Exception as exc:
            logger.error("Failed to probe bluealsa PCM devices", error=str(exc))
            return None
        for raw in output.splitlines():
            name = Path(raw).name.lower()
            if "hfp" in name or "hs" in name:
                return f"bluealsa:{self.target_address.replace(':', '').upper()},PROFILE=hfp"
        return None
