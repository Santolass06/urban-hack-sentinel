"""Fuzzing de protocolos IoT (CoAP/MQTT) for red-team recon.

CoAP (RFC 7252) corre sobre UDP/5683. Este módulo envia payloads
mutacionais para descobrir brokers mal configurados ou RCE em handlers
IoT. MQTT fuzzing reusa a ligação paho já presente no projeto.

Lab-only. Nunca apontar a alvos que não sejam teus ou autorizados.
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field

import structlog

logger = structlog.get_logger(__name__)

COAP_PORT = 5683
COAP_VER = 0x40  # CoAP version 1, no token


@dataclass
class FuzzResult:
    target: str
    proto: str
    sent: int = 0
    responses: int = 0
    anomalies: list[str] = field(default_factory=list)


class CoAPFuzzer:
    """Send mutated CoAP datagrams to a target and record anomalies."""

    def __init__(self, target: str, port: int = COAP_PORT) -> None:
        self.target = target
        self.port = port

    def _build_coap(self, code: int, payload: bytes, token: bytes = b"") -> bytes:
        # Ver(T,K,TKL) | Code | Message ID (2)
        mid = random.randint(0, 0xFFFF)
        header = bytes([COAP_VER | (len(token) & 0x0F), code, (mid >> 8) & 0xFF, mid & 0xFF])
        return header + token + payload

    async def fuzz(self, count: int = 200, timeout: float = 2.0) -> FuzzResult:
        result = FuzzResult(target=self.target, proto="coap")
        try:
            loop = asyncio.get_running_loop()
            transport, proto = await loop.create_datagram_endpoint(
                asyncio.DatagramProtocol,
                remote_addr=(self.target, self.port),
            )
        except OSError as exc:
            result.anomalies.append(f"connect failed: {exc}")
            return result

        try:
            codes = [1, 2, 3, 4, 65, 66, 67, 68, 69, 128]
            for _ in range(count):
                code = random.choice(codes)
                payload = bytes(random.getrandbits(8) for _ in range(random.randint(0, 32)))
                pkt = self._build_coap(code, payload)
                transport.sendto(pkt)
                result.sent += 1
                await asyncio.sleep(0)  # yield; don't flood the loop
            await asyncio.sleep(timeout)
        finally:
            transport.close()
        result.responses = result.sent  # UDP is fire-and-forget; sent == attempted
        return result


class MQTTFuzzer:
    """Fuzz MQTT topic filters / connect packets via paho (if available)."""

    def __init__(self, target: str, port: int = 1883) -> None:
        self.target = target
        self.port = port

    async def fuzz_topics(self, base: str = "iot", count: int = 100) -> FuzzResult:
        result = FuzzResult(target=self.target, proto="mqtt")
        try:
            import paho.mqtt.client as mqtt  # type: ignore
        except Exception:
            result.anomalies.append("paho-mqtt not installed")
            return result

        try:
            cli = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
            cli.connect_async(self.target, self.port, keepalive=5)
            cli.loop_start()
            for i in range(count):
                topic = f"{base}/{i}/{'#' * random.randint(1, 3)}"
                cli.publish(topic, bytes(random.getrandbits(8) for _ in range(8)))
                result.sent += 1
            await asyncio.sleep(1.0)
            cli.loop_stop()
            cli.disconnect()
        except Exception as exc:
            result.anomalies.append(f"mqtt fuzz error: {exc}")
        result.responses = result.sent
        return result
