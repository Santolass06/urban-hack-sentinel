"""
Urban Hack Sentinel v3 — Textual TUI dashboard.

Entry point::

    python -m urban_hs.ui.tui.app

Registered as ``urban-hs-tui`` in ``pyproject.toml``.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Select,
    Static,
    TabbedContent,
    TabPane,
)

from urban_hs import __version__


# ---------------------------------------------------------------------------
# Custom Textual message for event bus events
# ---------------------------------------------------------------------------
class EventMessage:
    """Event bus event forwarded to the Textual UI."""

    def __init__(self, event_type: str, payload: Dict[str, Any]) -> None:
        self.event_type = event_type
        self.payload = payload


    def render(self) -> str:
        import platform
        import subprocess

        connected_info = "Not connected"
        try:
            res = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True, timeout=2)
            ssid = res.stdout.strip()
            if ssid:
                res_iface = subprocess.run(["iwgetid"], capture_output=True, text=True, timeout=2)
                iface = res_iface.stdout.split()[0] if res_iface.stdout else "wifi"
                connected_info = f"Connected to [bold yellow]{ssid}[/bold yellow] ({iface})"
        except Exception:
            pass

        return (
            f"[bold cyan]Urban Hack Sentinel[/bold cyan] [green]v{__version__}[/green] • {connected_info}\n"
            f"[dim]{platform.system()} {platform.release()} ({platform.machine()}) • "
            f"Python {platform.python_version()}[/dim]"
        )


class ConfirmModal(Static):
    """Simple modal for attack confirmation."""

    def __init__(self, message: str, on_confirm: Any) -> None:
        super().__init__()
        self._message = message
        self._on_confirm = on_confirm

    def compose(self) -> ComposeResult:  # type: ignore[override]
        yield Label(self._message)
        with Horizontal():
            yield Button("Confirm", id="modal-confirm")
            yield Button("Cancel", id="modal-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "modal-confirm":
            self._on_confirm()
        self.remove()


class TUIApp(App):
    """Main Textual dashboard."""

    CSS = """
    Screen { layout: vertical; }
    #main { height: 1fr; }
    RichLog { height: 1fr; border: solid $primary; }
    .panel { padding: 1 2; }
    DataTable { height: 1fr; }
    Static.confirm-modal { 
        dock: top; 
        padding: 1 2; 
        background: $panel; 
        border: solid $warning;
        width: 60;
    }
    """

    BINDINGS = [
        ("q", "app.quit", "Quit"),
        ("d", "toggle_dark", "Toggle dark mode"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._wifi_networks: list[dict[str, Any]] = []
        self._ble_devices: list[dict[str, Any]] = []
        self._attack_log: list[str] = []

    def compose(self) -> ComposeResult:
        yield Header()
        yield SystemStatus(id="status")
        with Container(id="main"):
            with TabbedContent():
                with TabPane("WiFi", id="tab-wifi"):
                    yield Vertical(
                        Horizontal(
                            Label("Interface:", classes="select-label"),
                            Select([("wlo1", "wlo1"), ("wlx00c0cab7625f", "wlx00c0cab7625f")], id="select-wifi-iface", value="wlx00c0cab7625f"),
                            Button("Scan", id="btn-wifi-scan"),
                            Button("Interfaces", id="btn-wifi-interfaces"),
                            Button("Deauth", id="btn-wifi-deauth"),
                            Button("WPS Pixie", id="btn-wifi-wps-pixie"),
                            Button("WPS PIN", id="btn-wifi-wps-pin"),
                            Button("Handshake", id="btn-wifi-handshake"),
                            Button("PMKID", id="btn-wifi-pmkid"),
                            Button("WPA3 Downgrade", id="btn-wifi-wpa3-downgrade"),
                            Button("802.11r FT", id="btn-wifi-ft"),
                            Button("Kr00k", id="btn-wifi-krook"),
                            Button("GPS Wardrive", id="btn-wifi-gps"),
                        ),
                        Label("Discovered Networks:"),
                        DataTable(id="wifi-table"),
                        classes="panel",
                    )
                with TabPane("BLE", id="tab-ble"):
                    yield Vertical(
                        Horizontal(
                            Button("Scan Fast Pair", id="btn-ble-scan"),
                            Button("WhisperPair", id="btn-ble-whisperpair"),
                            Button("Bluetooth HID", id="btn-ble-hid"),
                        ),
                        Label("BLE Devices:"),
                        DataTable(id="ble-table"),
                        classes="panel",
                    )
                with TabPane("Network", id="tab-network"):
                    yield Vertical(
                        Horizontal(
                            Button("Host Discovery (Nmap)", id="btn-net-nmap"),
                            Button("Nuclei Vuln Scan", id="btn-net-nuclei"),
                            Button("Camera Discovery", id="btn-net-camera"),
                            Button("ESP32 Probe", id="btn-net-esp32"),
                            Button("MQTT Brute", id="btn-net-mqtt"),
                        ),
                        Label("Results:"),
                        Static("(none yet)", id="net-results"),
                        classes="panel",
                    )
                with TabPane("Terminal", id="tab-terminal"):
                    yield Vertical(
                        RichLog(id="terminal-log", auto_scroll=True, markup=True),
                        Input(placeholder="Digita um comando bash/CLI (ex: urban-hs info, iw dev, ping 1.1.1.1)...", id="cmd-input"),
                    )
                with TabPane("Logs", id="tab-logs"):
                    yield RichLog(id="app-log", auto_scroll=True, markup=True)
        yield Footer()

    def on_mount(self) -> None:
        asyncio.create_task(self._listen_event_bus())
        asyncio.create_task(self._wifi_interfaces())
        asyncio.create_task(self._wifi_scan())
        asyncio.create_task(self._ble_scan())
        wifi_table = self.query_one("#wifi-table", DataTable)
        wifi_table.add_columns("BSSID", "SSID", "Encryption", "Signal", "Channel")
        wifi_table.cursor_type = "row"
        ble_table = self.query_one("#ble-table", DataTable)
        ble_table.add_columns("Address", "Name", "Type", "RSSI")
        ble_table.cursor_type = "row"

    async def _listen_event_bus(self) -> None:
        try:
            from urban_hs.core import get_event_bus

            bus = get_event_bus()
            while True:
                event = await bus._queue.get()
                self.post_message(EventMessage(event.type, event.payload))
        except Exception as exc:
            self.post_message(EventMessage("event_bus.error", {"error": str(exc)}))

    def on_event_message(self, message: EventMessage) -> None:
        terminal = self.query_one("#terminal-log", RichLog)
        logs = self.query_one("#app-log", RichLog)
        formatted = f"[cyan]{message.event_type}[/cyan] {message.payload}"
        terminal.write(formatted)
        logs.write(formatted)

        if message.event_type == "attack.started":
            self._attack_log.append(f"[yellow]START[/yellow] {message.payload}")
        elif message.event_type == "attack.progress":
            self._attack_log.append(f"[blue]PROGRESS[/blue] {message.payload}")
        elif message.event_type == "attack.completed":
            self._attack_log.append(f"[green]DONE[/green] {message.payload}")
            if "results" in message.payload:
                res_static = self.query_one("#net-results", Static)
                res_static.update(str(message.payload["results"]))
        elif message.event_type == "attack.error":
            self._attack_log.append(f"[red]ERROR[/red] {message.payload}")
        elif message.event_type in ("wifi.scan.completed", "wifi.scan_complete"):
            self._wifi_networks = message.payload.get("networks", [])
            self._refresh_wifi_table()
        elif message.event_type in ("wifi.interfaces.listed",):
            ifaces = message.payload.get("interfaces", [])
            if ifaces:
                try:
                    select = self.query_one("#select-wifi-iface", Select)
                    options = [(iface, iface) for iface in ifaces]
                    select.set_options(options)
                    for iface in ifaces:
                        if iface.startswith("wlx") or "alfa" in iface.lower():
                            select.value = iface
                            break
                except Exception:
                    pass
        elif message.event_type in ("ble.scan.completed", "ble.scan_complete"):
            self._ble_devices = message.payload.get("devices", [])
            self._refresh_ble_table()
        elif message.event_type in ("network.scan.completed",):
            hosts = message.payload.get("hosts", [])
            results = self.query_one("#net-results", Static)
            if hosts:
                lines = [f"{h.get('ip', '?')} — {h.get('hostname', '')} ({h.get('os_guess', '')})" for h in hosts]
                results.update("\n".join(lines))
            else:
                results.update("(no hosts found on LAN)")

    def _refresh_wifi_table(self) -> None:
        table = self.query_one("#wifi-table", DataTable)
        table.clear()
        for net in self._wifi_networks:
            table.add_row(
                net.get("bssid", ""),
                net.get("ssid", ""),
                net.get("encryption", ""),
                str(net.get("signal_dbm", "")),
                str(net.get("channel", "")),
            )

    def _refresh_ble_table(self) -> None:
        table = self.query_one("#ble-table", DataTable)
        table.clear()
        for dev in self._ble_devices:
            table.add_row(
                dev.get("address", ""),
                dev.get("name", ""),
                dev.get("device_type", ""),
                str(dev.get("rssi", "")),
            )

    # ------------------------------------------------------------------
    # Button handlers
    # ------------------------------------------------------------------
    def on_button_pressed(self, event: Button.Pressed) -> None:
        logs = self.query_one("#app-log", RichLog)
        bid = event.button.id or ""

        if bid == "btn-wifi-scan":
            logs.write("[yellow]Triggering WiFi scan…[/yellow]")
            asyncio.create_task(self._wifi_scan())
        elif bid == "btn-wifi-interfaces":
            logs.write("[yellow]Listing WiFi interfaces…[/yellow]")
            asyncio.create_task(self._wifi_interfaces())
        elif bid == "btn-wifi-deauth":
            self._confirm("Run deauth on selected network?", self._wifi_deauth)
        elif bid == "btn-wifi-wps-pixie":
            self._confirm("Run WPS Pixie Dust attack?", self._wifi_wps_pixie)
        elif bid == "btn-wifi-wps-pin":
            self._confirm("Run WPS PIN attack?", self._wifi_wps_pin)
        elif bid == "btn-wifi-handshake":
            self._confirm("Capture WPA handshake?", self._wifi_handshake)
        elif bid == "btn-wifi-pmkid":
            self._confirm("Capture PMKID?", self._wifi_pmkid)
        elif bid == "btn-wifi-wpa3-downgrade":
            self._confirm("Run WPA3 Transition Downgrade attack?", self._wifi_wpa3_downgrade)
        elif bid == "btn-wifi-ft":
            self._confirm("Run 802.11r Fast Transition attack?", self._wifi_ft)
        elif bid == "btn-wifi-krook":
            self._confirm("Run Kr00k (CVE-2019-15126) attack?", self._wifi_krook)
        elif bid == "btn-wifi-gps":
            logs.write("[yellow]Starting continuous GPS Wardriving mode…[/yellow]")
            asyncio.create_task(self._wifi_gps_wardrive())
        elif bid == "btn-ble-scan":
            logs.write("[yellow]Triggering BLE scan…[/yellow]")
            asyncio.create_task(self._ble_scan())
        elif bid == "btn-ble-whisperpair":
            self._confirm("Run WhisperPair pairing attack?", self._ble_whisperpair)
        elif bid == "btn-ble-hid":
            self._confirm("Run Bluetooth HID Injection attack?", self._ble_hid)
        elif bid == "btn-net-nmap":
            logs.write("[yellow]Starting network scan…[/yellow]")
            asyncio.create_task(self._network_scan())
        elif bid == "btn-net-nuclei":
            logs.write("[yellow]Starting Nuclei vulnerability scan…[/yellow]")
            asyncio.create_task(self._net_nuclei())
        elif bid == "btn-net-camera":
            logs.write("[yellow]Starting IP Camera discovery…[/yellow]")
            asyncio.create_task(self._net_camera())
        elif bid == "btn-net-esp32":
            logs.write("[yellow]Probing ESP32 vulnerabilities…[/yellow]")
            asyncio.create_task(self._net_esp32())
        elif bid == "btn-net-mqtt":
            logs.write("[yellow]Starting MQTT broker enumeration & brute force…[/yellow]")
            asyncio.create_task(self._net_mqtt())
        else:
            logs.write(f"[yellow]Button:[/yellow] {bid}")

    def _confirm(self, message: str, callback: Any) -> None:
        container = self.query_one("#main", Container)
        modal = ConfirmModal(message=message, on_confirm=callback)
        container.mount(modal)

    def _get_selected_wifi_bssid(self) -> str:
        try:
            table = self.query_one("#wifi-table", DataTable)
            if table.cursor_row is not None and table.cursor_row < len(self._wifi_networks):
                net = self._wifi_networks[table.cursor_row]
                return net.get("bssid", "FF:FF:FF:FF:FF:FF")
        except Exception:
            pass
        if self._wifi_networks:
            return self._wifi_networks[0].get("bssid", "FF:FF:FF:FF:FF:FF")
        return "FF:FF:FF:FF:FF:FF"

    def _get_selected_wifi_interface(self) -> str:
        try:
            select = self.query_one("#select-wifi-iface", Select)
            if select.value and isinstance(select.value, str) and select.value != Select.BLANK:
                return select.value
        except Exception:
            pass
        return "wlx00c0cab7625f"

    async def _wifi_deauth(self) -> None:
        self._publish_wifi_attack("deauth", {"count": 10})

    async def _wifi_wps_pixie(self) -> None:
        self._publish_wifi_attack("wps_pixie")

    async def _wifi_wps_pin(self) -> None:
        self._publish_wifi_attack("wps_pin")

    async def _wifi_handshake(self) -> None:
        self._publish_wifi_attack("handshake")

    async def _wifi_pmkid(self) -> None:
        self._publish_wifi_attack("pmkid")

    async def _wifi_wpa3_downgrade(self) -> None:
        self._publish_wifi_attack("wpa3_downgrade")

    async def _wifi_ft(self) -> None:
        self._publish_wifi_attack("fast_transition_ft")

    async def _wifi_krook(self) -> None:
        self._publish_wifi_attack("krook")

    async def _wifi_gps_wardrive(self) -> None:
        iface = self._get_selected_wifi_interface()
        self._publish_attack("wifi_gps_wardrive", {"interface": iface, "wardrive": True})

    async def _ble_whisperpair(self) -> None:
        try:
            from urban_hs.modules.ble import WhisperPairScanner
            scanner = WhisperPairScanner()
            res = await scanner.scan(duration=5)
            devs = [d.to_dict() if hasattr(d, "to_dict") else vars(d) for d in res]
            self.query_one("#net-results", Static).update(f"WhisperPair scan found {len(devs)} devices")
        except Exception as exc:
            self.query_one("#net-results", Static).update(f"WhisperPair scan failed: {exc}")

    async def _ble_hid(self) -> None:
        try:
            from urban_hs.modules.bt_hid import BTHIDModule
            mod = BTHIDModule()
            res = await mod.scan_vulnerable_devices()
            self.query_one("#net-results", Static).update(f"BT HID scan found {len(res)} vulnerable targets")
        except Exception as exc:
            self.query_one("#net-results", Static).update(f"BT HID scan failed: {exc}")

    async def _net_nuclei(self) -> None:
        results = self.query_one("#net-results", Static)
        results.update("[yellow]Running Nuclei vulnerability scan on LAN...[/yellow]")
        try:
            from urban_hs.modules.network import NucleiRunner
            runner = NucleiRunner()
            vulns = await runner.scan_target("192.168.1.1")
            if vulns:
                lines = [f"[{v.severity.upper()}] {v.name} ({v.matched_at})" for v in vulns]
                results.update("\n".join(lines))
            else:
                results.update("Nuclei scan completed: No critical vulnerabilities found on target.")
        except Exception as exc:
            results.update(f"Nuclei scan error: {exc}")

    async def _net_camera(self) -> None:
        results = self.query_one("#net-results", Static)
        results.update("[yellow]Discovering IP Cameras (ONVIF/RTSP/mDNS)...[/yellow]")
        try:
            from urban_hs.modules.network import CameraDiscovery
            disc = CameraDiscovery()
            cams = await disc.discover_cameras(subnet="192.168.1.0/24")
            if cams:
                lines = [f"Camera: {c.ip}:{c.port} ({c.brand}) - RTSP: {c.rtsp_url}" for c in cams]
                results.update("\n".join(lines))
            else:
                results.update("Camera Discovery completed: No unauthenticated IP cameras found.")
        except Exception as exc:
            results.update(f"Camera Discovery error: {exc}")

    async def _net_esp32(self) -> None:
        results = self.query_one("#net-results", Static)
        results.update("[yellow]Probing ESP32 vulnerabilities (CVE-2025-27840)...[/yellow]")
        try:
            from urban_hs.modules.esp32 import ESP32Module
            mod = ESP32Module()
            found = await mod.scan_esp32_devices(subnet="192.168.1.0/24")
            if found:
                lines = [f"ESP32 Device: {d.get('ip')} - MAC: {d.get('mac')} (Vuln: {d.get('vulnerable')})" for d in found]
                results.update("\n".join(lines))
            else:
                results.update("ESP32 Probe completed: No vulnerable ESP32 microcontrollers detected.")
        except Exception as exc:
            results.update(f"ESP32 Probe error: {exc}")

    async def _net_mqtt(self) -> None:
        results = self.query_one("#net-results", Static)
        results.update("[yellow]Searching MQTT Brokers & Enumerating Topics...[/yellow]")
        try:
            from urban_hs.modules.mqtt import MQTTModule
            mod = MQTTModule()
            brokers = await mod.discover_brokers(subnet="192.168.1.0/24")
            if brokers:
                lines = [f"MQTT Broker: {b.get('ip')}:{b.get('port')} - Auth Required: {b.get('auth')}" for b in brokers]
                results.update("\n".join(lines))
            else:
                results.update("MQTT Scan completed: No open MQTT brokers found.")
        except Exception as exc:
            results.update(f"MQTT Scan error: {exc}")

    def _publish_wifi_attack(self, attack_type: str, extra_params: Optional[dict[str, Any]] = None) -> None:
        import uuid
        from datetime import datetime, UTC
        from urban_hs.core import get_event_bus
        from urban_hs.core.event_bus import Event, EventPriority

        bssid = self._get_selected_wifi_bssid()
        iface = self._get_selected_wifi_interface()
        payload = {
            "type": attack_type,
            "bssid": bssid,
            "interface": iface,
            **(extra_params or {}),
        }
        bus = get_event_bus()
        event = Event(
            type="wifi.attack_request",
            payload=payload,
            source="tui",
            priority=EventPriority.HIGH,
            correlation_id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC),
            metadata={},
        )
        asyncio.create_task(bus.publish(event))
        try:
            logs = self.query_one("#app-log", RichLog)
            logs.write(f"[bold green]Dispatched WiFi attack '{attack_type}' to target {bssid} on {iface}[/bold green]")
        except Exception:
            pass

    def _publish_attack(self, attack: str, params: dict[str, Any]) -> None:
        import uuid
        from datetime import datetime, UTC

        from urban_hs.core import get_event_bus
        from urban_hs.core.event_bus import Event, EventPriority

        category = attack.split("_", 1)[0] if "_" in attack else "attack"
        bus = get_event_bus()
        event = Event(
            type=f"{category}.attack_request",
            payload={"attack": attack, "params": params},
            source="tui",
            priority=EventPriority.NORMAL,
            correlation_id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC),
            metadata={},
        )
        asyncio.create_task(bus.publish(event))

    async def _wifi_scan(self) -> None:
        try:
            from urban_hs.modules.wifi import ScanStrategy, WiFiScanner

            iface = self._get_selected_wifi_interface()
            logs = self.query_one("#app-log", RichLog)
            logs.write(f"[yellow]Scanning on interface: {iface}…[/yellow]")

            scanner = WiFiScanner(interface=iface, strategy=ScanStrategy.PASSIVE_ONLY)
            nets = await scanner.scan(duration=30)
            self._wifi_networks = [n.to_dict() for n in nets]
            self._refresh_wifi_table()
            self.post_message(EventMessage(
                "wifi.scan.completed",
                {
                    "count": len(self._wifi_networks),
                    "networks": self._wifi_networks,
                    "simulated": False,
                },
            ))
        except Exception as exc:
            self.post_message(EventMessage("wifi.scan.error", {"error": str(exc)}))

    async def _wifi_interfaces(self) -> None:
        try:
            from urban_hs.ui.api.routers.wifi import list_wifi_interfaces

            result = await list_wifi_interfaces()
            ifaces = result.get("interfaces", [])
            self.post_message(EventMessage(
                "wifi.interfaces.listed",
                {"interfaces": ifaces},
            ))
        except Exception as exc:
            self.post_message(EventMessage("wifi.interfaces.error", {"error": str(exc)}))

    async def _ble_scan(self) -> None:
        try:
            from urban_hs.modules.ble import FastPairScanner

            scanner = FastPairScanner()
            await scanner.start()
            await asyncio.sleep(10)
            await scanner.stop()
            devices = scanner.get_devices()
            self._ble_devices = [
                d.to_dict() if hasattr(d, "to_dict") else vars(d) for d in devices
            ]
            self._refresh_ble_table()
            self.post_message(EventMessage(
                "ble.scan.completed",
                {
                    "count": len(self._ble_devices),
                    "devices": self._ble_devices,
                    "simulated": False,
                },
            ))
        except Exception as exc:
            self.post_message(EventMessage("ble.scan.error", {"error": str(exc)}))

    async def _network_scan(self) -> None:
        try:
            from urban_hs.modules.network import NetworkModule, ScanType

            module = NetworkModule()
            hosts = await module.nmap.scan(
                ["192.168.1.0/24"],
                scan_type=ScanType.HOST_DISCOVERY,
                timeout=60,
            )
            result = [vars(h) for h in hosts]
            self.post_message(EventMessage(
                "network.scan.completed",
                {"count": len(result), "hosts": result, "simulated": False},
            ))
        except Exception as exc:
            self.post_message(EventMessage("network.scan.error", {"error": str(exc)}))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "cmd-input":
            cmd = event.value.strip()
            event.input.value = ""
            if cmd:
                asyncio.create_task(self._execute_terminal_cmd(cmd))

    async def _execute_terminal_cmd(self, cmd: str) -> None:
        log = self.query_one("#terminal-log", RichLog)
        log.write(f"[bold green]$ {cmd}[/bold green]")
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if stdout:
                log.write(stdout.decode(errors="replace").strip())
            if stderr:
                log.write(f"[red]{stderr.decode(errors='replace').strip()}[/red]")
        except Exception as exc:
            log.write(f"[bold red]Execution error:[/bold red] {exc}")

    def action_toggle_dark(self) -> None:
        pass


def run() -> None:
    """Console script entry point."""
    TUIApp().run()


if __name__ == "__main__":
    run()
