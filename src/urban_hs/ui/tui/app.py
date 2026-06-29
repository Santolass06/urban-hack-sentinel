"""
Urban Hack Sentinel v3 — Textual TUI dashboard.

Entry point::

    python -m urban_hs.ui.tui.app

Registered as ``urban-hs-tui`` in ``pyproject.toml``.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Label,
    Log,
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


class SystemStatus(Static):
    """Header widget showing architecture + version."""

    def render(self) -> str:
        import platform

        return (
            f"[bold cyan]Urban Hack Sentinel[/bold cyan] [green]v{__version__}[/green]\n"
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
    Log { height: 1fr; border: solid $primary; }
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
        self._wifi_networks: List[Dict[str, Any]] = []
        self._ble_devices: List[Dict[str, Any]] = []
        self._attack_log: List[str] = []

    def compose(self) -> ComposeResult:
        yield Header()
        yield SystemStatus(id="status")
        with Container(id="main"):
            with TabbedContent():
                with TabPane("WiFi", id="tab-wifi"):
                    yield Vertical(
                        Horizontal(
                            Button("Scan", id="btn-wifi-scan"),
                            Button("Interfaces", id="btn-wifi-interfaces"),
                            Button("Deauth", id="btn-wifi-deauth"),
                            Button("WPS Pixie", id="btn-wifi-wps-pixie"),
                            Button("WPS PIN", id="btn-wifi-wps-pin"),
                            Button("Handshake", id="btn-wifi-handshake"),
                            Button("PMKID", id="btn-wifi-pmkid"),
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
                        ),
                        Label("BLE Devices:"),
                        DataTable(id="ble-table"),
                        classes="panel",
                    )
                with TabPane("Network", id="tab-network"):
                    yield Vertical(
                        Button("Host Discovery", id="btn-net-nmap"),
                        Label("Results:"),
                        Static("(none yet)", id="net-results"),
                        classes="panel",
                    )
                with TabPane("Terminal", id="tab-terminal"):
                    yield Log(id="terminal-log", auto_scroll=True, markup=True)
                with TabPane("Logs", id="tab-logs"):
                    yield Log(id="app-log", auto_scroll=True, markup=True)
        yield Footer()

    def on_mount(self) -> None:
        self.theme = "monokai"
        asyncio.create_task(self._listen_event_bus())
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
        terminal = self.query_one("#terminal-log", Log)
        logs = self.query_one("#app-log", Log)
        formatted = f"[cyan]{message.event_type}[/cyan] {message.payload}"
        terminal.write_line(formatted)
        logs.write_line(formatted)

        if message.event_type == "attack.started":
            self._attack_log.append(f"[yellow]START[/yellow] {message.payload}")
        elif message.event_type == "attack.progress":
            self._attack_log.append(f"[blue]PROGRESS[/blue] {message.payload}")
        elif message.event_type == "attack.completed":
            self._attack_log.append(f"[green]DONE[/green] {message.payload}")
        elif message.event_type == "attack.error":
            self._attack_log.append(f"[red]ERROR[/red] {message.payload}")
        elif message.event_type == "wifi.scan_complete":
            self._wifi_networks = message.payload.get("networks", [])
            self._refresh_wifi_table()
        elif message.event_type == "ble.scan_complete":
            self._ble_devices = message.payload.get("devices", [])
            self._refresh_ble_table()

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
        logs = self.query_one("#app-log", Log)
        bid = event.button.id or ""

        if bid == "btn-wifi-scan":
            logs.write_line("[yellow]Triggering WiFi scan…[/yellow]")
            asyncio.create_task(self._wifi_scan())
        elif bid == "btn-wifi-interfaces":
            logs.write_line("[yellow]Listing WiFi interfaces…[/yellow]")
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
        elif bid == "btn-ble-scan":
            logs.write_line("[yellow]Triggering BLE scan…[/yellow]")
            asyncio.create_task(self._ble_scan())
        elif bid == "btn-ble-whisperpair":
            self._confirm("Run WhisperPair pairing attack?", self._ble_whisperpair)
        elif bid == "btn-net-nmap":
            logs.write_line("[yellow]Nmap scan not yet implemented.[/yellow]")
        else:
            logs.write_line(f"[yellow]Button:[/yellow] {bid}")

    def _confirm(self, message: str, callback: Any) -> None:
        container = self.query_one("#main", Container)
        modal = ConfirmModal(message=message, on_confirm=callback)
        container.mount(modal)

    # ------------------------------------------------------------------
    # Stub attacks for TUI wiring
    # ------------------------------------------------------------------
    async def _wifi_deauth(self) -> None:
        self._publish_attack("wifi_deauth", {"count": 10})

    async def _wifi_wps_pixie(self) -> None:
        self._publish_attack("wifi_wps_pixie", {})

    async def _wifi_wps_pin(self) -> None:
        self._publish_attack("wifi_wps_pin", {})

    async def _wifi_handshake(self) -> None:
        self._publish_attack("wifi_handshake", {})

    async def _wifi_pmkid(self) -> None:
        self._publish_attack("wifi_pmkid", {})

    async def _ble_whisperpair(self) -> None:
        self._publish_attack("ble_whisperpair", {})

    def _publish_attack(self, attack: str, params: Dict[str, Any]) -> None:
        import uuid
        from datetime import datetime

        from urban_hs.core import get_event_bus
        from urban_hs.core.event_bus import Event, EventPriority

        bus = get_event_bus()
        event = Event(
            type="wifi.attack_request",
            payload={"type": attack, **params},
            source="tui",
            priority=EventPriority.NORMAL,
            correlation_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            metadata={},
        )
        asyncio.create_task(bus.publish(event))

    async def _wifi_scan(self) -> None:
        try:
            from urban_hs.modules.wifi import WiFiScanner, ScanStrategy

            scanner = WiFiScanner(interface="wlan1", strategy=ScanStrategy.PASSIVE_ONLY)
            nets = await scanner.scan(duration=30)
            self._wifi_networks = [n.to_dict() for n in nets]
            self._refresh_wifi_table()
            self.post_message(EventMessage(
                "wifi.scan.completed",
                {"count": len(self._wifi_networks), "networks": self._wifi_networks},
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
                {"count": len(self._ble_devices), "devices": self._ble_devices},
            ))
        except Exception as exc:
            self.post_message(EventMessage("ble.scan.error", {"error": str(exc)}))

    def action_toggle_dark(self) -> None:
        self.theme = "monokai" if self.theme == "default" else "default"


def run() -> None:
    """Console script entry point."""
    TUIApp().run()


if __name__ == "__main__":
    run()
