"""
Urban Hack Sentinel v3 — Textual TUI dashboard.

Entry point::

    python -m urban_hs.ui.tui.app

Registered as ``urban-hs-tui`` in ``pyproject.toml``.
"""

from __future__ import annotations

import asyncio
from typing import Any

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.message import Message
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
from urban_hs.core.event_bus import Event, EventHandler


# ---------------------------------------------------------------------------
# Custom Textual message for event bus events
# ---------------------------------------------------------------------------
class EventMessage(Message):
    """Event bus event forwarded to the Textual UI.

    Must subclass :class:`textual.message.Message` (and call
    ``super().__init__()``) so ``App.post_message`` accepts it; a plain
    object raises ``RuntimeError: Message is missing attributes``.
    """

    def __init__(self, event_type: str, payload: dict[str, Any]) -> None:
        super().__init__()
        self.event_type = event_type
        self.payload = payload


class _UIForwarder(EventHandler):
    """Relays event-bus events onto the Textual message pump.

    Subscribed with the ``*`` wildcard so every bus event (scan/attack
    results published by the plugins) reaches :meth:`TUIApp.on_event_message`.
    Replaces the old approach of draining ``bus._queue`` directly, which
    competed with the bus's own worker tasks.
    """

    def __init__(self, app: TUIApp) -> None:
        self._app = app

    @property
    def event_types(self) -> set[str]:
        return {"*"}

    async def handle(self, event: Event) -> None:
        payload = event.payload if isinstance(event.payload, dict) else {"data": event.payload}
        self._app.post_message(EventMessage(event.type, payload))


class SystemStatus(Static):
    """Header widget showing architecture + version + connected WiFi."""

    def render(self) -> str:
        import platform
        import shutil
        import subprocess

        connected_info = "Not connected"
        try:
            if shutil.which("iwgetid"):
                res = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True, timeout=2)
                ssid = res.stdout.strip()
                if ssid:
                    res_iface = subprocess.run(
                        ["iwgetid"], capture_output=True, text=True, timeout=2
                    )
                    iface = res_iface.stdout.split()[0] if res_iface.stdout else "wifi"
                    connected_info = f"Connected to [bold yellow]{ssid}[/bold yellow] ({iface})"
            elif shutil.which("iw"):
                # Fallback when iwgetid is absent: parse `iw dev` for the
                # connected interface's SSID.
                out = subprocess.run(
                    ["iw", "dev"], capture_output=True, text=True, timeout=2
                ).stdout
                iface = None
                for raw in out.splitlines():
                    line = raw.strip()
                    if line.startswith("Interface "):
                        iface = line.split()[1]
                    elif line.startswith("ssid ") and iface:
                        connected_info = (
                            f"Connected to [bold yellow]{line[5:]}[/bold yellow] ({iface})"
                        )
                        break
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
            # Callbacks are async methods (e.g. TUIApp._wifi_deauth); calling
            # one returns a coroutine that must be scheduled, otherwise the
            # attack is never dispatched.
            result = self._on_confirm()
            if asyncio.iscoroutine(result):
                asyncio.create_task(result)
        self.remove()


class TUIApp(App):
    """Main Textual dashboard."""

    CSS = """
    Screen { layout: vertical; }
    #main { height: 1fr; }
    RichLog { height: 1fr; border: solid $primary; }
    .panel { padding: 1 2; }
    DataTable { height: 1fr; }
    .btn-row { height: auto; align-vertical: middle; }
    .btn-row Button { margin: 0 1 0 0; }
    .row-label { width: 12; content-align: left middle; color: $text-muted; }
    .btn-row Input { width: 1fr; }
    .btn-row Select { width: 28; }
    .results {
        height: auto;
        max-height: 12;
        border: solid $accent;
        padding: 0 1;
        overflow-y: auto;
    }
    Static.confirm-modal {
        dock: top;
        padding: 1 2;
        background: $panel;
        border: solid $warning;
        width: 60;
    }
    """

    BINDINGS = [("q", "app.quit", "Quit"), ("d", "toggle_dark", "Toggle dark mode")]

    def __init__(self) -> None:
        super().__init__()
        self._wifi_networks: list[dict[str, Any]] = []
        self._ble_devices: list[dict[str, Any]] = []
        self._attack_log: list[str] = []
        self._wifi_plugin: Any = None
        self._ble_plugin: Any = None
        self._urban_plugin: Any = None
        # Strong refs: bus.subscribe() stores handlers in a WeakSet, so
        # anything not held here would be garbage-collected and silently
        # stop receiving events.
        self._bus_handlers: list[Any] = []

    def compose(self) -> ComposeResult:
        yield Header()
        yield SystemStatus(id="status")
        with Container(id="main"):
            with TabbedContent():
                with TabPane("WiFi", id="tab-wifi"):
                    yield Vertical(
                        Horizontal(
                            Label("Interface:", classes="row-label"),
                            Select([], id="select-wifi-iface", prompt="Scanning interfaces..."),
                            Button("Scan", id="btn-wifi-scan", variant="primary"),
                            Button("Interfaces", id="btn-wifi-interfaces"),
                            Button("GPS Wardrive", id="btn-wifi-gps"),
                            Button("⚡ Attack All", id="btn-attack-all", variant="error"),
                            classes="btn-row",
                        ),
                        Horizontal(
                            Label("Attacks:", classes="row-label"),
                            Button("Deauth", id="btn-wifi-deauth"),
                            Button("Handshake", id="btn-wifi-handshake"),
                            Button("PMKID", id="btn-wifi-pmkid"),
                            Button("WPS Pixie", id="btn-wifi-wps-pixie"),
                            Button("WPS PIN", id="btn-wifi-wps-pin"),
                            classes="btn-row",
                        ),
                        Horizontal(
                            Label("802.11:", classes="row-label"),
                            Button("Kr00k", id="btn-wifi-krook"),
                            Button("WPA3 Downgrade", id="btn-wifi-wpa3-downgrade"),
                            Button("802.11r FT", id="btn-wifi-ft"),
                            Button("SSID Confusion", id="btn-wifi-ssid-confusion"),
                            Button("FragAttacks", id="btn-wifi-fragattacks"),
                            classes="btn-row",
                        ),
                        Label("Discovered Networks:"),
                        DataTable(id="wifi-table"),
                        Static("", id="wifi-results", classes="results"),
                        classes="panel",
                    )
                with TabPane("BLE", id="tab-ble"):
                    yield Vertical(
                        Horizontal(
                            Button("Scan Fast Pair", id="btn-ble-scan", variant="primary"),
                            Button("WhisperPair Test", id="btn-ble-whisperpair"),
                            Button("WhisperPair Exploit", id="btn-ble-exploit"),
                            Button("Bluetooth HID", id="btn-ble-hid"),
                            classes="btn-row",
                        ),
                        Label("BLE Devices:"),
                        DataTable(id="ble-table"),
                        Static("", id="ble-results", classes="results"),
                        classes="panel",
                    )
                with TabPane("Network", id="tab-network"):
                    yield Vertical(
                        Horizontal(
                            Label("Subnet:", classes="row-label"),
                            Input(value="192.168.1.0/24", id="net-subnet"),
                            classes="btn-row",
                        ),
                        Horizontal(
                            Button("Host Discovery (Nmap)", id="btn-net-nmap", variant="primary"),
                            Button("Nuclei Vuln Scan", id="btn-net-nuclei"),
                            Button("Camera Discovery", id="btn-net-camera"),
                            Button("ESP32 Probe", id="btn-net-esp32"),
                            Button("MQTT Brute", id="btn-net-mqtt"),
                            Button("Router Brute", id="btn-net-router"),
                            classes="btn-row",
                        ),
                        Label("Results:"),
                        Static("(none yet)", id="net-results"),
                        classes="panel",
                    )
                with TabPane("Exploit", id="tab-exploit"):
                    yield Vertical(
                        Horizontal(
                            Label("SearchSploit:", classes="row-label"),
                            Input(placeholder="e.g. apache 2.4", id="exploit-query"),
                            Button("Search", id="btn-exploit-search", variant="primary"),
                            Button("Metasploit RPC", id="btn-exploit-msf"),
                            classes="btn-row",
                        ),
                        Horizontal(
                            Label("Local HID:", classes="row-label"),
                            Input(placeholder="text to inject via uinput", id="hid-text"),
                            Button("Inject", id="btn-hid-local"),
                            classes="btn-row",
                        ),
                        Label("Results:"),
                        Static("(none yet)", id="exploit-results", classes="results"),
                        classes="panel",
                    )
                with TabPane("Terminal", id="tab-terminal"):
                    yield Vertical(
                        RichLog(id="terminal-log", auto_scroll=True, markup=True),
                        Input(
                            placeholder="Digita um comando bash/CLI (ex: urban-hs info, iw dev, ping 1.1.1.1)...",
                            id="cmd-input",
                        ),
                    )
                with TabPane("Logs", id="tab-logs"):
                    yield RichLog(id="app-log", auto_scroll=True, markup=True)
        yield Footer()

    async def on_mount(self) -> None:
        wifi_table = self.query_one("#wifi-table", DataTable)
        wifi_table.add_columns("BSSID", "SSID", "Encryption", "Signal", "Channel")
        wifi_table.cursor_type = "row"
        ble_table = self.query_one("#ble-table", DataTable)
        ble_table.add_columns("Address", "Name", "Type", "RSSI")
        ble_table.cursor_type = "row"
        # Pre-fill the Subnet box with the machine's actual network so the
        # network scans target the connected LAN instead of a hardcoded guess.
        detected = self._detect_local_subnet()
        if detected:
            try:
                self.query_one("#net-subnet", Input).value = detected
            except Exception:
                pass
        await self._bootstrap_event_bus()
        # Only enumerate interfaces on startup (read-only). Do NOT auto-scan:
        # a Wi-Fi scan can switch the interface into monitor mode and, before
        # the user picks an adapter, it would hit the default (connected)
        # interface and drop the machine's internet. The user clicks Scan.
        asyncio.create_task(self._wifi_interfaces())
        self.query_one("#app-log", RichLog).write(
            "[dim]Ready. Pick an interface and click Scan "
            "(avoid your connected interface — scanning can enter monitor mode).[/dim]"
        )

    async def _bootstrap_event_bus(self) -> None:
        """Start the event bus and wire the UI + attack plugins to it.

        Attack buttons publish ``*.attack_request`` events; the plugin
        handlers subscribed here consume them (validating the session
        scope) and publish result events, which ``_UIForwarder`` relays
        back to the Textual message pump. Without this, ``bus.publish``
        drops every event because the bus is never started.
        """
        from urban_hs.core.event_bus import get_event_bus

        logs = self.query_one("#app-log", RichLog)
        bus = get_event_bus()
        await bus.start()  # idempotent: returns early if already running

        forwarder = _UIForwarder(self)
        self._bus_handlers.append(forwarder)
        bus.subscribe(forwarder)

        try:
            from urban_hs.modules.wifi.plugin import (
                WiFiEventHandler,
                WiFiModuleConfig,
                create_wifi_plugin,
            )

            iface = self._get_selected_wifi_interface()
            self._wifi_plugin = await create_wifi_plugin(WiFiModuleConfig(interface=iface))
            handler = WiFiEventHandler(self._wifi_plugin)
            self._bus_handlers.append(handler)
            bus.subscribe(handler)
        except Exception as exc:
            logs.write(f"[red]WiFi attack plugin unavailable: {exc}[/red]")

        try:
            from urban_hs.modules.ble.plugin import BLEEventHandler, create_ble_plugin

            self._ble_plugin = await create_ble_plugin()
            handler = BLEEventHandler(self._ble_plugin)
            self._bus_handlers.append(handler)
            bus.subscribe(handler)
        except Exception as exc:
            logs.write(f"[red]BLE attack plugin unavailable: {exc}[/red]")

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
                    selected = ifaces[0]
                    for iface in ifaces:
                        if iface.startswith("wlx") or "alfa" in iface.lower():
                            selected = iface
                            break
                    select.value = selected
                except Exception:
                    pass
        elif message.event_type in ("ble.scan.completed", "ble.scan_complete"):
            self._ble_devices = message.payload.get("devices", [])
            self._refresh_ble_table()
        elif message.event_type in ("network.scan.completed",):
            hosts = message.payload.get("hosts", [])
            results = self.query_one("#net-results", Static)
            if hosts:
                lines = [
                    f"{h.get('ip', '?')} — {h.get('hostname', '')} ({h.get('os_guess', '')})"
                    for h in hosts
                ]
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
            logs.write("[yellow]Detecting 802.11r Fast Transition networks…[/yellow]")
            asyncio.create_task(self._wifi_ft())
        elif bid == "btn-wifi-ssid-confusion":
            logs.write("[yellow]Running SSID Confusion assessment…[/yellow]")
            asyncio.create_task(self._ssid_confusion())
        elif bid == "btn-wifi-fragattacks":
            self._confirm(
                "Run FragAttacks (CVE-2020-2458x) on selected network?", self._wifi_fragattacks
            )
        elif bid == "btn-wifi-krook":
            self._confirm("Run Kr00k (CVE-2019-15126) attack?", self._wifi_krook)
        elif bid == "btn-wifi-gps":
            logs.write("[yellow]Starting GPS Wardriving tick…[/yellow]")
            asyncio.create_task(self._wifi_gps_wardrive())
        elif bid == "btn-attack-all":
            self._confirm(
                "⚡ ATTACK ALL discovered WiFi + BLE targets in parallel?", self._attack_all
            )
        elif bid == "btn-ble-scan":
            logs.write("[yellow]Triggering BLE scan…[/yellow]")
            asyncio.create_task(self._ble_scan())
        elif bid == "btn-ble-whisperpair":
            self._confirm("Run WhisperPair pairing test?", self._ble_whisperpair)
        elif bid == "btn-ble-exploit":
            self._confirm("Run WhisperPair FULL exploit chain?", self._ble_exploit)
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
            logs.write("[yellow]Starting MQTT broker enumeration…[/yellow]")
            asyncio.create_task(self._net_mqtt())
        elif bid == "btn-net-router":
            self._confirm("Run router credential brute-force (Hydra)?", self._net_router)
        elif bid == "btn-exploit-search":
            logs.write("[yellow]Searching Exploit-DB…[/yellow]")
            asyncio.create_task(self._exploit_search())
        elif bid == "btn-exploit-msf":
            logs.write("[yellow]Connecting to Metasploit RPC…[/yellow]")
            asyncio.create_task(self._exploit_msf())
        elif bid == "btn-hid-local":
            self._confirm("Inject keystrokes via local HID (uinput)?", self._hid_local)
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

    def on_select_changed(self, event: Select.Changed) -> None:
        """Re-target the attack plugin when the Wi-Fi interface is changed.

        The attack objects bind their interface at plugin-init time, so a
        later change in the dropdown would otherwise keep hitting the old
        interface. (The scan path already reads the Select on each scan.)
        """
        if event.select.id != "select-wifi-iface":
            return
        iface = event.value
        plugin = self._wifi_plugin
        if plugin is None or not isinstance(iface, str) or not iface or iface == Select.BLANK:
            return
        try:
            plugin.config.interface = iface
            for attr in (
                "_handshake_attack",
                "_pmkid_attack",
                "_wps_pixie_attack",
                "_wps_pin_attack",
                "_deauth_attack",
            ):
                attack = getattr(plugin, attr, None)
                if attack is not None:
                    attack.interface = iface
        except Exception:
            pass

    def _get_selected_wifi_interface(self) -> str:
        try:
            select = self.query_one("#select-wifi-iface", Select)
            if select.value and isinstance(select.value, str) and select.value != Select.BLANK:
                return select.value
        except Exception:
            pass
        return "wlo1"

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
        results = self.query_one("#wifi-results", Static)
        results.update("[yellow]Detecting 802.11r Fast Transition networks...[/yellow]")
        try:
            from urban_hs.modules.ssid_confusion import SSIDConfusionDetector

            iface = self._get_selected_wifi_interface()
            detector = SSIDConfusionDetector(interface=iface, scan_timeout=20)
            targets = await detector.scan_networks()
            ft = [t for t in targets if t.ft_enabled]
            if ft:
                lines = [
                    f"{t.bssid} {t.ssid} ({t.security_type}) MD={t.mobility_domain}" for t in ft
                ]
                results.update(
                    f"802.11r FT-capable ({len(ft)}/{len(targets)}):\n" + "\n".join(lines)
                )
            else:
                results.update(f"802.11r FT scan: {len(targets)} networks, none FT-capable.")
        except Exception as exc:
            results.update(f"802.11r FT scan failed: {exc}")

    async def _wifi_krook(self) -> None:
        self._publish_wifi_attack("krook")

    async def _wifi_gps_wardrive(self) -> None:
        logs = self.query_one("#app-log", RichLog)
        try:
            from urban_hs.modules.wifi.managers import GeoMapper

            geo = GeoMapper()
            await geo.start()
            fixed = geo.is_fixed()
            pos = geo.get_position() if fixed else None
            logs.write(f"[cyan]GPS fix={fixed} {pos or ''}[/cyan]")
            await self._wifi_scan()
            logs.write(
                f"[green]Wardrive tick: {len(self._wifi_networks)} networks "
                f"(GPS {'fixed' if fixed else 'no fix'})[/green]"
            )
            await geo.stop()
        except Exception as exc:
            logs.write(f"[red]GPS wardrive failed: {exc}[/red]")

    async def _attack_all(self) -> None:
        results = self.query_one("#wifi-results", Static)
        results.update(
            "[yellow]⚡ Attack All: fanning out every discovered target (WiFi + BLE)...[/yellow]"
        )
        try:
            from urban_hs.modules.urban_hack import UrbanHackConfig, create_urban_hack_plugin

            if self._urban_plugin is None:
                self._urban_plugin = await create_urban_hack_plugin(UrbanHackConfig())
            summary = await self._urban_plugin.attack_all(
                progress_callback=lambda m: self.query_one("#app-log", RichLog).write(
                    f"[dim]{m}[/dim]"
                )
            )
            results.update(
                f"Attack All: dispatched {summary['dispatched']}, ok={summary['ok']}, "
                f"errors={len(summary['errors'])}"
            )
        except Exception as exc:
            results.update(f"Attack All failed: {exc}")

    async def _ssid_confusion(self) -> None:
        results = self.query_one("#wifi-results", Static)
        results.update("[yellow]Running SSID Confusion assessment (CVE-2023-52425)...[/yellow]")
        try:
            from urban_hs.modules.ssid_confusion import scan_ssid_confusion

            iface = self._get_selected_wifi_interface()
            report = await scan_ssid_confusion(interface=iface)
            vulnerable = report.get("vulnerable", report.get("results", []))
            results.update(
                f"SSID Confusion: {len(vulnerable)} candidate(s). {report.get('summary', '')}"
            )
        except Exception as exc:
            results.update(f"SSID Confusion scan failed: {exc}")

    async def _wifi_fragattacks(self) -> None:
        results = self.query_one("#wifi-results", Static)
        bssid = self._get_selected_wifi_bssid()
        results.update(f"[yellow]Running FragAttacks (CVE-2020-2458x) on {bssid}...[/yellow]")
        try:
            from urban_hs.modules.wifi.fragattacks import FragAttackConfig, FragAttacksWrapper

            iface = self._get_selected_wifi_interface()
            wrapper = FragAttacksWrapper(FragAttackConfig(interface=iface, target_bssid=bssid))
            outcomes = await wrapper.run_tests(target_bssid=bssid)
            lines = [
                f"{r.attack_type.value}: vulnerable={r.vulnerable} frames={r.affected_frames}"
                for r in outcomes
            ]
            results.update(f"FragAttacks on {bssid}:\n" + ("\n".join(lines) or "no results"))
        except Exception as exc:
            results.update(f"FragAttacks failed: {exc}")

    def _get_selected_ble_address(self) -> str | None:
        try:
            table = self.query_one("#ble-table", DataTable)
            if table.cursor_row is not None and table.cursor_row < len(self._ble_devices):
                return self._ble_devices[table.cursor_row].get("address")
        except Exception:
            pass
        if self._ble_devices:
            return self._ble_devices[0].get("address")
        return None

    async def _ble_whisperpair(self) -> None:
        results = self.query_one("#ble-results", Static)
        address = self._get_selected_ble_address()
        if not address:
            results.update("WhisperPair: scan for BLE devices and select a target first.")
            return
        try:
            from urban_hs.modules.ble.fastpair import WhisperPairTester

            tester = WhisperPairTester()
            report = await tester.test_device(address)
            results.update(f"WhisperPair test on {address}: {report}")
        except Exception as exc:
            results.update(f"WhisperPair test failed: {exc}")

    async def _ble_hid(self) -> None:
        results = self.query_one("#ble-results", Static)
        try:
            from urban_hs.modules.bt_hid import BTHIDScanner

            scanner = BTHIDScanner()
            targets = await scanner.scan(duration=10)
            hid_capable = [t for t in targets if t.hid_supported]
            results.update(f"BT HID scan: {len(targets)} devices, {len(hid_capable)} HID-capable")
        except Exception as exc:
            results.update(f"BT HID scan failed: {exc}")

    async def _ble_exploit(self) -> None:
        results = self.query_one("#ble-results", Static)
        address = self._get_selected_ble_address()
        if not address:
            results.update("WhisperPair Exploit: scan + select a BLE target first.")
            return
        results.update(f"[yellow]Running WhisperPair full exploit chain on {address}...[/yellow]")
        try:
            from urban_hs.modules.ble.fastpair import WhisperPairExploit

            report = await WhisperPairExploit().execute_all_strategies(address)
            results.update(
                f"WhisperPair exploit on {address}: success={report.get('success')} "
                f"winning={report.get('winning_strategy', '-')}"
            )
        except Exception as exc:
            results.update(f"WhisperPair exploit failed: {exc}")

    async def _net_nuclei(self) -> None:
        results = self.query_one("#net-results", Static)
        results.update("[yellow]Running Nuclei vulnerability scan on LAN...[/yellow]")
        try:
            from urban_hs.modules.network import NucleiRunner

            runner = NucleiRunner()
            gateway = self._get_subnet_target().split("/")[0].rsplit(".", 1)[0] + ".1"
            vulns = await runner.scan(gateway)
            if vulns:
                lines = [
                    f"[{getattr(v.severity, 'value', v.severity)}] {v.name} @ {v.target_ip}:{v.target_port}"
                    for v in vulns
                ]
                results.update("\n".join(lines))
            else:
                results.update(
                    "Nuclei scan completed: No critical vulnerabilities found on target."
                )
        except Exception as exc:
            results.update(f"Nuclei scan error: {exc}")

    async def _net_camera(self) -> None:
        results = self.query_one("#net-results", Static)
        results.update("[yellow]Discovering IP Cameras (ONVIF/RTSP/mDNS)...[/yellow]")
        try:
            from urban_hs.modules.network import CameraDiscovery

            disc = CameraDiscovery()
            cams = await disc.discover_cameras(network=self._get_subnet_target())
            if cams:
                lines = [
                    f"Camera: {c.get('ip')}:{c.get('port')} ({c.get('service', '')}) {c.get('hostname', '')}"
                    for c in cams
                ]
                results.update("\n".join(lines))
            else:
                results.update("Camera Discovery completed: No unauthenticated IP cameras found.")
        except Exception as exc:
            results.update(f"Camera Discovery error: {exc}")

    async def _net_esp32(self) -> None:
        results = self.query_one("#net-results", Static)
        results.update("[yellow]Probing ESP32 vulnerabilities (CVE-2025-27840)...[/yellow]")
        try:
            from urban_hs.modules.esp32 import detect_esp32_devices

            found = await detect_esp32_devices(target_network=self._get_subnet_target())
            if found:
                lines = [
                    f"ESP32: {d.ip_address or '?'} - MAC: {d.mac_address} ({d.chip_model or 'unknown'})"
                    for d in found
                ]
                results.update("\n".join(lines))
            else:
                results.update(
                    "ESP32 Probe completed: No vulnerable ESP32 microcontrollers detected."
                )
        except Exception as exc:
            results.update(f"ESP32 Probe error: {exc}")

    async def _net_mqtt(self) -> None:
        results = self.query_one("#net-results", Static)
        results.update("[yellow]Searching MQTT Brokers & Enumerating Topics...[/yellow]")
        try:
            from urban_hs.modules.mqtt import scan_mqtt_brokers

            brokers = await scan_mqtt_brokers(self._get_subnet_target())
            if brokers:
                lines = [
                    f"MQTT Broker: {b.host}:{b.port} - Auth Required: {b.auth_required}"
                    for b in brokers
                ]
                results.update("\n".join(lines))
            else:
                results.update("MQTT Scan completed: No open MQTT brokers found.")
        except Exception as exc:
            results.update(f"MQTT Scan error: {exc}")

    async def _net_router(self) -> None:
        results = self.query_one("#net-results", Static)
        # Router IP: the subnet input with the host octet forced to .1 (gateway).
        target = self._get_subnet_target().split("/")[0].rsplit(".", 1)[0] + ".1"
        results.update(
            f"[yellow]Router vulnerability scan (RouterSploit autopwn) on {target}...[/yellow]"
        )
        try:
            from urban_hs.modules.network.router import RouterScanner

            findings = await RouterScanner().scan_router(target_ip=target)
            if findings:
                lines = [f"[VULN] {f.get('module')}" for f in findings]
                results.update(
                    f"Router scan on {target}: {len(findings)} vulnerable\n" + "\n".join(lines)
                )
            else:
                results.update(f"Router scan on {target}: no known vulnerabilities found.")
        except Exception as exc:
            results.update(f"Router scan failed: {exc}")

    async def _exploit_search(self) -> None:
        results = self.query_one("#exploit-results", Static)
        query = self.query_one("#exploit-query", Input).value.strip()
        if not query:
            results.update("Enter a search term (e.g. 'apache 2.4').")
            return
        results.update(f"[yellow]SearchSploit: '{query}'...[/yellow]")
        try:
            from urban_hs.modules.network.searchsploit import SearchSploitIntegration

            hits = await SearchSploitIntegration().search(query)
            if hits:
                lines = [
                    f"{h.get('Title') or h.get('title', '?')}  —  {h.get('Path') or h.get('path', '')}"
                    for h in hits[:15]
                ]
                results.update(f"{len(hits)} result(s):\n" + "\n".join(lines))
            else:
                results.update("No exploits found.")
        except Exception as exc:
            results.update(f"SearchSploit failed: {exc}")

    async def _exploit_msf(self) -> None:
        import os

        results = self.query_one("#exploit-results", Static)
        password = os.environ.get("URBAN_HS_MSF_PASSWORD", "")
        if not password:
            results.update(
                "Metasploit needs a password. Start msfrpcd and export it, e.g.:\n"
                "  msfrpcd -P yourpass -S -a 127.0.0.1\n"
                "  export URBAN_HS_MSF_PASSWORD=yourpass"
            )
            return
        results.update("[yellow]Connecting to Metasploit RPC...[/yellow]")
        try:
            from urban_hs.modules.metasploit import MetasploitRPC, MsfConfig

            config = MsfConfig(
                host=os.environ.get("URBAN_HS_MSF_HOST", "127.0.0.1"),
                port=int(os.environ.get("URBAN_HS_MSF_PORT", "55553")),
                username=os.environ.get("URBAN_HS_MSF_USER", "msf"),
                password=password,
                ssl_verify=False,
            )
            connected = await MetasploitRPC(config).connect()
            results.update(
                "Metasploit RPC connected."
                if connected
                else "Metasploit RPC connection failed (is msfrpcd running?)."
            )
        except Exception as exc:
            results.update(f"Metasploit RPC error: {exc}")

    async def _hid_local(self) -> None:
        results = self.query_one("#exploit-results", Static)
        text = self.query_one("#hid-text", Input).value
        if not text:
            results.update("Enter text to inject via local HID.")
            return
        results.update(f"[yellow]Injecting {len(text)} chars via local HID (uinput)...[/yellow]")
        try:
            from urban_hs.modules.hid.injector import quick_type

            ok = await quick_type(text)
            results.update(
                "HID injection sent."
                if ok
                else "HID injection failed (needs /dev/uinput + privileges)."
            )
        except Exception as exc:
            results.update(f"HID injection error: {exc}")

    def _get_subnet_target(self) -> str:
        try:
            value = self.query_one("#net-subnet", Input).value.strip()
            if value:
                return value
        except Exception:
            pass
        return self._detect_local_subnet() or "192.168.1.0/24"

    def _detect_local_subnet(self) -> str | None:
        """Return the CIDR network of the machine's primary LAN interface.

        Derives e.g. ``192.168.0.4/24`` -> ``192.168.0.0/24`` from ``ip addr``,
        preferring wireless interfaces and skipping loopback/virtual/VPN ones.
        """
        import ipaddress
        import subprocess

        try:
            out = subprocess.run(
                ["ip", "-o", "-f", "inet", "addr", "show"],
                capture_output=True,
                text=True,
                timeout=3,
            ).stdout
        except Exception:
            return None

        candidates: list[tuple[int, str]] = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            iface, cidr = parts[1], parts[3]
            if iface == "lo" or iface.startswith(("docker", "veth", "br-", "tailscale", "tun")):
                continue
            try:
                network = ipaddress.ip_interface(cidr).network
            except ValueError:
                continue
            # Prefer wireless interfaces (wl*), then everything else.
            preference = 0 if iface.startswith("wl") else 1
            candidates.append((preference, str(network)))

        candidates.sort()
        return candidates[0][1] if candidates else None

    def _publish_wifi_attack(
        self, attack_type: str, extra_params: dict[str, Any] | None = None
    ) -> None:
        import uuid
        from datetime import UTC, datetime

        from urban_hs.core import get_event_bus
        from urban_hs.core.event_bus import Event, EventPriority

        bssid = self._get_selected_wifi_bssid()
        iface = self._get_selected_wifi_interface()
        payload = {"type": attack_type, "bssid": bssid, "interface": iface, **(extra_params or {})}
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
            logs.write(
                f"[bold green]Dispatched WiFi attack '{attack_type}' to target {bssid} on {iface}[/bold green]"
            )
        except Exception:
            pass

    async def _wifi_scan(self) -> None:
        try:
            from urban_hs.modules.wifi import ScanStrategy, WiFiScanner

            iface = self._get_selected_wifi_interface()
            logs = self.query_one("#app-log", RichLog)
            # Always use the DIRECT (`iw`) backend for discovery: it scans in
            # the interface's current managed mode, so it does NOT switch to
            # monitor mode and drop the connection. (Monitor-mode / airodump is
            # only needed for the capture attacks, which use their own path.)
            logs.write(f"[yellow]Scanning on interface: {iface} (iw)…[/yellow]")
            scanner = WiFiScanner(interface=iface, strategy=ScanStrategy.DIRECT)
            nets = await scanner.scan(duration=10)
            self._wifi_networks = [n.to_dict() for n in nets]
            self._refresh_wifi_table()
            self.post_message(
                EventMessage(
                    "wifi.scan.completed",
                    {
                        "count": len(self._wifi_networks),
                        "networks": self._wifi_networks,
                        "simulated": False,
                    },
                )
            )
        except Exception as exc:
            self.post_message(EventMessage("wifi.scan.error", {"error": str(exc)}))

    async def _wifi_interfaces(self) -> None:
        try:
            from urban_hs.ui.api.routers.wifi import list_wifi_interfaces

            result = await list_wifi_interfaces()
            ifaces = result.get("interfaces", [])
            self.post_message(EventMessage("wifi.interfaces.listed", {"interfaces": ifaces}))
        except Exception as exc:
            self.post_message(EventMessage("wifi.interfaces.error", {"error": str(exc)}))

    async def _ble_scan(self) -> None:
        try:
            logs = self.query_one("#app-log", RichLog)
            logs.write("[yellow]Checking Bluetooth adapter status…[/yellow]")

            # Ensure Bluetooth power is ON via bluetoothctl / hciconfig
            try:
                proc = await asyncio.create_subprocess_exec(
                    "bluetoothctl",
                    "power",
                    "on",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await proc.wait()
            except Exception:
                pass

            from urban_hs.modules.ble import FastPairScanner

            logs.write("[yellow]Scanning for BLE & Fast Pair devices…[/yellow]")
            scanner = FastPairScanner()
            await scanner.start(scan_all=True)
            await asyncio.sleep(10)
            await scanner.stop()
            devices = scanner.get_devices()
            self._ble_devices = [d.to_dict() if hasattr(d, "to_dict") else vars(d) for d in devices]
            self._refresh_ble_table()
            self.post_message(
                EventMessage(
                    "ble.scan.completed",
                    {
                        "count": len(self._ble_devices),
                        "devices": self._ble_devices,
                        "simulated": False,
                    },
                )
            )
        except Exception as exc:
            logs.write(f"[red]BLE scan error: {exc}[/red]")
            self.post_message(EventMessage("ble.scan.error", {"error": str(exc)}))

    async def _network_scan(self) -> None:
        try:
            from urban_hs.modules.network import NetworkModule, ScanType

            module = NetworkModule()
            hosts = await module.nmap.scan(
                [self._get_subnet_target()], scan_type=ScanType.HOST_DISCOVERY, timeout=60
            )
            result = [vars(h) for h in hosts]
            self.post_message(
                EventMessage(
                    "network.scan.completed",
                    {"count": len(result), "hosts": result, "simulated": False},
                )
            )
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
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
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
