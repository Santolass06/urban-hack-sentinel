"""
Urban Hack Sentinel v3 — Textual TUI dashboard.

Entry point::

    python -m urban_hs.ui.tui.app

Registered as ``urban-hs-tui`` in ``pyproject.toml``.
"""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import (
    Button,
    Footer,
    Header,
    Label,
    Log,
    Static,
    TabbedContent,
    TabPane,
)

from urban_hs import __version__


class SystemStatus(Static):
    """Header widget showing architecture + version."""

    def render(self) -> str:
        import platform

        return (
            f"[bold cyan]Urban Hack Sentinel[/bold cyan] [green]v{__version__}[/green]\n"
            f"[dim]{platform.system()} {platform.release()} ({platform.machine()}) • "
            f"Python {platform.python_version()}[/dim]"
        )


class TUIApp(App):
    """Main Textual dashboard."""

    CSS = """
    Screen {
        layout: vertical;
    }
    #main {
        height: 1fr;
    }
    Log {
        height: 1fr;
        border: solid $primary;
    }
    .panel {
        padding: 1 2;
    }
    """

    BINDINGS = [
        ("q", "app.quit", "Quit"),
        ("d", "toggle_dark", "Toggle dark mode"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield SystemStatus(id="status")
        with Container(id="main"):
            with TabbedContent():
                with TabPane("WiFi", id="tab-wifi"):
                    yield Vertical(
                        Button("Scan", id="btn-wifi-scan"),
                        Button("PMKID Attack", id="btn-wifi-pmkid"),
                        Button("WPS Pixie Dust", id="btn-wifi-pixie"),
                        Button("Deauth", id="btn-wifi-deauth"),
                        Label("Discovered Networks:"),
                        Static("(none yet)", id="wifi-networks"),
                        classes="panel",
                    )
                with TabPane("BLE", id="tab-ble"):
                    yield Vertical(
                        Button("Scan Fast Pair", id="btn-ble-scan"),
                        Button("Test WhisperPair", id="btn-ble-whisper"),
                        Label("BLE Devices:"),
                        Static("(none yet)", id="ble-devices"),
                        classes="panel",
                    )
                with TabPane("Network", id="tab-network"):
                    yield Vertical(
                        Button("Nmap Host Discovery", id="btn-net-nmap"),
                        Button("Nuclei Scan", id="btn-net-nuclei"),
                        Label("Results:"),
                        Static("(none yet)", id="net-results"),
                        classes="panel",
                    )
                with TabPane("Logs", id="tab-logs"):
                    yield Log(id="app-log", auto_scroll=True)
        yield Footer()

    def on_mount(self) -> None:
        self.theme = "monokai" if self.theme == "default" else "default"

    def action_toggle_dark(self) -> None:
        self.theme = "monokai" if self.theme == "default" else "default"

    # ------------------------------------------------------------------
    # Placeholder button handlers
    # ------------------------------------------------------------------
    def on_button_pressed(self, event: Button.Pressed) -> None:
        log = self.query_one("#app-log", Log)
        log.write_line(f"[yellow]Button pressed:[/yellow] {event.button.id} — not yet implemented.")


def run() -> None:
    """Console script entry point."""
    TUIApp().run()


if __name__ == "__main__":
    run()
