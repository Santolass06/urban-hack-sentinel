# TUI Smoke Test & Custom Test Guide

Manual validation and guidance for writing custom tests against the Textual UI layer.

---

## Table of Contents

- [Environment](#environment)
- [Smoke test steps](#smoke-test-steps)
- [Expected result](#expected-result)
- [Developing custom tests](#developing-custom-tests)
- [Test patterns](#test-patterns)
- [CI integration](#ci-integration)

---

## Environment

- Host: Raspberry Pi 5 or x86/64 machine
- OS: Linux (kernel 6.x recommended)
- Terminal: `TERM=xterm-256color`
- Python: project `.venv` activated

---

## Smoke test steps

1. `cd /home/andresantos/Desktop/Projects/urban-hack-sentinel`
2. `. .venv/bin/activate`
3. `python -m urban_hs.ui.tui.app` (or `urban-hs-tui`)
4. Confirm:
   - Header shows version + system info
   - WiFi tab shows Scan and Interfaces buttons
   - BLE tab shows Scan Fast Pair button
   - Network tab shows Host Discovery button
   - Terminal tab shows an empty terminal widget
5. Press `Scan` on the WiFi tab → log shows event
6. Press `q` to exit

---

## Expected result

- TUI starts without crash
- At least one tab shows real data/events (Wi-Fi scan or BLE scan)
- Terminal tab scrolls automatically on new events

---

## Developing custom tests

The TUI uses Textual, which requires a real TTY for full integration tests. Automated tests should focus on:

- App instantiation
- Widget composition
- Event handler dispatch
- Action methods

### File convention

Place TUI tests under `tests/test_tui_*.py`. Use descriptive names:

- `tests/test_tui_phase10.py` — smoke tests for attack UI
- `tests/test_tui_events.py` — event bus wiring
- `tests/test_tui_widgets.py` — widget composition

### Fixtures

Reuse a factory function that returns a fresh `TUIApp` instance:

```python
from urban_hs.ui.tui.app import TUIApp

def _app() -> TUIApp:
    return TUIApp()
```

Avoid pytest fixtures that return the fixture function itself; instantiate the class directly.

---

## Test patterns

### 1. Verify attack actions exist

```python
def test_tui_app_has_attack_actions() -> None:
    app = _app()
    assert hasattr(app, "_wifi_deauth")
    assert hasattr(app, "_wifi_handshake")
    assert hasattr(app, "_ble_whisperpair")
```

### 2. Mock `query_one` for event dispatch

`query_one` requires a mounted DOM. Monkeypatch it with a fake widget:

```python
def test_tui_event_handler_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app()
    calls: list[str] = []

    class FakeLog:
        def write_line(self, line: str) -> None:
            calls.append(line)

    fake = FakeLog()
    monkeypatch.setattr(app, "query_one", lambda sel, cls, *args, **kwargs: fake)

    from urban_hs.ui.tui.app import EventMessage
    message = EventMessage(event_type="attack.started", payload={"attack": "x"})
    app.on_event_message(message)

    assert any("[yellow]START[/yellow]" in line for line in app._attack_log)
```

### 3. Test publish path without network

Override `get_event_bus` or `bus.publish` to capture events:

```python
def test_tui_publish_attack(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app()
    published: list[dict] = []

    async def fake_publish(event):
        published.append({"type": event.type, "payload": event.payload})

    class FakeBus:
        async def publish(self, event):
            await fake_publish(event)

    monkeypatch.setattr("urban_hs.ui.tui.app.get_event_bus", lambda: FakeBus())
    app._publish_attack("wifi_deauth", {"count": 10})
    assert len(published) == 1
    assert published[0]["payload"]["type"] == "wifi_deauth"
```

### 4. Test confirm modal rendering (static)

Call `compose()` and inspect yielded widgets:

```python
def test_tui_confirm_modal_composes() -> None:
    app = TUIApp()
    widgets = list(app.compose())
    # Confirm modal is created when _confirm() is called
    app._confirm("Run attack?", lambda: None)
    modal = [w for w in app._nodes if hasattr(w, "id") and w.id == "modal-confirm"]
    assert len(modal) == 1
```

---

## CI integration

Add TUI smoke tests to the CI matrix in `.github/workflows/ci.yml`:

```yaml
- name: TUI smoke tests
  run: pytest tests/test_tui_phase10.py -q
```

Full-screen TUI tests (`app.run()`) must remain manual-only. Do not attempt to run Textual in headless mode in CI without a virtual display (xvfb). If headless validation is required, use `textual run --headless` with a recorded snapshot comparison.

---

## Troubleshooting custom tests

- **`ScreenStackError: No screens on stack`** — `query_one` was called before `compose()`/`on_mount`. Use monkeypatch as shown above.
- **`AttributeError: 'FunctionType' object has no attribute 'compose'** — pytest fixture returned the wrapper function, not the instance. Instantiate `TUIApp()` directly in the test.
- **Linter errors on `TestClient`** — import from `fastapi.testclient`, not `fastapi`.
