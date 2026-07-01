# Phase 10 — Attack Selection UI

> Objective: give the operator an interface to view available modules, select attacks, confirm execution, and monitor output in real time — both in the TUI (Textual) and in the web frontend.

---

## Scope

- **TUI** (`urban-hs-tui`): category tabs, attack buttons, confirmation modals, integrated terminal widget.
- **Web UI** (`urban-hs-server`): frontend aligned with the existing API, same controls, real-time output via WebSocket.
- **Backend**: reuse existing endpoints and event bus; only add what is missing to connect UI → execution.

Out of scope for this phase: advanced dry-run, attack scheduling, UI preference persistence.

---

## Navigation Structure

```
┌─────────────────────────────────────────────────┐
│  URBAN HACK SENTINEL v3          status: idle    │
├──────────┬──────────┬──────────┬─────────────────┤
│ WiFi     │ BLE      │ Network  │ System / Logs   │  ← tabs
├──────────┴──────────┴──────────┴─────────────────┤
│                                                 │
│            CONTENT OF SELECTED TAB               │
│                                                 │
└─────────────────────────────────────────────────┘
```

Each tab shows:
- list of possible actions (attacks / scans) as clickable buttons/lines
- current execution state (idle / running / completed / error)
- progress bar or simple indicator while executing

---

## Tasks

### T10.1 — Dynamic attack inventory
**Objective**: the UI no longer has hardcoded attacks; it automatically reads modules registered in the plugin manager and categorises them by type.

**Acceptance criteria**:
- TUI automatically lists all modules with `plugin_type = SCANNER` or `EXPLOIT`.
- Changing the registry (adding a plugin) updates the UI without changing presentation-layer code.
- Web UI receives the same list via `GET /api/v1/modules`.

**Implementation**:
- New endpoint `GET /api/v1/attacks` that groups modules by category.
- `urban_hs.modules.list_modules()` already returns the necessary dictionary; it just needs to be exposed.

**Tests**:
- `tests/test_attacks_inventory.py`: scaffold with 2 tests.
  - `test_list_attacks_returns_grouped_modules`: validates that `/api/v1/attacks` returns a list grouped by category.
  - `test_attack_inventory_matches_registry`: validates that each item includes `name`, `plugin_type`, `description`.

### T10.2 — TUI: tabs + attack buttons
**Objective**: navigable screen with category tabs and attack buttons.

**Layout mockup (Textual)**:
```
┌─ TabBar ─────────────────────────────────────────┐
│ [WiFi] [BLE] [Network] [System]                  │
├──────────────────────────────────────────────────┤
│                                                  │
│  WiFi                                            │
│  ┌──────────────────────────────────────────┐   │
│  │ Scan                    [Run Scan]       │   │
│  │ PMKID Capture          [Run PMKID]       │   │
│  │ WPS Pixie Dust         [Run Pixie]       │   │
│  │ Deauth                 [Run Deauth]      │   │
│  └──────────────────────────────────────────┘   │
│                                                  │
│  Status: idle                                    │
└──────────────────────────────────────────────────┘
```

**Acceptance criteria**:
- Each tab filters only modules from the corresponding category.
- Buttons have action; clicking "Run X" opens a confirmation modal.
- TUI continues to boot without errors on the Pi.

**Tests**:
- `tests/test_tui_tabs.py`: scaffold with 1 smoke test (app import).
- Manual smoke test documented in `docs/SMOKE_TUI.md` to validate interaction on Pi.

### T10.3 — TUI: confirmation modal
**Objective**: force confirmation before executing any attack, with a description of what will happen.

**Layout mockup**:
```
╭─ Confirm execution ─────────────────────────────╮
│                                                  │
│  Attack: PMKID Capture                           │
│  Description: Client-less PMKID capture via      │
│  hcxdumptool on interface wlan1.                 │
│                                                  │
│  ⚠️ This attack sends packets on the network.    │
│                                                  │
│         [Cancel]  [Confirm and Execute]           │
╰──────────────────────────────────────────────────╯
```

**Acceptance criteria**:
- Modal shows name, description, and module warnings.
- `Cancel` closes the modal without side effects.
- `Confirm` triggers execution and publishes an event on the event bus.

**Tests**:
- `tests/test_tui_confirm_modal.py`: scaffold with 1 unit test (modal render without crash).

### T10.4 — TUI: integrated terminal widget
**Objective**: show real-time output of the running command, like a terminal inside the TUI.

**Layout mockup**:
```
┌─ Terminal ───────────────────────────────────────┐
│ [Wi-Fi Scan] running...                         │
│ $ hcxdumptool -i wlan1 -o /tmp/pmkid.pcapng    │
│ [00:11:22] Scanning channel 1                   │
│ [00:11:23] Found 3 networks                     │
│ [00:11:24] PMKID captured from AA:BB:CC:DD:EE  │
│ ...                                              │
└──────────────────────────────────────────────────┘
```

**Acceptance criteria**:
- Auto-scroll (last lines visible).
- Event bus events (`attack.stdout`, `attack.stderr`, `attack.completed`) are written to the widget.
- Confirmation modal disappears when the attack starts.

**Tests**:
- Integration via event bus mock in `tests/test_tui_terminal.py`: simulate 3 events and validate widget update.

### T10.5 — Web UI: attack panel aligned with TUI
**Objective**: frontend with the same controls, without duplicating logic.

**Layout mockup (HTML)**:
```
┌─ Header ─────────────────────────────────────────┐
│ Urban Hack Sentinel v3          status: idle      │
├──────────────────────────────────────────────────┤
│ Tabs: [WiFi] [BLE] [Network]                    │
├──────────────────────────────────────────────────┤
│                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ Scan     │  │ PMKID    │  │ WPS      │       │
│  │ Run      │  │ Run      │  │ Run      │       │
│  └──────────┘  └──────────┘  └──────────┘       │
│                                                  │
│  Terminal output (scrollable):                   │
│  > ready...                                      │
└──────────────────────────────────────────────────┘
```

**Acceptance criteria**:
- Loads attack list from `/api/v1/attacks`.
- Clicking "Run" asks for confirmation (browser modal).
- Output appears in real time via WebSocket `/api/v1/events`.
- Basic responsive (desktop + mobile).

**Tests**:
- `tests/test_web_attacks.py`: scaffold with 1 test (attack list loads without error).
- Manual test: open `http://localhost:8000` and validate scan → output flow.

### T10.6 — Backend: attack execution endpoint
**Objective**: allow the UI to request execution of a specific module with optional parameters.

**New endpoint**:
```
POST /api/v1/attacks/{attack_name}/execute
Content-Type: application/json

{
  "params": { "interface": "wlan1", "target_bssid": "AA:BB:CC:DD:EE:FF" },
  "dry_run": false
}
```

**Acceptance criteria**:
- Validates that `attack_name` is registered in the plugin manager.
- Validates `params` against the module's schema (if any); otherwise accepts free-form dict.
- Publishes `attack.started` on the event bus and returns `job_id`.
- `dry_run=true` simulates execution without running the command (mock).

**Tests**:
- `tests/test_attacks_execute.py`: scaffold with 3 tests.
  - `test_execute_known_attack_returns_job`: registered module returns 202 + job_id.
  - `test_execute_unknown_attack_returns_404`: unknown module returns 404.
  - `test_execute_dry_run_does_not_run_command`: `dry_run=true` does not invoke subprocess.

### T10.7 — Standardised events on the event bus
**Objective**: ensure all modules emit events in the format expected by the UI.

**Event contract**:
```
attack.started
  -> { "attack": "pmkid_capture", "params": {...}, "job_id": "..." }

attack.progress
  -> { "job_id": "...", "percent": 45, "message": "Scanning channel 6" }

attack.completed
  -> { "job_id": "...", "success": true, "result": {...} }

attack.error
  -> { "job_id": "...", "error": "Interface wlan1 not found" }
```

**Acceptance criteria**:
- Existing modules (`wifi`, `ble`, `network`) emit events in the format above.
- WebSocket router sends JSON with `type` = event name.
- TUI renders corresponding events in dedicated widgets.

**Tests**:
- `tests/test_event_contract.py`: scaffold with 2 tests.
  - `test_attack_events_have_required_fields`: validates minimum fields in each event type.
  - `test_event_bus_publishes_attack_completed`: simulates execution and validates final event.

### T10.8 — TUI + event bus integration
**Objective**: connect the existing TUI to events published by modules.

**Acceptance criteria**:
- TUI actions (buttons) trigger `POST /api/v1/attacks/{name}/execute` or call the event bus directly in local mode.
- Terminal widget writes lines in real time without UI blocking.
- Modals and buttons remain responsive during long executions.

**Tests**:
- `tests/test_tui_integration.py`: scaffold with 1 mocked execution test.

### T10.9 — Phase 10 documentation
**Objective**: operator can use the UI without opening code.

**Content**:
- `docs/SMOKE_TUI.md` updated with full flow (tab → button → confirmation → output).
- `docs/API.md` updated with `/api/v1/attacks` + `/api/v1/attacks/{name}/execute` endpoints + event contracts.
- `README.md` with ASCII screenshots or small GIFs (if possible).

**Acceptance criteria**:
- `docs/SMOKE_TUI.md` covers phase 10.
- `docs/API.md` includes curl examples for `/api/v1/attacks`.

**Tests**:
- Manual review (no pytest) to ensure screenshots/ASCII match the code.

---

## Recommended execution order

```
T10.1 (dynamic inventory)
  └─ T10.6 (execution endpoint)
       ├─ T10.7 (standardised events)
       │    ├─ T10.2 (TUI tabs + buttons)
       │    │    ├─ T10.3 (confirmation modal)
       │    │    └─ T10.4 (terminal widget)
       │    │         └─ T10.8 (TUI + event bus integration)
       │    └─ T10.5 (Web UI panel)
       └─ T10.9 (documentation)
```

---

## Aggregated tests (phase done criterion)

At least these files must exist and pass:
- `tests/test_attacks_inventory.py`
- `tests/test_attacks_execute.py`
- `tests/test_event_contract.py`
- `tests/test_tui_tabs.py`
- `tests/test_tui_confirm_modal.py`
- `tests/test_tui_terminal.py`
- `tests/test_tui_integration.py`
- `tests/test_web_attacks.py`

Validation command:
```bash
pytest tests/ -q
```

Phase closure criterion:
- Full suite green.
- `urban-hs-tui` boots, navigates tabs, executes mocked attack, and shows output.
- `urban-hs-server` boots and `/` loads frontend with functional buttons.
- Events pass from module → event bus → TUI and Web UI in < 1s.
