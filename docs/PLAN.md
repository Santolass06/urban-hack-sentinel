# Urban Hack Sentinel v3 — Sprint Plan

> **Working branch**: `andreas/catarinus`  
> **Last updated**: 2026-06-30  
> **Repository policy**: every feature push MUST update all documentation (EN + PT) following the style and structure rules defined in the project docs.

---

## Table of Contents

1. [Sprint 0 — Foundation + Hardware Abstraction / x86 Port](#sprint-0--foundation--hardware-abstraction--x86-port) *(completed)*
2. [Sprint 1 — Core Modules + CLI + TUI Basic + Docker / CI](#sprint-1--core-modules--cli--tui-basic--docker--ci) *(completed)*
3. [Sprint 2 — API + Event Bus + Attack Inventory](#sprint-2--api--event-bus--attack-inventory) *(completed)*
4. [Sprint 3 — Attack Selection UI Phase 10](#sprint-3--attack-selection-ui-phase-10) *(completed)*
5. [Sprint 4 — Documentation, Testing Guide, EN/PT Sync](#sprint-4--documentation-testing-guide-enpt-sync) *(active)*
6. [Sprint 5 — GPS/gpsd/NMEA/KML/CSV Export + Wardrive Mode](#sprint-5--gpsgpsdnmeakmlcsv-export--wardrive-mode)
7. [Sprint 6 — Real Module Validation (Nuclei, RouterScan, Bettercap BLE, HFP)](#sprint-6--real-module-validation-nuclei-routerscan-bettercap-ble-hfp)
8. [Sprint 7 — Advanced WiFi Attacks](#sprint-7--advanced-wifi-attacks)
9. [Sprint 8 — Security Hardening & Forensics](#sprint-8--security-hardening--forensics)
10. [Sprint 9 — Testing Hardening + Coverage Enforcement](#sprint-9--testing-hardening--coverage-enforcement)
11. [Sprint 10 — Web UI Evolution (Maps, PWA, Offline)](#sprint-10--web-ui-evolution-maps-pwa-offline)
12. [Sprint 11 — Plugin Marketplace & Extensibility](#sprint-11--plugin-marketplace--extensibility)
13. [Sprint 12 — Distributed Cracking & Offloading](#sprint-12--distributed-cracking--offloading)
14. [Sprint 13 — Cutting Edge Research](#sprint-13--cutting-edge-research)

---

## Sprint 0 — Foundation + Hardware Abstraction / x86 Port *(completed)*

**Objective**: prove the concept that the same codebase can target both Raspberry Pi (ARM64) and x86/64 through a HAL, and that the core process manager, config, storage, event bus, and plugin loader work end-to-end.

**Tasks**:
1. Repo structure (`src/` layout, `pyproject.toml`).
2. HAL layer with WiFi/BLE/Network/Platform abstractions.
3. x86 WiFi fallback (scapy) when `iw` JSON is unavailable.
4. Config (Pydantic v2), storage (SQLite WAL + JSONL), event bus, process manager.
5. Health checks, plugin registry, logging (structured JSONL).
6. Docker multiarch (`linux/amd64,linux/arm64`) with `TARGETARCH`.
7. CI skeleton (lint + type-check + tests).

**Acceptance criteria**:
- [x] `urban-hs --help` works on Pi and x86.
- [x] Plugin registry loads and reports module inventory.
- [x] Mock scan succeeds on x86 without monitor mode.
- [x] Docker image builds and runs on both architectures.
- [x] Health endpoint responds.

---

## Sprint 1 — Core Modules + CLI + TUI Basic + Docker / CI *(completed)*

**Objective**: deliver a usable local tool for WiFi/BLE/Network/Camera/Metasploit/HID/MQTT attacks with a Rich CLI and a basic Textual TUI, packaged in Docker.

**Tasks**:
1. WiFi scanner (passive/active, channel hopping, `iw` JSON + `airodump` fallback).
2. BLE module (Fast Pair scanner, WhisperPair tester/exploit, device quirks).
3. Network scanner (Nmap wrapper, OS fingerprint, service enum).
4. Camera discovery (mDNS, UPnP, ONVIF, RTSP, HTTP fingerprint).
5. Metasploit RPC client + exploit runner.
6. Credential manager + report generator (PDF/JSON/HTML + GPG signing).
7. MQTT attack suite (broker discovery, topic enum, cred brute).
8. HID/USB gadget stubs + ESP32/SSID/Bluetooth-HID attacks.
9. Rich CLI (`scan`, `attack`, `exploit`, `report`, `export`, `config`).
10. Basic Textual TUI (logs, metrics, device list).
11. Docker Compose, systemd service sample, release automation.
12. CI with `mac80211_hwsim` for virtual WiFi tests.

**Acceptance criteria**:
- [x] All documented attack categories are reachable from CLI/TUI.
- [x] Reports are generated and GPG-signed.
- [x] Docker Compose brings the stack up with a single command.
- [x] CI passes on every PR.

---

## Sprint 2 — API + Event Bus + Attack Inventory *(completed)*

**Objective**: give every module a standardised REST/WebSocket interface so the UI layers become thin consumers instead of module-specific integrations.

**Tasks**:
1. FastAPI app with JSON config, rate limiting, masked secrets.
2. `/api/v1/attacks` — inventory + execute (dry-run / real).
3. `/api/v1/jobs/{id}` — status + cancel.
4. WebSocket feed for `attack.started`, `attack.progress`, `attack.completed`, `attack.error`.
5. `AttackEventNormalizer` to translate module-specific events into the canonical contract.
6. Tests: inventory, execute (sync TestClient), event contract, TUI smoke tests.

**Acceptance criteria**:
- [x] UI does not import any module directly; it only talks `/api/v1/attacks`.
- [x] A new module added to the registry appears in the UI without frontend changes.
- [x] Event contract is covered by unit tests.

---

## Sprint 3 — Attack Selection UI Phase 10 *(completed)*

**Objective**: operator-facing interfaces to view modules, pick attacks, confirm execution, and monitor output live.

**Tasks**:
1. TUI: attack buttons by category, confirmation modal, live terminal widget.
2. Web UI: HTMX + Alpine panel bound to `/api/v1/attacks` + WebSocket.
3. Attack persistence: `job_id` tracking + history.

**Acceptance criteria**:
- [x] Operator can select an attack and see real-time output in both TUI and browser.
- [x] Destructive attacks require confirmation before execution.
- [x] Dry-run mode is available for every module.

---

## Sprint 4 — Documentation, Testing Guide, EN/PT Sync *(active)*

**Objective**: make the project approachable for beginners (no security background) while keeping it useful for advanced users.

**Tasks**:
1. Rewrite `README.md` (EN) + `README.pt.md` (PT AO90) — fix anchors, fix mobile tables, fix links.
2. `docs/OVERVIEW.md` + `docs/OVERVIEW.pt.md` — project origin, name meaning, target audience, learning-first narrative.
3. `docs/API.md` + `docs/API.pt.md` — extensive reference with core concepts, auth, schemas, event contract, custom module example, error handling, testing.
4. `docs/SMOKE_TUI.md` + `docs/SMOKE_TUI.pt.md` — manual test steps + custom test development guide.
5. `docs/WORKFLOW.md` + `docs/WORKFLOW.pt.md` — operator working flows normal and parallel usage.
6. `docs/CONTRIBUTING.md` + `docs/CONTRIBUTING.pt.md` — module template, commit rules, documentation sync obligations.
7. Sanitise every `.md`, `.yml`, `.toml`, `.sh`, `.service`, `.py` file for personal data (PII).
8. Ensure PT uses AO90 throughout (e.g., “objectivo”, “módulo”, “vários”).

**Acceptance criteria**:
- [x] README renders correctly on mobile with valid Markdown tables.
- [x] All doc links resolve to valid anchors.
- [x] Vocabulary is consistent across EN and PT docs.
- [x] No personal data remains in tracked files.

---

## Sprint 5 — GPS/gpsd/NMEA/KML/CSV Export + Wardrive Mode

**Objective**: complete the GPS pipeline from u-blox receiver to geotagged exports that can be loaded into Google Earth, WiGLE, and Kismet.

**Tasks**:
1. `gpsd` JSON protocol client — replace the socket stub with a real reader (no Python `gpsd` bindings required; use the direct TCP JSON stream).
2. NMEA sentence parser (GPRMC, GPGGA, GPGSA) for lat/lon/alt/speed/HDOP.
3. `GeoMapper` — link snapshots to `(bssid, lat, lon, alt, timestamp)`.
4. Exporters:
   - KML (Google Earth, with `Placemark` per BSSID).
   - WiGLE CSV (exact column order expected by wigle.net).
   - Kismet netxml (`<wireless-network>` with GPS tags).
   - JSONL (first-class, for audit pipeline).
5. Wardrive mode: continuous passive scan + GPS logging + auto-export at end of session.
6. Event bus wiring — publish `gps.fix`, `gps.lost`, `geo.exported`.
7. TUI and Web UI integration — show lat/lon in scan tables, offer export buttons.
8. Tests: mock gpsd server on a random port, validate parsing and all exporters.

**Acceptance criteria**:
- [ ] A walk with GPS produces a KML that opens in Google Earth with correct positions.
- [ ] WiGLE CSV accepts the export without column errors.
- [ ] Wardrive mode can run unattended and produce a complete session artefact.
- [ ] Tests run in CI without a real GPS dongle.

---

## Sprint 6 — Real Module Validation (Nuclei, RouterScan, Bettercap BLE, HFP)

**Objective**: move from scaffolding to working integrations with the underlying tools.

**Tasks**:
1. Nuclei runner — install templates, run against local targets, parse JSONL findings, deduplicate, map severity.
2. RouterScan / Hydra — credential brute on SSH, HTTP, FTP with custom wordlists.
3. Bettercap BLE module — use `bettercap -iface <ble>` for GATT enumeration as a complement to `bleak`.
4. HFP Audio Capture — SCO link via BlueZ + `pulseaudio`/`bluealsa` monitor, save WAV, stream via WebSocket.
5. Camera enumeration — default-credential testing, config dump, firmware extraction.
6. Metasploit RPC end-to-end — module search, execute, session interaction, proof collection.

**Acceptance criteria**:
- [ ] Nuclei returns findings that are displayed in the UI.
- [ ] RouterScan produces credential candidates with source attribution.
- [ ] BLE enumeration runs in parallel with `bleak` scans and merges results.
- [ ] HFP capture records audio when a headset is paired.
- [ ] Metasploit sessions are tracked in the credential and vulnerability tables.

---

## Sprint 7 — Advanced WiFi Attacks

**Objective**: modern WiFi security assessment capabilities beyond WPA2-PMKID/handshake/WPS.

**Tasks**:
1. WPA3-SAE detection and PMKID capture (`hcxdumptool` SAE support).
2. 802.11r Fast Transition — capture PMK-R0/R1 via forced reassociation.
3. Downgrade attack — force mixed-mode AP to WPA2 for easier capture.
4. OWE (Opportunistic Wireless Encryption) detection and handshake capture.
5. PMF (802.11w) — detect `MFPC`, `MFPR`, SA Query support; document deauth limitations.
6. Wi-Fi 6/6E/7 — parse `he_capab`, `eht_capab`, 6 GHz channel list, 320 MHz width flags.
7. MLO (Multi-Link Operation) — correlate multiple BSSIDs belonging to the same AP across bands.

**Acceptance criteria**:
- [ ] Scanner reports WPA3, OWE, PMF, HE, EHT flags.
- [ ] Operator can choose 802.11r or downgrade attacks from the UI.
- [ ] Documentation explains the legal/ethical boundary for each new attack.

---

## Sprint 8 — Security Hardening & Forensics

**Objective**: make the platform safe to expose on a LAN and safe to use for evidence collection.

**Tasks**:
1. API authentication — token Bearer or htpasswd (configurable).
2. RBAC roles — `admin`, `operator`, `viewer`.
3. Evasion / stealth — passive-only mode, MAC OUI spoof pool, scan-rate limiter (Poisson), channel dwell time randomisation.
4. Forensics — automated evidence report (Markdown/PDF), GPG signature per artefact, SHA256 evidence log, chain of custody fields.
5. GDPR compliance — MAC anonymisation option, retention policy, right-to-erasure command.
6. Log rotation, LUKS storage option, watchdog systemd integration.

**Acceptance criteria**:
- [ ] API without a valid token returns `401/403`.
- [ ] Viewer role can read but not trigger attacks.
- [ ] Evidence bundle can be verified as unaltered by checking GPG signatures and hashes.
- [ ] MAC-anonymised exports remove the ability to reconstruct the original MAC.

---

## Safari 9 — Testing Hardening + Coverage Enforcement

**Objective**: move from smoke tests to a rigorous, maintainable test suite that gives confidence before every release.

**Tasks**:
1. Coverage baseline — run `pytest --cov=urban_hs` and set the floor at **85%**.
2. Per-module contract tests — every module in `src/urban_hs/modules/...` has a companion `tests/test_<module>_contract.py`.
3. Custom test framework — helpers for `gpsd` mock, `mac80211_hwsim` reusable fixtures, HAL adapter matrix (`x86_scapy` vs `arm_iw`).
4. Integration tests — run real binaries in Docker (`airodump-ng`, `hcxdumptool`, `reaver`, `nmap`, `nuclei`) against intentionally vulnerable containers.
5. Concurrency / load tests — parallel attacks, event bus under pressure, TUI + Web UI connected simultaneously.
6. Security tests — path traversal, input fuzzing, secret leakage in logs, privilege checks.
7. CI matrix — add `ubuntu-latest` + `arm64` runner if available; fail build on coverage drop.

**Acceptance criteria**:
- [ ] PR cannot merge if coverage drops below 85%.
- [ ] Every new module must include `test_<module>_contract.py` and `test_<module>_execute.py`.
- [ ] A new contributor can run `make test` and see green locally.

---

## Sprint 10 — Web UI Evolution (Maps, PWA, Offline)

**Objective**: make the browser interface useful in the field with low bandwidth and intermittent connectivity.

**Tasks**:
1. Leaflet map — display networks on OpenStreetMap using the GPS pipeline.
2. Clustering + heatmap — show dense urban scans without crashing the browser.
3. Offline-first PWA — service worker, cached assets, queue actions when offline.
4. Real-time charting — signal strength over time, attack success/fail rates.
5. Dark/light theme, responsive layout, accessibility (keyboard navigation, ARIA).

**Acceptance criteria**:
- [ ] A wardrive session produces a map viewable without reloading.
- [ ] UI works when the operator loses network and reconnects later.
- [ ] All charts update via WebSocket without page refresh.

---

## Sprint 11 — Plugin Marketplace & Extensibility

**Objective**: lower the barrier for others to write and share modules.

**Tasks**:
1. Plugin metadata manifest (`pyproject.toml` `urban-hs.plugins` entry points).
2. `urban-hs plugin install <name>` from a registry (local directory or remote Git).
3. Signature verification for plugins.
4. Module skeleton generator (`urban-hs plugin new <name>`).
5. Runtime enable/disable without restart.
6. Version constraints and dependency isolation per plugin.

**Acceptance criteria**:
- [ ] A new module can be written, installed, and appear in the UI in under 5 minutes.
- [ ] Disabled plugins do not load or appear in the attack inventory.
- [ ] Plugin docs template exists in `CONTRIBUTING.md`.

---

## Sprint 12 — Distributed Cracking & Offloading

**Objective**: scale cracking beyond the Pi’s GPU.

**Tasks**:
1. Hash watcher — monitor `$HASH_DIR` for new `.22000` files.
2. Remote submit — `rsync`/`scp`/`syncthing` to a configurable cracking host.
3. Result poller — pull cracked `.potfile` and update local DB.
4. Hashtopolis / KrakenHashes API clients.
5. Cost estimator — estimate €/hash for cloud spot instances.
6. Auto-report — sessions report how many hashes were cracked and by which backend.

**Acceptance criteria**:
- [ ] A `.22000` created on the Pi can be cracked on a desktop and the password appears in the local credential manager.
- [ ] Operator sees in the UI which backend cracked each hash.

---

## Sprint 13 — Cutting Edge Research

**Objective**: keep the platform current with emerging WiFi/BLE/IoT/SDR techniques.

**Tasks**:
1. Wi-Fi 6/6E/7 — HE/EHT capabilities, 6 GHz channel list, MLO correlation.
2. SDR / Spectrum — integrate `rtl_power` / `soapy_power` waterfall.
3. IoT / Matter / Thread — `_matter._tcp`, Zigbee snapshot (if SDR present).
4. Bluetooth Classic — KARMA/MANA, Evil Twin (lab-only), Enterprise/EAP hash capture.
5. Wi-Fi Sensing / CSI — basic motion detection with Intel AX CSI tool.
6. ML scoring — lightweight XGBoost/ONNX model for `p(crack)`.
7. Rogue AP / hostapd-mana — requires second radio or VAP; lab-only policy.

**Acceptance criteria**:
- [ ] Each research topic has its own module directory and a clear “lab-only / requires HW” notice in the docs.
- [ ] No research feature is enabled by default; requires an explicit feature flag and operator confirmation.

---

## Global Rules

1. **No PII** in committed code or docs. Sanitise paths, usernames, emails, hardware serials.
2. **EN + PT**: every new or updated `.md` must have both language versions unless explicitly waived.
3. **Documentation-first for risky features**: before a destructive attack is merged, its doc must explain the legal/ethical boundary and the confirmation flow.
4. **Tests before code** for new modules: `test_<module>_contract.py` and `test_<module>_execute.py` are required for merge.
5. **Coverage floor**: 85% overall; new code must not decrease it.
6. **Branch discipline**: feature branches off `andreas/catarinus`; PR description must include a `docs/` checklist.
