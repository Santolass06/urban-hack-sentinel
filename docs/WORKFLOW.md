# Operator Workflows

How to use Urban Hack Sentinel in real operations — from a single scan to a full wardrive session with parallel attacks.

---

## 1. Prerequisites

- Raspberry Pi 5 or x86/64 host with Docker installed.
- Alfa AWUS036ACH (or another supported WiFi adapter) in monitor mode.
- Optional: u-blox GPS USB, Bluetooth adapter, second WiFi radio.
- Access to the TUI (`urban-hs-tui`) or Web UI (`urban-hs-server`).

---

## 2. Basic Single-Attack Flow

1. Start the backend:
   ```bash
   docker compose up -d
   ```
2. Open the TUI or Web UI.
3. Go to the **WiFi** tab and run **Scan**.
4. Wait for the network list to populate.
5. Select a target network and choose an attack (e.g., PMKID, Handshake, WPS).
6. Confirm in the modal.
7. Watch the live terminal for output.
8. When finished, go to **Exports** to download `.pcapng`, `.22000`, or reports.

---

## 3. Wardrive Mode (GPS)

1. Connect the u-blox GPS and ensure `gpsd` is running.
2. In the TUI/Web UI, enable **Wardrive Mode**.
3. The system performs a passive scan continuously while logging GPS coordinates.
4. Walk or drive through the target area.
5. Stop the session — the system auto-exports:
   - KML (Google Earth)
   - WiGLE CSV
   - Kismet netXML
   - JSONL (internal audit format)

---

## 4. Parallel Attacks

1. Start a **WiFi scan** in one tab.
2. Simultaneously start a **BLE Fast Pair scan** in another tab.
3. Both feeds appear in the same live terminal, normalised via the event bus (`attack.started`, `attack.progress`, `attack.completed`).
4. You can run up to N attacks in parallel (bounded by the process manager and HAL resource limits).
5. Each attack has its own `job_id` and can be cancelled independently.

---

## 5. Post-Operation

1. Review the **History** tab for all executed jobs.
2. Export the full session as PDF/HTML/JSON report.
3. Sign the artefacts with GPG (if enabled) to preserve chain of custody.
4. Import handshakes into Hashcat or upload CSV to WiGLE.

---

## 6. Common Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| Scan returns empty | Interface not in monitor mode | Run `urban-hs config set wifi.interface <iface>` and restart |
| GPS no fix | `gpsd` not running or USB GPS not detected | `sudo systemctl start gpsd`; check `gpsmon` |
| Attack stuck | Target out of range or interface busy | Cancel and retry with closer target |
| Web UI not loading | Backend not reachable | Check `urban-hs-server` logs; port 8000 must be open |
