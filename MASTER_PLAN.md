# Urban Hack Sentinel v3 — Master Specification & Sprint Plan

> **Objetivo**: Ferramenta de auditoria wireless/Bluetooth/IoT/Network unificada para Raspberry Pi (ARM64), multi-threaded, com armazenamento estruturado, dashboard web/TUI, chroot Alpine, integração Metasploit, descoberta de câmeras, vulnerability scanning e exploitation.

---

## 1. ARQUITETURA GLOBAL

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         URBAN HACK SENTINEL v3                              │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │   CORE       │  │   MODULES    │  │   STORAGE    │  │   UI/UX      │   │
│  │              │  │              │  │              │  │              │   │
│  │ • Event Bus  │  │ • WiFi       │  │ • SQLite     │  │ • FastAPI    │   │
│  │ • Scheduler  │  │ • BLE/BT     │  │   (WAL mode) │  │   + WebSocket│   │
│  │ • ProcessMgr │  │ • Network    │  │ • Redis      │  │ • Textual TUI│   │
│  │ • Config     │  │ • Camera/IoT │  │   (cache+pub)│  │ • Rich CLI   │   │
│  │ • Logger     │  │ • Metasploit │  │ • Filesystem │  │ • React PWA  │   │
│  │ • Plugin API │  │ • Vuln/Exploit│  │   (pcaps,    │  │              │   │
│  │              │  │ • HID/USB    │  │   audio,     │  │              │   │
│  └──────┬───────┘  └──────┬───────┘  │   logs)      │  └──────┬───────┘   │
│         │                 │          └──────┬───────┘         │            │
│         └─────────────────┼────────────────┘                 │            │
│                           ▼                                  ▼            │
│                    ┌──────────────────────────────────────────────────┐   │
│                    │              ALPINE CHROOT (optional)             │   │
│                    │  nmap • nuclei • hydra • msfconsole • hashcat     │   │
│                    │  searchsploit • routerSploit • bettercap          │   │
│                    └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Princípios de Design
1. **Async-first** — `asyncio` + `asyncio.subprocess` para tudo
2. **Event-driven** — Event bus central (pub/sub) para desacoplamento
3. **Plugin architecture** — Cada módulo = plugin carregável dinamicamente
4. **Structured storage** — SQLite (WAL) para dados, Redis para cache/streaming
5. **Observability built-in** — Métricas Prometheus, structured logging JSONL, health checks
6. **Resource-aware** — CPU/memory limits por módulo, backpressure automático

---

## 2. MODELO DE DADOS (SQLite Schema)

```sql
-- Core entities with UUIDv7 (time-ordered)
CREATE TABLE devices (
    id              TEXT PRIMARY KEY,           -- UUIDv7
    first_seen      INTEGER NOT NULL,           -- Unix ms
    last_seen       INTEGER NOT NULL,
    type            TEXT NOT NULL,              -- wifi_ap, wifi_client, ble_device, bt_classic, camera, router, iot, unknown
    mac             TEXT,                       -- Normalized MAC
    ip              TEXT,                       -- If known
    vendor          TEXT,                       -- OUI lookup
    labels          TEXT,                       -- JSON array: ["vulnerable", "compromised", "target"]
    meta            TEXT                        -- JSON extensível
);

-- WiFi specific
CREATE TABLE wifi_networks (
    device_id       TEXT PRIMARY KEY REFERENCES devices(id),
    ssid            TEXT,
    bssid           TEXT NOT NULL UNIQUE,
    encryption      TEXT,                       -- OPEN, WEP, WPA, WPA2, WPA3, WPS, OWE
    channel         INTEGER,
    frequency       INTEGER,
    signal_dbm      INTEGER,
    bandwidth       TEXT,                       -- HT20, HT40, VHT80, HE160, EHT320
    wps_enabled     BOOLEAN DEFAULT 0,
    wps_locked      BOOLEAN DEFAULT 0,
    pmf             TEXT,                       -- disabled, optional, required
    meta            TEXT
);

CREATE TABLE wifi_handshakes (
    id              TEXT PRIMARY KEY,           -- UUIDv7
    network_id      TEXT REFERENCES wifi_networks(device_id),
    bssid           TEXT NOT NULL,
    essid           TEXT,
    capture_path    TEXT NOT NULL,              -- .pcapng
    hash_path       TEXT,                       -- .22000
    hashcat_mode    INTEGER,                    -- 22000, 2500, 16800
    crack_status    TEXT DEFAULT 'uncracked',   -- uncracked, cracked, failed
    password        TEXT,                       -- Se cracked
    cracked_at      INTEGER,
    meta            TEXT
);

-- BLE / Bluetooth
CREATE TABLE ble_devices (
    device_id       TEXT PRIMARY KEY REFERENCES devices(id),
    address_type    TEXT,                       -- public, random, static
    name            TEXT,
    rssi            INTEGER,
    tx_power        INTEGER,
    services        TEXT,                       -- JSON array of UUIDs
    manufacturer_data  TEXT,                   -- JSON
    is_fast_pair    BOOLEAN DEFAULT 0,
    fast_pair_model_id TEXT,
    fast_pair_mode   TEXT,                      -- pairing, idle, account_key_filter
    whisperpair_vuln TEXT,                      -- unknown, vulnerable, patched, error
    whisperpair_exploited BOOLEAN DEFAULT 0,
    account_key_written BOOLEAN DEFAULT 0,
    hfp_connected    BOOLEAN DEFAULT 0,
    audio_recordings INTEGER DEFAULT 0,
    meta            TEXT
);

-- Bluetooth Classic
CREATE TABLE bt_classic_devices (
    device_id       TEXT PRIMARY KEY REFERENCES devices(id),
    name            TEXT,
    class_of_device INTEGER,
    services        TEXT,                       -- JSON array
    paired          BOOLEAN DEFAULT 0,
    meta            TEXT
);

-- Cameras / IoT
CREATE TABLE cameras (
    device_id       TEXT PRIMARY KEY REFERENCES devices(id),
    ip              TEXT NOT NULL,
    port            INTEGER,
    protocol        TEXT,                       -- rtsp, http, https, onvif, gstreamer
    manufacturer    TEXT,
    model           TEXT,
    firmware        TEXT,
    auth_required   BOOLEAN,
    default_creds   TEXT,                       -- JSON: {"user":"admin","pass":"admin"}
    rtsp_url        TEXT,
    snapshot_url    TEXT,
    vulnerable      BOOLEAN DEFAULT 0,
    cves            TEXT,                       -- JSON array
    meta            TEXT
);

-- Network hosts
CREATE TABLE network_hosts (
    device_id       TEXT PRIMARY KEY REFERENCES devices(id),
    ip              TEXT NOT NULL,
    mac             TEXT,
    hostname        TEXT,
    os_guess        TEXT,
    ports_open      TEXT,                       -- JSON array: [{"port":22,"service":"ssh","version":"OpenSSH 8.9"}]
    vulns           TEXT,                       -- JSON array of CVE IDs
    meta            TEXT
);

-- Exploit / Vulnerability tracking
CREATE TABLE vulnerabilities (
    id              TEXT PRIMARY KEY,           -- UUIDv7
    target_id       TEXT REFERENCES devices(id),
    target_type     TEXT,                       -- wifi, ble, camera, host, router
    cve_id          TEXT,
    name            TEXT,
    severity        TEXT,                       -- critical, high, medium, low, info
    exploit_available BOOLEAN DEFAULT 0,
    exploit_path    TEXT,
    metasploit_module TEXT,
    nuclei_template TEXT,
    status          TEXT DEFAULT 'identified',  -- identified, exploited, failed, patched
    exploited_at    INTEGER,
    proof           TEXT,                       -- JSON: command, output, artifacts
    meta            TEXT
);

-- Credentials captured
CREATE TABLE credentials (
    id              TEXT PRIMARY KEY,           -- UUIDv7
    target_id       TEXT REFERENCES devices(id),
    target_type     TEXT,
    username        TEXT,
    password        TEXT,
    hash            TEXT,                       -- Se capturado hash
    hash_type       TEXT,                       -- md5, ntlm, wpa_handshake, etc.
    source          TEXT,                       -- handshake_crack, wps_pin, default_creds, bruteforce, exploit
    captured_at     INTEGER NOT NULL,
    meta            TEXT
);

-- Sessions / Audit runs
CREATE TABLE audit_sessions (
    id              TEXT PRIMARY KEY,           -- UUIDv7
    started_at      INTEGER NOT NULL,
    ended_at        INTEGER,
    config_snapshot TEXT,                       -- JSON config usada
    stats           TEXT,                       -- JSON: networks_found, handshakes, exploits, etc.
    notes           TEXT
);

-- Artifacts (pcaps, audio, screenshots, logs)
CREATE TABLE artifacts (
    id              TEXT PRIMARY KEY,           -- UUIDv7
    session_id      TEXT REFERENCES audit_sessions(id),
    type            TEXT,                       -- pcap, audio, screenshot, log, report, hash
    path            TEXT NOT NULL,
    mime_type       TEXT,
    size_bytes      INTEGER,
    meta            TEXT,
    created_at      INTEGER NOT NULL
);

-- Indexes for performance
CREATE INDEX idx_devices_type ON devices(type);
CREATE INDEX idx_devices_last_seen ON devices(last_seen);
CREATE INDEX idx_wifi_bssid ON wifi_networks(bssid);
CREATE INDEX idx_ble_mac ON ble_devices(device_id);
CREATE INDEX idx_vulns_target ON vulnerabilities(target_id);
CREATE INDEX idx_creds_target ON credentials(target_id);
CREATE INDEX idx_artifacts_session ON artifacts(session_id);
```

---

## 3. MÓDULOS & RESPONSABILIDADES

| Módulo | Arquivo | Responsabilidade | Threads/Tasks |
|--------|---------|------------------|---------------|
| **core/event_bus.py** | Event Bus | Pub/sub assíncrono, decoupling | 1 task |
| **core/scheduler.py** | Scheduler | Cron-style + interval + cron triggers | 1 task |
| **core/process_mgr.py** | AdvancedProcess | Subprocess robusto, streaming, chroot, limits | Pool |
| **core/config.py** | Config | Pydantic settings, validação, hot-reload | — |
| **core/storage.py** | Storage | SQLite async (aiosqlite), Redis, migrations | Pool |
| **core/logger.py** | Logger | Structured JSONL, Rich console, log rotation | — |
| **core/health.py** | Health | Health checks, Prometheus `/metrics` | 1 task |
| **modules/wifi/scanner.py** | WiFi Scanner | Passive/active scan, channel hopping, JSON output | 1 task + subprocess |
| **modules/wifi/attacks/handshake.py** | Handshake | Deauth + capture, PMKID, validation | Subprocess pool |
| **modules/wifi/attacks/wps_pixie.py** | WPS Pixie | Reaver + pixiewps offline | Subprocess |
| **modules/wifi/attacks/wps_pins.py** | WPS PINs | Common PINs DB por OUI, bruteforce controlado | Subprocess |
| **modules/wifi/attacks/deauth.py** | Deauth | Aireplay-ng targeted/broadcast | Subprocess |
| **modules/wifi/handshake_mgr.py** | Handshake Mgr | Dedup, hashcat integration, export, reporting | 1 task |
| **modules/wifi/mac_changer.py** | MAC Changer | OUI profiles, randomization, persistence | 1 task |
| **modules/wifi/geomapper.py** | GeoMac | GPS + WiGLE/Kismet/CSV/KML export | 1 task |
| **modules/ble/fastpair_scanner.py** | FastPair Scanner | Bleak scanner, 0xFE2C, parse advertisement | 1 async task |
| **modules/ble/whisperpair_tester.py** | Vuln Tester | GATT connect → KBP request → analyze response | 1 async task |
| **modules/ble/whisperpair_exploit.py** | Exploit Chain | Multi-strategy KBP → bonding → account key → HFP | 1 async task |
| **modules/ble/audio_hfp.py** | HFP Audio | BlueZ/PyBlueZ SCO capture, recording | 1 async task |
| **modules/network/scanner.py** | Network Scanner | Nmap wrapper, host discovery, OS fingerprint | Subprocess |
| **modules/network/nmap_runner.py** | Nmap Runner | Async Nmap XML/JSON parsing, custom scripts | Subprocess |
| **modules/camera/discovery.py** | Camera Discovery | mDNS, UPnP, ONVIF, RTSP, HTTP probes | 1 async task |
| **modules/camera/enumeration.py** | Camera Enum | Auth test, default creds, config dump, firmware | 1 async task |
| **modules/camera/vuln_check.py** | Camera Vuln | CVE check, exploit availability | 1 async task |
| **modules/metasploit/msf_rpc.py** | MSF RPC | Metasploit RPC client, session mgmt, module exec | 1 async task |
| **modules/metasploit/msf_console.py** | MSF Console | Native msfconsole via process_mgr | Subprocess |
| **modules/vuln/nuclei_runner.py** | Nuclei | Nuclei template exec, findings parsing | Subprocess |
| **modules/vuln/searchsploit.py** | SearchSploit | ExploitDB search, local exploit retrieval | Subprocess |
| **modules/vuln/router_scan.py** | Router Scan | RouterSploit, Hydra, credential discovery | Subprocess |
| **modules/hid/ducky_parser.py** | DuckyScript | Parser Hak5 v1/v3, 7 layouts, encoder | — |
| **modules/hid/hid_injector.py** | HID Injector | uinput / usb-gadget HID keyboard/mouse | 1 task |
| **modules/usb/gadget_mgr.py** | USB Gadget | configfs profiles: HID, mass-storage, RNDIS, ECM | 1 task |
| **modules/exploit/runner.py** | Exploit Runner | Generic exploit execution, proof collection | Subprocess pool |
| **modules/reporting/generator.py** | Report Gen | Markdown/PDF/HTML reports, executive summary | 1 task |
| **ui/api/main.py** | FastAPI | REST + WebSocket, auth, RBAC | Uvicorn workers |
| **ui/tui/app.py** | Textual TUI | Dashboard terminal, live updates | 1 async task |
| **ui/cli/main.py** | Rich CLI | CLI commands, scripting | — |

---

## 4. SPRINT PLAN DETALHADO

### 📦 SPRINT 0 — Foundation (Semana 1) — **✅ COMPLETO**

| Task ID | Descrição | Esforço | Dependências |
|---------|-----------|---------|--------------|
| S0.1 | **Repo structure + Poetry/pyproject.toml** — src layout, deps: `asyncio`, `aiosqlite`, `redis`, `pydantic`, `pydantic-settings`, `rich`, `textual`, `fastapi`, `uvicorn`, `bleak`, `bluez-peripheral`, `scapy`, `aioredis`, `prometheus-client`, `python-nmap`, `jinja2`, `weasyprint` | 4h | — |
| S0.2 | **Core: Event Bus** — `asyncio.Queue` + subscribers, typed events, dead letter queue | 4h | S0.1 |
| S0.3 | **Core: Process Manager** — `asyncio.subprocess`, streaming stdout/stderr, timeout, kill tree, chroot support, resource limits (cgroups v2 se disponível) | 6h | S0.1 |
| S0.4 | **Core: Config (Pydantic Settings)** — YAML/ENV, validação, hot-reload via `watchfiles`, secrets via `keyring` | 4h | S0.1 |
| S0.5 | **Core: Storage Layer** — `aiosqlite` (WAL), connection pool, migrations (alembic-style simples), Redis client (cache + pub/sub) | 6h | S0.1 |
| S0.6 | **Core: Logger** — `structlog` + `rich` console, JSONL file rotation, structured fields, correlation IDs | 3h | S0.1 |
| S0.7 | **Core: Health + Prometheus** — `/healthz`, `/readyz`, `/metrics` (CPU, mem, disk, queue sizes, module status) | 3h | S0.5 |
| S0.8 | **Plugin System** — Entry points `urban_hs.plugins`, dynamic load, dependency graph, enable/disable runtime | 4h | S0.2 |
| S0.9 | **CI/CD GitHub Actions** — Lint (ruff), type-check (mypy), test (pytest-asyncio), build Docker ARM64 | 3h | S0.1 |

**Entregável Sprint 0**: Framework rodando, plugin dummy carrega, healthcheck responde, logs JSONL fluindo.

---

### 📦 SPRINT 1 — WiFi Hardening + WPS + Handshakes + MAC + Geo (Semanas 2-3)

| Task ID | Descrição | Esforço | Dependências |
|---------|-----------|---------|--------------|
| S1.1 | **WiFi Scanner Module** — `iw` JSON + fallback `airodump-ng` CSV, passive/active mode, channel hopping, JSONL output to event bus | 8h | S0.x |
| S1.2 | **Handshake Attack** — `aireplay-ng` deauth targeted + `airodump-ng` capture, PMKID via `hcxdumptool`, validação `aircrack-ng`, save `.pcapng` + `.22000` | 8h | S1.1 |
| S1.3 | **WPS Pixie Dust** — `reaver -K 1` integration, parse output for PIN/PSK, fallback `pixiewps` offline se M1-M3 capturados | 6h | S1.1 |
| S1.4 | **WPS Common PINs DB** — Carregar `wps_pins.csv` (OUI → PINs), bruteforce controlado (`reaver -p`), rate limiting | 6h | S1.1 |
| S1.5 | **Deauth Module** — Targeted (client MAC) + broadcast, rate limiting, legal gate `ENABLE_ACTIVE_ATTACKS` | 4h | S1.1 |
| S1.5 | **Handshake Manager** — Dedup (BSSID+ESSID), `hashcat` integration (`crack_all.py`), export WiGLE/Kismet/Hashcat, report CSV | 6h | S1.2 |
| S1.6 | **MAC Changer + OUI Profiles** — Profiles: `apple`, `samsung`, `intel`, `realtek`, `atheros`, `random`, `persistent`; `macchanger` wrapper | 4h | S0.x |
| S1.7 | **GeoMac + GPS** — `gpsd` client (TCP 2947), correlaciona scan com lat/lon, export WiGLE CSV + Kismet netxml + KML | 6h | S1.1 |
| S1.8 | **Tests + Mock** — `mac80211_hwsim` CI, mock `iw`/`airodump`, unit tests scanner/parser | 6h | S1.1-1.7 |

**Entregável Sprint 1**: ✅ **COMPLETO** — WiFi auditing completo rodando, handshakes salvos, WPS Pixie funcionando, geo export, PMKID attack em WPA3 funcional.

---

### 📦 SPRINT 2 — BLE / WhisperPair / Fast Pair (Semanas 4-5) — **🟡 EM ANDAMENTO**

| Task ID | Descrição | Esforço | Dependências |
|---------|-----------|---------|--------------|
| S2.1 | **FastPair Scanner (Bleak)** — Scan 0xFE2C UUID, parse advertisement (Model ID, pairing mode, account key filter), event bus publish | 6h | S0.x | ✅ **COMPLETO** |
| S2.2 | **WhisperPair Vulnerability Tester** — GATT connect → service 0xFE2C → char 0x1234 → send KBP request → parse response (SUCCESS=vuln, 0x0E/0x05=patched) | 8h | S2.1 | ✅ **COMPLETO** |
| S2.3 | **WhisperPair Exploit Chain** — Multi-strategy: RAW_KBP → RAW_WITH_SEEKER → RETROACTIVE → EXTENDED_RESPONSE; device quirks por Model ID | 10h | S2.2 | 🟡 PARCIAL (estrutura criada) |
| S2.4 | **BR/EDR Bonding** — BlueZ D-Bus `CreateBond`, `RemoveBond`, monitor `org.bluez.Device1` properties | 6h | S2.3 | 🟡 PARCIAL (implementado, precisa dispositivo Fast Pair real) |
| S2.5 | **Account Key Write / Flood** — Write 0x04 + random (encrypted com shared secret se disponível), flood loop com delay | 6h | S2.4 | 🟡 PARCIAL (estrutura criada, precisa dispositivo Fast Pair) |
| S2.6 | **HFP Audio Capture** — BlueZ SCO / `pynep` / `pulseaudio` monitor, gravação WAV/M4A, streaming WebSocket | 8h | S2.4 | ⏳ PENDENTE |
| S2.6 | **Device Quirks DB** — JSON por Model ID: `needsExtendedResponse`, `prefersBrEdrBonding`, `delayBeforeKbp`, `usesRetroactiveFlag` | 4h | S2.3 | ✅ **COMPLETO** (estrutura criada) |
| S2.7 | **Tests + Mock BlueZ** — Mock `bluetoothctl`/`bleak`, unit tests parser/tester/exploit | 6h | S2.1-2.6 | ⏳ PENDENTE |

**Entregável Sprint 2**: ⚠️ **PARCIAL** — Scanner + Tester completos, mas exploit chain precisa dispositivo Fast Pair real para validação completa. 

**Nota**: Dispositivos Fast Pair são acessórios Bluetooth (headphones, speakers, etc.), não APs WiFi. Necessário dispositivo Fast Pair real para validação completa do exploit chain.

---

### 📦 SPRINT 3 — Network / Camera / Vuln Scanning (Semanas 6-7)

| Task ID | Descrição | Esforço | Dependências |
|---------|-----------|---------|--------------|
| S3.1 | **Network Scanner (Nmap Wrapper)** — Async `python-nmap` ou subprocess XML/JSON, host discovery (-sn), port scan (-sS), OS detect (-O), service version (-sV), NSE scripts | 8h | S0.x |
| S3.2 | **Nuclei Runner** — Template execution (`-t cves/ -t exposures/ -t misconfig/`), JSONL parsing, deduplication, severity mapping | 6h | S3.1 |
| S3.3 | **SearchSploit Integration** — Local ExploitDB (`searchsploit -j`), filter por CVE/service, auto-download exploit para `artifacts/` | 4h | S3.1 |
| S3.4 | **Router Scan** — `RouterSploit` (autopwn), `hydra` credential brute (SSH, HTTP, Telnet, FTP), custom auth lists | 6h | S3.1 |
| S3.5 | **Camera Discovery** — mDNS (`_rtsp._tcp`, `_onvif._tcp`), UPnP SSDP, ONVIF `GetDeviceInformation`, RTSP `DESCRIBE`, HTTP fingerprint | 8h | S0.x |
| S3.6 | **Camera Enumeration** — Auth test (basic/digest), default creds list (admin/admin, admin/12345, etc.), config dump, firmware version | 6h | S3.5 |
| S3.7 | **Camera Vuln Check** — CVE mapping (CVEdb local), exploit availability (Nuclei/Metasploit), RTSP auth bypass test | 6h | S3.6 |
| S3.8 | **IoT Protocols** — Matter/Thread (mDNS `_matter._tcp`), Zigbee (via SDR/CC2531 se HW), BLE GATT enumeration | 6h | S2.1 |

**Entregável Sprint 3**: Network vuln scanning, camera discovery/enumeration/vuln check, IoT baseline.

---

### 📦 SPRINT 4 — Metasploit / Exploitation / Reporting (Semanas 8-9)

| Task ID | Descrição | Esforço | Dependências |
|---------|-----------|---------|--------------|
| S4.1 | **Alpine Chroot Bootstrap** — Script `bootstrap_chroot.sh`: Alpine minirootfs, `apk add nmap nuclei hydra metasploit-framework hashcat searchsploit bettercap routerSploit`, bind mounts `/data /artifacts /logs` | 8h | S0.x |
| S4.2 | **Chroot Process Manager** — `process_mgr` executa dentro do chroot via `nsenter`/`chroot`, env vars, bind mounts, resource limits | 6h | S4.1 |
| S4.3 | **Metasploit RPC Client** — `msgrpc` connection, auth, module search/execute, session management, `meterpreter` interaction | 8h | S4.2 |
| S4.4 | **Metasploit Console** — Native `msfconsole -r script.rc` via `process_mgr`, resource scripts auto-gerados | 4h | S4.2 |
| S4.5 | **Exploit Runner Generic** — Interface unificada: carrega exploit (Nuclei/Metasploit/SearchSploit/local), executa, coleta proof (output, artifacts, creds), atualiza `vulnerabilities` + `credentials` | 8h | S4.3 |
| S4.6 | **Credential Manager** — Normalização (user/pass/hash/type/source), dedup, hashcat integration para cracking offline, export | 6h | S4.5 |
| S4.7 | **Report Generator** — Templates Jinja2 → Markdown/HTML/PDF (WeasyPrint), executive summary, findings table, evidence appendix, chain of custody (GPG sign) | 6h | S4.5 |
| S4.8 | **GPG Evidence Signing** — `gpg --detach-sign --armor` cada artifact na captura, evidence log append-only | 4h | S4.1 |

**Entregável Sprint 4**: Chroot funcional, Metasploit integrado, exploitation pipeline end-to-end, relatórios assinados.

---

### 📦 SPRINT 5 — HID / USB Gadget / Dashboard (Semanas 10-11)

| Task ID | Descrição | Esforço | Dependências |
|---------|-----------|---------|--------------|
| S5.1 | **DuckyScript Parser** — Parser Hak5 v1/v3 superset, 7 layouts (US/GB/DE/FR/ES/IT/RU), encoder para `hid_injector` | 6h | S0.x |
| S5.2 | **HID Injector** — `uinput` (local) + `usb-gadget` (configfs `hid` function), payload queue, live execution log | 8h | S5.1 |
| S5.3 | **USB Gadget Manager** — configfs profiles: HID keyboard/mouse, mass-storage (IMG/ISO mount), RNDIS/ECM/ACM (network), ACM (serial), VID/PID/serial customization | 8h | S0.x |
| S5.4 | **FastAPI Backend** — REST CRUD devices/vulns/creds/artifacts, JWT auth, RBAC (admin/operator/viewer), WebSocket `/ws/metrics` + `/ws/events` | 10h | S0.x |
| S5.5 | **React PWA Frontend** — Vite + React + Tailwind + Leaflet.js (mapa) + Chart.js (métricas), offline-first (Service Worker), map clustering | 12h | S5.4 |
| S5.6 | **Textual TUI** — Dashboard terminal: scan status, live metrics, device list, exploit console, log tail | 8h | S0.x |
| S5.7 | **Rich CLI** — Comandos: `scan`, `attack`, `exploit`, `report`, `export`, `config`, `plugin` | 4h | S0.x |
| S5.8 | **Plugin Marketplace** — `urban-hs plugin install <name>`, registry JSON, signature verification | 6h | S0.8 |

**Entregável Sprint 5**: HID/USB gadget, Web/TUI/CLI completos, plugin system.

---

### 📦 SPRINT 6 — Polish / OTIMIZAÇÃO / HARDENING (Semanas 12-13)

| Task ID | Descrição | Esforço |
|---------|-----------|---------|
| S6.1 | **Concurrency Tuning** — Semáforos por recurso (radio, chroot, GPU), backpressure event bus, task prioritization |
| S6.2 | **Memory Profiling** — `memray`/`objgraph`, fix leaks, streaming parsers para large outputs |
| S6.3 | **SQLite Optimization** — Índices compostos, `PRAGMA optimize`, vacuum schedule, WAL checkpoint |
| S6.4 | **Security Hardening** — Seccomp profiles, capability dropping, rootless chroot (user namespaces), GPG supply chain (cosign) |
| S6.5 | **Documentation** — MkDocs + docstrings, architecture diagrams (Mermaid), API reference, user guide |
| S6.6 | **E2E Tests** — `pytest-asyncio` + `mac80211_hwsim` + mock BlueZ + testcontainers para chroot |
| S6.7 | **Release Automation** — `cargo-dist` style: version bump, changelog, Docker multi-arch (ARM64/AMD64), SBOM (Syft), cosign sign |

---

## 5. RECURSOS & HARDWARE NECESSÁRIOS

| Componente | Especificação | Uso |
|------------|---------------|-----|
| **Raspberry Pi 5** | 8GB RAM, 64-bit OS | Host principal |
| **WiFi USB (Monitor)** | Alfa AWUS036AXML (mt7921u) ou AWUS036ACH (rtl8812au) | WiFi monitor/injection |
| **Bluetooth** | Interno Pi 5 (brcmfmac) + USB dongle CSR 4.0/5.0 | BLE/Classic |
| **GPS** | u-blox 7/8/9 USB (ex: VK-172) | Wardriving geo |
| **SDR (opcional)** | HackRF One ou RTL-SDR v4 | Spectrum, Zigbee, hidden SSID |
| **CC2531/CC1352** | Zigbee sniffer | IoT Zigbee |
| **Storage** | SSD USB 3.0 256GB+ | PCAPs, chroot, artifacts |
| **Power** | 5V 5A (27W) + UPS HAT | Estabilidade |

---

## 6. CRITÉRIOS DE SUCESSO (Definition of Done)

| Sprint | Critério |
|--------|----------|
| 0 | `urban-hs health` retorna JSON, plugin carrega, logs JSONL fluem |
| 1 | Captura handshake + PMKID + WPS Pixie + PINs, export WiGLE/Kismet |
| 2 | Detecta Fast Pair, testa CVE-2025-36911, executa exploit chain, grava áudio |
| 3 | Descoberta rede + vuln scan (Nuclei), cameras ONVIF/RTSP, IoT baseline |
| 4 | Chroot Alpine funcional, MSF RPC ativo, exploitation pipeline, relatório PDF assinado |
| 5 | HID injection + USB gadget profiles, Web PWA + TUI + CLI operacionais |
| 6 | Load test 24h sem leaks, release assinado + SBOM, docs completas |

---

## 7. PRIORIZAÇÃO TÉCNICA (Se tempo curto)

| Prioridade | Módulos | Rationale |
|------------|---------|-----------|
| **P0** | Core + WiFi Scanner + Handshake + WPS Pixie + Handshake Mgr | Core value |
| **P1** | BLE FastPair + WhisperPair + MAC Changer + GeoMac | Diferencial único |
| **P2** | Network Scanner + Nuclei + Camera Discovery | Amplitude |
| **P3** | Metasploit + Chroot + Exploit Runner | Profundidade |
| **P4** | HID/USB Gadget + Dashboard Web/TUI | UX/Entrega |
| **P5** | Zigbee/Matter + Matter/Thread + Matter/Thread | Futuro |

---

## 8. PRÓXIMOS PASSOS IMEDIATOS

1. **Criar repo structure** + `pyproject.toml` + `docker/Dockerfile.arm64`
2. **Implementar S0.1-S0.9** (Foundation) — base para tudo
3. **Validar hardware** — Alfa em monitor mode, GPS fix, Bluetooth funcional
4. **Sprint Planning meeting** — Assign tasks, define branch strategy (`main` + `sprint/*`)

---

**Queres que eu comece a implementar o Sprint 0 (Foundation) agora?**
Posso criar a estrutura inicial, `pyproject.toml`, `core/event_bus.py`, `core/process_mgr.py`, `core/config.py`, `core/storage.py`, `core/logger.py` e o plugin system base.