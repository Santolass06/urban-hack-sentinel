# INVENTÁRIO DE ESTADO — mimo

- **Agente:** mimo (opencode/mimo-v2.5-free)
- **Timestamp:** 2026-07-01
- **Commit HEAD:** `6055087fe80c7f5df126337a2eae6580a2880f10`

---

## 1. Tabela feature → estado real

### Core

| Feature | Estado | Prova |
|---------|--------|-------|
| Event Bus | **Real** | `core/event_bus.py` — asyncio.Queue pub/sub, typed Event dataclass, dead letter queue |
| Process Manager | **Real** | `core/process_mgr.py` — asyncio.subprocess, streaming stdout/stderr, timeout, kill tree |
| Config (Pydantic) | **Real** | `core/config.py` — Pydantic v2 settings, YAML/ENV, hot-reload |
| Storage (SQLite WAL) | **Real** | `core/storage.py` — aiosqlite async, WAL mode |
| Logger | **Real** | `core/logger.py` + `core/logging_config.py` — structlog + Rich console, JSONL rotation |
| Health + Prometheus | **Real** | `core/health.py` — /healthz, /readyz, /metrics endpoints |
| Plugin System | **Real** | `core/plugins.py` — entry points, dynamic load, registry |
| Scheduler | **Real** | `core/scheduler.py` — cron-style + interval triggers |
| Concurrency | **Real** | `core/concurrency.py` — semaphore-based resource management |
| Security Hardening | **Real** | `core/security.py` — seccomp profiles, capability dropping, rootless chroot, supply-chain verification (cosign/syft). `verify_slsa_provenance()` is a stub (always returns True, line 513-520) |
| Forensics | **Real** | `core/forensics.py` — EvidenceBundle with SHA256+Blake2b hashing, GPG signing, custody chain |
| MAC Anonymiser | **Real** | `core/mac_anonymiser.py` — HMAC-Blake2b pseudonymisation, recursive dict redaction |
| SessionScope | **Real** | `core/session_scope.py` — target/category allowlist, active-attack guard, process-wide singleton |
| Binary Manifest | **Real** | `core/binary_manifest.py` — SHA256 manifest for external tooling verification |
| Memory Profiling | **Real** | `core/memory.py` — resource monitoring |
| Attack Event Adapter | **Real** | `core/attack_event_adapter.py` — normalizes module events to canonical contract |

### WiFi

| Feature | Estado | Prova |
|---------|--------|-------|
| WiFi Scanner (iw) | **Real** | `modules/wifi/scanner.py:109-113` — `iw dev <iface> scan -f json` subprocess, CSV fallback for airodump-ng, channel hopping |
| WiFi Scanner (airodump-ng) | **Real** | `modules/wifi/scanner.py:316-323` — `airodump-ng` passive scan subprocess |
| WiFi Plugin (orchestration) | **Real** | `modules/wifi/plugin.py:89-123` — instantiates scanner + all attacks, continuous scan loop, session-scope validation |
| Handshake Attack (WPA) | **Real** | `modules/wifi/attacks/wpa.py:68-105` — airodump-ng capture + aireplay-ng deauth, aircrack-ng validation |
| PMKID Attack | **Real** | `modules/wifi/attacks/wpa.py:188-252` — hcxdumptool PMKID capture + hcxpcapngtool conversion |
| Deauth Attack | **Real** | `modules/wifi/attacks/deauth.py:65-85` — aireplay-ng subprocess, targeted + broadcast |
| Kr00k (CVE-2019-15126) | **Real** | `modules/wifi/attacks/deauth.py:240-292` — tshark frame analysis + r00kie decryption |
| WPS Pixie Dust | **Real** | `modules/wifi/attacks/wps.py:64-109` — reaver -K 1 + pixiewps regex parsing |
| WPS PIN Dictionary | **Real** | `modules/wifi/attacks/wps.py:180-204` — reaver -p per PIN, PSK extraction |
| FragAttacks (CVE-2020-24586/87/88) | **Real** | `modules/wifi/fragattacks.py:259-272` — fragattacks tool subprocess execution. `scan_fragattacks_targets()` is a stub returning `[]` (line 353-360) |
| Handshake Manager | **Real** | `modules/wifi/managers.py:109-260` — hashcat 22000 parsing, dedup, export (WiGLE CSV, Kismet netXML partial) |
| MAC Changer | **Real** | `modules/wifi/managers.py:367-423` — macchanger subprocess, OUI profiles, randomization |
| GeoMapper + GPS | **Real** | `modules/wifi/managers.py:581-620` — gpsd TCP socket client, NMEA parsing, KML/WiGLE/Kismet export |
| Wardrive Mode | **Real** | `modules/wifi/managers.py:815-848` — continuous passive scan + GPS logging loop |
| WPA3-SAE Detection | **Real** | `modules/wifi/scanner.py` — parser extracts `wpa3`/`sae` flags from `iw` JSON |
| 802.11r FT Detection | **Real** | `modules/wifi/scanner.py` — parser extracts FT indicators |
| OWE Detection | **Real** | `modules/wifi/scanner.py` — parser extracts OWE AKM |
| PMF Detection | **Real** | `modules/wifi/scanner.py` — parser extracts MFPC/MFPR |
| HE/EHT (Wi-Fi 6/7) | **Real** | `modules/wifi/scanner.py` — parser extracts `he_capab`/`eht_capab` |
| MLO Correlation | **Real** | `modules/wifi/scanner.py` — multi-BSSID correlation logic |
| SSID Confusion (CVE-2023-52424) | **Real** | `modules/ssid_confusion.py:292-490` — hostapd-based Evil Twin with 802.11r FT config |
| Vendor OUI Lookup | **Stub** | `modules/wifi/scanner.py:235-242` — `_get_vendor()` returns `None` |

### BLE / Bluetooth

| Feature | Estado | Prova |
|---------|--------|-------|
| FastPair Scanner (bleak) | **Real** | `modules/ble/fastpair.py:43-132` — BleakScanner, 0xFE2C UUID, advertisement parsing |
| WhisperPair Vulnerability Tester | **Real** | `modules/ble/fastpair.py:157-216` — BleakClient GATT connect, KBP request, response analysis |
| WhisperPair Exploit Chain | **Real** | `modules/ble/fastpair.py:219-459` — Multi-strategy KBP (RAW_KBP, RETROACTIVE, EXTENDED_RESPONSE), device quirks DB |
| BlueZ Bonding Manager | **Real** | `modules/ble/exploit_chain.py:62-182` — D-Bus `CreateBond`, `RemoveBond`, property monitoring |
| Account Key Manager | **Real** | `modules/ble/exploit_chain.py:185-292` — AES-ECB key generation, GATT write |
| HFP Audio Capture (exploit_chain) | **Real** | `modules/ble/exploit_chain.py:295-479` — bluealsa PCM detection, arecord subprocess |
| HFP Audio Capture (hfp.py) | **Stub/Parcial** | `modules/ble/hfp.py:97-105` — `record()` sleeps then checks for nonexistent file; `_process` never assigned in `start()` |
| BLE Plugin | **Parcial** | `modules/ble/plugin.py:62-162` — scan + test wired. Exploit handler (line 232-272) returns `"not_implemented"` despite `exploit_chain.py` having full implementation |
| Bettercap BLE Client | **Real** | `modules/ble/bettercap.py:51-140` — aiohttp REST client for bettercap API |
| Device Quirks DB | **Real** | `modules/ble/fastpair.py:466-528` — JSON file loading from config paths |

### Network

| Feature | Estado | Prova |
|---------|--------|-------|
| Nmap Scanner | **Real** | `modules/network/scanner.py:122-126` — `asyncio.create_subprocess_exec("nmap", ...)` with XML parsing |
| Nuclei Runner | **Real** | `modules/network/nuclei.py:76-80` — `asyncio.create_subprocess_exec("nuclei", ...)` with JSONL parsing |
| SearchSploit Integration | **Real** | `modules/network/searchsploit.py:34-38` — searchsploit -j subprocess, exploit download |
| Router Scanner (brute) | **Real** | `modules/network/router.py:56-86` — Hydra brute force subprocess |
| Router Scanner (scan_router) | **Stub** | `modules/network/router.py:35` — `return []` in standalone file. Real code in `__init__.py:609-645` |
| Camera Discovery (mDNS/UPnP/ONVIF/RTSP/HTTP) | **Real** | `modules/network/camera.py:73-298` — avahi-browse, UDP SSDP, WS-Discovery SOAP, aiohttp fingerprinting |
| Camera Discovery (monolithic) | **Real** | `modules/network/__init__.py:800-1050` — full implementation with all protocols |

### Metasploit / SearchSploit

| Feature | Estado | Prova |
|---------|--------|-------|
| MSF RPC Client | **Real** | `modules/metasploit/rpc.py:139-608` — async msgrpc, MessagePack RPC, session/module/job management |
| MSF Console | **Real** | `modules/metasploit/console.py:91-367` — msfconsole subprocess, resource scripts, template generators |

### Camera Enumeration

| Feature | Estado | Prova |
|---------|--------|-------|
| Camera Enumeration | **Real** | `modules/camera/enumeration.py:246-654` — Basic/Digest auth testing, config dump, RTSP DESCRIBE, firmware extraction. ONVIF info is stub (line 645: `pass`) |
| Camera Vuln Check | **Real** | `modules/camera/vuln_check.py:156-326` — 12 real CVEs in DB, Nuclei/MSF verification |
| Default Creds DB | **Real** | `modules/camera/enumeration.py:122-157` — 34 default pairs + 23 manufacturer-specific |

### HID / USB Gadget

| Feature | Estado | Prova |
|---------|--------|-------|
| DuckyScript Parser | **Real** | `modules/hid/ducky.py:248-400` — v1/v3 parser, 7 layouts, 40+ command types |
| DuckyScript Encoder | **Real** | `modules/hid/ducky.py:400-584` — HID report byte encoding, 8-byte format |
| USB Gadget Manager | **Real** | `modules/hid/gadget.py:143-343` — ConfigFS write operations, HID/mass-storage/RNDIS/ECM/ACM profiles |
| HID Injector (uinput) | **Real** | `modules/hid/injector.py:91-293` — uinput device creation, key_down/key_up, type_string, mouse_move |
| HID Injector (USB Gadget) | **Real** | `modules/hid/injector.py:310-374` — /dev/hidg* endpoint, HID report injection |

### Credential Manager

| Feature | Estado | Prova |
|---------|--------|-------|
| Credential Manager | **Real** | `modules/credential/manager.py:242-881` — dedup, import (hashcat potfile, MSF, SearchSploit), validation (sshpass, curl, smbclient, hydra), Hashcat cracking, export (CSV, JSON, hashcat) |

### Exploit Runner

| Feature | Estado | Prova |
|---------|--------|-------|
| Exploit Runner | **Real** | `modules/exploit/runner.py:184-642` — Nuclei, MSF RPC, MSF Console, SearchSploit, Local chroot execution, batch mode |

### MQTT

| Feature | Estado | Prova |
|---------|--------|-------|
| MQTT Attack Suite | **Real** | `modules/mqtt.py:110-605` — broker discovery, unauth access, topic enum, cred brute, message injection, topic flooding via paho.mqtt |

### ESP32

| Feature | Estado | Prova |
|---------|--------|-------|
| ESP32 Detection | **Real** | `modules/esp32.py:163-358` — multi-method (WiFi OUI, BLE manufacturer, mDNS, HTTP fingerprint) |
| ESP32 CVE-2025-27840 | **Real** | `modules/esp32.py:476-699` — 18 HCI commands, hcitool cmd subprocess, memory/GPIO/NVRAM/flash operations |

### BT HID

| Feature | Estado | Prova |
|---------|--------|-------|
| BT HID Keystroke Injection | **Real** | `modules/bt_hid.py:135-538` — BlueZ D-Bus HID profile, CVE-2023-45866 NoInputNoOutput pairing, keystroke injection via uinput. SDP record builder is placeholder (line 127: `return b""`) |

### Reporting

| Feature | Estado | Prova |
|---------|--------|-------|
| Report Generator (Markdown/HTML/PDF/JSON) | **Real** | `modules/reporting/generator.py:284-661` — Jinja2 templates, WeasyPrint PDF, built-in HTML template (160 lines) |
| GPG Report Signing | **Real** | `modules/reporting/generator.py:730-769` — python-gnupg sign + verify |
| GPG Evidence Signing | **Real** | `modules/reporting/gpg_evidence.py:190-298` — detached ASCII/binary/clear-signed |
| Evidence Logger | **Real** | `modules/reporting/gpg_evidence.py:388-500` — append-only JSON log, GPG-signed, hash chain |
| Chain of Custody | **Real** | `modules/reporting/gpg_evidence.py:546-616` — artifact signing + log + chain verification |

### UI — FastAPI

| Feature | Estado | Prova |
|---------|--------|-------|
| FastAPI App | **Real** | `ui/api/main.py:47-138` — factory with lifespan, CORS, routers, static serving |
| JWT Auth | **Real** | `ui/api/auth.py:26-98` — HS256 signing, secret persistence, Bearer extraction |
| Rate Limiting (slowapi) | **Real** | `ui/api/rate_limit.py:10-13` — slowapi Limiter instance |
| Rate Limiting (token-bucket) | **Real** | `ui/api/middleware.py:58-85` — per-IP in-memory token-bucket |
| Security Headers | **Real** | `ui/api/middleware.py:21-38` — HSTS, CSP, nosniff |
| IP Allowlist | **Real** | `ui/api/middleware.py:41-55` — configurable whitelist |
| WebSocket /api/v1/events | **Real** | `ui/api/routers/events.py:80-103` — auth via Bearer header or `?token=`, broadcast |
| Attack Execute Endpoint | **Real** | `ui/api/routers/attacks.py:119-167` — rate-limited, session-scope validated, dry-run support |
| WiFi Scan Endpoint | **Real** | `ui/api/routers/wifi.py:51-113` — calls WiFiScanner |
| BLE Scan Endpoint | **Real** | `ui/api/routers/ble.py:24-89` — calls FastPairScanner |
| Network Scan Endpoint | **Real** | `ui/api/routers/network.py:24-94` — calls NetworkModule |

### TUI

| Feature | Estado | Prova |
|---------|--------|-------|
| TUI App (Textual) | **Real** | `ui/tui/app.py:77-387` — tabbed layout, WiFi/BLE/Network scans, event bus listener, confirmation modal |
| TUI WiFi/BLE/Network Scans | **Real** | `ui/tui/app.py:303-375` — creates real scanners |
| TUI Attack Buttons | **Stub** | `ui/tui/app.py:265-281` — publish `attack_request` events but **payload mismatch** (see Dívida Técnica) |

### CLI

| Feature | Estado | Prova |
|---------|--------|-------|
| CLI (Typer) | **Real** | `cli/main.py:41-278` — info, run, tui, modules, verify, audit-trail commands |
| `urban-hs seal` | **Stub** | `cli/main.py:223-233` — prints "not yet implemented" |

### Web UI

| Feature | Estado | Prova |
|---------|--------|-------|
| Web UI (static) | **Real** | `ui/web/index.html` — served by FastAPI at `/` |

---

## 2. Guard rails — estado atual

### SessionScope
- **Implementação:** `core/session_scope.py` — target/category allowlist, `validate()` raises `PermissionError`
- **Cobertura confirmada nos 4 caminhos de execução de ataque:**
  1. **WiFi plugin** (`modules/wifi/plugin.py:396-406`) — `get_active_scope().validate(bssid, "wifi")`
  2. **BLE plugin** (`modules/ble/plugin.py:146-162`) — scope validated in `test_vulnerability()`
  3. **Urban Hack WiFi** (`modules/urban_hack.py:342-436`) — via WiFiPlugin delegation
  4. **REST API** (`ui/api/routers/attacks.py:142-148`) — `get_session_scope().validate(target, category)`
- **Cinquanto caminho de execução de ataque SEM SessionScope:** Não encontrado.

### Auth WebSocket/REST
- JWT Bearer auth implementado em `ui/api/auth.py:75-93`
- REST endpoints protegidos via `Depends(require_auth())`
- WebSocket autentica via `Authorization` header ou `?token=` (`ui/api/routers/events.py:80-103`)

### Rate Limiting
- **Camada 1:** slowapi `Limiter` em `ui/api/rate_limit.py`
- **Camada 2:** Token-bucket middleware em `ui/api/middleware.py:58-85`
- **Endpoint-level:** decorators `@limiter.limit("10/minute")` em wifi, ble, network, attacks routers
- Coexistem sem conflito (slowapi at decorator level, middleware at request level)

---

## 3. Dívida técnica conhecida

### Bug do TUI: payload mismatch
- **Estado:** CONFIRMADO — ainda impede execução real via TUI.
- **Causa:** `_publish_attack()` em `ui/tui/app.py:283-301` envia `payload={"attack": attack, "params": params}`. O handler em `modules/wifi/plugin.py:384-408` lê `payload.get("type")` e `payload.get("bssid")` — ambos retornam `None`, causando return precoce sem execução.
- **Mensagem de debug:** `_handle_attack_request` lê `type`/`bssid` mas o TUI envia `attack`/`params`.

### `pyproject.toml` declara `dbus-fast` mas código usa `dbus`
- **Estado:** NÃO é mais o caso. `pyproject.toml` declara `dbus-fast>=2.8.0` (line 45). O código em `exploit_chain.py:16` faz `import dbus` (C-extension) com fallback. O `bt_hid.py:226` usa `dbus_fast`. Há divergência: `exploit_chain.py` usa `dbus` (C-extension), `bt_hid.py` usa `dbus_fast`. Não há `dbus-python` no `pyproject.toml`.

### `msfinstall` (script untracked)
- **Estado:** AINDA FORA DO CONTROLO DE VERSÃO. `git status` mostra `?? msfinstall` (untracked). É o script padrão de instalação do Metasploit da Rapid7 (175 linhas, executável).

### Pasta `audit/`
- **Estado:** EXISTE mas VAZIA. Diretório criado mas sem ficheiros. Não está tracked pelo git.

### Outras dívidas menores
- `_get_vendor()` retorna `None` em 2 lugares no scanner WiFi (`scanner.py:235`, `scanner.py:406`)
- `HandshakeManager.export_kismet_netxml()` retorna `0` sem gerar output (`managers.py:262-266`)
- `scan_fragattacks_targets()` retorna `[]` (`fragattacks.py:353-360`)
- `RouterScanner.scan_router()` retorna `[]` no ficheiro standalone (`router.py:35`) — código real existe em `__init__.py`
- `_build_sdp_record()` retorna `b""` no bt_hid (`bt_hid.py:127`)
- `cli/main.py:223-233` — `urban-hs seal` é stub
- `camera/enumeration.py:645` — `get_onvif_info()` é `pass`
- `security.py:513-520` — `verify_slsa_provenance()` sempre retorna True
- BLE plugin exploit handler retorna `"not_implemented"` (`ble/plugin.py:244,264`) apesar de `exploit_chain.py` ter implementação completa
- `ble/hfp.py:97-105` — `record()` não atribui `_process`, making `stop()` inoperante

---

## 4. Próximas fases segundo os planos

### docs/PLAN.md — Sprint 10 (próximo a fazer)

> **Objective**: move from smoke tests to a rigorous, maintainable test suite that gives confidence before every release.
>
> Tasks:
> 1. Coverage baseline — run `pytest --cov=urban_hs` and set the floor at **85%**.
> 2. Per-module contract tests — every module in `src/urban_hs/modules/...` has a companion `tests/test_<module>_contract.py`.
> 3. Custom test framework — helpers for `gpsd` mock, `mac80211_hwsim` reusable fixtures, HAL adapter matrix (`x86_scapy` vs `arm_iw`).
> 4. Integration tests — run real binaries in Docker (`airodump-ng`, `hcxdumptool`, `reaver`, `nmap`, `nuclei`) against intentionally vulnerable containers.
> 5. Concurrency / load tests — parallel attacks, event bus under pressure, TUI + Web UI connected simultaneously.
> 6. Security tests — path traversal, input fuzzing, secret leakage in logs, privilege checks.
> 7. CI matrix — add `ubuntu-latest` + `arm64` runner if available; fail build on coverage drop.
>
> Acceptance criteria:
> - [ ] PR cannot merge if coverage drops below 85%.
> - [ ] Every new module must include `test_<module>_contract.py` and `test_<module>_execute.py`.
> - [ ] A new contributor can run `make test` and see green locally.

### docs/PLAN.md — Sprint 11 (Plugin Marketplace)

> **Objective**: lower the barrier for others to write and share modules.
>
> Tasks:
> 1. Plugin metadata manifest (`pyproject.toml` `urban-hs.plugins` entry points).
> 2. `urban-hs plugin install <name>` from a registry (local directory or remote Git).
> 3. Signature verification for plugins.
> 4. Module skeleton generator (`urban-hs plugin new <name>`).
> 5. Runtime enable/disable without restart.
> 6. Version constraints and dependency isolation per plugin.

### docs/PLAN.md — Sprint 12 (Distributed Cracking & Offloading)

> **Objective**: scale cracking beyond the Pi's GPU.
>
> Tasks:
> 1. Hash watcher — monitor `$HASH_DIR` for new `.22000` files.
> 2. Remote submit — `rsync`/`scp`/`syncthing` to a configurable cracking host.
> 3. Result poller — pull cracked `.potfile` and update local DB.
> 4. Hashtopolis / KrakenHashes API clients.
> 5. Cost estimator — estimate €/hash for cloud spot instances.
> 6. Auto-report — sessions report how many hashes were cracked and by which backend.

### docs/PLAN.md — Sprint 13 (Cutting-Edge Research)

> **Objective**: keep the platform current with emerging WiFi/BLE/IoT/SDR techniques.
>
> Tasks:
> 1. Wi-Fi 6/6E/7 — HE/EHT capabilities, 6 GHz channel list, MLO correlation.
> 2. SDR / Spectrum — integrate `rtl_power` / `soapy_power` waterfall.
> 3. IoT / Matter / Thread — `_matter._tcp`, Zigbee snapshot (if SDR present).
> 4. Bluetooth Classic — KARMA/MANA, Evil Twin (lab-only), Enterprise/EAP hash capture.
> 5. Wi-Fi Sensing / CSI — basic motion detection with Intel AX CSI tool.
> 6. ML scoring — lightweight XGBoost/ONNX model for `p(crack)`.
> 7. Rogue AP / hostapd-mana — requires second radio or VAP; lab-only policy.

### MASTER_PLAN.md — Sprint 6 (Polish/Otimização/Hardening)

> | Task ID | Descrição |
> |---------|-----------|
> | S6.1 | Concurrency Tuning — Semáforos por recurso, backpressure event bus, task prioritization |
> | S6.2 | Memory Profiling — memray/objgraph, fix leaks, streaming parsers |
> | S6.3 | SQLite Optimization — Índices compostos, PRAGMA optimize, vacuum schedule |
> | S6.4 | Security Hardening — Seccomp profiles, capability dropping, rootless chroot, GPG supply chain |
> | S6.5 | Documentation — MkDocs + docstrings, architecture diagrams, API reference |
> | S6.6 | E2E Tests — pytest-asyncio + mac80211_hwsim + mock BlueZ + testcontainers |
> | S6.7 | Release Automation — cargo-dist style, Docker multi-arch, SBOM (Syft), cosign sign |

---

## 5. Notas adicionais

### Discrepância entre planos
- `MASTER_PLAN.md` declara Sprints 0-5 como completos. `docs/PLAN.md` detalha Sprints 0-9 como completos e Sprint 10+ como pendente.
- `MASTER_PLAN.md` é mais detalhado em features ofensivas (CVEs específicas, hardware requirements).
- `docs/PLAN.md` é mais operacional (testes, coverage, E2E).
- `ROADMAP.md` contém features avançadas F10-F21 que não estão nos outros planos.

### Ficheiros tracked mas com código duplicado
- `modules/network/__init__.py` (1150 linhas) contém código completo de todos os scanners, duplicando os ficheiros standalone (`scanner.py`, `nuclei.py`, `searchsploit.py`, `router.py`, `camera.py`).
- `modules/network/router.py:scan_router()` é stub mas `modules/network/__init__.py:609-645` tem implementação real. Import path determina qual código é executado.
| **CLI** | | |
| urban-hs info | **Real** | cli/main.py:41 |
| urban-hs run | **Real** | cli/main.py:75 - init_core() |
| urban-hs modules | **Real** | cli/main.py:142 |
| urban-hs verify | **Real** | cli/main.py:175 - chain of custody |
| urban-hs seal | **Stub** | cli/main.py:224 - not yet implemented |
| urban-hs audit-trail | **Real** | cli/main.py:237 |
| **Modulos pequenos** | | |
| SSID Confusion CVE-2023-52424 | **Real** | ssid_confusion.py - detector |
| Bluetooth HID CVE-2023-45866 | **Real** | bt_hid.py - BTHIDAttacker (usa dbus_fast) |
| UrbanHack Plugin | **Real** | urban_hack.py - orquestrador WiFi+BLE |

---

## 2. Guard Rails - Estado Atual

### SessionScope
* Confirmado: Cobertura nos 4 pontos de execucao de ataque conhecidos:
  1. REST /api/v1/attacks/{name}/execute (attacks.py:155)
  2. Event bus wifi.attack_request (wifi/plugin.py:397)
  3. Event bus wifi.attack_request (urban_hack.py:633)
  4. Event bus ble.exploit_request (urban_hack.py:633 + ble/plugin.py:252)
* Singleton partilhado: core/session_scope.py:110
* Testes: test_session_scope.py (20) + test_session_scope_guard.py (8) - todos passam
* Dry runs bypassam scope (intencional)

### Auth WebSocket + REST
* REST: require_auth() dependency em todos os routers (auth.py:96-98, usado em attacks.py:38, wifi.py:22, ble.py:22)
* WebSocket: events.py:84-92 - verifica token via Authorization ou ?token=; fecha com WS_1008_POLICY_VIOLATION
* Token: JWT HS256 com expiracao (default 60 min), segredo em ~/.config/urban-hs/jwt_secret

### Rate Limiting: Duas Camadas
* Middleware global (middleware.py:58): token-bucket por IP, 60 req/min
* Decorator slowapi (rate_limit.py + routers): 10/min em escrita
* Comportamento: "mais restritivo ganha" - 10/min efetivo para escrita, 60/min backstop global
* Testado: test_api_integration + test_attacks_execute (ambos passam)
* Nota: mensagem de erro difere entre camadas (cosmetico, status sempre 429)

---

## 3. Divida Tecnica Conhecida

### 3.1 Bug do TUI: _publish_attack envia {attack, params} mas handlers leem type/bssid

Estado atual: CONFIRMADO - ainda nao corrigido.
app.py:280-301 publica Event com payload={"attack": attack, "params": params}
Mas os handlers (wifi/plugin.py:384) esperam payload.get("type") e payload.get("bssid")
Impacto: Ataques lancados via TUI nao executam. Scans funcionam porque chamam scanners diretamente.
Primeira referencia: docs/SESSAO_AUTONOMA_2026-07-01.md:53-55

### 3.2 pyproject.toml declara dbus-fast mas codigo usa dbus (C-ext)

Estado atual: CONFIRMADO.
pyproject.toml:45: dbus-fast>=2.8.0
exploit_chain.py:17: import dbus (C-ext tradicional)
bt_hid.py:28: from dbus_fast import ... (o correto)
Ha inconsistencia entre modulos.

### 3.3 msfinstall (untracked) e pasta audit/ (vazia)

Estado: CONFIRMADO - ambos fora do controlo de versao.
msfinstall: untracked (git status mostra ?? msfinstall)
audit/: diretorio vazio em disco, nao no git

### 3.4 Missing import enum? nao confirmado

fastpair.py:9 tem from enum import Enum (OK). Mas 6 testes de guarda BLE/urban_hack ficam skipped - sugere que modulo BLE ainda nao carrega limpo em CI sem dbus.
Referencia: docs/CORRECAO_SESSIONSCOPE_2026-07-01.md:244

### 3.5 exploit_chain.py crash sem dbus

exploit_chain.py:74 invoca dbus.SystemBus() sem verificar _DBUS_AVAILABLE - crash em runtime se chamado.

### 3.6 TUI acede bus._queue.get() - atributo privado

Mencionado na sessao autonoma, nao confirmado na leitura atual - pode ter sido corrigido.

---

## 4. Proximas Fases Segundo os Planos

### De docs/PLAN.md (literais, s prints nao completados)

**Sprint 10 - Testing Hardening + Coverage Enforcement**
Objective: enforce an 85% coverage floor and ensure every module follows the contract + execute test pattern before it is considered shippable.

**Sprint 11 - Plugin Marketplace**
Objective: lower the barrier for others to write and share modules.

**Sprint 12 - Distributed Cracking & Offloading**
Objective: scale cracking beyond the Pi GPU.

**Sprint 13 - Cutting-Edge Research**
Objective: keep the platform current with emerging WiFi/BLE/IoT/SDR techniques.

### De ROADMAP.md (features pendentes)
| Feature | Task | Status Roadmap | Nota |
|---|---|---|---|
| F1 Wardriving | F1.5 Wardrive dedicado | Pendente | JA EXISTE em managers.py:788 - Roadmap desatualizado |
| F1 Wardriving | F1.6 Bettercap BLE | Pendente | JA EXISTE em ble/bettercap.py - Roadmap desatualizado |
| F3 Multi-Interface | F3.5 Deteccao capacidades | Pendente | Ausente |
| F4 WPA3 | F4.3-4.5 802.11r, Downgrade, SAE-PK | Pendente | Ausente |
| F5 Distributed Cracking | | Pendente | Ausente (coberto Sprint 12) |
| F7 Rogue AP | | Pendente | Ausente |
| F8 Wifi 6/7 | | Pendente | Ausente |
| F9 802.11w/PMF | | Pendente | Ausente |

### De INTEGRATION_ANALYSIS.md
Declara TODOS COMPLETOS na secao 3.1 (Alta Prioridade). Realidade:
* WhisperPair exploit chain: Parcial (KBP bypass funciona, bonding/audio sao stub)
* HFP Audio Capture: Stub (estrutura existe, captura real nao confirmada)

## 5. Observacoes Finais

1. Codigo significativamente mais avancado que os planos indicam (WardriveMode, BettercapBLE, SSID Confusion, BT HID, ESP32). Roadmap desatualizado.
2. Discrepancia mais relevante: TUI _publish_attack bug impede ataques lancados pela TUI. Scans funcionam.
3. Dependencia dbus vs dbus-fast precisa resolucao: exploit_chain.py usa dbus C-ext, bt_hid.py usa dbus_fast.
4. Modulo BLE limitado por dependencia dbus - 6 testes skipped em CI sem dbus.
5. Todas as falhas de teste sao ambientais (falta /var/lib/urban-hs/), nao regressoes.

---

*Relatorio gerado por mimo (Cline) - 2026-07-01. Nenhuma recomendacao ou priorizacao esta incluida; este e apenas um relatorio de estado.*
