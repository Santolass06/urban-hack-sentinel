# INVENTÁRIO DE ESTADO — Urban Hack Sentinel

**Agente**: mistral-vibe  
**Timestamp**: 2026-07-01 14:30:00 UTC  
**Commit HEAD**: `6055087fe80c7f5df126337a2eae6580a2880f10`  

---

## 1. FEATURES/FASES DECLARADAS NOS PLANOS VS ESTADO REAL

### Tabela: Feature → Estado Real (com prova em código)

| **Módulo/Feature** | **Estado no Plano** | **Estado Real** | **Ficheiro:Linha (prova)** | **Notas** |
|---|---|---|---|---|
| **WiFi Scanner** | Completo (MASTER_PLAN Sprint 1) | **Real** | `src/urban_hs/modules/wifi/scanner.py:1-258` | Implementacao completa com `iw` JSON + fallback `airodump-ng` |
| **WiFi Handshake Attack** | Completo (MASTER_PLAN S1.2) | **Real** | `src/urban_hs/modules/wifi/attacks/wpa.py:1-200+` | `aireplay-ng` deauth + `airodump-ng` capture |
| **WiFi PMKID Attack** | Completo (MASTER_PLAN S1.2) | **Real** | `src/urban_hs/modules/wifi/attacks/wpa.py` | via `hcxdumptool` |
| **WiFi WPS Pixie Dust** | Completo (MASTER_PLAN S1.3) | **Real** | `src/urban_hs/modules/wifi/attacks/wps.py:1-150+` | `reaver -K 1` integration |
| **WiFi WPS PIN Attack** | Completo (MASTER_PLAN S1.4) | **Real** | `src/urban_hs/modules/wifi/attacks/wps.py` | Common PINs DB por OUI |
| **WiFi Deauth Attack** | Completo (MASTER_PLAN S1.5) | **Real** | `src/urban_hs/modules/wifi/attacks/deauth.py:1-100+` | `aireplay-ng` targeted/broadcast |
| **WiFi FragAttacks** | Completo (MASTER_PLAN S4.11) | **Real** | `src/urban_hs/modules/wifi/fragattacks.py:1-250+` | Wrapper ferramenta Vanhoef |
| **WiFi MAC Changer** | Completo (MASTER_PLAN S1.6) | **Real** | `src/urban_hs/modules/wifi/managers.py` | OUI profiles, randomization |
| **WiFi GeoMac/GPS** | Completo (MASTER_PLAN S1.7) | **Real** | `src/urban_hs/modules/wifi/managers.py` | GPS correlaciona scan com lat/lon |
| **BLE FastPair Scanner** | Completo (MASTER_PLAN S2.1) | **Real** | `src/urban_hs/modules/ble/fastpair.py` | Bleak scanner, 0xFE2C UUID parse |
| **BLE WhisperPair Tester** | Completo (MASTER_PLAN S2.2) | **Real** | `src/urban_hs/modules/ble/whisperpair_tester.py` | GATT connect -> KBP request -> analyze response |
| **BLE WhisperPair Exploit Chain** | Parcial (MASTER_PLAN S2.3) | **Stub/parcial** | `src/urban_hs/modules/ble/plugin.py:264` | TODO: "Full exploit chain requires BlueZ D-Bus integration" |
| **BLE HFP Audio** | Pendente (MASTER_PLAN S2.6) | **Stub/parcial** | `src/urban_hs/modules/ble/hfp.py` | Requer `bluealsa`/BlueZ, estrutura criada |
| **Network Scanner (Nmap)** | Completo (MASTER_PLAN S3.1) | **Real** | `src/urban_hs/modules/network/scanner.py` | Async Nmap wrapper, XML parsing |
| **Network Nuclei Runner** | Completo (MASTER_PLAN S3.2) | **Real** | `src/urban_hs/modules/network/nuclei.py` | Template execution, JSONL parsing |
| **Network SearchSploit** | Estrutura (MASTER_PLAN S3.3) | **Stub/parcial** | `src/urban_hs/modules/network/searchsploit.py` | `searchsploit -j` nao instalado no sistema |
| **Network RouterSploit** | Estrutura (MASTER_PLAN S3.4) | **Stub/parcial** | `src/urban_hs/modules/network/router.py` | RouterSploit nao instalado, stub com script temporario |
| **Camera Discovery** | Completo (MASTER_PLAN S3.5) | **Real** | `src/urban_hs/modules/network/camera.py` | mDNS, UPnP, ONVIF, RTSP, HTTP fingerprint |
| **Camera Enumeration** | Estrutura (MASTER_PLAN S3.6) | **Stub/parcial** | `src/urban_hs/modules/camera/enumeration.py` | Estrutura criada, precisa validacao real |
| **Camera Vuln Check** | Estrutura (MASTER_PLAN S3.7) | **Stub/parcial** | `src/urban_hs/modules/camera/vuln_check.py` | CVE mapping, estrutura criada |
| **Metasploit RPC Client** | Completo (MASTER_PLAN S4.3) | **Real** | `src/urban_hs/modules/metasploit/rpc.py:1-635` | `msgrpc` connection, module exec, session mgmt |
| **Metasploit Console** | Completo (MASTER_PLAN S4.4) | **Real** | `src/urban_hs/modules/metasploit/console.py` | `msfconsole -r script.rc` via process_mgr |
| **Exploit Runner Generic** | Completo (MASTER_PLAN S4.5) | **Real** | `src/urban_hs/modules/exploit/runner.py` | Nuclei/Metasploit/SearchSploit/local, proof collection |
| **Credential Manager** | Completo (MASTER_PLAN S4.6) | **Real** | `src/urban_hs/modules/credential/manager.py` | Normalizacao, dedup, hashcat integration |
| **Reporting Generator** | Completo (MASTER_PLAN S4.7) | **Real** | `src/urban_hs/modules/reporting/generator.py` | Jinja2 -> Markdown/HTML/PDF |
| **GPG Evidence Signing** | Completo (MASTER_PLAN S4.8) | **Real** | `src/urban_hs/modules/reporting/gpg_evidence.py` | `gpg --detach-sign --armor` |
| **HID Duckyscript Parser** | Completo (MASTER_PLAN S5.1) | **Real** | `src/urban_hs/modules/hid/ducky.py` | Parser Hak5 v1/v3, 7 layouts |
| **HID Injector** | Completo (MASTER_PLAN S5.2) | **Real** | `src/urban_hs/modules/hid/injector.py` | `uinput` + `usb-gadget` |
| **USB Gadget Manager** | Completo (MASTER_PLAN S5.3) | **Real** | `src/urban_hs/modules/hid/gadget.py` | configfs profiles: HID, mass-storage, RNDIS |
| **MQTT Attack Suite** | Completo (MASTER_PLAN S4.15) | **Real** | `src/urban_hs/modules/mqtt.py` | Broker discovery, topic enum, cred brute |
| **ESP32 Fingerprinting** | Completo (MASTER_PLAN S4.18) | **Real** | `src/urban_hs/modules/esp32.py` | 29 comandos HCI nao documentados |
| **SSID Confusion** | Completo (MASTER_PLAN S4.17) | **Real** | `src/urban_hs/modules/ssid_confusion.py` | Downgrade 5GHz->2.4GHz |
| **Bluetooth HID Keystroke** | Completo (MASTER_PLAN S4.9) | **Real** | `src/urban_hs/modules/bt_hid.py` | CVE-2023-45866 + CVE-2024-21306 |
| **Kr00k** | Completo (MASTER_PLAN S4.10) | **Real** | `src/urban_hs/modules/wifi/attacks/` | CVE-2019-15126, captura frames all-zero |
| **Auth (JWT Bearer)** | Completo (docs/PLAN Sprint 8A) | **Real** | `src/urban_hs/ui/api/auth.py` | JWT-based Bearer token authentication |
| **WebSocket Events** | Completo (docs/PLAN Sprint 2) | **Real** | `src/urban_hs/ui/api/routers/events.py` | `/api/v1/events` com JWT auth |
| **FastAPI Backend** | Completo (docs/PLAN Sprint 5) | **Real** | `src/urban_hs/ui/api/main.py` | REST CRUD + WebSocket, auth, RBAC |
| **Textual TUI** | Completo (docs/PLAN Sprint 5) | **Real** | `src/urban_hs/ui/tui/app.py` | Dashboard terminal com tabs, attack buttons |
| **Rich CLI** | Completo (docs/PLAN Sprint 5) | **Real** | `src/urban_hs/cli/main.py` | Comandos: `scan`, `attack`, `exploit`, `report` |
| **Web UI (HTML/JS)** | Completo (docs/PLAN Sprint 5) | **Real** | `src/urban_hs/ui/web/index.html` | HTMX + Alpine panel, attack buttons |
| **Rate Limiting (Middleware Global)** | Completo (docs/PLAN Sprint 8A) | **Real** | `src/urban_hs/ui/api/middleware.py` | Token-bucket style, 120 req/min default |
| **Rate Limiting (Decorator por endpoint)** | Completo (docs/PLAN Sprint 8A) | **Real** | `src/urban_hs/ui/api/rate_limit.py` + `main.py:57,128` | slowapi Limiter instance |
| **SessionScope** | Completo (docs/PLAN Sprint 8A) | **Real** | `src/urban_hs/core/session_scope.py` | Allowlist + categorias, 4 pontos confirmados |
| **Chroot Process Manager** | Completo (MASTER_PLAN S4.2) | **Real** | `src/urban_hs/core/chroot_process.py` | nsenter/chroot, bind mounts, resource limits |
| **Bettercap BLE** | Completo (docs/PLAN Sprint 6) | **Real** | `src/urban_hs/modules/ble/bettercap.py` | BLE/GATT enumeration via REST API |

---

## 2. GUARD RAILS DE SEGURANCA — Estado Atual (2026-07-01)

### Confirmacao dos 4 pontos de execucao de ataque (SessionScope)

Os 4 pontos confirmados funcionais:

1. **REST attacks router** (`src/urban_hs/ui/api/routers/attacks.py:52`)
   - `get_active_scope().validate(...)` antes de executar

2. **WiFi plugin event handler** (`src/urban_hs/modules/wifi/plugin.py:397`)
   - `get_active_scope().validate(bssid, "wifi")`

3. **BLE plugin event handler** (`src/urban_hs/modules/ble/plugin.py:253`)
   - `get_active_scope().validate(address, "ble")`

4. **Urban Hack plugin event handler** (`src/urban_hs/modules/urban_hack.py:520,634`)
   - `validate(bssid, "wifi")` + `validate(address, "ble")`

### Autenticacao WebSocket/REST

- **JWT Bearer Auth** (`src/urban_hs/ui/api/auth.py:75-93`): `verify_bearer` dependency, decode JWT
- **WebSocket JWT Auth** (`src/urban_hs/ui/api/routers/events.py:84-92`): `_extract_ws_token` + `decode_access_token`
- **REST Endpoint Auth** (`src/urban_hs/ui/api/auth.py:96-97`): `require_auth()` dependency

### Rate Limiting (duas camadas)

- **Middleware Global** (`src/urban_hs/ui/api/middleware.py:58-88`): Token-bucket, 120 req/min default
- **Decorator por Endpoint** (`src/urban_hs/ui/api/rate_limit.py:1-13` + `main.py:57,128`): slowapi Limiter instance, coexiste com middleware

### QUINTO CAMINHO DE EXECUCAO DE ATAQUE DETETADO

**PRIORITARIO — Gap critico de seguranca:**

- **Local**: `src/urban_hs/modules/bt_hid.py:691-698`
- **Funcao**: `run_attack(target_mac: str, payload: Optional[Dict] = None)`
- **Caminho**: Chama diretamente `BluetoothHIDAttacker.run_full_attack()` **SEM** validacao SessionScope
- **Impacto**: BT HID attacks (CVE-2023-45866, CVE-2024-21306) podem ser executados **sem verificacao de allowlist**

**Codigo problematico:**
```python
async def run_attack(
    target_mac: str, payload: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Convenience function to run a BT HID attack."""
    attacker = BluetoothHIDAttacker(target_mac=target_mac)
    return await attacker.run_full_attack(payload=payload)
```

**Este e o QUINTO CAMINHO que nao passa por SessionScope.**
Os 4 pontos confirmados nas auditorias anteriores sao os listados acima.
Este quinto caminho (bt_hid.py) e **CRITICO** e deve ser corrigido IMEDIATAMENTE.

---

## 3. DIVIDA TECNICA CONHECIDA — Confirmacao de Estado Atual

| **Item** | **Estado** | **Local** | **Prova** |
|---|---|---|---|
| **Bug TUI: `_publish_attack` envia `{attack, params}` mas handlers leem `type`/`bssid`** | **AINDA EXISTE** | `src/urban_hs/ui/tui/app.py:283-301` | Event payload tem `{"attack": "wifi_deauth", "params": {"count": 10}}` mas handlers esperam `type` e `bssid` |
| **`pyproject.toml` declara `dbus-fast` mas codigo usa `dbus` (C-ext)** | **CONFIRMADO** | `pyproject.toml:45` vs `modules/ble/exploit_chain.py:17` | `import dbus` (C-ext) usado no exploit_chain.py |
| **`msfinstall` (script untracked)** | **CONFIRMADO FORA DO GIT** | `./msfinstall` | `git status --short` mostra `?? msfinstall` |
| **pasta `audit/` (relatorios de agentes)** | **CONFIRMADA FORA DO GIT** | `./audit/` | `git status --short` mostra `?? audit/` |

---

## 4. PROXIMAS FASES SEGUNDO OS PLANOS (Citacao Literal)

### Do `docs/PLAN.md` (Sprint 10):

> **Sprint 10 — Testing Hardening + Coverage Enforcement**
>
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

### Do `docs/PLAN.md` (Sprint 11-12):

> **Sprint 11 — Web UI Maps, PWA, Offline**
>
> **Objective**: Complete the GPS/geolocation visualisation in the web frontend.
>
> Tasks:
> 1. Leaflet.js integration for interactive maps.
> 2. Real-time GPS position updates via WebSocket.
> 3. PWA manifest + service worker for offline use.
> 4. Wardrive session replay (KML/WiGLE import).

> **Sprint 12 — Plugin Marketplace**
>
> **Objective**: Lower the barrier for others to write and share modules.
>
> Tasks:
> 1. Plugin metadata manifest (`pyproject.toml` `urban-hs.plugins` entry points).
> 2. `urban-hs plugin install <name>` from a registry (local directory or remote Git).
> 3. Signature verification for plugins.
> 4. Module skeleton generator (`urban-hs plugin new <name`).

### Do `MASTER_PLAN.md` (Sprint 6):

> **Sprint 6 — Polish / OTIMIZACAO / HARDENING (Semanas 12-13)**
>
> | Task ID | Descricao | Esforco |
> |---------|-----------|---------|
> | S6.1 | **Concurrency Tuning** — Semaphoros por recurso (radio, chroot, GPU), backpressure event bus, task prioritization |
> | S6.2 | **Memory Profiling** — `memray`/`objgraph`, fix leaks, streaming parsers para large outputs |
> | S6.3 | **SQLite Optimization** — Indices compostos, `PRAGMA optimize`, vacuum schedule, WAL checkpoint |
> | S6.4 | **Security Hardening** — Seccomp profiles, capability dropping, rootless chroot (user namespaces), GPG supply chain (cosign) |
> | S6.5 | **Documentation** — MkDocs + docstrings, architecture diagrams (Mermaid), API reference, user guide |
> | S6.6 | **E2E Tests** — `pytest-asyncio` + `mac80211_hwsim` + mock BlueZ + testcontainers para chroot |
> | S6.7 | **Release Automation** — `cargo-dist` style: version bump, changelog, Docker multi-arch (ARM64/AMD64), SBOM (Syft), cosign sign |

---

## RESUMO EXECUTIVO

### Estado Geral do Projeto

- **~85% dos modulos declarados como "Completo" nos planos tem implementacao REAL confirmada no codigo**
- **~10% dos modulos sao Stub/parcial** (principalmente BLE HFP Audio, Camera Enumeration/Vuln Check, SearchSploit, RouterSploit)
- **~5% dos modulos sao ausentes ou requerem hardware especifico** (KNOB/BIAS/BLUFFS, SweynTooth, TPMS, etc.)

### Guard Rails

- **SessionScope**: 4/4 pontos confirmados funcionais
- **Auth WebSocket/REST**: Confirmada em ambos os caminhos
- **Rate Limiting**: Duas camadas confirmadas coexistentes sem conflito
- **QUINTO CAMINHO CRITICO**: `bt_hid.py:run_attack()` nao usa SessionScope - **deve ser corrigido IMEDIATAMENTE**

### Divida Tecnica

- Bug TUI: **ainda existe** e impede execucao real via TUI
- dbus-fast vs dbus: **inconsistencia confirmada** entre dependencias
- msfinstall e pasta audit: **fora do controlo de versao confirmado**

---

**NOTA FINAL**: Este relatorio e baseado UNICAMENTE na analise do codigo-fonte atual (commit 6055087fe80c7f5df126337a2eae6580a2880f10). Nao foram considerados quaisquer outros relatorios de outros agentes em `inventario/`.
