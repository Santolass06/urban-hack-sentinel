# Inventário de Estado — urban-hack-sentinel

- **Agente**: Cline
- **Timestamp**: 2026-07-01T14:01:52Z (análise); relatório escrito pouco depois
- **Commit HEAD analisado**: `6055087fe80c7f5df126337a2eae6580a2880f10` (`fix: close SessionScope bypass on event-bus attack path + related fixes`)
- **Ramo**: `andreas/catarinus`
- **Método**: leitura direta do código-fonte em `src/urban_hs/` + `tests/`, planos `.md`, e `git`/`grep`. Não li nem citei nenhum outro ficheiro em `inventario/`.

> Estado dos testes na sessão (snapshot, sem hardware, ignorando `test_ble_module.py` + `test_e2e.py`):
> `pytest tests/ -q` → **165 passed, 3 failed, 7 warnings** em ~10s.
> As 3 falhas são `tests/test_wifi_plugin_contract.py::{test_initialize_plugin, test_start_then_stop, test_attack_execution}` — falham em `plugin.initialize()` ao tentar `mkdir /var/lib/urban-hs` (PermissionError ambiental, sem root). Pré-existentes e já documentadas em `docs/CORRECAO_SESSIONSCOPE_2026-07-01.md`.

---

## ⚠️ PRIORIDADE — QUINTO caminho de execução de ataque que NÃO passa por SessionScope

Encontrei um caminho de execução **ativa** contra um alvo BLE que **não tem guard SessionScope**, ao contrário dos 4 caminhos de ataque já cobertos (wifi/plugin, ble/plugin-exploit, urban_hack ×2) e do endpoint REST. **Isto é novo relativamente às auditorias anteriores.**

### Caminho: `ble.test_request` → teste de vulnerabilidade WhisperPair (GATT write ativo)

O evento `ble.test_request` é subscrito por **dois** handlers que ambos chamam `WhisperPairTester.test_device(address)`, o qual faz uma **escrita GATT real** num dispositivo que **não está em modo de emparelhamento** — precisamente o primitivo do CVE-2025-36911 (Key-Based Pairing bypass):

1. **`src/urban_hs/modules/ble/plugin.py`** — `BLEEventHandler` subscreve `ble.test_request` (linha 174, 181-182) → `_handle_test_request` (linha 214) → `self.plugin.test_vulnerability(address)` (linha 222) → `WhisperPairTester.test_device` (linha 162).
2. **`src/urban_hs/modules/urban_hack.py`** — `UrbanHackEventHandler` subscreve `ble.test_request` (linha 470, 483-484) → `_handle_ble_test` (linha 599) → `execute_ble_vuln_test(address)` (linha 606) → `self.ble_tester.test_device(address)` (linha 455).

Execução real confirmada em **`src/urban_hs/modules/ble/fastpair.py`**:
- `WhisperPairTester.test_device` (linha 154): `async with BleakClient(address, adapter=self.adapter) as client:` (linha 163)
- `await client.write_gatt_char(kbp_char, request, response=True)` (linha 199) — **escrita GATT ativa** ao alvo.

**Nenhum destes dois handlers chama `get_active_scope().validate(...)`** (verificado: ausência total de `session_scope`/`get_active_scope` em `_handle_test_request` e `_handle_ble_test`). O guard só existe nos handlers de **exploit** (`ble.exploit_request`), não nos de **teste**.

### Por que é um caminho de "ataque" e não apenas um scan
- Não é passivo: abre uma ligação GATT e **escreve** num characteristic (KBP) num dispositivo fora do modo de emparelhamento.
- É o **mesmo primitivo** do exploit completo; a única diferença semântica é que o "teste" para após a primeira estratégia em vez de encadear bonding/account-key/HFP.
- Um operador que configurasse `SessionScope` para restringir alvos **esperaria** que esta interação ativa fosse guardada. **Não é.**

### Acessibilidade do caminho
- O event bus é público a qualquer publicador. O TUI hoje **não** publica `ble.test_request` (publica `ble.attack_request`, que não tem handler — ver dívida técnica), mas qualquer subscritor/ferramenta externa pode publicar `ble.test_request` e desencadear a escrita GATT sem passar pelo guard.
- Não há endpoint REST direto para `/ble/test` (o router `ble.py` só expõe `/scan` e `/jobs/{id}`), pelo que o vetor primário é o event bus.

> **Nota de classificação**: se a intenção do projeto for tratar o "vuln test" como operação **não-ataque** (scan passivo), isso é uma decisão do André. Reporto apenas o facto: é uma execução ativa contra o alvo, sem guard, alcançável via event bus, enquanto o exploit semelhante já tem guard. A assimetria é real.

---

## 1. Tabela feature → estado real

Legenda: **Real** = lógica de execução real confirmada · **Stub/parcial** = estrutura existe mas `TODO`/`not_implemented`/fallback · **Ausente** = não encontrado · **Desatualizado no plano** = código diverge do que o plano declara.

### WiFi

| Feature | Estado | Prova (ficheiro:linha) |
|---|---|---|
| Scan (passive/active, channel hopping) | **Real** | `modules/wifi/scanner.py:96` `IWScanBackend` (`iw dev … scan -f json` subprocess); `AirodumpScanBackend` (airodump-ng CSV parse); `ScapyScanBackend` fallback (`hal/wifi/__init__.py:98` AsyncSniffer). `WiFiScanner` facade `scanner.py:524` |
| Deauth | **Real** | `modules/wifi/attacks/deauth.py:65-85` `aireplay-ng -0 …` via `asyncio.create_subprocess_exec` |
| WPS Pixie Dust | **Real** | `modules/wifi/attacks/wps.py:64-88` `reaver -K 1` subprocess + parse de PIN/PSK |
| WPS PIN (dicionário/OUI) | **Real** | `modules/wifi/attacks/wps.py:176-214` loop de PINs com `reaver -p <pin>` subprocess |
| Handshake capture | **Real** | `modules/wifi/attacks/wpa.py:68-101` airodump-ng + aireplay-ng deauth subprocess, espera de handshake |
| PMKID | **Real** | `modules/wifi/attacks/wpa.py:188-220` `hcxdumptool` + `hcxpcapngtool` (conversão .22000) subprocess |
| FragAttacks (CVE-2020-24586/7/8) | **Real (parcial)** | `modules/wifi/fragattacks.py:258` subprocess a `fragattacks.py`; parse de vulnerabilidade real (`_parse_result:334`). `affected_frames=0  # TODO: parse from output` (linha 290) — métrica não parseada. `scan_fragattacks_targets()` (linha 353) retorna `[]` (stub auxiliar) |
| MAC Changer / HandshakeMgr / GeoMapper | **Real** | `modules/wifi/managers.py:393-399` `subprocess.run(["ip","link",…], ["macchanger",…])`; `managers.py:367` subprocess (crack/hashcat) |
| Plugin (event handler) | **Real + guard** | `modules/wifi/plugin.py:_handle_attack_request` chama `get_active_scope().validate(bssid,"wifi")` (guard) antes de `execute_*` |

### BLE

| Feature | Estado | Prova (ficheiro:linha) |
|---|---|---|
| Scan (Fast Pair, 0xFE2C) | **Real** | `modules/ble/fastpair.py:43-84` `BleakScanner` + `detection_callback`; parse de advertisement Fast Pair (`_parse_fast_pair_advertisement:94`) |
| WhisperPair **teste** (CVE-2025-36911 KBP) | **Real mas SEM guard** | `modules/ble/fastpair.py:154-199` `BleakClient` + `write_gatt_char` (escrita ativa). Handlers `ble/plugin.py:214` e `urban_hack.py:599` **sem** SessionScope — **ver secção PRIORIDADE acima** |
| WhisperPair **exploit chain** (KBP→bonding→account key→HFP) | **Stub/parcial** | Código da cadeia existe em `modules/ble/exploit_chain.py` (`BlueZBondingManager`, `AccountKeyManager`, `HFPAudioCapture`, `WhisperPairFullExploit` ~linha 540-628) usando `dbus` C-ext. **MAS** os handlers que o orquestram devolvem `{"status":"not_implemented"}`: `ble/plugin.py:264` (`# TODO: Implement full exploit chain`) e `urban_hack.py:645`. O `WhisperPairExploit.exploit_with_audio` (`fastpair.py:432`) faz só o bypass KBP e retorna `"kbp_bypassed"` sem bonding/account-key/HFP. → **a cadeia completa não está ligada ao caminho de execução** |
| BlueZ backend (HAL) | **Real** | `hal/ble/__init__.py:94-111` usa `dbus_fast` (MessageBus BusType); fallback gracioso se indisponível |
| HFP audio | **Real (não ligado)** | `modules/ble/hfp.py` existe; `HFPAudioCapture` em `exploit_chain.py`. Só é invocado pela classe `WhisperPairFullExploit` que **não** é chamada pelos handlers do plugin |

### Network

| Feature | Estado | Prova (ficheiro:linha) |
|---|---|---|
| Nmap / host discovery | **Real** | `modules/network/scanner.py:77-160` constrói cmd nmap, `asyncio.create_subprocess_exec`, parse XML (`_parse_host_element:162`); valida alvos com `ipaddress` |
| Nuclei | **Real** | `modules/network/nuclei.py` (referenciado por `NetworkModule:1076`); `NetworkModule.full_network_assessment:1084` chama `self.nuclei.scan(...)` |
| SearchSploit | **Real** | `modules/network/searchsploit.py:34` `searchsploit -j` subprocess; `get_exploit:59` `searchsploit -m` |
| RouterSploit / Hydra (router scan) | **Real** | `modules/network/router.py` (`RouterScanner`, via `NetworkModule:1078`); paths configuráveis |
| Camera discovery (mDNS/UPnP/ONVIF/RTSP/HTTP) | **Real** | `modules/network/camera.py` `CameraDiscovery` (aiohttp + HTTP fingerprint, `network/__init__.py:1041-1055`); `NetworkModule:1082` |
| `NetworkModule` (fachada) | **Real** | `modules/network/__init__.py:1064` integra nmap+nuclei+searchsploit+router+camera |

### Metasploit / SearchSploit integration

| Feature | Estado | Prova (ficheiro:linha) |
|---|---|---|
| MSF RPC (msgrpc, MessagePack) | **Real** | `modules/metasploit/rpc.py:202` `_call` → `msgpack.packb` (linha 216) + `aiohttp.ClientSession` POST (linha 158) + `msgpack.unpackb` (linha 228); auth, module search/exec, session mgmt, console, db.* — cliente completo (~635 LOC) |
| MSF Console (msfconsole + .rc) | **Real** | `modules/metasploit/console.py:91` `execute_rc_script` → `asyncio.create_subprocess_exec("msfconsole","-r",…)`; templates de RC scripts (port_scan, vuln_scan, smb_enum, brute, exploit_chain) |
| SearchSploit (no Exploit Runner) | **Real** | `modules/exploit/runner.py` importa `SearchSploitIntegration`; fonte `SEARCHSPLOIT` |

### HID

| Feature | Estado | Prova (ficheiro:linha) |
|---|---|---|
| uinput injector (local) | **Real** | `modules/hid/injector.py:19-23` `import uinput`; `UInputInjector.start:91` cria device uinput; `type_string`, `key_press` reais |
| USB gadget HID (configfs) | **Real** | `modules/hid/gadget.py:110` `USBGadgetManager` escreve em `/sys/kernel/config/usb_gadget` (configfs); `HIDReportDescriptors` (~linha 548) descriptors keyboard/mouse reais |
| DuckyScript parser (v1/v3, 7 layouts) | **Real** | `modules/hid/ducky.py` `DuckyParser`, `KeyMapper` (US/GB/DE/FR/ES/IT/RU), `DuckyEncoder.encode_to_hid`; CLI `main:607` |
| HIDInjector.execute_ducky | **Real** | `modules/hid/injector.py:494-526` compila + envia HID reports ao endpoint do injector ativo |

### MQTT

| Feature | Estado | Prova (ficheiro:linha) |
|---|---|---|
| Broker discovery / unauth / topic enum / cred brute / injection / flood | **Real** | `modules/mqtt.py:26-31` `paho.mqtt.client`; `MQTTAttackSuite` (739 LOC); usa `NmapScanner` para discovery; `MQTTAttackType` enum com 8 tipos |

### ESP32

| Feature | Estado | Prova (ficheiro:linha) |
|---|---|---|
| Detecção passiva (OUI/mDNS/HTTP/BLE) | **Real** | `modules/esp32.py:64-100` OUIs Espressif; `ESP32Detector.run_full_detection`; `detect_from_ble_scan` integra `FastPairScanner` |
| CVE-2025-27840 HCI commands | **Parcial** | `ESP32AttackPlanner.execute_hci_command` (~linha 680) envia HCI via adapter; `plan_attacks:699` retorna **lista recomendada** de ataques (não executa automaticamente). Detecção real, "ataque" = planificação + comando HCI envocável |

### Camera enumeration

| Feature | Estado | Prova (ficheiro:linha) |
|---|---|---|
| Auth test / default creds / config dump / firmware / ONVIF / RTSP | **Real** | `modules/camera/enumeration.py:28-32` aiohttp; `CameraEnumerator` (linha 216) com `_get_session`, `test_auth` (Basic/Digest), `enumerate_camera:654`; `vuln_check.py` `CameraVulnChecker` + `DEFAULT_CVE_DB` |

### Credential Manager

| Feature | Estado | Prova (ficheiro:linha) |
|---|---|---|
| Normalização / dedup / index / save-load | **Real** | `modules/credential/manager.py` `CredentialManager`, `CredentialSet`; `deduplicate:~790`; `save_state:836` / `load_state:849` |
| Hashcat integration (crack) | **Real** | `manager.py:580` `crack_hashes` → `asyncio.create_subprocess_exec(self.hashcat_path,…)` (linha 652); `hashcat_modes` (linha 228); `import_from_hashcat_potfile:307` |
| Validação de creds (nxc/nmap/curl/hydra) | **Real** | `manager.py:466,491,516,539,570` `subprocess.run(...)` para validar credenciais |
| Export hashcat | **Real** | `manager.py:706` `export_to_hashcat` |

### Exploit Runner

| Feature | Estado | Prova (ficheiro:linha) |
|---|---|---|
| Execução unificada (nuclei/MSF RPC/MSF console/searchsploit/local) | **Real** | `modules/exploit/runner.py:26-31` importa `MetasploitConsole`, `MetasploitRPC`, `NucleiRunner`, `SearchSploitIntegration`; `ExploitSource` enum (linha 36); `execute` despacha por fonte; `_execute_local` (~linha 590) usa `ChrootProcessManager` |
| Proof collection / artifacts / batch | **Real** | `ExploitProof`, `ExploitResult`; `execute_batch:642` `asyncio.gather` |

### Reporting (GPG-signed)

| Feature | Estado | Prova (ficheiro:linha) |
|---|---|---|
| Gerador Markdown/HTML/PDF/JSON | **Real** | `modules/reporting/generator.py:27-36` Jinja2 + WeasyPrint (com flags `*_AVAILABLE`); `generate:284`; escreve ficheiros (linha 431, 463, 725); `HTML(filename=…)` WeasyPrint (linha 650) |
| GPG signing (detached) | **Real** | `generator.py:38-42` `gnupg`; `modules/reporting/gpg_evidence.py:23-30` `GPGSigner`; assinatura detach + verify (~linha 610) |
| Chain of custody / evidence log | **Real** | `gpg_evidence.py` `ChainOfCustody`, `EvidenceLogger`, `ChainOfCustodyManager.verify_integrity`; `create_gpg_key:638`, `verify_gpg_signature:667` |
| Finding templates (CVEs) | **Real** | `generator.py` `FindingTemplates` (fragattacks, whisperpair, ssid_confusion, bt_hid, kr00k) |

### SessionScope (allowlist + categorias)

| Feature | Estado | Prova (ficheiro:linha) |
|---|---|---|
| Singleton + validate + guard rails | **Real** | `core/session_scope.py:110` `_active_scope` singleton; `get_active_scope:113` / `set_active_scope:118`; `validate:68` (PermissionError humano); scope vazio bloqueia tudo |
| Guards nos 4 caminhos de ataque | **Real** | `wifi/plugin.py` (guard wifi), `ble/plugin.py:253` (guard ble-exploit), `urban_hack.py:520` (wifi), `urban_hack.py:634` (ble-exploit) |
| **5º caminho sem guard** | **Confirmado** | `ble.test_request` → `ble/plugin.py:214` e `urban_hack.py:599` **sem** `validate` — ver secção PRIORIDADE |

### Auth (JWT, Bearer middleware)

| Feature | Estado | Prova (ficheiro:linha) |
|---|---|---|
| JWT create/decode + segredo persistido | **Real** | `ui/api/auth.py:26` `_load_or_create_secret` (persiste `~/.config/urban-hs/jwt_secret` 0600); `create_access_token:54`, `decode_access_token:70` |
| Bearer dependency | **Real** | `auth.py:75` `verify_bearer`; `require_auth:96`. Todos os routers: `attacks.py:38`, `wifi.py:22`, `ble.py:21`, `network.py:21` usam `APIRouter(dependencies=[require_auth()])`; `system.py:19` por-endpoint |
| WebSocket auth (Bearer header + `?token=`) | **Real** | `ui/api/routers/events.py:72` `_extract_ws_token`; `websocket_events:80` valida JWT, fecha `WS_1008_POLICY_VIOLATION` se inválido |

### Rate limiting

| Feature | Estado | Prova (ficheiro:linha) |
|---|---|---|
| Camada global (middleware) | **Real** | `ui/api/middleware.py:58` `RateLimitMiddleware` (token-bucket per IP, 429) |
| Camada por-endpoint (slowapi) | **Real** | `ui/api/rate_limit.py:13` `Limiter`; decorators `@limiter.limit("10/minute")` em `attacks.py:120`, `wifi.py:52`, `ble.py:25`, `network.py:25` |
| Coexistência sem conflito | **Real** | middleware (global, backstop) + slowapi (10/min escrita) — composição monótona "mais restritivo ganha" |

### WebSocket de eventos (`/api/v1/events`)

| Feature | Estado | Prova (ficheiro:linha) |
|---|---|---|
| Stream em tempo real + broadcast | **Real** | `ui/api/routers/events.py:21` `WebSocketConnectionManager`; `WebSocketEventHandler` (linha 53) subscreve `"*"` e faz broadcast `{type,payload,timestamp,correlation_id,source}` |
| Auth JWT | **Real** | ver acima |

### Web UI

| Feature | Estado | Prova (ficheiro:linha) |
|---|---|---|
| Servir frontend | **Real** | `ui/web/index.html` (17 KB) servido pela app; **HTML vanilla + HTMX 1.9.10 + Alpine 3.x** (linhas 7-8), **não React** |
| Painéis WiFi/BLE/Network | **Real** | `fetch(...)` (linha 228), `WebSocket` (linha 390); secção Network adicionada (commit `cdb89ff`) |
| Auth UI (token) | **Real** | `fetch(API + '/auth/token')` (linha 206) |
| PWA / Leaflet map / offline | **Ausente** | sem service worker, sem Leaflet, sem manifest — `MASTER_PLAN.md` descreve "React PWA" (divergência) |
| Reconnect WS / indicador estado WS | **Ausente** | sem lógica de reconexão nem indicador ligado/desligado (já registado em `docs/SESSAO_AUTONOMA_2026-07-01.md`) |

> **Desatualizado no plano**: `MASTER_PLAN.md` Sprint 5 descreve "React PWA frontend"; o código é HTML vanilla + HTMX/Alpine. `docs/SESSAO_AUTONOMA_2026-07-01.md` já tinha registado a decisão de manter HTML vanilla.

### TUI

| Feature | Estado | Prova (ficheiro:linha) |
|---|---|---|
| App Textual (tabs WiFi/BLE/Network/System) | **Real** | `ui/tui/app.py:77` `TUIApp`; `compose:106` com `TabbedContent`/`TabPane`; `Header`, `Footer`, `RichLog`, `DataTable` |
| Scan WiFi/BLE/Network direto | **Real** | `_wifi_scan:303` chama `WiFiScanner.scan` diretamente (não via bus); `_ble_scan:335` `FastPairScanner`; `_network_scan:359` `NetworkModule.nmap.scan` |
| Confirm modal | **Real** | `ConfirmModal:57` + `_confirm:257` |
| **Botões de ataque (execução via bus)** | **STUB/quebrado** | `_publish_attack:283` publica `Event(type=f"{category}.attack_request", payload={"attack": attack, "params": params})` (linha 292-300). Handlers leem `payload.get("type")`/`payload.get("bssid")` (`urban_hack.py:512-513`, `wifi/plugin.py:_handle_attack_request`) — **payload mismatch** → `attack_type=None`, `bssid=None` → handlers retornam sem executar. Ver dívida técnica. |
| BLE via TUI | **Duplamente quebrado** | `_ble_whisperpair` → `_publish_attack("ble_whisperpair",{})` → categoria `"ble"` → publica `ble.attack_request`, mas **nenhum handler** subscreve `ble.attack_request` (handlers querem `ble.exploit_request`/`ble.test_request`) |

### CLI

| Feature | Estado | Prova (ficheiro:linha) |
|---|---|---|
| `info`, `run`, `modules`, `verify`, `audit-trail` | **Real** | `cli/main.py`: `info:41`, `run:75` (init_core + signal handlers), `modules`, `verify` (valida sha256/blake2b + custody, linha 192-220), `audit-trail:236` (timeline custody) |
| `seal` | **Stub** | `cli/main.py:223` `seal_session` imprime "Seal is not yet implemented …" — não faz nada |
| `scan`, `attack`, `exploit`, `report`, `export`, `config` | **Ausente** | `docs/PLAN.md` Sprint 1 declara "Rich CLI (`scan`, `attack`, `exploit`, `report`, `export`, `config`)" mas **não existem** no `cli/main.py` — **Desatualizado no plano** |

### Outros módulos no registry

| Feature | Estado | Prova (ficheiro:linha) |
|---|---|---|
| SSID Confusion (CVE-2023-52424) — detector + Evil Twin | **Real** | `modules/ssid_confusion.py:75` `SSIDConfusionDetector.scan_networks:100` (airodump); `analyze_confusion:157`; `run_evil_twin_attack:292` → `asyncio.create_subprocess_exec("hostapd", conf)` (linha 359) + `_generate_hostapd_config:421`; `stop_evil_twin_attack:400` |
| Bluetooth HID (CVE-2023-45866) | **Real** | `modules/bt_hid.py:28-30` `dbus_fast`; `BlueZHIDProfile`, `BTHIDAttacker.run_full_attack`, `BTHIDScanner.scan:624` (BlueZ ObjectManager) |
| Example plugins (sniffer/reporter) | **Stub (referência)** | `modules/plugins/example_sniffer.py:22` "Passive sniffer placeholder"; `example_reporter.py:22` "Minimal reporter placeholder". **Removidos do registry** (`modules/__init__.py:26-41` não os lista); ficheiros `.py` mantidos como referência |

---

## 2. Guard rails (ponto 3 — relato do estado atual confirmado nesta sessão)

> Não reavaliado do zero; confirmado por leitura do código no commit `6055087`.

- **SessionScope — 4 pontos de execução de ataque cobertos**: confirmado via `get_active_scope().validate(...)` em `wifi/plugin.py` (guard wifi), `ble/plugin.py:253` (guard ble-exploit), `urban_hack.py:520` (wifi), `urban_hack.py:634` (ble-exploit). O endpoint REST `attacks.py` valida via `get_session_scope()` que delega no mesmo singleton (`core/session_scope.py:113`). Singleton partilhado em `core` (camada mais baixa) para evitar import circular — confirmado.
- **⚠️ QUINTO caminho sem guard — ver secção PRIORIDADE no topo**: `ble.test_request` (2 handlers) faz escrita GATT ativa sem `validate`.
- **Auth WebSocket/REST**: confirmada. REST: `require_auth()` em todos os routers. WebSocket: `events.py:80` valida JWT (Bearer header ou `?token=`), fecha `WS_1008_POLICY_VIOLATION` se inválido.
- **Rate limiting — duas camadas coexistentes**: confirmado. Middleware global `RateLimitMiddleware` (`middleware.py:58`, 429) + slowapi `@limiter.limit("10/minute")` nos endpoints de escrita (`attacks.py:120`, `wifi.py:52`, `ble.py:25`, `network.py:25`). Composição monótona (qualquer cesta esgotada → 429). Sem conflito.

### Observação adicional (não nos 3 pontos listados, mas relevante)
- `urban_hack.py` `UrbanHackEventHandler.event_types` (linha 467-472) inclui `"network.scan_request"` e `"camera.discovery_request"`, **mas `handle()` (linha 474) não tem ramo `elif` para esses** → eventos recebidos e silenciosamente ignorados. Não é um bypass de ataque (são scans/descoberta), mas é um fio solto: subscritor morto.

---

## 3. Dívida técnica conhecida (ponto 4 — confirmação)

### Bug do TUI: `_publish_attack` envia `{attack, params}` mas handlers leem `type`/`bssid`
**AINDA PRESENTE — NÃO corrigido.**
- `_publish_attack` (`ui/tui/app.py:283-301`) publica `payload={"attack": attack, "params": params}`.
- Handlers leem `payload.get("type")` e `payload.get("bssid")`:
  - `urban_hack.py:512-513` (`_handle_wifi_attack`): `attack_type = payload.get("type")`, `bssid = payload.get("bssid")`.
  - `wifi/plugin.py:_handle_attack_request`: mesmo padrão (`type`/`bssid`).
- Resultado: `attack_type=None`, `bssid=None` → `if not bssid: return` (linha 515) → **nenhum ataque executa via TUI**.
- Agravante BLE: categoria calculada por `attack.split("_",1)[0]` → `"ble"` → publica `ble.attack_request`, evento que **nenhum handler** subscreve (handlers BLE querem `ble.exploit_request`/`ble.test_request`). Logo o botão WhisperPair do TUI nem chega a um handler.
- Nota: os scans WiFi/BLE/Network do TUI **funcionam** porque chamam os scanners diretamente (`_wifi_scan:303`, etc.), não via bus. Só os **botões de ataque** estão quebrados.
- O `docs/CORRECAO_SESSIONSCOPE_2026-07-01.md` lista isto como follow-up recomendado #3 ("Alinhar o contrato de payload do TUI `_publish_attack` (`type`/`bssid`) com os handlers") — **ainda por fazer**.

### `pyproject.toml` declara `dbus-fast` mas o código usa `dbus` (C-ext)
**AINDA PRESENTE — confirmado, e mais específico do que descrito:**
- `pyproject.toml` declara `dbus-fast>=2.8.0` (e `bleak`); **não** declara `dbus` (C-ext) nem `pybluez` (comentado).
- A maioria do código BLE usa `dbus_fast` corretamente: `hal/ble/__init__.py:94-95`, `modules/bt_hid.py:28-30`.
- **MAS** `modules/ble/exploit_chain.py:17-18` faz `import dbus` + `import dbus.mainloop.glib` (C-extension legacy) — **dependência não declarada** no `pyproject.toml`. Há fallback gracioso (`_DBUS_AVAILABLE=False` se import falhar, linha 22-24), mas quando `dbus` C-ext está ausente o módulo da cadeia de exploit BLE fica inerte.
- Consequência: a cadeia de exploit BLE completa (`BlueZBondingManager`, etc.) requer o pacote sistema `python3-dbus` (C-ext) que não está no manifesto de dependências.

### `msfinstall` (script untracked) e pasta `audit/`
- **`msfinstall`**: **ainda NÃO tracked.** `git status --short` → `?? msfinstall` (ficheiro executável de 6144 B na raiz). Continua fora do controlo de versão.
- **`audit/`**: a pasta **existe mas está VAZIA** (`ls -la audit/` → só `.` e `..`). Os relatórios de auditoria foram removidos no commit `fd60ab3` ("chore: remover relatórios de auditoria obsoletos"). O Git não rastreia diretórios vazios, pelo que `audit/` é efetivamente invisível ao controlo de versão (não aparece em `git status` nem em `git ls-files`). Resumo: os relatórios foram tratados (removidos); a pasta vazia permanece no working tree, não rastreada.

---

## 4. Próximas fases segundo os planos (ponto 5 — citação literal)

### De `docs/PLAN.md` (o plano sprint-based ativo)

Os Sprints 0-9 estão marcados `*(completed)*`. O que vem a seguir (não iniciado, caixas `[ ]`):

> **Sprint 10 — Testing Hardening + Coverage Enforcement**
> Acceptance criteria:
> - [ ] PR cannot merge if coverage drops below 85%.
> - [ ] Every new module must include `test_<module>_contract.py` and `test_<module>_execute.py`.
> - [ ] A new contributor can run `make test` and see green locally.

> **Sprint 11 — Plugin Marketplace**
> Acceptance criteria:
> - [ ] A new module can be written, installed, and appear in the UI in under 5 minutes.
> - [ ] Disabled plugins do not load or appear in the attack inventory.
> - [ ] Plugin docs template exists in `CONTRIBUTING.md`.

> **Sprint 12 — Distributed Cracking & Offloading**
> Acceptance criteria:
> - [ ] A `.22000` created on the Pi can be cracked on a desktop and the password appears in the local credential manager.
> - [ ] Operator sees in the UI which backend cracked each hash.

> **Sprint 13 — Cutting-Edge Research**
> Acceptance criteria:
> - [ ] Each research topic has its own module directory and a clear "lab-only / requires HW" notice in the docs.
> - [ ] No research feature is enabled by default; requires an explicit feature flag and operator confirmation.

> **Global Rules** (literais):
> 1. **No PII** in committed code or docs…
> 2. **EN + PT**: every new or updated `.md` must have both language versions unless explicitly waived.
> 3. **Documentation-first for risky features**…
> 4. **Tests before code** for new modules: `test_<module>_contract.py` and `test_<module>_execute.py` are required for merge.
> 5. **Coverage floor**: 85% overall; new code must not decrease it.
> 6. **Branch discipline**: feature branches off `andreas/catarinus`; PR description must include a `docs/` checklist.

### De `MASTER_PLAN.md` (secção 8 "PRÓXIMOS PASSOS IMEDIATOS")
> 1. **Criar repo structure** + `pyproject.toml` + `docker/Dockerfile.arm64`
> 2. **Implementar S0.1-S0.9** (Foundation) — base para tudo
> 3. **Validar hardware** — Alfa em monitor mode, GPS fix, Bluetooth funcional
> 4. **Sprint Planning meeting** — Assign tasks, define branch strategy (`main` + `sprint/*`)

### De `ROADMAP.md` (priorização extendida)
> | Mês | Foco Principal | Entregáveis Chave |
> | **Mês 1** | **Core Hardening + Wi-Fi 6/6E + Wardriving** | F8, F10.1-F10.4, F1, T8, T2, T5.6 |
> | **Mês 2** | **Dashboard + Distributed Cracking + Rogue AP** | F2, F17, F16.1-F16.2, T14, T15 |
> | **Mês 3** | **Advanced Attacks + Forensics + Stealth** | F4, F11, F13, F15, F18, F20, F21, T9, T11, T13, T18, T19 |

### De `docs/PLAN_PHASE10.md`
É a fase de "Attack Selection UI" — no `docs/PLAN.md` aparece já integrada como "Sprint 3 — Attack Selection UI Phase 10 *(completed)*". Não lista "próxima fase" explícita além dos critérios de fecho:
> Phase closure criterion:
> - Full suite green.
> - `urban-hs-tui` boots, navigates tabs, executes mocked attack, and shows output.
> - `urban-hs-server` boots and `/` loads frontend with functional buttons.
> - Events pass from module → event bus → TUI and Web UI in < 1s.

### De `docs/CORRECAO_SESSIONSCOPE_2026-07-01.md` (follow-ups fora de âmbito, ainda por tratar)
> 1. `from enum import Enum` em `modules/ble/fastpair.py` — desbloqueia o módulo BLE inteiro…
> 2. `from __future__ import annotations` (ou `"dbus.Interface"` em string) em `modules/ble/exploit_chain.py` — evita o crash de import sem `dbus`.
> 3. Alinhar o contrato de payload do TUI `_publish_attack` (`type`/`bssid`) com os handlers, e adicionar subscritor para `ble.attack_request`…

---

## Notas finais (sem recomendações — só factos)

- **Divergências plano↔codigo confirmadas** (caso pedido no enunciado):
  1. **Web UI**: plano diz "React PWA" (`MASTER_PLAN.md` Sprint 5); código é HTML vanilla + HTMX/Alpine. (`docs/SESSAO_AUTONOMA_2026-07-01.md` já registou a decisão de manter vanilla.)
  2. **CLI**: `docs/PLAN.md` Sprint 1 declara comandos `scan/attack/exploit/report/export/config`; **não existem** — só `info/run/modules/verify/seal/audit-trail` (`seal` é stub).
  3. **BLE exploit chain**: descrito como funcional nos planos (Sprint 1 "WhisperPair tester/exploit", critério Sprint 2 "executa exploit chain, grava áudio"); os **handlers devolvem `not_implemented`** (`ble/plugin.py:264`, `urban_hack.py:645`). A classe `WhisperPairFullExploit` existe mas não está ligada ao caminho de execução do plugin.
  4. **Exploit Runner / Credential Manager / BlueZ backend**: ao contrário de sessões anteriores (descritas como stubs), **hoje são Real** no código — `exploit/runner.py` despacha por fonte com subprocess/chroot; `credential/manager.py` corre hashcat/subprocess; `hal/ble/__init__.py` usa `dbus_fast` real. (Casos onde o código está **mais avançado** do que eventuais planos antigos sugeriam.)
- **Lint**: o gate `ruff` está vermelho por dívida pré-existente (~4656 erros em `src/urban_hs/`), já registado em `docs/CORRECAO_SESSIONSCOPE_2026-07-01.md`. Fora do âmbito desta auditoria.
- **`docs/PLAN.pt.md`, `docs/PLAN_PHASE10.pt.md`, versões `.pt.md`**: existem (sync EN/PT conforme Global Rule #2). Não alteram o estado das features.
