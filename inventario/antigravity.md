# Inventário de Estado — urban-hack-sentinel

* **Agente**: Antigravity (Gemini 3.5 Flash)
* **Timestamp**: 2026-07-01T15:23:00+01:00
* **Commit HEAD**: `6055087fe80c7f5df126337a2eae6580a2880f10`

---

## 1. Tabela de Estado Real de Módulos e Features

A tabela abaixo valida o estado real de cada funcionalidade/módulo no código-fonte atual do projeto comparado com o que está planeado.

| Módulo / Feature | Estado no Código | Ficheiro:Linha (Prova no Código) | Detalhes e Observações |
| :--- | :---: | :--- | :--- |
| **WiFi (Scan)** | **Real** | [scanner.py:L102-120](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/wifi/scanner.py#L102-L120) | Usa `iw dev <iface> scan -f json` assíncrono. |
| **WiFi (Deauth)** | **Real** | [deauth.py:L79-86](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/wifi/attacks/deauth.py#L79-L86) | Invoca o utilitário `aireplay-ng` via subprocesso. |
| **WiFi (WPS Pixie)** | **Real** | [wps.py:L78-82](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/wifi/attacks/wps.py#L78-L82) | Executa o `reaver -K 1` para Pixie Dust. |
| **WiFi (WPS PIN)** | **Real** | [wps.py:L192-196](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/wifi/attacks/wps.py#L192-L196) | Brute force de PINs comuns via `reaver`. |
| **WiFi (Handshake)** | **Real** | [wpa.py:L79-87](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/wifi/attacks/wpa.py#L79-L87) | Captura com `airodump-ng` e deauth com `aireplay-ng`, verificando com `aircrack-ng`. |
| **WiFi (PMKID)** | **Real** | [wpa.py:L188-193](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/wifi/attacks/wpa.py#L188-L193) | Usa `hcxdumptool` para capturar e `hcxpcapngtool` para extrair. |
| **WiFi (Fragattacks)** | **Real** | [fragattacks.py:L259-264](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/wifi/fragattacks.py#L259-L264) | Invoca o script da suite `fragattacks` do Mathy Vanhoef. |
| **BLE (Scan/FastPair)** | **Real** | [fastpair.py:L77-84](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/ble/fastpair.py#L77-L84) | Utiliza a biblioteca `bleak` para scanner de publicidades 0xFE2C. |
| **BLE (WhisperPair)** | **Real** | [fastpair.py:L163-199](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/ble/fastpair.py#L163-L199) | Efetua testes e conexão GATT para validar bypass de emparelhamento (CVE-2025-36911). |
| **BLE (Exploit Chain)** | **Real** | [exploit_chain.py:L91-102](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/ble/exploit_chain.py#L91-L102) | Integração com D-Bus do BlueZ para `CreateBond`/`RemoveBond` e gravação de chaves de conta. |
| **Network (nmap/host discovery)** | **Real** | [scanner.py:L77-99](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/network/scanner.py#L77-L99) | Invoca binário `nmap` local de forma assíncrona. |
| **Metasploit RPC / Console** | **Real** | [rpc.py:L123-138](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/metasploit/rpc.py#L123-L138) e [console.py:L129-134](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/metasploit/console.py#L129-L134) | Possui cliente msgrpc MessagePack (RPC) e console wrapper real. |
| **SearchSploit** | **Real** | [searchsploit.py:L34-39](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/network/searchsploit.py#L34-L39) | Wrapper de pesquisa no ExploitDB local via linha de comandos. |
| **HID** | **Real** | [injector.py:L91-100](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/hid/injector.py#L91-L100) e [gadget.py:L152-180](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/hid/gadget.py#L152-L180) | Suporta emulação local via `uinput` e USB gadget físico via ConfigFS no Linux. |
| **MQTT** | **Real** | [mqtt.py:L138-142](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/mqtt.py#L138-L142) | Suporta descoberta, enumeração de tópicos e força bruta com `paho-mqtt`. |
| **ESP32** | **Real** | [esp32.py:L547-557](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/esp32.py#L547-L557) | Envia comandos HCI de baixo nível com `hcitool` para CVE-2025-27840. |
| **Camera Enumeration** | **Real** | [enumeration.py:L263-280](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/camera/enumeration.py#L263-L280) | Testes reais de credenciais sobre HTTP com `aiohttp` e ONVIF. |
| **Credential Manager** | **Real** | [manager.py:L652-658](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/credential/manager.py#L652-L658) | Invoca o `hashcat` real para cracking de hashes capturados. |
| **Exploit Runner** | **Real** | [runner.py:L184-238](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/exploit/runner.py#L184-L238) | Orquestrador de execução de exploits (Nuclei, MSF, etc.). |
| **Reporting (GPG-signed)** | **Real** | [gpg_evidence.py:L138-148](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/reporting/gpg_evidence.py#L138-L148) e [generator.py:L26-36](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/reporting/generator.py#L26-L36) | Geração de PDFs com `Jinja2`/`WeasyPrint` e assinaturas digitais via `python-gnupg`. |
| **SessionScope** | **Real** | [session_scope.py:L23-39](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/core/session_scope.py#L23-L39) | Implementado como escopo global contendo allowlists de targets/categorias. |
| **Auth (JWT/Bearer)** | **Real** | [auth.py:L75-98](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/ui/api/auth.py#L75-L98) | Token JWT persistido em disco para autenticação Bearer. |
| **Rate limiting** | **Real** | [rate_limit.py:L13](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/ui/api/rate_limit.py#L13) e [middleware.py:L58-85](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/ui/api/middleware.py#L58-L85) | Rate limiter global em middleware + decorator `@limiter.limit` no router API. |
| **WebSocket (`/api/v1/events`)** | **Real** | [events.py:L80-103](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/ui/api/routers/events.py#L80-L103) | Envia streams de eventos estruturados em tempo real para Web/TUI. |
| **Web UI** | **Real** | [index.html:L139-150](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/ui/web/index.html#L139-L150) e [main.py:L105-112](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/ui/api/main.py#L105-L112) | Servida diretamente pelo FastAPI em `/`. Contém painéis WiFi, BLE, Network, Attacks, System e terminal interativo. |
| **TUI (Textual)** | **Stub/parcial** | [app.py:L110-147](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/ui/tui/app.py#L110-L147) e [app.py:L283-300](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/ui/tui/app.py#L283-L300) | A interface textual está implementada e é real, porém possui integração parcial/quebrada com os handlers de ataque devido ao bug de assinaturas/chaves do evento no método `_publish_attack` que impede a execução real de qualquer ataque a partir da TUI. |
| **CLI** | **Real** | [main.py:L32-37](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/cli/main.py#L32-L37) | CLI baseado em `Typer` com suporte a run, tui, info, verify, seal, audit-trail. |

---

## 2. Guard Rails de Segurança

Com base nas sessões de auditoria e correções recentes, confirma-se o seguinte estado:

* **SessionScope**: A cobertura e aplicação do guard rail estão confirmadas em 4 pontos-chave de execução real do código-fonte:
  1. No módulo de WiFi: [plugin.py:L397](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/wifi/plugin.py#L397) (`get_active_scope().validate(bssid, "wifi")`).
  2. No módulo de BLE: [plugin.py:L253](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/ble/plugin.py#L253) (`get_active_scope().validate(address, "ble")`).
  3. No módulo orquestrador `urban_hack` (WiFi): [urban_hack.py:L520](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/urban_hack.py#L520) (`get_active_scope().validate(bssid, "wifi")`).
  4. No módulo orquestrador `urban_hack` (BLE): [urban_hack.py:L634](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/urban_hack.py#L634) (`get_active_scope().validate(address, "ble")`).
* **REST Execution Path**: Adicionalmente, o endpoint REST de execução de ataques (`POST /attacks/{attack_name}/execute`) também valida as permissões do escopo ativo em [attacks.py:L146-147](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/ui/api/routers/attacks.py#L146-L147) (`get_session_scope().validate(target, category)`).
* **Auth (WebSocket & REST)**: Autenticação baseada em tokens JWT. Exigida e validada em chamadas REST via dependência `require_auth` ([auth.py:L96-98](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/ui/api/auth.py#L96-L98)) e nas conexões WebSocket `/api/v1/events` ([events.py:L84-92](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/ui/api/routers/events.py#L84-L92)).
* **Rate Limiting**: Confirmada a existência e coexistência pacífica de duas camadas:
  1. Limiter local por endpoint usando a biblioteca `slowapi` ([rate_limit.py](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/ui/api/rate_limit.py)).
  2. Middleware global baseado em bucket de tokens por endereço IP do cliente ([middleware.py:L58-85](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/ui/api/middleware.py#L58-L85)).

*Nota: Não foi encontrado um quinto caminho de execução de ataque ativo que ignore a validação do `SessionScope`.*

---

## 3. Dívida Técnica Conhecida

* **Bug do TUI (`_publish_attack`)**: **Ainda existe**. O método `_publish_attack` no ficheiro [app.py:L283-300](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/ui/tui/app.py#L283-L300) envia um payload estruturado como `{"attack": attack, "params": params}`. No entanto, os event handlers como o do módulo WiFi em [plugin.py:L387-391](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/wifi/plugin.py#L387-L391) tentam extrair `type` e `bssid` diretamente da raiz do payload do evento (`payload.get("type")` / `payload.get("bssid")`). Como estes campos são retornados como `None`, a execução aborta silenciosamente antes da validação ou execução.
* **dbus-fast vs dbus**: O ficheiro [pyproject.toml:L45](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/pyproject.toml#L45) declara a biblioteca pure-Python `dbus-fast>=2.8.0`, porém o código de ligação BLE em [exploit_chain.py:L17](file:///home/andresantos/Secret%C3%A1ria/Projects/urban-hack-sentinel/src/urban_hs/modules/ble/exploit_chain.py#L17) tenta importar a biblioteca C `dbus` e o loop GLib (`import dbus`, `import dbus.mainloop.glib`), mantendo a discrepância.
* **Msfinstall & pasta audit/**: O script `msfinstall` permanece como um ficheiro untracked na raiz do repositório. A pasta `audit/` está vazia no sistema de ficheiros (não contendo nenhum relatório) e, por isso, não está a ser rastreada pelo Git nem se encontra listada no `.gitignore`.

---

## 4. Próximas Fases segundo os Planos

Citação literal das próximas fases de sprints extraídas de `docs/PLAN.md`:

```markdown
## Sprint 10 — Testing Hardening + Coverage Enforcement

**Objective**: move from smoke tests to a rigorous, maintainable test suite that gives confidence before every release.

Tasks:
1. Coverage baseline — run `pytest --cov=urban_hs` and set the floor at **85%**.
2. Per-module contract tests — every module in `src/urban_hs/modules/...` has a companion `tests/test_<module>_contract.py`.
3. Custom test framework — helpers for `gpsd` mock, `mac80211_hwsim` reusable fixtures, HAL adapter matrix (`x86_scapy` vs `arm_iw`).
4. Integration tests — run real binaries in Docker (`airodump-ng`, `hcxdumptool`, `reaver`, `nmap`, `nuclei`) against intentionally vulnerable containers.
5. Concurrency / load tests — parallel attacks, event bus under pressure, TUI + Web UI connected simultaneously.
6. Security tests — path traversal, input fuzzing, secret leakage in logs, privilege checks.
7. CI matrix — add `ubuntu-latest` + `arm64` runner if available; fail build on coverage drop.

Acceptance criteria:
- [ ] PR cannot merge if coverage drops below 85%.
- [ ] Every new module must include `test_<module>_contract.py` and `test_<module>_execute.py`.
- [ ] A new contributor can run `make test` and see green locally.
```

```markdown
## Sprint 11 — Plugin Marketplace

**Objective**: lower the barrier for others to write and share modules.

Tasks:
1. Plugin metadata manifest (`pyproject.toml` `urban-hs.plugins` entry points).
2. `urban-hs plugin install <name>` from a registry (local directory or remote Git).
3. Signature verification for plugins.
4. Module skeleton generator (`urban-hs plugin new <name>`).
5. Runtime enable/disable without restart.
6. Version constraints and dependency isolation per plugin.

Acceptance criteria:
- [ ] A new module can be written, installed, and appear in the UI in under 5 minutes.
- [ ] Disabled plugins do not load or appear in the attack inventory.
- [ ] Plugin docs template exists in `CONTRIBUTING.md`.
```

```markdown
## Sprint 12 — Distributed Cracking & Offloading

**Objective**: scale cracking beyond the Pi’s GPU.

Tasks:
1. Hash watcher — monitor `$HASH_DIR` for new `.22000` files.
2. Remote submit — `rsync`/`scp`/`syncthing` to a configurable cracking host.
3. Result poller — pull cracked `.potfile` and update local DB.
4. Hashtopolis / KrakenHashes API clients.
5. Cost estimator — estimate €/hash for cloud spot instances.
6. Auto-report — sessions report how many hashes were cracked and by which backend.

Acceptance criteria:
- [ ] A `.22000` created on the Pi can be cracked on a desktop and the password appears in the local credential manager.
- [ ] Operator sees in the UI which backend cracked each hash.
```

```markdown
## Sprint 13 — Cutting-Edge Research

**Objective**: keep the platform current with emerging WiFi/BLE/IoT/SDR techniques.

Tasks:
1. Wi-Fi 6/6E/7 — HE/EHT capabilities, 6 GHz channel list, MLO correlation.
2. SDR / Spectrum — integrate `rtl_power` / `soapy_power` waterfall.
3. IoT / Matter / Thread — `_matter._tcp`, Zigbee snapshot (if SDR present).
4. Bluetooth Classic — KARMA/MANA, Evil Twin (lab-only), Enterprise/EAP hash capture.
5. Wi-Fi Sensing / CSI — basic motion detection with Intel AX CSI tool.
6. ML scoring — lightweight XGBoost/ONNX model for `p(crack)`.
7. Rogue AP / hostapd-mana — requires second radio or VAP; lab-only policy.

Acceptance criteria:
- [ ] Each research topic has its own module directory and a clear “lab-only / requires HW” notice in the docs.
- [ ] No research feature is enabled by default; requires an explicit feature flag and operator confirmation.
```
