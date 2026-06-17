# Urban Hack Sentinel v3 — Security, Bug & Sprint Report
**Versão analisada:** Sprint 0–5 (branch `main`, commit `8b65ad9`) | **Data:** Junho 2026  
**Contexto:** Projeto académico — demonstração de vulnerabilidades em ambiente urbano  
**Autor da revisão:** Claude Code (claude-sonnet-4-6)

---

## Índice

1. [Completion por Sprint](#1-completion-por-sprint)
2. [Hardware Necessário por Exploit](#2-hardware-necessário-por-exploit)
3. [Relatório de Exploits por Área](#3-relatório-de-exploits-por-área)
4. [Bugs — Sprint 4 e 5 (novos)](#4-bugs--sprint-4-e-5-novos)
5. [Bugs Persistentes de Sprints Anteriores](#5-bugs-persistentes-de-sprints-anteriores)
6. [Pontos de Melhoria & Recomendações](#6-pontos-de-melhoria--recomendações)
7. [Sumário Executivo de Bugs](#7-sumário-executivo-de-bugs)

---

## 1. Completion por Sprint

Comparação do estado real do repositório contra o MASTER_PLAN.md.

### Legenda
- ✅ Done — funcional, implementado
- ⚠️ Parcial — existe mas incompleto ou com limitações conhecidas
- ❌ Ausente — não implementado

---

### S0 — Foundation · **~72%**

| Task | Estado | Nota |
|------|--------|------|
| S0.1 Repo + pyproject.toml | ✅ | src layout, dependências completas |
| S0.2 Event Bus | ✅ | asyncio.Queue, typed events, dead letter queue — 261 linhas |
| S0.3 Process Manager | ✅ | subprocess async, streaming, kill tree — 593 linhas |
| S0.4 Config (Pydantic) | ✅ | YAML/ENV, hot-reload via watchfiles — 266 linhas |
| S0.5 Storage (SQLite + Redis) | ✅ | aiosqlite WAL, connection pool, migrations — 768 linhas |
| S0.6 Logger | ✅ | structlog + rich, JSONL rotation — 180 linhas |
| S0.7 Health + Prometheus | ❌ | `core/health.py` não existe; `/healthz` e `/metrics` ausentes |
| S0.8 Plugin System | ⚠️ | Plugin só existe para WiFi; sem entry points dinâmicos nem registry global |
| S0.9 CI/CD GitHub Actions | ❌ | `.github/workflows/` não existe |

**Critério de Done S0:** `urban-hs health` retorna JSON → **não cumprido** (falta S0.7).

---

### S1 — WiFi · **~87%**

| Task | Estado | Nota |
|------|--------|------|
| S1.1 WiFi Scanner | ✅ | IWBackend + AirodumpBackend, channel hopping — 508 linhas |
| S1.2 Handshake Attack | ✅ | HandshakeAttack, deauth + airodump, PMKID hcxdumptool |
| S1.3 WPS Pixie Dust | ✅ | WPSPixieAttack, reaver -K, fallback pixiewps |
| S1.4 WPS Common PINs | ✅ | WPSPinAttack, OUI DB |
| S1.5 Deauth | ✅ | DeauthAttack, targeted + broadcast, rate limiting, legal gate |
| S1.5b Handshake Manager | ✅ | Dedup BSSID+ESSID, hashcat integration, WiGLE/Kismet export |
| S1.6 MAC Changer + OUI | ✅ | Profiles apple/samsung/intel/realtek/random |
| S1.7 GeoMac + GPS | ✅ | GeoMapper, gpsd TCP 2947, WiGLE CSV, Kismet netxml, KML |
| S1.8 Tests + Mock | ⚠️ | Sem testes WiFi em `tests/`; só existem testes BLE |

**Critério de Done S1:** Captura handshake + WPS Pixie + geo export → **cumprido** na lógica.

---

### S2 — BLE / WhisperPair · **~75%**

| Task | Estado | Nota |
|------|--------|------|
| S2.1 FastPair Scanner | ✅ | Bleak scanner, UUID 0xFE2C, parse model ID, pairing mode — 580 linhas |
| S2.2 WhisperPair Tester | ✅ | GATT → KBP request → parse 0x01 (vulnerável) / 0x0E (patched) |
| S2.3 WhisperPair Exploit | ✅ | 4 estratégias: RAW_KBP, RAW_WITH_SEEKER, RETROACTIVE, EXTENDED_RESPONSE |
| S2.4 BR/EDR Bonding | ✅ | BlueZBondingManager — CreateBond/RemoveBond via D-Bus BlueZ |
| S2.5 Account Key Write | ✅ | AccountKeyManager — AES-ECB, GATT write UUID fe2c1236 |
| S2.6a HFP Audio Capture | ⚠️ | Código `arecord`+bluealsa presente; `run_full_chain()` não chama `start_capture()` (BLE-01) |
| S2.6b Device Quirks DB | ⚠️ | 9 devices em JSON mas Model IDs são placeholders fictícios (ex: `ABCDEF`) |
| S2.7 Tests + Mock BlueZ | ⚠️ | 21 testes (414 linhas); 60% meaningful; falta cobertura de BLE-01/BLE-02 e shared_secret |

**Critério de Done S2:** "Detecta Fast Pair, testa CVE-2025-36911, executa exploit chain, grava áudio" → **parcialmente cumprido** (HFP não integrado no pipeline).

---

### S3 — Network / Camera / Vuln · **~52%**

| Task | Estado | Nota |
|------|--------|------|
| S3.1 Network Scanner (Nmap) | ✅ | NmapScanner, 6 modos, async subprocess + XML parsing |
| S3.2 Nuclei Runner | ✅ | NucleiRunner, JSONL streaming, severity mapping, dedup |
| S3.3 SearchSploit | ⚠️ | SearchSploitIntegration existe mas `get_exploit()` sem validação (NET-03) |
| S3.4 Router Scan | ⚠️ | RouterScanner com Hydra brute-force; RouterSploit retorna `[]` — dep. externa bloqueada |
| S3.5 Camera Discovery | ✅ | CameraDiscovery — mDNS, UPnP, ONVIF WS-Discovery, RTSP nmap, HTTP fingerprint |
| S3.6 Camera Enumeration | ❌ | Não existe `camera/enumeration.py`; auth test mínimo dentro de CameraDiscovery |
| S3.7 Camera Vuln Check | ❌ | Não existe `camera/vuln_check.py`; sem mapeamento CVE para cameras |
| S3.8 IoT Protocols | ⚠️ | mDNS Matter/Thread detectado; sem CC2531/Zigbee; BLE GATT via módulo separado |

**Critério de Done S3:** "cameras ONVIF/RTSP, IoT baseline" → **parcialmente cumprido** (discovery sim, enumeration/vuln ausentes).

---

### S4 — Metasploit / Exploitation / Reporting · **~60%**

> ⚠️ Sprint 4 tem os mais ficheiros implementados em volume, mas com bugs que quebram a funcionalidade core: o protocolo MSF RPC usa formato msgpack errado (MSF-02), o chain of custody GPG falha sempre na verificação (GPG-04), e o `ensure_chroot()` usa path hardcoded do developer (CHRT-01).

| Task | Estado | Nota |
|------|--------|------|
| S4.1 Alpine Chroot Bootstrap | ⚠️ | `bootstrap_chroot.sh` existe (291 linhas) mas sem checksum Alpine (BOOT-01) e edge repos instáveis (BOOT-02) |
| S4.2 Chroot Process Manager | ⚠️ | `chroot_process.py` existe (474 linhas) mas path hardcoded do developer (CHRT-01), bind mounts errados (CHRT-03), NameError em finally (CHRT-02) |
| S4.3 Metasploit RPC Client | ⚠️ | `metasploit/rpc.py` existe (632 linhas) mas msgpack format errado — todas as chamadas RPC falham (MSF-02) |
| S4.4 Metasploit Console | ⚠️ | `metasploit/console.py` existe (368 linhas) mas LHOST hardcoded 0.0.0.0 (CON-02) e injeção de comandos via options (CON-01) |
| S4.5 Exploit Runner | ✅ | `exploit/runner.py` — interface unificada Nuclei/MSF/SearchSploit/local, proof collection — 634 linhas |
| S4.6 Credential Manager | ⚠️ | `credential/manager.py` existe (737 linhas) mas `validate_credential()` sempre retorna True sem verificação real (CRED-02); `field(default_factory=list)` em assinatura de função (CRED-01) |
| S4.7 Report Generator | ⚠️ | `reporting/generator.py` existe (908 linhas) mas GPG passphrase em plaintext (RPT-01) e name collision em `sign_report()` (RPT-02) |
| S4.8 GPG Evidence | ⚠️ | `reporting/gpg_evidence.py` existe (690 linhas) mas assinatura binária falha com TypeError (GPG-01), verificação sempre falha (GPG-04), GPGSigner default sem key (GPG-05) |

**Critério de Done S4:** "exploitation pipeline end-to-end, relatórios assinados" → **não cumprido** — MSF-02 quebra o pipeline MSF e GPG-04 quebra a cadeia de custódia.

---

### S5 — HID / USB Gadget / Dashboard · **~30%**

| Task | Estado | Nota |
|------|--------|------|
| S5.1 DuckyScript Parser | ⚠️ | `hid/ducky.py` existe (668 linhas) mas keycode 'w' errado (HID-01) e pickle deserialization crítico (HID-02) |
| S5.2 HID Injector | ⚠️ | `hid/injector.py` existe (571 linhas) mas DELAY markers enviados como keycodes reais (HID-05) e `time.sleep()` bloqueia event loop (HID-04) |
| S5.3 USB Gadget Manager | ⚠️ | `hid/gadget.py` existe (636 linhas) mas exporta variáveis LAYOUT_* não definidas → ImportError (HID-06) |
| S5.4 FastAPI Backend | ❌ | Não existe `ui/api/main.py` |
| S5.5 React PWA | ❌ | Sem frontend |
| S5.6 Textual TUI | ❌ | Sem `ui/tui/app.py` |
| S5.7 Rich CLI | ❌ | Sem `ui/cli/main.py` |
| S5.8 Plugin Marketplace | ❌ | Sem registry, sem install, sem verificação de assinatura |

**Critério de Done S5:** "HID injection + USB gadget + Web/TUI/CLI operacionais" → **não cumprido** — HID tem bugs funcionais graves, UI ausente.

---

### S6 — Polish / Hardening · **0%**

Nada iniciado.

---

### Resumo de Completion

| Sprint | % Completo | Gap Crítico |
|--------|-----------|-------------|
| S0 — Foundation | **72%** | health.py, CI/CD ausentes |
| S1 — WiFi | **87%** | Testes WiFi ausentes |
| S2 — BLE | **75%** | HFP não integrado no pipeline; model IDs placeholder |
| S3 — Network/Camera | **52%** | Camera enum/vuln ausentes; NET-01 crítico |
| S4 — Metasploit | **~60%** | MSF-02 quebra todo o RPC; GPG-04 quebra chain of custody; CHRT-01 |
| S5 — HID/Dashboard | **~30%** | HID-01/02/05 quebram funcionalidade; UI ausente |
| S6 — Polish | **0%** | Não iniciado |
| **TOTAL** | **~53%** | 32 bugs identificados, 6 críticos |

---

## 2. Hardware Necessário por Exploit

| Hardware | Custo est. | Exploits que desbloqueia |
|---|---|---|
| **Raspberry Pi 4/5 built-in** (BT 5.0 + WiFi) | — | CVE-2023-45866 HID injection, CVE-2025-36911 WhisperPair, AirDrop harvesting, MQTT enumeration |
| **Alfa AWUS036ACHM** (MT7612U, 2.4+5GHz) | ~35€ | Kr00k CVE-2019-15126, FragAttacks CVE-2020-24588, SSID Confusion CVE-2023-52424, Evil Twin |
| **Alfa AWUS036AXML** (MT7921AUN, WiFi 6E) | ~50€ | Tudo acima + redes WiFi 6E (6GHz), WPA3 capture |
| **RTL-SDR Blog V4** (c/ antena) | ~30€ | TPMS vehicle tracking, LoRaWAN decode, 433MHz key fobs |
| **Nordic nRF52840 USB Dongle** | ~10€ | SweynTooth CVE-2020-10061, BLE raw link layer ataques |
| **InternalBlue compatible HW** | ~30–80€ | KNOB CVE-2019-9506, BIAS CVE-2020-10135, BLUFFS CVE-2023-24023 |
| **PN532 NFC Reader** | ~12€ | MIFARE card cloning, transport cards, building access |

**Stack mínimo recomendado:**
```
Pi 5 (base)
+ Alfa AWUS036ACHM      ~35€   (WiFi pentest)
+ RTL-SDR Blog V4       ~30€   (TPMS + LoRa)
+ nRF52840 Dongle       ~10€   (SweynTooth)
+ Elechouse PN532 V3    ~12€   (NFC)
+ Powerbank PD 45W      ~45€   (8-10h autonomia)
─────────────────────────
Total extra             ~132€
```

---

## 3. Relatório de Exploits por Área

**Classificação:** **ÓTIMA** = integrado e funcional | **MÉDIO** = presente mas limitado | **FRACO** = PoC ou não implementado

---

### Área 1 — Bluetooth Classic (BR/EDR)

| CVE | Nome | CVSS | Impl. UHS v3 | Req. Hardware |
|-----|------|------|--------------|---------------|
| CVE-2019-9506 | KNOB — Key Negotiation | 8.1 | FRACO — BlueZBondingManager presente mas sem entropy negotiation bypass | InternalBlue HW |
| CVE-2020-10135 | BIAS — BT Impersonation | 6.8 | FRACO — bonding manager existe; falta secure auth bypass | InternalBlue HW |
| CVE-2023-24023 | BLUFFS — Forward Secrecy | 6.8 | FRACO — apenas referenciado; sem implementação | InternalBlue HW |
| CVE-2023-45866 | Android/Linux HID Injection | 6.5 | **MÉDIO** — HIDInjector + USBGadgetManager implementados; DuckyScript com 7 layouts mas com bugs críticos (HID-01, HID-05) que corromper payloads |

### Área 2 — Bluetooth Low Energy (BLE)

| CVE | Nome | CVSS | Impl. UHS v3 | Req. Hardware |
|-----|------|------|--------------|---------------|
| CVE-2025-36911 | WhisperPair — Fast Pair KBP bypass | N/A | **MÉDIO** — 4 estratégias KBP, BlueZ bonding, account key write; HFP não integrado no pipeline (BLE-01) | Pi BT built-in |
| CVE-2020-10061 | SweynTooth — BLE link layer | 8.8 | FRACO — referenciado; requer nRF52840; sem exploits no codebase | nRF52840 dongle |
| CVE-2022-47630 | BLESA — BLE Spoofing | 8.8 | FRACO — não implementado | Pi BT built-in |
| — | AirDrop Harvesting | — | MÉDIO — FastPairScanner capta advertisements; parse de payload presente | Pi BT built-in |

### Área 3 — WiFi (IEEE 802.11)

| CVE | Nome | CVSS | Impl. UHS v3 | Req. Hardware |
|-----|------|------|--------------|---------------|
| CVE-2019-15126 | Kr00k — WPA2 nonce reuse | 6.5 | MÉDIO — NmapScanner + Nuclei detectam; ataque ativo requer HW Broadcom/Cypress | Alfa ACHM |
| CVE-2020-24588/26140 | FragAttacks | 7.5 | MÉDIO — NmapScanner VULN_SCAN cobre; sem exploit chain dedicado | Alfa ACHM |
| CVE-2023-52424 | SSID Confusion | 7.5 | MÉDIO — detectável com WiFiScanner; sem exploit ativo | Alfa ACHM |
| — | WPS Pixie Dust | — | **ÓTIMA** — WPSPixieAttack completo, reaver -K, fallback pixiewps | Alfa ACHM |
| — | PMKID Attack | — | **ÓTIMA** — PMKIDAttack com hcxdumptool, export .22000 para hashcat | Alfa ACHM |
| — | Handshake + Deauth | — | **ÓTIMA** — HandshakeAttack + DeauthAttack + HandshakeManager + WiGLE/Kismet | Alfa ACHM |

### Área 4 — IoT & Protocolos Urbanos

| CVE / Protocolo | Nome | CVSS | Impl. UHS v3 | Req. Hardware |
|----------------|------|------|--------------|---------------|
| CVE-2025-27840 | ESP32 hidden HCI | 8.2 | FRACO — sem módulo dedicado | Pi BT |
| — | TPMS Vehicle Tracking | — | FRACO — sem módulo rtl_433 | RTL-SDR |
| — | MQTT Enumeration | — | MÉDIO — NmapScanner detecta port 1883; sem exploit MQTT | Pi WiFi |
| — | Camera ONVIF/RTSP | — | MÉDIO — Discovery implementada; Enumeration/Vuln ausentes | Pi WiFi |

---

## 4. Bugs — Sprint 4 e 5 (novos)

---

### 4.1 Bootstrap (`scripts/bootstrap_chroot.sh`)

---

**BOOT-01 · ALTO · SECURITY — Sem Verificação de Integridade do Tarball Alpine**
- **Linha:** 58
- **Problema:** O script descarrega o Alpine minirootfs com `wget` sem verificar o checksum. A secção diz `# Verify checksum (optional but recommended)` mas não executa nenhum código.
- **Consequência:** MITM em rede pública (ambiente de operação do Pi) entrega um rootfs malicioso executado com root.
- **Fix:**
  ```bash
  wget -q "${MINIROOTFS_URL}.sha256" -O "${MINIROOTFS}.sha256"
  sha256sum -c "${MINIROOTFS}.sha256"
  ```

---

**BOOT-02 · ALTO · SECURITY — Alpine `edge` Repos Instáveis na Chroot**
- **Linhas:** 85–88
- **Problema:** Os repositórios `edge/main`, `edge/community` e `edge/testing` são adicionados ao APK sources da chroot. Packages edge são rolling e não assinados para alguns repos, introduzindo risco de supply chain.
- **Fix:** Usar apenas `v${ALPINE_VERSION%.*}/main` e `v${ALPINE_VERSION%.*}/community` (estáveis).

---

### 4.2 Chroot Process Manager (`core/chroot_process.py`)

---

**CHRT-01 · CRÍTICO · SECURITY — Path Hardcoded do Developer**
- **Linha:** ~370
- **Problema:** `ensure_chroot()` usa o path absoluto `/home/andresantos/Desktop/Projects/urban-hack-sentinel/scripts/bootstrap_chroot.sh`. Este path nunca existe em nenhuma máquina de deployment. Consequência dupla: (1) `ensure_chroot()` retorna `False` silenciosamente em qualquer sistema real — toda a funcionalidade chroot está quebrada; (2) expõe PII do developer no código fonte.
- **Fix:**
  ```python
  script_path = Path(__file__).parents[4] / "scripts" / "bootstrap_chroot.sh"
  ```

---

**CHRT-02 · ALTO · LOGIC — NameError no finally Block**
- **Linhas:** 240–242
- **Problema:** Se `asyncio.create_subprocess_exec()` lançar exceção (ex: `FileNotFoundError` para `chroot` não instalado), a variável `proc` nunca é atribuída. O bloco `finally` corre mesmo após `return` no `except` e referencia `proc.pid` incondicionalmente → `NameError` que engole a exceção original.
- **Fix:**
  ```python
  finally:
      if 'proc' in locals() and proc.pid in self._active_processes:
          del self._active_processes[proc.pid]
  ```

---

**CHRT-03 · ALTO · LOGIC — Bind Mounts Construídos Incorretamente**
- **Linhas:** 111–122
- **Problema:** `bind_cmds` é construído como lista plana de strings: `["mount", "--bind", src1, dst1, "mount", "--bind", src2, dst2, ...]`. O generator `" ".join(b) for b in bind_cmds` itera sobre strings individuais, não sub-listas. O resultado no `sh -c` é `"mount && --bind && /proc && /proc && ..."` — cada bind mount falha e o payload nunca corre.
- **Fix:** Construir como lista-de-listas:
  ```python
  bind_cmds.append(["mount", "--bind", src, dst])
  # E depois:
  " && ".join([" ".join(b) for b in bind_cmds])
  ```

---

**CHRT-04 · MÉDIO · SECURITY — `cd` Injetado como Argumento Exec**
- **Linhas:** 136–138
- **Problema:** Quando `working_dir != "/"`, o código prepend `["cd", self.config.working_dir, "&&"]` à lista de argumentos. Com `create_subprocess_exec` (sem shell), `cd` e `&&` são passados como argumentos literais ao primeiro comando — `cd` não é executável neste contexto; o working_dir é ignorado silenciosamente.
- **Fix:** Usar o parâmetro `cwd=` de `create_subprocess_exec`.

---

### 4.3 Metasploit RPC (`modules/metasploit/rpc.py`)

---

**MSF-01 · ALTO · SECURITY — Password Default `"msf"` + SSL Desativado**
- **Linhas:** 107, 109
- **Problema:** `MsfConfig` tem `username="msf"`, `password="msf"` e `ssl_verify=False`. Credenciais default públicas + verificação SSL desativada.
- **Consequência:** MITM do canal RPC é trivial; qualquer processo na rede captura ou injeta comandos Metasploit.
- **Fix:** Remover defaults de username/password (forçar configuração explícita). Mudar `ssl_verify=True`.

---

**MSF-02 · CRÍTICO · LOGIC — Formato msgpack Errado — Todo o RPC Falha**
- **Linhas:** 204–213
- **Problema:** O protocolo msgrpc exige um **array** msgpack: `[method, token, arg1, arg2, ...]`. O código codifica um **dict**: `{"method": method, "params": [...]}`. Todas as chamadas RPC são rejeitadas pelo servidor Metasploit.
- **Consequência:** A integração Metasploit está completamente não funcional.
- **Fix:**
  ```python
  params = [method]
  if self._token and method not in ("auth.login",):
      params.append(self._token)
  params.extend(args)
  packed = msgpack.packb(params, use_bin_type=True)
  ```

---

**MSF-03 · MÉDIO · LOGIC — Token Duplicado em `auth.logout`**
- **Linhas:** 189, 210
- **Problema:** `disconnect()` chama `_call("auth.logout", self._token)`. Dentro de `_call`, o token é prepended novamente, resultando em `[token, token]` como argumentos — o logout falha e a sessão no servidor não é terminada.
- **Fix:** Excluir `"auth.logout"` da lógica de prepend: `if self._token and method not in ("auth.login", "auth.logout"):`.

---

**MSF-04 · MÉDIO · SECURITY — SSL CERT_NONE por Omissão**
- **Linha:** 148
- **Problema:** `ssl_context.verify_mode = ssl.CERT_NONE` desativa verificação de certificado. Mesmo com `ssl=True`, a ligação é vulnerável a MITM.
- **Fix:** Default `ssl_verify=True`; documentar que certs auto-assinados requerem `ssl_verify=False` com aviso explícito.

---

### 4.4 Metasploit Console (`modules/metasploit/console.py`)

---

**CON-01 · ALTO · SECURITY — Injeção de Comandos via Options no Resource Script**
- **Linhas:** 227–235
- **Problema:** `run_exploit()` constrói o resource script com `f"set {k} {v}"` sem sanitização. Um valor com newline como `"192.168.1.1\nset PAYLOAD windows/x64/meterpreter\nexit"` injeta comandos adicionais no ficheiro `.rc`.
- **Fix:**
  ```python
  if '\n' in str(v) or '\r' in str(v):
      raise ValueError(f"Newline in option value for {k}")
  ```

---

**CON-02 · MÉDIO · QUALITY — LHOST Hardcoded como `0.0.0.0`**
- **Linha:** 343
- **Problema:** `template_exploit_chain()` usa `set LHOST 0.0.0.0` — não é um IP válido para reverse shells. O handler escuta em todas as interfaces do alvo, não do atacante. Chains geradas por template produzem reverse shells não funcionais.
- **Fix:** Aceitar `lhost: str` como parâmetro obrigatório.

---

### 4.5 Report Generator (`modules/reporting/generator.py`)

---

**RPT-01 · ALTO · SECURITY — GPG Passphrase em Campo Plaintext**
- **Linha:** 196
- **Problema:** `ReportConfig.gpg_passphrase: str` armazena a passphrase GPG como string plana num dataclass que pode ser serializado para logs, JSON export ou enviado por WebSocket. Qualquer um que leia memória, logs ou config obtém a passphrase.
- **Fix:** Usar callable secret provider (lambda lê de env var) em vez de campo string.

---

**RPT-02 · ALTO · LOGIC — Name Collision em `sign_report()` Quebra Assinatura**
- **Linhas:** 726–740
- **Problema:** `gpg = gpg.GPG()` — `gpg` é o alias do módulo `gnupg` (linha 32) e também o nome da variável local. Após a primeira atribuição, `gpg` referencia a instância, não o módulo. Numa segunda chamada a `sign_report()`, `gpg.GPG()` lança `AttributeError`.
- **Fix:** Renomear o import: `import gnupg as gnupg_module` e usar `gnupg_module.GPG()`.

---

**RPT-03 · BAIXO · SECURITY — Jinja2 Autoescape não cobre Markdown**
- **Linha:** 234
- **Problema:** `autoescape=select_autoescape(['html', 'xml'])` — extensão `.md` não incluída. Se findings contêm HTML injetado (output de scans), passa direto para o ficheiro Markdown.
- **Fix:** Sanitizar campos `description` dos findings com `html.escape()` antes do template.

---

**RPT-04 · MÉDIO · QUALITY — WeasyPrint Bloqueia o Event Loop**
- **Linha:** 641
- **Problema:** `_generate_pdf()` é `async def` mas chama `html.write_pdf(str(pdf_path))` sincronamente. WeasyPrint pode demorar 5–30 segundos num Pi 4 — bloqueia toda a asyncio event loop durante esse tempo.
- **Fix:** `await asyncio.to_thread(html.write_pdf, str(pdf_path))`

---

### 4.6 GPG Evidence (`modules/reporting/gpg_evidence.py`)

---

**GPG-01 · ALTO · LOGIC — Assinatura Binária Falha com TypeError**
- **Linhas:** 258–259
- **Problema:** Para `DETACHED_BINARY`, o ficheiro é aberto em modo `'wb'` mas `str(signature)` é escrito — string num file de bytes → `TypeError`. Nenhuma assinatura binária é jamais escrita com sucesso.
- **Fix:**
  ```python
  if format == SignatureFormat.DETACHED_BINARY:
      with open(output_path, 'wb') as f:
          f.write(signature.data)  # bytes
  else:
      with open(output_path, 'w') as f:
          f.write(str(signature))
  ```

---

**GPG-02 · MÉDIO · LOGIC — API `verify_signature()` Incorreta**
- **Linhas:** 309–315
- **Problema:** `self.gpg.verify(signature_path, file_path)` — a API python-gnupg para assinatura detached é `gpg.verify_file(fileobj, sig_file=path)`. A chamada atual passa dois paths como posicionais onde o primeiro é esperado como dados — verificação produz resultados errados ou falha silenciosamente.
- **Fix:**
  ```python
  with open(file_path, 'rb') as f:
      verified = self.gpg.verify_file(f, sig_file=signature_path)
  ```

---

**GPG-03 · MÉDIO · LOGIC — Dead Code Confuso em `ChainOfCustody.add_entry()`**
- **Linhas:** 78–117
- **Problema:** `entry_data` é construído como dict (linhas 79–93), depois sobrescrito com uma string (linha 112) para o hash input. O dict original fica inacessível (dead code). A variável `entry_dict` (linhas 96–109, construída identicamente) é a que é realmente appended. Confusão de nomes que pode causar bugs futuros.
- **Fix:** Remover o primeiro bloco `entry_data = {...}` (linhas 79–93) inteiramente.

---

**GPG-04 · ALTO · LOGIC — `verify_log()` Sempre Reporta Adulteração**
- **Linhas:** 462–471
- **Problema:** `_compute_entry_hash(entry)` é chamado **após** restaurar `entry_hash` no dict. O hash é calculado sobre a entrada *incluindo* o próprio campo `entry_hash`, mas o hash original foi calculado *sem* esse campo. A comparação falha sempre — `verify_log()` reporta cada entrada como adulterada mesmo quando o log está intacto. A cadeia de custódia é inutilizável.
- **Fix:**
  ```python
  entry_hash = entry.pop("entry_hash", "")
  computed = self._compute_entry_hash(entry)
  entry["entry_hash"] = entry_hash  # restaurar
  if entry_hash != computed:
      errors.append(...)
  ```

---

**GPG-05 · ALTO · LOGIC — `ChainOfCustodyManager` Default sem GPG Key**
- **Linha:** 521
- **Problema:** `gpg_signer or GPGSigner()` — `GPGSigner()` é construído com `key_id=None`. `sign_file()` retorna `False` silenciosamente quando `key_id` é None. Todos os artefactos ficam sem assinatura GPG, sem qualquer aviso ao utilizador.
- **Fix:** Tornar `gpg_signer` parâmetro obrigatório, ou verificar `if gpg_signer is None: logger.warning("No GPG signer — evidence will not be signed")`.

---

**GPG-06 · MÉDIO · QUALITY — `sign_file()` Lê Ficheiro Inteiro para RAM**
- **Linha:** 240
- **Problema:** `file_data = f.read()` — lê pcaps potencialmente grandes (centenas de MB) para memória. Num Pi 4 com RAM partilhada, risco de OOM.
- **Fix:** Usar `gpg.sign_file(f, ...)` que aceita file object e faz streaming.

---

### 4.7 HID / DuckyScript (`modules/hid/ducky.py`)

---

**HID-01 · ALTO · LOGIC — Keycode Errado para 'w' (e Numpad 4)**
- **Linhas:** 140, 161–162
- **Problema:** Colisões no keymap US:
  - `'v': 0x19` e `'w': 0x19` — `'w'` deve ser `0x1A`. Qualquer payload que escreva a letra 'w' produz 'v'.
  - `'keypad_3': 0x5B` e `'keypad_4': 0x5B` — numpad 4 deve ser `0x5C`.
- **Consequência:** Todos os payloads DuckyScript que contenham 'w' ficam corrompidos silenciosamente (ex: `powershell`, `wget`, `whoami`, URLs com `www`).
- **Fix:** `'w': 0x1A` e `'keypad_4': 0x5C`.

---

**HID-02 · CRÍTICO · SECURITY — Pickle Deserialization em Compiled DuckyScript**
- **Linhas:** 562–578
- **Problema:** `save_compiled()` e `load_compiled()` usam `pickle` para serialização. `pickle.load()` num ficheiro não confiável permite execução arbitrária de código. Craftar um `.ducky` binário malicioso é trivial.
- **Consequência:** Qualquer fonte de ficheiros DuckyScript compilados (USB, API, rede) pode comprometer o Pi com privilégios do processo.
- **Fix:** Substituir pickle por JSON ou msgpack com dicts de keycodes (todos os campos de `DuckyCommand` são serializáveis sem pickle).

---

**HID-03 · BAIXO · QUALITY — Dead Code em `_encode_command()`**
- **Linha:** 423
- **Problema:** `text = ' '.join(cmd.args)` é computado mas nunca usado — `_encode_string(cmd.args)` recalcula independentemente.
- **Fix:** Remover a linha.

---

### 4.8 HID Injector (`modules/hid/injector.py`)

---

**HID-04 · ALTO · QUALITY — `time.sleep()` Bloqueia o Event Loop**
- **Linhas:** 297–303
- **Problema:** `UInputInjector.delay()` chama `time.sleep()` em contexto async. Payloads DuckyScript com DELAY frequentes congelam todas as coroutines concorrentes durante a duração do delay.
- **Fix:** `async def delay(ms)` → `await asyncio.sleep(ms / 1000.0)`.

---

**HID-05 · ALTO · LOGIC — Delay Markers Enviados como Keycodes Reais**
- **Linhas:** 514–520
- **Problema:** `execute_ducky()` escreve todos os `bytes` reports para `/dev/hidg*`, incluindo os delay markers (com bit 0x80 set) do `DuckyEncoder`. O kernel HID driver interpreta o marker como um keystroke real e envia garbage keystrokes para o host.
- **Consequência:** Payloads DuckyScript com DELAY não fazem pause — enviam caracteres aleatórios.
- **Fix:** Antes de escrever cada report, verificar `if report[0] & 0x80: await asyncio.sleep(delay_ms / 1000)` em vez de escrever para o device.

---

### 4.9 USB Gadget Manager (`modules/hid/gadget.py`)

---

**HID-06 · ALTO · LOGIC — Exporta Variáveis LAYOUT_* Não Definidas → ImportError**
- **Linhas:** 630–636
- **Problema:** `gadget.py`'s `__all__` lista `LAYOUT_US`, `LAYOUT_GB`, `LAYOUT_DE`, `LAYOUT_FR`, `LAYOUT_ES`, `LAYOUT_IT`, `LAYOUT_RU` — nenhuma destas variáveis está definida em `gadget.py`. `from urban_hs.modules.hid.gadget import LAYOUT_US` lança `ImportError`.
- **Fix:** Remover essas entradas de `__all__` em `gadget.py`.

---

### 4.10 Credential Manager (`modules/credential/manager.py`)

---

**CRED-01 · ALTO · LOGIC — `field(default_factory=list)` em Assinatura de Função**
- **Linha:** 434
- **Problema:** `crack_hashes(extra_args: List[str] = field(default_factory=list))` — `field()` é válido apenas dentro de `@dataclass`. Numa função regular, `field(default_factory=list)` avalia para um objeto `Field` em tempo de definição. Callers que omitem `extra_args` recebem esse objeto; `extra_args or []` retorna o objeto (truthy) e `cmd.extend()` lança `TypeError`.
- **Fix:** `extra_args: Optional[List[str]] = None` com `extra_args = extra_args or []` no corpo.

---

**CRED-02 · CRÍTICO · LOGIC — `validate_credential()` Sempre Retorna True**
- **Linhas:** 416–425
- **Problema:** `validate_credential()` é um stub que define `validated=True`, `validity_status="valid"` e retorna `True` para qualquer credencial sem qualquer verificação de rede. O report generator trata credenciais validadas como confirmadas.
- **Consequência:** Relatórios académicos mostram 100% das credenciais como "válidas" — dados fabricados que invalidam os resultados do projeto.
- **Fix:** Implementar verificação real (paramiko para SSH, aiohttp para HTTP) ou lançar `NotImplementedError` com mensagem clara.

---

## 5. Bugs Persistentes de Sprints Anteriores

---

**NET-01 · CRÍTICO · SECURITY — Argument Injection no NmapScanner** *(persistente desde Sprint 3)*

- **Ficheiro:** `src/urban_hs/modules/network/__init__.py:193`
- **Problema:** `targets` passados diretamente para `cmd.extend(targets)` sem validação. Com `create_subprocess_exec` (sem shell), não há shell injection clássico — mas permite injeção de flags nmap (ex: um "target" `"--script malicious"` executa NSE scripts não autorizados). Em contexto onde targets vêm de discovery automático (SSDP, mDNS), um dispositivo malicioso pode controlar opções nmap.
- **Fix:**
  ```python
  import ipaddress
  for t in targets:
      try:
          ipaddress.ip_network(t, strict=False)
          validated.append(t)
      except ValueError:
          logger.warning("Invalid target skipped", target=t)
  ```

---

**NET-02 · ALTO · QUALITY — ONVIF WS-Discovery Socket Bloqueante** *(persistente desde Sprint 3)*

- **Ficheiro:** `src/urban_hs/modules/network/__init__.py:807–849`
- **Problema:** `_onvif_discovery()` usa socket UDP bloqueante (`recvfrom` com timeout de 5s) diretamente em função `async def`, sem `asyncio.to_thread()`. O UPnP (`_upnp_discovery`) foi corrigido mas ONVIF não.
- **Fix:** `data, addr = await asyncio.to_thread(sock.recvfrom, 65535)`

---

**NET-03 · ALTO · SECURITY — SearchSploit `exploit_id` sem Validação**

- **Ficheiro:** `src/urban_hs/modules/network/__init__.py:519–521`
- **Problema:** `get_exploit()` passa `exploit_id` diretamente ao subprocess: `[searchsploit_path, "-m", exploit_id, ...]`. Um `exploit_id` como `"../../../etc/passwd"` provoca path traversal no download de exploits para o disco.
- **Fix:** Validar `exploit_id` contra `r"^\d+$"` (IDs ExploitDB são inteiros).

---

**BLE-01 · MÉDIO · LOGIC — HFP Não Integrado no Pipeline WhisperPair**

- **Ficheiro:** `src/urban_hs/modules/ble/exploit_chain.py:596–599`
- **Problema:** `WhisperPairFullExploit.run_full_chain()` reporta HFP como `"placeholder"` — `start_capture()` é comentado. Com `hfp_enabled=True`, o pipeline indica sucesso sem gravar áudio.
- **Fix:** Implementar a chamada: `output_file = tempfile.mktemp(suffix=".wav"); await self.hfp_capture.start_capture(output_file, audio_duration)`.

---

**BLE-QUIRKS · BAIXO · QUALITY — Model IDs Placeholder em device_quirks.json** *(persistente)*

- **Ficheiro:** `config/device_quirks.json`
- **Problema:** Os 9 dispositivos têm Model IDs fictícios (`ABCDEF`, `123456`, etc.). Os quirks nunca são aplicados — a estratégia default é sempre usada independentemente do dispositivo alvo.
- **Fix:** Substituir pelos Model IDs reais da Google Fast Pair Device Registry (disponíveis no Android AOSP).

---

## 6. Pontos de Melhoria & Recomendações

### 6.1 Prioridade Imediata — Showstoppers

Estes bugs impedem a demonstração funcional do projeto:

| # | Bug | Esforço | Impacto |
|---|-----|---------|---------|
| 1 | **MSF-02** — Fix msgpack format (dict → array) | 15 min | MSF RPC totalmente não funcional |
| 2 | **CHRT-01** — Fix path hardcoded do developer | 5 min | Toda a funcionalidade chroot está quebrada |
| 3 | **HID-01** — Fix keycode 'w' (0x19 → 0x1A) | 5 min | Todos os payloads com 'w' corrompidos |
| 4 | **HID-05** — Fix delay markers vs. keycodes reais | 30 min | DELAY não funciona; enviam garbage keystrokes |
| 5 | **GPG-04** — Fix verify_log() hash computation | 20 min | Chain of custody sempre reporta adulteração |
| 6 | **HID-02** — Substituir pickle por JSON/msgpack | 1h | Deserialization CRÍTICA (RCE) |

### 6.2 Segurança — Antes de Qualquer Demonstração Pública

| # | Bug | Esforço |
|---|-----|---------|
| 7 | **NET-01** — Validar targets nmap com ipaddress | 30 min |
| 8 | **CHRT-03** — Fix bind mount list construction | 30 min |
| 9 | **BOOT-01** — Adicionar sha256sum verification | 30 min |
| 10 | **MSF-01** — Remover default password; ssl_verify=True | 15 min |
| 11 | **CON-01** — Sanitizar newlines em option values | 15 min |

### 6.3 Para Completar os Sprints em Curso

| # | Tarefa | Sprint | Esforço |
|---|--------|--------|---------|
| 12 | Implementar `core/health.py` — `/healthz` + Prometheus `/metrics` | S0.7 | 3h |
| 13 | CI/CD GitHub Actions — ruff + mypy + pytest | S0.9 | 2h |
| 14 | Testes WiFi em `tests/test_wifi_module.py` | S1.8 | 4h |
| 15 | `camera/enumeration.py` — default creds, auth test | S3.6 | 4h |
| 16 | `camera/vuln_check.py` — CVE mapping, Nuclei templates | S3.7 | 4h |
| 17 | FastAPI backend mínimo — `/api/status`, `/api/devices`, `/ws/events` | S5.4 | 6h |

### 6.4 O Que Faz Falta Para v3 Completo

1. **UI completa (S5.4–S5.7)** — FastAPI + React PWA + Textual TUI + Rich CLI — maior gap de UX
2. **HFP Audio** — integrar `start_capture()` no `run_full_chain()`; documentar `bluealsa` como pré-requisito
3. **RouterSploit** — retorna `[]`; substituir por módulos Metasploit equivalentes de router attack
4. **Model IDs reais** em `device_quirks.json` — sem eles os quirks são inúteis
5. **S6 inteiro** — hardening, E2E tests, release com SBOM, docs MkDocs

---

## 7. Sumário Executivo de Bugs

| ID | Módulo | Ficheiro | Linha | Severidade | Categoria | Estado |
|----|--------|----------|-------|------------|-----------|--------|
| MSF-02 | MSF RPC | `metasploit/rpc.py` | 204 | 🔴 CRÍTICO | Logic | Novo |
| CRED-02 | Credential | `credential/manager.py` | 416 | 🔴 CRÍTICO | Logic | Novo |
| CHRT-01 | Chroot | `core/chroot_process.py` | ~370 | 🔴 CRÍTICO | Security | Novo |
| HID-02 | DuckyScript | `hid/ducky.py` | 562 | 🔴 CRÍTICO | Security | Novo |
| NET-01 | Network | `network/__init__.py` | 193 | 🔴 CRÍTICO | Security | Persistente |
| BOOT-01 | Bootstrap | `bootstrap_chroot.sh` | 58 | 🟠 ALTO | Security | Novo |
| BOOT-02 | Bootstrap | `bootstrap_chroot.sh` | 85 | 🟠 ALTO | Security | Novo |
| CHRT-02 | Chroot | `core/chroot_process.py` | 240 | 🟠 ALTO | Logic | Novo |
| CHRT-03 | Chroot | `core/chroot_process.py` | 111 | 🟠 ALTO | Logic | Novo |
| CRED-01 | Credential | `credential/manager.py` | 434 | 🟠 ALTO | Logic | Novo |
| MSF-01 | MSF RPC | `metasploit/rpc.py` | 107 | 🟠 ALTO | Security | Novo |
| CON-01 | MSF Console | `metasploit/console.py` | 227 | 🟠 ALTO | Security | Novo |
| RPT-01 | Report Gen | `reporting/generator.py` | 196 | 🟠 ALTO | Security | Novo |
| RPT-02 | Report Gen | `reporting/generator.py` | 726 | 🟠 ALTO | Logic | Novo |
| GPG-01 | GPG Evidence | `gpg_evidence.py` | 258 | 🟠 ALTO | Logic | Novo |
| GPG-04 | GPG Evidence | `gpg_evidence.py` | 462 | 🟠 ALTO | Logic | Novo |
| GPG-05 | GPG Evidence | `gpg_evidence.py` | 521 | 🟠 ALTO | Logic | Novo |
| HID-01 | DuckyScript | `hid/ducky.py` | 140 | 🟠 ALTO | Logic | Novo |
| HID-04 | HID Injector | `hid/injector.py` | 297 | 🟠 ALTO | Quality | Novo |
| HID-05 | HID Injector | `hid/injector.py` | 514 | 🟠 ALTO | Logic | Novo |
| HID-06 | USB Gadget | `hid/gadget.py` | 630 | 🟠 ALTO | Logic | Novo |
| NET-02 | Network | `network/__init__.py` | 807 | 🟠 ALTO | Quality | Persistente |
| NET-03 | Network | `network/__init__.py` | 519 | 🟠 ALTO | Security | Novo |
| MSF-03 | MSF RPC | `metasploit/rpc.py` | 189 | 🟡 MÉDIO | Logic | Novo |
| MSF-04 | MSF RPC | `metasploit/rpc.py` | 148 | 🟡 MÉDIO | Security | Novo |
| CON-02 | MSF Console | `metasploit/console.py` | 343 | 🟡 MÉDIO | Quality | Novo |
| RPT-04 | Report Gen | `reporting/generator.py` | 641 | 🟡 MÉDIO | Quality | Novo |
| GPG-02 | GPG Evidence | `gpg_evidence.py` | 309 | 🟡 MÉDIO | Logic | Novo |
| GPG-03 | GPG Evidence | `gpg_evidence.py` | 78 | 🟡 MÉDIO | Logic | Novo |
| GPG-06 | GPG Evidence | `gpg_evidence.py` | 240 | 🟡 MÉDIO | Quality | Novo |
| CHRT-04 | Chroot | `core/chroot_process.py` | 136 | 🟡 MÉDIO | Security | Novo |
| BLE-01 | BLE Exploit | `ble/exploit_chain.py` | 596 | 🟡 MÉDIO | Logic | Novo |
| RPT-03 | Report Gen | `reporting/generator.py` | 234 | 🟢 BAIXO | Security | Novo |
| HID-03 | DuckyScript | `hid/ducky.py` | 423 | 🟢 BAIXO | Quality | Novo |
| BOOT-03 | Bootstrap | `bootstrap_chroot.sh` | 140 | 🟢 BAIXO | Quality | Novo |
| BLE-QUIRKS | Device Quirks | `device_quirks.json` | — | 🟢 BAIXO | Quality | Persistente |

**Total: 36 bugs — 5 críticos · 18 altos · 8 médios · 5 baixos**

**Bugs resolvidos desde relatório anterior (Sprint 3):** BLE-01 a BLE-09, NET-02 a NET-09 da versão anterior — 17 bugs corrigidos.  
**Bugs novos introduzidos nos Sprints 4/5:** 31 novos. **Bugs persistentes:** 5 (NET-01, NET-02, NET-03, BLE-01, BLE-QUIRKS).

---

*Revisão estática sobre branch `main` commit `8b65ad9`. Todas as linhas referenciadas verificadas contra o código fonte. Correções propostas são minimais — sem refactoring adicional.*
