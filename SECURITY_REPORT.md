# Urban Hack Sentinel v3 — Security, Bug & Sprint Report
**Versão analisada:** Sprint 0–5 (branch `main`, commit `8b65ad9`) | **Data:** Junho 2026  
**Contexto:** Projeto académico — demonstração de vulnerabilidades em ambiente urbano  
**Autor da revisão:** Claude Code (claude-sonnet-4-6)

---

## Índice

1. [Completion por Sprint](#1-completion-por-sprint)
2. [Análise de Qualidade de Implementação por CVE](#2-análise-de-qualidade-de-implementação-por-cve)
3. [Bugs por Módulo](#3-bugs-por-módulo)
4. [Avaliação Geral de Arquitetura](#4-avaliação-geral-de-arquitetura)
5. [Sumário Executivo de Bugs](#5-sumário-executivo-de-bugs)

---

## 1. Completion por Sprint

Comparação do estado real do repositório contra o MASTER_PLAN.md.

| Sprint | % | Gap Crítico |
|--------|---|-------------|
| S0 — Foundation | **72%** | `core/health.py` ausente; CI/CD ausente; plugin system incompleto |
| S1 — WiFi | **87%** | Testes WiFi ausentes; apenas BLE tem testes |
| S2 — BLE | **75%** | HFP não integrado no pipeline; model IDs placeholder no quirks DB |
| S3 — Network/Camera | **52%** | `camera/enumeration.py` e `camera/vuln_check.py` ausentes; NET-01 crítico |
| S4 — Metasploit | **~60%** | MSF-02 quebra todo o RPC; GPG-04 quebra chain of custody; CHRT-01 path hardcoded |
| S5 — HID/Dashboard | **~30%** | HID bugs funcionais graves (keycode errado, delays corrompem payloads); UI ausente |
| S6 — Polish | **0%** | Não iniciado |
| **TOTAL** | **~53%** | 36 bugs identificados, 5 críticos |

### Detalhe por Sprint

#### S0 — Foundation (72%)
✅ EventBus · ProcessManager · Config (Pydantic v2) · Storage (SQLite WAL + Redis) · Logger (structlog + rich)  
❌ `core/health.py` — `/healthz` e `/metrics` Prometheus ausentes → critério de Done S0 não cumprido  
⚠️ Plugin system — existe apenas para WiFi; sem entry points dinâmicos nem registry global  
❌ CI/CD GitHub Actions — `.github/workflows/` não existe  

#### S1 — WiFi (87%)
✅ WiFiScanner (iw + airodump-ng backends) · HandshakeAttack · PMKIDAttack · WPSPixieAttack · WPSPinAttack · DeauthAttack · HandshakeManager · MACChanger · GeoMapper (gpsd + WiGLE/Kismet/KML)  
⚠️ Testes — apenas `tests/test_ble_module.py` existe; sem `test_wifi_module.py`

#### S2 — BLE (75%)
✅ FastPairScanner · WhisperPairTester · WhisperPairExploit (4 estratégias KBP) · BlueZBondingManager · AccountKeyManager  
⚠️ HFPAudioCapture — código com `arecord` + bluealsa presente mas `run_full_chain()` não chama `start_capture()` (BLE-01)  
⚠️ Device quirks JSON — 9 devices mas Model IDs são placeholders fictícios  

#### S3 — Network/Camera (52%)
✅ NmapScanner · NucleiRunner · CameraDiscovery (mDNS, UPnP, ONVIF, RTSP, HTTP)  
⚠️ RouterScanner — Hydra presente; RouterSploit retorna `[]`  
⚠️ SearchSploitIntegration — presente mas `exploit_id` sem validação (NET-03)  
❌ `camera/enumeration.py` · `camera/vuln_check.py` — ausentes  

#### S4 — Metasploit/Exploitation/Reporting (~60%)
Muito volume em linhas de código mas com bugs que quebram funcionalidade core:  
⚠️ `bootstrap_chroot.sh` — sem checksum Alpine (BOOT-01); edge repos instáveis (BOOT-02)  
⚠️ `chroot_process.py` — path hardcoded do developer (CHRT-01); bind mounts logic errada (CHRT-03)  
⚠️ `metasploit/rpc.py` — msgpack format dict vs array → **todas as chamadas RPC falham** (MSF-02)  
⚠️ `reporting/gpg_evidence.py` — `verify_log()` sempre reporta adulteração (GPG-04); assinatura binária falha TypeError (GPG-01)  
✅ ExploitRunner · CredentialManager (estrutura) · ReportGenerator (estrutura)

#### S5 — HID/Dashboard (~30%)
⚠️ DuckyScript — keycode 'w' errado (HID-01); pickle deserialization CRÍTICO (HID-02)  
⚠️ HIDInjector — DELAY markers enviados como keycodes reais (HID-05); `time.sleep()` bloqueia event loop (HID-04)  
⚠️ USBGadgetManager — exporta variáveis LAYOUT_* não definidas → ImportError (HID-06)  
❌ FastAPI backend · React PWA · Textual TUI · Rich CLI · Plugin Marketplace — ausentes  

---

## 2. Análise de Qualidade de Implementação por CVE

**Escala de implementação:**
- **ÓTIMA** — funcional, integrado no pipeline, testado
- **MÉDIO** — presente mas com gaps funcionais ou bugs bloqueantes
- **FRACO** — estrutura ou referência apenas; sem implementação funcional
- **AUSENTE** — não iniciado

---

### 2.1 Bluetooth Low Energy

---

#### CVE-2025-36911 — WhisperPair (Fast Pair KBP Authentication Bypass) · **MÉDIO**

O exploit mais diferenciador do projeto, com mais trabalho investido.

| Componente | Estado | Detalhe |
|---|---|---|
| Scanner (UUID 0xFE2C) | ✅ Done | `FastPairScanner` via Bleak; parse model ID, pairing mode, account key filter |
| Vulnerability tester | ✅ Done | `WhisperPairTester` — GATT connect → KBP request → parse 0x01 (vuln) / 0x0E (patched) |
| KBP bypass — RAW_KBP | ✅ Done | Strategy 0: KBP sem seeker MAC; fallback mais simples |
| KBP bypass — RAW_WITH_SEEKER | ✅ Done | Strategy 1: KBP com seeker MAC no payload |
| KBP bypass — RETROACTIVE | ✅ Done | Strategy 2: usa flag `usesRetroactiveFlag` do quirks DB |
| KBP bypass — EXTENDED_RESPONSE | ✅ Done | Strategy 3: testa resposta extended response |
| BR/EDR Bonding | ✅ Done | `BlueZBondingManager` — CreateBond/RemoveBond via D-Bus BlueZ |
| Account Key Write | ✅ Done | `AccountKeyManager` — AES-ECB (modo correto), GATT write UUID `fe2c1236` |
| HFP Audio Capture | ⚠️ Parcial | Código `arecord`+bluealsa presente em `HFPAudioCapture`; chamada não integrada em `run_full_chain()` (BLE-01) |
| Device Quirks DB | ⚠️ Parcial | 9 dispositivos em JSON mas Model IDs são placeholders fictícios (`ABCDEF`, `123456`) — quirks nunca aplicados |
| Testes | ⚠️ Parcial | 21 testes; falta coverage de account key com shared_secret e de quirks reordering |

**O que impede ÓTIMA:** HFP não integrado no pipeline + Model IDs placeholder + CRED-02 (validate sempre True) compromete reporting de credenciais capturadas.

---

#### CVE-2023-45866 + CVE-2024-21306 — Bluetooth HID Keystroke Injection · **FRACO**

CVE-2023-45866: Android/Linux aceitam HID connection de dispositivo BT não autenticado.  
CVE-2024-21306: variante Microsoft — mesma primitiva, diferente stack.

| Componente | Estado | Detalhe |
|---|---|---|
| DuckyScript Parser | ⚠️ Parcial | 7 layouts (US/GB/DE/FR/ES/IT/RU); mas keycode 'w'=0x19 (=0x19 de 'v') — HID-01 corrompe payloads |
| HID Injector (uinput) | ⚠️ Parcial | Funcional para injeção local; DELAY markers enviados como keycodes reais (HID-05) |
| HID Injector (USB Gadget) | ⚠️ Parcial | USBGadgetManager via configfs; LAYOUT_* ImportError (HID-06) |
| **BT wireless OTA injection** | ❌ Ausente | O CVE exige envio de HID reports via Bluetooth não autenticado. A implementação usa `uinput` (local) ou USB Gadget — **não implementa o vector OTA que define o CVE**. Falta integração BlueZ HID Profile para connection não autenticada |

**Avaliação:** O módulo HID em si está razoavelmente construído mas explora um vetor diferente do CVE — injeção USB/uinput local vs. injeção BT wireless. Para ser fiel ao CVE, precisaria de `bluetoothctl connect` + registar HID profile via BlueZ `ProfileManager1` sem pairing.

---

#### CVE-2019-9506 — KNOB (Key Negotiation of Bluetooth) · **AUSENTE**

Força a negociação de entropy da chave de sessão BR/EDR para 1 byte, quebrando qualquer criptografia Bluetooth Classic.

| Componente | Estado | Detalhe |
|---|---|---|
| Link layer entropy negotiation | ❌ Ausente | Requer InternalBlue para manipular PDUs LMP diretamente |
| Detecção passiva | ❌ Ausente | `BlueZBondingManager` existe mas não instrumenta a negociação de chave |

**Avaliação:** Não implementável sem hardware InternalBlue (CYW20735 dev board ~30€ ou chip Broadcom específico). O MASTER_PLAN reconhece este constraint. Sem HW, zero funcionalidade.

---

#### CVE-2020-10135 — BIAS (Bluetooth Impersonation Attack) · **AUSENTE**

Permite impersonation de dispositivo previamente emparelhado sem conhecer a link key, explorando legacy authentication no Bluetooth 5.1 e anteriores.

| Componente | Estado | Detalhe |
|---|---|---|
| Secure connection downgrade | ❌ Ausente | |
| Legacy auth bypass | ❌ Ausente | |

**Avaliação:** Mesma limitação de hardware que KNOB. `BlueZBondingManager` poderia servir de base mas a manipulação da autenticação requer acesso ao link layer que BlueZ não expõe via D-Bus.

---

#### CVE-2023-24023 — BLUFFS (Bluetooth Forward & Future Secrecy Break) · **AUSENTE**

Permite que um attacker force reuso de session keys derivando-as com entropy controlada, quebrando forward secrecy.

| Componente | Estado | Detalhe |
|---|---|---|
| Session key forcing | ❌ Ausente | |
| Referência no código | ❌ Ausente | Nem sequer referenciado nos ficheiros de código |

**Avaliação:** CVSS 6.8. Tecnicamente o mais recente dos três ataques Bluetooth Classic. Requer InternalBlue + patch específico. Sem qualquer foothold no codebase.

---

#### SweynTooth (12 CVEs: CVE-2019-16336, CVE-2019-17060/61, CVE-2020-10069, et al.) — BLE SoC Vulnerabilities · **AUSENTE**

Afeta SoCs BLE de TI, NXP, Cypress, Dialog, Microchip, ST e Telink. Inclui deadlock, OOB write, crash de link layer.

| Componente | Estado | Detalhe |
|---|---|---|
| Auto-detect por advertisement | ❌ Ausente | `FastPairScanner` captura advertisements mas sem lógica de fingerprinting de SoC |
| Exploit primitives | ❌ Ausente | Requer nRF52840 dongle para raw BLE link layer access |

**Avaliação:** O MASTER_PLAN planeia (S4.13) mas sem implementação. Para um Pi + nRF52840, o projeto sweyntooth-bt existe como referência — wrapping seria de alto impacto académico.

---

#### CVE-2025-27840 — ESP32 Hidden HCI Commands · **AUSENTE**

29 comandos HCI não documentados na ROM do ESP32 permitem leitura de RAM, GPIO e NVRAM via interface BT.

| Componente | Estado | Detalhe |
|---|---|---|
| Detecção de ESP32 via BLE scan | ❌ Ausente | `FastPairScanner` não tem fingerprinting específico de ESP32 |
| Execução dos 29 comandos HCI | ❌ Ausente | |

**Avaliação:** CVE publicado em Março 2025. Academicamente muito relevante dado o número de devices IoT urbanos com ESP32. A detecção passiva via BLE (pelo OUI `A4:CF:12` da Espressif) seria simples de adicionar ao `FastPairScanner`.

---

### 2.2 WiFi

---

#### CVE-2019-15126 — Kr00k (WPA2 CCMP Nonce Reuse After Disassociation) · **FRACO**

Chips Broadcom e Cypress usam chave all-zero após disassociação. Dados encriptados decifráveis offline.

| Componente | Estado | Detalhe |
|---|---|---|
| Deauth para forçar disassociação | ✅ Done | `DeauthAttack` funcional |
| Captura de frames pós-disassociação | ❌ Ausente | `HandshakeAttack` foca em EAPOL, não em data frames com all-zero key |
| Detecção automática de HW vulnerável | ❌ Ausente | OUI lookup para Broadcom/Cypress presente no `wifi/scanner.py` (via vendor) mas sem lógica de triagem |
| Decifração offline | ❌ Ausente | Sem integração com r00kie-kr00kie / hexway |

**Avaliação:** Os pré-requisitos (deauth + scan) existem no WiFi module mas o núcleo do ataque — capturar frames com key nula e decifrar — não está implementado. PoC público disponível (hexway/r00kie-kr00kie); integração seria de esforço médio.

---

#### CVE-2020-24586 / CVE-2020-24587 / CVE-2020-24588 — FragAttacks · **FRACO**

Vulnerabilidades no aggregation e mixed key de fragmentos 802.11. Permitem injection de frames arbitrários em redes WPA2/WPA3.

| Componente | Estado | Detalhe |
|---|---|---|
| Detecção via NmapScanner VULN_SCAN | ⚠️ Parcial | NSE scripts podem cobrir se nuclei templates disponíveis |
| Teste de fragmentação | ❌ Ausente | Sem wrapper da ferramenta de Vanhoef (`fragattacks`) |
| Injection de frames | ❌ Ausente | |

**Avaliação:** Ferramenta pública de Mathy Vanhoef (vanhoefm/fragattacks) seria o wrapper natural. O `ProcessManager` e `ChrootProcessManager` têm a infraestrutura para executar ferramentas externas; falta apenas o módulo `wifi/attacks/fragattacks.py`.

---

#### CVE-2023-52424 — SSID Confusion · **FRACO**

Cliente conecta a rede diferente da pretendida porque o SSID não faz parte do PMK em redes multi-band transitioning.

| Componente | Estado | Detalhe |
|---|---|---|
| Detecção de redes em modo transition | ❌ Ausente | `WiFiScanner` lista SSIDs mas sem lógica de downgrade band |
| Evil Twin setup | ❌ Ausente | Sem módulo `rogue_ap.py` ou `hostapd-mana` wrapper |
| MITM após downgrade | ❌ Ausente | |

**Avaliação:** Sem ferramenta pública — seria contribuição original de alto valor. Requer segunda interface WiFi (Evil Twin) ou `hostapd-mana`. A deteção passiva de transition mode seria de impacto imediato e mais simples de implementar.

---

#### WPS Pixie Dust + WPS Common PINs · **ÓTIMA**

| Componente | Estado | Detalhe |
|---|---|---|
| `WPSPixieAttack` | ✅ Done | `reaver -K 1`; parse de PIN/PSK; fallback `pixiewps` se M1-M3 capturados |
| `WPSPinAttack` | ✅ Done | OUI DB para PINs por vendor; `reaver -p`; rate limiting configurável |
| Relatório de resultado | ✅ Done | `AttackResult` com status/output/credentials |

**Avaliação:** Implementação sólida e completa. O único gap é que depende de `reaver` no sistema ou na chroot Alpine (que o bootstrap instala). Integração com HandshakeManager poderia exportar PINs crackeados para o CredentialManager.

---

#### WPA2 Handshake Capture + PMKID + Deauth · **ÓTIMA**

| Componente | Estado | Detalhe |
|---|---|---|
| `HandshakeAttack` | ✅ Done | `aireplay-ng` deauth → `airodump-ng` capture; validação `aircrack-ng` |
| `PMKIDAttack` | ✅ Done | `hcxdumptool` captura PMKID; export `.22000` para hashcat |
| `HandshakeManager` | ✅ Done | Dedup BSSID+ESSID; hashcat integration; WiGLE CSV + Kismet netxml |
| `MACChanger` | ✅ Done | Profiles apple/samsung/intel/random; persistence |
| `GeoMapper` | ✅ Done | gpsd TCP 2947; KML + WiGLE CSV + Kismet netxml |

**Avaliação:** O módulo WiFi é o mais maduro do projeto. Pipeline end-to-end funcional. A falta de testes unitários (mock `iw`/`airodump-ng`) é o único gap visível.

---

### 2.3 IoT & Protocolos Urbanos

---

#### TPMS Vehicle Tracking (RTL-SDR 433MHz) · **AUSENTE**

Cada pneu transmite um ID único a 433MHz. Tracking passivo de veículos possível a centenas de metros.

| Componente | Estado | Detalhe |
|---|---|---|
| RTL-SDR integration | ❌ Ausente | Sem módulo `rtl_433` wrapper; sem módulo SDR genérico |
| GPS correlation | ❌ Ausente | `GeoMapper` existe mas sem ligação a TPMS |

**Avaliação:** Alto impacto de demonstração urbana — tracking de um carro num estacionamento é visualmente apelativo. `rtl_433` (software open-source) decodifica automaticamente; integração seria de esforço baixo se o hardware RTL-SDR estiver disponível.

---

#### MQTT Attack Suite · **FRACO**

Brokers MQTT sem autenticação são comuns em redes IoT urbanas (contadores inteligentes, sensores de estacionamento, semáforos).

| Componente | Estado | Detalhe |
|---|---|---|
| Broker discovery (port 1883) | ⚠️ Parcial | `NmapScanner` deteta port 1883/8883 via scan genérico |
| Subscribe a topics sem auth | ❌ Ausente | Sem cliente MQTT (`paho-mqtt` não está nas deps) |
| Enumeração de topics | ❌ Ausente | |
| Injeção de mensagens | ❌ Ausente | |

**Avaliação:** O `NetworkModule` tem a infraestrutura de discovery mas sem cliente MQTT dedicado. `paho-mqtt` seria simples de adicionar. Enumeração de topics `#` num broker sem auth é de alto impacto e muito demonstrável.

---

#### AirDrop Phone Number Harvesting · **FRACO**

Os iPhones transmitem os últimos 3 bytes do SHA256 do número de telefone via AWDL/BLE. Com rainbow tables para o espaço `+351 9XXXXXXXX`, é possível recuperar números.

| Componente | Estado | Detalhe |
|---|---|---|
| Captura de BLE advertisements | ✅ Done | `FastPairScanner` captura advertisements; parse de manufacturer data |
| Detecção de AWDL/AirDrop | ❌ Ausente | Sem filtro para company ID Apple + service UUID AirDrop |
| SHA256 lookup / rainbow tables | ❌ Ausente | |

**Avaliação:** O `FastPairScanner` poderia ser adaptado para filtrar anúncios AirDrop com poucas linhas. As rainbow tables para números portugueses (~10M números) seriam o componente mais demorado a construir mas pré-computáveis offline.

---

### Resumo de Implementação por CVE

| CVE / Ataque | Área | Qualidade | Estado Real |
|---|---|---|---|
| CVE-2025-36911 WhisperPair | BLE | **MÉDIO** | Pipeline 80% funcional; HFP e quirks por completar |
| CVE-2023-45866/CVE-2024-21306 HID | BLE/HID | **FRACO** | Módulo HID presente mas ataca vector diferente (USB/uinput vs. BT OTA) |
| CVE-2019-9506 KNOB | BT Classic | **AUSENTE** | Requer InternalBlue; zero implementação |
| CVE-2020-10135 BIAS | BT Classic | **AUSENTE** | Requer InternalBlue; zero implementação |
| CVE-2023-24023 BLUFFS | BT Classic | **AUSENTE** | Nem referenciado no código |
| SweynTooth (12 CVEs) | BLE SoC | **AUSENTE** | Requer nRF52840; zero implementação |
| CVE-2025-27840 ESP32 HCI | IoT/BLE | **AUSENTE** | Detecção passiva seria simples; não iniciada |
| CVE-2019-15126 Kr00k | WiFi | **FRACO** | Deauth existe; captura/decifração Kr00k ausente |
| CVE-2020-24586/87/88 FragAttacks | WiFi | **FRACO** | Infraestrutura de subprocess disponível; módulo dedicado ausente |
| CVE-2023-52424 SSID Confusion | WiFi | **FRACO** | Scanner lista SSIDs; sem lógica de downgrade/rogue AP |
| WPS Pixie Dust | WiFi | **ÓTIMA** | Funcional end-to-end |
| WPA2 Handshake + PMKID | WiFi | **ÓTIMA** | Funcional end-to-end; pipeline hashcat completo |
| TPMS Vehicle Tracking | IoT/SDR | **AUSENTE** | Sem RTL-SDR module |
| MQTT Attack Suite | IoT | **FRACO** | Discovery genérico; sem cliente MQTT |
| AirDrop Harvesting | BLE/AWDL | **FRACO** | FastPairScanner pode ser adaptado; SHA256 lookup ausente |

**CVEs com implementação real (ÓTIMA ou MÉDIO): 3/15 (20%)**

---

## 3. Bugs por Módulo

### Severidade CRÍTICA

---

**MSF-02 · `metasploit/rpc.py:204` — Formato msgpack Errado → Todo o RPC Falha**

O protocolo msgrpc exige um **array**: `[method, token, arg1, ...]`. O código envia um **dict**: `{"method": ..., "params": [...]}`. Todas as chamadas RPC são rejeitadas pelo servidor Metasploit. A integração MSF está completamente não funcional.

Fix: `params = [method] + ([self._token] if self._token and method != "auth.login" else []) + list(args); packed = msgpack.packb(params, use_bin_type=True)`

---

**CRED-02 · `credential/manager.py:416` — `validate_credential()` Sempre Retorna True**

Stub que define `validated=True` e `validity_status="valid"` sem qualquer verificação de rede. Relatórios académicos mostram 100% das credenciais como "válidas" — dados fabricados.

Fix: Implementar verificação real ou lançar `NotImplementedError`.

---

**CHRT-01 · `core/chroot_process.py:~370` — Path Hardcoded do Developer**

`ensure_chroot()` referencia `/home/andresantos/Desktop/Projects/urban-hack-sentinel/scripts/...`. Este path nunca existe em deployment — toda a funcionalidade chroot retorna `False` silenciosamente. Expõe PII do developer.

Fix: `script_path = Path(__file__).parents[4] / "scripts" / "bootstrap_chroot.sh"`

---

**HID-02 · `hid/ducky.py:562` — Pickle Deserialization → RCE**

`save_compiled()` e `load_compiled()` usam `pickle`. `pickle.load()` num ficheiro não confiável permite execução arbitrária de código. Qualquer fonte de ficheiros `.ducky` compilados (USB, API, rede) pode comprometer o Pi.

Fix: Substituir pickle por JSON com dicts de keycodes inteiros.

---

**NET-01 · `network/__init__.py:193` — Argument Injection no NmapScanner** *(persistente)*

`targets` passados diretamente para `cmd.extend(targets)` sem validação. Com `create_subprocess_exec`, permite injeção de flags nmap (ex: um target `"--script malicious"` executa NSE scripts não autorizados).

Fix: Validar cada target com `ipaddress.ip_network(t, strict=False)` antes de aceitar.

---

### Severidade ALTA

---

**BOOT-01 · `bootstrap_chroot.sh:58` — Sem Checksum Alpine Tarball**

`# Verify checksum (optional but recommended)` sem código — tarball extraído sem verificação. MITM entrega rootfs malicioso executado como root.

Fix: `wget -q "${MINIROOTFS_URL}.sha256" && sha256sum -c "${MINIROOTFS}.sha256"`

---

**BOOT-02 · `bootstrap_chroot.sh:85` — Alpine Edge Repos na Chroot**

`edge/main`, `edge/community`, `edge/testing` adicionados. Packages rolling e sem assinatura introduzem risco de supply chain.

Fix: Usar apenas repos estáveis `v${ALPINE_VERSION%.*}/main` e `/community`.

---

**CHRT-02 · `chroot_process.py:240` — NameError no finally Block**

Se `create_subprocess_exec()` lançar exceção, `proc` nunca é atribuído mas o `finally` referencia `proc.pid` → `NameError` engole a exceção original.

Fix: `if 'proc' in locals() and proc.pid in self._active_processes: del self._active_processes[proc.pid]`

---

**CHRT-03 · `chroot_process.py:111` — Bind Mounts Construídos Incorretamente**

`bind_cmds` é lista plana de strings; o generator itera sobre strings individuais e o `sh -c` recebe `"mount && --bind && /proc && ..."` — todos os bind mounts falham e o payload nunca corre.

Fix: Construir como lista-de-listas: `bind_cmds.append(["mount", "--bind", src, dst])`

---

**CRED-01 · `credential/manager.py:434` — `field(default_factory=list)` em Assinatura de Função**

`field()` é válido apenas em `@dataclass`. Na função, avalia para um objeto `Field` como default — callers que omitem `extra_args` recebem o objeto; `cmd.extend()` lança `TypeError`.

Fix: `extra_args: Optional[List[str]] = None` com `extra_args = extra_args or []` no corpo.

---

**MSF-01 · `rpc.py:107,109` — Password Default `"msf"` + SSL Desativado**

`password: str = "msf"` e `ssl_verify: bool = False` por omissão. MITM trivial ao canal RPC.

Fix: Sem default para password (forçar config explícita). `ssl_verify=True` por omissão.

---

**MSF-03 · `rpc.py:189,210` — Token Duplicado em `auth.logout`**

`_call("auth.logout", self._token)` prepend o token novamente → servidor recebe `[token, token]` → logout falha e sessão fica aberta no servidor.

Fix: Excluir `"auth.logout"` do prepend: `if method not in ("auth.login", "auth.logout")`.

---

**CON-01 · `metasploit/console.py:227` — Injeção de Comandos via Options**

`f"set {k} {v}"` sem sanitização. Um valor com `\n` injeta comandos adicionais no resource script `.rc`.

Fix: `if '\n' in str(v) or '\r' in str(v): raise ValueError(...)`

---

**RPT-01 · `reporting/generator.py:196` — GPG Passphrase em Campo Plaintext**

`ReportConfig.gpg_passphrase: str` num dataclass serializável. Qualquer serialização (JSON, logs, WebSocket) expõe a passphrase GPG.

Fix: Callable secret provider em vez de campo string.

---

**RPT-02 · `reporting/generator.py:726` — Name Collision Quebra sign_report()**

`gpg = gpg.GPG()` sobrescreve o alias do módulo. Na segunda chamada, `gpg.GPG()` lança `AttributeError`.

Fix: `import gnupg as gnupg_module` → `gnupg_module.GPG()`.

---

**GPG-01 · `gpg_evidence.py:258` — Assinatura Binária Falha com TypeError**

Para `DETACHED_BINARY`, abre em modo `'wb'` mas escreve `str(signature)` → `TypeError`. Nenhuma assinatura binária é jamais escrita.

Fix: `f.write(signature.data)` (bytes) para o modo binário.

---

**GPG-04 · `gpg_evidence.py:462` — `verify_log()` Sempre Reporta Adulteração**

Hash calculado *incluindo* o campo `entry_hash`, mas o hash original foi calculado *sem* esse campo. Comparação falha sempre — chain of custody inutilizável.

Fix: `entry_hash = entry.pop("entry_hash", ""); computed = _compute_entry_hash(entry); entry["entry_hash"] = entry_hash`

---

**GPG-05 · `gpg_evidence.py:521` — GPGSigner Default sem Key → Silenciosamente Não Assina**

`gpg_signer or GPGSigner()` com `key_id=None`. `sign_file()` retorna `False` sem aviso. Todos os artefactos ficam sem assinatura GPG.

Fix: Tornar `gpg_signer` obrigatório ou logar aviso explícito quando `None`.

---

**HID-01 · `hid/ducky.py:140` — Keycode Errado para 'w' (e Numpad 4)**

`'v': 0x19` e `'w': 0x19` — colisão. Qualquer payload com `powershell`, `wget`, `whoami`, URLs com `www` produz 'v' em vez de 'w'. `'keypad_4': 0x5B` deve ser `0x5C`.

Fix: `'w': 0x1A`, `'keypad_4': 0x5C`.

---

**HID-04 · `hid/injector.py:297` — `time.sleep()` Bloqueia o Event Loop**

`delay()` chama `time.sleep()` em contexto async. Payloads DuckyScript com DELAY frequente congelam todas as coroutines.

Fix: `async def delay(ms): await asyncio.sleep(ms / 1000.0)`

---

**HID-05 · `hid/injector.py:514` — DELAY Markers Enviados como Keycodes Reais**

`execute_ducky()` escreve todos os reports para `/dev/hidg*` incluindo delay markers (bit 0x80 set). O kernel interpreta-os como keystrokes → garbage characters enviados ao host em vez de pause.

Fix: `if report[0] & 0x80: await asyncio.sleep(delay_ms / 1000)` em vez de escrever para o device.

---

**HID-06 · `hid/gadget.py:630` — Exporta LAYOUT_* Não Definidas → ImportError**

`__all__` de `gadget.py` lista `LAYOUT_US`, `LAYOUT_GB`, etc., que não estão definidas nesse ficheiro.

Fix: Remover essas entradas de `__all__` em `gadget.py`.

---

**NET-02 · `network/__init__.py:807` — ONVIF WS-Discovery Socket Bloqueante** *(persistente)*

`_onvif_discovery()` usa `recvfrom` bloqueante (timeout 5s) em `async def`. Bloqueia o event loop durante esse tempo.

Fix: `data, addr = await asyncio.to_thread(sock.recvfrom, 65535)`

---

**NET-03 · `network/__init__.py:519` — SearchSploit `exploit_id` sem Validação**

`exploit_id` passado diretamente ao subprocess. Path traversal: `"../../../etc/passwd"` força download para localização arbitrária.

Fix: Validar contra `r"^\d+$"` (IDs ExploitDB são inteiros).

---

### Severidade MÉDIA

**MSF-04** — SSL CERT_NONE mesmo com `ssl=True` (`rpc.py:148`)  
**CON-02** — LHOST hardcoded `0.0.0.0` em `template_exploit_chain()` → reverse shells não funcionais (`console.py:343`)  
**GPG-02** — `verify_signature()` usa API errada do python-gnupg; verificação produz resultados incorretos (`gpg_evidence.py:309`)  
**GPG-03** — Dead code `entry_data` vs `entry_dict` em `add_entry()` cria confusão de nomes (`gpg_evidence.py:78`)  
**GPG-06** — `sign_file()` lê ficheiro inteiro para RAM; pcaps grandes causam OOM (`gpg_evidence.py:240`)  
**CHRT-04** — `["cd", working_dir, "&&"]` prepend em lista exec; `&&` não funciona sem shell (`chroot_process.py:136`)  
**RPT-04** — `html.write_pdf()` síncrono em `async def`; bloqueia event loop 5-30s num Pi 4 (`generator.py:641`)  
**BLE-01** — `run_full_chain()` não chama `start_capture()`; HFP reporta sucesso sem gravar (`exploit_chain.py:596`)  

### Severidade BAIXA

**BOOT-03** — Packages duplicados na lista `apk add` (`bootstrap_chroot.sh:140`)  
**RPT-03** — Jinja2 autoescape não cobre `.md`; HTML em findings passa direto para Markdown (`generator.py:234`)  
**HID-03** — Dead code `text = ' '.join(cmd.args)` nunca usado (`ducky.py:423`)  
**BLE-QUIRKS** — Model IDs placeholder em `device_quirks.json` — quirks nunca aplicados  

---

## 4. Avaliação Geral de Arquitetura

### 4.1 Arquitetura · 7/10

**Pontos fortes:**

O plano arquitetural do Urban Hack Sentinel v3 é bem pensado para um projeto académico. A escolha de async-first com `asyncio` como primitiva central é correta para um tool de field operations — I/O bound workloads (scans de rede, BLE, subprocess de ferramentas externas) beneficiam diretamente do modelo não-bloqueante. O EventBus (pub/sub com `asyncio.Queue`) é um padrão adequado para desacoplar módulos heterogéneos.

O SQLite WAL mode para dados estruturados e Redis para pub/sub é uma stack razoável para um Pi: zero config, zero infra externa, mas com capacidade de streaming e cache. A escolha de Pydantic v2 para configuração com hot-reload é moderna e certa.

**Limitações estruturais:**

O modelo async não é aplicado de forma consistente — vários módulos introduzem `time.sleep()`, sockets bloqueantes e leituras de ficheiro inteiro em funções `async def` (RPT-04, ONVIF-01, HID-04, GPG-06), o que contradiz o princípio async-first e pode travar o Pi em momentos críticos de field operation.

O plugin system está anunciado mas incompleto: existe apenas para o módulo WiFi e sem o mecanismo de registry/entry-points dinâmicos que permitiria adicionar módulos novos sem modificar o código core. Os módulos S4 (Metasploit, Credential, Report) são importados diretamente pelo ExploitRunner, criando acoplamento tight em vez de passar pelo EventBus.

A ausência de `/healthz` e `/metrics` Prometheus é uma lacuna real — num Pi em campo não há ecrã; saber se o processo está vivo e saudável via HTTP é essencial para qualquer operação autónoma.

---

### 4.2 Performance · 5/10

**Contexto de hardware:** Raspberry Pi 4 (4GB RAM, Cortex-A72 1.8GHz) ou Pi 5 (8GB RAM, Cortex-A76 2.4GHz). O projeto declaradamente targets ARM64.

**Problemas identificados:**

*Event loop contention* — Os bloqueios mais críticos são: WeasyPrint PDF (5-30s no Pi 4), ONVIF socket (5s), DuckyScript DELAYs (seconds por payload), GPG signing de ficheiros grandes (variável). Qualquer um destes bloqueia **todas** as coroutines durante esse tempo — o Pi deixa de responder a BLE events, não processa callbacks, não envia WebSocket updates. Num tool de field, isto pode significar perder captures.

*Sem resource limits entre módulos* — Um scan Nmap com `-A` (aggressive) mais Nuclei runner mais Metasploit RPC simultâneos podem saturar a CPU de um Pi 4 facilmente. O `ProcessManager` tem suporte a cgroups v2 no plano mas não está implementado.

*Credential Manager em memória* — `CredentialManager._credentials` acumula todas as credenciais em RAM (`Dict[str, Credential]`). Em sessões longas com muitos hosts, pode crescer indefinidamente.

*WeasyPrint* — biblioteca C com binding Python, muito pesada para ARM. Numa sessão de 8 horas, gerar um relatório PDF pode ser a operação mais cara do projeto. `asyncio.to_thread()` é a correção imediata; alternativa a longo prazo: usar `pandoc` via subprocess (mais leve no Pi).

**O que funciona bem:** A pipeline WiFi (scanner + airodump + hashcat) é subprocess-based e naturalmente async. O NmapScanner com `asyncio.create_subprocess_exec` e streaming de XML é eficiente. O EventBus com `asyncio.Queue` tem backpressure natural.

---

### 4.3 Modularidade · 6/10

**Pontos fortes:**

A divisão em domínios (`ble/`, `wifi/`, `network/`, `hid/`, `metasploit/`, `reporting/`, `credential/`, `exploit/`) é coerente e reflecte o threat model urbano. Cada domínio tem `__init__.py` com exports bem definidos. Os dataclasses (`AttackResult`, `ExploitResult`, `Credential`, `Finding`) criam contratos de dados razoavelmente estáveis entre módulos.

**Limitações:**

A `ExploitRunner` importa diretamente `MetasploitRPC`, `MetasploitConsole`, `NucleiRunner`, `SearchSploitIntegration` e `ChrootProcessManager` — 5 módulos diferentes com import direto. Qualquer mudança numa dessas interfaces exige atualizar `ExploitRunner`. A intenção de routing via EventBus não está implementada.

O módulo `network/__init__.py` com 1072 linhas é demasiado monolítico — `NmapScanner`, `NucleiRunner`, `SearchSploitIntegration`, `RouterScanner`, `CameraDiscovery` e `NetworkModule` num único ficheiro. A divisão planeada no MASTER_PLAN (um ficheiro por classe) deveria ser implementada.

Módulos que faltam e que criam buracos na modularidade: `camera/enumeration.py`, `camera/vuln_check.py`, `ui/api/main.py`, `ui/tui/app.py`, `ui/cli/main.py`, `core/health.py`.

---

### 4.4 Compatibilidade · 4/10

| Target | Suporte | Notas |
|---|---|---|
| **Raspberry Pi 5 (ARM64)** | ✅ First-class | Target declarado; Alpine chroot ARM64 |
| **Raspberry Pi 4 (ARM64)** | ✅ Funcional | Mesma arquitectura; RAM pode ser limitante com Metasploit |
| **Raspberry Pi 3 (ARM32)** | ❌ Não suportado | Python 3.11 arm64 só; sem ARM32 path |
| **Raspberry Pi Zero 2W** | ⚠️ Marginal | ARM64 mas 512MB RAM — Metasploit + BlueZ + Python não cabem |
| **x86_64 Linux (dev machine)** | ⚠️ Parcial | Código Python corre; `dbus-fast`/`bleak` funcionam; USB gadget configfs e HID requerem kernel OTG |
| **x86_64 com VM** | ⚠️ Degradado | BlueZ passthrough requer USB BT adapter; WiFi monitor mode requer passthrough |
| **macOS / Windows** | ❌ Não suportado | `dbus-fast`, `uinput`, configfs são Linux-only by design |
| **Kali Linux ARM64** | ✅ Funcional | Todas as ferramentas externas disponíveis via apt |
| **Alpine Linux (chroot)** | ✅ By design | Bootstrap script cria chroot ARM64 |

**Limitações de compatibilidade:**

O USB Gadget (configfs HID) requer que o Pi esteja ligado via USB OTG — funciona apenas com Pi 4/5 ligados a um host via USB-C como device, ou com hat de USB gadget. Num Pi com alimentação normal, configfs existe mas sem UDC (USB Device Controller) disponível.

O `core/health.py` ausente e a falta de CI/CD significa que não há teste automatizado de compatibilidade — qualquer alteração pode quebrar silenciosamente em ARM64 real.

A dependência de `bluealsa` para HFP audio não está em `pyproject.toml` nem no bootstrap script — é um sistema Debian que precisa de instalação manual.

---

### 4.5 Segurança da Própria Ferramenta · 4/10

Paradoxalmente, uma ferramenta de segurança com bugs de segurança sérios no seu próprio código:

- **MSF-01** — password default pública para o daemon Metasploit
- **HID-02** — pickle deserialization = RCE via ficheiros DuckyScript
- **BOOT-01** — bootstrap sem verificação de integridade do rootfs
- **CHRT-01** — path hardcoded em `ensure_chroot()` quebra isolamento pretendido
- **RPT-01** — passphrase GPG em campo de dataclass serializável
- **CRED-01** — export de credenciais capturadas em CSV/JSON plaintext sem encriptação

Num contexto académico em que o Pi pode ser confiscado durante uma demonstração, a exposição de credenciais capturadas (CRED-01) e a passphrase GPG (RPT-01) são riscos reais.

---

### 4.6 Rating Geral

| Dimensão | Rating | Nota |
|---|---|---|
| **Conceito e Plano** | 9/10 | MASTER_PLAN ambicioso, bem estruturado, urbano e relevante |
| **Arquitetura Core (S0)** | 7/10 | EventBus + ProcessMgr + Config + Storage sólidos |
| **WiFi Module (S1)** | 8/10 | Pipeline mais maduro; WPS + Handshake + Geo funcionais |
| **BLE/WhisperPair (S2)** | 6/10 | 4 estratégias KBP implementadas; HFP e quirks por completar |
| **Network/Camera (S3)** | 5/10 | Camera enum/vuln ausentes; NET-01 crítico por resolver |
| **Metasploit/Reporting (S4)** | 4/10 | Muito volume mas MSF RPC e GPG chain of custody quebrados |
| **HID/Dashboard (S5)** | 3/10 | HID bugs funcionais; UI (FastAPI/TUI/CLI) ausente |
| **CVE Coverage** | 3/10 | 3/15 CVEs com implementação real; restantes ausentes ou FRACO |
| **Qualidade de Código** | 5/10 | Bons padrões mas inconsistentemente aplicados; 36 bugs |
| **Segurança da Ferramenta** | 4/10 | Vários bugs de segurança na própria ferramenta |
| **OVERALL** | **5.4/10** | Projeto academicamente sólido em conceito; implementação em ~53% com bugs bloqueantes |

---

### 4.7 Melhorias Prioritárias

**Semana 1 — Resolver bugs bloqueantes (5h total)**

| # | Fix | Esforço |
|---|-----|---------|
| 1 | MSF-02: dict → array em msgpack | 15 min |
| 2 | CHRT-01: path hardcoded do developer | 5 min |
| 3 | HID-01: keycode 'w' = 0x1A | 5 min |
| 4 | HID-05: check `report[0] & 0x80` antes de escrever para hidg | 30 min |
| 5 | GPG-04: pop entry_hash antes de calcular hash de verificação | 20 min |
| 6 | HID-02: substituir pickle por JSON | 1h |
| 7 | NET-01: validar targets com `ipaddress.ip_network()` | 30 min |
| 8 | CRED-02: lançar `NotImplementedError` em `validate_credential()` | 10 min |
| 9 | CHRT-03: bind_cmds como lista-de-listas | 30 min |
| 10 | HID-06: remover LAYOUT_* de `__all__` em gadget.py | 5 min |

**Semana 2 — Completar o que está a 80%**

| # | Tarefa | Esforço |
|---|--------|---------|
| 11 | Integrar `start_capture()` em `run_full_chain()` (BLE-01) | 1h |
| 12 | Implementar `core/health.py` — `/healthz` + Prometheus `/metrics` | 3h |
| 13 | `camera/enumeration.py` — default creds, auth test | 4h |
| 14 | `camera/vuln_check.py` — CVE mapping | 4h |
| 15 | Substituir `time.sleep()` por `asyncio.sleep()` em HID (HID-04) + WeasyPrint por `asyncio.to_thread()` (RPT-04) | 30 min |

**Semana 3 — Fechar gaps de CVE com maior impacto visual**

| # | CVE | Esforço | Impacto Académico |
|---|-----|---------|-------------------|
| 16 | CVE-2025-27840 — Deteção passiva ESP32 por OUI `A4:CF:12` no FastPairScanner | 2h | Alto — muitos IoT urbanos usam ESP32 |
| 17 | TPMS — `rtl_433` subprocess wrapper + GPS correlation | 4h | Muito alto — tracking de carros em tempo real |
| 18 | MQTT — `paho-mqtt` subscriber; enumerate topics `#`; log mensagens | 3h | Alto — infra urbana real |
| 19 | AirDrop — filtro AWDL no FastPairScanner | 3h | Médio-alto — impacto de privacidade imediato |

**A Longo Prazo — Para v3 Completo**

1. UI completa (S5.4–S5.7) — FastAPI + React + TUI + CLI; maior gap de usabilidade
2. CI/CD GitHub Actions com ruff + mypy + pytest (S0.9)
3. Model IDs reais no `device_quirks.json`
4. Kr00k: integrar `r00kie-kr00kie` via ChrootProcessManager
5. FragAttacks: wrapping da tool de Vanhoef
6. Sprint 6 — hardening, E2E tests, release SBOM, docs MkDocs

---

## 5. Sumário Executivo de Bugs

| ID | Módulo | Ficheiro | Linha | Severidade | Estado |
|----|--------|----------|-------|------------|--------|
| MSF-02 | MSF RPC | `metasploit/rpc.py` | 204 | 🔴 CRÍTICO | Novo |
| CRED-02 | Credential | `credential/manager.py` | 416 | 🔴 CRÍTICO | Novo |
| CHRT-01 | Chroot | `core/chroot_process.py` | ~370 | 🔴 CRÍTICO | Novo |
| HID-02 | DuckyScript | `hid/ducky.py` | 562 | 🔴 CRÍTICO | Novo |
| NET-01 | Network | `network/__init__.py` | 193 | 🔴 CRÍTICO | Persistente |
| BOOT-01 | Bootstrap | `bootstrap_chroot.sh` | 58 | 🟠 ALTO | Novo |
| BOOT-02 | Bootstrap | `bootstrap_chroot.sh` | 85 | 🟠 ALTO | Novo |
| CHRT-02 | Chroot | `core/chroot_process.py` | 240 | 🟠 ALTO | Novo |
| CHRT-03 | Chroot | `core/chroot_process.py` | 111 | 🟠 ALTO | Novo |
| CRED-01 | Credential | `credential/manager.py` | 434 | 🟠 ALTO | Novo |
| MSF-01 | MSF RPC | `metasploit/rpc.py` | 107 | 🟠 ALTO | Novo |
| MSF-03 | MSF RPC | `metasploit/rpc.py` | 189 | 🟠 ALTO | Novo |
| CON-01 | MSF Console | `metasploit/console.py` | 227 | 🟠 ALTO | Novo |
| RPT-01 | Report Gen | `reporting/generator.py` | 196 | 🟠 ALTO | Novo |
| RPT-02 | Report Gen | `reporting/generator.py` | 726 | 🟠 ALTO | Novo |
| GPG-01 | GPG Evidence | `gpg_evidence.py` | 258 | 🟠 ALTO | Novo |
| GPG-04 | GPG Evidence | `gpg_evidence.py` | 462 | 🟠 ALTO | Novo |
| GPG-05 | GPG Evidence | `gpg_evidence.py` | 521 | 🟠 ALTO | Novo |
| HID-01 | DuckyScript | `hid/ducky.py` | 140 | 🟠 ALTO | Novo |
| HID-04 | HID Injector | `hid/injector.py` | 297 | 🟠 ALTO | Novo |
| HID-05 | HID Injector | `hid/injector.py` | 514 | 🟠 ALTO | Novo |
| HID-06 | USB Gadget | `hid/gadget.py` | 630 | 🟠 ALTO | Novo |
| NET-02 | Network | `network/__init__.py` | 807 | 🟠 ALTO | Persistente |
| NET-03 | Network | `network/__init__.py` | 519 | 🟠 ALTO | Novo |
| MSF-04 | MSF RPC | `metasploit/rpc.py` | 148 | 🟡 MÉDIO | Novo |
| CON-02 | MSF Console | `metasploit/console.py` | 343 | 🟡 MÉDIO | Novo |
| GPG-02 | GPG Evidence | `gpg_evidence.py` | 309 | 🟡 MÉDIO | Novo |
| GPG-03 | GPG Evidence | `gpg_evidence.py` | 78 | 🟡 MÉDIO | Novo |
| GPG-06 | GPG Evidence | `gpg_evidence.py` | 240 | 🟡 MÉDIO | Novo |
| CHRT-04 | Chroot | `core/chroot_process.py` | 136 | 🟡 MÉDIO | Novo |
| RPT-04 | Report Gen | `reporting/generator.py` | 641 | 🟡 MÉDIO | Novo |
| BLE-01 | BLE Exploit | `ble/exploit_chain.py` | 596 | 🟡 MÉDIO | Novo |
| BOOT-03 | Bootstrap | `bootstrap_chroot.sh` | 140 | 🟢 BAIXO | Novo |
| RPT-03 | Report Gen | `reporting/generator.py` | 234 | 🟢 BAIXO | Novo |
| HID-03 | DuckyScript | `hid/ducky.py` | 423 | 🟢 BAIXO | Novo |
| BLE-QUIRKS | Device Quirks | `device_quirks.json` | — | 🟢 BAIXO | Persistente |

**Total: 36 bugs — 5 críticos · 18 altos · 8 médios · 5 baixos**

**Bugs resolvidos desde o relatório Sprint 3:** BLE-01 a BLE-09, NET-02 a NET-09 (versão anterior) — 17 corrigidos.

---

*Revisão estática sobre branch `main` commit `8b65ad9`. Linhas verificadas contra código fonte. Fixes propostos são minimais — sem refactoring adicional ao necessário.*
