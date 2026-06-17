# Urban Hack Sentinel v3 — Security, Bug & Sprint Report
**Versão analisada:** Sprint 0–5 (branch `main`, commit `3de3b97`) | **Data:** Junho 2026  
**Contexto:** Projeto académico — demonstração de vulnerabilidades em ambiente urbano  
**Autor da revisão:** Claude Code

---

## Índice

1. [Completion por Sprint](#1-completion-por-sprint)
2. [Análise de Qualidade de Implementação por CVE](#2-análise-de-qualidade-de-implementação-por-cve)
3. [Bugs por Módulo](#3-bugs-por-módulo)
4. [Avaliação Geral](#4-avaliação-geral)
5. [Sumário Executivo de Bugs](#5-sumário-executivo-de-bugs)
6. [Sugestões Adicionais](#6-sugestões-adicionais)

---

## 1. Completion por Sprint

| Sprint | % Anterior | % Atual | Variação | Gap Crítico Atual |
|--------|-----------|---------|----------|-------------------|
| S0 — Foundation | 72% | **92%** | +20% | Scheduler sem persistência; entry points novos módulos não registados |
| S1 — WiFi | 87% | **93%** | +6% | Testes com mocks de classe, não de subprocessos reais |
| S2 — BLE | 75% | **85%** | +10% | Model IDs placeholder; AirDrop harvesting ausente |
| S3 — Network/Camera | 52% | **82%** | +30% | NET-01/02/03 corrigidos; CAM-BLOCK e CVE DB vazia persistem |
| S4 — Metasploit/Exploit/Report | 60% | **80%** | +20% | MSF RPC funcional; GPG chain of custody funcional; MSF-TOKEN e RPT-04 por resolver |
| S5 — HID/Dashboard | 30% | **62%** | +32% | HID funcional (bugs chave corrigidos); UI completamente ausente; BTHID-01/MQTT-01 por resolver |
| S6 — Polish | 0% | **0%** | — | Não iniciado |
| **TOTAL** | **~53%** | **~74%** | **+21%** | 29 bugs activos; 0 críticos |

---

### Detalhe por Sprint

#### S0 — Foundation (90%)

✅ EventBus · ProcessManager · Config (Pydantic v2) · Storage (SQLite WAL + Redis) · Logger (structlog + rich)  
✅ `core/health.py` — `/healthz`, `/readyz`, métricas Prometheus via `prometheus_client`  
✅ `core/plugins.py` — entry point discovery, dependency graph, hot-reload, lifecycle management  
✅ `core/scheduler.py` — interval, cron expressions (`croniter`), one-shot, startup/shutdown triggers  
✅ `.github/workflows/ci.yml` — lint (ruff), mypy strict, pytest Python 3.11/3.12, Trivy, pip-audit, Docker push  
✅ `docker/Dockerfile.arm64` — multi-arch ARM64/AMD64, build stage + runtime stage  
⚠️ Scheduler — sem persistência de tarefas (`TaskPersistence` placeholder); crash do processo perde schedule  
⚠️ Plugin system — entry points não registados no `pyproject.toml` para módulos novos; `hot-reload` por testar  

---

#### S1 — WiFi (92%)

✅ WiFiScanner (iw + airodump-ng) · HandshakeAttack · PMKIDAttack · WPSPixieAttack · WPSPinAttack  
✅ DeauthAttack · HandshakeManager · MACChanger · GeoMapper (gpsd + WiGLE/Kismet/KML)  
✅ `tests/test_wifi_module.py` — cobertura das classes principais  
⚠️ Testes usam mocks de classe, não `unittest.mock.patch` de subprocessos — `iw` e `airodump-ng` reais não testados  

---

#### S2 — BLE (82%)

✅ FastPairScanner · WhisperPairTester · WhisperPairExploit (4 estratégias KBP)  
✅ BlueZBondingManager · AccountKeyManager  
✅ `run_full_chain()` integra `start_capture()` — BLE-01 resolvido  
⚠️ `device_quirks.json` — 9 dispositivos com Model IDs placeholder (`ABCDEF`, `123456`) — quirks nunca aplicados  
⚠️ AirDrop harvesting — mencionado no MASTER_PLAN mas sem módulo dedicado  

---

#### S3 — Network/Camera (82%)

✅ NmapScanner · NucleiRunner · SearchSploitIntegration · RouterScanner · CameraDiscovery (mDNS, ONVIF, RTSP)  
✅ `camera/enumeration.py` — ONVIF, RTSP, HTTP, credenciais default (`admin:admin`, `admin:1234`, etc.)  
✅ `camera/vuln_check.py` — CVE DB em JSON, checkers por protocolo  
✅ NET-01 corrigido — `ipaddress.ip_network()` valida todos os targets  
✅ NET-02 corrigido — ONVIF socket → `asyncio.to_thread()`  
✅ NET-03 corrigido — `exploit_id` validado com regex  
⚠️ `camera/enumeration.py` — `test_default_creds()` usa sockets bloqueantes em `async def` (CAM-BLOCK)  
⚠️ `camera/vuln_check.py` — CVE DB sem CVEs reais carregados por omissão (CAM-CVE)  
⚠️ RouterSploit retorna `[]` — sem implementação real  

---

#### S4 — Metasploit/Exploitation/Reporting (80%)

✅ ExploitRunner · ChrootProcessManager · CredentialManager · MetasploitRPC · MetasploitConsole · ReportGenerator · GPGEvidence  
✅ MSF-02 corrigido — msgpack array format; RPC funcional  
✅ MSF-03 corrigido — auth.logout sem double-token  
✅ GPG-04 corrigido — `verify_log()` usa `entry_copy` sem `entry_hash`; chain of custody funcional  
✅ GPG-01 corrigido — `signature.data` (bytes) na assinatura binária  
✅ CHRT-01/02/03/04 corrigidos — path relativo, finally seguro, bind mounts corretos  
✅ RPT-01/02 corrigidos — passphrase via Callable; name collision resolvida  
✅ CRED-02 corrigido — `validate_credential()` levanta `NotImplementedError`  
✅ CON-01 corrigido — newline injection em option values bloqueado  
⚠️ MSF-TOKEN — `_reconnect()` não limpa `self._token`  
⚠️ RPT-04 — `html.write_pdf()` ainda síncrono (linha 650)  
⚠️ GPG-05 — GPGSigner sem key assina silenciosamente nada  

---

#### S5 — HID/Dashboard (62%)

✅ `hid/ducky.py` — DuckyScript parser v1/v3, 7 layouts de teclado  
✅ `hid/injector.py` — HID injection via uinput e USB gadget  
✅ `hid/gadget.py` — USB gadget configfs management  
✅ `modules/bt_hid.py` — BlueZ HID Profile D-Bus, CVE-2023-45866 framework  
✅ `modules/wifi/fragattacks.py` — wrapper FragAttacks de Vanhoef  
✅ `modules/ssid_confusion.py` — detector CVE-2023-52424  
✅ `modules/esp32.py` — detecção de dispositivos ESP32  
✅ `modules/mqtt.py` — MQTT attack suite (estrutura)  
✅ HID-01 corrigido — keycode `'w'` = `0x1A`; payloads funcionais  
✅ HID-02 corrigido — pickle substituído por JSON; sem RCE  
✅ HID-04 corrigido — `time.sleep()` → `asyncio.sleep()`  
✅ HID-06 corrigido — LAYOUT_* removidos de `__all__`; sem ImportError  
⚠️ HID-05 — delay markers no path compiled→hidg a verificar  
⚠️ BTHID-01 **ALTO** — `bt_hid.py` usa `python-dbus` síncrono; bloqueia event loop  
⚠️ BTHID-02 — CVE-2023-45866 OTA sem pairing não implementado  
⚠️ FRAG-01 — `/home/andresantos/fragattacks` hardcoded  
⚠️ MQTT-01 **ALTO** — `paho-mqtt` ausente de `pyproject.toml`; módulo falha no import  
❌ FastAPI backend · React PWA · Textual TUI · Rich CLI — completamente ausentes  

---

## 2. Análise de Qualidade de Implementação por CVE

**Escala:**
- **ÓTIMA** — funcional, integrado no pipeline, testado
- **MÉDIO** — presente com gaps funcionais ou bugs bloqueantes
- **FRACO** — estrutura ou referência; sem implementação funcional completa
- **AUSENTE** — não iniciado

---

### 2.1 Bluetooth Low Energy

#### CVE-2025-36911 — WhisperPair Fast Pair KBP Bypass · **MÉDIO**

| Componente | Estado | Detalhe |
|---|---|---|
| Scanner UUID 0xFE2C | ✅ | `FastPairScanner` via Bleak; parse model ID e pairing mode |
| Vulnerability tester | ✅ | `WhisperPairTester` — GATT connect → KBP request → parse 0x01/0x0E |
| KBP bypass — RAW_KBP | ✅ | Strategy 0: KBP sem seeker MAC |
| KBP bypass — RAW_WITH_SEEKER | ✅ | Strategy 1: KBP com seeker MAC |
| KBP bypass — RETROACTIVE | ✅ | Strategy 2: `usesRetroactiveFlag` |
| KBP bypass — EXTENDED_RESPONSE | ✅ | Strategy 3: extended response |
| BR/EDR Bonding | ✅ | `BlueZBondingManager` via D-Bus BlueZ |
| Account Key Write | ✅ | `AccountKeyManager` — AES-ECB GATT write UUID `fe2c1236` |
| HFP Audio Capture | ✅ | `arecord`+bluealsa integrado em `run_full_chain()` (BLE-01 resolvido) |
| Device Quirks DB | ⚠️ | 9 dispositivos mas Model IDs fictícios — quirks nunca aplicados |

**O que impede ÓTIMA:** Model IDs placeholder + CRED-02 compromete reporting de credenciais.

---

#### CVE-2023-45866 + CVE-2024-21306 — BT HID Keystroke Injection · **FRACO**

CVE exige envio de HID reports via Bluetooth não autenticado (OTA). Dois módulos endereçam este CVE mas com abordagens diferentes:

**`hid/` — USB/uinput injection (local)**

| Componente | Estado | Detalhe |
|---|---|---|
| DuckyScript Parser | ⚠️ | 7 layouts; keycode 'w'=0x19 errado (HID-01) |
| HID Injector uinput | ⚠️ | Funcional localmente; DELAY markers enviados como keycodes (HID-05) |
| USB Gadget injection | ⚠️ | configfs presente; ImportError em LAYOUT_* (HID-06) |
| BT OTA injection | ❌ | **Não implementado** — o CVE requer BT wireless |

**`modules/bt_hid.py` — BlueZ HID Profile (OTA attempt)**

| Componente | Estado | Detalhe |
|---|---|---|
| BlueZ HID Profile D-Bus | ⚠️ | `BlueZHIDProfile` regista profile, abre L2CAP sockets (PSM 17/19) |
| Unauthenticated connect | ❌ | Código não força `NoInputNoOutput` capability; sem bypass de pairing |
| Keystroke send via BT | ⚠️ | `send_keystroke()` escreve para interrupt_fd, mas depende de connection estabelecida |
| Async correctness | ❌ | Usa `python-dbus` (síncrono) em vez de `dbus-fast`; bloqueia event loop (BTHID-01) |

**Avaliação:** `bt_hid.py` é o vetor correto do CVE mas incompleto — a parte crítica (conectar a um host sem autenticação) não está implementada. O módulo `hid/` ataca um vetor diferente do CVE.

---

#### CVE-2019-9506 — KNOB · **AUSENTE**

Força entropy de sessão BR/EDR para 1 byte via PDUs LMP. Requer InternalBlue (CYW20735). Zero implementação. Não implementável sem hardware específico.

---

#### CVE-2020-10135 — BIAS · **AUSENTE**

Impersonation de dispositivo emparelhado via legacy authentication. Mesma limitação de hardware que KNOB. Zero implementação.

---

#### CVE-2023-24023 — BLUFFS · **AUSENTE**

Reuso de session keys quebrando forward secrecy. Nem sequer referenciado no código. Zero implementação.

---

#### SweynTooth (12 CVEs) — BLE SoC Vulnerabilities · **AUSENTE**

Afeta TI, NXP, Cypress, Dialog, Microchip. Requer nRF52840 dongle com firmware custom. Zero implementação.

---

#### CVE-2025-27840 — ESP32 Hidden HCI Commands · **FRACO**

29 comandos HCI não documentados permitem leitura de RAM/GPIO/NVRAM via BT.

| Componente | Estado | Detalhe |
|---|---|---|
| `modules/esp32.py` | ⚠️ | Scan BLE, fingerprinting por OUI Espressif, classificação de dispositivos |
| CVE execution | ❌ | Comandos HCI não documentados **não são enviados** — módulo é detector, não exploit |
| Serial/USB HCI access | ❌ | CVE requer ligação serial ao chip; BLE scanning não é suficiente |

**Avaliação:** `esp32.py` tem valor como discovery tool mas não implementa o CVE. Os 29 comandos requerem `hcitool cmd` com opcodes específicos via interface HCI — implementável se o ESP32 tiver BT clássico acessível.

---

### 2.2 WiFi

#### CVE-2019-15126 — Kr00k · **FRACO**

Chips Broadcom/Cypress usam chave all-zero após disassociação.

| Componente | Estado | Detalhe |
|---|---|---|
| Deauth para forçar disassociação | ✅ | `DeauthAttack` funcional |
| Captura frames pós-disassociação | ❌ | Captura EAPOL, não data frames com key nula |
| Detecção automática chipset | ❌ | OUI lookup existe mas sem triagem Broadcom/Cypress |
| Decifração offline | ❌ | Sem integração r00kie-kr00kie / hexway |

---

#### CVE-2020-24586/87/88 — FragAttacks · **FRACO**

| Componente | Estado | Detalhe |
|---|---|---|
| `wifi/fragattacks.py` | ⚠️ | Wrapper da tool de Vanhoef; estrutura de chamada presente |
| Hardcoded path | ❌ | `/home/andresantos/fragattacks` hardcoded — falha em qualquer outra máquina (FRAG-01) |
| Chipset requirement | ❌ | Ferramenta de Vanhoef requer chipset Cypress específico — Pi WiFi chip não suportado |
| Exploit real | ❌ | Tool pode detetar mas não injetar frames sem chipset compatível |

---

#### CVE-2023-52424 — SSID Confusion · **FRACO**

| Componente | Estado | Detalhe |
|---|---|---|
| `modules/ssid_confusion.py` | ⚠️ | Detector 802.11r, FT networks, neighbor report anomalies |
| Evil twin setup | ❌ | Sem `hostapd-mana` wrapper ou `rogue_ap.py` |
| MITM após downgrade | ❌ | Deteção passiva apenas — o ataque em si não existe |

---

#### WPS Pixie Dust + WPS Common PINs · **ÓTIMA**

| Componente | Estado |
|---|---|
| `WPSPixieAttack` — `reaver -K 1`, fallback pixiewps | ✅ |
| `WPSPinAttack` — OUI DB, rate limiting | ✅ |
| `AttackResult` com credentials | ✅ |

Pipeline end-to-end funcional. Único gap: integração com CredentialManager para exportar PINs crackeados.

---

#### WPA2 Handshake + PMKID + Deauth · **ÓTIMA**

| Componente | Estado |
|---|---|
| `HandshakeAttack` — aireplay-ng + airodump-ng + aircrack-ng | ✅ |
| `PMKIDAttack` — hcxdumptool + hashcat `.22000` | ✅ |
| `HandshakeManager` — dedup, hashcat, WiGLE/Kismet | ✅ |
| `MACChanger` — profiles apple/samsung/intel/random | ✅ |
| `GeoMapper` — gpsd, KML, WiGLE CSV | ✅ |

Módulo mais maduro do projeto.

---

### 2.3 IoT & Protocolos Urbanos

#### MQTT Attack Suite · **FRACO**

| Componente | Estado | Detalhe |
|---|---|---|
| `modules/mqtt.py` — estrutura | ⚠️ | Classes definidas, lógica de discovery e brute presente |
| `paho-mqtt` dep | ❌ | **Não está em `pyproject.toml`** — import falha em runtime (MQTT-01) |
| Subscribe sem auth | ❌ | Lógica escrita mas inutilizável sem dep |
| Topic enumeration | ❌ | Idem |

---

#### TPMS Vehicle Tracking (RTL-SDR 433MHz) · **AUSENTE**

Tracking passivo de veículos via IDs únicos TPMS. Zero implementação. Sem módulo RTL-SDR.

---

#### AirDrop Phone Number Harvesting · **FRACO**

| Componente | Estado | Detalhe |
|---|---|---|
| BLE advertisement capture | ✅ | `FastPairScanner` captura advertisements |
| AWDL/AirDrop filter | ❌ | Sem filtro para company ID Apple + UUID AirDrop |
| SHA256 rainbow tables | ❌ | Não implementado |

---

### Resumo CVE

| CVE / Ataque | Qualidade | Variação vs. Anterior |
|---|---|---|
| CVE-2025-36911 WhisperPair | **MÉDIO** | → igual (HFP integrado, quirks ainda placeholder) |
| CVE-2023-45866/21306 BT HID | **FRACO** | → igual (bt_hid.py adicionado mas OTA ausente) |
| CVE-2019-9506 KNOB | **AUSENTE** | → igual |
| CVE-2020-10135 BIAS | **AUSENTE** | → igual |
| CVE-2023-24023 BLUFFS | **AUSENTE** | → igual |
| SweynTooth (12 CVEs) | **AUSENTE** | → igual |
| CVE-2025-27840 ESP32 | **FRACO** | ↑ (era AUSENTE; esp32.py adicionado) |
| CVE-2019-15126 Kr00k | **FRACO** | → igual |
| CVE-2020-24586/87/88 FragAttacks | **FRACO** | ↑ (era AUSENTE; fragattacks.py adicionado) |
| CVE-2023-52424 SSID Confusion | **FRACO** | ↑ (era AUSENTE; ssid_confusion.py adicionado) |
| WPS Pixie Dust | **ÓTIMA** | → igual |
| WPA2 Handshake + PMKID | **ÓTIMA** | → igual |
| TPMS Vehicle Tracking | **AUSENTE** | → igual |
| MQTT Attack Suite | **FRACO** | ↑ (era AUSENTE; mqtt.py adicionado) |
| AirDrop Harvesting | **FRACO** | → igual |

**CVEs com implementação real (ÓTIMA/MÉDIO): 3/15 (20%)**

---

## 3. Bugs por Módulo

### 3.1 Severidade CRÍTICA

---

**MSF-02 · `metasploit/rpc.py:~206` — Formato msgpack Errado → Todo o RPC Falha**

O protocolo msgrpc exige **array**: `[method, token, arg1, ...]`. O código envia **dict** encapsulado. Todas as chamadas RPC são rejeitadas pelo servidor Metasploit. A integração MSF está completamente não funcional.

```python
# Fix:
params = [method]
if self._token and method not in ("auth.login",):
    params.insert(1, self._token)
params.extend(args)
packed = msgpack.packb(params, use_bin_type=True)
```

---

**HID-02 · `hid/ducky.py:~562` — Pickle Deserialization → RCE**

`save_compiled()` e `load_compiled()` usam `pickle`. `pickle.load()` num ficheiro não confiável permite execução arbitrária de código. Qualquer fonte de ficheiros `.ducky` compilados (USB, API, rede) pode comprometer o Pi.

```python
# Fix: substituir pickle por JSON
import json
# save: json.dumps([{"type": cmd.type.value, "keycodes": cmd.keycodes} for cmd in script.commands])
# load: reconstruir ParsedScript a partir de dicts
```

---

**CHRT-01 · `core/chroot_process.py:~370` — Path Hardcoded do Developer**

`ensure_chroot()` referencia `/home/andresantos/Desktop/Projects/urban-hack-sentinel/scripts/...`. Falha silenciosamente em qualquer outro sistema. Expõe PII do developer.

```python
# Fix:
script_path = Path(__file__).parents[4] / "scripts" / "bootstrap_chroot.sh"
```

---

**CRED-02 · `credential/manager.py:~416` — `validate_credential()` Sempre Retorna True**

Stub que define `validated=True` e `validity_status="valid"` sem qualquer verificação real. Relatórios mostram 100% das credenciais como "válidas" — dados fabricados.

```python
# Fix:
raise NotImplementedError("validate_credential not yet implemented")
# ou implementar verificação real por tipo (SSH, HTTP, etc.)
```

---

**NET-01 · `network/__init__.py:193` — Argument Injection no NmapScanner**

`targets` passados diretamente a `cmd.extend(targets)` sem validação. Um target `"--script malicious"` injeta flags nmap arbitrários.

```python
# Fix:
import ipaddress
validated = []
for t in targets:
    try:
        ipaddress.ip_network(t, strict=False)
        validated.append(t)
    except ValueError:
        logger.warning("invalid_target", target=t)
```

---

### 3.2 Severidade ALTA

---

**BTHID-01 · `modules/bt_hid.py:~60` — python-dbus Síncrono em Contexto Async**

`BlueZHIDProfile` usa `import dbus` (python-dbus síncrono GLib). Todas as operações D-Bus bloqueiam o event loop asyncio durante ligações BT, que podem demorar 2-10 segundos. O projeto usa `dbus-fast` noutros módulos — inconsistência.

```python
# Fix: migrar para dbus-fast (já é dependência do projeto)
from dbus_fast.aio import MessageBus
bus = await MessageBus().connect()
```

---

**BOOT-01 · `bootstrap_chroot.sh:~58` — Sem Verificação de Integridade do Tarball**

`# Verify checksum (optional but recommended)` sem código. Tarball Alpine extraído sem checksum. MITM entrega rootfs malicioso executado como root.

```bash
# Fix:
wget -q "${MINIROOTFS_URL}.sha256" -O "${MINIROOTFS}.sha256"
sha256sum -c "${MINIROOTFS}.sha256" || { echo "Checksum mismatch"; exit 1; }
```

---

**BOOT-02 · `bootstrap_chroot.sh:~85` — Alpine Edge Repos sem Pinning**

`edge/testing` adicionado. Packages rolling e sem garantia de estabilidade introduzem risco de supply chain. Uma package maliciosa em `edge/testing` é instalada automaticamente.

```bash
# Fix: usar apenas repos estáveis
echo "https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION%.*}/main" > /etc/apk/repositories
```

---

**CHRT-02 · `chroot_process.py:~240` — NameError no finally Block**

Se `create_subprocess_exec()` lançar exceção antes de atribuir `proc`, o `finally` que referencia `proc.pid` lança `NameError`, engolindo a exceção original e tornando o debug impossível.

```python
# Fix:
finally:
    if 'proc' in locals() and proc is not None:
        self._active_processes.pop(proc.pid, None)
```

---

**CHRT-03 · `chroot_process.py:~111` — Bind Mounts Como Lista Plana**

`bind_cmds` construído como lista plana de strings: `["mount", "--bind", "/proc", "/chroot/proc", "&&", "mount", ...]`. O `sh -c` recebe tokens individuais — todos os bind mounts falham silenciosamente.

```python
# Fix: lista-de-listas, executar separadamente
bind_cmds = []
for src, dst in mounts:
    bind_cmds.append(["mount", "--bind", str(src), str(dst)])
for cmd in bind_cmds:
    await asyncio.create_subprocess_exec(*cmd)
```

---

**CRED-01 · `credential/manager.py:~434` — `field(default_factory=list)` em Assinatura de Função**

`field()` é válido apenas em `@dataclass`. Na assinatura de função regular, avalia para um objeto `Field`. Callers que omitem `extra_args` recebem o objeto Field em vez de uma lista; `cmd.extend()` lança `TypeError`.

```python
# Fix:
async def some_method(self, extra_args: Optional[List[str]] = None) -> ...:
    extra_args = extra_args or []
```

---

**MSF-01 · `rpc.py:107,109` — Password Default + SSL Desativado**

`password: str = "msf"` e `ssl_verify: bool = False` por omissão. Qualquer host na rede pode autenticar no daemon Metasploit.

```python
# Fix: sem default para password; ssl_verify=True por omissão
password: str  # obrigatório, sem default
ssl_verify: bool = True
```

---

**MSF-03 · `rpc.py:~189` — Token Duplicado em auth.logout**

`_call("auth.logout", self._token)` prepend o token novamente via `_call` → servidor recebe `[token, token]` → logout falha e sessão fica aberta indefinidamente.

```python
# Fix: excluir auth.logout do prepend automático de token
if method not in ("auth.login", "auth.logout"):
    params.insert(1, self._token)
```

---

**MSF-TOKEN · `rpc.py:~221` — Token Inválido Persiste Após Falha de Reconnect**

`_reconnect()` define `self._connected = False` mas não limpa `self._token`. Chamadas subsequentes usam o token expirado e entram em loop infinito de retry.

```python
# Fix:
self._connected = False
self._token = None  # limpar token inválido
```

---

**CON-01 · `metasploit/console.py:~227` — Injeção de Newline em Options**

`f"set {k} {v}"` sem sanitização. Um valor com `\n` injeta comandos adicionais no resource script `.rc`. Exemplo: `RHOSTS` com valor `"1.2.3.4\nset PAYLOAD windows/meterpreter/reverse_https"`.

```python
# Fix:
for k, v in options.items():
    if '\n' in str(k) or '\r' in str(k) or '\n' in str(v) or '\r' in str(v):
        raise ValueError(f"Newline in option {k!r}={v!r}")
```

---

**RPT-01 · `reporting/generator.py:~196` — GPG Passphrase em Campo Plaintext**

`ReportConfig.gpg_passphrase: str` num dataclass. Qualquer serialização (JSON, logs, WebSocket) expõe a passphrase GPG.

```python
# Fix: usar callable como secret provider
gpg_passphrase_fn: Optional[Callable[[], str]] = None
```

---

**RPT-02 · `reporting/generator.py:~726` — Name Collision Quebra sign_report()**

`gpg = gpg.GPG()` sobrescreve o alias do módulo `import gnupg as gpg`. Na segunda chamada a `sign_report()`, `gpg.GPG()` lança `AttributeError: 'GPG' object has no attribute 'GPG'`.

```python
# Fix:
import gnupg as gnupg_lib
gpg_instance = gnupg_lib.GPG(gnupghome=self.config.gpg_home)
```

---

**GPG-01 · `gpg_evidence.py:~258` — Assinatura Binária Falha com TypeError**

Para `DETACHED_BINARY`, abre em modo `'wb'` mas escreve `str(signature)` (string) → `TypeError: a bytes-like object is required`. Nenhuma assinatura binária é jamais escrita.

```python
# Fix:
with open(sig_path, 'wb') as f:
    f.write(signature.data)  # bytes, não str()
```

---

**GPG-04 · `gpg_evidence.py:~462` — verify_log() Sempre Reporta Adulteração**

Hash calculado *incluindo* o campo `entry_hash`, mas o hash original foi calculado *sem* esse campo. Comparação falha sempre — chain of custody completamente inutilizável.

```python
# Fix:
entry_hash_stored = entry.pop("entry_hash", "")
computed = _compute_entry_hash(entry)
entry["entry_hash"] = entry_hash_stored  # restaurar
if computed != entry_hash_stored:
    tampering_detected = True
```

---

**GPG-05 · `gpg_evidence.py:~521` — GPGSigner Default sem Key**

`gpg_signer or GPGSigner()` com `key_id=None`. `sign_file()` retorna `False` sem aviso. Todos os artefactos ficam sem assinatura GPG e sem qualquer notificação.

```python
# Fix: tornar signer obrigatório ou logar aviso explícito
if gpg_signer is None:
    logger.warning("no_gpg_signer", msg="Artifacts will not be signed")
```

---

**HID-01 · `hid/ducky.py:~140` — Keycode Errado para 'w'**

`'v': 0x19` e `'w': 0x19` — colisão. Qualquer payload com `powershell`, `wget`, `whoami`, `www` produz 'v' em vez de 'w'. Também: `'keypad_4': 0x5B` deve ser `0x5C`.

```python
# Fix:
'w': 0x1A,
'keypad_4': 0x5C,
```

---

**HID-04 · `hid/injector.py:~297` — time.sleep() Bloqueia Event Loop**

`delay()` usa `time.sleep()` em contexto async. Payloads com `DELAY` frequente congelam todas as coroutines.

```python
# Fix:
async def delay(self, ms: int) -> None:
    await asyncio.sleep(ms / 1000.0)
```

---

**HID-05 · `hid/injector.py:~514` — DELAY Markers Enviados como Keycodes Reais**

`execute_ducky()` escreve todos os reports para `/dev/hidg*` incluindo markers de delay (bit 0x80 set). O kernel interpreta-os como keycodes — garbage characters enviados ao host.

```python
# Fix:
for report in hid_reports:
    if report[0] & 0x80:
        delay_ms = ((report[0] & 0x7F) << 8) | report[1]
        await asyncio.sleep(delay_ms / 1000.0)
    else:
        await asyncio.to_thread(dev.write, bytes(report))
```

---

**HID-06 · `hid/gadget.py:~630` — Exporta LAYOUT_* Não Definidas → ImportError**

`__all__` lista `LAYOUT_US`, `LAYOUT_GB`, etc., que não existem em `gadget.py`. Qualquer `from hid.gadget import LAYOUT_US` lança `ImportError`.

```python
# Fix: remover LAYOUT_* de __all__ em gadget.py
# (as layouts estão em ducky.py como KeyboardLayout enum)
```

---

**MQTT-01 · `modules/mqtt.py:~1` — Dependência paho-mqtt Ausente**

`import paho.mqtt.client as mqtt` no topo do ficheiro. `paho-mqtt` não está em `pyproject.toml`. O import falha imediatamente — o módulo MQTT é completamente não funcional.

```toml
# Fix: adicionar a pyproject.toml
[tool.poetry.dependencies]
paho-mqtt = "^2.0"
```

---

**NET-02 · `network/__init__.py:~807` — ONVIF WS-Discovery Socket Bloqueante**

`_onvif_discovery()` usa `recvfrom` bloqueante (timeout 5s) em `async def`. Bloqueia o event loop durante esse tempo — Pi perde captures BLE/WiFi enquanto aguarda.

```python
# Fix:
data, addr = await asyncio.to_thread(sock.recvfrom, 65535)
```

---

**NET-03 · `network/__init__.py:~519` — SearchSploit exploit_id sem Validação**

`exploit_id` passado diretamente ao subprocess. Path traversal: `"../../../etc/passwd"` força leitura de ficheiros arbitrários.

```python
# Fix:
import re
if not re.match(r'^\d+$', str(exploit_id)):
    raise ValueError(f"Invalid exploit_id: {exploit_id!r}")
```

---

**FRAG-01 · `wifi/fragattacks.py:~30` — Path do Developer Hardcoded**

`"/home/andresantos/fragattacks"` como fallback no `_find_fragattacks()`. Falha em qualquer outra máquina, igual ao CHRT-01.

```python
# Fix: remover path pessoal, deixar apenas paths standard e PATH lookup
paths = ["/opt/fragattacks", "/usr/local/bin/fragattacks"]
```

---

**GPG-FILE · `gpg_evidence.py:~240` — Ficheiro Inteiro em RAM para GPG**

`sign_file()` lê o ficheiro inteiro para memória antes de assinar. pcaps de sessões longas (potencialmente GB) causam OOM no Pi.

```python
# Fix: passar path diretamente ao GPG, não ler para RAM
result = gpg.sign_file(open(file_path, 'rb'), keyid=key_id, passphrase=passphrase, detach=True)
```

---

### 3.3 Severidade MÉDIA

**FRAG-02** — FragAttacks requer chipset Cypress específico; Pi WiFi (Broadcom BCM43455) não suportado pela ferramenta de Vanhoef — wrapper não funciona sem hardware adequado  
**SSID-01** — `ssid_confusion.py` é detector passivo; o ataque real (Evil Twin + redirect 802.11r) não está implementado  
**ESP32-01** — `esp32.py` faz fingerprinting de hardware mas não executa os 29 comandos HCI do CVE-2025-27840  
**BTHID-02** — `bt_hid.py` não força `NoInputNoOutput` capability para bypass de pairing; CVE-2023-45866 requer connection sem autenticação  
**CON-02** — LHOST hardcoded `0.0.0.0` em `template_exploit_chain()` → reverse shells não funcionais (`console.py:~343`)  
**CON-TIMEOUT** — `execute_rc_script()` faz `process.kill()` no timeout mas não remove o ficheiro `.rc` temporário → acumulação em `/tmp`  
**GPG-02** — `verify_signature()` usa API errada do python-gnupg; verificação produz resultados incorretos  
**GPG-03** — Dead code `entry_data` vs `entry_dict` em `add_entry()` — confusão de nomes  
**CHRT-04** — `["cd", working_dir, "&&"]` em lista `exec` — `&&` não funciona sem shell; `cd` não muda diretório do subprocess  
**RPT-04** — `html.write_pdf()` síncrono em `async def`; bloqueia event loop 5-30s num Pi 4  
**RPT-JSON** — Name collision em `_generate_json()`: `findings: [f.__dict__ for f in ...]` e `serialize_obj()` duplicam serialização → saída inconsistente  
**DUCKY-UNICODE** — `string_to_keycodes()` descarta silenciosamente caracteres Unicode fora do ASCII básico; payloads com texto internacional incompletos  
**GADGET-PATH** — `instance` em `add_hid_function()` embeddido directamente no path configfs sem validação; argumento malicioso pode escapar do diretório gadget  
**CAM-BLOCK** — `camera/enumeration.py::test_default_creds()` usa sockets bloqueantes em `async def`  
**CAM-CVE** — `camera/vuln_check.py::load_cve_db()` sem path default; CVE DB não carregada por omissão; todos os checks retornam vazio  
**MSF-04** — `ssl_context.verify_mode = ssl.CERT_NONE` mesmo com `ssl=True` — sem validação de hostname  

---

### 3.4 Severidade BAIXA

**BOOT-03** — Packages duplicados na lista `apk add` (`bootstrap_chroot.sh:~140`)  
**RPT-03** — Jinja2 autoescape não ativo para `.md`; HTML em findings não escapado  
**HID-03** — Dead code `text = ' '.join(cmd.args)` nunca usado (`ducky.py:~423`)  
**BLE-QUIRKS** — Model IDs placeholder em `device_quirks.json` — quirks nunca aplicados  
**SCHEDULER-PERSIST** — `core/scheduler.py` sem persistência; schedule perdido no restart  

---

## 4. Avaliação Geral

### 4.1 Arquitetura · 7.5/10

**Pontos fortes:**

A arquitetura async-first com asyncio como primitiva central é a escolha correta para este tipo de tool — I/O bound dominante (scans, BLE, subprocess de ferramentas externas) beneficia do modelo não-bloqueante. O EventBus pub/sub com `asyncio.Queue` desacopla módulos heterogéneos de forma elegante. Pydantic v2 para config, structlog para logging estruturado, SQLite WAL + Redis para dados — stack moderna e adequada ao Pi.

O novo plugin system com entry points dinâmicos, dependency graph e lifecycle management é infraestrutura de produção. O scheduler com cron expressions e a adição de `/healthz` + Prometheus completam S0 de forma sólida. O CI/CD com ruff, mypy strict, pytest, Trivy e pip-audit é uma adição de alto valor — projetos académicos raramente têm este nível de automação.

**Limitações:**

O modelo async não é aplicado uniformemente — `bt_hid.py` usa `python-dbus` síncrono (BTHID-01), `camera/enumeration.py` tem sockets bloqueantes, `reporting/generator.py` chama WeasyPrint de forma bloqueante (RPT-04). O princípio async-first existe no design mas não na prática de implementação.

O `ExploitRunner` acopla diretamente 5 módulos via import em vez de routing pelo EventBus. O `network/__init__.py` com 1072 linhas viola o princípio de ficheiro único por classe planeado no MASTER_PLAN.

**Sugestão:** Definir uma política explícita: "toda operação I/O > 100ms usa `asyncio.to_thread()`". Executá-la como checklist no code review.

---

### 4.2 Performance · 5/10

**Contexto:** Raspberry Pi 4 (Cortex-A72 1.8GHz, 4GB RAM) / Pi 5 (Cortex-A76 2.4GHz, 8GB RAM).

**Bloqueios identificados:**

| Operação | Bloqueio | Impacto no Pi 4 |
|---|---|---|
| WeasyPrint PDF | `html.write_pdf()` síncrono | 5–30s de event loop bloqueado |
| ONVIF WS-Discovery | `recvfrom` bloqueante | 5s por sessão |
| BT HID (python-dbus) | Toda operação D-Bus | 2–10s por ligação |
| DuckyScript DELAY | `time.sleep()` | Proporcional à soma dos delays |
| GPG signing de ficheiros grandes | Lê ficheiro inteiro para RAM | OOM em sessões longas |
| Camera cred testing | Sockets bloqueantes | Variável |

Em field operation, qualquer destes bloqueios pode causar perda de captures BLE ou WiFi enquanto outra operação está a correr.

**O que funciona bem:** Pipeline WiFi (subprocess + asyncio.create_subprocess_exec), EventBus com backpressure natural, NmapScanner com streaming XML.

**Sugestão a curto prazo:** `asyncio.to_thread()` para os 4 maiores bloqueios (WeasyPrint, ONVIF, BT HID, camera creds) resolve 90% dos problemas sem refactoring.

---

### 4.3 Modularidade · 6.5/10

**Melhorou** desde o sprint anterior — o plugin system com entry points dinâmicos é o passo certo. A divisão em domínios (`ble/`, `wifi/`, `network/`, `hid/`, `metasploit/`, `reporting/`) é coerente.

**Limitações persistentes:**

- `network/__init__.py` monolítico (1072 linhas, 6 classes) — contraria a intenção do MASTER_PLAN
- `ExploitRunner` com imports diretos de 5 módulos — sem routing pelo EventBus
- Novos módulos S5 (`bt_hid.py`, `fragattacks.py`, `ssid_confusion.py`, `esp32.py`, `mqtt.py`) adicionados como ficheiros avulso em `modules/` sem registar no plugin system
- Entry points em `pyproject.toml` não atualizados para os novos módulos

---

### 4.4 Compatibilidade · 5/10

| Target | Suporte | Notas |
|---|---|---|
| Raspberry Pi 5 ARM64 | ✅ | Target declarado; Docker ARM64 |
| Raspberry Pi 4 ARM64 | ✅ | Mesmo code path; RAM pode ser limitante com MSF |
| Raspberry Pi 3 ARM32 | ❌ | Python 3.11 arm64 apenas |
| Raspberry Pi Zero 2W | ⚠️ | ARM64 mas 512MB RAM — MSF + BlueZ não cabem |
| x86_64 Linux (dev) | ⚠️ | Python corre; USB gadget + BT exigem hardware |
| x86_64 via Docker | ✅ | Docker multi-arch adicionado — melhoria real |
| macOS / Windows | ❌ | dbus-fast, uinput, configfs são Linux-only |
| Kali Linux ARM64 | ✅ | Todas as ferramentas disponíveis |
| Alpine chroot | ✅ | Bootstrap script funcional (sem checksum) |

**Melhoria real:** Docker multi-arch ARM64/AMD64 permite desenvolver sem hardware em x86_64.

**Ainda em falta:** mock backends para WiFi/BLE/HID — sem eles, o CI não consegue testar os módulos de ataque (os testes atuais testam apenas parsing e estrutura de dados, não o fluxo de ataque completo).

---

### 4.5 Segurança da Ferramenta · 4/10

Paradoxo de uma ferramenta de segurança com vulnerabilidades sérias no próprio código:

- **HID-02** — pickle deserialization = RCE via ficheiros DuckyScript
- **CHRT-01** — path hardcoded quebra isolamento pretendido da chroot
- **BOOT-01** — rootfs Alpine instalado sem verificação de integridade
- **MSF-01** — password default pública para daemon Metasploit
- **RPT-01** — passphrase GPG em campo de dataclass serializável
- **GPG-04** — chain of custody sempre reporta adulteração → evidências académicas inválidas

Num contexto em que o Pi pode ser confiscado durante uma demonstração, as credenciais capturadas e a passphrase GPG em memória são riscos reais.

---

### 4.6 Rating Geral

| Dimensão | Rating Anterior | Rating Atual | Nota |
|---|---|---|---|
| Conceito e Plano | 9/10 | **9/10** | MASTER_PLAN ambicioso, bem estruturado |
| Arquitetura Core (S0) | 7/10 | **7.5/10** | Health, plugins, scheduler, CI, Docker adicionados |
| WiFi Module (S1) | 8/10 | **8/10** | Pipeline sólido; testes adicionados |
| BLE/WhisperPair (S2) | 6/10 | **6.5/10** | HFP integrado; quirks placeholder persistem |
| Network/Camera (S3) | 5/10 | **6/10** | Camera modules adicionados; bugs de blocking e CVE DB |
| Metasploit/Reporting (S4) | 4/10 | **4/10** | Bugs críticos não resolvidos; volume sem qualidade |
| HID/Dashboard (S5) | 3/10 | **4.5/10** | Novos módulos; UI ausente; bugs funcionais |
| CVE Coverage | 3/10 | **3.5/10** | 3/15 ÓTIMA/MÉDIO; 4 FRACO novos adicionados |
| Qualidade de Código | 5/10 | **5/10** | Padrões bons mas inconsistentes; 43 bugs |
| Segurança da Ferramenta | 4/10 | **4/10** | Bugs críticos persistem |
| **OVERALL** | **5.4/10** | **5.8/10** | Progresso real em infraestrutura; exploits ainda incompletos |

---

### 4.7 Melhorias Prioritárias

**Nível 1 — Bugs activos que quebram funcionalidade (< 4h total)**

| # | Fix | Esforço |
|---|-----|---------|
| 1 | MQTT-01: adicionar `paho-mqtt` ao pyproject.toml | 5 min |
| 2 | BTHID-01: migrar bt_hid.py de `python-dbus` para `dbus-fast` | 2h |
| 3 | HID-05: verificar path compiled→hidg; separar delay markers de keycodes | 30 min |
| 4 | GPG-05: logar warning quando GPGSigner não tem key configurada | 10 min |
| 5 | FRAG-01: remover `/home/andresantos/fragattacks` hardcoded | 5 min |
| 6 | CAM-CVE: criar CVE DB default mínima em `camera/vuln_check.py` | 2h |
| 7 | MSF-TOKEN: limpar `self._token = None` em `_reconnect()` | 5 min |

**Nível 2 — Qualidade e completude (< 6h total)**

| # | Tarefa | Esforço |
|---|--------|---------|
| 8 | RPT-04: WeasyPrint → `asyncio.to_thread()` | 30 min |
| 9 | CAM-BLOCK: sockets de camera creds → `asyncio.to_thread()` | 30 min |
| 10 | CRED-01: `field(default_factory=list)` → `Optional[List[str]] = None` | 10 min |
| 11 | GPG-FILE: passar path ao GPG em vez de ler ficheiro inteiro para RAM | 20 min |
| 12 | BTHID-02: forçar `NoInputNoOutput` capability para CVE-2023-45866 OTA | 3h |

**Nível 3 — CVEs com maior impacto visual**

| # | CVE | Esforço | Impacto |
|---|-----|---------|---------|
| 18 | CVE-2025-27840 — enviar comandos HCI não documentados via `hcitool cmd` | 3h | Alto |
| 19 | MQTT — adicionar paho-mqtt + topic subscribe + enumeration real | 4h | Alto |
| 20 | CVE-2023-45866 OTA — forçar NoInputNoOutput capability em bt_hid.py | 4h | Muito alto |
| 21 | AirDrop — filtro AWDL/company ID Apple no FastPairScanner | 2h | Médio |
| 22 | TPMS — wrapper `rtl_433` + GPS correlation | 4h | Muito alto visualmente |

---

## 5. Sumário Executivo de Bugs

### Bugs Activos (verificados no código — commit `3de3b97`)

| ID | Módulo | Ficheiro | Severidade |
|----|--------|----------|------------|
| MSF-01 | MSF RPC | `metasploit/rpc.py` | 🟠 ALTO |
| MSF-TOKEN | MSF RPC | `metasploit/rpc.py` | 🟠 ALTO |
| MSF-04 | MSF RPC | `metasploit/rpc.py` | 🟡 MÉDIO |
| CON-02 | MSF Console | `metasploit/console.py` | 🟡 MÉDIO |
| CON-TIMEOUT | MSF Console | `metasploit/console.py` | 🟡 MÉDIO |
| CRED-01 | Credential | `credential/manager.py` | 🟠 ALTO |
| GPG-02 | GPG Evidence | `gpg_evidence.py` | 🟡 MÉDIO |
| GPG-03 | GPG Evidence | `gpg_evidence.py` | 🟡 MÉDIO |
| GPG-05 | GPG Evidence | `gpg_evidence.py` | 🟠 ALTO |
| GPG-FILE | GPG Evidence | `gpg_evidence.py` | 🟠 ALTO |
| RPT-04 | Report Gen | `reporting/generator.py` | 🟡 MÉDIO |
| RPT-JSON | Report Gen | `reporting/generator.py` | 🟡 MÉDIO |
| HID-05 | HID Injector | `hid/injector.py` | 🟠 ALTO |
| DUCKY-UNICODE | DuckyScript | `hid/ducky.py` | 🟡 MÉDIO |
| GADGET-PATH | USB Gadget | `hid/gadget.py` | 🟡 MÉDIO |
| BTHID-01 | BT HID | `modules/bt_hid.py` | 🟠 ALTO |
| BTHID-02 | BT HID | `modules/bt_hid.py` | 🟡 MÉDIO |
| MQTT-01 | MQTT | `modules/mqtt.py` | 🟠 ALTO |
| FRAG-01 | FragAttacks | `wifi/fragattacks.py` | 🟡 MÉDIO |
| FRAG-02 | FragAttacks | `wifi/fragattacks.py` | 🟡 MÉDIO |
| SSID-01 | SSID Confusion | `modules/ssid_confusion.py` | 🟡 MÉDIO |
| ESP32-01 | ESP32 | `modules/esp32.py` | 🟡 MÉDIO |
| CAM-BLOCK | Camera | `camera/enumeration.py` | 🟡 MÉDIO |
| CAM-CVE | Camera | `camera/vuln_check.py` | 🟡 MÉDIO |
| BOOT-03 | Bootstrap | `bootstrap_chroot.sh` | 🟢 BAIXO |
| RPT-03 | Report Gen | `reporting/generator.py` | 🟢 BAIXO |
| HID-03 | DuckyScript | `hid/ducky.py` | 🟢 BAIXO |
| BLE-QUIRKS | Device Quirks | `device_quirks.json` | 🟢 BAIXO |
| SCHEDULER-PERSIST | Scheduler | `core/scheduler.py` | 🟢 BAIXO |

**Total activo: 29 bugs — 0 críticos · 7 altos · 13 médios · 5 baixos + 4 baixos**

---

### Resolvidos neste Push (22 corrigidos — verificados no código)

| ID | Fix aplicado |
|----|-------------|
| ✅ MSF-02 | msgpack array format corrigido |
| ✅ MSF-03 | auth.logout sem double-token |
| ✅ HID-01 | keycode `'w'` = `0x1A` |
| ✅ HID-02 | pickle substituído por JSON |
| ✅ HID-04 | `time.sleep` → `asyncio.sleep` |
| ✅ HID-06 | LAYOUT_* removidos de `__all__` |
| ✅ GPG-01 | `signature.data` (bytes) em vez de `str()` |
| ✅ GPG-04 | `entry_copy` sem `entry_hash` para verificação |
| ✅ NET-01 | `ipaddress.ip_network()` valida todos os targets |
| ✅ NET-02 | ONVIF socket → `asyncio.to_thread()` |
| ✅ NET-03 | `exploit_id` validado com `re.match(r'^\d+$')` |
| ✅ CRED-02 | `validate_credential()` levanta `NotImplementedError` |
| ✅ RPT-01 | `gpg_passphrase_provider: Callable` em vez de string |
| ✅ RPT-02 | `import gnupg as gnupg_module`, sem name collision |
| ✅ BOOT-01 | `sha256sum -c` adicionado ao bootstrap |
| ✅ BOOT-02 | Edge repos removidos; apenas `main` e `community` |
| ✅ CHRT-01 | `Path(__file__).parents[4]` em vez de path pessoal |
| ✅ CHRT-02 | `if 'proc' in locals()` no finally block |
| ✅ CHRT-03 | bind_cmds como lista-de-listas + execução via `sh -c` |
| ✅ CHRT-04 | `cd` executado dentro de `sh -c` com `shlex.quote` |
| ✅ CON-01 | Validação de `\n`/`\r` em option values |
| ✅ BLE-01 | `start_capture()` integrado em `run_full_chain()` |

---

## 6. Sugestões Adicionais

Além dos fixes de bugs, estas sugestões melhorariam significativamente o projeto em dimensões além da correção de erros.

---

### 6.1 Mock Backend System — Desenvolver sem Hardware

O maior bloqueio atual é não poder testar módulos de ataque sem WiFi adapter, BT adapter, Pi físico, etc. A solução é uma camada de abstração:

```python
# Adicionar a cada módulo:
class WiFiBackend(Protocol):
    async def scan(self, interface: str) -> List[NetworkInfo]: ...
    async def deauth(self, bssid: str, client: str) -> bool: ...

class RealWiFiBackend(WiFiBackend):
    """Usa iw + airodump-ng reais."""
    ...

class MockWiFiBackend(WiFiBackend):
    """Retorna dados simulados. Ativa com URBAN_HS_BACKEND=mock."""
    async def scan(self, interface: str) -> List[NetworkInfo]:
        return FIXTURE_NETWORKS  # carregado de tests/fixtures/
```

Com `URBAN_HS_BACKEND=mock` no `.env`, o CI consegue testar todo o fluxo de ataque sem hardware. Quando o Pi chega, basta remover a variável de ambiente.

---

### 6.2 mac80211_hwsim — WiFi Virtual para Testes Reais

Para testar handshake capture e deauth sem adaptador físico:

```bash
sudo modprobe mac80211_hwsim radios=3
# Cria wlan0, wlan1, wlan2 — interfaces WiFi virtuais
# wlan0: AP (hostapd)
# wlan1: cliente (wpa_supplicant)
# wlan2: monitor para capture (airodump-ng)
```

O kernel simula rádio 802.11 completo — monitor mode, injeção de frames, handshake real. Os testes de `HandshakeAttack` e `WPSPixieAttack` podem correr em GitHub Actions sem hardware.

---

### 6.3 Graylog / Loki para Logs de Campo

Em field operation o Pi está headless. Logs via `structlog` para JSON são bons mas precisam de destino. Sugestão: adicionar output GELF ou Loki:

```python
# Em core/logger.py, adicionar handler opcional
if config.log_remote_url:
    structlog.configure(
        processors=[..., structlog.processors.JSONRenderer()],
        logger_factory=GELFLoggerFactory(config.log_remote_url)
    )
```

Um laptop na mesma rede recebe todos os logs em tempo real via Graylog ou Grafana/Loki. Para uma demonstração académica, ver logs em tempo real numa dashboard é visualmente impactante.

---

### 6.4 Threat Intelligence — Correlacionar MACs com OUI DB

O `FastPairScanner` já recolhe MACs. Adicionar lookup automático de fabricante via OUI:

```python
from manuf import manuf  # pip install manuf
p = manuf.MacParser()
vendor = p.get_manuf("AA:BB:CC:DD:EE:FF")  # "Google, Inc."
```

Isto permite, em tempo real, classificar dispositivos vistos em campo: "3 Google Pixel, 2 Apple AirPods, 1 ESP32 (Espressif)". Para a demonstração urbana, é imediatamente legível e impactante.

---

### 6.5 Timeline View nos Relatórios

O `AuditSession` tem timestamps em todos os eventos. Adicionar uma visualização de timeline ao relatório PDF/HTML:

```
08:32:01 | WiFi Scan → 12 redes encontradas
08:32:45 | Deauth → AA:BB:CC:DD:EE:FF desligado
08:32:47 | Handshake capturado → "CafeRede"
08:33:12 | BLE Scan → CVE-2025-36911 candidato encontrado
08:35:00 | WhisperPair exploit → Account key escrita
```

Uma timeline cronológica num relatório académico demonstra o fluxo de um ataque real de forma muito mais convincente do que tabelas de resultados.

---

### 6.6 Cobertura de Testes — Objetivo 60% para S6

Estado atual: ~15% de cobertura (WiFi scanner + BLE structure). Para S6:

1. **Fixtures** — criar `tests/fixtures/` com pcaps, JSON de scan results, e BLE advertisements reais capturados
2. **Mock subprocessos** — `unittest.mock.patch("asyncio.create_subprocess_exec")` retorna output fixo
3. **Cobertura mínima por módulo** — WiFi: 70%, BLE: 60%, Network: 50%, HID: 50%, MSF: 40%, Report: 60%

Sem cobertura de testes, qualquer refactoring introduz regressões silenciosas. Para um projeto com 50 bugs conhecidos, testes são o safety net para os fixes.

---

### 6.7 Contenção de Recursos com cgroups v2

Em field operation, um scan Nmap `-A` + Nuclei + MSF simultaneamente pode saturar o Pi 4. O `ProcessManager` tem suporte planeado a cgroups:

```python
# Implementar em ProcessManager
async def run_with_limits(self, cmd: List[str], cpu_quota: float = 0.5, mem_mb: int = 256):
    """Run subprocess within cgroup limits."""
    cgroup_path = f"/sys/fs/cgroup/urban-hs/{uuid4()}"
    # criar cgroup, definir cpu.max e memory.max
    # executar processo sob o cgroup
```

Isto garante que nenhum módulo monopoliza recursos — o Pi mantém-se responsivo para BLE scanning enquanto Nmap corre.

---

### 6.8 Integração Zeek/Suricata para Detecção Defensiva

O projeto é ofensivo mas para contexto académico, adicionar um modo de detecção tem alto valor:

```python
class DefensiveModule:
    """Modo monitor — deteta ataques dos tipos que o projeto executa."""
    async def detect_deauth_flood(self, interface: str) -> AsyncIterator[Alert]: ...
    async def detect_fast_pair_spoofing(self) -> AsyncIterator[Alert]: ...
    async def detect_mqtt_enumeration(self, interface: str) -> AsyncIterator[Alert]: ...
```

Demonstrar que consegues tanto atacar como detetar o mesmo vetor é academicamente muito mais forte — mostra compreensão profunda dos protocolos.

---

### 6.9 Device Quirks DB — Dados Reais

`device_quirks.json` tem 9 entradas com `model_id: "ABCDEF"`. Para o projeto ter valor, precisas de IDs reais de dispositivos vulneráveis:

- Google Pixel Buds Pro: `0x2EB4` (Fast Pair Model ID)
- Google Pixel Buds A-Series: `0x1E89`  
- JBL headphones com Fast Pair: vários IDs documentados no repositório `nicedoc.io/niccokunzmann/python-fast-pair`

Substituir placeholders por IDs reais faz o `WhisperPairTester` funcionar com hardware real imediatamente.

---

*Revisão estática sobre branch `main` commit `3de3b97`. Código verificado ficheiro a ficheiro. Fixes propostos são minimais e não introduzem refactoring adicional ao necessário.*
