# Análise de Integração: WPair + Stryker → Urban Hack Sentinel

> Ambos projetos são do **ZalexDev** e são referências em pentesting mobile/wireless. Este documento analisa como incorporar suas capacidades ao nosso `urban-hack-sentinel` (Raspberry Pi / Linux ARM64).

---

## 1. Visão Geral dos Projetos

| Projeto | Plataforma | Foco Principal | Licença |
|---------|------------|----------------|---------|
| **WPair** (wpair-app) | Android (Kotlin) | **CVE-2025-36911** - WhisperPair / Fast Pair exploit | Apache 2.0 |
| **Stryker** (strykerapp) | Android (Java) + Alpine chroot | Suite completa de pentest mobile (WiFi, BLE, Web, HID, USB, Metasploit) | GPL v3 |

---

## 2. O que cada um traz de valioso

### 2.1 WPair — Bluetooth / Fast Pair Exploit Chain

| Capacidade | Descrição | Código-chave |
|------------|-----------|--------------|
| **BLE Scanner Fast Pair** | Scan direto UUID 0xFE2C, parsing anúncio (Model ID, pairing mode, account key filter) | `Scanner.kt` |
| **Vulnerability Tester** | Teste não-invasivo: envia KBP request → se aceita = VULNERABLE, se rejeita = PATCHED | `VulnerabilityTester.kt` |
| **Exploit Chain Completa** | Estratégias: RAW_KBP → RAW_WITH_SEEKER → RETROACTIVE → EXTENDED_RESPONSE | `FastPairExploit.kt` |
| **BR/EDR Bonding** | Após KBP accepted, inicia bonding Bluetooth Classic via endereço BR/EDR | `FastPairExploit.kt` |
| **Account Key Write** | Escreve Account Key (0x04 + random) → registra dispositivo na conta atacante | `FastPairExploit.kt` |
| **Account Key Flood** | Escreve múltiplas chaves para empurrar chaves originais (prioriza attacker) | `FastPairExploit.kt` |
| **HFP Audio Capture** | Conecta perfil Hands-Free → captura stream de microfone em tempo real | `BluetoothAudioManager.kt` |
| **Device Quirks** | Base de dados por Model ID para delays, flags, MTU preferences | `FastPairExploit.kt` |

### 2.2 Stryker — Suite Pentest Mobile Completa

| Módulo | Capacidades | Código-chave |
|--------|-------------|--------------|
| **WiFi** | Scan (monitor mode), deauth, handshake capture, WPS Pixie Dust, PINs comuns, MAC changer profiles | `Wifi.java`, `ScanWifi.java` |
| **Handshakes** | Armazenamento local, rename, share, export OnlineHashCrack, cracking on-device Hashcat | `handshakes/` |
| **MAC Changer** | Inline + profiles persistentes (OUI spoofing) | `macchanger/` |
| **Router Scan** | RouterScan v2, Hydra, credencial discovery | `routerscan/` |
| **WhisperPair (BLE)** | Integração completa do WPair no app | `wpair/` |
| **Local Network** | Nmap host discovery, port scan, OS fingerprint, exploit dispatch | `localnetwork/`, `nmap/` |
| **Web Scanner** | Nuclei multi-target, findings agrupados por severidade | `nuclei/` |
| **Arsenal** | DB custom exploits/scanners com templates `{IP}`, `{PORT}`, `{MAC}`, `{GW}`, `{MASK}` | `arsenal/` |
| **HID Attacks** | DuckyScript parser (Hak5 v1+v3), 7 layouts, payloads bundled | `hid/` |
| **USB Arsenal** | Gadget profiles: HID keyboard/mouse, mass-storage (IMG/ISO), RNDIS/ECM/ACM | `usbarsenal/` |
| **Metasploit** | MSF console nativo no chroot, sessions, payload gen, module browser | `metasploit/` |
| **GeoMac** | Mapa OSM BSSIDs/handshakes, export WiGLE KML/CSV | `geomac/` |
| **VNC Desktop** | XFCE/Xfce-VNC in-chroot | `vnc/` |
| **Core Manager** | Mount/unmount/repair chroot, component installation | `coremanager/` |
| **AdvancedProcess** | Wrapper robusto para processos longos (chroot, logging, callbacks) | `AdvancedProcess.java` |

---

## 3. Mapeamento: O que aplicar ao Urban Hack Sentinel (Pi / Linux)

### 3.1 **Alta Prioridade — Implementar Agora** ✅ **TODOS COMPLETOS**

| Feature | Origem | Esforço | Valor | Status |
|---------|--------|---------|-------|--------|
| **WPS Pixie Dust (Offline)** | Stryker | Médio | Captura PIN sem brute-force online | ✅ Completo |
| **WPS Common PINs Database** | Stryker | Baixo | Dicionário de PINs padrão por OUI | ✅ Completo |
| **MAC Changer Profiles / OUI Spoofing** | Stryker | Baixo | Anti-tracking avançado (Apple, Samsung, Intel) | ✅ Completo |
| **Handshake Manager + Hashcat Integration** | Stryker | Médio | UI/CLI para gerenciar .22000, cracking local | ✅ Completo |
| **GeoMac / WiGLE Export** | Stryker | Médio | Mapa OSM + KML/CSV para wardriving | ✅ Completo |
| **BLE Fast Pair Scanner** | WPair | Médio | Descoberta dispositivos Fast Pair (0xFE2C) | ✅ Completo |
| **CVE-2025-36911 Vulnerability Test** | WPair | Alto | Teste não-invasivo vulnerabilidade WhisperPair | ✅ Completo |
| **Account Key Flood** | WPair | Alto | Expulsão chaves originais, persistência | ✅ Completo |
| **Bluetooth HID Keystroke Injection** | Stryker | Alto | CVE-2023-45866/21306, HID injection | ✅ Completo |
| **Kr00k (CVE-2019-15126)** | Stryker | Médio | Deauth + captura frames all-zero key | ✅ Completo |
| **FragAttacks (CVE-2020-24586/87/88)** | Stryker | Médio | Wrapper vanhoefm/fragattacks | ✅ Completo |
| **MQTT Attack Suite** | Stryker | Médio | Broker discovery, topic enum, cred brute force | ✅ Completo |
| **ESP32 Fingerprinting** | Original | Médio | CVE-2025-27840 passive detection | ✅ Completo |
| **SSID Confusion** | Original | Médio | CVE-2023-52424 detection | ✅ Completo |

### 3.2 **Média Prioridade — Próximas Sprints**

| Feature | Origem | Esforço |
|---------|--------|---------|
| **DuckyScript HID Injection** | Stryker | Alto (precisa kernel gadget) |
| **USB Gadget Profiles** | Stryker | Alto (kernel configfs) |
| **Nuclei Web Scanner Integration** | Stryker | Médio |
| **Router Credential Discovery** | Stryker | Médio |
| **Metasploit RPC / Console** | Stryker | Alto |
| **VNC Desktop (headless)** | Stryker | Médio |

### 3.3 **Baixa Prioridade / Research**

| Feature | Origem |
|---------|--------|
| HFP Audio Capture (microfone BT) | WPair |
| Mass Storage Gadget (ISO/IMG) | Stryker |
| RNDIS/ECM Network Gadget | Stryker |
| In-chroot Alpine environment | Stryker |

---

## 4. Arquitetura Recomendada para Integração

### 4.1 Estrutura Modular (inspirada no Stryker)

```
urban-hack-sentinel/
├── core/
│   ├── sentinel.py              # Main loop (Python remplace bash para complexidade)
│   ├── process_mgr.py           # AdvancedProcess equivalente (robust subprocess)
│   ├── config.py                # Config parsing + validation
│   └── logger.py                # Structured logging (JSONL + rich console)
├── modules/
│   ├── wifi/
│   │   ├── scanner.py           # iw/airodump wrapper + passive/active modes
│   │   ├── attacks/
│   │   │   ├── pmkid.py         # hcxdumptool
│   │   │   ├── handshake.py     # aircrack-ng/aireplay
│   │   │   ├── wps_pixie.py     # reaver + pixiewps (NOVO)
│   │   │   ├── wps_pins.py      # common PINs por OUI (NOVO)
│   │   │   └── deauth.py        # aireplay-ng
│   │   ├── handshake_mgr.py     # .22000 storage, dedup, hashcat integration (NOVO)
│   │   ├── mac_changer.py       # macchanger + OUI profiles + spoofing (NOVO)
│   │   └── geomapper.py         # GeoMac + WiGLE KML/CSV export (NOVO)
│   ├── ble/
│   │   ├── fastpair_scanner.py  # WPair Scanner.kt → Python (NOVO)
│   │   ├── whisperpair_tester.py # VulnerabilityTester.kt → Python (NOVO)
│   │   ├── whisperpair_exploit.py # FastPairExploit.kt → Python (NOVO)
│   │   └── audio_hfp.py         # HFP capture via bluez/pynep (NOVO)
│   ├── web/
│   │   ├── nuclei_runner.py     # Nuclei integration (NOVO)
│   │   └── arsenal.py           # Custom exploit templates (NOVO)
│   ├── hid/
│   │   ├── ducky_parser.py      # DuckyScript parser (NOVO)
│   │   └── hid_injector.py      # uinput / usb-gadget (NOVO)
│   ├── usb/
│   │   ├── gadget_mgr.py        # configfs profiles (NOVO)
│   │   └── mass_storage.py      # IMG/ISO mounting (NOVO)
│   ├── router/
│   │   ├── scanner.py           # RouterScan + Hydra (NOVO)
│   │   └── creds.py             # Credential DB (NOVO)
│   ├── metasploit/
│   │   └── msf_rpc.py           # MSFRPC client (NOVO)
│   └── vnc/
│       └── vnc_server.py        # XFCE headless (NOVO)
├── chroot/
│   └── alpine/                  # Alpine chroot bootstrap (NOVO)
├── ui/
│   ├── cli.py                   # Rich CLI (substitui bash)
│   ├── tui.py                   # Textual TUI dashboard (NOVO)
│   └── web.py                   # FastAPI + WebSocket dashboard (NOVO)
└── tests/
    └── mac80211_hwsim/          # CI testing
```

### 4.2 Migração Bash → Python

**Por que Python?**
- WPair/Stryker são Kotlin/Java → port direto para Python mantém lógica
- `asyncio` para concorrência nativa (substitui `jobs` + `sleep`)
- Rich/Textual para TUI/dashboard moderno
- FastAPI para web dashboard + WebSocket métricas tempo real
- Melhor handling de subprocessos, parsing, erro handling
- Type hints + mypy = manutenibilidade

**Subprocess Manager (equivalente AdvancedProcess):**
```python
# core/process_mgr.py
import asyncio
from dataclasses import dataclass
from typing import AsyncIterator, Optional

@dataclass
class ProcessResult:
    cmd: str
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int

class ProcessManager:
    async def run(self, cmd: str, timeout: int = 30, chroot: bool = False) -> ProcessResult:
        # Robust subprocess com logging, callbacks, chroot support
        ...
    
    async def run_streaming(self, cmd: str, chroot: bool = False) -> AsyncIterator[str]:
        # Yield lines em tempo real para callbacks
        ...
    
    def kill_all(self):
        # Cleanup garantido
        ...
```

---

## 5. Implementação Concreta: Próximos Passos

### Sprint 1 (Semana 1-2): WPS + MAC + Handshake Manager

```bash
# 1. WPS Pixie Dust
sudo apt install reaver pixiewps

# 2. Common PINs database
wget https://raw.githubusercontent.com/hak5darren/USB-Rubber-Ducky/master/payloads/library/WPS-PINs.txt

# 3. MAC Changer com OUI profiles
# Implementar em Python: random_oui(apple|samsung|intel|realtek|atheros)

# 4. Handshake Manager CLI
# urban-hs list | show | crack | export-wigle | export-kismet
```

### Sprint 2 (Semana 3-4): BLE/WhisperPair

```python
# ble/fastpair_scanner.py
# Port direto de Scanner.kt:
# - bluetoothctl / bluepy / bleak para BLE scan
# - UUID 0xFE2C filter
# - Parse advertisement: Model ID, pairing mode, account key filter

# ble/whisperpair_tester.py
# Port de VulnerabilityTester.kt:
# - GATT connect → service 0xFE2C → char 0x1234
# - Send KBP request (0x00 + flags + addr + salt)
# - Analyze response: SUCCESS=vulnerable, 0x0e/0x05=patched

# ble/whisperpair_exploit.py
# Port de FastPairExploit.kt:
# - Multi-strategy: RAW_KBP → RAW_WITH_SEEKER → RETROACTIVE → EXTENDED
# - BR/EDR bonding via bluez
# - Account Key write (0x04 + random) / flood
# - HFP audio via bluez/pynep
```

### Sprint 3 (Semana 5-6): GeoMac + Dashboard Web

```python
# modules/wifi/geomapper.py
# - SQLite DB: bssid, ssid, lat, lon, alt, channel, encryption, last_seen
# - Export: KML (Google Earth), CSV (WiGLE), netxml (Kismet)
# - Folium/Leaflet map generation

# ui/web.py
# FastAPI + WebSocket
# - /api/status → métricas tempo real
# - /api/networks → lista com geo
# - /api/metrics/ws → Server-Sent Events
# - Frontend: Leaflet.js + Chart.js
```

### Sprint 4 (Semana 7-8): Alpine Chroot + Arsenal

```bash
# Bootstrap Alpine chroot em /opt/urban-chroot
# Instala: nmap, nuclei, hydra, metasploit, hashcat, searchsploit
# ProcessManager executa comandos via chroot transparentemente
```

---

## 6. Código de Exemplo: WPS Pixie Dust Integration

```python
# modules/wifi/attacks/wps_pixie.py
import asyncio
import re
from dataclasses import dataclass
from core.process_mgr import ProcessManager

@dataclass
class PixieResult:
    bssid: str
    pin: Optional[str] = None
    psk: Optional[str] = None
    pixie_data: dict = None
    success: bool = False

class WPSPixieAttack:
    def __init__(self, pmgr: ProcessManager):
        self.pmgr = pmgr
    
    async def attack(self, bssid: str, channel: int, iface: str) -> PixieResult:
        # reaver com --pixie-dust
        cmd = f"reaver -i {iface} -b {bssid} -c {channel} -K 1 -vv"
        result = await self.pmgr.run(cmd, timeout=120)
        
        # Parse output para extrair PIN/PSK
        pin_match = re.search(r'WPS PIN: (\d{8})', result.stdout)
        psk_match = re.search(r'WPA PSK: (.+)', result.stdout)
        pixie_match = re.search(r'Pixie-Dust.*?(PKR|PKE|E-Hash1|E-Hash2|AuthKey):', result.stdout)
        
        return PixieResult(
            bssid=bssid,
            pin=pin_match.group(1) if pin_match else None,
            psk=psk_match.group(1) if psk_match else None,
            success=bool(pin_match or psk_match)
        )
```

---

## 7. Exemplo: Fast Pair Scanner (Python Port)

```python
# modules/ble/fastpair_scanner.py
import asyncio
from bleak import BleakScanner, AdvertisementData
from dataclasses import dataclass
from typing import Callable, Optional

FAST_PAIR_UUID = "0000fe2c-0000-1000-8000-00805f9b34fb"

@dataclass
class FastPairDevice:
    name: Optional[str]
    address: str
    rssi: int
    is_pairing_mode: bool
    has_account_key_filter: bool
    model_id: Optional[str]
    is_fast_pair: bool
    last_seen: float

class FastPairScanner:
    def __init__(self, callback: Callable[[FastPairDevice], None]):
        self.callback = callback
        self.scanner = None
        self.scan_all = False
    
    async def start(self, scan_all: bool = False):
        self.scan_all = scan_all
        
        def detection_callback(device, adv: AdvertisementData):
            if FAST_PAIR_UUID in adv.service_data:
                # Parse service data (igual ao Scanner.kt)
                data = adv.service_data[FAST_PAIR_UUID]
                fp_device = self._parse_advertisement(
                    name=device.name,
                    address=device.address,
                    data=data,
                    rssi=adv.rssi
                )
                self.callback(fp_device)
            elif self.scan_all:
                self.callback(FastPairDevice(
                    name=device.name, address=device.address, rssi=adv.rssi,
                    is_pairing_mode=False, has_account_key_filter=False,
                    model_id=None, is_fast_pair=False, last_seen=asyncio.get_event_loop().time()
                ))
        
        self.scanner = BleakScanner(detection_callback)
        await self.scanner.start()
    
    async def stop(self):
        if self.scanner:
            await self.scanner.stop()
    
    def _parse_advertisement(self, name, address, data, rssi) -> FastPairDevice:
        # Lógica idêntica ao Scanner.kt lines 71-120
        model_id = None
        is_pairing = False
        has_ak_filter = False
        
        if data:
            first = data[0]
            if len(data) == 3 and (first & 0x80) == 0:
                model_id = data.hex().upper()
                is_pairing = True
            elif (first & 0x60) != 0:
                has_ak_filter = True
            elif len(data) > 3 and (first & 0x80) == 0:
                model_id = data[:3].hex().upper()
        
        return FastPairDevice(
            name=name, address=address, rssi=rssi,
            is_pairing_mode=is_pairing, has_account_key_filter=has_ak_filter,
            model_id=model_id, is_fast_pair=True, last_seen=asyncio.get_event_loop().time()
        )
```

---

## 8. Dependências Adicionais (resumo)

```bash
# Sistema
sudo apt install reaver pixiewps bully hashcat nmap nuclei python3-bleak python3-bluepy
sudo apt install bluez-tools python3-dbus python3-pybluez  # BLE/HFP
sudo apt install folium leaflet  # GeoMac
sudo pip install textual fastapi uvicorn websockets rich asyncio-mqtt

# Kernel (para USB Gadget/HID)
# CONFIG_USB_CONFIGFS=y
# CONFIG_USB_CONFIGFS_F_HID=y
# CONFIG_USB_CONFIGFS_MASS_STORAGE=y
# CONFIG_USB_CONFIGFS_RNDIS=y
# CONFIG_USB_CONFIGFS_ECM=y
# CONFIG_USB_GADGET=y
```

---

## 9. Conclusão

**WPair + Stryker = Referência ouro para pentest wireless/Bluetooth mobile.**

Nosso `urban-hack-sentinel` no Pi pode evoluir para **o Stryker para Linux ARM64** incorporando:

1. **Imediato**: WPS Pixie Dust, MAC profiles, Handshake Manager, GeoMac
2. **Curto prazo**: BLE Fast Pair scanner, WhisperPair vulnerability test, exploit chain
3. **Médio prazo**: Dashboard web/TUI, Alpine chroot, Nuclei, Arsenal, HID/USB gadget
4. **Longo prazo**: Metasploit RPC, VNC, Mass storage gadget, RNDIS/ECM

A arquitetura **modular + process manager robusto + async Python** é o caminho para escalar além do bash atual mantendo compatibilidade com as tools CLI existentes (aircrack-ng, hcxdumptool, reaver, etc.).

---

*Documento baseado em análise de código-fonte dos repositórios originais (Apache 2.0 / GPL v3). Uso ético/legal obrigatório.*