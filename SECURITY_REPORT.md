# Urban Hack Sentinel — Security & Bug Report
**Versão:** Sprint 3 | **Data:** Junho 2026  
**Contexto:** Projeto académico — demonstração de vulnerabilidades em ambiente urbano  
**Autor da revisão:** Claude Code (claude-sonnet-4-6)

---

## Índice

1. [Hardware Necessário por Exploit](#1-hardware-necessário-por-exploit)
2. [Relatório de Exploits por Área](#2-relatório-de-exploits-por-área)
   - [Área 1 — Bluetooth Classic (BR/EDR)](#área-1--bluetooth-classic-bredr)
   - [Área 2 — Bluetooth Low Energy (BLE)](#área-2--bluetooth-low-energy-ble)
   - [Área 3 — WiFi (IEEE 80211)](#área-3--wifi-ieee-80211)
   - [Área 4 — IoT & Protocolos Urbanos](#área-4--iot--protocolos-urbanos)
3. [Relatório de Bugs por Sprint](#3-relatório-de-bugs-por-sprint)
   - [Sprint 2 — Módulo BLE](#sprint-2--módulo-ble)
   - [Sprint 3 — Módulo Network](#sprint-3--módulo-network)
4. [Sumário de Bugs](#4-sumário-de-bugs)

---

## 1. Hardware Necessário por Exploit

Antes de implementar, mapeia o hardware disponível para saber o que podes executar imediatamente.

| Hardware | Custo est. | Exploits que desbloqueia |
|---|---|---|
| **Raspberry Pi built-in** (BT 5.0 + WiFi) | — | CVE-2023-45866, CVE-2024-21306, WhisperPair, AirDrop harvesting, MQTT attacks, ESP32 fingerprinting |
| **Alfa AWUS036ACHM** (MT7612U, 2.4+5GHz) | ~35€ | Kr00k, FragAttacks, SSID Confusion, Evil Twin |
| **Alfa AWUS036AXML** (MT7921AUN, WiFi 6E) | ~50€ | Tudo acima + redes WiFi 6E (6GHz) |
| **RTL-SDR Blog V4** (c/ antena) | ~30€ | TPMS vehicle tracking, LoRaWAN decode, 433MHz key fobs |
| **Nordic nRF52840 USB Dongle** | ~10€ | SweynTooth (obrigatório — BLE raw link layer) |
| **InternalBlue compatible HW** | ~30–80€* | KNOB, BIAS, BLUFFS (requer chip Broadcom/Cypress específico) |
| **PN532 NFC Reader** | ~12€ | MIFARE card reading, transport cards, building access |

> *InternalBlue funciona com CYW20735 development board (~30€), Nexus 5, ou alguns chips BCM presentes no próprio Pi. É o hardware mais difícil de obter nesta lista.

**Stack mínimo recomendado para máximo impacto urbano:**
```
Pi 5 (base)
+ Alfa AWUS036ACHM      ~35€   (WiFi pentest)
+ RTL-SDR Blog V4       ~30€   (TPMS + LoRa + 433MHz)
+ nRF52840 Dongle       ~10€   (SweynTooth)
+ Elechouse PN532 V3    ~12€   (NFC)
+ Powerbank PD 45W      ~45€   (8-10h autonomia)
─────────────────────────────
Total extra             ~132€
```

---

## 2. Relatório de Exploits por Área

Organizado por criticidade decrescente dentro de cada área. A coluna **Implementação** classifica os repositórios públicos existentes como:
- **ÓTIMA** — implementação completa, nada mais a fazer além de integrar
- **MÉDIO** — funcional mas pode ser expandido (automação, integração, mais targets)
- **FRACO** — PoC básico ou apenas research sem ferramenta — grande oportunidade de contribuição original

---

### Área 1 — Bluetooth Classic (BR/EDR)

---

#### CVE-2023-45866 + CVE-2024-21306 — Bluetooth HID Keystroke Injection
**Criticidade: CRÍTICA** | **Hardware: Pi built-in**

Falha na state-machine do host Bluetooth (BlueZ, Android, macOS, iOS, Windows) que aceita um teclado HID falso sem confirmação do utilizador. O atacante emula um teclado Bluetooth com capability `NoInputNoOutput`, explora o modelo *Just Works* e injeta keystrokes arbitrários sem emparelhamento. É um ataque **zero-click** — basta o Bluetooth estar ativo na vítima.

CVE-2024-21306 é a variante Windows do mesmo ataque. CVE-2024-0230 afeta iOS/macOS.

**Impacto urbano:** num café ou metro, podes abrir um terminal, executar comandos, ou enviar mensagens em telemóveis Android e laptops Linux desbloqueados ao teu redor. A integração com DuckyScript (que já tens no roadmap HID) permite carregar payloads `.duck` diretamente.

| Repositório | Descrição | Implementação |
|---|---|---|
| [marcnewlin/hi_my_name_is_keyboard](https://github.com/marcnewlin/hi_my_name_is_keyboard) | PoC original do descobridor Marc Newlin (SkySafe), cobre CVE-2023-45866 + 21306 + 0230, Python + BlueZ | **ÓTIMA** |
| [Eason-zz/BluetoothDucky](https://github.com/Eason-zz/BluetoothDucky) | Integração com DuckyScript — carrega payloads `.duck` via Bluetooth, executa keystrokes formatados | **ÓTIMA** |
| [PhucHauDeveloper/BadBlue](https://github.com/PhucHauDeveloper/BadBlue) | Variante CVE-2024-21306 (Windows), DuckyScript, menos features | **MÉDIO** |
| [Chedrian07/CVE-2023-45866-POC](https://github.com/Chedrian07/CVE-2023-45866-POC) | PoC minimalista, sem DuckyScript | **FRACO** |

*Fontes: [Mobile Hacker writeup](https://www.mobile-hacker.com/2024/01/23/exploiting-0-click-android-bluetooth-vulnerability-to-inject-keystrokes-without-pairing/) · [SkySafe disclosure](https://github.com/skysafe/reblog/tree/main/cve-2023-45866)*

---

#### KNOB — CVE-2019-9506 — Key Negotiation of Bluetooth
**Criticidade: ALTA** | **Hardware: InternalBlue compatible**

Força a negociação da chave de encriptação BR/EDR para entropia mínima (1 byte = 256 combinações possíveis). Com essa entropia reduzida, o atacante faz brute-force da chave em tempo real e desencripta toda a comunicação Bluetooth entre dois dispositivos. É uma falha do **standard**, não de uma implementação específica — afeta todos os dispositivos Bluetooth sem exceção.

**Impacto urbano:** desencriptar conversas de headsets Bluetooth, teclados wireless, e ratos em tempo real, dentro do raio do Pi.

| Repositório | Descrição | Implementação |
|---|---|---|
| [francozappa/knob](https://github.com/francozappa/knob) | PoC oficial do investigador Daniele Antonioli, usa InternalBlue Python API, inclui validação de entropia + brute-force da chave E0 | **MÉDIO** |
| [u10427687/bluetooth-KNOB](https://github.com/u10427687/bluetooth-KNOB) | Implementação alternativa com internalblue v0.1, menos completa | **FRACO** |

> MÉDIO: o PoC funciona mas requer hardware InternalBlue específico e não tem automação. Pode ser expandido para integrar com o scanner BLE existente no projeto para identificar alvos automaticamente.

*Fontes: [knobattack.com](https://knobattack.com/) · [francozappa/knob](https://github.com/francozappa/knob)*

---

#### BIAS — CVE-2020-10135 — Bluetooth Impersonation AttackS
**Criticidade: ALTA** | **Hardware: InternalBlue compatible**

Permite impersonar um dispositivo **já emparelhado** sem conhecer a link key, explorando a ausência de autenticação mútua obrigatória no Bluetooth BR/EDR. Funciona independentemente da versão Bluetooth, fabricante, ou modo de segurança — é standard-compliant. Afeta todos os dispositivos desde BT 2.1.

**Impacto urbano:** impersonar o headset Bluetooth de um utilizador para intercetar chamadas, injetar áudio, ou usar o dispositivo como relay.

| Repositório | Descrição | Implementação |
|---|---|---|
| [francozappa/bias](https://github.com/francozappa/bias) | Toolkit oficial do investigador Daniele Antonioli, primeiro toolkit a implementar impersonação BT, usa InternalBlue Python API | **MÉDIO** |

> MÉDIO: sólido e o único toolkit público para este ataque. Depende de InternalBlue e não integra com deteção automática de dispositivos. O módulo BLE scanner do projeto seria uma base natural para alimentar alvos ao BIAS toolkit.

*Fontes: [BIAS research site](https://francozappa.github.io/about-bias/) · [Full Disclosure](https://seclists.org/fulldisclosure/2020/Jun/5)*

---

#### BLUFFS — CVE-2023-24023 — Bluetooth Forward Secrecy Attacks
**Criticidade: ALTA** | **Hardware: InternalBlue compatible**

Seis ataques que quebram forward e future secrecy do Bluetooth clássico, forçando a derivação da mesma session key entre sessões. Com a chave repetida, o atacante estabelece uma posição MITM persistente entre sessões — mesmo depois de o utilizador "desligar e reconectar". Afeta Bluetooth Core Specification 4.2 a 5.4. Apresentado no ACM CCS 2023.

| Repositório | Descrição | Implementação |
|---|---|---|
| [francozappa/bluffs](https://github.com/francozappa/bluffs) | PoC oficial com packet captures, ferramentas de análise por vulnerabilidade, e patches individuais para testar por dispositivo | **MÉDIO** |

> MÉDIO: ferramenta de investigação completa mas orientada a investigadores, não a automação de pentest. A integração com o event bus do projeto seria uma expansão natural.

*Fontes: [The Hacker News](https://thehackernews.com/2023/12/new-bluffs-bluetooth-attack-expose.html) · [CCC talk](https://media.ccc.de/v/37c3-12342-bluffs_bluetooth_forward_and_future_secrecy_attacks_and_defenses)*

---

### Área 2 — Bluetooth Low Energy (BLE)

---

#### WhisperPair — CVE-2025-36911 — Fast Pair KBP Bypass
**Criticidade: CRÍTICA** | **Hardware: Pi built-in**

Logic error na implementação do Key-Based Pairing do Google Fast Pair — dispositivos não verificam se estão em modo pairing antes de aceitar requests KBP, permitindo emparelhar forçadamente acessórios de áudio (headphones, speakers) sem consentimento do utilizador. Com bond estabelecido, abre caminho para captura de áudio via HFP.

**Estado no projeto:** Scanner e tester implementados (Sprint 2). Exploit chain em desenvolvimento — KBP bypass e HFP audio ainda em implementação.

*Fonte: [SecurityWeek](https://www.securityweek.com/whisperpair-attack-leaves-millions-of-bluetooth-accessories-open-to-hijacking/)*

---

#### SweynTooth — 12 CVEs — BLE SoC Crashes & Security Bypasses
**Criticidade: ALTA** | **Hardware: Nordic nRF52840 USB Dongle (~10€)**

Família de 12 vulnerabilidades em SDKs BLE de 7 fabricantes de SoC: Texas Instruments, NXP, Cypress, Dialog Semiconductor, Microchip, STMicroelectronics, e Telink. Permite crashes, deadlocks, buffer overflows, e bypass do security mode por BLE — afeta Fitbit, August Smart Lock, Eve Energy, e dispositivos médicos (pacemakers, monitores de glicose).

**Impacto urbano:** qualquer sensor de cidade inteligente, wearable barato, ou fechadura smart provavelmente usa um destes SoCs. O ataque é possível passando por qualquer pessoa que use um destes dispositivos.

| Repositório | Descrição | Implementação |
|---|---|---|
| [Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks](https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks) | Scripts de exploit por vulnerabilidade, tabela de correspondência SoC→script, documentação clara | **MÉDIO** |

> MÉDIO: scripts funcionais mas requerem o dongle nRF52840 específico e identificação manual do SoC alvo. Pode ser expandido com deteção automática de SoC por BLE advertisement fingerprinting, integrado com o scanner BLE existente.

*Fontes: [USENIX ATC 2020 paper](https://www.usenix.org/system/files/atc20-garbelini.pdf) · [CISA Alert](https://www.cisa.gov/news-events/ics-alerts/ics-alert-20-063-01)*

---

#### AirDrop Phone Number Harvesting — AWDL Privacy Leak
**Criticidade: MÉDIA** | **Hardware: Pi built-in**

O protocolo AWDL (Apple Wireless Direct Link) transmite hashes SHA256 truncados do número de telemóvel e email do utilizador durante a descoberta AirDrop. Com rainbow tables pré-computadas para prefixos nacionais (+351 9XXXXXXXX = ~100M combinações, bruteforçável em minutos), é possível recuperar números de telefone de todas as pessoas ao redor com AirDrop em "Todos". Explorado por autoridades chinesas em 2024 para deanonimizar utilizadores.

**Impacto urbano:** numa praça ou metro, podes passivamente recolher números de telemóvel de dezenas de pessoas por hora, sem qualquer interação.

| Repositório | Descrição | Implementação |
|---|---|---|
| [privatedrop.github.io](https://privatedrop.github.io/) | Investigação académica com análise do protocolo e solução proposta (PrivateDrop), sem ferramenta de exploit pública | **FRACO** |

> FRACO: existe o research detalhado mas não há ferramenta pública de exploração. **Grande oportunidade de implementação original** — seria uma das contribuições mais impactantes academicamente do projeto.

*Fontes: [WeLiveSecurity](https://www.welivesecurity.com/2021/04/22/airdrop-flaws-could-leak-phone-numbers-email-addresses/) · [PrivateDrop](https://privatedrop.github.io/)*

---

#### CVE-2025-27840 — ESP32 Hidden HCI Commands
**Criticidade: MÉDIA** | **Hardware: Pi built-in (deteção passiva)**

O ESP32 (presente em mais de 1 mil milhões de dispositivos IoT — smart home, wearables, sensores urbanos) tem 29 comandos HCI não documentados. O mais crítico, `0xFC02`, permite escrita direta em memória do chip. A exploração completa requer acesso físico, mas a **deteção e fingerprinting de dispositivos ESP32** via resposta HCI é imediatamente implementável via BLE scan — útil para mapear a superfície de ataque IoT de uma área urbana.

| Repositório | Descrição | Implementação |
|---|---|---|
| Nenhum repositório público completo | Apenas análise de firmware e artigos técnicos | **FRACO** |

*Fontes: [CNX Software](https://www.cnx-software.com/2025/03/10/hidden-proprietary-bluetooth-hci-commands-in-esp32-microcontroller-could-pose-a-security-risk/) · [SOC Prime](https://socprime.com/blog/cve-2025-27840-vulnerability-in-esp32-bluetooth-chips/)*

---

### Área 3 — WiFi (IEEE 802.11)

---

#### Kr00k — CVE-2019-15126 — All-Zero Key Post-Disassociation
**Criticidade: ALTA** | **Hardware: Alfa WiFi adapter**

Chips Broadcom/Cypress (iPhone, Android, Raspberry Pi built-in, routers Asus/Netgear/D-Link, Amazon Echo, Kindle) usam chave de encriptação all-zero após disassociação do cliente. O ataque é direto: força disassociação com o módulo deauth que já existe no projeto, captura os frames transmitidos com chave zero, e desencripta-os. Afeta WPA2 CCMP em 2.4GHz.

**Integração natural:** o módulo `wifi/attacks.py` já tem deauth implementado — Kr00k é uma extensão lógica do mesmo fluxo.

| Repositório | Descrição | Implementação |
|---|---|---|
| [hexway/r00kie-kr00kie](https://github.com/hexway/r00kie-kr00kie) | PoC completo: deauth + captura + desencriptação CCMP com Scapy, CLI com opções de interface/canal/BSSID/MAC | **ÓTIMA** |
| [EaglerLight/wifi_poc](https://github.com/EaglerLight/wifi_poc) | Script alternativo mais simples, menos features | **FRACO** |

*Fontes: [ESET Kr00k whitepaper](https://web-assets.esetstatic.com/wls/2020/02/ESET_Kr00k.pdf) · [hexway/r00kie-kr00kie](https://github.com/hexway/r00kie-kr00kie)*

---

#### FragAttacks — CVE-2020-24586/87/88 — Wi-Fi Fragmentation Attacks
**Criticidade: ALTA** | **Hardware: Alfa WiFi adapter**

Família de falhas de design no IEEE 802.11 desde 1997 — virtualmente todos os dispositivos WiFi são afetados. Permitem injetar frames arbitrários em redes WPA2/WPA3 protegidas explorando como fragmentos e agregados de frames são processados. Especialmente perigoso contra IoT que nunca recebe patches de firmware.

| Repositório | Descrição | Implementação |
|---|---|---|
| [vanhoefm/fragattacks](https://github.com/vanhoefm/fragattacks) | Ferramenta oficial de Mathy Vanhoef (mesmo investigador do KRACK/SSID Confusion), testa APs e clientes para todos os FragAttacks, framework de testes automatizados completo | **ÓTIMA** |

> ÓTIMA: é a ferramenta definitiva, do próprio investigador. Nada mais a acrescentar — apenas integrar no projeto.

*Fontes: [fragattacks.com](https://www.fragattacks.com/) · [BleepingComputer](https://www.bleepingcomputer.com/news/security/all-wi-fi-devices-impacted-by-new-fragattacks-vulnerabilities/)*

---

#### SSID Confusion — CVE-2023-52424 — Network Name Spoofing
**Criticidade: MÉDIA** | **Hardware: Alfa WiFi adapter**

Falha de design no IEEE 802.11: o SSID não é incluído na derivação da PMK (Pairwise Master Key). Um atacante com as mesmas credenciais pode fazer clientes ligarem-se a uma rede diferente sem que saibam — caso de uso típico: downgrade de clientes do 5GHz (mais seguro) para 2.4GHz (menos seguro), permitindo subsequente MITM. Afeta WEP, WPA2, WPA3, Enterprise, e redes mesh. Descoberto por Mathy Vanhoef (KU Leuven).

| Repositório | Descrição | Implementação |
|---|---|---|
| Nenhuma ferramenta pública | Apenas o paper académico de Mathy Vanhoef | **FRACO** |

> FRACO: não existe ferramenta pública de demonstração. **Implementar seria uma contribuição original** — o paper de Vanhoef descreve o ataque com detalhe suficiente para implementar. Combinado com o Evil Twin já no roadmap, seria muito poderoso.

*Fontes: [Paper WiSec 2024 — Mathy Vanhoef](https://papers.mathyvanhoef.com/wisec2024.pdf) · [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2023-52424/)*

---

### Área 4 — IoT & Protocolos Urbanos

---

#### TPMS Vehicle Tracking — 433MHz Passive Surveillance
**Criticidade: MÉDIA** | **Hardware: RTL-SDR Blog V4**

Cada carro moderno transmite continuamente a pressão dos pneus a 433MHz com um **ID único e fixo por sensor**. Com RTL-SDR, podes passivamente identificar e rastrear veículos específicos ao longo do tempo e por localização (com GPS). O utilizador nunca sabe que está a ser rastreado — não há nenhum campo magnético que altere, nenhuma bateria que drene, e nenhum aviso visível.

**Impacto urbano:** estacionado numa rua movimentada, o Pi conta e identifica cada carro que passa. Com GPS integrado, cria um log de movimento de veículos específicos.

| Repositório | Descrição | Implementação |
|---|---|---|
| [jboone/tpms](https://github.com/jboone/tpms) | Captura, demodulação FSK, Manchester decoding, extração de IDs únicos | **MÉDIO** |
| [jimkoeh/tpms](https://github.com/jimkoeh/tpms) | Ferramentas de decoding de pacotes TPMS, análise estatística | **FRACO** |
| rtl_433 (tool separada) | Decodifica TPMS automaticamente entre 100+ protocolos SDR, tem output JSON | **MÉDIO** |

> MÉDIO: as ferramentas decodificam e extraem IDs mas não têm camada de tracking/persistência/mapa. Integrar com GPS + SQLite + dashboard do projeto seria uma adição visualmente impactante e academicamente original.

*Fontes: [RTL-SDR.com TPMS](https://www.rtl-sdr.com/tag/tpms/) · [GitHub Topics: tpms](https://github.com/topics/tpms)*

---

#### MQTT Attack Suite — IoT Protocol Exploitation
**Criticidade: MÉDIA** | **Hardware: Nenhum extra**

MQTT (porta 1883/8883) é o protocolo de mensagens de facto para IoT — câmeras IP, sensores de cidade inteligente, smart home, automação industrial. Brokers mal configurados expõem todos os tópicos com subscrição `#`, permitindo ler e injetar mensagens. CVE-2023-28366 afeta Eclipse Mosquitto causando memory leak remoto.

**Impacto urbano:** numa rede local urbana (café, escritório, condomínio), um broker MQTT exposto dá acesso a termostatos, câmeras, fechaduras, e sensores sem qualquer autenticação.

| Repositório | Descrição | Implementação |
|---|---|---|
| [akamai-threat-research/mqtt-pwn](https://github.com/akamai-threat-research/mqtt-pwn) | Suite completa: credential brute-force, topic enumeration, data harvesting, CLI interativo | **MÉDIO** |
| [kh4sh3i/MQTT-Pentesting](https://github.com/kh4sh3i/MQTT-Pentesting) | Guia e scripts de pentesting MQTT, mais educativo | **FRACO** |

> MÉDIO: mqtt-pwn é funcional mas não está integrado com nenhum scanner de rede. Combinar com o NmapScanner do projeto para descoberta automática de brokers MQTT abertos seria uma expansão direta.

*Fontes: [Airbus Protect MQTT](https://www.protect.airbus.com/blog/exposing-mqtt-hidden-talks/) · [HackTricks MQTT](https://angelica.gitbook.io/hacktricks/network-services-pentesting/1883-pentesting-mqtt-mosquitto)*

---

### Tabela de Prioridade Global

| # | Exploit | Área | Criticidade | Hardware | Impl. pública | Oportunidade no projeto |
|---|---|---|---|---|---|---|
| 1 | CVE-2023-45866 + DuckyScript | BT Classic | CRÍTICA | Pi built-in | ÓTIMA | Integrar com HID module (DuckyScript) |
| 2 | WhisperPair CVE-2025-36911 | BLE | CRÍTICA | Pi built-in | (projeto) | Completar KBP bypass + HFP |
| 3 | Kr00k CVE-2019-15126 | WiFi | ALTA | Alfa | ÓTIMA | Integrar com deauth module existente |
| 4 | FragAttacks CVE-2020-24586 | WiFi | ALTA | Alfa | ÓTIMA | Wrapping da ferramenta de Vanhoef |
| 5 | KNOB CVE-2019-9506 | BT Classic | ALTA | InternalBlue | MÉDIO | Automação sobre BLE scanner |
| 6 | BIAS CVE-2020-10135 | BT Classic | ALTA | InternalBlue | MÉDIO | Combinar com BLE scanner |
| 7 | BLUFFS CVE-2023-24023 | BT Classic | ALTA | InternalBlue | MÉDIO | MITM persistente entre sessões |
| 8 | SweynTooth | BLE IoT | ALTA | nRF52840 | MÉDIO | Auto-detect SoC por advertisement |
| 9 | TPMS Tracking | SDR/Urbano | MÉDIA | RTL-SDR | MÉDIO | GPS + SQLite + mapa em tempo real |
| 10 | MQTT Attack Suite | IoT | MÉDIA | Nenhum | MÉDIO | Integrar com NmapScanner |
| 11 | AirDrop Harvesting | BLE/AWDL | MÉDIA | Pi built-in | FRACO | Implementação original — alto impacto académico |
| 12 | SSID Confusion CVE-2023-52424 | WiFi | MÉDIA | Alfa | FRACO | Implementação original — contribuição nova |
| 13 | ESP32 Fingerprinting CVE-2025-27840 | BLE IoT | MÉDIA | Pi built-in | FRACO | Mapear superfície IoT urbana |

---

---

## 3. Relatório de Bugs por Sprint

Cada bug inclui: ficheiro, linha exata, descrição do problema, consequência em runtime, e sugestão de correção.

---

### Sprint 2 — Módulo BLE

---

#### BLE-01 — NameError: variável `proxy` não definida
**Severidade: CRÍTICA** | **Ficheiro:** `src/urban_hs/modules/ble/exploit_chain.py` **linha 305**

```python
# Linha 304 — correto: cria device_proxy
device_proxy = self.bus.get_object("org.bluez", device_path)

# Linha 305 — ERRO: usa 'proxy' que não existe neste scope
device_iface = dbus.Interface(proxy, "org.bluez.Device1")
#                             ^^^^^
#                             NameError: name 'proxy' is not defined
```

**Consequência:** `HFPAudioCapture.connect_hfp()` lança `NameError` imediatamente ao ser chamado. O método nunca executa.

**Correção:**
```python
device_iface = dbus.Interface(device_proxy, "org.bluez.Device1")
```

---

#### BLE-02 — AttributeError: `self.config` não existe em WhisperPairFullExploit
**Severidade: CRÍTICA** | **Ficheiro:** `src/urban_hs/modules/ble/exploit_chain.py` **linhas 453–454**

```python
# WhisperPairFullExploit é um dataclass com campos:
# target_mac, target_essid, channel, adapter_wifi, adapter_ble,
# bonding_manager, account_key_manager, hfp_capture,
# exploit_state, shared_secret, account_key_written, audio_capture_active, audio_file
# Não há nenhum campo 'config'!

# Linhas 453-454 — ERRO: self.config não existe
if self.config.ble_hfp_audio_enabled:
    log_step("hfp_capture", "running", f"Starting HFP audio capture for {self.config.ble_audio_duration}s")
```

**Consequência:** `run_full_chain()` lança `AttributeError: 'WhisperPairFullExploit' object has no attribute 'config'` sempre que tenta iniciar a captura HFP.

**Correção:** usar o parâmetro `audio_duration` que já é recebido pela função, e um novo campo `hfp_enabled`:

```python
# No dataclass, adicionar:
hfp_enabled: bool = False
audio_duration: int = 60

# Nas linhas 453-454, substituir por:
if self.hfp_enabled:
    log_step("hfp_capture", "running", f"Starting HFP audio capture for {audio_duration}s")
```

---

#### BLE-03 — BondingStatus duplicado em `__all__` e no import
**Severidade: BAIXA** | **Ficheiro:** `src/urban_hs/modules/ble/exploit_chain.py` **linhas 473 e 476** e `src/urban_hs/modules/ble/__init__.py` **linha 26**

```python
# exploit_chain.py — __all__ com BondingStatus duas vezes:
__all__ = [
    "BlueZBondingManager",
    "BondedDevice",
    "BondingStatus",   # linha 473
    "AccountKeyManager",
    "HFPAudioCapture",
    "WhisperPairFullExploit",
    "BondingStatus",   # linha 476 — duplicado
]

# ble/__init__.py — importado duas vezes:
from urban_hs.modules.ble.exploit_chain import (
    BlueZBondingManager,
    BondedDevice,
    BondingStatus,         # linha 22
    AccountKeyManager,
    HFPAudioCapture,
    WhisperPairFullExploit,
    BondingStatus,         # linha 26 — duplicado
)
```

**Consequência:** Não causa erro em runtime (Python ignora duplicados em imports e listas), mas sinaliza um copy-paste descuidado e confunde quem lê o código.

**Correção:** remover a segunda ocorrência de `BondingStatus` em ambos os ficheiros.

---

#### BLE-04 — API asyncio deprecada: `asyncio.get_event_loop()`
**Severidade: MÉDIA** | **Ficheiro:** `src/urban_hs/modules/ble/exploit_chain.py` **linhas 93–94**

```python
# Deprecated desde Python 3.10, aviso em 3.12, remoção prevista em 3.14:
start_time = asyncio.get_event_loop().time()
while asyncio.get_event_loop().time() - start_time < timeout:
```

**Consequência:** Em Python 3.12+, emite `DeprecationWarning`. Em versões futuras, pode lançar `RuntimeError` se não houver event loop em execução.

**Correção:**
```python
import time
start_time = time.monotonic()
while time.monotonic() - start_time < timeout:
```

---

#### BLE-05 — HFPAudioCapture: estado inconsistente em `start_capture()`
**Severidade: MÉDIA** | **Ficheiro:** `src/urban_hs/modules/ble/exploit_chain.py` **linhas 330–339**

```python
async def start_capture(self, output_file: str, duration: int = 60) -> bool:
    self.capture_active = True   # Estado marcado como ativo...
    self.audio_file = output_file
    logger.warning("HFPAudioCapture not fully implemented - requires bluealsa/ofono")
    return False                 # ...mas retorna False (falha)
```

**Consequência:** Qualquer chamador que verifique `capture_active` vai ver `True` (ativo), mas a função retornou `False` (falhou). Estado interno contradiz o valor de retorno. Se algum código fizer `if not await hfp.start_capture(...)` para detetar falha, vai limpar recursos que nunca foram criados; mas se verificar `hfp.capture_active`, vai pensar que está a capturar.

**Correção:** ou não alterar `capture_active` quando a implementação não existe, ou lançar `NotImplementedError`:
```python
async def start_capture(self, output_file: str, duration: int = 60) -> bool:
    raise NotImplementedError("HFP audio capture requires bluealsa/ofono integration")
```

---

#### BLE-06 — Imports dentro de método em vez de top-level
**Severidade: BAIXA** | **Ficheiro:** `src/urban_hs/modules/ble/exploit_chain.py` **linhas 192 e 200**

```python
def _generate_account_key(self, shared_secret: Optional[bytes] = None) -> bytes:
    import os                                                    # linha 192 — import aqui
    key = bytearray(16)
    key[0] = 0x04
    key[1:] = os.urandom(15)
    if shared_secret:
        from cryptography.hazmat.primitives.ciphers import ...  # linha 200 — import aqui
```

**Consequência:** `os` já está importado no topo do ficheiro (linha 22). O import dentro do método é redundante. O import de `cryptography` dentro do método significa que o erro de módulo não instalado só aparece em runtime quando a função é chamada, não na inicialização.

**Correção:** mover ambos os imports para o topo do ficheiro, com tratamento adequado do import opcional:
```python
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
```

---

#### BLE-07 — AES-ECB sobre input de 15 bytes (tamanho incorreto para AES)
**Severidade: MÉDIA** | **Ficheiro:** `src/urban_hs/modules/ble/exploit_chain.py` **linhas 201–204**

```python
cipher = Cipher(algorithms.AES(shared_secret[:16]), modes.ECB())
encryptor = cipher.encryptor()
key_encrypted = encryptor.update(key[1:]) + encryptor.finalize()
#                                ^^^^^^^
#                                key[1:] tem 15 bytes — AES-ECB requer múltiplos de 16!
key[1:] = key_encrypted[:15]
```

**Consequência:** AES em modo ECB requer que o input seja múltiplo de 16 bytes. `key[1:]` tem exactamente 15 bytes. A biblioteca `cryptography` vai lançar `ValueError: The length of the provided data is not a multiple of the block length` em runtime quando `shared_secret` for fornecido.

**Correção:** usar 16 bytes completos ou aplicar padding:
```python
# Opção 1: usar key completa (16 bytes) e depois usar bytes 1-15
key_to_encrypt = bytes(key)  # 16 bytes
key_encrypted = encryptor.update(key_to_encrypt) + encryptor.finalize()
new_key = bytearray([0x04]) + bytearray(key_encrypted[1:16])
return bytes(new_key)
```

---

#### BLE-08 — Import duplicado em `urban_hack.py`
**Severidade: BAIXA** | **Ficheiro:** `src/urban_hs/modules/urban_hack.py` **linhas 20 e 22**

```python
from urban_hs.modules.ble import (
    FastPairScanner, WhisperPairTester, WhisperPairExploit,  # linha 20
    BLEDevice, BLEDeviceType,
    FastPairScanner, WhisperPairTester, WhisperPairExploit,  # linha 22 — duplicado exato
)
```

**Consequência:** Sem impacto em runtime (Python ignora reimports do mesmo nome). Sinaliza copy-paste descuidado.

**Correção:** remover as linhas duplicadas.

---

#### BLE-09 — KBP exploit é um TODO sem implementação
**Severidade: ALTA (feature)** | **Ficheiro:** `src/urban_hs/modules/ble/exploit_chain.py` **linhas 424–428**

```python
# Step 2: KBP Exploit
log_step("kbp_exploit", "running", "Executing KBP exploit")
# TODO: Implement full KBP exploit from WhisperPairExploit
# For now, mark as placeholder
log_step("kbp_exploit", "placeholder", "KBP exploit needs full implementation")
```

**Consequência:** O passo central do CVE-2025-36911 — o bypass do Key-Based Pairing — não existe. O exploit chain continua para bonding sem o KBP bypass, o que significa que o ataque vai falhar em dispositivos que não aceitem bonds sem autenticação prévia. O README e o MASTER_PLAN descrevem estratégias (RAW_KBP, RETROACTIVE, EXTENDED_RESPONSE) que não estão implementadas.

---

### Sprint 3 — Módulo Network

---

#### NET-01 — Blocking socket I/O dentro de função async (bloqueia o event loop)
**Severidade: CRÍTICA** | **Ficheiro:** `src/urban_hs/modules/network/__init__.py` **linhas 755–762**

```python
async def _upnp_discovery(self) -> List[Dict[str, Any]]:
    # ...
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(5)
    sock.sendto(ssdp_request.encode(), ("239.255.255.250", 1900))

    try:
        while True:
            data, addr = sock.recvfrom(65535)  # BLOQUEANTE — congela o event loop
```

**Consequência:** `socket.recvfrom()` é uma chamada bloqueante. Dentro de uma `async def`, bloqueia o event loop inteiro do asyncio durante até 5 segundos (o timeout do socket). Nesse tempo, zero outras coroutines executam — o BLE scanner para, o WiFi scanner para, nenhum evento é processado. Num projeto com scans paralelos, isto é um problema sério.

**Correção:**
```python
# Opção 1 — wrapping em thread:
data, addr = await asyncio.to_thread(sock.recvfrom, 65535)

# Opção 2 — usar asyncio DatagramProtocol (mais correto):
loop = asyncio.get_running_loop()
transport, protocol = await loop.create_datagram_endpoint(...)
```

---

#### NET-02 — Parâmetro `network` ignorado em `discover_cameras()`
**Severidade: ALTA** | **Ficheiro:** `src/urban_hs/modules/network/__init__.py` **linhas 695 e 699**

```python
async def discover_cameras(self, network: str = "192.168.1.0/24") -> List[Dict[str, Any]]:
    # ...
    rtsp_cameras = await self._rtsp_scan("192.168.1.0/24")   # linha 695 — hardcoded
    http_cameras = await self._http_fingerprint("192.168.1.0/24")  # linha 699 — hardcoded
```

**Consequência:** qualquer chamador que passe um `network` diferente (ex: `"10.0.0.0/8"`) vai receber resultados de `192.168.1.0/24` — silenciosamente errado. O scanner de câmeras nunca analisa a rede correta.

**Correção:**
```python
rtsp_cameras = await self._rtsp_scan(network)
http_cameras = await self._http_fingerprint(network)
```

---

#### NET-03 — Comparação de Enum com string falha silenciosamente
**Severidade: CRÍTICA** | **Ficheiro:** `src/urban_hs/modules/network/__init__.py` **linhas 900–901**

```python
# linha 878 — vulnerabilidades são convertidas para dict com __dict__:
results["vulnerabilities"] = [v.__dict__ for v in vulns]
# O campo 'severity' no dict é Severity.CRITICAL (Enum), não a string "critical"

# linhas 900-901 — comparação com string sempre retorna False:
"critical_vulns": len([v for v in results["vulnerabilities"] if v.get("severity") == "critical"]),
"high_vulns":     len([v for v in results["vulnerabilities"] if v.get("severity") == "high"]),
```

**Consequência:** `Severity.CRITICAL == "critical"` é sempre `False` em Python. O summary vai reportar sempre `critical_vulns: 0` e `high_vulns: 0` independentemente do número real de vulnerabilidades críticas encontradas.

**Correção:** converter o valor do Enum para string ao fazer `__dict__`, ou comparar contra o Enum:
```python
# Opção 1 — converter ao serializar:
results["vulnerabilities"] = [
    {**v.__dict__, "severity": v.severity.value} for v in vulns
]

# Opção 2 — comparar contra Enum no summary:
"critical_vulns": len([v for v in vulns if v.severity == Severity.CRITICAL]),
```

---

#### NET-04 — Hydra output parsing frágil — risco de IndexError
**Severidade: ALTA** | **Ficheiro:** `src/urban_hs/modules/network/__init__.py` **linhas 618–633**

```python
for line in stdout_str.split("\n"):
    if "login:" in line and "password:" in line:
        parts = line.split()
        login_idx = parts.index("login:") if "login:" in parts else -1
        pass_idx = parts.index("password:") if "password:" in parts else -1
        if login_idx >= 0 and pass_idx >= 0:
            username = parts[login_idx + 1]  # IndexError se login: for o último token
            password = parts[pass_idx + 1]   # IndexError se password: for o último token
```

O output real do Hydra é:
```
[22][ssh] host: 192.168.1.1   login: admin   password: 12345
```

**Consequência:** Se `"login:"` aparecer como substring de uma palavra (ex: `"[login:admin]"`) a condição `"login:" in parts` falha porque `parts.index()` procura o token exato. Inversamente, se `login:` for o último token da linha, `parts[login_idx + 1]` lança `IndexError`. O parser pode crash ou extrair dados errados.

**Correção:** usar regex:
```python
match = re.search(r"login:\s+(\S+)\s+password:\s+(\S+)", line)
if match:
    username, password = match.group(1), match.group(2)
    results.append({"service": service, "ip": target_ip, "port": port,
                    "username": username, "password": password})
```

---

#### NET-05 — mDNS parsing errado: avahi-browse usa `;` não espaços
**Severidade: ALTA** | **Ficheiro:** `src/urban_hs/modules/network/__init__.py` **linhas 726–735**

```python
for line in stdout.decode().split("\n"):
    if "IPv4" in line or "IPv6" in line:
        parts = line.split()          # split por espaço
        if len(parts) >= 4:
            cameras.append({
                "service": parts[2],  # campo errado
                "hostname": parts[3], # campo errado
            })
```

O output real de `avahi-browse -p` usa `;` como separador:
```
=;eth0;IPv4;camera_name;_rtsp._tcp;local;hostname.local;192.168.1.100;554;
```

**Consequência:** `line.split()` por whitespace produz um array com um único elemento (ou muito poucos, se o nome tiver espaços). `parts[2]` e `parts[3]` ou causam `IndexError` ou retornam valores sem sentido. O discovery mDNS nunca extrai IPs ou nomes corretos.

**Correção:**
```python
parts = line.split(";")
if len(parts) >= 8:
    cameras.append({
        "discovery_method": "mdns",
        "hostname": parts[6],   # hostname.local
        "ip": parts[7],         # endereço IP
        "port": int(parts[8]) if parts[8].isdigit() else None,
        "service": parts[4],    # _rtsp._tcp
    })
```

---

#### NET-06 — ONVIF discovery é `pass` vazio
**Severidade: ALTA (feature)** | **Ficheiro:** `src/urban_hs/modules/network/__init__.py` **linhas 780–789**

```python
async def _onvif_discovery(self) -> List[Dict[str, Any]]:
    """Discover ONVIF cameras via WS-Discovery."""
    cameras = []
    try:
        pass  # corpo completamente vazio
    except Exception as e:
        logger.warning("ONVIF discovery failed", error=str(e))
    return cameras
```

**Consequência:** nenhum request WS-Discovery SOAP é enviado. Retorna lista vazia sempre. A câmera ONVIF descoberta via mDNS ou UPnP não será encontrada por este método.

---

#### NET-07 — HTTP fingerprinting é stub completo
**Severidade: ALTA (feature)** | **Ficheiro:** `src/urban_hs/modules/network/__init__.py` **linhas 827–829**

```python
async def _http_fingerprint(self, network: str) -> List[Dict[str, Any]]:
    """Fingerprint cameras via HTTP."""
    return []
```

**Consequência:** nenhum pedido HTTP é feito. Câmeras que exponham apenas HTTP (porta 80/8080) nunca são descobertas por este método.

---

#### NET-08 — RouterSploit scan retorna sempre lista vazia
**Severidade: MÉDIA (feature)** | **Ficheiro:** `src/urban_hs/modules/network/__init__.py` **linhas 566–575**

```python
async def scan_router(self, target_ip: str, ...) -> List[Dict[str, Any]]:
    """Run RouterSploit against target."""
    # This would run routersploit modules
    return []
```

**Consequência:** `RouterScanner.scan_router()` é exportado em `__all__` e prometido no README, mas nunca executa nada. A linha que chamaria este método no `full_network_assessment()` está comentada (linha 891), por isso não há impacto imediato — mas qualquer utilizador que chame diretamente vai receber resultados vazios sem aviso.

---

#### NET-09 — Nmap scan usa `-sT` sem verificar permissões de root
**Severidade: BAIXA** | **Ficheiro:** `src/urban_hs/modules/network/__init__.py` **linhas 152–165**

```python
elif scan_type == ScanType.OS_FINGERPRINT:
    cmd.extend(["-sT", "-O"])   # -O requer root!
elif scan_type == ScanType.FULL_SCAN:
    cmd.extend(["-sT", "-sV", "-O"])   # -O requer root!
```

**Consequência:** `-O` (OS fingerprinting) requer privilégios root. Se o Pi não correr com root (ou `CAP_NET_RAW`), o nmap vai falhar com `You requested OS detection (-O) which requires root privileges`. O erro é retornado como lista vazia sem mensagem clara ao utilizador.

**Correção:** verificar `os.geteuid() == 0` antes de adicionar `-O`, ou usar `-sV --version-intensity 5` como alternativa sem root.

---

## 4. Sumário de Bugs

### Por Sprint e Severidade

| ID | Sprint | Severidade | Ficheiro | Linha | Descrição curta |
|---|---|---|---|---|---|
| BLE-01 | Sprint 2 | **CRÍTICA** | `ble/exploit_chain.py` | 305 | NameError: `proxy` devia ser `device_proxy` |
| BLE-02 | Sprint 2 | **CRÍTICA** | `ble/exploit_chain.py` | 453–454 | AttributeError: `self.config` não existe |
| BLE-07 | Sprint 2 | MÉDIA | `ble/exploit_chain.py` | 201–204 | AES-ECB sobre 15 bytes (requer múltiplo de 16) |
| BLE-05 | Sprint 2 | MÉDIA | `ble/exploit_chain.py` | 330–339 | Estado inconsistente: `capture_active=True` mas retorna `False` |
| BLE-04 | Sprint 2 | MÉDIA | `ble/exploit_chain.py` | 93–94 | `asyncio.get_event_loop()` deprecated Python 3.10+ |
| BLE-09 | Sprint 2 | ALTA (feat) | `ble/exploit_chain.py` | 424–428 | KBP exploit — passo central do CVE não implementado |
| BLE-03 | Sprint 2 | BAIXA | `ble/__init__.py` + `exploit_chain.py` | 26 / 476 | `BondingStatus` duplicado em imports e `__all__` |
| BLE-06 | Sprint 2 | BAIXA | `ble/exploit_chain.py` | 192, 200 | Imports dentro de método em vez de top-level |
| BLE-08 | Sprint 2 | BAIXA | `modules/urban_hack.py` | 20, 22 | Import duplicado de 3 classes BLE |
| NET-01 | Sprint 3 | **CRÍTICA** | `network/__init__.py` | 755–762 | Blocking socket bloqueia o asyncio event loop |
| NET-03 | Sprint 3 | **CRÍTICA** | `network/__init__.py` | 900–901 | `Severity` Enum comparado com string — sempre `False` |
| NET-02 | Sprint 3 | ALTA | `network/__init__.py` | 695, 699 | Parâmetro `network` ignorado — sempre usa `192.168.1.0/24` |
| NET-04 | Sprint 3 | ALTA | `network/__init__.py` | 618–633 | Hydra parser frágil — IndexError potencial |
| NET-05 | Sprint 3 | ALTA | `network/__init__.py` | 726–735 | mDNS parser errado — avahi usa `;` não espaços |
| NET-06 | Sprint 3 | ALTA (feat) | `network/__init__.py` | 780–789 | ONVIF discovery é `pass` vazio |
| NET-07 | Sprint 3 | ALTA (feat) | `network/__init__.py` | 827–829 | HTTP fingerprinting retorna `[]` sempre |
| NET-08 | Sprint 3 | MÉDIA (feat) | `network/__init__.py` | 566–575 | RouterSploit retorna `[]` sempre |
| NET-09 | Sprint 3 | BAIXA | `network/__init__.py` | 152–165 | `-O` nmap sem verificar root — falha silenciosa |

### Contagem por Severidade

| Severidade | Total | BLE | Network |
|---|---|---|---|
| CRÍTICA | 4 | 2 | 2 |
| ALTA | 7 | 1 (feature) | 4 + 2 (feature) |
| MÉDIA | 3 | 2 | 1 |
| BAIXA | 4 | 3 | 1 |
| **Total** | **18** | **9** | **9** |

---

*Relatório para uso interno do projeto. Todos os exploits e testes devem ser executados exclusivamente em ambientes controlados ou com autorização explícita dos proprietários dos sistemas.*
