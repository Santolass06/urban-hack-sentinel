# Inventário de Estado — urban-hack-sentinel

**Agente**: Antigravity (Gemini)
**Timestamp**: 2026-07-01
**HEAD Commit**: (Atual)

---

## 1. Feature Inventory & Real-Status

Baseado numa análise direta do código em `src/urban_hs/modules/`:

| Feature | Estado | Ficheiro/Evidência |
| :--- | :--- | :--- |
| **Camera Enumeration** | **Parcial/Misto** | `modules/camera/enumeration.py` (Autenticação HTTP e parser de configurações estão implementados usando `aiohttp`, mas a integração ONVIF é um stub que retorna sempre `None`). |
| **Exploit Runner** | **Real** | `modules/exploit/runner.py` (Implementa runners reais para Nuclei, Metasploit RPC/Console, SearchSploit via subprocess e chroot local). |
| **Credential Manager** | **Real** | `modules/credential/manager.py` (Integrações reais com hashcat, exportações e validações suportadas através de subprocessos de `sshpass`, `curl`, `smbclient` e `hydra`). |
| **SSID Confusion (CVE-2023-52424)** | **Real** | `modules/ssid_confusion.py` (Contém lógica complexa para agrupar e detetar anomalias 802.11r/k/v, bem como geração dinâmica de configurações `hostapd` para ataques Evil Twin). |
| **Bluetooth HID Injection** | **Real** | `modules/bt_hid.py` (Exploração efetiva da CVE-2023-45866 usando `dbus_fast` para manipular o ProfileManager1 e enganar a autenticação de dispositivos alvo como teclados). |
| **ESP32 Fingerprinting & HCI Exploit** | **Real** | `modules/esp32.py` (Implementa scanning mDNS/WiFi/BLE e comandos passivos. Também envia ativamente raw HCI commands (0xFC00, etc.) com o `hcitool` via `asyncio.create_subprocess_exec` referentes à vulnerabilidade CVE-2025-27840). |
| **Urban Hack Plugin Manager** | **Real** | `modules/urban_hack.py` (Gere eventos reais e efetua o agendamento no `EventBus` para todos os scanners e attacks). |

---

## 2. Guard rails de segurança

- A política do `SessionScope` encontra-se implementada nas handlers da infraestrutura principal do plugin (`modules/urban_hack.py`), especificamente nas funções de callback `_handle_wifi_attack` e `_handle_ble_exploit`.
- É lançada e comunicada no bus de eventos a recusa de qualquer ataque via `Event(type="wifi.attack_denied")` em caso da exceção `PermissionError` gerada por `get_active_scope().validate(target)`.

---

## 3. Dívida técnica conhecida e Stubs Detetados

- **Integrações de Dependências:** O scanner de câmaras (`camera/enumeration.py`) tem a dependência `onvif` parcialmente não-suportada/stubbed: o método `_get_onvif_config` e o `get_onvif_info` retornam `None` em hardcode.
- **BLE WhisperPair Exploit:** Dentro de `modules/urban_hack.py`, o handler `_handle_ble_exploit` contém um TODO afirmando que a chain de exploit completa para este ataque exige "BlueZ D-Bus integration" e o resultado enviado na mensagem é `"status": "not_implemented"`.
