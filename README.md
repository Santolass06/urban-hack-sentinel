# 🛡️ Urban Hack Sentinel v3

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux%20%7C%20ARM64%20%7C%20x86__64-lightgrey.svg)](https://www.kernel.org/)
[![Tests: 203 Passed](https://img.shields.io/badge/tests-203%20passed-brightgreen.svg)]()

> **Plataforma Modular Automatizada de Auditoria Wireless, BLE, IoT e Redes** para Raspberry Pi (ARM64) e Linux (x86_64).

---

## 📚 Índice

- [Sobre o Projeto](#-sobre-o-projeto)
- [Funcionalidades Principais](#-funcionalidades-principais)
- [Instalação Rápida](#-instalação-rápida)
- [Como Executar a TUI (Interface de Terminal)](#-como-executar-a-tui-interface-de-terminal)
- [Modos de Execução da App](#-modos-de-execução-da-app)
- [Mapa Interativo & Web UI](#-mapa-interativo--web-ui)
- [Arquitetura & Estrutura](#-arquitetura--estrutura)
- [Testes Automatizados](#-testes-automatizados)
- [Documentação Oficial](#-documentação-oficial)

---

## 🎯 Sobre o Projeto

O **Urban Hack Sentinel v3** transforma o teu Raspberry Pi ou computador Linux numa estação autónoma de auditoria de segurança wireless e geolocalização (*Wardriving*). Integra varreduras passivas e ativas de Wi-Fi (2.4/5/6 GHz), BLE (FastPair & WhisperPair), testes Nmap/Nuclei, servidor REST/WebSockets em FastAPI, Dashboard Web com mapa Leaflet.js e uma interface retro TUI (`Textual`).

---

## ⚡ Funcionalidades Principais

| Módulo | Descrição |
|--------|-----------|
| **Wi-Fi Scanner** | Varredura em 2.4 / 5 / 6 GHz via `iw` JSON + fallback `airodump-ng` |
| **Ataques WPA/WPA2/WPA3** | Captura Handshake 4-Way, PMKID (Jens Steube), WPA3 Downgrade & Fast Transition (802.11r) |
| **WPS Attacks** | Pixie Dust offline (`reaver` + `pixiewps`) & ataque por dicionário PIN |
| **Wardriving + GPS** | Suporte `gpsd`, exportação WiGLE/Kismet e modo `--wardrive` dedicado |
| **BLE & Fast Pair** | FastPair scanner, teste de vulnerabilidade WhisperPair (CVE-2025-36911) |
| **Network & Exploits** | Wrapper Nmap, scanner Nuclei, integração SearchSploit e ExploitRunner |
| **Dashboard TUI & Web** | TUI em terminal (`urban-hs-tui`), Web UI com Mapa Leaflet.js e streaming SSE |
| **Integridade de Evidências** | Selagem de sessões (`urban-hs seal`), verificação GPG e hashes SHA256/BLAKE2b |

---

## 🚀 Instalação Rápida

```bash
# 1. Clonar o repositório
git clone https://github.com/Santolass06/urban-hack-sentinel.git
cd urban-hack-sentinel

# 2. Criar e ativar ambiente virtual Python
python3 -m venv .venv
source .venv/bin/activate

# 3. Instalar dependências
pip install -e ".[dev]"
```

---

## 📺 Como Executar a TUI (Interface de Terminal)

Para testares a **Textual TUI** nos teus dispositivos e controladores wireless:

```bash
# Iniciar a TUI interativa em ecrã inteiro
./.venv/bin/urban-hs-tui
```

### 🎮 Atalhos da TUI:
* **Separadores (`WiFi`, `BLE`, `Network`, `Logs`)**: Navega entre os painéis com o rato ou com a tecla `Tab`.
* **Varredura Wi-Fi / BLE**: Clica em `Scan` para atualizar a tabela de redes em tempo real.
* **Disparar Ataques**: Seleciona uma rede na tabela e clica nos botões de ataque (`Deauth`, `PMKID`, `Handshake`, `WPS Pixie`). A TUI emite eventos reais para o motor do Sentinel.
* **Sair**: Prime a tecla `q` ou `Ctrl+C`.

---

## 🛠️ Modos de Execução da App

### 1. Linha de Comandos CLI (`urban-hs`)
```bash
# Ver capacidades de hardware detetadas (placas Wi-Fi, monitor mode, Bluetooth)
./.venv/bin/urban-hs info --verbose

# Arrancar o Sentinel em modo autónomo padrão
./.venv/bin/urban-hs run

# 🚗 Modo Wardrive Dedicado (Passivo + GPS logging, sem ataques ativos)
./.venv/bin/urban-hs run --wardrive

# 📄 Gerar Relatório Executivo de Auditoria (HTML / Markdown)
./.venv/bin/urban-hs report --session default --format html

# 🔏 Selar Sessão de Auditoria (Modo Leitura Apenas)
./.venv/bin/urban-hs seal <SESSION_ID>
```

### 2. Servidor Web & API REST (`urban-hs-server`)
```bash
# Iniciar o servidor FastAPI (REST + WebSockets + Dashboard Web)
./.venv/bin/urban-hs-server
```
Acede a `http://localhost:8000/` para veres o Dashboard Web interativo e o Mapa Leaflet.js de Wardriving!

---

## 🧪 Testes Automatizados

```bash
# Executar a suíte de testes unitários e de integração (203+ testes)
./.venv/bin/pytest -v

# Verificar linting e regras de estilo
./.venv/bin/ruff check src/
```

---

## 📖 Documentação Oficial

- [ROADMAP.md](ROADMAP.md) — Sprints, lista de funcionalidades e estado de desenvolvimento
- [MASTER_PLAN.md](MASTER_PLAN.md) — Arquitetura de software e contratos de dados
- [docs/API.md](docs/API.md) — Documentação dos endpoints REST e tópicos WebSocket
- [docs/archive/](docs/archive/) — Arquivo de relatórios históricos

---

<p align="center">
  <i>Desenvolvido para fins académicos e de auditoria de segurança autorizada.</i>
</p>
