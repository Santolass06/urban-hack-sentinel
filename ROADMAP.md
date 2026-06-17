# Urban Hack Sentinel — Roadmap de Melhorias

> Lista estruturada por **Features** (funcionalidades grandes) e **Tasks** (tarefas atómicas).
> Prioridade: 🔴 Crítica · 🟠 Alta · 🟡 Média · 🟢 Baixa · 🔵 Nice-to-have

---

## 🎯 FEATURES (Funcionalidades maiores)

### F1 — Wardriving + Geolocalização 🟠
**Objetivo**: Registar redes com coordenadas GPS, exportar para Kismet/Wigle/CSV.
| Task | Prioridade | Detalhes | Status |
|------|------------|----------|--------|
| F1.1 | 🟠 | Integrar `gpsd` + USB GPS (u-blox, etc.) — ler `$GPRMC`/`$GPGGA` via TCP 2947 | ✅ Completo |
| F1.2 | 🟠 | Adicionar `lat`, `lon`, `alt`, `speed`, `hdop` a cada entrada em `REDES[]` e `metrics.jsonl` | ✅ Completo |
| F1.3 | 🟡 | Exportador `to_kismet_netxml()` — gera `.netxml` compatível Kismet | ✅ Completo |
| F1.4 | 🟡 | Exportador `to_wigle_csv()` — formato WiGLE WiFi Wardriving | ✅ Completo |
| F1.5 | 🟢 | Modo "wardrive" dedicado: scan contínuo sem ataques, só logging + GPS | 🔄 Pendente |
| F1.6 | 🟢 | Integração opcional com **Bettercap** para BLE/Bluetooth LE simultâneo | ⏳ Pendente |

### F2 — Dashboard Web Local (Read-Only) 🟡
**Objetivo**: Visualizar status, métricas, mapa de redes via browser no LAN.
| Task | Prioridade | Detalhes | Status |
|------|------------|----------|--------|
| F2.1 | 🟡 | Servidor HTTP leve (Go `net/http` ou Python `aiohttp`) na porta 8080 | 🔄 Pendente |
| F2.2 | 🟡 | API `/api/status` → JSON com métricas atuais (temp, jobs, targets, uptime) | ✅ Completo |
| F2.2 | 🟡 | API `/api/networks` → lista redes + última vista + sinal + tipo + GPS | ✅ Completo |
| F2.4 | 🟡 | API `/api/metrics` → streaming Server-Sent Events (SSE) para gráficos tempo real | ✅ Completo |
| F2.5 | 🟢 | Frontend simples: Leaflet.js + OpenStreetMap para mapa de redes (se GPS) | 🔄 Pendente |
| F2.6 | 🟢 | Página `/cracked` — lista hashes cracked do `.potfile` | 🔄 Pendente |
| F2.7 | 🔵 | Autenticação básica (htpasswd) ou token Bearer para exposição LAN | 🔄 Pendente |

### F3 — Suporte Multi-Interface Simultâneo 🟠
**Objetivo**: Usar 2+ rádios USB em paralelo (ex: 2.4 GHz + 5 GHz dedicados).
| Task | Prioridade | Detalhes | Status |
|------|------------|----------|--------|
| F3.1 | 🟠 | Config `WIFI_IFACES="wlan1,wlan2"` — array de interfaces | ✅ Completo |
| F3.2 | 🟠 | Round-robin ou divisão de canais por interface (2.4G numa, 5G noutra) | ✅ Completo |
| F3.3 | 🟡 | `hcxdumptool` suporta múltiplas interfaces (`-i wlan1 -i wlan2`) — aproveitar | ✅ Completo |
| F3.4 | 🟡 | Sincronização de estado: `REDES` global, `CURRENT_TARGETS` por interface | ✅ Completo |
| F3.5 | 🟢 | Detecção automática de capacidades por interface (injection, monitor, 5G/6G) | 🔄 Pendente |

### F4 — Ataques Avançados WPA3 / 802.11r 🟡
**Objetivo**: Capturar material crackável em redes WPA3-SAE e Fast Transition.
| Task | Prioridade | Detalhes | Status |
|------|------------|----------|--------|
| F4.1 | 🟡 | Detectar redes WPA3-SAE (flags `sae`/`wpa3` no `iw` JSON) | ✅ Completo |
| F4.2 | 🟡 | PMKID em WPA3: `hcxdumptool` já suporta — validar e documentar | ✅ Completo |
| F4.3 | 🟢 | 802.11r (Fast Transition): capturar PMK-R0/R1 via reassociação forçada | 🔄 Pendente |
| F4.4 | 🟢 | Downgrade attack: forçar WPA2 se AP suporta transição (mixed mode) | 🔄 Pendente |
| F4.5 | 🔵 | SAE-PK (WPA3-Enterprise) — fora de escopo por agora | ⏳ Pendente |

### F5 — Cracking Distribuído / Offloading 🟢
**Objetivo**: Enviar hashes para máquinas potentes (desktop, cloud) para cracking.
| Task | Prioridade | Detalhes | Status |
|------|------------|----------|--------|
| F5.1 | 🟢 | Watcher em `$HASH_DIR` — detecta novos `.22000` | ✅ Completo |
| F5.2 | 🟢 | Upload via `rsync`/`scp`/`syncthing` para host remoto configurado | ✅ Completo |
| F5.3 | 🟢 | Polling de resultados: baixa `.potfile` cracked do remoto | ✅ Completo |
| F5.4 | 🔵 | Integração opcional com **Hashtopolis** (API REST) para fleet management | 🔄 Pendente |
| F5.5 | 🔵 | Auto-geração de relatório: "X redes, Y cracked, top passwords" | 🔄 Pendente |

### F6 — Inteligência de Alvos (Priorização) 🟡
**Objetivo**: Atacar primeiro redes com maior probabilidade de sucesso.
| Task | Prioridade | Detalhes | Status |
|------|------------|----------|--------|
| F6.1 | 🟡 | Scoring: sinal + tipo (WPS > WPA2 > WPA3 > OPEN) + histórico sucessos | ✅ Completo |
| F6.2 | 🟡 | Base de dados local (SQLite) com `bssid`, `essid`, `last_seen`, `cracked`, `attempts` | ✅ Completo |
| F6.3 | 🟢 | Lista "known vulnerable": OUI conhecida, firmware padrão, WPS PIN fraco | ✅ Completo |
| F6.4 | 🟢 | Integração com **Wigle.net API** — enriquece com localização globalKnown | 🔄 Pendente |
| F6.5 | 🔵 | ML leve: regressão logística `p(crack) ~ signal + vendor + encryption + time` | ⏳ Pendente |

### F7 — Bluetooth / BLE / IoT Reconnaissance 🔵
**Objetivo**: Expandir além de Wi-Fi para superfície de ataque IoT.
| Task | Prioridade | Detalhes | Status |
|------|------------|----------|--------|
| F7.1 | 🔵 | `bluetoothctl` / `btmon` scan passivo — log devices, RSSI, serviços | ✅ Completo |
| F7.2 | 🔵 | Bettercap BLE module para enumeração GATT | ✅ Completo |
| F7.3 | 🔵 | Correlação MAC Wi-Fi ↔ BLE (mesmo dispositivo, OUI partilhado) | ✅ Completo |
| F7.4 | 🔵 | Exportador para formato Kismet BLE | ✅ Completo |

### F8 — Hardening & Reliability 🔴
**Objetivo**: Produção robusta, auto-recovery, zero supervisão manual.
| Task | Prioridade | Detalhes | Status |
|------|------------|----------|--------|
| F8.1 | 🔴 | Watchdog: `systemd` `WatchdogSec=` + script heartbeat a cada 30s | ✅ Completo |
| F8.2 | 🔴 | Auto-recovery interface: se `iw` falha 3x → `ip link set down/up` + re-set monitor | ✅ Completo |
| F8.3 | 🔴 | Log rotation: `logrotate` config para `/var/log/urban-hack-sentinel/*.log` | ✅ Completo |
| F8.4 | 🟠 | Healthcheck HTTP endpoint (`/healthz`) para orchestração (k8s, systemd) | ✅ Completo |
| F8.5 | 🟠 | Métricas Prometheus (`/metrics`) — `temp_c`, `jobs_active`, `networks_seen`, `hashes_captured` | ✅ Completo |
| F8.6 | 🟡 | Testes de integração (bats/shunit2) em CI — mock `iw`, `hcxdumptool` | ✅ Completo |
| F8.7 | 🟡 | Assinatura GPG dos artefactos (hashes, pcaps) para cadeia de custódia | ✅ Completo |

### F9 — IA/ML Local (Edge) 🔵
**Objetivo**: Decisão de parâmetros sem API externa (substitui o antigo GPT).
| Task | Prioridade | Detalhes | Status |
|------|------------|----------|--------|
| F9.1 | 🔵 | Modelo leve (ONNX/TFLite) embutido: input=métricas → output=timeout, jobs, signal_thresh | 🔄 Pendente |
| F9.2 | 🔵 | Treino offline: recolhe dataset `(metrics, outcome)` → treina XGBoost/LightGBM pequeno | 🔄 Pendente |
| F9.3 | 🔵 | Inferência via `onnxruntime` ou `python3 -c "import onnxruntime"` no loop | 🔄 Pendente |
| F9.4 | 🔵 | Fallback heurístico se modelo falhar (regras atuais) | 🔄 Pendente |

---

## ⚙️ TASKS (Tarefas atómicas, independentes)

### T1 — Qualidade de Código & DX 🟠
| ID | Task | Prioridade | Esforço | Status |
|----|------|------------|---------|--------|
| T1.1 | Adicionar `shellcheck` no CI (GitHub Actions) | 🟠 | 1h | ✅ Completo |
| T1.2 | `set -euo pipefail` já feito — adicionar `shopt -s inherit_errexit` | 🟢 | 15m | ✅ Completo |
| T1.3 | Função `die()` unificada para erros fatais com cleanup | 🟡 | 30m | ✅ Completo |
| T1.4 | Logging estruturado: `log_info`, `log_warn`, `log_error`, `log_debug` | 🟡 | 1h | ✅ Completo |
| T1.5 | Configuração via `getopt`/`argparse` para flags CLI (`--config`, `--dry-run`, `--once`) | 🟢 | 2h | ✅ Completo |
| T1.6 | Modo `--dry-run`: só scan, não ataca, imprime plano | 🟢 | 1h | ✅ Completo |
| T1.7 | Completar `config.env.example` com todas as vars documentadas | 🟠 | 30m | ✅ Completo |

### T2 — Scanner & Parsing 🟠
| ID | Task | Prioridade | Esforço | Status |
|----|------|------------|---------|--------|
| T2.1 | Migrar 100% para `iw -f json` (remover fallback `iwlist` se `jq` sempre presente) | 🟡 | 1h | ✅ Completo |
| T2.2 | Parse completo de `flags` array: `privacy`, `wpa3`, `sae`, `wps`, `802.11r`, `802.11k`, `802.11v` | 🟠 | 2h | ✅ Completo |
| T2.3 | Detectar canal real (`primary`, `secondary`, `width`: 20/40/80/160 MHz) | 🟡 | 1h | ✅ Completo |
| T2.4 | Vendor OUI lookup local (base `ieee-oui.txt` embutida) → `vendor` field | 🟢 | 2h | ✅ Completo |
| T2.5 | Deduplicação inteligente: mesmo BSSID, múltiplos SSIDs (hidden + broadcast) | 🟢 | 1h | ✅ Completo |

### T3 — Ataques & Captura 🟠
| ID | Task | Prioridade | Esforço | Status |
|----|------|------------|---------|--------|
| T3.1 | `attack_pmkid`: adicionar `--active_beacon` + `--enable_status=15` para mais info | 🟡 | 30m | ✅ Completo |
| T3.2 | `attack_handshake`: usar `airodump-ng --wps` para capturar WPS info simultâneo | 🟢 | 30m | ✅ Completo |
| T3.3 | `attack_wps`: suporte a `pixiewps` offline (se reaver captura M1-M3) | 🟠 | 2h | ✅ Completo |
| T3.4 | `capture_open`: filtro BPF para tráfego interessante (HTTP, DNS, TLS SNI) | 🟢 | 1h | ✅ Completo |
| T3.5 | Timeout adaptativo: mais tempo em canais 5G (propagation), menos em 2.4G | 🟢 | 1h | ✅ Completo |
| T3.6 | Captura de **EAPOL M1/M3** para PMKID mesmo sem handshake completo | 🟠 | 2h | ✅ Completo |

### T4 — Pós-Processamento & Hashes 🟡
| ID | Task | Prioridade | Esforço | Status |
|----|------|------------|---------|--------|
| T4.1 | `hcxpcapngtool` flags: `--pmkid`, `--eapol`, `--username` (identity) | 🟡 | 30m | ✅ Completo |
| T4.2 | Deduplicação de hashes: mesmo PMKID/ESSID → não re-escrever | 🟡 | 1h | ✅ Completo |
| T4.3 | Metadados no `.22000`: embed ESSID, BSSID, timestamp, GPS (hcxtools 6.2+) | 🟢 | 1h | ✅ Completo |
| T4.4 | Script `crack_all.sh`: itera `$HASH_DIR/*.22000` com hashcat profiles | 🟢 | 2h | ✅ Completo |
| T4.5 | Integração `hashcat --show` → CSV relatório: `essid,bssid,password,method` | 🟢 | 1h | ✅ Completo |

### T5 — Sistema & Deploy 🟠
| ID | Task | Prioridade | Esforço | Status |
|----|------|------------|---------|--------|
| T5.1 | `Makefile` alvos: `install`, `uninstall`, `config`, `test`, `package` | 🟠 | 1h | ✅ Completo |
| T5.2 | Pacote `.deb` / `.rpm` / `PKGBUILD` (Arch) para instalação nativa | 🟢 | 4h | 🔄 Pendente |
| T5.3 | Dockerfile para build isolado (cross-compile ARM64) | 🟢 | 2h | ✅ Completo |
| T5.4 | Ansible role para provisioning em fleet de Pis | 🔵 | 4h | 🔄 Pendente |
| T5.5 | `systemd` drop-in para override de `WIFI_IFACE` por host | 🟡 | 30m | ✅ Completo |
| T5.6 | `logrotate.d/urban-hack-sentinel` — compress, maxage 30d, rotate 12 | 🟠 | 15m | ✅ Completo |

### T6 — Documentação & UX 🟡
| ID | Task | Prioridade | Esforço | Status |
|----|------|------------|---------|--------|
| T6.1 | `man urban-hack-sentinel.8` page | 🟢 | 2h | ✅ Completo |
| T6.2 | Diagrama de arquitetura (Mermaid/Excalidraw) no README | 🟢 | 1h | ✅ Completo |
| T6.3 | Guia "Primeiros passos" para não-especialistas | 🟡 | 2h | ✅ Completo |
| T6.4 | Página `CONTRIBUTING.md` + `CODE_OF_CONDUCT.md` | 🟢 | 1h | ✅ Completo |
| T6.5 | Badges no README: license, build status, version, platform | 🟢 | 15m | ✅ Completo |

### T7 — Testes & Validação 🟠
| ID | Task | Prioridade | Esforço | Status |
|----|------|------------|---------|--------|
| T7.1 | Testes unitários BATS para funções puras (`freq_to_channel`, `parse_json`, etc.) | 🟠 | 3h | ✅ Completo |
| T7.2 | Testes de integração com `mac80211_hwsim` (virtual Wi-Fi no CI) | 🟡 | 6h | ✅ Completo |
| T7.3 | Fuzzing config parsing (valores inválidos, injection) | 🟢 | 2h | ✅ Completo |
| T7.4 | Benchmark: ciclos/segundo, CPU%, memoria, hashes/hora por HW | 🟢 | 2h | ✅ Completo |

---

## 📦 DEPENDÊNCIAS NOVAS (para features acima)

| Feature | Pacotes adicionais | Notas |
|---------|-------------------|-------|
| F1 GPS | `gpsd`, `gpsd-clients`, `python3-gps` | USB GPS u-blox 7/8/9 ~€20 |
| F2 Dashboard | `golang-go` (build) ou `python3-aiohttp` | Go = single binary, ~5MB |
| F3 Multi-iface | — | Já suportado pelo kernel/tools |
| F4 WPA3/11r | `pixiewps`, `wpa-supplicant` (para testes) | `pixiewps` em `apt` |
| F5 Dist cracking | `rsync`, `sshpass`, `syncthing` | Opcional |
| F6 Scoring/DB | `sqlite3`, `python3-sqlite3` | Já no base |
| F7 BLE | `bluez`, `bluez-tools`, `bettercap` | Bettercap via Go install |
| F8 Prometheus | `prometheus-node-exporter` (sidecar) | Ou lib Go `promhttp` |
| F9 ML Edge | `onnxruntime` (C API) ou Python + `onnx` | Modelo <1MB |

---

## 🎯 PRIORIZAÇÃO SUGERIDA (Próximas 4 semanas)

| Semana | Foco | Entregáveis |
|--------|------|-------------|
| 1 | **Hardening + Scanner robusto** | F8.1-F8.4, T2.1-T2.3, T5.1, T5.6 |
| 2 | **Wardriving + GPS** | F1.1-F1.4, T2.4 (OUI) |
| 3 | **Dashboard Web + Métricas** | F2.1-F2.4, F8.5 (Prometheus) |
| 4 | **Ataques avançados + Pós-proc** | F4.1-F4.3, T3.1-T3.3, T4.1-T4.3 |

---

## 💡 IDEIAS EXPERIMENTAIS (Backlog)

- **Honeypot Wi-Fi**: `hostapd` + `freeradius` para capturar credenciais de clientes que conectam ao nosso AP rogue
- **Deauth seletivo**: só deauth clientes de APs alvo (não broadcast) — menos ruído
- **802.11k/v RRM**: pedir relatórios de vizinhos a clientes associados (mapa passivo)
- **Bluetooth LE Anwesenheit**: detetar devices BLE (tiles, airtags, wearables) correlacionados com Wi-Fi
- **SDN/Cloud sync**: enviar métricas para Elasticsearch/Grafana Cloud remoto
- **Auto-update**: `git pull` + rebuild se tag nova (com verificação GPG)

---

## 📝 NOTAS DE IMPLEMENTAÇÃO

1. **Mantém Bash** para o core loop — portável, zero deps, roda em BusyBox. Features pesadas (Dashboard, ML) em Go/Python como processos separados comunicando via FIFO/Unix socket/JSONL.
2. **Config-driven**: tudo via `config.env` + flags CLI. Zero hardcoded paths.
3. **Observability first**: cada feature nova adiciona métricas JSONL + Prometheus.
4. **Testável**: `mac80211_hwsim` no CI para testes reais sem hardware.
5. **Legal**: mantém disclaimer proeminente. Features ofensivas (deauth, WPS) gated por config `ENABLE_ACTIVE_ATTACKS=true`.

---

## 🚀 FEATURES AVANÇADAS (Pesquisa 2024-2025 — Cutting Edge)

### F10 — Suporte Wi-Fi 6/6E/7 (802.11ax/be) 🟡
**Objetivo**: Capturar e analisar redes modernas (HE/EHT), incluyendo 6 GHz e MLO.
| Task | Prioridade | Detalhes |
|------|------------|----------|
| F10.1 | 🟡 | Detectar capabilities HE (802.11ax) e EHT (802.11be) no `iw` JSON: `he_capab`, `eht_capab` |
| F10.2 | 🟡 | Suporte a canais 6 GHz (1-233, 20/40/80/160/320 MHz) — `iw phy` info |
| F10.3 | 🟢 | **MLO (Multi-Link Operation)**: detetar multiple links (2.4+5+6 GHz) do mesmo AP — correlacionar BSSIDs |
| F10.4 | 🟢 | Captura PMKID em 6 GHz — `hcxdumptool` suporta canais > 14 (verificar `--channel`) |
| F10.5 | 🟢 | WPA3 mandatory em Wi-Fi 7 — ajustar scoring: WPA3 = baseline, não exceção |
| F10.6 | 🔵 | 320 MHz channel width, 4096-QAM, MLO STR/eMLSR — métricas de capacidade no JSONL |

### F11 — Dragonblood / SAE Side-Channel Analysis 🔵
**Objetivo**: Explorar vulnerabilidades conhecidas no WPA3-SAE (Dragonfly) — timing, cache, downgrade.
| Task | Prioridade | Detalhes |
|------|------------|----------|
| F11.1 | 🔵 | Detectar grupos SAE suportados (MODP 2048/3072/4096, ECP 256/384/521) via `iw` scan flags |
| F11.2 | 🔵 | **Timing attack detection**: medir variação de tempo na resposta SAE commit/confirm (requer acesso local ao AP) |
| F11.3 | 🔵 | **Downgrade to WPA2**: forçar transição se AP suporta mixed mode (WPA2/WPA3) — `aireplay-ng` deauth + reassoc |
| F11.4 | 🔵 | **Group downgrade**: forçar grupo MODP mais fraco (2048 vs 4096) — capturar handshake mais fraco |
| F11.5 | 🔵 | Documentar apenas — exploração ativa requer acesso ao AP (não passivo) — ético/legal |

### F12 — OWE (Opportunistic Wireless Encryption) / 802.11w PMF 🟡
**Objetivo**: Auditar redes abertas criptografadas (OWE) e Protected Management Frames.
| Task | Prioridade | Detalhes |
|------|------------|----------|
| F12.1 | 🟡 | Detectar OWE (AKM=OWE no `iw` JSON) — redes "open" mas com criptografia DH individual |
| F12.2 | 🟡 | Detectar PMF (802.11w): `MFPC` (required), `MFPR` (required), `SA Query` support |
| F12.3 | 🟢 | **OWE transition mode**: AP com OWE + open simultâneo — capturar transição |
| F12.4 | 🟢 | Testar **deauth contra PMF**: SA Query protection — medir se deauth falha (expected) |
| F12.5 | 🔵 | Capturar OWE handshake (DH public keys) — não crackável offline, mas valida implementação |

### F13 — Wi-Fi RTT / 802.11mc (Fine Timing Measurement) 🟢
**Objetivo**: Localização passiva de dispositivos via Round-Trip Time (sub-metro accuracy).
| Task | Prioridade | Detalhes |
|------|------------|----------|
| F13.1 | 🟢 | Detectar suporte 802.11mc (FTM responder) em APs — flags `ftm_responder` no `iw` |
| F13.2 | 🟢 | Usar `iw phy <phy> ftm` para iniciar medição RTT a APs/clients |
| F13.3 | 🟢 | Trilateração: 3+ APs com FTM → posição relativa (não GPS) — indoor positioning |
| F13.4 | 🔵 | Correlacionar RTT + RSSI + GPS (se wardriving) → mapa de cobertura preciso |

### F14 — SDR / Spectrum Analysis Integration 🔵
**Objetivo**: Visão de espectro completa (não só 802.11) — interferência, hidden SSIDs, Bluetooth, Zigbee, LoRa.
| Task | Prioridade | Detalhes |
|------|------------|----------|
| F14.1 | 🔵 | Integrar **Sparrow-wifi** (GUI) ou `soapy_power`/`rtl_power` para waterfall 2.4/5/6 GHz |
| F14.2 | 🔵 | **HackRF One** / **RTL-SDR** (v3/v4) — sweep 1 MHz–6 GHz, detectar jammers, interferentes |
| F14.3 | 🔵 | **Ubertooth One** para Bluetooth Classic/LE spectrum — coexistência Wi-Fi/BT |
| F14.4 | 🔵 | Detetar **hidden SSIDs** via beacon analysis no espectro (mesmo sem beacon decode) |
| F14.5 | 🔵 | Exportar espectro como PNG/CSV para relatórios de site survey |

### F15 — Advanced Roaming / FT / 802.11k/v/r Attacks 🟡
**Objetivo**: Explorar Fast Transition, RRM, BSS Transition para captura de material criptográfico.
| Task | Prioridade | Detalhes |
|------|------------|----------|
| F15.1 | 🟡 | **802.11r FT over-the-air**: capturar FT reassociation (PMK-R0/R1) — `aireplay-ng` forced reassoc |
| F15.2 | 🟡 | **802.11k RRM**: enviar Neighbor Report Request a clients associados → mapa de APs vizinhos |
| F15.3 | 🟢 | **802.11v BSS Transition**: forçar client a roam para nosso AP rogue (KARMA/MANA style) |
| F15.4 | 🟢 | **PMK-R0/R1 extraction**: se capturado FT handshake, derivar PMK para outras redes do mesmo ESS |
| F15.5 | 🔵 | **OKC (Opportunistic Key Caching)**: testar se AP aceita PMKID de rede anterior do mesmo ESS |

### F16 — Client-Side Attacks (KARMA / MANA / Rogue AP) 🟠
**Objetivo**: Atrair clients para AP controlado — capturar credenciais, forçar downgrade.
| Task | Prioridade | Detalhes |
|------|------------|----------|
| F16.1 | 🟠 | **KARMA attack**: `hostapd` + `hostapd-mana` — responde a probe requests com ESSID solicitado |
| F16.2 | 🟠 | **MANA toolkit**: `hostapd-mana` + `mitm6` — captura NetNTLM, credenciais, forced proxy |
| F16.3 | 🟡 | **Evil Twin com captive portal**: portal clone de login (hotel, enterprise) — phishing credenciais |
| F16.4 | 🟡 | **Downgrade via rogue AP**: anuncia WPA2 apenas, força client a conectar sem SAE/PMF |
| F16.5 | 🟢 | **Enterprise/EAP**: `hostapd-wpe` — captura EAP-MSCHAPv2, EAP-TTLS, PEAP hashes para cracking |

### F17 — Distributed Cracking Fleet (Hashtopolis / KrakenHashes) 🟢
**Objetivo**: Escalar cracking além do Pi — fleet management, GPU offloading.
| Task | Prioridade | Detalhes |
|------|------------|----------|
| F17.1 | 🟢 | **Hashtopolis agent** no Pi — regista-se em servidor central, recebe tasks, devolve cracked |
| F17.2 | 🟢 | **KrakenHashes** (novo 2024) — API REST moderna, multi-hashcat, web UI |
| F17.3 | 🟡 | Auto-upload hashes `.22000` → fleet, auto-download `.potfile` cracked |
| F17.4 | 🟢 | **GPU offload**: Pi só captura, desktop/cloud (RTX 4090, A100) faz cracking |
| F17.5 | 🔵 | **Cost-aware cracking**: cálculo €/hash (cloud spot instances) vs. tempo |

### F18 — IoT / OT / Matter / Thread / Zigbee Reconnaissance 🔵
**Objetivo**: Superfície de ataque além de Wi-Fi — Matter/Thread (IPv6 over 802.15.4), Zigbee, BLE.
| Task | Prioridade | Detalhes |
|------|------------|----------|
| F18.1 | 🔵 | **Matter/Thread**: detectar border routers (Thread + Wi-Fi) — `cotopaxi`/`chip-tool` scanning |
| F18.2 | 🔵 | **Zigbee**: SDR (CC2531/CC1352) + `zigbee2mqtt`/`killerbee` — channel 11-26 (2.4 GHz overlap) |
| F18.3 | 🔵 | **Bluetooth LE**: `btmon` + `bettercap` BLE — GATT enumeration, pairing vulnerabilities |
| F18.4 | 🔵 | Correlação MAC OUI: mesmo vendor Wi-Fi + Zigbee + BLE = mesmo dispositivo físico |
| F18.5 | 🔵 | Export unificado: Kismet netxml + BLE + Zigbee → single view |

### F19 — Wi-Fi Sensing / CSI (Channel State Information) 🔵
**Objetivo**: Análise de CSI para detecção de presença, gestos, respiração — "Wi-Fi radar".
| Task | Prioridade | Detalhes |
|------|------------|----------|
| F19.1 | 🔵 | **nexmon_csi** (ESP32/BCM43455) ou **AX-CSI** (Intel AX200/210) — extrai CSI per packet |
| F19.2 | 🔵 | Processamento: amplitude/phase por subcarrier → detecção movimento, contagem pessoas |
| F19.3 | 🔵 | Integração: CSI logs correlacionados com scan Wi-Fi → "quem está na sala" |
| F19.4 | 🔵 | Privacy: documentar risco — CSI pode revelar atividade em redes alheias |

### F20 — Regulatory Compliance / Forensics / Chain of Custody 🟡
**Objetivo**: Relatório pronto para auditoria, GDPR, ISO 27001, cadeia de custódia legal.
| Task | Prioridade | Detalhes |
|------|------------|----------|
| F20.1 | 🟡 | **Relatório automático**: Markdown/PDF com executive summary, findings, risk rating (CVSS) |
| F20.2 | 🟡 | **Chain of custody**: GPG sign cada `.pcapng` + `.22000` + `metrics.jsonl` no momento da captura |
| F20.3 | 🟡 | **Hash evidence log**: SHA256 de cada artefacto + timestamp + GPS + hash do script versão |
| F20.4 | 🟢 | **GDPR compliance**: anonimização MAC (hash truncado), retenção configurável, right to erasure |
| F20.5 | 🟢 | **ISO 27001 annex A mapping**: cada finding mapeado para control A.8/A.12/A.13 |

### F21 — Stealth / Evasion / Anti-Forensics 🔵
**Objetivo**: Operar sem ser detectado por WIPS/WIDS (Cisco, Aruba, Mist, Fortinet).
| Task | Prioridade | Detalhes |
|------|------------|----------|
| F21.1 | 🔵 | **Low-rate scanning**: 1-2 canais/ciclo, intervalos aleatórios (Poisson) — evita threshold de rate |
| F21.2 | 🔵 | **MAC OUI spoofing**: usa OUI de vendor comum (Apple, Samsung, Intel) — não "ALFA" ou "Raspberry" |
| F21.3 | 🔵 | **Passive-only mode**: zero TX packets (only `hcxdumptool` passive, no deauth, no probe) |
| F21.4 | 🔵 | **Channel dwell time randomization**: 100-500ms por canal — evita fingerprinting de scanner |
| F21.5 | 🔵 | **Encrypted storage**: LUKS em `/var/lib/urban-hack-sentinel` — auto-mount no boot, wipe on tamper |

---

## ⚙️ TASKS ADICIONAIS (Cutting Edge)

### T8 — Wi-Fi 6/6E/7 Support 🟡
| ID | Task | Prioridade | Esforço |
|----|------|------------|---------|
| T8.1 | Parse `he_capab`/`eht_capab` do `iw -f json` | 🟡 | 2h |
| T8.2 | Channel list 6 GHz (1-233) + 320 MHz width support | 🟡 | 1h |
| T8.3 | MLO link correlation: mesmo AP, múltiplos BSSIDs, múltiplas bandas | 🟢 | 3h |
| T8.4 | Testar `hcxdumptool` em canais 6 GHz (pode precisar kernel >= 6.2) | 🟡 | 2h |

### T9 — Dragonblood/SAE Analysis 🔵
| ID | Task | Prioridade | Esforço |
|----|------|------------|---------|
| T9.1 | SAE group detection no scan (`sae_groups` flag) | 🔵 | 1h |
| T9.2 | Documentar vectores conhecidos (CVE-2019-9494 a CVE-2019-9503) | 🔵 | 2h |
| T9.3 | Implementar detector de downgrade capability (mixed mode) | 🔵 | 2h |

### T10 — OWE/PMF Detection 🟡
| ID | Task | Prioridade | Esforço |
|----|------|------------|---------|
| T10.1 | Detectar AKM=OWE (valor 18) no RSN IE | 🟡 | 1h |
| T10.2 | Parse PMF capabilities: MFPC, MFPR, SA Query | 🟡 | 1h |
| T10.3 | Testar deauth contra PMF-enabled AP (deve falhar) | 🟢 | 1h |

### T11 — RTT/802.11mc 🟢
| ID | Task | Prioridade | Esforço |
|----|------|------------|---------|
| T11.1 | `iw phy <phy> ftm` integration — iniciar medição | 🟢 | 2h |
| T11.2 | Trilateração simples (3+ APs) → posição relativa | 🟢 | 3h |
| T11.3 | Fusion RTT + RSSI + GPS → heatmaps precisos | 🔵 | 4h |

### T12 — SDR/Spectrum 🔵
| ID | Task | Prioridade | Esforço |
|----|------|------------|---------|
| T12.1 | `rtl_power_fftw` / `soapy_power` sweep 2.4/5/6 GHz → waterfall PNG | 🔵 | 3h |
| T12.2 | `sparrow-wifi` headless mode para JSON output | 🔵 | 2h |
| T12.3 | Detetar jammers: power spike > threshold em canal sem AP | 🔵 | 2h |

### T13 — Advanced Roaming/FT 🟡
| ID | Task | Prioridade | Esforço |
|----|------|------------|---------|
| T13.1 | `aireplay-ng` forced FT reassociation (`-F` flag) | 🟡 | 2h |
| T13.2 | `iw` RRM Neighbor Report Request (`iw dev <iface> rrm ...`) | 🟡 | 2h |
| T13.3 | BSS Transition Management Request injection | 🟢 | 3h |
| T13.4 | PMK-R0/R1 extraction via `hcxpcapngtool --ft` (se suportado) | 🟢 | 2h |

### T14 — Client-Side / Rogue AP 🟠
| ID | Task | Prioridade | Esforço |
|----|------|------------|---------|
| T14.1 | `hostapd-mana` compile/install no Pi (ARM64) | 🟠 | 2h |
| T14.2 | Config KARMA: `enable_karma=1`, `karma_blacklist` para evitar alvos sensíveis | 🟠 | 1h |
| T14.3 | `hostapd-wpe` para Enterprise/EAP hash capture | 🟡 | 2h |
| T14.4 | Captive portal template (generic hotel/enterprise) | 🟢 | 3h |

### T15 — Distributed Cracking Fleet 🟢
| ID | Task | Prioridade | Esforço |
|----|------|------------|---------|
| T15.1 | Hashtopolis agent systemd service + config | 🟢 | 2h |
| T15.2 | KrakenHashes API client (Go/Python) | 🟢 | 2h |
| T15.3 | Watcher `$HASH_DIR` → auto-submit via API | 🟢 | 1h |
| T15.4 | Result poller → update local DB com cracked | 🟢 | 1h |

### T16 — IoT/OT Protocols 🔵
| ID | Task | Prioridade | Esforço |
|----|------|------------|---------|
| T16.1 | Matter/Thread border router detection (mDNS `_matter._tcp`, `_thread._udp`) | 🔵 | 2h |
| T16.2 | Zigbee coordinator detection via SDR (channel 11-26, O-QPSK) | 🔵 | 3h |
| T16.3 | BLE GATT enumeração passiva (`bluetoothctl` + `btmon`) | 🔵 | 2h |

### T17 — CSI/Wi-Fi Sensing 🔵
| ID | Task | Prioridade | Esforço |
|----|------|------------|---------|
| T17.1 | `nexmon_csi` no Pi (precisa firmware modificado) — avaliar viabilidade | 🔵 | 4h |
| T17.2 | Intel AX200/210 CSI tool (`linux-80211n-csitool`) se HW compatível | 🔵 | 3h |
| T17.3 | Processamento básico: variance detection → motion alert | 🔵 | 3h |

### T18 — Compliance/Forensics 🟡
| ID | Task | Prioridade | Esforço |
|----|------|------------|---------|
| T18.1 | `generate_report.sh` — Markdown → PDF (pandoc) com template | 🟡 | 3h |
| T18.2 | GPG sign artefacts: `gpg --detach-sign --armor file` no capture hook | 🟡 | 1h |
| T18.3 | Evidence log JSONL: `sha256`, `timestamp`, `gps`, `script_version`, `git_commit` | 🟡 | 1h |
| T18.4 | MAC anonymization: `sha256(mac)[:8]` config option | 🟢 | 1h |

### T19 — Stealth/Evasion 🔵
| ID | Task | Prioridade | Esforço |
|----|------|------------|---------|
| T19.1 | Scan rate limiter: Poisson process, config `SCAN_RATE_LAMBDA` | 🔵 | 2h |
| T19.2 | OUI spoof pool: lista OUIs comuns, seleciona aleatório no `randomize_mac()` | 🔵 | 1h |
| T19.3 | Passive-only mode flag: `PASSIVE_ONLY=true` — desliga todo TX | 🔵 | 1h |
| T19.4 | LUKS encrypt `/var/lib/urban-hack-sentinel` + systemd `cryptsetup` | 🔵 | 2h |

---

## 📦 DEPENDÊNCIAS ADICIONAIS (Cutting Edge)

| Feature | Pacotes / Hardware | Notas |
|---------|-------------------|-------|
| F10 Wi-Fi 6/7 | Kernel >= 6.2, `iw` >= 5.19, adaptador 6E (AX210, mt7921u) | Pi 5 suporta PCIe → AX210 M.2 |
| F11 Dragonblood | Acesso local ao AP (lab) — **não passivo** | Ético: só em laboratório próprio |
| F12 OWE/PMF | `iw` suporte (já tem), `hostapd` 2.10+ para testes | |
| F13 RTT | `iw` >= 5.19, AP/client com 802.11mc | Raro em APs consumer |
| F14 SDR | **HackRF One** (~€300) ou **RTL-SDR v4** (~€30) + `sparrow-wifi` | Sparrow-wifi = Go GUI |
| F15 FT/RRM | `aireplay-ng` >= 1.7, `iw` com RRM/FT commands | |
| F16 Rogue AP | `hostapd-mana`, `hostapd-wpe` (compile from source) | Requer 2ª interface ou VAP |
| F17 Dist cracking | Hashtopolis server (Docker) + agent; KrakenHashes (novo) | GPU offload essencial |
| F18 IoT/OT | CC2531/CC1352 (Zigbee), `chip-tool` (Matter), `bluez` | SDR para Zigbee/Thread |
| F19 CSI | `nexmon_csi` (firmware mod BCM43455) ou Intel AX200 CSI tool | HW específico necessário |
| F20 Forensics | `gpg`, `pandoc`, `jq`, `sha256sum` | Já base |
| F21 Stealth | `cryptsetup`, `luks`, `haveged` (entropy) | LUKS no boot |

---

## 🎯 PRIORIZAÇÃO ESTENDIDA (Próximos 3 meses)

| Mês | Foco Principal | Entregáveis Chave |
|-----|----------------|-------------------|
| **Mês 1** | **Core Hardening + Wi-Fi 6/6E + Wardriving** | F8, F10.1-F10.4, F1, T8, T2, T5.6 |
| **Mês 2** | **Dashboard + Distributed Cracking + Rogue AP** | F2, F17, F16.1-F16.2, T14, T15 |
| **Mês 3** | **Advanced Attacks + Forensics + Stealth** | F4, F11, F13, F15, F18, F20, F21, T9, T11, T13, T18, T19 |

---

## 🔬 PESQUISA EM ANDAMENTO (Watch List 2025+)

| Tópico | Fonte | Relevância |
|--------|-------|------------|
| **Wi-Fi 8 (802.11bn)** | IEEE 802.11bn TG — UHR (Ultra High Reliability) | Próximo padrão, 2028+ |
| **Wi-Fi HaLow (802.11ah)** | Sub-1 GHz, IoT, longo alcance | Novo vetor de ataque rural/industrial |
| **6G / THz communications** | 100-300 GHz, integração Wi-Fi/Cellular | Longo prazo |
| **AI-driven WIPS** | Mist, Cisco AI/ML para detecção anomalias | Evasion fica mais difícil |
| **Post-quantum Wi-Fi** | WPA3-PQC (Kyber, Dilithium) — IETF/Wi-Fi Alliance | Transição 2025-2030 |
| **Ambient backscatter** | Dispositivos sem bateria usando Wi-Fi existente | Nova superfície passiva |
| **Wi-Fi 7 MLO security** | Multi-link key hierarchy, cross-link attacks | Emergente 2024-2025 |

---

## 📝 NOTAS DE IMPLEMENTAÇÃO (Atualizadas)

1. **Mantém Bash** para o core loop — portável, zero deps, roda em BusyBox. Features pesadas (Dashboard, ML, SDR, Rogue AP) em Go/Python/C como processos separados comunicando via FIFO/Unix socket/JSONL/Redis.
2. **Config-driven**: tudo via `config.env` + flags CLI. Zero hardcoded paths. Feature flags para cada módulo ofensivo (`ENABLE_KARMA`, `ENABLE_FT_ATTACKS`, `ENABLE_SDR`).
3. **Observability first**: cada feature nova adiciona métricas JSONL + Prometheus + structured logs.
4. **Testável**: `mac80211_hwsim` no CI para testes reais sem hardware. Mock SDR com `fakesdr`.
5. **Legal/Ethical**: disclaimer proeminente. **Features ofensivas gated por config + warning + confirm**. Rogue AP/KARMA/FT attacks só em laboratório próprio. Documenta CVE references.
6. **Modularidade**: cada Feature = diretório `modules/<feature>/` com `init.sh`, `capture.sh`, `process.sh`, `cleanup.sh` — load dinâmico no main loop.
7. **Supply chain**: `cosign`/`sigstore` para assinar releases. `SBOM` (Syft) no CI. Dependências vendored onde crítico.

---

*Documento vivo — atualiza conforme implementas. Marca tasks com `[x]` quando done.*