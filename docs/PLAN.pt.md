# Urban Hack Sentinel v3 — Plano de Sprints

> **Branch de trabalho**: `andreas/catarinus`
> **Última actualização**: 2026-06-30
> **Política do repositório**: cada *push* de funcionalidade exige actualização de **toda a documentação** (EN + PT), seguindo as regras de estilo, estrutura e formato definidas nos documentos do projecto.
> **Definição de Feito por sprint**: todas as tasks concluídas, testes passam, docs actualizadas (EN + PT), sem PII, cobertura não desce.

---

## Índice

1. [Fundação Concluída (Sprints 0-3)](#fundação-concluída-sprints-0-3)
2. [Sprint 4 — Estabilização de Documentação & Sinc EN/PT](#sprint-4--estabilização-de-documentação--sinc-enpt) *(em curso)*
3. [Sprint 5 — Pipeline GPS + Modo Wardrive](#sprint-5--pipeline-gps--modo-wardrive)
4. [Sprint 6 — Validação Real dos Módulos (Nuclei, RouterScan, Bettercap, HFP)](#sprint-6--validação-real-dos-módulos-nuclei-routerscan-bettercap-hfp)
5. [Sprint 7 — Ataques Avançados a WiFi](#sprint-7--ataques-avançados-a-wi-fi)
6. [Sprint 8 — Reforço de Segurança & Forense](#sprint-8--reforço-de-segurança--forense)
7. [Sprint 9 — Testes & Cobertura](#sprint-9--testes--cobertura)
8. [Sprint 10 — Web UI com Mapas, PWA, Offline](#sprint-10--web-ui-com-mapas-pwa-offline)
9. [Sprint 11 — Marketplace de Plugins](#sprint-11--marketplace-de-plugins)
10. [Sprint 12 — Cracking Distribuído & Offloading](#sprint-12--cracking-distribuída--offloading)
11. [Sprint 13 — Investigação de Fronteira](#sprint-13--investigação-de-fronteira)
12. [Regras Globais](#regras-globais)

---

## Fundação Concluída (Sprints 0-3)

### Sprint 0 — Fundação + Abstração de Hardware / Porte para x86 *(concluída)*
Tasks:
- Estrutura do repositório (`src/` layout, `pyproject.toml`).
- Camada HAL para WiFi, BLE, rede e plataforma.
- Fallback WiFi x86 via `scapy` quando `iw` JSON não está disponível.
- Configuração (Pydantic v2), armazenamento (SQLite WAL + JSONL), event bus, gestor de processos.
- Health checks, registo de *plugins*, logging estruturado (JSONL).
- Docker multi-arquitectura (`linux/amd64,linux/arm64`) com `TARGETARCH`.
- Esqueleto de CI (lint, verificação de tipos, testes).

Critérios de aceitação:
- [x] `urban-hs --help` funciona em Pi e em x86.
- [x] O registo de plugins carrega e devolve o inventário de módulos.
- [x] Um scan simulado corre em x86 sem modo monitor.
- [x] A imagem Docker compila e executa em ambas as arquitecturas.
- [x] O endpoint de saúde responde.

---

### Sprint 1 — Módulos Core + CLI + TUI Básica + Docker / CI *(concluída)*
Tasks:
- Scanner WiFi (passivo/activo, *channel hopping*, `iw` JSON + fallback `airodump`).
- Módulo BLE (scanner Fast Pair, testador/exploit WhisperPair, *quirks* por dispositivo).
- Scanner de rede (wrapper Nmap, OS fingerprint, enumeração de serviços).
- Descoberta de câmaras (mDNS, UPnP, ONVIF, RTSP, fingerprint HTTP).
- Cliente Metasploit RPC + *runner* de exploits.
- Gestor de credenciais + gerador de relatórios (PDF/JSON/HTML + assinatura GPG).
- Suite MQTT (descoberta de *brokers*, enumeração de tópicos, *brute force* de credenciais).
- Esqueletos HID/USB gadget + ataques ESP32/SSID/Bluetooth-HID.
- CLI Rich (`scan`, `attack`, `exploit`, `report`, `export`, `config`).
- TUI Textual básica (logs, métricas, lista de dispositivos).
- Docker Compose, exemplo de *systemd service*, automatização de *release*.
- CI com `mac80211_hwsim` para testes virtuais de WiFi.

Critérios de aceitação:
- [x] Todas as categorias de ataque documentadas são atingíveis por CLI e TUI.
- [x] Os relatórios são gerados e assinados com GPG.
- [x] O Docker Compose levanta o *stack* com um único comando.
- [x] A CI passa em cada PR.

---

### Sprint 2 — API + Event Bus + Inventário de Ataques *(concluída)*
Tasks:
- App FastAPI com configuração JSON, *rate limiting*, máscara de segredos.
- `/api/v1/attacks` — inventário + execução (`dry-run` / real).
- `/api/v1/jobs/{id}` — estado + cancelamento.
- Feed WebSocket para `attack.started`, `attack.progress`, `attack.completed`, `attack.error`.
- `AttackEventNormalizer` — traduz eventos específicos de cada módulo para o contrato canónico.
- Testes: inventário, execução (`TestClient` síncrono), contrato de eventos, *smoke test* da TUI.

Critérios de aceitação:
- [x] A UI não importa nenhum módulo directamente; fala apenas com `/api/v1/attacks`.
- [x] Um módulo novo adicionado ao registo aparece automaticamente na UI sem alterar *frontend*.
- [x] O contrato de eventos tem cobertura de testes unitários.

---

### Sprint 3 — UI de Selecção de Ataques — Fase 10 *(concluída)*
Tasks:
- TUI: botões de ataque por categoria, modal de confirmação, widget de terminal *live*.
- Web UI: painel HTMX + Alpine ligado a `/api/v1/attacks` + WebSocket.
- Histórico de execuções e rastreamento por `job_id`.
- Normalização de eventos com consumidores TUI + Web UI.
- Smoke tests de TUI e contratos.

Critérios de aceitação:
- [x] O operador consegue seleccionar um ataque e ver o *output* em tempo real tanto na TUI como no browser.
- [x] Ataques destrutivos pedem confirmação antes de correr.
- [x] O modo `dry-run` está disponível para todos os módulos.

---

## Sprint 4 — Estabilização de Documentação & Sinc EN/PT *(concluída)*

**Objectivo**: tornar o projecto acessível a principiantes mantendo utilidade para utilizadores avançados; garantir que cada artefacto público é consistente, sanitizado e bilingue.

Tasks:
1. Reescrever `README.md` (EN) + `README.pt.md` (PT AO90) — corrigir *anchors*, tabelas para *mobile*, links quebrados, secção de testing.
2. `docs/OVERVIEW.md` + `docs/OVERVIEW.pt.md` — origem do projecto, significado do nome, público-alvo, narrativa pedagógica.
3. `docs/API.md` + `docs/API.pt.md` — referência extensa com conceitos base, autenticação, *schemas*, exemplo de módulo novo, contrato de eventos, tratamento de erros, testes.
4. `docs/SMOKE_TUI.md` + `docs/SMOKE_TUI.pt.md` — passos do *smoke test* + guia para desenvolver testes *custom*.
5. `docs/WORKFLOW.md` + `docs/WORKFLOW.pt.md` — fluxos de trabalho normais e paralelos do operador.
6. `docs/CONTRIBUTING.md` + `docs/CONTRIBUTING.pt.md` — template de módulo, regras de *commit*, obrigação de sincronizar docs.
7. `docs/PLAN.md` + `docs/PLAN.pt.md` — consolidar num único plano sprint-based substituindo docs legadas.
8. Saneamento de PII em todos os `.md`, `.yml`, `.toml`, `.sh`, `.service`, `.py`.
9. Garantir PT consistente com AO90 (ex.: “objectivo”, “módulo”, “vários”, “nível”).

Critérios de aceitação:
- [ ] O `README` renderiza correctamente em *mobile* com tabelas Markdown válidas.
- [ ] Todos os *links* da documentação resolvem para *anchors* válidas.
- [ ] A terminologia é consistente entre os documentos EN e PT.
- [ ] Não restam dados pessoais em ficheiros rastreados.

---

## Sprint 5 — Pipeline GPS + Modo Wardrive *(concluída)*

**Objectivo**: completar o pipeline GPS desde o receptor u-blox até aos exports georreferenciados que podem ser carregados no Google Earth, WiGLE e Kismet.

Tasks:
1. Cliente `gpsd` via protocolo JSON directo (sem *bindings* Python; usar o stream TCP 2947).
2. Parse de frases NMEA (`NMEAParser`) para `GPRMC`, `GPGGA`, `GPGSA`.
3. `GeoMapper` — associar capturas a `(bssid, lat, lon, alt, timestamp)`.
4. Exportadores:
   - KML (Google Earth, com `Placemark` por BSSID).
   - CSV WiGLE (ordem exacta de colunas esperada por wigle.net).
   - NetXML Kismet (`<wireless-network>` com tags GPS).
   - JSONL (primário, para pipeline de auditoria).
5. `WardriveMode` — scan passivo contínuo + log GPS + auto-export no fim da sessão.
6. *Wiring* no event bus — `gps.fix`, `gps.lost`, `wardrive.snapshot`, `geo.exported`.
7. Integração na TUI e Web UI — lat/lon nas tabelas de scans, botões de export.
8. Testes (`tests/test_gps_geo.py`) cobrindo NMEA, exporters e ciclo de vida do wardrive.

Critérios de aceitação:
- [x] Um passeio com GPS produz um KML que abre no Google Earth com posições correctas.
- [x] O CSV WiGLE aceita o *export* sem erros de colunas.
- [x] O modo Wardrive corre sem supervisão e produz um artefacto completo de sessão.
- [x] Os testes correm na CI sem GPS real.

---

## Sprint 6 — Validação Real dos Módulos (Nuclei, RouterScan, Bettercap, HFP)
## Sprint 6 — Validação de Módulos Reais (Nuclei, RouterScan, Bettercap, HFP) *(concluída)*

**Objectivo**: transformar os wrappers existentes em integrações funcionais com as ferramentas subjacentes.

Realizado:
- `NucleiRunner` já estava completo e integrado no `NetworkModule`.
- `RouterScanner.brute_force_credentials` (Hydra) estava funcional e foi mantido.
- `RouterScanner.scan_router` estava como *stub* e agora:
  - gera um script temporário para o RouterSploit;
  - trata o output como texto bruto para não bloquear o pipeline;
  - faz `cleanup` do ficheiro temporário.
- Módulo `BettercapBLEClient` criado (`bettercap -iface ... -eval ...` via REST) para complementar `bleak`; eventos `ble.discovered` e `scan.completed` no event bus.
- Módulo `HFPAudioCapture` colocado em `src/urban_hs/modules/ble/hfp.py`, reaproveitando o comportamento já existente no projecto e documentando a necessidade de `bluealsa`.

Nota: HFP e Bettercap continuam dependentes do software e hardware reais (`bettercap`, `bluealsa`, headset pareado); os módulos estão prontos, mas o uso em campo só é possível com esses pré-requisitos instalados.

---

## Sprint 7 — Ataques Avançados a WiFi

**Objectivo**: capacidades modernas de avaliação de segurança WiFi além de WPA2-PMKID, *handshake*, WPS e deauth.

Tasks:
1. Detecção WPA3-SAE e captura de PMKID (`hcxdumptool` com suporte SAE).
2. 802.11r Fast Transition — capturar PMK-R0/R1 via reassociação forçada.
3. Ataque de *downgrade* — forçar AP em modo misto a descer para WPA2.
4. OWE (Opportunistic Wireless Encryption) — detectar e capturar *handshake*.
5. PMF (802.11w) — detectar `MFPC`, `MFPR`, suporte SA Query; documentar limitações do deauth.
6. Wi-Fi 6/6E/7 — *parse* de `he_capab`, `eht_capab`, lista de canais 6 GHz, *flags* de 320 MHz.
7. MLO (Multi-Link Operation) — correlacionar múltiplos BSSIDs do mesmo AP em diferentes bandas.

Critérios de aceitação:
- [ ] O scanner reporta *flags* WPA3, OWE, PMF, HE e EHT.
- [ ] O operador pode escolher ataques 802.11r ou *downgrade* a partir da UI.
- [ ] A documentação explica a fronteira legal/ética de cada ataque novo.

---

## Sprint 8 — Reforço de Segurança & Forense

**Objectivo**: tornar a plataforma segura para expor numa LAN e segura para recolha de evidências.

Tasks:
1. Autenticação na API — *token Bearer* ou htpasswd (configurável).
2. RBAC — papéis `admin`, `operator`, `viewer`.
3. Evasão / furtividade — modo passivo, *pool* de OUI para *spoofing* de MAC, limitador de taxa de scan (Poisson), aleatorização de *dwell time* por canal.
4. Forense — relatório automático de evidências (Markdown/PDF), assinatura GPG por artefacto, log de hashes SHA256, campos de *chain of custody*.
5. Conformidade GDPR — opção de anonimização de MAC, política de retenção, comando de eliminação.
6. Rotação de logs, armazenamento LUKS opcional, *watchdog* systemd.

Critérios de aceitação:
- [ ] API sem *token* válido devolve `401/403`.
- [ ] O papel `viewer` lê mas não dispara ataques.
- [ ] O pacote de evidências pode ser verificado como não alterado (GPG + hashes).
- [ ] Os exports com MAC anonimizado não permitem reconstruir o MAC original.

---

## Sprint 9 — Testes & Cobertura

**Objectivo**: passar de *smoke tests* para uma suíte rigorosa e maintainable.

Tasks:
1. Patamar de cobertura — correr `pytest --cov=urban_hs` e fixar o mínimo em **85%**.
2. Testes de contrato por módulo — cada módulo em `src/urban_hs/modules/...` tem `tests/test_<module>_contract.py`.
3. *Framework* de testes *custom* — *fixtures* reutilizáveis para *mock* `gpsd`, `mac80211_hwsim`, matriz HAL (`x86_scapy` vs `arm_iw`).
4. Testes de integração — correr binários reais em Docker (`airodump-ng`, `hcxdumptool`, `reaver`, `nmap`, `nuclei`) contra alvos vulneráveis previsíveis.
5. Testes de concorrência / carga — ataques em paralelo, event bus sob pressão, TUI + Web UI ligadas em simultâneo.
6. Testes de segurança — *path traversal*, fuzz a inputs, fugas de segredos em logs, verificações de privilégio.
7. Matriz CI — adicionar runner `ubuntu-latest` + `arm64`; falhar se a cobertura descer.

Critérios de aceitação:
- [ ] PR não faz *merge* se a cobertura descer abaixo de 85%.
- [ ] Todo o módulo novo deve incluir `test_<module>_contract.py` e `test_<module>_execute.py`.
- [ ] Um novo colaborador corre `make test` e vê tudo verde localmente.

---

## Sprint 10 — Web UI com Mapas, PWA, Offline

**Objectivo**: tornar a interface web útil em campo com baixa largura de banda e conectividade intermitente.

Tasks:
1. Mapa Leaflet — exibir redes no OpenStreetMap usando o pipeline GPS.
2. *Clustering* + *heatmap* — mostrar scans urbanos densos sem travar o browser.
3. PWA *offline-first* — *service worker*, recursos em *cache*, fila de acções para quando ficar offline.
4. Gráficos em tempo real — intensidade de sinal ao longo do tempo, taxa de sucesso/insucesso de ataques.
5. Tema escuro/claro, layout responsivo, acessibilidade (navegação por teclado, ARIA).

Critérios de aceitação:
- [ ] Uma sessão de wardrive produz uma visualização em mapa sem necessidade de *reload*.
- [ ] A UI funciona quando o operador perde rede e volta a ligar mais tarde.
- [ ] Todos os gráficos actualizam via WebSocket sem *refresh* da página.

---

## Sprint 11 — Marketplace de Plugins

**Objectivo**: baixar a barreira para outros escreverem e partilharem módulos.

Tasks:
1. Manifesto de metadados de plugin (`pyproject.toml` com *entry points* `urban-hs.plugins`).
2. `urban-hs plugin install <nome>` a partir de um registo (directório local ou Git remoto).
3. Verificação de assinatura de plugins.
4. Gerador de esqueleto de módulo (`urban-hs plugin new <nome>`).
5. Activar/desactivar plugins em tempo real sem reinício.
6. Restrições de versão e isolamento de dependências por plugin.

Critérios de aceitação:
- [ ] Um módulo novo pode ser escrito, instalado e aparecer na UI em menos de 5 minutos.
- [ ] Plugins desactivados não carregam nem aparecem no inventário de ataques.
- [ ] Existe um template de docs para plugins em `CONTRIBUTING.md`.

---

## Sprint 12 — Cracking Distribuído & Offloading

**Objectivo**: escalar o *cracking* para além da GPU do Pi.

Tasks:
1. *Hash watcher* — monitorizar `$HASH_DIR` por novos ficheiros `.22000`.
2. *Submit* remoto — `rsync`/`scp`/`syncthing` para um host de *cracking* configurável.
3. *Result poller* — recolher `.potfile` com hashes quebrados e actualizar a BD local.
4. Clientes de API para Hashtopolis / KrakenHashes.
5. Estimador de custo — estimar €/hash para instâncias *spot* na cloud.
6. Auto-relatório — sessões indicam quantos hashes foram quebrados e em que *backend*.

Critérios de aceitação:
- [ ] Um `.22000` criado no Pi pode ser quebrado num *desktop* e a senha aparece no gestor de credenciais local.
- [ ] O operador vê na UI qual o *backend* que quebrou cada *hash*.

---

## Sprint 13 — Investigação de Fronteira

**Objectivo**: manter a plataforma atualizada com técnicas emergentes em WiFi, BLE, IoT e SDR.

Tasks:
1. Wi-Fi 6/6E/7 — capacidades HE/EHT, lista de canais 6 GHz, correlação MLO.
2. SDR / Espectro — integrar waterfall com `rtl_power` / `soapy_power`.
3. IoT / Matter / Thread — detecção de `_matter._tcp`, Zigbee (se SDR presente).
4. Bluetooth Classic — KARMA/MANA, *Evil Twin* (apenas em laboratório), captura de hashes Enterprise/EAP.
5. Sensibilidade Wi-Fi / CSI — detecção básica de movimento com Intel AX CSI tool.
6. *Scoring* ML — modelo leve XGBoost/ONNX para prever `p(crack)`.
7. AP *Rogue* / hostapd-mana — requer segunda *radio* ou VAP; política estritamente de laboratório.

Critérios de aceitação:
- [ ] Cada tópico de investigação tem o seu próprio directório e um aviso claro “lab-only / requer HW” na documentação.
- [ ] Nenhuma funcionalidade de investigação fica activa por defeito; exige *flag* explícita e confirmação do operador.

---

## Regras Globais

1. **Sem PII** em código ou documentação commitados. Sanitizar caminhos, nomes de utilizador, e-mails, *serials* de hardware.
2. **EN + PT**: cada `.md` novo ou actualizado deve ter ambas as versões, salvo dispensa explícita.
3. **Documentação primeiro para funcionalidades arriscadas**: antes de *merge* de um ataque destrutivo, a documentação deve explicar a fronteira legal/ética e o fluxo de confirmação.
4. **Testes antes do código** para módulos novos: `test_<module>_contract.py` e `test_<module>_execute.py` são obrigatórios para *merge*.
5. **Patamar de cobertura**: 85% global; código novo não pode descer a cobertura.
6. **Disciplina de branches**: *feature branches* a partir de `andreas/catarinus`; a descrição do PR deve incluir uma *checklist* de actualização de docs.
