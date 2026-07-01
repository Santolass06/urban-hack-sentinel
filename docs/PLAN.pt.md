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
6. [Sprint 8A — Reforço de Segurança *(em curso)*](#sprint-8a--reforço-de-segurança-em-curso)
7. [Sprint 8B — Forense & Integridade de Evidências *(concluída)*](#sprint-8b--forense--integridade-de-evidências-concluída)
8. [Sprint 9 — Testes & Cobertura](#sprint-9--testes--cobertura)
9. [Sprint 10 — Web UI com Mapas, PWA, Offline](#sprint-10--web-ui-com-mapas-pwa-offline)
10. [Sprint 11 — Marketplace de Plugins](#sprint-11--marketplace-de-plugins)
11. [Sprint 12 — Cracking Distribuído & Offloading](#sprint-12--cracking-distribuída--offloading)
12. [Sprint 13 — Investigação de Fronteira](#sprint-13--investigação-de-fronteira)
13. [Regras Globais](#regras-globais)

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

## Sprint 6 — Validação de Módulos Reais (Nuclei, RouterScan, Bettercap, HFP) *(concluída)*

**Objectivo**: transformar os *wrappers* existentes em integrações funcionais com as ferramentas subjacentes.

Realizado:
- `NucleiRunner` já estava completo e integrado no `NetworkModule`.
- `RouterScanner.brute_force_credentials` (Hydra) estava funcional e foi mantido.
- `RouterScanner.scan_router` estava como *stub* e agora gera um script temporário para o RouterSploit, executa-o e faz `cleanup` do ficheiro temporário.
- Módulo `BettercapBLEClient` criado para enumerar BLE/GATT via REST do bettercap, com eventos `ble.discovered` e `scan.completed` no *event bus*.
- Módulo `HFPAudioCapture` colocado em `src/urban_hs/modules/ble/hfp.py`, documentando a dependência de `bluealsa`/BlueZ.

Nota: HFP e Bettercap dependem dos stacks reais de software/hardware; os módulos estão prontos, mas o uso em campo requer `bettercap`, `bluealsa` e um *headset* pareado.

---

## Sprint 7 — Ataques Avançados a WiFi *(concluída)*

**Objectivo**: capacidades modernas de avaliação de segurança WiFi além de WPA2-PMKID, *handshake*, WPS e deauth.

Realizado:
- O *scanner* passou a reportar detecção de WPA3-SAE, *flags* OWE, indicadores de 802.11r Fast Transition, presença HE/EHT, inferência de banda 6 GHz, *flags* de 320 MHz e BSSIDs relacionados com MLO.
- Captura de PMKID para WPA3-SAE habilitada via fluxos SAE do `hcxdumptool`, mantendo o comportamento WPA2 existente.
- Suporte a 802.11r Fast Transition documentado e ligado à camada de ataques WiFi, permitindo ao operador forçar reassociação e capturar materiais PMK-R0/R1.
- Fluxo de *downgrade* adicionado para hosts em modo misto, com confirmação explícita e protecções de `dry-run`.
- Detecção OWE e captura de *handshake* encapsulada nas extensões do módulo WiFi.
- PMF (802.11w): detecção de `MFPC` / `MFPR` e suporte SA Query; limitações do deauth documentadas nos *docstrings* dos módulos.
- *Parsing* de Wi-Fi 6/6E/7 estendido para `he_capab`, `eht_capab`, lista de canais 6 GHz e *flags* relacionadas com 320 MHz.
- Correlação MLO: lógica de correlação multi-BSSID adicionada ao *scanner* e ao *event bus*.
- *UI* actualizada para o operador poder escolher acções relacionadas com 802.11r, *downgrade*, OWE e PMF através dos endpoints existentes.
- Documentação passa a explicar a fronteira legal/ética de cada ataque novo antes da execução.

Critérios de aceitação:
- [x] O *scanner* reporta *flags* WPA3, OWE, PMF, HE e EHT.
- [x] O operador pode escolher ataques 802.11r ou *downgrade* a partir da UI.
- [x] A documentação explica a fronteira legal/ética de cada ataque novo.

---

## Sprint 8A — Reforço de Segurança *(em curso)*

**Objectivo**: reduzir a superfície de ataque e garantir execução segura dos módulos, sem depender de decisões de auth/PKI externas.

**Dependências**: nenhuma decisão de auth pendente.

### Tasks
1. API hardening — rate limiting por IP, headers de segurança (`HSTS`, `CSP`, `nosniff`), IP allowlist para endpoints sensíveis, remoção de headers de fingerprinting.
2. Evasão / furtividade — modo passivo, *pool* de OUI para *spoofing* de MAC, limitador de taxa de scan (Poisson), aleatorização de *dwell time* por canal.
3. Confinamento em execução — aplicar perfis seccomp e *capability dropping* por módulo; *fallback* gracioso se `libseccomp`/`libcap` não estiver disponível.
4. Integridade de binários — manifest SHA256 dos binários externos (`iw`, `airodump-ng`, `hcxdumptool`, `nmap`, `reaver`); *startup check* com *allowlist* por módulo.
5. Higiene de logs — rotação real (tamanho + idade), sem PII por omissão, separação entre *audit log* e *operational log*.
6. Tooling / docs — modos `lab`, `field`, `airgap` (*feature flags* por ambiente), guia de hardening EN + PT.

### Critérios de aceitação
- [ ] API rejeita tráfego não autorizado para endpoints `/execute` e `/scan`;
- [ ] O modo passivo respeita *dwell times* aleatórios sem sondas activas;
- [ ] Os módulos falham de forma explícita se o binário esperado não existir ou o *hash* não coincidir;
- [ ] Logs não incluem MACs brutos por omissão e sem necessidade de reconfiguração.

---

## Sprint 8B — Forense & Integridade de Evidências *(concluída)*

**Objectivo**: garantir que todos os artefactos são verificáveis, com cadeia de custódia imutável e comandos claros para verificar/selar/eliminar dados.

**Dependências**: Sprint 8A em curso (não bloqueia).

### Tasks
1. ~~Anonimização de MAC~~ — *redactor* central para `devices`, `wifi_networks`, `ble_devices`, endpoints e exports WiGLE/Kismet/JSONL.
2. ~~Política de retenção~~ — aplicar TTL por sessão/artefacto; comando de *right-to-erasure* (*hard-delete* seguro + verificação).
3. ~~Pacote de evidências~~ — *wrapper* que usa `EvidenceLogger` + `GPGSigner`; hash SHA256/BLAKE2b em todos os artefactos.
4. ~~Verificação / *seal*~~ — `urban-hs verify --session <id>`, `urban-hs seal --session <id>`, `urban-hs audit-trail --session <id>`.
5. ~~*Audit trail*~~ — registar quem, quando, quê, hash do comando + *params*, resultado; sem PII.
6. Documentação e *migration guide* — EN + PT, incluindo fluxo de verificação para laboratório e para admissibilidade forense.

### Critérios de aceitação
- [x] Exports com MAC anonimizado não permitem reconstrução do MAC original;
- [x] `verify --session` confirma GPG, integridade e consistência da cadeia;
- [ ] `seal --session` move artefactos para storage só-leitura/append-only;
- [x] `audit-trail` produz *timeline* legível para relatório final.

### Notas
- `seal` está esqueleado: o comportamento pretendido é relocar artefactos para `/var/lib/urban-hs/sealed/<session_id>/` e definir flags imutáveis; pode ser concluído quando houver storage backend adequado.

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
