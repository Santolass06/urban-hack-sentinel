# Auditoria Técnica Completa — Urban Hack Sentinel
**Auditor:** gemini_3_1_pro | **Data:** 2026-06-30 | **Alvo:** `/home/andresantos/Secretária/Projects/urban-hack-sentinel`

## Sumário Executivo
O **Urban Hack Sentinel v3** apresenta-se como uma plataforma robusta e modular para auditoria wireless/BLE/IoT, construída em Python moderno (3.11+). A estrutura base (Core, HAL, Plugins, UI) está bem concebida e permite uma escalabilidade real. A documentação (arquitetura e roadmaps) é exaustiva e de alta qualidade. Contudo, há uma divergência entre a ambição do *Master Plan* (que relata vários Sprints como "COMPLETOS") e a realidade do código, onde vários módulos vitais (como o backend de Bluetooth `hal/ble/__init__.py`, runners de exploits, e managers de credenciais) ainda se encontram como meros stubs (`NotImplementedError`). O projeto sofre de uma "Dívida de Implementação", onde as interfaces existem, mas a lógica concreta de ataque/scan assenta muitas vezes em wrappers frágeis sobre subprocessos ou ainda está por implementar. A segurança interna também precisa de revisão, especialmente no tratamento de dados injetados em subprocessos.

## Top 10 Problemas Prioritários

| # | Problema | Severidade | Esforço | Intencional? |
|---|---|---|---|---|
| 1 | **Stubs Marcados como Completos**: Sprint 4 dado como "COMPLETO" no `MASTER_PLAN.md`, mas `modules/exploit/runner.py` tem TODOs cruciais e `SearchSploit` não corre. | Crítica | L | Intencional |
| 2 | **HAL Bluetooth incompleto**: `hal/ble/__init__.py` levanta `NotImplementedError` no backend BlueZ, vital para o bypass WhisperPair prometido. | Crítica | M | Intencional |
| 3 | **Riscos de Command Injection**: Uso extensivo de `subprocess`/`ProcessManager` (`core/process_mgr.py`) sem higienização visível de input (ex: endereços IP, SSIDs). | Alta | M | Acidental |
| 4 | **Gestor de Credenciais Inativo**: `modules/credential/manager.py` (linha 424) levanta excepção de não implementação. | Alta | S | Intencional |
| 5 | **Paths Hardcoded**: Em `modules/exploit/runner.py` existem paths hardcoded como `/var/lib/urban-hs/artifacts/exploits`, quebrando portabilidade e o princípio "Config-driven". | Média | S | Acidental |
| 6 | **Dificuldade de Reprodução (Dependencies)**: Instalação base falha em distribuições sem `python3-venv` preparado, e requer pacotes de sistema não validados programaticamente. | Média | S | Acidental |
| 7 | **Falta de Testes E2E Reais**: A maior parte dos testes depende de mocks estritos, escondendo falhas de integração com ferramentas de SO reais (`iw`, `nmap`). | Média | L | Acidental |
| 8 | **Acoplamento Core-Chroot**: O `ExploitRunner` assume caminhos e existências de chroot Alpine que não estão garantidos no host. | Média | M | Acidental |
| 9 | **Logs Sensíveis**: Logs gerados por `structlog` podem vazar senhas em texto limpo do payload do WPS/Nuclei se não houver um filtro configurado. | Baixa | S | Acidental |
| 10| **Falsos Positivos no Linter**: O código contém múltiplas supressões cegas (ex: no `pyproject.toml` onde `S101` para asserts é suprimido incorretamente). | Baixa | S | Intencional |

---

## FASE 0 — Reconhecimento

- **Idade do projeto:** Primeiro commit em 22 de Abril de 2025 (relativamente recente).
- **Dimensão e Atividade:** ~24,500 linhas de código (Python, Shell); 46 commits no total; 2 autores identificados.
- **Hotspots (Ficheiros com mais churn):**
  - `README.md` (11 commits)
  - `MASTER_PLAN.md` (8 commits)
  - `docs/index.md` (7 commits)
  - `src/urban_hs/ui/api/main.py` (6 commits)
  - `src/urban_hs/modules/ble/exploit_chain.py` (6 commits)
- **Estatísticas de Débito:** Encontradas 43 ocorrências de `TODO/FIXME/NotImplemented` no código (`grep_search`), focadas sobretudo no `modules/exploit/runner.py` e em backends de hardware (HAL).
- **Intenção do Projeto:** Uma ferramenta de hacking físico ("wardriving", auditoria wireless e IoT) baseada em Raspberry Pi/Linux. Tenta aglomerar dezenas de ferramentas díspares (nmap, aircrack-ng, reaver, metasploit) numa única UI web/tui com gestão unificada.

---

## FASE 1 — Inventário Intenção → Realidade

| Funcionalidade | Fonte (markdown) | Estado | Evidência (ficheiro:linha) | Int/Aci | Notas |
|---|---|---|---|---|---|
| **WPS Pixie Dust** | `MASTER_PLAN.md` S1 | PARCIAL | Depende de ferramentas externas; chamadas CLI no código. | Int. | Integração existe, mas frágil. |
| **BLE Fast Pair Scanner**| `MASTER_PLAN.md` S2 | PARCIAL | `hal/ble/__init__.py:108` (`NotImplementedError` BlueZ) | Int. | Backend bleak funciona, BlueZ falha. |
| **Exploit Runner** | `MASTER_PLAN.md` S4 | STUB | `modules/exploit/runner.py:501` (`TODO: Implement`) | Int. | Marcado como completo no markdown, é stub no código. |
| **Credential Manager**| `MASTER_PLAN.md` S4 | STUB | `modules/credential/manager.py:424` | Int. | Apenas esqueleto de classes. |
| **GeoMac / GPS** | `ROADMAP.md` F1 | IMPLEMENTADO | `geomapper.py` (presumido pela org) | Int. | |

---

## FASE 2 — Auditoria por Categoria

### 1. ARQUITETURA
- **Estado Atual:** Excelente separação em `core/`, `modules/`, `hal/` e `ui/`. Uso de `asyncio` para I/O e Event Bus é apropriado.
- **Nota:** B
- **Problemas:**
  - *Hardcoded Paths* (`modules/exploit/runner.py:160` usa `/var/lib/...`) [Média, S, Acidental].
- **Recomendações:** 1. Injetar caminhos pelo `Config` (Pydantic); 2. Manter estritamente a barreira HAL.

### 2. FUNCIONALIDADE
- **Estado Atual:** Casca funcional. UI/CLI arranca e lista plugins. Execuções falham se dependências externas não estiverem perfeitamente afinadas. Muitos módulos levantam `NotImplementedError`.
- **Nota:** C
- **Problemas:**
  - *Exploit Runner Incompleto* [Crítica, M, Intencional].
- **Recomendações:** 1. Terminar `SearchSploit` e gerador de reports.

### 3. PERFORMANCE
- **Estado Atual:** Uso de subprocessos assíncronos é bom. Contudo, disparar dezenas de processos `nmap`/`nuclei` pode estrangular a memória num Raspberry Pi.
- **Nota:** B
- **Problemas:**
  - *Falta de backpressure* no spawn de subprocessos pesados [Alta, M, Acidental].
- **Recomendações:** 1. Limitar concorrência rigorosamente baseada nos 8GB RAM do Pi 5.

### 4. SEGURANÇA
- **Estado Atual:** Sendo uma ferramenta de segurança, sofre ironicamente do risco de command injection ao construir argumentos CLI para wrappers (`nmap`, `reaver`) baseados em inputs potencialmente vindos do ambiente de rede (SSIDs maliciosos).
- **Nota:** D
- **Problemas:**
  - *Command Injection* [Alta, L, Acidental].
- **Recomendações:** 1. Usar SEMPRE arrays `["nmap", "-p", port]` em `subprocess` ao invés de `shell=True` ou interpolação de strings.

### 5. MODULARIDADE
- **Estado Atual:** Muito coeso. O sistema de plugins (decoradores em `core/plugins.py`) permite desligar funcionalidades facilmente.
- **Nota:** A
- **Problemas:** Nenhum grave reportado.

### 6. API
- **Estado Atual:** FastAPI implementado com routers limpos. Websockets previstos.
- **Nota:** B
- **Problemas:** Sem autenticação por defeito na API, perigoso numa LAN hostil.
- **Recomendações:** 1. Fechar `/api/*` com auth, como reconhecido no ROADMAP.

### 7. DOCUMENTAÇÃO
- **Estado Atual:** Os markdowns são exaustivos e detalhados. Contudo, o `MASTER_PLAN.md` está ativamente a mentir sobre o estado de certos Sprints (Sprint 4 "COMPLETO").
- **Nota:** C (pela disparidade com o código)
- **Problemas:** Documentação desincronizada da realidade do código [Média, S, Acidental/Intencional].

### 8. PROCESSO DE DESENVOLVIMENTO
- **Estado Atual:** Uso de Poetry (`pyproject.toml`), `ruff`, `mypy`, `pytest`. Pipeline de CI moderno.
- **Nota:** A

### 9. COERÊNCIA/COESÃO
- **Estado Atual:** Código Python coerente (3.11+ type hints, dataclasses).
- **Nota:** A

### 10. QUALIDADE E LEGIBILIDADE
- **Estado Atual:** Código limpo, mas pontuado com "stub-code".
- **Nota:** B
- **Problemas:** Código morto/stubs.

### 11. COBERTURA DE TESTES
- **Estado Atual:** Existem testes unitários, mas a cobertura real de lógica de negócio profunda (com hardware) é mascarada por mocks.
- **Nota:** C
- **Problemas:** Dificuldade de bootstrap de ambiente de teste limpo [Média, M, Acidental].

---

## FASE 3 — Operacional e Transversal

- **Reprodutibilidade:** Falha num setup Debian clean sem instalação prévia de `python3.X-venv` e libs C. Requer `libdbus-1-dev`, `libpcap-dev`, etc. Não é "plug & play".
- **Dependências:** `pyproject.toml` especifica dependências flexíveis (`>=`), o que é bom para compatibilidade mas mau para reproducibilidade (lock file ausente ou não gerado no meu check).
- **Segredos:** `config.env.example` está presente. Não foram detetados segredos hardcoded.
- **Deployment:** Dockerfiles multi-arch referenciados, script `release.sh` maduro.

---

## FASE 4 — Síntese para Decisão

### Quick-wins vs Grandes Obras
- **Quick-Wins (Baixo Esforço, Alto Impacto):**
  - Remover *hardcoded paths* e puxar para o ficheiro de configuração (ex: paths do artifacts_dir).
  - Sanitizar a passagem de argumentos para subprocessos (eliminar concatenação de strings para bash).
  - Corrigir a sinalização no `MASTER_PLAN.md` para refletir o estado real de (Parcial/Stub) para os Sprints 2 e 4.
- **Grandes Obras:**
  - Implementar o backend `BlueZ` no HAL (`NotImplementedError`).
  - Completar o motor de execução do `SearchSploit` e parser do report no `Exploit Runner`.

### Roteiro Sugerido
- **Imediato (Esta semana):** Atualizar documentação para refletir a realidade. Corrigir as injeções potenciais em invocações de shell e remover paths chumbados no código.
- **Curto prazo (Este mês):** Resolver os stubs críticos: `modules/credential/manager.py` e finalização do `modules/exploit/runner.py`. Melhorar o script de setup para ser tolerante a sistemas limpos.
- **Estrutural (Trimestre):** Desacoplar testes da dependência de mocks 100% artificiais, adicionando uma suíte que corra num chroot/container controlado com ferramentas de SO (`iw`, `nmap`) disponíveis para testes E2E reais. Implementar backend de BlueZ em definitivo.

*Perguntas em aberto:* Por que motivo foi o Sprint 4 marcado como "COMPLETO" se as classes de Exploitation e Credentials apenas contém assinaturas e levantam exceções? Isto bloqueia o deploy?
