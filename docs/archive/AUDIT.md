# Urban Hack Sentinel v3 — Full Audit Report

**Date:** 2026-07-20  
**Scope:** Holistic audit — architecture, domain/data, product, UX/UI/i18n, security, tests, build/distribution  
**Method:** Static evidence from the repository (code, configs, docs, local coverage/ruff stats). No clean Pi/Alfa hardware smoke; no live RF attacks.  
**Out of scope:** Performance & DX deep-dive; implementing fixes; formal legal review of offensive tooling use; writing exploit PoCs.

**Severity**

| Level | Meaning |
|-------|---------|
| **P0** | Blocks real use or risks data loss / remote abuse of the control plane |
| **P1** | Critical feature degraded or high regression / exposure risk |
| **P2** | Material debt/gap, non-blocking |
| **P3** | Polish / nice-to-have |

**ID prefixes:** `ARC` architecture · `DOM` domain · `FUN` product · `UX` UX/i18n · `SEC` security · `QA` tests · `BLD` build

---

## Checklist (re-audit)

- [ ] P0/P1 from matrix addressed or explicitly deferred in ROADMAP/MASTER_PLAN
- [ ] Real identity auth (or documented localhost-only + bind locked)
- [ ] Credentials/handshakes at-rest policy documented and/or encrypted
- [ ] Path namespace unified (`urban-hs` vs `urban-hack-sentinel`)
- [ ] CI green: ruff policy realistic OR debt triaged; BLE/e2e strategy clear
- [ ] README claims (React PWA, coverage %, Docker entrypoints) match code
- [ ] Hardware validation on Pi 5 + monitor-mode adapter recorded
- [ ] SessionScope still enforced on all active attack paths after new modules

---

## Executive summary

### Overall state

**Urban Hack Sentinel v3** is a large Python 3.11+ wireless/Bluetooth/IoT auditing framework (~28k LOC under `src/urban_hs`) with a real modular core: async event bus, process manager, SQLite storage (WAL + `schema_version`), plugin loader, HAL stubs for Wi‑Fi/BLE, FastAPI + WebSocket API, Textual TUI, Typer CLI, Docker multi-arch sketches, systemd unit, and a substantial attack surface (WPA/WPS/deauth, BLE/Fast Pair, MQTT, HID, cameras, Metasploit RPC, reporting).

The project is **past “scaffold”**: many modules have non-trivial implementations, there are ~200 collected tests and recent hardening work (SessionScope guard, WS auth tests, env modes lab/field/airgap). It is **not yet “hand to operators as a polished release”**: the API control plane has **identity-less JWT minting**, several **path/name mismatches** across install docs/service/config, **CI lint gate is effectively broken** (~4.6k ruff findings), product docs over-promise a **React PWA**, and **credentials/passwords sit in SQLite as plaintext**. Hardware-dependent truth (monitor mode, BLE exploits, Pi packaging) remains the main external unknown.

### Top risks (ordered)

1. **[SEC-001]** `POST /api/v1/auth/token` mints a valid Bearer JWT with **no credentials** — anyone who can reach the API gets a session. Documented as localhost-only, but bind/misconfig is one step from full remote control of scans/attacks.
2. **[SEC-002 / DOM-001]** Captured **passwords and credentials stored plaintext** in SQLite (`wifi_handshakes.password`, `credentials.password`) with no at-rest encryption path evident.
3. **[BLD-001 / DOM-002]** **Fragmented filesystem namespace**: `/var/lib/urban-hs` (config default) vs `/var/lib/urban-hack-sentinel` (systemd) vs `/etc/urban-hs` (README) vs `/etc/urban-hack-sentinel` (shell script) — install/upgrade data loss risk.
4. **[QA-001]** **Ruff reports ~4652 issues** on `src/urban_hs` while CI runs `ruff check` — gate is red or ignored; signal-to-noise destroys lint value.
5. **[FUN-001]** README architecture still sells **“React PWA”**; reality is a **single static `index.html`** dashboard (~444 LOC). Coverage README says **19% / 99 tests**; local `.coverage` report shows **~57%** and pytest collects **~200** tests — docs drift.
6. **[FUN-002]** ROADMAP still lists auth/HTTP/map pages as pending while code already has FastAPI+JWT+static web — roadmap not reconciling “done vs next”.
7. **[ARC-001]** Several **god-modules** (`storage.py` ~963, `network/__init__.py` ~1150, reporting/credential/managers 700–900 LOC) + wide plugin surface — maintenance and review cost.
8. **[SEC-003]** Docker compose / multi-arch docs push **`privileged` / host network** for RF tools — expected for the domain, but compounds SEC-001 if API is exposed inside that network namespace.
9. **[QA-002]** CI **ignores** `test_ble_module.py` and `test_e2e.py`; wifi plugin contract tests fail without writable `/var/lib/urban-hs` — hardware/integration truth not gated.
10. **[BLD-002]** Packaging inconsistency: `poetry-core` build-backend + PEP 621 `[project]` + leftover `[tool.setuptools]` without clear `[tool.poetry]` package layout — fragile publish/install.

### Quick wins (≤1 day each)

| Win | Finding | Effort |
|-----|---------|--------|
| Require shared secret / basic auth / mTLS before minting JWT; rate-limit `/auth/token` | SEC-001 | Hours–1 day |
| Default-deny: refuse start if `api.host` is `0.0.0.0` unless `ALLOW_INSECURE_BIND=1` | SEC-001 | Hours |
| Document plaintext credential storage; chmod 0600 DB; optional SQLCipher/age later | SEC-002 | Hours (doc) |
| Single canonical paths in config + systemd + README + example env | BLD-001 | Hours |
| Narrow ruff `select` to a green baseline; fix or ignore per-file intentionally | QA-001 | ≤1 day |
| Rewrite README Architecture/Status: static web UI, real test/coverage numbers | FUN-001 | Hours |
| Align ROADMAP checkboxes with shipped FastAPI/WS/auth/static UI | FUN-002 | Hours |
| Make data_root default XDG or `./data` for non-root dev; keep `/var/lib/...` for systemd | BLD-001 / QA-002 | Hours |

### What is in good shape

- Clear package layout: `core` / `modules` / `hal` / `cli` / `ui/{api,tui,web}`.
- Async process manager uses `create_subprocess_exec` (not `shell=True` in the hot path reviewed).
- SQLite migrations via `schema_version`; WAL + busy_timeout; optional Redis degraded gracefully.
- SessionScope hardening recently documented and tested (`docs/CORRECAO_SESSIONSCOPE_2026-07-01.md`, guard tests).
- Attack router env modes (`lab` / `field` / `airgap`) with airgap blocking active exploits.
- WebSocket `/events` requires JWT (header or query); dedicated tests exist.
- Rate limit + security headers + optional IP allowlist middleware.
- Dual-language docs set (EN/PT) for major manuals; MkDocs wiring present.
- Docker non-root `USER urbanhs` in Dockerfiles (host RF still needs caps/privileged — documented).

---

## Inventory baseline

### Workspace

| Area | Path | Notes |
|------|------|-------|
| Package | `src/urban_hs/` | ~28 164 LOC Python |
| Core | `src/urban_hs/core/` | bus, config, storage, process, plugins, scheduler, security, session_scope, health… |
| Modules | `src/urban_hs/modules/` | wifi, ble, network, camera, hid, metasploit, mqtt, reporting, credential, exploit, esp32, bt_hid, urban_hack… |
| HAL | `src/urban_hs/hal/` | platform + wifi/ble facades |
| API | `src/urban_hs/ui/api/` | FastAPI main + routers + auth/middleware |
| TUI | `src/urban_hs/ui/tui/app.py` | Textual ~387 LOC |
| Web | `src/urban_hs/ui/web/index.html` | Static SPA-ish page, not React |
| CLI | `src/urban_hs/cli/main.py` | Typer entry `urban-hs` |
| Tests | `tests/` | ~20 files, ~3.7k LOC, ~200 tests collected |
| Docs | `README.md`, `MASTER_PLAN.md`, `ROADMAP.md`, `docs/*` | Heavy bilingual set |
| Ops | `docker/`, `urban-hack-sentinel.service`, `urban_hack_sentinel.sh` | |
| Config samples | `config/config.env.example`, `config.env.example` | Duplicate examples |

### Entry points (`pyproject.toml` scripts)

| Script | Target |
|--------|--------|
| `urban-hs` | `urban_hs.cli.main:app` |
| `urban-hs-server` | `urban_hs.ui.api.main:run` |
| `urban-hs-tui` | `urban_hs.ui.tui.app:run` |

### Module registry (code)

From `modules/__init__.py` registry (lazy): wifi, ble, network, camera, metasploit, hid, mqtt, reporting, credential, exploit, ssid_confusion, esp32, bt_hid, urban_hack — plus example plugins under `modules/plugins/`.

### Storage tables (`core/storage.py`)

`schema_version`, `devices`, `wifi_networks`, `wifi_handshakes`, `ble_devices`, `bt_classic_devices`, `cameras`, `network_hosts`, `vulnerabilities`, `credentials`, `audit_sessions`, `artifacts` (+ indexes). Aligns closely with `MASTER_PLAN.md` §2.

### God-files (LOC)

| File | ~LOC |
|------|------|
| `modules/network/__init__.py` | 1150 |
| `core/storage.py` | 963 |
| `modules/reporting/generator.py` | 919 |
| `modules/credential/manager.py` | 891 |
| `modules/wifi/managers.py` | 855 |
| `modules/esp32.py` | 784 |
| `modules/mqtt.py` | 739 |
| `modules/camera/enumeration.py` | 731 |
| `modules/bt_hid.py` | 731 |
| `modules/reporting/gpg_evidence.py` | 705 |
| `modules/exploit/runner.py` | 693 |
| `modules/urban_hack.py` | 685 |
| `core/plugins.py` | 670 |
| `modules/hid/ducky.py` | 667 |
| `core/scheduler.py` | 643 |
| `core/process_mgr.py` | 632 |
| `modules/metasploit/rpc.py` | 634 |
| `core/security.py` | 607 |

---

## 1. Architecture & code

### [ARC-001] Oversized modules and core files
- **Severidade:** P2
- **Dimensão:** Architecture
- **Evidência:** LOC table above; `network/__init__.py` alone ~1150 lines; `storage.py` mixes schema, CRUD, maintenance, Redis.
- **Impacto:** Hard reviews, merge conflicts, easy to miss security checks when adding attacks.
- **Recomendação:** Split only when touching (e.g. `storage/{schema,wifi,ble,credentials}.py`, `network/{scanner,nuclei,...}.py`). No big-bang rewrite.
- **Roadmap:** Align with “custom module expansion” without structural freeze.

### [ARC-002] Plugin architecture is real but uneven depth
- **Severidade:** P3
- **Dimensão:** Architecture
- **Evidência:** `core/plugins.py` (~670 LOC) — load, validate, dependency order, enable/disable, hot-reload concepts; example plugins are placeholders (`example_reporter`, `example_sniffer`).
- **Impacto:** Good extension story; first-party modules often bypass “thin plugin” and are fat packages.
- **Recomendação:** Document the canonical plugin contract (initialize/start/stop/attack) and keep examples green in CI.
- **Roadmap:** Module expansion phase.

### [ARC-003] Layering core → modules → UI is mostly respected
- **Severidade:** P3 (positive / residual)
- **Dimensão:** Architecture
- **Evidência:** API routers invoke modules/event bus; CLI/TUI separate entrypoints; modules registry lazy-imports to reduce cycles (`modules/__init__.py` comments).
- **Impacto:** Residual risk of UI importing heavy module graphs at startup.
- **Recomendação:** Keep lazy imports; add import-linter or a simple smoke `import urban_hs.cli.main` in CI.
- **Roadmap:** Quality.

### [ARC-004] HAL is thin facade, not full abstraction yet
- **Severidade:** P2
- **Dimensão:** Architecture
- **Evidência:** `hal/platform.py` ~101 LOC; `hal/wifi`, `hal/ble` small; many modules still shell out via process manager directly.
- **Impacto:** Multi-platform (Pi vs x86 vs container) behavior forks inside modules instead of HAL.
- **Recomendação:** Route new hardware I/O through HAL; leave legacy paths until hardware validation pass.
- **Roadmap:** README “next focus: real hardware validation”.

### [ARC-005] Config reload + global singleton pattern
- **Severidade:** P3
- **Dimensão:** Architecture
- **Evidência:** `core/config.py` global `_config`, watchfiles reload publishing `config.reloaded`.
- **Impacto:** Fine for single-process appliance; tests must reset globals carefully (SessionScope already learned this lesson).
- **Recomendação:** Continue explicit reset helpers in tests; avoid new process-wide mutables without guards.
- **Roadmap:** n/a

### [ARC-006] Dead / placeholder surfaces
- **Severidade:** P3
- **Dimensão:** Architecture
- **Evidência:** Example plugins; `security.py` “Verify SLSA provenance (placeholder)”; scattered `pass` in HAL cleanup; `urban_hack.py` “TODO: Full exploit chain”.
- **Impacto:** Noise for auditors; some TODOs are offensive-feature stubs (expected) vs security control stubs (riskier).
- **Recomendação:** Tag placeholders (`# STUB:`) and fail closed if a security control is stubbed in non-lab mode.
- **Roadmap:** Hardening.

---

## 2. Domain & data

### [DOM-001] Secrets and cracked passwords at rest in plaintext
- **Severidade:** P1
- **Dimensão:** Domain & data (cross-ref SEC-002)
- **Evidência:** `storage.py` schema: `wifi_handshakes.password TEXT`, `credentials.password TEXT`; `credential/manager.py` `CredentialType.PLAINTEXT` when `pass` present; no Fernet/SQLCipher usage found in credential path.
- **Impacto:** Disk theft, backup leak, or world-readable DB = full credential compromise from audits.
- **Recomendação:** Document threat model; default DB dir `0700`, file `0600`; optional encryption layer; never log passwords.
- **Roadmap:** Security hardening before multi-user/shared Pi.

### [DOM-002] Divergent data roots and product names
- **Severidade:** P1
- **Dimensão:** Domain & data (cross-ref BLD-001)
- **Evidência:**
  - Config default `storage.data_root` → `/var/lib/urban-hs` (from path scans / service notes)
  - systemd `ReadWritePaths=/var/lib/urban-hack-sentinel`
  - shell `CONFIG_FILE=/etc/urban-hack-sentinel/config.env`
  - README install `cp … /etc/urban-hs/config.env`
- **Impacto:** Service cannot write where app writes (or reverse); “empty DB after upgrade”; ops confusion.
- **Recomendação:** Pick one prefix (`urban-hs` **or** `urban-hack-sentinel`) and migrate paths in one release note.
- **Roadmap:** Packaging / Fase distribuição.

### [DOM-003] Schema versioning exists and matches master plan well
- **Severidade:** P3 (positive)
- **Dimensão:** Domain & data
- **Evidência:** `schema_version` table; `_migrate()` in `storage.py`; entities devices/wifi/ble/cameras/vulns/credentials/sessions/artifacts ≈ `MASTER_PLAN.md`.
- **Impacto:** Additive migrations are feasible; good base vs ad-hoc DDL-only apps.
- **Recomendação:** Keep migrations monotonic; add tests that open empty DB and assert table set.
- **Roadmap:** n/a

### [DOM-004] Foreign keys declared in spirit, PRAGMA not enabled
- **Severidade:** P2
- **Dimensão:** Domain & data
- **Evidência:** SQL `REFERENCES` in CREATE TABLE comments/plan; `rg` found **no** `PRAGMA foreign_keys` in `src/urban_hs`. WAL/busy_timeout set; FKs effectively off (SQLite default).
- **Impacto:** Orphan handshakes/devices possible if delete paths incomplete.
- **Recomendação:** Enable `PRAGMA foreign_keys=ON` per connection after delete-path audit, or keep manual cascades + tests.
- **Roadmap:** Storage hardening.

### [DOM-005] Redis optional and non-fatal
- **Severidade:** P3 (positive)
- **Dimensão:** Domain & data
- **Evidência:** Storage connects Redis optionally; warns and continues; compose includes redis service.
- **Impacto:** Correct degraded mode for single-node Pi.
- **Recomendação:** Document which features need Redis (if any beyond cache/pubsub).
- **Roadmap:** n/a

### [DOM-006] SessionScope as domain safety control
- **Severidade:** P2 (residual after fix)
- **Dimensão:** Domain & data
- **Evidência:** `core/session_scope.py`; fix write-up `docs/CORRECAO_SESSIONSCOPE_2026-07-01.md`; tests `test_session_scope*.py` including bypass attempts; enforcement in wifi/ble/urban_hack paths.
- **Impacto:** Reduces accidental cross-engagement attacks; residual risk = new modules forgetting `validate()`.
- **Recomendação:** Centralize “before attack” hook in process/attack base class so new modules inherit guard.
- **Roadmap:** Keep regression tests mandatory in CI.

### [DOM-007] Artifacts/pcaps path coupling
- **Severidade:** P2
- **Dimensão:** Domain & data
- **Evidência:** Handshakes store `capture_path` / `hash_path` as text; data_root layout assumed by managers.
- **Impacto:** Moving data_root without rewriting rows breaks crack/export; backups must be atomic (DB + files).
- **Recomendação:** Backup recipe: stop service → copy data_root tree; document relative paths only under root.
- **Roadmap:** Ops docs.

---

## 3. Functional / product

### Feature parity: README capabilities vs code

| Capability (README) | Status | Evidence |
|---------------------|--------|----------|
| Wi-Fi scan iw + airodump fallback | **Likely Done** | `modules/wifi/scanner.py` ~560 LOC, plugin |
| PMKID / handshake / WPS / deauth | **Partial–Done** | `wifi/attacks/{wpa,wps,deauth,base}.py`, managers |
| MAC randomization | **Partial** | `core/mac_anonymiser.py` |
| Handshake manager / hashcat / export | **Partial** | managers + reporting; ROADMAP still has potfile UI |
| BLE / Fast Pair / WhisperPair | **Partial** | `ble/fastpair.py`, `exploit_chain.py`; hardware tests skipped in CI |
| Network scanner nmap | **Likely Done** | `network/scanner.py` |
| Metasploit RPC | **Partial** | `metasploit/rpc.py` ~634 LOC |
| Camera discovery | **Partial** | `camera/enumeration.py`, `vuln_check.py` |
| HID / Ducky / gadget | **Partial** | `hid/{injector,gadget,ducky}.py` |
| MQTT suite | **Partial** | `mqtt.py` (includes auth-bypass *capability* notes — offensive feature) |
| ESP32 fingerprint CVE-2025-27840 | **Partial** | `esp32.py` |
| SSID confusion CVE-2023-52424 | **Partial** | `ssid_confusion.py` |
| BT HID CVEs | **Partial** | `bt_hid.py` |
| Web dashboard | **Partial** | static `ui/web/index.html` — **not** React PWA |
| TUI / CLI | **Done** | textual + typer entries |
| Docker multi-arch | **Partial** | Dockerfiles exist; entrypoint consistency varies |
| GPS wardriving mode | **Partial / pending** | ROADMAP F1.5 pendente; gps tests exist |

### [FUN-001] README over-promises React PWA and stale metrics
- **Severidade:** P1
- **Dimensão:** Functional
- **Evidência:** `MASTER_PLAN` / architecture diagrams mention React PWA; no `package.json`; only `src/urban_hs/ui/web/index.html`. README “Current coverage: **19%** (99 tests)” vs local collect **~200 tests** and coverage report **~57%**.
- **Impacto:** Wrong operator expectations; trust erosion; contributors optimize wrong stack.
- **Recomendação:** Fix README Architecture + Testing sections to match tree; regenerate coverage in CI artifact.
- **Roadmap:** Docs hygiene (immediate).

### [FUN-002] ROADMAP drift vs shipped control plane
- **Severidade:** P2
- **Dimensão:** Functional
- **Evidência:** ROADMAP F2.1 HTTP server, F2.7 auth still “Pendente” while FastAPI+JWT+static UI exist; F2.5 map / F2.6 cracked page still open (plausible).
- **Impacto:** Planning noise; duplicate work risk.
- **Recomendação:** Mark shipped items ✅ with pointers to modules; keep only true gaps open.
- **Roadmap:** Edit ROADMAP in same PR as README fix.

### [FUN-003] Offensive feature depth unproven without hardware
- **Severidade:** P1
- **Dimensão:** Functional
- **Evidência:** README next focus hardware validation; CI ignores BLE module + e2e; many modules wrap external binaries (`hcxdumptool`, `reaver`, `nmap`, `msf`).
- **Impacto:** “Green unit tests” ≠ “captures PMKID on Alfa/Pi”.
- **Recomendação:** Hardware acceptance checklist (per binary + one happy path) before calling v3 production-ready.
- **Roadmap:** Explicit hardware gate (README already points here).

### [FUN-004] Airgap/lab/field modes are a real product differentiator
- **Severidade:** P3 (positive)
- **Dimensão:** Functional
- **Evidência:** `ui/api/routers/attacks.py` documents modes; airgap → 403 on active exploit execution; rate limit 10/min on execute.
- **Impacto:** Safer defaults for demos if wired through config end-to-end.
- **Recomendação:** Surface mode in TUI/web header; default `field` for non-lab images.
- **Roadmap:** UX + security policy.

### [FUN-005] Known UI functional bugs still noted in session docs
- **Severidade:** P2
- **Dimensão:** Functional
- **Evidência:** `docs/SESSAO_AUTONOMA_2026-07-01.md` / correction notes: TUI wrong attack type publish; Web UI body vs query param issues (as recorded in session).
- **Impacto:** Operators trigger wrong actions or see spurious errors.
- **Recomendação:** Track as FUN tickets with repro; add API contract tests for attack payload shape.
- **Roadmap:** Post-SessionScope polish.

### [FUN-006] Dual EN/PT documentation is a product asset
- **Severidade:** P3 (positive)
- **Dimensão:** Functional
- **Evidência:** README + README.pt; docs/*.pt.md pairs; slight line-count drift (README 335 vs 284).
- **Impacto:** PT README may lag features.
- **Recomendação:** When editing EN claims, patch PT in same change.
- **Roadmap:** Docs.

---

## 4. UX / UI / i18n

### [UX-001] Three UIs, three maturity levels
- **Severidade:** P2
- **Dimensão:** UX
- **Evidência:** CLI Typer+Rich; TUI Textual single app module ~387 LOC; Web one HTML file with embedded CSS/JS.
- **Impacto:** Operators learn three metaphors; web is monitoring/trigger thin client; TUI denser; CLI scripting.
- **Recomendação:** Pick a “primary operator UX” for v3.1 (TUI **or** web) and make the other secondary in docs.
- **Roadmap:** Product choice.

### [UX-002] Web UI is usable prototype, not design system
- **Severidade:** P2
- **Dimensão:** UX
- **Evidência:** `ui/web/index.html` ~444 lines — monospace panels, fetch to API, token handling in-page.
- **Impacto:** No responsive story, limited a11y, easy to break when API shapes change.
- **Recomendação:** Keep static until API stabilizes; add smoke Playwright later only for critical paths (login token → scan status).
- **Roadmap:** Optional; don’t build React yet unless needed.

### [UX-003] TUI smoke doc exists
- **Severidade:** P3 (positive)
- **Dimensão:** UX
- **Evidência:** `docs/SMOKE_TUI.md` (+ PT).
- **Impacto:** Manual QA path defined.
- **Recomendação:** Run smoke on each release tag; link from CONTRIBUTING.
- **Roadmap:** Release checklist.

### [UX-004] No product UI i18n (PT/EN only in markdown)
- **Severidade:** P3
- **Dimensão:** UX / i18n
- **Evidência:** No gettext/i18n framework in `src/urban_hs`; strings inline English in TUI/API messages.
- **Impacto:** Acceptable for security tooling; PT operators rely on docs not UI.
- **Recomendação:** Don’t invest in UI i18n until primary UX chosen.
- **Roadmap:** Defer.

### [UX-005] API errors vs operator guidance
- **Severidade:** P2
- **Dimensão:** UX
- **Evidência:** Mixed HTTPException detail strings; binary missing errors depend on process_mgr; health checker exists (`core/health.py` ~567).
- **Impacto:** “nmap not found” may surface as generic 500 without remediation hint.
- **Recomendação:** Map missing binary → 503 + install hint from `binary_manifest.py`.
- **Roadmap:** Operator UX.

---

## 5. Security & privacy (control plane & data)

> This section audits **the safety of the platform itself** (authn/z, defaults, storage, supply chain), not the ethics of offensive modules. Operators remain responsible for lawful use.

### [SEC-001] Unauthenticated JWT minting
- **Severidade:** P0
- **Dimensão:** Security
- **Evidência:** `ui/api/main.py` — `POST /api/v1/auth/token` → `create_access_token(subject="api-user")` with **no password/API key**. Module docstring warns: never bind `0.0.0.0` without real auth. Default host in `APIConfig` is `127.0.0.1` (good). Token endpoint not rate-limited like attack routes (session notes).
- **Impacto:** Any local process (or remote client if mis-bound/proxied) obtains full API power: scans, attacks, event stream.
- **Recomendação:**
  1. Require `UHS_API_TOKEN` / basic auth / first-run bootstrap secret to mint JWT.
  2. Hard-fail start if bind is public without `ALLOW_INSECURE_BIND`.
  3. Rate-limit `/auth/token`.
  4. Short-lived JWTs + refresh optional later.
- **Roadmap:** Before any LAN exposure (ROADMAP F2.7 should be re-scoped as “replace mint-anything”).

### [SEC-002] Plaintext secrets in SQLite
- **Severidade:** P1
- **Dimensão:** Security (cross-ref DOM-001)
- **Evidência:** credentials/handshakes password columns; credential manager PLAINTEXT type.
- **Impacto:** High-value loot file on disk.
- **Recomendação:** Permissions + optional encryption; redacted exports by default.
- **Roadmap:** Data protection.

### [SEC-003] Privileged container / host network expectations
- **Severidade:** P2
- **Dimensão:** Security
- **Evidência:** `docker/docker-compose.yml` `privileged: true`, `cap_add`; MULTIARCH.md NET_ADMIN; host network in README docker run.
- **Impacto:** Expected for monitor mode; catastrophic if combined with open API bind inside container.
- **Recomendação:** Compose profiles: `lab-ui` (no priv, API only) vs `rf-full` (privileged). Document never publish 8080 publicly.
- **Roadmap:** Docker hardening.

### [SEC-004] JWT secret persistence
- **Severidade:** P2
- **Dimensão:** Security
- **Evidência:** `auth.py` — secret file `~/.config/urban-hs/jwt_secret`; generate on first run; config can supply `jwt_secret` (auto-generate if empty). Keyring skipped for headless.
- **Impacto:** Secret file permissions matter; multi-user home shared Pi may leak token signing key.
- **Recomendação:** `0600` on secret file; prefer `/var/lib/...` for system service user; rotate recipe.
- **Roadmap:** Install docs.

### [SEC-005] Middleware baseline is decent
- **Severidade:** P3 (positive)
- **Dimensão:** Security
- **Evidência:** `SecurityHeadersMiddleware`, `RateLimitMiddleware`, optional `IPAllowlistMiddleware`; WS auth tests.
- **Impacto:** Reduces casual abuse on localhost; not a substitute for SEC-001.
- **Recomendação:** Enable IP allowlist by default in field images.
- **Roadmap:** Hardening.

### [SEC-006] Subprocess construction
- **Severidade:** P2
- **Dimensão:** Security
- **Evidência:** `process_mgr.py` uses `asyncio.create_subprocess_exec`; hardening hooks; no widespread `shell=True` in core path from scan. Residual risk: argument injection if user-controlled strings passed unsanitized to external CLIs (BSSID/SSID/paths).
- **Impacto:** Classic wrapper risk for SSID with special characters / path traversal in output dirs.
- **Recomendação:** Central allowlist/validators for MAC/SSID/channel/paths before exec; reject `../` in artifact names.
- **Roadmap:** Input validation pass on attack APIs.

### [SEC-007] `.env` present locally but gitignored
- **Severidade:** P3 (positive / residual)
- **Dimensão:** Security
- **Evidência:** `.env` mode `600`; `.gitignore` has `*.env`; not tracked. Examples `config.env.example` tracked (OK).
- **Impacto:** Good local hygiene; ensure CI never prints secrets.
- **Recomendação:** Keep; add `jwt_secret` file patterns to gitignore if under repo cwd.
- **Roadmap:** n/a

### [SEC-008] GPG evidence reporting exists
- **Severidade:** P3 (positive)
- **Dimensão:** Security
- **Evidência:** `modules/reporting/gpg_evidence.py` ~705 LOC.
- **Impacto:** Good direction for chain-of-custody; ensure signing keys not baked into images.
- **Recomendação:** Document key management separately from app config.
- **Roadmap:** Reporting.

---

## 6. Testes & qualidade

### [QA-001] Lint CI vs reality (~4652 ruff issues)
- **Severidade:** P1
- **Dimensão:** Tests & quality
- **Evidência:** Local `ruff check src/urban_hs --statistics` → **Found 4652 errors**; many auto-fixable. CI workflow runs `ruff check` + `ruff format --check` on `src/urban_hs/`.
- **Impacto:** Either CI is permanently red (ignored) or never run; no reliable style gate.
- **Recomendação:** (a) slash `select` to critical rules (E/F/bugbear), baseline green; or (b) one-shot `ruff check --fix` + format PR; stop claiming strict ruff until green.
- **Roadmap:** Immediate quality.

### [QA-002] Integration/hardware tests sidelined
- **Severidade:** P1
- **Dimensão:** Tests & quality
- **Evidência:** CI ignores `tests/test_ble_module.py`, `tests/test_e2e.py`. Wifi plugin contract failures when `/var/lib/urban-hs` not writable (env). Markers `hardware`/`integration` defined in pyproject.
- **Impacto:** False confidence on BLE/e2e; path default hostile to dev users.
- **Recomendação:** Pytest tmp `data_root` fixture mandatory; run ignored suites in nightly/optional job; document hardware job.
- **Roadmap:** CI matrix.

### [QA-003] Solid pockets of unit/contract tests
- **Severidade:** P3 (positive)
- **Dimensão:** Tests & quality
- **Evidência:** attacks inventory/execute/submodules; session_scope (+ bypass); ws_auth; fragattacks contract; wifi/network modules; api smoke/integration; gps_geo; sprint6/8b; tui phase10.
- **Impacto:** Recent hardening is regression-protected better than average for offensive tools.
- **Recomendação:** Protect SessionScope and auth tests as merge-blocking always.
- **Roadmap:** n/a

### [QA-004] Coverage narrative inconsistent
- **Severidade:** P2
- **Dimensão:** Tests & quality
- **Evidência:** README 19%/99 tests; `.coverage` present; `coverage report` ~**57%** overall with weak `ui/api/*` lines; ~**200** tests collected.
- **Impacto:** Planning using README numbers is wrong.
- **Recomendação:** CI uploads coverage summary; README badge or “as of DATE”.
- **Roadmap:** Docs + CI.

### [QA-005] Type checking configured but not evidenced in CI
- **Severidade:** P2
- **Dimensão:** Tests & quality
- **Evidência:** `[tool.mypy]` strict-ish options in pyproject; CI snippet reviewed runs ruff+pytest only (no mypy step in the workflow content reviewed).
- **Impacto:** `disallow_untyped_defs` aspiration unused.
- **Recomendação:** Add `mypy` on `core/` first, expand gradually.
- **Roadmap:** Quality.

### [QA-006] Minimal test pyramid recommendation
- **Severidade:** P3
- **Dimensão:** Tests & quality
- **Recomendação:**
  1. **Unit:** pure parsers, MAC/SSID validators, SessionScope, JWT verify, schema migrate empty DB.
  2. **Component:** API TestClient authz matrix; attack router airgap/field; process_mgr with fake binaries.
  3. **Hardware nightly (optional):** marked `@pytest.mark.hardware`, not blocking PR.
  4. Avoid heavy e2e in PR until deterministic fixtures exist.
- **Roadmap:** QA strategy.

---

## 7. Build & distribuição

### [BLD-001] Install path / name fragmentation
- **Severidade:** P1
- **Dimensão:** Build (canonical with DOM-002)
- **Evidência:** `/etc/urban-hs` vs `/etc/urban-hack-sentinel`; `/var/lib/urban-hs` vs `/var/lib/urban-hack-sentinel`; scripts `urban-hs` vs `urban-hack-sentinel.sh` vs service `ExecStart=/usr/local/bin/urban-hack-sentinel.sh`.
- **Impacto:** Broken systemd deploys; split-brain data.
- **Recomendação:** One naming decision + migration notes + update all four of: README, example env, unit file, config defaults.
- **Roadmap:** Packaging sprint.

### [BLD-002] Build backend / packaging ambiguity
- **Severidade:** P2
- **Dimensão:** Build
- **Evidência:** `build-system` requires `poetry-core`, backend `poetry.core.masonry.api`; project metadata in PEP 621 `[project]`; trailing `[tool.setuptools.packages.find]`; no clear `[tool.poetry]` packages table in file head/tail reviewed.
- **Impacto:** `pip install .` / poetry publish may behave differently across tools; contributors confused.
- **Recomendação:** Prefer hatchling or setuptools with pure PEP 621, **or** complete Poetry layout; delete unused tool tables.
- **Roadmap:** Packaging.

### [BLD-003] Docker multi-arch present but entrypoints differ
- **Severidade:** P2
- **Dimensão:** Build
- **Evidência:** `Dockerfile`, `Dockerfile.amd64`, `Dockerfile.arm64` — different `CMD`/`ENTRYPOINT`/`HEALTHCHECK` import paths (`create_health_checker` vs `get_overall_status` variants); `USER urbanhs`; release workflow buildx to ghcr.
- **Impacto:** One arch “works”, other healthcheck fails; release lies.
- **Recomendação:** Single Dockerfile + `TARGETARCH`; one healthcheck module API; smoke `docker run … urban-hs info` in CI.
- **Roadmap:** Release workflow.

### [BLD-004] systemd hardening vs capabilities needs
- **Severidade:** P2
- **Dimensão:** Build
- **Evidência:** unit sets `NoNewPrivileges`, `ProtectSystem=strict`, `CapabilityBoundingSet=CAP_NET_ADMIN…`, monitor-mode prep via `iw`; app needs raw/net admin for RF.
- **Impacto:** Good template; path mismatches break it; setcap on host binaries still required per README.
- **Recomendação:** After path unify, test unit on clean Debian/Pi OS VM.
- **Roadmap:** Distribuição.

### [BLD-005] Heavy system dependency surface
- **Severidade:** P2
- **Dimensão:** Build
- **Evidência:** README apt list: aircrack-ng, hcxtools, reaver, bully, bluez, gpsd, nmap, nuclei, metasploit, hashcat, libgpgme, etc.
- **Impacto:** “pip install” is never enough; Docker/chroot story must carry binaries (`core/chroot_process.py`, `scripts/bootstrap_chroot.sh`).
- **Recomendação:** `urban-hs doctor` / health check lists missing binaries (binary_manifest) as first-run UX.
- **Roadmap:** Operator onboarding.

### [BLD-006] Pre-commit exists
- **Severidade:** P3 (positive)
- **Dimensão:** Build
- **Evidência:** `.pre-commit-config.yaml` present.
- **Impacto:** Helpful if hooks match a **green** ruff baseline (else developers disable hooks).
- **Recomendação:** Sync hook versions with CI after QA-001.
- **Roadmap:** DX (light).

---

## Prioritization matrix

| ID | Sev | Dim | Title |
|----|-----|-----|-------|
| SEC-001 | P0 | Security | Unauthenticated JWT mint |
| SEC-002 | P1 | Security | Plaintext passwords in DB |
| DOM-001 | P1 | Domain | Same as SEC-002 (canonical cross-ref) |
| BLD-001 | P1 | Build | Path/name fragmentation |
| DOM-002 | P1 | Domain | Cross-ref BLD-001 |
| QA-001 | P1 | QA | Ruff/CI unusable |
| FUN-001 | P1 | Product | README React/coverage drift |
| FUN-003 | P1 | Product | Hardware truth unproven |
| QA-002 | P1 | QA | e2e/BLE/path fixtures |
| SEC-003 | P2 | Security | Privileged docker + API |
| SEC-004 | P2 | Security | JWT secret file placement |
| SEC-006 | P2 | Security | CLI arg validation |
| DOM-004 | P2 | Domain | FK pragma off |
| DOM-006 | P2 | Domain | SessionScope inheritance |
| DOM-007 | P2 | Domain | Artifact path coupling |
| FUN-002 | P2 | Product | ROADMAP drift |
| FUN-005 | P2 | Product | Known TUI/web bugs |
| UX-001 | P2 | UX | Three UIs uneven |
| UX-002 | P2 | UX | Static web fragility |
| UX-005 | P2 | UX | Error remediation hints |
| QA-004 | P2 | QA | Coverage docs |
| QA-005 | P2 | QA | mypy not in CI |
| BLD-002 | P2 | Build | Poetry/setuptools mix |
| BLD-003 | P2 | Build | Dockerfile drift |
| BLD-004 | P2 | Build | systemd validation |
| BLD-005 | P2 | Build | Binary dependency UX |
| ARC-001 | P2 | Arch | God files |
| ARC-004 | P2 | Arch | Thin HAL |
| *(P3s)* | P3 | mixed | Plugins polish, i18n defer, Redis docs, GPG keys, pre-commit sync, dual PT docs lag, airgap UX surfacing |

---

## Map → existing planning docs

| Audit theme | Where it lives already | Suggested planning move |
|-------------|------------------------|-------------------------|
| Real auth for LAN | ROADMAP F2.7 “Pendente” | **Reopen as P0**: replace free `/token` mint |
| HTTP/web UI | ROADMAP F2.x | Mark static UI+FastAPI ✅; leave map/cracked pages open |
| Hardware validation | README Project Status | Keep as gate before “production” language |
| SessionScope | `CORRECAO_SESSIONSCOPE_*` | Done — guard new modules |
| Bettercap / wardrive | ROADMAP F1.5–F1.6 | Remain backlog |
| Chroot/tools | MASTER_PLAN Alpine chroot | Continue via `chroot_process` + bootstrap script |
| React PWA | MASTER_PLAN diagram | **Demote/remove** until explicit decision |
| CI/quality | CONTRIBUTING / workflows | Fix ruff baseline before new features |

---

## Out of scope / unverified

- Live RF capture success rates on specific adapters (Alfa AWUS036ACH, Pi 5 onboard Wi‑Fi limitations).
- Metasploit/nuclei effectiveness in real labs.
- Whether release workflow has successfully published images to GHCR for this fork.
- Full mypy error count.
- Runtime confirmation of every ROADMAP “✅ Completo” row (many marked complete; spot-checks only).
- Performance under sustained wardrive (CPU, disk growth of pcaps).
- Legal/compliance posture for end operators (must be operator-owned).

---

## Suggested next implementation order (for a future fix plan — not part of this audit)

1. **SEC-001** auth bootstrap + bind guard  
2. **BLD-001** unify paths + systemd/README  
3. **QA-001** ruff baseline green  
4. **FUN-001/002** docs/roadmap honesty  
5. **SEC-002** credential-at-rest policy  
6. **QA-002** tmp data_root fixtures + optional hardware job  
7. Hardware acceptance checklist on real Pi  

---

## Appendix — evidence anchors

| Topic | Anchor |
|-------|--------|
| JWT mint | `src/urban_hs/ui/api/main.py` `create_token` |
| JWT impl | `src/urban_hs/ui/api/auth.py` |
| API warning | docstring on `ui/api/main.py` |
| Middleware | `src/urban_hs/ui/api/middleware.py` |
| WS auth | `src/urban_hs/ui/api/routers/events.py`, `tests/test_ws_auth.py` |
| Storage/schema | `src/urban_hs/core/storage.py` |
| SessionScope | `src/urban_hs/core/session_scope.py`, `docs/CORRECAO_SESSIONSCOPE_2026-07-01.md` |
| Attacks modes | `src/urban_hs/ui/api/routers/attacks.py` |
| Process exec | `src/urban_hs/core/process_mgr.py` |
| Config | `src/urban_hs/core/config.py` |
| CI | `.github/workflows/ci.yml`, `release.yml` |
| Docker | `docker/Dockerfile*` , `docker-compose.yml` |
| systemd | `urban-hack-sentinel.service`, `urban_hack_sentinel.sh` |
| Web UI | `src/urban_hs/ui/web/index.html` |
| Packaging | `pyproject.toml` |
| Product claims | `README.md`, `MASTER_PLAN.md`, `ROADMAP.md` |
