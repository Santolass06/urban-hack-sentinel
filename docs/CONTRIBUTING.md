# Contributing to Urban Hack Sentinel

How to add a new module, write tests, and keep documentation in sync.

---

## 1. Module Skeleton

Create a new directory under `src/urban_hs/modules/<category>/`:

```
src/urban_hs/modules/<category>/<name>/
├── __init__.py      # exports ModuleName
├── module.py        # main class inheriting BaseModule
├── models.py        # Pydantic request/response models
└── tests/
    ├── test_<name>_contract.py
    └── test_<name>_execute.py
```

`module.py` must implement:
- `inventory()` — list available attacks/actions.
- `execute(request: AttackRequest) -> AttackResult` — run the attack.

---

## 2. Registration

Add the module to `src/urban_hs/modules/__init__.py` so the plugin registry discovers it. Do not import the module in the UI layers.

---

## 3. Event Contract

Emit events using the canonical contract:

- `attack.started` — execution began.
- `attack.progress` — intermediate updates (0–100%).
- `attack.completed` — success with result payload.
- `attack.error` — failure with error message.

Use `AttackEventNormalizer` if your module emits legacy event names.

---

## 4. Tests

Every new module must ship with:

- `tests/test_<name>_contract.py` — validates `inventory()` schema, required fields, types.
- `tests/test_<name>_execute.py` — validates `execute()` in dry-run and real modes.

Tests must pass in CI without special hardware. Use mocks for `gpsd`, `iw`, `bleak`, etc.

---

## 5. Documentation Rules

- Every new or updated feature must update:
  - `README.md` + `README.pt.md` (capabilities table)
  - `docs/API.md` + `docs/API.md.pt` (if new endpoints or schemas)
  - `docs/PLAN.md` + `docs/PLAN.pt.md` (if part of a sprint)
- Do not commit personal data (paths, usernames, emails, serials).
- Use clear language; the audience includes beginners.

---

## 6. Code Style

- Python 3.11+ type hints everywhere.
- Async-first: use `asyncio` for I/O-bound work.
- Structured logging (JSONL) for every module.
- No hardcoded paths; use `config` for all environment-specific values.

---

## 7. Pull Request Checklist

- [ ] `make test` passes locally.
- [ ] `pytest --cov=urban_hs` does not decrease coverage.
- [ ] `docs/` updated (EN + PT).
- [ ] No PII in diff.
- [ ] Legal/ethical boundary documented for any new destructive attack.
