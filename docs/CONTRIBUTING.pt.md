# Como Contribuir para o Urban Hack Sentinel

Guia para adicionar módulos, escrever testes e manter a documentação sincronizada.

---

## 1. Esqueleto de Módulo

Crie um novo directório em `src/urban_hs/modules/<categoria>/`:

```
src/urban_hs/modules/<categoria>/<nome>/
├── __init__.py      # exporta NomeModulo
├── module.py        # classe principal que herda de BaseModule
├── models.py        # modelos Pydantic (request/response)
└── tests/
    ├── test_<nome>_contract.py
    └── test_<nome>_execute.py
```

`module.py` deve implementar:
- `inventory()` — lista ataques/acções disponíveis.
- `execute(request: AttackRequest) -> AttackResult` — executa o ataque.

---

## 2. Registo

Adicione o módulo em `src/urban_hs/modules/__init__.py` para que o *plugin registry* o descubra. Não importe o módulo nas camadas de UI.

---

## 3. Contrato de Eventos

Emita eventos usando o contrato canónico:

- `attack.started` — execução iniciada.
- `attack.progress` — actualizações intermédias (0–100%).
- `attack.completed` — sucesso com *payload* do resultado.
- `attack.error` — falha com mensagem de erro.

Use `AttackEventNormalizer` se o módulo emitir nomes de eventos legados.

---

## 4. Testes

Cada módulo novo deve incluir:

- `tests/test_<nome>_contract.py` — valida schema de `inventory()`, campos obrigatórios, tipos.
- `tests/test_<nome>_execute.py` — valida `execute()` em modo `dry-run` e real.

Os testes devem passar na CI sem hardware especial. Use *mocks* para `gpsd`, `iw`, `bleak`, etc.

---

## 5. Regras de Documentação

- Cada funcionalidade nova ou actualizada exige actualização de:
  - `README.md` + `README.pt.md` (tabela de capacidades)
  - `docs/API.md` + `docs/API.pt.md` (se houver novos endpoints ou schemas)
  - `docs/PLAN.md` + `docs/PLAN.pt.md` (se pertencer a uma *sprint*)
- Não commit dados pessoais (caminhos, nomes de utilizador, e-mails, *serials*).
- Use linguagem clara; o público inclui principiantes.

---

## 6. Estilo de Código

- Type hints em Python 3.11+ em todo o lado.
- Async-first: use `asyncio` para trabalho I/O-bound.
- Logging estruturado (JSONL) em cada módulo.
- Sem caminhos hardcoded; use `config` para todos os valores dependentes do ambiente.

---

## 7. Checklist de Pull Request

- [ ] `make test` passa localmente.
- [ ] `pytest --cov=urban_hs` não desce a cobertura.
- [ ] `docs/` actualizado (EN + PT).
- [ ] Sem PII no diff.
- [ ] Fronteira legal/ética documentada para qualquer ataque destrutivo novo.
