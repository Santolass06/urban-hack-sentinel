"""Auto-exploit chaining via LLM local (Ollama).

Dado um conjunto de CVEs/achados detetados (camera, wifi, ble), pede a um
LLM local (Ollama, acessível no hardware do operador) uma cadeia de exploit
ordenada e as ferramentas a usar. Sem dependências extra: usa ``aiohttp``
(já no projeto) para falar com o endpoint Ollama; se indisponível, devolve
uma cadeia por regras simples (fallback determinístico).

Lab-only. O LLM não executa nada — só propõe; o operador aprova.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# ponytail: default to the operator's local Ollama; override via config/env
DEFAULT_OLLAMA_URL = "http://localhost:11434/api/generate"


@dataclass
class ChainStep:
    order: int
    module: str
    action: str
    target_field: str
    rationale: str = ""


@dataclass
class ExploitChain:
    model: str
    steps: list[ChainStep] = field(default_factory=list)
    fallback: bool = False


_PROMPT = (
    "You are a red-team planner. Given detected CVEs, return a JSON list of "
    "exploit steps ordered by dependency. Each step: {order, module, action, "
    "target_field, rationale}. Modules: wifi, ble, camera, network, hid. "
    "Only propose, never execute. Detected:\n"
)


def _rule_based_chain(findings: list[dict[str, Any]]) -> ExploitChain:
    """Deterministic fallback when no LLM is available."""
    steps: list[ChainStep] = []
    order = 1
    for f in findings:
        cve = f.get("cve", "")
        module = f.get("module", "network")
        action = f.get("suggested_action", "recon")
        steps.append(
            ChainStep(
                order=order,
                module=module,
                action=action,
                target_field=f.get("target_field", "target"),
                rationale="rule-based",
            )
        )
        order += 1
    return ExploitChain(model="rule-based", steps=steps, fallback=True)


async def build_chain(
    findings: list[dict[str, Any]], model: str = "llama3", ollama_url: str = DEFAULT_OLLAMA_URL
) -> ExploitChain:
    """Ask Ollama to order the detected findings into an exploit chain."""
    import aiohttp  # already a project dependency

    payload = {
        "model": model,
        "prompt": _PROMPT + json.dumps(findings),
        "format": "json",
        "stream": False,
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(ollama_url, json=payload, timeout=30) as resp:
                if resp.status != 200:
                    logger.warning("ollama unavailable", status=resp.status)
                    return _rule_based_chain(findings)
                data = await resp.json()
        raw = data.get("response", "")
        parsed = json.loads(raw)
        steps_raw = parsed if isinstance(parsed, list) else parsed.get("steps", [])
        steps = [
            ChainStep(
                order=int(s.get("order", i + 1)),
                module=s.get("module", "network"),
                action=s.get("action", "recon"),
                target_field=s.get("target_field", "target"),
                rationale=s.get("rationale", ""),
            )
            for i, s in enumerate(steps_raw)
        ]
        return ExploitChain(model=model, steps=steps)
    except Exception as exc:
        logger.debug("llm chain fell back to rules", error=str(exc))
        return _rule_based_chain(findings)
