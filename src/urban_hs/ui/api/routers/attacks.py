"""
Attack inventory and execution endpoints.

Exposes registered modules as attacks and allows
the UI to trigger execution with parameters.

Sprint 8A hardening supports environment modes:
- lab: full functionality for isolated labs
- field: restricted active attacks, dry-run preferred
- airgap: no external calls and no active exploit execution
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from urban_hs.core.config import get_config
from urban_hs.core.event_bus import Event, EventPriority, get_event_bus
from urban_hs.core.process_mgr import ProcessLimits, ProcessManager
from urban_hs.core.session_scope import (
    SessionScope,
    get_active_scope,
    set_active_scope,
)
from urban_hs.modules import list_modules
from urban_hs.ui.api.auth import require_auth
from urban_hs.ui.api.rate_limit import limiter

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[require_auth()])
_process_manager = ProcessManager()

# The only registry entry currently wired to a real execution engine.
# Other module names keep returning the inert placeholder below until
# they get an equivalent, audited execution path.
EXPLOIT_ATTACK_NAME = "exploit"

# The session scope is a process-wide singleton owned by
# ``core.session_scope`` so that this REST path and the event-bus attack
# handlers share one state. These wrappers preserve the existing public
# API used by the TUI/Web UI and tests.
def get_session_scope() -> SessionScope:
    """Return the shared session scope (for external configuration)."""
    return get_active_scope()


def set_session_scope(scope: SessionScope) -> None:
    """Replace the shared session scope (e.g. from TUI/Web UI on session start)."""
    set_active_scope(scope)


class AttackSummary(BaseModel):
    name: str
    plugin_type: str
    description: str


class AttackInventory(BaseModel):
    attacks: List[AttackSummary]
    total: int


class ExecuteRequest(BaseModel):
    params: Dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = False


class ExecuteResponse(BaseModel):
    job_id: str
    attack: str


@router.get("/attacks", response_model=AttackInventory)
async def list_attacks() -> AttackInventory:
    raw: Dict[str, str] = list_modules()
    attacks: List[AttackSummary] = []
    for name, class_path in raw.items():
        attacks.append(
            AttackSummary(
                name=name,
                plugin_type=_infer_plugin_type(name, class_path),
                description=class_path,
            )
        )
    return AttackInventory(attacks=attacks, total=len(attacks))


def _infer_plugin_type(name: str, class_path: str) -> str:
    lowered = name.lower()
    if any(k in lowered for k in ["scan", "scanner", "discovery", "enumeration"]):
        return "scanner"
    if any(k in lowered for k in ["attack", "exploit", "inject"]):
        return "exploit"
    if any(k in lowered for k in ["report", "reporter"]):
        return "reporter"
    return "module"


def _environment_mode() -> str:
    try:
        return get_config().environment.mode.lower()
    except Exception:
        return "lab"


def _raise_if_airgap() -> None:
    if _environment_mode() == "airgap":
        raise HTTPException(status_code=403, detail="Active execution is disabled in airgap mode")


@router.post("/attacks/{attack_name}/execute", response_model=ExecuteResponse)
@limiter.limit("10/minute")
async def execute_attack(
    request: Request, attack_name: str, payload: ExecuteRequest
) -> ExecuteResponse:
    modules = list_modules()
    if attack_name not in modules:
        raise HTTPException(status_code=404, detail="Unknown attack")

    job_id = str(uuid.uuid4())

    if payload.dry_run:
        await _audit_log(attack_name, payload.params, job_id, "dry_run")
        await _publish(
            "attack.completed",
            {
                "job_id": job_id,
                "success": True,
                "result": {"dry_run": True},
            },
        )
        return ExecuteResponse(job_id=job_id, attack=attack_name)

    # --- Session scope guard rail (blocks real execution) ---
    category = attack_name.split("_", 1)[0] if "_" in attack_name else attack_name
    target = payload.params.get("target") or payload.params.get("interface") or ""
    try:
        get_session_scope().validate(target, category)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    await _publish(
        "attack.started",
        {
            "attack": attack_name,
            "params": payload.params,
            "job_id": job_id,
        },
    )

    if attack_name == EXPLOIT_ATTACK_NAME:
        return await _execute_exploit(attack_name, payload, job_id)

    cmd = f"echo 'Executing {attack_name} with params={payload.params}'"
    limits = ProcessLimits(max_duration_sec=60)
    asyncio.create_task(_process_manager.run(cmd, limits=limits))
    await _audit_log(attack_name, payload.params, job_id, "queued")

    return ExecuteResponse(job_id=job_id, attack=attack_name)


async def _execute_exploit(
    attack_name: str, payload: ExecuteRequest, job_id: str
) -> ExecuteResponse:
    """Dispatch to the real ExploitRunner, gated by the active-attacks guard rails.

    enable_active_attacks and legal_warning_shown must both be set before
    any exploit code is downloaded/executed against a target — mirrors the
    guard already enforced for WiFi active attacks (urban_hack.py, wifi/plugin.py).
    """
    cfg = get_config()
    if not cfg.wifi.enable_active_attacks or not cfg.wifi.legal_warning_shown:
        await _audit_log(
            attack_name, payload.params, job_id, "denied", error="guard_rails_not_satisfied"
        )
        await _publish(
            "attack.denied",
            {"job_id": job_id, "attack": attack_name, "reason": "guard_rails_not_satisfied"},
        )
        raise HTTPException(
            status_code=403,
            detail=(
                "Exploit execution requires both enable_active_attacks and "
                "legal_warning_shown to be enabled in configuration."
            ),
        )

    from urban_hs.modules.exploit.runner import ExploitRunner, ExploitSource, ExploitTarget

    params = payload.params
    target = ExploitTarget(
        id=job_id,
        target_type="service",
        address=params.get("target", ""),
        port=params.get("port"),
        service=params.get("service"),
    )

    runner = ExploitRunner()
    result = await runner.execute(
        exploit_name=str(params.get("exploit_id", "")),
        target=target,
        source=ExploitSource.SEARCHSPLOIT,
        options=params.get("options"),
    )

    await _audit_log(
        attack_name,
        params,
        job_id,
        result.status.value,
        error=result.error or None,
    )
    await _publish(
        "attack.completed",
        {
            "job_id": job_id,
            "success": result.success,
            "result": result.to_dict(),
        },
    )
    return ExecuteResponse(job_id=job_id, attack=attack_name)


async def _audit_log(
    attack_name: str,
    params: Dict[str, Any],
    job_id: str,
    outcome: str,
    error: Optional[str] = None,
    simulated: bool = False,
) -> None:
    """Persist an auditable record of every execution attempt.

    Best-effort: a storage failure (e.g. unwritable log_root) must not
    break the request — the gate/event-bus decision already happened.
    """
    try:
        from urban_hs.core.storage import get_storage

        await get_storage().log_jsonl(
            "attack_audit",
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "job_id": job_id,
                "attack": attack_name,
                "target": params.get("target") or params.get("target_address"),
                "outcome": outcome,
                "error": error,
                "simulated": simulated,
            },
        )
    except Exception as exc:
        logger.warning(
            "Failed to persist attack audit log",
            extra={"attack": attack_name, "error": str(exc)},
        )


async def _publish(event_type: str, payload: Dict[str, Any]) -> None:
    event_bus = get_event_bus()
    await event_bus.publish(
        Event(
            type=event_type,
            payload=payload,
            timestamp=datetime.now(timezone.utc),
            correlation_id=payload.get("job_id", str(uuid.uuid4())),
            source="api.attacks",
            priority=EventPriority.NORMAL,
            metadata={},
        )
    )
