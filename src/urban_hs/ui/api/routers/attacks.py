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
import os
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from urban_hs.core.config import get_config
from urban_hs.core.event_bus import Event, EventPriority, get_event_bus
from urban_hs.core.session_scope import SessionScope, get_active_scope, set_active_scope
from urban_hs.modules import list_modules
from urban_hs.ui.api.auth import require_auth
from urban_hs.ui.api.rate_limit import limiter

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[require_auth()])

# "exploit" runs synchronously through the in-process ExploitRunner (with its
# own enable_active_attacks/legal_warning guard). Every other module is
# dispatched asynchronously onto the event bus, where the plugin handlers
# registered in the API lifespan consume "<module>.attack_request".
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
    attacks: list[AttackSummary]
    total: int


class ExecuteRequest(BaseModel):
    params: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = False


class ExecuteResponse(BaseModel):
    job_id: str
    attack: str


@router.get("/attacks", response_model=AttackInventory)
async def list_attacks() -> AttackInventory:
    raw: dict[str, str] = list_modules()
    attacks: list[AttackSummary] = []
    for name, class_path in raw.items():
        attacks.append(
            AttackSummary(
                name=name, plugin_type=_infer_plugin_type(name, class_path), description=class_path
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
    """Return the deployment environment mode: lab (default), field, or airgap.

    Sourced from the ``URBAN_HS_ENVIRONMENT_MODE`` env var. (Previously this
    read ``config.environment.mode``, a field that does not exist, so the
    airgap gate below was permanently unreachable.)
    """
    return os.environ.get("URBAN_HS_ENVIRONMENT_MODE", "lab").strip().lower()


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
            "attack.completed", {"job_id": job_id, "success": True, "result": {"dry_run": True}}
        )
        return ExecuteResponse(job_id=job_id, attack=attack_name)

    # Airgap mode forbids any real (non-dry-run) execution.
    _raise_if_airgap()

    # --- Session scope guard rail (blocks real execution) ---
    category = attack_name.split("_", 1)[0] if "_" in attack_name else attack_name
    target = payload.params.get("target") or payload.params.get("interface") or ""
    try:
        get_session_scope().validate(target, category)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    await _publish(
        "attack.started", {"attack": attack_name, "params": payload.params, "job_id": job_id}
    )

    if attack_name == EXPLOIT_ATTACK_NAME:
        return await _execute_exploit(attack_name, payload, job_id)

    # Dispatch to the audited event-bus path: the plugin handlers registered
    # in the API lifespan consume "<module>.attack_request" and execute the
    # request (re-validating the session scope). Replaces the former inert
    # `echo` placeholder.
    await get_event_bus().publish(
        Event(
            type=f"{attack_name}.attack_request",
            payload={"job_id": job_id, **payload.params},
            source="api",
            priority=EventPriority.HIGH,
        )
    )
    await _audit_log(attack_name, payload.params, job_id, "dispatched")

    return ExecuteResponse(job_id=job_id, attack=attack_name)


class AttackAllRequest(BaseModel):
    active: bool = False
    ble_exploit: bool = False


@router.post("/attacks/attack-all")
@limiter.limit("2/minute")
async def attack_all(request: Request, payload: AttackAllRequest) -> dict[str, Any]:
    """Fan out every discovered WiFi AP + BLE device to all enabled attacks.

    Non-blocking: the fan-out runs as a background task (it can take a long
    time) and this returns a job id immediately.
    """
    _raise_if_airgap()
    plugin = getattr(request.app.state, "urban_hack_plugin", None)
    if plugin is None:
        raise HTTPException(status_code=503, detail="Orchestrator plugin not available")

    if payload.active:
        plugin.config.wifi_enable_active_attacks = True
    if payload.ble_exploit:
        plugin.config.attack_all_ble_exploit = True

    job_id = str(uuid.uuid4())
    await _audit_log("attack_all", payload.model_dump(), job_id, "dispatched")
    asyncio.create_task(plugin.attack_all())
    return {"job_id": job_id, "status": "dispatched"}


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

    await _audit_log(attack_name, params, job_id, result.status.value, error=result.error or None)
    await _publish(
        "attack.completed",
        {"job_id": job_id, "success": result.success, "result": result.to_dict()},
    )
    return ExecuteResponse(job_id=job_id, attack=attack_name)


async def _audit_log(
    attack_name: str,
    params: dict[str, Any],
    job_id: str,
    outcome: str,
    error: str | None = None,
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
                "timestamp": datetime.now(UTC).isoformat(),
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
            "Failed to persist attack audit log", extra={"attack": attack_name, "error": str(exc)}
        )


async def _publish(event_type: str, payload: dict[str, Any]) -> None:
    event_bus = get_event_bus()
    await event_bus.publish(
        Event(
            type=event_type,
            payload=payload,
            timestamp=datetime.now(UTC),
            correlation_id=payload.get("job_id", str(uuid.uuid4())),
            source="api.attacks",
            priority=EventPriority.NORMAL,
            metadata={},
        )
    )
