"""
Attack inventory and execution endpoints.

Exposes registered modules as attacks and allows
the UI to trigger execution with parameters.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address

from urban_hs.core.event_bus import Event, EventPriority, get_event_bus
from urban_hs.core.process_mgr import ProcessLimits, ProcessManager
from urban_hs.modules import list_modules
from urban_hs.ui.api.auth import require_auth

router = APIRouter(dependencies=[require_auth()])
_process_manager = ProcessManager()
_limiter = Limiter(key_func=get_remote_address)

_process_manager = ProcessManager()


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


@router.post("/attacks/{attack_name}/execute", response_model=ExecuteResponse)
async def execute_attack(request: Request, attack_name: str, payload: ExecuteRequest) -> ExecuteResponse:
    modules = list_modules()
    if attack_name not in modules:
        raise HTTPException(status_code=404, detail="Unknown attack")

    job_id = str(uuid.uuid4())
    await _publish(
        "attack.started",
        {
            "attack": attack_name,
            "params": payload.params,
            "job_id": job_id,
        },
    )

    if payload.dry_run:
        await _publish(
            "attack.completed",
            {
                "job_id": job_id,
                "success": True,
                "result": {"dry_run": True},
            },
        )
        return ExecuteResponse(job_id=job_id, attack=attack_name)

    cmd = f"echo 'Executing {attack_name} with params={payload.params}'"
    limits = ProcessLimits(max_duration_sec=60)
    asyncio.create_task(_process_manager.run(cmd, limits=limits))

    return ExecuteResponse(job_id=job_id, attack=attack_name)


async def _publish(event_type: str, payload: Dict[str, Any]) -> None:
    event_bus = get_event_bus()
    await event_bus.publish(
        Event(
            type=event_type,
            payload=payload,
            timestamp=datetime.utcnow(),
            correlation_id=payload.get("job_id", str(uuid.uuid4())),
            source="api.attacks",
            priority=EventPriority.NORMAL,
            metadata={},
        )
    )
