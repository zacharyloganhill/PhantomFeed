"""
FedRAMP 20x — Audit log API.
Provides query access to the audit log and CSV export.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from fastapi import HTTPException
from auth.auth import get_current_user, require_client_access
from db.audit_log import get_audit_events, count_audit_events, events_to_csv

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["audit"])


def _enforce_audit_scope(user: dict, client_id: Optional[str]) -> Optional[str]:
    """Non-admins can only see their own client's events; admins see all."""
    if user.get("role") == "admin":
        return client_id
    own = user.get("client_id")
    if client_id and client_id != own:
        raise HTTPException(403, "Access denied")
    return own  # non-admin always filtered to their client


@router.get("/audit")
async def list_audit_events(
    client_id: Optional[str] = None,
    event_type: Optional[str] = None,
    username: Optional[str] = None,
    limit: int = Query(200, le=1000),
    offset: int = 0,
    user=Depends(get_current_user),
):
    client_id = _enforce_audit_scope(user, client_id)
    events = await get_audit_events(
        client_id=client_id, event_type=event_type,
        username=username, limit=limit, offset=offset,
    )
    total = await count_audit_events(client_id=client_id, event_type=event_type)
    return {"events": events, "total": total, "limit": limit, "offset": offset}


@router.get("/audit/export.csv")
async def export_audit_csv(
    client_id: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = Query(5000, le=50000),
    token: Optional[str] = Query(None),
    user=Depends(get_current_user),
):
    client_id = _enforce_audit_scope(user, client_id)
    events = await get_audit_events(client_id=client_id, event_type=event_type, limit=limit)
    csv_data = events_to_csv(events)
    return Response(
        content=csv_data.encode(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_log.csv"},
    )


@router.get("/clients/{client_id}/audit")
async def list_client_audit(
    client_id: str,
    event_type: Optional[str] = None,
    limit: int = Query(200, le=1000),
    offset: int = 0,
    user=Depends(get_current_user),
):
    require_client_access(user, client_id)
    events = await get_audit_events(
        client_id=client_id, event_type=event_type, limit=limit, offset=offset
    )
    total = await count_audit_events(client_id=client_id, event_type=event_type)
    return {"events": events, "total": total}


@router.get("/clients/{client_id}/audit.csv")
async def export_client_audit_csv(
    client_id: str,
    limit: int = Query(5000, le=50000),
    token: Optional[str] = Query(None),
    user=Depends(get_current_user),
):
    require_client_access(user, client_id)
    events = await get_audit_events(client_id=client_id, limit=limit)
    csv_data = events_to_csv(events)
    return Response(
        content=csv_data.encode(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=audit_{client_id}.csv"},
    )
