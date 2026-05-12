"""
PhantomFeed — Dark Web Alert API Routes
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from auth.auth import get_current_user, require_client_access

router = APIRouter()


@router.get("/clients/{client_id}/darkweb-alerts")
async def list_darkweb_alerts(
    client_id: str,
    limit: int = Query(100, le=500),
    unacknowledged_only: bool = Query(False),
    user: dict = Depends(get_current_user),
):
    require_client_access(user, client_id)
    from db import database as db
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    alerts = await db.get_darkweb_alerts(client_id, limit=limit,
                                          unacknowledged_only=unacknowledged_only)
    return {
        "client_id": client_id,
        "count": len(alerts),
        "unacknowledged": sum(1 for a in alerts if not a.get("is_acknowledged")),
        "alerts": alerts,
    }


@router.post("/clients/{client_id}/darkweb-alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    client_id: str,
    alert_id: str,
    user: dict = Depends(get_current_user),
):
    require_client_access(user, client_id)
    from db import database as db
    await db.acknowledge_darkweb_alert(alert_id)
    return {"acknowledged": True, "alert_id": alert_id}


@router.post("/clients/{client_id}/darkweb-scan")
async def trigger_darkweb_scan(
    client_id: str,
    user: dict = Depends(get_current_user),
):
    require_client_access(user, client_id)
    from ingest.darkweb import run_client_darkweb_scan
    result = await run_client_darkweb_scan(client_id)
    return result


@router.get("/notifications")
async def get_notifications(
    limit: int = Query(10, le=50),
    user: dict = Depends(get_current_user),
):
    from db import database as db
    client_id = user.get("client_id")
    notifications = await db.get_notifications(client_id=client_id, limit=limit)
    return {"count": len(notifications), "notifications": notifications}
