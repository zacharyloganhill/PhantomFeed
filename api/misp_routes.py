"""
PhantomFeed — MISP Integration API Routes
"""
from fastapi import APIRouter, Depends, BackgroundTasks
from auth.auth import require_admin

router = APIRouter()


@router.get("/misp/status")
async def misp_status(user: dict = Depends(require_admin)):
    from ingest.misp_connector import get_misp_status
    return await get_misp_status()


@router.post("/misp/sync")
async def misp_sync(background_tasks: BackgroundTasks, user: dict = Depends(require_admin)):
    from ingest.misp_connector import pull_misp_events
    background_tasks.add_task(pull_misp_events, 1)
    return {"status": "sync_started", "message": "MISP pull triggered in background"}


@router.get("/misp/events")
async def misp_events(limit: int = 50, user: dict = Depends(require_admin)):
    from db import database as db
    items = await db.get_items(limit=limit, feed_id="misp_pull")
    return {"count": len(items), "events": items}


@router.post("/misp/push/{item_id}")
async def push_to_misp(item_id: str, user: dict = Depends(require_admin)):
    from ingest.misp_connector import push_item_to_misp
    return await push_item_to_misp(item_id)
