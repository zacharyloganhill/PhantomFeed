"""
ThreatPulse — REST API Routes
Auto-docs available at http://localhost:8000/docs
"""

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from typing import Optional
from db import database as db
from ingest import scheduler

router = APIRouter()


@router.get("/items", summary="List threat items with filters")
async def list_items(
    severity: Optional[str] = Query(None, description="Comma-separated: CRITICAL,HIGH,MEDIUM,LOW,INFO"),
    category: Optional[str] = Query(None, description="cve, kev, advisory, vendor, ics, threat, malware, supply"),
    feed_id: Optional[str] = Query(None, description="Filter by specific feed ID"),
    is_new: Optional[bool] = Query(None, description="Filter to new/unseen items only"),
    search: Optional[str] = Query(None, description="Full-text search across title, desc, vendor, tags"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    items = await db.get_items(
        severity=severity,
        category=category,
        feed_id=feed_id,
        is_new=is_new,
        search=search,
        limit=limit,
        offset=offset,
    )
    return {"count": len(items), "items": items}


@router.get("/items/{item_id}", summary="Get a single threat item by ID")
async def get_item(item_id: str):
    item = await db.get_item(item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return item


@router.post("/items/{item_id}/read", summary="Mark an item as read")
async def mark_read(item_id: str):
    await db.mark_read(item_id)
    return {"status": "ok", "item_id": item_id}


@router.post("/items/read-all", summary="Mark all (or all in a feed) as read")
async def mark_all_read(feed_id: Optional[str] = Query(None)):
    await db.mark_all_read(feed_id=feed_id)
    return {"status": "ok"}


@router.get("/stats", summary="Counts, feed breakdown, and ingestion status")
async def stats():
    return await db.get_stats()


@router.get("/feeds", summary="List all registered feed IDs")
async def list_feeds():
    feed_ids = scheduler.get_feed_ids()
    return {"feeds": feed_ids}


@router.post("/refresh", summary="Trigger an immediate poll of all feeds")
async def refresh_all(background_tasks: BackgroundTasks):
    """Fires all fetchers in the background. Returns immediately."""
    background_tasks.add_task(scheduler.run_all)
    return {"status": "refresh_started", "message": "All feeds are being polled in the background."}


@router.post("/refresh/{feed_id}", summary="Trigger an immediate poll of one feed")
async def refresh_feed(feed_id: str, background_tasks: BackgroundTasks):
    feed_ids = scheduler.get_feed_ids()
    if feed_id not in feed_ids:
        raise HTTPException(status_code=404, detail=f"Unknown feed: {feed_id}. Known feeds: {feed_ids}")
    background_tasks.add_task(scheduler.run_feed, feed_id)
    return {"status": "refresh_started", "feed_id": feed_id}


@router.delete("/items/purge", summary="Manually purge items older than retention period")
async def purge():
    deleted = await db.purge_old_items()
    return {"status": "ok", "deleted": deleted}
