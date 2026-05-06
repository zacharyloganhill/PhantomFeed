"""PhantomFeed — TAXII API Routes"""

from fastapi import APIRouter, HTTPException
from ingest.taxii_feeds import get_taxii_status, build_taxii_fetchers
import config

router = APIRouter()


@router.get("/taxii/sources", summary="List configured TAXII servers and connection status")
async def list_taxii_sources():
    status = await get_taxii_status()
    return {"sources": status}


@router.post("/taxii/test/{feed_id}", summary="Test a TAXII connection")
async def test_taxii(feed_id: str):
    cfg = next((f for f in config.TAXII_FEEDS if f["id"] == feed_id), None)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Unknown TAXII feed: {feed_id}")
    status = await get_taxii_status()
    result = next((s for s in status if s["id"] == feed_id), None)
    return result or {"id": feed_id, "status": "unknown"}
