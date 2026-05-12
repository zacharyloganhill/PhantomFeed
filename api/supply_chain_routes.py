"""
PhantomFeed — Supply Chain Risk API Routes
"""
from fastapi import APIRouter, Depends, BackgroundTasks
from auth.auth import get_current_user, require_client_access

router = APIRouter()


@router.get("/clients/{client_id}/vendors")
async def list_vendors(client_id: str, user: dict = Depends(get_current_user)):
    require_client_access(user, client_id)
    from db import database as db
    vendors = await db.get_vendors(client_id)
    return {"count": len(vendors), "vendors": vendors}


@router.post("/clients/{client_id}/vendors")
async def add_vendor(client_id: str, body: dict, user: dict = Depends(get_current_user)):
    require_client_access(user, client_id)
    from db import database as db
    vendor = await db.create_vendor_full(
        client_id=client_id,
        vendor_name=body.get("vendor_name", ""),
        vendor_type=body.get("vendor_type", ""),
        criticality=body.get("criticality", "medium"),
        products=body.get("products", []),
        category=body.get("category", ""),
        contact_email=body.get("contact_email", ""),
    )
    return vendor


@router.delete("/clients/{client_id}/vendors/{vendor_id}")
async def delete_vendor(
    client_id: str, vendor_id: str, user: dict = Depends(get_current_user)
):
    require_client_access(user, client_id)
    from db import database as db
    await db.delete_vendor(vendor_id)
    return {"deleted": vendor_id}


@router.post("/clients/{client_id}/vendors/scan")
async def scan_vendors(
    client_id: str,
    background_tasks: BackgroundTasks,
    user: dict = Depends(get_current_user),
):
    require_client_access(user, client_id)
    from ingest.supply_chain_monitor import run_supply_chain_monitor
    background_tasks.add_task(run_supply_chain_monitor, client_id)
    return {"status": "scan_started", "message": "Supply chain risk scan running in background"}


@router.get("/clients/{client_id}/supply-chain-graph")
async def supply_chain_graph(client_id: str, user: dict = Depends(get_current_user)):
    require_client_access(user, client_id)
    from ingest.supply_chain_monitor import build_supply_chain_graph
    return await build_supply_chain_graph(client_id)
