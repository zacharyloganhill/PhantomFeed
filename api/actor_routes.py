"""
PhantomFeed — Threat Actor Dossier API Routes
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from auth.auth import get_current_user, require_client_access

router = APIRouter()


@router.get("/actors")
async def list_actors(
    origin: Optional[str] = Query(None),
    motivation: Optional[str] = Query(None),
    active_only: bool = Query(False),
    user: dict = Depends(get_current_user),
):
    from db import database as db
    actors = await db.get_threat_actors(origin=origin, motivation=motivation, active_only=active_only)
    return {"count": len(actors), "actors": actors}


@router.get("/actors/{actor_id}")
async def get_actor(actor_id: str, user: dict = Depends(get_current_user)):
    from db import database as db
    actor = await db.get_threat_actor(actor_id)
    if not actor:
        raise HTTPException(404, "Actor not found")
    return actor


@router.get("/actors/{actor_id}/items")
async def get_actor_items(
    actor_id: str,
    limit: int = Query(50, le=200),
    user: dict = Depends(get_current_user),
):
    from db import database as db
    actor = await db.get_threat_actor(actor_id)
    if not actor:
        raise HTTPException(404, "Actor not found")
    items = await db.get_actor_items(actor_id, limit=limit)
    return {"actor_id": actor_id, "count": len(items), "items": items}


@router.get("/actors/{actor_id}/ttps")
async def get_actor_ttps(actor_id: str, user: dict = Depends(get_current_user)):
    from db import database as db
    actor = await db.get_threat_actor(actor_id)
    if not actor:
        raise HTTPException(404, "Actor not found")
    ttps = actor.get("ttps") or []
    return {
        "actor_id": actor_id,
        "actor_name": actor["name"],
        "ttps": ttps,
        "count": len(ttps),
    }


@router.get("/clients/{client_id}/actor-alerts")
async def get_client_actor_alerts(
    client_id: str,
    user: dict = Depends(get_current_user),
):
    require_client_access(user, client_id)
    from db import database as db
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(404, "Client not found")

    # Get all actors and find those targeting client's industry
    stack = client.get("stack_profile") or {}
    client_industry = (client.get("industry") or stack.get("industry") or "").lower()

    actors = await db.get_threat_actors(active_only=True)
    targeting = []
    for actor in actors:
        industries = [i.lower() for i in (actor.get("target_industries") or [])]
        if client_industry and any(
            ind in client_industry or client_industry in ind
            for ind in industries
        ):
            targeting.append(actor)

    return {
        "client_id": client_id,
        "client_industry": client_industry or "Not configured",
        "count": len(targeting),
        "actors_targeting": targeting,
    }
