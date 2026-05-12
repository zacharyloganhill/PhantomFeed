"""
FedRAMP 20x — KSI validation API.
Validation runs automatically every 6 hours via APScheduler.
Manual trigger available for on-demand checks.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks

import db.database as db
from auth.auth import get_current_user, require_client_access
from compliance.ksi_definitions import KSI_DEFINITIONS
from compliance.ksi_engine import KSIEngine

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["ksi"])


@router.get("/clients/{client_id}/ksi")
async def get_ksi_results(client_id: str, user=Depends(get_current_user)):
    require_client_access(user, client_id)
    """Latest KSI result for each of the 7 indicators."""
    results = await db.get_latest_ksi_results(client_id)
    passing = sum(1 for r in results if r["status"] == "pass")
    conditional = sum(1 for r in results if r["status"] == "conditional")
    failing = sum(1 for r in results if r["status"] == "fail")
    avg_score = (sum(r["score"] for r in results) / len(results)) if results else None
    return {
        "client_id": client_id,
        "results": results,
        "summary": {
            "total": len(results),
            "passing": passing,
            "conditional": conditional,
            "failing": failing,
            "avg_score": round(avg_score, 3) if avg_score is not None else None,
            "authorization_status": _auth_status(passing, conditional, failing, len(results)),
        },
        "definitions": KSI_DEFINITIONS,
    }


@router.get("/clients/{client_id}/ksi/{ksi_id}/history")
async def get_ksi_history(client_id: str, ksi_id: str,
                           limit: int = 30, user=Depends(get_current_user)):
    require_client_access(user, client_id)
    history = await db.get_ksi_history(client_id, ksi_id, limit=limit)
    return {"ksi_id": ksi_id, "history": history}


@router.post("/clients/{client_id}/ksi/validate")
async def trigger_validation(client_id: str, background_tasks: BackgroundTasks,
                              user=Depends(get_current_user)):
    require_client_access(user, client_id)
    """Manually trigger KSI validation (runs in background)."""
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    background_tasks.add_task(_run_ksi_validation, client_id)
    return {"message": "KSI validation triggered", "client_id": client_id}


@router.get("/admin/ksi/summary")
async def global_ksi_summary(user=Depends(get_current_user)):
    """Cross-client KSI summary for admin overview."""
    return {"clients": await db.get_all_clients_ksi_summary()}


def _auth_status(passing: int, conditional: int, failing: int, total: int) -> str:
    if total == 0:
        return "unknown"
    if failing > 0:
        return "not-authorized"
    if conditional > 2:
        return "conditional"
    if passing == total:
        return "authorized"
    return "conditional"


async def _run_ksi_validation(client_id: str):
    try:
        engine = KSIEngine(client_id)
        results = await engine.validate_all()
        logger.info("KSI validation done for %s: %d results", client_id, len(results))
    except Exception as exc:
        logger.error("KSI validation error for %s: %s", client_id, exc)


async def run_all_ksi_validations():
    """Called by scheduler every 6 hours — validates all clients."""
    db_conn = db.get_db()
    async with db_conn.execute("SELECT id FROM clients") as cur:
        clients = await cur.fetchall()
    for row in clients:
        await _run_ksi_validation(row["id"])
