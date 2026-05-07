"""
PhantomFeed — CMMC 2.0 Assessment API Routes
"""
from fastapi import APIRouter, Depends, Query
from auth.auth import get_current_user

router = APIRouter()


@router.get("/clients/{client_id}/cmmc/assessment")
async def get_cmmc_assessment(client_id: str, user: dict = Depends(get_current_user)):
    from compliance.cmmc_assessor import CMMCAssessor
    return await CMMCAssessor().get_assessment(client_id)


@router.patch("/clients/{client_id}/cmmc/practices/{practice_id}")
async def update_practice(
    client_id: str,
    practice_id: str,
    body: dict,
    user: dict = Depends(get_current_user),
):
    from compliance.cmmc_assessor import CMMCAssessor
    return await CMMCAssessor().update_practice(
        client_id, practice_id,
        status=body.get("status", "not_implemented"),
        notes=body.get("notes", ""),
    )


@router.post("/clients/{client_id}/cmmc/bulk-update")
async def bulk_update_practices(
    client_id: str,
    body: dict,
    user: dict = Depends(get_current_user),
):
    from compliance.cmmc_assessor import CMMCAssessor
    updates = body.get("updates", [])
    return await CMMCAssessor().bulk_update(client_id, updates)


@router.get("/cmmc/practices")
async def list_practices(domain: str = Query(None), user: dict = Depends(get_current_user)):
    from compliance.cmmc_practices import CMMC_PRACTICES
    if domain:
        return [p for p in CMMC_PRACTICES if p["domain"].lower() == domain.lower()]
    return CMMC_PRACTICES
