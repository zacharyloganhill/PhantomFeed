"""
FedRAMP 20x — OSCAL document export endpoints.
All documents are generated on-demand from live DB state.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response

import db.database as db
from auth.auth import get_current_user, require_client_access
from compliance.oscal.generator import OSCALGenerator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["oscal"])

# Allow ?token= for browser downloads (same pattern as deck_routes)
async def _require_user(token: Optional[str] = Query(None),
                         user=Depends(get_current_user)):
    return user


@router.get("/clients/{client_id}/oscal/poam.xml")
async def export_poam(client_id: str, user=Depends(_require_user)):
    require_client_access(user, client_id)
    client = await _get_client_or_404(client_id)
    gen = OSCALGenerator(client)
    xml_bytes = await gen.generate_poam()
    return Response(
        content=xml_bytes,
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="{client["name"]}_poam.xml"'},
    )


@router.get("/clients/{client_id}/oscal/sar.xml")
async def export_sar(client_id: str, user=Depends(_require_user)):
    require_client_access(user, client_id)
    client = await _get_client_or_404(client_id)
    gen = OSCALGenerator(client)
    xml_bytes = await gen.generate_sar()
    return Response(
        content=xml_bytes,
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="{client["name"]}_sar.xml"'},
    )


@router.get("/clients/{client_id}/oscal/vdr.json")
async def export_vdr(client_id: str, user=Depends(_require_user)):
    require_client_access(user, client_id)
    client = await _get_client_or_404(client_id)
    gen = OSCALGenerator(client)
    json_bytes = await gen.generate_vdr()
    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{client["name"]}_vdr.json"'},
    )


@router.get("/clients/{client_id}/oscal/oar.json")
async def export_oar(client_id: str, user=Depends(_require_user)):
    require_client_access(user, client_id)
    client = await _get_client_or_404(client_id)
    gen = OSCALGenerator(client)
    json_bytes = await gen.generate_oar()
    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{client["name"]}_oar.json"'},
    )


@router.get("/clients/{client_id}/oscal/ssp.xml")
async def export_ssp(client_id: str, user=Depends(_require_user)):
    require_client_access(user, client_id)
    client = await _get_client_or_404(client_id)
    gen = OSCALGenerator(client)
    xml_bytes = await gen.generate_ssp()
    return Response(
        content=xml_bytes,
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="{client["name"]}_ssp.xml"'},
    )


@router.get("/clients/{client_id}/oscal/bundle.zip")
async def export_bundle(client_id: str, user=Depends(_require_user)):
    require_client_access(user, client_id)
    """Download all 5 OSCAL documents as a ZIP archive."""
    client = await _get_client_or_404(client_id)
    gen = OSCALGenerator(client)
    zip_bytes = await gen.generate_bundle_zip()
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{client["name"]}_oscal_bundle.zip"'},
    )


@router.get("/clients/{client_id}/oscal/summary")
async def oscal_summary(client_id: str, user=Depends(get_current_user)):
    require_client_access(user, client_id)
    """Return document availability metadata for the FedRAMP dashboard."""
    client = await _get_client_or_404(client_id)
    counts = await db.count_scan_findings_by_severity(client_id)
    remediations = await db.get_remediations(client_id, status="open")
    posture = await db.get_latest_posture_score(client_id)
    return {
        "client_id": client_id,
        "client_name": client["name"],
        "documents": [
            {"type": "poam", "label": "POA&M", "format": "xml",
             "url": f"/api/v1/clients/{client_id}/oscal/poam.xml",
             "count": len(remediations)},
            {"type": "sar", "label": "SAR", "format": "xml",
             "url": f"/api/v1/clients/{client_id}/oscal/sar.xml",
             "count": sum(counts.values())},
            {"type": "vdr", "label": "VDR", "format": "json",
             "url": f"/api/v1/clients/{client_id}/oscal/vdr.json",
             "count": counts.get("CRITICAL", 0) + counts.get("HIGH", 0)},
            {"type": "oar", "label": "OAR", "format": "json",
             "url": f"/api/v1/clients/{client_id}/oscal/oar.json",
             "count": 1},
            {"type": "ssp", "label": "SSP", "format": "xml",
             "url": f"/api/v1/clients/{client_id}/oscal/ssp.xml",
             "count": 8},
        ],
        "bundle_url": f"/api/v1/clients/{client_id}/oscal/bundle.zip",
        "posture": posture,
    }


async def _get_client_or_404(client_id: str) -> dict:
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return dict(client)
