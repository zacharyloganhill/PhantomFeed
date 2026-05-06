"""PhantomFeed — Admin API Routes (client portal management)"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import Response
from pydantic import BaseModel

from auth.auth import require_admin
from db import database as db

router = APIRouter()


class ClientCreate(BaseModel):
    name: str
    contact_email: str = ""
    stack_profile: dict = {}


class ClientUpdate(BaseModel):
    name: Optional[str] = None
    contact_email: Optional[str] = None
    stack_profile: Optional[dict] = None


class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "analyst"
    client_id: Optional[str] = None


# ── Clients ───────────────────────────────────────────────────────────────────

@router.get("/clients", summary="List all clients")
async def list_clients(_: dict = Depends(require_admin)):
    return {"clients": await db.get_clients()}


@router.post("/clients", summary="Create a new client")
async def create_client(req: ClientCreate, _: dict = Depends(require_admin)):
    client = await db.create_client(
        name=req.name,
        contact_email=req.contact_email,
        stack_profile=req.stack_profile,
    )
    return client


@router.get("/clients/{client_id}", summary="Get a single client")
async def get_client(client_id: str, _: dict = Depends(require_admin)):
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client


@router.put("/clients/{client_id}", summary="Update a client")
async def update_client(client_id: str, req: ClientUpdate, _: dict = Depends(require_admin)):
    client = await db.update_client(
        client_id,
        name=req.name,
        contact_email=req.contact_email,
        stack_profile=req.stack_profile,
    )
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client


@router.delete("/clients/{client_id}", summary="Delete a client")
async def delete_client(client_id: str, _: dict = Depends(require_admin)):
    await db.delete_client(client_id)
    return {"status": "ok", "deleted": client_id}


@router.get("/clients/{client_id}/preview", summary="Preview filtered feed for a client")
async def preview_client_feed(client_id: str, limit: int = 50, _: dict = Depends(require_admin)):
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    items = await db.get_items(limit=limit, sort="risk")
    return {"client": client, "count": len(items), "items": items}


# ── Users ─────────────────────────────────────────────────────────────────────

@router.post("/users", summary="Create a new user")
async def create_user(req: UserCreate, _: dict = Depends(require_admin)):
    from auth.auth import hash_password
    existing = await db.get_user_by_username(req.username)
    if existing:
        raise HTTPException(status_code=409, detail="Username already exists")
    hashed = hash_password(req.password)
    user = await db.create_user(
        username=req.username,
        password_hash=hashed,
        role=req.role,
        client_id=req.client_id,
    )
    return {k: v for k, v in user.items() if k != "password_hash"}


# ── Reports ───────────────────────────────────────────────────────────────────

@router.get("/clients/{client_id}/report.html", summary="Generate HTML report for a client")
async def client_report_html(
    client_id: str,
    days: int = Query(7, ge=1, le=365),
    _: dict = Depends(require_admin),
):
    from reports.pdf_generator import generate_client_report_html
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    items = await db.get_items(limit=500, sort="risk")
    html = generate_client_report_html(client, items, days)
    return Response(content=html, media_type="text/html")


@router.get("/clients/{client_id}/report.pdf", summary="Generate PDF report for a client")
async def client_report_pdf(
    client_id: str,
    days: int = Query(7, ge=1, le=365),
    _: dict = Depends(require_admin),
):
    from reports.pdf_generator import generate_client_report
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    items = await db.get_items(limit=500, sort="risk")
    content, media_type = generate_client_report(client, items, days)
    filename = f"phantomfeed-report-{client.get('name','client').replace(' ','-')}.pdf"
    headers = {}
    if media_type == "application/pdf":
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return Response(content=content, media_type=media_type, headers=headers)


@router.post("/clients/{client_id}/send-digest", summary="Send email digest to client")
async def send_digest(
    client_id: str,
    days: int = Query(7, ge=1, le=365),
    _: dict = Depends(require_admin),
):
    from reports.email_digest import send_client_digest
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    items = await db.get_items(limit=500, sort="risk")
    result = await send_client_digest(client, items, days)
    return result
