"""PhantomFeed — Admin API Routes (client portal management)"""

import csv
import io
import ipaddress
import re
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Depends, Query, Request, UploadFile, File
from fastapi.responses import Response
from pydantic import BaseModel, field_validator

from auth.auth import require_admin, decode_token, _validate_decoded_token
from db import database as db


async def _require_admin_token_or_header(
    request: Request,
    token: Optional[str] = Query(None),
) -> dict:
    """Accept JWT from ?token= query param or Authorization: Bearer header, require admin role."""
    raw = token
    if not raw:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            raw = auth_header[7:]
    if not raw:
        raise HTTPException(401, "Not authenticated")
    payload = decode_token(raw)
    user = await _validate_decoded_token(payload)
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin access required")
    return user

router = APIRouter()


class ClientCreate(BaseModel):
    name: str
    contact_email: str = ""
    stack_profile: dict = {}

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name cannot be empty")
        if len(v) > 200:
            raise ValueError("name too long")
        return v


class ClientUpdate(BaseModel):
    name: Optional[str] = None
    contact_email: Optional[str] = None
    stack_profile: Optional[dict] = None


class UserCreate(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def username_valid(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 1:
            raise ValueError("username cannot be empty")
        if len(v) > 100:
            raise ValueError("username too long")
        return v

    @field_validator("password")
    @classmethod
    def password_min_length(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("password must be at least 8 characters")
        return v


class UserUpdate(BaseModel):
    password: Optional[str] = None
    role: Optional[str] = None
    client_id: Optional[str] = None

    @field_validator("password")
    @classmethod
    def password_min_length(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v) < 8:
            raise ValueError("password must be at least 8 characters")
        return v

    @field_validator("role")
    @classmethod
    def role_valid(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in ("admin", "analyst", "viewer"):
            raise ValueError("role must be admin, analyst, or viewer")
        return v


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

@router.get("/clients/{client_id}/users", summary="List users for a client")
async def list_client_users(client_id: str, _: dict = Depends(require_admin)):
    conn = db.get_db()
    async with conn.execute(
        "SELECT id, username, role, client_id, created_at FROM users WHERE client_id = ? ORDER BY created_at",
        (client_id,)
    ) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


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


@router.patch("/users/{user_id}", summary="Update a user (reset password or change role)")
async def update_user(user_id: str, req: UserUpdate, _: dict = Depends(require_admin)):
    from auth.auth import hash_password
    user = await db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.get("username") == "admin" and req.role and req.role != "admin":
        raise HTTPException(status_code=400, detail="Cannot demote the built-in admin user")
    updates = {}
    if req.password:
        updates["password_hash"] = hash_password(req.password)
    if req.role:
        updates["role"] = req.role
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    updated = await db.update_user(user_id, **updates)
    return {k: v for k, v in updated.items() if k != "password_hash"}


@router.delete("/users/{user_id}", status_code=204, summary="Delete a user")
async def delete_user(user_id: str, _: dict = Depends(require_admin)):
    user = await db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.get("username") == "admin":
        raise HTTPException(status_code=400, detail="Cannot delete the built-in admin user")
    deleted = await db.delete_user(user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="User not found")


@router.post("/users/{user_id}/revoke-tokens", summary="Force-invalidate all tokens for a user")
async def revoke_user_tokens(user_id: str, _: dict = Depends(require_admin)):
    """
    Increments the user's token_version, immediately invalidating every JWT they hold.
    Use when an account is compromised or an employee is terminated.
    """
    user = await db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await db.bump_token_version(user_id)
    return {"status": "ok", "user_id": user_id, "message": "All active tokens invalidated"}


# ── Reports ───────────────────────────────────────────────────────────────────

@router.get("/clients/{client_id}/report.html", summary="Generate HTML report for a client")
async def client_report_html(
    client_id: str,
    days: int = Query(7, ge=1, le=365),
    _: dict = Depends(require_admin),
):
    from reports.pdf_generator import generate_client_report_html, _get_report_extras
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    items = await db.get_items(client_id=client_id, limit=500, sort="risk")
    extras = await _get_report_extras(client_id, days)
    html = generate_client_report_html(client, items, days, extras=extras)
    # Add download PDF button at top
    btn = f'<div style="padding:12px;background:#1a1a2e;text-align:center"><a href="/api/v1/admin/clients/{client_id}/report.pdf?days={days}" style="color:#fff;background:#6b46c1;padding:8px 20px;text-decoration:none;font-family:sans-serif;font-size:13px">⬇ Download PDF</a></div>'
    html = html.replace("<body>", "<body>" + btn)
    return Response(content=html, media_type="text/html")


@router.get("/clients/{client_id}/report.pdf", summary="Generate PDF report for a client")
async def client_report_pdf(
    client_id: str,
    days: int = Query(7, ge=1, le=365),
    _: dict = Depends(_require_admin_token_or_header),
):
    from reports.pdf_generator import generate_client_report, _get_report_extras
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    items = await db.get_items(client_id=client_id, limit=500, sort="risk")
    extras = await _get_report_extras(client_id, days)
    content, media_type = generate_client_report(client, items, days, extras=extras)
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


# ── Assets ────────────────────────────────────────────────────────────────────

@router.get("/clients/{client_id}/assets", summary="List client assets")
async def list_assets(client_id: str, _: dict = Depends(_require_admin_token_or_header)):
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    assets = await db.get_assets(client_id)
    return {"client_id": client_id, "count": len(assets), "assets": assets}


@router.post("/clients/{client_id}/assets/import", summary="Import assets from CSV")
async def import_assets(
    client_id: str,
    file: UploadFile = File(...),
    _: dict = Depends(require_admin),
):
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    content = await file.read()
    text = content.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))

    imported = 0
    errors = []
    for i, row in enumerate(reader):
        software = (row.get("software") or "").strip()
        if not software:
            errors.append(f"Row {i+2}: missing 'software' column")
            continue
        try:
            await db.upsert_asset(
                client_id=client_id,
                software=software,
                version=(row.get("version") or "").strip(),
                hostname=(row.get("hostname") or "").strip(),
                ip_address=(row.get("ip_address") or "").strip(),
                os=(row.get("os") or "").strip(),
                os_version=(row.get("os_version") or "").strip(),
                cpe_string=(row.get("cpe_string") or "").strip(),
                asset_type=(row.get("asset_type") or "workstation").strip(),
            )
            imported += 1
        except Exception as exc:
            errors.append(f"Row {i+2}: {exc}")

    return {"imported": imported, "errors": errors[:20]}


@router.delete("/clients/{client_id}/assets/{asset_id}", summary="Delete an asset")
async def delete_asset(client_id: str, asset_id: str, _: dict = Depends(require_admin)):
    await db.delete_asset(asset_id)
    return {"status": "ok", "deleted": asset_id}


# ── Webhooks ──────────────────────────────────────────────────────────────────

# RFC-1918 + loopback + link-local ranges that must never be webhook targets
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / AWS metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

def _validate_webhook_url(url: str) -> str:
    if not url:
        raise ValueError("Webhook URL is required")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Webhook URL must use http or https")
    host = parsed.hostname or ""
    if not host:
        raise ValueError("Webhook URL must contain a valid hostname")
    # Reject bare 'localhost' and variants
    if re.match(r"^(localhost|127\.|0\.0\.0\.0)", host):
        raise ValueError("Webhook URL must not target localhost or loopback addresses")
    # Reject numeric IPs in private ranges
    try:
        addr = ipaddress.ip_address(host)
        if any(addr in net for net in _PRIVATE_NETS):
            raise ValueError("Webhook URL must not target private/reserved IP addresses")
    except ValueError as exc:
        if "Webhook URL" in str(exc):
            raise
        # Not an IP address — hostname; allow it (DNS resolution happens at fire time)
    return url


class WebhookCreate(BaseModel):
    webhook_type: str  # generic, slack, splunk_hec, sentinel
    url: str
    secret: str = ""
    min_severity: str = "HIGH"
    categories: list = []

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        return _validate_webhook_url(v)

    @field_validator("webhook_type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        allowed = {"generic", "slack", "splunk_hec", "sentinel"}
        if v not in allowed:
            raise ValueError(f"webhook_type must be one of {sorted(allowed)}")
        return v


class WebhookUpdate(BaseModel):
    url: Optional[str] = None
    secret: Optional[str] = None
    min_severity: Optional[str] = None
    categories: Optional[list] = None
    is_active: Optional[int] = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return _validate_webhook_url(v)
        return v


@router.get("/clients/{client_id}/webhooks", summary="List webhooks for a client")
async def list_webhooks(client_id: str, _: dict = Depends(require_admin)):
    return {"webhooks": await db.get_webhooks(client_id)}


@router.post("/clients/{client_id}/webhooks", summary="Create a webhook")
async def create_webhook(client_id: str, req: WebhookCreate, _: dict = Depends(require_admin)):
    wh = await db.create_webhook(
        client_id=client_id,
        webhook_type=req.webhook_type,
        url=req.url,
        secret=req.secret,
        min_severity=req.min_severity,
        categories=req.categories,
    )
    return wh


@router.put("/clients/{client_id}/webhooks/{wh_id}", summary="Update a webhook")
async def update_webhook(client_id: str, wh_id: str, req: WebhookUpdate, _: dict = Depends(require_admin)):
    fields = {k: v for k, v in req.model_dump().items() if v is not None}
    wh = await db.update_webhook(wh_id, **fields)
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return wh


@router.delete("/clients/{client_id}/webhooks/{wh_id}", summary="Delete a webhook")
async def delete_webhook(client_id: str, wh_id: str, _: dict = Depends(require_admin)):
    await db.delete_webhook(wh_id)
    return {"status": "ok", "deleted": wh_id}


@router.post("/clients/{client_id}/webhooks/{wh_id}/test", summary="Send test payload to webhook")
async def test_webhook(client_id: str, wh_id: str, _: dict = Depends(require_admin)):
    from reports.webhook_dispatcher import WebhookDispatcher
    wh = await db.get_webhook(wh_id)
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")
    test_item = {
        "id": "test-item-000",
        "title": "PhantomFeed Test Webhook",
        "severity": "HIGH",
        "cvss": 7.5,
        "risk_score": 6.0,
        "vendor": "PhantomFeed",
        "product": "Test",
        "published_at": "2025-01-01",
        "url": "https://github.com/zacharyloganhill/PhantomFeed",
        "cve_ids": ["CVE-2024-TEST"],
        "tags": ["Test", "Webhook"],
        "compliance_tags": ["CMMC-RA"],
        "category": "advisory",
    }
    dispatcher = WebhookDispatcher()
    result = await dispatcher.dispatch_to_webhook(wh, test_item)
    return {"status": result}
